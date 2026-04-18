use super::{check_reserve, owner_dir, TecCode, TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::sle::{LedgerEntryType, SLE};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use std::sync::Arc;

pub struct CheckCreateHandler;

impl TxHandler for CheckCreateHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        if tx.destination.is_none() {
            return Err(TER::Malformed("temDST_NEEDED"));
        }
        Ok(())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let dest_id = tx.destination.unwrap();
        let send_max = match &tx.amount {
            Some(amt) => amt.to_bytes(),
            None => match tx.amount_drops {
                Some(d) => {
                    let wire = d | 0x4000_0000_0000_0000;
                    wire.to_be_bytes().to_vec()
                }
                None => return TER::Malformed("temBAD_AMOUNT"),
            },
        };

        // Reserve check — sender must afford one more owned object
        let sender_keylet = keylet::account(&tx.account);
        let sender_sle = match view.peek(&sender_keylet) {
            Some(s) => s,
            None => return TER::LocalFail("terNO_ACCOUNT"),
        };
        let balance = sender_sle.balance_xrp().unwrap_or(0);
        if let Err(ter) = check_reserve(balance, sender_sle.owner_count(), 1, view.fees()) {
            return ter;
        }

        let check_keylet = keylet::check(&tx.account, tx.sequence);
        let owner_node = owner_dir::dir_add(view, &tx.account, check_keylet.key.0);
        let destination_node = if dest_id != tx.account {
            owner_dir::dir_add(view, &dest_id, check_keylet.key.0)
        } else {
            0
        };

        // Build check SLE
        let mut data = Vec::with_capacity(128);
        crate::ledger::meta::write_field_header(&mut data, 1, 1);
        data.extend_from_slice(&0x0043u16.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 2, 2);
        data.extend_from_slice(&0u32.to_be_bytes()); // Flags
        crate::ledger::meta::write_field_header(&mut data, 2, 4);
        data.extend_from_slice(&tx.sequence.to_be_bytes()); // Sequence
        if let Some(exp) = tx.expiration {
            crate::ledger::meta::write_field_header(&mut data, 2, 10);
            data.extend_from_slice(&exp.to_be_bytes());
        }
        crate::ledger::meta::write_field_header(&mut data, 3, 4);
        data.extend_from_slice(&owner_node.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 3, 9);
        data.extend_from_slice(&destination_node.to_be_bytes());
        // SendMax
        crate::ledger::meta::write_field_header(&mut data, 6, 9);
        data.extend_from_slice(&send_max);
        // Account
        crate::ledger::meta::write_field_header(&mut data, 8, 1);
        crate::ledger::meta::encode_vl_length(&mut data, 20);
        data.extend_from_slice(&tx.account);
        // Destination
        crate::ledger::meta::write_field_header(&mut data, 8, 3);
        crate::ledger::meta::encode_vl_length(&mut data, 20);
        data.extend_from_slice(&dest_id);

        view.insert(Arc::new(SLE::new(
            check_keylet.key,
            LedgerEntryType::Check,
            data,
        )));

        // Bump owner count
        let mut s = (*sender_sle).clone();
        s.set_owner_count(s.owner_count() + 1);
        view.update(Arc::new(s));

        TER::Success
    }
}

pub struct CheckCancelHandler;

impl TxHandler for CheckCancelHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        // CheckCancel uses the check ID from nftoken_id field (overloaded)
        // or from the Check's key derived from account + sequence
        let check_id = tx.nftoken_id.unwrap_or([0u8; 32]); // sfCheckID reuses the Hash256 slot
        if check_id == [0u8; 32] {
            return TER::Malformed("temBAD_AMOUNT");
        }

        let check_keylet = crate::ledger::keylet::from_raw(check_id, 0x0043).unwrap_or(
            keylet::Keylet::new(crate::ledger::Key(check_id), LedgerEntryType::Check),
        );

        let check_sle = match view.peek(&check_keylet) {
            Some(s) => s,
            None => return TER::ClaimedCost(TecCode::NoEntry),
        };
        let creator_id = check_sle.account_id().unwrap_or([0u8; 20]);
        let dest_id = check_sle.get_field_account(8, 3).unwrap_or(creator_id);

        owner_dir::dir_remove(view, &creator_id, &check_keylet.key.0);
        if dest_id != creator_id {
            owner_dir::dir_remove(view, &dest_id, &check_keylet.key.0);
        }
        view.erase(&check_keylet.key);

        let creator_keylet = keylet::account(&creator_id);
        if let Some(creator_sle) = view.peek(&creator_keylet) {
            let mut creator = (*creator_sle).clone();
            creator.set_owner_count(creator.owner_count().saturating_sub(1));
            view.update(Arc::new(creator));
        }

        TER::Success
    }
}

pub struct CheckCashHandler;

impl TxHandler for CheckCashHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        // CheckCash uses nftoken_id field to pass the CheckID (overloaded Hash256)
        let check_id = match tx.nftoken_id {
            Some(id) if id != [0u8; 32] => id,
            _ => return TER::Malformed("temMALFORMED"),
        };

        let check_keylet =
            keylet::Keylet::new(crate::ledger::Key(check_id), LedgerEntryType::Check);
        let check_sle = match view.peek(&check_keylet) {
            Some(s) => s,
            None => return TER::ClaimedCost(TecCode::NoEntry),
        };

        // Get check fields
        let check_creator = check_sle.account_id().unwrap_or([0u8; 20]);
        let check_dest = check_sle.get_field_account(8, 3).unwrap_or([0u8; 20]);

        // Only destination can cash a check
        if tx.account != check_dest {
            return TER::ClaimedCost(TecCode::Generic("tecNO_PERMISSION"));
        }

        // Get the `SendMax` amount. This path supports XRP only.
        let send_max_drops = check_sle.get_field_xrp_drops(6, 9).unwrap_or(0);
        let cash_drops = tx
            .amount_drops
            .unwrap_or(send_max_drops)
            .min(send_max_drops);

        if cash_drops == 0 {
            return TER::ClaimedCost(TecCode::Generic("tecINSUFFICIENT_FUNDS"));
        }

        // Debit creator
        let creator_keylet = keylet::account(&check_creator);
        if let Some(creator_sle) = view.peek(&creator_keylet) {
            let bal = creator_sle.balance_xrp().unwrap_or(0);
            if bal < cash_drops {
                return TER::ClaimedCost(TecCode::Unfunded);
            }
            let mut creator = (*creator_sle).clone();
            creator.set_balance_xrp(bal - cash_drops);
            creator.set_owner_count(creator.owner_count().saturating_sub(1));
            view.update(Arc::new(creator));
        } else {
            return TER::ClaimedCost(TecCode::Unfunded);
        }

        // Credit destination
        let dest_keylet = keylet::account(&tx.account);
        if let Some(dest_sle) = view.peek(&dest_keylet) {
            let bal = dest_sle.balance_xrp().unwrap_or(0);
            let mut dest = (*dest_sle).clone();
            dest.set_balance_xrp(bal + cash_drops);
            view.update(Arc::new(dest));
        }

        owner_dir::dir_remove(view, &check_creator, &check_keylet.key.0);
        if check_dest != check_creator {
            owner_dir::dir_remove(view, &check_dest, &check_keylet.key.0);
        }

        // Remove check
        view.erase(&check_keylet.key);

        TER::Success
    }
}
