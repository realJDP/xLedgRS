use super::{check_reserve, owner_dir, TecCode, TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::sle::SLE;
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use std::sync::Arc;

pub struct DepositPreauthHandler;

impl TxHandler for DepositPreauthHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        let op_count = tx.authorize.is_some() as u8 + tx.unauthorize.is_some() as u8;
        if op_count != 1 {
            return Err(TER::Malformed("temMALFORMED"));
        }
        let target = tx.authorize.or(tx.unauthorize).unwrap_or([0u8; 20]);
        if target == [0u8; 20] {
            return Err(TER::Malformed("temINVALID_ACCOUNT_ID"));
        }
        if tx.authorize == Some(tx.account) {
            return Err(TER::Malformed("temCANNOT_PREAUTH_SELF"));
        }
        Ok(())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        if let Some(authorized) = tx.unauthorize {
            return remove_deposit_preauth(tx, view, authorized);
        }

        let authorized = match tx.authorize {
            Some(d) => d,
            None => return TER::Malformed("temMALFORMED"),
        };
        let dp_keylet = crate::ledger::keylet::deposit_preauth(&tx.account, &authorized);

        if view.exists(&dp_keylet) {
            return TER::ClaimedCost(TecCode::DuplicateEntry);
        }
        if !view.exists(&keylet::account(&authorized)) {
            return TER::ClaimedCost(TecCode::NoTarget);
        } else {
            // Reserve check — sender must afford one more owned object
            let sender_keylet_chk = keylet::account(&tx.account);
            if let Some(sender_sle) = view.peek(&sender_keylet_chk) {
                let balance = sender_sle.balance_xrp().unwrap_or(0);
                if let Err(ter) = check_reserve(balance, sender_sle.owner_count(), 1, view.fees()) {
                    return ter;
                }
            }

            let owner_node = owner_dir::dir_add(view, &tx.account, dp_keylet.key.0);

            // Create new preauth
            let mut data = Vec::with_capacity(64);
            // LedgerEntryType = DepositPreauth (0x0070)
            crate::ledger::meta::write_field_header(&mut data, 1, 1);
            data.extend_from_slice(&0x0070u16.to_be_bytes());
            // Flags = 0
            crate::ledger::meta::write_field_header(&mut data, 2, 2);
            data.extend_from_slice(&0u32.to_be_bytes());
            crate::ledger::meta::write_field_header(&mut data, 3, 4);
            data.extend_from_slice(&owner_node.to_be_bytes());
            // Account
            crate::ledger::meta::write_field_header(&mut data, 8, 1);
            crate::ledger::meta::encode_vl_length(&mut data, 20);
            data.extend_from_slice(&tx.account);
            // Authorize (type=8, field=5)
            crate::ledger::meta::write_field_header(&mut data, 8, 5);
            crate::ledger::meta::encode_vl_length(&mut data, 20);
            data.extend_from_slice(&authorized);

            let sle = SLE::new(
                dp_keylet.key,
                crate::ledger::sle::LedgerEntryType::DepositPreauth,
                data,
            );
            view.insert(Arc::new(sle));

            // Increment owner count
            let sender_keylet = keylet::account(&tx.account);
            if let Some(sender_sle) = view.peek(&sender_keylet) {
                let mut sender = (*sender_sle).clone();
                let oc = sender.owner_count();
                sender.set_owner_count(oc + 1);
                view.update(Arc::new(sender));
            }
        }

        TER::Success
    }
}

fn remove_deposit_preauth(tx: &ParsedTx, view: &mut dyn ApplyView, authorized: [u8; 20]) -> TER {
    let dp_keylet = crate::ledger::keylet::deposit_preauth(&tx.account, &authorized);
    if !view.exists(&dp_keylet) {
        return TER::ClaimedCost(TecCode::NoEntry);
    }

    owner_dir::dir_remove(view, &tx.account, &dp_keylet.key.0);
    view.erase(&dp_keylet.key);

    let sender_keylet = keylet::account(&tx.account);
    if let Some(sender_sle) = view.peek(&sender_keylet) {
        let mut sender = (*sender_sle).clone();
        sender.set_owner_count(sender.owner_count().saturating_sub(1));
        view.update(Arc::new(sender));
    }

    TER::Success
}
