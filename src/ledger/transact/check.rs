use super::{check_reserve, legacy_path_not_supported, owner_dir, TecCode, TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::sle::{LedgerEntryType, SLE};
use crate::ledger::views::{ApplyView, ReadView};
use crate::transaction::{Amount, ParsedTx};
use std::sync::Arc;

pub struct CheckCreateHandler;

const LSF_REQUIRE_DEST_TAG: u32 = 0x0002_0000;
const LSF_GLOBAL_FREEZE: u32 = 0x0040_0000;
const LSF_DISALLOW_INCOMING_CHECK: u32 = 0x0800_0000;
const LSF_LOW_FREEZE: u32 = 0x0040_0000;
const LSF_HIGH_FREEZE: u32 = 0x0080_0000;

fn xrp_drops(amount: &Amount) -> Option<u64> {
    match amount {
        Amount::Xrp(drops) => Some(*drops),
        _ => None,
    }
}

fn amount_wire(amount: &Amount) -> Vec<u8> {
    amount.to_bytes()
}

fn required_check_id(tx: &ParsedTx) -> Result<[u8; 32], TER> {
    crate::transaction::parse::parsed_check_id(tx).ok_or(TER::Malformed("temMALFORMED"))
}

impl TxHandler for CheckCreateHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        let destination = tx.destination.ok_or(TER::Malformed("temDST_NEEDED"))?;
        if destination == tx.account {
            return Err(TER::Malformed("temREDUNDANT"));
        }
        match &tx.send_max {
            Some(Amount::Xrp(drops)) if *drops > 0 => {}
            Some(Amount::Xrp(_)) => return Err(TER::Malformed("temBAD_AMOUNT")),
            Some(Amount::Iou {
                value, currency, ..
            }) => {
                if !value.is_positive() {
                    return Err(TER::Malformed("temBAD_AMOUNT"));
                }
                if currency.is_bad_currency() {
                    return Err(TER::Malformed("temBAD_CURRENCY"));
                }
            }
            Some(Amount::Mpt(_)) => return Err(TER::Malformed("temBAD_AMOUNT")),
            None => return Err(TER::Malformed("temBAD_AMOUNT")),
        }
        if matches!(tx.expiration, Some(0)) {
            return Err(TER::Malformed("temBAD_EXPIRATION"));
        }
        Ok(())
    }

    fn preclaim(&self, tx: &ParsedTx, view: &dyn ReadView) -> Result<(), TER> {
        let destination = tx.destination.ok_or(TER::Malformed("temDST_NEEDED"))?;
        let dest_keylet = keylet::account(&destination);
        let dest_sle = view
            .read(&dest_keylet)
            .ok_or(TER::ClaimedCost(TecCode::NoDst))?;
        let dest_flags = dest_sle.get_field_u32(2, 2).unwrap_or(0);
        if (dest_flags & LSF_DISALLOW_INCOMING_CHECK) != 0 {
            return Err(TER::ClaimedCost(TecCode::Generic("tecNO_PERMISSION")));
        }
        if (dest_flags & LSF_REQUIRE_DEST_TAG) != 0 && tx.destination_tag.is_none() {
            return Err(TER::ClaimedCost(TecCode::Generic("tecDST_TAG_NEEDED")));
        }
        if matches!(tx.expiration, Some(expiration) if view.info().close_time as u32 >= expiration)
        {
            return Err(TER::ClaimedCost(TecCode::Generic("tecEXPIRED")));
        }

        if let Some(Amount::Iou {
            currency, issuer, ..
        }) = &tx.send_max
        {
            if view
                .read(&keylet::account(issuer))
                .and_then(|issuer_sle| issuer_sle.get_field_u32(2, 2))
                .is_some_and(|flags| (flags & LSF_GLOBAL_FREEZE) != 0)
            {
                return Err(TER::ClaimedCost(TecCode::Generic("tecFROZEN")));
            }
            if issuer != &tx.account {
                if let Some(line) =
                    view.read(&keylet::trustline(&tx.account, issuer, &currency.code))
                {
                    let issuer_is_high = issuer > &tx.account;
                    let freeze = if issuer_is_high {
                        LSF_HIGH_FREEZE
                    } else {
                        LSF_LOW_FREEZE
                    };
                    if (line.get_field_u32(2, 2).unwrap_or(0) & freeze) != 0 {
                        return Err(TER::ClaimedCost(TecCode::Generic("tecFROZEN")));
                    }
                }
            }
            if issuer != &destination {
                if let Some(line) =
                    view.read(&keylet::trustline(issuer, &destination, &currency.code))
                {
                    let dest_is_high = destination > *issuer;
                    let freeze = if dest_is_high {
                        LSF_HIGH_FREEZE
                    } else {
                        LSF_LOW_FREEZE
                    };
                    if (line.get_field_u32(2, 2).unwrap_or(0) & freeze) != 0 {
                        return Err(TER::ClaimedCost(TecCode::Generic("tecFROZEN")));
                    }
                }
            }
        }

        Ok(())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let dest_id = tx.destination.unwrap();
        let send_max = match &tx.send_max {
            Some(amount) => amount_wire(amount),
            None => return TER::Malformed("temBAD_AMOUNT"),
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
        if let Some(tag) = crate::transaction::parse::parsed_source_tag(tx) {
            crate::ledger::meta::write_field_header(&mut data, 2, 3);
            data.extend_from_slice(&tag.to_be_bytes());
        }
        if let Some(exp) = tx.expiration {
            crate::ledger::meta::write_field_header(&mut data, 2, 10);
            data.extend_from_slice(&exp.to_be_bytes());
        }
        if let Some(tag) = tx.destination_tag {
            crate::ledger::meta::write_field_header(&mut data, 2, 14);
            data.extend_from_slice(&tag.to_be_bytes());
        }
        crate::ledger::meta::write_field_header(&mut data, 3, 4);
        data.extend_from_slice(&owner_node.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 3, 9);
        data.extend_from_slice(&destination_node.to_be_bytes());
        if let Some(invoice_id) = crate::transaction::parse::parsed_invoice_id(tx) {
            crate::ledger::meta::write_field_header(&mut data, 5, 17);
            data.extend_from_slice(&invoice_id);
        }
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
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        required_check_id(tx).map(|_| ())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let check_id = match required_check_id(tx) {
            Ok(id) => id,
            Err(ter) => return ter,
        };
        let check_keylet =
            keylet::Keylet::new(crate::ledger::Key(check_id), LedgerEntryType::Check);

        let check_sle = match view.peek(&check_keylet) {
            Some(s) => s,
            None => return TER::ClaimedCost(TecCode::NoEntry),
        };
        let creator_id = check_sle.account_id().unwrap_or([0u8; 20]);
        let dest_id = check_sle.get_field_account(8, 3).unwrap_or(creator_id);
        let is_expired = check_sle
            .get_field_u32(2, 10)
            .is_some_and(|expiration| view.info().close_time as u32 >= expiration);
        if !is_expired && tx.account != creator_id && tx.account != dest_id {
            return TER::ClaimedCost(TecCode::Generic("tecNO_PERMISSION"));
        }

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
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        required_check_id(tx)?;
        if tx.amount.is_some() == tx.deliver_min.is_some() {
            return Err(TER::Malformed("temMALFORMED"));
        }
        if let Some(amount) = tx.amount.as_ref().or(tx.deliver_min.as_ref()) {
            match amount {
                Amount::Xrp(drops) if *drops > 0 => {}
                Amount::Xrp(_) => return Err(TER::Malformed("temBAD_AMOUNT")),
                Amount::Iou {
                    value, currency, ..
                } => {
                    if !value.is_positive() {
                        return Err(TER::Malformed("temBAD_AMOUNT"));
                    }
                    if currency.is_bad_currency() {
                        return Err(TER::Malformed("temBAD_CURRENCY"));
                    }
                }
                Amount::Mpt(_) => return Err(TER::Malformed("temBAD_AMOUNT")),
            }
        }
        Ok(())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let check_id = match required_check_id(tx) {
            Ok(id) => id,
            Err(ter) => return ter,
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
        let dest_keylet = keylet::account(&tx.account);
        if view.peek(&dest_keylet).is_none() {
            return TER::ClaimedCost(TecCode::NoEntry);
        }

        let send_max_raw = match check_sle.find_field_raw(6, 9) {
            Some(raw) => raw,
            None => return TER::Malformed("temBAD_AMOUNT"),
        };
        let (send_max, _) = match Amount::from_bytes(&send_max_raw) {
            Ok(decoded) => decoded,
            Err(_) => return TER::Malformed("temBAD_AMOUNT"),
        };
        let send_max_drops = match send_max {
            Amount::Xrp(drops) if drops > 0 => drops,
            Amount::Xrp(_) => return TER::Malformed("temBAD_AMOUNT"),
            Amount::Iou { .. } => return legacy_path_not_supported(),
            Amount::Mpt(_) => return TER::Malformed("temBAD_AMOUNT"),
        };
        let requested = match tx
            .amount
            .as_ref()
            .or(tx.deliver_min.as_ref())
            .and_then(xrp_drops)
        {
            Some(drops) if drops > 0 => drops,
            Some(_) => return TER::Malformed("temBAD_AMOUNT"),
            None => return TER::Malformed("temMALFORMED"),
        };
        if requested > send_max_drops {
            return TER::ClaimedCost(TecCode::Generic("tecPATH_PARTIAL"));
        }

        // Debit creator
        let creator_keylet = keylet::account(&check_creator);
        if let Some(creator_sle) = view.peek(&creator_keylet) {
            let bal = creator_sle.balance_xrp().unwrap_or(0);
            let owner_count_after = creator_sle.owner_count().saturating_sub(1);
            let fees = view.fees();
            let reserve_after =
                fees.reserve_base + (owner_count_after as u64).saturating_mul(fees.reserve_inc);
            let liquid = bal.saturating_sub(reserve_after);
            if requested > liquid {
                return TER::ClaimedCost(TecCode::Generic("tecPATH_PARTIAL"));
            }
            let cash_drops = if tx.amount.is_some() {
                requested
            } else {
                std::cmp::min(send_max_drops, liquid)
            };
            if bal < cash_drops {
                return TER::ClaimedCost(TecCode::Generic("tecPATH_PARTIAL"));
            }
            let mut creator = (*creator_sle).clone();
            creator.set_balance_xrp(bal - cash_drops);
            creator.set_owner_count(creator.owner_count().saturating_sub(1));
            view.update(Arc::new(creator));

            // Credit destination
            if let Some(dest_sle) = view.peek(&dest_keylet) {
                let bal = dest_sle.balance_xrp().unwrap_or(0);
                let mut dest = (*dest_sle).clone();
                dest.set_balance_xrp(bal + cash_drops);
                view.update(Arc::new(dest));
            }
        } else {
            return TER::ClaimedCost(TecCode::NoEntry);
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
