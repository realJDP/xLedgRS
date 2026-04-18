use super::{legacy_path_not_supported, TecCode, TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::sle::{LedgerEntryType, SLE};
use crate::ledger::views::{ApplyView, ReadView};
use crate::transaction::ParsedTx;
use std::sync::Arc;

pub struct PaymentHandler;

impl TxHandler for PaymentHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        if tx.destination.is_none() {
            return Err(TER::Malformed("temDST_NEEDED"));
        }
        if tx.amount_drops.is_none() && tx.amount.is_none() {
            return Err(TER::Malformed("temBAD_AMOUNT"));
        }
        Ok(())
    }

    fn preclaim(&self, tx: &ParsedTx, view: &dyn ReadView) -> Result<(), TER> {
        // Check destination exists (for XRP payments to existing accounts)
        // New accounts can be created if amount >= reserve
        let dest_id = tx.destination.unwrap();
        let dest_keylet = keylet::account(&dest_id);

        if let Some(drops) = tx.amount_drops {
            if !view.exists(&dest_keylet) {
                // Creating new account — check reserve
                if drops < view.fees().reserve_base {
                    return Err(TER::ClaimedCost(TecCode::NoDstInsuf));
                }
            }
        }
        Ok(())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let dest_id = tx.destination.unwrap();
        let dest_keylet = keylet::account(&dest_id);

        // XRP payment
        if let Some(drops) = tx.amount_drops {
            // Deduct from sender (fee already deducted by Transactor)
            let sender_keylet = keylet::account(&tx.account);
            let sender_sle = match view.peek(&sender_keylet) {
                Some(s) => s,
                None => return TER::LocalFail("terNO_ACCOUNT"),
            };

            let sender_balance = sender_sle.balance_xrp().unwrap_or(0);
            if sender_balance < drops {
                return TER::ClaimedCost(TecCode::Unfunded);
            }

            let mut sender = (*sender_sle).clone();
            sender.set_balance_xrp(sender_balance - drops);
            view.update(Arc::new(sender));

            // Credit destination
            match view.peek(&dest_keylet) {
                Some(dest_sle) => {
                    let dest_balance = dest_sle.balance_xrp().unwrap_or(0);
                    let mut dest = (*dest_sle).clone();
                    dest.set_balance_xrp(dest_balance + drops);
                    view.update(Arc::new(dest));
                }
                None => {
                    // Create new account
                    let mut data = Vec::with_capacity(64);
                    // LedgerEntryType
                    crate::ledger::meta::write_field_header(&mut data, 1, 1);
                    data.extend_from_slice(&0x0061u16.to_be_bytes());
                    // Flags = 0
                    crate::ledger::meta::write_field_header(&mut data, 2, 2);
                    data.extend_from_slice(&0u32.to_be_bytes());
                    // Sequence = 1
                    crate::ledger::meta::write_field_header(&mut data, 2, 4);
                    data.extend_from_slice(&1u32.to_be_bytes());
                    // OwnerCount = 0
                    crate::ledger::meta::write_field_header(&mut data, 2, 13);
                    data.extend_from_slice(&0u32.to_be_bytes());
                    // Balance
                    crate::ledger::meta::write_field_header(&mut data, 6, 2);
                    let balance_wire = drops | 0x4000_0000_0000_0000;
                    data.extend_from_slice(&balance_wire.to_be_bytes());
                    // Account
                    crate::ledger::meta::write_field_header(&mut data, 8, 1);
                    crate::ledger::meta::encode_vl_length(&mut data, 20);
                    data.extend_from_slice(&dest_id);

                    let sle = SLE::new(dest_keylet.key, LedgerEntryType::AccountRoot, data);
                    view.insert(Arc::new(sle));
                }
            }

            TER::Success
        } else {
            // The legacy view-stack transactor never implemented RippleCalc.
            // Reject this path explicitly so callers use `ledger::tx::payment`.
            legacy_path_not_supported()
        }
    }
}
