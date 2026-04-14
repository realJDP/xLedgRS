use std::sync::Arc;
use crate::ledger::keylet;
use crate::ledger::sle::SLE;
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use super::{TER, TxHandler, check_reserve, owner_dir};

pub struct DepositPreauthHandler;

impl TxHandler for DepositPreauthHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let authorized = match tx.destination {
            Some(d) => d,
            None => return TER::Malformed("temDST_NEEDED"),
        };

        let dp_keylet = crate::ledger::keylet::deposit_preauth(&tx.account, &authorized);

        if view.exists(&dp_keylet) {
            // Already authorized -- remove (toggle behavior)
            owner_dir::dir_remove(view, &tx.account, &dp_keylet.key.0);
            view.erase(&dp_keylet.key);

            // Decrement owner count
            let sender_keylet = keylet::account(&tx.account);
            if let Some(sender_sle) = view.peek(&sender_keylet) {
                let mut sender = (*sender_sle).clone();
                let oc = sender.owner_count();
                sender.set_owner_count(oc.saturating_sub(1));
                view.update(Arc::new(sender));
            }
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
