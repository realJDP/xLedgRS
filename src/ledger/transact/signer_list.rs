use super::{check_reserve, owner_dir, TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::sle::{LedgerEntryType, SLE};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use std::sync::Arc;

pub struct SignerListSetHandler;

impl TxHandler for SignerListSetHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        match tx.signer_quorum {
            Some(0) => Ok(()),
            Some(_) if tx.signer_entries_raw.as_deref() != Some(&[0xF1]) => Ok(()),
            _ => Err(TER::Malformed("temMALFORMED")),
        }
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let signer_list_keylet = keylet::signer_list(&tx.account);

        let quorum = match tx.signer_quorum {
            Some(q) => q,
            None => return TER::Malformed("temMALFORMED"),
        };

        if quorum == 0 {
            // Delete signer list
            if view.exists(&signer_list_keylet) {
                owner_dir::dir_remove(view, &tx.account, &signer_list_keylet.key.0);
                view.erase(&signer_list_keylet.key);
                let sender_keylet = keylet::account(&tx.account);
                if let Some(sender_sle) = view.peek(&sender_keylet) {
                    let mut s = (*sender_sle).clone();
                    s.set_owner_count(s.owner_count().saturating_sub(1));
                    view.update(Arc::new(s));
                }
            }
            return TER::Success;
        }

        let entries_raw = match tx.signer_entries_raw.as_deref() {
            Some(entries) if entries != [0xF1] => entries,
            _ => return TER::Malformed("temMALFORMED"),
        };

        // Create or replace signer list
        let existed = view.exists(&signer_list_keylet);
        let owner_node = if existed {
            view.peek(&signer_list_keylet)
                .and_then(|sle| sle.get_field_u64(3, 4))
                .unwrap_or(0)
        } else {
            let sender_keylet = keylet::account(&tx.account);
            if let Some(sender_sle) = view.peek(&sender_keylet) {
                let balance = sender_sle.balance_xrp().unwrap_or(0);
                if let Err(ter) = check_reserve(balance, sender_sle.owner_count(), 1, view.fees()) {
                    return ter;
                }
            }
            owner_dir::dir_add(view, &tx.account, signer_list_keylet.key.0)
        };

        let mut data = Vec::with_capacity(128 + entries_raw.len());
        crate::ledger::meta::write_field_header(&mut data, 1, 1);
        data.extend_from_slice(&0x0053u16.to_be_bytes()); // SignerList
        crate::ledger::meta::write_field_header(&mut data, 2, 2);
        data.extend_from_slice(&0u32.to_be_bytes()); // Flags
        crate::ledger::meta::write_field_header(&mut data, 2, 35);
        data.extend_from_slice(&quorum.to_be_bytes()); // SignerQuorum
        crate::ledger::meta::write_field_header(&mut data, 2, 38);
        data.extend_from_slice(&0u32.to_be_bytes()); // SignerListID = 0
        crate::ledger::meta::write_field_header(&mut data, 3, 4);
        data.extend_from_slice(&owner_node.to_be_bytes());
        // SignerEntries (STArray, type=15, field=4)
        crate::ledger::meta::write_field_header(&mut data, 15, 4);
        data.extend_from_slice(entries_raw);
        // Account
        crate::ledger::meta::write_field_header(&mut data, 8, 1);
        crate::ledger::meta::encode_vl_length(&mut data, 20);
        data.extend_from_slice(&tx.account);

        if existed {
            // Replace existing
            let sle = SLE::new(signer_list_keylet.key, LedgerEntryType::SignerList, data);
            view.update(Arc::new(sle));
        } else {
            let sle = SLE::new(signer_list_keylet.key, LedgerEntryType::SignerList, data);
            view.insert(Arc::new(sle));

            let sender_keylet = keylet::account(&tx.account);
            if let Some(sender_sle) = view.peek(&sender_keylet) {
                let mut s = (*sender_sle).clone();
                s.set_owner_count(s.owner_count() + 1);
                view.update(Arc::new(s));
            }
        }

        TER::Success
    }
}
