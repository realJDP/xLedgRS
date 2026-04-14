use std::sync::Arc;
use crate::ledger::keylet;
use crate::ledger::sle::{SLE, LedgerEntryType};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use crate::ledger::views::ReadView;
use super::{TER, TxHandler, check_reserve};

pub struct SignerListSetHandler;

impl TxHandler for SignerListSetHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let signer_list_keylet = keylet::signer_list(&tx.account);

        if let Some(quorum) = tx.signer_quorum {
            if quorum == 0 {
                // Delete signer list
                if view.exists(&signer_list_keylet) {
                    view.erase(&signer_list_keylet.key);
                    let sender_keylet = keylet::account(&tx.account);
                    if let Some(sender_sle) = view.peek(&sender_keylet) {
                        let mut s = (*sender_sle).clone();
                        s.set_owner_count(s.owner_count().saturating_sub(1));
                        view.update(Arc::new(s));
                    }
                }
            } else if let Some(ref entries_raw) = tx.signer_entries_raw {
                // Create or replace signer list
                let existed = view.exists(&signer_list_keylet);

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
                data.extend_from_slice(&0u64.to_be_bytes()); // OwnerNode
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
                    // Reserve check — sender must afford one more owned object
                    let sender_keylet = keylet::account(&tx.account);
                    if let Some(sender_sle) = view.peek(&sender_keylet) {
                        let balance = sender_sle.balance_xrp().unwrap_or(0);
                        if let Err(ter) = check_reserve(balance, sender_sle.owner_count(), 1, view.fees()) {
                            return ter;
                        }
                    }

                    let sle = SLE::new(signer_list_keylet.key, LedgerEntryType::SignerList, data);
                    view.insert(Arc::new(sle));

                    let sender_keylet = keylet::account(&tx.account);
                    if let Some(sender_sle) = view.peek(&sender_keylet) {
                        let mut s = (*sender_sle).clone();
                        s.set_owner_count(s.owner_count() + 1);
                        view.update(Arc::new(s));
                    }
                }
            }
        }

        TER::Success
    }
}
