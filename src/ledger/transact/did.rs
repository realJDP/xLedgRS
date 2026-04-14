use std::sync::Arc;
use crate::ledger::keylet;
use crate::ledger::sle::{SLE, LedgerEntryType};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use super::{TER, TecCode, TxHandler, check_reserve, owner_dir};

pub struct DIDSetHandler;

impl TxHandler for DIDSetHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let did_keylet = keylet::did(&tx.account);

        if let Some(did_sle) = view.peek(&did_keylet) {
            // Modify existing DID
            let mut did = (*did_sle).clone();

            if let Some(ref uri) = tx.uri {
                if uri.is_empty() {
                    did.remove_field(7, 5); // sfURI
                } else {
                    did.set_field_raw_pub(7, 5, uri);
                }
            }
            if let Some(ref doc) = tx.did_document {
                if doc.is_empty() {
                    did.remove_field(7, 26); // sfDIDDocument
                } else {
                    did.set_field_raw_pub(7, 26, doc);
                }
            }
            if let Some(ref data) = tx.did_data {
                if data.is_empty() {
                    did.remove_field(7, 27); // sfData
                } else {
                    did.set_field_raw_pub(7, 27, data);
                }
            }

            view.update(Arc::new(did));
        } else {
            // Reserve check — sender must afford one more owned object
            let sender_keylet_chk = keylet::account(&tx.account);
            if let Some(sender_sle) = view.peek(&sender_keylet_chk) {
                let balance = sender_sle.balance_xrp().unwrap_or(0);
                if let Err(ter) = check_reserve(balance, sender_sle.owner_count(), 1, view.fees()) {
                    return ter;
                }
            }

            let owner_node = owner_dir::dir_add(view, &tx.account, did_keylet.key.0);

            // Create new DID
            let mut data = Vec::with_capacity(128);
            crate::ledger::meta::write_field_header(&mut data, 1, 1);
            data.extend_from_slice(&0x0049u16.to_be_bytes()); // DID
            crate::ledger::meta::write_field_header(&mut data, 2, 2);
            data.extend_from_slice(&0u32.to_be_bytes()); // Flags
            crate::ledger::meta::write_field_header(&mut data, 3, 4);
            data.extend_from_slice(&owner_node.to_be_bytes());
            // Account
            crate::ledger::meta::write_field_header(&mut data, 8, 1);
            crate::ledger::meta::encode_vl_length(&mut data, 20);
            data.extend_from_slice(&tx.account);
            // Optional fields
            if let Some(ref uri) = tx.uri {
                if !uri.is_empty() {
                    crate::ledger::meta::write_field_header(&mut data, 7, 5);
                    crate::ledger::meta::encode_vl_length(&mut data, uri.len());
                    data.extend_from_slice(uri);
                }
            }
            if let Some(ref doc) = tx.did_document {
                if !doc.is_empty() {
                    crate::ledger::meta::write_field_header(&mut data, 7, 26);
                    crate::ledger::meta::encode_vl_length(&mut data, doc.len());
                    data.extend_from_slice(doc);
                }
            }
            if let Some(ref d) = tx.did_data {
                if !d.is_empty() {
                    crate::ledger::meta::write_field_header(&mut data, 7, 27);
                    crate::ledger::meta::encode_vl_length(&mut data, d.len());
                    data.extend_from_slice(d);
                }
            }

            view.insert(Arc::new(SLE::new(did_keylet.key, LedgerEntryType::DID, data)));

            // Increment owner count
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

pub struct DIDDeleteHandler;

impl TxHandler for DIDDeleteHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let did_keylet = keylet::did(&tx.account);
        if !view.exists(&did_keylet) {
            return TER::ClaimedCost(TecCode::NoEntry);
        }
        owner_dir::dir_remove(view, &tx.account, &did_keylet.key.0);
        view.erase(&did_keylet.key);

        let sender_keylet = keylet::account(&tx.account);
        if let Some(sender_sle) = view.peek(&sender_keylet) {
            let mut s = (*sender_sle).clone();
            s.set_owner_count(s.owner_count().saturating_sub(1));
            view.update(Arc::new(s));
        }

        TER::Success
    }
}
