//! xLedgRS purpose: Nftoken legacy transactor for XRPL transaction apply.
use super::{check_reserve, legacy_path_not_supported, owner_dir, TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::sle::{LedgerEntryType, SLE};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use std::sync::Arc;

pub struct NFTokenMintHandler;

impl TxHandler for NFTokenMintHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        // The legacy view-stack transactor never implemented NFToken page
        // management; the maintained implementation lives in `ledger::tx`.
        legacy_path_not_supported()
    }
}

pub struct NFTokenBurnHandler;

impl TxHandler for NFTokenBurnHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let _ = (tx, view);
        legacy_path_not_supported()
    }
}

pub struct NFTokenCreateOfferHandler;

impl TxHandler for NFTokenCreateOfferHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        if tx.nftoken_id.is_none() {
            return Err(TER::Malformed("temMALFORMED"));
        }
        Ok(())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let nftoken_id = tx.nftoken_id.unwrap();

        let amount_bytes = match &tx.amount {
            Some(amt) => amt.to_bytes(),
            None => {
                // XRP amount of 0 (sell offer with no price)
                let wire = 0u64 | 0x4000_0000_0000_0000;
                wire.to_be_bytes().to_vec()
            }
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

        let offer_keylet = keylet::nft_offer(&tx.account, tx.sequence);
        let owner_node = owner_dir::dir_add(view, &tx.account, offer_keylet.key.0);

        // Build NFTokenOffer SLE
        let mut data = Vec::with_capacity(128);
        crate::ledger::meta::write_field_header(&mut data, 1, 1);
        data.extend_from_slice(&0x0037u16.to_be_bytes()); // NFTokenOffer
        crate::ledger::meta::write_field_header(&mut data, 2, 2);
        data.extend_from_slice(&tx.flags.to_be_bytes()); // Flags
        crate::ledger::meta::write_field_header(&mut data, 2, 4);
        data.extend_from_slice(&tx.sequence.to_be_bytes()); // Sequence
        crate::ledger::meta::write_field_header(&mut data, 3, 4);
        data.extend_from_slice(&owner_node.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 3, 12);
        data.extend_from_slice(&0u64.to_be_bytes()); // NFTokenOfferNode
                                                     // NFTokenID (Hash256, type=5, field=10)
        crate::ledger::meta::write_field_header(&mut data, 5, 10);
        data.extend_from_slice(&nftoken_id);
        // Amount
        crate::ledger::meta::write_field_header(&mut data, 6, 1);
        data.extend_from_slice(&amount_bytes);
        // Owner (type=8, field=2)
        crate::ledger::meta::write_field_header(&mut data, 8, 2);
        crate::ledger::meta::encode_vl_length(&mut data, 20);
        data.extend_from_slice(&tx.account);
        // Destination (optional)
        if let Some(dest) = tx.destination {
            crate::ledger::meta::write_field_header(&mut data, 8, 3);
            crate::ledger::meta::encode_vl_length(&mut data, 20);
            data.extend_from_slice(&dest);
        }

        view.insert(Arc::new(SLE::new(
            offer_keylet.key,
            LedgerEntryType::NFTokenOffer,
            data,
        )));

        // Increment owner count
        let mut s = (*sender_sle).clone();
        s.set_owner_count(s.owner_count() + 1);
        view.update(Arc::new(s));

        TER::Success
    }
}
