use std::sync::Arc;
use crate::ledger::keylet;
use crate::ledger::sle::{SLE, LedgerEntryType};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use crate::ledger::views::ReadView;
use super::{TER, TxHandler, check_reserve};

pub struct NFTokenMintHandler;

impl TxHandler for NFTokenMintHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        // NFTokenMint involves NFT page management which is complex.
        // For now, stub -- metadata patches handle the state changes.
        TER::Success
    }
}

pub struct NFTokenBurnHandler;

impl TxHandler for NFTokenBurnHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        // NFTokenBurn involves NFT page management which requires
        // walking NFTokenPage SLEs. For now, stub -- metadata patches
        // handle the page updates during follower replay.
        // Decrement owner count for the burner
        let sender_keylet = keylet::account(&tx.account);
        if let Some(sender_sle) = view.peek(&sender_keylet) {
            let mut s = (*sender_sle).clone();
            // Increment burned count (sfBurnedNFTokens type=2, field=44)
            let burned = s.get_field_u32(2, 44).unwrap_or(0);
            s.set_field_u32(2, 44, burned + 1);
            view.update(Arc::new(s));
        }
        TER::Success
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

        let offer_keylet = keylet::nft_offer(&tx.account, tx.sequence);

        // Build NFTokenOffer SLE
        let mut data = Vec::with_capacity(128);
        crate::ledger::meta::write_field_header(&mut data, 1, 1);
        data.extend_from_slice(&0x0037u16.to_be_bytes()); // NFTokenOffer
        crate::ledger::meta::write_field_header(&mut data, 2, 2);
        data.extend_from_slice(&tx.flags.to_be_bytes()); // Flags
        crate::ledger::meta::write_field_header(&mut data, 2, 4);
        data.extend_from_slice(&tx.sequence.to_be_bytes()); // Sequence
        crate::ledger::meta::write_field_header(&mut data, 3, 4);
        data.extend_from_slice(&0u64.to_be_bytes()); // OwnerNode
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
