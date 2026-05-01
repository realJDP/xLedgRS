//! xLedgRS purpose: Offer Cancel legacy transactor for XRPL transaction apply.
use super::{TecCode, TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use std::sync::Arc;

pub struct OfferCancelHandler;

impl TxHandler for OfferCancelHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        if tx.offer_sequence.is_none() {
            return Err(TER::Malformed("temBAD_OFFER"));
        }
        Ok(())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let offer_seq = tx.offer_sequence.unwrap();
        let offer_keylet = keylet::offer(&tx.account, offer_seq);

        if !view.exists(&offer_keylet) {
            return TER::ClaimedCost(TecCode::NoEntry);
        }

        // Remove offer
        view.erase(&offer_keylet.key);

        // Decrement owner count
        let sender_keylet = keylet::account(&tx.account);
        if let Some(sender_sle) = view.peek(&sender_keylet) {
            let mut sender = (*sender_sle).clone();
            let oc = sender.owner_count();
            sender.set_owner_count(oc.saturating_sub(1));
            view.update(Arc::new(sender));
        }

        TER::Success
    }
}
