//! xLedgRS purpose: Offer Create legacy transactor for XRPL transaction apply.
use super::{legacy_path_not_supported, TxHandler, TER};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;

/// The authoritative OfferCreate implementation lives in `ledger::tx::offer`.
/// The legacy view-stack transactor must fail loudly instead of pretending
/// the replay metadata made this path complete.
pub struct OfferCreateHandler;

impl TxHandler for OfferCreateHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}
