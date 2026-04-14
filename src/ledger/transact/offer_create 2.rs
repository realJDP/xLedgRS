use crate::transaction::ParsedTx;
use crate::ledger::views::ApplyView;
use super::{TER, TxHandler};

/// Stub — order book crossing is complex; metadata patches handle state during replay.
pub struct OfferCreateHandler;

impl TxHandler for OfferCreateHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}
