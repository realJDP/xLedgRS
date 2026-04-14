use crate::transaction::ParsedTx;
use crate::ledger::views::ApplyView;
use super::{TER, TxHandler, legacy_path_not_supported};

/// The authoritative OfferCreate implementation lives in `ledger::tx::offer`.
/// The legacy view-stack transactor must fail loudly instead of pretending
/// the replay metadata made this path complete.
pub struct OfferCreateHandler;

impl TxHandler for OfferCreateHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}
