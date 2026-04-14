use crate::transaction::ParsedTx;
use crate::ledger::views::ApplyView;
use super::{TER, TxHandler, legacy_path_not_supported};

/// SetFee pseudo-transaction (type 100).
pub struct SetFeeHandler;

impl TxHandler for SetFeeHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

/// EnableAmendment pseudo-transaction (type 101).
pub struct EnableAmendmentHandler;

impl TxHandler for EnableAmendmentHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

/// UNLModify pseudo-transaction (type 102).
pub struct UNLModifyHandler;

impl TxHandler for UNLModifyHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}
