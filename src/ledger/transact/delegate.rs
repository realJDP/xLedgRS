//! xLedgRS purpose: Delegate legacy transactor for XRPL transaction apply.
use super::{legacy_path_not_supported, TxHandler, TER};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;

pub struct DelegateSetHandler;

impl TxHandler for DelegateSetHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}
