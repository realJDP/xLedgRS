use super::{legacy_path_not_supported, TxHandler, TER};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;

/// The legacy view-stack transactor does not implement XChain semantics.
pub struct XChainHandler;

impl TxHandler for XChainHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}
