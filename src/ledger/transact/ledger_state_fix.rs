use super::{legacy_path_not_supported, TxHandler, TER};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;

pub struct LedgerStateFixHandler;

impl TxHandler for LedgerStateFixHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}
