use crate::transaction::ParsedTx;
use crate::ledger::views::ApplyView;
use super::{TER, TxHandler};

/// Single stub handler for all XChain bridge transaction types (41-48).
pub struct XChainHandler;

impl TxHandler for XChainHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}
