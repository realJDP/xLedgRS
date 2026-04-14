use crate::transaction::ParsedTx;
use crate::ledger::views::ApplyView;
use super::{TER, TxHandler};

pub struct OracleSetHandler;

impl TxHandler for OracleSetHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

pub struct OracleDeleteHandler;

impl TxHandler for OracleDeleteHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}
