use crate::transaction::ParsedTx;
use crate::ledger::views::ApplyView;
use super::{TER, TxHandler};

pub struct MPTokenIssuanceCreateHandler;

impl TxHandler for MPTokenIssuanceCreateHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

pub struct MPTokenIssuanceDestroyHandler;

impl TxHandler for MPTokenIssuanceDestroyHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

pub struct MPTokenIssuanceSetHandler;

impl TxHandler for MPTokenIssuanceSetHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

pub struct MPTokenAuthorizeHandler;

impl TxHandler for MPTokenAuthorizeHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}
