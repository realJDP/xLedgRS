use crate::transaction::ParsedTx;
use crate::ledger::views::ApplyView;
use super::{TER, TxHandler};

pub struct LoanBrokerSetHandler;

impl TxHandler for LoanBrokerSetHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

pub struct LoanBrokerDeleteHandler;

impl TxHandler for LoanBrokerDeleteHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

pub struct LoanSetHandler;

impl TxHandler for LoanSetHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

pub struct LoanDeleteHandler;

impl TxHandler for LoanDeleteHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

pub struct LoanManageHandler;

impl TxHandler for LoanManageHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

pub struct LoanPayHandler;

impl TxHandler for LoanPayHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

/// Single stub for LoanBrokerCover / LoanBrokerCoverCancel / LoanBrokerCoverForceClose (76-78).
pub struct LoanCoverHandler;

impl TxHandler for LoanCoverHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}
