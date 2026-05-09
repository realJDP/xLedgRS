use super::{legacy_path_not_supported, TxHandler, TER};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;

pub struct AMMCreateHandler;

impl TxHandler for AMMCreateHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct AMMDepositHandler;

impl TxHandler for AMMDepositHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct AMMWithdrawHandler;

impl TxHandler for AMMWithdrawHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct AMMVoteHandler;

impl TxHandler for AMMVoteHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct AMMBidHandler;

impl TxHandler for AMMBidHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct AMMDeleteHandler;

impl TxHandler for AMMDeleteHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct AMMClawbackHandler;

impl TxHandler for AMMClawbackHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}
