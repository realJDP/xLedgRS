//! xLedgRS purpose: Vault legacy transactor for XRPL transaction apply.
use super::{legacy_path_not_supported, TxHandler, TER};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;

pub struct VaultCreateHandler;

impl TxHandler for VaultCreateHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct VaultSetHandler;

impl TxHandler for VaultSetHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct VaultDeleteHandler;

impl TxHandler for VaultDeleteHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct VaultDepositHandler;

impl TxHandler for VaultDepositHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct VaultWithdrawHandler;

impl TxHandler for VaultWithdrawHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct VaultClawbackHandler;

impl TxHandler for VaultClawbackHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}
