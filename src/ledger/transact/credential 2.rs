use crate::transaction::ParsedTx;
use crate::ledger::views::ApplyView;
use super::{TER, TxHandler};

pub struct CredentialCreateHandler;

impl TxHandler for CredentialCreateHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

pub struct CredentialAcceptHandler;

impl TxHandler for CredentialAcceptHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}

pub struct CredentialDeleteHandler;

impl TxHandler for CredentialDeleteHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}
