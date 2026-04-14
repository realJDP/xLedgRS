use crate::transaction::ParsedTx;
use crate::ledger::views::ApplyView;
use super::{TER, TxHandler};

pub struct ClawbackHandler;

impl TxHandler for ClawbackHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Success
    }
}
