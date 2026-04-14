use crate::transaction::ParsedTx;
use crate::ledger::views::ApplyView;
use super::{TER, TxHandler, legacy_path_not_supported};

pub struct NFTokenCancelOfferHandler;

impl TxHandler for NFTokenCancelOfferHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct NFTokenAcceptOfferHandler;

impl TxHandler for NFTokenAcceptOfferHandler {
    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}
