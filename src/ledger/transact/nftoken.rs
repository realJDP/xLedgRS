use super::{legacy_path_not_supported, TxHandler, TER};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;

pub struct NFTokenMintHandler;

impl TxHandler for NFTokenMintHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        // The legacy view-stack transactor never implemented NFToken page
        // management; the maintained implementation lives in `ledger::tx`.
        legacy_path_not_supported()
    }
}

pub struct NFTokenBurnHandler;

impl TxHandler for NFTokenBurnHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}

pub struct NFTokenCreateOfferHandler;

impl TxHandler for NFTokenCreateOfferHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        if tx.nftoken_id.is_none() {
            return Err(TER::Malformed("temMALFORMED"));
        }
        Err(legacy_path_not_supported())
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        legacy_path_not_supported()
    }
}
