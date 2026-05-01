//! xLedgRS purpose: Account Delete legacy transactor for XRPL transaction apply.
use super::{TecCode, TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use std::sync::Arc;

pub struct AccountDeleteHandler;

impl TxHandler for AccountDeleteHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        if tx.destination.is_none() {
            return Err(TER::Malformed("temDST_NEEDED"));
        }
        Ok(())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let dest_id = tx.destination.unwrap();

        // Load sender
        let sender_keylet = keylet::account(&tx.account);
        let sender_sle = match view.peek(&sender_keylet) {
            Some(s) => s,
            None => return TER::LocalFail("terNO_ACCOUNT"),
        };

        // Check owner count is 0 (no owned objects)
        if sender_sle.owner_count() > 0 {
            return TER::ClaimedCost(TecCode::Generic("tecHAS_OBLIGATIONS"));
        }

        let balance = sender_sle.balance_xrp().unwrap_or(0);

        // Credit destination
        let dest_keylet = keylet::account(&dest_id);
        match view.peek(&dest_keylet) {
            Some(dest_sle) => {
                let dest_balance = dest_sle.balance_xrp().unwrap_or(0);
                let mut dest = (*dest_sle).clone();
                dest.set_balance_xrp(dest_balance + balance);
                view.update(Arc::new(dest));
            }
            None => return TER::ClaimedCost(TecCode::NoDst),
        }

        // Delete sender account
        view.erase(&sender_keylet.key);

        TER::Success
    }
}
