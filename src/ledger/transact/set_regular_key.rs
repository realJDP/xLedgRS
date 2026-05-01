//! xLedgRS purpose: Set Regular Key legacy transactor for XRPL transaction apply.
use super::{TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use std::sync::Arc;

pub struct SetRegularKeyHandler;

impl TxHandler for SetRegularKeyHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let sender_keylet = keylet::account(&tx.account);
        let sender_sle = match view.peek(&sender_keylet) {
            Some(s) => s,
            None => return TER::LocalFail("terNO_ACCOUNT"),
        };

        let mut sender = (*sender_sle).clone();

        match tx.regular_key {
            Some(key) => {
                // Set regular key -- sfRegularKey (type=8, field=8)
                sender.set_field_account(8, 8, &key);
            }
            None => {
                // Clear regular key
                sender.remove_field(8, 8);
            }
        }

        view.update(Arc::new(sender));
        TER::Success
    }
}
