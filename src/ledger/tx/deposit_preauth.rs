//! DepositPreauth — IMPLEMENTED

use super::ApplyResult;
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

/// Apply DepositPreauth: authorize an account to send deposits.
pub(crate) fn apply_deposit_preauth(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    // sfAuthorize (AccountID field 5), NOT sfDestination
    let authorized = match tx.authorize {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = crate::ledger::deposit_preauth::shamap_key(&tx.account, &authorized);

    // If preauth already exists, this is a no-op
    if state.has_deposit_preauth(&key) {
        return ApplyResult::Success;
    }

    let owner_node = directory::dir_add(state, &tx.account, key.0);
    let dp = crate::ledger::DepositPreauth {
        account: tx.account,
        authorized,
        owner_node,
        previous_txn_id: [0u8; 32],
        previous_txn_lgrseq: 0,
        raw_sle: None,
    };
    state.insert_deposit_preauth(dp);
    new_sender.owner_count += 1;

    ApplyResult::Success
}
