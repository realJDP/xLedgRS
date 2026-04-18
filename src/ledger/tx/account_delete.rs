//! AccountDelete — IMPLEMENTED

use super::ApplyResult;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

/// Apply AccountDelete: remove an account and transfer remaining XRP to destination.
///
/// Requirements: `owner_count` must be 0 (no owned objects), and the account
/// must have existed for at least 256 ledgers. This implementation skips the
/// age check.
pub(crate) fn apply_account_delete(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let destination = match tx.destination {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };

    // Can't delete if account owns objects
    if new_sender.owner_count > 0 {
        return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
    }

    // Transfer remaining balance (after fee) to destination
    let transfer = new_sender.balance;
    new_sender.balance = 0;

    if let Some(dest) = state.get_account(&destination) {
        let mut dest = dest.clone();
        dest.balance = dest.balance.saturating_add(transfer);
        state.insert_account(dest);
    } else {
        state.insert_account(crate::ledger::AccountRoot {
            account_id: destination,
            balance: transfer,
            sequence: 1,
            owner_count: 0,
            flags: 0,
            regular_key: None,
            minted_nftokens: 0,
            burned_nftokens: 0,
            transfer_rate: 0,
            domain: Vec::new(),
            tick_size: 0,
            ticket_count: 0,
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        });
    }

    ApplyResult::Success
}
