//! TrustSet — IMPLEMENTED

use crate::ledger::LedgerState;
use crate::ledger::directory;
use crate::transaction::amount::Amount;
use crate::transaction::ParsedTx;
use super::ApplyResult;

pub(crate) fn apply_trustset(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let limit = match &tx.limit_amount {
        Some(Amount::Iou { value, currency, issuer }) => (value.clone(), currency.clone(), *issuer),
        _ => return ApplyResult::ClaimedCost("temBAD_LIMIT"),
    };
    let (limit_value, currency, counterparty) = limit;

    let key = crate::ledger::trustline::shamap_key(&tx.account, &counterparty, &currency);

    let had_trustline = state.get_trustline(&key).is_some();
    let mut tl = match state.get_trustline(&key) {
        Some(existing) => existing.clone(),
        None => crate::ledger::RippleState::new(&tx.account, &counterparty, currency),
    };

    // Set the limit for the sender's side
    tl.set_limit_for(&tx.account, limit_value);

    if tl.is_empty() && had_trustline {
        // Delete the trust line if both limits are zero and balance is zero
        // Remove from both accounts' owner directories (rippled RippleStateHelpers.cpp:283,290)
        directory::dir_remove(state, &tx.account, &key.0);
        directory::dir_remove(state, &counterparty, &key.0);
        state.remove_trustline(&key);
        // Decrement owner count on both accounts
        new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
        if let Some(peer) = state.get_account(&counterparty) {
            let mut peer = peer.clone();
            peer.owner_count = peer.owner_count.saturating_sub(1);
            state.insert_account(peer);
        }
    } else {
        if !had_trustline {
            // New trust line — add to BOTH accounts' owner directories
            // (rippled RippleStateHelpers.cpp:192,198)
            directory::dir_add(state, &tx.account, key.0);
            directory::dir_add(state, &counterparty, key.0);
            // New trust line — increment owner counts
            new_sender.owner_count += 1;
            if let Some(peer) = state.get_account(&counterparty) {
                let mut peer = peer.clone();
                peer.owner_count += 1;
                state.insert_account(peer);
            }
        }
        state.insert_trustline(tl);
    }

    ApplyResult::Success
}
