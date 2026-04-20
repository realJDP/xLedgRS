//! TrustSet — IMPLEMENTED

use super::ApplyResult;
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::amount::Amount;
use crate::transaction::ParsedTx;

pub(crate) fn apply_trustset(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let limit = match &tx.limit_amount {
        Some(Amount::Iou {
            value,
            currency,
            issuer,
        }) => (value.clone(), currency.clone(), *issuer),
        _ => return ApplyResult::ClaimedCost("temBAD_LIMIT"),
    };
    let (limit_value, currency, counterparty) = limit;

    let key = crate::ledger::trustline::shamap_key(&tx.account, &counterparty, &currency);

    // Check typed map AND NuDB for existing trust line (hydration gap).
    let had_trustline = state.get_trustline(&key).is_some() || state.get_raw_owned(&key).is_some();
    let mut tl = if let Some(existing) = state.get_trustline(&key) {
        existing.clone()
    } else if let Some(raw) = state.get_raw_owned(&key) {
        if let Some(decoded) = crate::ledger::RippleState::decode_from_sle(&raw) {
            state.hydrate_trustline(decoded.clone());
            decoded
        } else {
            crate::ledger::RippleState::new(&tx.account, &counterparty, currency)
        }
    } else {
        // No existing trust line. If limit is zero, this is redundant.
        if limit_value.is_zero() {
            return ApplyResult::ClaimedCost("tecNO_LINE_REDUNDANT");
        }
        crate::ledger::RippleState::new(&tx.account, &counterparty, currency)
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
            // Reserve check: account must afford the new owner object.
            // rippled returns tecNO_LINE_INSUF_RESERVE if insufficient.
            let fees = crate::ledger::fees::Fees::default();
            let required =
                fees.reserve_base + ((new_sender.owner_count as u64 + 1) * fees.reserve_inc);
            if new_sender.balance < required {
                return ApplyResult::ClaimedCost("tecNO_LINE_INSUF_RESERVE");
            }
            // New trust line — add to BOTH accounts' owner directories
            // (rippled RippleStateHelpers.cpp:192,198)
            let sender_owner_node = directory::dir_add(state, &tx.account, key.0);
            let counterparty_owner_node = directory::dir_add(state, &counterparty, key.0);
            if tx.account == tl.low_account {
                tl.low_node = sender_owner_node;
                tl.high_node = counterparty_owner_node;
            } else {
                tl.low_node = counterparty_owner_node;
                tl.high_node = sender_owner_node;
            }
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
