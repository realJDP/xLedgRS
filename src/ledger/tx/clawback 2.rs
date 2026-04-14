//! Clawback — IMPLEMENTED

use crate::ledger::LedgerState;
use crate::ledger::directory;
use crate::transaction::amount::Amount;
use crate::transaction::ParsedTx;
use super::ApplyResult;

/// Apply Clawback: issuer reclaims IOU tokens from a holder via trust line.
///
/// rippled: Clawback.cpp — for IOU clawback, the issuer (tx.account) claws back
/// tokens from the holder (encoded in the Amount field's issuer).  The actual
/// transfer is `rippleCredit(holder, issuer, min(spendable, clawAmount))`.
///
/// We implement the IOU trust-line clawback case.  MPT clawback is not yet
/// supported (we don't track MPToken state).
pub(crate) fn apply_clawback(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
) -> ApplyResult {
    // The Amount field encodes the clawback: the "issuer" in the Amount is
    // actually the holder account, and tx.account is the real issuer.
    let (claw_value, currency, holder) = match &tx.amount {
        Some(Amount::Iou { value, currency, issuer }) => (value.clone(), currency.clone(), *issuer),
        _ => {
            // MPT clawback or malformed — fee+seq only for now
            return ApplyResult::Success;
        }
    };

    let issuer = tx.account;

    // Look up trust line between issuer and holder
    let key = crate::ledger::trustline::shamap_key(&issuer, &holder, &currency);
    let tl = match state.get_trustline(&key) {
        Some(t) => t.clone(),
        None    => return ApplyResult::ClaimedCost("tecNO_LINE"),
    };

    let mut tl = tl;

    // Transfer tokens from holder back to issuer (credit issuer, debit holder).
    tl.transfer(&holder, &claw_value);

    // If the trust line is now empty (zero balance, zero limits), remove it
    if tl.is_empty() {
        // Remove from both accounts' owner directories (rippled RippleStateHelpers.cpp:283,290)
        directory::dir_remove(state, &holder, &key.0);
        directory::dir_remove(state, &issuer, &key.0);
        state.remove_trustline(&key);
        // Decrement owner counts for both sides
        if let Some(h) = state.get_account(&holder) {
            let mut h = h.clone();
            h.owner_count = h.owner_count.saturating_sub(1);
            state.insert_account(h);
        }
        if let Some(i) = state.get_account(&issuer) {
            let mut i = i.clone();
            i.owner_count = i.owner_count.saturating_sub(1);
            state.insert_account(i);
        }
    } else {
        state.insert_trustline(tl);
    }

    ApplyResult::Success
}
