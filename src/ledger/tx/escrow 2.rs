//! Escrow — IMPLEMENTED
//!
//! Supports XRP escrows natively. TokenEscrow amendment (IOU/MPT escrows)
//! is handled by accepting the tx and letting metadata patches apply the
//! trust line / MPT balance changes. The sender-side XRP balance deduction
//! only applies when the amount is XRP; IOU/MPT locking is handled by the
//! network's metadata patches.

use crate::ledger::LedgerState;
use crate::ledger::directory;
use crate::transaction::{ParsedTx, Amount};
use super::ApplyResult;

/// Apply EscrowCreate: lock funds in a time-locked escrow object.
/// Supports XRP (native) and IOU/MPT (via TokenEscrow amendment — metadata patches).
pub(crate) fn apply_escrow_create(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    // TokenEscrow: Amount can be XRP, IOU, or MPT.
    // For XRP: deduct from sender balance here.
    // For IOU/MPT: trust line/MPT balance changes come from metadata patches.
    let xrp_amount: Option<u64> = match (&tx.amount, tx.amount_drops) {
        (Some(Amount::Xrp(d)), _) if *d > 0 => Some(*d),
        (_, Some(d)) if d > 0 => Some(d),
        (Some(Amount::Iou { .. }), _) | (Some(Amount::Mpt { .. }), _) => None,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    let destination = match tx.destination {
        Some(d) => d,
        None    => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };

    // Deduct the escrowed XRP from sender (IOU/MPT handled by metadata patches)
    if let Some(drops) = xrp_amount {
        new_sender.balance = new_sender.balance.saturating_sub(drops);
    }
    new_sender.owner_count += 1;

    let escrow_key = crate::ledger::escrow::shamap_key(&tx.account, tx.sequence);
    let owner_node = directory::dir_add(state, &tx.account, escrow_key.0);
    // Also add to destination's directory (rippled EscrowCreate.cpp:462)
    let destination_node = if destination != tx.account {
        directory::dir_add(state, &destination, escrow_key.0)
    } else {
        0
    };
    let escrow = crate::ledger::Escrow {
        account:      tx.account,
        destination,
        amount: xrp_amount.unwrap_or(0),
        sequence:     tx.sequence,
        finish_after: tx.finish_after.unwrap_or(0),
        cancel_after: tx.cancel_after.unwrap_or(0),
        condition:        None,
        owner_node,
        destination_node,
        source_tag:       None,
        destination_tag:  None,
        raw_sle: None,
    };
    state.insert_escrow(escrow);

    ApplyResult::Success
}

/// Apply EscrowFinish: release escrowed funds to the destination.
/// XRP credit is handled here; IOU/MPT credit comes from metadata patches.
pub(crate) fn apply_escrow_finish(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    let escrow_seq = match tx.offer_sequence {
        Some(s) => s,
        None    => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let owner = tx.owner.unwrap_or(tx.account);

    let key = crate::ledger::escrow::shamap_key(&owner, escrow_seq);
    let escrow = match state.get_escrow(&key) {
        Some(e) => e.clone(),
        None    => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // Check finish_after time condition
    if escrow.finish_after > 0 && (close_time as u32) < escrow.finish_after {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    // Credit destination with XRP (IOU/MPT handled by metadata patches)
    if escrow.amount > 0 {
        if let Some(dest) = state.get_account(&escrow.destination) {
            let mut dest = dest.clone();
            dest.balance = dest.balance.saturating_add(escrow.amount);
            state.insert_account(dest);
        } else {
            // Create destination account if it doesn't exist
            state.insert_account(crate::ledger::AccountRoot {
                account_id: escrow.destination, balance: escrow.amount,
                sequence: 1, owner_count: 0, flags: 0, regular_key: None, minted_nftokens: 0, burned_nftokens: 0,
                transfer_rate: 0, domain: Vec::new(), tick_size: 0, ticket_count: 0,
                previous_txn_id: [0u8; 32], previous_txn_lgr_seq: 0, raw_sle: None,
            });
        }
    }

    // Remove escrow from owner directory
    directory::dir_remove(state, &escrow.account, &key.0);
    // Remove from destination directory if present (rippled EscrowFinish.cpp:317)
    if escrow.destination != escrow.account {
        directory::dir_remove(state, &escrow.destination, &key.0);
    }

    // Remove escrow and decrement owner's owner_count
    state.remove_escrow(&key);
    if let Some(owner_acct) = state.get_account(&escrow.account) {
        let mut owner_acct = owner_acct.clone();
        owner_acct.owner_count = owner_acct.owner_count.saturating_sub(1);
        state.insert_account(owner_acct);
    }

    ApplyResult::Success
}

/// Apply EscrowCancel: return escrowed funds to the sender.
/// XRP refund is handled here; IOU/MPT refund comes from metadata patches.
pub(crate) fn apply_escrow_cancel(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    let escrow_seq = match tx.offer_sequence {
        Some(s) => s,
        None    => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let owner = tx.owner.unwrap_or(tx.account);

    let key = crate::ledger::escrow::shamap_key(&owner, escrow_seq);
    let escrow = match state.get_escrow(&key) {
        Some(e) => e.clone(),
        None    => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // Check cancel_after time condition
    if escrow.cancel_after > 0 && (close_time as u32) < escrow.cancel_after {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    // Remove escrow from owner directory
    directory::dir_remove(state, &escrow.account, &key.0);
    // Remove from destination directory if present (rippled EscrowCancel.cpp:143)
    if escrow.destination != escrow.account {
        directory::dir_remove(state, &escrow.destination, &key.0);
    }

    // Refund the escrow creator (XRP only; IOU/MPT handled by metadata patches)
    if let Some(creator) = state.get_account(&escrow.account) {
        let mut creator = creator.clone();
        if escrow.amount > 0 {
            creator.balance = creator.balance.saturating_add(escrow.amount);
        }
        creator.owner_count = creator.owner_count.saturating_sub(1);
        state.insert_account(creator);
    }

    state.remove_escrow(&key);

    ApplyResult::Success
}
