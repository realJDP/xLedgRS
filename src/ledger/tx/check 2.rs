//! Check — IMPLEMENTED

use crate::ledger::LedgerState;
use crate::ledger::directory;
use crate::transaction::ParsedTx;
use super::ApplyResult;

/// Apply CheckCreate: create a deferred payment (does NOT lock funds).
pub(crate) fn apply_check_create(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let amount = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    let destination = match tx.destination {
        Some(d) => d,
        None    => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };

    new_sender.owner_count += 1;

    let check_key = crate::ledger::check::shamap_key(&tx.account, tx.sequence);
    let owner_node = directory::dir_add(state, &tx.account, check_key.0);
    // Also add to destination's directory (rippled CheckCreate.cpp:190)
    let destination_node = if destination != tx.account {
        directory::dir_add(state, &destination, check_key.0)
    } else {
        0
    };
    let check = crate::ledger::Check {
        account:     tx.account,
        destination,
        send_max:    crate::transaction::Amount::Xrp(amount),
        sequence:    tx.sequence,
        expiration:  tx.expiration.unwrap_or(0),
        owner_node,
        destination_node,
        source_tag:       None,
        destination_tag:  None,
        raw_sle: None,
    };
    state.insert_check(check);

    ApplyResult::Success
}

/// Apply CheckCash: destination claims the check (debits creator at cash time).
pub(crate) fn apply_check_cash(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    let check_seq = match tx.offer_sequence {
        Some(s) => s,
        None    => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let check_owner = tx.owner.unwrap_or(tx.account);
    let key = crate::ledger::check::shamap_key(&check_owner, check_seq);
    let check = match state.get_check(&key) {
        Some(c) => c.clone(),
        None    => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // Only the destination can cash
    if tx.account != check.destination {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    // Check expiration
    if check.expiration > 0 && (close_time as u32) >= check.expiration {
        return ApplyResult::ClaimedCost("tecEXPIRED");
    }

    // Determine cash amount
    let cash_amount = if let Some(drops) = tx.amount_drops {
        // Exact amount mode
        let max_drops = match &check.send_max {
            crate::transaction::Amount::Xrp(d) => *d,
            _ => 0, // IOU checks not fully supported yet
        };
        if drops > max_drops {
            return ApplyResult::ClaimedCost("tecPATH_PARTIAL");
        }
        drops
    } else {
        // DeliverMin mode or full amount
        match &check.send_max {
            crate::transaction::Amount::Xrp(d) => *d,
            _ => 0, // IOU checks not fully supported yet
        }
    };

    // Verify creator has sufficient balance
    let creator = match state.get_account(&check.account) {
        Some(a) => a.clone(),
        None    => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    if creator.balance < cash_amount {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }

    // Debit creator
    let mut creator = creator;
    creator.balance = creator.balance.saturating_sub(cash_amount);
    creator.owner_count = creator.owner_count.saturating_sub(1);
    state.insert_account(creator);

    // Credit destination (tx.account)
    if let Some(dest) = state.get_account(&tx.account) {
        let mut dest = dest.clone();
        dest.balance = dest.balance.saturating_add(cash_amount);
        state.insert_account(dest);
    }

    // Remove from owner directory (rippled CheckCash.cpp:433)
    directory::dir_remove(state, &check.account, &key.0);
    // Remove from destination directory (rippled CheckCash.cpp:423)
    if check.destination != check.account {
        directory::dir_remove(state, &check.destination, &key.0);
    }

    state.remove_check(&key);
    ApplyResult::Success
}

/// Apply CheckCancel: remove a check without cashing it.
pub(crate) fn apply_check_cancel(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    let check_seq = match tx.offer_sequence {
        Some(s) => s,
        None    => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let check_owner = tx.owner.unwrap_or(tx.account);
    let key = crate::ledger::check::shamap_key(&check_owner, check_seq);
    let check = match state.get_check(&key) {
        Some(c) => c.clone(),
        None    => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // Creator or destination can cancel, OR anyone can cancel if expired
    let is_participant = tx.account == check.account || tx.account == check.destination;
    let is_expired = check.expiration > 0 && (close_time as u32) >= check.expiration;
    if !is_participant && !is_expired {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    // Remove from owner directory (rippled CheckCancel.cpp:77)
    directory::dir_remove(state, &check.account, &key.0);
    // Remove from destination directory (rippled CheckCancel.cpp:67)
    if check.destination != check.account {
        directory::dir_remove(state, &check.destination, &key.0);
    }

    // Decrement creator's owner_count
    if let Some(creator) = state.get_account(&check.account) {
        let mut creator = creator.clone();
        creator.owner_count = creator.owner_count.saturating_sub(1);
        state.insert_account(creator);
    }

    state.remove_check(&key);
    ApplyResult::Success
}
