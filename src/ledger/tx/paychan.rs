//! xLedgRS purpose: Paychan transaction engine logic for ledger replay.
//! PaymentChannel — IMPLEMENTED

use super::ApplyResult;
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

/// Apply PaymentChannelCreate: lock XRP in a channel.
pub(crate) fn apply_paychan_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let sequence = super::sequence_proxy(tx);
    let amount = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    let destination = match tx.destination {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };
    let settle_delay = match tx.settle_delay {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temBAD_EXPIRATION"),
    };
    let public_key = match &tx.public_key {
        Some(pk) => pk.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    new_sender.balance = new_sender.balance.saturating_sub(amount);
    new_sender.owner_count += 1;

    let paychan_key = crate::ledger::paychan::shamap_key(&tx.account, &destination, sequence);
    let owner_node = directory::dir_add(state, &tx.account, paychan_key.0);
    // Also add to destination's directory (rippled PaymentChannelCreate.cpp:161)
    let destination_node = if destination != tx.account {
        directory::dir_add(state, &destination, paychan_key.0)
    } else {
        0
    };
    let paychan = crate::ledger::PayChannel {
        account: tx.account,
        destination,
        amount,
        balance: 0,
        settle_delay,
        public_key,
        sequence,
        cancel_after: tx.cancel_after.unwrap_or(0),
        expiration: 0,
        owner_node,
        destination_node,
        source_tag: None,
        destination_tag: None,
        raw_sle: None,
    };
    state.insert_paychan(paychan);

    ApplyResult::Success
}

/// Apply PaymentChannelFund: add XRP to an existing channel.
pub(crate) fn apply_paychan_fund(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let channel_hash = match tx.channel {
        Some(h) => h,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let add_amount = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };

    let key = crate::ledger::Key(channel_hash);
    let mut pc = match state.get_paychan(&key) {
        Some(p) => p.clone(),
        None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // Only the channel creator can fund it
    if pc.account != tx.account {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    new_sender.balance = new_sender.balance.saturating_sub(add_amount);
    pc.amount = pc.amount.saturating_add(add_amount);

    // Optionally update expiration
    if let Some(exp) = tx.expiration {
        pc.expiration = exp;
    }

    state.insert_paychan(pc);
    ApplyResult::Success
}

/// Apply PaymentChannelClaim: claim XRP from a channel.
pub(crate) fn apply_paychan_claim(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    let channel_hash = match tx.channel {
        Some(h) => h,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = crate::ledger::Key(channel_hash);
    let mut pc = match state.get_paychan(&key) {
        Some(p) => p.clone(),
        None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // If a claim amount + signature are provided, verify and advance balance
    if let (Some(claimed_drops), Some(sig)) = (tx.amount_drops, &tx.paychan_sig) {
        if !pc.verify_claim(claimed_drops, sig) {
            return ApplyResult::ClaimedCost("temBAD_SIGNATURE");
        }
        if claimed_drops > pc.amount {
            return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
        }

        let delta = claimed_drops.saturating_sub(pc.balance);
        pc.balance = claimed_drops;

        // Credit the destination
        if let Some(dest) = state.get_account(&pc.destination) {
            let mut dest = dest.clone();
            dest.balance = dest.balance.saturating_add(delta);
            state.insert_account(dest);
        } else {
            state.insert_account(crate::ledger::AccountRoot {
                account_id: pc.destination,
                balance: delta,
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
    }

    // Check for channel close (tfClose flag = 0x00010000)
    let tf_close = tx.flags & 0x00010000 != 0;
    if tf_close {
        // Set expiration to close_time + settle_delay
        pc.expiration = (close_time as u32).saturating_add(pc.settle_delay);
    }

    // Check if the channel can be deleted (expired or fully claimed)
    let can_delete =
        (pc.expiration > 0 && (close_time as u32) >= pc.expiration) || pc.balance >= pc.amount;

    if can_delete {
        // Remove from owner directory (rippled PaymentChannelHelpers.cpp:21)
        directory::dir_remove(state, &pc.account, &key.0);
        // Remove from destination directory (rippled PaymentChannelHelpers.cpp:34)
        if pc.destination != pc.account {
            directory::dir_remove(state, &pc.destination, &key.0);
        }

        // Refund any unclaimed balance to the creator
        let refund = pc.amount.saturating_sub(pc.balance);
        if refund > 0 {
            if let Some(creator) = state.get_account(&pc.account) {
                let mut creator = creator.clone();
                creator.balance = creator.balance.saturating_add(refund);
                creator.owner_count = creator.owner_count.saturating_sub(1);
                state.insert_account(creator);
            }
        } else {
            // Just decrement owner count
            if let Some(creator) = state.get_account(&pc.account) {
                let mut creator = creator.clone();
                creator.owner_count = creator.owner_count.saturating_sub(1);
                state.insert_account(creator);
            }
        }
        state.remove_paychan(&key);
    } else {
        state.insert_paychan(pc);
    }

    ApplyResult::Success
}
