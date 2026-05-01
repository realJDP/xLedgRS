//! xLedgRS purpose: Trust Set transaction engine logic for ledger replay.
//! TrustSet — IMPLEMENTED

use super::ApplyResult;
use super::{balance_before_fee, load_existing_account};
use crate::ledger::directory;
use crate::ledger::trustline::{
    LSF_HIGH_AUTH, LSF_HIGH_FREEZE, LSF_HIGH_NO_RIPPLE, LSF_HIGH_RESERVE, LSF_LOW_AUTH,
    LSF_LOW_FREEZE, LSF_LOW_NO_RIPPLE, LSF_LOW_RESERVE,
};
use crate::ledger::LedgerState;
use crate::transaction::amount::Amount;
use crate::transaction::ParsedTx;

const TF_SET_AUTH: u32 = 0x0001_0000;
const TF_SET_NO_RIPPLE: u32 = 0x0002_0000;
const TF_CLEAR_NO_RIPPLE: u32 = 0x0004_0000;
const TF_SET_FREEZE: u32 = 0x0010_0000;
const TF_CLEAR_FREEZE: u32 = 0x0020_0000;
const QUALITY_ONE: u32 = 1_000_000_000;

fn reserve_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        LSF_LOW_RESERVE
    } else if account == &tl.high_account {
        LSF_HIGH_RESERVE
    } else {
        panic!("account is not part of this trust line");
    }
}

fn auth_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        LSF_LOW_AUTH
    } else if account == &tl.high_account {
        LSF_HIGH_AUTH
    } else {
        panic!("account is not part of this trust line");
    }
}

fn no_ripple_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        LSF_LOW_NO_RIPPLE
    } else if account == &tl.high_account {
        LSF_HIGH_NO_RIPPLE
    } else {
        panic!("account is not part of this trust line");
    }
}

fn freeze_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        LSF_LOW_FREEZE
    } else if account == &tl.high_account {
        LSF_HIGH_FREEZE
    } else {
        panic!("account is not part of this trust line");
    }
}

fn set_owner_node_for(tl: &mut crate::ledger::RippleState, account: &[u8; 20], node: u64) {
    if account == &tl.low_account {
        tl.low_node = node;
    } else if account == &tl.high_account {
        tl.high_node = node;
    } else {
        panic!("account is not part of this trust line");
    }
}

fn normalize_quality(quality: u32) -> u32 {
    if quality == QUALITY_ONE {
        0
    } else {
        quality
    }
}

fn apply_sender_qualities(
    tl: &mut crate::ledger::RippleState,
    account: &[u8; 20],
    quality_in: Option<u32>,
    quality_out: Option<u32>,
) {
    if account == &tl.low_account {
        if let Some(quality) = quality_in {
            tl.low_quality_in = normalize_quality(quality);
        }
        if let Some(quality) = quality_out {
            tl.low_quality_out = normalize_quality(quality);
        }
    } else if account == &tl.high_account {
        if let Some(quality) = quality_in {
            tl.high_quality_in = normalize_quality(quality);
        }
        if let Some(quality) = quality_out {
            tl.high_quality_out = normalize_quality(quality);
        }
    } else {
        panic!("account is not part of this trust line");
    }
}

fn side_has_nondefault_limit_or_quality(
    tl: &crate::ledger::RippleState,
    account: &[u8; 20],
) -> bool {
    if account == &tl.low_account {
        !tl.low_limit.is_zero() || tl.low_quality_in != 0 || tl.low_quality_out != 0
    } else if account == &tl.high_account {
        !tl.high_limit.is_zero() || tl.high_quality_in != 0 || tl.high_quality_out != 0
    } else {
        panic!("account is not part of this trust line");
    }
}

fn apply_sender_trustline_flags(
    tl: &mut crate::ledger::RippleState,
    account: &[u8; 20],
    tx_flags: u32,
) -> Option<&'static str> {
    if (tx_flags & TF_SET_AUTH) != 0 {
        tl.flags |= auth_flag_for(tl, account);
    }

    let no_ripple = no_ripple_flag_for(tl, account);
    if (tx_flags & TF_SET_NO_RIPPLE) != 0 && (tx_flags & TF_CLEAR_NO_RIPPLE) == 0 {
        if tl.balance_for(account).mantissa < 0 {
            return Some("tecNO_PERMISSION");
        }
        tl.flags |= no_ripple;
    } else if (tx_flags & TF_CLEAR_NO_RIPPLE) != 0 && (tx_flags & TF_SET_NO_RIPPLE) == 0 {
        tl.flags &= !no_ripple;
    }

    let freeze = freeze_flag_for(tl, account);
    if (tx_flags & TF_SET_FREEZE) != 0 && (tx_flags & TF_CLEAR_FREEZE) == 0 {
        tl.flags |= freeze;
    } else if (tx_flags & TF_CLEAR_FREEZE) != 0 && (tx_flags & TF_SET_FREEZE) == 0 {
        tl.flags &= !freeze;
    }

    None
}

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
    let requested_quality_in = tx.quality_in.map(normalize_quality);
    let requested_quality_out = tx.quality_out.map(normalize_quality);

    // Check typed map AND NuDB for existing trust line (hydration gap).
    let had_trustline = state.get_trustline(&key).is_some()
        || state.get_raw_owned(&key).is_some()
        || state.get_committed_raw_owned(&key).is_some();
    let mut tl = if let Some(existing) = state.get_trustline(&key) {
        existing.clone()
    } else if let Some(raw) = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))
    {
        if let Some(decoded) = crate::ledger::RippleState::decode_from_sle(&raw) {
            state.hydrate_trustline(decoded.clone());
            decoded
        } else {
            crate::ledger::RippleState::new(&tx.account, &counterparty, currency)
        }
    } else {
        // No existing trust line. If limit is zero, this is redundant.
        if limit_value.is_zero()
            && requested_quality_in.unwrap_or(0) == 0
            && requested_quality_out.unwrap_or(0) == 0
        {
            return ApplyResult::ClaimedCost("tecNO_LINE_REDUNDANT");
        }
        crate::ledger::RippleState::new(&tx.account, &counterparty, currency)
    };

    // Set the limit for the sender's side
    let reserve_flag = reserve_flag_for(&tl, &tx.account);
    let sender_reserved_before = (tl.flags & reserve_flag) != 0;
    tl.set_limit_for(&tx.account, limit_value);
    apply_sender_qualities(
        &mut tl,
        &tx.account,
        requested_quality_in,
        requested_quality_out,
    );
    if let Some(ter) = apply_sender_trustline_flags(&mut tl, &tx.account, tx.flags) {
        return ApplyResult::ClaimedCost(ter);
    }
    let sender_reserved_after = side_has_nondefault_limit_or_quality(&tl, &tx.account);

    if tl.is_empty() && had_trustline {
        // Delete the trust line if both limits are zero and balance is zero
        // Remove from both accounts' owner directories (rippled RippleStateHelpers.cpp:283,290)
        directory::dir_remove(state, &tx.account, &key.0);
        directory::dir_remove(state, &counterparty, &key.0);
        state.remove_trustline(&key);
        // Owner reserve applies only on the side carrying the reserve flag.
        if sender_reserved_before {
            new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
        }
        if let Some(peer) = state.get_account(&counterparty) {
            let mut peer = peer.clone();
            let peer_flag = reserve_flag_for(&tl, &counterparty);
            if (tl.flags & peer_flag) != 0 {
                peer.owner_count = peer.owner_count.saturating_sub(1);
            }
            state.insert_account(peer);
        }
    } else {
        if !had_trustline {
            // Reserve check uses the pre-fee balance, matching rippled's
            // reserve-creating transactor convention.
            let fees = crate::ledger::fees::Fees::default();
            let pre_fee_balance = balance_before_fee(new_sender.balance, tx.fee);
            let required =
                fees.reserve_base + ((new_sender.owner_count as u64 + 1) * fees.reserve_inc);
            if pre_fee_balance < required {
                return ApplyResult::ClaimedCost("tecNO_LINE_INSUF_RESERVE");
            }
            // New trust line — add to BOTH accounts' owner directories
            // (rippled RippleStateHelpers.cpp:192,198)
            let sender_node = directory::dir_add(state, &tx.account, key.0);
            let counterparty_node = directory::dir_add(state, &counterparty, key.0);
            set_owner_node_for(&mut tl, &tx.account, sender_node);
            set_owner_node_for(&mut tl, &counterparty, counterparty_node);
            if let Some(peer) = load_existing_account(state, &counterparty) {
                // rippled's trustCreate peeks the peer AccountRoot; validated
                // metadata threads it even when only PreviousTxn fields change.
                let peer_key = crate::ledger::account::shamap_key(&counterparty);
                state.force_previous_txn_touch(&peer_key);
                state.insert_account(peer);
            }
        }

        if sender_reserved_before != sender_reserved_after {
            if sender_reserved_after {
                tl.flags |= reserve_flag;
                new_sender.owner_count += 1;
            } else {
                tl.flags &= !reserve_flag;
                new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
            }
        }
        state.insert_trustline(tl);
    }

    ApplyResult::Success
}
