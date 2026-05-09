//! Clawback — IMPLEMENTED

use super::mptoken;
use super::{ApplyResult, TxContext};
use crate::ledger::account::{
    AccountRoot, LSF_ALLOW_TRUST_LINE_CLAWBACK, LSF_DEFAULT_RIPPLE, LSF_DEPOSIT_AUTH,
    LSF_DISABLE_MASTER, LSF_NO_FREEZE,
};
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::amount::Amount;
use crate::transaction::amount::IouValue;
use crate::transaction::ParsedTx;
use std::cmp::Ordering;

/// Apply Clawback: issuer reclaims IOU tokens from a holder via trust line.
///
/// rippled: Clawback.cpp — for IOU clawback, the issuer (tx.account) claws back
/// tokens from the holder (encoded in the Amount field's issuer).  The actual
/// transfer is `rippleCredit(holder, issuer, min(spendable, clawAmount))`.
///
/// Handles IOU trust-line clawback directly and delegates MPT clawback to the
/// MPToken handler. Other Amount shapes hard-fail without metadata bridging.
pub(crate) fn apply_clawback(
    state: &mut LedgerState,
    tx: &ParsedTx,
    _ctx: &TxContext,
) -> ApplyResult {
    if matches!(tx.amount.as_ref(), Some(Amount::Mpt(_))) {
        if let Some(result) = mpt_clawback_holder_pseudo_guard(state, tx) {
            return result;
        }
        return mptoken::apply_mpt_clawback(state, tx);
    }

    if tx.holder.is_some() {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    // The Amount field encodes the clawback: the "issuer" in the Amount is
    // actually the holder account, and tx.account is the real issuer.
    let (claw_value, currency, holder) = match &tx.amount {
        Some(Amount::Iou {
            value,
            currency,
            issuer,
        }) => (value.clone(), currency.clone(), *issuer),
        Some(Amount::Xrp(_)) => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
        Some(Amount::Mpt(_)) => unreachable!("MPT clawback handled above"),
    };

    if !claw_value.is_positive() {
        return ApplyResult::ClaimedCost("temBAD_AMOUNT");
    }

    let issuer = tx.account;
    if holder == issuer {
        return ApplyResult::ClaimedCost("temBAD_AMOUNT");
    }

    let Some(holder_account) = super::load_existing_account(state, &holder) else {
        return ApplyResult::ClaimedCost("terNO_ACCOUNT");
    };
    let Some(issuer_account) = super::load_existing_account(state, &issuer) else {
        return ApplyResult::ClaimedCost("terNO_ACCOUNT");
    };
    if is_amm_pseudo_account(&holder_account) {
        return ApplyResult::ClaimedCost("tecAMM_ACCOUNT");
    }
    if is_pseudo_account(&holder_account) {
        return ApplyResult::ClaimedCost("tecPSEUDO_ACCOUNT");
    }
    if (issuer_account.flags & LSF_ALLOW_TRUST_LINE_CLAWBACK) == 0
        || (issuer_account.flags & LSF_NO_FREEZE) != 0
    {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let key = crate::ledger::trustline::shamap_key(&issuer, &holder, &currency);
    let tl = match load_trustline_for_clawback(state, &key) {
        Some(t) => t.clone(),
        None => return ApplyResult::ClaimedCost("tecNO_LINE"),
    };

    let mut tl = tl;
    let issuer_reserved_before = (tl.flags & reserve_flag_for(&tl, &issuer)) != 0;
    let holder_reserved_before = (tl.flags & reserve_flag_for(&tl, &holder)) != 0;
    if (tl.balance.is_positive() && issuer < holder)
        || (tl.balance.is_negative() && issuer > holder)
    {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    let holder_balance = tl.balance_for(&holder);
    if !holder_balance.is_positive() {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }
    let claw_value = if cmp_iou_positive(&holder_balance, &claw_value) == Ordering::Less {
        holder_balance
    } else {
        claw_value
    };

    tl.transfer(&holder, &claw_value);

    if tl.is_empty() {
        let holder_node = if holder == tl.low_account {
            tl.low_node
        } else {
            tl.high_node
        };
        let issuer_node = if issuer == tl.low_account {
            tl.low_node
        } else {
            tl.high_node
        };
        directory::dir_remove_owner_page(state, &holder, holder_node, &key.0);
        directory::dir_remove_owner_page(state, &issuer, issuer_node, &key.0);
        state.remove_trustline(&key);
        if holder_reserved_before {
            if let Some(h) = state.get_account(&holder) {
                let mut h = h.clone();
                h.owner_count = h.owner_count.saturating_sub(1);
                state.insert_account(h);
            }
        }
        if issuer_reserved_before {
            if let Some(i) = state.get_account(&issuer) {
                let mut i = i.clone();
                i.owner_count = i.owner_count.saturating_sub(1);
                state.insert_account(i);
            }
        }
    } else {
        state.insert_trustline(tl);
    }

    ApplyResult::Success
}

fn mpt_clawback_holder_pseudo_guard(state: &LedgerState, tx: &ParsedTx) -> Option<ApplyResult> {
    let amount = tx.amount.as_ref()?;
    let (requested, mptid) = match mptoken::mpt_amount_parts(amount) {
        Some(parts) => parts,
        None => return None,
    };
    if requested == 0 {
        return None;
    }

    let holder = tx.holder?;
    let issuer = mptoken::mpt_issuer(&mptid);
    if holder == issuer {
        return None;
    }

    let holder_account = state.get_account(&holder)?;
    state.get_account(&tx.account)?;

    if is_amm_pseudo_account(holder_account) {
        return Some(ApplyResult::ClaimedCost("tecAMM_ACCOUNT"));
    }
    if is_pseudo_account(holder_account) {
        return Some(ApplyResult::ClaimedCost("tecPSEUDO_ACCOUNT"));
    }
    None
}

fn is_amm_pseudo_account(account: &AccountRoot) -> bool {
    account_sle_has_hash256_field(account, 14)
}

fn is_pseudo_account(account: &AccountRoot) -> bool {
    is_amm_pseudo_account(account)
        || account_sle_has_hash256_field(account, 35)
        || account_sle_has_hash256_field(account, 37)
        || (account.sequence == 0
            && (account.flags & (LSF_DISABLE_MASTER | LSF_DEFAULT_RIPPLE | LSF_DEPOSIT_AUTH))
                == (LSF_DISABLE_MASTER | LSF_DEFAULT_RIPPLE | LSF_DEPOSIT_AUTH))
}

fn account_sle_has_hash256_field(account: &AccountRoot, field_code: u16) -> bool {
    let encoded;
    let raw = if let Some(raw) = account.raw_sle.as_deref() {
        raw
    } else {
        encoded = account.encode();
        &encoded
    };
    crate::ledger::meta::parse_sle(raw).is_some_and(|sle| {
        sle.fields
            .iter()
            .any(|field| field.type_code == 5 && field.field_code == field_code)
    })
}

fn load_trustline_for_clawback(
    state: &mut LedgerState,
    key: &crate::ledger::Key,
) -> Option<crate::ledger::RippleState> {
    if let Some(tl) = state.get_trustline(key) {
        return Some(tl.clone());
    }
    let raw = state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))?;
    let decoded = crate::ledger::RippleState::decode_from_sle(&raw)?;
    state.hydrate_trustline(decoded.clone());
    Some(decoded)
}

fn reserve_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        crate::ledger::trustline::LSF_LOW_RESERVE
    } else if account == &tl.high_account {
        crate::ledger::trustline::LSF_HIGH_RESERVE
    } else {
        0
    }
}

fn cmp_iou_positive(lhs: &IouValue, rhs: &IouValue) -> Ordering {
    debug_assert!(lhs.is_positive());
    debug_assert!(rhs.is_positive());

    match lhs.exponent.cmp(&rhs.exponent) {
        Ordering::Equal => lhs.mantissa.cmp(&rhs.mantissa),
        Ordering::Greater => {
            let diff = (lhs.exponent - rhs.exponent) as u32;
            if diff > 18 {
                return Ordering::Greater;
            }
            ((lhs.mantissa as i128) * 10_i128.pow(diff)).cmp(&(rhs.mantissa as i128))
        }
        Ordering::Less => {
            let diff = (rhs.exponent - lhs.exponent) as u32;
            if diff > 18 {
                return Ordering::Less;
            }
            (lhs.mantissa as i128).cmp(&((rhs.mantissa as i128) * 10_i128.pow(diff)))
        }
    }
}
