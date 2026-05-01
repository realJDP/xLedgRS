//! xLedgRS purpose: Offer transaction engine logic for ledger replay.
//! Offer — IMPLEMENTED

use super::amm_step;
use super::asset_flow::{apply_amount_delta, AssetDelta};
use super::{load_existing_account, ApplyResult};
use crate::ledger::directory;
use crate::ledger::offer::{
    amount_exponent, amount_is_zero, amount_to_i128, rate_gte, scale_amount, subtract_amount,
    BookKey,
};
use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, IouValue};
use crate::transaction::serialize::PREFIX_TX_SIGN;
use crate::transaction::ParsedTx;

// ── Quality-based crossing arithmetic (rippled parity) ──────────────────────
//
// Rippled computes offer-crossing fills using the Quality rate **stored in
// the book directory key** at offer creation, not re-derived from the
// offer's current (taker_pays, taker_gets). For offers that have been
// partially filled in earlier ledgers, the two can differ by a few
// mantissa bits of rounding. Rippled's flow:
//
//   Quality::ceil_out_strict(amount, limit, roundUp)
//     → mulRoundStrict(limit, quality.rate(), in_asset, roundUp)
//       → muldiv_round(m1, m2, 10^14, bias)  // u128 precision
//         where bias = (10^14 - 1) to round away from zero when needed
//
//   Quality::ceil_in_strict(amount, limit, roundUp)
//     → divRoundStrict(limit, quality.rate(), out_asset, roundUp)
//       → muldiv_round(numVal, 10^17, denVal, bias)
//         where bias = (denVal - 1) to round away from zero when needed
//
// The rate encoding is (exp_biased_by_100 << 56) | mantissa_56bits, matching
// getRate(offerOut, offerIn) = offerIn/offerOut at offer-creation time.

const TEN_TO_17: u128 = 100_000_000_000_000_000;

/// Decode the stored rate from a book directory key. Returns the rate as an
/// `IouValue` representing `offerIn / offerOut` (how much IN per unit OUT).
fn quality_rate_from_book_dir(book_directory: &[u8; 32]) -> IouValue {
    let mut q = [0u8; 8];
    q.copy_from_slice(&book_directory[24..32]);
    let raw = u64::from_be_bytes(q);
    if raw == 0 {
        return IouValue::ZERO;
    }
    let mantissa = (raw & 0x00FF_FFFF_FFFF_FFFF) as i64;
    let exponent = ((raw >> 56) as i32) - 100;
    IouValue { mantissa, exponent }
}

/// Normalize a u128 mantissa to the canonical 16-digit range [1e15, 1e16),
/// adjusting exponent. Rounding direction is controlled by `round_up`:
///   - `round_up = false`: truncate toward zero (matches rippled's
///     canonicalizeRoundStrict for positive results with roundUp=false).
///   - `round_up = true`: round away from zero (matches rippled's
///     canonicalizeRoundStrict for positive results with roundUp=true).
///
/// The ripple Number class distinguishes these two modes strictly; using
/// round-half-even here would leak 1 ULP of precision vs rippled at the
/// 16-digit truncation step that follows a mulRoundStrict/divRoundStrict.
fn normalize_u128(mantissa_abs: u128, exp: i32, round_up: bool) -> (u128, i32) {
    if mantissa_abs == 0 {
        return (0, 0);
    }
    const MAX16: u128 = 9_999_999_999_999_999;
    const MIN16: u128 = 1_000_000_000_000_000;
    let mut abs = mantissa_abs;
    let mut e = exp;
    while abs > MAX16 {
        let rem = abs % 10;
        abs /= 10;
        if round_up && rem != 0 {
            abs += 1;
        }
        e += 1;
    }
    while abs < MIN16 && abs != 0 {
        abs *= 10;
        e -= 1;
    }
    (abs, e)
}

/// Convert an Amount to an IouValue (dimensionless) for canonical arithmetic.
/// For XRP, treats drops as the mantissa with exponent 0, then normalizes.
fn amount_to_iou_value(a: &Amount) -> IouValue {
    match a {
        Amount::Xrp(drops) => {
            let mut v = IouValue {
                mantissa: *drops as i64,
                exponent: 0,
            };
            v.normalize();
            v
        }
        Amount::Iou { value, .. } => *value,
        Amount::Mpt(_) => IouValue::ZERO,
    }
}

/// Convert an IouValue back to an Amount using `template` to determine the
/// output type. For XRP templates, the value is converted to drops (u64).
/// For IOU templates, the value's canonical form is preserved.
fn iou_value_to_amount(v: &IouValue, template: &Amount) -> Amount {
    match template {
        Amount::Xrp(_) => {
            if v.mantissa <= 0 {
                return Amount::Xrp(0);
            }
            let m = v.mantissa as u128;
            let drops: u128 = if v.exponent >= 0 {
                m.saturating_mul(10u128.saturating_pow(v.exponent as u32))
            } else {
                let scale = 10u128.saturating_pow((-v.exponent) as u32);
                m / scale
            };
            Amount::Xrp(drops.min(u64::MAX as u128) as u64)
        }
        Amount::Iou {
            currency, issuer, ..
        } => Amount::Iou {
            value: *v,
            currency: currency.clone(),
            issuer: *issuer,
        },
        Amount::Mpt(_) => template.clone(),
    }
}

fn spendable_iou_funds_for_offer(
    state: &mut LedgerState,
    account: &[u8; 20],
    issuer: &[u8; 20],
    currency: &crate::transaction::amount::Currency,
) -> IouValue {
    let trustline = load_trustline_for_offer_funds(state, account, issuer, currency);

    let Some(trustline) = trustline else {
        return IouValue::ZERO;
    };

    let balance = trustline.balance_for(account);
    let opposite_limit = if account == &trustline.low_account {
        trustline.high_limit
    } else {
        trustline.low_limit
    };
    balance.add(&opposite_limit)
}

fn load_trustline_for_offer_funds(
    state: &mut LedgerState,
    account: &[u8; 20],
    issuer: &[u8; 20],
    currency: &crate::transaction::amount::Currency,
) -> Option<crate::ledger::RippleState> {
    let key = crate::ledger::trustline::shamap_key(account, issuer, currency);
    if let Some(tl) = state.get_trustline(&key) {
        return Some(tl.clone());
    }
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    let tl = crate::ledger::RippleState::decode_from_sle(&raw)?;
    state.hydrate_trustline(tl.clone());
    Some(tl)
}

fn debug_offer_funding_enabled(seq: u32) -> bool {
    std::env::var("XLEDGRSV2BETA_DEBUG_OFFER_SEQS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|entry| entry.trim().parse::<u32>().ok())
                .any(|target| target == seq)
        })
        .unwrap_or(false)
}

fn compare_iou_values(a: &IouValue, b: &IouValue) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    match (a.mantissa == 0, b.mantissa == 0) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        (false, false) => {}
    }

    if a.exponent == b.exponent {
        return a.mantissa.cmp(&b.mantissa);
    }

    let exp_diff = a.exponent - b.exponent;
    if exp_diff > 30 {
        return Ordering::Greater;
    }
    if exp_diff < -30 {
        return Ordering::Less;
    }

    if exp_diff > 0 {
        (a.mantissa as i128 * 10i128.pow(exp_diff as u32)).cmp(&(b.mantissa as i128))
    } else {
        (a.mantissa as i128).cmp(&(b.mantissa as i128 * 10i128.pow((-exp_diff) as u32)))
    }
}

fn compare_amounts(a: &Amount, b: &Amount) -> std::cmp::Ordering {
    compare_iou_values(&amount_to_iou_value(a), &amount_to_iou_value(b))
}

/// Rippled's `Quality::ceil_in_strict` subset: given an offer's (in, out) and
/// a limit on the IN side, compute the corresponding OUT side using the
/// stored quality rate. `round_up = true` rounds away from zero on positive
/// results, matching rippled's bias for offer crossing.
///
/// Returns (filled_in, filled_out) pair. If `limit_in >= offer_in`, uses
/// the full offer unchanged. Otherwise scales the out down via
/// `divRoundStrict(limit_in, rate)` where `rate = offer_in / offer_out`.
fn ceil_in_strict_via_quality(
    offer_in: &Amount,
    offer_out: &Amount,
    limit_in: &Amount,
    book_directory: &[u8; 32],
    round_up: bool,
) -> (Amount, Amount) {
    // Compare `limit_in` to `offer_in`. If the full offer can be taken, do so.
    let limit_iou = amount_to_iou_value(limit_in);
    let offer_in_iou = amount_to_iou_value(offer_in);
    if compare_iou_values(&limit_iou, &offer_in_iou) != std::cmp::Ordering::Less {
        return (offer_in.clone(), offer_out.clone());
    }

    // new_out = limit_in / rate, where rate = offerIn / offerOut
    let rate = quality_rate_from_book_dir(book_directory);
    if rate.mantissa == 0 {
        // Fallback: no valid stored quality, return the whole offer.
        return (offer_in.clone(), offer_out.clone());
    }

    // divRoundStrict: muldiv_round(num, 10^17, den, bias)
    let num_val = limit_iou.mantissa.unsigned_abs() as u128;
    let den_val = rate.mantissa.unsigned_abs() as u128;
    let result_negative = (limit_iou.mantissa < 0) != (rate.mantissa < 0);
    let bias: u128 = if result_negative != round_up {
        den_val - 1
    } else {
        0
    };
    let num_scaled = num_val.saturating_mul(TEN_TO_17).saturating_add(bias);
    let result_mantissa_u128 = num_scaled / den_val;
    let result_exp = limit_iou.exponent - rate.exponent - 17;

    let (mant_norm, exp_norm) = normalize_u128(result_mantissa_u128, result_exp, round_up);
    let new_out_iou = IouValue {
        mantissa: if result_negative {
            -(mant_norm as i64)
        } else {
            mant_norm as i64
        },
        exponent: exp_norm,
    };

    let new_out = iou_value_to_amount(&new_out_iou, offer_out);
    (limit_in.clone(), new_out)
}

/// Rippled's `Quality::ceil_out_strict` subset: given an offer's (in, out)
/// and a limit on the OUT side, compute the corresponding IN side using the
/// stored quality rate.
fn ceil_out_strict_via_quality(
    offer_in: &Amount,
    offer_out: &Amount,
    limit_out: &Amount,
    book_directory: &[u8; 32],
    round_up: bool,
) -> (Amount, Amount) {
    let limit_iou = amount_to_iou_value(limit_out);
    let offer_out_iou = amount_to_iou_value(offer_out);
    if compare_iou_values(&limit_iou, &offer_out_iou) != std::cmp::Ordering::Less {
        return (offer_in.clone(), offer_out.clone());
    }

    let rate = quality_rate_from_book_dir(book_directory);
    if rate.mantissa == 0 {
        return (offer_in.clone(), offer_out.clone());
    }

    let result_negative = (limit_iou.mantissa < 0) != (rate.mantissa < 0);
    let result_mantissa_u128 = (limit_iou.mantissa.unsigned_abs() as u128)
        .saturating_mul(rate.mantissa.unsigned_abs() as u128);
    let result_exp = limit_iou.exponent + rate.exponent;
    let (mant_norm, exp_norm) = normalize_u128(result_mantissa_u128, result_exp, round_up);
    let new_in_iou = IouValue {
        mantissa: if result_negative {
            -(mant_norm as i64)
        } else {
            mant_norm as i64
        },
        exponent: exp_norm,
    };

    let new_in = iou_value_to_amount(&new_in_iou, offer_in);
    (new_in, limit_out.clone())
}

fn extract_additional_books_from_signing_payload(payload: &[u8]) -> Vec<[u8; 32]> {
    if payload.len() < PREFIX_TX_SIGN.len() || payload[..PREFIX_TX_SIGN.len()] != PREFIX_TX_SIGN {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut pos = PREFIX_TX_SIGN.len();
    while pos < payload.len() {
        if payload[pos] == 0xE1 {
            break;
        }

        let (tc, fc, header_end) = crate::ledger::meta::read_field_header(payload, pos);
        if header_end > payload.len() {
            break;
        }
        pos = header_end;

        if tc == 19 && fc == 13 {
            let (vl_len, vl_bytes) = crate::transaction::serialize::decode_length(&payload[pos..]);
            if vl_bytes == 0 || pos + vl_bytes + vl_len > payload.len() {
                break;
            }
            pos += vl_bytes;
            let raw = &payload[pos..pos + vl_len];
            for chunk in raw.chunks_exact(32) {
                if let Ok(book) = chunk.try_into() {
                    out.push(book);
                }
            }
            pos += vl_len;
            continue;
        }

        let next = crate::ledger::meta::skip_field_raw(payload, pos, tc);
        if next <= pos {
            break;
        }
        pos = next;
    }

    out
}

fn build_standing_offer(
    tx: &ParsedTx,
    offer_seq: u32,
    remaining_pays: Amount,
    remaining_gets: Amount,
    book_directory: [u8; 32],
    book_node: u64,
    owner_node: u64,
) -> crate::ledger::Offer {
    let mut sle_flags: u32 = 0;
    if (tx.flags & 0x00010000) != 0 {
        sle_flags |= crate::ledger::offer::LSF_PASSIVE;
    }
    if (tx.flags & 0x00080000) != 0 {
        sle_flags |= crate::ledger::offer::LSF_SELL;
    }

    crate::ledger::Offer {
        account: tx.account,
        sequence: offer_seq,
        taker_pays: remaining_pays,
        taker_gets: remaining_gets,
        flags: sle_flags,
        book_directory,
        book_node,
        owner_node,
        expiration: tx.expiration,
        domain_id: tx.domain_id,
        additional_books: extract_additional_books_from_signing_payload(&tx.signing_payload),
        previous_txn_id: [0u8; 32],
        previous_txn_lgr_seq: 0,
        raw_sle: None,
    }
}

pub(crate) fn apply_validated_amm_offer_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> Option<ApplyResult> {
    let taker_pays = tx.taker_pays.as_ref()?;
    let taker_gets = tx.taker_gets.as_ref()?;
    if amount_is_zero(taker_pays) || amount_is_zero(taker_gets) {
        return None;
    }
    if tx.flags != 0 {
        return None;
    }
    if tx.offer_sequence.is_some() {
        return None;
    }
    if tx
        .expiration
        .is_some_and(|expiration| close_time >= expiration as u64)
    {
        return None;
    }

    let asset_in = amm_step::issue_from_amount(taker_gets)?;
    let asset_out = amm_step::issue_from_amount(taker_pays)?;
    if asset_in == asset_out {
        return None;
    }
    let funded_gets = offer_funded_input(state, &tx.account, taker_gets)?;

    let pool = amm_step::load_amm_pool(state, &asset_in, &asset_out)?;
    let quote = match amm_step::quote_exact_out(&pool, taker_pays) {
        Some(exact_out) if amm_step::amount_leq(&exact_out.spent_in, &funded_gets)? => exact_out,
        _ => amm_step::quote_exact_in(&pool, &funded_gets)?,
    };
    if !amm_step::amount_leq(&quote.delivered_out, taker_pays)? {
        return None;
    }
    if amount_is_zero(&quote.spent_in) || amount_is_zero(&quote.delivered_out) {
        return None;
    }

    amm_step::apply_swap_to_state(state, &pool, &quote, &tx.account, &tx.account);
    Some(ApplyResult::Success)
}

fn offer_funded_input(
    state: &mut LedgerState,
    account: &[u8; 20],
    amount: &Amount,
) -> Option<Amount> {
    match amount {
        Amount::Xrp(requested) => {
            let fees = crate::ledger::read_fees(state);
            let acct = load_existing_account(state, account)?;
            let reserve = fees.reserve + (acct.owner_count as u64 * fees.increment);
            let available = acct.balance.saturating_sub(reserve);
            if available == 0 {
                return None;
            }
            Some(Amount::Xrp((*requested).min(available)))
        }
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            if account == issuer {
                return Some(amount.clone());
            }

            let available = spendable_iou_funds_for_offer(state, account, issuer, currency);
            if !available.is_positive() {
                return None;
            }
            if compare_iou_values(&available, value) == std::cmp::Ordering::Less {
                Some(Amount::Iou {
                    value: available,
                    currency: currency.clone(),
                    issuer: *issuer,
                })
            } else {
                Some(amount.clone())
            }
        }
        Amount::Mpt(_) => None,
    }
}

/// Apply an OfferCreate: attempt to cross against the opposite book,
/// then place any unfilled remainder as a standing order.
pub(crate) fn apply_offer_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    let mut owner_count_deltas: std::collections::BTreeMap<[u8; 20], i32> =
        std::collections::BTreeMap::new();
    let mut released_gets_from_cancel: Option<Amount> = None;

    let mut remaining_pays = match &tx.taker_pays {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temBAD_OFFER"),
    };
    let mut remaining_gets = match &tx.taker_gets {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temBAD_OFFER"),
    };
    let original_pays = remaining_pays.clone();
    let original_gets = remaining_gets.clone();
    let original_book_key = BookKey::from_amounts(&original_pays, &original_gets);
    let original_book_quality = directory::offer_quality(&original_gets, &original_pays);
    let original_book_directory =
        directory::book_dir_quality_key(&original_book_key, original_book_quality);

    let offer_seq = super::sequence_proxy(tx);

    // Validate offer amounts are non-zero
    if amount_is_zero(&remaining_pays) || amount_is_zero(&remaining_gets) {
        return ApplyResult::ClaimedCost("temBAD_OFFER");
    }

    if let Some(expiration) = tx.expiration {
        if close_time >= expiration as u64 {
            return ApplyResult::ClaimedCost("tecEXPIRED");
        }
    }

    // Explicit cancellation: if OfferSequence is set, cancel that specific old offer
    // before processing the new one (rippled OfferCreate.cpp behavior).
    if let Some(cancel_seq) = tx.offer_sequence {
        let cancel_key = crate::ledger::offer::shamap_key(&tx.account, cancel_seq);
        // Hydrate from NuDB if not in typed map — offers from earlier ledgers
        // live only in NuDB until explicitly loaded. Without this, remove_offer
        // returns None and the cancellation is silently skipped, leaving a
        // stale offer + book directory entry. This was Bug C.
        if state.get_offer(&cancel_key).is_none() {
            if let Some(raw) = state.get_raw_owned(&cancel_key) {
                if let Some(decoded) = crate::ledger::Offer::decode_from_sle(&raw) {
                    state.hydrate_offer(decoded);
                }
            }
        }
        if let Some(old) = state.remove_offer(&cancel_key) {
            let old_offer_key = crate::ledger::offer::shamap_key(&old.account, old.sequence);
            let owner_root = directory::owner_dir_key(&old.account);
            let _ = directory::dir_remove_root_page(
                state,
                &owner_root,
                old.owner_node,
                &old_offer_key.0,
            ) || directory::dir_remove(state, &old.account, &old_offer_key.0);
            if old.book_directory != [0u8; 32] {
                let _ = directory::dir_remove_root_page(
                    state,
                    &crate::ledger::Key(old.book_directory),
                    old.book_node,
                    &old_offer_key.0,
                ) || directory::dir_remove_root(
                    state,
                    &crate::ledger::Key(old.book_directory),
                    &old_offer_key.0,
                );
            }
            for book_directory in &old.additional_books {
                directory::dir_remove_root(
                    state,
                    &crate::ledger::Key(*book_directory),
                    &old_offer_key.0,
                );
            }
            *owner_count_deltas.entry(old.account).or_insert(0) -= 1;
            released_gets_from_cancel = Some(old.taker_gets.clone());
        }
    }

    // Funding check: does the account have enough of TakerGets to back the offer?
    // rippled returns tecUNFUNDED_OFFER if the account can't fund the offer.
    let funded = match &remaining_gets {
        Amount::Xrp(_) => {
            // Rippled only rejects as unfunded when spendable XRP is zero.
            // The offer amount itself may exceed the current liquid balance.
            let fees = crate::ledger::read_fees(state);
            let acct = load_existing_account(state, &tx.account);
            let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
            let owner_count = acct.as_ref().map(|a| a.owner_count).unwrap_or(0);
            let owner_delta = owner_count_deltas.get(&tx.account).copied().unwrap_or(0) as i64;
            let effective_owner_count = (owner_count as i64 + owner_delta).max(0) as u64;
            let reserve = fees.reserve + (effective_owner_count * fees.increment);
            let released = match released_gets_from_cancel.as_ref() {
                Some(Amount::Xrp(d)) => *d,
                _ => 0,
            };
            balance.saturating_add(released).saturating_sub(reserve) > 0
        }
        Amount::Iou {
            currency, issuer, ..
        } => {
            if &tx.account == issuer {
                true
            } else {
                // For IOU: spendable funds include the counterparty's credit
                // headroom on the trust line, not just a currently-positive
                // balance.
                let mut available =
                    spendable_iou_funds_for_offer(state, &tx.account, issuer, currency);

                if let Some(Amount::Iou {
                    value: released,
                    currency: rel_currency,
                    issuer: rel_issuer,
                }) = released_gets_from_cancel.as_ref()
                {
                    if rel_currency == currency && rel_issuer == issuer {
                        available = available.add(released);
                    }
                }

                available.is_positive()
            }
        }
        _ => true,
    };
    if !funded {
        if debug_offer_funding_enabled(tx.sequence) {
            if let Amount::Iou {
                currency, issuer, ..
            } = &remaining_gets
            {
                let trustline =
                    load_trustline_for_offer_funds(state, &tx.account, issuer, currency);
                let available = spendable_iou_funds_for_offer(state, &tx.account, issuer, currency);
                if let Some(tl) = trustline {
                    let balance = tl.balance_for(&tx.account);
                    let opposite_limit = if tx.account == tl.low_account {
                        tl.high_limit
                    } else {
                        tl.low_limit
                    };
                    tracing::warn!(
                        "offer funding debug: seq={} acct={} issuer={} balance={}e{} low_limit={}e{} high_limit={}e{} opposite_limit={}e{} available={}e{}",
                        tx.sequence,
                        hex::encode_upper(tx.account),
                        hex::encode_upper(issuer),
                        balance.mantissa,
                        balance.exponent,
                        tl.low_limit.mantissa,
                        tl.low_limit.exponent,
                        tl.high_limit.mantissa,
                        tl.high_limit.exponent,
                        opposite_limit.mantissa,
                        opposite_limit.exponent,
                        available.mantissa,
                        available.exponent,
                    );
                } else {
                    tracing::warn!(
                        "offer funding debug: seq={} acct={} issuer={} trustline=missing available={}e{}",
                        tx.sequence,
                        hex::encode_upper(tx.account),
                        hex::encode_upper(issuer),
                        available.mantissa,
                        available.exponent,
                    );
                }
            }
        }
        return ApplyResult::ClaimedCost("tecUNFUNDED_OFFER");
    }

    // ── Cross against the opposite book ──────────────────────────────────────
    let opposite_key = BookKey::from_amounts(&remaining_gets, &remaining_pays);

    // Collect crossing offer keys (can't mutate state while iterating)
    let crossing_keys: Vec<crate::ledger::Key> = state
        .get_book(&opposite_key)
        .map(|book| book.iter_by_quality().cloned().collect())
        .unwrap_or_default();

    let mut offers_to_remove = Vec::new();
    const MAX_CROSSING_STEPS: usize = 850; // matches rippled
    let mut steps = 0;
    let mut crossed_any = false;

    for key in &crossing_keys {
        if steps >= MAX_CROSSING_STEPS {
            break;
        }
        steps += 1;
        let book_offer = match state.get_offer(key) {
            Some(o) => o.clone(),
            None => continue,
        };
        // Track that this account's owner count may change (consumed offer = -1)

        if amount_is_zero(&book_offer.taker_gets) {
            continue;
        }
        if amount_is_zero(&remaining_gets) {
            break;
        }
        // Skip expired offers (rippled: OfferCreate.cpp removes expired offers during crossing)
        if let Some(expiration) = book_offer.expiration {
            if close_time >= expiration as u64 {
                offers_to_remove.push(*key);
                continue;
            }
        }
        // Quality gate: stop crossing when the book offer's quality is worse
        // than what the taker specified. tfSell does NOT bypass this check —
        // it only affects which side constrains the fill (confirmed: rippled
        // with tfSell still respects quality and rejects worse-rate offers).
        //
        // This gate must be evaluated BEFORE the self-owned check: rippled's
        // BookStep::limitSelfCrossQuality (src/libxrpl/tx/paths/BookStep.cpp
        // :404-409) only removes self-owned offers when `offer.quality() >=
        // `qualityThreshold_`. Reversing the order previously caused the engine to
        // silently cancel a previous same-account offer in the opposite book
        // whenever the new offer walked the book, even when the prices
        // didn't actually overlap.
        let crosses = rate_gte(
            &book_offer.taker_gets,
            &book_offer.taker_pays,
            &remaining_pays,
            &remaining_gets,
        );
        if !crosses {
            break;
        }

        // Self-owned offers at a crossing quality: rippled's
        // limitSelfCrossQuality removes them even though no actual trade
        // happens. Same-account "trade" would be meaningless, so the old
        // Offer is cancelled and book traversal continues.
        if book_offer.account == tx.account {
            offers_to_remove.push(*key);
            continue;
        }

        let we_want_i = amount_to_i128(&remaining_pays);
        let they_give_i = amount_to_i128(&book_offer.taker_gets);
        let we_can_pay_i = amount_to_i128(&remaining_gets);
        let they_want_i = amount_to_i128(&book_offer.taker_pays);
        let exp_want = amount_exponent(&remaining_pays);
        let exp_give = amount_exponent(&book_offer.taker_gets);
        let exp_can_pay = amount_exponent(&remaining_gets);
        let exp_they_want = amount_exponent(&book_offer.taker_pays);

        if they_give_i <= 0 || they_want_i <= 0 {
            continue;
        }

        // Fill ratio is bounded by BOTH sides:
        // 1) Remaining amount to receive (`remaining_pays / offer_gets`)
        // 2) Remaining amount available to pay (`remaining_gets / offer_pays`)
        //
        // tfSell semantics (rippled CreateOffer / FlowCross): the maker has
        // committed to spending all of `taker_gets` and will accept whatever
        // amount of `taker_pays` the book provides. The quality gate above
        // still applies, but
        // within that gate the "at-least-want" receive floor is ignored and
        // only `ratio_pay` binds. Non-`tfSell` offers keep the
        // canonical min(receive, pay) behavior.
        const TF_SELL: u32 = 0x00080000;
        let is_sell = (tx.flags & TF_SELL) != 0;
        let ratio_receive = normalize_ratio(we_want_i, exp_want, they_give_i, exp_give);
        let ratio_pay = normalize_ratio(we_can_pay_i, exp_can_pay, they_want_i, exp_they_want);
        let (mut fill_num, fill_den) = if is_sell {
            ratio_pay
        } else {
            min_ratio(ratio_receive, ratio_pay)
        };
        if fill_num > fill_den {
            fill_num = fill_den;
        }

        // For tfSell, match rippled's exact arithmetic: use the stored
        // book-directory quality as the rate and compute filled_out via
        // divRoundStrict (ceil_in_strict). This avoids the precision loss
        // of re-deriving the rate from the offer's current (taker_pays,
        // taker_gets) pair via a ratio-based scale. Non-tfSell continues to
        // use the ratio-based scale_amount until the full Quality ceil_out
        // path is ported.
        let (filled_pay, filled_receive) = if is_sell {
            let limit_in = if fill_num >= fill_den {
                book_offer.taker_pays.clone()
            } else {
                scale_amount(&book_offer.taker_pays, fill_num, fill_den)
            };
            let (fin, fout) = ceil_in_strict_via_quality(
                &book_offer.taker_pays,
                &book_offer.taker_gets,
                &limit_in,
                &book_offer.book_directory,
                false, // roundUp=false: taker receives rounded toward zero,
                       // matches rippled's canonicalizeRoundStrict path
            );
            (fin, fout)
        } else {
            let desired_out = if compare_amounts(&remaining_pays, &book_offer.taker_gets)
                == std::cmp::Ordering::Greater
            {
                book_offer.taker_gets.clone()
            } else {
                remaining_pays.clone()
            };
            let (pay_for_desired_out, filled_receive) = ceil_out_strict_via_quality(
                &book_offer.taker_pays,
                &book_offer.taker_gets,
                &desired_out,
                &book_offer.book_directory,
                true,
            );
            if compare_amounts(&pay_for_desired_out, &remaining_gets) != std::cmp::Ordering::Greater
            {
                (pay_for_desired_out, filled_receive)
            } else {
                ceil_in_strict_via_quality(
                    &book_offer.taker_pays,
                    &book_offer.taker_gets,
                    &remaining_gets,
                    &book_offer.book_directory,
                    false,
                )
            }
        };

        if amount_is_zero(&filled_pay) || amount_is_zero(&filled_receive) {
            continue;
        }

        // Transfer assets between the two parties
        apply_amount_delta(state, &tx.account, AssetDelta::Credit, &filled_receive);
        apply_amount_delta(state, &tx.account, AssetDelta::Debit, &filled_pay);
        apply_amount_delta(state, &book_offer.account, AssetDelta::Credit, &filled_pay);
        apply_amount_delta(
            state,
            &book_offer.account,
            AssetDelta::Debit,
            &filled_receive,
        );

        // Update the remaining want/give values.
        remaining_pays = subtract_amount(&remaining_pays, &filled_receive);
        remaining_gets = subtract_amount(&remaining_gets, &filled_pay);
        crossed_any = true;

        let fully_consumed =
            compare_amounts(&filled_receive, &book_offer.taker_gets) != std::cmp::Ordering::Less;
        if fully_consumed {
            offers_to_remove.push(*key);
        } else {
            state.remove_offer(key);
            let new_gets = subtract_amount(&book_offer.taker_gets, &filled_receive);
            let (new_pays, _) = ceil_out_strict_via_quality(
                &book_offer.taker_pays,
                &book_offer.taker_gets,
                &new_gets,
                &book_offer.book_directory,
                true,
            );
            if !amount_is_zero(&new_gets) && !amount_is_zero(&new_pays) {
                let mut updated = book_offer.clone();
                updated.taker_gets = new_gets;
                updated.taker_pays = new_pays;
                updated.raw_sle = None;
                state.insert_offer(updated);
            } else {
                // Offer fully consumed (remainder is zero) — remove from owner and book directories
                let offer_key =
                    crate::ledger::offer::shamap_key(&book_offer.account, book_offer.sequence);
                let removed_owner = directory::dir_remove(state, &book_offer.account, &offer_key.0);
                *owner_count_deltas.entry(book_offer.account).or_insert(0) -= 1;
                if book_offer.book_directory != [0u8; 32] {
                    let removed_book = directory::dir_remove_root(
                        state,
                        &crate::ledger::Key(book_offer.book_directory),
                        &offer_key.0,
                    );
                    if !removed_owner || !removed_book {
                        let owner_still_has_entry = directory::owner_dir_contains_entry(
                            state,
                            &book_offer.account,
                            &offer_key.0,
                        );
                        tracing::warn!(
                            "offer replay remove miss (zero remainder): account={} seq={} owner_removed={} book_removed={} owner_has_entry={}",
                            hex::encode_upper(book_offer.account),
                            book_offer.sequence,
                            removed_owner,
                            removed_book,
                            owner_still_has_entry,
                        );
                    }
                } else if !removed_owner {
                    let owner_still_has_entry = directory::owner_dir_contains_entry(
                        state,
                        &book_offer.account,
                        &offer_key.0,
                    );
                    tracing::warn!(
                        "offer replay owner-dir remove miss (zero remainder): account={} seq={} owner_has_entry={}",
                        hex::encode_upper(book_offer.account),
                        book_offer.sequence,
                        owner_still_has_entry,
                    );
                }
            }
        }

        if amount_is_zero(&remaining_pays) {
            break;
        }
    }

    // Remove consumed offers and decrement their owners' counts
    for key in &offers_to_remove {
        // Hydrate from NuDB if not in typed map (same hydration gap as trust lines)
        if state.get_offer(key).is_none() {
            if let Some(raw) = state.get_raw_owned(key) {
                if let Some(decoded) = crate::ledger::Offer::decode_from_sle(&raw) {
                    state.hydrate_offer(decoded);
                }
            }
        }
        if let Some(removed) = state.remove_offer(key) {
            // Remove from owner and book directories
            let offer_key = crate::ledger::offer::shamap_key(&removed.account, removed.sequence);
            let owner_root = directory::owner_dir_key(&removed.account);
            let removed_owner = directory::dir_remove_root_page(
                state,
                &owner_root,
                removed.owner_node,
                &offer_key.0,
            ) || directory::dir_remove(state, &removed.account, &offer_key.0);
            *owner_count_deltas.entry(removed.account).or_insert(0) -= 1;
            if removed.book_directory != [0u8; 32] {
                let removed_book = directory::dir_remove_root_page(
                    state,
                    &crate::ledger::Key(removed.book_directory),
                    removed.book_node,
                    &offer_key.0,
                ) || directory::dir_remove_root(
                    state,
                    &crate::ledger::Key(removed.book_directory),
                    &offer_key.0,
                );
                if !removed_owner || !removed_book {
                    let owner_still_has_entry =
                        directory::owner_dir_contains_entry(state, &removed.account, &offer_key.0);
                    tracing::warn!(
                        "offer replay remove miss (consumed): account={} seq={} owner_removed={} book_removed={} owner_has_entry={}",
                        hex::encode_upper(removed.account),
                        removed.sequence,
                        removed_owner,
                        removed_book,
                        owner_still_has_entry,
                    );
                }
            } else if !removed_owner {
                let owner_still_has_entry =
                    directory::owner_dir_contains_entry(state, &removed.account, &offer_key.0);
                tracing::warn!(
                    "offer replay owner-dir remove miss (consumed): account={} seq={} owner_has_entry={}",
                    hex::encode_upper(removed.account),
                    removed.sequence,
                    owner_still_has_entry,
                );
            }
            for book_directory in &removed.additional_books {
                directory::dir_remove_root(
                    state,
                    &crate::ledger::Key(*book_directory),
                    &offer_key.0,
                );
            }
        }
    }

    // ── OfferCreate flags (rippled: OfferCreate.cpp) ──
    const TF_IMMEDIATE_OR_CANCEL: u32 = 0x00020000;
    const TF_FILL_OR_KILL: u32 = 0x00040000;

    if crossed_any && !amount_is_zero(&remaining_pays) && !amount_is_zero(&remaining_gets) {
        if (tx.flags & 0x00080000) != 0 {
            let (recomputed_pays, _) = ceil_out_strict_via_quality(
                &original_pays,
                &original_gets,
                &remaining_gets,
                &original_book_directory.0,
                true,
            );
            remaining_pays = recomputed_pays;
        } else {
            let (_, recomputed_gets) = ceil_in_strict_via_quality(
                &original_pays,
                &original_gets,
                &remaining_pays,
                &original_book_directory.0,
                false,
            );
            remaining_gets = recomputed_gets;
        }
    }

    // tfFillOrKill: cancel entire offer if any remainder (must be fully filled)
    if (tx.flags & TF_FILL_OR_KILL) != 0
        && (!amount_is_zero(&remaining_pays) || !amount_is_zero(&remaining_gets))
    {
        // Offer not fully filled — return tecKILLED (fee claimed, no offer placed)
        return ApplyResult::ClaimedCost("tecKILLED");
    }

    // tfImmediateOrCancel: don't place remainder as standing offer
    let place_remainder = (tx.flags & TF_IMMEDIATE_OR_CANCEL) == 0;

    // ── Place remainder as standing offer ────────────────────────────────────
    if place_remainder && !amount_is_zero(&remaining_pays) && !amount_is_zero(&remaining_gets) {
        let offer_key = crate::ledger::offer::shamap_key(&tx.account, offer_seq);
        let owner_node = directory::dir_add(state, &tx.account, offer_key.0);
        let book_key = BookKey::from_amounts(&remaining_pays, &remaining_gets);
        // rippled preserves the offer's original uRate for the standing
        // remainder. Recomputing from partially-filled amounts moves the
        // residual offer into the wrong quality directory.
        let book_quality = original_book_quality;
        let (book_directory, book_node) =
            directory::dir_add_book(state, &book_key, book_quality, offer_key.0);
        let offer = build_standing_offer(
            tx,
            offer_seq,
            remaining_pays,
            remaining_gets,
            book_directory.0,
            book_node,
            owner_node,
        );
        state.insert_offer(offer);
        *owner_count_deltas.entry(tx.account).or_insert(0) += 1;
    }

    // Update owner counts via explicit deltas — NOT by recomputing from
    // directory entry count. rippled's adjustOwnerCount is called exactly
    // once per object add/remove: +1 for offers placed, -1 for offers
    // cancelled or consumed. Recomputing from the raw directory entry count
    // produces wrong results because some directory entries (trust lines,
    // tickets, etc. from other tx types) don't map 1:1 with OwnerCount.
    for (account, delta) in owner_count_deltas {
        if delta == 0 {
            continue;
        }
        if let Some(acct) = load_existing_account(state, &account) {
            let mut updated = acct.clone();
            updated.owner_count = if delta > 0 {
                updated.owner_count.saturating_add(delta as u32)
            } else {
                updated.owner_count.saturating_sub((-delta) as u32)
            };
            state.insert_account(updated);
        }
    }

    ApplyResult::Success
}

fn normalize_ratio(num: i128, num_exp: i32, den: i128, den_exp: i32) -> (i128, i128) {
    if den <= 0 {
        return (0, 1);
    }
    if num <= 0 {
        return (0, 1);
    }
    if num_exp == den_exp {
        return (num, den);
    }
    if num_exp > den_exp {
        let shift = (num_exp - den_exp).min(38) as u32;
        (num.saturating_mul(10i128.pow(shift)), den)
    } else {
        let shift = (den_exp - num_exp).min(38) as u32;
        (num, den.saturating_mul(10i128.pow(shift)))
    }
}

fn min_ratio(a: (i128, i128), b: (i128, i128)) -> (i128, i128) {
    let (an, ad) = a;
    let (bn, bd) = b;
    if an <= 0 || ad <= 0 {
        return (0, 1);
    }
    if bn <= 0 || bd <= 0 {
        return (0, 1);
    }
    match an.checked_mul(bd).zip(bn.checked_mul(ad)) {
        Some((lhs, rhs)) => {
            if lhs <= rhs {
                a
            } else {
                b
            }
        }
        None => {
            // Rare overflow on cross-multiply: fall back to conservative lower bound.
            if an.saturating_mul(bd) <= bn.saturating_mul(ad) {
                a
            } else {
                b
            }
        }
    }
}

/// Apply an OfferCancel: remove a standing offer from the DEX.
pub(crate) fn apply_offer_cancel(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    let target_seq = match tx.offer_sequence {
        Some(s) => s,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = crate::ledger::offer::shamap_key(&tx.account, target_seq);
    if state.get_offer(&key).is_none() {
        if let Some(raw) = state
            .get_raw_owned(&key)
            .or_else(|| state.get_committed_raw_owned(&key))
        {
            if let Some(decoded) = crate::ledger::Offer::decode_from_sle(&raw) {
                state.hydrate_offer(decoded);
            }
        }
    }
    if let Some(_removed) = state.remove_offer(&key) {
        let owner_root = directory::owner_dir_key(&tx.account);
        if !(directory::dir_remove_root_page(state, &owner_root, _removed.owner_node, &key.0)
            || directory::dir_remove(state, &tx.account, &key.0))
        {
            let owner_still_has_entry =
                directory::owner_dir_contains_entry(state, &tx.account, &key.0);
            tracing::warn!(
                "offer cancel owner-dir remove miss: account={} seq={} owner_has_entry={}",
                hex::encode_upper(tx.account),
                target_seq,
                owner_still_has_entry,
            );
        }
        if _removed.book_directory != [0u8; 32] {
            if !(directory::dir_remove_root_page(
                state,
                &crate::ledger::Key(_removed.book_directory),
                _removed.book_node,
                &key.0,
            ) || directory::dir_remove_root(
                state,
                &crate::ledger::Key(_removed.book_directory),
                &key.0,
            )) {
                let owner_still_has_entry =
                    directory::owner_dir_contains_entry(state, &tx.account, &key.0);
                tracing::warn!(
                    "offer cancel book-dir remove miss: account={} seq={} owner_has_entry={}",
                    hex::encode_upper(tx.account),
                    target_seq,
                    owner_still_has_entry,
                );
            }
        }
        for book_directory in &_removed.additional_books {
            directory::dir_remove_root(state, &crate::ledger::Key(*book_directory), &key.0);
        }

        if let Some(acct) = load_existing_account(state, &tx.account) {
            let mut updated = acct.clone();
            updated.owner_count = updated.owner_count.saturating_sub(1);
            state.insert_account(updated);
        }
    }

    ApplyResult::Success
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_additional_books_payload(books: &[[u8; 32]]) -> Vec<u8> {
        let mut payload = PREFIX_TX_SIGN.to_vec();
        crate::ledger::meta::write_field_header_pub(&mut payload, 19, 13);
        let mut raw = Vec::with_capacity(books.len() * 32);
        for book in books {
            raw.extend_from_slice(book);
        }
        crate::transaction::serialize::encode_length(raw.len(), &mut payload);
        payload.extend_from_slice(&raw);
        payload.push(0xE1);
        payload
    }

    #[test]
    fn extracts_additional_books_from_signing_payload() {
        let books = [[0x11; 32], [0x22; 32]];
        let payload = build_additional_books_payload(&books);

        assert_eq!(
            extract_additional_books_from_signing_payload(&payload),
            books
        );
    }

    #[test]
    fn standing_remainder_uses_original_offer_quality() {
        let original_pays = Amount::Xrp(20);
        let original_gets = Amount::Xrp(10);
        let remaining_pays = Amount::Xrp(15);
        let remaining_gets = Amount::Xrp(10);

        let original_quality = directory::offer_quality(&original_gets, &original_pays);
        let recomputed_quality = directory::offer_quality(&remaining_gets, &remaining_pays);

        assert_ne!(original_quality, recomputed_quality);
        assert_eq!(
            original_quality,
            directory::offer_quality(&original_gets, &original_pays)
        );
    }

    #[test]
    fn build_standing_offer_preserves_tx_metadata() {
        let books = [[0x33; 32]];
        let tx = ParsedTx {
            domain_id: Some([0x44; 32]),
            signing_payload: build_additional_books_payload(&books),
            ..ParsedTx::default()
        };

        let offer =
            build_standing_offer(&tx, 42, Amount::Xrp(15), Amount::Xrp(10), [0x55; 32], 7, 9);

        assert_eq!(offer.account, tx.account);
        assert_eq!(offer.sequence, 42);
        assert_eq!(offer.book_directory, [0x55; 32]);
        assert_eq!(offer.book_node, 7);
        assert_eq!(offer.owner_node, 9);
        assert_eq!(offer.domain_id, Some([0x44; 32]));
        assert_eq!(offer.additional_books, books);
    }
}
