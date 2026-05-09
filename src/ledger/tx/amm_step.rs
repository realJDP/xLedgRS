//! Single AMM liquidity step for Payment/OfferCreate.
//!
//! This module intentionally does not implement AMM transaction lifecycle.
//! It reads an existing AMM pool and applies one XRP/IOU swap using real pool
//! reserves from the pseudo AccountRoot and pseudo/issuer RippleState.

use super::amm::amm_key;
use super::asset_flow::{apply_amount_delta, AssetDelta};
use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, IouValue, Issue};

const FEE_DENOMINATOR: u128 = 100_000;
const INITIAL_FIB_SEQUENCE_NUMERATOR: u128 = 5;
const INITIAL_FIB_SEQUENCE_DENOMINATOR: u128 = 20_000;
const AMM_MAX_FIB_ITERATIONS: usize = 30;
const AMM_FIB_SEQUENCE: [u128; AMM_MAX_FIB_ITERATIONS] = [
    1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 6765, 10946,
    17711, 28657, 46368, 75025, 121393, 196418, 317811, 514229, 832040, 1346269,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AmmPool {
    pub pseudo_account: [u8; 20],
    pub asset_in: Issue,
    pub asset_out: Issue,
    pub reserve_in: Amount,
    pub reserve_out: Amount,
    pub trading_fee: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AmmQuote {
    pub spent_in: Amount,
    pub delivered_out: Amount,
}

pub(crate) fn issue_from_amount(amount: &Amount) -> Option<Issue> {
    match amount {
        Amount::Xrp(_) => Some(Issue::Xrp),
        Amount::Iou {
            currency, issuer, ..
        } => Some(Issue::Iou {
            currency: currency.clone(),
            issuer: *issuer,
        }),
        Amount::Mpt(_) => None,
    }
}

pub(crate) fn load_amm_pool(
    state: &LedgerState,
    asset_in: &Issue,
    asset_out: &Issue,
) -> Option<AmmPool> {
    load_amm_pool_with_fee_context(state, asset_in, asset_out, None)
}

pub(crate) fn load_amm_pool_for_account(
    state: &LedgerState,
    asset_in: &Issue,
    asset_out: &Issue,
    account: &[u8; 20],
    close_time: u64,
) -> Option<AmmPool> {
    load_amm_pool_with_fee_context(state, asset_in, asset_out, Some((account, close_time)))
}

fn load_amm_pool_with_fee_context(
    state: &LedgerState,
    asset_in: &Issue,
    asset_out: &Issue,
    fee_context: Option<(&[u8; 20], u64)>,
) -> Option<AmmPool> {
    if !supported_pair(asset_in, asset_out) {
        return None;
    }

    let key = amm_key(asset_in, asset_out);
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    let parsed = crate::ledger::meta::parse_sle(&raw)?;
    if parsed.entry_type != 0x0079 {
        return None;
    }

    let pseudo_account = parsed_account(&parsed.fields, 8, 1)?;
    let parsed_asset = parsed_issue(&parsed.fields, 24, 3);
    let parsed_asset2 = parsed_issue(&parsed.fields, 24, 4);
    if let (Some(lhs), Some(rhs)) = (parsed_asset.as_ref(), parsed_asset2.as_ref()) {
        if !pool_contains_issue(lhs, rhs, asset_in) || !pool_contains_issue(lhs, rhs, asset_out) {
            return None;
        }
    }

    let reserve_in = reserve_for_issue(state, &pseudo_account, asset_in)?;
    let reserve_out = reserve_for_issue(state, &pseudo_account, asset_out)?;
    if amount_is_zero(&reserve_in) || amount_is_zero(&reserve_out) {
        return None;
    }

    let trading_fee = parsed_u16(&parsed.fields, 1, 5)
        // Local synthetic AMMCreate historically wrote the wrong field. Keep a
        // fallback so existing tests/fixtures do not become unreadable.
        .or_else(|| parsed_u16(&parsed.fields, 1, 2))
        .unwrap_or(0);
    if trading_fee > 1000 {
        return None;
    }
    let trading_fee = fee_context
        .and_then(|(account, close_time)| {
            auction_discounted_fee(&parsed.fields, account, close_time)
        })
        .unwrap_or(trading_fee);

    Some(AmmPool {
        pseudo_account,
        asset_in: asset_in.clone(),
        asset_out: asset_out.clone(),
        reserve_in,
        reserve_out,
        trading_fee,
    })
}

fn auction_discounted_fee(
    fields: &[crate::ledger::meta::ParsedField],
    account: &[u8; 20],
    close_time: u64,
) -> Option<u16> {
    let auction_slot = parsed_field(fields, 14, 26)?;
    let info = parse_auction_slot(auction_slot)?;
    if close_time >= info.expiration as u64 {
        return None;
    }
    let account_is_authorized = info.account.as_ref() == Some(account)
        || info
            .auth_accounts
            .as_deref()
            .is_some_and(|auth_accounts| contains_account_field(auth_accounts, account));
    if !account_is_authorized {
        return None;
    }
    Some(info.discounted_fee.unwrap_or(0))
}

#[derive(Debug)]
struct AuctionSlotInfo {
    account: Option<[u8; 20]>,
    expiration: u32,
    discounted_fee: Option<u16>,
    auth_accounts: Option<Vec<u8>>,
}

fn parse_auction_slot(data: &[u8]) -> Option<AuctionSlotInfo> {
    let mut account = None::<[u8; 20]>;
    let mut expiration = None::<u32>;
    let mut discounted_fee = None::<u16>;
    let mut auth_accounts = None::<Vec<u8>>;
    let mut pos = 0usize;
    while pos < data.len() {
        if data[pos] == 0xE1 {
            break;
        }
        let (tc, fc, new_pos) = crate::ledger::meta::read_field_header(data, pos);
        if new_pos > data.len() {
            break;
        }
        pos = new_pos;
        match (tc, fc) {
            (1, 6) if pos + 2 <= data.len() => {
                discounted_fee = Some(u16::from_be_bytes(data[pos..pos + 2].try_into().ok()?));
                pos += 2;
            }
            (2, 10) if pos + 4 <= data.len() => {
                expiration = Some(u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?));
                pos += 4;
            }
            (8, 1) => {
                let (len, consumed) = crate::ledger::meta::decode_vl_length(data, pos);
                pos += consumed;
                if len == 20 && pos + 20 <= data.len() {
                    let mut id = [0u8; 20];
                    id.copy_from_slice(&data[pos..pos + 20]);
                    account = Some(id);
                }
                pos = pos.saturating_add(len).min(data.len());
            }
            (15, 25) => {
                let end = crate::ledger::meta::skip_field_raw(data, pos, tc);
                if end <= data.len() {
                    auth_accounts = Some(data[pos..end].to_vec());
                }
                pos = end.min(data.len());
            }
            _ => {
                let end = crate::ledger::meta::skip_field_raw(data, pos, tc);
                if end <= pos {
                    break;
                }
                pos = end.min(data.len());
            }
        }
    }
    Some(AuctionSlotInfo {
        account,
        expiration: expiration?,
        discounted_fee,
        auth_accounts,
    })
}

fn contains_account_field(data: &[u8], account: &[u8; 20]) -> bool {
    let mut pos = 0usize;
    while pos < data.len() {
        let marker = data[pos];
        if marker == 0xE1 || marker == 0xF1 {
            pos += 1;
            continue;
        }
        let (tc, fc, new_pos) = crate::ledger::meta::read_field_header(data, pos);
        if new_pos > data.len() {
            break;
        }
        pos = new_pos;
        if (tc, fc) == (8, 1) {
            let (len, consumed) = crate::ledger::meta::decode_vl_length(data, pos);
            pos += consumed;
            if len == 20 && pos + 20 <= data.len() && &data[pos..pos + 20] == account {
                return true;
            }
            pos = pos.saturating_add(len).min(data.len());
        } else {
            let end = crate::ledger::meta::skip_field_raw(data, pos, tc);
            if (tc == 14 || tc == 15)
                && end <= data.len()
                && contains_account_field(&data[pos..end], account)
            {
                return true;
            }
            if end <= pos {
                break;
            }
            pos = end.min(data.len());
        }
    }
    false
}

pub(crate) fn quote_exact_in(pool: &AmmPool, input: &Amount) -> Option<AmmQuote> {
    if !amount_matches_issue(input, &pool.asset_in) || amount_is_zero(input) {
        return None;
    }

    let effective_in = apply_fee_to_input(input, pool.trading_fee)?;
    if amount_is_zero(&effective_in) {
        return None;
    }

    let delivered_out = swap_asset_in(pool, &effective_in)?;

    if amount_is_zero(&delivered_out) {
        return None;
    }

    Some(AmmQuote {
        spent_in: input.clone(),
        delivered_out,
    })
}

pub(crate) fn quote_exact_out(pool: &AmmPool, want_out: &Amount) -> Option<AmmQuote> {
    if !amount_matches_issue(want_out, &pool.asset_out) || amount_is_zero(want_out) {
        return None;
    }

    let required_effective_in = swap_asset_out(pool, want_out)?;

    let spent_in = remove_fee_from_required_input(&required_effective_in, pool.trading_fee)?;
    if amount_is_zero(&spent_in) {
        return None;
    }

    Some(AmmQuote {
        spent_in,
        delivered_out: want_out.clone(),
    })
}

#[allow(dead_code)]
pub(crate) fn quote_fibonacci_offer(pool: &AmmPool, iteration: u16) -> Option<AmmQuote> {
    quote_fibonacci_offer_with_initial(pool, pool, iteration)
}

pub(crate) fn quote_fibonacci_offer_with_initial(
    pool: &AmmPool,
    initial_pool: &AmmPool,
    iteration: u16,
) -> Option<AmmQuote> {
    if iteration as usize >= AMM_MAX_FIB_ITERATIONS {
        return None;
    }
    if pool.asset_in != initial_pool.asset_in || pool.asset_out != initial_pool.asset_out {
        return None;
    }

    let initial_in = mul_amount_ratio(
        &initial_pool.reserve_in,
        INITIAL_FIB_SEQUENCE_NUMERATOR,
        INITIAL_FIB_SEQUENCE_DENOMINATOR,
        true,
    )?;
    let initial_quote = quote_exact_in(initial_pool, &initial_in)?;
    if iteration == 0 {
        return Some(initial_quote);
    }

    let scaled_out = mul_amount_ratio(
        &initial_quote.delivered_out,
        AMM_FIB_SEQUENCE[(iteration - 1) as usize],
        1,
        false,
    )?;
    if amount_is_zero(&scaled_out) || amount_leq(&pool.reserve_out, &scaled_out)? {
        return None;
    }
    quote_exact_out(pool, &scaled_out)
}

pub(crate) fn apply_swap_to_state(
    state: &mut LedgerState,
    pool: &AmmPool,
    quote: &AmmQuote,
    debit_input_from: &[u8; 20],
    credit_output_to: &[u8; 20],
) -> bool {
    apply_amount_delta(state, debit_input_from, AssetDelta::Debit, &quote.spent_in)
        && apply_amount_delta(
            state,
            &pool.pseudo_account,
            AssetDelta::Credit,
            &quote.spent_in,
        )
        && apply_amount_delta(
            state,
            &pool.pseudo_account,
            AssetDelta::Debit,
            &quote.delivered_out,
        )
        && apply_amount_delta(
            state,
            credit_output_to,
            AssetDelta::Credit,
            &quote.delivered_out,
        )
}

pub(crate) fn amount_leq(lhs: &Amount, rhs: &Amount) -> Option<bool> {
    if issue_from_amount(lhs)? != issue_from_amount(rhs)? {
        return None;
    }
    match (lhs, rhs) {
        (Amount::Xrp(a), Amount::Xrp(b)) => Some(a <= b),
        (Amount::Iou { value: a, .. }, Amount::Iou { value: b, .. }) => {
            Some(cmp_iou_positive(a, b)? != std::cmp::Ordering::Greater)
        }
        _ => None,
    }
}

#[allow(dead_code)] // Batch 9 uses this when AMM synthetic offers enter BookStep.
pub(crate) fn max_swap_output(pool: &AmmPool) -> Option<Amount> {
    match &pool.reserve_out {
        Amount::Xrp(drops) => Some(Amount::Xrp(floor_mul_div(*drops as u128, 99, 100)? as u64)),
        Amount::Iou {
            value,
            currency,
            issuer,
        } => Some(Amount::Iou {
            value: iou_mul_ratio(value, 99, 100, false)?,
            currency: currency.clone(),
            issuer: *issuer,
        }),
        Amount::Mpt(_) => None,
    }
}

#[allow(dead_code)]
pub(crate) fn spot_quality(pool: &AmmPool) -> Option<IouValue> {
    amm_quality_function(pool)
        .and_then(|qf| qf.spot_quality())
        .map(|quality| quality.rate())
}

#[allow(dead_code)]
pub(crate) fn spot_quality_close_or_worse_than(
    pool: &AmmPool,
    clob_quality: IouValue,
) -> Option<bool> {
    Some(
        amm_quality_function(pool)?
            .spot_quality_close_or_worse_than(super::flow::FlowQuality::new(clob_quality)),
    )
}

#[allow(dead_code)]
pub(crate) fn output_from_average_quality(pool: &AmmPool, quality: IouValue) -> Option<Amount> {
    let out = amm_quality_function(pool)?
        .out_from_average_quality(super::flow::FlowQuality::new(quality))?;
    Some(super::flow::iou_value_to_amount(&out, &pool.reserve_out))
}

#[allow(dead_code)]
pub(crate) fn output_to_clob_quality(pool: &AmmPool, clob_quality: IouValue) -> Option<Amount> {
    let out = amm_quality_function(pool)?
        .out_to_clob_quality(super::flow::FlowQuality::new(clob_quality))?;
    Some(super::flow::iou_value_to_amount(&out, &pool.reserve_out))
}

#[allow(dead_code)]
pub(crate) fn quote_to_clob_quality(pool: &AmmPool, clob_quality: IouValue) -> Option<AmmQuote> {
    let out = output_to_clob_quality(pool, clob_quality)?;
    quote_exact_out(pool, &out)
}

fn amm_quality_function(pool: &AmmPool) -> Option<super::flow::QualityFunction> {
    super::flow::QualityFunction::amm(&pool.reserve_in, &pool.reserve_out, pool.trading_fee)
}

fn supported_pair(asset_in: &Issue, asset_out: &Issue) -> bool {
    asset_in != asset_out
        && matches!(
            (asset_in, asset_out),
            (Issue::Xrp, Issue::Iou { .. })
                | (Issue::Iou { .. }, Issue::Xrp)
                | (Issue::Iou { .. }, Issue::Iou { .. })
        )
}

fn reserve_for_issue(
    state: &LedgerState,
    pseudo_account: &[u8; 20],
    issue: &Issue,
) -> Option<Amount> {
    match issue {
        Issue::Xrp => {
            let acct = state.get_account(pseudo_account)?;
            Some(Amount::Xrp(acct.balance))
        }
        Issue::Iou { currency, issuer } => {
            if issuer_global_frozen(state, issuer) {
                return None;
            }
            let key = crate::ledger::trustline::shamap_key(pseudo_account, issuer, currency);
            let tl = if let Some(existing) = state.get_trustline(&key) {
                existing.clone()
            } else {
                let raw = state
                    .get_raw_owned(&key)
                    .or_else(|| state.get_committed_raw_owned(&key))?;
                crate::ledger::RippleState::decode_from_sle(&raw)?
            };
            if trustline_frozen_by_issuer(&tl, issuer) || trustline_has_deep_freeze(&tl) {
                return None;
            }
            let value = tl.balance_for(pseudo_account);
            if value.mantissa < 0 {
                return None;
            }
            Some(Amount::Iou {
                value,
                currency: currency.clone(),
                issuer: *issuer,
            })
        }
        Issue::Mpt(_) => None,
    }
}

fn issuer_global_frozen(state: &LedgerState, issuer: &[u8; 20]) -> bool {
    state
        .get_account(issuer)
        .map(|account| (account.flags & crate::ledger::account::LSF_GLOBAL_FREEZE) != 0)
        .unwrap_or(false)
}

fn trustline_frozen_by_issuer(line: &crate::ledger::RippleState, issuer: &[u8; 20]) -> bool {
    if issuer == &line.low_account {
        (line.flags & crate::ledger::trustline::LSF_LOW_FREEZE) != 0
    } else if issuer == &line.high_account {
        (line.flags & crate::ledger::trustline::LSF_HIGH_FREEZE) != 0
    } else {
        false
    }
}

fn trustline_has_deep_freeze(line: &crate::ledger::RippleState) -> bool {
    (line.flags
        & (crate::ledger::trustline::LSF_LOW_DEEP_FREEZE
            | crate::ledger::trustline::LSF_HIGH_DEEP_FREEZE))
        != 0
}

fn pool_contains_issue(asset1: &Issue, asset2: &Issue, issue: &Issue) -> bool {
    asset1 == issue || asset2 == issue
}

fn amount_matches_issue(amount: &Amount, issue: &Issue) -> bool {
    issue_from_amount(amount).as_ref() == Some(issue)
}

fn amount_is_zero(amount: &Amount) -> bool {
    match amount {
        Amount::Xrp(drops) => *drops == 0,
        Amount::Iou { value, .. } => value.mantissa == 0,
        Amount::Mpt(raw) => raw.is_empty(),
    }
}

fn swap_asset_in(pool: &AmmPool, effective_input: &Amount) -> Option<Amount> {
    match (&pool.reserve_in, &pool.reserve_out, effective_input) {
        (
            Amount::Xrp(reserve_in),
            Amount::Iou {
                value: reserve_out,
                currency,
                issuer,
            },
            Amount::Xrp(effective_drops),
        ) => {
            let denom = (*reserve_in as u128).checked_add(*effective_drops as u128)?;
            let remaining = iou_mul_ratio(reserve_out, *reserve_in as u128, denom, true)?;
            Some(Amount::Iou {
                value: reserve_out.sub(&remaining),
                currency: currency.clone(),
                issuer: *issuer,
            })
        }
        (
            Amount::Iou {
                value: reserve_in, ..
            },
            Amount::Xrp(reserve_out),
            Amount::Iou {
                value: effective_iou,
                ..
            },
        ) => {
            let denom = reserve_in.add(effective_iou);
            let (num, den) = align_iou_pair(reserve_in, &denom)?;
            let remaining = ceil_mul_div(*reserve_out as u128, num, den)? as u64;
            Some(Amount::Xrp(reserve_out.saturating_sub(remaining)))
        }
        (
            Amount::Iou {
                value: reserve_in, ..
            },
            Amount::Iou {
                value: reserve_out,
                currency,
                issuer,
            },
            Amount::Iou {
                value: effective_iou,
                ..
            },
        ) => {
            let denom = reserve_in.add(effective_iou);
            let (num, den) = align_iou_pair(reserve_in, &denom)?;
            let remaining = iou_mul_ratio(reserve_out, num, den, true)?;
            Some(Amount::Iou {
                value: reserve_out.sub(&remaining),
                currency: currency.clone(),
                issuer: *issuer,
            })
        }
        _ => None,
    }
}

fn swap_asset_out(pool: &AmmPool, want_out: &Amount) -> Option<Amount> {
    match (&pool.reserve_in, &pool.reserve_out, want_out) {
        (
            Amount::Xrp(reserve_in),
            Amount::Iou {
                value: reserve_out, ..
            },
            Amount::Iou {
                value: want_iou, ..
            },
        ) => {
            if cmp_iou_positive(want_iou, reserve_out)? != std::cmp::Ordering::Less {
                return None;
            }
            let remaining_out = reserve_out.sub(want_iou);
            let (num, den) = align_iou_pair(reserve_out, &remaining_out)?;
            let ratio = ceil_mul_div(*reserve_in as u128, num, den)?;
            Some(Amount::Xrp(ratio.checked_sub(*reserve_in as u128)? as u64))
        }
        (
            Amount::Iou {
                value: reserve_in,
                currency,
                issuer,
            },
            Amount::Xrp(reserve_out),
            Amount::Xrp(want_drops),
        ) => {
            if *want_drops >= *reserve_out {
                return None;
            }
            let remaining_out = (*reserve_out - *want_drops) as u128;
            let ratio = iou_mul_ratio(reserve_in, *reserve_out as u128, remaining_out, true)?;
            Some(Amount::Iou {
                value: ratio.sub(reserve_in),
                currency: currency.clone(),
                issuer: *issuer,
            })
        }
        (
            Amount::Iou {
                value: reserve_in,
                currency,
                issuer,
            },
            Amount::Iou {
                value: reserve_out, ..
            },
            Amount::Iou {
                value: want_iou, ..
            },
        ) => {
            if cmp_iou_positive(want_iou, reserve_out)? != std::cmp::Ordering::Less {
                return None;
            }
            let remaining_out = reserve_out.sub(want_iou);
            let (num, den) = align_iou_pair(reserve_out, &remaining_out)?;
            let ratio = iou_mul_ratio(reserve_in, num, den, true)?;
            Some(Amount::Iou {
                value: ratio.sub(reserve_in),
                currency: currency.clone(),
                issuer: *issuer,
            })
        }
        _ => None,
    }
}

fn apply_fee_to_input(input: &Amount, trading_fee: u16) -> Option<Amount> {
    let factor = FEE_DENOMINATOR.checked_sub(trading_fee as u128)?;
    match input {
        Amount::Xrp(drops) => {
            Some(Amount::Xrp(
                floor_mul_div(*drops as u128, factor, FEE_DENOMINATOR)? as u64,
            ))
        }
        Amount::Iou {
            value,
            currency,
            issuer,
        } => Some(Amount::Iou {
            value: iou_mul_ratio(value, factor, FEE_DENOMINATOR, false)?,
            currency: currency.clone(),
            issuer: *issuer,
        }),
        Amount::Mpt(_) => None,
    }
}

fn mul_amount_ratio(amount: &Amount, num: u128, den: u128, round_up: bool) -> Option<Amount> {
    if den == 0 {
        return None;
    }
    match amount {
        Amount::Xrp(drops) => {
            let value = if round_up {
                ceil_mul_div(*drops as u128, num, den)?
            } else {
                floor_mul_div(*drops as u128, num, den)?
            };
            Some(Amount::Xrp(value as u64))
        }
        Amount::Iou {
            value,
            currency,
            issuer,
        } => Some(Amount::Iou {
            value: iou_mul_ratio(value, num, den, round_up)?,
            currency: currency.clone(),
            issuer: *issuer,
        }),
        Amount::Mpt(_) => None,
    }
}

fn remove_fee_from_required_input(required_effective: &Amount, trading_fee: u16) -> Option<Amount> {
    let factor = FEE_DENOMINATOR.checked_sub(trading_fee as u128)?;
    if factor == 0 {
        return None;
    }
    match required_effective {
        Amount::Xrp(drops) => {
            Some(Amount::Xrp(
                ceil_mul_div(*drops as u128, FEE_DENOMINATOR, factor)? as u64,
            ))
        }
        Amount::Iou {
            value,
            currency,
            issuer,
        } => Some(Amount::Iou {
            value: iou_mul_ratio(value, FEE_DENOMINATOR, factor, true)?,
            currency: currency.clone(),
            issuer: *issuer,
        }),
        Amount::Mpt(_) => None,
    }
}

fn iou_mul_ratio(value: &IouValue, num: u128, den: u128, round_up: bool) -> Option<IouValue> {
    if den == 0 {
        return None;
    }
    if value.mantissa == 0 || num == 0 {
        return Some(IouValue::ZERO);
    }

    const MIN_MANTISSA: u128 = 1_000_000_000_000_000;
    const MAX_MANTISSA: u128 = 9_999_999_999_999_999;

    let mut scaled = (value.mantissa as i128).unsigned_abs().checked_mul(num)?;
    let mut exponent = value.exponent;

    // Preserve XRPL decimal precision before dividing. Without this, ratios
    // that shrink an IOU value lose low-order digits before normalization.
    while scaled / den < MIN_MANTISSA {
        scaled = scaled.checked_mul(10)?;
        exponent = exponent.checked_sub(1)?;
    }

    let mut abs = scaled / den;
    if round_up && scaled % den != 0 {
        abs = abs.checked_add(1)?;
    }

    while abs > MAX_MANTISSA {
        let rem = abs % 10;
        abs /= 10;
        if round_up && rem != 0 {
            abs = abs.checked_add(1)?;
        }
        exponent = exponent.checked_add(1)?;
    }

    let signed = if value.mantissa < 0 {
        -(abs as i128)
    } else {
        abs as i128
    };
    if signed < i64::MIN as i128 || signed > i64::MAX as i128 {
        return None;
    }
    let mut out = IouValue {
        mantissa: signed as i64,
        exponent,
    };
    out.normalize();
    Some(out)
}

fn cmp_iou_positive(lhs: &IouValue, rhs: &IouValue) -> Option<std::cmp::Ordering> {
    let (l, r) = align_iou_pair(lhs, rhs)?;
    Some(l.cmp(&r))
}

fn align_iou_pair(lhs: &IouValue, rhs: &IouValue) -> Option<(u128, u128)> {
    if lhs.mantissa < 0 || rhs.mantissa < 0 {
        return None;
    }
    let exp = lhs.exponent.min(rhs.exponent);
    let lhs_scale = pow10((lhs.exponent - exp) as u32)?;
    let rhs_scale = pow10((rhs.exponent - exp) as u32)?;
    Some((
        (lhs.mantissa as u128).checked_mul(lhs_scale)?,
        (rhs.mantissa as u128).checked_mul(rhs_scale)?,
    ))
}

fn floor_mul_div(a: u128, b: u128, den: u128) -> Option<u128> {
    if den == 0 {
        return None;
    }
    Some(a.checked_mul(b)? / den)
}

fn ceil_mul_div(a: u128, b: u128, den: u128) -> Option<u128> {
    if den == 0 {
        return None;
    }
    let product = a.checked_mul(b)?;
    Some(product / den + u128::from(product % den != 0))
}

fn pow10(exp: u32) -> Option<u128> {
    let mut out = 1u128;
    for _ in 0..exp {
        out = out.checked_mul(10)?;
    }
    Some(out)
}

fn parsed_account(
    fields: &[crate::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<[u8; 20]> {
    let data = parsed_field(fields, type_code, field_code)?;
    if data.len() != 20 {
        return None;
    }
    data.as_slice().try_into().ok()
}

fn parsed_u16(
    fields: &[crate::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<u16> {
    let data = parsed_field(fields, type_code, field_code)?;
    if data.len() != 2 {
        return None;
    }
    Some(u16::from_be_bytes(data.as_slice().try_into().ok()?))
}

fn parsed_issue(
    fields: &[crate::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<Issue> {
    let data = parsed_field(fields, type_code, field_code)?;
    Issue::from_bytes(data).map(|(issue, _)| issue)
}

fn parsed_field(
    fields: &[crate::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<&Vec<u8>> {
    fields
        .iter()
        .find(|field| field.type_code == type_code && field.field_code == field_code)
        .map(|field| &field.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::amount::Currency;

    fn usd_issue() -> Issue {
        Issue::Iou {
            currency: Currency::from_code("USD").unwrap(),
            issuer: [0xAA; 20],
        }
    }

    fn usd_amount(value: f64) -> Amount {
        Amount::Iou {
            value: IouValue::from_f64(value),
            currency: Currency::from_code("USD").unwrap(),
            issuer: [0xAA; 20],
        }
    }

    fn usd_value(mantissa: i64, exponent: i32) -> Amount {
        Amount::Iou {
            value: IouValue { mantissa, exponent },
            currency: Currency::from_code("USD").unwrap(),
            issuer: [0xAA; 20],
        }
    }

    fn pool(asset_in: Issue, reserve_in: Amount, asset_out: Issue, reserve_out: Amount) -> AmmPool {
        AmmPool {
            pseudo_account: [0xBB; 20],
            asset_in,
            asset_out,
            reserve_in,
            reserve_out,
            trading_fee: 0,
        }
    }

    fn auction_fields(
        owner: [u8; 20],
        expiration: u32,
        discounted_fee: Option<u16>,
        auth_accounts: &[[u8; 20]],
    ) -> Vec<crate::ledger::meta::ParsedField> {
        let mut slot = Vec::new();
        if let Some(fee) = discounted_fee {
            crate::ledger::meta::write_field_header_pub(&mut slot, 1, 6);
            slot.extend_from_slice(&fee.to_be_bytes());
        }
        crate::ledger::meta::write_field_header_pub(&mut slot, 2, 10);
        slot.extend_from_slice(&expiration.to_be_bytes());
        crate::ledger::meta::write_field_header_pub(&mut slot, 8, 1);
        slot.push(20);
        slot.extend_from_slice(&owner);
        if !auth_accounts.is_empty() {
            crate::ledger::meta::write_field_header_pub(&mut slot, 15, 25);
            for account in auth_accounts {
                crate::ledger::meta::write_field_header_pub(&mut slot, 14, 27);
                crate::ledger::meta::write_field_header_pub(&mut slot, 8, 1);
                slot.push(20);
                slot.extend_from_slice(account);
                slot.push(0xE1);
            }
            slot.push(0xF1);
        }
        slot.push(0xE1);
        vec![crate::ledger::meta::ParsedField {
            type_code: 14,
            field_code: 26,
            data: slot,
        }]
    }

    #[test]
    fn exact_in_xrp_to_iou_rounds_output_down() {
        let pool = pool(
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
            usd_issue(),
            usd_amount(1_000.0),
        );

        let quote = quote_exact_in(&pool, &Amount::Xrp(100_000_000)).unwrap();

        match quote.delivered_out {
            Amount::Iou { value, .. } => {
                assert_eq!(value.mantissa, 9900990099010000);
                assert_eq!(value.exponent, -15);
            }
            other => panic!("unexpected output: {other:?}"),
        }
    }

    #[test]
    fn exact_out_iou_to_xrp_rounds_input_up() {
        let pool = pool(
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
            usd_issue(),
            usd_amount(1_000.0),
        );

        let quote = quote_exact_out(&pool, &usd_amount(10.0)).unwrap();

        assert_eq!(quote.spent_in, Amount::Xrp(101_010_102));
        assert_eq!(quote.delivered_out, usd_amount(10.0));
    }

    #[test]
    fn exact_in_iou_to_xrp_applies_fee_against_input() {
        let mut pool = pool(
            usd_issue(),
            usd_amount(1_000.0),
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
        );
        pool.trading_fee = 1000;

        let quote = quote_exact_in(&pool, &usd_amount(10.0)).unwrap();

        assert_eq!(quote.spent_in, usd_amount(10.0));
        assert_eq!(quote.delivered_out, Amount::Xrp(98_029_507));
    }

    #[test]
    fn exact_in_tiny_iou_returns_none_when_xrp_output_rounds_to_zero() {
        let pool = pool(
            usd_issue(),
            usd_amount(1_000.0),
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
        );

        assert!(quote_exact_in(&pool, &usd_value(1_000_000_000_000_000, -30)).is_none());
    }

    #[test]
    fn exact_out_rejects_entire_pool_output() {
        let pool = pool(
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
            usd_issue(),
            usd_amount(1_000.0),
        );

        assert!(quote_exact_out(&pool, &usd_amount(1_000.0)).is_none());
    }

    #[test]
    fn max_swap_output_matches_rippled_overflow_guard_shape() {
        let xrp_pool = pool(
            usd_issue(),
            usd_amount(1_000.0),
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
        );
        assert_eq!(max_swap_output(&xrp_pool), Some(Amount::Xrp(9_900_000_000)));

        let iou_pool = pool(
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
            usd_issue(),
            usd_amount(1_000.0),
        );
        assert_eq!(max_swap_output(&iou_pool), Some(usd_amount(990.0)));
    }

    #[test]
    fn fibonacci_offer_starts_at_initial_pool_fraction() {
        let pool = pool(
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
            usd_issue(),
            usd_amount(1_000.0),
        );

        let quote = quote_fibonacci_offer(&pool, 0).unwrap();

        assert_eq!(quote.spent_in, Amount::Xrp(2_500_000));
        assert!(!amount_is_zero(&quote.delivered_out));
    }

    #[test]
    fn fibonacci_offer_grows_and_stops_at_rippled_iteration_cap() {
        let pool = pool(
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
            usd_issue(),
            usd_amount(1_000.0),
        );

        let first = quote_fibonacci_offer(&pool, 0).unwrap();
        let third = quote_fibonacci_offer(&pool, 2).unwrap();

        assert_eq!(amount_leq(&first.spent_in, &third.spent_in), Some(true));
        assert_ne!(first.spent_in, third.spent_in);
        assert_eq!(
            amount_leq(&first.delivered_out, &third.delivered_out),
            Some(true)
        );
        assert_ne!(first.delivered_out, third.delivered_out);
        assert!(quote_fibonacci_offer(&pool, AMM_MAX_FIB_ITERATIONS as u16).is_none());
    }

    #[test]
    fn fibonacci_offer_uses_initial_pool_for_base_output_after_pool_moves() {
        let initial = pool(
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
            usd_issue(),
            usd_amount(1_000.0),
        );
        let current = pool(
            Issue::Xrp,
            Amount::Xrp(10_500_000_000),
            usd_issue(),
            usd_amount(952.5),
        );

        let initial_base = quote_fibonacci_offer(&initial, 0).unwrap();
        let rippled_style = quote_fibonacci_offer_with_initial(&current, &initial, 1).unwrap();
        let current_only = quote_fibonacci_offer(&current, 1).unwrap();

        assert_eq!(rippled_style.delivered_out, initial_base.delivered_out);
        assert_ne!(rippled_style.delivered_out, current_only.delivered_out);
    }

    #[test]
    fn auction_owner_gets_discounted_trading_fee_before_expiration() {
        let owner = [0x11; 20];
        let fields = auction_fields(owner, 200, Some(12), &[]);

        assert_eq!(auction_discounted_fee(&fields, &owner, 199), Some(12));
    }

    #[test]
    fn auction_authorized_account_gets_discounted_trading_fee() {
        let owner = [0x11; 20];
        let authorized = [0x22; 20];
        let fields = auction_fields(owner, 200, Some(25), &[authorized]);

        assert_eq!(auction_discounted_fee(&fields, &authorized, 100), Some(25));
    }

    #[test]
    fn auction_discount_expires_at_expiration_time() {
        let owner = [0x11; 20];
        let fields = auction_fields(owner, 200, Some(12), &[]);

        assert_eq!(auction_discounted_fee(&fields, &owner, 200), None);
    }

    #[test]
    fn auction_discount_does_not_apply_to_unlisted_account() {
        let owner = [0x11; 20];
        let stranger = [0x33; 20];
        let fields = auction_fields(owner, 200, Some(12), &[]);

        assert_eq!(auction_discounted_fee(&fields, &stranger, 199), None);
    }
}
