//! Single AMM liquidity step for Payment/OfferCreate.
//!
//! This module intentionally does not implement AMM transaction lifecycle.
//! It reads an existing AMM pool and applies one XRP/IOU swap using real pool
//! reserves from the pseudo AccountRoot and pseudo/issuer RippleState.

use super::amm::amm_key;
use super::asset_flow::{apply_amount_delta, AssetDelta};
use super::load_existing_account;
use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, IouValue, Issue};

const FEE_DENOMINATOR: u128 = 100_000;

#[derive(Clone, Debug)]
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
    state: &mut LedgerState,
    asset_in: &Issue,
    asset_out: &Issue,
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

    Some(AmmPool {
        pseudo_account,
        asset_in: asset_in.clone(),
        asset_out: asset_out.clone(),
        reserve_in,
        reserve_out,
        trading_fee,
    })
}

pub(crate) fn quote_exact_in(pool: &AmmPool, input: &Amount) -> Option<AmmQuote> {
    if !amount_matches_issue(input, &pool.asset_in) || amount_is_zero(input) {
        return None;
    }

    let effective_in = apply_fee_to_input(input, pool.trading_fee)?;
    if amount_is_zero(&effective_in) {
        return None;
    }

    let delivered_out = match (&pool.reserve_in, &pool.reserve_out, &effective_in) {
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
            let value = iou_mul_ratio(reserve_out, *effective_drops as u128, denom, false)?;
            Amount::Iou {
                value,
                currency: currency.clone(),
                issuer: *issuer,
            }
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
            let (num, den) = align_iou_pair(effective_iou, &denom)?;
            Amount::Xrp(floor_mul_div(*reserve_out as u128, num, den)? as u64)
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
            let (num, den) = align_iou_pair(effective_iou, &denom)?;
            let value = iou_mul_ratio(reserve_out, num, den, false)?;
            Amount::Iou {
                value,
                currency: currency.clone(),
                issuer: *issuer,
            }
        }
        _ => return None,
    };

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

    let required_effective_in = match (&pool.reserve_in, &pool.reserve_out, want_out) {
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
            let (num, den) = align_iou_pair(want_iou, &remaining_out)?;
            Amount::Xrp(ceil_mul_div(*reserve_in as u128, num, den)? as u64)
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
            let value = iou_mul_ratio(reserve_in, *want_drops as u128, remaining_out, true)?;
            Amount::Iou {
                value,
                currency: currency.clone(),
                issuer: *issuer,
            }
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
            let (num, den) = align_iou_pair(want_iou, &remaining_out)?;
            let value = iou_mul_ratio(reserve_in, num, den, true)?;
            Amount::Iou {
                value,
                currency: currency.clone(),
                issuer: *issuer,
            }
        }
        _ => return None,
    };

    let spent_in = remove_fee_from_required_input(&required_effective_in, pool.trading_fee)?;
    if amount_is_zero(&spent_in) {
        return None;
    }

    Some(AmmQuote {
        spent_in,
        delivered_out: want_out.clone(),
    })
}

pub(crate) fn apply_swap_to_state(
    state: &mut LedgerState,
    pool: &AmmPool,
    quote: &AmmQuote,
    debit_input_from: &[u8; 20],
    credit_output_to: &[u8; 20],
) {
    apply_amount_delta(state, debit_input_from, AssetDelta::Debit, &quote.spent_in);
    apply_amount_delta(
        state,
        &pool.pseudo_account,
        AssetDelta::Credit,
        &quote.spent_in,
    );
    apply_amount_delta(
        state,
        &pool.pseudo_account,
        AssetDelta::Debit,
        &quote.delivered_out,
    );
    apply_amount_delta(
        state,
        credit_output_to,
        AssetDelta::Credit,
        &quote.delivered_out,
    );
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
    state: &mut LedgerState,
    pseudo_account: &[u8; 20],
    issue: &Issue,
) -> Option<Amount> {
    match issue {
        Issue::Xrp => {
            let acct = load_existing_account(state, pseudo_account)?;
            Some(Amount::Xrp(acct.balance))
        }
        Issue::Iou { currency, issuer } => {
            let key = crate::ledger::trustline::shamap_key(pseudo_account, issuer, currency);
            let tl = if let Some(existing) = state.get_trustline(&key) {
                existing.clone()
            } else {
                let raw = state
                    .get_raw_owned(&key)
                    .or_else(|| state.get_committed_raw_owned(&key))?;
                let decoded = crate::ledger::RippleState::decode_from_sle(&raw)?;
                state.hydrate_trustline(decoded.clone());
                decoded
            };
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
                assert_eq!(value.mantissa, 9900990099009900);
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
}
