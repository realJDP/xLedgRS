//! Shared offer-crossing arithmetic.
//!
//! Rippled computes offer fills from the Quality rate stored in the book
//! directory key, not by re-deriving the rate from the offer's current amounts.
//! Partial fills can otherwise drift by a few mantissa bits.

use crate::transaction::amount::{Amount, IouValue};

const TEN_TO_17: u128 = 100_000_000_000_000_000;

/// Decode the stored rate from a book directory key. Returns the rate as an
/// `IouValue` representing `offerIn / offerOut`.
pub(crate) fn quality_rate_from_book_dir(book_directory: &[u8; 32]) -> IouValue {
    let mut q = [0u8; 8];
    q.copy_from_slice(&book_directory[24..32]);
    quality_rate_from_u64(u64::from_be_bytes(q))
}

pub(crate) fn quality_rate_from_u64(raw: u64) -> IouValue {
    if raw == 0 {
        return IouValue::ZERO;
    }
    let mantissa = (raw & 0x00FF_FFFF_FFFF_FFFF) as i64;
    let exponent = ((raw >> 56) as i32) - 100;
    IouValue { mantissa, exponent }
}

/// Normalize a u128 mantissa to the canonical 16-digit range [1e15, 1e16),
/// adjusting exponent. `round_up = true` rounds away from zero.
pub(crate) fn normalize_u128(mantissa_abs: u128, exp: i32, round_up: bool) -> (u128, i32) {
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

/// Convert an Amount to an IouValue for dimensionless canonical arithmetic.
pub(crate) fn amount_to_iou_value(a: &Amount) -> IouValue {
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

/// Convert an IouValue back to an Amount using `template` to choose the issue.
pub(crate) fn iou_value_to_amount(v: &IouValue, template: &Amount) -> Amount {
    iou_value_to_amount_with_rounding(v, template, false)
}

/// Convert an IouValue back to an Amount using `template` to choose the issue.
///
/// IOUs already carry decimal precision, but XRP has drop granularity. When a
/// strict quality calculation asks to round up an XRP side, preserve rippled's
/// ceil behavior instead of silently truncating fractional drops.
pub(crate) fn iou_value_to_amount_with_rounding(
    v: &IouValue,
    template: &Amount,
    round_up: bool,
) -> Amount {
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
                let q = m / scale;
                if round_up && m % scale != 0 {
                    q.saturating_add(1)
                } else {
                    q
                }
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

pub(crate) fn compare_iou_values(a: &IouValue, b: &IouValue) -> std::cmp::Ordering {
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

pub(crate) fn compare_amounts(a: &Amount, b: &Amount) -> std::cmp::Ordering {
    compare_iou_values(&amount_to_iou_value(a), &amount_to_iou_value(b))
}

pub(crate) fn zero_amount_like(amount: &Amount) -> Amount {
    match amount {
        Amount::Xrp(_) => Amount::Xrp(0),
        Amount::Iou {
            currency, issuer, ..
        } => Amount::Iou {
            value: IouValue::ZERO,
            currency: currency.clone(),
            issuer: *issuer,
        },
        Amount::Mpt(_) => amount.clone(),
    }
}

/// Rippled's `Quality::ceil_in_strict` subset: given an offer's (in, out) and
/// a limit on the IN side, compute the corresponding OUT side using stored
/// quality.
pub(crate) fn ceil_in_strict_via_quality(
    offer_in: &Amount,
    offer_out: &Amount,
    limit_in: &Amount,
    book_directory: &[u8; 32],
    round_up: bool,
) -> (Amount, Amount) {
    let limit_iou = amount_to_iou_value(limit_in);
    let offer_in_iou = amount_to_iou_value(offer_in);
    if compare_iou_values(&limit_iou, &offer_in_iou) != std::cmp::Ordering::Less {
        return (offer_in.clone(), offer_out.clone());
    }

    let rate = quality_rate_from_book_dir(book_directory);
    if rate.mantissa == 0 {
        return (offer_in.clone(), offer_out.clone());
    }

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

    let new_out = iou_value_to_amount_with_rounding(&new_out_iou, offer_out, round_up);
    let clamped_out = if compare_amounts(&new_out, offer_out) == std::cmp::Ordering::Greater {
        offer_out.clone()
    } else {
        new_out
    };
    (limit_in.clone(), clamped_out)
}

/// Rippled's `Quality::ceil_out_strict` subset: given an offer's (in, out)
/// and a limit on the OUT side, compute the corresponding IN side using stored
/// quality.
pub(crate) fn ceil_out_strict_via_quality(
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

    let new_in = iou_value_to_amount_with_rounding(&new_in_iou, offer_in, round_up);
    let clamped_in = if compare_amounts(&new_in, offer_in) == std::cmp::Ordering::Greater {
        offer_in.clone()
    } else {
        new_in
    };
    (clamped_in, limit_out.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{directory, BookKey};
    use crate::transaction::amount::{Currency, IouValue};

    fn usd(issuer: [u8; 20], value: f64) -> Amount {
        Amount::Iou {
            value: IouValue::from_f64(value),
            currency: Currency::from_code("USD").unwrap(),
            issuer,
        }
    }

    fn book_directory(offer_in: &Amount, offer_out: &Amount) -> [u8; 32] {
        let book_key = BookKey::from_amounts(offer_in, offer_out);
        let quality = directory::offer_quality(offer_out, offer_in);
        directory::book_dir_quality_key(&book_key, quality).0
    }

    #[test]
    fn exact_out_rounds_xrp_input_up_to_drops() {
        let issuer = [2u8; 20];
        let offer_in = Amount::Xrp(3);
        let offer_out = usd(issuer, 2.0);
        let dir = book_directory(&offer_in, &offer_out);

        let (input, output) =
            ceil_out_strict_via_quality(&offer_in, &offer_out, &usd(issuer, 1.0), &dir, true);

        assert_eq!(input, Amount::Xrp(2));
        assert_eq!(output, usd(issuer, 1.0));
    }

    #[test]
    fn exact_in_rounds_xrp_output_down_to_drops() {
        let issuer = [2u8; 20];
        let offer_in = usd(issuer, 2.0);
        let offer_out = Amount::Xrp(3);
        let dir = book_directory(&offer_in, &offer_out);

        let (input, output) =
            ceil_in_strict_via_quality(&offer_in, &offer_out, &usd(issuer, 1.0), &dir, false);

        assert_eq!(input, usd(issuer, 1.0));
        assert_eq!(output, Amount::Xrp(1));
    }

    #[test]
    fn strict_quality_outputs_are_clamped_to_offer_amounts() {
        let issuer = [2u8; 20];
        let offer_in = Amount::Xrp(3);
        let offer_out = usd(issuer, 2.0);
        let dir = book_directory(&offer_in, &offer_out);
        let almost_all = usd(issuer, 1.999999999999999);

        let (input, output) =
            ceil_out_strict_via_quality(&offer_in, &offer_out, &almost_all, &dir, true);

        assert!(compare_amounts(&input, &offer_in) != std::cmp::Ordering::Greater);
        assert!(compare_amounts(&output, &offer_out) != std::cmp::Ordering::Greater);
    }
}
