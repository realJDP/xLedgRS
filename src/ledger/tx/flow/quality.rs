use crate::transaction::amount::{Amount, IouValue};
use num_bigint::{BigInt, BigUint, Sign};

use super::{amount_to_iou_value, compare_iou_values};

const AMM_FEE_DENOMINATOR: u128 = 100_000;
const QUALITY_SCALE_U128: u128 = 1_000_000_000_000_000_000;
const AMM_QUALITY_RELATIVE_DISTANCE_NUMERATOR: u128 = 1;
const AMM_QUALITY_RELATIVE_DISTANCE_DENOMINATOR: u128 = 10_000_000;

/// Stored quality/rate wrapper used by flow steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlowQuality {
    rate: IouValue,
}

impl FlowQuality {
    pub(crate) const ONE: Self = Self {
        rate: IouValue {
            mantissa: 1_000_000_000_000_000,
            exponent: -15,
        },
    };

    pub(crate) fn new(rate: IouValue) -> Self {
        Self { rate }
    }

    pub(crate) fn from_amounts(input: &Amount, output: &Amount, round_up: bool) -> Option<Self> {
        let output = amount_to_iou_value(output);
        if output.mantissa <= 0 {
            return None;
        }
        let input = amount_to_iou_value(input);
        if input.mantissa <= 0 {
            return None;
        }
        Some(Self::new(input.div_round(&output, round_up)))
    }

    pub(crate) fn amm_spot(reserve_in: &Amount, reserve_out: &Amount) -> Option<Self> {
        let reserve_in = amount_to_iou_value(reserve_in);
        let reserve_out = amount_to_iou_value(reserve_out);
        if reserve_in.mantissa <= 0 || reserve_out.mantissa <= 0 {
            return None;
        }
        Some(Self::new(reserve_in.div_round(&reserve_out, true)))
    }

    pub(crate) fn rate(&self) -> IouValue {
        self.rate
    }

    pub(crate) fn compose(self, rhs: Self) -> Self {
        Self {
            rate: self.rate.mul_round(&rhs.rate, false),
        }
    }

    pub(crate) fn divide_by(self, rhs: Self) -> Option<Self> {
        if rhs.rate.mantissa <= 0 {
            return None;
        }
        Some(Self {
            rate: self.rate.div_round(&rhs.rate, true),
        })
    }

    pub(crate) fn checked_compose(self, rhs: Self) -> Option<Self> {
        if self.rate.mantissa <= 0 || rhs.rate.mantissa <= 0 {
            return None;
        }
        Some(Self {
            rate: self.rate.mul_round(&rhs.rate, true),
        })
    }

    pub(crate) fn not_worse_than(self, rhs: Self) -> bool {
        compare_iou_values(&self.rate, &rhs.rate) != std::cmp::Ordering::Greater
            || self.within_amm_quality_distance(rhs)
    }

    pub(crate) fn within_relative_distance_ratio(
        self,
        rhs: Self,
        numerator: u128,
        denominator: u128,
    ) -> bool {
        if self == rhs {
            return true;
        }
        if numerator == 0 || denominator == 0 {
            return false;
        }
        let Some(lhs) = iou_to_scaled(&self.rate) else {
            return false;
        };
        let Some(rhs) = iou_to_scaled(&rhs.rate) else {
            return false;
        };
        let diff = if lhs >= rhs { &lhs - &rhs } else { &rhs - &lhs };
        let max = if lhs > rhs { lhs } else { rhs };
        diff * BigInt::from(denominator) < max * BigInt::from(numerator)
    }

    pub(crate) fn within_amm_quality_distance(self, rhs: Self) -> bool {
        self.within_relative_distance_ratio(
            rhs,
            AMM_QUALITY_RELATIVE_DISTANCE_NUMERATOR,
            AMM_QUALITY_RELATIVE_DISTANCE_DENOMINATOR,
        )
    }
}

/// Constant quality descriptor reserved for strand scheduling hooks.
///
/// AMM variable-quality math is handled inside the active AMM step today; this
/// wrapper lets future schedulers expose that shape without changing FlowStep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QualityFunction {
    quality: FlowQuality,
    variable: Option<AmmQualityShape>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AmmQualityShape {
    reserve_in: IouValue,
    reserve_out: IouValue,
    fee_factor: IouValue,
}

impl QualityFunction {
    pub(crate) fn constant(quality: FlowQuality) -> Self {
        Self {
            quality,
            variable: None,
        }
    }

    /// Variable AMM average-cost quality for a single pool step.
    ///
    /// Local `FlowQuality` stores cost (`input / output`). For a constant
    /// product AMM, average cost for output `out` is:
    ///
    /// `reserve_in / ((reserve_out - out) * fee_factor)`.
    pub(crate) fn amm(reserve_in: &Amount, reserve_out: &Amount, trading_fee: u16) -> Option<Self> {
        let reserve_in = amount_to_iou_value(reserve_in);
        let reserve_out = amount_to_iou_value(reserve_out);
        if reserve_in.mantissa <= 0 || reserve_out.mantissa <= 0 {
            return None;
        }
        let fee_factor = fee_factor(trading_fee)?;
        if fee_factor.mantissa <= 0 {
            return None;
        }

        let spot = reserve_in
            .div_round(&reserve_out, true)
            .div_round(&fee_factor, true);
        Some(Self {
            quality: FlowQuality::new(spot),
            variable: Some(AmmQualityShape {
                reserve_in,
                reserve_out,
                fee_factor,
            }),
        })
    }

    pub(crate) fn quality(&self) -> FlowQuality {
        self.quality
    }

    pub(crate) fn scaled_by(mut self, factor: FlowQuality) -> Option<Self> {
        if factor.rate.mantissa <= 0 {
            return None;
        }
        self.quality = self.quality.checked_compose(factor)?;
        if let Some(shape) = self.variable.as_mut() {
            shape.reserve_in = shape.reserve_in.mul_round(&factor.rate, true);
        }
        Some(self)
    }

    /// AMM spot price quality at the current reserves, excluding trading fee.
    pub(crate) fn spot_quality(&self) -> Option<FlowQuality> {
        let shape = self.variable.as_ref()?;
        Some(FlowQuality::new(
            shape.reserve_in.div_round(&shape.reserve_out, true),
        ))
    }

    pub(crate) fn is_constant(&self) -> bool {
        self.variable.is_none()
    }

    pub(crate) fn is_variable(&self) -> bool {
        self.variable.is_some()
    }

    pub(crate) fn spot_quality_close_or_worse_than(&self, clob_quality: FlowQuality) -> bool {
        let Some(spot) = self.spot_quality() else {
            return false;
        };
        compare_iou_values(&spot.rate, &clob_quality.rate) != std::cmp::Ordering::Less
            || spot.within_amm_quality_distance(clob_quality)
    }

    pub(crate) fn out_from_average_quality(&self, quality: FlowQuality) -> Option<IouValue> {
        let shape = self.variable.as_ref()?;
        if quality.rate.mantissa <= 0 {
            return None;
        }

        let denominator = quality.rate.mul_round(&shape.fee_factor, false);
        if denominator.mantissa <= 0 {
            return None;
        }
        let remaining_out = shape.reserve_in.div_round(&denominator, true);
        let out = shape.reserve_out.sub(&remaining_out);
        if out.mantissa <= 0 {
            return None;
        }
        Some(out)
    }

    pub(crate) fn input_from_output(&self, output: IouValue) -> Option<IouValue> {
        if output.mantissa <= 0 {
            return None;
        }
        let Some(shape) = self.variable.as_ref() else {
            return Some(output.mul_round(&self.quality.rate, true));
        };
        if compare_iou_values(&output, &shape.reserve_out) != std::cmp::Ordering::Less {
            return None;
        }
        let remaining_out = shape.reserve_out.sub(&output);
        if remaining_out.mantissa <= 0 {
            return None;
        }
        let denominator = remaining_out.mul_round(&shape.fee_factor, false);
        if denominator.mantissa <= 0 {
            return None;
        }
        let ratio = output.div_round(&denominator, true);
        if ratio.mantissa <= 0 {
            return None;
        }
        Some(shape.reserve_in.mul_round(&ratio, true))
    }

    pub(crate) fn out_from_composed_average_quality(
        functions: &[QualityFunction],
        limit_quality: FlowQuality,
        max_out: IouValue,
    ) -> Option<IouValue> {
        if functions.is_empty() || limit_quality.rate.mantissa <= 0 || max_out.mantissa <= 0 {
            return None;
        }
        if composed_quality_not_worse_than(functions, max_out, limit_quality) {
            return Some(max_out);
        }

        let mut lo = BigInt::from(0u8);
        let mut hi = iou_to_scaled(&max_out)?;
        while (&hi - &lo) > BigInt::from(1u8) {
            let mid = (&lo + &hi) / 2u8;
            let Some(mid_out) = scaled_to_iou_floor(&mid) else {
                hi = mid;
                continue;
            };
            if composed_quality_not_worse_than(functions, mid_out, limit_quality) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        scaled_to_iou_floor(&lo)
    }

    /// Output that moves post-trade AMM spot price quality up to `quality`.
    ///
    /// Local quality is cost (`input / output`). The returned output is also
    /// capped by the average/effective-quality solution so the AMM offer does
    /// not become worse than the competing CLOB quality.
    pub(crate) fn out_from_spot_quality(&self, quality: FlowQuality) -> Option<IouValue> {
        let shape = self.variable.as_ref()?;
        let reserve_in = iou_to_scaled(&shape.reserve_in)?;
        let reserve_out = iou_to_scaled(&shape.reserve_out)?;
        let fee_factor = iou_to_scaled(&shape.fee_factor)?;
        let target = iou_to_scaled(&quality.rate)?;
        if reserve_in.sign() != Sign::Plus
            || reserve_out.sign() != Sign::Plus
            || fee_factor.sign() != Sign::Plus
            || target.sign() != Sign::Plus
        {
            return None;
        }

        let scale = BigInt::from(QUALITY_SCALE_U128);
        let one_minus_inverse_fee = &scale - (&scale * &scale / &fee_factor);
        let b = ((&reserve_in * one_minus_inverse_fee / &scale) * &scale / &target)
            - (&reserve_out * 2u8);
        let c = (&reserve_out * &reserve_out / &scale) - (&reserve_in * &reserve_out / &target);
        let discriminant = (&b * &b / &scale) - (&c * 4u8);
        if discriminant.sign() == Sign::Minus {
            return None;
        }
        let root = BigInt::from(biguint_sqrt_floor(
            &(discriminant.to_biguint()? * BigUint::from(QUALITY_SCALE_U128)),
        ));
        let roots = [((-&b - &root) / 2u8), ((-&b + &root) / 2u8)];
        let mut spot_out = roots
            .into_iter()
            .filter(|value| value.sign() == Sign::Plus && value < &reserve_out)
            .min()?;
        if spot_out.sign() != Sign::Plus {
            return None;
        }

        let avg_out = self.out_from_average_quality(quality)?;
        let avg_out = iou_to_scaled(&avg_out)?;
        if avg_out.sign() != Sign::Plus {
            return None;
        }
        if avg_out < spot_out {
            spot_out = avg_out;
        }
        if spot_out.sign() != Sign::Plus || spot_out >= reserve_out {
            return None;
        }
        scaled_to_iou_floor(&spot_out)
    }

    pub(crate) fn out_to_clob_quality(&self, clob_quality: FlowQuality) -> Option<IouValue> {
        if self.spot_quality_close_or_worse_than(clob_quality) {
            return None;
        }
        self.out_from_spot_quality(clob_quality)
    }
}

fn composed_quality_not_worse_than(
    functions: &[QualityFunction],
    final_out: IouValue,
    limit_quality: FlowQuality,
) -> bool {
    let Some(input) = composed_input_for_output(functions, final_out) else {
        return false;
    };
    if input.mantissa <= 0 || final_out.mantissa <= 0 {
        return false;
    }
    let quality = FlowQuality::new(input.div_round(&final_out, true));
    compare_iou_values(&quality.rate, &limit_quality.rate) != std::cmp::Ordering::Greater
}

fn composed_input_for_output(
    functions: &[QualityFunction],
    final_out: IouValue,
) -> Option<IouValue> {
    let mut required = final_out;
    for function in functions.iter().rev() {
        required = function.input_from_output(required)?;
    }
    Some(required)
}

fn iou_to_scaled(value: &IouValue) -> Option<BigInt> {
    if value.mantissa <= 0 {
        return None;
    }
    let exponent = value.exponent + 18;
    let mantissa = BigInt::from(value.mantissa);
    if exponent >= 0 {
        Some(mantissa * BigInt::from(10u8).pow(exponent as u32))
    } else {
        Some(mantissa / BigInt::from(10u8).pow((-exponent) as u32))
    }
}

fn scaled_to_iou_floor(value: &BigInt) -> Option<IouValue> {
    if value.sign() != Sign::Plus {
        return None;
    }
    let mut mantissa = value.to_biguint()?;
    let mut exponent = -18i32;
    let min = BigUint::from(1_000_000_000_000_000u64);
    let max = BigUint::from(9_999_999_999_999_999u64);
    while mantissa > max {
        mantissa /= 10u8;
        exponent += 1;
    }
    while mantissa < min {
        mantissa *= 10u8;
        exponent -= 1;
    }
    Some(IouValue {
        mantissa: mantissa.to_u64_digits().first().copied()? as i64,
        exponent,
    })
}

fn biguint_sqrt_floor(n: &BigUint) -> BigUint {
    if n <= &BigUint::from(1u8) {
        return n.clone();
    }
    let two = BigUint::from(2u8);
    let mut x0 = n.clone();
    let mut x1 = (&x0 + n / &x0) / &two;
    while x1 < x0 {
        x0 = x1;
        x1 = (&x0 + n / &x0) / &two;
    }
    x0
}

fn fee_factor(trading_fee: u16) -> Option<IouValue> {
    let numerator = AMM_FEE_DENOMINATOR.checked_sub(trading_fee as u128)?;
    if numerator == 0 {
        return None;
    }
    let mut factor = IouValue {
        mantissa: numerator as i64,
        exponent: 0,
    }
    .div_round(
        &IouValue {
            mantissa: AMM_FEE_DENOMINATOR as i64,
            exponent: 0,
        },
        false,
    );
    factor.normalize();
    Some(factor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::amount::{Currency, IouValue};

    fn usd_amount(value: f64) -> Amount {
        Amount::Iou {
            value: IouValue::from_f64(value),
            currency: Currency::from_code("USD").unwrap(),
            issuer: [0xAA; 20],
        }
    }

    fn iou_value(mantissa: i64, exponent: i32) -> IouValue {
        IouValue { mantissa, exponent }
    }

    #[test]
    fn amm_quality_function_finds_output_for_average_cost() {
        let qf = QualityFunction::amm(&usd_amount(100.0), &usd_amount(100.0), 0).unwrap();
        let out = qf
            .out_from_average_quality(FlowQuality::new(IouValue::from_f64(2.0)))
            .unwrap();

        assert_eq!(out, IouValue::from_f64(50.0));
        assert!(!qf.is_constant());
    }

    #[test]
    fn amm_quality_function_rejects_quality_better_than_spot() {
        let qf = QualityFunction::amm(&usd_amount(100.0), &usd_amount(100.0), 0).unwrap();

        assert!(qf
            .out_from_average_quality(FlowQuality::new(IouValue::from_f64(0.5)))
            .is_none());
    }

    #[test]
    fn amm_quality_function_finds_output_for_spot_boundary_without_float() {
        let qf = QualityFunction::amm(&usd_amount(100.0), &usd_amount(100.0), 0).unwrap();
        let out = qf
            .out_from_spot_quality(FlowQuality::new(iou_value(2_000_000_000_000_000, -15)))
            .unwrap();

        assert_eq!(
            compare_iou_values(&out, &iou_value(2_900_000_000_000_000, -14)),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_iou_values(&out, &iou_value(3_000_000_000_000_000, -14)),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn amm_quality_distance_uses_scaled_integer_ratio() {
        let lhs = FlowQuality::new(iou_value(9_007_199_254_740_993, -15));
        let rhs = FlowQuality::new(iou_value(9_007_199_254_740_994, -15));

        assert!(lhs.within_amm_quality_distance(rhs));
    }

    #[test]
    fn constant_quality_function_has_no_variable_limit() {
        let qf = QualityFunction::constant(FlowQuality::ONE);

        assert!(qf.is_constant());
        assert!(qf.out_from_average_quality(FlowQuality::ONE).is_none());
    }

    #[test]
    fn composed_quality_function_solves_multiple_amm_steps() {
        let functions = vec![
            QualityFunction::amm(&usd_amount(100.0), &usd_amount(100.0), 0).unwrap(),
            QualityFunction::amm(&usd_amount(100.0), &usd_amount(100.0), 0).unwrap(),
        ];

        let out = QualityFunction::out_from_composed_average_quality(
            &functions,
            FlowQuality::new(IouValue::from_f64(2.0)),
            IouValue::from_f64(50.0),
        )
        .unwrap();

        assert_eq!(
            compare_iou_values(&out, &IouValue::from_f64(24.999)),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_iou_values(&out, &IouValue::from_f64(25.001)),
            std::cmp::Ordering::Less
        );
    }
}
