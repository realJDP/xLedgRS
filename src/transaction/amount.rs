//! XRPL Amount type — XRP (drops) or IOU (value + currency + issuer).
//!
//! Binary encoding:
//!
//! **XRP drops** (8 bytes):
//!   bit 63 = 0  (not IOU)
//!   bit 62 = 1  (positive; 0 would be negative, illegal for fees/amounts)
//!   bits 61-0 = drop count (u62)
//!
//! **IOU** (48 bytes total):
//!   8 bytes: IEEE-754-like mantissa+exponent with XRPL-specific encoding
//!   20 bytes: currency code (ASCII left-aligned, zero-padded)
//!   20 bytes: issuer AccountID

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Currency {
    /// 3-character ISO 4217 code, e.g. "USD", "EUR", or 20-byte hex for non-standard.
    pub code: [u8; 20],
}

impl Currency {
    /// Create a standard 3-letter currency (e.g. "USD").
    pub fn from_code(code: &str) -> Result<Self, AmountError> {
        let bytes = code.as_bytes();
        if bytes.len() != 3
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"<>(){}[]|?!@#$%^&*".contains(b))
        {
            return Err(AmountError::InvalidCurrency(code.to_string()));
        }
        let mut arr = [0u8; 20];
        arr[12] = bytes[0];
        arr[13] = bytes[1];
        arr[14] = bytes[2];
        Ok(Self { code: arr })
    }

    /// XRP's special "currency" (all zeros).
    pub fn xrp() -> Self {
        Self { code: [0u8; 20] }
    }

    pub fn is_xrp(&self) -> bool {
        self.code == [0u8; 20]
    }

    pub fn to_ascii(&self) -> String {
        // Standard 3-letter codes live at bytes 12-14
        let s = std::str::from_utf8(&self.code[12..15])
            .unwrap_or("???")
            .trim_matches('\0');
        if s.is_empty() {
            hex::encode(self.code)
        } else {
            s.to_string()
        }
    }
}

/// An asset issue — identifies an asset type without an amount.
/// Used in AMM and other contexts where the asset pair is specified.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Issue {
    /// XRP (native).
    Xrp,
    /// IOU: currency + issuer account.
    Iou {
        currency: Currency,
        issuer: [u8; 20],
    },
    /// MPT: 24-byte MPTID.
    Mpt([u8; 24]),
}

impl Issue {
    /// Serialize to wire format (matching rippled's STIssue serialization).
    /// XRP: 20 zero bytes. IOU: 20 currency + 20 account. MPT: 20 issuer + 20 zeros + 4 seq.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Issue::Xrp => vec![0u8; 20],
            Issue::Iou { currency, issuer } => {
                let mut out = Vec::with_capacity(40);
                out.extend_from_slice(&currency.code);
                out.extend_from_slice(issuer);
                out
            }
            Issue::Mpt(mptid) => {
                // MPT wire format: issuer(20) + zeros(20) + sequence(4)
                let mut out = Vec::with_capacity(44);
                out.extend_from_slice(&mptid[4..24]); // issuer = bytes 4..24 of MPTID
                out.extend_from_slice(&[0u8; 20]); // zero account = MPT marker
                out.extend_from_slice(&mptid[0..4]); // sequence = bytes 0..4 of MPTID
                out
            }
        }
    }

    /// Parse from wire bytes.
    pub fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 20 {
            return None;
        }
        let first_20: [u8; 20] = data[..20].try_into().ok()?;

        // XRP: first 20 bytes are all zeros
        if first_20 == [0u8; 20] {
            return Some((Issue::Xrp, 20));
        }

        // Need at least 40 bytes for IOU/MPT
        if data.len() < 40 {
            return None;
        }
        let second_20: [u8; 20] = data[20..40].try_into().ok()?;

        // MPT: second 20 bytes are all zeros (noAccount marker)
        if second_20 == [0u8; 20] {
            if data.len() < 44 {
                return None;
            }
            let seq = u32::from_be_bytes(data[40..44].try_into().ok()?);
            let mut mptid = [0u8; 24];
            mptid[0..4].copy_from_slice(&seq.to_be_bytes());
            mptid[4..24].copy_from_slice(&first_20);
            return Some((Issue::Mpt(mptid), 44));
        }

        // IOU: currency(20) + account(20)
        Some((
            Issue::Iou {
                currency: Currency { code: first_20 },
                issuer: second_20,
            },
            40,
        ))
    }

    /// Is this XRP?
    pub fn is_xrp(&self) -> bool {
        matches!(self, Issue::Xrp)
    }
}

/// An XRPL amount: either XRP (in drops), an IOU, or an MPT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Amount {
    /// XRP in drops (1 XRP = 1,000,000 drops). Max ~1e17 drops.
    Xrp(u64),
    /// IOU with a decimal value, currency, and issuer AccountID.
    Iou {
        value: IouValue,
        currency: Currency,
        issuer: [u8; 20],
    },
    /// MPT (Multi-Purpose Token) amount — stored as opaque 33 bytes.
    Mpt(Vec<u8>),
}

impl Amount {
    const MPT_HEADER: u8 = 0x60;

    pub fn xrp_drops(drops: u64) -> Self {
        Amount::Xrp(drops)
    }

    pub fn from_xrp(xrp: f64) -> Self {
        Amount::Xrp((xrp * 1_000_000.0) as u64)
    }

    /// Construct an MPT amount from a holder amount and issuance id.
    pub fn from_mpt_value(value: u64, mptid: [u8; 24]) -> Self {
        let mut raw = Vec::with_capacity(33);
        raw.push(Self::MPT_HEADER);
        raw.extend_from_slice(&value.to_be_bytes());
        raw.extend_from_slice(&mptid);
        Amount::Mpt(raw)
    }

    /// Decode an MPT amount into `(value, issuance_id)`.
    pub fn mpt_parts(&self) -> Option<(u64, [u8; 24])> {
        match self {
            Amount::Mpt(raw) => Self::decode_mpt_bytes(raw),
            _ => None,
        }
    }

    /// Decode the raw 33-byte MPT wire format into `(value, issuance_id)`.
    pub fn decode_mpt_bytes(raw: &[u8]) -> Option<(u64, [u8; 24])> {
        if raw.len() < 33 || raw[0] != Self::MPT_HEADER {
            return None;
        }
        let value = u64::from_be_bytes(raw[1..9].try_into().ok()?);
        let mut mptid = [0u8; 24];
        mptid.copy_from_slice(&raw[9..33]);
        Some((value, mptid))
    }

    /// Encode to XRPL binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Amount::Xrp(drops) => encode_xrp_drops(*drops),
            Amount::Iou {
                value,
                currency,
                issuer,
            } => {
                let mut buf = Vec::with_capacity(48);
                buf.extend_from_slice(&value.to_bytes());
                buf.extend_from_slice(&currency.code);
                buf.extend_from_slice(issuer);
                buf
            }
            Amount::Mpt(raw) => raw.to_vec(),
        }
    }

    /// Decode from XRPL binary (consumes 8 bytes for XRP, 48 for IOU, 33 for MPT).
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), AmountError> {
        if data.is_empty() {
            return Err(AmountError::TooShort);
        }
        let is_iou = (data[0] & 0x80) != 0;
        if is_iou {
            if data.len() < 48 {
                return Err(AmountError::TooShort);
            }
            let value = IouValue::from_bytes(&data[..8])?;
            let mut currency_code = [0u8; 20];
            currency_code.copy_from_slice(&data[8..28]);
            let mut issuer = [0u8; 20];
            issuer.copy_from_slice(&data[28..48]);
            Ok((
                Amount::Iou {
                    value,
                    currency: Currency {
                        code: currency_code,
                    },
                    issuer,
                },
                48,
            ))
        } else {
            // Bit 63 clear — check bit 61 for MPT
            let is_mpt = (data[0] & 0x20) != 0;
            if is_mpt {
                if data.len() < 33 {
                    return Err(AmountError::TooShort);
                }
                Ok((Amount::Mpt(data[..33].to_vec()), 33))
            } else {
                if data.len() < 8 {
                    return Err(AmountError::TooShort);
                }
                let raw = u64::from_be_bytes(data[..8].try_into().unwrap());
                let drops = raw & 0x1FFF_FFFF_FFFF_FFFF; // strip top 3 bits (IOU/sign/MPT)
                Ok((Amount::Xrp(drops), 8))
            }
        }
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Amount::Xrp(drops) => write!(f, "{} drops", drops),
            Amount::Iou {
                value, currency, ..
            } => {
                write!(f, "{} {}", value, currency.to_ascii())
            }
            Amount::Mpt(raw) => write!(f, "MPT({})", hex::encode(raw)),
        }
    }
}

// ── XRP encoding ─────────────────────────────────────────────────────────────

fn encode_xrp_drops(drops: u64) -> Vec<u8> {
    // bit 63 = 0 (XRP), bit 62 = 1 (positive)
    let encoded = 0x4000_0000_0000_0000_u64 | drops;
    encoded.to_be_bytes().to_vec()
}

// ── IOU value encoding ───────────────────────────────────────────────────────

/// An IOU decimal value with XRPL's mantissa/exponent encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub struct IouValue {
    pub mantissa: i64,
    pub exponent: i32,
}

impl IouValue {
    pub const ZERO: Self = Self {
        mantissa: 0,
        exponent: 0,
    };

    /// Create a value from a floating-point number (best effort precision).
    pub fn from_f64(v: f64) -> Self {
        if v == 0.0 {
            return Self::ZERO;
        }
        // Normalize: mantissa in [1e15, 1e16), exponent adjusted
        let sign = if v < 0.0 { -1i64 } else { 1i64 };
        let mut abs = v.abs();
        let mut exp = 0i32;
        while abs < 1e15 {
            abs *= 10.0;
            exp -= 1;
        }
        while abs >= 1e16 {
            abs /= 10.0;
            exp += 1;
        }
        Self {
            mantissa: sign * abs as i64,
            exponent: exp,
        }
    }

    /// Encode to XRPL's 8-byte IOU amount encoding.
    ///
    /// bit 63 = 1  (IOU, not XRP)
    /// bit 62 = sign (1 = positive, 0 = negative)
    /// bits 61-54 = exponent + 97 (biased by 97, range -96..+80)
    /// bits 53-0  = mantissa (unsigned, 54 bits)
    pub fn to_bytes(&self) -> [u8; 8] {
        if self.mantissa == 0 {
            // Canonical zero for IOU
            return 0x8000_0000_0000_0000_u64.to_be_bytes();
        }

        // Normalize mantissa into the valid range [1e15, 1e16-1]
        let positive = self.mantissa > 0;
        let mut abs_m = self.mantissa.unsigned_abs();
        let mut exp = self.exponent;

        // Shift mantissa into valid range
        while abs_m < 1_000_000_000_000_000 && abs_m != 0 {
            abs_m *= 10;
            exp -= 1;
        }
        while abs_m > 9_999_999_999_999_999 {
            abs_m /= 10;
            exp += 1;
        }

        // If exponent is out of range after normalization, return canonical zero
        if exp < -96 || exp > 80 || abs_m < 1_000_000_000_000_000 {
            return 0x8000_0000_0000_0000_u64.to_be_bytes();
        }

        let biased_exp = (exp + 97) as u64;

        let mut val: u64 = 0x8000_0000_0000_0000; // bit 63 = IOU
        if positive {
            val |= 0x4000_0000_0000_0000;
        } // bit 62 = sign
        val |= (biased_exp & 0xFF) << 54;
        val |= abs_m & 0x003F_FFFF_FFFF_FFFF;
        val.to_be_bytes()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, AmountError> {
        if data.len() < 8 {
            return Err(AmountError::TooShort);
        }
        let raw = u64::from_be_bytes(data[..8].try_into().unwrap());
        // Canonical zero
        if raw == 0x8000_0000_0000_0000 {
            return Ok(Self::ZERO);
        }
        let positive = (raw & 0x4000_0000_0000_0000) != 0;
        let biased_exp = ((raw >> 54) & 0xFF) as i32;
        let mantissa = (raw & 0x003F_FFFF_FFFF_FFFF) as i64;
        let exponent = biased_exp - 97;
        let signed_mantissa = if positive { mantissa } else { -mantissa };
        Ok(Self {
            mantissa: signed_mantissa,
            exponent,
        })
    }
}

impl IouValue {
    /// Normalize mantissa into [1e15, 1e16-1] range, adjusting exponent.
    pub fn normalize(&mut self) {
        if self.mantissa == 0 {
            self.exponent = 0;
            return;
        }
        let mut abs = self.mantissa.unsigned_abs();
        while abs < 1_000_000_000_000_000 && abs != 0 {
            abs *= 10;
            self.exponent -= 1;
        }
        while abs > 9_999_999_999_999_999 {
            // Truncate toward zero — matches rippled's canonicalize direction
            // (Number::normalize in Number.cpp). No rounding.
            abs /= 10;
            self.exponent += 1;
        }
        self.mantissa = if self.mantissa < 0 {
            -(abs as i64)
        } else {
            abs as i64
        };
    }

    pub fn is_zero(&self) -> bool {
        self.mantissa == 0
    }

    pub fn is_negative(&self) -> bool {
        self.mantissa < 0
    }

    pub fn is_positive(&self) -> bool {
        self.mantissa > 0
    }

    pub fn abs(&self) -> Self {
        Self {
            mantissa: self.mantissa.abs(),
            exponent: self.exponent,
        }
    }

    pub fn negate(&self) -> Self {
        Self {
            mantissa: -self.mantissa,
            exponent: self.exponent,
        }
    }

    /// Convert to f64 (lossy, for comparisons and quality calculations).
    pub fn to_f64(&self) -> f64 {
        if self.mantissa == 0 {
            return 0.0;
        }
        self.mantissa as f64 * 10f64.powi(self.exponent)
    }

    /// Add two IOU values.
    pub fn add(&self, other: &Self) -> Self {
        if self.mantissa == 0 {
            return *other;
        }
        if other.mantissa == 0 {
            return *self;
        }

        // Align exponents by shifting the smaller one
        let (a, b) = if self.exponent >= other.exponent {
            (*self, *other)
        } else {
            (*other, *self)
        };

        let exp_diff = (a.exponent - b.exponent) as u32;
        if exp_diff > 30 {
            return a; // b is negligibly small
        }

        // Scale b's mantissa down to match a's exponent
        let b_scaled = b.mantissa / 10i64.pow(exp_diff.min(18));
        let mut result = Self {
            mantissa: a.mantissa + b_scaled,
            exponent: a.exponent,
        };
        result.normalize();
        result
    }

    /// Subtract: self - other.
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.negate())
    }

    /// Multiply two IOU values.
    pub fn mul(&self, other: &Self) -> Self {
        if self.mantissa == 0 || other.mantissa == 0 {
            return Self::ZERO;
        }
        // Use i128 to avoid overflow
        let m = self.mantissa as i128 * other.mantissa as i128;
        let e = self.exponent + other.exponent;

        // Renormalize back into i64 range with rounding
        let sign: i128 = if m < 0 { -1 } else { 1 };
        let mut abs = m.unsigned_abs();
        let mut exp = e;
        while abs > 9_999_999_999_999_999 {
            let rem = abs % 10;
            abs /= 10;
            if rem > 5 || (rem == 5 && abs % 2 != 0) {
                abs += 1;
            }
            exp += 1;
        }
        while abs < 1_000_000_000_000_000 && abs != 0 {
            abs *= 10;
            exp -= 1;
        }
        Self {
            mantissa: (sign * abs as i128) as i64,
            exponent: exp,
        }
    }

    /// Divide: self / other. Returns ZERO if other is zero.
    pub fn div(&self, other: &Self) -> Self {
        if other.mantissa == 0 || self.mantissa == 0 {
            return Self::ZERO;
        }
        // Match rippled's STAmount::divide exactly:
        // 1. muldiv(numVal, tenTo17, denVal) — truncating 128-bit division
        // 2. result + 5  (rounding bias before canonicalize's /10)
        // 3. canonicalize normalizes to [1e15, 1e16) with round-half-even
        let num = self.mantissa as i128 * 100_000_000_000_000_000i128; // 1e17
        let den = other.mantissa as i128;
        let m = if den == 0 {
            0i128
        } else {
            let sign = if (self.mantissa < 0) != (other.mantissa < 0) {
                -1i128
            } else {
                1i128
            };
            let abs_q = (num.unsigned_abs()) / (den.unsigned_abs()); // truncating
            sign * (abs_q as i128 + 5) // +5 matches rippled
        };
        let e = self.exponent - other.exponent - 17;

        let sign: i128 = if m < 0 { -1 } else { 1 };
        let mut abs = m.unsigned_abs();
        let mut exp = e;
        while abs > 9_999_999_999_999_999 {
            let rem = abs % 10;
            abs /= 10;
            if rem > 5 || (rem == 5 && abs % 2 != 0) {
                abs += 1;
            }
            exp += 1;
        }
        while abs < 1_000_000_000_000_000 && abs != 0 {
            abs *= 10;
            exp -= 1;
        }
        Self {
            mantissa: (sign * abs as i128) as i64,
            exponent: exp,
        }
    }

    /// Crossing-specific multiply: matches rippled's mulRound / STAmount::multiply.
    /// muldiv(v1, v2, 1e14) + 7, then canonicalize (plain truncation).
    /// When `round_up` is true and the result is positive, uses ceiling
    /// division (+1e14-1 bias) matching rippled's mulRound(roundUp=true).
    pub fn mul_round(&self, other: &Self, round_up: bool) -> Self {
        if self.mantissa == 0 || other.mantissa == 0 {
            return Self::ZERO;
        }
        const TEN14: u128 = 100_000_000_000_000;
        let result_negative = (self.mantissa < 0) != (other.mantissa < 0);
        let abs_product =
            (self.mantissa as i128).unsigned_abs() * (other.mantissa as i128).unsigned_abs();
        // muldiv_round: add bias for ceiling when rounding away from zero
        let bias: u128 = if result_negative != round_up {
            TEN14 - 1
        } else {
            0
        };
        let abs_q = (abs_product + bias) / TEN14;
        // +7 rounding bias before canonicalize (matches rippled multiply)
        let abs_biased = abs_q + 7;
        let exp = self.exponent + other.exponent + 14;

        let mut abs = abs_biased;
        let mut e = exp;
        // canonicalize: plain truncation
        while abs > 9_999_999_999_999_999 {
            abs /= 10;
            e += 1;
        }
        while abs < 1_000_000_000_000_000 && abs != 0 {
            abs *= 10;
            e -= 1;
        }
        let sign: i128 = if result_negative { -1 } else { 1 };
        Self {
            mantissa: (sign * abs as i128) as i64,
            exponent: e,
        }
    }

    /// Crossing-specific divide: matches rippled's divRound / STAmount::divide.
    /// muldiv(num, 1e17, den) + 5, then canonicalize (plain truncation).
    /// When `round_up` is true and the result is positive, uses ceiling
    /// division (+den-1 bias) matching rippled's divRound(roundUp=true).
    pub fn div_round(&self, other: &Self, round_up: bool) -> Self {
        if other.mantissa == 0 || self.mantissa == 0 {
            return Self::ZERO;
        }
        const TEN17: u128 = 100_000_000_000_000_000;
        let result_negative = (self.mantissa < 0) != (other.mantissa < 0);
        let num_abs = (self.mantissa as i128).unsigned_abs();
        let den_abs = (other.mantissa as i128).unsigned_abs();
        // muldiv_round: add bias for ceiling when rounding away from zero
        let bias: u128 = if result_negative != round_up {
            den_abs - 1
        } else {
            0
        };
        let num_scaled = num_abs.saturating_mul(TEN17).saturating_add(bias);
        let abs_q = num_scaled / den_abs;
        // +5 rounding bias before canonicalize (matches rippled divide)
        let abs_biased = abs_q + 5;
        let exp = self.exponent - other.exponent - 17;

        let mut abs = abs_biased;
        let mut e = exp;
        // canonicalize: plain truncation
        while abs > 9_999_999_999_999_999 {
            abs /= 10;
            e += 1;
        }
        while abs < 1_000_000_000_000_000 && abs != 0 {
            abs *= 10;
            e -= 1;
        }
        let sign: i128 = if result_negative { -1 } else { 1 };
        Self {
            mantissa: (sign * abs as i128) as i64,
            exponent: e,
        }
    }

    /// Multiply by a u32 rate and divide by QUALITY_ONE (1e9).
    /// Used for quality factor adjustments.
    pub fn mul_rate(&self, rate: u32) -> Self {
        if rate == 0 || rate == QUALITY_ONE {
            return *self;
        }
        let m = self.mantissa as i128 * rate as i128;
        let mut result = Self {
            mantissa: (m / QUALITY_ONE as i128) as i64,
            exponent: self.exponent,
        };
        result.normalize();
        result
    }

    /// Compare magnitudes (ignoring sign).
    pub fn cmp_abs(&self, other: &Self) -> std::cmp::Ordering {
        let a = self.abs().to_f64();
        let b = other.abs().to_f64();
        a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal)
    }

    /// Returns the minimum of self and other (by absolute value, preserving sign).
    pub fn min_abs(&self, other: &Self) -> Self {
        if self.abs().to_f64() <= other.abs().to_f64() {
            *self
        } else {
            *other
        }
    }
}

/// Quality factor neutral value (1.0x = 1,000,000,000).
pub const QUALITY_ONE: u32 = 1_000_000_000;

impl fmt::Display for IouValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.mantissa == 0 {
            return write!(f, "0");
        }
        write!(f, "{}e{}", self.mantissa, self.exponent)
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AmountError {
    #[error("buffer too short to decode amount")]
    TooShort,
    #[error("invalid currency code: {0}")]
    InvalidCurrency(String),
    #[error("drop count exceeds maximum (1e17)")]
    DropsOverflow,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xrp_encoding_roundtrip() {
        for drops in [0u64, 1, 1_000_000, 100_000_000_000, 99_999_999_999_999_999] {
            let encoded = Amount::Xrp(drops).to_bytes();
            assert_eq!(encoded.len(), 8);
            let (decoded, consumed) = Amount::from_bytes(&encoded).unwrap();
            assert_eq!(consumed, 8);
            assert_eq!(
                decoded,
                Amount::Xrp(drops),
                "round-trip failed for {drops} drops"
            );
        }
    }

    #[test]
    fn test_xrp_not_iou_bit() {
        // XRP amounts must have bit 63 = 0
        let encoded = Amount::Xrp(1_000_000).to_bytes();
        assert_eq!(encoded[0] & 0x80, 0, "XRP must have bit 63 = 0");
        assert_eq!(encoded[0] & 0x40, 0x40, "XRP positive must have bit 62 = 1");
    }

    #[test]
    fn test_iou_zero() {
        let zero = IouValue::ZERO;
        let bytes = zero.to_bytes();
        let decoded = IouValue::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.mantissa, 0);
    }

    #[test]
    fn test_iou_value_roundtrip() {
        let val = IouValue {
            mantissa: 1_000_000_000_000_000,
            exponent: -15,
        };
        let bytes = val.to_bytes();
        assert_eq!(bytes[0] & 0x80, 0x80, "IOU must have bit 63 = 1");
        let decoded = IouValue::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.mantissa, val.mantissa);
        assert_eq!(decoded.exponent, val.exponent);
    }

    #[test]
    fn test_currency_code() {
        let usd = Currency::from_code("USD").unwrap();
        assert_eq!(usd.to_ascii(), "USD");
        assert!(!usd.is_xrp());
        assert!(Currency::xrp().is_xrp());
    }

    #[test]
    fn test_currency_valid_lowercase() {
        assert!(Currency::from_code("usd").is_ok()); // lowercase is now accepted
        assert!(Currency::from_code("U$D").is_ok()); // special chars accepted
    }

    #[test]
    fn test_currency_invalid() {
        assert!(Currency::from_code("USDT").is_err()); // 4 chars
        assert!(Currency::from_code("US").is_err()); // 2 chars
        assert!(Currency::from_code("A B").is_err()); // space not allowed
    }

    #[test]
    fn test_mpt_amount_roundtrip() {
        let mptid = [0xAB; 24];
        let amount = Amount::from_mpt_value(42, mptid);
        let encoded = amount.to_bytes();
        assert_eq!(encoded.len(), 33);
        assert_eq!(encoded[0], 0x60);

        let (decoded, consumed) = Amount::from_bytes(&encoded).unwrap();
        assert_eq!(consumed, 33);
        assert_eq!(decoded, amount);
        assert_eq!(decoded.mpt_parts(), Some((42, mptid)));
    }
}
