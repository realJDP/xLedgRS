//! RippleState — the on-ledger state of a trust line between two accounts.
//!
//! A trust line connects two accounts for a specific currency.  The "low"
//! account is the one with the numerically smaller AccountID (canonical order).
//!
//! The SHAMap key is `SHA-512-half(0x0072 || low_account || high_account || currency)`.

use serde::{Serialize, Deserialize};

use crate::crypto::sha512_first_half;
use crate::ledger::Key;
use crate::transaction::amount::{Currency, IouValue};

// ── RippleState flag constants ───────────────────────────────────────────────

pub const LSF_LOW_RESERVE: u32 = 0x00010000;
pub const LSF_HIGH_RESERVE: u32 = 0x00020000;
pub const LSF_LOW_AUTH: u32 = 0x00040000;
pub const LSF_HIGH_AUTH: u32 = 0x00080000;
pub const LSF_LOW_NO_RIPPLE: u32 = 0x00100000;
pub const LSF_HIGH_NO_RIPPLE: u32 = 0x00200000;
pub const LSF_LOW_FREEZE: u32 = 0x00400000;
pub const LSF_HIGH_FREEZE: u32 = 0x00800000;

/// Namespace prefix for RippleState objects.
const RIPPLE_STATE_SPACE: [u8; 2] = [0x00, 0x72];

/// XRPL `ACCOUNT_ONE` sentinel — 19 zero bytes followed by a single 0x01.
/// rippled uses this value as the `issuer` field of a trust line's Balance
/// STAmount, where the real issuer is implicit in the trust line's Low/High
/// accounts. Must be used for Balance serialization to produce byte-exact
/// canonical SLE output.
const ACCOUNT_ONE: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

/// Compute the SHAMap key for a trust line between two accounts + currency.
///
/// Accounts are placed in canonical (low/high) order automatically.
pub fn shamap_key(account_a: &[u8; 20], account_b: &[u8; 20], currency: &Currency) -> Key {
    let (low, high) = canonical_order(account_a, account_b);
    let mut data = Vec::with_capacity(2 + 20 + 20 + 20);
    data.extend_from_slice(&RIPPLE_STATE_SPACE);
    data.extend_from_slice(low);
    data.extend_from_slice(high);
    data.extend_from_slice(&currency.code);
    Key(sha512_first_half(&data))
}

/// Returns (low, high) in canonical order.
pub fn canonical_order<'a>(a: &'a [u8; 20], b: &'a [u8; 20]) -> (&'a [u8; 20], &'a [u8; 20]) {
    if a < b { (a, b) } else { (b, a) }
}

// ── RippleState ───────────────────────────────────────────────────────────────

/// A trust line between two accounts for one currency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RippleState {
    /// The numerically lower AccountID.
    pub low_account:  [u8; 20],
    /// The numerically higher AccountID.
    pub high_account: [u8; 20],
    /// The currency this trust line is for.
    pub currency:     Currency,
    /// Current balance (positive = high owes low, negative = low owes high).
    pub balance:      IouValue,
    /// Low account's trust limit.
    pub low_limit:    IouValue,
    /// High account's trust limit.
    pub high_limit:   IouValue,
    /// Flags (NoRipple, Freeze, etc.)
    pub flags:        u32,
    /// sfLowNode — directory page index for low account.
    #[serde(default)]
    pub low_node:     u64,
    /// sfHighNode — directory page index for high account.
    #[serde(default)]
    pub high_node:    u64,
    /// Low account quality in (0 = default).
    #[serde(default)]
    pub low_quality_in:  u32,
    /// Low account quality out (0 = default).
    #[serde(default)]
    pub low_quality_out: u32,
    /// High account quality in (0 = default).
    #[serde(default)]
    pub high_quality_in:  u32,
    /// High account quality out (0 = default).
    #[serde(default)]
    pub high_quality_out: u32,
    /// PreviousTxnID — hash of the last transaction that modified this object.
    #[serde(default)]
    pub previous_txn_id: [u8; 32],
    /// PreviousTxnLgrSeq — ledger index of the last transaction that modified this object.
    #[serde(default)]
    pub previous_txn_lgr_seq: u32,

    /// Original binary SLE data — preserved for round-trip safety.
    #[serde(skip)]
    pub raw_sle: Option<Vec<u8>>,
}

impl PartialEq for RippleState {
    fn eq(&self, other: &Self) -> bool {
        self.low_account == other.low_account
            && self.high_account == other.high_account
            && self.currency == other.currency
            && self.balance == other.balance
            && self.low_limit == other.low_limit
            && self.high_limit == other.high_limit
            && self.flags == other.flags
            && self.low_node == other.low_node
            && self.high_node == other.high_node
            && self.low_quality_in == other.low_quality_in
            && self.low_quality_out == other.low_quality_out
            && self.high_quality_in == other.high_quality_in
            && self.high_quality_out == other.high_quality_out
            && self.previous_txn_id == other.previous_txn_id
            && self.previous_txn_lgr_seq == other.previous_txn_lgr_seq
    }
}

impl RippleState {
    /// Create a new trust line with zero balance.
    pub fn new(
        account_a: &[u8; 20],
        account_b: &[u8; 20],
        currency:  Currency,
    ) -> Self {
        let (low, high) = canonical_order(account_a, account_b);
        Self {
            low_account:  *low,
            high_account: *high,
            currency,
            balance:    IouValue::ZERO,
            low_limit:  IouValue::ZERO,
            high_limit: IouValue::ZERO,
            flags:      0,
            low_node:   0,
            high_node:  0,
            low_quality_in:  0,
            low_quality_out: 0,
            high_quality_in:  0,
            high_quality_out: 0,
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        }
    }

    /// The SHAMap key for this trust line.
    pub fn key(&self) -> Key {
        shamap_key(&self.low_account, &self.high_account, &self.currency)
    }

    /// `true` if neither side has a balance and both limits are zero — safe to delete.
    pub fn is_empty(&self) -> bool {
        self.balance.mantissa == 0
            && self.low_limit.mantissa == 0
            && self.high_limit.mantissa == 0
    }

    /// Set the limit for `account`.  Panics if `account` is neither low nor high.
    pub fn set_limit_for(&mut self, account: &[u8; 20], limit: IouValue) {
        if account == &self.low_account {
            self.low_limit = limit;
        } else if account == &self.high_account {
            self.high_limit = limit;
        } else {
            panic!("account is not part of this trust line");
        }
    }

    /// Get the balance from `account`'s perspective.
    ///
    /// If `account` is the low account and balance is positive, it means
    /// high owes low → low has a positive IOU balance.
    /// If `account` is the high account, negate.
    pub fn balance_for(&self, account: &[u8; 20]) -> IouValue {
        if account == &self.low_account {
            self.balance.clone()
        } else {
            IouValue {
                mantissa: -self.balance.mantissa,
                exponent: self.balance.exponent,
            }
        }
    }

    /// Adjust the balance: transfer `amount` (positive IouValue) from
    /// `sender` to the other party of this trust line.
    ///
    /// `sender` must be either `low_account` or `high_account`. The trust
    /// line's `balance` is interpreted as "the amount the low account holds
    /// of the high account's issued IOU":
    ///   - positive balance → low is net creditor / high is net debtor
    ///   - if `sender == low`: low is paying out → balance decreases
    ///   - if `sender == high`: high is issuing / paying → balance increases
    ///
    /// Delegates arithmetic to `IouValue::add` / `sub`, which canonicalize
    /// mantissas in a wider intermediate and renormalize the result. The
    /// previous inline implementation used raw i64 math with saturating_mul
    /// and no renormalization, which could overflow (debug: panic, release:
    /// wrapping) and produce catastrophically wrong balances on crossing
    /// paths that touched the trust line via tfSell offers. See the bug hunt
    /// for 103483090:tx0, where this was the source of a +1.30 → -0.00092
    /// RLUSD divergence against rippled.
    pub fn transfer(&mut self, sender: &[u8; 20], amount: &IouValue) {
        if sender == &self.low_account {
            self.balance = self.balance.sub(amount);
        } else {
            self.balance = self.balance.add(amount);
        }
    }

    /// Serialize as canonical STObject (rippled-compatible SLE binary).
    pub fn encode(&self) -> Vec<u8> {
        use crate::ledger::meta::ParsedField;

        // Helper: encode an IOU Amount field (48 bytes: 8 value + 20 currency + 20 issuer)
        fn iou_amount_bytes(value: &IouValue, currency: &Currency, issuer: &[u8; 20]) -> Vec<u8> {
            let mut buf = Vec::with_capacity(48);
            buf.extend_from_slice(&value.to_bytes());
            buf.extend_from_slice(&currency.code);
            buf.extend_from_slice(issuer);
            buf
        }

        let mut fields = Vec::new();

        // sfFlags (2,2) — always present
        fields.push(ParsedField { type_code: 2, field_code: 2, data: self.flags.to_be_bytes().to_vec() });

        // sfLowQualityIn (2,18) — optional, only when non-zero
        if self.low_quality_in != 0 {
            fields.push(ParsedField { type_code: 2, field_code: 18, data: self.low_quality_in.to_be_bytes().to_vec() });
        }
        // sfLowQualityOut (2,19) — optional
        if self.low_quality_out != 0 {
            fields.push(ParsedField { type_code: 2, field_code: 19, data: self.low_quality_out.to_be_bytes().to_vec() });
        }
        // sfHighQualityIn (2,16) — optional
        if self.high_quality_in != 0 {
            fields.push(ParsedField { type_code: 2, field_code: 16, data: self.high_quality_in.to_be_bytes().to_vec() });
        }
        // sfHighQualityOut (2,17) — optional
        if self.high_quality_out != 0 {
            fields.push(ParsedField { type_code: 2, field_code: 17, data: self.high_quality_out.to_be_bytes().to_vec() });
        }

        // sfBalance (6,2) — issuer = ACCOUNT_ONE sentinel (rippled canonical
        // encoding for trust-line Balance; the actual issuer is implicit in
        // the Low/High account IDs).
        fields.push(ParsedField { type_code: 6, field_code: 2, data: iou_amount_bytes(&self.balance, &self.currency, &ACCOUNT_ONE) });
        // sfLowLimit (6,6) — issuer = low_account
        fields.push(ParsedField { type_code: 6, field_code: 6, data: iou_amount_bytes(&self.low_limit, &self.currency, &self.low_account) });
        // sfHighLimit (6,7) — issuer = high_account
        fields.push(ParsedField { type_code: 6, field_code: 7, data: iou_amount_bytes(&self.high_limit, &self.currency, &self.high_account) });

        crate::ledger::meta::build_sle(
            0x0072,
            &fields,
            Some(self.previous_txn_id),
            Some(self.previous_txn_lgr_seq),
        )
    }

    /// Produce the binary SLE for this RippleState.
    ///
    /// If `raw_sle` is present, patches the original binary to preserve
    /// unknown/future fields. Falls back to `encode()` for new trust lines.
    pub fn to_sle_binary(&self) -> Vec<u8> {
        let raw = match &self.raw_sle {
            Some(r) => r,
            None => return self.encode(),
        };

        let mut sle = crate::ledger::sle::SLE::new(
            self.key(),
            crate::ledger::sle::LedgerEntryType::RippleState,
            raw.clone(),
        );

        // Patch typed fields into the binary
        sle.set_flags(self.flags);

        // PreviousTxnID / LgrSeq
        if self.previous_txn_id != [0u8; 32] {
            sle.set_previous_txn_id(&self.previous_txn_id);
        }
        if self.previous_txn_lgr_seq > 0 {
            sle.set_previous_txn_lgr_seq(self.previous_txn_lgr_seq);
        }

        // Quality fields
        if self.low_quality_in != 0 {
            sle.set_field_u32(2, 18, self.low_quality_in);
        } else {
            sle.remove_field(2, 18);
        }
        if self.low_quality_out != 0 {
            sle.set_field_u32(2, 19, self.low_quality_out);
        } else {
            sle.remove_field(2, 19);
        }
        if self.high_quality_in != 0 {
            sle.set_field_u32(2, 16, self.high_quality_in);
        } else {
            sle.remove_field(2, 16);
        }
        if self.high_quality_out != 0 {
            sle.set_field_u32(2, 17, self.high_quality_out);
        } else {
            sle.remove_field(2, 17);
        }

        // LowNode / HighNode
        sle.set_field_u64(3, 7, self.low_node);
        sle.set_field_u64(3, 8, self.high_node);

        // Balance, LowLimit, HighLimit — IOU amounts (48 bytes each)
        // These need special handling: 8 value + 20 currency + 20 issuer
        fn iou_bytes(value: &IouValue, currency: &Currency, issuer: &[u8; 20]) -> Vec<u8> {
            let mut buf = Vec::with_capacity(48);
            buf.extend_from_slice(&value.to_bytes());
            buf.extend_from_slice(&currency.code);
            buf.extend_from_slice(issuer);
            buf
        }
        sle.set_field_raw_pub(6, 2, &iou_bytes(&self.balance, &self.currency, &ACCOUNT_ONE));
        sle.set_field_raw_pub(6, 6, &iou_bytes(&self.low_limit, &self.currency, &self.low_account));
        sle.set_field_raw_pub(6, 7, &iou_bytes(&self.high_limit, &self.currency, &self.high_account));

        sle.into_data()
    }

    /// Deserialize from binary.
    pub fn decode(data: &[u8]) -> Option<Self> {
        // Minimum: 20+20+20+8+8+8+4 = 88 (original fields)
        if data.len() < 20 + 20 + 20 + 8 + 8 + 8 + 4 { return None; }
        let mut pos = 0;
        let mut low_account = [0u8; 20];
        low_account.copy_from_slice(&data[pos..pos+20]); pos += 20;
        let mut high_account = [0u8; 20];
        high_account.copy_from_slice(&data[pos..pos+20]); pos += 20;
        let mut currency_code = [0u8; 20];
        currency_code.copy_from_slice(&data[pos..pos+20]); pos += 20;
        let balance   = IouValue::from_bytes(&data[pos..]).ok()?; pos += 8;
        let low_limit = IouValue::from_bytes(&data[pos..]).ok()?; pos += 8;
        let high_limit= IouValue::from_bytes(&data[pos..]).ok()?; pos += 8;
        let flags = u32::from_be_bytes(data[pos..pos+4].try_into().ok()?); pos += 4;

        // New fields — optional, default to zero if not present
        let low_node = if pos + 8 <= data.len() {
            let v = u64::from_be_bytes(data[pos..pos+8].try_into().ok()?); pos += 8; v
        } else { 0 };
        let high_node = if pos + 8 <= data.len() {
            let v = u64::from_be_bytes(data[pos..pos+8].try_into().ok()?); pos += 8; v
        } else { 0 };
        let low_quality_in = if pos + 4 <= data.len() {
            let v = u32::from_be_bytes(data[pos..pos+4].try_into().ok()?); pos += 4; v
        } else { 0 };
        let low_quality_out = if pos + 4 <= data.len() {
            let v = u32::from_be_bytes(data[pos..pos+4].try_into().ok()?); pos += 4; v
        } else { 0 };
        let high_quality_in = if pos + 4 <= data.len() {
            let v = u32::from_be_bytes(data[pos..pos+4].try_into().ok()?); pos += 4; v
        } else { 0 };
        let high_quality_out = if pos + 4 <= data.len() {
            let v = u32::from_be_bytes(data[pos..pos+4].try_into().ok()?); pos += 4; v
        } else { 0 };
        let mut previous_txn_id = [0u8; 32];
        if pos + 32 <= data.len() {
            previous_txn_id.copy_from_slice(&data[pos..pos+32]); pos += 32;
        }
        let previous_txn_lgr_seq = if pos + 4 <= data.len() {
            u32::from_be_bytes(data[pos..pos+4].try_into().ok()?)
        } else { 0 };

        Some(Self {
            low_account, high_account,
            currency: Currency { code: currency_code },
            balance, low_limit, high_limit, flags,
            low_node, high_node,
            low_quality_in, low_quality_out,
            high_quality_in, high_quality_out,
            previous_txn_id, previous_txn_lgr_seq,
            raw_sle: None, // old format — no STObject binary to preserve
        })
    }
    /// Decode from XRPL STObject binary (SLE format), as produced by
    /// `build_pre_tx_sle` / `build_sle` in meta.rs.
    ///
    /// Field codes (type_code, field_code):
    ///   (1,1)  LedgerEntryType UInt16 — skipped
    ///   (2,2)  Flags            UInt32
    ///   (2,5)  PreviousTxnLgrSeq UInt32
    ///   (2,16) HighQualityIn    UInt32
    ///   (2,17) HighQualityOut   UInt32
    ///   (2,18) LowQualityIn     UInt32
    ///   (2,19) LowQualityOut    UInt32
    ///   (3,7)  LowNode          UInt64
    ///   (3,8)  HighNode         UInt64
    ///   (5,5)  PreviousTxnID    Hash256
    ///   (6,2)  Balance          Amount (IOU)
    ///   (6,6)  LowLimit         Amount (IOU — issuer = low account)
    ///   (6,7)  HighLimit        Amount (IOU — issuer = high account)
    pub fn decode_from_sle(data: &[u8]) -> Option<Self> {
        let mut pos = 0;
        let mut flags = 0u32;
        let mut balance: Option<IouValue> = None;
        let mut low_limit: Option<IouValue> = None;
        let mut high_limit: Option<IouValue> = None;
        let mut low_account = [0u8; 20];
        let mut high_account = [0u8; 20];
        let mut currency = Currency { code: [0u8; 20] };
        let mut low_node = 0u64;
        let mut high_node = 0u64;
        let mut low_quality_in = 0u32;
        let mut low_quality_out = 0u32;
        let mut high_quality_in = 0u32;
        let mut high_quality_out = 0u32;
        let mut previous_txn_id = [0u8; 32];
        let mut previous_txn_lgr_seq = 0u32;

        while pos < data.len() {
            let b = data[pos];
            pos += 1;

            let top = (b >> 4) as u16;
            let bot = (b & 0x0F) as u16;
            let (type_code, field_code) = if top == 0 && bot == 0 {
                if pos + 2 > data.len() { break; }
                let t = data[pos] as u16; let f = data[pos + 1] as u16;
                pos += 2; (t, f)
            } else if top == 0 {
                if pos >= data.len() { break; }
                let t = data[pos] as u16; pos += 1; (t, bot)
            } else if bot == 0 {
                if pos >= data.len() { break; }
                let f = data[pos] as u16; pos += 1; (top, f)
            } else {
                (top, bot)
            };

            match (type_code, field_code) {
                (1, 1) => {
                    // LedgerEntryType — skip
                    if pos + 2 > data.len() { break; }
                    pos += 2;
                }
                (2, 2) => {
                    // Flags
                    if pos + 4 > data.len() { break; }
                    flags = u32::from_be_bytes(data[pos..pos+4].try_into().ok()?);
                    pos += 4;
                }
                (2, 5) => {
                    // sfPreviousTxnLgrSeq (type=2, field=5, NOT field=3 which is sfSourceTag)
                    if pos + 4 > data.len() { break; }
                    previous_txn_lgr_seq = u32::from_be_bytes(data[pos..pos+4].try_into().ok()?);
                    pos += 4;
                }
                (2, 16) => {
                    // HighQualityIn
                    if pos + 4 > data.len() { break; }
                    high_quality_in = u32::from_be_bytes(data[pos..pos+4].try_into().ok()?);
                    pos += 4;
                }
                (2, 17) => {
                    // HighQualityOut
                    if pos + 4 > data.len() { break; }
                    high_quality_out = u32::from_be_bytes(data[pos..pos+4].try_into().ok()?);
                    pos += 4;
                }
                (2, 18) => {
                    // LowQualityIn
                    if pos + 4 > data.len() { break; }
                    low_quality_in = u32::from_be_bytes(data[pos..pos+4].try_into().ok()?);
                    pos += 4;
                }
                (2, 19) => {
                    // LowQualityOut
                    if pos + 4 > data.len() { break; }
                    low_quality_out = u32::from_be_bytes(data[pos..pos+4].try_into().ok()?);
                    pos += 4;
                }
                (3, 7) => {
                    // LowNode
                    if pos + 8 > data.len() { break; }
                    low_node = u64::from_be_bytes(data[pos..pos+8].try_into().ok()?);
                    pos += 8;
                }
                (3, 8) => {
                    // HighNode
                    if pos + 8 > data.len() { break; }
                    high_node = u64::from_be_bytes(data[pos..pos+8].try_into().ok()?);
                    pos += 8;
                }
                (5, 5) => {
                    // PreviousTxnID
                    if pos + 32 > data.len() { break; }
                    previous_txn_id.copy_from_slice(&data[pos..pos+32]);
                    pos += 32;
                }
                (6, 2) => {
                    // Balance (IOU amount — 48 bytes)
                    if pos >= data.len() { break; }
                    let (amt, consumed) = crate::transaction::amount::Amount::from_bytes(&data[pos..]).ok()?;
                    if let crate::transaction::amount::Amount::Iou { value, currency: cur, .. } = amt {
                        balance = Some(value);
                        currency = cur;
                    }
                    pos += consumed;
                }
                (6, 6) => {
                    // LowLimit (IOU amount — issuer = low account)
                    if pos >= data.len() { break; }
                    let (amt, consumed) = crate::transaction::amount::Amount::from_bytes(&data[pos..]).ok()?;
                    if let crate::transaction::amount::Amount::Iou { value, issuer, .. } = amt {
                        low_limit = Some(value);
                        low_account = issuer;
                    }
                    pos += consumed;
                }
                (6, 7) => {
                    // HighLimit (IOU amount — issuer = high account)
                    if pos >= data.len() { break; }
                    let (amt, consumed) = crate::transaction::amount::Amount::from_bytes(&data[pos..]).ok()?;
                    if let crate::transaction::amount::Amount::Iou { value, issuer, .. } = amt {
                        high_limit = Some(value);
                        high_account = issuer;
                    }
                    pos += consumed;
                }
                // Skip unknown fields by type
                (1, _) => { if pos + 2 > data.len() { break; } pos += 2; }
                (2, _) => { if pos + 4 > data.len() { break; } pos += 4; }
                (3, _) => { if pos + 8 > data.len() { break; } pos += 8; }
                (4, _) => { if pos + 16 > data.len() { break; } pos += 16; }
                (5, _) => { if pos + 32 > data.len() { break; } pos += 32; }
                (6, _) => {
                    if pos >= data.len() { break; }
                    if (data[pos] & 0x80) != 0 { pos += 48; }
                    else if (data[pos] & 0x20) != 0 { pos += 33; }
                    else { pos += 8; }
                }
                (7, _) | (8, _) | (19, _) => {
                    if pos >= data.len() { break; }
                    let (vl_len, vl_bytes) = crate::transaction::serialize::decode_length(&data[pos..]);
                    pos += vl_bytes + vl_len;
                }
                (16, _) => { if pos >= data.len() { break; } pos += 1; }
                (17, _) => { if pos + 20 > data.len() { break; } pos += 20; }
                _ => { break; }
            }
        }

        Some(Self {
            low_account,
            high_account,
            currency,
            balance: balance.unwrap_or(IouValue::ZERO),
            low_limit: low_limit.unwrap_or(IouValue::ZERO),
            high_limit: high_limit.unwrap_or(IouValue::ZERO),
            flags,
            low_node,
            high_node,
            low_quality_in,
            low_quality_out,
            high_quality_in,
            high_quality_out,
            previous_txn_id,
            previous_txn_lgr_seq,
            raw_sle: Some(data.to_vec()),
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(n: u8) -> [u8; 20] { [n; 20] }
    fn usd() -> Currency { Currency::from_code("USD").unwrap() }

    #[test]
    fn test_canonical_order() {
        let a5 = acct(5);
        let a2 = acct(2);
        let (low, high) = canonical_order(&a5, &a2);
        assert_eq!(low, &a2);
        assert_eq!(high, &a5);
    }

    #[test]
    fn test_new_trust_line_is_empty() {
        let tl = RippleState::new(&acct(1), &acct(2), usd());
        assert!(tl.is_empty());
        assert_eq!(tl.low_account, acct(1));
        assert_eq!(tl.high_account, acct(2));
    }

    #[test]
    fn test_canonical_order_in_constructor() {
        // Pass high first — constructor should swap
        let tl = RippleState::new(&acct(9), &acct(1), usd());
        assert_eq!(tl.low_account, acct(1));
        assert_eq!(tl.high_account, acct(9));
    }

    #[test]
    fn test_set_limit() {
        let mut tl = RippleState::new(&acct(1), &acct(2), usd());
        tl.set_limit_for(&acct(1), IouValue { mantissa: 1_000_000_000_000_000, exponent: -15 });
        assert_eq!(tl.low_limit.mantissa, 1_000_000_000_000_000);
        assert!(!tl.is_empty());
    }

    #[test]
    fn test_transfer_low_to_high() {
        let mut tl = RippleState::new(&acct(1), &acct(2), usd());
        tl.low_limit = IouValue { mantissa: 1_000_000_000_000_000, exponent: -12 };
        tl.high_limit = IouValue { mantissa: 1_000_000_000_000_000, exponent: -12 };

        // Low sends 100 USD to high → balance decreases
        tl.transfer(&acct(1), &IouValue { mantissa: 100_000_000_000_000_0, exponent: -15 });
        assert!(tl.balance.mantissa < 0, "balance should be negative after low sends");
    }

    #[test]
    fn test_balance_for_perspective() {
        let mut tl = RippleState::new(&acct(1), &acct(2), usd());
        tl.balance = IouValue { mantissa: 500, exponent: 0 }; // high owes low 500

        let low_bal = tl.balance_for(&acct(1));
        assert_eq!(low_bal.mantissa, 500); // low holds +500

        let high_bal = tl.balance_for(&acct(2));
        assert_eq!(high_bal.mantissa, -500); // high owes -500
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut tl = RippleState::new(&acct(3), &acct(7), usd());
        tl.balance = IouValue { mantissa: 1_000_000_000_000_000, exponent: -13 };
        tl.low_limit = IouValue { mantissa: 5_000_000_000_000_000, exponent: -13 };
        tl.flags = 0x00020000;

        let bytes = tl.encode();
        // encode() now produces STObject format — decode with decode_from_sle
        let decoded = RippleState::decode_from_sle(&bytes).expect("decode_from_sle should succeed");
        assert_eq!(decoded.low_account, tl.low_account);
        assert_eq!(decoded.high_account, tl.high_account);
        assert_eq!(decoded.balance.mantissa, tl.balance.mantissa);
        assert_eq!(decoded.low_limit.mantissa, tl.low_limit.mantissa);
        assert_eq!(decoded.flags, tl.flags);
    }

    #[test]
    fn test_shamap_key_deterministic() {
        let k1 = shamap_key(&acct(1), &acct(2), &usd());
        let k2 = shamap_key(&acct(1), &acct(2), &usd());
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_shamap_key_order_independent() {
        // (a, b) and (b, a) must produce the same key
        let k1 = shamap_key(&acct(1), &acct(5), &usd());
        let k2 = shamap_key(&acct(5), &acct(1), &usd());
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_different_currencies_different_keys() {
        let eur = Currency::from_code("EUR").unwrap();
        let k1 = shamap_key(&acct(1), &acct(2), &usd());
        let k2 = shamap_key(&acct(1), &acct(2), &eur);
        assert_ne!(k1, k2);
    }
}
