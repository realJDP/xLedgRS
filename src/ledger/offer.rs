//! xLedgRS purpose: Offer support for XRPL ledger state and SHAMap logic.
//! Offer — a standing order on the XRPL decentralized exchange.
//!
//! An offer says: "I will give `taker_gets` in exchange for `taker_pays`."
//! Offers are matched when a new OfferCreate crosses existing offers on the
//! opposite side of the order book.
//!
//! SHAMap key: `SHA-512-half(0x006F || account_id || sequence_u32_be)`

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::sha512_first_half;
use crate::ledger::Key;
use crate::transaction::amount::{Amount, IouValue};

// ── Offer flag constants ─────────────────────────────────────────────────────

pub const LSF_PASSIVE: u32 = 0x00010000;
pub const LSF_SELL: u32 = 0x00020000;

/// Namespace prefix for Offer objects.
const OFFER_SPACE: [u8; 2] = [0x00, 0x6F];

/// Compute the SHAMap key for an offer.
pub fn shamap_key(account: &[u8; 20], sequence: u32) -> Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&OFFER_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(&sequence.to_be_bytes());
    Key(sha512_first_half(&data))
}

/// Parse an sfAdditionalBooks STArray payload.
///
/// rippled stores each additional book as an inner sfBook object containing
/// sfBookDirectory and sfBookNode. Older local fixtures wrote a malformed
/// STArray entry directly; keep a small compatibility path so we can still
/// inspect those fixtures.
pub(crate) fn additional_book_entries_from_payload(data: &[u8]) -> Vec<([u8; 32], u64)> {
    let mut out = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let (tc, fc, new_pos) = crate::ledger::meta::read_field_header(data, pos);
        if new_pos <= pos {
            break;
        }
        pos = new_pos;

        match (tc, fc) {
            (15, 1) | (14, 1) => break,
            (14, 36) => {
                if let Some(entry) = parse_additional_book_object(data, &mut pos) {
                    out.push(entry);
                }
            }
            (15, 3) => {
                if let Some(entry) = parse_legacy_additional_book_object(data, &mut pos) {
                    out.push(entry);
                }
            }
            _ => {
                pos = crate::ledger::meta::skip_field_raw(data, pos, tc);
            }
        }
    }

    out
}

pub(crate) fn additional_book_directories_from_payload(data: &[u8]) -> Vec<[u8; 32]> {
    additional_book_entries_from_payload(data)
        .into_iter()
        .map(|(book_directory, _)| book_directory)
        .collect()
}

fn parse_additional_book_object(data: &[u8], pos: &mut usize) -> Option<([u8; 32], u64)> {
    let mut book_directory = None;
    let mut book_node = 0u64;

    while *pos < data.len() {
        let (tc, fc, new_pos) = crate::ledger::meta::read_field_header(data, *pos);
        if new_pos <= *pos {
            break;
        }
        *pos = new_pos;

        match (tc, fc) {
            (14, 1) | (15, 1) => break,
            (5, 16) => {
                if *pos + 32 <= data.len() {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&data[*pos..*pos + 32]);
                    book_directory = Some(h);
                }
                *pos = (*pos + 32).min(data.len());
            }
            (3, 3) => {
                if *pos + 8 <= data.len() {
                    book_node = u64::from_be_bytes(data[*pos..*pos + 8].try_into().ok()?);
                }
                *pos = (*pos + 8).min(data.len());
            }
            _ => {
                *pos = crate::ledger::meta::skip_field_raw(data, *pos, tc);
            }
        }
    }

    book_directory.map(|dir| (dir, book_node))
}

fn parse_legacy_additional_book_object(data: &[u8], pos: &mut usize) -> Option<([u8; 32], u64)> {
    let mut book_directory = None;
    let mut book_node = 0u64;

    while *pos < data.len() {
        let (tc, fc, new_pos) = crate::ledger::meta::read_field_header(data, *pos);
        if new_pos <= *pos {
            break;
        }
        *pos = new_pos;

        match (tc, fc) {
            (14, 1) => break,
            (5, 16) => {
                if *pos + 32 <= data.len() {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&data[*pos..*pos + 32]);
                    book_directory = Some(h);
                }
                *pos = (*pos + 32).min(data.len());
            }
            (3, 3) => {
                if *pos + 8 <= data.len() {
                    book_node = u64::from_be_bytes(data[*pos..*pos + 8].try_into().ok()?);
                }
                *pos = (*pos + 8).min(data.len());
            }
            _ => {
                *pos = crate::ledger::meta::skip_field_raw(data, *pos, tc);
            }
        }
    }

    book_directory.map(|dir| (dir, book_node))
}

// ── Offer ─────────────────────────────────────────────────────────────────────

/// A standing order on the DEX.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offer {
    /// The account that placed the offer.
    pub account: [u8; 20],
    /// The sequence number of the OfferCreate tx (also serves as the offer ID).
    pub sequence: u32,
    /// What the taker must pay (what the offerer wants).
    pub taker_pays: Amount,
    /// What the taker gets (what the offerer is giving away).
    pub taker_gets: Amount,
    /// Flags (e.g., passive, immediate-or-cancel, fill-or-kill).
    pub flags: u32,
    /// sfBookDirectory — the directory this offer is listed in.
    #[serde(default)]
    pub book_directory: [u8; 32],
    /// sfBookNode — page index in the book directory.
    #[serde(default)]
    pub book_node: u64,
    /// sfOwnerNode — page index in the owner directory.
    #[serde(default)]
    pub owner_node: u64,
    /// sfExpiration — optional expiration time.
    #[serde(default)]
    pub expiration: Option<u32>,
    /// sfDomainID — optional permissioned domain id.
    #[serde(default)]
    pub domain_id: Option<[u8; 32]>,
    /// sfAdditionalBooks — optional array of extra book directories.
    #[serde(default)]
    pub additional_books: Vec<[u8; 32]>,
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

impl Offer {
    pub fn to_sle_binary(&self) -> Vec<u8> {
        let raw = match &self.raw_sle {
            Some(r) => r,
            None => return self.encode(),
        };

        let mut sle = crate::ledger::sle::SLE::new(
            self.key(),
            crate::ledger::sle::LedgerEntryType::Offer,
            raw.clone(),
        );

        // UInt32 fields
        sle.set_flags(self.flags);
        sle.set_sequence(self.sequence);

        // PreviousTxnID / PreviousTxnLgrSeq
        if self.previous_txn_id != [0u8; 32] {
            sle.set_previous_txn_id(&self.previous_txn_id);
        }
        if self.previous_txn_lgr_seq > 0 {
            sle.set_previous_txn_lgr_seq(self.previous_txn_lgr_seq);
        }

        // Expiration (UInt32, 2, 10)
        if let Some(exp) = self.expiration {
            sle.set_field_u32(2, 10, exp);
        } else {
            sle.remove_field(2, 10);
        }

        // BookNode (UInt64, 3, 3)
        sle.set_field_u64(3, 3, self.book_node);
        // OwnerNode (UInt64, 3, 4)
        sle.set_field_u64(3, 4, self.owner_node);

        // BookDirectory (Hash256, 5, 16)
        sle.set_field_h256(5, 16, &self.book_directory);

        // TakerPays (Amount, 6, 4)
        sle.set_field_raw_pub(6, 4, &self.taker_pays.to_bytes());
        // TakerGets (Amount, 6, 5)
        sle.set_field_raw_pub(6, 5, &self.taker_gets.to_bytes());

        // Account (AccountID, 8, 1)
        sle.set_field_account(8, 1, &self.account);

        // DomainID (Hash256, 5, 34)
        if let Some(domain_id) = self.domain_id {
            sle.set_field_h256(5, 34, &domain_id);
        } else {
            sle.remove_field(5, 34);
        }

        sle.into_data()
    }

    pub fn key(&self) -> Key {
        shamap_key(&self.account, self.sequence)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut fields = vec![
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 2,
                data: self.flags.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 4,
                data: self.sequence.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 3,
                data: self.book_node.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 4,
                data: self.owner_node.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 5,
                field_code: 16,
                data: self.book_directory.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 6,
                field_code: 4,
                data: self.taker_pays.to_bytes(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 6,
                field_code: 5,
                data: self.taker_gets.to_bytes(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 1,
                data: self.account.to_vec(),
            },
        ];

        if let Some(expiration) = self.expiration {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 10,
                data: expiration.to_be_bytes().to_vec(),
            });
        }

        if let Some(domain_id) = self.domain_id {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 5,
                field_code: 34,
                data: domain_id.to_vec(),
            });
        }

        if !self.additional_books.is_empty() {
            let mut array = Vec::new();
            for book in &self.additional_books {
                crate::ledger::meta::write_field_header_pub(&mut array, 14, 36); // sfBook
                crate::ledger::meta::write_field_header_pub(&mut array, 3, 3); // sfBookNode
                array.extend_from_slice(&0u64.to_be_bytes());
                crate::ledger::meta::write_field_header_pub(&mut array, 5, 16); // sfBookDirectory
                array.extend_from_slice(book);
                array.push(0xE1); // STObject end marker
            }
            array.push(0xF1); // STArray end marker
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 15,
                field_code: 13,
                data: array,
            });
        }

        crate::ledger::meta::build_sle(
            0x006f,
            &fields,
            Some(self.previous_txn_id),
            Some(self.previous_txn_lgr_seq),
        )
    }

    /// Decode from XRPL STObject binary (SLE format), as produced by
    /// `build_pre_tx_sle` / `build_sle` in meta.rs.
    ///
    /// Field codes (type_code, field_code):
    ///   (1,1)  LedgerEntryType  UInt16 — skipped
    ///   (2,2)  Flags             UInt32
    ///   (2,5)  PreviousTxnLgrSeq UInt32
    ///   (2,4)  Sequence          UInt32
    ///   (2,10) Expiration        UInt32
    ///   (3,3)  BookNode          UInt64
    ///   (3,4)  OwnerNode         UInt64
    ///   (5,5)  PreviousTxnID     Hash256
    ///   (5,16) BookDirectory     Hash256  (field_code > 15 → extended)
    ///   (6,4)  TakerPays         Amount
    ///   (6,5)  TakerGets         Amount
    ///   (8,1)  Account           AccountID (VL-encoded)
    pub fn decode_from_sle(data: &[u8]) -> Option<Self> {
        let mut pos = 0;
        let mut account = [0u8; 20];
        let mut sequence = 0u32;
        let mut taker_pays: Option<Amount> = None;
        let mut taker_gets: Option<Amount> = None;
        let mut flags = 0u32;
        let mut book_directory = [0u8; 32];
        let mut book_node = 0u64;
        let mut owner_node = 0u64;
        let mut expiration: Option<u32> = None;
        let mut domain_id: Option<[u8; 32]> = None;
        let mut additional_books: Vec<[u8; 32]> = Vec::new();
        let mut previous_txn_id = [0u8; 32];
        let mut previous_txn_lgr_seq = 0u32;

        while pos < data.len() {
            let b = data[pos];
            pos += 1;

            let top = (b >> 4) as u16;
            let bot = (b & 0x0F) as u16;
            let (type_code, field_code) = if top == 0 && bot == 0 {
                if pos + 2 > data.len() {
                    break;
                }
                let t = data[pos] as u16;
                let f = data[pos + 1] as u16;
                pos += 2;
                (t, f)
            } else if top == 0 {
                if pos >= data.len() {
                    break;
                }
                let t = data[pos] as u16;
                pos += 1;
                (t, bot)
            } else if bot == 0 {
                if pos >= data.len() {
                    break;
                }
                let f = data[pos] as u16;
                pos += 1;
                (top, f)
            } else {
                (top, bot)
            };

            match (type_code, field_code) {
                (1, 1) => {
                    // LedgerEntryType — skip
                    if pos + 2 > data.len() {
                        break;
                    }
                    pos += 2;
                }
                (2, 2) => {
                    // Flags
                    if pos + 4 > data.len() {
                        break;
                    }
                    flags = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?);
                    pos += 4;
                }
                (2, 5) => {
                    // sfPreviousTxnLgrSeq (type=2, field=5, NOT field=3 which is sfSourceTag)
                    if pos + 4 > data.len() {
                        break;
                    }
                    previous_txn_lgr_seq = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?);
                    pos += 4;
                }
                (2, 4) => {
                    // Sequence
                    if pos + 4 > data.len() {
                        break;
                    }
                    sequence = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?);
                    pos += 4;
                }
                (2, 10) => {
                    // Expiration
                    if pos + 4 > data.len() {
                        break;
                    }
                    expiration = Some(u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?));
                    pos += 4;
                }
                (3, 3) => {
                    // BookNode
                    if pos + 8 > data.len() {
                        break;
                    }
                    book_node = u64::from_be_bytes(data[pos..pos + 8].try_into().ok()?);
                    pos += 8;
                }
                (3, 4) => {
                    // OwnerNode
                    if pos + 8 > data.len() {
                        break;
                    }
                    owner_node = u64::from_be_bytes(data[pos..pos + 8].try_into().ok()?);
                    pos += 8;
                }
                (5, 5) => {
                    // PreviousTxnID
                    if pos + 32 > data.len() {
                        break;
                    }
                    previous_txn_id.copy_from_slice(&data[pos..pos + 32]);
                    pos += 32;
                }
                (5, 16) => {
                    // BookDirectory
                    if pos + 32 > data.len() {
                        break;
                    }
                    book_directory.copy_from_slice(&data[pos..pos + 32]);
                    pos += 32;
                }
                (5, 34) => {
                    // DomainID
                    if pos + 32 > data.len() {
                        break;
                    }
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&data[pos..pos + 32]);
                    domain_id = Some(h);
                    pos += 32;
                }
                (6, 4) => {
                    // TakerPays
                    if pos >= data.len() {
                        break;
                    }
                    let (amt, consumed) = Amount::from_bytes(&data[pos..]).ok()?;
                    taker_pays = Some(amt);
                    pos += consumed;
                }
                (6, 5) => {
                    // TakerGets
                    if pos >= data.len() {
                        break;
                    }
                    let (amt, consumed) = Amount::from_bytes(&data[pos..]).ok()?;
                    taker_gets = Some(amt);
                    pos += consumed;
                }
                (8, 1) => {
                    // Account (VL-encoded)
                    if pos >= data.len() {
                        break;
                    }
                    let vl = data[pos] as usize;
                    pos += 1;
                    if pos + vl > data.len() {
                        break;
                    }
                    if vl == 20 {
                        account.copy_from_slice(&data[pos..pos + 20]);
                    }
                    pos += vl;
                }
                // Skip unknown fields by type
                (1, _) => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    pos += 2;
                }
                (2, _) => {
                    if pos + 4 > data.len() {
                        break;
                    }
                    pos += 4;
                }
                (3, _) => {
                    if pos + 8 > data.len() {
                        break;
                    }
                    pos += 8;
                }
                (4, _) => {
                    if pos + 16 > data.len() {
                        break;
                    }
                    pos += 16;
                }
                (5, _) => {
                    if pos + 32 > data.len() {
                        break;
                    }
                    pos += 32;
                }
                (6, _) => {
                    if pos >= data.len() {
                        break;
                    }
                    if (data[pos] & 0x80) != 0 {
                        pos += 48;
                    } else if (data[pos] & 0x20) != 0 {
                        pos += 33;
                    } else {
                        pos += 8;
                    }
                }
                (7, _) | (8, _) | (19, _) => {
                    if pos >= data.len() {
                        break;
                    }
                    let (vl_len, vl_bytes) =
                        crate::transaction::serialize::decode_length(&data[pos..]);
                    pos += vl_bytes + vl_len;
                }
                (15, 13) => {
                    let end = crate::ledger::meta::skip_field_raw(data, pos, 15);
                    additional_books
                        .extend(additional_book_directories_from_payload(&data[pos..end]));
                    pos = end;
                }
                (16, _) => {
                    if pos >= data.len() {
                        break;
                    }
                    pos += 1;
                }
                (17, _) => {
                    if pos + 20 > data.len() {
                        break;
                    }
                    pos += 20;
                }
                _ => {
                    break;
                }
            }
        }

        Some(Self {
            account,
            sequence,
            taker_pays: taker_pays.unwrap_or(Amount::Xrp(0)),
            taker_gets: taker_gets.unwrap_or(Amount::Xrp(0)),
            flags,
            book_directory,
            book_node,
            owner_node,
            expiration,
            domain_id,
            additional_books,
            previous_txn_id,
            previous_txn_lgr_seq,
            raw_sle: Some(data.to_vec()),
        })
    }

    /// Quality as (pays, gets) ratio for deterministic comparison.
    /// Use `quality_cmp` for ordering instead of f64 division.
    pub fn quality(&self) -> Option<f64> {
        let pays = amount_to_f64(&self.taker_pays);
        let gets = amount_to_f64(&self.taker_gets);
        if gets == 0.0 {
            None
        } else {
            Some(pays / gets)
        }
    }
}

// ── Deterministic amount arithmetic (i128) ────────────────────────────────────

/// Convert an Amount to i128 "normalized drops" for integer comparison.
/// XRP uses drops. IOU values use the mantissa, with the exponent handled via
/// cross-multiplication.
pub fn amount_to_i128(a: &Amount) -> i128 {
    match a {
        Amount::Xrp(drops) => *drops as i128,
        Amount::Iou { value, .. } => value.mantissa as i128,
        Amount::Mpt(_) => 0,
    }
}

/// Get the exponent (0 for XRP, value.exponent for IOU).
pub fn amount_exponent(a: &Amount) -> i32 {
    match a {
        Amount::Xrp(_) => 0, // drops are base units
        Amount::Iou { value, .. } => value.exponent,
        Amount::Mpt(_) => 0,
    }
}

/// Deterministic rate comparison: is rate(a_pays/a_gets) >= rate(b_pays/b_gets)?
/// Uses cross-multiplication to avoid division/float.
pub fn rate_gte(a_pays: &Amount, a_gets: &Amount, b_pays: &Amount, b_gets: &Amount) -> bool {
    // a_pays/a_gets >= b_pays/b_gets  ⟺  a_pays * b_gets >= b_pays * a_gets
    // For mixed XRP/IOU: normalize via exponent difference
    let ap = amount_to_i128(a_pays);
    let ag = amount_to_i128(a_gets);
    let bp = amount_to_i128(b_pays);
    let bg = amount_to_i128(b_gets);
    // Exponent adjustment: 10^(ea_pays + eb_gets) vs 10^(eb_pays + ea_gets)
    let exp_lhs = amount_exponent(a_pays) + amount_exponent(b_gets);
    let exp_rhs = amount_exponent(b_pays) + amount_exponent(a_gets);
    let lhs = ap * bg;
    let rhs = bp * ag;
    // Compare lhs * 10^exp_lhs vs rhs * 10^exp_rhs
    let exp_diff = exp_lhs - exp_rhs;
    match exp_diff.cmp(&0) {
        std::cmp::Ordering::Equal => lhs >= rhs,
        std::cmp::Ordering::Greater => {
            // lhs side is larger by 10^exp_diff. If diff > 38, i128 can't hold it.
            if exp_diff > 38 {
                return lhs > 0;
            } // definitively larger if non-zero
            lhs.saturating_mul(10i128.pow(exp_diff as u32)) >= rhs
        }
        std::cmp::Ordering::Less => {
            let diff = -exp_diff;
            if diff > 38 {
                return rhs <= 0;
            } // rhs side definitively larger
            lhs >= rhs.saturating_mul(10i128.pow(diff as u32))
        }
    }
}

/// Check if an amount is effectively zero.
pub fn amount_is_zero(a: &Amount) -> bool {
    match a {
        Amount::Xrp(d) => *d == 0,
        Amount::Iou { value, .. } => value.mantissa == 0,
        Amount::Mpt(_) => true,
    }
}

/// Legacy f64 conversion (kept for OrderBook sorting and display).
pub fn amount_to_f64(a: &Amount) -> f64 {
    match a {
        Amount::Xrp(drops) => *drops as f64,
        Amount::Iou { value, .. } => {
            if value.mantissa == 0 {
                return 0.0;
            }
            value.mantissa as f64 * 10f64.powi(value.exponent)
        }
        Amount::Mpt(_) => 0.0,
    }
}

/// Scale an amount by a ratio (numerator/denominator) using integer arithmetic.
pub fn scale_amount(a: &Amount, numerator: i128, denominator: i128) -> Amount {
    if denominator == 0 {
        return a.clone();
    }
    match a {
        Amount::Xrp(drops) => {
            // XRP: integer scale with truncation (rippled truncates XRP drops)
            let scaled = (*drops as i128 * numerator / denominator).max(0) as u64;
            Amount::Xrp(scaled)
        }
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            // IOU: use IouValue mul/div which match rippled's STAmount arithmetic
            // (muldiv with truncation + 5, then round-half-even normalize)
            let num_iou = IouValue {
                mantissa: numerator.clamp(i64::MIN as i128, i64::MAX as i128) as i64,
                exponent: 0,
            };
            let den_iou = IouValue {
                mantissa: denominator.clamp(i64::MIN as i128, i64::MAX as i128) as i64,
                exponent: 0,
            };
            let product = value.mul(&num_iou);
            let result = product.div(&den_iou);
            Amount::Iou {
                value: result,
                currency: currency.clone(),
                issuer: *issuer,
            }
        }
        Amount::Mpt(_) => a.clone(),
    }
}

/// Subtract `b` from `a` using integer arithmetic.
pub fn subtract_amount(a: &Amount, b: &Amount) -> Amount {
    match (a, b) {
        (Amount::Xrp(da), Amount::Xrp(db)) => Amount::Xrp(da.saturating_sub(*db)),
        (
            Amount::Iou {
                value: va,
                currency,
                issuer,
            },
            Amount::Iou { value: vb, .. },
        ) => {
            // Align exponents for subtraction using i128.
            // When exponent difference is large (>30), the smaller value is negligible.
            let exp_diff = (va.exponent - vb.exponent).abs();
            let (ma, mb, exp) = if va.exponent == vb.exponent {
                (va.mantissa as i128, vb.mantissa as i128, va.exponent)
            } else if exp_diff > 30 {
                // The smaller value is negligible relative to the larger
                if va.exponent > vb.exponent {
                    (va.mantissa as i128, 0i128, va.exponent)
                } else {
                    (0i128, vb.mantissa as i128, vb.exponent)
                }
            } else if va.exponent > vb.exponent {
                // Scale va up to match vb's exponent
                let shift = exp_diff as u32;
                (
                    va.mantissa as i128 * 10i128.pow(shift),
                    vb.mantissa as i128,
                    vb.exponent,
                )
            } else {
                // Scale vb up to match va's exponent
                let shift = exp_diff as u32;
                (
                    va.mantissa as i128,
                    vb.mantissa as i128 * 10i128.pow(shift),
                    va.exponent,
                )
            };
            let diff = (ma - mb).max(0).clamp(0, i64::MAX as i128) as i64;
            let mut result = IouValue {
                mantissa: diff,
                exponent: exp,
            };
            result.normalize();
            Amount::Iou {
                value: result,
                currency: currency.clone(),
                issuer: *issuer,
            }
        }
        _ => a.clone(), // mixed types — shouldn't happen
    }
}

// ── Book key ──────────────────────────────────────────────────────────────────

/// Identifies one side of an order book: (pay_currency, get_currency).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BookKey {
    pub pays_currency: [u8; 20],
    pub pays_issuer: [u8; 20],
    pub gets_currency: [u8; 20],
    pub gets_issuer: [u8; 20],
}

impl BookKey {
    pub fn from_amounts(pays: &Amount, gets: &Amount) -> Self {
        let (pc, pi) = currency_issuer(pays);
        let (gc, gi) = currency_issuer(gets);
        Self {
            pays_currency: pc,
            pays_issuer: pi,
            gets_currency: gc,
            gets_issuer: gi,
        }
    }

    /// The opposite book (swap pays/gets).
    pub fn inverse(&self) -> Self {
        Self {
            pays_currency: self.gets_currency,
            pays_issuer: self.gets_issuer,
            gets_currency: self.pays_currency,
            gets_issuer: self.pays_issuer,
        }
    }
}

fn currency_issuer(a: &Amount) -> ([u8; 20], [u8; 20]) {
    match a {
        Amount::Xrp(_) => ([0u8; 20], [0u8; 20]),
        Amount::Iou {
            currency, issuer, ..
        } => (currency.code, *issuer),
        Amount::Mpt(_) => ([0u8; 20], [0u8; 20]),
    }
}

// ── Order book ────────────────────────────────────────────────────────────────

/// Integer-exact quality key for deterministic BTreeMap ordering.
/// Uses i128 cross-multiplication (via rate_gte) instead of f64 division.
#[derive(Debug, Clone, Eq, PartialEq)]
struct QualityKey {
    pays: Amount,
    gets: Amount,
    seq: u32,
}

impl Ord for QualityKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_gte = rate_gte(&self.pays, &self.gets, &other.pays, &other.gets);
        let other_gte = rate_gte(&other.pays, &other.gets, &self.pays, &self.gets);
        match (self_gte, other_gte) {
            (true, true) => self.seq.cmp(&other.seq), // equal quality — older first
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            (false, false) => self.seq.cmp(&other.seq), // shouldn't happen, tiebreak
        }
    }
}

impl PartialOrd for QualityKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// An order book: offers sorted by deterministic integer quality (cheapest first).
#[derive(Debug, Clone, Default)]
pub struct OrderBook {
    offers: BTreeMap<QualityKey, Key>,
}

impl OrderBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, offer: &Offer) {
        let qk = QualityKey {
            pays: offer.taker_pays.clone(),
            gets: offer.taker_gets.clone(),
            seq: offer.sequence,
        };
        self.offers.insert(qk, offer.key());
    }

    pub fn remove(&mut self, offer: &Offer) {
        let qk = QualityKey {
            pays: offer.taker_pays.clone(),
            gets: offer.taker_gets.clone(),
            seq: offer.sequence,
        };
        self.offers.remove(&qk);
    }

    /// Iterate offers in ascending quality order (cheapest first).
    pub fn iter_by_quality(&self) -> impl Iterator<Item = &Key> {
        self.offers.values()
    }

    pub fn len(&self) -> usize {
        self.offers.len()
    }
    pub fn is_empty(&self) -> bool {
        self.offers.is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::amount::Currency;

    fn acct(n: u8) -> [u8; 20] {
        [n; 20]
    }

    fn xrp(drops: u64) -> Amount {
        Amount::Xrp(drops)
    }

    fn usd(v: f64, issuer: u8) -> Amount {
        Amount::Iou {
            value: IouValue::from_f64(v),
            currency: Currency::from_code("USD").unwrap(),
            issuer: acct(issuer),
        }
    }

    fn additional_books_payload(entries: &[([u8; 32], u64)]) -> Vec<u8> {
        let mut data = Vec::new();
        for (book_directory, book_node) in entries {
            crate::ledger::meta::write_field_header_pub(&mut data, 14, 36);
            crate::ledger::meta::write_field_header_pub(&mut data, 3, 3);
            data.extend_from_slice(&book_node.to_be_bytes());
            crate::ledger::meta::write_field_header_pub(&mut data, 5, 16);
            data.extend_from_slice(book_directory);
            data.push(0xE1);
        }
        data.push(0xF1);
        data
    }

    #[test]
    fn parses_rippled_additional_books_payload() {
        let book_directory = [0x42; 32];
        let payload = additional_books_payload(&[(book_directory, 9)]);

        assert_eq!(
            additional_book_entries_from_payload(&payload),
            vec![(book_directory, 9)]
        );
        assert_eq!(
            additional_book_directories_from_payload(&payload),
            vec![book_directory]
        );
    }

    #[test]
    fn encodes_additional_books_as_book_objects() {
        let book_directory = [0x55; 32];
        let offer = Offer {
            account: acct(1),
            sequence: 1,
            taker_pays: xrp(1_000_000),
            taker_gets: usd(10.0, 2),
            flags: 0,
            book_directory: [0u8; 32],
            book_node: 0,
            owner_node: 0,
            expiration: None,
            domain_id: None,
            additional_books: vec![book_directory],
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };

        let raw = offer.encode();
        let decoded = Offer::decode_from_sle(&raw).expect("valid offer SLE");

        assert!(raw.windows(2).any(|window| window == [0xE0, 0x24]));
        assert_eq!(decoded.additional_books, vec![book_directory]);
    }

    #[test]
    fn test_offer_key_deterministic() {
        let k1 = shamap_key(&acct(1), 5);
        let k2 = shamap_key(&acct(1), 5);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_different_sequence_different_key() {
        assert_ne!(shamap_key(&acct(1), 1), shamap_key(&acct(1), 2));
    }

    #[test]
    fn test_offer_quality() {
        let offer = Offer {
            account: acct(1),
            sequence: 1,
            taker_pays: xrp(1_000_000), // wants 1 XRP
            taker_gets: usd(10.0, 2),   // giving 10 USD
            flags: 0,
            book_directory: [0u8; 32],
            book_node: 0,
            owner_node: 0,
            expiration: None,
            domain_id: None,
            additional_books: Vec::new(),
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let q = offer.quality().unwrap();
        // quality = pays/gets = 1_000_000 / 10 = 100_000
        assert!((q - 100_000.0).abs() < 1.0);
    }

    #[test]
    fn test_order_book_sorted_by_quality() {
        let mut book = OrderBook::new();

        let cheap = Offer {
            account: acct(1),
            sequence: 1,
            taker_pays: xrp(1_000_000),
            taker_gets: usd(100.0, 2), // quality = 10000
            flags: 0,
            book_directory: [0u8; 32],
            book_node: 0,
            owner_node: 0,
            expiration: None,
            domain_id: None,
            additional_books: Vec::new(),
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let expensive = Offer {
            account: acct(3),
            sequence: 2,
            taker_pays: xrp(1_000_000),
            taker_gets: usd(10.0, 2), // quality = 100000
            flags: 0,
            book_directory: [0u8; 32],
            book_node: 0,
            owner_node: 0,
            expiration: None,
            domain_id: None,
            additional_books: Vec::new(),
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };

        book.insert(&expensive);
        book.insert(&cheap);

        // Cheapest (lowest quality) should come first
        let keys: Vec<_> = book.iter_by_quality().collect();
        assert_eq!(keys[0], &cheap.key());
        assert_eq!(keys[1], &expensive.key());
    }

    #[test]
    fn test_book_key_inverse() {
        let bk = BookKey::from_amounts(&xrp(100), &usd(10.0, 2));
        let inv = bk.inverse();
        assert_eq!(inv.pays_currency, bk.gets_currency);
        assert_eq!(inv.gets_currency, bk.pays_currency);
    }

    #[test]
    fn test_order_book_remove() {
        let mut book = OrderBook::new();
        let offer = Offer {
            account: acct(1),
            sequence: 1,
            taker_pays: xrp(1_000_000),
            taker_gets: usd(10.0, 2),
            flags: 0,
            book_directory: [0u8; 32],
            book_node: 0,
            owner_node: 0,
            expiration: None,
            domain_id: None,
            additional_books: Vec::new(),
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        book.insert(&offer);
        assert_eq!(book.len(), 1);
        book.remove(&offer);
        assert!(book.is_empty());
    }
}
