//! Ledger primitives, state trees, and transaction application.
//!
//! View stack: `ClosedLedger` (`ReadView` + `RawView`) → `OpenView`
//! (`TxsRawView`) → `ApplyViewImpl` (`ApplyView`).

pub mod account;
pub mod tx;

// View stack.
pub mod apply_view_impl;
#[cfg(test)]
#[allow(dead_code, unused_imports)]
mod close_v2;
pub mod fees;
pub mod keylet;
pub mod ledger_core;
pub mod open_view;
pub mod prune;
pub mod rules;
pub mod sfield_meta;
pub mod sle;
pub mod state_table;
#[allow(dead_code, unused_imports)]
pub mod transact;
#[cfg(test)]
#[allow(dead_code, unused_imports)]
mod transactor;
pub mod views;
// Preserve the legacy `crate::ledger::apply::*` import path.
pub mod apply {
    pub use super::tx::{apply_tx, ApplyResult, TxContext};
}
pub mod check;
pub mod close;
pub mod control;
pub mod deposit_preauth;
pub mod did;
pub mod diff_sync;
pub mod directory;
pub mod escrow;
pub mod fetch_pack;
#[allow(dead_code, unused_imports)]
pub mod follow;
pub mod forensic;
pub mod full_below_cache;
pub mod history;
pub mod inbound;
pub mod inbound_transactions;
pub mod invariants;
pub mod master;
pub mod meta;
pub mod nft_page;
pub mod nftoken;
pub mod node_store;
pub mod offer;
pub mod open_ledger;
pub mod paychan;
pub mod pool;
pub mod shamap;
pub mod shamap_id;
pub mod shamap_sync;
pub mod sparse_shamap;
pub mod ter;
pub mod ticket;
pub mod tree_cache;
pub mod trustline;

pub use account::{shamap_key, AccountRoot};
pub use check::Check;
pub use close::{
    close_ledger, extract_tx_blobs_from_tx_tree, replay_ledger, CloseResult, ReplayResult,
};
pub use deposit_preauth::DepositPreauth;
pub use did::Did;
pub use directory::DirectoryNode;
pub use escrow::Escrow;
pub use history::{LedgerStore, TxRecord};
pub use nftoken::{NFToken, NFTokenOffer};
pub use offer::{BookKey, Offer, OrderBook};
pub use paychan::PayChannel;
pub use pool::TxPool;
pub use shamap::{Key, MapType, SHAMap};
pub use ticket::Ticket;
pub use trustline::RippleState;

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, MutexGuard};

use serde::{Deserialize, Serialize};

fn amendment_hash(name: &str) -> [u8; 32] {
    crate::crypto::sha512_first_half(name.as_bytes())
}

static FEATURE_FIX_PREVIOUS_TXN_ID: LazyLock<[u8; 32]> =
    LazyLock::new(|| amendment_hash("fixPreviousTxnID"));

pub(crate) fn fix_previous_txn_id_enabled(state: &LedgerState) -> bool {
    state.is_amendment_active(&FEATURE_FIX_PREVIOUS_TXN_ID)
}

pub(crate) fn should_thread_previous_txn_fields_with_fix_previous_txn_id(
    fix_previous_txn_id_enabled: bool,
    entry_type: sle::LedgerEntryType,
) -> bool {
    let has_previous_txn_fields = !matches!(entry_type, sle::LedgerEntryType::LedgerHashes);
    if !has_previous_txn_fields {
        return false;
    }

    let gated_by_fix_previous_txn_id = matches!(
        entry_type,
        sle::LedgerEntryType::DirectoryNode
            | sle::LedgerEntryType::Amendments
            | sle::LedgerEntryType::FeeSettings
            | sle::LedgerEntryType::NegativeUNL
            | sle::LedgerEntryType::AMM
    );

    !gated_by_fix_previous_txn_id || fix_previous_txn_id_enabled
}

pub(crate) fn should_thread_previous_txn_fields(
    state: &LedgerState,
    entry_type: sle::LedgerEntryType,
) -> bool {
    should_thread_previous_txn_fields_with_fix_previous_txn_id(
        fix_previous_txn_id_enabled(state),
        entry_type,
    )
}

// ── Fee settings (from FeeSettings ledger object) ────────────────────────────

/// Network fee parameters — matches rippled's `Fees` struct.
/// Populated from the FeeSettings SLE; falls back to defaults.
#[derive(Debug, Clone, Copy)]
pub struct Fees {
    /// Base transaction fee in drops (default: 10).
    pub base: u64,
    /// Minimum XRP reserve for an account in drops (default: 1_000_000 = 1 XRP).
    pub reserve: u64,
    /// Additional reserve per owned object in drops (default: 200_000 = 0.2 XRP).
    pub increment: u64,
}

impl Default for Fees {
    fn default() -> Self {
        Self {
            base: 10,
            reserve: 1_000_000,
            increment: 200_000,
        }
    }
}

/// FeeSettings namespace byte: 'e' = 0x65.
const FEE_SETTINGS_SPACE: [u8; 2] = [0x00, 0x65];

/// Compute the FeeSettings singleton key: sha512Half(0x0065).
pub fn fees_key() -> Key {
    Key(crate::crypto::sha512_first_half(&FEE_SETTINGS_SPACE))
}

/// Parse a FeeSettings SLE from raw serialized bytes.
/// Supports both old format (sfBaseFee/sfReserveBase/sfReserveIncrement)
/// and new format (sfBaseFeeDrops/sfReserveBaseDrops/sfReserveIncrementDrops).
/// Returns Fees with defaults for any missing fields.
pub fn parse_fee_settings(data: &[u8]) -> Fees {
    let mut fees = Fees::default();

    // Skip the SLE prefix: first 4 bytes are typically the LedgerEntryType prefix.
    // The raw SLE starts with a field-header-encoded type + index.
    // Scan for known field codes instead of assuming a fixed offset.
    let mut pos = 0;
    while pos < data.len() {
        if data.len() - pos < 1 {
            break;
        }
        let byte = data[pos];
        pos += 1;

        // Decode field header (same as transaction serialization)
        let type_code;
        let field_code;
        let hi = (byte >> 4) & 0x0F;
        let lo = byte & 0x0F;
        if hi != 0 && lo != 0 {
            type_code = hi as u16;
            field_code = lo as u16;
        } else if hi == 0 && lo != 0 {
            if pos >= data.len() {
                break;
            }
            type_code = data[pos] as u16;
            pos += 1;
            field_code = lo as u16;
        } else if hi != 0 && lo == 0 {
            if pos >= data.len() {
                break;
            }
            type_code = hi as u16;
            field_code = data[pos] as u16;
            pos += 1;
        } else {
            if pos + 1 >= data.len() {
                break;
            }
            type_code = data[pos] as u16;
            pos += 1;
            field_code = data[pos] as u16;
            pos += 1;
        }

        match type_code {
            1 => {
                // UInt16 (2 bytes) — includes LedgerEntryType
                if pos + 2 > data.len() {
                    break;
                }
                pos += 2;
            }
            2 => {
                // UInt32 (4 bytes)
                if pos + 4 > data.len() {
                    break;
                }
                let v = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
                match field_code {
                    // Old format fields
                    30 => { /* sfReferenceFeeUnits — ignored, deprecated */ }
                    31 => fees.reserve = v as u64,   // sfReserveBase
                    32 => fees.increment = v as u64, // sfReserveIncrement
                    _ => {}
                }
                pos += 4;
            }
            3 => {
                // UInt64 (8 bytes)
                if pos + 8 > data.len() {
                    break;
                }
                let v = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
                if field_code == 5 {
                    fees.base = v; // sfBaseFee (old format)
                }
                pos += 8;
            }
            5 => {
                // Hash256 (32 bytes)
                if pos + 32 > data.len() {
                    break;
                }
                pos += 32;
            }
            6 => {
                // Amount (variable: 8 bytes for XRP, 48 for IOU)
                if pos + 8 > data.len() {
                    break;
                }
                let first = data[pos];
                if first & 0x80 != 0 {
                    // XRP amount: 8 bytes, top bit is "positive" flag
                    let raw = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
                    let drops = raw & 0x3FFF_FFFF_FFFF_FFFF; // mask off top 2 bits
                    match field_code {
                        22 => fees.base = drops,      // sfBaseFeeDrops (new format)
                        23 => fees.reserve = drops,   // sfReserveBaseDrops
                        24 => fees.increment = drops, // sfReserveIncrementDrops
                        _ => {}
                    }
                    pos += 8;
                } else {
                    // IOU amount: 48 bytes — skip (shouldn't appear in FeeSettings)
                    if pos + 48 > data.len() {
                        break;
                    }
                    pos += 48;
                }
            }
            7 => {
                // VL (variable length) — skip
                if pos >= data.len() {
                    break;
                }
                let (len, consumed) = decode_vl_length(&data[pos..]);
                pos += consumed + len;
            }
            14 => {
                // STObject — skip all nested fields until end marker
                // (PreviousTxnID etc. are flat fields, not nested objects in FeeSettings)
            }
            15 => {
                // STArray — skip until array end marker (0xF1)
                while pos < data.len() && data[pos] != 0xF1 {
                    pos += 1;
                }
                if pos < data.len() {
                    pos += 1;
                } // skip end marker
            }
            _ => {
                // Unknown type — can't determine length, stop parsing
                break;
            }
        }
    }
    fees
}

/// Read Fees from a LedgerState by looking up the FeeSettings singleton.
/// Returns defaults if the object doesn't exist.
pub fn read_fees(state: &LedgerState) -> Fees {
    let key = fees_key();
    match state.get_raw_owned(&key) {
        Some(data) => parse_fee_settings(&data),
        None => Fees::default(),
    }
}

/// Decode a variable-length prefix (1-3 bytes) used in XRPL serialization.
pub fn decode_vl_length(data: &[u8]) -> (usize, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    let b0 = data[0] as usize;
    if b0 <= 192 {
        (b0, 1)
    } else if b0 <= 240 {
        if data.len() < 2 {
            return (0, 1);
        }
        let b1 = data[1] as usize;
        (193 + ((b0 - 193) * 256) + b1, 2)
    } else if b0 <= 254 {
        if data.len() < 3 {
            return (0, 1);
        }
        let b1 = data[1] as usize;
        let b2 = data[2] as usize;
        (12481 + ((b0 - 241) * 65536) + (b1 * 256) + b2, 3)
    } else {
        (0, 1) // 0xFF = reserved
    }
}

// ── SLE serialization helpers ────────────────────────────────────────────────

/// Encode a field header for the XRPL STObject binary format.
pub fn encode_field_header(out: &mut Vec<u8>, type_code: u8, field_code: u8) {
    if type_code < 16 && field_code < 16 {
        out.push((type_code << 4) | field_code);
    } else if type_code < 16 && field_code >= 16 {
        out.push(type_code << 4); // low nibble 0
        out.push(field_code);
    } else if type_code >= 16 && field_code < 16 {
        out.push(field_code); // high nibble 0
        out.push(type_code);
    } else {
        out.push(0);
        out.push(type_code);
        out.push(field_code);
    }
}

/// Encode a VL (variable-length) prefix.
fn encode_vl_length(out: &mut Vec<u8>, len: usize) {
    if len <= 192 {
        out.push(len as u8);
    } else if len <= 12480 {
        let adj = len - 193;
        out.push((adj / 256 + 193) as u8);
        out.push((adj % 256) as u8);
    } else {
        let adj = len - 12481;
        out.push((adj / 65536 + 241) as u8);
        out.push(((adj / 256) % 256) as u8);
        out.push((adj % 256) as u8);
    }
}

/// Serialize a FeeSettings SLE to binary.
/// Supports both old format (sfBaseFee/sfReserveBase/sfReserveIncrement) and new
/// format (sfBaseFeeDrops/sfReserveBaseDrops/sfReserveIncrementDrops).
/// For simplicity, always writes old format — the XRPFees amendment switches to new.
pub fn serialize_fee_settings(fees: &Fees) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);

    // LedgerEntryType = 0x0073 (type=1 UInt16, field=1)
    encode_field_header(&mut out, 1, 1);
    out.extend_from_slice(&0x0073u16.to_be_bytes());

    // sfReferenceFeeUnits = 10 (type=2 UInt32, field=30)
    encode_field_header(&mut out, 2, 30);
    out.extend_from_slice(&10u32.to_be_bytes());

    // sfReserveBase (type=2 UInt32, field=31)
    encode_field_header(&mut out, 2, 31);
    out.extend_from_slice(&(fees.reserve as u32).to_be_bytes());

    // sfReserveIncrement (type=2 UInt32, field=32)
    encode_field_header(&mut out, 2, 32);
    out.extend_from_slice(&(fees.increment as u32).to_be_bytes());

    // sfBaseFee (type=3 UInt64, field=5)
    encode_field_header(&mut out, 3, 5);
    out.extend_from_slice(&fees.base.to_be_bytes());

    out
}

/// Serialize an Amendments SLE to binary.
/// `enabled`: the sfAmendments vector (hashes of enabled amendments).
/// `majorities_raw`: optional raw bytes for the sfMajorities array (passed through unchanged).
pub fn serialize_amendments(enabled: &[[u8; 32]], majorities_raw: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + enabled.len() * 32);

    // LedgerEntryType = 0x0066 (type=1 UInt16, field=1)
    encode_field_header(&mut out, 1, 1);
    out.extend_from_slice(&0x0066u16.to_be_bytes());

    // sfAmendments (type=19 VECTOR256, field=3) — if non-empty
    if !enabled.is_empty() {
        encode_field_header(&mut out, 19, 3);
        let vl_len = enabled.len() * 32;
        encode_vl_length(&mut out, vl_len);
        for hash in enabled {
            out.extend_from_slice(hash);
        }
    }

    // sfMajorities (type=15 ARRAY, field=16) — pass through raw if present
    if let Some(raw) = majorities_raw {
        if !raw.is_empty() {
            encode_field_header(&mut out, 15, 16);
            out.extend_from_slice(raw);
            // Array end marker already in raw bytes (0xF1)
        }
    }

    out
}

/// Serialize a NegativeUNL SLE to binary.
/// `disabled_validators`: list of public key blobs.
/// `to_disable`: optional validator to disable next.
/// `to_reenable`: optional validator to re-enable next.
pub fn serialize_negative_unl(
    disabled_validators: &[Vec<u8>],
    to_disable: Option<&[u8]>,
    to_reenable: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);

    // LedgerEntryType = 0x004e (type=1 UInt16, field=1)
    encode_field_header(&mut out, 1, 1);
    out.extend_from_slice(&0x004eu16.to_be_bytes());

    // sfValidatorToDisable (type=7 VL, field=20)
    if let Some(pk) = to_disable {
        encode_field_header(&mut out, 7, 20);
        encode_vl_length(&mut out, pk.len());
        out.extend_from_slice(pk);
    }

    // sfValidatorToReEnable (type=7 VL, field=21)
    if let Some(pk) = to_reenable {
        encode_field_header(&mut out, 7, 21);
        encode_vl_length(&mut out, pk.len());
        out.extend_from_slice(pk);
    }

    // sfDisabledValidators (type=15 ARRAY, field=17)
    if !disabled_validators.is_empty() {
        encode_field_header(&mut out, 15, 17);
        for pk in disabled_validators {
            // Each element is an STObject (sfDisabledValidator, type=14 OBJECT, field=19)
            encode_field_header(&mut out, 14, 19);
            // sfPublicKey (type=7 VL, field=1)
            encode_field_header(&mut out, 7, 1);
            encode_vl_length(&mut out, pk.len());
            out.extend_from_slice(pk);
            // Object end marker
            out.push(0xE1);
        }
        // Array end marker
        out.push(0xF1);
    }

    out
}

// ── Amendments (from Amendments ledger object) ──────────────────────────────

/// Amendments namespace byte: 'f' = 0x66.
const AMENDMENTS_SPACE: [u8; 2] = [0x00, 0x66];

/// Compute the Amendments singleton key: sha512Half(0x0066).
pub fn amendments_key() -> Key {
    Key(crate::crypto::sha512_first_half(&AMENDMENTS_SPACE))
}

/// Parse the Amendments SLE and extract enabled amendment hashes.
/// The sfAmendments field is VECTOR256 (type=19, field=3): VL-length prefix + N×32 bytes.
pub fn parse_amendments(data: &[u8]) -> Vec<[u8; 32]> {
    let mut amendments = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        if data.len() - pos < 1 {
            break;
        }
        let byte = data[pos];
        pos += 1;

        let type_code;
        let field_code;
        let hi = (byte >> 4) & 0x0F;
        let lo = byte & 0x0F;
        if hi != 0 && lo != 0 {
            type_code = hi as u16;
            field_code = lo as u16;
        } else if hi == 0 && lo != 0 {
            if pos >= data.len() {
                break;
            }
            type_code = data[pos] as u16;
            pos += 1;
            field_code = lo as u16;
        } else if hi != 0 && lo == 0 {
            if pos >= data.len() {
                break;
            }
            type_code = hi as u16;
            field_code = data[pos] as u16;
            pos += 1;
        } else {
            if pos + 1 >= data.len() {
                break;
            }
            type_code = data[pos] as u16;
            pos += 1;
            field_code = data[pos] as u16;
            pos += 1;
        }

        match type_code {
            1 => {
                // UInt16
                if pos + 2 > data.len() {
                    break;
                }
                pos += 2;
            }
            2 => {
                // UInt32
                if pos + 4 > data.len() {
                    break;
                }
                pos += 4;
            }
            3 => {
                // UInt64
                if pos + 8 > data.len() {
                    break;
                }
                pos += 8;
            }
            5 => {
                // Hash256
                if pos + 32 > data.len() {
                    break;
                }
                pos += 32;
            }
            7 => {
                // VL (Blob)
                if pos >= data.len() {
                    break;
                }
                let (len, consumed) = decode_vl_length(&data[pos..]);
                pos += consumed + len;
            }
            15 => {
                // STArray (sfMajorities = type 15, field 16) — skip until end marker 0xF1.
                // Each element is an STObject ending with 0xE1, array ends with 0xF1.
                while pos < data.len() && data[pos] != 0xF1 {
                    pos += 1;
                }
                if pos < data.len() {
                    pos += 1;
                } // skip 0xF1 end marker
            }
            19 => {
                // VECTOR256 — sfAmendments (field=3): VL-length + N×32 raw hashes.
                if field_code == 3 {
                    if pos >= data.len() {
                        break;
                    }
                    let (vl_len, consumed) = decode_vl_length(&data[pos..]);
                    pos += consumed;
                    if pos + vl_len > data.len() {
                        break;
                    }
                    let count = vl_len / 32;
                    for i in 0..count {
                        let start = pos + i * 32;
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&data[start..start + 32]);
                        amendments.push(hash);
                    }
                    pos += vl_len;
                } else {
                    // Unknown VECTOR256 field — skip via VL length
                    if pos >= data.len() {
                        break;
                    }
                    let (vl_len, consumed) = decode_vl_length(&data[pos..]);
                    pos += consumed + vl_len;
                }
            }
            _ => {
                break; // Unknown type, stop
            }
        }
    }
    amendments
}

/// Read enabled amendments from the Amendments SLE in a LedgerState.
/// Returns empty vec if the object doesn't exist.
pub fn read_amendments(state: &LedgerState) -> Vec<[u8; 32]> {
    let key = amendments_key();
    match state.get_raw_owned(&key) {
        Some(data) => parse_amendments(&data),
        None => Vec::new(),
    }
}

/// A closed, validated ledger header.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LedgerHeader {
    pub sequence: u32,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub close_time: u64, // stored as u64 internally, serialized as u32
    /// Total XRP in existence, in drops.
    pub total_coins: u64,
    /// Root hash of the account-state SHAMap.
    pub account_hash: [u8; 32],
    /// Root hash of the transaction SHAMap.
    pub transaction_hash: [u8; 32],
    /// Parent ledger's close time (u32 in rippled).
    pub parent_close_time: u32,
    /// Close time resolution in seconds.
    pub close_time_resolution: u8,
    /// Close flags.
    pub close_flags: u8,
}

impl LedgerHeader {
    /// The ledger hash is SHA-512-half of the serialized header fields.
    /// Matches rippled's calculateLedgerHash exactly.
    pub fn compute_hash(&self) -> [u8; 32] {
        use crate::crypto::sha512_first_half;
        // Hash prefix: "LWR\0" = 0x4C575200
        let mut payload = Vec::with_capacity(4 + 4 + 8 + 32 + 32 + 32 + 4 + 4 + 1 + 1);
        payload.extend_from_slice(&[0x4C, 0x57, 0x52, 0x00]);
        payload.extend_from_slice(&self.sequence.to_be_bytes());
        payload.extend_from_slice(&self.total_coins.to_be_bytes());
        payload.extend_from_slice(&self.parent_hash);
        payload.extend_from_slice(&self.transaction_hash);
        payload.extend_from_slice(&self.account_hash);
        payload.extend_from_slice(&self.parent_close_time.to_be_bytes());
        payload.extend_from_slice(&(self.close_time as u32).to_be_bytes());
        payload.push(self.close_time_resolution);
        payload.push(self.close_flags);
        sha512_first_half(&payload)
    }
}

// ── Dirty tracking ────────────────────────────────────────────────────────────

/// Snapshot of which entries were modified or deleted since the last save.
#[derive(Clone, Default)]
pub struct DirtyState {
    pub dirty_accounts: HashSet<[u8; 20]>,
    pub deleted_accounts: HashSet<[u8; 20]>,
    pub dirty_trustlines: HashSet<Key>,
    pub deleted_trustlines: HashSet<Key>,
    pub dirty_checks: HashSet<Key>,
    pub deleted_checks: HashSet<Key>,
    pub dirty_deposit_preauths: HashSet<Key>,
    pub deleted_deposit_preauths: HashSet<Key>,
    pub dirty_dids: HashSet<Key>,
    pub deleted_dids: HashSet<Key>,
    pub dirty_escrows: HashSet<Key>,
    pub deleted_escrows: HashSet<Key>,
    pub dirty_paychans: HashSet<Key>,
    pub deleted_paychans: HashSet<Key>,
    pub dirty_tickets: HashSet<Key>,
    pub deleted_tickets: HashSet<Key>,
    pub dirty_offers: HashSet<Key>,
    pub deleted_offers: HashSet<Key>,
    pub dirty_nft_offers: HashSet<Key>,
    pub dirty_directories: HashSet<Key>,
    pub deleted_directories: HashSet<Key>,
    pub dirty_raw: HashSet<Key>,
    pub deleted_raw: HashSet<Key>,
}

struct TxJournal {
    order: Vec<Key>,
    before: HashMap<Key, Option<Vec<u8>>>,
}

// ── Per-tx typed snapshot (for rollback) ─────────────────────────────────────

/// A typed ledger entry, clonable for snapshot purposes.
#[derive(Clone)]
enum TypedEntry {
    Account([u8; 20], AccountRoot),
    Trustline(Key, RippleState),
    Check(Key, Check),
    DepositPreauth(Key, DepositPreauth),
    Did(Key, Did),
    Escrow(Key, Escrow),
    PayChannel(Key, PayChannel),
    Ticket(Key, Ticket),
    NFToken([u8; 32], NFToken),
    NFTokenOffer(Key, NFTokenOffer),
    Offer(Key, Offer),
    Directory(Key, DirectoryNode),
}

/// Snapshot state for one transaction, enabling rollback on discard.
struct TxSnapshot {
    /// For each SHAMap key touched: the typed entry that existed before
    /// (None = entry didn't exist, Some = entry to restore).
    typed_before: Vec<(Key, Option<TypedEntry>)>,
    /// Dirty/deleted tracking state at begin_tx time.
    dirty_accounts_snap: HashSet<[u8; 20]>,
    deleted_accounts_snap: HashSet<[u8; 20]>,
    dirty_trustlines_snap: HashSet<Key>,
    deleted_trustlines_snap: HashSet<Key>,
    dirty_checks_snap: HashSet<Key>,
    deleted_checks_snap: HashSet<Key>,
    dirty_deposit_preauths_snap: HashSet<Key>,
    deleted_deposit_preauths_snap: HashSet<Key>,
    dirty_dids_snap: HashSet<Key>,
    deleted_dids_snap: HashSet<Key>,
    dirty_escrows_snap: HashSet<Key>,
    deleted_escrows_snap: HashSet<Key>,
    dirty_paychans_snap: HashSet<Key>,
    deleted_paychans_snap: HashSet<Key>,
    dirty_tickets_snap: HashSet<Key>,
    deleted_tickets_snap: HashSet<Key>,
    dirty_offers_snap: HashSet<Key>,
    deleted_offers_snap: HashSet<Key>,
    dirty_nft_offers_snap: HashSet<Key>,
    dirty_directories_snap: HashSet<Key>,
    deleted_directories_snap: HashSet<Key>,
    dirty_raw_snap: HashSet<Key>,
    deleted_raw_snap: HashSet<Key>,
}

// ── LedgerState ───────────────────────────────────────────────────────────────

/// The live account state for one validated ledger.
///
/// Maintains a SHAMap (for root-hash computation) and a HashMap index
/// (for O(1) account lookups by AccountID).
pub struct LedgerState {
    state_map: SHAMap,
    /// Sparse SHAMap — when set, used for state_hash() instead of state_map.
    /// Stores only hashes (~1GB), not leaf data (~19GB).
    sparse_map: Option<sparse_shamap::SparseSHAMap>,
    /// Storage reference for disk fallback in sparse mode.
    storage: Option<std::sync::Arc<crate::storage::Storage>>,
    accounts: HashMap<[u8; 20], AccountRoot>,
    /// Trust lines keyed by SHAMap key (derived from low+high accounts + currency).
    trustlines: HashMap<Key, RippleState>,
    /// Checks keyed by SHAMap key.
    checks: HashMap<Key, Check>,
    /// Deposit pre-authorizations.
    pub(crate) deposit_preauths: HashMap<Key, DepositPreauth>,
    /// DIDs keyed by SHAMap key (derived from account).
    dids: HashMap<Key, Did>,
    /// Escrows keyed by SHAMap key (derived from account + sequence).
    escrows: HashMap<Key, Escrow>,
    /// Payment channels keyed by SHAMap key.
    paychans: HashMap<Key, PayChannel>,
    /// Tickets keyed by SHAMap key.
    tickets: HashMap<Key, Ticket>,
    /// NFTokens keyed by NFTokenID (32 bytes) — flat store (legacy, being migrated to pages).
    nftokens: HashMap<[u8; 32], NFToken>,
    /// NFTokenPages keyed by page Key — page-based store matching rippled.
    nft_pages: std::collections::BTreeMap<Key, nft_page::NFTokenPage>,
    /// NFToken offers keyed by SHAMap key.
    nft_offers: HashMap<Key, NFTokenOffer>,
    /// All offers keyed by SHAMap key (derived from account + sequence).
    offers: HashMap<Key, Offer>,
    /// Order books keyed by (pays_currency, gets_currency) pair.
    order_books: HashMap<BookKey, OrderBook>,
    /// Directory nodes keyed by SHAMap key.
    directories: HashMap<Key, DirectoryNode>,
    /// Secondary index: account → trust line keys.
    account_trustlines: HashMap<[u8; 20], Vec<Key>>,
    /// Secondary index: account → offer keys.
    account_offers_idx: HashMap<[u8; 20], Vec<Key>>,
    /// Active amendments (set of 32-byte amendment hashes).
    active_amendments: HashSet<[u8; 32]>,
    // ── Dirty tracking ──
    dirty_accounts: HashSet<[u8; 20]>,
    deleted_accounts: HashSet<[u8; 20]>,
    dirty_trustlines: HashSet<Key>,
    deleted_trustlines: HashSet<Key>,
    dirty_checks: HashSet<Key>,
    deleted_checks: HashSet<Key>,
    dirty_deposit_preauths: HashSet<Key>,
    deleted_deposit_preauths: HashSet<Key>,
    dirty_dids: HashSet<Key>,
    deleted_dids: HashSet<Key>,
    dirty_escrows: HashSet<Key>,
    deleted_escrows: HashSet<Key>,
    dirty_paychans: HashSet<Key>,
    deleted_paychans: HashSet<Key>,
    dirty_tickets: HashSet<Key>,
    deleted_tickets: HashSet<Key>,
    dirty_offers: HashSet<Key>,
    deleted_offers: HashSet<Key>,
    dirty_nft_offers: HashSet<Key>,
    dirty_directories: HashSet<Key>,
    deleted_directories: HashSet<Key>,
    dirty_raw: HashSet<Key>,
    deleted_raw: HashSet<Key>,
    previous_txn_only_touches: HashSet<Key>,
    tx_journal: Option<TxJournal>,
    tx_snapshot: Option<TxSnapshot>,
    /// When true, insert_raw/remove_raw skip per-entry storage writes
    /// and buffer data in state_map instead. Used by follower replay to
    /// avoid write amplification — the snapshot persist does a single
    /// batch write afterward.
    defer_storage: bool,
    /// Content-addressed SHAMap backed by NuDB via NodeStore.
    /// When set, insert_raw/remove_raw dual-write to both state_map and this map.
    /// After validation, this becomes the primary store (replacing state_map).
    /// Wrapped in Mutex for thread-safe interior mutability — reads resolve stubs.
    nudb_shamap: Option<std::sync::Mutex<shamap::SHAMap>>,
}

impl LedgerState {
    pub fn new() -> Self {
        Self {
            state_map: SHAMap::new_state(),
            sparse_map: None,
            storage: None,
            accounts: HashMap::new(),
            trustlines: HashMap::new(),
            checks: HashMap::new(),
            deposit_preauths: HashMap::new(),
            dids: HashMap::new(),
            escrows: HashMap::new(),
            paychans: HashMap::new(),
            tickets: HashMap::new(),
            nftokens: HashMap::new(),
            nft_pages: std::collections::BTreeMap::new(),
            nft_offers: HashMap::new(),
            offers: HashMap::new(),
            order_books: HashMap::new(),
            directories: HashMap::new(),
            account_trustlines: HashMap::new(),
            account_offers_idx: HashMap::new(),
            active_amendments: HashSet::new(),
            dirty_accounts: HashSet::new(),
            deleted_accounts: HashSet::new(),
            dirty_trustlines: HashSet::new(),
            deleted_trustlines: HashSet::new(),
            dirty_checks: HashSet::new(),
            deleted_checks: HashSet::new(),
            dirty_deposit_preauths: HashSet::new(),
            deleted_deposit_preauths: HashSet::new(),
            dirty_dids: HashSet::new(),
            deleted_dids: HashSet::new(),
            dirty_escrows: HashSet::new(),
            deleted_escrows: HashSet::new(),
            dirty_paychans: HashSet::new(),
            deleted_paychans: HashSet::new(),
            dirty_tickets: HashSet::new(),
            deleted_tickets: HashSet::new(),
            dirty_offers: HashSet::new(),
            deleted_offers: HashSet::new(),
            dirty_nft_offers: HashSet::new(),
            dirty_directories: HashSet::new(),
            deleted_directories: HashSet::new(),
            dirty_raw: HashSet::new(),
            deleted_raw: HashSet::new(),
            previous_txn_only_touches: HashSet::new(),
            tx_journal: None,
            tx_snapshot: None,
            defer_storage: false,
            nudb_shamap: None,
        }
    }

    /// Set a content-addressed SHAMap backed by a NodeStore (NuDB).
    /// Enables dual-write mode: insert_raw writes to both state_map and nudb_shamap.
    pub fn set_nudb_shamap(&mut self, map: shamap::SHAMap) {
        self.nudb_shamap = Some(std::sync::Mutex::new(map));
    }

    fn nudb_map_guard(&self) -> Option<MutexGuard<'_, shamap::SHAMap>> {
        self.nudb_shamap
            .as_ref()
            .map(|m| m.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Get the NuDB-backed SHAMap's root hash (for comparison with state_map hash).
    pub fn nudb_root_hash(&self) -> Option<[u8; 32]> {
        self.nudb_map_guard().map(|mut map| map.root_hash())
    }

    /// Rehydrate the NuDB-backed SHAMap root from a persisted account-state hash.
    pub fn load_nudb_root(&mut self, root_hash: [u8; 32]) -> std::io::Result<bool> {
        match self.nudb_map_guard() {
            Some(mut map) => map.load_root_from_hash(root_hash),
            None => Ok(false),
        }
    }

    /// After re-pointing the live NuDB-backed SHAMap at a known-good root,
    /// clear any buffered overlay and deferred replay bookkeeping so stale
    /// in-memory state cannot shadow the reloaded tree.
    pub fn reset_overlay_after_root_rehydrate(&mut self) {
        self.state_map = SHAMap::new_state();
        self.sparse_map = None;

        self.dirty_accounts.clear();
        self.deleted_accounts.clear();
        self.dirty_trustlines.clear();
        self.deleted_trustlines.clear();
        self.dirty_checks.clear();
        self.deleted_checks.clear();
        self.dirty_deposit_preauths.clear();
        self.deleted_deposit_preauths.clear();
        self.dirty_dids.clear();
        self.deleted_dids.clear();
        self.dirty_escrows.clear();
        self.deleted_escrows.clear();
        self.dirty_paychans.clear();
        self.deleted_paychans.clear();
        self.dirty_tickets.clear();
        self.deleted_tickets.clear();
        self.dirty_offers.clear();
        self.deleted_offers.clear();
        self.dirty_directories.clear();
        self.deleted_directories.clear();
        self.dirty_raw.clear();
        self.deleted_raw.clear();
        self.tx_journal = None;
        self.tx_snapshot = None;
        self.defer_storage = false;
    }

    /// Drop all in-memory typed state and SHAMap overlays before a fresh
    /// state-sync epoch, while preserving disk access and the live amendment set.
    ///
    /// This is intentionally stronger than `reset_overlay_after_root_rehydrate()`.
    /// Resyncs after follower failure must release the old typed collections and
    /// any lazily-loaded SHAMap tree retained from the previous epoch; otherwise
    /// repeated replay/resync cycles ratchet heap usage upward.
    pub fn reset_for_fresh_sync(&mut self) {
        let storage = self.storage.clone();
        let active_amendments = std::mem::take(&mut self.active_amendments);
        let nudb_backend = {
            let backend = self.nudb_map_guard().and_then(|map| map.backend().cloned());
            if let Some(ref backend) = backend {
                backend.clear_in_memory();
            }
            backend
        };

        *self = Self::new();
        self.storage = storage;
        self.active_amendments = active_amendments;
        if let Some(backend) = nudb_backend {
            self.nudb_shamap = Some(std::sync::Mutex::new(SHAMap::with_backend(
                MapType::AccountState,
                backend,
            )));
        }
    }

    /// Diagnostic-only: take a lazy snapshot of the current NuDB-backed SHAMap.
    /// Used to preserve the pristine sync-anchor base before replay mutates it.
    pub fn snapshot_nudb_for_diagnostics(&self) -> Option<shamap::SHAMap> {
        let mut map = self.nudb_map_guard()?;
        Some(map.snapshot())
    }

    /// Create a copy-on-write ledger view suitable for dry-run transaction
    /// execution. The cloned state shares read-only backend access but starts
    /// with a clean transaction journal and never writes through to storage.
    pub fn simulation_copy(&mut self) -> Self {
        let state_map = self.state_map.snapshot();
        let nudb_shamap = self
            .nudb_map_guard()
            .map(|mut map| std::sync::Mutex::new(map.snapshot()));

        Self {
            state_map,
            sparse_map: None,
            storage: self.storage.clone(),
            accounts: self.accounts.clone(),
            trustlines: self.trustlines.clone(),
            checks: self.checks.clone(),
            deposit_preauths: self.deposit_preauths.clone(),
            dids: self.dids.clone(),
            escrows: self.escrows.clone(),
            paychans: self.paychans.clone(),
            tickets: self.tickets.clone(),
            nftokens: self.nftokens.clone(),
            nft_pages: self.nft_pages.clone(),
            nft_offers: self.nft_offers.clone(),
            offers: self.offers.clone(),
            order_books: self.order_books.clone(),
            directories: self.directories.clone(),
            account_trustlines: self.account_trustlines.clone(),
            account_offers_idx: self.account_offers_idx.clone(),
            active_amendments: self.active_amendments.clone(),
            dirty_accounts: HashSet::new(),
            deleted_accounts: HashSet::new(),
            dirty_trustlines: HashSet::new(),
            deleted_trustlines: HashSet::new(),
            dirty_checks: HashSet::new(),
            deleted_checks: HashSet::new(),
            dirty_deposit_preauths: HashSet::new(),
            deleted_deposit_preauths: HashSet::new(),
            dirty_dids: HashSet::new(),
            deleted_dids: HashSet::new(),
            dirty_escrows: HashSet::new(),
            deleted_escrows: HashSet::new(),
            dirty_paychans: HashSet::new(),
            deleted_paychans: HashSet::new(),
            dirty_tickets: HashSet::new(),
            deleted_tickets: HashSet::new(),
            dirty_offers: HashSet::new(),
            deleted_offers: HashSet::new(),
            dirty_nft_offers: HashSet::new(),
            dirty_directories: HashSet::new(),
            deleted_directories: HashSet::new(),
            dirty_raw: HashSet::new(),
            deleted_raw: HashSet::new(),
            previous_txn_only_touches: HashSet::new(),
            tx_journal: None,
            tx_snapshot: None,
            // Dry runs should never write through to the shared backend.
            defer_storage: true,
            nudb_shamap,
        }
    }

    /// Write a batch of leaf nodes directly to the NuDB backend, bypassing the SHAMap tree.
    /// Used during sync to avoid building the full tree in memory.
    /// Each entry is (key_32_bytes, sle_data). Computes leaf hash and stores as [data || key].
    pub fn store_leaves_to_nudb(&self, leaves: &[(Vec<u8>, Vec<u8>)]) {
        if let Some(ref nudb_map) = self.nudb_shamap {
            let map = nudb_map.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(backend) = map.backend() {
                let mut batch: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(leaves.len());
                for (key_bytes, data) in leaves {
                    if key_bytes.len() == 32 {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(key_bytes);
                        let lh = sparse_shamap::leaf_hash(data, &k);
                        let mut sd = Vec::with_capacity(data.len() + 32);
                        sd.extend_from_slice(data);
                        sd.extend_from_slice(&k);
                        batch.push((lh, sd));
                    }
                }
                let _ = backend.store_batch(&batch);
            }
        }
    }

    /// Number of objects in the NuDB store (content-addressed nodes).
    pub fn nudb_object_count(&self) -> usize {
        if let Some(map) = self.nudb_map_guard() {
            if let Some(backend) = map.backend() {
                return backend.count() as usize;
            }
        }
        0
    }

    /// Flush dirty nodes from the NuDB-backed SHAMap to disk,
    /// then evict clean leaves back to stubs to free memory.
    pub fn flush_nudb(&self) -> std::io::Result<usize> {
        match self.nudb_map_guard() {
            Some(mut map) => {
                let flushed = map.flush_dirty()?;
                let evicted = map.evict_clean_leaves();
                if flushed > 0 || evicted > 0 {
                    tracing::info!(
                        "flush_nudb: flushed {} node(s), evicted {} clean leaf/leaves",
                        flushed,
                        evicted,
                    );
                }
                Ok(flushed)
            }
            None => Ok(0),
        }
    }

    /// Evict clean leaves from the NuDB-backed SHAMap without forcing a dirty flush.
    /// This is used after sync handoff and other restart-style transitions where the
    /// tree is already persisted but still fully materialized in memory.
    pub fn evict_clean_nudb_leaves(&self) -> usize {
        self.nudb_map_guard()
            .map(|mut map| map.evict_clean_leaves())
            .unwrap_or(0)
    }

    /// Enable deferred storage mode. insert_raw/remove_raw will skip
    /// per-entry redb writes and buffer data in state_map instead.
    /// Call this before replay, clear it after.
    pub fn set_defer_storage(&mut self, defer: bool) {
        self.defer_storage = defer;
    }

    /// Update the sparse hash tree for a key whose data was just written
    /// to state_map. Must be called by every typed insert method so that
    /// state_hash() reflects the mutation.
    fn sparse_sync_insert(&mut self, key: &Key, data: &[u8]) {
        if let Some(ref mut sparse) = self.sparse_map {
            let lh = sparse_shamap::leaf_hash(data, &key.0);
            sparse.insert(key.0, lh);
        }
    }

    /// Update the sparse hash tree for a key that was just removed from
    /// state_map. Must be called by every typed remove method.
    fn sparse_sync_remove(&mut self, key: &Key) {
        if let Some(ref mut sparse) = self.sparse_map {
            sparse.remove(&key.0);
        }
    }

    fn record_preimage(&mut self, key: &Key) {
        let should_record = self
            .tx_journal
            .as_ref()
            .map(|journal| !journal.before.contains_key(key))
            .unwrap_or(false);
        if !should_record {
            return;
        }

        // Check both in-memory state_map AND NuDB for the before-image.
        // Objects loaded via hydrate_account() etc. exist in typed collections
        // and NuDB but NOT in state_map — missing the NuDB check causes them
        // to be recorded as before=None (falsely classified as "created").
        let existing = self.get_raw_owned(key);

        if let Some(journal) = self.tx_journal.as_mut() {
            journal.order.push(*key);
            journal.before.insert(*key, existing);
        }

        // Also capture typed entry for rollback
        if self.tx_snapshot.is_some() {
            let typed = self.lookup_typed_entry(key);
            if let Some(snap) = self.tx_snapshot.as_mut() {
                snap.typed_before.push((*key, typed));
            }
        }
    }

    /// Look up the typed entry for a given SHAMap key, if one exists.
    /// Returns None if the key doesn't correspond to any loaded typed object.
    fn lookup_typed_entry(&self, key: &Key) -> Option<TypedEntry> {
        // Check each typed collection to find which one owns this key.
        // Accounts are keyed differently (by account_id), so scan them.
        for (id, acct) in &self.accounts {
            if account::shamap_key(id) == *key {
                return Some(TypedEntry::Account(*id, acct.clone()));
            }
        }
        if let Some(tl) = self.trustlines.get(key) {
            return Some(TypedEntry::Trustline(*key, tl.clone()));
        }
        if let Some(chk) = self.checks.get(key) {
            return Some(TypedEntry::Check(*key, chk.clone()));
        }
        if let Some(dp) = self.deposit_preauths.get(key) {
            return Some(TypedEntry::DepositPreauth(*key, dp.clone()));
        }
        if let Some(d) = self.dids.get(key) {
            return Some(TypedEntry::Did(*key, d.clone()));
        }
        if let Some(esc) = self.escrows.get(key) {
            return Some(TypedEntry::Escrow(*key, esc.clone()));
        }
        if let Some(pc) = self.paychans.get(key) {
            return Some(TypedEntry::PayChannel(*key, pc.clone()));
        }
        if let Some(tkt) = self.tickets.get(key) {
            return Some(TypedEntry::Ticket(*key, tkt.clone()));
        }
        // NFTokens are keyed by nftoken_id, not SHAMap key — scan
        for (id, nft) in &self.nftokens {
            if nft.shamap_key() == *key {
                return Some(TypedEntry::NFToken(*id, nft.clone()));
            }
        }
        if let Some(off) = self.nft_offers.get(key) {
            return Some(TypedEntry::NFTokenOffer(*key, off.clone()));
        }
        if let Some(off) = self.offers.get(key) {
            return Some(TypedEntry::Offer(*key, off.clone()));
        }
        if let Some(dir) = self.directories.get(key) {
            return Some(TypedEntry::Directory(*key, dir.clone()));
        }
        None
    }

    pub fn begin_tx_journal(&mut self) {
        self.tx_journal = Some(TxJournal {
            order: Vec::new(),
            before: HashMap::new(),
        });
    }

    /// Peek at the current tx journal without consuming it.
    /// Returns the same data as `take_tx_journal` but leaves the journal intact.
    pub fn peek_tx_journal(&self) -> Vec<(Key, Option<Vec<u8>>)> {
        self.tx_journal
            .as_ref()
            .map(|journal| {
                journal
                    .order
                    .iter()
                    .filter_map(|key| {
                        journal
                            .before
                            .get(key)
                            .cloned()
                            .map(|snapshot| (*key, snapshot))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn take_tx_journal(&mut self) -> Vec<(Key, Option<Vec<u8>>)> {
        self.tx_journal
            .take()
            .map(|journal| {
                let TxJournal { order, before } = journal;
                order
                    .into_iter()
                    .filter_map(|key| before.get(&key).cloned().map(|snapshot| (key, snapshot)))
                    .collect()
            })
            .unwrap_or_default()
    }

    // ── Transactional scope (begin / commit / discard) ───────────────────

    /// Begin a new transaction scope.  Initialises both the raw journal
    /// (for metadata generation) and a typed snapshot (for rollback).
    pub fn begin_tx(&mut self) {
        self.previous_txn_only_touches.clear();
        // Raw journal (same as begin_tx_journal)
        self.tx_journal = Some(TxJournal {
            order: Vec::new(),
            before: HashMap::new(),
        });
        // Typed snapshot + dirty-tracking checkpoint
        self.tx_snapshot = Some(TxSnapshot {
            typed_before: Vec::new(),
            dirty_accounts_snap: self.dirty_accounts.clone(),
            deleted_accounts_snap: self.deleted_accounts.clone(),
            dirty_trustlines_snap: self.dirty_trustlines.clone(),
            deleted_trustlines_snap: self.deleted_trustlines.clone(),
            dirty_checks_snap: self.dirty_checks.clone(),
            deleted_checks_snap: self.deleted_checks.clone(),
            dirty_deposit_preauths_snap: self.dirty_deposit_preauths.clone(),
            deleted_deposit_preauths_snap: self.deleted_deposit_preauths.clone(),
            dirty_dids_snap: self.dirty_dids.clone(),
            deleted_dids_snap: self.deleted_dids.clone(),
            dirty_escrows_snap: self.dirty_escrows.clone(),
            deleted_escrows_snap: self.deleted_escrows.clone(),
            dirty_paychans_snap: self.dirty_paychans.clone(),
            deleted_paychans_snap: self.deleted_paychans.clone(),
            dirty_tickets_snap: self.dirty_tickets.clone(),
            deleted_tickets_snap: self.deleted_tickets.clone(),
            dirty_offers_snap: self.dirty_offers.clone(),
            deleted_offers_snap: self.deleted_offers.clone(),
            dirty_nft_offers_snap: self.dirty_nft_offers.clone(),
            dirty_directories_snap: self.dirty_directories.clone(),
            deleted_directories_snap: self.deleted_directories.clone(),
            dirty_raw_snap: self.dirty_raw.clone(),
            deleted_raw_snap: self.deleted_raw.clone(),
        });
    }

    /// Commit the current transaction.  Returns the journal entries for
    /// metadata generation (same data as `take_tx_journal`).  Drops the
    /// typed snapshot — changes are permanent.
    pub fn commit_tx(&mut self) -> Vec<(Key, Option<Vec<u8>>)> {
        self.tx_snapshot = None;
        self.take_tx_journal()
    }

    /// Discard the current transaction, restoring all state to what it was
    /// at `begin_tx` time.  Both raw SHAMap entries and typed collections
    /// are rolled back.  Dirty-tracking sets are restored to their
    /// begin_tx checkpoint.
    pub fn discard_tx(&mut self) {
        self.previous_txn_only_touches.clear();
        // 1. Restore raw SHAMap entries from journal
        if let Some(journal) = self.tx_journal.take() {
            // Walk in reverse order so that if the same key was touched
            // multiple times, the original pre-transaction state is restored.
            for key in journal.order.iter().rev() {
                if let Some(before_opt) = journal.before.get(key) {
                    match before_opt {
                        Some(data) => {
                            // Entry existed before tx — restore it
                            self.sparse_sync_insert(key, data);
                            self.state_map.insert(*key, data.clone());
                        }
                        None => {
                            // Entry did NOT exist before tx — remove it
                            self.sparse_sync_remove(key);
                            self.state_map.remove(key);
                        }
                    }
                }
            }
        }

        // 2. Restore typed collections from snapshot
        if let Some(snap) = self.tx_snapshot.take() {
            // First, collect all touched keys so the temporary entries can be removed.
            // any typed entries that were CREATED during this tx.
            let touched_keys: Vec<Key> = snap.typed_before.iter().map(|(k, _)| *k).collect();

            // Remove typed entries for all touched keys (undo inserts/modifications)
            for key in &touched_keys {
                self.remove_typed_entry_silent(key);
            }

            // Re-insert the before-state entries
            for (_key, entry_opt) in snap.typed_before {
                if let Some(entry) = entry_opt {
                    self.restore_typed_entry(entry);
                }
            }

            // 3. Restore dirty/deleted tracking
            self.dirty_accounts = snap.dirty_accounts_snap;
            self.deleted_accounts = snap.deleted_accounts_snap;
            self.dirty_trustlines = snap.dirty_trustlines_snap;
            self.deleted_trustlines = snap.deleted_trustlines_snap;
            self.dirty_checks = snap.dirty_checks_snap;
            self.deleted_checks = snap.deleted_checks_snap;
            self.dirty_deposit_preauths = snap.dirty_deposit_preauths_snap;
            self.deleted_deposit_preauths = snap.deleted_deposit_preauths_snap;
            self.dirty_dids = snap.dirty_dids_snap;
            self.deleted_dids = snap.deleted_dids_snap;
            self.dirty_escrows = snap.dirty_escrows_snap;
            self.deleted_escrows = snap.deleted_escrows_snap;
            self.dirty_paychans = snap.dirty_paychans_snap;
            self.deleted_paychans = snap.deleted_paychans_snap;
            self.dirty_tickets = snap.dirty_tickets_snap;
            self.deleted_tickets = snap.deleted_tickets_snap;
            self.dirty_offers = snap.dirty_offers_snap;
            self.deleted_offers = snap.deleted_offers_snap;
            self.dirty_nft_offers = snap.dirty_nft_offers_snap;
            self.dirty_directories = snap.dirty_directories_snap;
            self.deleted_directories = snap.deleted_directories_snap;
            self.dirty_raw = snap.dirty_raw_snap;
            self.deleted_raw = snap.deleted_raw_snap;
        }
    }

    /// Remove a typed entry by SHAMap key without touching raw state or
    /// dirty tracking.  Used during discard to clear tx-created entries.
    fn remove_typed_entry_silent(&mut self, key: &Key) {
        // Accounts — must scan by account_id
        let acct_id = self
            .accounts
            .iter()
            .find(|(id, _)| account::shamap_key(id) == *key)
            .map(|(id, _)| *id);
        if let Some(id) = acct_id {
            self.accounts.remove(&id);
            return;
        }
        if self.trustlines.remove(key).is_some() {
            // Also clean up secondary index
            // (rebuilt when the before-state entry is restored)
            self.account_trustlines
                .values_mut()
                .for_each(|v| v.retain(|k| k != key));
            return;
        }
        if self.checks.remove(key).is_some() {
            return;
        }
        if self.deposit_preauths.remove(key).is_some() {
            return;
        }
        if self.dids.remove(key).is_some() {
            return;
        }
        if self.escrows.remove(key).is_some() {
            return;
        }
        if self.paychans.remove(key).is_some() {
            return;
        }
        if self.tickets.remove(key).is_some() {
            return;
        }
        // NFTokens — scan by shamap_key
        let nft_id = self
            .nftokens
            .iter()
            .find(|(_, nft)| nft.shamap_key() == *key)
            .map(|(id, _)| *id);
        if let Some(id) = nft_id {
            self.nftokens.remove(&id);
            return;
        }
        if self.nft_offers.remove(key).is_some() {
            return;
        }
        if let Some(off) = self.offers.remove(key) {
            // Clean up secondary indexes
            let bk = offer::BookKey::from_amounts(&off.taker_pays, &off.taker_gets);
            if let Some(book) = self.order_books.get_mut(&bk) {
                book.remove(&off);
            }
            if let Some(v) = self.account_offers_idx.get_mut(&off.account) {
                v.retain(|k| k != key);
            }
            return;
        }
        self.directories.remove(key);
    }

    /// Clear any cached typed view for a SHAMap key without mutating raw
    /// state. Used by authoritative repair paths before re-hydrating a key
    /// from known-good bytes.
    pub fn clear_typed_entry_for_key(&mut self, key: &Key) {
        self.remove_typed_entry_silent(key);
    }

    /// Restore a typed entry from a snapshot.  Re-inserts into the correct
    /// typed collection and rebuilds secondary indexes.  Does NOT touch
    /// raw SHAMap state (that's handled separately via journal).
    fn restore_typed_entry(&mut self, entry: TypedEntry) {
        match entry {
            TypedEntry::Account(id, acct) => {
                self.accounts.insert(id, acct);
            }
            TypedEntry::Trustline(key, tl) => {
                let low_idx = self.account_trustlines.entry(tl.low_account).or_default();
                if !low_idx.contains(&key) {
                    low_idx.push(key);
                }
                let high_idx = self.account_trustlines.entry(tl.high_account).or_default();
                if !high_idx.contains(&key) {
                    high_idx.push(key);
                }
                self.trustlines.insert(key, tl);
            }
            TypedEntry::Check(key, chk) => {
                self.checks.insert(key, chk);
            }
            TypedEntry::DepositPreauth(key, dp) => {
                self.deposit_preauths.insert(key, dp);
            }
            TypedEntry::Did(key, d) => {
                self.dids.insert(key, d);
            }
            TypedEntry::Escrow(key, esc) => {
                self.escrows.insert(key, esc);
            }
            TypedEntry::PayChannel(key, pc) => {
                self.paychans.insert(key, pc);
            }
            TypedEntry::Ticket(key, tkt) => {
                self.tickets.insert(key, tkt);
            }
            TypedEntry::NFToken(id, nft) => {
                self.nftokens.insert(id, nft);
            }
            TypedEntry::NFTokenOffer(key, off) => {
                self.nft_offers.insert(key, off);
            }
            TypedEntry::Offer(key, off) => {
                let bk = offer::BookKey::from_amounts(&off.taker_pays, &off.taker_gets);
                self.order_books
                    .entry(bk)
                    .or_insert_with(offer::OrderBook::new)
                    .insert(&off);
                let idx = self.account_offers_idx.entry(off.account).or_default();
                if !idx.contains(&key) {
                    idx.push(key);
                }
                self.offers.insert(key, off);
            }
            TypedEntry::Directory(key, dir) => {
                self.directories.insert(key, dir);
            }
        }
    }

    // ── Accounts ──────────────────────────────────────────────────────────────

    /// Insert or update an account.  Updates both the SHAMap and the index.
    pub fn insert_account(&mut self, account: AccountRoot) {
        let key = account::shamap_key(&account.account_id);
        let data = account.to_sle_binary();
        self.record_preimage(&key);
        self.sparse_sync_insert(&key, &data);
        // Write to NuDB SHAMap if active — skip during deferred mode
        // (follower replay) to avoid overwriting correct SLEs before
        // metadata patches can read them.
        if !self.defer_storage {
            if let Some(mut map) = self.nudb_map_guard() {
                map.insert(key, data.clone());
            }
        }
        self.state_map.insert(key, data);
        self.dirty_accounts.insert(account.account_id);
        self.deleted_accounts.remove(&account.account_id);
        self.accounts.insert(account.account_id, account);
    }

    /// Mark an object as intentionally modified when rippled would only
    /// thread PreviousTxnID/PreviousTxnLgrSeq onto it.
    pub fn force_previous_txn_touch(&mut self, key: &Key) {
        self.record_preimage(key);
        self.previous_txn_only_touches.insert(*key);
    }

    pub fn is_forced_previous_txn_touch(&self, key: &Key) -> bool {
        self.previous_txn_only_touches.contains(key)
    }

    /// Hydrate an account from storage — populates typed collection only.
    /// No dirty tracking, no sparse sync, no state_map write.
    pub fn hydrate_account(&mut self, account: AccountRoot) {
        self.accounts.insert(account.account_id, account);
    }

    /// Alias for backward compat.
    pub fn update_account_typed(&mut self, account: AccountRoot) {
        self.deleted_accounts.remove(&account.account_id);
        self.dirty_accounts.remove(&account.account_id);
        self.hydrate_account(account);
    }

    /// Remove an account from state (account deletion).
    pub fn remove_account(&mut self, account_id: &[u8; 20]) -> Option<AccountRoot> {
        if self.accounts.contains_key(account_id) {
            let key = account::shamap_key(account_id);
            self.record_preimage(&key);
            let acct = self.accounts.remove(account_id).unwrap();
            self.sparse_sync_remove(&key);
            // Remove from NuDB SHAMap only when not buffering a replay overlay.
            if !self.defer_storage {
                if let Some(mut map) = self.nudb_map_guard() {
                    map.remove(&key);
                }
            }
            self.state_map.remove(&key);
            self.deleted_accounts.insert(*account_id);
            self.dirty_accounts.remove(account_id);
            Some(acct)
        } else {
            None
        }
    }

    /// Look up an account by its 20-byte AccountID.
    pub fn get_account(&self, account_id: &[u8; 20]) -> Option<&AccountRoot> {
        self.accounts.get(account_id)
    }

    /// Number of accounts loaded.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    // ── Amendments ───────────────────────────────────────────────────────────

    /// Record an amendment as active.
    pub fn enable_amendment(&mut self, hash: [u8; 32]) {
        self.active_amendments.insert(hash);
    }

    /// Check if an amendment is active.
    pub fn is_amendment_active(&self, hash: &[u8; 32]) -> bool {
        self.active_amendments.contains(hash)
    }

    /// Number of active amendments.
    pub fn amendment_count(&self) -> usize {
        self.active_amendments.len()
    }

    // ── Trust lines ───────────────────────────────────────────────────────────

    /// Hydrate a trustline from storage — populates typed collection + indices only.
    pub fn hydrate_trustline(&mut self, tl: RippleState) {
        let key = tl.key();
        let low_idx = self.account_trustlines.entry(tl.low_account).or_default();
        if !low_idx.contains(&key) {
            low_idx.push(key);
        }
        let high_idx = self.account_trustlines.entry(tl.high_account).or_default();
        if !high_idx.contains(&key) {
            high_idx.push(key);
        }
        self.trustlines.insert(key, tl);
    }

    /// Alias for backward compat.
    pub fn update_trustline_typed(&mut self, tl: RippleState) {
        let key = tl.key();
        self.deleted_trustlines.remove(&key);
        self.dirty_trustlines.remove(&key);
        self.hydrate_trustline(tl);
    }

    /// Insert or update a trust line.
    pub fn insert_trustline(&mut self, tl: RippleState) {
        let key = tl.key();
        let data = tl.to_sle_binary();
        let low_idx = self.account_trustlines.entry(tl.low_account).or_default();
        if !low_idx.contains(&key) {
            low_idx.push(key);
        }
        let high_idx = self.account_trustlines.entry(tl.high_account).or_default();
        if !high_idx.contains(&key) {
            high_idx.push(key);
        }
        self.record_preimage(&key);
        self.sparse_sync_insert(&key, &data);
        self.state_map.insert(key, data);
        self.dirty_trustlines.insert(key);
        self.deleted_trustlines.remove(&key);
        self.trustlines.insert(key, tl);
    }

    /// Remove a trust line.
    pub fn remove_trustline(&mut self, key: &Key) -> bool {
        if self.trustlines.contains_key(key) {
            self.record_preimage(key);
            let tl = self.trustlines.remove(key).unwrap();
            self.sparse_sync_remove(key);
            self.state_map.remove(key);
            self.deleted_trustlines.insert(*key);
            self.dirty_trustlines.remove(key);
            if let Some(v) = self.account_trustlines.get_mut(&tl.low_account) {
                v.retain(|k| k != key);
            }
            if let Some(v) = self.account_trustlines.get_mut(&tl.high_account) {
                v.retain(|k| k != key);
            }
            true
        } else {
            false
        }
    }

    /// Look up a trust line by its SHAMap key.
    pub fn get_trustline(&self, key: &Key) -> Option<&RippleState> {
        self.trustlines.get(key)
    }

    /// Look up a trust line between two accounts for a currency.
    pub fn get_trustline_for(
        &self,
        account_a: &[u8; 20],
        account_b: &[u8; 20],
        currency: &crate::transaction::amount::Currency,
    ) -> Option<&RippleState> {
        let key = trustline::shamap_key(account_a, account_b, currency);
        self.trustlines.get(&key)
    }

    /// All trust lines where `account` is one side (low or high). O(k) where k = account's trust lines.
    pub fn trustlines_for_account(&self, account: &[u8; 20]) -> Vec<&RippleState> {
        self.account_trustlines
            .get(account)
            .map(|keys| keys.iter().filter_map(|k| self.trustlines.get(k)).collect())
            .unwrap_or_default()
    }

    // ── Checks ────────────────────────────────────────────────────────────────

    /// Hydrate a check from storage — typed collection only.
    pub fn hydrate_check(&mut self, chk: Check) {
        let key = chk.key();
        self.checks.insert(key, chk);
    }

    pub fn insert_check(&mut self, chk: Check) {
        let key = chk.key();
        let data = chk.to_sle_binary();
        self.record_preimage(&key);
        self.sparse_sync_insert(&key, &data);
        self.state_map.insert(key, data);
        self.dirty_checks.insert(key);
        self.deleted_checks.remove(&key);
        self.checks.insert(key, chk);
    }

    pub fn remove_check(&mut self, key: &Key) -> Option<Check> {
        if self.checks.contains_key(key) {
            self.record_preimage(key);
            let chk = self.checks.remove(key).unwrap();
            self.sparse_sync_remove(key);
            self.state_map.remove(key);
            self.deleted_checks.insert(*key);
            self.dirty_checks.remove(key);
            Some(chk)
        } else {
            None
        }
    }

    pub fn get_check(&self, key: &Key) -> Option<&Check> {
        self.checks.get(key)
    }

    // ── Deposit preauths ──────────────────────────────────────────────────────

    pub fn hydrate_deposit_preauth(&mut self, dp: DepositPreauth) {
        let key = dp.key();
        self.deposit_preauths.insert(key, dp);
    }

    pub fn insert_deposit_preauth(&mut self, dp: DepositPreauth) {
        let key = dp.key();
        let data = dp.to_sle_binary();
        self.record_preimage(&key);
        self.sparse_sync_insert(&key, &data);
        self.state_map.insert(key, data);
        self.dirty_deposit_preauths.insert(key);
        self.deleted_deposit_preauths.remove(&key);
        self.deposit_preauths.insert(key, dp);
    }

    pub fn remove_deposit_preauth(&mut self, key: &Key) -> Option<DepositPreauth> {
        if self.deposit_preauths.contains_key(key) {
            self.record_preimage(key);
            let dp = self.deposit_preauths.remove(key).unwrap();
            self.sparse_sync_remove(key);
            self.state_map.remove(key);
            self.deleted_deposit_preauths.insert(*key);
            self.dirty_deposit_preauths.remove(key);
            Some(dp)
        } else {
            None
        }
    }

    pub fn has_deposit_preauth(&self, key: &Key) -> bool {
        self.deposit_preauths.contains_key(key)
    }

    pub fn iter_deposit_preauths(&self) -> impl Iterator<Item = (&Key, &DepositPreauth)> {
        self.deposit_preauths.iter()
    }

    // ── DIDs ──────────────────────────────────────────────────────────────────

    pub fn hydrate_did(&mut self, d: Did) {
        let key = d.key();
        self.dids.insert(key, d);
    }

    pub fn insert_did(&mut self, d: Did) {
        let key = d.key();
        let data = d.to_sle_binary();
        self.record_preimage(&key);
        self.sparse_sync_insert(&key, &data);
        self.state_map.insert(key, data);
        self.dirty_dids.insert(key);
        self.deleted_dids.remove(&key);
        self.dids.insert(key, d);
    }

    pub fn remove_did(&mut self, key: &Key) -> Option<Did> {
        if self.dids.contains_key(key) {
            self.record_preimage(key);
            let d = self.dids.remove(key).unwrap();
            self.sparse_sync_remove(key);
            self.state_map.remove(key);
            self.deleted_dids.insert(*key);
            self.dirty_dids.remove(key);
            Some(d)
        } else {
            None
        }
    }

    pub fn get_did(&self, key: &Key) -> Option<&Did> {
        self.dids.get(key)
    }

    pub fn get_did_mut(&mut self, key: &Key) -> Option<&mut Did> {
        self.dids.get_mut(key)
    }

    pub fn has_did(&self, key: &Key) -> bool {
        self.dids.contains_key(key)
    }

    pub fn iter_dids(&self) -> impl Iterator<Item = (&Key, &Did)> {
        self.dids.iter()
    }

    // ── Escrows ───────────────────────────────────────────────────────────────

    pub fn hydrate_escrow(&mut self, esc: Escrow) {
        let key = esc.key();
        self.escrows.insert(key, esc);
    }

    pub fn insert_escrow(&mut self, esc: Escrow) {
        let key = esc.key();
        let data = esc.to_sle_binary();
        self.record_preimage(&key);
        self.sparse_sync_insert(&key, &data);
        self.state_map.insert(key, data);
        self.dirty_escrows.insert(key);
        self.deleted_escrows.remove(&key);
        self.escrows.insert(key, esc);
    }

    pub fn remove_escrow(&mut self, key: &Key) -> Option<Escrow> {
        if self.escrows.contains_key(key) {
            self.record_preimage(key);
            let esc = self.escrows.remove(key).unwrap();
            self.sparse_sync_remove(key);
            self.state_map.remove(key);
            self.deleted_escrows.insert(*key);
            self.dirty_escrows.remove(key);
            Some(esc)
        } else {
            None
        }
    }

    pub fn get_escrow(&self, key: &Key) -> Option<&Escrow> {
        self.escrows.get(key)
    }

    // ── Payment channels ──────────────────────────────────────────────────────

    pub fn hydrate_paychan(&mut self, pc: PayChannel) {
        let key = pc.key();
        self.paychans.insert(key, pc);
    }

    pub fn insert_paychan(&mut self, pc: PayChannel) {
        let key = pc.key();
        let data = pc.to_sle_binary();
        self.record_preimage(&key);
        self.sparse_sync_insert(&key, &data);
        self.state_map.insert(key, data);
        self.dirty_paychans.insert(key);
        self.deleted_paychans.remove(&key);
        self.paychans.insert(key, pc);
    }

    pub fn remove_paychan(&mut self, key: &Key) -> Option<PayChannel> {
        if self.paychans.contains_key(key) {
            self.record_preimage(key);
            let pc = self.paychans.remove(key).unwrap();
            self.sparse_sync_remove(key);
            self.state_map.remove(key);
            self.deleted_paychans.insert(*key);
            self.dirty_paychans.remove(key);
            Some(pc)
        } else {
            None
        }
    }

    pub fn get_paychan(&self, key: &Key) -> Option<&PayChannel> {
        self.paychans.get(key)
    }

    // ── Tickets ───────────────────────────────────────────────────────────────

    pub fn hydrate_ticket(&mut self, tkt: Ticket) {
        let key = tkt.key();
        self.tickets.insert(key, tkt);
    }

    pub fn insert_ticket(&mut self, tkt: Ticket) {
        let key = tkt.key();
        let data = tkt.to_sle_binary();
        self.record_preimage(&key);
        self.sparse_sync_insert(&key, &data);
        self.state_map.insert(key, data);
        self.dirty_tickets.insert(key);
        self.deleted_tickets.remove(&key);
        self.tickets.insert(key, tkt);
    }

    pub fn remove_ticket(&mut self, key: &Key) -> Option<Ticket> {
        if self.tickets.contains_key(key) {
            self.record_preimage(key);
            let tkt = self.tickets.remove(key).unwrap();
            self.sparse_sync_remove(key);
            self.state_map.remove(key);
            self.deleted_tickets.insert(*key);
            self.dirty_tickets.remove(key);
            Some(tkt)
        } else {
            None
        }
    }

    // ── NFTokens ──────────────────────────────────────────────────────────────

    pub fn insert_nftoken(&mut self, nft: NFToken) {
        let key = nft.shamap_key();
        self.insert_raw(key, vec![]);
        self.nftokens.insert(nft.nftoken_id, nft);
    }

    pub fn remove_nftoken(&mut self, id: &[u8; 32]) -> Option<NFToken> {
        if self.nftokens.contains_key(id) {
            let key = self.nftokens[id].shamap_key();
            let nft = self.nftokens.remove(id).unwrap();
            self.remove_raw(&key);
            Some(nft)
        } else {
            None
        }
    }

    pub fn get_nftoken(&self, id: &[u8; 32]) -> Option<&NFToken> {
        self.nftokens.get(id)
    }

    /// Look up an NFToken from the page-based store by ID.
    /// Searches all pages for the owner prefix matching the token ID.
    pub fn get_nftoken_from_pages(&self, id: &[u8; 32]) -> Option<&nft_page::PageToken> {
        // The token could be on any page owned by the account embedded in the ID.
        // The owner cannot be derived from the ID alone, so all pages are scanned.
        for (_, page) in &self.nft_pages {
            for token in &page.tokens {
                if token.nftoken_id == *id {
                    return Some(token);
                }
            }
        }
        None
    }

    /// Find which owner holds a given NFToken in the page store.
    pub fn nftoken_page_owner(&self, id: &[u8; 32]) -> Option<[u8; 20]> {
        for (key, page) in &self.nft_pages {
            if page.tokens.iter().any(|t| t.nftoken_id == *id) {
                let mut owner = [0u8; 20];
                owner.copy_from_slice(&key.0[..20]);
                return Some(owner);
            }
        }
        None
    }

    // ── Page-based NFToken operations ────────────────────────────────────

    /// Insert an NFToken into the page-based store.
    /// Finds or creates the appropriate page, handles splitting if full.
    /// Also updates the SHAMap with the page SLE.
    pub fn insert_nftoken_paged(
        &mut self,
        owner: &[u8; 20],
        token_id: [u8; 32],
        uri: Option<Vec<u8>>,
    ) {
        use nft_page::*;

        let token = PageToken {
            nftoken_id: token_id,
            uri: uri.clone(),
        };
        let target_page_key = page_key_for_token(owner, &token_id);
        let max_key = page_max(owner);

        // Find existing page or use max_key for new page
        let page_key = self
            .nft_pages
            .range(target_page_key..=max_key)
            .next()
            .map(|(k, _)| *k)
            .unwrap_or(max_key);

        if !self.nft_pages.contains_key(&page_key) {
            self.nft_pages.insert(page_key, NFTokenPage::new(page_key));
        }

        // Try insert; if full, split first
        let needs_split = self.nft_pages.get(&page_key).unwrap().len() >= MAX_TOKENS_PER_PAGE;

        if needs_split {
            let mut page = self.nft_pages.remove(&page_key).unwrap();
            let new_page = page.split();
            let new_page_key = new_page.key;

            // Re-insert both halves
            let sle = self.encode_nft_page(&page);
            self.insert_raw(page_key, sle);
            self.nft_pages.insert(page_key, page);

            let sle = self.encode_nft_page(&new_page);
            self.insert_raw(new_page_key, sle);
            self.nft_pages.insert(new_page_key, new_page);

            // Now insert into the correct half
            let first_upper = self.nft_pages[&new_page_key]
                .tokens
                .first()
                .map(|t| t.nftoken_id)
                .unwrap_or([0xFF; 32]);
            let insert_key = if token_id >= first_upper {
                new_page_key
            } else {
                page_key
            };
            let updated = {
                let target = self.nft_pages.get_mut(&insert_key).unwrap();
                target.insert(token.clone());
                target.clone()
            };
            let sle = self.encode_nft_page(&updated);
            self.insert_raw(insert_key, sle);
        } else {
            let updated = {
                let page = self.nft_pages.get_mut(&page_key).unwrap();
                page.insert(token.clone());
                page.clone()
            };
            let sle = self.encode_nft_page(&updated);
            self.insert_raw(page_key, sle);
        }

        // Keep flat store in sync during migration
        self.nftokens.insert(
            token_id,
            NFToken {
                nftoken_id: token_id,
                owner: *owner,
                issuer: *owner,
                uri,
                flags: 0,
                transfer_fee: 0,
                taxon: 0,
            },
        );
    }

    /// Remove an NFToken from the page-based store.
    /// Handles empty page cleanup and merging.
    pub fn remove_nftoken_paged(&mut self, owner: &[u8; 20], token_id: &[u8; 32]) -> bool {
        use nft_page::*;

        let target_key = page_key_for_token(owner, token_id);
        let max_key = page_max(owner);

        // Find the page containing this token
        let page_key = {
            let found = self
                .nft_pages
                .range(target_key..=max_key)
                .find(|(_, p)| p.tokens.iter().any(|t| t.nftoken_id == *token_id))
                .map(|(k, _)| *k);
            match found {
                Some(k) => k,
                None => return false,
            }
        };

        // Remove the page, mutate, then re-insert
        let mut page = self.nft_pages.remove(&page_key).unwrap();
        if page.remove(token_id).is_none() {
            self.nft_pages.insert(page_key, page);
            return false;
        }

        if page.is_empty() {
            let prev = page.prev_page;
            let next = page.next_page;

            self.remove_raw(&page_key);
            // Don't re-insert empty page

            // Fix neighbor links
            if let Some(prev_key) = prev {
                let updated = {
                    if let Some(p) = self.nft_pages.get_mut(&prev_key) {
                        p.next_page = next;
                        Some(p.clone())
                    } else {
                        None
                    }
                };
                if let Some(p) = updated {
                    self.insert_raw(prev_key, self.encode_nft_page(&p));
                }
            }
            if let Some(next_key) = next {
                let updated = {
                    if let Some(p) = self.nft_pages.get_mut(&next_key) {
                        p.prev_page = prev;
                        Some(p.clone())
                    } else {
                        None
                    }
                };
                if let Some(p) = updated {
                    self.insert_raw(next_key, self.encode_nft_page(&p));
                }
            }
        } else {
            // Re-insert the modified page
            self.nft_pages.insert(page_key, page);

            // Attempt merge with previous neighbor, then next
            let merged =
                self.try_merge_nft_pages(page_key) || self.try_merge_nft_pages_next(page_key);
            if !merged {
                // If no merge, just update the SHAMap for this page
                if let Some(p) = self.nft_pages.get(&page_key) {
                    let p = p.clone();
                    self.insert_raw(page_key, self.encode_nft_page(&p));
                }
            }
        }

        // Keep flat store in sync
        self.nftokens.remove(token_id);
        true
    }

    /// Try to merge an NFT page with its previous neighbor.
    /// Returns true if a merge happened.
    fn try_merge_nft_pages(&mut self, page_key: Key) -> bool {
        // Get current page and its prev link
        let (prev_key, current_len) = {
            let page = match self.nft_pages.get(&page_key) {
                Some(p) => p,
                None => return false,
            };
            match page.prev_page {
                Some(pk) => (pk, page.tokens.len()),
                None => return false,
            }
        };

        // Check if prev exists and merge is possible
        let prev_len = match self.nft_pages.get(&prev_key) {
            Some(p) => p.tokens.len(),
            None => return false,
        };

        if prev_len + current_len > nft_page::MAX_TOKENS_PER_PAGE {
            return false;
        }

        // Merge: move all tokens from current into prev
        let mut current = self.nft_pages.remove(&page_key).unwrap();
        let next_of_current = current.next_page;

        let prev = self.nft_pages.get_mut(&prev_key).unwrap();
        prev.tokens.append(&mut current.tokens);
        prev.tokens.sort();
        prev.next_page = next_of_current;
        let prev_clone = prev.clone();

        // Update prev page in SHAMap
        self.insert_raw(prev_key, self.encode_nft_page(&prev_clone));

        // Remove current page from SHAMap
        self.remove_raw(&page_key);

        // Fix next page's prev link
        if let Some(next_key) = next_of_current {
            let updated = {
                if let Some(next) = self.nft_pages.get_mut(&next_key) {
                    next.prev_page = Some(prev_key);
                    Some(next.clone())
                } else {
                    None
                }
            };
            if let Some(p) = updated {
                self.insert_raw(next_key, self.encode_nft_page(&p));
            }
        }

        true
    }

    /// Try to merge an NFT page with its next neighbor.
    /// Returns true if a merge happened.
    fn try_merge_nft_pages_next(&mut self, page_key: Key) -> bool {
        let (next_key, current_len) = {
            let page = match self.nft_pages.get(&page_key) {
                Some(p) => p,
                None => return false,
            };
            match page.next_page {
                Some(nk) => (nk, page.tokens.len()),
                None => return false,
            }
        };

        let next_len = match self.nft_pages.get(&next_key) {
            Some(p) => p.tokens.len(),
            None => return false,
        };

        if current_len + next_len > nft_page::MAX_TOKENS_PER_PAGE {
            return false;
        }

        // Merge: move all tokens from next into current
        let mut next_page = self.nft_pages.remove(&next_key).unwrap();
        let after_next = next_page.next_page;

        let current = self.nft_pages.get_mut(&page_key).unwrap();
        current.tokens.append(&mut next_page.tokens);
        current.tokens.sort();
        current.next_page = after_next;
        let current_clone = current.clone();

        // Update current page in SHAMap
        self.insert_raw(page_key, self.encode_nft_page(&current_clone));

        // Remove next page from SHAMap
        self.remove_raw(&next_key);

        // Fix the page after next's prev link
        if let Some(after_key) = after_next {
            let updated = {
                if let Some(p) = self.nft_pages.get_mut(&after_key) {
                    p.prev_page = Some(page_key);
                    Some(p.clone())
                } else {
                    None
                }
            };
            if let Some(p) = updated {
                self.insert_raw(after_key, self.encode_nft_page(&p));
            }
        }

        true
    }

    /// Encode an NFTokenPage as an SLE binary.
    fn encode_nft_page(&self, page: &nft_page::NFTokenPage) -> Vec<u8> {
        use crate::ledger::meta::ParsedField;

        // Build the NFTokens array as a serialized STArray
        let mut array_data = Vec::new();
        for token in &page.tokens {
            // Each token is an STObject within the array
            // sfNFToken wrapper: STObject type=14, field=12 (per rippled sfields.macro)
            crate::ledger::meta::write_field_header_pub(&mut array_data, 14, 12);
            // sfNFTokenID: Hash256 type=5, field=10
            crate::ledger::meta::write_field_header_pub(&mut array_data, 5, 10);
            array_data.extend_from_slice(&token.nftoken_id);
            // sfURI if present: Blob type=7, field=5
            if let Some(ref uri) = token.uri {
                crate::ledger::meta::write_field_header_pub(&mut array_data, 7, 5);
                crate::transaction::serialize::encode_length(uri.len(), &mut array_data);
                array_data.extend_from_slice(uri);
            }
            array_data.push(0xE1); // end of object
        }
        array_data.push(0xF1); // end of array

        let mut fields = vec![
            // sfNFTokens (STArray=15, field=10 per rippled sfields.macro)
            ParsedField {
                type_code: 15,
                field_code: 10,
                data: array_data,
            },
        ];

        // sfPreviousPageMin (Hash256=5, field=26 per rippled sfields.macro)
        if let Some(ref prev) = page.prev_page {
            fields.push(ParsedField {
                type_code: 5,
                field_code: 26,
                data: prev.0.to_vec(),
            });
        }
        // sfNextPageMin (Hash256=5, field=27 per rippled sfields.macro)
        if let Some(ref next) = page.next_page {
            fields.push(ParsedField {
                type_code: 5,
                field_code: 27,
                data: next.0.to_vec(),
            });
        }

        // NFTokenPage entry type = 0x0050
        crate::ledger::meta::build_sle(0x0050, &fields, None, None)
    }

    pub fn insert_nft_offer(&mut self, off: NFTokenOffer) {
        let key = off.key();
        self.insert_raw(key, off.to_sle_binary());
        self.dirty_nft_offers.remove(&key);
        self.nft_offers.insert(key, off);
    }

    pub fn hydrate_nft_offer(&mut self, off: NFTokenOffer) {
        let key = off.key();
        self.dirty_nft_offers.insert(key);
        self.nft_offers.insert(key, off);
    }

    pub fn remove_nft_offer(&mut self, key: &Key) -> Option<NFTokenOffer> {
        if self.nft_offers.contains_key(key) {
            let off = self.nft_offers.remove(key).unwrap();
            self.dirty_nft_offers.remove(key);
            self.remove_raw(key);
            Some(off)
        } else {
            None
        }
    }

    pub fn get_nft_offer(&self, key: &Key) -> Option<&NFTokenOffer> {
        self.nft_offers.get(key)
    }

    pub fn iter_nftokens(&self) -> impl Iterator<Item = (&[u8; 32], &NFToken)> {
        self.nftokens.iter()
    }

    /// Count NFTokenPages belonging to an owner.
    pub fn nft_page_count(&self, owner: &[u8; 20]) -> usize {
        let min = nft_page::page_min(owner);
        let max = nft_page::page_max(owner);
        self.nft_pages.range(min..=max).count()
    }

    /// Iterate over NFTokenPages for a specific owner.
    pub fn iter_nft_pages_for(
        &self,
        owner: &[u8; 20],
    ) -> impl Iterator<Item = (Key, &nft_page::NFTokenPage)> {
        let min = nft_page::page_min(owner);
        let max = nft_page::page_max(owner);
        self.nft_pages.range(min..=max).map(|(k, p)| (*k, p))
    }

    pub fn iter_nft_offers(&self) -> impl Iterator<Item = (&Key, &NFTokenOffer)> {
        self.nft_offers.iter()
    }
    pub fn iter_order_books(&self) -> impl Iterator<Item = (&BookKey, &OrderBook)> {
        self.order_books.iter()
    }

    // ── Offers ────────────────────────────────────────────────────────────────

    /// Update the typed offer collection without touching the SHAMap.
    /// Used when the SHAMap already has the raw SLE binary from metadata seeding.
    pub fn hydrate_offer(&mut self, off: Offer) {
        let key = off.key();
        let book_key = BookKey::from_amounts(&off.taker_pays, &off.taker_gets);
        self.order_books
            .entry(book_key)
            .or_insert_with(OrderBook::new)
            .insert(&off);
        let idx = self.account_offers_idx.entry(off.account).or_default();
        if !idx.contains(&key) {
            idx.push(key);
        }
        self.offers.insert(key, off);
    }

    pub fn update_offer_typed(&mut self, off: Offer) {
        let key = off.key();
        self.deleted_offers.remove(&key);
        self.dirty_offers.remove(&key);
        self.hydrate_offer(off);
    }

    /// Insert an offer into the state and order book.
    pub fn insert_offer(&mut self, off: Offer) {
        let key = off.key();
        let data = off.to_sle_binary();
        let book_key = BookKey::from_amounts(&off.taker_pays, &off.taker_gets);
        self.order_books
            .entry(book_key)
            .or_insert_with(OrderBook::new)
            .insert(&off);
        let idx = self.account_offers_idx.entry(off.account).or_default();
        if !idx.contains(&key) {
            idx.push(key);
        }
        self.record_preimage(&key);
        self.sparse_sync_insert(&key, &data);
        self.state_map.insert(key, data);
        self.dirty_offers.insert(key);
        self.deleted_offers.remove(&key);
        self.offers.insert(key, off);
    }

    /// Remove an offer by key.
    pub fn remove_offer(&mut self, key: &Key) -> Option<Offer> {
        if self.offers.contains_key(key) {
            self.record_preimage(key);
            let off = self.offers.remove(key).unwrap();
            let book_key = BookKey::from_amounts(&off.taker_pays, &off.taker_gets);
            if let Some(book) = self.order_books.get_mut(&book_key) {
                book.remove(&off);
            }
            if let Some(v) = self.account_offers_idx.get_mut(&off.account) {
                v.retain(|k| k != key);
            }
            self.sparse_sync_remove(key);
            self.state_map.remove(key);
            self.deleted_offers.insert(*key);
            self.dirty_offers.remove(key);
            Some(off)
        } else {
            None
        }
    }

    /// Look up an offer by key.
    pub fn get_offer(&self, key: &Key) -> Option<&Offer> {
        self.offers.get(key)
    }

    /// Get the order book for a given currency pair.
    pub fn get_book(&self, book_key: &BookKey) -> Option<&OrderBook> {
        self.order_books.get(book_key)
    }

    /// All offers placed by a specific account. O(k) where k = account's offers.
    pub fn offers_by_account(&self, account: &[u8; 20]) -> Vec<&Offer> {
        self.account_offers_idx
            .get(account)
            .map(|keys| keys.iter().filter_map(|k| self.offers.get(k)).collect())
            .unwrap_or_default()
    }

    // ── Directories ──────────────────────────────────────────────────────────

    /// Insert or update a directory node.
    pub fn hydrate_directory(&mut self, dir: DirectoryNode) {
        let key = dir.shamap_key();
        self.directories.insert(key, dir);
    }

    pub fn update_directory_typed(&mut self, dir: DirectoryNode) {
        let key = dir.shamap_key();
        self.deleted_directories.remove(&key);
        self.dirty_directories.remove(&key);
        self.hydrate_directory(dir);
    }

    pub fn insert_directory(&mut self, dir: DirectoryNode) {
        let key = dir.shamap_key();
        let data = dir.to_sle_binary();
        // Use insert_raw for the bytes so that nudb_shamap, sparse_map, and
        // dirty_raw are all updated consistently. Without this, later
        // stamp_touched_previous_fields writes stamped bytes to NuDB via
        // insert_raw but the unstamped version persists in state_map, causing
        // PreviousTxnID to be missing from the final SLE bytes.
        self.insert_raw(key, data);
        self.dirty_directories.insert(key);
        self.deleted_directories.remove(&key);
        self.directories.insert(key, dir);
    }

    /// Remove a directory node.
    pub fn remove_directory(&mut self, key: &Key) -> Option<DirectoryNode> {
        if self.directories.contains_key(key) {
            self.record_preimage(key);
            let dir = self.directories.remove(key).unwrap();
            self.sparse_sync_remove(key);
            self.state_map.remove(key);
            self.deleted_directories.insert(*key);
            self.dirty_directories.remove(key);
            // Block NuDB read-through: without this, get_raw_owned falls
            // through to nudb_shamap and resurrects the old directory bytes
            // even after removal from state_map. This was the root cause of
            // Bug C (stale book directory entries persisting after offer
            // cancellation via OfferSequence).
            self.deleted_raw.insert(*key);
            Some(dir)
        } else {
            None
        }
    }

    /// Remove a directory from state regardless of whether it's in the typed
    /// `directories` HashMap or only in state_map / NuDB. Ensures
    /// `deleted_raw` is set so that `get_raw_owned` won't resurrect stale
    /// bytes from NuDB after removal.
    pub fn remove_directory_any(&mut self, key: &Key) {
        if self.remove_directory(key).is_some() {
            return;
        }
        // Not in typed map — remove directly from raw state.
        // remove_raw handles record_preimage, sparse_sync_remove,
        // state_map.remove, and deleted_raw.insert.
        self.remove_raw(key);
    }

    /// Look up a directory node by its SHAMap key.
    pub fn get_directory(&self, key: &Key) -> Option<&DirectoryNode> {
        self.directories.get(key)
    }

    /// Look up an account's owner directory root.
    pub fn get_owner_directory(&self, account_id: &[u8; 20]) -> Option<&DirectoryNode> {
        let key = directory::owner_dir_key(account_id);
        self.directories.get(&key)
    }

    // ── Hash ────────────────────────────────────────────────────────────────

    // ── Iterators (for persistence) ─────────────────────────────────────────

    pub fn iter_accounts(&self) -> impl Iterator<Item = (&[u8; 20], &AccountRoot)> {
        self.accounts.iter()
    }
    pub fn iter_trustlines(&self) -> impl Iterator<Item = (&Key, &RippleState)> {
        self.trustlines.iter()
    }
    pub fn iter_checks(&self) -> impl Iterator<Item = (&Key, &Check)> {
        self.checks.iter()
    }
    pub fn iter_escrows(&self) -> impl Iterator<Item = (&Key, &Escrow)> {
        self.escrows.iter()
    }
    pub fn iter_paychans(&self) -> impl Iterator<Item = (&Key, &PayChannel)> {
        self.paychans.iter()
    }
    pub fn iter_offers(&self) -> impl Iterator<Item = (&Key, &Offer)> {
        self.offers.iter()
    }
    pub fn iter_tickets(&self) -> impl Iterator<Item = (&Key, &Ticket)> {
        self.tickets.iter()
    }
    pub fn iter_directories(&self) -> impl Iterator<Item = (&Key, &DirectoryNode)> {
        self.directories.iter()
    }

    // ── Dirty tracking ─────────────────────────────────────────────────────

    /// Drain all dirty/deleted tracking sets and return them as a snapshot.
    fn drain_dirty_state(&mut self) -> DirtyState {
        let dirty_accounts = std::mem::take(&mut self.dirty_accounts);
        let deleted_accounts = std::mem::take(&mut self.deleted_accounts);
        let dirty_trustlines = std::mem::take(&mut self.dirty_trustlines);
        let deleted_trustlines = std::mem::take(&mut self.deleted_trustlines);
        let dirty_checks = std::mem::take(&mut self.dirty_checks);
        let deleted_checks = std::mem::take(&mut self.deleted_checks);
        let dirty_deposit_preauths = std::mem::take(&mut self.dirty_deposit_preauths);
        let deleted_deposit_preauths = std::mem::take(&mut self.deleted_deposit_preauths);
        let dirty_dids = std::mem::take(&mut self.dirty_dids);
        let deleted_dids = std::mem::take(&mut self.deleted_dids);
        let dirty_escrows = std::mem::take(&mut self.dirty_escrows);
        let deleted_escrows = std::mem::take(&mut self.deleted_escrows);
        let dirty_paychans = std::mem::take(&mut self.dirty_paychans);
        let deleted_paychans = std::mem::take(&mut self.deleted_paychans);
        let dirty_tickets = std::mem::take(&mut self.dirty_tickets);
        let deleted_tickets = std::mem::take(&mut self.deleted_tickets);
        let dirty_offers = std::mem::take(&mut self.dirty_offers);
        let deleted_offers = std::mem::take(&mut self.deleted_offers);
        let dirty_nft_offers = std::mem::take(&mut self.dirty_nft_offers);
        let dirty_directories = std::mem::take(&mut self.dirty_directories);
        let deleted_directories = std::mem::take(&mut self.deleted_directories);
        let mut dirty_raw = std::mem::take(&mut self.dirty_raw);
        let mut deleted_raw = std::mem::take(&mut self.deleted_raw);

        dirty_raw.extend(dirty_accounts.iter().map(account::shamap_key));
        deleted_raw.extend(deleted_accounts.iter().map(account::shamap_key));
        dirty_raw.extend(dirty_trustlines.iter().copied());
        deleted_raw.extend(deleted_trustlines.iter().copied());
        dirty_raw.extend(dirty_checks.iter().copied());
        deleted_raw.extend(deleted_checks.iter().copied());
        dirty_raw.extend(dirty_deposit_preauths.iter().copied());
        deleted_raw.extend(deleted_deposit_preauths.iter().copied());
        dirty_raw.extend(dirty_dids.iter().copied());
        deleted_raw.extend(deleted_dids.iter().copied());
        dirty_raw.extend(dirty_escrows.iter().copied());
        deleted_raw.extend(deleted_escrows.iter().copied());
        dirty_raw.extend(dirty_paychans.iter().copied());
        deleted_raw.extend(deleted_paychans.iter().copied());
        dirty_raw.extend(dirty_tickets.iter().copied());
        deleted_raw.extend(deleted_tickets.iter().copied());
        dirty_raw.extend(dirty_offers.iter().copied());
        deleted_raw.extend(deleted_offers.iter().copied());
        dirty_raw.extend(dirty_nft_offers.iter().copied());
        dirty_raw.extend(dirty_directories.iter().copied());
        deleted_raw.extend(deleted_directories.iter().copied());

        DirtyState {
            dirty_accounts,
            deleted_accounts,
            dirty_trustlines,
            deleted_trustlines,
            dirty_checks,
            deleted_checks,
            dirty_deposit_preauths,
            deleted_deposit_preauths,
            dirty_dids,
            deleted_dids,
            dirty_escrows,
            deleted_escrows,
            dirty_paychans,
            deleted_paychans,
            dirty_tickets,
            deleted_tickets,
            dirty_offers,
            deleted_offers,
            dirty_nft_offers,
            dirty_directories,
            deleted_directories,
            dirty_raw,
            deleted_raw,
        }
    }

    fn restore_dirty_state(&mut self, result: &DirtyState) {
        self.dirty_accounts
            .extend(result.dirty_accounts.iter().copied());
        self.deleted_accounts
            .extend(result.deleted_accounts.iter().copied());
        self.dirty_trustlines
            .extend(result.dirty_trustlines.iter().copied());
        self.deleted_trustlines
            .extend(result.deleted_trustlines.iter().copied());
        self.dirty_checks
            .extend(result.dirty_checks.iter().copied());
        self.deleted_checks
            .extend(result.deleted_checks.iter().copied());
        self.dirty_deposit_preauths
            .extend(result.dirty_deposit_preauths.iter().copied());
        self.deleted_deposit_preauths
            .extend(result.deleted_deposit_preauths.iter().copied());
        self.dirty_dids.extend(result.dirty_dids.iter().copied());
        self.deleted_dids
            .extend(result.deleted_dids.iter().copied());
        self.dirty_escrows
            .extend(result.dirty_escrows.iter().copied());
        self.deleted_escrows
            .extend(result.deleted_escrows.iter().copied());
        self.dirty_paychans
            .extend(result.dirty_paychans.iter().copied());
        self.deleted_paychans
            .extend(result.deleted_paychans.iter().copied());
        self.dirty_tickets
            .extend(result.dirty_tickets.iter().copied());
        self.deleted_tickets
            .extend(result.deleted_tickets.iter().copied());
        self.dirty_offers
            .extend(result.dirty_offers.iter().copied());
        self.deleted_offers
            .extend(result.deleted_offers.iter().copied());
        self.dirty_nft_offers
            .extend(result.dirty_nft_offers.iter().copied());
        self.dirty_directories
            .extend(result.dirty_directories.iter().copied());
        self.deleted_directories
            .extend(result.deleted_directories.iter().copied());
        self.dirty_raw.extend(result.dirty_raw.iter().copied());
        self.deleted_raw.extend(result.deleted_raw.iter().copied());
    }

    fn take_dirty_impl(&mut self) -> Result<DirtyState, (DirtyState, std::io::Error)> {
        let result = self.drain_dirty_state();
        if let Some(mut map) = self.nudb_map_guard() {
            for key in &result.deleted_raw {
                map.remove(key);
            }
            for key in &result.dirty_raw {
                if let Some(data) = self.state_map.get_if_loaded(key) {
                    map.insert(*key, data.to_vec());
                }
            }
        }

        // Flush NuDB-backed SHAMap dirty nodes to disk after each ledger.
        if self.nudb_shamap.is_some() {
            if let Err(e) = self.flush_nudb() {
                self.restore_dirty_state(&result);
                return Err((result, e));
            }
        }

        Ok(result)
    }

    pub fn try_take_dirty(&mut self) -> std::io::Result<DirtyState> {
        self.take_dirty_impl().map_err(|(_, err)| err)
    }

    pub fn take_dirty(&mut self) -> DirtyState {
        match self.take_dirty_impl() {
            Ok(result) => result,
            Err((result, err)) => {
                tracing::warn!("failed to flush NuDB SHAMap: {err}");
                result
            }
        }
    }

    /// Mark every entry in state as dirty (used for initial full save).
    pub fn mark_all_dirty(&mut self) {
        for id in self.accounts.keys() {
            self.dirty_accounts.insert(*id);
        }
        for k in self.trustlines.keys() {
            self.dirty_trustlines.insert(*k);
        }
        for k in self.checks.keys() {
            self.dirty_checks.insert(*k);
        }
        for k in self.deposit_preauths.keys() {
            self.dirty_deposit_preauths.insert(*k);
        }
        for k in self.dids.keys() {
            self.dirty_dids.insert(*k);
        }
        for k in self.escrows.keys() {
            self.dirty_escrows.insert(*k);
        }
        for k in self.paychans.keys() {
            self.dirty_paychans.insert(*k);
        }
        for k in self.tickets.keys() {
            self.dirty_tickets.insert(*k);
        }
        for k in self.offers.keys() {
            self.dirty_offers.insert(*k);
        }
        for k in self.nft_offers.keys() {
            self.dirty_nft_offers.insert(*k);
        }
        for k in self.directories.keys() {
            self.dirty_directories.insert(*k);
        }
        for (key, _) in self.state_map.iter_leaves() {
            self.dirty_raw.insert(key);
        }
    }

    // ── Storage ───────────────────────────────────────────────────────────

    /// Set the storage backend for disk fallback in sparse mode.
    pub fn set_storage(&mut self, storage: std::sync::Arc<crate::storage::Storage>) {
        self.storage = Some(storage);
    }

    // ── Raw SHAMap access (for full state loading and binary updates) ─────

    /// Read raw binary data from the SHAMap by key.
    /// In full mode, reads from in-memory SHAMap.
    /// Note: in sparse mode, data is on disk — use `get_raw_owned()` instead.
    pub fn get_raw(&self, key: &Key) -> Option<&[u8]> {
        self.state_map.get_if_loaded(key)
    }

    /// Read raw binary data, returning owned bytes.
    /// Falls through to persistent storage in sparse mode.
    pub fn get_raw_owned(&self, key: &Key) -> Option<Vec<u8>> {
        self.current_overlay_bytes(key)
    }

    /// Read committed bytes directly from the durable NuDB-backed store.
    /// Ignores overlay deletes and typed-only entries.
    pub fn get_committed_raw_owned(&self, key: &Key) -> Option<Vec<u8>> {
        self.nudb_map_guard().and_then(|mut map| map.get(key))
    }

    /// Explain where a raw lookup would source data from.
    /// Used for follower diagnostics when a ModifiedNode base object is missing.
    pub fn inspect_raw_lookup(&self, key: &Key) -> (bool, bool, bool, bool) {
        let deleted_overlay = self.deleted_raw.contains(key);
        let dirty_overlay = self.dirty_raw.contains(key);
        let loaded_overlay = self.state_map.get_if_loaded(key).is_some();
        let nudb_present = self
            .nudb_map_guard()
            .and_then(|mut map| map.get(key))
            .is_some();
        (deleted_overlay, dirty_overlay, loaded_overlay, nudb_present)
    }

    /// Trace the NuDB-backed SHAMap path for a key lookup.
    pub fn debug_trace_nudb_key_path(&self, key: &Key) -> Vec<String> {
        match self.nudb_map_guard() {
            Some(mut map) => map.debug_trace_key_path(key),
            None => vec!["no_nudb_shamap".to_string()],
        }
    }

    /// Insert raw binary data.
    /// In sparse mode: updates the hash tree + persists to storage on disk.
    /// In deferred mode: updates hash tree + buffers in state_map (no disk I/O).
    /// In full mode: stores data in the in-memory SHAMap.
    pub fn insert_raw(&mut self, key: Key, data: Vec<u8>) {
        self.record_preimage(&key);
        self.dirty_raw.insert(key);
        self.deleted_raw.remove(&key);

        // Update sparse hash tree
        if let Some(ref mut sparse) = self.sparse_map {
            let lh = sparse_shamap::leaf_hash(&data, &key.0);
            sparse.insert(key.0, lh);
        }

        if self.defer_storage {
            self.state_map.insert(key, data);
            return;
        }

        // Write to NuDB-backed SHAMap if available (content-addressed, disk-primary).
        // Keep state_map mirrored too: follower repair and dirty-flush paths still
        // read overlay bytes from state_map, and stale buffered bytes here can
        // overwrite authoritative direct-NuDB repairs during take_dirty().
        if self.nudb_shamap.is_some() {
            if let Some(mut map) = self.nudb_map_guard() {
                map.insert(key, data.clone());
            }
            self.state_map.insert(key, data);
            return;
        }

        // Legacy path: write to state_map
        self.state_map.insert(key, data);
    }

    /// Insert a pre-computed leaf hash into the sparse map only (no data stored).
    /// Used during startup to build the hash tree without loading data into RAM.
    pub fn insert_leaf_hash(&mut self, key: Key, hash: [u8; 32]) {
        if let Some(ref mut sparse) = self.sparse_map {
            sparse.insert(key.0, hash);
        }
    }

    /// Remove an entry.
    /// In sparse mode: updates the hash tree + removes from storage.
    /// In deferred mode: updates hash tree + removes from state_map (no disk I/O).
    /// In full mode: removes from in-memory SHAMap.
    pub fn remove_raw(&mut self, key: &Key) {
        self.record_preimage(key);
        self.deleted_raw.insert(*key);
        self.dirty_raw.remove(key);

        // Update sparse hash tree
        if let Some(ref mut sparse) = self.sparse_map {
            sparse.remove(&key.0);
        }

        if self.defer_storage {
            self.state_map.remove(key);
            return;
        }

        // Remove from NuDB-backed SHAMap if available and clear any mirrored
        // overlay bytes so stale entries cannot shadow the authoritative delete.
        if self.nudb_shamap.is_some() {
            if let Some(mut map) = self.nudb_map_guard() {
                map.remove(key);
            }
            self.state_map.remove(key);
            return;
        }

        // Legacy path: remove from state_map
        self.state_map.remove(key);
    }

    /// Enable sparse SHAMap mode.
    /// Migrates any existing state_map entries into the sparse map as leaf hashes,
    /// then clears state_map to free memory.
    pub fn enable_sparse(&mut self) {
        let mut sparse = sparse_shamap::SparseSHAMap::new();

        // Migrate existing state_map entries into sparse as leaf hashes
        let mut migrated = 0usize;
        for (key, data) in self.state_map.iter_leaves() {
            let lh = sparse_shamap::leaf_hash(data, &key.0);
            sparse.insert(key.0, lh);
            migrated += 1;
        }
        if migrated > 0 {
            tracing::info!(
                "enable_sparse: migrated {} state_map entries to sparse",
                migrated
            );
        }

        self.sparse_map = Some(sparse);
        // Clear state_map to free memory — data is on disk, hashes in sparse
        self.state_map = SHAMap::new_state();

        // If a NuDB-backed SHAMap is present, compact any clean leaves now that
        // the sparse view is active. This frees the large in-memory payloads that
        // were retained by the sync handoff tree.
        let evicted = self.evict_clean_nudb_leaves();
        if evicted > 0 {
            tracing::info!(
                "enable_sparse: evicted {} clean leaf/leaves from NuDB-backed tree",
                evicted
            );
        }
    }

    /// Merge typed collections (accounts, trustlines, etc.) from another
    /// LedgerState into this one, without touching the SHAMap.
    /// Used after loading all raw objects into the SHAMap, to get the
    /// typed lookups working for RPC handlers.
    pub fn merge_typed(&mut self, other: LedgerState) {
        self.accounts = other.accounts;
        self.trustlines = other.trustlines;
        self.checks = other.checks;
        self.deposit_preauths = other.deposit_preauths;
        self.dids = other.dids;
        self.escrows = other.escrows;
        self.paychans = other.paychans;
        self.tickets = other.tickets;
        self.nftokens = other.nftokens;
        self.nft_offers = other.nft_offers;
        self.offers = other.offers;
        self.order_books = other.order_books;
        self.directories = other.directories;
        self.account_trustlines = other.account_trustlines;
        self.account_offers_idx = other.account_offers_idx;
        self.active_amendments = other.active_amendments;
    }

    pub fn iter_raw_entries(&self) -> Vec<(Key, &[u8])> {
        self.state_map.iter_leaves()
    }

    /// Get a reference to the sparse SHAMap (for deletion enumeration, etc.)
    pub fn sparse_map_ref(&self) -> Option<&sparse_shamap::SparseSHAMap> {
        self.sparse_map.as_ref()
    }

    /// Peek at the first key in dirty_raw (for diagnostic probes).
    pub fn peek_first_dirty_raw(&self) -> Option<Key> {
        self.dirty_raw.iter().next().copied()
    }

    // ── Hash ────────────────────────────────────────────────────────────────

    /// Create a copy-on-write snapshot of the state SHAMap.
    /// Leaves become stubs (hash only), shares NuDB backend.
    pub fn snapshot_state_map(&mut self) -> crate::ledger::shamap::SHAMap {
        self.state_map.snapshot()
    }

    fn serialize_typed_entry(entry: &TypedEntry) -> Option<Vec<u8>> {
        match entry {
            TypedEntry::Account(_, acct) => Some(acct.to_sle_binary()),
            TypedEntry::Trustline(_, tl) => Some(tl.to_sle_binary()),
            TypedEntry::Check(_, chk) => Some(chk.to_sle_binary()),
            TypedEntry::DepositPreauth(_, dp) => Some(dp.to_sle_binary()),
            TypedEntry::Did(_, did) => Some(did.to_sle_binary()),
            TypedEntry::Escrow(_, esc) => Some(esc.to_sle_binary()),
            TypedEntry::PayChannel(_, pc) => Some(pc.to_sle_binary()),
            TypedEntry::Ticket(_, tkt) => Some(tkt.to_sle_binary()),
            TypedEntry::NFToken(_, _) => None,
            TypedEntry::NFTokenOffer(_, off) => Some(off.to_sle_binary()),
            TypedEntry::Offer(_, off) => Some(off.to_sle_binary()),
            TypedEntry::Directory(_, dir) => Some(dir.to_sle_binary()),
        }
    }

    fn typed_overlay_key_sets(
        &self,
    ) -> (
        std::collections::BTreeSet<Key>,
        std::collections::BTreeSet<Key>,
    ) {
        let mut dirty = std::collections::BTreeSet::new();
        let mut deleted = std::collections::BTreeSet::new();

        dirty.extend(self.dirty_accounts.iter().map(account::shamap_key));
        deleted.extend(self.deleted_accounts.iter().map(account::shamap_key));
        dirty.extend(self.dirty_trustlines.iter().copied());
        deleted.extend(self.deleted_trustlines.iter().copied());
        dirty.extend(self.dirty_checks.iter().copied());
        deleted.extend(self.deleted_checks.iter().copied());
        dirty.extend(self.dirty_deposit_preauths.iter().copied());
        deleted.extend(self.deleted_deposit_preauths.iter().copied());
        dirty.extend(self.dirty_dids.iter().copied());
        deleted.extend(self.deleted_dids.iter().copied());
        dirty.extend(self.dirty_escrows.iter().copied());
        deleted.extend(self.deleted_escrows.iter().copied());
        dirty.extend(self.dirty_paychans.iter().copied());
        deleted.extend(self.deleted_paychans.iter().copied());
        dirty.extend(self.dirty_tickets.iter().copied());
        deleted.extend(self.deleted_tickets.iter().copied());
        dirty.extend(self.dirty_offers.iter().copied());
        deleted.extend(self.deleted_offers.iter().copied());
        dirty.extend(self.dirty_nft_offers.iter().copied());
        dirty.extend(self.dirty_directories.iter().copied());
        deleted.extend(self.deleted_directories.iter().copied());

        (dirty, deleted)
    }

    fn typed_entry_is_dirty(&self, entry: &TypedEntry) -> bool {
        match entry {
            TypedEntry::Account(account_id, _) => self.dirty_accounts.contains(account_id),
            TypedEntry::Trustline(key, _) => self.dirty_trustlines.contains(key),
            TypedEntry::Check(key, _) => self.dirty_checks.contains(key),
            TypedEntry::DepositPreauth(key, _) => self.dirty_deposit_preauths.contains(key),
            TypedEntry::Did(key, _) => self.dirty_dids.contains(key),
            TypedEntry::Escrow(key, _) => self.dirty_escrows.contains(key),
            TypedEntry::PayChannel(key, _) => self.dirty_paychans.contains(key),
            TypedEntry::Ticket(key, _) => self.dirty_tickets.contains(key),
            TypedEntry::NFToken(_, _) => false,
            TypedEntry::NFTokenOffer(key, _) => self.dirty_nft_offers.contains(key),
            TypedEntry::Offer(key, _) => self.dirty_offers.contains(key),
            TypedEntry::Directory(key, _) => self.dirty_directories.contains(key),
        }
    }

    fn current_overlay_bytes(&self, key: &Key) -> Option<Vec<u8>> {
        if self.deleted_raw.contains(key) {
            return None;
        }
        if let Some(typed) = self.lookup_typed_entry(key) {
            if self.typed_entry_is_dirty(&typed) {
                if let Some(data) = Self::serialize_typed_entry(&typed) {
                    return Some(data);
                }
            }
        }
        if let Some(data) = self.state_map.get_if_loaded(key) {
            return Some(data.to_vec());
        }
        if let Some(typed) = self.lookup_typed_entry(key) {
            if let Some(data) = Self::serialize_typed_entry(&typed) {
                return Some(data);
            }
        }
        self.nudb_map_guard().and_then(|mut map| map.get(key))
    }

    fn overlay_state_hash_from_nudb(&self) -> Option<[u8; 32]> {
        let mut snapshot = {
            let mut map = self.nudb_map_guard()?;
            map.snapshot()
        };

        Some(Self::overlay_hash_from_snapshot(&mut snapshot, self))
    }

    fn overlay_hash_from_snapshot(snapshot: &mut shamap::SHAMap, state: &LedgerState) -> [u8; 32] {
        Self::apply_current_overlay_to_snapshot(snapshot, state);
        snapshot.root_hash()
    }

    fn apply_current_overlay_to_snapshot(snapshot: &mut shamap::SHAMap, state: &LedgerState) {
        let (typed_dirty, typed_deleted) = state.typed_overlay_key_sets();
        let mut deleted_sorted: std::collections::BTreeSet<Key> =
            state.deleted_raw.iter().copied().collect();
        deleted_sorted.extend(typed_deleted);
        let mut dirty_sorted: std::collections::BTreeSet<Key> =
            state.dirty_raw.iter().copied().collect();
        dirty_sorted.extend(typed_dirty);

        for key in &deleted_sorted {
            snapshot.remove(key);
        }
        for key in &dirty_sorted {
            if deleted_sorted.contains(key) {
                continue;
            }
            if let Some(data) = state.current_overlay_bytes(key) {
                snapshot.insert(*key, data);
            }
        }
    }

    /// Build a peer-serving snapshot of the current account-state tree.
    /// Uses the NuDB-backed base plus the live overlay when sparse mode is active.
    pub fn peer_state_map_snapshot(&mut self) -> shamap::SHAMap {
        if self.nudb_shamap.is_some() {
            let mut snapshot = {
                let mut map = self
                    .nudb_map_guard()
                    .expect("nudb_shamap presence checked above");
                map.snapshot()
            };
            Self::apply_current_overlay_to_snapshot(&mut snapshot, self);
            snapshot
        } else {
            let mut snapshot = self.state_map.snapshot();
            Self::apply_current_overlay_to_snapshot(&mut snapshot, self);
            snapshot
        }
    }

    /// Rehydrate an immutable historical state map from a persisted root hash.
    pub fn historical_state_map_from_root(&self, root_hash: [u8; 32]) -> Option<shamap::SHAMap> {
        let backend = {
            let map = self.nudb_map_guard()?;
            map.backend().cloned()
        }?;

        let mut map = shamap::SHAMap::with_backend(MapType::AccountState, backend);
        map.load_root_from_hash(root_hash).ok()?.then_some(map)
    }

    /// Diagnostic-only: compute the overlay root hash by snapshotting the
    /// NuDB-backed SHAMap and applying the current dirty/deleted overlay.
    pub fn overlay_state_hash_for_diagnostics(&self) -> Option<[u8; 32]> {
        self.overlay_state_hash_from_nudb()
    }

    /// Diagnostic-only: compute the sparse SHAMap root hash directly.
    pub fn sparse_state_hash_for_diagnostics(&mut self) -> Option<[u8; 32]> {
        self.sparse_map.as_mut().map(|sparse| sparse.root_hash())
    }

    /// Diagnostic-only: compute an overlay root from an explicit set of
    /// upserts/deletes applied over the current NuDB-backed base snapshot.
    pub fn overlay_hash_from_entries_for_diagnostics(
        &self,
        upserts: &[(Key, Vec<u8>)],
        deletes: &[Key],
    ) -> Option<[u8; 32]> {
        let mut snapshot = {
            let mut map = self.nudb_map_guard()?;
            map.snapshot()
        };

        let mut deleted_sorted = deletes.to_vec();
        deleted_sorted.sort_by_key(|k| k.0);
        let mut upserts_sorted = upserts.to_vec();
        upserts_sorted.sort_by_key(|(k, _)| k.0);

        for key in &deleted_sorted {
            snapshot.remove(key);
        }
        for (key, data) in &upserts_sorted {
            if deleted_sorted.binary_search_by_key(&key.0, |k| k.0).is_ok() {
                continue;
            }
            snapshot.insert(*key, data.clone());
        }
        Some(snapshot.root_hash())
    }

    /// Diagnostic-only: compute an overlay root from an explicit base snapshot.
    /// This is used to compare local and authoritative overlays against the
    /// pristine sync-anchor base rather than the already-mutated live tree.
    pub fn overlay_hash_from_snapshot_for_diagnostics(
        base: &mut shamap::SHAMap,
        upserts: &[(Key, Vec<u8>)],
        deletes: &[Key],
    ) -> [u8; 32] {
        let mut deleted_sorted = deletes.to_vec();
        deleted_sorted.sort_by_key(|k| k.0);
        let mut upserts_sorted = upserts.to_vec();
        upserts_sorted.sort_by_key(|(k, _)| k.0);

        for key in &deleted_sorted {
            base.remove(key);
        }
        for (key, data) in &upserts_sorted {
            if deleted_sorted.binary_search_by_key(&key.0, |k| k.0).is_ok() {
                continue;
            }
            base.insert(*key, data.clone());
        }
        base.root_hash()
    }

    /// Diagnostic-only: expose the current raw overlay key sets.
    pub fn raw_overlay_keys_for_diagnostics(&self) -> (Vec<Key>, Vec<Key>) {
        let mut dirty: Vec<Key> = self.dirty_raw.iter().copied().collect();
        dirty.sort_by_key(|k| k.0);
        let mut deleted: Vec<Key> = self.deleted_raw.iter().copied().collect();
        deleted.sort_by_key(|k| k.0);
        (dirty, deleted)
    }

    /// Diagnostic-only: expose the typed dirty/deleted keys after mapping
    /// them to their raw SHAMap keys.
    pub fn typed_overlay_keys_for_diagnostics(&self) -> (Vec<Key>, Vec<Key>) {
        let (dirty, deleted) = self.typed_overlay_key_sets();
        (dirty.into_iter().collect(), deleted.into_iter().collect())
    }

    fn has_typed_overlay_changes(&self) -> bool {
        !self.dirty_accounts.is_empty()
            || !self.deleted_accounts.is_empty()
            || !self.dirty_trustlines.is_empty()
            || !self.deleted_trustlines.is_empty()
            || !self.dirty_checks.is_empty()
            || !self.deleted_checks.is_empty()
            || !self.dirty_deposit_preauths.is_empty()
            || !self.deleted_deposit_preauths.is_empty()
            || !self.dirty_dids.is_empty()
            || !self.deleted_dids.is_empty()
            || !self.dirty_escrows.is_empty()
            || !self.deleted_escrows.is_empty()
            || !self.dirty_paychans.is_empty()
            || !self.deleted_paychans.is_empty()
            || !self.dirty_tickets.is_empty()
            || !self.deleted_tickets.is_empty()
            || !self.dirty_offers.is_empty()
            || !self.deleted_offers.is_empty()
            || !self.dirty_nft_offers.is_empty()
            || !self.dirty_directories.is_empty()
            || !self.deleted_directories.is_empty()
    }

    /// Root hash of the account-state SHAMap.
    pub fn state_hash(&mut self) -> [u8; 32] {
        if self.defer_storage
            || !self.dirty_raw.is_empty()
            || !self.deleted_raw.is_empty()
            || self.has_typed_overlay_changes()
        {
            if let Some(hash) = self.overlay_state_hash_from_nudb() {
                return hash;
            }
            if self.sparse_map.is_none() {
                let mut snapshot = self.state_map.snapshot();
                Self::apply_current_overlay_to_snapshot(&mut snapshot, self);
                return snapshot.root_hash();
            }
            if let Some(ref mut sparse) = self.sparse_map {
                return sparse.root_hash();
            }
        }
        // Prefer NuDB-backed SHAMap (content-addressed, disk-primary)
        if let Some(mut map) = self.nudb_map_guard() {
            return map.root_hash();
        }
        // Fall back to sparse map (legacy)
        if let Some(ref mut sparse) = self.sparse_map {
            sparse.root_hash()
        } else {
            self.state_map.root_hash()
        }
    }
}

impl Default for LedgerState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_account(id_byte: u8, balance: u64, sequence: u32) -> AccountRoot {
        let mut account_id = [0u8; 20];
        account_id[0] = id_byte;
        AccountRoot {
            account_id,
            balance,
            sequence,
            owner_count: 0,
            flags: 0,
            regular_key: None,
            minted_nftokens: 0,
            burned_nftokens: 0,
            transfer_rate: 0,
            domain: Vec::new(),
            tick_size: 0,
            ticket_count: 0,
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        }
    }

    #[test]
    fn previous_txn_threading_matches_fix_previous_txn_id_gate() {
        let mut state = LedgerState::new();

        assert!(should_thread_previous_txn_fields(
            &state,
            sle::LedgerEntryType::AccountRoot,
        ));
        assert!(should_thread_previous_txn_fields(
            &state,
            sle::LedgerEntryType::RippleState,
        ));
        assert!(!should_thread_previous_txn_fields(
            &state,
            sle::LedgerEntryType::DirectoryNode,
        ));
        assert!(!should_thread_previous_txn_fields(
            &state,
            sle::LedgerEntryType::AMM,
        ));
        assert!(!should_thread_previous_txn_fields(
            &state,
            sle::LedgerEntryType::LedgerHashes,
        ));

        state.enable_amendment(*FEATURE_FIX_PREVIOUS_TXN_ID);

        assert!(should_thread_previous_txn_fields(
            &state,
            sle::LedgerEntryType::DirectoryNode,
        ));
        assert!(should_thread_previous_txn_fields(
            &state,
            sle::LedgerEntryType::AMM,
        ));
    }

    #[test]
    fn commit_tx_preserves_changes() {
        let mut state = LedgerState::new();
        let acct = make_account(1, 1000, 1);

        state.begin_tx();
        state.insert_account(acct.clone());
        let journal = state.commit_tx();

        // Account should still be there after commit
        assert!(state.get_account(&acct.account_id).is_some());
        assert_eq!(state.get_account(&acct.account_id).unwrap().balance, 1000);
        // Journal should have one entry
        assert_eq!(journal.len(), 1);
    }

    #[test]
    fn discard_tx_restores_empty_state() {
        let mut state = LedgerState::new();
        let acct = make_account(1, 1000, 1);

        state.begin_tx();
        state.insert_account(acct.clone());

        // Account is visible during the tx
        assert!(state.get_account(&acct.account_id).is_some());

        state.discard_tx();

        // Account should be gone after discard
        assert!(state.get_account(&acct.account_id).is_none());
        assert_eq!(state.account_count(), 0);
    }

    #[test]
    fn discard_tx_restores_modified_account() {
        let mut state = LedgerState::new();
        let acct = make_account(1, 1000, 1);
        state.insert_account(acct.clone());

        // Modify within a tx scope
        state.begin_tx();
        let mut modified = acct.clone();
        modified.balance = 500;
        modified.sequence = 2;
        state.insert_account(modified);

        // Verify modification is visible
        assert_eq!(state.get_account(&acct.account_id).unwrap().balance, 500);

        state.discard_tx();

        // Should be restored to original
        let restored = state.get_account(&acct.account_id).unwrap();
        assert_eq!(restored.balance, 1000);
        assert_eq!(restored.sequence, 1);
    }

    #[test]
    fn discard_tx_restores_removed_account() {
        let mut state = LedgerState::new();
        let acct = make_account(1, 1000, 1);
        state.insert_account(acct.clone());

        state.begin_tx();
        state.remove_account(&acct.account_id);
        assert!(state.get_account(&acct.account_id).is_none());

        state.discard_tx();

        // Should be back
        assert!(state.get_account(&acct.account_id).is_some());
        assert_eq!(state.get_account(&acct.account_id).unwrap().balance, 1000);
    }

    #[test]
    fn discard_tx_restores_dirty_tracking() {
        let mut state = LedgerState::new();
        let acct = make_account(1, 1000, 1);

        // Insert outside tx — marks dirty
        state.insert_account(acct.clone());
        assert!(state.dirty_accounts.contains(&acct.account_id));

        // Clear dirty to simulate a clean baseline
        state.dirty_accounts.clear();
        assert!(!state.dirty_accounts.contains(&acct.account_id));

        state.begin_tx();
        let mut modified = acct.clone();
        modified.balance = 500;
        state.insert_account(modified);
        // Now dirty again
        assert!(state.dirty_accounts.contains(&acct.account_id));

        state.discard_tx();

        // Dirty tracking should be restored to the begin_tx snapshot (empty)
        assert!(!state.dirty_accounts.contains(&acct.account_id));
    }

    #[test]
    fn discard_tx_restores_check() {
        let mut state = LedgerState::new();

        let chk = Check {
            account: [1u8; 20],
            destination: [2u8; 20],
            send_max: crate::transaction::Amount::Xrp(500),
            sequence: 1,
            expiration: 0,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };

        state.begin_tx();
        state.insert_check(chk.clone());
        assert!(state.get_check(&chk.key()).is_some());

        state.discard_tx();
        assert!(state.get_check(&chk.key()).is_none());
    }

    #[test]
    fn discard_tx_restores_escrow() {
        let mut state = LedgerState::new();

        let esc = Escrow {
            account: [1u8; 20],
            destination: [2u8; 20],
            amount: 1000,
            held_amount: None,
            sequence: 1,
            finish_after: 100,
            cancel_after: 200,
            condition: None,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };

        state.begin_tx();
        state.insert_escrow(esc.clone());
        assert!(state.get_escrow(&esc.key()).is_some());

        state.discard_tx();
        assert!(state.get_escrow(&esc.key()).is_none());
    }

    #[test]
    fn discard_tx_multi_object_rollback() {
        let mut state = LedgerState::new();

        // Pre-existing account
        let acct = make_account(1, 1000, 1);
        state.insert_account(acct.clone());
        state.dirty_accounts.clear();

        state.begin_tx();

        // Modify existing account
        let mut modified = acct.clone();
        modified.balance = 500;
        state.insert_account(modified);

        // Insert new check
        let chk = Check {
            account: [1u8; 20],
            destination: [2u8; 20],
            send_max: crate::transaction::Amount::Xrp(100),
            sequence: 1,
            expiration: 0,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };
        state.insert_check(chk.clone());

        state.discard_tx();

        // Account restored
        assert_eq!(state.get_account(&acct.account_id).unwrap().balance, 1000);
        // Check removed
        assert!(state.get_check(&chk.key()).is_none());
    }

    #[test]
    fn fee_only_reset_pattern() {
        // Simulates the rippled reset() pattern:
        // 1. begin_tx
        // 2. Apply full tx (modifies multiple objects)
        // 3. discard_tx (undo everything)
        // 4. begin_tx again
        // 5. Apply only fee + sequence bump
        // 6. commit_tx
        let mut state = LedgerState::new();
        let acct = make_account(1, 1000, 1);
        state.insert_account(acct.clone());
        state.dirty_accounts.clear();

        // First attempt: full tx that creates a check + modifies account
        state.begin_tx();
        let mut modified = acct.clone();
        modified.balance = 500;
        modified.sequence = 2;
        state.insert_account(modified);
        let chk = Check {
            account: [1u8; 20],
            destination: [2u8; 20],
            send_max: crate::transaction::Amount::Xrp(100),
            sequence: 1,
            expiration: 0,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };
        state.insert_check(chk.clone());

        // Discard — tx failed with tec
        state.discard_tx();

        // Verify clean state
        assert_eq!(state.get_account(&acct.account_id).unwrap().balance, 1000);
        assert!(state.get_check(&chk.key()).is_none());

        // Second attempt: fee-only (just deduct fee + bump sequence)
        state.begin_tx();
        let mut fee_only = acct.clone();
        fee_only.balance = 1000 - 12; // 12 drop fee
        fee_only.sequence = 2;
        state.insert_account(fee_only);
        let journal = state.commit_tx();

        // Verify fee-only state persisted
        let final_acct = state.get_account(&acct.account_id).unwrap();
        assert_eq!(final_acct.balance, 988);
        assert_eq!(final_acct.sequence, 2);
        assert!(state.get_check(&chk.key()).is_none());
        assert!(!journal.is_empty());
    }

    #[test]
    fn state_hash_uses_nudb_base_plus_overlay_after_restart() {
        use crate::ledger::node_store::NuDBNodeStore;

        let dir = std::env::temp_dir().join("ledger_state_overlay_hash_test");
        let _ = std::fs::remove_dir_all(&dir);
        let backend = std::sync::Arc::new(NuDBNodeStore::open(&dir).unwrap());

        let key1 = Key([0x11; 32]);
        let key2 = Key([0x22; 32]);
        let data1 = vec![0xAA; 80];
        let data2 = vec![0xBB; 96];

        let mut seeded = LedgerState::new();
        seeded.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend.clone()));
        seeded.insert_raw(key1, data1.clone());
        seeded.insert_raw(key2, data2.clone());
        let _ = seeded.take_dirty();
        let root = seeded.nudb_root_hash().unwrap();

        let mut restarted = LedgerState::new();
        restarted.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend.clone()));
        assert!(restarted.load_nudb_root(root).unwrap());
        restarted.enable_sparse();
        restarted.set_defer_storage(true);

        let new_data1 = vec![0xCC; 80];
        restarted.insert_raw(key1, new_data1.clone());
        let overlay_hash = restarted.state_hash();

        let mut expected = SHAMap::with_backend(MapType::AccountState, backend.clone());
        assert!(expected.load_root_from_hash(root).unwrap());
        expected.insert(key1, new_data1);
        let expected_hash = expected.root_hash();

        assert_eq!(overlay_hash, expected_hash);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn state_hash_applies_typed_overlay_without_nudb() {
        let mut state = LedgerState::new();
        let original = make_account(0x51, 1000, 1);
        let key = account::shamap_key(&original.account_id);

        state.insert_account(original.clone());
        state.dirty_accounts.clear();

        let base_hash = state.state_hash();

        let mut updated = original.clone();
        updated.balance = 2500;
        updated.sequence = 2;
        state.accounts.insert(updated.account_id, updated.clone());
        state.dirty_accounts.insert(updated.account_id);

        let mut expected = state.state_map.snapshot();
        expected.insert(key, updated.to_sle_binary());

        assert_eq!(state.state_hash(), expected.root_hash());
        assert_ne!(state.state_hash(), base_hash);
    }

    #[test]
    fn state_hash_applies_typed_nft_offer_overlay_without_nudb() {
        use crate::ledger::nftoken::NFTokenOffer;
        use crate::transaction::amount::Amount;

        let mut state = LedgerState::new();
        let offer = NFTokenOffer {
            account: [0x61; 20],
            sequence: 9,
            nftoken_id: [0xA7; 32],
            amount: Amount::Xrp(25),
            destination: None,
            expiration: None,
            flags: 0x0001,
            owner_node: 0,
            nft_offer_node: 0,
            previous_txn_id: [0; 32],
            previous_txn_lgrseq: 0,
            raw_sle: None,
        };
        let key = offer.key();

        let base_hash = state.state_hash();
        state.hydrate_nft_offer(offer.clone());

        let (dirty, deleted) = state.typed_overlay_keys_for_diagnostics();
        assert!(dirty.contains(&key));
        assert!(deleted.is_empty());

        let mut expected = state.state_map.snapshot();
        expected.insert(key, offer.to_sle_binary());

        assert_eq!(state.state_hash(), expected.root_hash());
        assert_ne!(state.state_hash(), base_hash);
    }

    #[test]
    fn peer_state_map_snapshot_includes_overlay_inserts() {
        use crate::ledger::node_store::NuDBNodeStore;

        let dir = std::env::temp_dir().join("ledger_state_peer_snapshot_test");
        let _ = std::fs::remove_dir_all(&dir);
        let backend = std::sync::Arc::new(NuDBNodeStore::open(&dir).unwrap());

        let persisted_key = Key([0x11; 32]);
        let persisted_data = vec![0xAA; 40];
        let overlay_key = Key([0x22; 32]);
        let overlay_data = vec![0xBB; 48];

        let mut seeded = LedgerState::new();
        seeded.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend.clone()));
        seeded.insert_raw(persisted_key, persisted_data);
        let _ = seeded.take_dirty();
        let root = seeded.nudb_root_hash().unwrap();

        let mut restarted = LedgerState::new();
        restarted.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend.clone()));
        assert!(restarted.load_nudb_root(root).unwrap());
        restarted.enable_sparse();
        restarted.set_defer_storage(true);
        restarted.insert_raw(overlay_key, overlay_data.clone());

        let mut snapshot = restarted.peer_state_map_snapshot();
        let wire = snapshot
            .get_wire_node_by_id(&crate::ledger::shamap_id::SHAMapNodeID::from_key(
                &overlay_key.0,
            ))
            .expect("overlay leaf should be visible in peer snapshot");

        assert_eq!(wire.last().copied(), Some(0x01));
        assert_eq!(&wire[..overlay_data.len()], overlay_data.as_slice());
        assert_eq!(
            &wire[overlay_data.len()..overlay_data.len() + 32],
            &overlay_key.0,
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn historical_state_map_from_root_reads_old_versions() {
        use crate::ledger::node_store::NuDBNodeStore;

        let dir = std::env::temp_dir().join("ledger_state_historical_root_test");
        let _ = std::fs::remove_dir_all(&dir);
        let backend = std::sync::Arc::new(NuDBNodeStore::open(&dir).unwrap());

        let key = Key([0x33; 32]);
        let old_data = vec![0xAA; 24];
        let new_data = vec![0xCC; 24];

        let mut state = LedgerState::new();
        state.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend.clone()));
        state.insert_raw(key, old_data.clone());
        let _ = state.take_dirty();
        let old_root = state.nudb_root_hash().unwrap();

        state.insert_raw(key, new_data.clone());
        let _ = state.take_dirty();
        let new_root = state.nudb_root_hash().unwrap();

        let old_map = state.historical_state_map_from_root(old_root).unwrap();
        let new_map = state.historical_state_map_from_root(new_root).unwrap();

        let mut old_map = old_map;
        let mut new_map = new_map;
        assert_eq!(old_map.get(&key), Some(old_data));
        assert_eq!(new_map.get(&key), Some(new_data));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn direct_nudb_insert_raw_overwrites_stale_buffered_overlay_bytes() {
        use crate::ledger::node_store::NuDBNodeStore;

        let dir = std::env::temp_dir().join("ledger_state_direct_nudb_insert_raw_test");
        let _ = std::fs::remove_dir_all(&dir);
        let backend = std::sync::Arc::new(NuDBNodeStore::open(&dir).unwrap());

        let key = Key([0x44; 32]);
        let old_data = vec![0xAA; 24];
        let new_data = vec![0xCC; 24];

        let mut state = LedgerState::new();
        state.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend));
        state.set_defer_storage(true);
        state.insert_raw(key, old_data.clone());
        state.set_defer_storage(false);
        let _ = state.take_dirty();

        state.insert_raw(key, new_data.clone());
        assert_eq!(state.get_raw_owned(&key), Some(new_data.clone()));

        let _ = state.take_dirty();
        let root = state.nudb_root_hash().unwrap();
        let mut historical = state.historical_state_map_from_root(root).unwrap();
        assert_eq!(historical.get(&key), Some(new_data));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reset_for_fresh_sync_drops_runtime_state_but_preserves_backend() {
        use crate::ledger::node_store::MemNodeStore;

        let backend = std::sync::Arc::new(MemNodeStore::new());
        let key = Key([0xAB; 32]);
        let data = vec![0x11; 64];
        let leaf_hash = crate::ledger::sparse_shamap::leaf_hash(&data, &key.0);
        let mut state = LedgerState::new();
        state.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend.clone()));
        state.enable_amendment(*FEATURE_FIX_PREVIOUS_TXN_ID);
        state.insert_raw(key, data);
        state.flush_nudb().unwrap();
        state.hydrate_account(make_account(0x22, 10, 1));
        state.enable_sparse();
        assert!(state.sparse_map.is_some());
        assert_eq!(state.account_count(), 1);
        assert!(state.nudb_shamap.is_some());

        state.reset_for_fresh_sync();

        assert_eq!(state.account_count(), 0);
        assert!(state.sparse_map.is_none());
        assert!(state.iter_raw_entries().is_empty());
        assert_eq!(state.amendment_count(), 1);
        assert!(state.nudb_shamap.is_some());
        let nudb_map = state.nudb_map_guard().expect("nudb backend should persist");
        let fetched = nudb_map
            .backend()
            .expect("backend should remain attached")
            .fetch(&leaf_hash)
            .unwrap();
        assert!(fetched.is_some());
        drop(nudb_map);
        assert!(state.get_raw_owned(&key).is_none());
    }

    #[test]
    fn flush_nudb_compacts_clean_loaded_leaves() {
        use crate::ledger::node_store::MemNodeStore;

        let backend = std::sync::Arc::new(MemNodeStore::new());
        let key = Key([0xCD; 32]);
        let data = vec![0x22; 80];

        let mut seeded = LedgerState::new();
        seeded.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend.clone()));
        seeded.insert_raw(key, data.clone());
        seeded.flush_nudb().unwrap();
        let root = seeded.nudb_root_hash().unwrap();

        let mut restarted = LedgerState::new();
        restarted.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend.clone()));
        assert!(restarted.load_nudb_root(root).unwrap());
        assert_eq!(restarted.get_raw_owned(&key), Some(data.clone()));

        {
            let map = restarted
                .nudb_map_guard()
                .expect("nudb map should exist after root load");
            assert!(map.get_if_loaded(&key).is_some());
        }

        let flushed = restarted.flush_nudb().unwrap();
        assert_eq!(flushed, 0, "clean map should not require a dirty flush");

        {
            let map = restarted
                .nudb_map_guard()
                .expect("nudb map should exist after compaction");
            assert!(
                map.get_if_loaded(&key).is_none(),
                "clean leaves should be evicted even when nothing was flushed"
            );
        }
        assert_eq!(restarted.get_raw_owned(&key), Some(data));
    }

    #[test]
    fn get_raw_owned_uses_typed_overlay_when_raw_bytes_are_absent() {
        let mut state = LedgerState::new();
        let account = make_account(0x52, 42, 7);
        let key = crate::ledger::account::shamap_key(&account.account_id);

        state.hydrate_account(account.clone());

        assert_eq!(state.get_raw(&key), None);
        assert_eq!(state.get_raw_owned(&key), Some(account.to_sle_binary()));
    }

    #[test]
    fn committed_raw_lookup_bypasses_deleted_overlay() {
        use crate::ledger::node_store::MemNodeStore;

        let backend = std::sync::Arc::new(MemNodeStore::new());
        let key = Key([0xEF; 32]);
        let data = vec![0x5A; 96];

        let mut state = LedgerState::new();
        state.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend));
        state.insert_raw(key, data.clone());
        state.flush_nudb().unwrap();

        state.deleted_raw.insert(key);
        state.state_map.remove(&key);

        assert_eq!(state.get_raw_owned(&key), None);
        assert_eq!(state.get_committed_raw_owned(&key), Some(data));
    }
}
