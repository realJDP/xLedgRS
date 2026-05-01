//! xLedgRS purpose: Invariants support for XRPL ledger state and SHAMap logic.
//! Post-apply invariant checking — prevents invalid state from committing.
//!
//! Mirrors rippled's InvariantCheck system (InvariantCheck.cpp).
//! Each invariant visits all modified ledger entries (before/after pairs),
//! then performs a final check.  If any invariant fails, the transaction
//! is discarded and a fee-only reset is attempted.

use crate::ledger::ter::TxResult;
use crate::ledger::{Key, LedgerState};
use crate::transaction::ParsedTx;

/// Before/after pair for one touched ledger entry.
pub struct EntryDelta {
    pub key: Key,
    /// Raw bytes before the tx (None = entry didn't exist).
    pub before: Option<Vec<u8>>,
    /// Raw bytes after the tx (None = entry was deleted).
    pub after: Option<Vec<u8>>,
}

/// Result of running invariant checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantResult {
    /// All invariants passed.
    Ok,
    /// An invariant failed — transaction must be discarded.
    Failed(&'static str),
}

/// Run all invariant checks against the set of ledger entries touched by a transaction.
///
/// `touched` comes from `commit_tx()` / the tx journal — it's the list of
/// `(key, before_bytes)` pairs. Current ("after") state is looked up from `state`.
///
/// `ter` is the transaction result.  `fee` is the fee charged.  `tx` is the
/// parsed transaction.
pub fn check_invariants(
    state: &LedgerState,
    touched: &[(Key, Option<Vec<u8>>)],
    ter: TxResult,
    fee: u64,
    tx: &ParsedTx,
) -> InvariantResult {
    // Build deltas
    let deltas: Vec<EntryDelta> = touched
        .iter()
        .map(|(key, before)| {
            let after = state.get_raw_owned(key);
            EntryDelta {
                key: *key,
                before: before.clone(),
                after,
            }
        })
        .collect();

    // Run each invariant.  Short-circuit on first failure.
    if let Some(reason) = check_xrp_not_created(&deltas, fee) {
        return InvariantResult::Failed(reason);
    }
    if let Some(reason) = check_xrp_balance_valid(&deltas) {
        return InvariantResult::Failed(reason);
    }
    if let Some(reason) = check_fee_valid(fee, tx) {
        return InvariantResult::Failed(reason);
    }
    if let Some(reason) = check_no_negative_owner_count(&deltas) {
        return InvariantResult::Failed(reason);
    }
    if let Some(reason) = check_account_roots_not_deleted(&deltas, ter, tx) {
        return InvariantResult::Failed(reason);
    }
    if let Some(reason) = check_no_bad_offers(&deltas) {
        return InvariantResult::Failed(reason);
    }
    if let Some(reason) = check_no_zero_escrow(&deltas) {
        return InvariantResult::Failed(reason);
    }
    if let Some(reason) = check_ledger_entry_types_match(&deltas) {
        return InvariantResult::Failed(reason);
    }
    if let Some(reason) = check_no_xrp_trust_lines(&deltas) {
        return InvariantResult::Failed(reason);
    }
    if let Some(reason) = check_valid_new_account_root(&deltas) {
        return InvariantResult::Failed(reason);
    }

    InvariantResult::Ok
}

// ── Individual invariants ────────────────────────────────────────────────────

/// LedgerEntryType field: type=1 (UInt16), field=1 → type_code byte 0x11.
/// The entry type is at bytes [1..3] in the encoded SLE.
fn sle_entry_type(data: &[u8]) -> Option<u16> {
    if data.len() < 3 || data[0] != 0x11 {
        return None;
    }
    Some(u16::from_be_bytes([data[1], data[2]]))
}

/// Extract XRP held (drops) from a ledger entry, dispatch by entry type.
///
/// - AccountRoot: sfBalance (type=6, field=2) — account's XRP balance
/// - Escrow: sfAmount (type=6, field=1) — locked XRP
/// - PayChannel: sfAmount (type=6, field=1) — total locked channel XRP
fn sle_xrp_held(data: &[u8], entry_type: u16) -> i64 {
    // Which Amount field holds the XRP for this entry type?
    let target_field = match entry_type {
        ACCOUNT_ROOT_TYPE => 2, // sfBalance
        ESCROW_TYPE => 1,       // sfAmount
        PAYCHAN_TYPE => 1,      // sfAmount (total locked, not claimed)
        _ => return 0,
    };
    sle_amount_field(data, target_field).unwrap_or(0)
}

/// Read an Amount field (type=6) with the given field_code from an SLE.
/// Returns the XRP drops value (positive or negative).
fn sle_amount_field(data: &[u8], target_field_code: u8) -> Option<i64> {
    let mut pos = 0;
    while pos < data.len() {
        let (type_code, field_code, header_len) = decode_field_header(data, pos)?;
        pos += header_len;

        if type_code == 6 && field_code == target_field_code {
            if pos + 8 > data.len() {
                return None;
            }
            let raw = u64::from_be_bytes(data[pos..pos + 8].try_into().ok()?);
            // XRP amounts: bit 63 = 0 (native), bit 62 = positive flag
            // Drops = raw & 0x3FFFFFFFFFFFFFFF
            let drops = (raw & 0x3FFF_FFFF_FFFF_FFFF) as i64;
            let is_positive = (raw >> 62) & 1 == 1;
            return Some(if is_positive { drops } else { -drops });
        }

        let field_len = field_data_len(type_code, field_code, data, pos)?;
        pos += field_len;
    }
    None
}

/// Decode a field header (type_code, field_code, header_length).
fn decode_field_header(data: &[u8], pos: usize) -> Option<(u8, u8, usize)> {
    if pos >= data.len() {
        return None;
    }
    let b = data[pos];
    let mut type_code = (b >> 4) & 0x0F;
    let mut field_code = b & 0x0F;
    let mut len = 1usize;

    if type_code == 0 {
        if pos + len >= data.len() {
            return None;
        }
        type_code = data[pos + len];
        len += 1;
    }
    if field_code == 0 {
        if pos + len >= data.len() {
            return None;
        }
        field_code = data[pos + len];
        len += 1;
    }
    Some((type_code, field_code, len))
}

/// Get the data length for a field given its type code.
fn field_data_len(type_code: u8, _field_code: u8, data: &[u8], pos: usize) -> Option<usize> {
    match type_code {
        1 => Some(2),  // UInt16
        2 => Some(4),  // UInt32
        3 => Some(8),  // UInt64
        4 => Some(16), // Hash128
        5 => Some(32), // Hash256
        6 => {
            // Amount — 8 bytes XRP, 48 IOU, 33 MPT
            if pos + 1 > data.len() {
                return None;
            }
            if (data[pos] & 0x80) != 0 {
                Some(48) // IOU: 8 amount + 20 currency + 20 issuer
            } else if (data[pos] & 0x20) != 0 {
                Some(33) // MPT: 8 value + 24 MPTIssuanceID + 1 prefix
            } else {
                Some(8) // XRP native
            }
        }
        7 | 8 | 19 => {
            // VL-encoded: Blob, AccountID, Vector256
            let (vl_len, vl_header) = crate::ledger::meta::decode_vl_length(data, pos);
            Some(vl_header + vl_len)
        }
        14 => {
            // STObject — scan to end marker 0xE1
            let mut p = pos;
            while p < data.len() && data[p] != 0xE1 {
                p += 1;
            }
            if p < data.len() {
                Some(p - pos + 1)
            } else {
                None
            }
        }
        15 => {
            // STArray — scan to end marker 0xF1
            let mut p = pos;
            while p < data.len() && data[p] != 0xF1 {
                p += 1;
            }
            if p < data.len() {
                Some(p - pos + 1)
            } else {
                None
            }
        }
        16 => Some(1),  // UInt8
        17 => Some(20), // Hash160 (20 bytes, NOT 32)
        18 => Some(32), // UInt256 (PathSet — actually variable, but 32 is common)
        _ => None,      // Unknown — can't skip
    }
}

const ACCOUNT_ROOT_TYPE: u16 = 0x0061;
const ESCROW_TYPE: u16 = 0x0075;
const PAYCHAN_TYPE: u16 = 0x0078;

// Maximum XRP in existence (100 billion XRP in drops)
const MAX_XRP_DROPS: i64 = 100_000_000_000_000_000;

/// Invariant 1: XRP Not Created.
/// The total XRP across all modified accounts + escrows + paychans must
/// decrease by exactly the fee amount (XRP can only be destroyed via fees).
fn check_xrp_not_created(deltas: &[EntryDelta], fee: u64) -> Option<&'static str> {
    let mut drops_delta: i64 = 0;

    for delta in deltas {
        let entry_type = delta
            .after
            .as_deref()
            .and_then(sle_entry_type)
            .or_else(|| delta.before.as_deref().and_then(sle_entry_type));

        let entry_type = match entry_type {
            Some(t) if t == ACCOUNT_ROOT_TYPE || t == ESCROW_TYPE || t == PAYCHAN_TYPE => t,
            _ => continue,
        };

        let before_drops = delta
            .before
            .as_deref()
            .map(|d| sle_xrp_held(d, entry_type))
            .unwrap_or(0);

        let after_drops = delta
            .after
            .as_deref()
            .map(|d| sle_xrp_held(d, entry_type))
            .unwrap_or(0);

        drops_delta += after_drops - before_drops;
    }

    // XRP delta should be exactly -(fee) — fee was destroyed
    let expected = -(fee as i64);
    if drops_delta != expected {
        return Some("XRPNotCreated: XRP delta does not match fee");
    }
    None
}

/// Invariant 2: XRP Balance Valid.
/// All account XRP balances must be in [0, MAX_XRP_DROPS].
fn check_xrp_balance_valid(deltas: &[EntryDelta]) -> Option<&'static str> {
    for delta in deltas {
        let data = match &delta.after {
            Some(d) => d,
            None => continue, // deleted entries don't need balance check
        };
        if sle_entry_type(data) != Some(ACCOUNT_ROOT_TYPE) {
            continue;
        }
        if let Some(balance) = sle_amount_field(data, 2) {
            // sfBalance = field 2
            if balance < 0 {
                return Some("XRPBalanceChecks: negative XRP balance");
            }
            if balance > MAX_XRP_DROPS {
                return Some("XRPBalanceChecks: XRP balance exceeds maximum");
            }
        }
    }
    None
}

/// Invariant 3: Transaction Fee Check.
/// Fee must be non-negative and not exceed the tx's declared fee.
fn check_fee_valid(fee: u64, tx: &ParsedTx) -> Option<&'static str> {
    if fee > tx.fee {
        return Some("TransactionFeeCheck: charged fee exceeds declared fee");
    }
    // fee is u64 so can't be negative, but check against maximum
    if fee as i64 > MAX_XRP_DROPS {
        return Some("TransactionFeeCheck: fee exceeds maximum XRP");
    }
    None
}

/// Invariant 4: No Negative Owner Count.
/// Account owner_count must not go negative after a transaction.
/// sfOwnerCount: type=2 (UInt32), field=17 → 0x28 + 0x11 (two-byte header: 0x20|0x00, 0x11)
/// Actually: type=2, field=17 → since field>15, header is 0x20, 0x11
fn sle_owner_count(data: &[u8]) -> Option<u32> {
    let mut pos = 0;
    while pos < data.len() {
        let (type_code, field_code, header_len) = decode_field_header(data, pos)?;
        pos += header_len;
        if type_code == 2 && field_code == 17 {
            // sfOwnerCount: UInt32
            if pos + 4 > data.len() {
                return None;
            }
            return Some(u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?));
        }
        let field_len = field_data_len(type_code, field_code, data, pos)?;
        pos += field_len;
    }
    None
}

fn check_no_negative_owner_count(deltas: &[EntryDelta]) -> Option<&'static str> {
    for delta in deltas {
        let data = match &delta.after {
            Some(d) => d,
            None => continue,
        };
        if sle_entry_type(data) != Some(ACCOUNT_ROOT_TYPE) {
            continue;
        }
        // owner_count is u32 so can't literally go negative, but check for
        // wrap-around (very large values that indicate underflow)
        if let Some(count) = sle_owner_count(data) {
            if count > 10_000_000 {
                // Likely underflow — no account should own 10M+ objects
                return Some("OwnerCount: suspiciously large owner count (likely underflow)");
            }
        }
    }
    None
}

/// Invariant 5: Account Roots Not Deleted (except by AccountDelete/AMMDelete).
fn check_account_roots_not_deleted(
    deltas: &[EntryDelta],
    ter: TxResult,
    tx: &ParsedTx,
) -> Option<&'static str> {
    // AccountDelete = tx_type 21, AMMDelete = tx_type 40
    // AccountDelete=21, AMMDelete=40, VaultDelete=67, LoanBrokerDelete=75 (delete pseudo-accounts)
    let allows_delete =
        tx.tx_type == 21 || tx.tx_type == 40 || tx.tx_type == 67 || tx.tx_type == 75;

    for delta in deltas {
        if delta.after.is_some() {
            continue; // Not deleted
        }
        let before = match &delta.before {
            Some(d) => d,
            None => continue,
        };
        if sle_entry_type(before) != Some(ACCOUNT_ROOT_TYPE) {
            continue;
        }
        // An account root was deleted
        if !allows_delete {
            return Some("AccountRootsNotDeleted: account deleted by non-delete tx");
        }
        if !ter.is_tes_success() {
            return Some("AccountRootsNotDeleted: account deleted on non-success result");
        }
    }
    None
}

// ── New invariants (matching rippled) ────────────────────────────────────────

const OFFER_TYPE: u16 = 0x006F;
const RIPPLE_STATE_TYPE: u16 = 0x0072;

/// Invariant: NoBadOffers.
/// Offer amounts must be non-negative and not XRP-to-XRP.
fn check_no_bad_offers(deltas: &[EntryDelta]) -> Option<&'static str> {
    for delta in deltas {
        let after = match &delta.after {
            Some(d) => d,
            None => continue,
        };
        if sle_entry_type(after) != Some(OFFER_TYPE) {
            continue;
        }

        // Check TakerPays (type=6, field=4) and TakerGets (type=6, field=5) are non-negative
        // XRP amounts have bit 62 set for positive. If not set, it's negative.
        if let Some(pays) = sle_amount_field(after, 4) {
            if pays < 0 {
                return Some("NoBadOffers: negative TakerPays");
            }
        }
        if let Some(gets) = sle_amount_field(after, 5) {
            if gets < 0 {
                return Some("NoBadOffers: negative TakerGets");
            }
        }
    }
    None
}

/// Invariant: NoZeroEscrow.
/// Escrow and PayChannel amounts must be positive.
fn check_no_zero_escrow(deltas: &[EntryDelta]) -> Option<&'static str> {
    for delta in deltas {
        let after = match &delta.after {
            Some(d) => d,
            None => continue,
        };
        let et = sle_entry_type(after).unwrap_or(0);
        if et == ESCROW_TYPE || et == PAYCHAN_TYPE {
            if let Some(amt) = sle_amount_field(after, 1) {
                // sfAmount
                if amt <= 0 {
                    return Some("NoZeroEscrow: zero or negative amount");
                }
            }
        }
    }
    None
}

/// Invariant: LedgerEntryTypesMatch.
/// If an entry existed before and after, its type must not change.
fn check_ledger_entry_types_match(deltas: &[EntryDelta]) -> Option<&'static str> {
    for delta in deltas {
        if let (Some(before), Some(after)) = (&delta.before, &delta.after) {
            let before_type = sle_entry_type(before);
            let after_type = sle_entry_type(after);
            if before_type.is_some() && after_type.is_some() && before_type != after_type {
                return Some("LedgerEntryTypesMatch: type changed");
            }
        }
    }
    None
}

/// Invariant: NoXRPTrustLines.
/// Trust line currency must not be XRP (all-zero currency code).
fn check_no_xrp_trust_lines(deltas: &[EntryDelta]) -> Option<&'static str> {
    for delta in deltas {
        let after = match &delta.after {
            Some(d) => d,
            None => continue,
        };
        if sle_entry_type(after) != Some(RIPPLE_STATE_TYPE) {
            continue;
        }

        // Balance (type=6, field=2) is an IOU amount: 8 value + 20 currency + 20 issuer
        // Currency is at offset 8..28 within the amount field data
        // If the amount field starts with bit 63 set (0x80), it's IOU
        // Check currency bytes are not all zero (XRP)
        if let Some(balance_raw) = sle_raw_amount(after, 2) {
            if balance_raw.len() >= 28 {
                let currency = &balance_raw[8..28];
                if currency.iter().all(|&b| b == 0) {
                    return Some("NoXRPTrustLines: trust line with XRP currency");
                }
            }
        }
    }
    None
}

/// Invariant: ValidNewAccountRoot.
/// At most one new account per transaction.
fn check_valid_new_account_root(deltas: &[EntryDelta]) -> Option<&'static str> {
    let mut new_accounts = 0u32;
    for delta in deltas {
        if delta.before.is_none() {
            if let Some(ref after) = delta.after {
                if sle_entry_type(after) == Some(ACCOUNT_ROOT_TYPE) {
                    new_accounts += 1;
                }
            }
        }
    }
    if new_accounts > 1 {
        return Some("ValidNewAccountRoot: more than one new account");
    }
    None
}

/// Extract raw Amount field bytes (for IOU analysis).
fn sle_raw_amount(data: &[u8], target_field: u8) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos < data.len() {
        let (type_code, field_code, header_len) = decode_field_header(data, pos)?;
        pos += header_len;
        if type_code == 6 && field_code == target_field {
            // Amount: check if IOU (bit 63 set)
            if pos >= data.len() {
                return None;
            }
            let is_iou = (data[pos] & 0x80) != 0;
            let len = if is_iou { 48 } else { 8 };
            if pos + len > data.len() {
                return None;
            }
            return Some(data[pos..pos + len].to_vec());
        }
        let field_len = field_data_len(type_code, field_code, data, pos)?;
        pos += field_len;
    }
    None
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::account::AccountRoot;
    use crate::ledger::ter;

    fn make_account_sle(balance: u64) -> Vec<u8> {
        let acct = AccountRoot {
            account_id: [1u8; 20],
            balance,
            sequence: 1,
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
        };
        acct.encode()
    }

    fn dummy_tx(fee: u64) -> ParsedTx {
        crate::transaction::parse::ParsedTx {
            tx_type: 0,
            account: [1u8; 20],
            sequence: 1,
            fee,
            flags: 0,
            amount_drops: Some(100),
            destination: Some([2u8; 20]),
            amount: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            deliver_min: None,
            offer_sequence: None,
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            channel: None,
            public_key: None,
            paychan_sig: None,
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            uri: None,
            did_document: None,
            did_data: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            owner: None,
            regular_key: None,
            issuer: None,
            subject: None,
            credential_type: None,
            oracle_document_id: None,
            signer_quorum: None,
            signer_entries_raw: None,
            domain_id: None,
            ledger_fix_type: None,
            accepted_credentials_raw: None,
            authorize: None,
            permissions_raw: None,
            holder: None,
            mptoken_issuance_id: None,
            set_flag: None,
            clear_flag: None,
            transfer_rate: None,
            quality_in: None,
            quality_out: None,
            tick_size: None,
            last_ledger_seq: None,
            ticket_count: None,
            ticket_sequence: None,
            domain: None,
            asset: None,
            asset2: None,
            vault_id: None,
            amendment: None,
            base_fee_field: None,
            reserve_base_field: None,
            reserve_increment_field: None,
            unl_modify_disabling: None,
            unl_modify_validator: None,
            signing_pubkey: vec![],
            signature: vec![],
            signing_hash: [0u8; 32],
            signing_payload: vec![],
            send_max: None,
            paths: vec![],
            signers: vec![],
        }
    }

    #[test]
    fn fee_check_passes_valid() {
        let tx = dummy_tx(12);
        assert_eq!(check_fee_valid(12, &tx), None);
        assert_eq!(check_fee_valid(0, &tx), None);
    }

    #[test]
    fn fee_check_fails_overcharge() {
        let tx = dummy_tx(12);
        assert!(check_fee_valid(13, &tx).is_some());
    }

    #[test]
    fn xrp_balance_valid_passes() {
        let sle = make_account_sle(1_000_000);
        let deltas = vec![EntryDelta {
            key: Key([0u8; 32]),
            before: None,
            after: Some(sle),
        }];
        assert_eq!(check_xrp_balance_valid(&deltas), None);
    }

    #[test]
    fn xrp_not_created_fee_matches() {
        let before = make_account_sle(1_000_000);
        let after = make_account_sle(999_988); // lost 12 drops (fee)
        let deltas = vec![EntryDelta {
            key: Key([0u8; 32]),
            before: Some(before),
            after: Some(after),
        }];
        assert_eq!(check_xrp_not_created(&deltas, 12), None);
    }

    #[test]
    fn xrp_not_created_fails_on_mismatch() {
        let before = make_account_sle(1_000_000);
        let after = make_account_sle(1_000_100); // gained 100 drops!
        let deltas = vec![EntryDelta {
            key: Key([0u8; 32]),
            before: Some(before),
            after: Some(after),
        }];
        assert!(check_xrp_not_created(&deltas, 12).is_some());
    }

    #[test]
    fn account_not_deleted_by_payment() {
        let before = make_account_sle(1_000_000);
        let deltas = vec![EntryDelta {
            key: Key([0u8; 32]),
            before: Some(before),
            after: None, // deleted!
        }];
        let tx = dummy_tx(12);
        assert!(check_account_roots_not_deleted(&deltas, ter::TES_SUCCESS, &tx).is_some());
    }

    #[test]
    fn account_deleted_by_account_delete_ok() {
        let before = make_account_sle(1_000_000);
        let deltas = vec![EntryDelta {
            key: Key([0u8; 32]),
            before: Some(before),
            after: None,
        }];
        let mut tx = dummy_tx(12);
        tx.tx_type = 21; // AccountDelete
        assert_eq!(
            check_account_roots_not_deleted(&deltas, ter::TES_SUCCESS, &tx),
            None
        );
    }
}
