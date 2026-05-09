//! Post-apply invariant checking — prevents invalid state from committing.
//!
//! Mirrors rippled's InvariantCheck system (InvariantCheck.cpp).
//! Each invariant visits all modified ledger entries (before/after pairs),
//! then performs a final check.  If any invariant fails, the transaction
//! is discarded and a fee-only reset is attempted.

use crate::ledger::ter::TxResult;
use crate::ledger::{Key, LedgerState};
use crate::transaction::amount::Amount;
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
    ledger_seq: u32,
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
    if let Some(reason) = check_canonical_sle_fields(&deltas) {
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
    if let Some(reason) = check_valid_new_account_root(&deltas, ter, tx, ledger_seq) {
        return InvariantResult::Failed(reason);
    }
    if let Some(reason) = check_valid_clawback(&deltas, ter, tx) {
        return InvariantResult::Failed(reason);
    }
    if let Some(reason) = check_valid_mpt_issuance(&deltas, ter, tx) {
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
/// - PayChannel: sfAmount - sfBalance — unclaimed locked channel XRP
fn sle_xrp_held(data: &[u8], entry_type: u16) -> i64 {
    if entry_type == PAYCHAN_TYPE {
        let amount = sle_amount_field(data, 1).unwrap_or(0);
        let balance = sle_amount_field(data, 2).unwrap_or(0);
        return amount - balance;
    }

    // Which Amount field holds the XRP for this entry type?
    let target_field = match entry_type {
        ACCOUNT_ROOT_TYPE => 2, // sfBalance
        ESCROW_TYPE => 1,       // sfAmount
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
            if (data[pos] & 0x80) != 0 || (data[pos] & 0x20) != 0 {
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
const MPTOKEN_ISSUANCE_TYPE: u16 = 0x007e;
const MPTOKEN_TYPE: u16 = 0x007f;

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
        for data in [delta.before.as_deref(), delta.after.as_deref()]
            .into_iter()
            .flatten()
        {
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
/// sfOwnerCount: type=2 (UInt32), field=13.
fn sle_owner_count(data: &[u8]) -> Option<u32> {
    let mut pos = 0;
    while pos < data.len() {
        let (type_code, field_code, header_len) = decode_field_header(data, pos)?;
        pos += header_len;
        if type_code == 2 && field_code == 13 {
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
    let must_delete_account = matches!(tx.tx_type, 21 | 40 | 67 | 75); // AccountDelete, AMMDelete, VaultDelete, LoanBrokerDelete
    let may_delete_account = matches!(tx.tx_type, 31 | 37); // AMMClawback, AMMWithdraw

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
        if !ter.is_tes_success() {
            return Some("AccountRootsNotDeleted: account deleted on non-success result");
        }
        if !(must_delete_account || may_delete_account) {
            return Some("AccountRootsNotDeleted: account deleted by non-delete tx");
        }
    }
    if must_delete_account && ter.is_tes_success() {
        let accounts_deleted = deltas
            .iter()
            .filter(|delta| {
                delta.after.is_none()
                    && delta.before.as_deref().and_then(sle_entry_type) == Some(ACCOUNT_ROOT_TYPE)
            })
            .count();
        if accounts_deleted != 1 {
            return Some("AccountRootsNotDeleted: successful delete tx deleted wrong count");
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
        for data in [delta.before.as_deref(), delta.after.as_deref()]
            .into_iter()
            .flatten()
        {
            if sle_entry_type(data) != Some(OFFER_TYPE) {
                continue;
            }

            let pays = sle_raw_amount(data, 4);
            let gets = sle_raw_amount(data, 5);
            if pays
                .as_deref()
                .and_then(amount_signum)
                .is_some_and(|sign| sign < 0)
            {
                return Some("NoBadOffers: negative TakerPays");
            }
            if gets
                .as_deref()
                .and_then(amount_signum)
                .is_some_and(|sign| sign < 0)
            {
                return Some("NoBadOffers: negative TakerGets");
            }
            if pays.as_deref().is_some_and(amount_is_native)
                && gets.as_deref().is_some_and(amount_is_native)
            {
                return Some("NoBadOffers: XRP to XRP offer");
            }
        }
    }
    None
}

/// Invariant: NoZeroEscrow.
/// Escrow and PayChannel amounts must be positive.
fn check_no_zero_escrow(deltas: &[EntryDelta]) -> Option<&'static str> {
    for delta in deltas {
        for data in [delta.before.as_deref(), delta.after.as_deref()]
            .into_iter()
            .flatten()
        {
            if sle_entry_type(data) == Some(ESCROW_TYPE) {
                if let Some(raw) = sle_raw_amount(data, 1) {
                    if amount_signum(&raw).is_some_and(|sign| sign <= 0) {
                        return Some("NoZeroEscrow: zero or negative amount");
                    }
                    if amount_is_native(&raw) {
                        if sle_amount_field(data, 1).is_some_and(|drops| drops >= MAX_XRP_DROPS) {
                            return Some("NoZeroEscrow: amount exceeds system limit");
                        }
                    }
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
        if let Some(after) = &delta.after {
            let Some(entry_type) = sle_entry_type(after) else {
                return Some("LedgerEntryTypesMatch: missing ledger entry type");
            };
            if !is_enabled_mainnet_ledger_type(entry_type) {
                return Some("LedgerEntryTypesMatch: invalid ledger entry type added");
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

        if sle_raw_amount(after, 6)
            .as_deref()
            .is_some_and(issue_is_xrp)
            || sle_raw_amount(after, 7)
                .as_deref()
                .is_some_and(issue_is_xrp)
        {
            return Some("NoXRPTrustLines: trust line with XRP currency");
        }
    }
    None
}

/// Invariant: ValidNewAccountRoot.
/// At most one new account per transaction, and only successful account-creating
/// transaction types may create one.
fn check_valid_new_account_root(
    deltas: &[EntryDelta],
    ter: TxResult,
    tx: &ParsedTx,
    ledger_seq: u32,
) -> Option<&'static str> {
    let mut new_accounts = 0u32;
    let mut new_account_seq = None;
    let mut new_account_is_pseudo = false;
    for delta in deltas {
        if delta.before.is_none() {
            if let Some(ref after) = delta.after {
                if sle_entry_type(after) == Some(ACCOUNT_ROOT_TYPE) {
                    new_accounts += 1;
                    new_account_seq = sle_u32_field(after, 4);
                    new_account_is_pseudo =
                        sle_has_field(after, 5, 14) || new_account_seq == Some(0);
                }
            }
        }
    }
    if new_accounts > 1 {
        return Some("ValidNewAccountRoot: more than one new account");
    }
    if new_accounts == 1 {
        if !ter.is_tes_success() {
            return Some("ValidNewAccountRoot: account created on non-success result");
        }
        let allowed = matches!(tx.tx_type, 0 | 35 | 65 | 74); // Payment, AMMCreate, VaultCreate, LoanBrokerSet
        if !allowed {
            return Some("ValidNewAccountRoot: account created illegally");
        }
        if new_account_is_pseudo {
            if !matches!(tx.tx_type, 35 | 65 | 74) {
                return Some("ValidNewAccountRoot: pseudo-account created illegally");
            }
            if new_account_seq != Some(0) {
                return Some("ValidNewAccountRoot: pseudo-account wrong sequence");
            }
        } else if tx.tx_type == 35 || new_account_seq != Some(ledger_seq.max(1)) {
            return Some("ValidNewAccountRoot: account wrong starting sequence");
        }
    }
    None
}

/// Invariant: ValidClawback.
/// A Clawback may affect at most one matching holder object, and failed
/// Clawbacks must not leave token-holder state changed.
fn check_valid_clawback(
    deltas: &[EntryDelta],
    ter: TxResult,
    tx: &ParsedTx,
) -> Option<&'static str> {
    if tx.tx_type != 30 {
        return None;
    }

    let mut trustlines_changed: Vec<&EntryDelta> = Vec::new();
    let mut mptokens_changed: Vec<&EntryDelta> = Vec::new();
    for delta in deltas {
        if delta.before == delta.after {
            continue;
        }
        if delta_touches_type(delta, RIPPLE_STATE_TYPE) {
            trustlines_changed.push(delta);
        }
        if delta_touches_type(delta, MPTOKEN_TYPE) {
            mptokens_changed.push(delta);
        }
    }

    if ter.is_tes_success() {
        if trustlines_changed.len() > 1 {
            return Some("ValidClawback: more than one trust line changed");
        }
        if mptokens_changed.len() > 1 {
            return Some("ValidClawback: more than one MPToken changed");
        }
        if trustlines_changed
            .iter()
            .any(|delta| delta.before.is_none())
        {
            return Some("ValidClawback: trust line created by clawback");
        }
        if mptokens_changed.iter().any(|delta| delta.before.is_none()) {
            return Some("ValidClawback: MPToken created by clawback");
        }

        match tx.amount.as_ref() {
            Some(Amount::Iou {
                currency,
                issuer: holder,
                ..
            }) => {
                if !mptokens_changed.is_empty() {
                    return Some("ValidClawback: MPToken changed for IOU clawback");
                }
                for delta in &trustlines_changed {
                    if !clawback_trustline_matches(delta, &tx.account, holder, &currency.code) {
                        return Some("ValidClawback: wrong trust line changed");
                    }
                    match clawback_holder_balance_non_negative(delta, holder) {
                        Some(true) => {}
                        Some(false) => {
                            return Some("ValidClawback: trust line holder balance is negative");
                        }
                        None => return Some("ValidClawback: malformed trust line changed"),
                    }
                }
            }
            Some(Amount::Mpt(_)) => {
                if !trustlines_changed.is_empty() {
                    return Some("ValidClawback: trust line changed for MPToken clawback");
                }
                let Some((_, mptid)) = tx.amount.as_ref().and_then(Amount::mpt_parts) else {
                    return Some("ValidClawback: malformed MPToken clawback amount");
                };
                let Some(holder) = tx.holder else {
                    return Some("ValidClawback: missing MPToken clawback holder");
                };
                for delta in &mptokens_changed {
                    if !clawback_mptoken_matches(delta, &holder, &mptid) {
                        return Some("ValidClawback: wrong MPToken changed");
                    }
                    if !clawback_mptoken_balance_decreased(delta) {
                        return Some("ValidClawback: MPToken holder balance increased");
                    }
                }
            }
            _ if !trustlines_changed.is_empty() || !mptokens_changed.is_empty() => {
                return Some("ValidClawback: holder object changed for malformed clawback");
            }
            _ => {}
        }
    } else {
        if !trustlines_changed.is_empty() {
            return Some("ValidClawback: trust line changed on failure");
        }
        if !mptokens_changed.is_empty() {
            return Some("ValidClawback: MPToken changed on failure");
        }
    }

    None
}

/// Invariant: ValidMPTIssuance.
///
/// Mirrors the active MPT object lifecycle checks from rippled for the local
/// transaction types implemented here. Clawback may adjust an existing holder
/// balance, but it must not create or delete MPToken ledger objects.
fn check_valid_mpt_issuance(
    deltas: &[EntryDelta],
    ter: TxResult,
    tx: &ParsedTx,
) -> Option<&'static str> {
    let mut issuances_created = 0u32;
    let mut issuances_deleted = 0u32;
    let mut mptokens_created = 0u32;
    let mut mptokens_deleted = 0u32;
    let mut mpt_created_by_issuer = false;

    for delta in deltas {
        match (
            delta.before.as_deref().and_then(sle_entry_type),
            delta.after.as_deref().and_then(sle_entry_type),
        ) {
            (None, Some(MPTOKEN_ISSUANCE_TYPE)) => issuances_created += 1,
            (Some(MPTOKEN_ISSUANCE_TYPE), None) => issuances_deleted += 1,
            (None, Some(MPTOKEN_TYPE)) => {
                mptokens_created += 1;
                if let Some(after) = delta.after.as_deref() {
                    if let (Some(account), Some(mptid)) =
                        (sle_account_field(after, 1), sle_uint192_field(after, 1))
                    {
                        if account == mpt_issuer_from_id(&mptid) {
                            mpt_created_by_issuer = true;
                        }
                    }
                }
            }
            (Some(MPTOKEN_TYPE), None) => mptokens_deleted += 1,
            _ => {}
        }
    }

    let any_mpt_lifecycle_change =
        issuances_created + issuances_deleted + mptokens_created + mptokens_deleted;

    if ter.is_tes_success() {
        if mpt_created_by_issuer {
            return Some("ValidMPTIssuance: MPToken created for issuer");
        }
        return match tx.tx_type {
            54 if issuances_created != 1 || issuances_deleted != 0 => {
                Some("ValidMPTIssuance: bad issuance create")
            }
            55 if issuances_created != 0 || issuances_deleted != 1 => {
                Some("ValidMPTIssuance: bad issuance destroy")
            }
            57 if issuances_created != 0 || issuances_deleted != 0 => {
                Some("ValidMPTIssuance: authorize changed issuance")
            }
            57 if tx.holder.is_some() && (mptokens_created != 0 || mptokens_deleted != 0) => {
                Some("ValidMPTIssuance: issuer authorize created or deleted MPToken")
            }
            57 if tx.holder.is_none() && mptokens_created + mptokens_deleted != 1 => {
                Some("ValidMPTIssuance: holder authorize changed wrong MPToken count")
            }
            30 if any_mpt_lifecycle_change != 0 => {
                Some("ValidMPTIssuance: clawback created or deleted MPT object")
            }
            _ => None,
        };
    }

    if any_mpt_lifecycle_change != 0 {
        return Some("ValidMPTIssuance: MPT object lifecycle changed on failure");
    }

    None
}

fn delta_touches_type(delta: &EntryDelta, entry_type: u16) -> bool {
    delta.before.as_deref().and_then(sle_entry_type) == Some(entry_type)
        || delta.after.as_deref().and_then(sle_entry_type) == Some(entry_type)
}

fn clawback_mptoken_matches(delta: &EntryDelta, holder: &[u8; 20], mptid: &[u8; 24]) -> bool {
    delta
        .after
        .as_deref()
        .or(delta.before.as_deref())
        .is_some_and(|data| {
            sle_entry_type(data) == Some(MPTOKEN_TYPE)
                && sle_account_field(data, 1).as_ref() == Some(holder)
                && sle_uint192_field(data, 1).as_ref() == Some(mptid)
        })
}

fn clawback_mptoken_balance_decreased(delta: &EntryDelta) -> bool {
    let Some(before) = delta.before.as_deref() else {
        return false;
    };
    let Some(after) = delta.after.as_deref() else {
        return false;
    };
    match (sle_u64_field(before, 26), sle_u64_field(after, 26)) {
        (Some(before_amount), Some(after_amount)) => after_amount < before_amount,
        _ => false,
    }
}

fn sle_account_field(data: &[u8], target_field_code: u16) -> Option<[u8; 20]> {
    crate::ledger::meta::parse_sle(data).and_then(|sle| {
        sle.fields.into_iter().find_map(|field| {
            (field.type_code == 8
                && field.field_code == target_field_code
                && field.data.len() == 20)
                .then(|| field.data.try_into().ok())
                .flatten()
        })
    })
}

fn sle_uint192_field(data: &[u8], target_field_code: u16) -> Option<[u8; 24]> {
    crate::ledger::meta::parse_sle(data).and_then(|sle| {
        sle.fields.into_iter().find_map(|field| {
            (field.type_code == 21
                && field.field_code == target_field_code
                && field.data.len() == 24)
                .then(|| field.data.try_into().ok())
                .flatten()
        })
    })
}

fn sle_u64_field(data: &[u8], target_field_code: u16) -> Option<u64> {
    crate::ledger::meta::parse_sle(data).and_then(|sle| {
        sle.fields.into_iter().find_map(|field| {
            (field.type_code == 3 && field.field_code == target_field_code && field.data.len() >= 8)
                .then(|| {
                    u64::from_be_bytes([
                        field.data[0],
                        field.data[1],
                        field.data[2],
                        field.data[3],
                        field.data[4],
                        field.data[5],
                        field.data[6],
                        field.data[7],
                    ])
                })
        })
    })
}

fn mpt_issuer_from_id(mptid: &[u8; 24]) -> [u8; 20] {
    let mut issuer = [0u8; 20];
    issuer.copy_from_slice(&mptid[4..24]);
    issuer
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustLineIdentity {
    low_account: [u8; 20],
    high_account: [u8; 20],
    currency: [u8; 20],
}

fn clawback_trustline_matches(
    delta: &EntryDelta,
    issuer: &[u8; 20],
    holder: &[u8; 20],
    currency: &[u8; 20],
) -> bool {
    let Some(identity) = delta
        .after
        .as_deref()
        .or(delta.before.as_deref())
        .and_then(sle_trustline_identity)
    else {
        return false;
    };

    identity.currency == *currency
        && ((identity.low_account == *issuer && identity.high_account == *holder)
            || (identity.low_account == *holder && identity.high_account == *issuer))
}

fn clawback_holder_balance_non_negative(delta: &EntryDelta, holder: &[u8; 20]) -> Option<bool> {
    let Some(after) = delta.after.as_deref() else {
        return Some(true);
    };

    let identity = sle_trustline_identity(after)?;
    let sign = sle_raw_amount(after, 2)
        .as_deref()
        .and_then(amount_signum)?;
    if *holder == identity.low_account {
        Some(sign >= 0)
    } else if *holder == identity.high_account {
        Some(sign <= 0)
    } else {
        None
    }
}

fn sle_trustline_identity(data: &[u8]) -> Option<TrustLineIdentity> {
    if sle_entry_type(data) != Some(RIPPLE_STATE_TYPE) {
        return None;
    }

    let low_limit = sle_raw_amount(data, 6)?;
    let high_limit = sle_raw_amount(data, 7)?;
    let currency_amount = sle_raw_amount(data, 2).or_else(|| Some(low_limit.clone()))?;

    Some(TrustLineIdentity {
        low_account: iou_amount_issuer(&low_limit)?,
        high_account: iou_amount_issuer(&high_limit)?,
        currency: iou_amount_currency(&currency_amount)?,
    })
}

fn iou_amount_currency(raw: &[u8]) -> Option<[u8; 20]> {
    if raw.len() != 48 {
        return None;
    }
    raw[8..28].try_into().ok()
}

fn iou_amount_issuer(raw: &[u8]) -> Option<[u8; 20]> {
    if raw.len() != 48 {
        return None;
    }
    raw[28..48].try_into().ok()
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
            let len = if (data[pos] & 0x80) != 0 {
                48
            } else if (data[pos] & 0x20) != 0 {
                33
            } else {
                8
            };
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

fn amount_is_native(raw: &[u8]) -> bool {
    raw.len() == 8 && (raw[0] & 0x80) == 0
}

fn amount_signum(raw: &[u8]) -> Option<i8> {
    if raw.len() < 8 {
        return None;
    }
    let raw64 = u64::from_be_bytes(raw[..8].try_into().ok()?);
    let value_bits = raw64 & 0x3FFF_FFFF_FFFF_FFFF;
    if value_bits == 0 {
        return Some(0);
    }
    if (raw64 >> 62) & 1 == 1 {
        Some(1)
    } else {
        Some(-1)
    }
}

fn issue_is_xrp(raw: &[u8]) -> bool {
    if amount_is_native(raw) {
        return true;
    }
    raw.len() >= 48 && raw[8..28].iter().all(|b| *b == 0) && raw[28..48].iter().all(|b| *b == 0)
}

fn sle_u32_field(data: &[u8], target_field_code: u8) -> Option<u32> {
    let mut pos = 0;
    while pos < data.len() {
        let (type_code, field_code, header_len) = decode_field_header(data, pos)?;
        pos += header_len;
        if type_code == 2 && field_code == target_field_code {
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

fn sle_has_field(data: &[u8], target_type_code: u8, target_field_code: u8) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        let Some((type_code, field_code, header_len)) = decode_field_header(data, pos) else {
            return false;
        };
        pos += header_len;
        if type_code == target_type_code && field_code == target_field_code {
            return true;
        }
        let Some(field_len) = field_data_len(type_code, field_code, data, pos) else {
            return false;
        };
        pos += field_len;
    }
    false
}

fn is_enabled_mainnet_ledger_type(entry_type: u16) -> bool {
    matches!(
        entry_type,
        0x0037 // NFTokenOffer
            | 0x0043 // Check
            | 0x0049 // DID
            | 0x004e // NegativeUNL
            | 0x0050 // NFTokenPage
            | 0x0053 // SignerList
            | 0x0054 // Ticket
            | 0x0061 // AccountRoot
            | 0x0064 // DirectoryNode
            | 0x0066 // Amendments
            | 0x0068 // LedgerHashes
            | 0x006f // Offer
            | 0x0070 // DepositPreauth
            | 0x0072 // RippleState
            | 0x0073 // FeeSettings
            | 0x0075 // Escrow
            | 0x0078 // PayChannel
            | 0x0079 // AMM
            | 0x007e // MPTokenIssuance
            | 0x007f // MPToken
            | 0x0080 // Oracle
            | 0x0081 // Credential
            | 0x0082 // PermissionedDomain
            | 0x0083 // Delegate
            | 0x0084 // Vault
            | 0x0088 // LoanBroker
            | 0x0089 // Loan
    )
}

fn valid_serialized_type(type_code: u16) -> bool {
    matches!(type_code, 1..=11 | 14..=26)
}

fn check_canonical_sle_fields(deltas: &[EntryDelta]) -> Option<&'static str> {
    for delta in deltas {
        for data in [delta.before.as_deref(), delta.after.as_deref()]
            .into_iter()
            .flatten()
        {
            let mut pos = 0;
            let mut previous_key: Option<(u16, u16)> = None;
            while pos < data.len() {
                let field_start = pos;
                let (type_code, field_code, data_start) =
                    crate::ledger::meta::read_field_header(data, pos);
                if data_start <= field_start || data_start > data.len() {
                    return Some("CanonicalFields: malformed field header");
                }
                if !valid_serialized_type(type_code) || field_code == 0 {
                    return Some("CanonicalFields: invalid field code");
                }
                if (type_code, field_code) == (14, 1) || (type_code, field_code) == (15, 1) {
                    return Some("CanonicalFields: unexpected end marker");
                }
                if previous_key.is_some_and(|prev| prev >= (type_code, field_code)) {
                    return Some("CanonicalFields: fields not strictly canonical");
                }
                let next = crate::ledger::meta::skip_field_raw(data, data_start, type_code);
                if next <= field_start || next > data.len() {
                    return Some("CanonicalFields: malformed field payload");
                }
                previous_key = Some((type_code, field_code));
                pos = next;
            }
        }
    }
    None
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::account::AccountRoot;
    use crate::ledger::ter;
    use crate::ledger::trustline::RippleState;
    use crate::transaction::amount::{Currency, IouValue};

    fn acct(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn make_account_sle(balance: u64) -> Vec<u8> {
        let acct = AccountRoot {
            account_id: [1u8; 20],
            balance,
            sequence: 1,
            owner_count: 0,
            flags: 0,
            regular_key: None,
            minted_nftokens: 0,
            first_nftoken_sequence: 0,
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

    fn make_paychan_sle(amount: u64, balance: u64) -> Vec<u8> {
        crate::ledger::PayChannel {
            account: [1u8; 20],
            destination: [2u8; 20],
            amount,
            balance,
            settle_delay: 60,
            public_key: vec![0x02; 33],
            sequence: 1,
            cancel_after: 0,
            expiration: 0,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        }
        .encode()
    }

    fn dummy_tx(fee: u64) -> ParsedTx {
        crate::transaction::parse::ParsedTx {
            tx_id: [0u8; 32],
            tx_type: 0,
            network_id: None,
            account: [1u8; 20],
            sequence: 1,
            fee,
            flags: 0,
            amount_drops: Some(100),
            destination: Some([2u8; 20]),
            destination_tag: None,
            amount: None,
            amount2: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            deliver_min: None,
            bid_min: None,
            bid_max: None,
            lp_token_out: None,
            lp_token_in: None,
            eprice: None,
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
            nftoken_broker_fee: None,
            uri: None,
            did_document: None,
            did_data: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            trading_fee: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            owner: None,
            regular_key: None,
            nftoken_minter: None,
            issuer: None,
            subject: None,
            credential_type: None,
            oracle_document_id: None,
            oracle_last_update_time: None,
            oracle_price_data_series_raw: None,
            signer_quorum: None,
            signer_entries_raw: None,
            domain_id: None,
            ledger_fix_type: None,
            accepted_credentials_raw: None,
            authorize: None,
            unauthorize: None,
            delegate: None,
            account_txn_id: None,
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
            email_hash: None,
            wallet_locator: None,
            message_key: None,
            asset: None,
            asset2: None,
            vault_id: None,
            loan_broker_id: None,
            loan_id: None,
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

    fn clawback_tx(issuer: [u8; 20], holder: [u8; 20], currency: Currency) -> ParsedTx {
        let mut tx = dummy_tx(12);
        tx.tx_type = 30;
        tx.account = issuer;
        tx.amount = Some(Amount::Iou {
            value: IouValue::from_f64(1.0),
            currency,
            issuer: holder,
        });
        tx
    }

    fn mpt_clawback_tx(issuer: [u8; 20], holder: [u8; 20], mptid: [u8; 24]) -> ParsedTx {
        let mut tx = dummy_tx(12);
        tx.tx_type = 30;
        tx.account = issuer;
        tx.amount = Some(Amount::from_mpt_value(1, mptid));
        tx.holder = Some(holder);
        tx
    }

    fn make_mptid(seq: u32, issuer: &[u8; 20]) -> [u8; 24] {
        let mut id = [0u8; 24];
        id[0..4].copy_from_slice(&seq.to_be_bytes());
        id[4..24].copy_from_slice(issuer);
        id
    }

    fn make_mptoken_sle(account: [u8; 20], mptid: [u8; 24], amount: u64) -> Vec<u8> {
        crate::ledger::meta::build_sle(
            MPTOKEN_TYPE,
            &[
                crate::ledger::meta::ParsedField {
                    type_code: 8,
                    field_code: 1,
                    data: account.to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 21,
                    field_code: 1,
                    data: mptid.to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 3,
                    field_code: 26,
                    data: amount.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 2,
                    field_code: 2,
                    data: 0u32.to_be_bytes().to_vec(),
                },
            ],
            None,
            None,
        )
    }

    fn make_trustline_sle(
        account_a: [u8; 20],
        account_b: [u8; 20],
        currency: Currency,
        balance: IouValue,
    ) -> Vec<u8> {
        let mut tl = RippleState::new(&account_a, &account_b, currency);
        tl.balance = balance;
        tl.low_limit = IouValue::from_f64(100.0);
        tl.high_limit = IouValue::from_f64(100.0);
        tl.encode()
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
    fn xrp_not_created_counts_paychan_unclaimed_balance() {
        let deltas = vec![
            EntryDelta {
                key: Key([0x01; 32]),
                before: Some(make_account_sle(10_000)),
                after: Some(make_account_sle(9_988)),
            },
            EntryDelta {
                key: Key([0x02; 32]),
                before: Some(make_account_sle(500)),
                after: Some(make_account_sle(600)),
            },
            EntryDelta {
                key: Key([0x03; 32]),
                before: Some(make_paychan_sle(1_000, 100)),
                after: Some(make_paychan_sle(1_000, 200)),
            },
        ];

        assert_eq!(check_xrp_not_created(&deltas, 12), None);
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

    #[test]
    fn valid_clawback_rejects_negative_holder_balance_after_iou() {
        let holder = acct(1);
        let issuer = acct(9);
        let usd = Currency::from_code("USD").unwrap();
        let before = make_trustline_sle(holder, issuer, usd.clone(), IouValue::from_f64(10.0));
        let after = make_trustline_sle(holder, issuer, usd.clone(), IouValue::from_f64(-1.0));
        let deltas = vec![EntryDelta {
            key: Key([0x72; 32]),
            before: Some(before),
            after: Some(after),
        }];
        let tx = clawback_tx(issuer, holder, usd);

        assert_eq!(
            check_valid_clawback(&deltas, ter::TES_SUCCESS, &tx),
            Some("ValidClawback: trust line holder balance is negative")
        );
    }

    #[test]
    fn valid_clawback_allows_deleted_target_trustline() {
        let holder = acct(1);
        let issuer = acct(9);
        let usd = Currency::from_code("USD").unwrap();
        let before = make_trustline_sle(holder, issuer, usd.clone(), IouValue::from_f64(10.0));
        let deltas = vec![EntryDelta {
            key: Key([0x72; 32]),
            before: Some(before),
            after: None,
        }];
        let tx = clawback_tx(issuer, holder, usd);

        assert_eq!(check_valid_clawback(&deltas, ter::TES_SUCCESS, &tx), None);
    }

    #[test]
    fn valid_clawback_rejects_wrong_trustline_mutation() {
        let holder = acct(1);
        let issuer = acct(9);
        let other_holder = acct(2);
        let other_issuer = acct(8);
        let usd = Currency::from_code("USD").unwrap();
        let before = make_trustline_sle(
            other_holder,
            other_issuer,
            usd.clone(),
            IouValue::from_f64(10.0),
        );
        let after = make_trustline_sle(
            other_holder,
            other_issuer,
            usd.clone(),
            IouValue::from_f64(9.0),
        );
        let deltas = vec![EntryDelta {
            key: Key([0x73; 32]),
            before: Some(before),
            after: Some(after),
        }];
        let tx = clawback_tx(issuer, holder, usd);

        assert_eq!(
            check_valid_clawback(&deltas, ter::TES_SUCCESS, &tx),
            Some("ValidClawback: wrong trust line changed")
        );
    }

    #[test]
    fn valid_clawback_rejects_trustline_created_on_success() {
        let holder = acct(1);
        let issuer = acct(9);
        let usd = Currency::from_code("USD").unwrap();
        let after = make_trustline_sle(holder, issuer, usd.clone(), IouValue::from_f64(10.0));
        let deltas = vec![EntryDelta {
            key: Key([0x75; 32]),
            before: None,
            after: Some(after),
        }];
        let tx = clawback_tx(issuer, holder, usd);

        assert_eq!(
            check_valid_clawback(&deltas, ter::TES_SUCCESS, &tx),
            Some("ValidClawback: trust line created by clawback")
        );
    }

    #[test]
    fn valid_clawback_rejects_trustline_created_on_failure() {
        let holder = acct(1);
        let issuer = acct(9);
        let usd = Currency::from_code("USD").unwrap();
        let after = make_trustline_sle(holder, issuer, usd.clone(), IouValue::from_f64(10.0));
        let deltas = vec![EntryDelta {
            key: Key([0x74; 32]),
            before: None,
            after: Some(after),
        }];
        let tx = clawback_tx(issuer, holder, usd);

        assert_eq!(
            check_valid_clawback(&deltas, ter::TEC_NO_LINE, &tx),
            Some("ValidClawback: trust line changed on failure")
        );
    }

    #[test]
    fn valid_clawback_rejects_wrong_mptoken_holder() {
        let holder = acct(1);
        let other_holder = acct(2);
        let issuer = acct(9);
        let mptid = make_mptid(1, &issuer);
        let before = make_mptoken_sle(other_holder, mptid, 10);
        let after = make_mptoken_sle(other_holder, mptid, 5);
        let deltas = vec![EntryDelta {
            key: Key([0x76; 32]),
            before: Some(before),
            after: Some(after),
        }];
        let tx = mpt_clawback_tx(issuer, holder, mptid);

        assert_eq!(
            check_valid_clawback(&deltas, ter::TES_SUCCESS, &tx),
            Some("ValidClawback: wrong MPToken changed")
        );
    }

    #[test]
    fn valid_mpt_issuance_rejects_clawback_mptoken_creation() {
        let holder = acct(1);
        let issuer = acct(9);
        let mptid = make_mptid(1, &issuer);
        let after = make_mptoken_sle(holder, mptid, 1);
        let deltas = vec![EntryDelta {
            key: Key([0x77; 32]),
            before: None,
            after: Some(after),
        }];
        let tx = mpt_clawback_tx(issuer, holder, mptid);

        assert_eq!(
            check_valid_mpt_issuance(&deltas, ter::TES_SUCCESS, &tx),
            Some("ValidMPTIssuance: clawback created or deleted MPT object")
        );
    }
}
