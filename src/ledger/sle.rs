//! xLedgRS purpose: Sle support for XRPL ledger state and SHAMap logic.
//! Serialized Ledger Entry — the fundamental unit of XRPL ledger state.
//!
//! An SLE is a binary STObject with a 32-byte SHAMap key and a type tag.
//! All ledger state lives as SLEs in the SHAMap. Field access parses the
//! binary on demand — there are no typed structs at this layer.
//!
//! This matches rippled's STLedgerEntry which extends STObject.

use crate::ledger::meta::{
    decode_vl_length, encode_vl_length, is_vl_type, read_field_header, skip_field_raw,
    write_field_header,
};
use crate::ledger::Key;

// ── LedgerEntryType ─────────────────────────────────────────────────────────

/// Ledger entry type codes (from rippled's LedgerFormats.h / ledger_entries.macro).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LedgerEntryType {
    AccountRoot = 0x0061,
    DirectoryNode = 0x0064,
    RippleState = 0x0072,
    Offer = 0x006F,
    LedgerHashes = 0x0068,
    Amendments = 0x0066,
    FeeSettings = 0x0073,
    NegativeUNL = 0x004E,
    Escrow = 0x0075,
    PayChannel = 0x0078,
    Check = 0x0043,
    DepositPreauth = 0x0070,
    Ticket = 0x0054,
    SignerList = 0x0053,
    NFTokenPage = 0x0050,
    NFTokenOffer = 0x0037,
    AMM = 0x0079,
    DID = 0x0049,
    Oracle = 0x0080,
    MPToken = 0x007F,
    MPTokenIssuance = 0x007E,
    Bridge = 0x0069,
    XChainOwnedClaimID = 0x0071,
    XChainOwnedCreateAccountClaimID = 0x0074,
    Credential = 0x0081,
    PermissionedDomain = 0x0082,
    Delegate = 0x0083,
    Vault = 0x0084,
    LoanBroker = 0x0088,
    Loan = 0x0089,
}

impl LedgerEntryType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0061 => Some(Self::AccountRoot),
            0x0064 => Some(Self::DirectoryNode),
            0x0072 => Some(Self::RippleState),
            0x006F => Some(Self::Offer),
            0x0068 => Some(Self::LedgerHashes),
            0x0066 => Some(Self::Amendments),
            0x0073 => Some(Self::FeeSettings),
            0x004E => Some(Self::NegativeUNL),
            0x0075 => Some(Self::Escrow),
            0x0078 => Some(Self::PayChannel),
            0x0043 => Some(Self::Check),
            0x0070 => Some(Self::DepositPreauth),
            0x0054 => Some(Self::Ticket),
            0x0053 => Some(Self::SignerList),
            0x0050 => Some(Self::NFTokenPage),
            0x0037 => Some(Self::NFTokenOffer),
            0x0079 => Some(Self::AMM),
            0x0049 => Some(Self::DID),
            0x0080 => Some(Self::Oracle),
            0x007F => Some(Self::MPToken),
            0x007E => Some(Self::MPTokenIssuance),
            0x0069 => Some(Self::Bridge),
            0x0071 => Some(Self::XChainOwnedClaimID),
            0x0074 => Some(Self::XChainOwnedCreateAccountClaimID),
            0x0081 => Some(Self::Credential),
            0x0082 => Some(Self::PermissionedDomain),
            0x0083 => Some(Self::Delegate),
            0x0084 => Some(Self::Vault),
            0x0088 => Some(Self::LoanBroker),
            0x0089 => Some(Self::Loan),
            _ => None,
        }
    }
}

// ── SLE ─────────────────────────────────────────────────────────────────────

/// A Serialized Ledger Entry — binary STObject with a key and type tag.
///
/// This is the fundamental unit of ledger state. All state access goes through
/// SLE. Typed accessors (balance, sequence, etc.) parse fields on demand from
/// the binary representation.
#[derive(Clone, Debug)]
pub struct SLE {
    key: Key,
    entry_type: LedgerEntryType,
    /// Raw binary STObject data (the serialized fields).
    /// This is exactly what goes into the SHAMap leaf.
    data: Vec<u8>,
}

impl SLE {
    /// Create an SLE with a known key, type, and binary data.
    pub fn new(key: Key, entry_type: LedgerEntryType, data: Vec<u8>) -> Self {
        Self {
            key,
            entry_type,
            data,
        }
    }

    /// Parse an SLE from raw binary data, extracting the entry type from
    /// the sfLedgerEntryType field (type=1, field=1).
    pub fn from_raw(key: Key, data: Vec<u8>) -> Option<Self> {
        // sfLedgerEntryType is UINT16, header byte 0x11 (type=1, field=1)
        if data.len() >= 3 && data[0] == 0x11 {
            let code = u16::from_be_bytes([data[1], data[2]]);
            let entry_type = LedgerEntryType::from_u16(code)?;
            Some(Self {
                key,
                entry_type,
                data,
            })
        } else {
            // Try scanning for the field
            let mut pos = 0;
            while pos < data.len() {
                let (tc, fc, new_pos) = read_field_header(&data, pos);
                if tc == 0 && fc == 0 {
                    break;
                }
                if tc == 1 && fc == 1 {
                    // Found LedgerEntryType
                    if new_pos + 2 <= data.len() {
                        let code = u16::from_be_bytes([data[new_pos], data[new_pos + 1]]);
                        let entry_type = LedgerEntryType::from_u16(code)?;
                        return Some(Self {
                            key,
                            entry_type,
                            data,
                        });
                    }
                }
                pos = new_pos;
                pos = skip_field_raw(&data, pos, tc);
            }
            None
        }
    }

    pub fn key(&self) -> &Key {
        &self.key
    }
    pub fn entry_type(&self) -> LedgerEntryType {
        self.entry_type
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    // ── Generic field accessors ─────────────────────────────────────────

    /// Get a UInt32 field by (type_code, field_code).
    pub fn get_field_u32(&self, type_code: u16, field_code: u16) -> Option<u32> {
        let raw = self.find_field(type_code, field_code)?;
        if raw.len() >= 4 {
            Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
        } else {
            None
        }
    }

    /// Get a UInt64 field.
    pub fn get_field_u64(&self, type_code: u16, field_code: u16) -> Option<u64> {
        let raw = self.find_field(type_code, field_code)?;
        if raw.len() >= 8 {
            Some(u64::from_be_bytes(raw[..8].try_into().unwrap()))
        } else {
            None
        }
    }

    /// Get a UInt16 field.
    pub fn get_field_u16(&self, type_code: u16, field_code: u16) -> Option<u16> {
        let raw = self.find_field(type_code, field_code)?;
        if raw.len() >= 2 {
            Some(u16::from_be_bytes([raw[0], raw[1]]))
        } else {
            None
        }
    }

    /// Get a Hash256 field.
    pub fn get_field_h256(&self, type_code: u16, field_code: u16) -> Option<[u8; 32]> {
        let raw = self.find_field(type_code, field_code)?;
        if raw.len() >= 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&raw[..32]);
            Some(h)
        } else {
            None
        }
    }

    /// Get an AccountID field (VL-encoded, 20 bytes).
    pub fn get_field_account(&self, type_code: u16, field_code: u16) -> Option<[u8; 20]> {
        let raw = self.find_field(type_code, field_code)?;
        if raw.len() >= 20 {
            let mut a = [0u8; 20];
            a.copy_from_slice(&raw[..20]);
            Some(a)
        } else {
            None
        }
    }

    /// Get an XRP Amount field (8 bytes, top bit = positive).
    pub fn get_field_xrp_drops(&self, type_code: u16, field_code: u16) -> Option<u64> {
        let raw = self.find_field(type_code, field_code)?;
        if raw.len() >= 8 {
            let v = u64::from_be_bytes(raw[..8].try_into().unwrap());
            // XRP amount: bit 62 set = positive, bits 0-61 = drops
            Some(v & 0x3FFF_FFFF_FFFF_FFFF)
        } else {
            None
        }
    }

    /// Get a VL (variable-length blob) field.
    pub fn get_field_vl(&self, type_code: u16, field_code: u16) -> Option<Vec<u8>> {
        self.find_field(type_code, field_code).map(|v| v.to_vec())
    }

    // ── Generic field mutators ──────────────────────────────────────────

    /// Set a UInt32 field. Inserts if absent, replaces if present.
    pub fn set_field_u32(&mut self, type_code: u16, field_code: u16, value: u32) {
        self.set_field_raw(type_code, field_code, &value.to_be_bytes());
    }

    /// Set a UInt64 field.
    pub fn set_field_u64(&mut self, type_code: u16, field_code: u16, value: u64) {
        self.set_field_raw(type_code, field_code, &value.to_be_bytes());
    }

    /// Set a Hash256 field.
    pub fn set_field_h256(&mut self, type_code: u16, field_code: u16, value: &[u8; 32]) {
        self.set_field_raw(type_code, field_code, value);
    }

    /// Set an XRP Amount field (drops, positive).
    pub fn set_field_xrp_drops(&mut self, type_code: u16, field_code: u16, drops: u64) {
        let v = drops | 0x4000_0000_0000_0000; // set positive bit
        self.set_field_raw(type_code, field_code, &v.to_be_bytes());
    }

    /// Set an AccountID field (VL-encoded, 20 bytes).
    pub fn set_field_account(&mut self, type_code: u16, field_code: u16, account: &[u8; 20]) {
        // AccountID is VL type (type_code 8), stored as VL(20 bytes)
        self.set_field_raw(type_code, field_code, account);
    }

    /// Remove a field from the SLE.
    pub fn remove_field(&mut self, type_code: u16, field_code: u16) {
        let mut out = Vec::with_capacity(self.data.len());
        let mut pos = 0;
        while pos < self.data.len() {
            let field_start = pos;
            let (tc, fc, header_end) = read_field_header(&self.data, pos);
            if header_end > self.data.len() {
                break;
            }
            let data_end = skip_field_raw(&self.data, header_end, tc);
            if tc == type_code && fc == field_code {
                // Skip this field
            } else {
                out.extend_from_slice(&self.data[field_start..data_end]);
            }
            pos = data_end;
        }
        self.data = out;
    }

    // ── Convenience named accessors ─────────────────────────────────────

    /// sfFlags (UInt32, type=2, field=2). Returns 0 if absent.
    pub fn flags(&self) -> u32 {
        self.get_field_u32(2, 2).unwrap_or(0)
    }

    pub fn set_flags(&mut self, flags: u32) {
        self.set_field_u32(2, 2, flags);
    }

    /// sfSequence (UInt32, type=2, field=4).
    pub fn sequence(&self) -> Option<u32> {
        self.get_field_u32(2, 4)
    }

    pub fn set_sequence(&mut self, seq: u32) {
        self.set_field_u32(2, 4, seq);
    }

    /// sfBalance as XRP drops (Amount, type=6, field=2). For AccountRoot.
    pub fn balance_xrp(&self) -> Option<u64> {
        self.get_field_xrp_drops(6, 2)
    }

    pub fn set_balance_xrp(&mut self, drops: u64) {
        self.set_field_xrp_drops(6, 2, drops);
    }

    /// sfOwnerCount (UInt32, type=2, field=13).
    pub fn owner_count(&self) -> u32 {
        self.get_field_u32(2, 13).unwrap_or(0)
    }

    pub fn set_owner_count(&mut self, count: u32) {
        self.set_field_u32(2, 13, count);
    }

    /// sfAccount (AccountID, type=8, field=1).
    pub fn account_id(&self) -> Option<[u8; 20]> {
        self.get_field_account(8, 1)
    }

    /// sfPreviousTxnID (Hash256, type=5, field=5).
    pub fn previous_txn_id(&self) -> Option<[u8; 32]> {
        self.get_field_h256(5, 5)
    }

    pub fn set_previous_txn_id(&mut self, id: &[u8; 32]) {
        self.set_field_h256(5, 5, id);
    }

    /// sfPreviousTxnLgrSeq (UInt32, type=2, field=5).
    pub fn previous_txn_lgr_seq(&self) -> Option<u32> {
        self.get_field_u32(2, 5)
    }

    pub fn set_previous_txn_lgr_seq(&mut self, seq: u32) {
        self.set_field_u32(2, 5, seq);
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Public access to find a field's raw bytes. For non-VL types (like Amount),
    /// returns the inline data directly.
    pub fn find_field_raw(&self, type_code: u16, field_code: u16) -> Option<Vec<u8>> {
        self.find_field(type_code, field_code).map(|s| s.to_vec())
    }

    /// Find a field's data in the binary. Returns the raw bytes (no header, no VL prefix).
    fn find_field(&self, type_code: u16, field_code: u16) -> Option<&[u8]> {
        let mut pos = 0;
        while pos < self.data.len() {
            let (tc, fc, header_end) = read_field_header(&self.data, pos);
            if tc == 0 && fc == 0 {
                break;
            }
            if header_end > self.data.len() {
                break;
            }

            if tc == type_code && fc == field_code {
                // Found it — extract the data portion
                if is_vl_type(tc) {
                    let (vl_len, vl_bytes) = decode_vl_length(&self.data, header_end);
                    let start = header_end + vl_bytes;
                    let end = (start + vl_len).min(self.data.len());
                    return Some(&self.data[start..end]);
                } else {
                    let data_end = skip_field_raw(&self.data, header_end, tc);
                    return Some(&self.data[header_end..data_end]);
                }
            }

            // Skip this field
            let data_end = skip_field_raw(&self.data, header_end, tc);
            pos = data_end;
        }
        None
    }

    /// Set a field's raw data. Replaces if present, inserts in canonical order if absent.
    /// For VL types, the caller provides raw data (WITHOUT the VL length prefix).
    pub fn set_field_raw_pub(&mut self, type_code: u16, field_code: u16, value: &[u8]) {
        self.set_field_raw(type_code, field_code, value);
    }

    /// Internal: set a field's raw data.
    fn set_field_raw(&mut self, type_code: u16, field_code: u16, value: &[u8]) {
        let target_key = (type_code, field_code);
        let mut out = Vec::with_capacity(self.data.len() + value.len() + 4);
        let mut pos = 0;
        let mut inserted = false;

        while pos < self.data.len() {
            let field_start = pos;
            let (tc, fc, header_end) = read_field_header(&self.data, pos);
            if header_end > self.data.len() {
                break;
            }
            let data_end = skip_field_raw(&self.data, header_end, tc);
            let current_key = (tc, fc);

            // Insert new field before the first field with higher canonical order
            if !inserted && current_key > target_key {
                write_new_field(&mut out, type_code, field_code, value);
                inserted = true;
            }

            if current_key == target_key {
                // Replace this field
                write_new_field(&mut out, type_code, field_code, value);
                inserted = true;
            } else {
                // Keep original
                out.extend_from_slice(&self.data[field_start..data_end]);
            }

            pos = data_end;
        }

        // If not yet inserted, append at end
        if !inserted {
            write_new_field(&mut out, type_code, field_code, value);
        }

        self.data = out;
    }
}

/// Write a field header + data (with VL prefix if applicable).
fn write_new_field(out: &mut Vec<u8>, type_code: u16, field_code: u16, value: &[u8]) {
    write_field_header(out, type_code, field_code);
    if is_vl_type(type_code) {
        encode_vl_length(out, value.len());
    }
    out.extend_from_slice(value);
}

// ── Well-known field codes ──────────────────────────────────────────────────
// Naming: SF_<type_prefix>_<name> = (type_code, field_code)
// These can be used with the generic accessors: sle.get_field_u32(SF_SEQUENCE.0, SF_SEQUENCE.1)

/// sfLedgerEntryType (UInt16, 1, 1)
pub const SF_LEDGER_ENTRY_TYPE: (u16, u16) = (1, 1);
/// sfFlags (UInt32, 2, 2)
pub const SF_FLAGS: (u16, u16) = (2, 2);
/// sfSequence (UInt32, 2, 4)
pub const SF_SEQUENCE: (u16, u16) = (2, 4);
/// sfPreviousTxnLgrSeq (UInt32, 2, 5)
pub const SF_PREVIOUS_TXN_LGR_SEQ: (u16, u16) = (2, 5);
/// sfOwnerCount (UInt32, 2, 13)
pub const SF_OWNER_COUNT: (u16, u16) = (2, 13);
/// sfTransferRate (UInt32, 2, 11)
pub const SF_TRANSFER_RATE: (u16, u16) = (2, 11);
/// sfBalance (Amount, 6, 2)
pub const SF_BALANCE: (u16, u16) = (6, 2);
/// sfAmount (Amount, 6, 1)
pub const SF_AMOUNT: (u16, u16) = (6, 1);
/// sfPreviousTxnID (Hash256, 5, 5)
pub const SF_PREVIOUS_TXN_ID: (u16, u16) = (5, 5);
/// sfAccount (AccountID, 8, 1)
pub const SF_ACCOUNT: (u16, u16) = (8, 1);
/// sfDestination (AccountID, 8, 3)
pub const SF_DESTINATION: (u16, u16) = (8, 3);
/// sfOwner (AccountID, 8, 2)
pub const SF_OWNER: (u16, u16) = (8, 2);
/// sfRegularKey (AccountID, 8, 8)
pub const SF_REGULAR_KEY: (u16, u16) = (8, 8);
/// sfBookDirectory (Hash256, 5, 16)
pub const SF_BOOK_DIRECTORY: (u16, u16) = (5, 16);
/// sfBookNode (UInt64, 3, 3)
pub const SF_BOOK_NODE: (u16, u16) = (3, 3);
/// sfOwnerNode (UInt64, 3, 4)
pub const SF_OWNER_NODE: (u16, u16) = (3, 4);
/// sfRootIndex (Hash256, 5, 8)
pub const SF_ROOT_INDEX: (u16, u16) = (5, 8);
/// sfIndexes (Vector256, 19, 1)
pub const SF_INDEXES: (u16, u16) = (19, 1);
/// sfLowLimit (Amount, 6, 6)
pub const SF_LOW_LIMIT: (u16, u16) = (6, 6);
/// sfHighLimit (Amount, 6, 7)
pub const SF_HIGH_LIMIT: (u16, u16) = (6, 7);
/// sfTakerPays (Amount, 6, 4)
pub const SF_TAKER_PAYS: (u16, u16) = (6, 4);
/// sfTakerGets (Amount, 6, 5)
pub const SF_TAKER_GETS: (u16, u16) = (6, 5);
/// sfIndexNext (UInt64, 3, 1)
pub const SF_INDEX_NEXT: (u16, u16) = (3, 1);
/// sfIndexPrevious (UInt64, 3, 2)
pub const SF_INDEX_PREVIOUS: (u16, u16) = (3, 2);

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ACCOUNT_ID: [u8; 20] = [0xAA; 20];

    fn make_account_sle() -> SLE {
        // Build a minimal AccountRoot SLE:
        // LedgerEntryType=0x0061, Flags=0, Sequence=42, Balance=1000000 drops
        let mut data = Vec::new();
        // sfLedgerEntryType (1,1) = 0x11, value 0x0061
        data.extend_from_slice(&[0x11, 0x00, 0x61]);
        // sfFlags (2,2) = 0x22, value 0x00000000
        data.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
        // sfSequence (2,4) = 0x24, value 42
        data.extend_from_slice(&[0x24, 0x00, 0x00, 0x00, 0x2A]);
        // sfOwnerCount (2,13) = 0x2D, value 3
        data.extend_from_slice(&[0x2D, 0x00, 0x00, 0x00, 0x03]);
        // sfBalance (6,2) = 0x62, XRP 1000000 drops (positive)
        let drops: u64 = 1_000_000 | 0x4000_0000_0000_0000;
        data.push(0x62);
        data.extend_from_slice(&drops.to_be_bytes());
        // sfAccount (8,1) = 0x81, VL(20 bytes)
        data.push(0x81);
        data.push(20); // VL length
        data.extend_from_slice(&TEST_ACCOUNT_ID); // deterministic fixture account

        SLE::new(Key([0u8; 32]), LedgerEntryType::AccountRoot, data)
    }

    #[test]
    fn test_from_raw() {
        let sle = make_account_sle();
        let parsed = SLE::from_raw(Key([0u8; 32]), sle.data().to_vec()).unwrap();
        assert_eq!(parsed.entry_type(), LedgerEntryType::AccountRoot);
    }

    #[test]
    fn test_field_accessors() {
        let sle = make_account_sle();
        assert_eq!(sle.flags(), 0);
        assert_eq!(sle.sequence(), Some(42));
        assert_eq!(sle.owner_count(), 3);
        assert_eq!(sle.balance_xrp(), Some(1_000_000));
        assert_eq!(sle.account_id(), Some(TEST_ACCOUNT_ID));
    }

    #[test]
    fn test_set_field_replace() {
        let mut sle = make_account_sle();
        sle.set_sequence(100);
        assert_eq!(sle.sequence(), Some(100));
        // Other fields unchanged
        assert_eq!(sle.flags(), 0);
        assert_eq!(sle.owner_count(), 3);
        assert_eq!(sle.balance_xrp(), Some(1_000_000));
    }

    #[test]
    fn test_set_field_insert() {
        let mut sle = make_account_sle();
        // sfTransferRate (2, 11) doesn't exist yet
        assert_eq!(sle.get_field_u32(2, 11), None);
        sle.set_field_u32(2, 11, 1_200_000_000);
        assert_eq!(sle.get_field_u32(2, 11), Some(1_200_000_000));
        // Existing fields still work
        assert_eq!(sle.sequence(), Some(42));
    }

    #[test]
    fn test_remove_field() {
        let mut sle = make_account_sle();
        assert_eq!(sle.owner_count(), 3);
        sle.remove_field(2, 13); // sfOwnerCount
        assert_eq!(sle.get_field_u32(2, 13), None);
        // Other fields intact
        assert_eq!(sle.sequence(), Some(42));
    }

    #[test]
    fn test_set_balance() {
        let mut sle = make_account_sle();
        sle.set_balance_xrp(5_000_000);
        assert_eq!(sle.balance_xrp(), Some(5_000_000));
    }
}
