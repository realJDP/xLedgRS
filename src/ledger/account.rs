//! AccountRoot — the on-ledger state of a single XRPL account.
//!
//! AccountRoot objects are stored in the account-state SHAMap.  Each leaf's
//! key is `SHA-512-half(0x0061_u16_be || account_id_20_bytes)` and the value
//! is the STObject binary-encoded AccountRoot.
//!
//! # Binary format (XRPL STObject canonical encoding)
//!
//! Each field is prefixed by a one- or two-byte header encoding `(type, field)`:
//!   - Both < 16: single byte `(type << 4) | field`
//!   - type < 16, field >= 16: `type << 4`, then `field` as a second byte
//!
//! Type codes used here:
//!   UInt16 = 1, UInt32 = 2, Amount = 6, AccountID = 8
//!
//! XRP Amount encoding: 8 bytes, `0x4000000000000000 | drops_u64`.
//! AccountID is VL-prefixed: one byte length (0x14 = 20), then 20 bytes.

use serde::{Deserialize, Serialize};

use crate::crypto::sha512_first_half;
use crate::ledger::Key;

// ── AccountRoot flag constants ───────────────────────────────────────────────

pub const LSF_PASSWORD_SPENT: u32 = 0x00010000;
pub const LSF_REQUIRE_DEST_TAG: u32 = 0x00020000;
pub const LSF_REQUIRE_AUTH: u32 = 0x00040000;
pub const LSF_DISALLOW_XRP: u32 = 0x00080000;
pub const LSF_DISABLE_MASTER: u32 = 0x00100000;
pub const LSF_NO_FREEZE: u32 = 0x00200000;
pub const LSF_GLOBAL_FREEZE: u32 = 0x00400000;
pub const LSF_DEFAULT_RIPPLE: u32 = 0x00800000;
pub const LSF_DEPOSIT_AUTH: u32 = 0x01000000;

/// Namespace prefix for AccountRoot keys in the SHAMap.
/// `0x0061` == ASCII 'a' in a u16.
const ACCOUNT_SPACE: [u8; 2] = [0x00, 0x61];

/// Compute the SHAMap key for an AccountRoot.
pub fn shamap_key(account_id: &[u8; 20]) -> Key {
    let mut data = [0u8; 22];
    data[..2].copy_from_slice(&ACCOUNT_SPACE);
    data[2..].copy_from_slice(account_id);
    Key(sha512_first_half(&data))
}

// ── AccountRoot ───────────────────────────────────────────────────────────────

/// XRPL `AccountRoot` fields used by `account_info`.
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct AccountRoot {
    /// 20-byte AccountID = RIPEMD160(SHA256(pubkey)).
    pub account_id: [u8; 20],
    /// Balance in drops (1 XRP = 1_000_000 drops).
    pub balance: u64,
    /// Transaction sequence number (starts at 1 for new accounts).
    pub sequence: u32,
    /// Number of owned objects (trust lines, offers, etc.).
    pub owner_count: u32,
    /// Account flags bitmask.
    pub flags: u32,
    /// Optional regular key — a secondary AccountID authorized to sign transactions.
    pub regular_key: Option<[u8; 20]>,
    /// Total NFTs minted by this account (monotonically increasing).
    #[serde(default)]
    pub minted_nftokens: u32,
    /// Total NFTs burned by this account.
    #[serde(default)]
    pub burned_nftokens: u32,
    /// Transfer rate (0 = no rate).
    #[serde(default)]
    pub transfer_rate: u32,
    /// Domain (empty = none).
    #[serde(default)]
    pub domain: Vec<u8>,
    /// Tick size (0 = not set).
    #[serde(default)]
    pub tick_size: u8,
    /// Ticket count (0 = none).
    #[serde(default)]
    pub ticket_count: u32,
    /// PreviousTxnID — hash of the last transaction that modified this object.
    #[serde(default)]
    pub previous_txn_id: [u8; 32],
    /// PreviousTxnLgrSeq — ledger index of the last transaction that modified this object.
    #[serde(default)]
    pub previous_txn_lgr_seq: u32,

    /// Original binary SLE data — preserved for round-trip safety.
    /// When present, `to_sle_binary()` patches this instead of using `encode()`,
    /// ensuring unknown/future fields are not dropped.
    #[serde(skip)]
    pub raw_sle: Option<Vec<u8>>,
}

/// PartialEq ignores raw_sle — it's round-trip metadata, not semantic content.
impl PartialEq for AccountRoot {
    fn eq(&self, other: &Self) -> bool {
        self.account_id == other.account_id
            && self.balance == other.balance
            && self.sequence == other.sequence
            && self.owner_count == other.owner_count
            && self.flags == other.flags
            && self.regular_key == other.regular_key
            && self.minted_nftokens == other.minted_nftokens
            && self.burned_nftokens == other.burned_nftokens
            && self.transfer_rate == other.transfer_rate
            && self.domain == other.domain
            && self.tick_size == other.tick_size
            && self.ticket_count == other.ticket_count
            && self.previous_txn_id == other.previous_txn_id
            && self.previous_txn_lgr_seq == other.previous_txn_lgr_seq
    }
}

impl AccountRoot {
    /// Serialize to XRPL STObject binary format.
    ///
    /// Fields are written in canonical order (sorted by type then field).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);

        // Canonical order: sorted by (type_code, field_code)
        // Field codes verified against rippled sfields.macro

        // (1,1) sfLedgerEntryType = 0x11
        out.push(0x11);
        out.extend_from_slice(&0x0061u16.to_be_bytes());

        // (2,2) sfFlags = 0x22
        out.push(0x22);
        out.extend_from_slice(&self.flags.to_be_bytes());

        // (2,4) sfSequence = 0x24
        out.push(0x24);
        out.extend_from_slice(&self.sequence.to_be_bytes());

        // (2,5) sfPreviousTxnLgrSeq = 0x25 (NOT 0x23 which is sfSourceTag)
        if self.previous_txn_lgr_seq > 0 {
            out.push(0x25);
            out.extend_from_slice(&self.previous_txn_lgr_seq.to_be_bytes());
        }

        // (2,11) sfTransferRate = 0x2B
        if self.transfer_rate > 0 {
            out.push(0x2B);
            out.extend_from_slice(&self.transfer_rate.to_be_bytes());
        }

        // (2,13) sfOwnerCount = 0x2D
        out.push(0x2D);
        out.extend_from_slice(&self.owner_count.to_be_bytes());

        // (2,40) sfTicketCount = extended (0x20, 40) (NOT 0x2F which is field 15)
        if self.ticket_count > 0 {
            out.push(0x20);
            out.push(40);
            out.extend_from_slice(&self.ticket_count.to_be_bytes());
        }

        // (2,43) sfMintedNFTokens = extended (0x20, 43)
        if self.minted_nftokens > 0 {
            out.push(0x20);
            out.push(43);
            out.extend_from_slice(&self.minted_nftokens.to_be_bytes());
        }

        // (2,44) sfBurnedNFTokens = extended (0x20, 44)
        if self.burned_nftokens > 0 {
            out.push(0x20);
            out.push(44);
            out.extend_from_slice(&self.burned_nftokens.to_be_bytes());
        }

        // (5,5) sfPreviousTxnID = 0x55 (NOT 0x52 which is sfParentHash field=2)
        if self.previous_txn_id != [0u8; 32] {
            out.push(0x55);
            out.extend_from_slice(&self.previous_txn_id);
        }

        // (6,2) sfBalance = 0x62
        out.push(0x62);
        out.extend_from_slice(&(0x4000_0000_0000_0000u64 | self.balance).to_be_bytes());

        // (7,7) sfDomain = 0x77
        if !self.domain.is_empty() {
            out.push(0x77);
            out.push(self.domain.len() as u8);
            out.extend_from_slice(&self.domain);
        }

        // (8,1) sfAccount = 0x81, VL(20) = 0x14
        out.push(0x81);
        out.push(0x14);
        out.extend_from_slice(&self.account_id);

        // (8,8) sfRegularKey = 0x88, VL(20) = 0x14
        if let Some(ref rk) = self.regular_key {
            out.push(0x88);
            out.push(0x14);
            out.extend_from_slice(rk);
        }

        // TickSize is UInt8 field 8; type code 16 uses extended type encoding.
        if self.tick_size > 0 {
            out.push(0x08); // field=8, type extended
            out.push(16); // type=16 (UInt8)
            out.push(self.tick_size);
        }

        out
    }

    /// Produce the binary SLE for this AccountRoot.
    ///
    /// If `raw_sle` is present (account was decoded from an existing binary),
    /// patches the original binary with any changed fields. This preserves
    /// unknown/future fields that the struct doesn't model.
    ///
    /// If `raw_sle` is None (new account), falls back to `encode()`.
    pub fn to_sle_binary(&self) -> Vec<u8> {
        let raw = match &self.raw_sle {
            Some(r) => r,
            None => return self.encode(),
        };

        // Patch only the modeled fields from the SLE.
        let mut sle = crate::ledger::sle::SLE::new(
            shamap_key(&self.account_id),
            crate::ledger::sle::LedgerEntryType::AccountRoot,
            raw.clone(),
        );

        sle.set_flags(self.flags);
        sle.set_sequence(self.sequence);
        sle.set_owner_count(self.owner_count);
        sle.set_balance_xrp(self.balance);

        // PreviousTxnID / PreviousTxnLgrSeq
        if self.previous_txn_id != [0u8; 32] {
            sle.set_previous_txn_id(&self.previous_txn_id);
        }
        if self.previous_txn_lgr_seq > 0 {
            sle.set_previous_txn_lgr_seq(self.previous_txn_lgr_seq);
        }

        // TransferRate
        if self.transfer_rate > 0 {
            sle.set_field_u32(2, 11, self.transfer_rate);
        } else {
            sle.remove_field(2, 11);
        }

        // TicketCount
        if self.ticket_count > 0 {
            sle.set_field_u32(2, 40, self.ticket_count);
        } else {
            sle.remove_field(2, 40);
        }

        // MintedNFTokens
        if self.minted_nftokens > 0 {
            sle.set_field_u32(2, 43, self.minted_nftokens);
        } else {
            sle.remove_field(2, 43);
        }

        // BurnedNFTokens
        if self.burned_nftokens > 0 {
            sle.set_field_u32(2, 44, self.burned_nftokens);
        } else {
            sle.remove_field(2, 44);
        }

        // Domain (VL type=7, field=7)
        if !self.domain.is_empty() {
            sle.set_field_raw_pub(7, 7, &self.domain);
        } else {
            sle.remove_field(7, 7);
        }

        // RegularKey (AccountID type=8, field=8)
        if let Some(ref rk) = self.regular_key {
            sle.set_field_account(8, 8, rk);
        } else {
            sle.remove_field(8, 8);
        }

        // TickSize (UInt8 type=16, field=8)
        if self.tick_size > 0 {
            sle.set_field_raw_pub(16, 8, &[self.tick_size]);
        } else {
            sle.remove_field(16, 8);
        }

        sle.into_data()
    }

    /// Deserialize from XRPL STObject binary format.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut pos = 0;
        let mut account_id = None::<[u8; 20]>;
        let mut balance = None::<u64>;
        let mut sequence = None::<u32>;
        let mut owner_count = None::<u32>;
        let mut flags = None::<u32>;
        let mut regular_key = None::<[u8; 20]>;
        let mut minted_nftokens = 0u32;
        let mut burned_nftokens = 0u32;
        let mut transfer_rate = 0u32;
        let mut domain = Vec::new();
        let mut tick_size = 0u8;
        let mut ticket_count = 0u32;
        let mut previous_txn_id = [0u8; 32];
        let mut previous_txn_lgr_seq = 0u32;

        while pos < data.len() {
            let b = data[pos];
            pos += 1;

            // Decode field header
            let top = (b >> 4) as u16;
            let bot = (b & 0x0F) as u16;
            let (type_code, field_code) = if top == 0 && bot == 0 {
                // Both values use extended encoding. This encoder does not emit
                // that form, but the parser still skips it cleanly.
                if pos + 2 > data.len() {
                    break;
                }
                let t = data[pos] as u16;
                let f = data[pos + 1] as u16;
                pos += 2;
                (t, f)
            } else if top == 0 {
                // Type extended
                if pos >= data.len() {
                    break;
                }
                let t = data[pos] as u16;
                pos += 1;
                (t, bot)
            } else if bot == 0 {
                // Field extended
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
                    // `LedgerEntryType` (UInt16) can be skipped because the
                    // enclosing object is already known to be `AccountRoot`.
                    if pos + 2 > data.len() {
                        break;
                    }
                    pos += 2;
                }
                (2, 2) => {
                    // Flags (UInt32)
                    if pos + 4 > data.len() {
                        break;
                    }
                    flags = Some(u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()));
                    pos += 4;
                }
                (2, 4) => {
                    // Sequence (UInt32), sfSequence
                    if pos + 4 > data.len() {
                        break;
                    }
                    sequence = Some(u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()));
                    pos += 4;
                }
                (8, 8) => {
                    // RegularKey (AccountID), sfRegularKey = ACCOUNT field 8
                    if pos >= data.len() {
                        break;
                    }
                    let (vl_len, vl_bytes) =
                        crate::transaction::serialize::decode_length(&data[pos..]);
                    pos += vl_bytes;
                    if pos + vl_len > data.len() {
                        break;
                    }
                    if vl_len == 20 {
                        let mut id = [0u8; 20];
                        id.copy_from_slice(&data[pos..pos + 20]);
                        regular_key = Some(id);
                    }
                    pos += vl_len;
                }
                (6, 2) => {
                    // Balance (Amount — XRP), sfBalance = AMOUNT field 2
                    if pos + 8 > data.len() {
                        break;
                    }
                    let raw = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
                    // Mask off the positive-XRP and IOU-flag bits
                    balance = Some(raw & 0x3FFF_FFFF_FFFF_FFFFu64);
                    pos += 8;
                }
                (2, 13) => {
                    // OwnerCount (UInt32), sfOwnerCount = UINT32 field 13
                    if pos + 4 > data.len() {
                        break;
                    }
                    owner_count = Some(u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()));
                    pos += 4;
                }
                (8, 1) => {
                    // Account (AccountID, VL-encoded), sfAccount = ACCOUNT field 1
                    if pos >= data.len() {
                        break;
                    }
                    let vl = data[pos] as usize;
                    pos += 1;
                    if pos + vl > data.len() {
                        break;
                    }
                    if vl == 20 {
                        let mut id = [0u8; 20];
                        id.copy_from_slice(&data[pos..pos + 20]);
                        account_id = Some(id);
                    }
                    pos += vl;
                }
                (2, 43) => {
                    // MintedNFTokens (UInt32), sfMintedNFTokens
                    if pos + 4 > data.len() {
                        break;
                    }
                    minted_nftokens = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                }
                (2, 44) => {
                    // BurnedNFTokens (UInt32), sfBurnedNFTokens
                    if pos + 4 > data.len() {
                        break;
                    }
                    burned_nftokens = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                }
                (2, 11) => {
                    // TransferRate (UInt32)
                    if pos + 4 > data.len() {
                        break;
                    }
                    transfer_rate = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                }
                (2, 40) => {
                    // sfTicketCount (UInt32, field code 40, extended header 0x20 0x28)
                    if pos + 4 > data.len() {
                        break;
                    }
                    ticket_count = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                }
                (2, 5) => {
                    // PreviousTxnLgrSeq (UInt32)
                    if pos + 4 > data.len() {
                        break;
                    }
                    previous_txn_lgr_seq =
                        u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                }
                (5, 5) => {
                    // PreviousTxnID (Hash256)
                    if pos + 32 > data.len() {
                        break;
                    }
                    previous_txn_id.copy_from_slice(&data[pos..pos + 32]);
                    pos += 32;
                }
                (7, 7) => {
                    // Domain (Blob/VL)
                    if pos >= data.len() {
                        break;
                    }
                    let (vl_len, vl_bytes) =
                        crate::transaction::serialize::decode_length(&data[pos..]);
                    pos += vl_bytes;
                    if pos + vl_len > data.len() {
                        break;
                    }
                    domain = data[pos..pos + vl_len].to_vec();
                    pos += vl_len;
                }
                (16, 8) => {
                    // TickSize (UInt8)
                    if pos >= data.len() {
                        break;
                    }
                    tick_size = data[pos];
                    pos += 1;
                }
                // Skip unknown fields by type
                (1, _) => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    pos += 2;
                } // UInt16
                (2, _) => {
                    if pos + 4 > data.len() {
                        break;
                    }
                    pos += 4;
                } // UInt32
                (3, _) => {
                    if pos + 8 > data.len() {
                        break;
                    }
                    pos += 8;
                } // UInt64
                (4, _) => {
                    if pos + 16 > data.len() {
                        break;
                    }
                    pos += 16;
                } // Hash128
                (5, _) => {
                    if pos + 32 > data.len() {
                        break;
                    }
                    pos += 32;
                } // Hash256
                (6, _) => {
                    // Amount
                    if pos >= data.len() {
                        break;
                    }
                    if (data[pos] & 0x80) != 0 {
                        pos += 48; // IOU
                    } else if (data[pos] & 0x20) != 0 {
                        pos += 33; // MPT
                    } else {
                        pos += 8; // XRP
                    }
                }
                (7, _) | (8, _) | (19, _) => {
                    // VL types
                    if pos >= data.len() {
                        break;
                    }
                    let (vl_len, vl_bytes) =
                        crate::transaction::serialize::decode_length(&data[pos..]);
                    pos += vl_bytes + vl_len;
                }
                (16, _) => {
                    if pos >= data.len() {
                        break;
                    }
                    pos += 1;
                } // UInt8
                (17, _) => {
                    if pos + 20 > data.len() {
                        break;
                    }
                    pos += 20;
                } // Hash160
                _ => {
                    break;
                } // truly unknown
            }
        }

        Ok(AccountRoot {
            account_id: account_id.ok_or(DecodeError::MissingField("Account"))?,
            balance: balance.ok_or(DecodeError::MissingField("Balance"))?,
            sequence: sequence.ok_or(DecodeError::MissingField("Sequence"))?,
            owner_count: owner_count.unwrap_or(0),
            flags: flags.unwrap_or(0),
            regular_key,
            minted_nftokens,
            burned_nftokens,
            transfer_rate,
            domain,
            tick_size,
            ticket_count,
            previous_txn_id,
            previous_txn_lgr_seq,
            raw_sle: Some(data.to_vec()),
        })
    }
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis_account_id() -> [u8; 20] {
        // rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh — known genesis account
        let kp = crate::crypto::keys::Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb")
            .expect("genesis seed valid");
        crate::crypto::account_id(&kp.public_key_bytes())
    }

    fn genesis() -> AccountRoot {
        AccountRoot {
            account_id: genesis_account_id(),
            balance: 100_000_000_000_000_000,
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
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let orig = genesis();
        let bytes = orig.encode();
        let decoded = AccountRoot::decode(&bytes).expect("decode should succeed");
        assert_eq!(decoded, orig);
    }

    #[test]
    fn test_encode_starts_with_ledger_entry_type() {
        let bytes = genesis().encode();
        // First byte is field header for LedgerEntryType (type=1,field=1 → 0x11)
        assert_eq!(bytes[0], 0x11);
        // Next two bytes are 0x0061 (AccountRoot entry type)
        assert_eq!(&bytes[1..3], &[0x00, 0x61]);
    }

    #[test]
    fn test_balance_encoding_xrp_bit() {
        let acct = AccountRoot {
            account_id: [0u8; 20],
            balance: 1_000_000,
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
        let bytes = acct.encode();
        // Find the Balance field (0x62) and check the XRP positive bit is set
        let pos = bytes
            .iter()
            .position(|&b| b == 0x62)
            .expect("Balance field present");
        let raw = u64::from_be_bytes(bytes[pos + 1..pos + 9].try_into().unwrap());
        assert_ne!(
            raw & 0x4000_0000_0000_0000,
            0,
            "positive XRP bit must be set"
        );
        assert_eq!(raw & 0x3FFF_FFFF_FFFF_FFFF, 1_000_000);
    }

    #[test]
    fn test_shamap_key_is_deterministic() {
        let id = genesis_account_id();
        assert_eq!(shamap_key(&id), shamap_key(&id));
    }

    #[test]
    fn test_different_accounts_have_different_keys() {
        let mut id1 = [0u8; 20];
        let mut id2 = [0u8; 20];
        id1[0] = 1;
        id2[0] = 2;
        assert_ne!(shamap_key(&id1), shamap_key(&id2));
    }

    #[test]
    fn test_decode_missing_field_error() {
        // Encode with only LedgerEntryType and Flags — missing Balance, Sequence, Account
        let mut bytes = vec![];
        bytes.push(0x11);
        bytes.extend_from_slice(&0x0061u16.to_be_bytes());
        bytes.push(0x22);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        let err = AccountRoot::decode(&bytes);
        assert!(err.is_err());
    }
}
