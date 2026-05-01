//! xLedgRS purpose: Keylet support for XRPL ledger state and SHAMap logic.
//! Keylet — type-safe SHAMap lookup key.
//!
//! A Keylet pairs a 32-byte SHAMap key with its expected LedgerEntryType.
//! This prevents accidentally reading an AccountRoot when you wanted an Offer.
//!
//! Constructor functions in the `keylet` module consolidate all the
//! `shamap_key()` functions that were scattered across the codebase.
//! Each computes SHA-512-half(namespace || params) and pairs it with
//! the correct LedgerEntryType.

use crate::crypto::sha512_first_half;
use crate::ledger::sle::{LedgerEntryType, SLE};
use crate::ledger::Key;

/// A type-safe lookup key: SHAMap key + expected entry type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Keylet {
    pub key: Key,
    pub entry_type: LedgerEntryType,
}

impl Keylet {
    pub fn new(key: Key, entry_type: LedgerEntryType) -> Self {
        Self { key, entry_type }
    }

    /// Check if an SLE matches this keylet (key AND type both match).
    pub fn check(&self, sle: &SLE) -> bool {
        *sle.key() == self.key && sle.entry_type() == self.entry_type
    }
}

// ── Namespace constants ─────────────────────────────────────────────────────
// These are the 2-byte prefixes used in rippled's Indexes.cpp / keylet:: namespace.

const SPACE_ACCOUNT: [u8; 2] = [0x00, 0x61]; // 'a'
const SPACE_DIR_NODE: [u8; 2] = [0x00, 0x64]; // 'd'
const SPACE_RIPPLE_STATE: [u8; 2] = [0x00, 0x72]; // 'r'
const SPACE_OFFER: [u8; 2] = [0x00, 0x6F]; // 'o'
const SPACE_OWNER_DIR: [u8; 2] = [0x00, 0x4F]; // 'O'
#[allow(dead_code)]
const SPACE_BOOK_DIR: [u8; 2] = [0x00, 0x42]; // 'B'
const SPACE_ESCROW: [u8; 2] = [0x00, 0x75]; // 'u'
const SPACE_CHECK: [u8; 2] = [0x00, 0x43]; // 'C'
const SPACE_DEPOSIT_PREAUTH: [u8; 2] = [0x00, 0x70]; // 'p'
const SPACE_TICKET: [u8; 2] = [0x00, 0x54]; // 'T'
const SPACE_SIGNER_LIST: [u8; 2] = [0x00, 0x53]; // 'S'
const SPACE_PAYCHAN: [u8; 2] = [0x00, 0x78]; // 'x'
const SPACE_NFT_OFFER: [u8; 2] = [0x00, 0x37]; // '7'
const SPACE_SKIP: [u8; 2] = [0x00, 0x73]; // 's' (ledger hashes)
const SPACE_AMENDMENTS: [u8; 2] = [0x00, 0x66]; // 'f'
const SPACE_FEES: [u8; 2] = [0x00, 0x65]; // 'e'
const SPACE_NEGATIVE_UNL: [u8; 2] = [0x00, 0x4E]; // 'N'
const SPACE_DID: [u8; 2] = [0x00, 0x49]; // 'I'
#[allow(dead_code)]
const SPACE_AMM: [u8; 2] = [0x00, 0x41]; // 'A'
#[allow(dead_code)]
const SPACE_ORACLE: [u8; 2] = [0x00, 0x52]; // 'R'
#[allow(dead_code)]
const SPACE_CREDENTIAL: [u8; 2] = [0x00, 0x44]; // 'D'
#[allow(dead_code)]
const SPACE_MPTOKEN: [u8; 2] = [0x00, 0x74]; // 't'
#[allow(dead_code)]
const SPACE_MPTOKEN_ISSUANCE: [u8; 2] = [0x00, 0x7E]; // '~'

// ── Keylet constructors ─────────────────────────────────────────────────────

/// AccountRoot keylet: SHA-512-half(0x0061 || account_id)
pub fn account(account_id: &[u8; 20]) -> Keylet {
    let mut buf = [0u8; 22];
    buf[..2].copy_from_slice(&SPACE_ACCOUNT);
    buf[2..].copy_from_slice(account_id);
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::AccountRoot)
}

/// Owner directory keylet: SHA-512-half(0x004F || account_id)
pub fn owner_dir(account_id: &[u8; 20]) -> Keylet {
    let mut buf = [0u8; 22];
    buf[..2].copy_from_slice(&SPACE_OWNER_DIR);
    buf[2..].copy_from_slice(account_id);
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::DirectoryNode)
}

/// Directory page keylet: SHA-512-half(0x0064 || root_key || page_index)
/// The root_key is the Hash256 of the directory root (from owner_dir or book_dir).
pub fn dir_page(root: &[u8; 32], page: u64) -> Keylet {
    if page == 0 {
        // Page 0 IS the root
        return Keylet::new(Key(*root), LedgerEntryType::DirectoryNode);
    }
    let mut buf = [0u8; 42]; // 2 + 32 + 8
    buf[..2].copy_from_slice(&SPACE_DIR_NODE);
    buf[2..34].copy_from_slice(root);
    buf[34..42].copy_from_slice(&page.to_be_bytes());
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::DirectoryNode)
}

/// Offer keylet: SHA-512-half(0x006F || account || sequence)
pub fn offer(account: &[u8; 20], sequence: u32) -> Keylet {
    let mut buf = [0u8; 26]; // 2 + 20 + 4
    buf[..2].copy_from_slice(&SPACE_OFFER);
    buf[2..22].copy_from_slice(account);
    buf[22..26].copy_from_slice(&sequence.to_be_bytes());
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::Offer)
}

/// RippleState (trust line) keylet: SHA-512-half(0x0072 || min(a,b) || max(a,b) || currency)
/// `currency` is the 20-byte currency code (Hash160).
pub fn trustline(account_a: &[u8; 20], account_b: &[u8; 20], currency: &[u8; 20]) -> Keylet {
    let (low, high) = if account_a < account_b {
        (account_a, account_b)
    } else {
        (account_b, account_a)
    };
    let mut buf = [0u8; 62]; // 2 + 20 + 20 + 20
    buf[..2].copy_from_slice(&SPACE_RIPPLE_STATE);
    buf[2..22].copy_from_slice(low);
    buf[22..42].copy_from_slice(high);
    buf[42..62].copy_from_slice(currency);
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::RippleState)
}

/// Escrow keylet: SHA-512-half(0x0075 || account || sequence)
pub fn escrow(account: &[u8; 20], sequence: u32) -> Keylet {
    let mut buf = [0u8; 26];
    buf[..2].copy_from_slice(&SPACE_ESCROW);
    buf[2..22].copy_from_slice(account);
    buf[22..26].copy_from_slice(&sequence.to_be_bytes());
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::Escrow)
}

/// Check keylet: SHA-512-half(0x0043 || account || sequence)
pub fn check(account: &[u8; 20], sequence: u32) -> Keylet {
    let mut buf = [0u8; 26];
    buf[..2].copy_from_slice(&SPACE_CHECK);
    buf[2..22].copy_from_slice(account);
    buf[22..26].copy_from_slice(&sequence.to_be_bytes());
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::Check)
}

/// PayChannel keylet: SHA-512-half(0x0078 || src || dst || sequence)
pub fn paychan(src: &[u8; 20], dst: &[u8; 20], sequence: u32) -> Keylet {
    let mut buf = [0u8; 46]; // 2 + 20 + 20 + 4
    buf[..2].copy_from_slice(&SPACE_PAYCHAN);
    buf[2..22].copy_from_slice(src);
    buf[22..42].copy_from_slice(dst);
    buf[42..46].copy_from_slice(&sequence.to_be_bytes());
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::PayChannel)
}

/// DepositPreauth keylet: SHA-512-half(0x0070 || owner || authorized)
pub fn deposit_preauth(owner: &[u8; 20], authorized: &[u8; 20]) -> Keylet {
    let mut buf = [0u8; 42]; // 2 + 20 + 20
    buf[..2].copy_from_slice(&SPACE_DEPOSIT_PREAUTH);
    buf[2..22].copy_from_slice(owner);
    buf[22..42].copy_from_slice(authorized);
    Keylet::new(
        Key(sha512_first_half(&buf)),
        LedgerEntryType::DepositPreauth,
    )
}

/// Ticket keylet: SHA-512-half(0x0054 || account || sequence)
pub fn ticket(account: &[u8; 20], sequence: u32) -> Keylet {
    let mut buf = [0u8; 26];
    buf[..2].copy_from_slice(&SPACE_TICKET);
    buf[2..22].copy_from_slice(account);
    buf[22..26].copy_from_slice(&sequence.to_be_bytes());
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::Ticket)
}

/// SignerList keylet: SHA-512-half(0x0053 || account || 0x00000000)
pub fn signer_list(account: &[u8; 20]) -> Keylet {
    let mut buf = [0u8; 26];
    buf[..2].copy_from_slice(&SPACE_SIGNER_LIST);
    buf[2..22].copy_from_slice(account);
    // signerListID = 0 (always, per rippled)
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::SignerList)
}

/// NFTokenOffer keylet: SHA-512-half(0x0037 || account || sequence)
pub fn nft_offer(account: &[u8; 20], sequence: u32) -> Keylet {
    let mut buf = [0u8; 26];
    buf[..2].copy_from_slice(&SPACE_NFT_OFFER);
    buf[2..22].copy_from_slice(account);
    buf[22..26].copy_from_slice(&sequence.to_be_bytes());
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::NFTokenOffer)
}

/// Fees singleton keylet: SHA-512-half(0x0065)
pub fn fees() -> Keylet {
    Keylet::new(
        Key(sha512_first_half(&SPACE_FEES)),
        LedgerEntryType::FeeSettings,
    )
}

/// Amendments singleton keylet: SHA-512-half(0x0066)
pub fn amendments() -> Keylet {
    Keylet::new(
        Key(sha512_first_half(&SPACE_AMENDMENTS)),
        LedgerEntryType::Amendments,
    )
}

/// NegativeUNL singleton keylet: SHA-512-half(0x004E)
pub fn negative_unl() -> Keylet {
    Keylet::new(
        Key(sha512_first_half(&SPACE_NEGATIVE_UNL)),
        LedgerEntryType::NegativeUNL,
    )
}

/// Short skip list (last 256 ledger hashes): SHA-512-half(0x0073)
/// Updated every ledger. Circular buffer of 256 parent hashes.
pub fn skip() -> Keylet {
    Keylet::new(
        Key(sha512_first_half(&SPACE_SKIP)),
        LedgerEntryType::LedgerHashes,
    )
}

/// Long skip list (flag ledger hashes): SHA-512-half(0x0073 || ledger_seq >> 16)
/// Created every 256 ledgers. Stores hashes for that 65536-ledger range.
pub fn skip_for_ledger(seq: u32) -> Keylet {
    let mut buf = [0u8; 6]; // 2 + 4
    buf[..2].copy_from_slice(&SPACE_SKIP);
    buf[2..6].copy_from_slice(&(seq >> 16).to_be_bytes());
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::LedgerHashes)
}

/// DID keylet: SHA-512-half(0x0049 || account)
pub fn did(account: &[u8; 20]) -> Keylet {
    let mut buf = [0u8; 22];
    buf[..2].copy_from_slice(&SPACE_DID);
    buf[2..].copy_from_slice(account);
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::DID)
}

/// Look up a keylet by its raw 32-byte key and entry type code.
/// Useful when you have the key from metadata but need a Keylet.
pub fn from_raw(key: [u8; 32], entry_type_code: u16) -> Option<Keylet> {
    let entry_type = LedgerEntryType::from_u16(entry_type_code)?;
    Some(Keylet::new(Key(key), entry_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_keylet_matches_existing() {
        // Compare with the existing account::shamap_key function
        let id = [0xAA; 20];
        let kl = account(&id);
        let existing = crate::ledger::account::shamap_key(&id);
        assert_eq!(kl.key, existing);
        assert_eq!(kl.entry_type, LedgerEntryType::AccountRoot);
    }

    #[test]
    fn test_keylet_check() {
        let id = [0xBB; 20];
        let kl = account(&id);
        let data = vec![0x11, 0x00, 0x61]; // LedgerEntryType = AccountRoot
        let sle = SLE::new(kl.key, LedgerEntryType::AccountRoot, data);
        assert!(kl.check(&sle));
    }

    #[test]
    fn test_fees_singleton() {
        let kl = fees();
        assert_eq!(kl.entry_type, LedgerEntryType::FeeSettings);
    }

    #[test]
    fn test_dir_page_zero_is_root() {
        let root = [0x42; 32];
        let kl = dir_page(&root, 0);
        assert_eq!(kl.key.0, root);
    }
}
