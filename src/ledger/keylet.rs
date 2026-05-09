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
use crate::transaction::amount::Issue;

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
const SPACE_NFT_OFFER: [u8; 2] = [0x00, 0x71]; // 'q'
const SPACE_SKIP: [u8; 2] = [0x00, 0x73]; // 's' (ledger hashes)
const SPACE_AMENDMENTS: [u8; 2] = [0x00, 0x66]; // 'f'
const SPACE_FEES: [u8; 2] = [0x00, 0x65]; // 'e'
const SPACE_NEGATIVE_UNL: [u8; 2] = [0x00, 0x4E]; // 'N'
const SPACE_DID: [u8; 2] = [0x00, 0x49]; // 'I'
const SPACE_AMM: [u8; 2] = [0x00, 0x41]; // 'A'
const SPACE_ORACLE: [u8; 2] = [0x00, 0x52]; // 'R'
const SPACE_CREDENTIAL: [u8; 2] = [0x00, 0x44]; // 'D'
const SPACE_MPTOKEN: [u8; 2] = [0x00, 0x74]; // 't'
const SPACE_MPTOKEN_ISSUANCE: [u8; 2] = [0x00, 0x7E]; // '~'
const SPACE_DELEGATE: [u8; 2] = [0x00, 0x45]; // 'E'

const NFT_PAGE_MASK: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

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

/// NFTokenOffer keylet: SHA-512-half(0x0071 || account || sequence)
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

fn issue_parts(issue: &Issue) -> ([u8; 20], [u8; 20]) {
    match issue {
        Issue::Xrp => ([0u8; 20], [0u8; 20]),
        Issue::Iou { currency, issuer } => (*issuer, currency.code),
        Issue::Mpt(_) => ([0u8; 20], [0u8; 20]),
    }
}

/// AMM keylet: SHA-512-half(0x0041 || minIssue.account || minIssue.currency || maxIssue.account || maxIssue.currency)
pub fn amm(issue1: &Issue, issue2: &Issue) -> Keylet {
    if matches!(issue1, Issue::Mpt(_)) || matches!(issue2, Issue::Mpt(_)) {
        return amm_with_tagged_issues(issue1, issue2);
    }
    let (acct1, cur1) = issue_parts(issue1);
    let (acct2, cur2) = issue_parts(issue2);
    let (min_acct, min_cur, max_acct, max_cur) = match cur1.cmp(&cur2) {
        std::cmp::Ordering::Less => (acct1, cur1, acct2, cur2),
        std::cmp::Ordering::Greater => (acct2, cur2, acct1, cur1),
        std::cmp::Ordering::Equal => {
            if cur1 == [0u8; 20] || acct1 <= acct2 {
                (acct1, cur1, acct2, cur2)
            } else {
                (acct2, cur2, acct1, cur1)
            }
        }
    };

    let mut buf = Vec::with_capacity(82);
    buf.extend_from_slice(&SPACE_AMM);
    buf.extend_from_slice(&min_acct);
    buf.extend_from_slice(&min_cur);
    buf.extend_from_slice(&max_acct);
    buf.extend_from_slice(&max_cur);
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::AMM)
}

fn tagged_issue_bytes(issue: &Issue) -> Vec<u8> {
    let mut out = Vec::with_capacity(45);
    match issue {
        Issue::Xrp => out.push(0),
        Issue::Iou { currency, issuer } => {
            out.push(1);
            out.extend_from_slice(&currency.code);
            out.extend_from_slice(issuer);
        }
        Issue::Mpt(mptid) => {
            out.push(2);
            out.extend_from_slice(mptid);
        }
    }
    out
}

fn amm_with_tagged_issues(issue1: &Issue, issue2: &Issue) -> Keylet {
    let mut a = tagged_issue_bytes(issue1);
    let mut b = tagged_issue_bytes(issue2);
    if b < a {
        std::mem::swap(&mut a, &mut b);
    }
    let mut buf = Vec::with_capacity(2 + a.len() + b.len());
    buf.extend_from_slice(&SPACE_AMM);
    buf.extend_from_slice(&a);
    buf.extend_from_slice(&b);
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::AMM)
}

/// AMM keylet from an already-derived AMM object id.
pub fn amm_id(id: [u8; 32]) -> Keylet {
    Keylet::new(Key(id), LedgerEntryType::AMM)
}

/// Oracle keylet: SHA-512-half(0x0052 || account || OracleDocumentID)
pub fn oracle(account: &[u8; 20], document_id: u32) -> Keylet {
    let mut buf = Vec::with_capacity(26);
    buf.extend_from_slice(&SPACE_ORACLE);
    buf.extend_from_slice(account);
    buf.extend_from_slice(&document_id.to_be_bytes());
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::Oracle)
}

/// Credential keylet: SHA-512-half(0x0044 || subject || issuer || CredentialType)
pub fn credential(subject: &[u8; 20], issuer: &[u8; 20], credential_type: &[u8]) -> Keylet {
    let mut buf = Vec::with_capacity(42 + credential_type.len());
    buf.extend_from_slice(&SPACE_CREDENTIAL);
    buf.extend_from_slice(subject);
    buf.extend_from_slice(issuer);
    buf.extend_from_slice(credential_type);
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::Credential)
}

/// MPTokenIssuance keylet: SHA-512-half(0x007E || MPTID)
pub fn mpt_issuance(mptid: &[u8; 24]) -> Keylet {
    let mut buf = Vec::with_capacity(26);
    buf.extend_from_slice(&SPACE_MPTOKEN_ISSUANCE);
    buf.extend_from_slice(mptid);
    Keylet::new(
        Key(sha512_first_half(&buf)),
        LedgerEntryType::MPTokenIssuance,
    )
}

/// MPTokenIssuance keylet from issuer sequence and account.
pub fn mpt_issuance_from_seq(sequence: u32, issuer: &[u8; 20]) -> Keylet {
    let mut mptid = [0u8; 24];
    mptid[..4].copy_from_slice(&sequence.to_be_bytes());
    mptid[4..].copy_from_slice(issuer);
    mpt_issuance(&mptid)
}

/// MPToken keylet: SHA-512-half(0x0074 || issuance_key || holder)
pub fn mptoken_by_issuance_key(issuance_key: &[u8; 32], holder: &[u8; 20]) -> Keylet {
    let mut buf = Vec::with_capacity(54);
    buf.extend_from_slice(&SPACE_MPTOKEN);
    buf.extend_from_slice(issuance_key);
    buf.extend_from_slice(holder);
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::MPToken)
}

/// MPToken keylet from MPTID and holder.
pub fn mptoken(mptid: &[u8; 24], holder: &[u8; 20]) -> Keylet {
    let issuance = mpt_issuance(mptid);
    mptoken_by_issuance_key(&issuance.key.0, holder)
}

/// Delegate keylet: SHA-512-half(0x0045 || account || authorize)
pub fn delegate(account: &[u8; 20], authorize: &[u8; 20]) -> Keylet {
    let mut buf = Vec::with_capacity(42);
    buf.extend_from_slice(&SPACE_DELEGATE);
    buf.extend_from_slice(account);
    buf.extend_from_slice(authorize);
    Keylet::new(Key(sha512_first_half(&buf)), LedgerEntryType::Delegate)
}

/// Minimum NFTokenPage key for an owner.
pub fn nftpage_min(owner: &[u8; 20]) -> Keylet {
    let mut key = [0u8; 32];
    key[..20].copy_from_slice(owner);
    Keylet::new(Key(key), LedgerEntryType::NFTokenPage)
}

/// Maximum NFTokenPage key for an owner.
pub fn nftpage_max(owner: &[u8; 20]) -> Keylet {
    let mut key = NFT_PAGE_MASK;
    key[..20].copy_from_slice(owner);
    Keylet::new(Key(key), LedgerEntryType::NFTokenPage)
}

/// NFTokenPage keylet for a token under a page base.
pub fn nftpage(base: &Keylet, token: &[u8; 32]) -> Keylet {
    let mut key = base.key.0;
    for i in 20..32 {
        key[i] = (key[i] & !NFT_PAGE_MASK[i]) + (token[i] & NFT_PAGE_MASK[i]);
    }
    Keylet::new(Key(key), LedgerEntryType::NFTokenPage)
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

    #[test]
    fn amm_mpt_issue_does_not_collide_with_xrp_or_other_mpts() {
        let xrp_key = amm(
            &Issue::Xrp,
            &Issue::Iou {
                currency: crate::transaction::amount::Currency { code: [1u8; 20] },
                issuer: [2u8; 20],
            },
        );
        let mpt_key = amm(
            &Issue::Mpt([0u8; 24]),
            &Issue::Iou {
                currency: crate::transaction::amount::Currency { code: [1u8; 20] },
                issuer: [2u8; 20],
            },
        );
        let other_mpt_key = amm(
            &Issue::Mpt([3u8; 24]),
            &Issue::Iou {
                currency: crate::transaction::amount::Currency { code: [1u8; 20] },
                issuer: [2u8; 20],
            },
        );

        assert_ne!(mpt_key.key, xrp_key.key);
        assert_ne!(mpt_key.key, other_mpt_key.key);
    }
}
