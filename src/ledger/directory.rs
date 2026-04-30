//! DirectoryNode — ownership tracking in the XRP Ledger state tree.
//!
//! Every account has an "owner directory" that lists all objects it owns
//! (offers, trust lines, checks, escrows, tickets, payment channels, etc.).
//! There are also "book directories" for the DEX order book.
//!
//! DirectoryNode SLE type = 0x0064 ('d').
//!
//! Key computation (from rippled Indexes.cpp):
//!   Owner dir root:  SHA-512-half(0x004F || AccountID)    namespace 'O' = 0x4F
//!   Dir page (>0):   SHA-512-half(0x0064 || root_key || page_u64_BE)  namespace 'd' = 0x64
//!   Book dir root:   SHA-512-half(0x0042 || pays_currency || gets_currency || pays_issuer || gets_issuer)
//!                    then the quality (u64 BE) is placed in the last 8 bytes
//!
//! Max entries per page: 32 (dirNodeMaxEntries in rippled Protocol.h).

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::crypto::sha512_first_half;
use crate::ledger::offer::BookKey;
use crate::ledger::Key;
use crate::transaction::amount::{Amount, IouValue};

/// Maximum entries per directory page (matches rippled's dirNodeMaxEntries).
pub const DIR_NODE_MAX_ENTRIES: usize = 32;

/// Namespace for owner directory root keys: 'O' = 0x4F.
const OWNER_DIR_SPACE: [u8; 2] = [0x00, 0x4F];

/// Namespace for directory page keys: 'd' = 0x64.
const DIR_NODE_SPACE: [u8; 2] = [0x00, 0x64];

/// Namespace for book directory root keys: 'B' = 0x42.
#[allow(dead_code)]
const BOOK_DIR_SPACE: [u8; 2] = [0x00, 0x42];

// ── Key computation ──────────────────────────────────────────────────────────

/// Compute the SHAMap key for an owner directory root.
/// `SHA-512-half(0x004F || account_id)`
pub fn owner_dir_key(account_id: &[u8; 20]) -> Key {
    let mut data = [0u8; 22];
    data[..2].copy_from_slice(&OWNER_DIR_SPACE);
    data[2..].copy_from_slice(account_id);
    Key(sha512_first_half(&data))
}

/// Compute the quality-0 root key for a book directory.
pub fn book_dir_root_key(book: &BookKey) -> Key {
    let mut data = [0u8; 82]; // 2 + 20 + 20 + 20 + 20
    data[..2].copy_from_slice(&BOOK_DIR_SPACE);
    data[2..22].copy_from_slice(&book.pays_currency);
    data[22..42].copy_from_slice(&book.gets_currency);
    data[42..62].copy_from_slice(&book.pays_issuer);
    data[62..82].copy_from_slice(&book.gets_issuer);
    let mut root = sha512_first_half(&data);
    root[24..32].copy_from_slice(&0u64.to_be_bytes());
    Key(root)
}

/// Compute the quality-specific book directory key (rippled keylet::quality).
pub fn book_dir_quality_key(book: &BookKey, quality: u64) -> Key {
    let mut root = book_dir_root_key(book).0;
    root[24..32].copy_from_slice(&quality.to_be_bytes());
    Key(root)
}

/// Compute rippled-style offer quality from (takerGets, takerPays).
pub fn offer_quality(offer_out: &Amount, offer_in: &Amount) -> u64 {
    if amount_is_zero(offer_out) {
        return 0;
    }
    let out = amount_as_iou_value(offer_out);
    let inn = amount_as_iou_value(offer_in);
    let mut rate = inn.div(&out);
    if rate.is_zero() {
        return 0;
    }
    rate.normalize();
    if !(matches!(rate.exponent, -100..=155)) {
        return 0;
    }
    let mantissa = rate.mantissa.unsigned_abs() & 0x00FF_FFFF_FFFF_FFFF;
    (((rate.exponent + 100) as u64) << 56) | mantissa
}

fn amount_as_iou_value(amount: &Amount) -> IouValue {
    match amount {
        Amount::Xrp(drops) => {
            let mut v = IouValue {
                mantissa: *drops as i64,
                exponent: 0,
            };
            v.normalize();
            v
        }
        Amount::Iou { value, .. } => *value,
        Amount::Mpt(_) => IouValue::ZERO,
    }
}

fn amount_is_zero(amount: &Amount) -> bool {
    match amount {
        Amount::Xrp(drops) => *drops == 0,
        Amount::Iou { value, .. } => value.is_zero(),
        Amount::Mpt(_) => true,
    }
}

pub(crate) fn load_directory_fresh(state: &LedgerState, key: &Key) -> Option<DirectoryNode> {
    state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))
        .and_then(|raw| DirectoryNode::decode(&raw, key.0).ok())
        .or_else(|| state.get_directory(key).cloned())
}

pub(crate) fn is_debug_directory_root(root: &[u8; 32]) -> bool {
    configured_debug_directory_root().is_some_and(|debug_root| debug_root == *root)
}

pub(crate) fn is_debug_directory_key(key: &Key) -> bool {
    is_debug_directory_root(&key.0)
}

pub(crate) fn directory_matches_debug_root(dir: &DirectoryNode) -> bool {
    is_debug_directory_root(&dir.root_index)
}

pub(crate) fn debug_directory_summary(dir: &DirectoryNode) -> String {
    format!(
        "dir_key={} root={} next={} prev={} indexes={} owner={} rate={}",
        hex::encode_upper(dir.key),
        hex::encode_upper(dir.root_index),
        dir.index_next,
        dir.index_previous,
        dir.indexes.len(),
        dir.owner
            .map(hex::encode_upper)
            .unwrap_or_else(|| "none".to_string()),
        dir.exchange_rate
            .map(|rate| rate.to_string())
            .unwrap_or_else(|| "none".to_string()),
    )
}

fn configured_debug_directory_root() -> Option<[u8; 32]> {
    let value = std::env::var("XLEDGRSV2BETA_DEBUG_DIRECTORY_ROOT").ok()?;
    let bytes = hex::decode(value.trim()).ok()?;
    bytes.try_into().ok()
}

/// Compute the SHAMap key for a directory page (page > 0).
/// `SHA-512-half(0x0064 || root_key || page_u64_BE)`
///
/// For page == 0, the key is the root_key itself.
pub fn page_key(root_key: &[u8; 32], page: u64) -> Key {
    if page == 0 {
        return Key(*root_key);
    }
    let mut data = [0u8; 42]; // 2 + 32 + 8
    data[..2].copy_from_slice(&DIR_NODE_SPACE);
    data[2..34].copy_from_slice(root_key);
    data[34..42].copy_from_slice(&page.to_be_bytes());
    Key(sha512_first_half(&data))
}

// ── DirectoryNode ────────────────────────────────────────────────────────────

/// A directory node SLE from the XRP Ledger state tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryNode {
    /// SHAMap key for this directory page.
    pub key: [u8; 32],
    /// Root index of this directory (same as key for root page).
    pub root_index: [u8; 32],
    /// Entries in this page -- up to 32 object keys.
    pub indexes: Vec<[u8; 32]>,
    /// Next page number (0 = no next page).
    pub index_next: u64,
    /// Previous page number (0 = no previous page).
    pub index_previous: u64,
    /// Owner account (for owner directories).
    pub owner: Option<[u8; 20]>,
    /// Exchange rate (for book directories).
    pub exchange_rate: Option<u64>,
    /// TakerPaysCurrency (for book directories).
    pub taker_pays_currency: Option<[u8; 20]>,
    /// TakerPaysIssuer (for book directories).
    pub taker_pays_issuer: Option<[u8; 20]>,
    /// TakerGetsCurrency (for book directories).
    pub taker_gets_currency: Option<[u8; 20]>,
    /// TakerGetsIssuer (for book directories).
    pub taker_gets_issuer: Option<[u8; 20]>,
    /// NFTokenID (optional, NFT directories).
    pub nftoken_id: Option<[u8; 32]>,
    /// DomainID (optional, permissioned domain directories).
    pub domain_id: Option<[u8; 32]>,
    /// PreviousTxnID (optional, present when amendment enabled).
    pub previous_txn_id: Option<[u8; 32]>,
    /// PreviousTxnLgrSeq (optional).
    pub previous_txn_lgr_seq: Option<u32>,
    /// Whether sfIndexNext was present in the original SLE (including when
    /// zero). Pre-existing directories set this during decode; newly-created
    /// directories leave it false. encode() uses this to decide whether to
    /// serialize IndexNext=0 (which rippled includes only when the field was
    /// previously set, not on freshly-created single-page directories).
    pub has_index_next: bool,
    /// Same for sfIndexPrevious.
    pub has_index_previous: bool,
    /// Original binary SLE data — preserved for round-trip safety.
    #[serde(skip)]
    pub raw_sle: Option<Vec<u8>>,
}

impl DirectoryNode {
    pub fn to_sle_binary(&self) -> Vec<u8> {
        let raw = match &self.raw_sle {
            Some(r) => r,
            None => return self.encode(),
        };

        let mut sle = crate::ledger::sle::SLE::new(
            crate::ledger::Key(self.key),
            crate::ledger::sle::LedgerEntryType::DirectoryNode,
            raw.clone(),
        );

        // Flags — directories always have flags=0
        sle.set_flags(0);

        // PreviousTxnID / PreviousTxnLgrSeq (optional)
        if let Some(ref txn_id) = self.previous_txn_id {
            sle.set_previous_txn_id(txn_id);
        }
        if let Some(seq) = self.previous_txn_lgr_seq {
            sle.set_previous_txn_lgr_seq(seq);
        }

        // IndexNext (UInt64, 3, 1) — include when non-zero OR when originally present
        if self.index_next != 0 || self.has_index_next {
            sle.set_field_u64(3, 1, self.index_next);
        } else {
            sle.remove_field(3, 1);
        }

        // IndexPrevious (UInt64, 3, 2)
        if self.index_previous != 0 || self.has_index_previous {
            sle.set_field_u64(3, 2, self.index_previous);
        } else {
            sle.remove_field(3, 2);
        }

        // ExchangeRate (UInt64, 3, 6) — book directories only
        if let Some(rate) = self.exchange_rate {
            sle.set_field_u64(3, 6, rate);
        }

        // RootIndex (Hash256, 5, 8)
        sle.set_field_h256(5, 8, &self.root_index);

        // NFTokenID (Hash256, 5, 10) — optional
        if let Some(ref nftoken_id) = self.nftoken_id {
            sle.set_field_h256(5, 10, nftoken_id);
        }

        // DomainID (Hash256, 5, 34) — optional
        if let Some(ref domain_id) = self.domain_id {
            sle.set_field_h256(5, 34, domain_id);
        }

        // Owner (AccountID, 8, 2) — optional, owner directories only
        if let Some(ref owner) = self.owner {
            sle.set_field_account(8, 2, owner);
        }

        // TakerPaysCurrency (UInt160, 17, 1)
        if let Some(ref v) = self.taker_pays_currency {
            sle.set_field_raw_pub(17, 1, v);
        }
        // TakerPaysIssuer (UInt160, 17, 2)
        if let Some(ref v) = self.taker_pays_issuer {
            sle.set_field_raw_pub(17, 2, v);
        }
        // TakerGetsCurrency (UInt160, 17, 3)
        if let Some(ref v) = self.taker_gets_currency {
            sle.set_field_raw_pub(17, 3, v);
        }
        // TakerGetsIssuer (UInt160, 17, 4)
        if let Some(ref v) = self.taker_gets_issuer {
            sle.set_field_raw_pub(17, 4, v);
        }

        // Indexes (Vector256, 19, 1) — sorted by hash
        let mut sorted_indexes = self.indexes.clone();
        sorted_indexes.sort();
        let mut idx_data = Vec::with_capacity(sorted_indexes.len() * 32);
        for idx in &sorted_indexes {
            idx_data.extend_from_slice(idx);
        }
        sle.set_field_raw_pub(19, 1, &idx_data);

        sle.into_data()
    }

    /// Create a new empty owner directory root.
    pub fn new_owner_root(owner: &[u8; 20]) -> Self {
        let k = owner_dir_key(owner);
        Self {
            key: k.0,
            root_index: k.0,
            indexes: Vec::new(),
            index_next: 0,
            index_previous: 0,
            owner: Some(*owner),
            exchange_rate: None,
            taker_pays_currency: None,
            taker_pays_issuer: None,
            taker_gets_currency: None,
            taker_gets_issuer: None,
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        }
    }

    /// Create a new directory page linked to a root.
    pub fn new_page(root_key: &[u8; 32], page: u64, owner: Option<[u8; 20]>) -> Self {
        let k = page_key(root_key, page);
        Self {
            key: k.0,
            root_index: *root_key,
            indexes: Vec::new(),
            index_next: 0,
            index_previous: 0,
            owner,
            exchange_rate: None,
            taker_pays_currency: None,
            taker_pays_issuer: None,
            taker_gets_currency: None,
            taker_gets_issuer: None,
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        }
    }

    /// Create a new empty book directory root/page.
    pub fn new_book_root(book: &BookKey, quality: u64) -> Self {
        let k = book_dir_quality_key(book, quality);
        Self {
            key: k.0,
            root_index: k.0,
            indexes: Vec::new(),
            index_next: 0,
            index_previous: 0,
            owner: None,
            exchange_rate: Some(quality),
            taker_pays_currency: Some(book.pays_currency),
            taker_pays_issuer: Some(book.pays_issuer),
            taker_gets_currency: Some(book.gets_currency),
            taker_gets_issuer: Some(book.gets_issuer),
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        }
    }

    /// Create a new book directory page linked to a quality root.
    pub fn new_book_page(root_key: &[u8; 32], page: u64, book: &BookKey, quality: u64) -> Self {
        let k = page_key(root_key, page);
        Self {
            key: k.0,
            root_index: *root_key,
            indexes: Vec::new(),
            index_next: 0,
            index_previous: 0,
            owner: None,
            exchange_rate: Some(quality),
            taker_pays_currency: Some(book.pays_currency),
            taker_pays_issuer: Some(book.pays_issuer),
            taker_gets_currency: Some(book.gets_currency),
            taker_gets_issuer: Some(book.gets_issuer),
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        }
    }

    /// Return this directory's SHAMap key.
    pub fn shamap_key(&self) -> Key {
        Key(self.key)
    }

    /// Serialize to XRPL STObject binary format (canonical field order).
    ///
    /// Fields are sorted by (type_code, field_code):
    ///   UInt16(1): LedgerEntryType(1)
    ///   UInt32(2): Flags(2), PreviousTxnLgrSeq(5)
    ///   UInt64(3): IndexNext(1), IndexPrevious(2), ExchangeRate(6)
    ///   Hash256(5): PreviousTxnID(5), RootIndex(8), NFTokenID(10), DomainID(34)
    ///   Account(8): Owner(2)
    ///   UInt160(17): TakerPaysCurrency(1), TakerPaysIssuer(2),
    ///                TakerGetsCurrency(3), TakerGetsIssuer(4)
    ///   Vector256(19): Indexes(1)
    pub fn encode(&self) -> Vec<u8> {
        // Invariant: book directories (exchange_rate set) must have all four
        // type-17 fields. Encoding without them produces bytes that diverge
        // from rippled and corrupt the state hash.
        debug_assert!(
            self.exchange_rate.is_none()
                || (self.taker_pays_currency.is_some()
                    && self.taker_pays_issuer.is_some()
                    && self.taker_gets_currency.is_some()
                    && self.taker_gets_issuer.is_some()),
            "book DirectoryNode missing type-17 fields: key={}",
            hex::encode_upper(self.key),
        );
        let mut out = Vec::with_capacity(64 + self.indexes.len() * 32);

        // type=1 (UInt16), field=1: LedgerEntryType = 0x0064
        out.push(0x11);
        out.extend_from_slice(&0x0064u16.to_be_bytes());

        // type=2 (UInt32), field=2: Flags = 0 (directories always have flags=0)
        out.push(0x22);
        out.extend_from_slice(&0u32.to_be_bytes());

        // type=2 (UInt32), field=5: PreviousTxnLgrSeq (optional)
        if let Some(seq) = self.previous_txn_lgr_seq {
            out.push(0x25);
            out.extend_from_slice(&seq.to_be_bytes());
        }

        // type=3 (UInt64), field=1: IndexNext — include when non-zero OR when
        // the original SLE had the field (has_index_next). Omit only for
        // newly-created single-page directories where it was never set.
        if self.index_next != 0 || self.has_index_next {
            out.push(0x31);
            out.extend_from_slice(&self.index_next.to_be_bytes());
        }

        // type=3 (UInt64), field=2: IndexPrevious — same convention.
        if self.index_previous != 0 || self.has_index_previous {
            out.push(0x32);
            out.extend_from_slice(&self.index_previous.to_be_bytes());
        }

        // type=3 (UInt64), field=6: ExchangeRate (optional, book dirs)
        if let Some(rate) = self.exchange_rate {
            out.push(0x36);
            out.extend_from_slice(&rate.to_be_bytes());
        }

        // type=5 (Hash256), field=5: PreviousTxnID (optional)
        if let Some(ref txn_id) = self.previous_txn_id {
            out.push(0x55);
            out.extend_from_slice(txn_id);
        }

        // type=5 (Hash256), field=8: RootIndex
        out.push(0x58);
        out.extend_from_slice(&self.root_index);

        // type=5 (Hash256), field=10: NFTokenID (optional)
        if let Some(ref nftoken_id) = self.nftoken_id {
            out.push(0x5A);
            out.extend_from_slice(nftoken_id);
        }

        // type=5 (Hash256), field=34: DomainID (optional, extended field id)
        if let Some(ref domain_id) = self.domain_id {
            out.push(0x50);
            out.push(34);
            out.extend_from_slice(domain_id);
        }

        // type=8 (Account), field=2: Owner (optional, VL-prefixed)
        if let Some(ref owner) = self.owner {
            out.push(0x82);
            out.push(0x14); // VL length = 20
            out.extend_from_slice(owner);
        }

        // type=17 (UInt160), field=1: TakerPaysCurrency (optional)
        // type >= 16, field < 16: first byte = field, second byte = type
        if let Some(ref v) = self.taker_pays_currency {
            out.push(0x01);
            out.push(17);
            out.extend_from_slice(v);
        }

        // type=17 (UInt160), field=2: TakerPaysIssuer
        if let Some(ref v) = self.taker_pays_issuer {
            out.push(0x02);
            out.push(17);
            out.extend_from_slice(v);
        }

        // type=17 (UInt160), field=3: TakerGetsCurrency
        if let Some(ref v) = self.taker_gets_currency {
            out.push(0x03);
            out.push(17);
            out.extend_from_slice(v);
        }

        // type=17 (UInt160), field=4: TakerGetsIssuer
        if let Some(ref v) = self.taker_gets_issuer {
            out.push(0x04);
            out.push(17);
            out.extend_from_slice(v);
        }

        // type=19 (Vector256), field=1: Indexes
        // VL-prefixed: length = count * 32. Entries sorted by 256-bit hash
        // to match rippled's canonical serialization (STVector256::sort at
        // STVector256.cpp:47 is called before serialization).
        let mut sorted_indexes = self.indexes.clone();
        sorted_indexes.sort();
        out.push(0x01);
        out.push(19);
        let vl_len = sorted_indexes.len() * 32;
        crate::transaction::serialize::encode_length(vl_len, &mut out);
        for idx in &sorted_indexes {
            out.extend_from_slice(idx);
        }

        out
    }

    /// Deserialize from XRPL STObject binary format.
    pub fn decode(data: &[u8], key: [u8; 32]) -> Result<Self, DirectoryDecodeError> {
        let mut pos = 0;
        let mut root_index = None::<[u8; 32]>;
        let mut indexes = Vec::new();
        let mut index_next = 0u64;
        let mut index_previous = 0u64;
        let mut has_index_next = false;
        let mut has_index_previous = false;
        let mut owner = None::<[u8; 20]>;
        let mut exchange_rate = None::<u64>;
        let mut taker_pays_currency = None::<[u8; 20]>;
        let mut taker_pays_issuer = None::<[u8; 20]>;
        let mut taker_gets_currency = None::<[u8; 20]>;
        let mut taker_gets_issuer = None::<[u8; 20]>;
        let mut nftoken_id = None::<[u8; 32]>;
        let mut domain_id = None::<[u8; 32]>;
        let mut previous_txn_id = None::<[u8; 32]>;
        let mut previous_txn_lgr_seq = None::<u32>;

        while pos < data.len() {
            let b = data[pos];
            pos += 1;

            // Decode field header
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
                // Type extended: bot = field, next byte = type
                if pos >= data.len() {
                    break;
                }
                let t = data[pos] as u16;
                pos += 1;
                (t, bot)
            } else if bot == 0 {
                // Field extended: top = type, next byte = field
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
                // UInt16(1), LedgerEntryType(1) — skip
                (1, 1) => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    pos += 2;
                }
                // UInt16 — skip any other
                (1, _) => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    pos += 2;
                }

                // UInt32(2), Flags(2) — skip (always 0 for directories)
                (2, 2) => {
                    if pos + 4 > data.len() {
                        break;
                    }
                    pos += 4;
                }
                // UInt32(2), PreviousTxnLgrSeq(5)
                (2, 5) => {
                    if pos + 4 > data.len() {
                        break;
                    }
                    previous_txn_lgr_seq =
                        Some(u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()));
                    pos += 4;
                }
                // UInt32 — skip any other
                (2, _) => {
                    if pos + 4 > data.len() {
                        break;
                    }
                    pos += 4;
                }

                // UInt64(3), IndexNext(1)
                (3, 1) => {
                    if pos + 8 > data.len() {
                        break;
                    }
                    index_next = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
                    has_index_next = true;
                    pos += 8;
                }
                // UInt64(3), IndexPrevious(2)
                (3, 2) => {
                    if pos + 8 > data.len() {
                        break;
                    }
                    index_previous = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
                    has_index_previous = true;
                    pos += 8;
                }
                // UInt64(3), ExchangeRate(6)
                (3, 6) => {
                    if pos + 8 > data.len() {
                        break;
                    }
                    exchange_rate =
                        Some(u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap()));
                    pos += 8;
                }
                // UInt64 — skip any other
                (3, _) => {
                    if pos + 8 > data.len() {
                        break;
                    }
                    pos += 8;
                }

                // Hash128(4) — 16 bytes, skip
                (4, _) => {
                    if pos + 16 > data.len() {
                        break;
                    }
                    pos += 16;
                }

                // Hash256(5), PreviousTxnID(5)
                (5, 5) => {
                    if pos + 32 > data.len() {
                        break;
                    }
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&data[pos..pos + 32]);
                    previous_txn_id = Some(h);
                    pos += 32;
                }
                // Hash256(5), RootIndex(8)
                (5, 8) => {
                    if pos + 32 > data.len() {
                        break;
                    }
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&data[pos..pos + 32]);
                    root_index = Some(h);
                    pos += 32;
                }
                // Hash256(5), NFTokenID(10)
                (5, 10) => {
                    if pos + 32 > data.len() {
                        break;
                    }
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&data[pos..pos + 32]);
                    nftoken_id = Some(h);
                    pos += 32;
                }
                // Hash256(5), DomainID(34)
                (5, 34) => {
                    if pos + 32 > data.len() {
                        break;
                    }
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&data[pos..pos + 32]);
                    domain_id = Some(h);
                    pos += 32;
                }
                // Hash256 — skip any other
                (5, _) => {
                    if pos + 32 > data.len() {
                        break;
                    }
                    pos += 32;
                }

                // Amount(6) — 8 bytes for XRP, 48 bytes for IOU
                (6, _) => {
                    if pos >= data.len() {
                        break;
                    }
                    let first = data[pos];
                    if first & 0x80 == 0 {
                        // XRP (negative) — shouldn't appear, but 8 bytes
                        if pos + 8 > data.len() {
                            break;
                        }
                        pos += 8;
                    } else if (first >> 1) & 0x7F == 0 {
                        // XRP amount: 8 bytes total
                        if pos + 8 > data.len() {
                            break;
                        }
                        pos += 8;
                    } else {
                        // IOU amount: 8 + 20 + 20 = 48 bytes
                        if pos + 48 > data.len() {
                            break;
                        }
                        pos += 48;
                    }
                }

                // VL/Blob(7) — variable length
                (7, _) => {
                    let (vl_len, vl_bytes) =
                        crate::transaction::serialize::decode_length(&data[pos..]);
                    pos += vl_bytes;
                    if pos + vl_len > data.len() {
                        break;
                    }
                    pos += vl_len;
                }

                // Account(8), Owner(2) — VL-prefixed AccountID
                (8, 2) => {
                    if pos >= data.len() {
                        break;
                    }
                    let (vl_len, vl_bytes) =
                        crate::transaction::serialize::decode_length(&data[pos..]);
                    pos += vl_bytes;
                    if vl_len == 20 && pos + 20 <= data.len() {
                        let mut a = [0u8; 20];
                        a.copy_from_slice(&data[pos..pos + 20]);
                        owner = Some(a);
                    }
                    pos += vl_len;
                }
                // Account — skip any other
                (8, _) => {
                    if pos >= data.len() {
                        break;
                    }
                    let (vl_len, vl_bytes) =
                        crate::transaction::serialize::decode_length(&data[pos..]);
                    pos += vl_bytes;
                    if pos + vl_len > data.len() {
                        break;
                    }
                    pos += vl_len;
                }

                // UInt160(17), TakerPaysCurrency(1)
                (17, 1) => {
                    if pos + 20 > data.len() {
                        break;
                    }
                    let mut v = [0u8; 20];
                    v.copy_from_slice(&data[pos..pos + 20]);
                    taker_pays_currency = Some(v);
                    pos += 20;
                }
                // UInt160(17), TakerPaysIssuer(2)
                (17, 2) => {
                    if pos + 20 > data.len() {
                        break;
                    }
                    let mut v = [0u8; 20];
                    v.copy_from_slice(&data[pos..pos + 20]);
                    taker_pays_issuer = Some(v);
                    pos += 20;
                }
                // UInt160(17), TakerGetsCurrency(3)
                (17, 3) => {
                    if pos + 20 > data.len() {
                        break;
                    }
                    let mut v = [0u8; 20];
                    v.copy_from_slice(&data[pos..pos + 20]);
                    taker_gets_currency = Some(v);
                    pos += 20;
                }
                // UInt160(17), TakerGetsIssuer(4)
                (17, 4) => {
                    if pos + 20 > data.len() {
                        break;
                    }
                    let mut v = [0u8; 20];
                    v.copy_from_slice(&data[pos..pos + 20]);
                    taker_gets_issuer = Some(v);
                    pos += 20;
                }
                // UInt160 — skip any other
                (17, _) => {
                    if pos + 20 > data.len() {
                        break;
                    }
                    pos += 20;
                }

                // Hash384(18) — 48 bytes, skip
                (18, _) => {
                    if pos + 48 > data.len() {
                        break;
                    }
                    pos += 48;
                }

                // Vector256(19), Indexes(1)
                (19, 1) => {
                    let (vl_len, vl_bytes) =
                        crate::transaction::serialize::decode_length(&data[pos..]);
                    pos += vl_bytes;
                    if pos + vl_len > data.len() {
                        break;
                    }
                    let count = vl_len / 32;
                    indexes.reserve(count);
                    for i in 0..count {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&data[pos + i * 32..pos + (i + 1) * 32]);
                        indexes.push(h);
                    }
                    pos += vl_len;
                }
                // Vector256 — skip any other
                (19, _) => {
                    let (vl_len, vl_bytes) =
                        crate::transaction::serialize::decode_length(&data[pos..]);
                    pos += vl_bytes;
                    if pos + vl_len > data.len() {
                        break;
                    }
                    pos += vl_len;
                }

                // STObject(14) begin — skip nested objects
                (14, _) => {
                    // Skip until end marker 0xE1
                    while pos < data.len() && data[pos] != 0xE1 {
                        pos += 1;
                    }
                    if pos < data.len() {
                        pos += 1;
                    } // skip 0xE1
                }

                // STArray(15) begin — skip nested arrays
                (15, _) => {
                    // Skip until end marker 0xF1
                    while pos < data.len() && data[pos] != 0xF1 {
                        pos += 1;
                    }
                    if pos < data.len() {
                        pos += 1;
                    } // skip 0xF1
                }

                // Unknown type: size cannot be determined safely, so stop parsing.
                _ => {
                    break;
                }
            }
        }

        let root = root_index.ok_or(DirectoryDecodeError::MissingRootIndex)?;

        Ok(Self {
            key,
            root_index: root,
            indexes,
            index_next,
            index_previous,
            owner,
            exchange_rate,
            taker_pays_currency,
            taker_pays_issuer,
            taker_gets_currency,
            taker_gets_issuer,
            nftoken_id,
            domain_id,
            previous_txn_id,
            previous_txn_lgr_seq,
            has_index_next,
            has_index_previous,
            raw_sle: Some(data.to_vec()),
        })
    }
}

/// Errors from decoding a DirectoryNode SLE.
#[derive(Debug)]
pub enum DirectoryDecodeError {
    MissingRootIndex,
}

impl std::fmt::Display for DirectoryDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRootIndex => write!(f, "missing RootIndex field in DirectoryNode"),
        }
    }
}

impl std::error::Error for DirectoryDecodeError {}

// ── Directory maintenance helpers ────────────────────────────────────────────

use crate::ledger::LedgerState;

/// Add an entry to an account's owner directory.
///
/// Creates the root directory if it doesn't exist.
/// Handles page overflow (max 32 entries per page) by creating new pages
/// and linking them into the doubly-linked page chain.
///
/// Returns the page number where the entry was inserted.
///
/// Matches rippled's `ApplyView::dirAdd` logic.
pub fn dir_add(state: &mut LedgerState, owner: &[u8; 20], entry_key: [u8; 32]) -> u64 {
    let root_key = owner_dir_key(owner);

    // Check if root exists
    if load_directory_fresh(state, &root_key).is_none() {
        // Create new root with this single entry
        let mut root = DirectoryNode::new_owner_root(owner);
        root.indexes.push(entry_key);
        state.insert_directory(root);
        return 0;
    }

    // Root exists — find the last page (follow index_previous from root).
    // rippled's findPreviousPage: starts at root, reads IndexPrevious to
    // find the last page in the chain.
    // Safe because the root existence check above already succeeded. Clone it
    // before mutation.
    let root = load_directory_fresh(state, &root_key).unwrap();
    let last_page_num = root.index_previous;

    let last_key = page_key(&root_key.0, last_page_num);
    let last = match load_directory_fresh(state, &last_key) {
        Some(d) => d,
        None => {
            // Last page not in state — fall back to root page
            let mut updated = root;
            updated.indexes.push(entry_key);
            updated.raw_sle = None;
            state.insert_directory(updated);
            return 0;
        }
    };

    if last.indexes.len() < DIR_NODE_MAX_ENTRIES {
        // Space on the last page — insert there
        let mut updated = last;
        updated.indexes.push(entry_key);
        updated.raw_sle = None;
        state.insert_directory(updated);
        return last_page_num;
    }

    // Last page is full — create a new page.
    // New page number = last_page_num + 1 (unless last_page_num is the root,
    // then it's 1).
    let new_page_num = if last_page_num == 0 {
        // A full root uses `IndexNext` to locate the next page. If it is `0`,
        // there are no other pages yet, so new page = 1
        if root.index_next == 0 {
            1
        } else {
            // Walk to find the highest page number
            let mut highest = root.index_next;
            loop {
                let pk = page_key(&root_key.0, highest);
                if let Some(p) = load_directory_fresh(state, &pk) {
                    if p.index_next == 0 {
                        break;
                    }
                    highest = p.index_next;
                } else {
                    break;
                }
            }
            highest + 1
        }
    } else {
        last_page_num + 1
    };

    // Create the new page
    let mut new_page = DirectoryNode::new_page(&root_key.0, new_page_num, Some(*owner));
    new_page.indexes.push(entry_key);
    // Link: new page's previous = last_page_num
    // rippled: if page != 1, set IndexPrevious. For page 1, it defaults to 0 (root).
    if new_page_num != 1 {
        new_page.index_previous = last_page_num;
    }
    // new page's next = 0 (it's the new tail, pointing to root implicitly)

    // Update the old last page to point to the new page.
    // Reuse the clone from line 601 — no re-fetch needed.
    if last_page_num == 0 {
        let mut root_updated = root;
        root_updated.index_next = new_page_num;
        root_updated.index_previous = new_page_num;
        root_updated.raw_sle = None;
        state.insert_directory(root_updated);
    } else {
        let mut old_last = last;
        old_last.index_next = new_page_num;
        old_last.raw_sle = None;
        state.insert_directory(old_last);

        let mut root_updated = root;
        root_updated.index_previous = new_page_num;
        root_updated.raw_sle = None;
        state.insert_directory(root_updated);
    }

    state.insert_directory(new_page);
    new_page_num
}

/// Add an entry to a quality-specific book directory.
pub fn dir_add_book(
    state: &mut LedgerState,
    book: &BookKey,
    quality: u64,
    entry_key: [u8; 32],
) -> (Key, u64) {
    let root_key = book_dir_quality_key(book, quality);

    if load_directory_fresh(state, &root_key).is_none() {
        let mut root = DirectoryNode::new_book_root(book, quality);
        root.indexes.push(entry_key);
        state.insert_directory(root);
        return (root_key, 0);
    }

    let root = load_directory_fresh(state, &root_key).unwrap();
    let last_page_num = root.index_previous;
    let last_key = page_key(&root_key.0, last_page_num);
    let last = match load_directory_fresh(state, &last_key) {
        Some(d) => d,
        None => {
            let mut updated = root;
            updated.indexes.push(entry_key);
            updated.raw_sle = None;
            state.insert_directory(updated);
            return (root_key, 0);
        }
    };

    if last.indexes.len() < DIR_NODE_MAX_ENTRIES {
        let mut updated = last;
        updated.indexes.push(entry_key);
        updated.raw_sle = None;
        state.insert_directory(updated);
        return (root_key, last_page_num);
    }

    let new_page_num = if last_page_num == 0 {
        if root.index_next == 0 {
            1
        } else {
            let mut highest = root.index_next;
            loop {
                let pk = page_key(&root_key.0, highest);
                if let Some(p) = load_directory_fresh(state, &pk) {
                    if p.index_next == 0 {
                        break;
                    }
                    highest = p.index_next;
                } else {
                    break;
                }
            }
            highest + 1
        }
    } else {
        last_page_num + 1
    };

    let mut new_page = DirectoryNode::new_book_page(&root_key.0, new_page_num, book, quality);
    new_page.indexes.push(entry_key);
    if new_page_num != 1 {
        new_page.index_previous = last_page_num;
    }

    if last_page_num == 0 {
        let mut root_updated = root;
        root_updated.index_next = new_page_num;
        root_updated.index_previous = new_page_num;
        root_updated.raw_sle = None;
        state.insert_directory(root_updated);
    } else {
        let mut old_last = last;
        old_last.index_next = new_page_num;
        old_last.raw_sle = None;
        state.insert_directory(old_last);

        let mut root_updated = root;
        root_updated.index_previous = new_page_num;
        root_updated.raw_sle = None;
        state.insert_directory(root_updated);
    }

    state.insert_directory(new_page);
    (root_key, new_page_num)
}

/// Remove an entry from an account's owner directory.
///
/// Searches all pages for the entry. If found, removes it.
/// If a non-root page becomes empty, unlinks and deletes it.
/// If the root page becomes empty and has no other pages, deletes it.
///
/// Returns `true` if the entry was found and removed.
///
/// Matches rippled's `ApplyView::dirRemove` logic.
pub fn dir_remove(state: &mut LedgerState, owner: &[u8; 20], entry_key: &[u8; 32]) -> bool {
    let root_key = owner_dir_key(owner);
    dir_remove_root(state, &root_key, entry_key)
}

/// Remove an entry from a directory when the root key is already known.
pub fn dir_remove_root(state: &mut LedgerState, root_key: &Key, entry_key: &[u8; 32]) -> bool {
    let trace_root = is_debug_directory_root(&root_key.0);
    // Verify the directory exists
    if load_directory_fresh(state, root_key).is_none() {
        if trace_root {
            info!(
                "dir-trace dir_remove_root phase=missing_root root={} entry={}",
                hex::encode_upper(root_key.0),
                hex::encode_upper(entry_key),
            );
        }
        return false;
    }

    if trace_root {
        if let Some(root) = load_directory_fresh(state, root_key) {
            info!(
                "dir-trace dir_remove_root phase=start root={} entry={} {}",
                hex::encode_upper(root_key.0),
                hex::encode_upper(entry_key),
                debug_directory_summary(&root),
            );
        }
    }

    // Search starting from root (page 0), then follow index_next
    let mut current_page_num: u64 = 0;
    loop {
        let pk = page_key(&root_key.0, current_page_num);
        let page = match load_directory_fresh(state, &pk) {
            Some(p) => p,
            None => return false,
        };

        if trace_root {
            info!(
                "dir-trace dir_remove_root phase=visit root={} page={} page_num={} {}",
                hex::encode_upper(root_key.0),
                hex::encode_upper(pk.0),
                current_page_num,
                debug_directory_summary(&page),
            );
        }

        if page.indexes.iter().any(|k| k == entry_key) {
            return dir_remove_loaded_page(
                state,
                root_key,
                current_page_num,
                page,
                entry_key,
                trace_root,
            );
        }

        // Not on this page — follow the chain
        if page.index_next == 0 || page.index_next == current_page_num {
            // Reached end of chain
            if trace_root {
                info!(
                    "dir-trace dir_remove_root phase=not_found root={} final_page={} page_num={} entry={}",
                    hex::encode_upper(root_key.0),
                    hex::encode_upper(pk.0),
                    current_page_num,
                    hex::encode_upper(entry_key),
                );
            }
            return false;
        }
        current_page_num = page.index_next;
    }
}

/// Remove an entry from a known directory page.
///
/// Offer SLEs carry `sfOwnerNode` and `sfBookNode`; rippled passes those page
/// hints into `dirRemove` rather than scanning from the root. This avoids
/// deleting a duplicate/stale entry from the wrong page when directory pages
/// are sparse or partially hydrated.
pub fn dir_remove_root_page(
    state: &mut LedgerState,
    root_key: &Key,
    page_num: u64,
    entry_key: &[u8; 32],
) -> bool {
    let trace_root = is_debug_directory_root(&root_key.0);
    if page_num == 0 && load_directory_fresh(state, root_key).is_none() {
        if trace_root {
            info!(
                "dir-trace dir_remove_root_page phase=missing_root root={} page_num={} entry={}",
                hex::encode_upper(root_key.0),
                page_num,
                hex::encode_upper(entry_key),
            );
        }
        return false;
    }

    let pk = page_key(&root_key.0, page_num);
    let Some(page) = load_directory_fresh(state, &pk) else {
        if trace_root {
            info!(
                "dir-trace dir_remove_root_page phase=missing_page root={} page={} page_num={} entry={}",
                hex::encode_upper(root_key.0),
                hex::encode_upper(pk.0),
                page_num,
                hex::encode_upper(entry_key),
            );
        }
        return false;
    };

    dir_remove_loaded_page(state, root_key, page_num, page, entry_key, trace_root)
}

fn dir_remove_loaded_page(
    state: &mut LedgerState,
    root_key: &Key,
    page_num: u64,
    page: DirectoryNode,
    entry_key: &[u8; 32],
    trace_root: bool,
) -> bool {
    let pk = page_key(&root_key.0, page_num);
    let Some(idx) = page.indexes.iter().position(|k| k == entry_key) else {
        if trace_root {
            info!(
                "dir-trace dir_remove_loaded_page phase=not_found root={} page={} page_num={} entry={}",
                hex::encode_upper(root_key.0),
                hex::encode_upper(pk.0),
                page_num,
                hex::encode_upper(entry_key),
            );
        }
        return false;
    };

    let mut updated = page.clone();
    updated.indexes.remove(idx);
    updated.raw_sle = None;

    if !updated.indexes.is_empty() {
        // Rippled unlinks empty pages, but it does not compact surviving
        // entries into the previous page. Keep the touched page in place.
        if trace_root {
            info!(
                "dir-trace dir_remove_loaded_page phase=keep_nonempty root={} page={} removed_idx={} before_indexes={} after_indexes={}",
                hex::encode_upper(root_key.0),
                hex::encode_upper(pk.0),
                idx,
                page.indexes.len(),
                updated.indexes.len(),
            );
        }
        state.insert_directory(updated);
        return true;
    }

    if page_num == 0 {
        let next = page.index_next;
        let prev = page.index_previous;

        if next == 0 && prev == 0 {
            if trace_root {
                info!(
                    "dir-trace dir_remove_loaded_page phase=delete_entire_directory root={} page={} entry={}",
                    hex::encode_upper(root_key.0),
                    hex::encode_upper(pk.0),
                    hex::encode_upper(entry_key),
                );
            }
            state.remove_directory_any(&pk);
            return true;
        }

        // Root is empty but other pages exist: keep root (rippled keepRoot behavior).
        if next == prev && next != 0 {
            let last_key = page_key(&root_key.0, next);
            if let Some(last) = load_directory_fresh(state, &last_key) {
                if last.indexes.is_empty() {
                    updated.index_next = 0;
                    updated.index_previous = 0;
                    updated.raw_sle = None;
                    if trace_root {
                        info!(
                            "dir-trace dir_remove_loaded_page phase=prune_trailing_empty_last root={} page={} last_page={} last_page_num={}",
                            hex::encode_upper(root_key.0),
                            hex::encode_upper(pk.0),
                            hex::encode_upper(last_key.0),
                            next,
                        );
                    }
                    state.insert_directory(updated);
                    state.remove_directory_any(&last_key);
                    return true;
                }
            }
        }

        if trace_root {
            info!(
                "dir-trace dir_remove_loaded_page phase=keep_empty_root root={} page={} next={} prev={}",
                hex::encode_upper(root_key.0),
                hex::encode_upper(pk.0),
                next,
                prev,
            );
        }
        state.insert_directory(updated);
        return true;
    }

    let prev_page_num = page.index_previous;
    let next_page_num = page.index_next;

    let prev_key = page_key(&root_key.0, prev_page_num);
    if let Some(prev_page) = load_directory_fresh(state, &prev_key) {
        let mut prev_updated = prev_page;
        prev_updated.index_next = next_page_num;
        prev_updated.raw_sle = None;
        state.insert_directory(prev_updated);
    }

    // `next_page_num == 0` points back to the root page.
    let next_key = page_key(&root_key.0, next_page_num);
    if let Some(next_page) = load_directory_fresh(state, &next_key) {
        let mut next_updated = next_page;
        next_updated.index_previous = prev_page_num;
        next_updated.raw_sle = None;
        state.insert_directory(next_updated);
    }

    if trace_root {
        info!(
            "dir-trace dir_remove_loaded_page phase=delete_empty_nonroot root={} page={} prev_page={} next_page={}",
            hex::encode_upper(root_key.0),
            hex::encode_upper(pk.0),
            prev_page_num,
            next_page_num,
        );
    }
    state.remove_directory_any(&pk);

    true
}

/// Count total entries across an account's owner directory pages.
pub fn owner_dir_entry_count(state: &LedgerState, owner: &[u8; 20]) -> usize {
    let root_key = owner_dir_key(owner);
    let Some(_) = load_directory_fresh(state, &root_key) else {
        return 0;
    };

    let mut total = 0usize;
    let mut current_page_num: u64 = 0;
    loop {
        let pk = page_key(&root_key.0, current_page_num);
        let Some(page) = load_directory_fresh(state, &pk) else {
            break;
        };
        total += page.indexes.len();
        if page.index_next == 0 || page.index_next == current_page_num {
            break;
        }
        current_page_num = page.index_next;
    }
    total
}

/// Return (total entries across pages, unique entry count) for an owner directory.
pub fn owner_dir_entry_stats(state: &LedgerState, owner: &[u8; 20]) -> (usize, usize) {
    let root_key = owner_dir_key(owner);
    let Some(_) = load_directory_fresh(state, &root_key) else {
        return (0, 0);
    };

    let mut total = 0usize;
    let mut seen = std::collections::BTreeSet::<[u8; 32]>::new();
    let mut current_page_num: u64 = 0;
    loop {
        let pk = page_key(&root_key.0, current_page_num);
        let Some(page) = load_directory_fresh(state, &pk) else {
            break;
        };
        total += page.indexes.len();
        for key in &page.indexes {
            seen.insert(*key);
        }
        if page.index_next == 0 || page.index_next == current_page_num {
            break;
        }
        current_page_num = page.index_next;
    }
    (total, seen.len())
}

/// Check whether an owner directory currently contains a specific entry key.
pub fn owner_dir_contains_entry(
    state: &LedgerState,
    owner: &[u8; 20],
    entry_key: &[u8; 32],
) -> bool {
    owner_dir_page_for_entry(state, owner, entry_key).is_some()
}

/// Return the owner-directory page number containing a specific entry key.
pub fn owner_dir_page_for_entry(
    state: &LedgerState,
    owner: &[u8; 20],
    entry_key: &[u8; 32],
) -> Option<u64> {
    let root_key = owner_dir_key(owner);
    let Some(_) = load_directory_fresh(state, &root_key) else {
        return None;
    };
    let mut current_page_num: u64 = 0;
    loop {
        let pk = page_key(&root_key.0, current_page_num);
        let Some(page) = load_directory_fresh(state, &pk) else {
            return None;
        };
        if page.indexes.iter().any(|k| k == entry_key) {
            return Some(current_page_num);
        }
        if page.index_next == 0 || page.index_next == current_page_num {
            return None;
        }
        current_page_num = page.index_next;
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(n: u8) -> [u8; 20] {
        [n; 20]
    }

    fn entry(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn test_owner_dir_key_deterministic() {
        let a = owner_dir_key(&acct(1));
        let b = owner_dir_key(&acct(1));
        assert_eq!(a, b);
    }

    #[test]
    fn test_different_accounts_different_keys() {
        assert_ne!(owner_dir_key(&acct(1)), owner_dir_key(&acct(2)));
    }

    #[test]
    fn test_page_key_page0_is_root() {
        let root = owner_dir_key(&acct(1));
        let p0 = page_key(&root.0, 0);
        assert_eq!(root, p0);
    }

    #[test]
    fn test_page_key_different_pages() {
        let root = owner_dir_key(&acct(1));
        let p1 = page_key(&root.0, 1);
        let p2 = page_key(&root.0, 2);
        assert_ne!(p1, p2);
        assert_ne!(root, p1);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut dir = DirectoryNode::new_owner_root(&acct(0xAB));
        dir.indexes.push(entry(1));
        dir.indexes.push(entry(2));
        dir.index_next = 1;
        dir.index_previous = 3;

        let encoded = dir.encode();
        let decoded = DirectoryNode::decode(&encoded, dir.key).unwrap();

        assert_eq!(decoded.root_index, dir.root_index);
        assert_eq!(decoded.indexes.len(), 2);
        assert_eq!(decoded.indexes[0], entry(1));
        assert_eq!(decoded.indexes[1], entry(2));
        assert_eq!(decoded.index_next, 1);
        assert_eq!(decoded.index_previous, 3);
        assert_eq!(decoded.owner, Some(acct(0xAB)));
    }

    #[test]
    fn test_encode_decode_book_dir() {
        let root_key = [0x42u8; 32];
        let mut dir = DirectoryNode::new_page(&root_key, 0, None);
        dir.key = root_key;
        dir.exchange_rate = Some(12345678);
        dir.taker_pays_currency = Some([0x01; 20]);
        dir.taker_pays_issuer = Some([0x02; 20]);
        dir.taker_gets_currency = Some([0x03; 20]);
        dir.taker_gets_issuer = Some([0x04; 20]);
        dir.indexes.push(entry(0xFF));

        let encoded = dir.encode();
        let decoded = DirectoryNode::decode(&encoded, root_key).unwrap();

        assert_eq!(decoded.exchange_rate, Some(12345678));
        assert_eq!(decoded.taker_pays_currency, Some([0x01; 20]));
        assert_eq!(decoded.taker_pays_issuer, Some([0x02; 20]));
        assert_eq!(decoded.taker_gets_currency, Some([0x03; 20]));
        assert_eq!(decoded.taker_gets_issuer, Some([0x04; 20]));
        assert_eq!(decoded.indexes.len(), 1);
        assert_eq!(decoded.owner, None);
    }

    #[test]
    fn test_dir_add_creates_root() {
        let mut state = LedgerState::new();
        let owner = acct(1);
        let page = dir_add(&mut state, &owner, entry(0xAA));
        assert_eq!(page, 0);

        let root_key = owner_dir_key(&owner);
        let dir = state.get_directory(&root_key).unwrap();
        assert_eq!(dir.indexes.len(), 1);
        assert_eq!(dir.indexes[0], entry(0xAA));
    }

    #[test]
    fn test_dir_add_multiple_entries() {
        let mut state = LedgerState::new();
        let owner = acct(1);
        for i in 0..10u8 {
            dir_add(&mut state, &owner, entry(i));
        }

        let root_key = owner_dir_key(&owner);
        let dir = state.get_directory(&root_key).unwrap();
        assert_eq!(dir.indexes.len(), 10);
    }

    #[test]
    fn test_dir_add_overflow_creates_new_page() {
        let mut state = LedgerState::new();
        let owner = acct(1);

        // Fill root page (32 entries)
        for i in 0..32u8 {
            dir_add(&mut state, &owner, entry(i));
        }

        // 33rd entry should go to page 1
        let page = dir_add(&mut state, &owner, entry(99));
        assert_eq!(page, 1);

        let root_key = owner_dir_key(&owner);
        let page1_key = page_key(&root_key.0, 1);
        let page1 = state.get_directory(&page1_key).unwrap();
        assert_eq!(page1.indexes.len(), 1);
        assert_eq!(page1.indexes[0], entry(99));
    }

    #[test]
    fn test_dir_remove_basic() {
        let mut state = LedgerState::new();
        let owner = acct(1);
        dir_add(&mut state, &owner, entry(1));
        dir_add(&mut state, &owner, entry(2));
        dir_add(&mut state, &owner, entry(3));

        assert!(dir_remove(&mut state, &owner, &entry(2)));

        let root_key = owner_dir_key(&owner);
        let dir = state.get_directory(&root_key).unwrap();
        assert_eq!(dir.indexes.len(), 2);
        assert!(!dir.indexes.contains(&entry(2)));
    }

    #[test]
    fn test_dir_remove_last_entry_deletes_root() {
        let mut state = LedgerState::new();
        let owner = acct(1);
        dir_add(&mut state, &owner, entry(1));

        assert!(dir_remove(&mut state, &owner, &entry(1)));

        let root_key = owner_dir_key(&owner);
        assert!(state.get_directory(&root_key).is_none());
    }

    #[test]
    fn test_dir_remove_nonexistent() {
        let mut state = LedgerState::new();
        let owner = acct(1);
        dir_add(&mut state, &owner, entry(1));

        assert!(!dir_remove(&mut state, &owner, &entry(99)));
    }

    #[test]
    fn test_dir_remove_no_directory() {
        let mut state = LedgerState::new();
        assert!(!dir_remove(&mut state, &acct(1), &entry(1)));
    }

    #[test]
    fn test_dir_remove_keeps_first_overflow_page_when_root_stays_nonempty() {
        let mut state = LedgerState::new();
        let owner = acct(1);

        for i in 0..33u8 {
            dir_add(&mut state, &owner, entry(i));
        }

        let root_key = owner_dir_key(&owner);
        let page1_key = page_key(&root_key.0, 1);
        assert!(state.get_directory(&page1_key).is_some());

        assert!(dir_remove(&mut state, &owner, &entry(0)));

        let root = state.get_directory(&root_key).unwrap();
        let page1 = state.get_directory(&page1_key).unwrap();
        assert_eq!(root.indexes.len(), 31);
        assert_eq!(root.index_next, 1);
        assert_eq!(root.index_previous, 1);
        assert!(!root.indexes.contains(&entry(32)));
        assert_eq!(page1.indexes, vec![entry(32)]);
        assert_eq!(owner_dir_entry_count(&state, &owner), 32);
    }

    #[test]
    fn test_dir_remove_keeps_page_one_and_page_two_linked_after_root_removals() {
        let mut state = LedgerState::new();
        let owner = acct(1);

        for i in 0..65u8 {
            dir_add(&mut state, &owner, entry(i));
        }

        let root_key = owner_dir_key(&owner);
        let page1_key = page_key(&root_key.0, 1);
        let page2_key = page_key(&root_key.0, 2);
        assert!(state.get_directory(&page1_key).is_some());
        assert!(state.get_directory(&page2_key).is_some());

        for i in 32..39u8 {
            assert!(dir_remove(&mut state, &owner, &entry(i)));
        }

        for i in 0..25u8 {
            assert!(dir_remove(&mut state, &owner, &entry(i)));
        }

        let root = state.get_directory(&root_key).unwrap();
        let page1 = state.get_directory(&page1_key).unwrap();
        let page2 = state.get_directory(&page2_key).unwrap();
        assert_eq!(root.index_next, 1);
        assert_eq!(root.index_previous, 2);
        assert_eq!(root.indexes.len(), 7);
        assert_eq!(page1.index_previous, 0);
        assert_eq!(page1.index_next, 2);
        assert_eq!(page1.indexes.len(), 25);
        assert_eq!(page2.index_previous, 1);
        assert_eq!(page2.index_next, 0);
        assert_eq!(page2.indexes.len(), 1);
        assert!(state.get_directory(&page1_key).is_some());
        assert_eq!(owner_dir_entry_count(&state, &owner), 33);
    }

    #[test]
    fn test_dir_remove_keeps_deep_non_root_page_uncompacted_when_previous_has_space() {
        let mut state = LedgerState::new();
        let owner = acct(1);

        for i in 0..66u8 {
            dir_add(&mut state, &owner, entry(i));
        }

        let root_key = owner_dir_key(&owner);
        let page1_key = page_key(&root_key.0, 1);
        let page2_key = page_key(&root_key.0, 2);
        assert!(state.get_directory(&page1_key).is_some());
        assert!(state.get_directory(&page2_key).is_some());

        for i in 32..63u8 {
            assert!(dir_remove(&mut state, &owner, &entry(i)));
        }

        assert!(dir_remove(&mut state, &owner, &entry(64)));

        let root = state.get_directory(&root_key).unwrap();
        let page1 = state.get_directory(&page1_key).unwrap();
        let page2 = state.get_directory(&page2_key).unwrap();
        assert_eq!(root.index_next, 1);
        assert_eq!(root.index_previous, 2);
        assert_eq!(root.indexes.len(), 32);
        assert_eq!(page1.index_previous, 0);
        assert_eq!(page1.index_next, 2);
        assert_eq!(page1.indexes, vec![entry(63)]);
        assert_eq!(page2.index_previous, 1);
        assert_eq!(page2.index_next, 0);
        assert_eq!(page2.indexes, vec![entry(65)]);
        assert_eq!(owner_dir_entry_count(&state, &owner), 34);
    }
}
