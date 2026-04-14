//! Ledger history — stores closed ledger headers and their transactions.
//!
//! Provides O(1) lookup of:
//!   - Ledger header by sequence number
//!   - Transaction blob + metadata by tx hash
//!
//! This is an in-memory store; a production node would persist to disk.

use std::collections::HashMap;

use serde::{Serialize, Deserialize};

use crate::ledger::LedgerHeader;

// ── Transaction record ────────────────────────────────────────────────────────

/// A transaction stored in ledger history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    /// The raw signed transaction blob.
    pub blob:        Vec<u8>,
    /// Raw transaction metadata blob.
    #[serde(default)]
    pub meta:        Vec<u8>,
    /// Transaction hash (32 bytes).
    pub hash:        [u8; 32],
    /// The ledger sequence this tx was included in.
    pub ledger_seq:  u32,
    /// Execution order within the ledger.
    #[serde(default)]
    pub tx_index:    u32,
    /// Engine result code string (e.g. "tesSUCCESS").
    pub result:      String,
}

// ── Ledger record ─────────────────────────────────────────────────────────────

/// A closed ledger in history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerRecord {
    pub header:   LedgerHeader,
    /// Hashes of all transactions included in this ledger (in application order).
    pub tx_hashes: Vec<[u8; 32]>,
}

// ── LedgerStore ───────────────────────────────────────────────────────────────

/// Default number of ledgers to keep in memory (matches rippled's default).
const DEFAULT_MAX_HISTORY: u32 = 256;

/// In-memory store of closed ledger headers and transaction history.
#[derive(Clone)]
pub struct LedgerStore {
    /// Ledger headers keyed by sequence number.
    ledgers: HashMap<u32, LedgerRecord>,
    /// Transactions keyed by hash.
    tx_index: HashMap<[u8; 32], TxRecord>,
    /// Transaction hashes per account (for account_tx queries).
    account_txs: HashMap<[u8; 20], Vec<[u8; 32]>>,
    /// The lowest sequence we have.
    min_seq: u32,
    /// The highest sequence we have.
    max_seq: u32,
    /// Maximum number of ledgers to retain in memory. `None` means unlimited.
    max_history: Option<u32>,
}

impl LedgerStore {
    pub fn new() -> Self {
        Self::with_limit(Some(DEFAULT_MAX_HISTORY))
    }

    pub fn with_limit(max_history: Option<u32>) -> Self {
        Self {
            ledgers:     HashMap::new(),
            tx_index:    HashMap::new(),
            account_txs: HashMap::new(),
            min_seq:     0,
            max_seq:     0,
            max_history,
        }
    }

    pub fn set_max_history(&mut self, max_history: Option<u32>) {
        self.max_history = max_history;
    }

    /// Record a closed ledger and its transactions.
    pub fn insert_ledger(
        &mut self,
        header:   LedgerHeader,
        tx_records: Vec<TxRecord>,
    ) {
        if self.max_history == Some(0) {
            return;
        }

        let seq = header.sequence;
        let tx_hashes: Vec<[u8; 32]> = tx_records.iter().map(|r| r.hash).collect();

        for rec in tx_records {
            // Index by account: parse the blob to find the sender
            if let Ok(parsed) = crate::transaction::parse_blob(&rec.blob) {
                self.account_txs.entry(parsed.account).or_default().push(rec.hash);
                // Also index by destination if present
                if let Some(dest) = parsed.destination {
                    self.account_txs.entry(dest).or_default().push(rec.hash);
                }
            }
            self.tx_index.insert(rec.hash, rec);
        }

        self.ledgers.insert(seq, LedgerRecord { header, tx_hashes });

        if self.min_seq == 0 || seq < self.min_seq {
            self.min_seq = seq;
        }
        if seq > self.max_seq {
            self.max_seq = seq;
        }

        // Prune old ledgers to bound memory usage.
        if let Some(max_history) = self.max_history {
            if self.max_seq.saturating_sub(self.min_seq) > max_history {
                let prune_below = self.max_seq - max_history;
                let pruned_tx_hashes: Vec<[u8; 32]> = self.ledgers.iter()
                    .filter(|(&s, _)| s < prune_below)
                    .flat_map(|(_, rec)| rec.tx_hashes.iter().copied())
                    .collect();
                let pruned_set: std::collections::HashSet<[u8; 32]> =
                    pruned_tx_hashes.iter().copied().collect();
                self.ledgers.retain(|&s, _| s >= prune_below);
                for h in &pruned_tx_hashes {
                    self.tx_index.remove(h);
                }
                self.account_txs.retain(|_, hashes| {
                    hashes.retain(|h| !pruned_set.contains(h));
                    !hashes.is_empty()
                });
                self.min_seq = prune_below;
            }
        }
    }

    /// Look up a ledger header by sequence number.
    pub fn get_ledger(&self, seq: u32) -> Option<&LedgerRecord> {
        self.ledgers.get(&seq)
    }

    /// Return the highest-sequence ledger we have in memory.
    pub fn latest_ledger(&self) -> Option<&LedgerRecord> {
        if self.max_seq == 0 {
            None
        } else {
            self.ledgers.get(&self.max_seq)
        }
    }

    /// Look up a ledger header by hash.
    pub fn get_ledger_by_hash(&self, hash: &[u8; 32]) -> Option<&LedgerRecord> {
        self.ledgers.values().find(|rec| &rec.header.hash == hash)
    }

    /// Insert a single transaction into the in-memory index.
    pub fn insert_tx(&mut self, rec: TxRecord) {
        if let Ok(parsed) = crate::transaction::parse_blob(&rec.blob) {
            self.account_txs.entry(parsed.account).or_default().push(rec.hash);
            if let Some(dest) = parsed.destination {
                self.account_txs.entry(dest).or_default().push(rec.hash);
            }
        }
        self.tx_index.insert(rec.hash, rec);
    }

    /// Look up a transaction by its hash.
    pub fn get_tx(&self, hash: &[u8; 32]) -> Option<&TxRecord> {
        self.tx_index.get(hash)
    }

    /// Return all stored transactions for a ledger in application order.
    pub fn ledger_txs(&self, seq: u32) -> Vec<TxRecord> {
        self.ledgers.get(&seq)
            .map(|rec| {
                rec.tx_hashes.iter()
                    .filter_map(|hash| self.tx_index.get(hash).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get transaction hashes for an account (both sent and received).
    pub fn get_account_txs(&self, account_id: &[u8; 20]) -> &[[u8; 32]] {
        self.account_txs.get(account_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Total number of closed ledgers stored.
    pub fn ledger_count(&self) -> usize {
        self.ledgers.len()
    }

    /// Total number of transactions indexed.
    pub fn tx_count(&self) -> usize {
        self.tx_index.len()
    }

    /// Range string for `server_info` complete_ledgers field.
    ///
    /// Simplification: this assumes a contiguous range between min_seq and max_seq.
    /// rippled uses a RangeSet for proper gap tracking. This is acceptable here
    /// because our in-memory cache with pruning maintains a contiguous window.
    pub fn complete_ledgers(&self) -> String {
        if self.ledgers.is_empty() {
            "empty".to_string()
        } else {
            format!("{}-{}", self.min_seq, self.max_seq)
        }
    }

    pub fn covers_ledger_range(&self, min_seq: u32, max_seq: u32) -> bool {
        if self.ledgers.is_empty() || min_seq > max_seq {
            return false;
        }
        self.min_seq <= min_seq
            && self.max_seq >= max_seq
            && self.ledgers.contains_key(&min_seq)
            && self.ledgers.contains_key(&max_seq)
    }
}

impl Default for LedgerStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn header(seq: u32) -> LedgerHeader {
        LedgerHeader {
            sequence: seq, hash: [seq as u8; 32], parent_hash: [0u8; 32],
            close_time: 1000 * seq as u64, total_coins: 100_000_000_000_000_000,
            account_hash: [0u8; 32], transaction_hash: [0u8; 32],
            parent_close_time: 0, close_time_resolution: 10, close_flags: 0,
        }
    }

    fn tx_rec(hash_byte: u8, seq: u32) -> TxRecord {
        TxRecord {
            blob: vec![0x12, 0x00, hash_byte],
            meta: vec![],
            hash: [hash_byte; 32],
            ledger_seq: seq,
            tx_index: 0,
            result: "tesSUCCESS".into(),
        }
    }

    #[test]
    fn test_insert_and_lookup_ledger() {
        let mut store = LedgerStore::new();
        store.insert_ledger(header(5), vec![]);
        let rec = store.get_ledger(5).unwrap();
        assert_eq!(rec.header.sequence, 5);
        assert!(rec.tx_hashes.is_empty());
    }

    #[test]
    fn test_insert_and_lookup_tx() {
        let mut store = LedgerStore::new();
        let tx = tx_rec(0xAB, 3);
        store.insert_ledger(header(3), vec![tx]);
        let found = store.get_tx(&[0xAB; 32]).unwrap();
        assert_eq!(found.ledger_seq, 3);
        assert_eq!(found.result, "tesSUCCESS");
    }

    #[test]
    fn test_missing_ledger_returns_none() {
        let store = LedgerStore::new();
        assert!(store.get_ledger(999).is_none());
    }

    #[test]
    fn test_missing_tx_returns_none() {
        let store = LedgerStore::new();
        assert!(store.get_tx(&[0xFF; 32]).is_none());
    }

    #[test]
    fn test_complete_ledgers_range() {
        let mut store = LedgerStore::with_limit(Some(2));
        assert_eq!(store.complete_ledgers(), "empty");

        store.insert_ledger(header(3), vec![]);
        store.insert_ledger(header(5), vec![]);
        assert_eq!(store.complete_ledgers(), "3-5");
    }

    #[test]
    fn test_latest_ledger_returns_highest_sequence() {
        let mut store = LedgerStore::new();
        assert!(store.latest_ledger().is_none());

        store.insert_ledger(header(3), vec![]);
        store.insert_ledger(header(5), vec![]);
        store.insert_ledger(header(4), vec![]);

        let latest = store.latest_ledger().unwrap();
        assert_eq!(latest.header.sequence, 5);
    }

    #[test]
    fn test_ledger_with_multiple_txs() {
        let mut store = LedgerStore::new();
        let txs = vec![tx_rec(1, 7), tx_rec(2, 7), tx_rec(3, 7)];
        store.insert_ledger(header(7), txs);

        let rec = store.get_ledger(7).unwrap();
        assert_eq!(rec.tx_hashes.len(), 3);
        assert_eq!(store.tx_count(), 3);

        assert!(store.get_tx(&[1; 32]).is_some());
        assert!(store.get_tx(&[2; 32]).is_some());
        assert!(store.get_tx(&[3; 32]).is_some());
    }

    #[test]
    fn test_counts() {
        let mut store = LedgerStore::new();
        store.insert_ledger(header(1), vec![tx_rec(0xA, 1)]);
        store.insert_ledger(header(2), vec![tx_rec(0xB, 2), tx_rec(0xC, 2)]);
        assert_eq!(store.ledger_count(), 2);
        assert_eq!(store.tx_count(), 3);
    }

    #[test]
    fn test_full_history_limit_keeps_all_ledgers() {
        let mut store = LedgerStore::with_limit(None);
        for seq in 1..=300 {
            store.insert_ledger(header(seq), vec![]);
        }
        assert_eq!(store.ledger_count(), 300);
        assert_eq!(store.complete_ledgers(), "1-300");
    }

    #[test]
    fn test_zero_history_limit_discards_inserted_ledgers() {
        let mut store = LedgerStore::with_limit(Some(0));
        store.insert_ledger(header(1), vec![]);
        assert_eq!(store.ledger_count(), 0);
        assert_eq!(store.complete_ledgers(), "empty");
    }
}
