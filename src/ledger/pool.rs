//! Transaction pool (mempool) with fee escalation matching rippled's TxQ.
//!
//! Key formula: `required_fee_level = multiplier × current² / target²`
//! where multiplier is the escalation multiplier from the previous ledger
//! (minimum 128,000 fee level units = baseLevel × 500).

use std::collections::HashMap;

use crate::transaction::ParsedTx;

/// rippled's base fee level — a single-signed reference transaction.
pub const BASE_LEVEL: u64 = 256;

/// Minimum escalation multiplier (baseLevel × 500 = 128,000).
const MIN_ESCALATION_MULTIPLIER: u64 = BASE_LEVEL * 500;

/// Default target transactions per ledger (rippled: minimumTxnInLedger).
const MIN_TXN_IN_LEDGER: u64 = 32;

/// Maximum target transactions per ledger.
const MAX_TXN_IN_LEDGER: u64 = 256;

/// Maximum queued transactions per account.
const MAX_TXN_PER_ACCOUNT: usize = 10;

/// Queue size minimum (rippled default).
const QUEUE_SIZE_MIN: usize = 2000;

/// Number of ledgers of capacity in queue sizing.
const LEDGERS_IN_QUEUE: u64 = 20;

/// A transaction in the pool — the raw blob plus its pre-parsed fields.
#[derive(Clone)]
pub struct PoolEntry {
    pub hash: [u8; 32],
    pub blob: Vec<u8>,
    pub parsed: PoolTxInfo,
}

/// The subset of parsed fields needed for ordering and deduplication.
#[derive(Clone, Debug)]
pub struct PoolTxInfo {
    pub account: [u8; 20],
    pub sequence: u32,
    pub fee: u64,
}

/// Fee metrics tracked across ledger closes — drives escalation.
#[derive(Clone, Debug)]
pub struct FeeMetrics {
    /// Escalation multiplier — computed from median fee of last closed ledger.
    /// Minimum value: MIN_ESCALATION_MULTIPLIER (128,000).
    pub escalation_multiplier: u64,
    /// Dynamic target: how many txs can enter at base fee level.
    /// Adjusted ±20% per healthy close, halved on slow consensus.
    pub txns_expected: u64,
}

impl Default for FeeMetrics {
    fn default() -> Self {
        Self {
            escalation_multiplier: MIN_ESCALATION_MULTIPLIER,
            txns_expected: MIN_TXN_IN_LEDGER,
        }
    }
}

impl FeeMetrics {
    /// Update metrics after a ledger closes.
    /// `tx_count`: number of transactions in the closed ledger.
    /// `slow_consensus`: true if consensus took > 5 seconds.
    pub fn update(&mut self, tx_count: u64, slow_consensus: bool) {
        if slow_consensus {
            // Slow consensus — decrease target by 50%
            self.txns_expected = (self.txns_expected / 2).max(MIN_TXN_IN_LEDGER);
        } else if tx_count > self.txns_expected {
            // Healthy and ledger was full — increase target by 20%
            self.txns_expected = (self.txns_expected * 6 / 5).min(MAX_TXN_IN_LEDGER);
        }
    }

    /// Compute the maximum queue size based on current target.
    pub fn max_queue_size(&self) -> usize {
        (self.txns_expected * LEDGERS_IN_QUEUE).max(QUEUE_SIZE_MIN as u64) as usize
    }

    /// Compute the escalated fee level when `current` txs are in the open ledger.
    /// Returns the fee level required for the next transaction to enter.
    ///
    /// Formula: `multiplier × current² / target²`
    pub fn escalated_fee_level(&self, current: u64) -> u64 {
        if current <= self.txns_expected {
            return BASE_LEVEL;
        }
        // Safe multiply: (multiplier * current * current) / (target * target)
        // Use u128 to avoid overflow
        let num = self.escalation_multiplier as u128 * current as u128 * current as u128;
        let den = self.txns_expected as u128 * self.txns_expected as u128;
        (num / den).min(u64::MAX as u128) as u64
    }

    /// Convert a fee level back to drops.
    /// `fee_level = (fee_drops × BASE_LEVEL) / base_fee`
    /// So: `fee_drops = (fee_level × base_fee) / BASE_LEVEL`
    pub fn fee_level_to_drops(fee_level: u64, base_fee: u64) -> u64 {
        ((fee_level as u128 * base_fee as u128 + BASE_LEVEL as u128 - 1) / BASE_LEVEL as u128)
            .min(u64::MAX as u128) as u64
    }

    /// Compute fee level from drops.
    pub fn fee_level_from_drops(fee_drops: u64, base_fee: u64) -> u64 {
        if base_fee == 0 {
            return u64::MAX;
        }
        ((fee_drops as u128 * BASE_LEVEL as u128) / base_fee as u128).min(u64::MAX as u128) as u64
    }
}

/// A pool of transactions waiting to be included in the next ledger.
#[derive(Clone)]
pub struct TxPool {
    /// tx_hash → entry
    entries: HashMap<[u8; 32], PoolEntry>,
    /// Per-account transaction count for enforcing MAX_TXN_PER_ACCOUNT.
    account_counts: HashMap<[u8; 20], usize>,
    /// Fee metrics for escalation calculations.
    pub metrics: FeeMetrics,
}

impl TxPool {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            account_counts: HashMap::new(),
            metrics: FeeMetrics::default(),
        }
    }

    /// Add a pre-validated transaction to the pool.
    ///
    /// The caller (submit handler) has already verified the signature, auth,
    /// sequence, and balance.  Returns `true` if inserted, `false` if the
    /// hash was already present or the account has too many queued txs.
    pub fn insert(&mut self, hash: [u8; 32], blob: Vec<u8>, parsed: &ParsedTx) -> bool {
        if self.entries.contains_key(&hash) {
            return false;
        }

        // Per-account limit
        let acct_count = self
            .account_counts
            .get(&parsed.account)
            .copied()
            .unwrap_or(0);
        if acct_count >= MAX_TXN_PER_ACCOUNT {
            return false;
        }

        self.entries.insert(
            hash,
            PoolEntry {
                hash,
                blob,
                parsed: PoolTxInfo {
                    account: parsed.account,
                    sequence: parsed.sequence,
                    fee: parsed.fee,
                },
            },
        );
        *self.account_counts.entry(parsed.account).or_insert(0) += 1;

        // Evict lowest-fee transactions when pool exceeds the dynamic max size.
        let max_size = self.metrics.max_queue_size();
        while self.entries.len() > max_size {
            self.evict_lowest_fee();
        }

        true
    }

    /// Evict the lowest-fee transaction to make room when the pool is full.
    fn evict_lowest_fee(&mut self) {
        if let Some((&worst_hash, _)) = self.entries.iter().min_by_key(|(_, e)| e.parsed.fee) {
            if let Some(entry) = self.entries.remove(&worst_hash) {
                let count = self.account_counts.entry(entry.parsed.account).or_insert(1);
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.account_counts.remove(&entry.parsed.account);
                }
            }
        }
    }

    /// Drain the pool and return all entries sorted by fee level (descending),
    /// with ties broken by tx hash XOR'd with a salt for deterministic ordering.
    pub fn drain_sorted(&mut self) -> Vec<PoolEntry> {
        let mut entries: Vec<PoolEntry> = self.entries.drain().map(|(_, e)| e).collect();
        self.account_counts.clear();
        // Sort by fee descending, then by (account, sequence) for same-fee ties
        entries.sort_by(|a, b| {
            b.parsed
                .fee
                .cmp(&a.parsed.fee)
                .then(a.parsed.account.cmp(&b.parsed.account))
                .then(a.parsed.sequence.cmp(&b.parsed.sequence))
        });
        entries
    }

    /// Number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Count transactions in the pool from a specific account.
    pub fn count_by_account(&self, account: &[u8; 20]) -> usize {
        self.account_counts.get(account).copied().unwrap_or(0)
    }

    /// Get all transaction hashes without draining (for proposal hash computation).
    pub fn peek_hashes(&self) -> Vec<[u8; 32]> {
        self.entries.keys().copied().collect()
    }

    /// Deterministic transaction-set hash matching a tx SHAMap root:
    /// transactions are placed by txID, and each leaf hash is the transaction ID.
    pub fn canonical_set_hash(&self) -> [u8; 32] {
        if self.entries.is_empty() {
            return [0u8; 32];
        }

        let mut map = crate::ledger::sparse_shamap::SparseSHAMap::new();
        for entry in self.entries.values() {
            let mut payload = Vec::with_capacity(
                crate::transaction::serialize::PREFIX_TX_ID.len() + entry.blob.len(),
            );
            payload.extend_from_slice(&crate::transaction::serialize::PREFIX_TX_ID);
            payload.extend_from_slice(&entry.blob);
            let tx_id = crate::crypto::sha512_first_half(&payload);
            map.insert(entry.hash, tx_id);
        }
        map.root_hash()
    }

    /// Remove a single transaction by hash (e.g., if it expires).
    pub fn remove(&mut self, hash: &[u8; 32]) -> bool {
        if let Some(entry) = self.entries.remove(hash) {
            let count = self.account_counts.entry(entry.parsed.account).or_insert(1);
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.account_counts.remove(&entry.parsed.account);
            }
            true
        } else {
            false
        }
    }

    /// Update fee metrics after a ledger closes.
    pub fn update_metrics(&mut self, tx_count: u64, slow_consensus: bool) {
        self.metrics.update(tx_count, slow_consensus);
    }
}

impl Default for TxPool {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
    use crate::transaction::{builder::TxBuilder, parse_blob, Amount};

    fn genesis_kp() -> KeyPair {
        KeyPair::Secp256k1(Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap())
    }

    fn make_signed_tx(seq: u32) -> (Vec<u8>, [u8; 32]) {
        let kp = genesis_kp();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(seq)
            .sign(&kp)
            .unwrap();
        (signed.blob, signed.hash)
    }

    #[test]
    fn test_insert_and_drain() {
        let mut pool = TxPool::new();
        let (blob, hash) = make_signed_tx(1);
        let parsed = parse_blob(&blob).unwrap();
        assert!(pool.insert(hash, blob, &parsed));
        assert_eq!(pool.len(), 1);

        let entries = pool.drain_sorted();
        assert_eq!(entries.len(), 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut pool = TxPool::new();
        let (blob, hash) = make_signed_tx(1);
        let parsed = parse_blob(&blob).unwrap();
        assert!(pool.insert(hash, blob.clone(), &parsed));
        assert!(!pool.insert(hash, blob, &parsed));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_drain_sorted_by_fee_desc() {
        let mut pool = TxPool::new();
        // Insert in sequence order — all have same fee so will sort by account+seq
        for seq in [3u32, 1, 2] {
            let (blob, hash) = make_signed_tx(seq);
            let parsed = parse_blob(&blob).unwrap();
            pool.insert(hash, blob, &parsed);
        }
        let entries = pool.drain_sorted();
        let seqs: Vec<u32> = entries.iter().map(|e| e.parsed.sequence).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn test_remove() {
        let mut pool = TxPool::new();
        let (blob, hash) = make_signed_tx(1);
        let parsed = parse_blob(&blob).unwrap();
        pool.insert(hash, blob, &parsed);
        assert!(pool.remove(&hash));
        assert!(pool.is_empty());
        assert!(!pool.remove(&hash));
    }

    #[test]
    fn test_canonical_set_hash_is_order_independent() {
        let mut a = TxPool::new();
        let mut b = TxPool::new();

        let (blob1, hash1) = make_signed_tx(1);
        let parsed1 = parse_blob(&blob1).unwrap();
        let (blob2, hash2) = make_signed_tx(2);
        let parsed2 = parse_blob(&blob2).unwrap();

        a.insert(hash1, blob1.clone(), &parsed1);
        a.insert(hash2, blob2.clone(), &parsed2);

        b.insert(hash2, blob2, &parsed2);
        b.insert(hash1, blob1, &parsed1);

        assert_eq!(a.canonical_set_hash(), b.canonical_set_hash());
    }

    #[test]
    fn test_canonical_set_hash_empty_is_zero() {
        let pool = TxPool::new();
        assert_eq!(pool.canonical_set_hash(), [0u8; 32]);
    }

    #[test]
    fn test_fee_escalation_below_target() {
        let m = FeeMetrics {
            escalation_multiplier: 128_000,
            txns_expected: 32,
        };
        // Below target: should return base level
        assert_eq!(m.escalated_fee_level(10), BASE_LEVEL);
        assert_eq!(m.escalated_fee_level(32), BASE_LEVEL);
    }

    #[test]
    fn test_fee_escalation_above_target() {
        let m = FeeMetrics {
            escalation_multiplier: 128_000,
            txns_expected: 32,
        };
        // At 64 txs (2× target): 128000 × 64² / 32² = 128000 × 4 = 512,000
        assert_eq!(m.escalated_fee_level(64), 512_000);
        // At 96 txs (3× target): 128000 × 9 = 1,152,000
        assert_eq!(m.escalated_fee_level(96), 1_152_000);
    }

    #[test]
    fn test_fee_level_roundtrip() {
        let base_fee = 10;
        let fee_drops = 1000u64;
        let level = FeeMetrics::fee_level_from_drops(fee_drops, base_fee);
        assert_eq!(level, 25600); // 1000 * 256 / 10
        let back = FeeMetrics::fee_level_to_drops(level, base_fee);
        assert_eq!(back, fee_drops);
    }

    #[test]
    fn test_metrics_update_healthy() {
        let mut m = FeeMetrics {
            escalation_multiplier: 128_000,
            txns_expected: 32,
        };
        // Ledger with 50 txs (above target) and healthy consensus
        m.update(50, false);
        assert_eq!(m.txns_expected, 38); // 32 * 6/5 = 38
    }

    #[test]
    fn test_metrics_update_slow() {
        let mut m = FeeMetrics {
            escalation_multiplier: 128_000,
            txns_expected: 64,
        };
        m.update(100, true);
        assert_eq!(m.txns_expected, 32); // 64 / 2 = 32 (floor at MIN)
    }

    #[test]
    fn test_per_account_limit() {
        let mut pool = TxPool::new();
        for seq in 1..=11 {
            let (blob, hash) = make_signed_tx(seq);
            let parsed = parse_blob(&blob).unwrap();
            let inserted = pool.insert(hash, blob, &parsed);
            if seq <= 10 {
                assert!(inserted, "should accept seq {seq}");
            } else {
                assert!(!inserted, "should reject seq {seq} (per-account limit)");
            }
        }
        assert_eq!(pool.len(), 10);
    }
}
