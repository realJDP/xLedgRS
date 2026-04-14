//! InboundLedger — per-hash ledger acquisition, modeled after rippled's
//! InboundLedger / InboundLedgers.
//!
//! Each ledger acquisition has its own slot keyed by hash. Responses are
//! routed by hash — no shared channel. Unknown hashes are dropped at the
//! gate. Completion uses state + watch signal (not Notify) so late readers
//! always see the current state — matching rippled's cache + job pattern.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ledger::LedgerHeader;

/// Tracks the acquisition of a single ledger, identified by hash.
pub struct InboundLedger {
    /// Target hash — frozen at creation.
    pub ledger_hash: [u8; 32],
    /// Expected sequence (for logging).
    pub ledger_seq: u32,
    /// Filled when liBASE response arrives.
    pub header: Option<LedgerHeader>,
    /// Filled when liTX_NODE response arrives: (tx_blob, meta_blob) pairs.
    pub tx_blobs: Option<Vec<(Vec<u8>, Vec<u8>)>>,
    /// Watch channel — stores completion state. Late readers always see it.
    watch_tx: Arc<tokio::sync::watch::Sender<bool>>,
    pub watch_rx: tokio::sync::watch::Receiver<bool>,
    /// For timeout cleanup.
    pub created_at: Instant,
    /// How many times we've retried requests for this acquisition.
    pub retry_count: u8,
    /// When we last sent retry requests (creation counts as first attempt).
    pub last_retry: Instant,
}

impl InboundLedger {
    pub fn new(ledger_hash: [u8; 32], ledger_seq: u32) -> Self {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let now = Instant::now();
        Self {
            ledger_hash,
            ledger_seq,
            header: None,
            tx_blobs: None,
            watch_tx: Arc::new(tx),
            watch_rx: rx,
            created_at: now,
            retry_count: 0,
            last_retry: now,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.header.is_some() && self.tx_blobs.is_some()
    }

    /// Ingest a liBASE header. Returns true if now complete.
    pub fn got_header(&mut self, header: LedgerHeader) -> bool {
        if self.header.is_some() { return false; }
        if header.hash != self.ledger_hash { return false; }
        if header.transaction_hash == [0u8; 32] {
            self.tx_blobs = Some(Vec::new());
        }
        self.header = Some(header);
        if self.is_complete() {
            let _ = self.watch_tx.send(true);
            true
        } else {
            false
        }
    }

    /// Ingest a liTX_NODE response. Returns true if now complete.
    pub fn got_tx_data(&mut self, nodes: &[crate::proto::TmLedgerNode]) -> bool {
        if self.tx_blobs.is_some() { return false; }
        let blobs = crate::ledger::close::extract_tx_blobs_from_tx_tree(nodes);
        self.tx_blobs = Some(blobs);
        if self.is_complete() {
            let _ = self.watch_tx.send(true);
            true
        } else {
            false
        }
    }
}

/// Collection of active acquisitions, keyed by ledger hash.
pub struct InboundLedgers {
    map: HashMap<[u8; 32], InboundLedger>,
    /// Sequence → hash lookup, populated by got_header for follower catch-up.
    seq_hashes: HashMap<u32, [u8; 32]>,
    /// Sequence → header cache for headers that arrived before a per-hash
    /// acquisition existed. This lets the follower request by sequence and
    /// later attach the real header once it knows the hash.
    seq_headers: HashMap<u32, LedgerHeader>,
}

impl InboundLedgers {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            seq_hashes: HashMap::new(),
            seq_headers: HashMap::new(),
        }
    }

    /// Look up a ledger hash by sequence (populated by got_header).
    pub fn hash_for_seq(&self, seq: u32) -> Option<[u8; 32]> {
        self.seq_hashes.get(&seq).copied()
    }

    /// Get a cached header by sequence if one arrived before acquisition
    /// registration.
    pub fn header_for_seq(&self, seq: u32) -> Option<LedgerHeader> {
        self.seq_headers.get(&seq).cloned()
    }

    /// Remove and return a cached header by sequence.
    pub fn take_header_for_seq(&mut self, seq: u32) -> Option<LedgerHeader> {
        self.seq_headers.remove(&seq)
    }

    /// Forget a cached sequence candidate when it proved unusable.
    /// This lets the follower retry the same sequence and wait for a
    /// different header/hash instead of reusing the known-bad one.
    pub fn reject_seq_candidate(&mut self, seq: u32, hash: [u8; 32]) {
        if self.seq_hashes.get(&seq).copied() == Some(hash) {
            self.seq_hashes.remove(&seq);
        }
        if self
            .seq_headers
            .get(&seq)
            .map(|hdr| hdr.hash == hash)
            .unwrap_or(false)
        {
            self.seq_headers.remove(&seq);
        }
    }

    /// Get a reference to an InboundLedger by hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<&InboundLedger> {
        self.map.get(hash)
    }

    /// Create or get an acquisition. Returns a watch receiver that
    /// the caller can await — it will see `true` when complete, even
    /// if the completion happened before the caller starts watching.
    pub fn create(&mut self, hash: [u8; 32], seq: u32) -> tokio::sync::watch::Receiver<bool> {
        let is_new = !self.map.contains_key(&hash);
        let total = self.map.len();
        let il = self.map.entry(hash)
            .or_insert_with(|| InboundLedger::new(hash, seq));
        if is_new {
            tracing::info!(
                "inbound_ledgers.create: NEW hash={} seq={} total={}",
                hex::encode_upper(&hash[..8]), seq, total + 1,
            );
        } else {
            tracing::info!(
                "inbound_ledgers.create: EXISTING hash={} seq={} has_header={} has_tx={} complete={}",
                hex::encode_upper(&hash[..8]), seq, il.header.is_some(), il.tx_blobs.is_some(), il.is_complete(),
            );
        }
        il.watch_rx.clone()
    }

    /// Route a liBASE header by hash. Drops if unknown.
    /// Also records seq→hash for follower catch-up lookups.
    pub fn got_header(&mut self, hash: &[u8; 32], header: LedgerHeader) -> bool {
        // Always record seq→hash for follower catch-up
        if header.sequence > 0 {
            self.seq_hashes.insert(header.sequence, *hash);
            // Keep the map bounded
            if self.seq_hashes.len() > 1024 {
                let min_seq = self.seq_hashes.keys().copied().min().unwrap_or(0);
                self.seq_hashes.remove(&min_seq);
            }
        }
        match self.map.get_mut(hash) {
            Some(il) => {
                let was_complete = il.is_complete();
                let result = il.got_header(header);
                self.seq_headers.remove(&il.ledger_seq);
                tracing::info!(
                    "inbound_ledgers.got_header: hash={} seq={} matched=true was_complete={} now_complete={}",
                    hex::encode_upper(&hash[..8]), il.ledger_seq, was_complete, il.is_complete(),
                );
                result
            }
            None => {
                if header.sequence > 0 {
                    self.seq_headers.insert(header.sequence, header.clone());
                    if self.seq_headers.len() > 1024 {
                        let min_seq = self.seq_headers.keys().copied().min().unwrap_or(0);
                        self.seq_headers.remove(&min_seq);
                    }
                }
                tracing::info!(
                    "inbound_ledgers.got_header: hash={} seq={} NO ACQUISITION (pending={}, cached_by_seq=true)",
                    hex::encode_upper(&hash[..8]),
                    header.sequence,
                    self.map.len(),
                );
                false
            }
        }
    }

    /// Route a liTX_NODE response by hash. If no acquisition exists yet,
    /// create one and buffer the TX data — the header may arrive shortly after.
    pub fn got_tx_data(&mut self, hash: &[u8; 32], nodes: &[crate::proto::TmLedgerNode]) -> bool {
        if let Some(il) = self.map.get_mut(hash) {
            let was_complete = il.is_complete();
            let result = il.got_tx_data(nodes);
            tracing::info!(
                "inbound_ledgers.got_tx_data: hash={} seq={} matched=true nodes={} was_complete={} now_complete={}",
                hex::encode_upper(&hash[..8]), il.ledger_seq, nodes.len(), was_complete, il.is_complete(),
            );
            return result;
        }
        // TX data arrived before header — create acquisition and buffer it.
        tracing::debug!(
            "inbound_ledgers.got_tx_data: hash={} NO ACQUISITION — auto-creating (nodes={})",
            hex::encode_upper(&hash[..8]), nodes.len(),
        );
        let mut il = InboundLedger::new(*hash, 0);
        il.got_tx_data(nodes);
        self.map.insert(*hash, il);
        false
    }

    /// Check if complete.
    pub fn is_complete(&self, hash: &[u8; 32]) -> bool {
        self.map.get(hash).map_or(false, |il| il.is_complete())
    }

    /// Take a completed acquisition out. Returns (header, tx_blobs).
    pub fn take(&mut self, hash: &[u8; 32]) -> Option<(LedgerHeader, Vec<(Vec<u8>, Vec<u8>)>)> {
        let complete = self.is_complete(hash);
        if !complete {
            // Diagnostic: why isn't it complete?
            if let Some(il) = self.map.get(hash) {
                tracing::info!(
                    "inbound_ledgers.take: hash={} seq={} INCOMPLETE has_header={} has_tx={} age={:.1}s",
                    hex::encode_upper(&hash[..8]), il.ledger_seq,
                    il.header.is_some(), il.tx_blobs.is_some(),
                    il.created_at.elapsed().as_secs_f64(),
                );
            } else {
                tracing::info!(
                    "inbound_ledgers.take: hash={} NOT FOUND (pending={})",
                    hex::encode_upper(&hash[..8]), self.map.len(),
                );
            }
            return None;
        }
        let il = self.map.remove(hash)?;
        tracing::info!(
            "inbound_ledgers.take: hash={} seq={} COMPLETE tx_count={}",
            hex::encode_upper(&hash[..8]), il.ledger_seq,
            il.tx_blobs.as_ref().map_or(0, |b| b.len()),
        );
        Some((il.header.unwrap(), il.tx_blobs.unwrap()))
    }

    /// Remove stale acquisitions older than max_age.
    pub fn sweep(&mut self, max_age: Duration) -> usize {
        let before = self.map.len();
        self.map.retain(|_, il| il.created_at.elapsed() < max_age);
        before - self.map.len()
    }

    pub fn len(&self) -> usize { self.map.len() }

    /// Returns incomplete acquisitions that are eligible for retry.
    /// Criteria: not complete, retry_count < 6, last_retry >= 3s ago.
    /// Read-only — does not mutate state.
    pub fn needs_retry(&self) -> Vec<([u8; 32], u32, bool, bool)> {
        let mut out = Vec::new();
        for il in self.map.values() {
            if il.is_complete() { continue; }
            if il.retry_count >= 6 { continue; }
            if il.last_retry.elapsed() < Duration::from_secs(3) { continue; }
            out.push((
                il.ledger_hash,
                il.ledger_seq,
                il.header.is_none(),   // needs_header
                il.tx_blobs.is_none(), // needs_tx
            ));
        }
        out
    }

    /// Mark an acquisition as retried. Returns the new retry_count.
    /// Call immediately after sending retry requests.
    pub fn mark_retried(&mut self, hash: &[u8; 32]) -> u8 {
        if let Some(il) = self.map.get_mut(hash) {
            il.retry_count = il.retry_count.saturating_add(1);
            il.last_retry = Instant::now();
            il.retry_count
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(seq: u32) -> LedgerHeader {
        let mut hdr = LedgerHeader {
            sequence: seq,
            hash: [0u8; 32],
            parent_hash: [0x11; 32],
            close_time: seq as u64,
            total_coins: 100_000_000_000_000_000,
            account_hash: [0x22; 32],
            transaction_hash: [0x33; 32],
            parent_close_time: seq.saturating_sub(1),
            close_time_resolution: 10,
            close_flags: 0,
        };
        hdr.hash = hdr.compute_hash();
        hdr
    }

    #[test]
    fn unknown_header_is_cached_by_sequence() {
        let hdr = header(123);
        let mut inbound = InboundLedgers::new();

        assert!(!inbound.got_header(&hdr.hash, hdr.clone()));
        assert_eq!(inbound.hash_for_seq(123), Some(hdr.hash));
        assert_eq!(inbound.header_for_seq(123).map(|h| h.hash), Some(hdr.hash));
    }

    #[test]
    fn cached_sequence_header_can_be_attached_after_create() {
        let hdr = header(456);
        let mut inbound = InboundLedgers::new();

        assert!(!inbound.got_header(&hdr.hash, hdr.clone()));
        let _ = inbound.create(hdr.hash, hdr.sequence);
        let cached = inbound.take_header_for_seq(hdr.sequence).expect("cached header");
        assert!(!inbound.is_complete(&hdr.hash));
        assert!(!inbound.got_header(&hdr.hash, cached));
        assert!(inbound.get(&hdr.hash).and_then(|il| il.header.as_ref()).is_some());
    }
}
