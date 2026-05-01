//! xLedgRS purpose: Inbound support for XRPL ledger state and SHAMap logic.
//! InboundLedger — per-hash ledger acquisition, modeled after rippled's
//! InboundLedger / InboundLedgers.
//!
//! Each ledger acquisition has its own slot keyed by hash. Responses are
//! routed by hash — no shared channel. Unknown hashes are dropped at the
//! gate. Completion uses state + watch signal (not Notify) so late readers
//! always see the current state — matching rippled's cache + job pattern.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ledger::LedgerHeader;

pub(crate) const LEDGER_ACQUIRE_TIMEOUT: Duration = Duration::from_millis(3_000);
pub(crate) const LEDGER_TIMEOUT_RETRIES_MAX: u8 = 6;
pub(crate) const LEDGER_REACQUIRE_INTERVAL: Duration = Duration::from_secs(300);
pub(crate) const LEDGER_BECOME_AGGRESSIVE_THRESHOLD: u8 = 4;
pub(crate) const MISSING_NODES_FIND: usize = 256;
pub(crate) const REQ_NODES_REPLY: usize = 128;
pub(crate) const REQ_NODES_TIMEOUT: usize = 12;
pub(crate) const REPLY_FOLLOWUP_PEERS: usize = 6;
pub(crate) const TIMEOUT_FOLLOWUP_PEERS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundReason {
    History,
    Generic,
    Consensus,
}

impl InboundReason {
    fn label(self) -> &'static str {
        match self {
            InboundReason::History => "history",
            InboundReason::Generic => "generic",
            InboundReason::Consensus => "consensus",
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutTick {
    Progress,
    Timeout(u32),
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct TimeoutCounterState {
    pub timeout_interval: Duration,
    pub timeouts: u32,
    pub complete: bool,
    pub failed: bool,
    pub progress: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
impl TimeoutCounterState {
    pub fn new(timeout_interval: Duration) -> Self {
        Self {
            timeout_interval,
            timeouts: 0,
            complete: false,
            failed: false,
            progress: false,
        }
    }

    pub fn is_done(&self) -> bool {
        self.complete || self.failed
    }

    pub fn note_progress(&mut self) {
        self.progress = true;
    }

    pub fn mark_complete(&mut self) {
        self.complete = true;
        self.progress = true;
    }

    pub fn mark_failed(&mut self) {
        self.failed = true;
    }

    pub fn on_timer_tick(&mut self) -> Option<TimeoutTick> {
        if self.is_done() {
            return None;
        }
        if self.progress {
            self.progress = false;
            Some(TimeoutTick::Progress)
        } else {
            self.timeouts = self.timeouts.saturating_add(1);
            Some(TimeoutTick::Timeout(self.timeouts))
        }
    }
}

/// Tracks the acquisition of a single ledger, identified by hash.
pub struct InboundLedger {
    /// Target hash — frozen at creation.
    pub ledger_hash: [u8; 32],
    /// Expected sequence (for logging).
    pub ledger_seq: u32,
    /// Reason for acquiring this ledger.
    pub reason: InboundReason,
    /// Filled when liBASE response arrives.
    pub header: Option<LedgerHeader>,
    /// Filled when liTX_NODE response arrives: (tx_blob, meta_blob) pairs.
    pub tx_blobs: Option<Vec<(Vec<u8>, Vec<u8>)>>,
    /// Transaction tree root computed directly from the received wire nodes.
    tx_root: Option<[u8; 32]>,
    /// Indexed liTX_NODE wire nodes collected across one or more replies.
    tx_wire_nodes: BTreeMap<[u8; 33], Vec<u8>>,
    /// Watch channel — stores completion state. Late readers always see it.
    watch_tx: Arc<tokio::sync::watch::Sender<bool>>,
    pub watch_rx: tokio::sync::watch::Receiver<bool>,
    /// For timeout cleanup.
    pub created_at: Instant,
    /// Last meaningful interaction with this acquisition.
    pub last_action: Instant,
    /// Last time this acquisition's timer advanced.
    pub last_timeout: Instant,
    /// rippled-style timeout/progress bookkeeping for this acquisition.
    pub timeout: TimeoutCounterState,
    /// Recently requested node hashes for duplicate suppression.
    pub recent_nodes: HashSet<[u8; 32]>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboundLedgerSummary {
    pub ledger_hash: String,
    pub ledger_seq: u32,
    pub reason: String,
    pub has_header: bool,
    pub has_transactions: bool,
    pub complete: bool,
    pub failed: bool,
    pub timeout_count: u32,
    pub age_ms: u64,
    pub idle_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboundLedgersSnapshot {
    pub active: usize,
    pub complete: usize,
    pub failed: usize,
    pub retry_ready: usize,
    pub stale: usize,
    pub fetch_rate: usize,
    pub fetched_total: u64,
    pub fetch_pack_hits: u64,
    pub cache_size: usize,
    pub sweep_total: u64,
    pub last_sweep_removed: usize,
    pub last_sweep_unix: Option<u64>,
    pub stop_total: u64,
    pub last_stop_unix: Option<u64>,
    pub cached_seq_hashes: usize,
    pub cached_seq_headers: usize,
    pub recent_failures: usize,
    pub history: usize,
    pub generic: usize,
    pub consensus: usize,
    pub entries: Vec<InboundLedgerSummary>,
}

impl InboundLedger {
    pub fn new(ledger_hash: [u8; 32], ledger_seq: u32) -> Self {
        Self::with_reason(ledger_hash, ledger_seq, InboundReason::Generic)
    }

    pub fn with_reason(ledger_hash: [u8; 32], ledger_seq: u32, reason: InboundReason) -> Self {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let now = Instant::now();
        Self {
            ledger_hash,
            ledger_seq,
            reason,
            header: None,
            tx_blobs: None,
            tx_root: None,
            tx_wire_nodes: BTreeMap::new(),
            watch_tx: Arc::new(tx),
            watch_rx: rx,
            created_at: now,
            last_action: now,
            last_timeout: now,
            timeout: TimeoutCounterState::new(LEDGER_ACQUIRE_TIMEOUT),
            recent_nodes: HashSet::with_capacity(256),
        }
    }

    pub fn update(&mut self, ledger_seq: u32) {
        if self.ledger_seq == 0 && ledger_seq != 0 {
            self.ledger_seq = ledger_seq;
        }
        self.touch();
    }

    pub fn is_complete(&self) -> bool {
        self.timeout.complete || (self.header.is_some() && self.tx_blobs.is_some())
    }

    pub fn is_failed(&self) -> bool {
        self.timeout.failed
    }

    pub fn touch(&mut self) {
        self.last_action = Instant::now();
    }

    pub fn clear_recent_nodes(&mut self) {
        self.recent_nodes.clear();
    }

    /// Ingest a liBASE header. Returns true if now complete.
    pub fn got_header(&mut self, header: LedgerHeader) -> bool {
        if self.header.is_some() {
            return false;
        }
        if header.hash != self.ledger_hash {
            return false;
        }
        if header.transaction_hash == [0u8; 32] {
            self.tx_blobs = Some(Vec::new());
            self.tx_root = Some([0u8; 32]);
        } else {
            self.try_finalize_tx_tree();
        }
        self.header = Some(header);
        self.touch();
        self.timeout.note_progress();
        if self.is_complete() {
            self.timeout.mark_complete();
            let _ = self.watch_tx.send(true);
            true
        } else {
            false
        }
    }

    /// Ingest a liTX_NODE response. Returns true if now complete.
    pub fn got_tx_data(&mut self, nodes: &[crate::proto::TmLedgerNode]) -> bool {
        if self.tx_blobs.is_some() {
            return false;
        }
        self.merge_tx_wire_nodes(nodes);
        self.try_finalize_tx_tree();
        self.touch();
        self.timeout.note_progress();
        if self.is_complete() {
            self.timeout.mark_complete();
            let _ = self.watch_tx.send(true);
            true
        } else {
            false
        }
    }

    pub fn missing_tx_node_ids(&self, limit: usize) -> Vec<Vec<u8>> {
        if self.tx_blobs.is_some() {
            return Vec::new();
        }
        let mut missing = missing_tx_node_ids_from_wire_nodes(&self.tx_wire_nodes);
        if missing.len() > limit {
            missing.truncate(limit);
        }
        missing.into_iter().map(|id| id.to_vec()).collect()
    }

    fn merge_tx_wire_nodes(&mut self, nodes: &[crate::proto::TmLedgerNode]) {
        for node in nodes {
            let Some(node_id) = node.nodeid.as_deref().and_then(copy_node_id) else {
                continue;
            };
            self.tx_wire_nodes
                .entry(node_id)
                .or_insert_with(|| node.nodedata.clone());
        }
    }

    fn try_finalize_tx_tree(&mut self) {
        if self.tx_blobs.is_some() {
            return;
        }
        if !missing_tx_node_ids_from_wire_nodes(&self.tx_wire_nodes).is_empty() {
            return;
        }

        let indexed_nodes: Vec<_> = self
            .tx_wire_nodes
            .iter()
            .map(|(node_id, nodedata)| crate::proto::TmLedgerNode {
                nodedata: nodedata.clone(),
                nodeid: Some(node_id.to_vec()),
            })
            .collect();
        self.tx_root = compute_tx_root_from_wire_nodes(&indexed_nodes);
        self.tx_blobs = Some(crate::ledger::close::extract_tx_blobs_from_tx_tree(
            &indexed_nodes,
        ));
    }
}

fn copy_node_id(raw: &[u8]) -> Option<[u8; 33]> {
    if raw.len() != 33 {
        return None;
    }
    let mut node_id = [0u8; 33];
    node_id.copy_from_slice(raw);
    Some(node_id)
}

fn wire_inner_child_hashes(data: &[u8]) -> Option<[[u8; 32]; 16]> {
    if data.is_empty() {
        return None;
    }
    let (body, wire_type) = (data.get(..data.len() - 1)?, *data.last()?);
    if wire_type != 0x02 && wire_type != 0x03 {
        return None;
    }

    let start = if body.len() >= 516
        && body[0] == 0x4D
        && body[1] == 0x49
        && body[2] == 0x4E
        && body[3] == 0x00
    {
        4usize
    } else if body.len() == 512 {
        0usize
    } else {
        return None;
    };

    if body.len() < start + 512 {
        return None;
    }

    let mut child_hashes = [[0u8; 32]; 16];
    for (branch, child_hash) in child_hashes.iter_mut().enumerate() {
        let off = start + branch * 32;
        child_hash.copy_from_slice(&body[off..off + 32]);
    }
    Some(child_hashes)
}

fn missing_tx_node_ids_from_wire_nodes(
    tx_wire_nodes: &BTreeMap<[u8; 33], Vec<u8>>,
) -> Vec<[u8; 33]> {
    let root = crate::ledger::shamap_id::SHAMapNodeID::root().to_wire();
    if !tx_wire_nodes.contains_key(&root) {
        return vec![root];
    }

    let mut missing = Vec::new();
    let mut stack = vec![crate::ledger::shamap_id::SHAMapNodeID::root()];
    let mut visited = HashSet::new();

    while let Some(node_id) = stack.pop() {
        if !visited.insert(node_id.to_wire()) {
            continue;
        }
        let Some(nodedata) = tx_wire_nodes.get(&node_id.to_wire()) else {
            missing.push(node_id.to_wire());
            continue;
        };
        let Some(child_hashes) = wire_inner_child_hashes(nodedata) else {
            continue;
        };
        for (branch, child_hash) in child_hashes.iter().enumerate() {
            if *child_hash == [0u8; 32] {
                continue;
            }
            let child_id = node_id.child_id(branch as u8);
            if tx_wire_nodes.contains_key(&child_id.to_wire()) {
                stack.push(child_id);
            } else {
                missing.push(child_id.to_wire());
            }
        }
    }

    missing.sort_unstable();
    missing.dedup();
    missing
}

fn compute_tx_root_from_wire_nodes(nodes: &[crate::proto::TmLedgerNode]) -> Option<[u8; 32]> {
    let mut tx_map = crate::ledger::shamap::SHAMap::new_transaction();
    let mut full_below = crate::ledger::full_below_cache::FullBelowCache::new(256);

    for node in nodes {
        let node_id = node
            .nodeid
            .as_deref()
            .and_then(crate::ledger::shamap_id::SHAMapNodeID::from_wire)?;
        let result = crate::ledger::shamap_sync::add_known_node(
            &mut tx_map.root,
            &node_id,
            &node.nodedata,
            crate::ledger::shamap::MapType::Transaction,
            None,
            &mut full_below,
        );
        if matches!(result, crate::ledger::shamap_sync::AddNodeResult::Invalid) {
            return None;
        }
    }

    Some(tx_map.root_hash())
}

/// Collection of active acquisitions, keyed by ledger hash.
pub struct InboundLedgers {
    map: HashMap<[u8; 32], InboundLedger>,
    /// Sequence → hash lookup, populated by got_header for follower catch-up.
    seq_hashes: HashMap<u32, [u8; 32]>,
    /// Sequence → header cache for headers that arrived before a per-hash
    /// acquisition existed. This allows the follower to request by sequence
    /// and later attach the real header once the hash is known.
    seq_headers: HashMap<u32, LedgerHeader>,
    /// Recently failed acquisitions; used to back off reacquire attempts.
    recent_failures: HashMap<[u8; 32], (u32, Instant)>,
    /// Rolling window of completed historical ledger fetches.
    fetch_history: VecDeque<Instant>,
    /// Total count of completed historical ledger fetches.
    fetched_total: u64,
    /// Count of fetch-pack progress notifications.
    fetch_pack_hits: u64,
    /// Number of sweep passes executed.
    sweep_total: u64,
    /// Number of acquisitions removed by the most recent sweep.
    last_sweep_removed: usize,
    /// Wall-clock timestamp of the most recent sweep.
    last_sweep_unix: Option<u64>,
    /// Number of stop passes executed.
    stop_total: u64,
    /// Wall-clock timestamp of the most recent stop.
    last_stop_unix: Option<u64>,
}

impl InboundLedgers {
    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn prune_fetch_history(&mut self, now: Instant) {
        while self
            .fetch_history
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) > Duration::from_secs(60))
        {
            self.fetch_history.pop_front();
        }
    }

    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            seq_hashes: HashMap::new(),
            seq_headers: HashMap::new(),
            recent_failures: HashMap::new(),
            fetch_history: VecDeque::new(),
            fetched_total: 0,
            fetch_pack_hits: 0,
            sweep_total: 0,
            last_sweep_removed: 0,
            last_sweep_unix: None,
            stop_total: 0,
            last_stop_unix: None,
        }
    }

    pub fn snapshot(&self, limit: usize) -> InboundLedgersSnapshot {
        let now = Instant::now();
        let fetch_rate = self
            .fetch_history
            .iter()
            .filter(|at| now.saturating_duration_since(**at) <= Duration::from_secs(60))
            .count();
        let mut entries: Vec<_> = self
            .map
            .values()
            .map(|ledger| InboundLedgerSummary {
                ledger_hash: hex::encode_upper(ledger.ledger_hash),
                ledger_seq: ledger.ledger_seq,
                reason: ledger.reason.label().to_string(),
                has_header: ledger.header.is_some(),
                has_transactions: ledger.tx_blobs.is_some(),
                complete: ledger.is_complete(),
                failed: ledger.is_failed(),
                timeout_count: ledger.timeout.timeouts,
                age_ms: ledger.created_at.elapsed().as_millis() as u64,
                idle_ms: now.duration_since(ledger.last_action).as_millis() as u64,
            })
            .collect();
        entries.sort_by(|a, b| {
            a.complete
                .cmp(&b.complete)
                .then(a.failed.cmp(&b.failed))
                .then(b.ledger_seq.cmp(&a.ledger_seq))
                .then(a.ledger_hash.cmp(&b.ledger_hash))
        });
        if entries.len() > limit {
            entries.truncate(limit);
        }

        let mut snapshot = InboundLedgersSnapshot {
            active: self.map.len(),
            complete: self
                .map
                .values()
                .filter(|ledger| ledger.is_complete())
                .count(),
            failed: self
                .map
                .values()
                .filter(|ledger| ledger.is_failed())
                .count(),
            retry_ready: self.retry_ready_count(),
            stale: self.stale_count(LEDGER_REACQUIRE_INTERVAL),
            fetch_rate,
            fetched_total: self.fetched_total,
            fetch_pack_hits: self.fetch_pack_hits,
            cache_size: self.cache_size(),
            sweep_total: self.sweep_total,
            last_sweep_removed: self.last_sweep_removed,
            last_sweep_unix: self.last_sweep_unix,
            stop_total: self.stop_total,
            last_stop_unix: self.last_stop_unix,
            cached_seq_hashes: self.seq_hashes.len(),
            cached_seq_headers: self.seq_headers.len(),
            recent_failures: self.recent_failures.len(),
            history: 0,
            generic: 0,
            consensus: 0,
            entries,
        };
        for ledger in self.map.values() {
            match ledger.reason {
                InboundReason::History => snapshot.history += 1,
                InboundReason::Generic => snapshot.generic += 1,
                InboundReason::Consensus => snapshot.consensus += 1,
            }
        }
        snapshot
    }

    fn prune_recent_failures(&mut self) {
        self.recent_failures
            .retain(|_, (_, at)| at.elapsed() < LEDGER_REACQUIRE_INTERVAL);
    }

    pub fn fetch_rate(&mut self) -> usize {
        let now = Instant::now();
        self.prune_fetch_history(now);
        self.fetch_history.len()
    }

    pub fn on_ledger_fetched(&mut self, reason: InboundReason) {
        if reason != InboundReason::History {
            return;
        }
        let now = Instant::now();
        self.prune_fetch_history(now);
        self.fetch_history.push_back(now);
        self.fetched_total = self.fetched_total.saturating_add(1);
    }

    pub fn got_fetch_pack(&mut self) {
        self.fetch_pack_hits = self.fetch_pack_hits.saturating_add(1);
        for ledger in self.map.values_mut() {
            ledger.touch();
            ledger.timeout.note_progress();
            ledger.clear_recent_nodes();
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
    /// This allows the follower to retry the same sequence and wait for a
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

    pub fn find(&self, hash: &[u8; 32]) -> Option<&InboundLedger> {
        self.map.get(hash)
    }

    /// rippled-style acquire/create entry point.
    pub fn acquire(
        &mut self,
        hash: [u8; 32],
        seq: u32,
        reason: InboundReason,
    ) -> tokio::sync::watch::Receiver<bool> {
        self.prune_recent_failures();
        let is_new = !self.map.contains_key(&hash);
        let total = self.map.len();
        let il = self
            .map
            .entry(hash)
            .or_insert_with(|| InboundLedger::with_reason(hash, seq, reason));
        if !is_new {
            il.update(seq);
        }
        if is_new {
            tracing::info!(
                "inbound_ledgers.acquire: NEW hash={} seq={} reason={:?} total={}",
                hex::encode_upper(&hash[..8]),
                seq,
                reason,
                total + 1,
            );
        } else {
            tracing::info!(
                "inbound_ledgers.acquire: EXISTING hash={} seq={} reason={:?} has_header={} has_tx={} complete={}",
                hex::encode_upper(&hash[..8]), seq, il.reason, il.header.is_some(), il.tx_blobs.is_some(), il.is_complete(),
            );
        }
        il.watch_rx.clone()
    }

    /// Create or get an acquisition. Returns a watch receiver that
    /// the caller can await — it will see `true` when complete, even
    /// if the completion happened before the caller starts watching.
    pub fn create(&mut self, hash: [u8; 32], seq: u32) -> tokio::sync::watch::Receiver<bool> {
        self.acquire(hash, seq, InboundReason::Generic)
    }

    /// Route a liBASE header by hash. Drops if unknown.
    /// Also records seq→hash for follower catch-up lookups.
    pub fn got_header(&mut self, hash: &[u8; 32], header: LedgerHeader) -> bool {
        self.prune_recent_failures();
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
    /// create one and buffer the indexed TX tree nodes — the header may arrive
    /// shortly after, or a later follow-up may fill missing descendants.
    pub fn got_tx_data(&mut self, hash: &[u8; 32], nodes: &[crate::proto::TmLedgerNode]) -> bool {
        self.prune_recent_failures();
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
            hex::encode_upper(&hash[..8]),
            nodes.len(),
        );
        let mut il = InboundLedger::new(*hash, 0);
        il.got_tx_data(nodes);
        self.map.insert(*hash, il);
        false
    }

    pub fn missing_tx_node_ids(&self, hash: &[u8; 32], limit: usize) -> Vec<Vec<u8>> {
        self.map
            .get(hash)
            .map(|il| il.missing_tx_node_ids(limit))
            .unwrap_or_default()
    }

    /// Check if complete.
    pub fn is_complete(&self, hash: &[u8; 32]) -> bool {
        self.map.get(hash).map_or(false, |il| il.is_complete())
    }

    /// Take a completed acquisition out. Returns (header, tx_blobs, tx_root).
    pub fn take(
        &mut self,
        hash: &[u8; 32],
    ) -> Option<(LedgerHeader, Vec<(Vec<u8>, Vec<u8>)>, Option<[u8; 32]>)> {
        self.prune_recent_failures();
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
                    hex::encode_upper(&hash[..8]),
                    self.map.len(),
                );
            }
            return None;
        }
        let il = self.map.remove(hash)?;
        self.on_ledger_fetched(il.reason);
        tracing::info!(
            "inbound_ledgers.take: hash={} seq={} COMPLETE tx_count={}",
            hex::encode_upper(&hash[..8]),
            il.ledger_seq,
            il.tx_blobs.as_ref().map_or(0, |b| b.len()),
        );
        Some((il.header.unwrap(), il.tx_blobs.unwrap(), il.tx_root))
    }

    /// Remove stale acquisitions older than max_age.
    pub fn sweep(&mut self, max_age: Duration) -> usize {
        self.prune_recent_failures();
        let before = self.map.len();
        let mut removed = Vec::new();
        self.map.retain(|hash, il| {
            let keep = il.last_action.elapsed() < max_age;
            if !keep {
                removed.push((*hash, il.ledger_seq));
            }
            keep
        });
        let removed_count = removed.len();
        for (hash, seq) in removed {
            self.recent_failures.insert(hash, (seq, Instant::now()));
        }
        self.sweep_total = self.sweep_total.saturating_add(1);
        self.last_sweep_removed = removed_count;
        self.last_sweep_unix = Some(Self::unix_now());
        before - self.map.len()
    }

    /// Stop tracking all acquisitions, preserving a failure trace for the
    /// entries that were still active so the caller can back off cleanly.
    pub fn stop(&mut self) -> usize {
        self.prune_recent_failures();
        let removed = self.map.len();
        for (hash, il) in self.map.drain() {
            self.recent_failures
                .insert(hash, (il.ledger_seq, Instant::now()));
        }
        self.seq_hashes.clear();
        self.seq_headers.clear();
        self.stop_total = self.stop_total.saturating_add(1);
        self.last_stop_unix = Some(Self::unix_now());
        removed
    }

    /// Count acquisitions that are overdue for another retry tick.
    pub fn retry_ready_count(&self) -> usize {
        self.map
            .values()
            .filter(|il| !il.is_complete())
            .filter(|il| !il.is_failed())
            .filter(|il| il.last_timeout.elapsed() >= LEDGER_ACQUIRE_TIMEOUT)
            .count()
    }

    /// Count acquisitions that have gone stale by the normal reacquire budget.
    pub fn stale_count(&self, max_age: Duration) -> usize {
        self.map
            .values()
            .filter(|il| !il.is_complete())
            .filter(|il| !il.is_failed())
            .filter(|il| il.last_action.elapsed() >= max_age)
            .count()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns incomplete acquisitions that are eligible for retry.
    /// Mirrors rippled's timeout loop more closely: every timeout interval,
    /// advance the acquisition's timeout/progress state. Progress consumes
    /// the tick without retrying; no-progress produces a retry; too many
    /// timeouts marks the acquisition failed and logs a recent failure.
    pub fn needs_retry(&mut self) -> Vec<([u8; 32], u32, bool, bool)> {
        self.prune_recent_failures();
        let mut out = Vec::new();
        let mut failed = Vec::new();
        for il in self.map.values_mut() {
            if il.is_complete() {
                continue;
            }
            if il.is_failed() {
                continue;
            }
            if il.last_timeout.elapsed() < LEDGER_ACQUIRE_TIMEOUT {
                continue;
            }
            il.last_timeout = Instant::now();
            il.touch();
            // Match rippled's InboundLedger::onTimer(): every timeout tick
            // opens a fresh duplicate-suppression window before evaluating
            // progress or emitting a retry.
            il.clear_recent_nodes();
            match il.timeout.on_timer_tick() {
                Some(TimeoutTick::Progress) | None => {}
                Some(TimeoutTick::Timeout(timeouts)) => {
                    if timeouts > u32::from(LEDGER_TIMEOUT_RETRIES_MAX) {
                        il.timeout.mark_failed();
                        failed.push((il.ledger_hash, il.ledger_seq));
                        continue;
                    }
                    out.push((
                        il.ledger_hash,
                        il.ledger_seq,
                        il.header.is_none(),   // needs_header
                        il.tx_blobs.is_none(), // needs_tx
                    ));
                }
            }
        }
        for (hash, seq) in failed {
            self.recent_failures.insert(hash, (seq, Instant::now()));
        }
        out
    }

    /// Mark an acquisition as retried. Returns the current timeout count.
    /// Call immediately after sending retry requests.
    pub fn mark_retried(&mut self, hash: &[u8; 32]) -> u8 {
        if let Some(il) = self.map.get_mut(hash) {
            il.touch();
            il.timeout.timeouts.min(u32::from(u8::MAX)) as u8
        } else {
            0
        }
    }

    pub fn log_failure(&mut self, hash: [u8; 32], seq: u32) {
        self.recent_failures.insert(hash, (seq, Instant::now()));
    }

    pub fn is_failure(&mut self, hash: &[u8; 32]) -> bool {
        self.prune_recent_failures();
        self.recent_failures.contains_key(hash)
    }

    pub fn clear_failures(&mut self) {
        self.recent_failures.clear();
    }

    pub fn cache_size(&self) -> usize {
        self.map.len()
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

    fn tx_fixture() -> (
        crate::ledger::LedgerHeader,
        crate::ledger::shamap::SHAMap,
        usize,
    ) {
        let mut leaves = Vec::new();
        let mut used_root_branches = std::collections::HashSet::new();
        for seed in 0u16..4096 {
            let tx_blob = vec![0x12, (seed >> 8) as u8, seed as u8];
            let tx_id = crate::transaction::serialize::tx_blob_hash(&tx_blob);
            if !used_root_branches.insert(tx_id[0] >> 4) {
                continue;
            }
            let meta_blob = vec![0xE0, seed as u8];
            leaves.push((tx_id, tx_blob, meta_blob));
            if leaves.len() == 2 {
                break;
            }
        }
        assert_eq!(leaves.len(), 2, "fixture needs two distinct root branches");

        let mut tx_map = crate::ledger::shamap::SHAMap::new_transaction();
        for (tx_id, tx_blob, meta_blob) in &leaves {
            let mut leaf_data = Vec::new();
            crate::transaction::serialize::encode_length(tx_blob.len(), &mut leaf_data);
            leaf_data.extend_from_slice(tx_blob);
            crate::transaction::serialize::encode_length(meta_blob.len(), &mut leaf_data);
            leaf_data.extend_from_slice(meta_blob);
            tx_map.insert(crate::ledger::Key(*tx_id), leaf_data);
        }

        let mut hdr = header(3001);
        hdr.transaction_hash = tx_map.root_hash();
        hdr.hash = hdr.compute_hash();
        (hdr, tx_map, leaves.len())
    }

    fn tm_nodes_from_wire(nodes: Vec<([u8; 33], Vec<u8>)>) -> Vec<crate::proto::TmLedgerNode> {
        nodes
            .into_iter()
            .map(|(nodeid, nodedata)| crate::proto::TmLedgerNode {
                nodedata,
                nodeid: Some(nodeid.to_vec()),
            })
            .collect()
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
        let cached = inbound
            .take_header_for_seq(hdr.sequence)
            .expect("cached header");
        assert!(!inbound.is_complete(&hdr.hash));
        assert!(!inbound.got_header(&hdr.hash, cached));
        assert!(inbound
            .get(&hdr.hash)
            .and_then(|il| il.header.as_ref())
            .is_some());
    }

    #[test]
    fn timeout_counter_matches_rippled_progress_then_timeout_cycle() {
        let mut timeout = TimeoutCounterState::new(LEDGER_ACQUIRE_TIMEOUT);

        assert_eq!(timeout.on_timer_tick(), Some(TimeoutTick::Timeout(1)));
        timeout.note_progress();
        assert_eq!(timeout.on_timer_tick(), Some(TimeoutTick::Progress));
        assert_eq!(timeout.on_timer_tick(), Some(TimeoutTick::Timeout(2)));
    }

    #[test]
    fn acquire_updates_existing_sequence_without_replacing_watcher() {
        let hdr = header(777);
        let mut inbound = InboundLedgers::new();

        let rx1 = inbound.acquire(hdr.hash, 0, InboundReason::History);
        let rx2 = inbound.acquire(hdr.hash, hdr.sequence, InboundReason::History);

        assert_eq!(rx1.borrow().to_owned(), rx2.borrow().to_owned());
        assert_eq!(
            inbound.get(&hdr.hash).map(|il| il.ledger_seq),
            Some(hdr.sequence)
        );
        assert_eq!(
            inbound.get(&hdr.hash).map(|il| il.reason),
            Some(InboundReason::History)
        );
    }

    #[test]
    fn recent_failures_expire_after_reacquire_interval() {
        let hdr = header(888);
        let mut inbound = InboundLedgers::new();

        inbound.log_failure(hdr.hash, hdr.sequence);
        assert!(inbound.is_failure(&hdr.hash));

        if let Some((_, at)) = inbound.recent_failures.get_mut(&hdr.hash) {
            *at = Instant::now() - (LEDGER_REACQUIRE_INTERVAL + Duration::from_secs(1));
        }

        assert!(!inbound.is_failure(&hdr.hash));
    }

    #[test]
    fn sweep_uses_last_action_not_creation_time() {
        let hdr = header(999);
        let mut inbound = InboundLedgers::new();

        let _ = inbound.create(hdr.hash, hdr.sequence);
        {
            let il = inbound.map.get_mut(&hdr.hash).expect("acquisition");
            il.created_at = Instant::now() - Duration::from_secs(120);
            il.last_action = Instant::now();
        }

        assert_eq!(inbound.sweep(Duration::from_secs(60)), 0);
        assert_eq!(inbound.cache_size(), 1);
    }

    #[test]
    fn sweep_marks_removed_acquisitions_as_recent_failures() {
        let hdr = header(1000);
        let mut inbound = InboundLedgers::new();

        let _ = inbound.create(hdr.hash, hdr.sequence);
        {
            let il = inbound.map.get_mut(&hdr.hash).expect("acquisition");
            il.last_action = Instant::now() - Duration::from_secs(90);
        }

        assert_eq!(inbound.sweep(Duration::from_secs(30)), 1);
        assert!(inbound.is_failure(&hdr.hash));
        assert_eq!(inbound.cache_size(), 0);
    }

    #[test]
    fn stop_clears_all_tracked_state_and_records_failures() {
        let hdr = header(1004);
        let mut inbound = InboundLedgers::new();

        let _ = inbound.acquire(hdr.hash, hdr.sequence, InboundReason::History);
        inbound.seq_hashes.insert(hdr.sequence, hdr.hash);
        inbound.seq_headers.insert(hdr.sequence, hdr.clone());

        assert_eq!(inbound.stop(), 1);
        assert_eq!(inbound.len(), 0);
        assert_eq!(inbound.hash_for_seq(hdr.sequence), None);
        assert!(inbound.header_for_seq(hdr.sequence).is_none());
        assert!(inbound.is_failure(&hdr.hash));
        assert_eq!(inbound.stop_total, 1);
        assert!(inbound.last_stop_unix.is_some());
    }

    #[test]
    fn retry_and_stale_counts_track_overdue_acquisitions() {
        let hdr = header(1005);
        let mut inbound = InboundLedgers::new();

        let _ = inbound.acquire(hdr.hash, hdr.sequence, InboundReason::Consensus);
        {
            let il = inbound.map.get_mut(&hdr.hash).expect("acquisition");
            il.last_timeout = Instant::now() - LEDGER_ACQUIRE_TIMEOUT;
            il.last_action = Instant::now() - LEDGER_REACQUIRE_INTERVAL;
        }

        assert_eq!(inbound.retry_ready_count(), 1);
        assert_eq!(inbound.stale_count(LEDGER_REACQUIRE_INTERVAL), 1);
    }

    #[test]
    fn taking_history_ledger_updates_fetch_rate_and_totals() {
        let mut hdr = header(1006);
        hdr.transaction_hash = [0u8; 32];
        hdr.hash = hdr.compute_hash();
        let mut inbound = InboundLedgers::new();

        let _ = inbound.acquire(hdr.hash, hdr.sequence, InboundReason::History);
        assert!(inbound.got_header(&hdr.hash, hdr.clone()));
        assert!(!inbound.got_tx_data(&hdr.hash, &[]));

        let taken = inbound.take(&hdr.hash);

        assert!(taken.is_some());
        assert_eq!(inbound.fetch_rate(), 1);
        assert_eq!(inbound.fetched_total, 1);
    }

    #[test]
    fn got_fetch_pack_marks_progress_for_active_acquisitions() {
        let hdr = header(1007);
        let mut inbound = InboundLedgers::new();

        let _ = inbound.acquire(hdr.hash, hdr.sequence, InboundReason::History);
        let ledger = inbound
            .map
            .get_mut(&hdr.hash)
            .expect("acquisition should exist");
        ledger.recent_nodes.insert([0xAB; 32]);
        ledger.timeout.progress = false;

        inbound.got_fetch_pack();

        let ledger = inbound
            .map
            .get(&hdr.hash)
            .expect("acquisition should remain");
        assert!(ledger.timeout.progress);
        assert!(ledger.recent_nodes.is_empty());
        assert_eq!(inbound.fetch_pack_hits, 1);
    }

    #[test]
    fn needs_retry_consumes_progress_before_retrying_again() {
        let hdr = header(1001);
        let mut inbound = InboundLedgers::new();

        let _ = inbound.acquire(hdr.hash, hdr.sequence, InboundReason::Generic);
        {
            let il = inbound.map.get_mut(&hdr.hash).expect("acquisition");
            il.last_timeout = Instant::now() - LEDGER_ACQUIRE_TIMEOUT;
            il.timeout.note_progress();
        }

        assert!(inbound.needs_retry().is_empty());

        {
            let il = inbound.map.get_mut(&hdr.hash).expect("acquisition");
            il.last_timeout = Instant::now() - LEDGER_ACQUIRE_TIMEOUT;
        }

        let retries = inbound.needs_retry();
        assert_eq!(retries.len(), 1);
        assert_eq!(retries[0].0, hdr.hash);
    }

    #[test]
    fn needs_retry_clears_recent_nodes_on_each_timer_tick() {
        let hdr = header(1003);
        let mut inbound = InboundLedgers::new();

        let _ = inbound.acquire(hdr.hash, hdr.sequence, InboundReason::Generic);
        {
            let il = inbound.map.get_mut(&hdr.hash).expect("acquisition");
            il.recent_nodes.insert([0x55; 32]);
            il.last_timeout = Instant::now() - LEDGER_ACQUIRE_TIMEOUT;
            il.timeout.note_progress();
        }

        assert!(inbound.needs_retry().is_empty());
        assert!(inbound
            .get(&hdr.hash)
            .expect("acquisition")
            .recent_nodes
            .is_empty());
    }

    #[test]
    fn needs_retry_marks_failure_after_timeout_budget_exhausted() {
        let hdr = header(1002);
        let mut inbound = InboundLedgers::new();

        let _ = inbound.acquire(hdr.hash, hdr.sequence, InboundReason::Generic);
        {
            let il = inbound.map.get_mut(&hdr.hash).expect("acquisition");
            il.timeout.timeouts = u32::from(LEDGER_TIMEOUT_RETRIES_MAX);
            il.last_timeout = Instant::now() - LEDGER_ACQUIRE_TIMEOUT;
        }

        assert!(inbound.needs_retry().is_empty());
        assert!(inbound.is_failure(&hdr.hash));
        assert!(inbound.get(&hdr.hash).expect("acquisition").is_failed());
    }

    #[test]
    fn snapshot_reports_reason_mix_and_cached_counts() {
        let history = header(2001);
        let consensus = header(2002);
        let generic = header(2003);
        let mut inbound = InboundLedgers::new();

        let _ = inbound.acquire(history.hash, history.sequence, InboundReason::History);
        let _ = inbound.acquire(consensus.hash, consensus.sequence, InboundReason::Consensus);
        let _ = inbound.acquire(generic.hash, generic.sequence, InboundReason::Generic);
        inbound.got_header(&history.hash, history.clone());
        inbound.got_header(&consensus.hash, consensus.clone());
        inbound.log_failure([0xEE; 32], 3000);
        inbound.seq_hashes.insert(77, [0xAB; 32]);
        inbound.seq_headers.insert(88, generic.clone());

        let snapshot = inbound.snapshot(8);

        assert_eq!(snapshot.active, 3);
        assert_eq!(snapshot.history, 1);
        assert_eq!(snapshot.consensus, 1);
        assert_eq!(snapshot.generic, 1);
        assert_eq!(snapshot.fetch_rate, 0);
        assert_eq!(snapshot.fetched_total, 0);
        assert_eq!(snapshot.fetch_pack_hits, 0);
        assert_eq!(snapshot.cache_size, 3);
        assert_eq!(snapshot.cached_seq_hashes, 3);
        assert_eq!(snapshot.cached_seq_headers, 1);
        assert_eq!(snapshot.recent_failures, 1);
        assert_eq!(snapshot.entries.len(), 3);
        assert!(snapshot
            .entries
            .iter()
            .any(|entry| entry.reason == "history" && entry.has_header));
    }

    #[test]
    fn partial_tx_tree_waits_for_missing_node_followups() {
        let (hdr, mut tx_map, expected_txs) = tx_fixture();
        let mut inbound = InboundLedgers::new();

        let _ = inbound.acquire(hdr.hash, hdr.sequence, InboundReason::History);
        assert!(!inbound.got_header(&hdr.hash, hdr.clone()));

        let root_only = tm_nodes_from_wire(
            tx_map.get_wire_nodes_for_query(&crate::ledger::shamap_id::SHAMapNodeID::root(), 0),
        );
        assert!(!inbound.got_tx_data(&hdr.hash, &root_only));
        assert!(!inbound.is_complete(&hdr.hash));

        let missing = inbound.missing_tx_node_ids(&hdr.hash, 16);
        assert_eq!(missing.len(), expected_txs);
        for node_id in missing {
            let node_id = crate::ledger::shamap_id::SHAMapNodeID::from_wire(&node_id)
                .expect("valid child node id");
            let followup = tm_nodes_from_wire(tx_map.get_wire_nodes_for_query(&node_id, 0));
            assert!(
                !followup.is_empty(),
                "follow-up request for missing child should return a node"
            );
            inbound.got_tx_data(&hdr.hash, &followup);
        }

        assert!(inbound.is_complete(&hdr.hash));
        let (_taken_header, tx_blobs, tx_root) =
            inbound.take(&hdr.hash).expect("complete acquisition");
        assert_eq!(tx_blobs.len(), expected_txs);
        assert_eq!(tx_root, Some(hdr.transaction_hash));
    }

    #[test]
    fn tx_prefetch_before_header_still_completes_after_attach() {
        let (hdr, mut tx_map, expected_txs) = tx_fixture();
        let mut inbound = InboundLedgers::new();

        let root_only = tm_nodes_from_wire(
            tx_map.get_wire_nodes_for_query(&crate::ledger::shamap_id::SHAMapNodeID::root(), 0),
        );
        assert!(!inbound.got_tx_data(&hdr.hash, &root_only));
        assert_eq!(inbound.get(&hdr.hash).map(|il| il.ledger_seq), Some(0));

        let _ = inbound.acquire(hdr.hash, hdr.sequence, InboundReason::History);
        assert!(!inbound.got_header(&hdr.hash, hdr.clone()));
        assert!(!inbound.is_complete(&hdr.hash));

        let missing = inbound.missing_tx_node_ids(&hdr.hash, 16);
        assert_eq!(missing.len(), expected_txs);
        for node_id in missing {
            let node_id = crate::ledger::shamap_id::SHAMapNodeID::from_wire(&node_id)
                .expect("valid child node id");
            let followup = tm_nodes_from_wire(tx_map.get_wire_nodes_for_query(&node_id, 0));
            inbound.got_tx_data(&hdr.hash, &followup);
        }

        assert!(inbound.is_complete(&hdr.hash));
    }
}
