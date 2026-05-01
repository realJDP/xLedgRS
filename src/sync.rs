//! xLedgRS purpose: Coordinate ledger state synchronization from peer data.
//! Ledger synchronization from peer responses.
//!
//! When a validation arrives for a ledger sequence ahead of the local state,
//! the peer header (liBASE) is requested and parsed to update the displayed
//! ledger information.
//!
//! State-tree download uses TMGetLedger(liAS_NODE) and TMLedgerData. The flow
//! follows the same broad shape as rippled's InboundLedger:
//!   1. Build a local inner-node store incrementally
//!   2. `get_missing_nodes()` walks from the root and finds unreceived children
//!   3. Request missing nodes, receive responses, insert them, and repeat
//!   4. When `get_missing_nodes()` returns empty, sync is complete

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Global cookie counter used to match TMGetLedger requests with TMLedgerData
/// responses.
static COOKIE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Allocate a unique request cookie.
pub fn next_cookie() -> u64 {
    COOKIE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Parse a ledger header from a liBASE response's `nodes[0].nodedata`.
///
/// The raw data layout (big-endian):
///
/// ```text
/// [optional 4-byte prefix 0x4C575200 ("LWR\0")]
/// sequence:             u32
/// total_drops:          u64
/// parent_hash:          [u8; 32]
/// transaction_hash:     [u8; 32]
/// account_hash:         [u8; 32]
/// parent_close_time:    u32
/// close_time:           u32
/// close_time_resolution: u8
/// close_flags:          u8
/// ```
///
/// At least 118 bytes are required after skipping the optional prefix.
pub fn parse_ledger_header_from_base(data: &[u8]) -> Option<crate::ledger::LedgerHeader> {
    // Skip the optional "LWR\0" prefix if present.
    let d = if data.len() > 4 && data[0] == 0x4C && data[1] == 0x57 && data[2] == 0x52 {
        &data[4..]
    } else {
        data
    };

    // Minimum: 4 + 8 + 32 + 32 + 32 + 4 + 4 + 1 + 1 = 118 bytes.
    if d.len() < 118 {
        return None;
    }

    let sequence = u32::from_be_bytes(d[0..4].try_into().ok()?);
    let total_coins = u64::from_be_bytes(d[4..12].try_into().ok()?);

    let mut parent_hash = [0u8; 32];
    parent_hash.copy_from_slice(&d[12..44]);

    let mut tx_hash = [0u8; 32];
    tx_hash.copy_from_slice(&d[44..76]);

    let mut account_hash = [0u8; 32];
    account_hash.copy_from_slice(&d[76..108]);

    let parent_close_time = u32::from_be_bytes(d[108..112].try_into().ok()?);
    let close_time = u32::from_be_bytes(d[112..116].try_into().ok()?) as u64;
    let close_time_resolution = d[116];
    let close_flags = d[117];

    let mut header = crate::ledger::LedgerHeader {
        sequence,
        total_coins,
        parent_hash,
        transaction_hash: tx_hash,
        account_hash,
        close_time,
        parent_close_time,
        close_time_resolution,
        close_flags,
        hash: [0u8; 32],
    };
    header.hash = header.compute_hash();
    Some(header)
}

// Wire type constants (last byte of nodedata).

const WIRE_TYPE_ACCOUNT_STATE: u8 = 1;
const WIRE_TYPE_INNER: u8 = 2;
const WIRE_TYPE_COMPRESSED_INNER: u8 = 3;

/// Storage format prefixes (first 4 bytes of serialized node data).
const STORAGE_PREFIX_INNER: [u8; 4] = [0x4D, 0x49, 0x4E, 0x00]; // MIN\0
const STORAGE_PREFIX_LEAF: [u8; 4] = [0x4D, 0x4C, 0x4E, 0x00]; // MLN\0

/// Convert NodeStore storage format to peer wire format.
///
/// Storage format: 4-byte HashPrefix + payload
/// Wire format: payload + 1-byte wireType suffix
///
/// Returns None if the data isn't a recognized format.
pub fn storage_to_wire(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 5 {
        return None;
    }
    let prefix = &data[..4];
    let payload = &data[4..];

    if prefix == STORAGE_PREFIX_INNER {
        // Inner node: MIN\0 + 16×32 child hashes = 516 bytes total.
        // Wire form: 512 child hashes plus wireTypeInner.
        let mut wire = Vec::with_capacity(payload.len() + 1);
        wire.extend_from_slice(payload);
        wire.push(WIRE_TYPE_INNER);
        Some(wire)
    } else if prefix == STORAGE_PREFIX_LEAF {
        // Leaf node: MLN\0 + SLE data + 32-byte key = variable length.
        // Wire form: SLE data + 32-byte key plus wireTypeAccountState.
        let mut wire = Vec::with_capacity(payload.len() + 1);
        wire.extend_from_slice(payload);
        wire.push(WIRE_TYPE_ACCOUNT_STATE);
        Some(wire)
    } else {
        // Unknown prefix: pass through unchanged.
        // Transaction node prefixes are not needed by state sync.
        None
    }
}

/// Normalize a TMGetObjectByHash payload into the backend storage format used
/// by the sync walker.
///
/// rippled can return raw NodeStore data here, which may already be prefixless
/// bytes or may still carry the 4-byte hash prefix. The backend is kept in the
/// prefixless form expected by `get_missing_nodes`.
pub fn object_reply_to_store(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 32 {
        return None;
    }

    if data.starts_with(&STORAGE_PREFIX_INNER) || data.starts_with(&STORAGE_PREFIX_LEAF) {
        return Some(data[4..].to_vec());
    }

    Some(data.to_vec())
}

fn add_storage_prefix(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() == 16 * 32 {
        let mut prefixed = Vec::with_capacity(4 + data.len());
        prefixed.extend_from_slice(&STORAGE_PREFIX_INNER);
        prefixed.extend_from_slice(data);
        return Some(prefixed);
    }

    if data.len() > 32 {
        let mut prefixed = Vec::with_capacity(4 + data.len());
        prefixed.extend_from_slice(&STORAGE_PREFIX_LEAF);
        prefixed.extend_from_slice(data);
        return Some(prefixed);
    }

    None
}

pub fn store_to_object_reply(data: &[u8]) -> Option<Vec<u8>> {
    if data.starts_with(&STORAGE_PREFIX_INNER) || data.starts_with(&STORAGE_PREFIX_LEAF) {
        return Some(data.to_vec());
    }
    add_storage_prefix(data)
}

/// Normalize a TMGetObjectByHash payload and verify that the normalized bytes
/// hash to the expected SHAMap node hash.
pub fn object_reply_to_verified_store(expected_hash: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.starts_with(&STORAGE_PREFIX_INNER) || data.starts_with(&STORAGE_PREFIX_LEAF) {
        if &crate::crypto::sha512_first_half(data) == expected_hash {
            return object_reply_to_store(data);
        }
        return None;
    }

    if let Some(prefixed) = add_storage_prefix(data) {
        if &crate::crypto::sha512_first_half(&prefixed) == expected_hash {
            return Some(data.to_vec());
        }
    }

    None
}

/// Maximum SHAMapNodeIDs requested per TMGetLedger batch.
const MAX_BATCH_SIZE_REPLY: usize = 256;
const MAX_BATCH_SIZE_TIMEOUT: usize = 12;
const MAX_OBJECT_BY_HASH_BATCH: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncRequestReason {
    Reply,
    Timeout,
}

fn query_depth_for_reason(reason: SyncRequestReason) -> u32 {
    match reason {
        SyncRequestReason::Reply => 1,
        SyncRequestReason::Timeout => 0,
    }
}

// ── Inner node store ────────────────────────────────────────────────────────

/// A SHAMap inner node: 16 child hashes plus a bitmask of received children.
#[derive(Clone)]
pub struct InnerNode {
    /// Child hashes; zero indicates an empty branch.
    children: [[u8; 32]; 16],
    /// Bitmask where bit `i` indicates that child `i` has been received.
    received: u16,
    /// This node's hash, taken from the parent's child-hash array.
    self_hash: [u8; 32],
    /// True when the subtree below this node is complete.
    /// Checked inline during the tree walk to avoid a hash-set lookup.
    is_full_below: bool,
}

impl InnerNode {
    fn from_full(data: &[u8]) -> Option<Self> {
        if data.len() != 512 {
            return None;
        }
        let mut node = InnerNode {
            children: [[0u8; 32]; 16],
            received: 0,
            self_hash: [0u8; 32],
            is_full_below: false,
        };
        for i in 0..16 {
            node.children[i].copy_from_slice(&data[i * 32..(i + 1) * 32]);
        }
        Some(node)
    }

    fn from_compressed(data: &[u8]) -> Option<Self> {
        if data.len() % 33 != 0 {
            return None;
        }
        let mut node = InnerNode {
            children: [[0u8; 32]; 16],
            received: 0,
            self_hash: [0u8; 32],
            is_full_below: false,
        };
        let n = data.len() / 33;
        for c in 0..n {
            let base = c * 33;
            let pos = data[base + 32] as usize;
            if pos >= 16 {
                return None;
            }
            node.children[pos].copy_from_slice(&data[base..base + 32]);
        }
        Some(node)
    }

    fn is_empty_branch(&self, branch: usize) -> bool {
        self.children[branch].iter().all(|&b| b == 0)
    }

    pub fn is_received(&self, branch: usize) -> bool {
        self.received & (1 << branch) != 0
    }

    fn mark_received(&mut self, branch: usize) {
        self.received |= 1 << branch;
    }
}

/// Apply depthMask to a 32-byte path by zeroing all nibbles beyond the depth.
/// Matches the SHAMapNodeID constructor invariant: `id == (id & depthMask(depth))`.
fn apply_depth_mask(path: &mut [u8; 32], depth: u8) {
    let d = depth as usize;
    // Full bytes used: d / 2 (each byte holds two nibbles).
    let full_bytes = d / 2;
    // If depth is odd, the boundary byte keeps only the upper nibble.
    if d % 2 != 0 && full_bytes < 32 {
        path[full_bytes] &= 0xF0;
        for b in (full_bytes + 1)..32 {
            path[b] = 0;
        }
    } else {
        for b in full_bytes..32 {
            path[b] = 0;
        }
    }
}

/// Build a 33-byte SHAMapNodeID for a child node.
/// Applies `depthMask` so all nibbles beyond `child_depth` are zeroed. Without
/// this, rippled rejects the node ID in `deserializeSHAMapNodeID()` and drops
/// the request.
fn build_child_id(parent_path: &[u8; 32], parent_depth: u8, branch: u8) -> [u8; 33] {
    let mut id = [0u8; 33];
    id[..32].copy_from_slice(parent_path);
    let child_depth = parent_depth + 1;
    let nibble_pos = (parent_depth as usize) / 2;
    if nibble_pos < 32 {
        if parent_depth % 2 == 0 {
            id[nibble_pos] = (id[nibble_pos] & 0x0F) | (branch << 4);
        } else {
            id[nibble_pos] = (id[nibble_pos] & 0xF0) | branch;
        }
    }
    // Zero out all nibbles beyond child_depth — critical for rippled parity
    let mut path = [0u8; 32];
    path.copy_from_slice(&id[..32]);
    apply_depth_mask(&mut path, child_depth);
    id[..32].copy_from_slice(&path);
    id[32] = child_depth;
    id
}

/// Extract (path, depth) from a 33-byte SHAMapNodeID.
fn parse_node_id(nid: &[u8; 33]) -> ([u8; 32], u8) {
    let mut path = [0u8; 32];
    path.copy_from_slice(&nid[..32]);
    (path, nid[32])
}

/// Compute the parent's SHAMapNodeID and branch for a given child nodeID.
pub fn parent_and_branch(child_id: &[u8; 33]) -> Option<([u8; 33], u8)> {
    let depth = child_id[32];
    if depth == 0 {
        return None;
    } // root has no parent
    let parent_depth = depth - 1;
    let nibble_pos = (parent_depth as usize) / 2;
    let branch = if parent_depth % 2 == 0 {
        (child_id[nibble_pos] >> 4) & 0x0F
    } else {
        child_id[nibble_pos] & 0x0F
    };
    // Build parent ID: same path but mask off the child's nibble, set parent depth
    let mut parent_id = [0u8; 33];
    parent_id[..32].copy_from_slice(&child_id[..32]);
    if parent_depth % 2 == 0 {
        parent_id[nibble_pos] &= 0x0F; // clear high nibble
    } else {
        parent_id[nibble_pos] &= 0xF0; // clear low nibble
    }
    parent_id[32] = parent_depth;
    Some((parent_id, branch))
}

// ── Sync progress ────────────────────────────────────────────────────────────

/// Progress report returned by `StateSyncer::process_response`.
#[derive(Debug)]
pub struct SyncProgress {
    pub inner_received: usize,
    pub leaf_received: usize,
    pub pending: usize,
    pub total_inner: usize,
    pub total_leaf: usize,
    /// Leaves parsed from this batch only — `(32-byte key, raw STObject)`.
    pub leaves: Vec<(Vec<u8>, Vec<u8>)>,
    /// Deleted branches discovered during diff sync — `(branch, old_child_hash)`.
    /// Each entry means the branch at that node went from non-zero to zero.
    /// The nibble path to these branches can be reconstructed from the node IDs.
    pub diff_deletions: Vec<DiffDeletion>,
}

/// A deletion discovered during differential sync.
#[derive(Debug, Clone)]
pub struct DiffDeletion {
    /// The node ID of the parent inner node.
    pub parent_nid: [u8; 33],
    /// Which branch (0-15) was deleted.
    pub branch: u8,
}

impl DiffDeletion {
    /// Convert to a nibble prefix path for SparseSHAMap::collect_keys_under_prefix.
    /// The parent is at depth D with path P; the deleted child is at depth D+1
    /// with branch B appended.
    pub fn to_nibble_prefix(&self) -> Vec<u8> {
        let depth = self.parent_nid[32] as usize;
        let mut nibbles = Vec::with_capacity(depth + 1);
        for d in 0..depth {
            let byte = self.parent_nid[d / 2];
            let nib = if d % 2 == 0 { byte >> 4 } else { byte & 0x0F };
            nibbles.push(nib);
        }
        nibbles.push(self.branch);
        nibbles
    }
}

// ── StateSyncer ────────────────────────────────���─────────────────────────────

// ── PeerSyncManager ──────────────────────────────────────────────────────────

/// Manages peer coordination for state sync — request tracking, stall detection,
/// cookie management, retry logic. No tree knowledge.
pub struct PeerSyncManager {
    pub ledger_seq: u32,
    pub ledger_hash: [u8; 32],
    pub account_hash: [u8; 32],
    pub active: bool,
    pub by_hash_armed: bool,
    pub in_flight: usize,
    pub outstanding_cookies: std::collections::HashSet<u32>,
    pub outstanding_object_queries: std::collections::HashSet<u32>,
    pub responded_cookies: std::collections::HashSet<u32>,
    pub responded_object_queries: std::collections::HashSet<u32>,
    pub recent_nodes: std::collections::HashSet<[u8; 32]>,
    pub last_response: std::time::Instant,
    pub last_type2: std::time::Instant,
    pub stalled_retries: u32,
    pub tail_stuck_hash: [u8; 32],
    pub tail_stuck_retries: u32,
    pub pass_number: u32,
    pub pass_start_useful_count: usize,
    pub last_new_nodes: std::time::Instant,
    pub timeout: crate::ledger::inbound::TimeoutCounterState,
    pub last_failure: Option<std::time::Instant>,
    pub inner_count: usize,
    pub leaf_count: usize,
}

impl PeerSyncManager {
    pub fn new(seq: u32, hash: [u8; 32], account_hash: [u8; 32]) -> Self {
        let now = std::time::Instant::now();
        Self {
            ledger_seq: seq,
            ledger_hash: hash,
            account_hash,
            active: true,
            by_hash_armed: false,
            in_flight: 0,
            outstanding_cookies: std::collections::HashSet::new(),
            outstanding_object_queries: std::collections::HashSet::new(),
            responded_cookies: std::collections::HashSet::new(),
            responded_object_queries: std::collections::HashSet::new(),
            recent_nodes: std::collections::HashSet::with_capacity(1024),
            last_response: now,
            last_type2: now,
            stalled_retries: 0,
            tail_stuck_hash: [0u8; 32],
            tail_stuck_retries: 0,
            pass_number: 0,
            pass_start_useful_count: 0,
            last_new_nodes: now,
            timeout: crate::ledger::inbound::TimeoutCounterState::new(
                crate::ledger::inbound::LEDGER_ACQUIRE_TIMEOUT,
            ),
            last_failure: None,
            inner_count: 0,
            leaf_count: 0,
        }
    }

    pub fn accept_response(&mut self, resp_hash: &[u8], cookie: Option<u32>) -> bool {
        let ltclosed = self.ledger_hash == [0u8; 32];
        if resp_hash.len() != 32 {
            return false;
        }
        if !ltclosed && resp_hash != self.ledger_hash {
            return false;
        }
        let Some(c32) = cookie else {
            return false;
        };
        if !self.outstanding_cookies.remove(&c32) {
            return false;
        }
        self.responded_cookies.insert(c32);
        if self.in_flight > 0 {
            self.in_flight -= 1;
        }
        self.last_response = std::time::Instant::now();
        true
    }

    pub fn accept_object_response(&mut self, resp_hash: &[u8], seq: Option<u32>) -> bool {
        let Some(s32) = seq.map(|s| s as u32) else {
            return false;
        };
        let ltclosed = self.ledger_hash == [0u8; 32];
        if resp_hash.len() != 32 {
            return false;
        }
        if !ltclosed && resp_hash != self.ledger_hash {
            return false;
        }
        if !self.outstanding_object_queries.remove(&s32) {
            return false;
        }
        self.responded_object_queries.insert(s32);
        self.last_response = std::time::Instant::now();
        true
    }

    /// Accept a same-ledger GetObjects reply whose cookie aged out of the
    /// outstanding set, but only if import already proved the payload useful.
    pub fn accept_useful_stale_object_response(
        &mut self,
        resp_hash: &[u8],
        seq: Option<u32>,
        imported_count: usize,
    ) -> bool {
        if imported_count == 0 {
            return false;
        }
        let Some(s32) = seq.map(|s| s as u32) else {
            return false;
        };
        let ltclosed = self.ledger_hash == [0u8; 32];
        if resp_hash.len() != 32 {
            return false;
        }
        if !ltclosed && resp_hash != self.ledger_hash {
            return false;
        }
        if self.outstanding_object_queries.contains(&s32)
            || self.responded_object_queries.contains(&s32)
        {
            return false;
        }
        self.responded_object_queries.insert(s32);
        self.last_response = std::time::Instant::now();
        true
    }

    pub fn clear_recent(&mut self) {
        self.recent_nodes.clear();
    }

    pub fn note_progress(&mut self) {
        self.last_new_nodes = std::time::Instant::now();
        self.timeout.note_progress();
    }

    /// A successful TMGetObjectByHash rescue materially changes the frontier:
    /// the next position-based walk should start fresh instead of carrying
    /// forward stale timeout state and outstanding-request bookkeeping from the
    /// stuck tail wave.
    pub fn note_object_rescue_progress(&mut self) {
        self.stalled_retries = 0;
        self.by_hash_armed = false;
        self.tail_stuck_hash = [0u8; 32];
        self.tail_stuck_retries = 0;
        self.timeout.timeouts = 0;
        self.start_new_pass();
        self.timeout.note_progress();
    }

    pub fn mark_failed(&mut self) {
        self.last_failure = Some(std::time::Instant::now());
        self.timeout.mark_failed();
    }

    pub fn can_reacquire(&self) -> bool {
        self.last_failure
            .map(|at| at.elapsed() >= crate::ledger::inbound::LEDGER_REACQUIRE_INTERVAL)
            .unwrap_or(true)
    }

    pub fn on_timer_tick(&mut self) -> Option<crate::ledger::inbound::TimeoutTick> {
        // Match rippled's InboundLedger::onTimer(): every timer tick resets
        // the duplicate-suppression window before deciding whether this tick
        // represents progress or a real timeout.
        self.clear_recent();
        self.timeout.on_timer_tick()
    }

    pub fn reset_in_flight(&mut self) {
        self.in_flight = 0;
        self.outstanding_cookies.clear();
        self.outstanding_object_queries.clear();
    }

    pub fn start_new_pass(&mut self) {
        self.pass_number += 1;
        self.pass_start_useful_count = self.inner_count + self.leaf_count;
        self.reset_in_flight();
        self.recent_nodes.clear();
        self.last_new_nodes = std::time::Instant::now();
    }

    pub fn has_cookie(&self, cookie: u32) -> bool {
        self.outstanding_cookies.contains(&cookie)
    }
    pub fn outstanding_cookie_count(&self) -> usize {
        self.outstanding_cookies.len()
    }
    pub fn outstanding_object_query_count(&self) -> usize {
        self.outstanding_object_queries.len()
    }
    pub fn recent_node_count(&self) -> usize {
        self.recent_nodes.len()
    }
    pub fn new_objects_this_pass(&self) -> usize {
        (self.inner_count + self.leaf_count).saturating_sub(self.pass_start_useful_count)
    }
    pub fn accepts_ltclosed_responses(&self) -> bool {
        self.active && self.ledger_hash == [0u8; 32]
    }
    pub fn knows_object_query(&self, seq: u32) -> bool {
        self.outstanding_object_queries.contains(&seq)
            || self.responded_object_queries.contains(&seq)
    }

    /// Build sync requests from missing nodes found by SHAMap walk.
    /// Each missing node is (SHAMapNodeID, content_hash). Encodes as TMGetLedger.
    /// Returns list of requests (one per chunk of nodes).
    pub fn build_requests_from_missing(
        &mut self,
        missing: &[(crate::ledger::shamap_id::SHAMapNodeID, [u8; 32])],
        reason: SyncRequestReason,
    ) -> Vec<crate::network::message::RtxpMessage> {
        if missing.is_empty() {
            return vec![];
        }

        // Match rippled's `filterNodes()`: prefer hashes that are not already
        // in the recent-request window.
        // recently, suppress all-duplicate reply triggers, and only allow
        // timeout retries to reuse duplicates when there is no fresh work.
        let mut fresh = Vec::new();
        let mut dup = Vec::new();
        for item in missing {
            if self.recent_nodes.contains(&item.1) {
                dup.push(item);
            } else {
                fresh.push(item);
            }
        }
        let mut filtered = if fresh.is_empty() {
            if !matches!(reason, SyncRequestReason::Timeout) {
                return vec![];
            }
            dup
        } else {
            fresh
        };

        // Match rippled's TriggerReason handling:
        // - reply => queryDepth 1
        // - timeout/blind => queryDepth 0
        let query_depth = query_depth_for_reason(reason);
        let query_type = if self.stalled_retries > 0 || matches!(reason, SyncRequestReason::Timeout)
        {
            Some(crate::proto::TmQueryType::QtIndirect as i32)
        } else {
            None
        };

        // Encode node IDs as 33-byte wire format.
        // rippled uses reqNodesReply=128 for reply triggers, reqNodes=12 for blind.
        let per_request = match reason {
            SyncRequestReason::Reply => crate::ledger::inbound::REQ_NODES_REPLY,
            SyncRequestReason::Timeout => crate::ledger::inbound::REQ_NODES_TIMEOUT,
        };
        if filtered.len() > per_request {
            filtered.truncate(per_request);
        }

        for (_, hash) in &filtered {
            self.recent_nodes.insert(*hash);
        }

        let request_hash = self.ledger_hash;
        let mut reqs = Vec::new();
        let batch: Vec<Vec<u8>> = filtered
            .iter()
            .map(|(nid, _)| nid.to_wire().to_vec())
            .collect();
        let cookie = next_cookie() as u32;
        reqs.push(crate::network::relay::encode_get_ledger_state(
            &request_hash,
            &batch,
            u64::from(cookie),
            query_depth,
            query_type,
            self.ledger_seq,
        ));
        self.outstanding_cookies.insert(cookie);
        self.in_flight = self.in_flight.saturating_add(reqs.len());
        reqs
    }

    /// Parse nodes from a peer response. Returns (node_id, wire_data) pairs
    /// ready for insertion via shamap_sync::add_known_node.
    /// Also returns extracted leaves as (key, data) for NuDB persistence.
    pub fn parse_response(&mut self, ld: &crate::proto::TmLedgerData) -> ParsedSyncResponse {
        self.last_response = std::time::Instant::now();
        parse_sync_response(ld, self.inner_count < 100)
    }
}

/// Parsed response from a peer — ready for tree insertion + NuDB persistence.
pub struct ParsedSyncResponse {
    /// (SHAMapNodeID, wire_data) pairs for add_known_node.
    pub nodes: Vec<(crate::ledger::shamap_id::SHAMapNodeID, Vec<u8>)>,
    /// (key_bytes, sle_data) pairs for direct NuDB leaf storage.
    pub leaves: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Parse a peer response without touching sync coordinator state. This allows the
/// caller decode and clone the protobuf payload outside the sync mutex, keeping
/// the critical section focused on SHAMap mutation.
pub(crate) fn parse_sync_response(
    ld: &crate::proto::TmLedgerData,
    log_initial_nodes: bool,
) -> ParsedSyncResponse {
    let mut nodes = Vec::new();
    let mut leaves = Vec::new();

    for node in &ld.nodes {
        if node.nodedata.is_empty() {
            continue;
        }

        let node_id = match &node.nodeid {
            Some(nid) if nid.len() >= 33 => crate::ledger::shamap_id::SHAMapNodeID::from_wire(nid),
            Some(nid) if nid.is_empty() => Some(crate::ledger::shamap_id::SHAMapNodeID::root()),
            None => Some(crate::ledger::shamap_id::SHAMapNodeID::root()),
            _ => None,
        };

        let Some(nid) = node_id else {
            tracing::debug!(
                "sync: skipping node with unparseable nodeid len={:?}",
                node.nodeid.as_ref().map(|n| n.len())
            );
            continue;
        };

        if log_initial_nodes && nodes.len() < 3 {
            tracing::info!(
                "sync node: depth={} nodeid_len={:?} data_len={} wire_type={:#04x}",
                nid.depth(),
                node.nodeid.as_ref().map(|n| n.len()),
                node.nodedata.len(),
                node.nodedata.last().copied().unwrap_or(0)
            );
        }

        let wire_type = node.nodedata[node.nodedata.len() - 1];
        let data = &node.nodedata[..node.nodedata.len() - 1];

        if wire_type == 0x01 && data.len() > 32 {
            let key_start = data.len() - 32;
            leaves.push((data[key_start..].to_vec(), data[..key_start].to_vec()));
        } else if wire_type != 0x02 && wire_type != 0x03 {
            tracing::debug!(
                "sync: unknown wire_type={:#04x} data_len={}",
                wire_type,
                data.len()
            );
        }

        nodes.push((nid, node.nodedata.clone()));
    }

    ParsedSyncResponse { nodes, leaves }
}

// SyncRequestReason already defined above (line ~143)

// ── StateSyncer (legacy) ─────────────────────────────────────────────────────

/// Maximum entries in the in-memory LRU node cache.
const NODE_CACHE_CAP: usize = 50_000;
/// Flush write buffer to RocksDB when this many entries accumulate.
const WRITE_BUFFER_FLUSH_SIZE: usize = 1_000;
/// Max known_hashes entries (~16MB at 32 bytes each). Matches rippled's FullBelowCache target (524K).
const KNOWN_HASHES_CAP: usize = 524_288;

/// Downloads an account state SHAMap tree from peers via TMGetLedger(liAS_NODE).
///
/// Follows rippled's InboundLedger approach:
/// - Inner nodes stored in RocksDB with an in-memory LRU cache for the walk frontier
/// - get_missing_nodes() walks the tree to find unreceived children
/// - No bloom filter, no pending queue — the inner node store IS the tracker
pub struct StateSyncer {
    /// Target ledger for the active sync session.
    pub ledger_seq: u32,
    pub ledger_hash: [u8; 32],
    pub account_hash: [u8; 32],
    /// In-memory LRU cache for hot inner nodes (walk frontier).
    node_cache: HashMap<[u8; 33], InnerNode>,
    /// LRU eviction order — front is oldest, back is newest.
    cache_order: VecDeque<[u8; 33]>,
    /// RocksDB storage backend for inner nodes (on-demand reads/writes).
    _storage: Option<Arc<crate::storage::Storage>>,
    /// Batch buffer for RocksDB writes; flushed at `WRITE_BUFFER_FLUSH_SIZE`
    /// or when `process_response()` returns.
    /// Retained as an empty `Vec` for API compatibility.
    write_buffer: Vec<[u8; 33]>,
    /// FullBelowCache — like rippled's generation-based cache.
    /// Tracks hashes of inner nodes whose subtrees are fully downloaded.
    /// Generation increments on ledger change; stale entries ignored without clearing.
    known_hashes: HashSet<[u8; 32]>,
    /// Generation counter — incremented on restart_with_hash. Matches rippled's FullBelowCache.
    _full_below_generation: u32,
    /// Recently requested node hashes — prevents same nodes going to multiple peers.
    /// Cleared every 3 seconds.
    recent_nodes: HashSet<[u8; 32]>,
    /// Count of inner nodes received.
    pub inner_count: usize,
    /// Count of leaf nodes received.
    pub leaf_count: usize,
    /// Is sync active?
    pub active: bool,
    /// Timestamp of the last TMLedgerData response (for stall detection).
    pub last_response: std::time::Instant,
    /// Timestamp of the last time new nodes were discovered.
    pub last_new_nodes: std::time::Instant,
    /// Number of batches sent but not yet responded to.
    pub in_flight: usize,
    /// Outstanding liAS_NODE request cookies still expected from peers.
    outstanding_cookies: HashSet<u32>,
    /// Outstanding TMGetObjectByHash request sequences still expected.
    outstanding_object_queries: HashSet<u32>,
    /// Cookies that received at least one response.
    /// Still accepted for duplicate responses.
    responded_cookies: HashSet<u32>,
    responded_object_queries: HashSet<u32>,
    /// Timestamp of last liAS_NODE (type=2) response — for hash expiry detection.
    pub last_type2: std::time::Instant,
    /// Current pass number (kept for API compat).
    pub pass_number: u32,
    /// leaf_count at the start of the current pass.
    pub pass_start_leaf_count: usize,
    /// Consecutive timeout-driven retry attempts for the current sync target.
    pub stalled_retries: u32,
    /// Tail-stall tracker: hash of the currently stuck node (when missing<=1).
    /// Resets only when the stuck node changes or is resolved.
    pub tail_stuck_hash: [u8; 32],
    /// Retry count for the current tail-stuck node. Used to escalate to GetObjects.
    pub tail_stuck_retries: u32,
}

use std::collections::HashSet;

impl StateSyncer {
    /// Create a new syncer for the given ledger.
    pub fn new(
        seq: u32,
        hash: [u8; 32],
        account_hash: [u8; 32],
        storage: Option<Arc<crate::storage::Storage>>,
    ) -> Self {
        Self {
            ledger_seq: seq,
            ledger_hash: hash,
            account_hash,
            node_cache: HashMap::with_capacity(NODE_CACHE_CAP),
            cache_order: VecDeque::with_capacity(NODE_CACHE_CAP),
            _storage: storage,
            write_buffer: Vec::with_capacity(WRITE_BUFFER_FLUSH_SIZE),
            known_hashes: HashSet::with_capacity(1_000_000),
            _full_below_generation: 1,
            recent_nodes: HashSet::new(),
            inner_count: 0,
            leaf_count: 0,
            active: true,
            last_response: std::time::Instant::now(),
            last_new_nodes: std::time::Instant::now(),
            in_flight: 0,
            outstanding_cookies: HashSet::new(),
            outstanding_object_queries: HashSet::new(),
            responded_cookies: HashSet::new(),
            responded_object_queries: HashSet::new(),
            last_type2: std::time::Instant::now(),
            pass_number: 1,
            pass_start_leaf_count: 0,
            stalled_retries: 0,
            tail_stuck_hash: [0u8; 32],
            tail_stuck_retries: 0,
        }
    }

    // ── Cache + RocksDB inner node accessors ─────────────────────────────

    /// Look up an inner node: cache first, then RocksDB fallback.
    pub fn get_node(&self, id: &[u8; 33]) -> Option<&InnerNode> {
        // Fast path: check cache
        if let Some(node) = self.node_cache.get(id) {
            return Some(node);
        }
        // NOTE: Can't return a reference to a RocksDB-loaded node without inserting
        // into cache. Use get_node_or_load() for the load+insert path.
        None
    }

    /// Look up an inner node in the in-memory cache.
    fn get_node_or_load(&mut self, id: &[u8; 33]) -> Option<&InnerNode> {
        self.node_cache.get(id)
    }

    /// Check if a node exists in the in-memory cache.
    pub fn has_node(&self, id: &[u8; 33]) -> bool {
        self.node_cache.contains_key(id)
    }

    /// Insert a node into the in-memory cache.
    fn insert_node(&mut self, id: [u8; 33], node: InnerNode) {
        self.cache_insert(id, node);
    }

    /// Return mutable ref to a cached node (if present).
    fn ensure_cached_mut(&mut self, id: &[u8; 33]) -> Option<&mut InnerNode> {
        self.node_cache.get_mut(id)
    }

    /// Insert into the LRU cache, evicting oldest if at capacity.
    fn cache_insert(&mut self, id: [u8; 33], node: InnerNode) {
        if self.node_cache.contains_key(&id) {
            // Already present — just update value (don't double-add to order)
            self.node_cache.insert(id, node);
            return;
        }
        // Evict if at capacity
        while self.node_cache.len() >= NODE_CACHE_CAP {
            if let Some(old_key) = self.cache_order.pop_front() {
                self.node_cache.remove(&old_key);
            } else {
                break;
            }
        }
        self.node_cache.insert(id, node);
        self.cache_order.push_back(id);
    }

    /// Read-only lookup from in-memory cache. Returns a clone.
    fn get_node_or_load_readonly(&self, id: &[u8; 33]) -> Option<InnerNode> {
        self.node_cache.get(id).cloned()
    }

    /// Number of nodes in the in-memory cache.
    pub fn cache_len(&self) -> usize {
        self.node_cache.len()
    }

    /// Clear recently-requested nodes (call every 3 seconds from timer).
    pub fn clear_recent(&mut self) {
        self.recent_nodes.clear();
    }

    /// Clear in-flight request tracking after a timeout or restart.
    pub fn reset_in_flight(&mut self) {
        self.in_flight = 0;
        self.outstanding_cookies.clear();
        self.outstanding_object_queries.clear();
        self.responded_cookies.clear();
        self.responded_object_queries.clear();
    }

    /// Legacy single-lock check_local for startup path (not on async runtime).
    /// Inner nodes are no longer persisted — always returns 0.
    pub fn check_local(
        &mut self,
        _storage: Option<&crate::storage::Storage>,
        _max: usize,
    ) -> usize {
        0
    }

    /// Restart sync with a fresh ledger hash.
    /// Clears the in-memory cache and the RocksDB INNER_NODES CF.
    /// The walk will re-discover inner nodes from peers; known_hashes
    /// ensures completed subtrees are skipped.
    pub fn restart_with_hash(&mut self, hash: [u8; 32], account_hash: [u8; 32], seq: u32) {
        self.ledger_hash = hash;
        self.account_hash = account_hash;
        self.ledger_seq = seq;
        // Clear cache — stale received/full_below bits from the old ledger
        // would cause the walker to skip branches that need re-downloading.
        self.node_cache.clear();
        self.cache_order.clear();
        self.write_buffer.clear();
        // Inner nodes are in-memory only — cache clear above is sufficient.
        self.recent_nodes.clear();
        self.active = true;
        self.reset_in_flight();
        self.last_response = std::time::Instant::now();
        self.last_new_nodes = std::time::Instant::now();
        self.last_type2 = std::time::Instant::now();
        self.pass_number += 1;
        self.pass_start_leaf_count = self.leaf_count;
        self.stalled_retries = 0;
    }

    /// Prepare for differential sync: install new root, use content-addressed
    /// known_hashes to skip unchanged subtrees. Returns deletions (branches
    /// that went from non-zero to zero).
    pub fn update_root_for_diff(
        &mut self,
        new_root_data: &[u8],
        new_ledger_hash: [u8; 32],
        new_account_hash: [u8; 32],
        new_seq: u32,
    ) -> Vec<(u8, [u8; 32])> {
        let root_id = [0u8; 33];
        let mut deletions = Vec::new();

        // Parse the new root inner node
        let new_root = if new_root_data.len() == 512 {
            InnerNode::from_full(new_root_data)
        } else {
            InnerNode::from_compressed(new_root_data)
        };
        let new_root = match new_root {
            Some(r) => r,
            None => return deletions,
        };

        // Get old root's children for deletion detection
        let old_children: [[u8; 32]; 16] = if let Some(old_root) = self.get_node_or_load(&root_id) {
            old_root.children
        } else {
            [[0u8; 32]; 16]
        };

        // Keep inner_nodes — the tree walk uses them to recurse into subtrees.
        // The known_hashes check in get_missing_nodes handles skipping unchanged subtrees.

        let mut new_node = new_root;
        new_node.self_hash = new_account_hash;
        new_node.received = 0;
        new_node.is_full_below = false;

        // Detect deletions and mark empty branches
        for b in 0..16 {
            let new_hash = new_node.children[b];
            let new_empty = new_hash.iter().all(|&x| x == 0);
            if new_empty {
                let old_hash = old_children[b];
                if old_hash.iter().any(|&x| x != 0) {
                    deletions.push((b as u8, old_hash));
                }
                new_node.mark_received(b);
            }
            // Don't mark non-empty children as received here —
            // get_missing_nodes will check known_hashes to skip them.
        }

        // Install the new root
        self.insert_node(root_id, new_node);

        // Update ledger target
        self.ledger_hash = new_ledger_hash;
        self.account_hash = new_account_hash;
        self.ledger_seq = new_seq;
        self.recent_nodes.clear();
        self.active = true;
        self.last_response = std::time::Instant::now();
        self.last_new_nodes = std::time::Instant::now();
        self.last_type2 = std::time::Instant::now();
        self.stalled_retries = 0;

        deletions
    }

    /// Number of known inner node hashes in the content-addressed cache.
    pub fn known_hash_count(&self) -> usize {
        self.known_hashes.len()
    }

    /// After a verified ledger diff (hash_match=true), commit all current
    /// inner node hashes to known_hashes so future diffs can skip them.
    pub fn commit_known_hashes(&mut self) {
        // Commit from cache (hot nodes from the current sync)
        for node in self.node_cache.values() {
            if node.self_hash != [0u8; 32] && self.known_hashes.len() < KNOWN_HASHES_CAP {
                self.known_hashes.insert(node.self_hash);
            }
        }
        // Inner nodes are in-memory only — cache above is the complete set.
    }

    /// Check if the inner_nodes tree has a root (i.e., has been synced at least once).
    pub fn has_root(&self) -> bool {
        self.has_node(&[0u8; 33])
    }

    /// Build up to `count` requests from a SINGLE tree walk.
    /// Much faster than calling build_next_request() N times, which does N separate walks.
    pub fn build_batch_requests(
        &mut self,
        count: usize,
        storage: Option<&crate::storage::Storage>,
    ) -> Vec<crate::network::message::RtxpMessage> {
        self.build_requests(count, storage, SyncRequestReason::Reply)
    }

    fn child_hash_for_request(&self, id: &[u8; 33]) -> Option<[u8; 32]> {
        let (parent_id, branch) = parent_and_branch(id)?;
        let parent = self.get_node(&parent_id)?;
        Some(parent.children[branch as usize])
    }

    fn filter_recent_nodes(
        &self,
        mut missing: Vec<[u8; 33]>,
        reason: SyncRequestReason,
    ) -> Vec<[u8; 33]> {
        // Check if ALL nodes are duplicates first (needed for timeout bypass).
        let all_dup = missing.iter().all(|id| {
            self.child_hash_for_request(id)
                .is_some_and(|child_hash| self.recent_nodes.contains(&child_hash))
        });

        if all_dup {
            // Match rippled's filterNodes: if all duplicates, only timeout
            // requests are allowed through (re-request everything).
            if !matches!(reason, SyncRequestReason::Timeout) {
                missing.clear();
            }
            return missing;
        }

        // Remove recently-requested nodes. Uses retain() — correct O(n)
        // partition unlike the previous partition_point() which required
        // a pre-sorted slice that DFS order doesn't guarantee.
        missing.retain(|id| {
            self.child_hash_for_request(id)
                .is_none_or(|child_hash| !self.recent_nodes.contains(&child_hash))
        });
        missing
    }

    fn mark_recent_nodes(&mut self, missing: &[[u8; 33]]) {
        for id in missing {
            if let Some(child_hash) = self.child_hash_for_request(id) {
                self.recent_nodes.insert(child_hash);
            }
        }
    }

    fn build_requests(
        &mut self,
        count: usize,
        storage: Option<&crate::storage::Storage>,
        reason: SyncRequestReason,
    ) -> Vec<crate::network::message::RtxpMessage> {
        let random_start = (rand::random::<u8>()) as usize % 256;
        let per_request = match reason {
            SyncRequestReason::Reply => MAX_BATCH_SIZE_REPLY,
            SyncRequestReason::Timeout => MAX_BATCH_SIZE_TIMEOUT,
        };
        let max_nodes = per_request * count.max(1);
        let missing = self.get_missing_nodes(max_nodes, random_start, storage);
        if missing.is_empty() {
            return vec![];
        }

        let missing = self.filter_recent_nodes(missing, reason);
        if missing.is_empty() {
            return vec![];
        }

        self.mark_recent_nodes(&missing);

        // Log requested node_ids when few remain
        if missing.len() <= 10 {
            for (i, nid) in missing.iter().enumerate() {
                let depth = nid[32];
                let child_hash = self.get_self_hash(nid);
                tracing::info!(
                    "REQUEST_NODE[{}]: depth={} hash={} nid={} reason={:?}",
                    i,
                    depth,
                    hex::encode_upper(&child_hash[..8]),
                    hex::encode_upper(&nid[..8]),
                    reason,
                );
            }
        }

        // Split into chunks of 256 (missingNodesFind) and build requests
        let mut reqs = Vec::new();
        // Match rippled's TriggerReason handling:
        // - reply => queryDepth 1
        // - timeout/blind => queryDepth 0
        let query_depth = query_depth_for_reason(reason);
        // rippled: set qtINDIRECT on ALL requests once there's been at least 1 timeout.
        // This tells peers to relay requests they can't serve directly.
        let query_type = if self.stalled_retries > 0 || matches!(reason, SyncRequestReason::Timeout)
        {
            Some(crate::proto::TmQueryType::QtIndirect as i32)
        } else {
            None
        };

        // Check whether the tail-stuck nodes are in the batch being sent.
        if missing.len() <= 20 {
            let current_stuck = self.get_missing_nodes(5, 0, None);
            let stuck_set: std::collections::HashSet<[u8; 33]> =
                current_stuck.iter().cloned().collect();
            let in_batch = missing.iter().filter(|id| stuck_set.contains(*id)).count();
            tracing::info!(
                "BATCH CHECK: sending {} nodes, {} of {} stuck are in batch",
                missing.len(),
                in_batch,
                current_stuck.len(),
            );
        }

        for chunk in missing.chunks(per_request) {
            let batch: Vec<Vec<u8>> = chunk.iter().map(|id| id.to_vec()).collect();
            reqs.push(crate::network::relay::encode_get_ledger_state(
                &self.ledger_hash,
                &batch,
                0, // no cookie — matches rippled
                query_depth,
                query_type,
                self.ledger_seq,
            ));
        }
        reqs
    }

    /// Build the next TMGetLedger(liAS_NODE) request from missing nodes.
    /// Uses randomized DFS start and filters out recently-requested nodes.
    /// Returns `None` if no missing nodes (sync complete or root not yet received).
    pub fn build_next_request(
        &mut self,
        storage: Option<&crate::storage::Storage>,
    ) -> Option<crate::network::message::RtxpMessage> {
        self.build_request(storage, SyncRequestReason::Reply)
    }

    pub fn build_timeout_request(
        &mut self,
        storage: Option<&crate::storage::Storage>,
    ) -> Option<crate::network::message::RtxpMessage> {
        self.build_request(storage, SyncRequestReason::Timeout)
    }

    pub fn build_timeout_object_request(
        &mut self,
        storage: Option<&crate::storage::Storage>,
    ) -> Option<crate::network::message::RtxpMessage> {
        let mut needed = Vec::with_capacity(MAX_OBJECT_BY_HASH_BATCH);

        // Include the tail-stuck node first so it is always requested.
        // DFS order can deprioritize deep nodes, causing them to never be fetched.
        if self.tail_stuck_hash != [0u8; 32] {
            // Find the node_id for this hash
            let missing = self.get_missing_nodes(1, 0, storage);
            if let Some(node_id) = missing.first() {
                let hash = self.get_self_hash(node_id);
                if hash != [0u8; 32] {
                    needed.push((hash, *node_id));
                } else {
                    tracing::info!("tail-stuck node has no resolvable hash (orphaned parent)");
                }
            }
        }

        // Fill remaining slots with other needed hashes (deduped)
        let others = self.get_needed_hashes(MAX_OBJECT_BY_HASH_BATCH, storage);
        for entry in others {
            if needed.len() >= MAX_OBJECT_BY_HASH_BATCH {
                break;
            }
            if !needed.iter().any(|(h, _)| *h == entry.0) {
                needed.push(entry);
            }
        }

        if needed.is_empty() {
            return None;
        }
        let seq = next_cookie() as u32;
        self.outstanding_object_queries.insert(seq);
        Some(crate::network::relay::encode_get_state_nodes_by_hash(
            &self.ledger_hash,
            &needed,
            self.ledger_seq,
            seq,
        ))
    }

    fn build_request(
        &mut self,
        storage: Option<&crate::storage::Storage>,
        reason: SyncRequestReason,
    ) -> Option<crate::network::message::RtxpMessage> {
        let random_start = (rand::random::<u8>()) as usize % 256;
        let max_nodes = match reason {
            SyncRequestReason::Reply => MAX_BATCH_SIZE_REPLY,
            SyncRequestReason::Timeout => MAX_BATCH_SIZE_TIMEOUT,
        };
        let missing = self.get_missing_nodes(max_nodes, random_start, storage);
        if missing.is_empty() {
            return None;
        }

        let mut missing = self.filter_recent_nodes(missing, reason);
        missing.truncate(max_nodes);

        if missing.is_empty() {
            return None;
        }

        self.mark_recent_nodes(&missing);

        let batch: Vec<Vec<u8>> = missing.iter().map(|id| id.to_vec()).collect();
        // Match rippled's TriggerReason handling:
        // - reply => queryDepth 1
        // - timeout/blind => queryDepth 0
        let query_depth = query_depth_for_reason(reason);
        let query_type = if self.stalled_retries > 0 || matches!(reason, SyncRequestReason::Timeout)
        {
            Some(crate::proto::TmQueryType::QtIndirect as i32)
        } else {
            None
        };
        // No request_cookie — matches rippled's InboundLedger which never
        // sets it. The cookie field is reserved for relay routing. Setting it
        // blocks relay (peers check !has_requestcookie() before forwarding).
        // Responses are accepted by ledger hash match, not cookie.
        Some(crate::network::relay::encode_get_ledger_state(
            &self.ledger_hash,
            &batch,
            0, // no cookie
            query_depth,
            query_type,
            self.ledger_seq,
        ))
    }

    /// Accept liAS_NODE responses for the active sync target.
    /// Matches rippled: no cookie validation — accept all responses with
    /// matching ledger hash. Progress tracked via last_response timestamp.
    pub fn accept_response(&mut self, ledger_hash: &[u8], _cookie: Option<u32>) -> bool {
        if ledger_hash.len() != 32 || ledger_hash != self.ledger_hash {
            return false;
        }
        self.last_response = std::time::Instant::now();
        true
    }

    /// Accept GetObjects responses with same fanout-safe logic.
    pub fn accept_object_response(&mut self, ledger_hash: &[u8], seq: Option<u32>) -> bool {
        if ledger_hash.len() != 32 || ledger_hash != self.ledger_hash {
            return false;
        }
        let Some(seq) = seq else {
            return false;
        };
        if self.outstanding_object_queries.contains(&seq) {
            self.outstanding_object_queries.remove(&seq);
            self.responded_object_queries.insert(seq);
        } else if self.responded_object_queries.contains(&seq) {
            // Duplicate — accept
        } else {
            return false;
        }
        self.last_response = std::time::Instant::now();
        true
    }

    /// Process a TMLedgerData response.
    ///
    /// For each node in the response:
    /// - Parse wire type (last byte): inner nodes go into inner_nodes map,
    ///   leaf nodes returned as (key, stobject) pairs
    /// - Mark the parent inner node's branch as received
    pub fn process_response(&mut self, ld: &crate::proto::TmLedgerData) -> SyncProgress {
        let mut inner_received = 0;
        let mut leaf_received = 0;
        let mut leaves = Vec::new();
        let mut diff_deletions = Vec::new();

        // Log response details for tail diagnostics
        let response_node_count = ld.nodes.len();
        let response_depths: Vec<u8> = ld
            .nodes
            .iter()
            .filter_map(|n| {
                n.nodeid
                    .as_ref()
                    .and_then(|id| if id.len() == 33 { Some(id[32]) } else { None })
            })
            .collect();
        if response_node_count > 0 && response_node_count <= 10 {
            tracing::info!(
                "process_response: {} nodes, depths={:?}, data_sizes={:?}",
                response_node_count,
                response_depths,
                ld.nodes
                    .iter()
                    .map(|n| n.nodedata.len())
                    .collect::<Vec<_>>(),
            );
        }

        // Check if response contains any currently-missing nodes
        let current_missing = self.get_missing_nodes(5, 0, None);
        if !current_missing.is_empty() && current_missing.len() <= 5 && ld.nodes.len() <= 20 {
            let missing_set: std::collections::HashSet<[u8; 33]> =
                current_missing.iter().cloned().collect();
            let mut found_missing = false;
            for node in &ld.nodes {
                if let Some(ref raw_nid) = node.nodeid {
                    if raw_nid.len() == 33 {
                        let mut nid = [0u8; 33];
                        nid.copy_from_slice(raw_nid);
                        if missing_set.contains(&nid) {
                            found_missing = true;
                            tracing::warn!(
                                "FOUND MISSING NODE IN RESPONSE: depth={} nid={} data_len={} wire_type={}",
                                nid[32],
                                hex::encode_upper(&nid[..8]),
                                node.nodedata.len(),
                                node.nodedata.last().copied().unwrap_or(255),
                            );
                        }
                    }
                }
            }
            // Log all response node_ids when tail is near and response is small
            if !found_missing {
                let resp_nids: Vec<String> = ld
                    .nodes
                    .iter()
                    .map(|n| {
                        if let Some(ref id) = n.nodeid {
                            if id.len() == 33 {
                                format!("{}d{}", hex::encode_upper(&id[..4]), id[32])
                            } else {
                                format!("len{}", id.len())
                            }
                        } else {
                            "NONE".to_string()
                        }
                    })
                    .collect();
                let missing_nids: Vec<String> = current_missing
                    .iter()
                    .map(|id| format!("{}d{}", hex::encode_upper(&id[..4]), id[32]))
                    .collect();
                tracing::info!(
                    "TAIL MISS: response has [{}] but missing=[{}]",
                    resp_nids.join(","),
                    missing_nids.join(","),
                );
            }
        }

        for node in &ld.nodes {
            let data = &node.nodedata;
            if data.len() < 2 {
                continue;
            }

            // Extract this node's SHAMapNodeID
            let nid: [u8; 33] = if let Some(ref raw_nid) = node.nodeid {
                if raw_nid.len() == 33 {
                    let mut id = [0u8; 33];
                    id.copy_from_slice(raw_nid);
                    id
                } else {
                    [0u8; 33] // root
                }
            } else {
                [0u8; 33] // root
            };

            // Wire type is the last byte
            let wire_type = data[data.len() - 1];
            let body = &data[..data.len() - 1];

            // Get self_hash from parent (if not root)
            let self_hash = self.get_self_hash(&nid);

            match wire_type {
                WIRE_TYPE_INNER | WIRE_TYPE_COMPRESSED_INNER => {
                    let parsed = if wire_type == WIRE_TYPE_INNER {
                        InnerNode::from_full(body)
                    } else {
                        InnerNode::from_compressed(body)
                    };
                    if let Some(mut inner) = parsed {
                        inner.self_hash = self_hash;
                        // Content-addressed skip: mark children whose hashes
                        // are already known (from previous ledgers) as received.
                        for b in 0..16 {
                            let child_hash = inner.children[b];
                            if child_hash.iter().all(|&x| x == 0) {
                                continue;
                            }
                            if self.known_hashes.contains(&child_hash) {
                                inner.mark_received(b);
                            }
                        }
                        // Detect deletions at this node
                        let dels = self.diff_detect_deletions(&nid, &mut inner);
                        for (branch, _old_hash) in dels {
                            diff_deletions.push(DiffDeletion {
                                parent_nid: nid,
                                branch,
                            });
                        }
                        // Don't add to known_hashes here — wait until the
                        // ledger diff is verified (hash_match=true). Otherwise
                        // new child hashes from queryDepth responses get marked
                        // "known" before their subtrees are walked.
                        // Validate hash: compute the node's hash from its children
                        // and verify it matches the parent's expected child hash.
                        // Matches rippled's addKnownNode hash check.
                        let computed_hash = {
                            let mut payload = Vec::with_capacity(4 + 512);
                            payload.extend_from_slice(&[0x4D, 0x49, 0x4E, 0x00]); // MIN\0
                            for child in &inner.children {
                                payload.extend_from_slice(child);
                            }
                            crate::crypto::sha512_first_half(&payload)
                        };
                        if self_hash != [0u8; 32] && computed_hash != self_hash {
                            // Hash mismatch — reject this node (peer sent invalid data)
                            tracing::warn!(
                                "sync: hash mismatch for nid={} expected={} computed={}",
                                hex::encode_upper(&nid[..8]),
                                hex::encode_upper(&self_hash[..8]),
                                hex::encode_upper(&computed_hash[..8]),
                            );
                            continue;
                        }

                        self.inner_count += 1;
                        inner_received += 1;
                        // Match rippled's addKnownNode: if node already exists,
                        // don't overwrite — just mark parent as received.
                        if self.has_node(&nid) {
                            self.mark_parent_received(&nid);
                        } else {
                            self.insert_node(nid, inner);
                            self.mark_parent_received(&nid);
                            self.update_full_below(&nid);
                        }
                        self.last_new_nodes = std::time::Instant::now();
                        self.stalled_retries = 0;
                    }
                }
                WIRE_TYPE_ACCOUNT_STATE => {
                    // Account state leaf: stobject + 32-byte key (wire type stripped)
                    if body.len() > 32 {
                        let key = body[body.len() - 32..].to_vec();
                        let stobject = body[..body.len() - 32].to_vec();
                        let mut key32 = [0u8; 32];
                        key32.copy_from_slice(&key);
                        let expected_hash = self_hash;
                        let computed_hash =
                            crate::ledger::sparse_shamap::leaf_hash(&stobject, &key32);
                        if expected_hash != [0u8; 32] && computed_hash != expected_hash {
                            tracing::warn!(
                                "sync: leaf hash mismatch for nid={} expected={} computed={} key={}",
                                hex::encode_upper(&nid[..8]),
                                hex::encode_upper(&expected_hash[..8]),
                                hex::encode_upper(&computed_hash[..8]),
                                hex::encode_upper(&key32[..8]),
                            );
                            continue;
                        }

                        self.leaf_count += 1;
                        leaf_received += 1;
                        leaves.push((key, stobject));
                        self.mark_parent_received(&nid);
                        self.update_full_below(&nid);
                        self.last_new_nodes = std::time::Instant::now();
                        self.stalled_retries = 0;
                    }
                }
                _ => {
                    // Transaction nodes (0, 4) or unknown — skip for state sync
                }
            }
        }

        if inner_received + leaf_received > 0 {
            self.last_response = std::time::Instant::now();
            self.last_type2 = self.last_response;
            self.stalled_retries = 0;
        }

        SyncProgress {
            inner_received,
            leaf_received,
            pending: 0, // caller uses build_next_request / is_truly_complete instead
            total_inner: self.inner_count,
            total_leaf: self.leaf_count,
            leaves,
            diff_deletions,
        }
    }

    /// Mark a node's parent inner node branch as received.
    fn mark_parent_received(&mut self, child_id: &[u8; 33]) {
        if let Some((parent_id, branch)) = parent_and_branch(child_id) {
            if let Some(parent) = self.ensure_cached_mut(&parent_id) {
                parent.mark_received(branch as usize);
            }
        }
    }

    /// For differential sync: when a new inner node arrives, compare its children
    /// against the old node at the same position. Children with matching hashes
    /// are unchanged — mark them as received (skipping re-download).
    /// Also detects deletions (old non-zero → new zero) and returns them.
    /// Check a new inner node for deletions (branches that went non-zero → zero).
    /// Content-addressed skipping is handled in process_response via known_hashes.
    fn diff_detect_deletions(
        &self,
        _nid: &[u8; 33],
        _new_node: &mut InnerNode,
    ) -> Vec<(u8, [u8; 32])> {
        // With inner_nodes cleared in update_root_for_diff, there's no old node
        // to compare against at non-root positions. Deletions at deeper levels
        // are detected when the parent inner node arrives and a child hash is zero
        // where the old parent (from known_hashes) had non-zero. For now, deletions
        // are detected at the root level in update_root_for_diff.
        Vec::new()
    }

    /// Get a node's self_hash from its parent's child hash array.
    pub fn get_self_hash(&self, nid: &[u8; 33]) -> [u8; 32] {
        if let Some((parent_id, branch)) = parent_and_branch(nid) {
            if let Some(parent) = self.get_node(&parent_id) {
                return parent.children[branch as usize];
            }
        }
        [0u8; 32] // root has no parent — hash comes from ledger header
    }

    /// After receiving a child node, check if the parent is now fully complete.
    /// If all children of the parent are received and all inner children are
    /// fullBelow → insert parent's self_hash into full_below.
    /// Propagates up the tree.
    fn update_full_below(&mut self, child_id: &[u8; 33]) {
        let mut current = *child_id;
        loop {
            let (parent_id, _branch) = match parent_and_branch(&current) {
                Some(p) => p,
                None => break,
            };
            // Load parent into cache if needed
            let _ = self.get_node_or_load(&parent_id);
            // Check if ALL non-empty children are received and full below
            let all_complete = {
                let parent = match self.node_cache.get(&parent_id) {
                    Some(p) => p,
                    None => break,
                };
                let mut complete = true;
                for b in 0..16 {
                    if parent.is_empty_branch(b) {
                        continue;
                    }
                    if !parent.is_received(b) {
                        complete = false;
                        break;
                    }
                    let child =
                        build_child_id(&parse_node_id(&parent_id).0, parent_id[32], b as u8);
                    // Check child in cache — leaf children (not in cache) are implicitly full
                    let child_full_below = if let Some(child_node) = self.node_cache.get(&child) {
                        child_node.is_full_below
                    } else {
                        true // not in cache = leaf or already complete
                    };
                    if !child_full_below {
                        complete = false;
                        break;
                    }
                }
                complete
            };
            if all_complete {
                if let Some(parent) = self.node_cache.get_mut(&parent_id) {
                    parent.is_full_below = true;
                }
                current = parent_id;
            } else {
                break;
            }
        }
    }

    /// Walk the inner node tree from root, find children that haven't been received.
    /// Uses rippled's deferred-read pattern: walk tree, on cache miss defer the read,
    /// batch-fetch deferred IDs from RocksDB, then resume walk with fetched data.
    /// Returns up to `max` missing node IDs.
    pub fn get_missing_nodes(
        &self,
        max: usize,
        _random_start: usize,
        _storage: Option<&crate::storage::Storage>,
    ) -> Vec<[u8; 33]> {
        let root_id = [0u8; 33];
        let root = match self.get_node_or_load_readonly(&root_id) {
            Some(n) => n,
            None => return vec![root_id],
        };
        if root.is_full_below {
            return vec![];
        }

        let mut missing = Vec::new();
        let mut stack: Vec<[u8; 33]> = vec![root_id];

        while let Some(node_id) = stack.pop() {
            if missing.len() >= max {
                break;
            }

            let inner = match self.get_node_or_load_readonly(&node_id) {
                Some(n) => n,
                None => continue,
            };

            let (path, depth) = parse_node_id(&node_id);
            let node_random = rand::random::<u8>();
            for i in 0..16u8 {
                let branch = (node_random.wrapping_add(i)) % 16;
                if inner.is_empty_branch(branch as usize) {
                    continue;
                }

                let child_hash = inner.children[branch as usize];
                if self.known_hashes.contains(&child_hash) {
                    continue;
                }

                if inner.is_received(branch as usize) {
                    let child_id = build_child_id(&path, depth, branch);
                    let child_full_below = self
                        .get_node_or_load_readonly(&child_id)
                        .map(|n| n.is_full_below)
                        .unwrap_or(true); // not in RocksDB = leaf or evicted = complete
                    if !child_full_below {
                        stack.push(child_id);
                    }
                } else {
                    let child_id = build_child_id(&path, depth, branch);
                    missing.push(child_id);
                    if missing.len() >= max {
                        break;
                    }
                }
            }
        }

        missing
    }

    /// Check if a specific cookie is outstanding (for diagnostics on dropped responses).
    pub fn has_cookie(&self, cookie: u32) -> bool {
        self.outstanding_cookies.contains(&cookie)
    }

    /// Number of outstanding request cookies (for diagnostics).
    pub fn outstanding_cookie_count(&self) -> usize {
        self.outstanding_cookies.len()
    }

    pub fn recent_node_count(&self) -> usize {
        self.recent_nodes.len()
    }

    /// Returns `true` when sync is complete: root exists and no missing nodes.
    pub fn is_truly_complete(&self, storage: Option<&crate::storage::Storage>) -> bool {
        // Don't gate on in_flight — lost responses can leave it nonzero.
        // The actual authority is get_missing_nodes returning empty.
        self.has_node(&[0u8; 33]) && self.get_missing_nodes(1, 0, storage).is_empty()
    }

    /// Returns `true` when the current pass has stalled or completed.
    /// A pass is "complete" when either:
    ///   - Sync is truly done, OR
    ///   - No new leaves arrived since the pass started (stalled pass)
    /// This allows the stall recovery logic to start a new pass with fresh requests.
    pub fn is_pass_complete(&self, storage: Option<&crate::storage::Storage>) -> bool {
        if self.is_truly_complete(storage) {
            return true;
        }
        // Pass stalled if no new leaves since pass start
        self.leaf_count == self.pass_start_leaf_count
            && self.last_new_nodes.elapsed().as_secs() > 10
    }

    /// Start a new pass — resets in_flight and timestamps so the walker
    /// re-discovers missing nodes and sends fresh requests.
    /// Does NOT reset stalled_retries — caller decides based on progress.
    pub fn start_new_pass(&mut self) {
        self.pass_number += 1;
        self.pass_start_leaf_count = self.leaf_count;
        self.reset_in_flight();
        self.last_response = std::time::Instant::now();
        self.last_new_nodes = std::time::Instant::now();
    }

    /// Evict completed subtrees from the in-memory cache to free memory.
    /// With RocksDB backing, the LRU cache is bounded at NODE_CACHE_CAP so
    /// explicit eviction is less critical. This now only evicts full_below
    /// nodes from the cache (they remain in RocksDB), adding their hashes
    /// to known_hashes for walk skipping.
    /// Returns the number of evicted nodes.

    /// Returns the leaf count (for persistence).
    pub fn get_leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Returns the number of new objects discovered in the current pass.
    pub fn new_objects_this_pass(&self) -> usize {
        self.leaf_count.saturating_sub(self.pass_start_leaf_count)
    }

    /// Try to parse an AccountRoot from a leaf node's STObject data.
    pub fn parse_account_root(stobject: &[u8]) -> Option<crate::ledger::AccountRoot> {
        if stobject.len() < 3 {
            return None;
        }
        if stobject[0] != 0x11 {
            return None;
        }
        let entry_type = u16::from_be_bytes([stobject[1], stobject[2]]);
        if entry_type != 0x0061 {
            return None;
        }
        crate::ledger::AccountRoot::decode(stobject).ok()
    }

    /// Returns a bounded count of currently missing nodes.
    /// This is used for logging and coarse control flow, not exact accounting.
    pub fn pending_count(&self, storage: Option<&crate::storage::Storage>) -> usize {
        self.get_missing_nodes(256, 0, storage).len()
    }

    /// Return child hashes for currently missing state nodes.
    /// Used by the rippled-style TMGetObjectByHash timeout fallback.
    pub fn get_needed_hashes(
        &self,
        max: usize,
        storage: Option<&crate::storage::Storage>,
    ) -> Vec<([u8; 32], [u8; 33])> {
        let missing = self.get_missing_nodes(max, 0, storage);
        let mut out = Vec::with_capacity(missing.len());
        for node_id in missing {
            if let Some((parent_id, branch)) = parent_and_branch(&node_id) {
                if let Some(parent) = self.get_node_or_load_readonly(&parent_id) {
                    let child_hash = parent.children[branch as usize];
                    if child_hash != [0u8; 32] {
                        out.push((child_hash, node_id));
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_header_too_short() {
        assert!(parse_ledger_header_from_base(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_header_with_prefix() {
        let mut data = vec![0x4C, 0x57, 0x52, 0x00]; // prefix
        data.extend_from_slice(&42u32.to_be_bytes());
        data.extend_from_slice(&100_000_000u64.to_be_bytes());
        data.extend_from_slice(&[0xAA; 32]);
        data.extend_from_slice(&[0xBB; 32]);
        data.extend_from_slice(&[0xCC; 32]);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&1000u32.to_be_bytes());
        data.push(10);
        data.push(0);

        let hdr = parse_ledger_header_from_base(&data).unwrap();
        assert_eq!(hdr.sequence, 42);
        assert_eq!(hdr.total_coins, 100_000_000);
        assert_eq!(hdr.parent_hash, [0xAA; 32]);
        assert_eq!(hdr.transaction_hash, [0xBB; 32]);
        assert_eq!(hdr.account_hash, [0xCC; 32]);
        assert_eq!(hdr.close_time, 1000);
    }

    #[test]
    fn test_parse_header_without_prefix() {
        let mut data = Vec::new();
        data.extend_from_slice(&7u32.to_be_bytes());
        data.extend_from_slice(&500u64.to_be_bytes());
        data.extend_from_slice(&[0x11; 32]);
        data.extend_from_slice(&[0x22; 32]);
        data.extend_from_slice(&[0x33; 32]);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&2000u32.to_be_bytes());
        data.push(20);
        data.push(1);

        let hdr = parse_ledger_header_from_base(&data).unwrap();
        assert_eq!(hdr.sequence, 7);
        assert_eq!(hdr.close_time, 2000);
    }

    #[test]
    fn test_build_child_id() {
        let parent = [0u8; 32];
        // Depth 0, branch 5 → nibble at pos 0 high nibble = 0x50
        let child = build_child_id(&parent, 0, 5);
        assert_eq!(child[0], 0x50);
        assert_eq!(child[32], 1); // depth

        // Depth 1, branch 3 → nibble at pos 0 low nibble = 0x03
        let mut parent2 = [0u8; 32];
        parent2[0] = 0x50; // from previous
        let child2 = build_child_id(&parent2, 1, 3);
        assert_eq!(child2[0], 0x53);
        assert_eq!(child2[32], 2); // depth
    }

    #[test]
    fn test_parent_and_branch() {
        let parent = [0u8; 32];
        let child = build_child_id(&parent, 0, 7);
        let (parent_id, branch) = parent_and_branch(&child).unwrap();
        assert_eq!(parent_id, [0u8; 33]); // root
        assert_eq!(branch, 7);
    }

    #[test]
    fn test_inner_node_full() {
        let mut data = [0u8; 512];
        // Set branch 3 to a non-zero hash
        data[3 * 32] = 0xFF;
        let node = InnerNode::from_full(&data).unwrap();
        assert!(node.is_empty_branch(0));
        assert!(!node.is_empty_branch(3));
        assert!(!node.is_received(3));
        // mark received
        let mut node = node;
        node.mark_received(3);
        assert!(node.is_received(3));
    }

    #[test]
    fn test_inner_node_compressed() {
        // One child at branch 5
        let mut data = vec![0xAA; 32]; // hash
        data.push(5); // branch position
        let node = InnerNode::from_compressed(&data).unwrap();
        assert!(node.is_empty_branch(0));
        assert!(!node.is_empty_branch(5));
        assert_eq!(node.children[5][0], 0xAA);
    }

    #[test]
    fn test_get_missing_nodes_empty() {
        let syncer = StateSyncer::new(1, [0; 32], [0; 32], None);
        let missing = syncer.get_missing_nodes(256, 0, None);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], [0u8; 33]);
    }

    #[test]
    fn test_get_missing_nodes_with_root() {
        let mut syncer = StateSyncer::new(1, [0; 32], [0; 32], None);
        let mut root = InnerNode {
            children: [[0u8; 32]; 16],
            received: 0,
            self_hash: [0u8; 32],
            is_full_below: false,
        };
        root.children[0] = [0xAA; 32];
        root.children[1] = [0xBB; 32];
        syncer.insert_node([0u8; 33], root);

        let missing = syncer.get_missing_nodes(256, 0, None);
        assert_eq!(missing.len(), 2);
    }

    #[test]
    fn test_accept_response_requires_matching_hash() {
        let ledger_hash = [0xAB; 32];
        let mut syncer = StateSyncer::new(10, ledger_hash, [0xCD; 32], None);

        // Wrong hash → rejected
        assert!(!syncer.accept_response(&[0x11; 32], None));

        // Right hash, no cookie → accepted (matches rippled: no cookies used)
        assert!(syncer.accept_response(&ledger_hash, None));

        // Right hash, any cookie → accepted
        assert!(syncer.accept_response(&ledger_hash, Some(999)));
    }

    #[test]
    fn test_peer_sync_manager_accepts_ltclosed_ledgerdata_responses() {
        let mut peer = PeerSyncManager::new(10, [0u8; 32], [0xCD; 32]);
        assert!(peer.accepts_ltclosed_responses());
        peer.outstanding_cookies.insert(55);
        peer.in_flight = 1;
        assert!(peer.accept_response(&[0xAB; 32], Some(55)));
        assert_eq!(peer.in_flight, 0);
    }

    #[test]
    fn test_peer_sync_manager_accepts_ltclosed_object_response_by_seq() {
        let mut peer = PeerSyncManager::new(10, [0u8; 32], [0xCD; 32]);
        peer.outstanding_object_queries.insert(77);

        assert!(peer.accept_object_response(&[0xEF; 32], Some(77)));
        assert!(!peer.outstanding_object_queries.contains(&77));
        assert!(peer.responded_object_queries.contains(&77));
        assert!(!peer.accept_object_response(&[0xEF; 32], Some(78)));
    }

    #[test]
    fn test_peer_sync_manager_accepts_useful_stale_object_response_for_matching_ledger() {
        let mut peer = PeerSyncManager::new(10, [0xEF; 32], [0xCD; 32]);

        assert!(peer.accept_useful_stale_object_response(&[0xEF; 32], Some(77), 4));
        assert!(peer.responded_object_queries.contains(&77));
        assert!(!peer.accept_useful_stale_object_response(&[0xEF; 32], Some(77), 4));
    }

    #[test]
    fn test_peer_sync_manager_rejects_non_useful_or_wrong_hash_stale_object_response() {
        let mut peer = PeerSyncManager::new(10, [0xEF; 32], [0xCD; 32]);

        assert!(!peer.accept_useful_stale_object_response(&[0xEF; 32], Some(77), 0));
        assert!(!peer.accept_useful_stale_object_response(&[0xAA; 32], Some(77), 4));
        assert!(!peer.accept_useful_stale_object_response(&[0xEF; 32], None, 4));
        assert!(peer.responded_object_queries.is_empty());
    }

    #[test]
    fn test_peer_sync_manager_keeps_recent_hash_until_timer_clear() {
        let mut peer = PeerSyncManager::new(10, [0xAB; 32], [0xCD; 32]);
        let node_id = crate::ledger::shamap_id::SHAMapNodeID::new(1, [0u8; 32]);
        let node_hash = [0x11; 32];
        let missing = vec![(node_id, node_hash)];

        let reqs = peer.build_requests_from_missing(&missing, SyncRequestReason::Reply);
        assert_eq!(reqs.len(), 1);
        assert!(peer.recent_nodes.contains(&node_hash));

        let mut payload = vec![0u8; 64];
        payload.extend_from_slice(&node_id.id()[..]);
        payload.push(0x01);
        let ld = crate::proto::TmLedgerData {
            ledger_hash: vec![0xAB; 32],
            ledger_seq: 10,
            r#type: crate::proto::TmLedgerInfoType::LiAsNode as i32,
            nodes: vec![crate::proto::TmLedgerNode {
                nodedata: payload,
                nodeid: Some(node_id.to_wire().to_vec()),
            }],
            request_cookie: None,
            error: None,
        };

        let parsed = peer.parse_response(&ld);
        assert_eq!(parsed.nodes.len(), 1);
        assert!(peer.recent_nodes.contains(&node_hash));

        peer.clear_recent();
        assert!(!peer.recent_nodes.contains(&node_hash));
    }

    #[test]
    fn test_peer_sync_manager_query_depth_matches_rippled_reason_rules() {
        use prost::Message as _;

        let node_id = crate::ledger::shamap_id::SHAMapNodeID::new(1, [0u8; 32]);
        let missing = vec![(node_id, [0x11; 32])];

        let mut reply_peer = PeerSyncManager::new(10, [0xAB; 32], [0xCD; 32]);
        let reply_req = reply_peer.build_requests_from_missing(&missing, SyncRequestReason::Reply);
        assert_eq!(reply_req.len(), 1);
        let reply_pb = crate::proto::TmGetLedger::decode(reply_req[0].payload.as_slice())
            .expect("reply request should decode");
        assert_eq!(reply_pb.query_depth, Some(1));
        let reply_cookie = reply_pb
            .request_cookie
            .expect("reply request should carry a cookie") as u32;
        assert!(reply_peer.has_cookie(reply_cookie));

        let mut timeout_peer = PeerSyncManager::new(10, [0xAB; 32], [0xCD; 32]);
        let timeout_req =
            timeout_peer.build_requests_from_missing(&missing, SyncRequestReason::Timeout);
        assert_eq!(timeout_req.len(), 1);
        let timeout_pb = crate::proto::TmGetLedger::decode(timeout_req[0].payload.as_slice())
            .expect("timeout request should decode");
        assert_eq!(timeout_pb.query_depth, Some(0));
        let timeout_cookie = timeout_pb
            .request_cookie
            .expect("timeout request should carry a cookie") as u32;
        assert!(timeout_peer.has_cookie(timeout_cookie));
    }

    #[test]
    fn test_peer_sync_manager_request_caps_match_rippled_constants() {
        use prost::Message as _;

        let mut missing = Vec::new();
        for idx in 0..300u16 {
            let mut nibble = [0u8; 32];
            nibble[0] = (idx & 0xFF) as u8;
            let node_id = crate::ledger::shamap_id::SHAMapNodeID::new(1, nibble);
            let mut hash = [0u8; 32];
            hash[0] = (idx & 0xFF) as u8;
            missing.push((node_id, hash));
        }

        let mut reply_peer = PeerSyncManager::new(10, [0xAB; 32], [0xCD; 32]);
        let reply_req = reply_peer.build_requests_from_missing(&missing, SyncRequestReason::Reply);
        assert_eq!(reply_req.len(), 1);
        let reply_pb = crate::proto::TmGetLedger::decode(reply_req[0].payload.as_slice())
            .expect("reply request should decode");
        assert_eq!(
            reply_pb.node_i_ds.len(),
            crate::ledger::inbound::REQ_NODES_REPLY
        );

        let mut timeout_peer = PeerSyncManager::new(10, [0xAB; 32], [0xCD; 32]);
        let timeout_req =
            timeout_peer.build_requests_from_missing(&missing, SyncRequestReason::Timeout);
        assert_eq!(timeout_req.len(), 1);
        let timeout_pb = crate::proto::TmGetLedger::decode(timeout_req[0].payload.as_slice())
            .expect("timeout request should decode");
        assert_eq!(
            timeout_pb.node_i_ds.len(),
            crate::ledger::inbound::REQ_NODES_TIMEOUT
        );
    }

    #[test]
    fn test_peer_sync_manager_tracks_reply_requests_as_in_flight() {
        use prost::Message as _;

        let node_id = crate::ledger::shamap_id::SHAMapNodeID::new(1, [0u8; 32]);
        let missing = vec![(node_id, [0x11; 32])];
        let mut peer = PeerSyncManager::new(10, [0xAB; 32], [0xCD; 32]);

        let reqs = peer.build_requests_from_missing(&missing, SyncRequestReason::Reply);
        assert_eq!(reqs.len(), 1);
        assert_eq!(peer.in_flight, 1);
        let pb = crate::proto::TmGetLedger::decode(reqs[0].payload.as_slice())
            .expect("request should decode");
        let cookie = pb.request_cookie.expect("request should carry cookie") as u32;

        assert!(peer.accept_response(&[0xAB; 32], Some(cookie)));
        assert_eq!(peer.in_flight, 0);
    }

    #[test]
    fn test_peer_sync_manager_rejects_unknown_cookie_and_prefix_only_hash_match() {
        let mut peer = PeerSyncManager::new(10, [0xAB; 32], [0xCD; 32]);
        peer.outstanding_cookies.insert(7);

        let mut prefix_only = [0xAB; 32];
        prefix_only[31] = 0x42;
        assert!(!peer.accept_response(&prefix_only, Some(7)));
        assert!(peer.outstanding_cookies.contains(&7));

        assert!(!peer.accept_response(&[0xAB; 32], Some(8)));
        assert!(peer.outstanding_cookies.contains(&7));
        assert!(!peer.accept_response(&[0xAB; 32], None));
        assert!(peer.outstanding_cookies.contains(&7));
    }

    #[test]
    fn test_peer_sync_manager_timer_tick_clears_recent_nodes() {
        let mut peer = PeerSyncManager::new(10, [0xAB; 32], [0xCD; 32]);
        peer.recent_nodes.insert([0x44; 32]);
        peer.note_progress();

        assert_eq!(
            peer.on_timer_tick(),
            Some(crate::ledger::inbound::TimeoutTick::Progress)
        );
        assert!(peer.recent_nodes.is_empty());
    }

    #[test]
    fn test_object_rescue_progress_resets_timeout_and_inflight_state() {
        let mut peer = PeerSyncManager::new(10, [0xAB; 32], [0xCD; 32]);
        peer.in_flight = 7;
        peer.stalled_retries = 5;
        peer.by_hash_armed = true;
        peer.tail_stuck_hash = [0x55; 32];
        peer.tail_stuck_retries = 4;
        peer.timeout.timeouts = 6;
        peer.recent_nodes.insert([0x44; 32]);
        peer.outstanding_cookies.insert(123);
        peer.outstanding_object_queries.insert(456);

        peer.note_object_rescue_progress();

        assert_eq!(peer.stalled_retries, 0);
        assert!(!peer.by_hash_armed);
        assert_eq!(peer.tail_stuck_hash, [0u8; 32]);
        assert_eq!(peer.tail_stuck_retries, 0);
        assert_eq!(peer.timeout.timeouts, 0);
        assert_eq!(peer.in_flight, 0);
        assert!(peer.recent_nodes.is_empty());
        assert!(peer.outstanding_cookies.is_empty());
        assert!(peer.outstanding_object_queries.is_empty());
        assert_eq!(
            peer.on_timer_tick(),
            Some(crate::ledger::inbound::TimeoutTick::Progress)
        );
    }

    #[test]
    fn test_all_dup_suppressed_for_reply_allowed_for_timeout() {
        // When all missing nodes are in recent_nodes, reply requests are
        // suppressed (matching rippled). Timeout requests still go through.
        let mut syncer = StateSyncer::new(1, [0x11; 32], [0x22; 32], None);
        let mut root = InnerNode {
            children: [[0u8; 32]; 16],
            received: 0,
            self_hash: [0u8; 32],
            is_full_below: false,
        };
        root.children[0] = [0xAA; 32];
        syncer.insert_node([0u8; 33], root);
        syncer.recent_nodes.insert([0xAA; 32]);

        // All duplicates: reply suppressed, timeout allowed
        assert!(syncer.build_next_request(None).is_none());
        assert!(syncer.build_timeout_request(None).is_some());
    }

    #[test]
    fn test_legacy_state_sync_query_depth_matches_rippled_reason_rules() {
        use prost::Message as _;

        let mut syncer = StateSyncer::new(1, [0x11; 32], [0x22; 32], None);
        let mut root = InnerNode {
            children: [[0u8; 32]; 16],
            received: 0,
            self_hash: [0u8; 32],
            is_full_below: false,
        };
        root.children[0] = [0xAA; 32];
        syncer.insert_node([0u8; 33], root);

        let reply_req = syncer
            .build_next_request(None)
            .expect("reply request should exist");
        let reply_pb = crate::proto::TmGetLedger::decode(reply_req.payload.as_slice())
            .expect("reply request should decode");
        assert_eq!(reply_pb.query_depth, Some(1));

        syncer.clear_recent();
        let timeout_req = syncer
            .build_timeout_request(None)
            .expect("timeout request should exist");
        let timeout_pb = crate::proto::TmGetLedger::decode(timeout_req.payload.as_slice())
            .expect("timeout request should decode");
        assert_eq!(timeout_pb.query_depth, Some(0));
    }

    #[test]
    fn test_check_local_returns_zero_without_storage_backed_nodes() {
        // With RocksDB removed, check_local always returns 0 (no storage lookups).
        let mut syncer = StateSyncer::new(1, [0x11; 32], [0x22; 32], None);
        let mut root = InnerNode {
            children: [[0u8; 32]; 16],
            received: 0,
            self_hash: [0u8; 32],
            is_full_below: false,
        };
        root.children[0] = [0x55; 32];
        syncer.insert_node([0u8; 33], root);

        assert_eq!(syncer.check_local(None, 16), 0);
    }

    #[test]
    fn test_depth_mask_depth_0() {
        let mut path = [0xFF; 32];
        apply_depth_mask(&mut path, 0);
        assert_eq!(path, [0u8; 32], "depth 0: all bytes should be zero");
    }

    #[test]
    fn test_depth_mask_depth_1() {
        let mut path = [0xFF; 32];
        apply_depth_mask(&mut path, 1);
        assert_eq!(path[0], 0xF0, "depth 1: byte 0 upper nibble only");
        assert_eq!(path[1], 0x00);
        assert_eq!(path[31], 0x00);
    }

    #[test]
    fn test_depth_mask_depth_2() {
        let mut path = [0xFF; 32];
        apply_depth_mask(&mut path, 2);
        assert_eq!(path[0], 0xFF, "depth 2: byte 0 both nibbles");
        assert_eq!(path[1], 0x00, "depth 2: byte 1 zeroed");
        assert_eq!(path[31], 0x00);
    }

    #[test]
    fn test_depth_mask_depth_52() {
        let mut path = [0xFF; 32];
        apply_depth_mask(&mut path, 52);
        // depth 52 = 26 full bytes, bytes 26-31 zeroed
        for i in 0..26 {
            assert_eq!(path[i], 0xFF, "depth 52: byte {} should be FF", i);
        }
        for i in 26..32 {
            assert_eq!(path[i], 0x00, "depth 52: byte {} should be 00", i);
        }
    }

    #[test]
    fn test_depth_mask_depth_53() {
        let mut path = [0xFF; 32];
        apply_depth_mask(&mut path, 53);
        // depth 53 = 26 full bytes + upper nibble of byte 26
        for i in 0..26 {
            assert_eq!(path[i], 0xFF);
        }
        assert_eq!(path[26], 0xF0, "depth 53: byte 26 upper nibble only");
        for i in 27..32 {
            assert_eq!(path[i], 0x00);
        }
    }

    #[test]
    fn test_depth_mask_depth_63() {
        let mut path = [0xFF; 32];
        apply_depth_mask(&mut path, 63);
        // depth 63 = 31 full bytes + upper nibble of byte 31
        for i in 0..31 {
            assert_eq!(path[i], 0xFF);
        }
        assert_eq!(path[31], 0xF0, "depth 63: byte 31 upper nibble only");
    }

    #[test]
    fn test_depth_mask_depth_64() {
        let mut path = [0xFF; 32];
        apply_depth_mask(&mut path, 64);
        // depth 64 = all 32 bytes
        assert_eq!(path, [0xFF; 32], "depth 64: all bytes preserved");
    }

    #[test]
    fn test_build_child_id_masks_correctly_at_depth_52() {
        // Parent at depth 51 with garbage in bytes 26-31
        let mut parent = [0xFF; 32]; // all bits set
        apply_depth_mask(&mut parent, 51);
        // depth 51: bytes 0-24 = FF, byte 25 upper nibble = F0, bytes 26-31 = 00
        assert_eq!(parent[25], 0xF0);
        assert_eq!(parent[26], 0x00);

        // Build child at depth 52, branch 0xA
        let child = build_child_id(&parent, 51, 0xA);
        assert_eq!(child[32], 52, "child depth should be 52");
        // depth 51 is odd → branch goes in byte 25 lower nibble
        assert_eq!(child[25], 0xFA, "byte 25 = parent F0 | branch A");
        // bytes 26-31 must be zero (depth 52 mask)
        for i in 26..32 {
            assert_eq!(child[i], 0x00, "depth 52 child: byte {} must be 0", i);
        }
    }

    #[test]
    fn test_build_child_id_masks_correctly_at_depth_1() {
        let parent = [0u8; 32]; // root
        let child = build_child_id(&parent, 0, 0xC);
        assert_eq!(child[32], 1);
        assert_eq!(child[0], 0xC0, "branch C in upper nibble");
        for i in 1..32 {
            assert_eq!(child[i], 0x00, "depth 1: byte {} must be 0", i);
        }
    }

    #[test]
    fn test_object_reply_to_store_strips_known_prefixes() {
        let mut inner = STORAGE_PREFIX_INNER.to_vec();
        inner.extend_from_slice(&[0xAB; 16 * 32]);
        assert_eq!(
            object_reply_to_store(&inner).expect("inner blob should normalize"),
            vec![0xAB; 16 * 32]
        );

        let mut leaf = STORAGE_PREFIX_LEAF.to_vec();
        leaf.extend_from_slice(&[0xCD; 96]);
        assert_eq!(
            object_reply_to_store(&leaf).expect("leaf blob should normalize"),
            vec![0xCD; 96]
        );
    }

    #[test]
    fn test_object_reply_to_store_keeps_raw_payload() {
        let raw = vec![0xEF; 16 * 32];
        assert_eq!(
            object_reply_to_store(&raw).expect("raw blob should normalize"),
            raw
        );
    }

    #[test]
    fn test_object_reply_to_verified_store_accepts_matching_inner_node() {
        let normalized = vec![0xAB; 16 * 32];
        let mut prefixed = STORAGE_PREFIX_INNER.to_vec();
        prefixed.extend_from_slice(&normalized);
        let expected_hash = crate::crypto::sha512_first_half(&prefixed);
        assert_eq!(
            object_reply_to_verified_store(&expected_hash, &prefixed)
                .expect("matching inner node should verify"),
            normalized
        );
    }

    #[test]
    fn test_object_reply_to_verified_store_accepts_matching_stripped_inner_node() {
        let normalized = vec![0xBC; 16 * 32];
        let mut prefixed = STORAGE_PREFIX_INNER.to_vec();
        prefixed.extend_from_slice(&normalized);
        let expected_hash = crate::crypto::sha512_first_half(&prefixed);
        assert_eq!(
            object_reply_to_verified_store(&expected_hash, &normalized)
                .expect("stripped inner node should verify"),
            normalized
        );
    }

    #[test]
    fn test_store_to_object_reply_reprefixes_stripped_leaf() {
        let normalized = vec![0xCD; 96];
        let mut expected = STORAGE_PREFIX_LEAF.to_vec();
        expected.extend_from_slice(&normalized);
        assert_eq!(
            store_to_object_reply(&normalized).expect("stripped leaf should reprifix"),
            expected
        );
    }

    #[test]
    fn test_object_reply_to_verified_store_rejects_hash_mismatch() {
        let raw = vec![0x44; 16 * 32];
        assert!(
            object_reply_to_verified_store(&[0xAB; 32], &raw).is_none(),
            "mismatched content hash must be rejected"
        );
    }

    #[test]
    fn test_object_reply_to_verified_store_rejects_raw_hash_only_inner_payload() {
        let raw = vec![0x7A; 16 * 32];
        let expected_hash = crate::crypto::sha512_first_half(&raw);
        assert!(
            object_reply_to_verified_store(&expected_hash, &raw).is_none(),
            "raw hash-only payloads should not be accepted into typed SHAMap storage"
        );
    }
}
