//! Content-addressed storage for SHAMap nodes.
//!
//! Nodes are keyed by their content hash, which is the SHA-512-half of the
//! serialized node bytes. Both inner nodes and leaf nodes are stored here, and
//! the SHAMap structure itself provides the lookup path.
//!
//! The crate ships with a NuDB-backed store for persistent operation and an
//! in-memory store for tests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

const PREFIX_INNER_NODE: [u8; 4] = [0x4D, 0x49, 0x4E, 0x00]; // MIN\0
const PREFIX_LEAF_STATE: [u8; 4] = [0x4D, 0x4C, 0x4E, 0x00]; // MLN\0
const PREFIX_LEAF_TX_WITH_META: [u8; 4] = [0x53, 0x4E, 0x44, 0x00]; // SND\0
const PREFIX_LEAF_TX_NO_META: [u8; 4] = [0x54, 0x58, 0x4E, 0x00]; // TXN\0
const PREFIX_LEDGER: [u8; 4] = [0x4C, 0x57, 0x52, 0x00]; // LWR\0

/// xLedgRS-created NuDB files deliberately use a private appnum until the
/// backend can read/write rippled's NodeStore codec rows.
pub const XLEDGRS_NUDB_APPNUM: u64 = 0x4C44_5253;
pub const RIPPLED_NUDB_APPNUM: u64 = 1;
pub const RIPPLED_NODE_OBJECT_ENVELOPE_LEN: usize = 9;

/// rippled NodeStore object families.
///
/// rippled stores ledger headers, account-state SHAMap nodes, and transaction
/// SHAMap nodes in the same content-addressed backend. xLedgRS keeps the
/// public storage API simple, but typed writes let sync/fetch code stop
/// treating every persistent row as an account-state node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeObjectType {
    Ledger,
    AccountNode,
    /// Ledger transaction map nodes. Leaf rows include metadata and use
    /// rippled's SND hash domain.
    TransactionNode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeObjectKind {
    Ledger,
    Inner,
    Leaf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedNodeObject {
    pub object_type: NodeObjectType,
    /// Prefixless payload used by the current xLedgRS private store.
    pub data: Vec<u8>,
    /// Hash prefix that was present in the source payload, if any.
    pub hash_prefix: Option<[u8; 4]>,
    pub kind: NodeObjectKind,
}

impl NodeObjectType {
    pub fn rippled_code(self) -> u8 {
        match self {
            NodeObjectType::Ledger => 1,
            NodeObjectType::AccountNode => 3,
            NodeObjectType::TransactionNode => 4,
        }
    }

    pub fn from_rippled_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(NodeObjectType::Ledger),
            3 => Some(NodeObjectType::AccountNode),
            4 => Some(NodeObjectType::TransactionNode),
            _ => None,
        }
    }
}

/// Encode a rippled `EncodedBlob`-style NodeObject value.
///
/// This is only the NodeObject envelope (`8 unused bytes || type || data`).
/// rippled's NuDB backend can additionally wrap this value with its NodeStore
/// codec/LZ4 layer before insertion; xLedgRS does not implement that disk
/// format yet.
pub fn encode_rippled_node_object_envelope(
    object_type: NodeObjectType,
    data: &[u8],
) -> Option<Vec<u8>> {
    let payload = prefix_typed_node_object_payload(object_type, data)?;
    let mut row = Vec::with_capacity(RIPPLED_NODE_OBJECT_ENVELOPE_LEN + payload.len());
    row.extend_from_slice(&[0u8; 8]);
    row.push(object_type.rippled_code());
    row.extend_from_slice(&payload);
    Some(row)
}

/// Decode a rippled `EncodedBlob`-style NodeObject value and normalize the
/// payload to the prefixless xLedgRS representation.
pub fn decode_rippled_node_object_envelope(
    expected_hash: &[u8; 32],
    row: &[u8],
) -> Option<DecodedNodeObject> {
    if row.len() <= RIPPLED_NODE_OBJECT_ENVELOPE_LEN {
        return None;
    }
    let object_type = NodeObjectType::from_rippled_code(row[8])?;
    let decoded = normalize_typed_node_object_payload(object_type, &row[9..])?;
    validate_node_object(object_type, expected_hash, &decoded.data).then_some(decoded)
}

/// Normalize a persisted row into the prefixless representation expected by
/// the in-memory SHAMap code.
///
/// xLedgRS private stores write prefixless rows. rippled NodeStore rows may be
/// `EncodedBlob` envelopes (`8 unused bytes || type || hash-prefixed data`).
/// Accept both on read so a future rippled-compatible backend can be introduced
/// without teaching every SHAMap caller about storage envelopes.
pub fn normalize_persisted_node_row(expected_hash: &[u8; 32], row: Vec<u8>) -> Option<Vec<u8>> {
    if validate_shamap_store_node(expected_hash, &row)
        || validate_ledger_store_node(expected_hash, &row)
    {
        return Some(row);
    }
    decode_rippled_node_object_envelope(expected_hash, &row).map(|decoded| decoded.data)
}

/// Normalize typed NodeObject payload bytes.
///
/// Accepts either rippled's hash-prefixed object data or the current xLedgRS
/// prefixless form. Known hash prefixes for the wrong object family are
/// rejected so transaction rows cannot be silently imported as account nodes.
pub fn normalize_typed_node_object_payload(
    object_type: NodeObjectType,
    data: &[u8],
) -> Option<DecodedNodeObject> {
    match object_type {
        NodeObjectType::Ledger => normalize_ledger_payload(data),
        NodeObjectType::AccountNode => normalize_shamap_payload(data, &PREFIX_LEAF_STATE),
        NodeObjectType::TransactionNode => {
            normalize_shamap_payload(data, &PREFIX_LEAF_TX_WITH_META)
        }
    }
    .map(|(data, hash_prefix, kind)| DecodedNodeObject {
        object_type,
        data,
        hash_prefix,
        kind,
    })
}

pub fn prefix_typed_node_object_payload(
    object_type: NodeObjectType,
    data: &[u8],
) -> Option<Vec<u8>> {
    match object_type {
        NodeObjectType::Ledger => prefix_ledger_payload(data),
        NodeObjectType::AccountNode => prefix_shamap_payload(data, &PREFIX_LEAF_STATE),
        NodeObjectType::TransactionNode => prefix_shamap_payload(data, &PREFIX_LEAF_TX_WITH_META),
    }
}

pub fn validate_account_state_store_node(expected_hash: &[u8; 32], data: &[u8]) -> bool {
    validate_node_object(NodeObjectType::AccountNode, expected_hash, data)
}

pub fn validate_transaction_store_node(expected_hash: &[u8; 32], data: &[u8]) -> bool {
    validate_transaction_with_metadata_store_node(expected_hash, data)
}

pub fn validate_transaction_with_metadata_store_node(
    expected_hash: &[u8; 32],
    data: &[u8],
) -> bool {
    validate_node_object(NodeObjectType::TransactionNode, expected_hash, data)
}

pub fn validate_transaction_no_metadata_store_node(expected_hash: &[u8; 32], data: &[u8]) -> bool {
    decode_transaction_no_metadata_store_node_kind(expected_hash, data).is_some()
}

pub fn decode_transaction_no_metadata_store_node_kind(
    expected_hash: &[u8; 32],
    data: &[u8],
) -> Option<NodeObjectKind> {
    decode_shamap_node_with_leaf_prefix(expected_hash, data, &PREFIX_LEAF_TX_NO_META)
}

pub fn validate_ledger_store_node(expected_hash: &[u8; 32], data: &[u8]) -> bool {
    validate_node_object(NodeObjectType::Ledger, expected_hash, data)
}

pub fn validate_shamap_store_node(expected_hash: &[u8; 32], data: &[u8]) -> bool {
    validate_account_state_store_node(expected_hash, data)
        || validate_transaction_store_node(expected_hash, data)
        || validate_transaction_no_metadata_store_node(expected_hash, data)
}

pub fn validate_node_object(
    object_type: NodeObjectType,
    expected_hash: &[u8; 32],
    data: &[u8],
) -> bool {
    decode_node_object_kind(object_type, expected_hash, data).is_some()
}

pub fn decode_node_object_kind(
    object_type: NodeObjectType,
    expected_hash: &[u8; 32],
    data: &[u8],
) -> Option<NodeObjectKind> {
    match object_type {
        NodeObjectType::Ledger => {
            let mut payload = Vec::with_capacity(PREFIX_LEDGER.len() + data.len());
            payload.extend_from_slice(&PREFIX_LEDGER);
            payload.extend_from_slice(data);
            (crate::crypto::sha512_first_half(&payload) == *expected_hash)
                .then_some(NodeObjectKind::Ledger)
        }
        NodeObjectType::AccountNode => {
            decode_shamap_node_with_leaf_prefix(expected_hash, data, &PREFIX_LEAF_STATE)
        }
        NodeObjectType::TransactionNode => {
            decode_shamap_node_with_leaf_prefix(expected_hash, data, &PREFIX_LEAF_TX_WITH_META)
        }
    }
}

fn decode_shamap_node_with_leaf_prefix(
    expected_hash: &[u8; 32],
    data: &[u8],
    leaf_prefix: &[u8; 4],
) -> Option<NodeObjectKind> {
    if data.len() == 16 * 32 {
        let mut payload = Vec::with_capacity(PREFIX_INNER_NODE.len() + data.len());
        payload.extend_from_slice(&PREFIX_INNER_NODE);
        payload.extend_from_slice(data);
        if crate::crypto::sha512_first_half(&payload) == *expected_hash {
            return Some(NodeObjectKind::Inner);
        }
    }

    if data.len() < 32 {
        return None;
    }

    let key_start = data.len() - 32;
    let mut payload = Vec::with_capacity(leaf_prefix.len() + data.len());
    payload.extend_from_slice(leaf_prefix);
    payload.extend_from_slice(&data[..key_start]);
    payload.extend_from_slice(&data[key_start..]);
    (crate::crypto::sha512_first_half(&payload) == *expected_hash).then_some(NodeObjectKind::Leaf)
}

fn normalize_ledger_payload(data: &[u8]) -> Option<(Vec<u8>, Option<[u8; 4]>, NodeObjectKind)> {
    if data.is_empty() {
        return None;
    }
    if data.starts_with(&PREFIX_LEDGER) {
        return Some((
            data[PREFIX_LEDGER.len()..].to_vec(),
            Some(PREFIX_LEDGER),
            NodeObjectKind::Ledger,
        ));
    }
    if starts_with_known_hash_prefix(data) {
        return None;
    }
    Some((data.to_vec(), None, NodeObjectKind::Ledger))
}

fn normalize_shamap_payload(
    data: &[u8],
    leaf_prefix: &[u8; 4],
) -> Option<(Vec<u8>, Option<[u8; 4]>, NodeObjectKind)> {
    if data.starts_with(&PREFIX_INNER_NODE) {
        let payload = &data[PREFIX_INNER_NODE.len()..];
        return (payload.len() == 16 * 32).then(|| {
            (
                payload.to_vec(),
                Some(PREFIX_INNER_NODE),
                NodeObjectKind::Inner,
            )
        });
    }

    if data.starts_with(leaf_prefix) {
        let payload = &data[leaf_prefix.len()..];
        return (payload.len() > 32)
            .then(|| (payload.to_vec(), Some(*leaf_prefix), NodeObjectKind::Leaf));
    }

    if starts_with_known_hash_prefix(data) {
        return None;
    }

    if data.len() == 16 * 32 {
        return Some((data.to_vec(), None, NodeObjectKind::Inner));
    }
    (data.len() > 32).then(|| (data.to_vec(), None, NodeObjectKind::Leaf))
}

fn prefix_shamap_payload(data: &[u8], leaf_prefix: &[u8; 4]) -> Option<Vec<u8>> {
    if data.starts_with(&PREFIX_INNER_NODE) || data.starts_with(leaf_prefix) {
        return Some(data.to_vec());
    }
    if starts_with_known_hash_prefix(data) {
        return None;
    }
    if data.len() == 16 * 32 {
        return Some(prefix_payload_once(data, &PREFIX_INNER_NODE));
    }
    (data.len() > 32).then(|| prefix_payload_once(data, leaf_prefix))
}

fn prefix_ledger_payload(data: &[u8]) -> Option<Vec<u8>> {
    if data.starts_with(&PREFIX_LEDGER) {
        return Some(data.to_vec());
    }
    if starts_with_known_hash_prefix(data) {
        return None;
    }
    Some(prefix_payload_once(data, &PREFIX_LEDGER))
}

fn prefix_payload_once(data: &[u8], prefix: &[u8; 4]) -> Vec<u8> {
    if data.starts_with(prefix) {
        return data.to_vec();
    }
    let mut prefixed = Vec::with_capacity(prefix.len() + data.len());
    prefixed.extend_from_slice(prefix);
    prefixed.extend_from_slice(data);
    prefixed
}

fn starts_with_known_hash_prefix(data: &[u8]) -> bool {
    data.starts_with(&PREFIX_INNER_NODE)
        || data.starts_with(&PREFIX_LEAF_STATE)
        || data.starts_with(&PREFIX_LEAF_TX_WITH_META)
        || data.starts_with(&PREFIX_LEAF_TX_NO_META)
        || data.starts_with(&PREFIX_LEDGER)
}

/// Content-addressed storage for SHAMap nodes.
///
/// Keys are 32-byte content hashes, and values are the serialized node bytes.
/// Inner nodes store child hashes, while leaf nodes store SLE bytes plus the
/// entry key.
pub trait NodeStore: Send + Sync {
    /// Store a node under its content hash.
    fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()>;

    /// Fetch a node by its content hash.
    fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>>;

    /// Fetch a bounded window of nodes. The default preserves existing store
    /// semantics by issuing the same validated fetches one at a time.
    fn fetch_window(
        &self,
        hashes: &[[u8; 32]],
    ) -> Vec<([u8; 32], std::io::Result<Option<Vec<u8>>>)> {
        hashes
            .iter()
            .map(|hash| (*hash, self.fetch(hash)))
            .collect()
    }

    /// Existence-only fast path. This does not prove the stored bytes decode
    /// or hash correctly; sync completion/missing-frontier code must fetch and
    /// validate before marking a subtree complete.
    fn contains(&self, hash: &[u8; 32]) -> std::io::Result<bool> {
        self.fetch(hash).map(|value| value.is_some())
    }

    /// Number of nodes stored.
    fn count(&self) -> u64 {
        0
    }

    /// Store without duplicate checks. The default falls back to `store()`.
    fn store_unchecked(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        self.store(hash, data)
    }

    /// Store multiple nodes in a batch.
    fn store_batch(&self, nodes: &[([u8; 32], Vec<u8>)]) -> std::io::Result<()> {
        for (hash, data) in nodes {
            self.store(hash, data)?;
        }
        Ok(())
    }

    /// Store a rippled typed NodeObject.
    fn store_typed(
        &self,
        object_type: NodeObjectType,
        hash: &[u8; 32],
        data: &[u8],
    ) -> std::io::Result<()> {
        if !validate_node_object(object_type, hash, data) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid {:?} NodeObject for {}",
                    object_type,
                    hex::encode_upper(&hash[..8])
                ),
            ));
        }
        self.store_unchecked(hash, data)
    }

    /// Flush buffered writes to disk. The default implementation is a no-op.
    fn flush_to_disk(&self) -> std::io::Result<()> {
        Ok(())
    }

    /// Mark a hash as locally corrupt so future fetches can avoid reusing it.
    fn mark_corrupt(&self, _hash: &[u8; 32]) {}

    /// Clear in-memory caches without touching the persistent backend.
    fn clear_in_memory(&self) {}
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeStoreSnapshot {
    pub fetch_hits: u64,
    pub fetch_missing: u64,
    pub fetch_errors: u64,
    pub store_ops: u64,
    pub store_unchecked_ops: u64,
    pub batch_store_ops: u64,
    pub batch_store_nodes: u64,
    pub fetch_total_ms: u64,
    pub fetch_max_ms: u64,
    pub store_total_ms: u64,
    pub store_max_ms: u64,
    pub batch_store_total_ms: u64,
    pub batch_store_max_ms: u64,
    pub flush_total_ms: u64,
    pub flush_max_ms: u64,
    pub flush_ops: u64,
    pub last_flush_unix: Option<u64>,
    pub last_flush_duration_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Default)]
pub struct NodeStoreStats {
    fetch_hits: AtomicU64,
    fetch_missing: AtomicU64,
    fetch_errors: AtomicU64,
    store_ops: AtomicU64,
    store_unchecked_ops: AtomicU64,
    batch_store_ops: AtomicU64,
    batch_store_nodes: AtomicU64,
    fetch_total_ms: AtomicU64,
    fetch_max_ms: AtomicU64,
    store_total_ms: AtomicU64,
    store_max_ms: AtomicU64,
    batch_store_total_ms: AtomicU64,
    batch_store_max_ms: AtomicU64,
    flush_total_ms: AtomicU64,
    flush_max_ms: AtomicU64,
    flush_ops: AtomicU64,
    last_flush_unix: AtomicU64,
    last_flush_duration_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl NodeStoreStats {
    fn elapsed_ms(started_at: std::time::Instant) -> u64 {
        started_at
            .elapsed()
            .as_millis()
            .max(1)
            .min(u64::MAX as u128) as u64
    }

    fn set_max(slot: &AtomicU64, value: u64) {
        let mut current = slot.load(Ordering::Relaxed);
        while value > current {
            match slot.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    fn remember_error(&self, err: &std::io::Error) {
        let mut slot = self.last_error.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(err.to_string());
    }

    fn note_fetch_result(
        &self,
        started_at: std::time::Instant,
        result: &std::io::Result<Option<Vec<u8>>>,
    ) {
        let elapsed_ms = Self::elapsed_ms(started_at);
        self.fetch_total_ms.fetch_add(elapsed_ms, Ordering::Relaxed);
        Self::set_max(&self.fetch_max_ms, elapsed_ms);
        match result {
            Ok(Some(_)) => {
                self.fetch_hits.fetch_add(1, Ordering::Relaxed);
                self.last_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
            }
            Ok(None) => {
                self.fetch_missing.fetch_add(1, Ordering::Relaxed);
                self.last_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
            }
            Err(err) => {
                self.fetch_errors.fetch_add(1, Ordering::Relaxed);
                self.remember_error(err);
            }
        }
    }

    fn note_store_result(
        &self,
        unchecked: bool,
        started_at: std::time::Instant,
        result: &std::io::Result<()>,
    ) {
        let elapsed_ms = Self::elapsed_ms(started_at);
        self.store_total_ms.fetch_add(elapsed_ms, Ordering::Relaxed);
        Self::set_max(&self.store_max_ms, elapsed_ms);
        if unchecked {
            self.store_unchecked_ops.fetch_add(1, Ordering::Relaxed);
        } else {
            self.store_ops.fetch_add(1, Ordering::Relaxed);
        }
        if let Err(err) = result {
            self.remember_error(err);
        } else {
            self.last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        }
    }

    fn note_batch_result(
        &self,
        node_count: usize,
        started_at: std::time::Instant,
        result: &std::io::Result<()>,
    ) {
        let elapsed_ms = Self::elapsed_ms(started_at);
        self.batch_store_total_ms
            .fetch_add(elapsed_ms, Ordering::Relaxed);
        Self::set_max(&self.batch_store_max_ms, elapsed_ms);
        self.batch_store_ops.fetch_add(1, Ordering::Relaxed);
        self.batch_store_nodes
            .fetch_add(node_count as u64, Ordering::Relaxed);
        if let Err(err) = result {
            self.remember_error(err);
        } else {
            self.last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        }
    }

    fn note_flush_result(&self, started_at: std::time::Instant, result: &std::io::Result<()>) {
        self.flush_ops.fetch_add(1, Ordering::Relaxed);
        self.last_flush_unix.store(unix_now(), Ordering::Relaxed);
        let elapsed_ms = Self::elapsed_ms(started_at);
        self.flush_total_ms.fetch_add(elapsed_ms, Ordering::Relaxed);
        Self::set_max(&self.flush_max_ms, elapsed_ms);
        self.last_flush_duration_ms
            .store(elapsed_ms, Ordering::Relaxed);
        if let Err(err) = result {
            self.remember_error(err);
        } else {
            self.last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        }
    }

    pub fn snapshot(&self) -> NodeStoreSnapshot {
        NodeStoreSnapshot {
            fetch_hits: self.fetch_hits.load(Ordering::Relaxed),
            fetch_missing: self.fetch_missing.load(Ordering::Relaxed),
            fetch_errors: self.fetch_errors.load(Ordering::Relaxed),
            store_ops: self.store_ops.load(Ordering::Relaxed),
            store_unchecked_ops: self.store_unchecked_ops.load(Ordering::Relaxed),
            batch_store_ops: self.batch_store_ops.load(Ordering::Relaxed),
            batch_store_nodes: self.batch_store_nodes.load(Ordering::Relaxed),
            fetch_total_ms: self.fetch_total_ms.load(Ordering::Relaxed),
            fetch_max_ms: self.fetch_max_ms.load(Ordering::Relaxed),
            store_total_ms: self.store_total_ms.load(Ordering::Relaxed),
            store_max_ms: self.store_max_ms.load(Ordering::Relaxed),
            batch_store_total_ms: self.batch_store_total_ms.load(Ordering::Relaxed),
            batch_store_max_ms: self.batch_store_max_ms.load(Ordering::Relaxed),
            flush_total_ms: self.flush_total_ms.load(Ordering::Relaxed),
            flush_max_ms: self.flush_max_ms.load(Ordering::Relaxed),
            flush_ops: self.flush_ops.load(Ordering::Relaxed),
            last_flush_unix: atomic_option(self.last_flush_unix.load(Ordering::Relaxed)),
            last_flush_duration_ms: atomic_option(
                self.last_flush_duration_ms.load(Ordering::Relaxed),
            ),
            last_error: self
                .last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        }
    }
}

pub struct ObservedNodeStore {
    inner: Arc<dyn NodeStore>,
    stats: Arc<NodeStoreStats>,
}

impl ObservedNodeStore {
    pub fn wrap(inner: Arc<dyn NodeStore>) -> (Arc<dyn NodeStore>, Arc<NodeStoreStats>) {
        let stats = Arc::new(NodeStoreStats::default());
        let observed: Arc<dyn NodeStore> = Arc::new(Self {
            inner,
            stats: stats.clone(),
        });
        (observed, stats)
    }
}

impl NodeStore for ObservedNodeStore {
    fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        let started_at = std::time::Instant::now();
        let result = self.inner.store(hash, data);
        self.stats.note_store_result(false, started_at, &result);
        result
    }

    fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
        let started_at = std::time::Instant::now();
        let result = self.inner.fetch(hash);
        self.stats.note_fetch_result(started_at, &result);
        result
    }

    fn fetch_window(
        &self,
        hashes: &[[u8; 32]],
    ) -> Vec<([u8; 32], std::io::Result<Option<Vec<u8>>>)> {
        hashes
            .iter()
            .map(|hash| {
                let started_at = std::time::Instant::now();
                let result = self.inner.fetch(hash);
                self.stats.note_fetch_result(started_at, &result);
                (*hash, result)
            })
            .collect()
    }

    fn contains(&self, hash: &[u8; 32]) -> std::io::Result<bool> {
        self.inner.contains(hash)
    }

    fn count(&self) -> u64 {
        self.inner.count()
    }

    fn store_unchecked(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        let started_at = std::time::Instant::now();
        let result = self.inner.store_unchecked(hash, data);
        self.stats.note_store_result(true, started_at, &result);
        result
    }

    fn store_batch(&self, nodes: &[([u8; 32], Vec<u8>)]) -> std::io::Result<()> {
        let started_at = std::time::Instant::now();
        let result = self.inner.store_batch(nodes);
        self.stats
            .note_batch_result(nodes.len(), started_at, &result);
        result
    }

    fn store_typed(
        &self,
        object_type: NodeObjectType,
        hash: &[u8; 32],
        data: &[u8],
    ) -> std::io::Result<()> {
        let started_at = std::time::Instant::now();
        let result = self.inner.store_typed(object_type, hash, data);
        self.stats.note_store_result(true, started_at, &result);
        result
    }

    fn flush_to_disk(&self) -> std::io::Result<()> {
        let started_at = std::time::Instant::now();
        let result = self.inner.flush_to_disk();
        self.stats.note_flush_result(started_at, &result);
        result
    }

    fn mark_corrupt(&self, hash: &[u8; 32]) {
        self.inner.mark_corrupt(hash);
    }

    fn clear_in_memory(&self) {
        self.inner.clear_in_memory();
    }
}

fn atomic_option(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// NuDB-backed NodeStore — disk-primary, constant memory.
pub struct NuDBNodeStore {
    store: Mutex<nudb_rs::Store>,
}

impl NuDBNodeStore {
    pub fn new(store: nudb_rs::Store) -> Self {
        Self {
            store: Mutex::new(store),
        }
    }

    fn guard(&self) -> MutexGuard<'_, nudb_rs::Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Flush all buffered writes to disk.
    pub fn flush(&self) -> std::io::Result<()> {
        let mut s = self.guard();
        s.flush().map_err(nudb_err)
    }

    pub fn open(dir: &std::path::Path) -> std::io::Result<Self> {
        // Check for the actual data file, not just the directory.
        // After a wipe the directory may exist but be empty.
        let dat_exists = dir.join("nudb.dat").exists();
        let store = if dat_exists {
            nudb_rs::Store::open(
                dir.join("nudb.dat"),
                dir.join("nudb.key"),
                dir.join("nudb.log"),
            )
            .map_err(nudb_err)?
        } else {
            std::fs::create_dir_all(dir)?;
            let dat_path = dir.join("nudb.dat");
            let key_path = dir.join("nudb.key");
            let log_path = dir.join("nudb.log");
            nudb_rs::Store::create(
                &dat_path,
                &key_path,
                &log_path,
                nudb_rs::CreateOptions::new(XLEDGRS_NUDB_APPNUM, 32, 4096),
            )
            .map_err(nudb_err)?;
            nudb_rs::Store::open(dat_path, key_path, log_path).map_err(nudb_err)?
        };
        Ok(Self::new(store))
    }
}

impl NodeStore for NuDBNodeStore {
    fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        if !validate_shamap_store_node(hash, data) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid SHAMap store node for {}",
                    hex::encode_upper(&hash[..8])
                ),
            ));
        }
        let mut s = self.guard();
        match s.insert(hash, data) {
            Ok(()) | Err(nudb_rs::Error::KeyExists) => Ok(()),
            Err(err) => Err(nudb_err(err)),
        }
    }

    fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
        let mut s = self.guard();
        match s.fetch(hash) {
            Ok(data) => normalize_persisted_node_row(hash, data)
                .map(Some)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "stored NodeObject failed validation for {}",
                            hex::encode_upper(&hash[..8])
                        ),
                    )
                }),
            Err(nudb_rs::Error::KeyNotFound) => Ok(None),
            Err(err) => Err(nudb_err(err)),
        }
    }

    fn fetch_window(
        &self,
        hashes: &[[u8; 32]],
    ) -> Vec<([u8; 32], std::io::Result<Option<Vec<u8>>>)> {
        let mut s = self.guard();
        hashes
            .iter()
            .map(|hash| {
                let result = match s.fetch(hash) {
                    Ok(data) => normalize_persisted_node_row(hash, data)
                        .map(Some)
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!(
                                    "stored NodeObject failed validation for {}",
                                    hex::encode_upper(&hash[..8])
                                ),
                            )
                        }),
                    Err(nudb_rs::Error::KeyNotFound) => Ok(None),
                    Err(err) => Err(nudb_err(err)),
                };
                (*hash, result)
            })
            .collect()
    }

    fn contains(&self, hash: &[u8; 32]) -> std::io::Result<bool> {
        let mut s = self.guard();
        s.contains(hash).map_err(nudb_err)
    }

    fn count(&self) -> u64 {
        self.guard().key_count()
    }

    fn store_unchecked(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        let mut s = self.guard();
        match s.insert(hash, data) {
            Ok(()) | Err(nudb_rs::Error::KeyExists) => Ok(()),
            Err(err) => Err(nudb_err(err)),
        }
    }

    fn store_batch(&self, nodes: &[([u8; 32], Vec<u8>)]) -> std::io::Result<()> {
        for (hash, data) in nodes {
            if !validate_shamap_store_node(hash, data) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "invalid SHAMap store node for {}",
                        hex::encode_upper(&hash[..8])
                    ),
                ));
            }
        }
        let mut s = self.guard();
        for (hash, data) in nodes {
            match s.insert(hash, data) {
                Ok(()) | Err(nudb_rs::Error::KeyExists) => {}
                Err(err) => return Err(nudb_err(err)),
            }
        }
        // Keep the sync hot path buffered. Durability is forced by explicit
        // flush_to_disk() calls at sync checkpoints/handoff, while nudb-rs
        // still auto-flushes large pending sets internally.
        Ok(())
    }

    fn store_typed(
        &self,
        object_type: NodeObjectType,
        hash: &[u8; 32],
        data: &[u8],
    ) -> std::io::Result<()> {
        if !validate_node_object(object_type, hash, data) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid {:?} NodeObject for {}",
                    object_type,
                    hex::encode_upper(&hash[..8])
                ),
            ));
        }
        self.store_unchecked(hash, data)
    }

    fn flush_to_disk(&self) -> std::io::Result<()> {
        self.flush()
    }
}

fn nudb_err(err: nudb_rs::Error) -> std::io::Error {
    match err {
        nudb_rs::Error::Io(err) => err,
        other => std::io::Error::new(std::io::ErrorKind::Other, other.to_string()),
    }
}

/// In-memory NodeStore for testing.
pub struct MemNodeStore {
    nodes: Mutex<std::collections::HashMap<[u8; 32], Vec<u8>>>,
}

impl MemNodeStore {
    pub fn new() -> Self {
        Self {
            nodes: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn guard(&self) -> MutexGuard<'_, std::collections::HashMap<[u8; 32], Vec<u8>>> {
        self.nodes.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl NodeStore for MemNodeStore {
    fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        self.guard().insert(*hash, data.to_vec());
        Ok(())
    }

    fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.guard().get(hash).cloned())
    }

    fn contains(&self, hash: &[u8; 32]) -> std::io::Result<bool> {
        Ok(self.guard().contains_key(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn mem_store_roundtrip() {
        let store = MemNodeStore::new();
        let hash = [0xAB; 32];
        let data = b"test node data";
        store.store(&hash, data).unwrap();
        let fetched = store.fetch(&hash).unwrap().unwrap();
        assert_eq!(fetched, data);
    }

    #[test]
    fn mem_store_missing() {
        let store = MemNodeStore::new();
        assert!(store.fetch(&[0x01; 32]).unwrap().is_none());
    }

    #[test]
    fn fetch_window_preserves_order_hits_and_misses() {
        let store = MemNodeStore::new();
        let hit = [0xAB; 32];
        let miss = [0xCD; 32];
        store.store(&hit, b"window-hit").unwrap();

        let results = store.fetch_window(&[hit, miss]);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, hit);
        assert_eq!(
            results[0].1.as_ref().unwrap().as_deref(),
            Some(&b"window-hit"[..])
        );
        assert_eq!(results[1].0, miss);
        assert!(results[1].1.as_ref().unwrap().is_none());
    }

    #[test]
    fn rippled_envelope_encodes_and_decodes_account_leaf() {
        let key = [0x44; 32];
        let mut normalized = b"account-state-sle".to_vec();
        normalized.extend_from_slice(&key);
        let mut prefixed = Vec::with_capacity(4 + normalized.len());
        prefixed.extend_from_slice(b"MLN\0");
        prefixed.extend_from_slice(&normalized);
        let hash = crate::crypto::sha512_first_half(&prefixed);

        let row = encode_rippled_node_object_envelope(NodeObjectType::AccountNode, &normalized)
            .expect("account leaf should encode");
        assert_eq!(&row[..8], &[0u8; 8]);
        assert_eq!(row[8], NodeObjectType::AccountNode.rippled_code());
        assert_eq!(&row[9..], prefixed.as_slice());

        let decoded = decode_rippled_node_object_envelope(&hash, &row).unwrap();
        assert_eq!(decoded.object_type, NodeObjectType::AccountNode);
        assert_eq!(decoded.kind, NodeObjectKind::Leaf);
        assert_eq!(decoded.hash_prefix, Some(PREFIX_LEAF_STATE));
        assert_eq!(decoded.data, normalized);
    }

    #[test]
    fn rippled_envelope_decodes_prefixed_inner_node() {
        let normalized = vec![0x22; 16 * 32];
        let mut prefixed = Vec::with_capacity(4 + normalized.len());
        prefixed.extend_from_slice(b"MIN\0");
        prefixed.extend_from_slice(&normalized);
        let hash = crate::crypto::sha512_first_half(&prefixed);
        let mut row = vec![0u8; 8];
        row.push(NodeObjectType::AccountNode.rippled_code());
        row.extend_from_slice(&prefixed);

        let decoded = decode_rippled_node_object_envelope(&hash, &row).unwrap();
        assert_eq!(decoded.kind, NodeObjectKind::Inner);
        assert_eq!(decoded.hash_prefix, Some(PREFIX_INNER_NODE));
        assert_eq!(decoded.data, normalized);
    }

    #[test]
    fn rippled_envelope_decodes_prefixed_ledger_object() {
        let ledger_header = b"ledger-header-bytes";
        let mut prefixed = Vec::with_capacity(4 + ledger_header.len());
        prefixed.extend_from_slice(b"LWR\0");
        prefixed.extend_from_slice(ledger_header);
        let hash = crate::crypto::sha512_first_half(&prefixed);
        let mut row = vec![0u8; 8];
        row.push(NodeObjectType::Ledger.rippled_code());
        row.extend_from_slice(&prefixed);

        let decoded = decode_rippled_node_object_envelope(&hash, &row).unwrap();
        assert_eq!(decoded.object_type, NodeObjectType::Ledger);
        assert_eq!(decoded.kind, NodeObjectKind::Ledger);
        assert_eq!(decoded.hash_prefix, Some(PREFIX_LEDGER));
        assert_eq!(decoded.data, ledger_header);
    }

    #[test]
    fn typed_payload_normalization_rejects_cross_family_prefixes() {
        let key = [0x55; 32];
        let mut tx_payload = b"transaction-plus-meta".to_vec();
        tx_payload.extend_from_slice(&key);
        let mut tx_prefixed = Vec::with_capacity(4 + tx_payload.len());
        tx_prefixed.extend_from_slice(b"SND\0");
        tx_prefixed.extend_from_slice(&tx_payload);
        let tx_hash = crate::crypto::sha512_first_half(&tx_prefixed);

        assert!(
            normalize_typed_node_object_payload(NodeObjectType::AccountNode, &tx_prefixed)
                .is_none()
        );

        let mut wrong_type_row = vec![0u8; 8];
        wrong_type_row.push(NodeObjectType::AccountNode.rippled_code());
        wrong_type_row.extend_from_slice(&tx_prefixed);
        assert!(decode_rippled_node_object_envelope(&tx_hash, &wrong_type_row).is_none());

        let mut correct_type_row = vec![0u8; 8];
        correct_type_row.push(NodeObjectType::TransactionNode.rippled_code());
        correct_type_row.extend_from_slice(&tx_prefixed);
        let decoded = decode_rippled_node_object_envelope(&tx_hash, &correct_type_row).unwrap();
        assert_eq!(decoded.object_type, NodeObjectType::TransactionNode);
        assert_eq!(decoded.hash_prefix, Some(PREFIX_LEAF_TX_WITH_META));
        assert_eq!(decoded.data, tx_payload);
    }

    #[test]
    fn rippled_envelope_rejects_unknown_type_and_hash_only_rows() {
        let mut unknown = vec![0u8; 9];
        unknown[8] = 99;
        unknown.extend_from_slice(b"payload");
        assert!(decode_rippled_node_object_envelope(&[0u8; 32], &unknown).is_none());

        let mut hash_only = vec![0u8; 8];
        hash_only.push(NodeObjectType::AccountNode.rippled_code());
        hash_only.extend_from_slice(&[0x66; 32]);
        assert!(decode_rippled_node_object_envelope(&[0u8; 32], &hash_only).is_none());
    }

    #[test]
    fn xledgrs_nudb_appnum_is_private_not_rippled() {
        assert_ne!(XLEDGRS_NUDB_APPNUM, RIPPLED_NUDB_APPNUM);
    }

    #[test]
    fn nudb_store_roundtrip() {
        let dir = std::env::temp_dir().join("nudb_nodestore_test");
        let _ = std::fs::remove_dir_all(&dir);
        let store = NuDBNodeStore::open(&dir).unwrap();
        let key = [0xCD; 32];
        let data = b"shamap node bytes";
        let mut payload = Vec::with_capacity(4 + data.len() + key.len());
        payload.extend_from_slice(b"MLN\0");
        payload.extend_from_slice(data);
        payload.extend_from_slice(&key);
        let hash = crate::crypto::sha512_first_half(&payload);
        let mut store_data = data.to_vec();
        store_data.extend_from_slice(&key);
        store.store(&hash, &store_data).unwrap();
        let fetched = store.fetch(&hash).unwrap().unwrap();
        assert_eq!(fetched, store_data);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nudb_batch_store_is_buffered_until_explicit_flush() {
        let dir = std::env::temp_dir().join("nudb_batch_buffered_until_flush_test");
        let _ = std::fs::remove_dir_all(&dir);
        let key = [0xBC; 32];
        let data = b"buffered account state leaf";
        let mut payload = Vec::with_capacity(4 + data.len() + key.len());
        payload.extend_from_slice(b"MLN\0");
        payload.extend_from_slice(data);
        payload.extend_from_slice(&key);
        let hash = crate::crypto::sha512_first_half(&payload);
        let mut store_data = data.to_vec();
        store_data.extend_from_slice(&key);
        let batch = vec![(hash, store_data.clone())];

        {
            let store = NuDBNodeStore::open(&dir).unwrap();
            store.store_batch(&batch).unwrap();
            assert_eq!(store.fetch(&hash).unwrap(), Some(store_data.clone()));
        }
        {
            let reopened = NuDBNodeStore::open(&dir).unwrap();
            assert_eq!(reopened.fetch(&hash).unwrap(), None);
            reopened.store_batch(&batch).unwrap();
            reopened.flush_to_disk().unwrap();
        }
        {
            let reopened = NuDBNodeStore::open(&dir).unwrap();
            assert_eq!(reopened.fetch(&hash).unwrap(), Some(store_data));
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn observed_store_tracks_fetches_and_writes() {
        let inner: Arc<dyn NodeStore> = Arc::new(MemNodeStore::new());
        let (observed, stats) = ObservedNodeStore::wrap(inner);
        let hash = [0x11; 32];
        let missing = [0x22; 32];
        observed.store(&hash, b"abc").unwrap();
        assert_eq!(observed.fetch(&hash).unwrap(), Some(b"abc".to_vec()));
        assert_eq!(observed.fetch(&missing).unwrap(), None);
        observed.flush_to_disk().unwrap();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.store_ops, 1);
        assert_eq!(snapshot.fetch_hits, 1);
        assert_eq!(snapshot.fetch_missing, 1);
        assert_eq!(snapshot.fetch_errors, 0);
        assert_eq!(snapshot.flush_ops, 1);
        assert!(snapshot.store_total_ms >= 1);
        assert!(snapshot.store_max_ms >= 1);
        assert!(snapshot.fetch_total_ms >= 2);
        assert!(snapshot.fetch_max_ms >= 1);
        assert!(snapshot.flush_total_ms >= 1);
        assert!(snapshot.flush_max_ms >= 1);
        assert!(snapshot.last_flush_unix.is_some());
        assert!(snapshot.last_flush_duration_ms.is_some());
    }

    struct FlakyStore {
        fail_once: std::sync::atomic::AtomicBool,
        nodes: Mutex<std::collections::HashMap<[u8; 32], Vec<u8>>>,
    }

    impl FlakyStore {
        fn new() -> Self {
            Self {
                fail_once: std::sync::atomic::AtomicBool::new(true),
                nodes: Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn guard(&self) -> MutexGuard<'_, std::collections::HashMap<[u8; 32], Vec<u8>>> {
            self.nodes.lock().unwrap_or_else(|e| e.into_inner())
        }
    }

    impl NodeStore for FlakyStore {
        fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
            if self.fail_once.swap(false, Ordering::Relaxed) {
                return Err(std::io::Error::other("transient store failure"));
            }
            self.guard().insert(*hash, data.to_vec());
            Ok(())
        }

        fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
            Ok(self.guard().get(hash).cloned())
        }

        fn flush_to_disk(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn observed_store_clears_last_error_after_recovery() {
        let inner: Arc<dyn NodeStore> = Arc::new(FlakyStore::new());
        let (observed, stats) = ObservedNodeStore::wrap(inner);
        let hash = [0x33; 32];

        assert!(observed.store(&hash, b"first").is_err());
        assert!(stats.snapshot().last_error.is_some());

        observed.store(&hash, b"second").unwrap();
        let snapshot = stats.snapshot();
        assert!(snapshot.last_error.is_none());
        assert_eq!(snapshot.store_ops, 2);
    }

    #[test]
    fn validate_account_state_store_node_accepts_exact_512_byte_leaf() {
        let key = [0x44; 32];
        let data = vec![0xAA; 480];
        let mut payload = Vec::with_capacity(4 + data.len() + key.len());
        payload.extend_from_slice(b"MLN\0");
        payload.extend_from_slice(&data);
        payload.extend_from_slice(&key);
        let hash = crate::crypto::sha512_first_half(&payload);

        let mut store = data;
        store.extend_from_slice(&key);
        assert!(validate_account_state_store_node(&hash, &store));
    }

    #[test]
    fn validate_transaction_store_node_accepts_tx_leaf() {
        let key = [0x55; 32];
        let data = vec![0xBB; 96];
        let mut payload = Vec::with_capacity(4 + data.len() + key.len());
        payload.extend_from_slice(b"SND\0");
        payload.extend_from_slice(&data);
        payload.extend_from_slice(&key);
        let hash = crate::crypto::sha512_first_half(&payload);

        let mut store = data;
        store.extend_from_slice(&key);
        assert!(validate_transaction_store_node(&hash, &store));
        assert!(validate_shamap_store_node(&hash, &store));
    }

    #[test]
    fn validate_transaction_no_metadata_store_node_uses_txn_domain() {
        let key = [0x56; 32];
        let data = vec![0xBC; 96];
        let mut payload = Vec::with_capacity(4 + data.len() + key.len());
        payload.extend_from_slice(b"TXN\0");
        payload.extend_from_slice(&data);
        payload.extend_from_slice(&key);
        let hash = crate::crypto::sha512_first_half(&payload);

        let mut store = data;
        store.extend_from_slice(&key);
        assert!(validate_transaction_no_metadata_store_node(&hash, &store));
        assert!(!validate_transaction_with_metadata_store_node(
            &hash, &store
        ));
        assert!(!validate_account_state_store_node(&hash, &store));
        assert_eq!(
            decode_transaction_no_metadata_store_node_kind(&hash, &store),
            Some(NodeObjectKind::Leaf)
        );
    }

    #[test]
    fn typed_validation_rejects_cross_family_rows() {
        let key = [0x57; 32];
        let data = b"same serialized bytes";
        let mut tx_payload = Vec::with_capacity(4 + data.len() + key.len());
        tx_payload.extend_from_slice(b"SND\0");
        tx_payload.extend_from_slice(data);
        tx_payload.extend_from_slice(&key);
        let tx_hash = crate::crypto::sha512_first_half(&tx_payload);

        let mut tx_store = data.to_vec();
        tx_store.extend_from_slice(&key);
        assert!(validate_transaction_with_metadata_store_node(
            &tx_hash, &tx_store
        ));
        assert!(!validate_transaction_no_metadata_store_node(
            &tx_hash, &tx_store
        ));
        assert!(!validate_account_state_store_node(&tx_hash, &tx_store));
        assert!(!validate_ledger_store_node(&tx_hash, &tx_store));

        let mut ledger_payload = Vec::with_capacity(4 + data.len());
        ledger_payload.extend_from_slice(b"LWR\0");
        ledger_payload.extend_from_slice(data);
        let ledger_hash = crate::crypto::sha512_first_half(&ledger_payload);
        assert!(validate_ledger_store_node(&ledger_hash, data));
        assert!(!validate_shamap_store_node(&ledger_hash, data));
    }

    #[test]
    fn nudb_store_typed_accepts_ledger_object() {
        let dir = std::env::temp_dir().join("nudb_typed_ledger_object_test");
        let _ = std::fs::remove_dir_all(&dir);
        let store = NuDBNodeStore::open(&dir).unwrap();
        let data = b"ledger-header-bytes";
        let mut payload = Vec::with_capacity(4 + data.len());
        payload.extend_from_slice(b"LWR\0");
        payload.extend_from_slice(data);
        let hash = crate::crypto::sha512_first_half(&payload);

        store
            .store_typed(NodeObjectType::Ledger, &hash, data)
            .unwrap();
        assert_eq!(store.fetch(&hash).unwrap(), Some(data.to_vec()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nudb_store_rejects_rippled_envelope_as_private_row() {
        let dir = std::env::temp_dir().join("nudb_encodedblob_private_row_guard_test");
        let _ = std::fs::remove_dir_all(&dir);
        let store = NuDBNodeStore::open(&dir).unwrap();
        let key = [0x77; 32];
        let mut normalized = b"account-state-sle".to_vec();
        normalized.extend_from_slice(&key);
        let row = encode_rippled_node_object_envelope(NodeObjectType::AccountNode, &normalized)
            .expect("account leaf should encode");
        let mut prefixed = Vec::with_capacity(4 + normalized.len());
        prefixed.extend_from_slice(b"MLN\0");
        prefixed.extend_from_slice(&normalized);
        let hash = crate::crypto::sha512_first_half(&prefixed);

        let err = store.store(&hash, &row).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(store.fetch(&hash).unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nudb_store_rejects_invalid_account_state_row() {
        let dir = std::env::temp_dir().join("nudb_nodestore_invalid_test");
        let _ = std::fs::remove_dir_all(&dir);
        let store = NuDBNodeStore::open(&dir).unwrap();
        let err = store.store(&[0xAB; 32], &[0xCD; 96]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(&dir).ok();
    }
}
