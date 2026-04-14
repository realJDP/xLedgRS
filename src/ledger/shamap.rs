//! SHAMap — the radix-16 Merkle hash tree at the core of the XRP Ledger.
//!
//! Every closed ledger contains two SHAMaps:
//!   - **State map**:       keys = ledger object IDs, values = serialized objects
//!   - **Transaction map**: keys = transaction hashes, values = serialized tx + metadata
//!
//! The root hash of each SHAMap is committed to in the ledger header, making
//! the entire ledger state verifiable from a single 32-byte hash.
//!
//! # Structure
//! Keys are 256-bit (32 bytes = 64 nibbles). The tree is traversed one nibble
//! (4 bits) at a time, so inner nodes have exactly 16 children slots.
//!
//! # Hash prefixes
//! Each node type is hashed with a 4-byte prefix to domain-separate the hashes:
//!   Inner node:        `MIN\0`  0x4D494E00
//!   Transaction leaf:  `SND\0`  0x534E4400
//!   Account state leaf:`MLN\0`  0x4D4C4E00

use std::sync::Arc;

use serde::{Serialize, Deserialize};

use crate::crypto::sha512_first_half;
use crate::ledger::node_store::NodeStore;
use crate::ledger::shamap_id::SHAMapNodeID;

// ── Hash prefixes ─────────────────────────────────────────────────────────────

pub(crate) const PREFIX_INNER_NODE:    [u8; 4] = [0x4D, 0x49, 0x4E, 0x00]; // MIN\0
pub(crate) const PREFIX_LEAF_TX:       [u8; 4] = [0x53, 0x4E, 0x44, 0x00]; // SND\0
pub(crate) const PREFIX_LEAF_STATE:    [u8; 4] = [0x4D, 0x4C, 0x4E, 0x00]; // MLN\0

// ── Key ───────────────────────────────────────────────────────────────────────

/// A 256-bit SHAMap key (32 bytes = 64 nibbles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Key(pub [u8; 32]);

impl Key {
    /// Get the nibble (0–15) at tree depth `d` (0 = most significant).
    #[inline]
    pub fn nibble(&self, d: usize) -> usize {
        let byte = self.0[d / 2];
        if d % 2 == 0 { (byte >> 4) as usize } else { (byte & 0x0F) as usize }
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode_upper(self.0)
    }
}

// ── Node type ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapType {
    Transaction,
    AccountState,
}

// ── Node ──────────────────────────────────────────────────────────────────────

pub(crate) enum Node {
    Inner(InnerNode),
    Leaf(LeafNode),
    /// A stub leaf — we know the content hash but haven't loaded the data yet.
    /// The data lives in the NodeStore and is fetched on demand.
    Stub {
        key: Key,
        /// Content hash of the serialized leaf node in the NodeStore.
        content_hash: [u8; 32],
    },
}

impl Node {
    /// Compute (or return cached) hash for this node.
    pub(crate) fn hash(&mut self, map_type: MapType) -> [u8; 32] {
        match self {
            Node::Inner(n) => n.hash(map_type),
            Node::Leaf(n)  => n.hash(map_type),
            Node::Stub { content_hash, .. } => *content_hash,
        }
    }
}

// ── Inner node ────────────────────────────────────────────────────────────────

pub(crate) struct InnerNode {
    pub(crate) children: [Option<Box<Node>>; 16],
    pub(crate) child_hashes: [[u8; 32]; 16],
    pub(crate) is_branch: u16,
    pub(crate) cached_hash: Option<[u8; 32]>,
    pub(crate) dirty: bool,
    pub(crate) full_below_gen: u32,
}

impl InnerNode {
    pub(crate) fn new() -> Self {
        Self {
            children: Default::default(),
            child_hashes: [[0u8; 32]; 16],
            is_branch: 0,
            cached_hash: None,
            dirty: true,
            full_below_gen: 0,
        }
    }

    pub(crate) fn invalidate(&mut self) {
        self.cached_hash = None;
        self.dirty = true;
    }

    /// Does branch `b` have a child (known from wire data)?
    pub(crate) fn has_branch(&self, b: usize) -> bool {
        (self.is_branch & (1 << b)) != 0
    }

    /// Get the known hash for child at branch `b`.
    pub(crate) fn child_hash(&self, b: usize) -> [u8; 32] {
        self.child_hashes[b]
    }

    /// Set child hash and update is_branch bitmask.
    pub(crate) fn set_child_hash(&mut self, b: usize, hash: [u8; 32]) {
        self.child_hashes[b] = hash;
        if hash != [0u8; 32] {
            self.is_branch |= 1 << b;
        } else {
            self.is_branch &= !(1 << b);
        }
    }

    /// Is this subtree fully synced for the given generation?
    pub(crate) fn is_full_below(&self, generation: u32) -> bool {
        generation > 0 && self.full_below_gen == generation
    }

    /// Mark this subtree as fully synced for the given generation.
    pub(crate) fn set_full_below(&mut self, generation: u32) {
        self.full_below_gen = generation;
    }

    /// Hash = SHA-512-half(PREFIX_INNER || child_hashes...)
    /// Empty children contribute 32 zero bytes.
    /// Uses wire child_hashes for children without loaded pointers.
    /// Only updates child_hashes for children that ARE loaded (dirty).
    pub(crate) fn hash(&mut self, map_type: MapType) -> [u8; 32] {
        if let Some(h) = self.cached_hash {
            return h;
        }
        let mut payload = Vec::with_capacity(4 + 16 * 32);
        payload.extend_from_slice(&PREFIX_INNER_NODE);
        for (i, child) in self.children.iter_mut().enumerate() {
            let ch = match child {
                Some(n) => {
                    let h = n.hash(map_type);
                    self.child_hashes[i] = h; // update from loaded child
                    h
                }
                None => self.child_hashes[i], // preserve wire hash
            };
            if ch != [0u8; 32] {
                self.is_branch |= 1 << i;
            }
            payload.extend_from_slice(&ch);
        }
        let h = sha512_first_half(&payload);
        self.cached_hash = Some(h);
        h
    }
}

// ── Leaf node ─────────────────────────────────────────────────────────────────

pub(crate) struct LeafNode {
    pub(crate) key:         Key,
    pub(crate) data:        Vec<u8>,
    pub(crate) cached_hash: Option<[u8; 32]>,
    /// True if this leaf was created/modified and hasn't been flushed to backend.
    pub(crate) dirty:       bool,
}

impl LeafNode {
    fn new(key: Key, data: Vec<u8>) -> Self {
        Self { key, data, cached_hash: None, dirty: true }
    }

    /// Hash = SHA-512-half(PREFIX_LEAF || key || data)
    pub(crate) fn hash(&mut self, map_type: MapType) -> [u8; 32] {
        if let Some(h) = self.cached_hash {
            return h;
        }
        let prefix = match map_type {
            MapType::Transaction  => &PREFIX_LEAF_TX,
            MapType::AccountState => &PREFIX_LEAF_STATE,
        };
        let mut payload = Vec::with_capacity(4 + self.data.len() + 32);
        payload.extend_from_slice(prefix);
        payload.extend_from_slice(&self.data);  // data first (matches rippled)
        payload.extend_from_slice(&self.key.0); // key second
        let h = sha512_first_half(&payload);
        self.cached_hash = Some(h);
        h
    }
}

// ── SHAMap ────────────────────────────────────────────────────────────────────

/// A SHAMap — either a state map or a transaction map.
///
/// Optionally backed by a `NodeStore` for lazy loading: leaf nodes can be
/// "stubs" that only know their content hash. When accessed, the data is
/// fetched from the NodeStore on demand. This matches rippled's architecture
/// where NuDB is the primary store and the SHAMap walks fetch from disk.
pub struct SHAMap {
    pub(crate) root: InnerNode,
    map_type: MapType,
    count:    usize,
    /// Optional disk backend for lazy loading and flush.
    backend:  Option<Arc<dyn NodeStore>>,
}

const WIRE_TYPE_ACCOUNT_STATE: u8 = 0x01;
const WIRE_TYPE_INNER: u8 = 0x02;
const WIRE_TYPE_TRANSACTION: u8 = 0x04;

impl SHAMap {
    pub fn new(map_type: MapType) -> Self {
        Self { root: InnerNode::new(), map_type, count: 0, backend: None }
    }

    /// Create a SHAMap backed by a NodeStore for lazy loading.
    pub fn with_backend(map_type: MapType, backend: Arc<dyn NodeStore>) -> Self {
        Self { root: InnerNode::new(), map_type, count: 0, backend: Some(backend) }
    }

    pub fn new_state() -> Self       { Self::new(MapType::AccountState) }
    pub fn new_transaction() -> Self { Self::new(MapType::Transaction) }

    /// Number of items in the map.
    pub fn len(&self) -> usize { self.count }
    pub fn is_empty(&self) -> bool { self.count == 0 }

    /// The root hash — commits to all contents.
    pub fn root_hash(&mut self) -> [u8; 32] {
        self.root.hash(self.map_type)
    }

    /// Insert `data` at `key`. Returns `true` if inserted, `false` if key already existed.
    pub fn insert(&mut self, key: Key, data: Vec<u8>) -> bool {
        let inserted = insert_node(&mut self.root, key, data, self.map_type, 0, self.backend.as_ref());
        if inserted { self.count += 1; }
        inserted
    }

    /// Get the data stored at `key`, if present.
    /// If the leaf is a stub, fetches from the backend NodeStore.
    pub fn get(&mut self, key: &Key) -> Option<Vec<u8>> {
        get_node_lazy(&mut self.root, key, 0, self.backend.as_ref())
    }

    /// Get the data stored at `key` without resolving stubs (immutable access).
    pub fn get_if_loaded(&self, key: &Key) -> Option<&[u8]> {
        get_node(&self.root, key, 0)
    }

    /// Iterate all leaf nodes, returning (Key, &[u8]) pairs.
    pub fn iter_leaves(&self) -> Vec<(Key, &[u8])> {
        let mut results = Vec::new();
        collect_leaves(&self.root, &mut results);
        results
    }

    /// Remove `key`. Returns `true` if it was present.
    pub fn remove(&mut self, key: &Key) -> bool {
        let removed = remove_node(&mut self.root, key, 0, self.backend.as_ref());
        if removed { self.count -= 1; }
        removed
    }

    /// Insert a stub leaf — only the key and content hash are known.
    /// The data will be fetched from the backend on demand.
    pub fn insert_stub(&mut self, key: Key, content_hash: [u8; 32]) {
        insert_stub_node(&mut self.root, key, content_hash, 0);
        self.count += 1;
    }

    /// Flush all dirty (non-stub, modified) nodes to the backend NodeStore.
    /// After flushing, nodes are marked clean. Returns number of nodes flushed.
    pub fn flush_dirty(&mut self) -> std::io::Result<usize> {
        let backend = match &self.backend {
            Some(b) => b.clone(),
            None => return Ok(0),
        };
        let mt = self.map_type;
        let mut batch = Vec::new();

        // Collect dirty child nodes recursively
        collect_dirty_nodes(&mut self.root, mt, &mut batch);

        // Also flush the root inner node itself if dirty
        if self.root.dirty {
            let hash = self.root.hash(mt);
            let mut store_data = Vec::with_capacity(16 * 32);
            for child in self.root.children.iter_mut() {
                match child {
                    Some(n) => store_data.extend_from_slice(&n.hash(mt)),
                    None => store_data.extend_from_slice(&[0u8; 32]),
                }
            }
            batch.push((hash, store_data));
            self.root.dirty = false;
        }

        let count = batch.len();
        if !batch.is_empty() {
            backend.store_batch(&batch)?;
        }
        Ok(count)
    }

    /// Evict clean (already-flushed) leaf nodes back to stubs.
    /// Frees memory while keeping the tree structure and hashes intact.
    /// Call after flush_dirty() to bound memory during sync.
    pub fn evict_clean_leaves(&mut self) -> usize {
        evict_clean_recursive(&mut self.root, self.map_type)
    }

    /// Get a reference to the backend NodeStore (for direct writes bypassing the tree).
    pub fn backend(&self) -> Option<&Arc<dyn NodeStore>> {
        self.backend.as_ref()
    }

    /// Rehydrate the root inner node from a persisted backend hash.
    /// Lets restart rebuild the lazy tree shape from NuDB without re-running
    /// a full state sync.
    pub fn load_root_from_hash(&mut self, root_hash: [u8; 32]) -> std::io::Result<bool> {
        let Some(backend) = &self.backend else {
            return Ok(false);
        };
        let Some(stored) = backend.fetch(&root_hash)? else {
            return Ok(false);
        };
        if stored.len() != 16 * 32 {
            return Ok(false);
        }

        let mut root = InnerNode::new();
        for i in 0..16 {
            let mut child_hash = [0u8; 32];
            child_hash.copy_from_slice(&stored[i * 32..(i + 1) * 32]);
            root.set_child_hash(i, child_hash);
        }
        root.cached_hash = Some(root_hash);
        root.dirty = false;
        self.root = root;
        Ok(true)
    }

    /// Set the backend NodeStore.
    pub fn set_backend(&mut self, backend: Arc<dyn NodeStore>) {
        self.backend = Some(backend);
    }

    /// Create a mutable snapshot of this SHAMap.
    /// Clones the tree structure (inner nodes with child hashes) but converts
    /// leaf nodes to stubs (key + content hash only, no data copied).
    /// Shares the NuDB backend for lazy loading.
    /// This matches rippled's SHAMap copy constructor with isMutable=true.
    pub fn snapshot(&mut self) -> SHAMap {
        let new_root = snapshot_inner(&mut self.root, self.map_type);
        SHAMap {
            root: new_root,
            map_type: self.map_type,
            count: self.count,
            backend: self.backend.clone(),
        }
    }

    /// Find the next key strictly greater than `key` (in-order traversal).
    /// Returns None if no such key exists.
    pub fn upper_bound(&self, key: &Key) -> Option<Key> {
        upper_bound_inner(&self.root, key, 0)
    }

    /// Find the smallest key in the map, materializing backend-backed branches
    /// on demand. This lets historical root snapshots enumerate leaves without
    /// eagerly loading the whole tree into memory first.
    pub fn first_key_lazy(&mut self) -> Option<Key> {
        leftmost_key_lazy_inner(&mut self.root, self.backend.as_ref())
    }

    /// Find the next key strictly greater than `key`, materializing
    /// backend-backed branches on demand.
    pub fn upper_bound_lazy(&mut self, key: &Key) -> Option<Key> {
        upper_bound_lazy_inner(&mut self.root, key, 0, self.backend.as_ref())
    }

    /// Trace how a keyed lookup walks the current SHAMap/backend.
    /// Used only for diagnostics when a supposedly-present base object is missing.
    pub fn debug_trace_key_path(&mut self, key: &Key) -> Vec<String> {
        let mut lines = Vec::new();
        debug_trace_key_path_recursive(
            &mut self.root,
            key,
            0,
            self.backend.as_ref(),
            &mut lines,
        );
        lines
    }

    /// Fetch a SHAMap node by tree position and encode it in peer wire format.
    pub fn get_wire_node_by_id(&mut self, node_id: &SHAMapNodeID) -> Option<Vec<u8>> {
        get_wire_node_recursive(
            &mut self.root,
            &SHAMapNodeID::root(),
            node_id,
            self.map_type,
            self.backend.as_ref(),
        )
    }

    /// Fetch a SHAMap node plus descendants up to `query_depth` extra levels,
    /// matching TMGetLedger's "fat" node semantics.
    pub fn get_wire_nodes_for_query(
        &mut self,
        node_id: &SHAMapNodeID,
        query_depth: u32,
    ) -> Vec<([u8; 33], Vec<u8>)> {
        let mut out = Vec::new();
        collect_wire_nodes_for_query_recursive(
            &mut self.root,
            &SHAMapNodeID::root(),
            node_id,
            self.map_type,
            self.backend.as_ref(),
            query_depth,
            &mut out,
        );
        out
    }
}

/// Create a snapshot of an InnerNode, converting leaves to stubs.
fn snapshot_inner(node: &mut InnerNode, map_type: MapType) -> InnerNode {
    let mut new = InnerNode::new();
    new.child_hashes = node.child_hashes;
    new.is_branch = node.is_branch;
    new.cached_hash = node.cached_hash;
    new.full_below_gen = node.full_below_gen;
    new.dirty = false; // snapshot is clean

    for i in 0..16 {
        if let Some(ref mut child) = node.children[i] {
            new.children[i] = Some(Box::new(match child.as_mut() {
                Node::Inner(inner) => Node::Inner(snapshot_inner(inner, map_type)),
                Node::Leaf(leaf) => {
                    // Convert to stub — share data via backend, don't copy
                    let content_hash = leaf.hash(map_type);
                    Node::Stub { key: leaf.key, content_hash }
                }
                Node::Stub { key, content_hash } => {
                    Node::Stub { key: *key, content_hash: *content_hash }
                }
            }));
        }
    }

    new
}

/// Find the first leaf key strictly greater than `target` by in-order traversal.
fn upper_bound_inner(node: &InnerNode, target: &Key, depth: usize) -> Option<Key> {
    let nibble = target.nibble(depth);

    // First, search the child at the target's nibble
    if let Some(ref child) = node.children[nibble] {
        match child.as_ref() {
            Node::Leaf(leaf) if leaf.key > *target => return Some(leaf.key),
            Node::Stub { key, .. } if *key > *target => return Some(*key),
            Node::Inner(inner) => {
                if let Some(found) = upper_bound_inner(inner, target, depth + 1) {
                    return Some(found);
                }
            }
            _ => {} // leaf/stub <= target, fall through to higher nibbles
        }
    }

    // Search children with nibble > target's nibble (all "after" target)
    for i in (nibble + 1)..16 {
        if let Some(ref child) = node.children[i] {
            return leftmost_key(child);
        }
    }

    None
}

/// Find the leftmost (smallest) key in a subtree.
fn leftmost_key(node: &Node) -> Option<Key> {
    match node {
        Node::Leaf(leaf) => Some(leaf.key),
        Node::Stub { key, .. } => Some(*key),
        Node::Inner(inner) => {
            for child in &inner.children {
                if let Some(ref c) = child {
                    return leftmost_key(c);
                }
            }
            None
        }
    }
}

fn leftmost_key_lazy_node(
    node: &mut Node,
    backend: Option<&Arc<dyn NodeStore>>,
) -> Option<Key> {
    match node {
        Node::Leaf(leaf) => Some(leaf.key),
        Node::Stub { key, .. } => Some(*key),
        Node::Inner(inner) => leftmost_key_lazy_inner(inner, backend),
    }
}

fn leftmost_key_lazy_inner(
    node: &mut InnerNode,
    backend: Option<&Arc<dyn NodeStore>>,
) -> Option<Key> {
    for branch in 0..16 {
        if node.children[branch].is_none() && node.child_hashes[branch] != [0u8; 32] {
            materialize_child_from_backend(node, branch, backend);
        }
        if let Some(child) = node.children[branch].as_mut() {
            if let Some(found) = leftmost_key_lazy_node(child.as_mut(), backend) {
                return Some(found);
            }
        }
    }
    None
}

fn upper_bound_lazy_inner(
    node: &mut InnerNode,
    target: &Key,
    depth: usize,
    backend: Option<&Arc<dyn NodeStore>>,
) -> Option<Key> {
    let nibble = target.nibble(depth);

    if node.children[nibble].is_none() && node.child_hashes[nibble] != [0u8; 32] {
        materialize_child_from_backend(node, nibble, backend);
    }
    if let Some(child) = node.children[nibble].as_mut() {
        match child.as_mut() {
            Node::Leaf(leaf) if leaf.key > *target => return Some(leaf.key),
            Node::Stub { key, .. } if *key > *target => return Some(*key),
            Node::Inner(inner) => {
                if let Some(found) = upper_bound_lazy_inner(inner, target, depth + 1, backend) {
                    return Some(found);
                }
            }
            _ => {}
        }
    }

    for branch in (nibble + 1)..16 {
        if node.children[branch].is_none() && node.child_hashes[branch] != [0u8; 32] {
            materialize_child_from_backend(node, branch, backend);
        }
        if let Some(child) = node.children[branch].as_mut() {
            if let Some(found) = leftmost_key_lazy_node(child.as_mut(), backend) {
                return Some(found);
            }
        }
    }

    None
}

fn serialize_inner_wire(node: &mut InnerNode, map_type: MapType) -> Vec<u8> {
    let mut wire = Vec::with_capacity(16 * 32 + 1);
    for branch in 0..16 {
        let child_hash = match node.children[branch].as_mut() {
            Some(child) => child.hash(map_type),
            None => node.child_hashes[branch],
        };
        node.child_hashes[branch] = child_hash;
        wire.extend_from_slice(&child_hash);
    }
    wire.push(WIRE_TYPE_INNER);
    wire
}

fn leaf_wire_type(map_type: MapType) -> u8 {
    match map_type {
        MapType::AccountState => WIRE_TYPE_ACCOUNT_STATE,
        MapType::Transaction => WIRE_TYPE_TRANSACTION,
    }
}

fn serialize_leaf_wire(leaf: &LeafNode, map_type: MapType) -> Vec<u8> {
    let mut wire = Vec::with_capacity(leaf.data.len() + 33);
    wire.extend_from_slice(&leaf.data);
    wire.extend_from_slice(&leaf.key.0);
    wire.push(leaf_wire_type(map_type));
    wire
}

fn serialize_stub_wire(
    key: &Key,
    content_hash: &[u8; 32],
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
) -> Option<Vec<u8>> {
    let data = resolve_stub(content_hash, key, backend?.as_ref())?;
    let mut wire = Vec::with_capacity(data.len() + 33);
    wire.extend_from_slice(&data);
    wire.extend_from_slice(&key.0);
    wire.push(leaf_wire_type(map_type));
    Some(wire)
}

fn get_wire_node_recursive(
    node: &mut InnerNode,
    current_id: &SHAMapNodeID,
    target_id: &SHAMapNodeID,
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
) -> Option<Vec<u8>> {
    if current_id == target_id {
        return Some(serialize_inner_wire(node, map_type));
    }

    let branch = current_id.select_branch(target_id);
    materialize_child_from_backend(node, branch, backend);
    let child = node.children[branch].as_mut()?;
    let child_id = current_id.child_id(branch as u8);

    if child_id == *target_id {
        return match child.as_mut() {
            Node::Inner(inner) => Some(serialize_inner_wire(inner, map_type)),
            Node::Leaf(leaf) => Some(serialize_leaf_wire(leaf, map_type)),
            Node::Stub { key, content_hash } => serialize_stub_wire(key, content_hash, map_type, backend),
        };
    }

    match child.as_mut() {
        Node::Leaf(leaf) => {
            if target_id.depth() == 64 && leaf.key.0 == *target_id.id() {
                Some(serialize_leaf_wire(leaf, map_type))
            } else {
                None
            }
        }
        Node::Stub { key, content_hash } => {
            if target_id.depth() == 64 && key.0 == *target_id.id() {
                serialize_stub_wire(key, content_hash, map_type, backend)
            } else {
                None
            }
        }
        Node::Inner(inner) => get_wire_node_recursive(inner, &child_id, target_id, map_type, backend),
    }
}

fn collect_wire_subtree_from_node(
    node: &mut Node,
    response_id: &SHAMapNodeID,
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
    remaining_depth: u32,
    out: &mut Vec<([u8; 33], Vec<u8>)>,
) {
    match node {
        Node::Leaf(leaf) => out.push((response_id.to_wire(), serialize_leaf_wire(leaf, map_type))),
        Node::Stub { key, content_hash } => {
            if let Some(wire) = serialize_stub_wire(key, content_hash, map_type, backend) {
                out.push((response_id.to_wire(), wire));
            }
        }
        Node::Inner(inner) => {
            out.push((response_id.to_wire(), serialize_inner_wire(inner, map_type)));
            if remaining_depth == 0 {
                return;
            }
            for branch in 0..16 {
                if inner.children[branch].is_none() && inner.child_hashes[branch] != [0u8; 32] {
                    materialize_child_from_backend(inner, branch, backend);
                }
                if let Some(child) = inner.children[branch].as_mut() {
                    let child_id = response_id.child_id(branch as u8);
                    collect_wire_subtree_from_node(
                        child.as_mut(),
                        &child_id,
                        map_type,
                        backend,
                        remaining_depth - 1,
                        out,
                    );
                }
            }
        }
    }
}

fn collect_wire_nodes_for_query_recursive(
    node: &mut InnerNode,
    current_id: &SHAMapNodeID,
    target_id: &SHAMapNodeID,
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
    query_depth: u32,
    out: &mut Vec<([u8; 33], Vec<u8>)>,
) -> bool {
    if current_id == target_id {
        out.push((current_id.to_wire(), serialize_inner_wire(node, map_type)));
        if query_depth > 0 {
            for branch in 0..16 {
                if node.children[branch].is_none() && node.child_hashes[branch] != [0u8; 32] {
                    materialize_child_from_backend(node, branch, backend);
                }
                if let Some(child) = node.children[branch].as_mut() {
                    let child_id = current_id.child_id(branch as u8);
                    collect_wire_subtree_from_node(
                        child.as_mut(),
                        &child_id,
                        map_type,
                        backend,
                        query_depth - 1,
                        out,
                    );
                }
            }
        }
        return true;
    }

    let branch = current_id.select_branch(target_id);
    materialize_child_from_backend(node, branch, backend);
    let Some(child) = node.children[branch].as_mut() else {
        return false;
    };
    let child_id = current_id.child_id(branch as u8);

    if child_id == *target_id {
        collect_wire_subtree_from_node(
            child.as_mut(),
            &child_id,
            map_type,
            backend,
            query_depth,
            out,
        );
        return true;
    }

    match child.as_mut() {
        Node::Leaf(leaf) => {
            if target_id.depth() == 64 && leaf.key.0 == *target_id.id() {
                out.push((target_id.to_wire(), serialize_leaf_wire(leaf, map_type)));
                true
            } else {
                false
            }
        }
        Node::Stub { key, content_hash } => {
            if target_id.depth() == 64 && key.0 == *target_id.id() {
                if let Some(wire) = serialize_stub_wire(key, content_hash, map_type, backend) {
                    out.push((target_id.to_wire(), wire));
                    true
                } else {
                    false
                }
            } else {
                false
            }
        }
        Node::Inner(inner) => collect_wire_nodes_for_query_recursive(
            inner,
            &child_id,
            target_id,
            map_type,
            backend,
            query_depth,
            out,
        ),
    }
}

// ── Recursive tree operations ─────────────────────────────────────────────────

fn insert_node(
    node: &mut InnerNode,
    key: Key,
    data: Vec<u8>,
    mt: MapType,
    depth: usize,
    backend: Option<&Arc<dyn NodeStore>>,
) -> bool {
    let nibble = key.nibble(depth);
    node.invalidate();

    // In a backend-backed lazy tree, `children[nibble] == None` does not mean
    // the branch is empty. It can mean "the child exists only by hash so far".
    // Materialize that child before inserting, otherwise a new overlay leaf can
    // overwrite the unresolved backend subtree and hide synced state.
    materialize_child_from_backend(node, nibble, backend);

    match &mut node.children[nibble] {
        // Empty slot — just place a new leaf here
        slot @ None => {
            *slot = Some(Box::new(Node::Leaf(LeafNode::new(key, data))));
            true
        }
        Some(child) => match child.as_mut() {
            // Existing leaf at this slot
            Node::Leaf(leaf) => {
                if leaf.key == key {
                    // Key already exists — update data
                    leaf.data = data;
                    leaf.cached_hash = None;
                    return false; // not a new insertion
                }
                // Key collision at this depth — need to push both leaves deeper
                let existing_key  = leaf.key;
                let existing_data = std::mem::take(&mut leaf.data);
                let mut new_inner = InnerNode::new();
                insert_node(&mut new_inner, existing_key, existing_data, mt, depth + 1, backend);
                insert_node(&mut new_inner, key, data, mt, depth + 1, backend);
                *child = Box::new(Node::Inner(new_inner));
                true
            }
            // Existing inner node — recurse
            Node::Inner(inner) => {
                insert_node(inner, key, data, mt, depth + 1, backend)
            }
            // Existing stub — replace with full leaf (overwrite)
            Node::Stub { key: stub_key, .. } => {
                if *stub_key == key {
                    *child = Box::new(Node::Leaf(LeafNode::new(key, data)));
                    false // key existed (as stub), just loading data
                } else {
                    // Key collision with stub — push both deeper
                    let existing = std::mem::replace(child, Box::new(Node::Inner(InnerNode::new())));
                    if let Node::Inner(ref mut inner) = child.as_mut() {
                        if let Node::Stub { key: sk, content_hash: ch } = *existing {
                            insert_stub_node(inner, sk, ch, depth + 1);
                        }
                        insert_node(inner, key, data, mt, depth + 1, backend);
                    }
                    true
                }
            }
        }
    }
}

fn get_node<'a>(node: &'a InnerNode, key: &Key, depth: usize) -> Option<&'a [u8]> {
    let nibble = key.nibble(depth);
    match &node.children[nibble] {
        None => None,
        Some(child) => match child.as_ref() {
            Node::Leaf(leaf) => {
                if &leaf.key == key { Some(&leaf.data) } else { None }
            }
            Node::Inner(inner) => get_node(inner, key, depth + 1),
            Node::Stub { .. } => None, // Not loaded — caller must use get_node_lazy
        }
    }
}

fn remove_node(
    node: &mut InnerNode,
    key: &Key,
    depth: usize,
    backend: Option<&Arc<dyn NodeStore>>,
) -> bool {
    let nibble = key.nibble(depth);

    // In a backend-backed lazy tree, a missing child pointer can still mean
    // "known by hash, not yet materialized". Deletions must resolve that
    // child before deciding the key is absent, otherwise snapshot overlays
    // hide deleted leaves in lookups but leave them in the hashed tree.
    materialize_child_from_backend(node, nibble, backend);

    let found = match &mut node.children[nibble] {
        None => false,
        Some(child) => match child.as_mut() {
            Node::Leaf(leaf) => leaf.key == *key,
            Node::Stub { key: sk, .. } => *sk == *key,
            Node::Inner(inner) => {
                let removed = remove_node(inner, key, depth + 1, backend);
                if removed {
                    node.invalidate();
                    // Collapse: if inner node now has exactly one remaining branch,
                    // replace the inner node with that child. Count hash-only
                    // branches too; otherwise restarted backend-backed trees can
                    // leave non-canonical single-branch inner chains after deletion.
                    if let Some(ref inner_box) = node.children[nibble] {
                        if let Node::Inner(ref inner_node) = inner_box.as_ref() {
                            let remaining: Vec<usize> = (0..16)
                                .filter(|i| {
                                    inner_node.children[*i].is_some()
                                        || inner_node.child_hashes[*i] != [0u8; 32]
                                })
                                .collect();
                            if remaining.is_empty() {
                                node.children[nibble] = None;
                                node.child_hashes[nibble] = [0u8; 32];
                                node.is_branch &= !(1 << nibble);
                                return true;
                            }
                            if remaining.len() == 1 {
                                let idx = remaining[0];
                                if let Some(child) = &mut node.children[nibble] {
                                    if let Node::Inner(inner_mut) = child.as_mut() {
                                        materialize_child_from_backend(inner_mut, idx, backend);
                                    }
                                }
                                let can_collapse_to_child = if let Some(child) = &node.children[nibble] {
                                    if let Node::Inner(inner_ref) = child.as_ref() {
                                        matches!(
                                            inner_ref.children[idx].as_deref(),
                                            Some(Node::Leaf(_)) | Some(Node::Stub { .. })
                                        )
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };
                                if can_collapse_to_child {
                                    let mut replacement = None;
                                    if let Some(child) = node.children[nibble].take() {
                                        if let Node::Inner(mut inner_node) = *child {
                                            replacement = inner_node.children[idx].take();
                                        }
                                    }
                                    node.children[nibble] = replacement;
                                }
                            }
                        }
                    }
                }
                return removed;
            }
        }
    };
    if found {
        node.children[nibble] = None;
        node.child_hashes[nibble] = [0u8; 32];
        node.is_branch &= !(1 << nibble);
        node.invalidate();
    }
    found
}

fn materialize_child_from_backend(
    node: &mut InnerNode,
    nibble: usize,
    backend: Option<&Arc<dyn NodeStore>>,
) {
    if node.children[nibble].is_some() || node.child_hashes[nibble] == [0u8; 32] {
        return;
    }
    let Some(be) = backend else {
        return;
    };
    let child_hash = node.child_hashes[nibble];
    if let Ok(Some(stored)) = be.fetch(&child_hash) {
        if stored.len() == 16 * 32 {
            if let Some(inner) = deserialize_inner_from_store(&stored) {
                node.children[nibble] = Some(Box::new(Node::Inner(inner)));
            }
        } else if stored.len() >= 32 {
            let mut stored_key = [0u8; 32];
            stored_key.copy_from_slice(&stored[stored.len() - 32..]);
            node.children[nibble] = Some(Box::new(Node::Leaf(LeafNode {
                key: Key(stored_key),
                data: stored[..stored.len() - 32].to_vec(),
                cached_hash: Some(child_hash),
                dirty: false,
            })));
        }
    }
}

/// Resolve a stub leaf by fetching its data from the backend NodeStore.
/// Returns the deserialized leaf data (SLE bytes), or None if not found.
fn resolve_stub(content_hash: &[u8; 32], key: &Key, backend: &dyn NodeStore) -> Option<Vec<u8>> {
    let node_bytes = backend.fetch(content_hash).ok()??;
    // Leaf node in the store is: SLE data + 32-byte entry key
    // Verify the key matches
    if node_bytes.len() >= 32 {
        let stored_key = &node_bytes[node_bytes.len() - 32..];
        if stored_key == &key.0 {
            return Some(node_bytes[..node_bytes.len() - 32].to_vec());
        }
    }
    // Fallback: return all bytes (might be an inner node or different format)
    Some(node_bytes)
}

/// Get node data, resolving stubs on demand from the backend.
fn get_node_lazy(
    node: &mut InnerNode,
    key: &Key,
    depth: usize,
    backend: Option<&Arc<dyn NodeStore>>,
) -> Option<Vec<u8>> {
    let nibble = key.nibble(depth);
    match &mut node.children[nibble] {
        None => {
            let child_hash = node.child_hashes[nibble];
            if child_hash == [0u8; 32] {
                return None;
            }
            let backend = backend?;
            let stored = backend.fetch(&child_hash).ok()??;
            if stored.len() == 16 * 32 {
                let inner = deserialize_inner_from_store(&stored)?;
                node.children[nibble] = Some(Box::new(Node::Inner(inner)));
                if let Some(child) = &mut node.children[nibble] {
                    if let Node::Inner(inner) = child.as_mut() {
                        return get_node_lazy(inner, key, depth + 1, Some(backend));
                    }
                }
                None
            } else if stored.len() >= 32 {
                let mut stored_key = [0u8; 32];
                stored_key.copy_from_slice(&stored[stored.len() - 32..]);
                let loaded_key = Key(stored_key);
                let data = stored[..stored.len() - 32].to_vec();
                node.children[nibble] = Some(Box::new(Node::Leaf(LeafNode {
                    key: loaded_key,
                    data: data.clone(),
                    cached_hash: Some(child_hash),
                    dirty: false,
                })));
                if loaded_key == *key {
                    Some(data)
                } else {
                    None
                }
            } else {
                None
            }
        }
        Some(child) => match child.as_mut() {
            Node::Leaf(leaf) => {
                if &leaf.key == key { Some(leaf.data.clone()) } else { None }
            }
            Node::Inner(inner) => get_node_lazy(inner, key, depth + 1, backend),
            Node::Stub { key: stub_key, content_hash } => {
                if stub_key != key { return None; }
                // Resolve the stub
                let backend = backend?;
                let data = resolve_stub(content_hash, key, backend.as_ref())?;
                // Promote stub to full leaf (not dirty — loaded from backend)
                let ch = *content_hash;
                *child = Box::new(Node::Leaf(LeafNode {
                    key: *key,
                    data: data.clone(),
                    cached_hash: Some(ch),
                    dirty: false,
                }));
                Some(data)
            }
        }
    }
}

fn debug_trace_key_path_recursive(
    node: &mut InnerNode,
    key: &Key,
    depth: usize,
    backend: Option<&Arc<dyn NodeStore>>,
    lines: &mut Vec<String>,
) {
    if depth >= 64 {
        lines.push("depth>=64".to_string());
        return;
    }
    let nibble = key.nibble(depth);
    let child_hash = node.child_hashes[nibble];
    let has_branch = node.has_branch(nibble);
    lines.push(format!(
        "depth={} nibble={} has_branch={} child_hash={}",
        depth,
        nibble,
        has_branch,
        hex::encode_upper(&child_hash[..8]),
    ));

    match &mut node.children[nibble] {
        Some(child) => match child.as_mut() {
            Node::Inner(inner) => {
                lines.push("child=inner".to_string());
                debug_trace_key_path_recursive(inner, key, depth + 1, backend, lines);
            }
            Node::Leaf(leaf) => {
                lines.push(format!(
                    "child=leaf key_match={} leaf_key={}",
                    leaf.key == *key,
                    hex::encode_upper(&leaf.key.0[..8]),
                ));
            }
            Node::Stub { key: stub_key, content_hash } => {
                lines.push(format!(
                    "child=stub key_match={} stub_key={} content_hash={}",
                    *stub_key == *key,
                    hex::encode_upper(&stub_key.0[..8]),
                    hex::encode_upper(&content_hash[..8]),
                ));
                if let Some(be) = backend {
                    match be.fetch(content_hash) {
                        Ok(Some(stored)) => {
                            lines.push(format!("stub_fetch=found {}bytes", stored.len()));
                        }
                        Ok(None) => lines.push("stub_fetch=missing".to_string()),
                        Err(e) => lines.push(format!("stub_fetch=err {}", e)),
                    }
                } else {
                    lines.push("stub_fetch=no_backend".to_string());
                }
            }
        },
        None => {
            if child_hash == [0u8; 32] {
                lines.push("child=none hash_zero".to_string());
                return;
            }
            let Some(be) = backend else {
                lines.push("child=none no_backend".to_string());
                return;
            };
            match be.fetch(&child_hash) {
                Ok(Some(stored)) => {
                    lines.push(format!("child=none backend_found {}bytes", stored.len()));
                    if stored.len() == 16 * 32 {
                        if let Some(inner) = deserialize_inner_from_store(&stored) {
                            node.children[nibble] = Some(Box::new(Node::Inner(inner)));
                            if let Some(child) = &mut node.children[nibble] {
                                if let Node::Inner(inner) = child.as_mut() {
                                    debug_trace_key_path_recursive(inner, key, depth + 1, Some(be), lines);
                                }
                            }
                        } else {
                            lines.push("backend_inner_deserialize_failed".to_string());
                        }
                    } else if stored.len() >= 32 {
                        let mut stored_key = [0u8; 32];
                        stored_key.copy_from_slice(&stored[stored.len() - 32..]);
                        lines.push(format!(
                            "backend_leaf key_match={} stored_key={}",
                            stored_key == key.0,
                            hex::encode_upper(&stored_key[..8]),
                        ));
                    } else {
                        lines.push("backend_short_object".to_string());
                    }
                }
                Ok(None) => lines.push("child=none backend_missing".to_string()),
                Err(e) => lines.push(format!("child=none backend_err {}", e)),
            }
        }
    }
}

/// Insert a stub node into the tree.
fn insert_stub_node(node: &mut InnerNode, key: Key, content_hash: [u8; 32], depth: usize) {
    let nibble = key.nibble(depth);
    node.invalidate();

    match &mut node.children[nibble] {
        slot @ None => {
            *slot = Some(Box::new(Node::Stub { key, content_hash }));
        }
        Some(child) => match child.as_mut() {
            Node::Leaf(leaf) if leaf.key == key => {
                // Replace existing leaf with stub (shouldn't happen normally)
                *child = Box::new(Node::Stub { key, content_hash });
            }
            Node::Leaf(_) => {
                // Key collision — need inner node
                let existing = std::mem::replace(
                    child,
                    Box::new(Node::Inner(InnerNode::new())),
                );
                if let Node::Inner(ref mut inner) = child.as_mut() {
                    // Re-insert existing node
                    match *existing {
                        Node::Leaf(leaf) => {
                            insert_node(inner, leaf.key, leaf.data, MapType::AccountState, depth + 1, None);
                        }
                        Node::Stub { key: sk, content_hash: ch } => {
                            insert_stub_node(inner, sk, ch, depth + 1);
                        }
                        _ => {}
                    }
                    // Insert new stub
                    insert_stub_node(inner, key, content_hash, depth + 1);
                }
            }
            Node::Inner(inner) => {
                insert_stub_node(inner, key, content_hash, depth + 1);
            }
            Node::Stub { key: existing_key, .. } if *existing_key == key => {
                // Update stub hash
                *child = Box::new(Node::Stub { key, content_hash });
            }
            Node::Stub { .. } => {
                // Key collision with another stub — need inner node
                let existing = std::mem::replace(
                    child,
                    Box::new(Node::Inner(InnerNode::new())),
                );
                if let Node::Inner(ref mut inner) = child.as_mut() {
                    if let Node::Stub { key: sk, content_hash: ch } = *existing {
                        insert_stub_node(inner, sk, ch, depth + 1);
                    }
                    insert_stub_node(inner, key, content_hash, depth + 1);
                }
            }
        }
    }
}

fn deserialize_inner_from_store(data: &[u8]) -> Option<InnerNode> {
    if data.len() != 16 * 32 {
        return None;
    }
    let mut inner = InnerNode::new();
    for i in 0..16 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[i * 32..(i + 1) * 32]);
        inner.set_child_hash(i, hash);
    }
    inner.dirty = false;
    Some(inner)
}

/// Collect dirty nodes (full leaves + inner nodes) for flushing to the backend.
/// Each entry is (content_hash, serialized_bytes).
fn collect_dirty_nodes(
    node: &mut InnerNode,
    map_type: MapType,
    batch: &mut Vec<([u8; 32], Vec<u8>)>,
) {
    for child in node.children.iter_mut() {
        if let Some(ref mut boxed) = child {
            match boxed.as_mut() {
                Node::Leaf(leaf) if leaf.dirty => {
                    // Dirty leaf — compute hash and serialize for store
                    let hash = leaf.hash(map_type);
                    // Store format: SLE data + entry key (32 bytes)
                    let mut store_data = Vec::with_capacity(leaf.data.len() + 32);
                    store_data.extend_from_slice(&leaf.data);
                    store_data.extend_from_slice(&leaf.key.0);
                    batch.push((hash, store_data));
                    leaf.dirty = false; // Mark clean
                }
                Node::Inner(inner) => {
                    // Recurse into inner nodes
                    collect_dirty_nodes(inner, map_type, batch);
                    if inner.dirty {
                        // Dirty inner node — serialize children hashes
                        let hash = inner.hash(map_type);
                        let mut store_data = Vec::with_capacity(16 * 32);
                        for child in inner.children.iter_mut() {
                            match child {
                                Some(n) => store_data.extend_from_slice(&n.hash(map_type)),
                                None => store_data.extend_from_slice(&[0u8; 32]),
                            }
                        }
                        batch.push((hash, store_data));
                        inner.dirty = false;
                    }
                }
                _ => {} // Stubs and clean leaves don't need flushing
            }
        }
    }
}

/// Evict clean leaf nodes back to stubs (key + content_hash only).
/// Returns number of leaves evicted.
fn evict_clean_recursive(node: &mut InnerNode, map_type: MapType) -> usize {
    let mut evicted = 0;
    for slot in node.children.iter_mut() {
        if let Some(child) = slot {
            match child.as_mut() {
                Node::Leaf(leaf) if !leaf.dirty => {
                    // Clean leaf — evict to stub
                    let key = leaf.key;
                    let hash = leaf.cached_hash.unwrap_or_else(|| leaf.hash(map_type));
                    *child = Box::new(Node::Stub { key, content_hash: hash });
                    evicted += 1;
                }
                Node::Inner(inner) => {
                    evicted += evict_clean_recursive(inner, map_type);
                }
                _ => {} // Dirty leaves and stubs stay
            }
        }
    }
    evicted
}

/// Recursively collect all leaf (Key, &data) pairs from the tree.
fn collect_leaves<'a>(node: &'a InnerNode, results: &mut Vec<(Key, &'a [u8])>) {
    for child in &node.children {
        if let Some(ref boxed) = child {
            match boxed.as_ref() {
                Node::Leaf(leaf) => {
                    results.push((leaf.key, &leaf.data));
                }
                Node::Inner(inner) => {
                    collect_leaves(inner, results);
                }
                Node::Stub { .. } => {
                    // Stub leaves are not loaded — skip
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Key {
        let mut k = [0u8; 32];
        k[0] = n;
        Key(k)
    }

    #[allow(dead_code)]
    fn key2(a: u8, b: u8) -> Key {
        let mut k = [0u8; 32];
        k[0] = a;
        k[1] = b;
        Key(k)
    }

    #[test]
    fn test_empty_map_root_hash() {
        let mut m = SHAMap::new_state();
        let h1 = m.root_hash();
        let h2 = m.root_hash();
        // Deterministic on empty map
        assert_eq!(h1, h2);
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn test_insert_and_get() {
        let mut m = SHAMap::new_state();
        let k = key(0xAB);
        m.insert(k, b"account data".to_vec());
        assert_eq!(m.get(&k), Some(b"account data".to_vec()));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn test_missing_key_returns_none() {
        let mut m = SHAMap::new_state();
        m.insert(key(1), b"data".to_vec());
        assert_eq!(m.get(&key(2)), None);
    }

    #[test]
    fn test_hash_changes_on_insert() {
        let mut m = SHAMap::new_state();
        let h_empty = m.root_hash();
        m.insert(key(1), b"x".to_vec());
        let h_one = m.root_hash();
        assert_ne!(h_empty, h_one, "hash must change after insert");
    }

    #[test]
    fn test_hash_changes_on_update() {
        let mut m = SHAMap::new_state();
        m.insert(key(1), b"original".to_vec());
        let h1 = m.root_hash();
        m.insert(key(1), b"updated".to_vec()); // update existing key
        let h2 = m.root_hash();
        assert_ne!(h1, h2, "hash must change after update");
    }

    #[test]
    fn test_multiple_inserts_same_nibble() {
        // Keys that share the same first nibble force path splitting
        let mut m = SHAMap::new_state();
        m.insert(key(0x10), b"a".to_vec());
        m.insert(key(0x11), b"b".to_vec()); // same high nibble (0x1_)
        m.insert(key(0x12), b"c".to_vec());
        assert_eq!(m.len(), 3);
        assert_eq!(m.get(&key(0x10)), Some(b"a".to_vec()));
        assert_eq!(m.get(&key(0x11)), Some(b"b".to_vec()));
        assert_eq!(m.get(&key(0x12)), Some(b"c".to_vec()));
    }

    #[test]
    fn test_remove() {
        let mut m = SHAMap::new_state();
        let k = key(5);
        m.insert(k, b"hello".to_vec());
        let h_before = m.root_hash();
        assert!(m.remove(&k));
        assert_eq!(m.get(&k), None);
        assert_eq!(m.len(), 0);
        // After removal hash should differ from when item was present
        let h_after = m.root_hash();
        assert_ne!(h_before, h_after);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut m = SHAMap::new_state();
        assert!(!m.remove(&key(99)));
    }

    #[test]
    fn test_hash_deterministic_across_instances() {
        // Two maps with the same contents must produce the same root hash
        let mut m1 = SHAMap::new_state();
        let mut m2 = SHAMap::new_state();
        for i in 0u8..=10 {
            let data = vec![i; 32];
            m1.insert(key(i), data.clone());
            m2.insert(key(i), data);
        }
        assert_eq!(m1.root_hash(), m2.root_hash());
    }

    #[test]
    fn test_order_independence() {
        // Insert order must not affect the root hash
        let mut m1 = SHAMap::new_state();
        let mut m2 = SHAMap::new_state();
        let pairs: Vec<(Key, Vec<u8>)> = (0u8..8)
            .map(|i| (key(i), vec![i; 16]))
            .collect();
        for (k, v) in &pairs {
            m1.insert(*k, v.clone());
        }
        for (k, v) in pairs.iter().rev() {
            m2.insert(*k, v.clone());
        }
        assert_eq!(m1.root_hash(), m2.root_hash(),
            "insert order must not affect root hash");
    }

    #[test]
    fn test_nibble_extraction() {
        let mut k = [0u8; 32];
        k[0] = 0xAB;
        let key = Key(k);
        assert_eq!(key.nibble(0), 0xA);
        assert_eq!(key.nibble(1), 0xB);
        assert_eq!(key.nibble(2), 0x0); // next byte is 0
    }

    #[test]
    fn test_transaction_and_state_maps_differ() {
        // Same key+data in a tx map vs state map should hash differently (different prefix)
        let mut tx_map    = SHAMap::new_transaction();
        let mut state_map = SHAMap::new_state();
        tx_map.insert(key(1),    b"data".to_vec());
        state_map.insert(key(1), b"data".to_vec());
        assert_ne!(tx_map.root_hash(), state_map.root_hash(),
            "tx and state maps must use different hash prefixes");
    }

    // ── NodeStore round-trip tests ───────────────────────────────────────────

    #[test]
    fn test_flush_and_reload_from_backend() {
        use crate::ledger::node_store::MemNodeStore;

        let backend = Arc::new(MemNodeStore::new());

        // Build a SHAMap with some data and flush to backend
        let mut m1 = SHAMap::with_backend(MapType::AccountState, backend.clone());
        for i in 0u8..20 {
            m1.insert(key(i), vec![i; 64]);
        }
        let root_hash = m1.root_hash();
        let flushed = m1.flush_dirty().unwrap();
        assert!(flushed > 0, "should have flushed dirty nodes");

        // Build a new SHAMap from stubs — only leaf hashes, data on disk
        let mut m2 = SHAMap::with_backend(MapType::AccountState, backend.clone());
        for i in 0u8..20 {
            let k = key(i);
            // Compute the expected leaf hash
            let data = vec![i; 64];
            let mut payload = Vec::new();
            payload.extend_from_slice(&PREFIX_LEAF_STATE);
            payload.extend_from_slice(&data);
            payload.extend_from_slice(&k.0);
            let leaf_hash = sha512_first_half(&payload);
            m2.insert_stub(k, leaf_hash);
        }

        // Root hash from stubs should match original
        assert_eq!(m2.root_hash(), root_hash,
            "stub-based SHAMap must produce same root hash");

        // Data should be fetchable via lazy loading from backend
        for i in 0u8..20 {
            let data = m2.get(&key(i)).expect(&format!("key {} should resolve from backend", i));
            assert_eq!(data, vec![i; 64], "data mismatch for key {}", i);
        }
    }

    #[test]
    fn test_stub_overwrite_with_insert() {
        use crate::ledger::node_store::MemNodeStore;

        let backend = Arc::new(MemNodeStore::new());
        let mut m = SHAMap::with_backend(MapType::AccountState, backend.clone());

        // Insert real data, flush, then insert stub for same key
        let k = key(0x42);
        m.insert(k, b"original".to_vec());
        m.flush_dirty().unwrap();

        // Now insert new data at the same key (overwrite stub with real leaf)
        m.insert(k, b"updated".to_vec());
        let data = m.get(&k).unwrap();
        assert_eq!(data, b"updated");
    }

    #[test]
    fn test_remove_materializes_unresolved_backend_subtree() {
        use crate::ledger::node_store::MemNodeStore;

        let backend = Arc::new(MemNodeStore::new());

        let k1 = key(0x10);
        let k2 = key(0x11);
        let k3 = key(0x20);

        let mut seeded = SHAMap::with_backend(MapType::AccountState, backend.clone());
        seeded.insert(k1, b"one".to_vec());
        seeded.insert(k2, b"two".to_vec());
        seeded.insert(k3, b"three".to_vec());
        let root_hash = seeded.root_hash();
        seeded.flush_dirty().unwrap();

        let mut restarted = SHAMap::with_backend(MapType::AccountState, backend.clone());
        assert!(restarted.load_root_from_hash(root_hash).unwrap());
        restarted.count = 3;
        assert!(restarted.remove(&k1), "remove should resolve the hashed child subtree");

        let mut expected = SHAMap::with_backend(MapType::AccountState, backend);
        expected.insert(k2, b"two".to_vec());
        expected.insert(k3, b"three".to_vec());

        assert_eq!(
            restarted.root_hash(),
            expected.root_hash(),
            "removing from a restarted backend-backed SHAMap must update the hashed tree",
        );
    }

    #[test]
    fn test_leaf_serialization_format() {
        // Verify the store format: [sle_data || entry_key(32)]
        use crate::ledger::node_store::MemNodeStore;

        let backend = Arc::new(MemNodeStore::new());
        let mut m = SHAMap::with_backend(MapType::AccountState, backend.clone());

        let k = key(0xAA);
        let data = b"test sle data".to_vec();
        m.insert(k, data.clone());

        // Compute expected leaf hash
        let mut payload = Vec::new();
        payload.extend_from_slice(&PREFIX_LEAF_STATE);
        payload.extend_from_slice(&data);
        payload.extend_from_slice(&k.0);
        let expected_hash = sha512_first_half(&payload);

        m.flush_dirty().unwrap();

        // Verify the node is in the backend with correct format
        let stored = backend.fetch(&expected_hash).unwrap().expect("node should be in backend");
        assert_eq!(stored.len(), data.len() + 32, "stored = data + key");
        assert_eq!(&stored[..data.len()], data.as_slice(), "data portion");
        assert_eq!(&stored[data.len()..], &k.0, "key portion");
    }

    #[test]
    fn test_inner_node_serialization_format() {
        // Verify inner nodes are stored as 16 × 32-byte child hashes
        use crate::ledger::node_store::MemNodeStore;

        let backend = Arc::new(MemNodeStore::new());
        let mut m = SHAMap::with_backend(MapType::AccountState, backend.clone());

        // Insert two keys that share first nibble → creates inner node
        m.insert(key(0x10), b"a".to_vec());
        m.insert(key(0x11), b"b".to_vec());

        let root_hash = m.root_hash();
        m.flush_dirty().unwrap();

        // The root inner node should be in the backend
        let stored = backend.fetch(&root_hash).unwrap().expect("root node should be in backend");
        assert_eq!(stored.len(), 16 * 32, "inner node = 16 × 32-byte child hashes");
    }

    #[test]
    fn test_nudb_round_trip() {
        // Full round-trip through NuDB on disk
        use crate::ledger::node_store::NuDBNodeStore;

        let dir = std::env::temp_dir().join("shamap_nudb_test");
        let _ = std::fs::remove_dir_all(&dir);
        let backend = Arc::new(NuDBNodeStore::open(&dir).unwrap());

        let mut m1 = SHAMap::with_backend(MapType::AccountState, backend.clone());
        for i in 0u8..50 {
            let mut k = [0u8; 32];
            k[0] = i;
            k[31] = i; // spread across key space
            m1.insert(Key(k), vec![i; 100]);
        }
        let root_hash = m1.root_hash();
        m1.flush_dirty().unwrap();

        // Rebuild from stubs
        let mut m2 = SHAMap::with_backend(MapType::AccountState, backend.clone());
        for i in 0u8..50 {
            let mut k = [0u8; 32];
            k[0] = i;
            k[31] = i;
            let data = vec![i; 100];
            let mut payload = Vec::new();
            payload.extend_from_slice(&PREFIX_LEAF_STATE);
            payload.extend_from_slice(&data);
            payload.extend_from_slice(&k);
            let leaf_hash = sha512_first_half(&payload);
            m2.insert_stub(Key(k), leaf_hash);
        }
        assert_eq!(m2.root_hash(), root_hash, "NuDB round-trip: root hash must match");

        // Verify lazy loading works
        for i in 0u8..50 {
            let mut k = [0u8; 32];
            k[0] = i;
            k[31] = i;
            let data = m2.get(&Key(k)).expect(&format!("key {} should load from NuDB", i));
            assert_eq!(data, vec![i; 100]);
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_reload_root_from_backend_enables_lazy_lookup() {
        use crate::ledger::node_store::NuDBNodeStore;

        let dir = std::env::temp_dir().join("shamap_reload_root_test");
        let _ = std::fs::remove_dir_all(&dir);
        let backend = Arc::new(NuDBNodeStore::open(&dir).unwrap());

        let mut original = SHAMap::with_backend(MapType::AccountState, backend.clone());
        let k = key(0xAB);
        let v = b"root reload probe".to_vec();
        original.insert(k, v.clone());
        let root_hash = original.root_hash();
        original.flush_dirty().unwrap();

        let mut restarted = SHAMap::with_backend(MapType::AccountState, backend.clone());
        assert!(restarted.load_root_from_hash(root_hash).unwrap());
        assert_eq!(restarted.get(&k), Some(v));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lazy_key_walk_enumerates_backend_root_in_order() {
        use crate::ledger::node_store::NuDBNodeStore;

        let dir = std::env::temp_dir().join("shamap_lazy_key_walk_test");
        let _ = std::fs::remove_dir_all(&dir);
        let backend = Arc::new(NuDBNodeStore::open(&dir).unwrap());

        let keys = [
            Key::from_hex("0100000000000000000000000000000000000000000000000000000000000000").unwrap(),
            Key::from_hex("0110000000000000000000000000000000000000000000000000000000000000").unwrap(),
            Key::from_hex("0F00000000000000000000000000000000000000000000000000000000000000").unwrap(),
            Key::from_hex("A100000000000000000000000000000000000000000000000000000000000000").unwrap(),
        ];

        let mut seeded = SHAMap::with_backend(MapType::AccountState, backend.clone());
        for (i, key) in keys.iter().enumerate() {
            seeded.insert(*key, vec![i as u8; 8]);
        }
        let root_hash = seeded.root_hash();
        seeded.flush_dirty().unwrap();

        let mut restarted = SHAMap::with_backend(MapType::AccountState, backend);
        assert!(restarted.load_root_from_hash(root_hash).unwrap());
        restarted.count = keys.len();

        let mut walked = Vec::new();
        let mut next = restarted.first_key_lazy();
        while let Some(key) = next {
            walked.push(key);
            next = restarted.upper_bound_lazy(&key);
        }

        assert_eq!(walked.as_slice(), &keys);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_insert_does_not_clobber_unresolved_backend_subtree() {
        use crate::ledger::node_store::NuDBNodeStore;

        let dir = std::env::temp_dir().join("shamap_lazy_insert_collision_test");
        let _ = std::fs::remove_dir_all(&dir);
        let backend = Arc::new(NuDBNodeStore::open(&dir).unwrap());

        let key_a = Key::from_hex("14AB592D44C3EDD8000000000000000000000000000000000000000000000000").unwrap();
        let key_b = Key::from_hex("14E7C937CDA3190A000000000000000000000000000000000000000000000000").unwrap();

        let mut original = SHAMap::with_backend(MapType::AccountState, backend.clone());
        assert!(original.insert(key_a, b"account-a".to_vec()));
        original.flush_dirty().unwrap();
        let root_hash = original.root_hash();

        let mut restarted = SHAMap::with_backend(MapType::AccountState, backend.clone());
        assert!(restarted.load_root_from_hash(root_hash).unwrap());

        assert!(restarted.insert(key_b, b"account-b".to_vec()));
        assert_eq!(restarted.get(&key_a), Some(b"account-a".to_vec()));
        assert_eq!(restarted.get(&key_b), Some(b"account-b".to_vec()));

        std::fs::remove_dir_all(&dir).ok();
    }

    fn assert_map_matches_entries(
        actual: &mut SHAMap,
        expected_entries: &std::collections::BTreeMap<Key, Vec<u8>>,
        label: &str,
    ) {
        let mut expected = SHAMap::new_state();
        for (key, value) in expected_entries {
            expected.insert(*key, value.clone());
        }

        assert_eq!(
            actual.len(),
            expected_entries.len(),
            "{label}: item count must match expected entries",
        );
        assert_eq!(
            actual.root_hash(),
            expected.root_hash(),
            "{label}: backend-backed mutations must preserve canonical SHAMap root",
        );

        for (key, value) in expected_entries {
            assert_eq!(
                actual.get(key),
                Some(value.clone()),
                "{label}: expected key {} should resolve to the canonical value",
                key.to_hex(),
            );
        }
    }

    #[test]
    fn test_backend_snapshot_mutations_match_fresh_map() {
        use crate::ledger::node_store::MemNodeStore;

        let backend = Arc::new(MemNodeStore::new());

        let initial = [
            (key2(0x10, 0x00), b"a0".to_vec()),
            (key2(0x10, 0x10), b"a1".to_vec()),
            (key2(0x11, 0x00), b"b0".to_vec()),
            (key2(0x11, 0x10), b"b1".to_vec()),
            (key2(0x12, 0x00), b"c0".to_vec()),
            (key2(0x20, 0x00), b"d0".to_vec()),
        ];

        let mut seeded = SHAMap::with_backend(MapType::AccountState, backend.clone());
        let mut expected_entries = std::collections::BTreeMap::new();
        for (key, value) in initial {
            seeded.insert(key, value.clone());
            expected_entries.insert(key, value);
        }
        let root_hash = seeded.root_hash();
        seeded.flush_dirty().unwrap();

        let mut restarted = SHAMap::with_backend(MapType::AccountState, backend);
        assert!(restarted.load_root_from_hash(root_hash).unwrap());
        restarted.count = expected_entries.len();
        let mut snapshot = restarted.snapshot();

        assert_map_matches_entries(&mut snapshot, &expected_entries, "initial snapshot");

        let insert_1020 = key2(0x10, 0x20);
        snapshot.insert(key2(0x10, 0x00), b"a0-updated".to_vec());
        expected_entries.insert(key2(0x10, 0x00), b"a0-updated".to_vec());
        assert_map_matches_entries(&mut snapshot, &expected_entries, "after update a0");

        assert!(snapshot.remove(&key2(0x10, 0x10)));
        expected_entries.remove(&key2(0x10, 0x10));
        assert_map_matches_entries(&mut snapshot, &expected_entries, "after remove a1");

        snapshot.insert(insert_1020, b"a2".to_vec());
        expected_entries.insert(insert_1020, b"a2".to_vec());
        assert_map_matches_entries(&mut snapshot, &expected_entries, "after insert a2");

        assert!(snapshot.remove(&key2(0x11, 0x10)));
        expected_entries.remove(&key2(0x11, 0x10));
        assert_map_matches_entries(&mut snapshot, &expected_entries, "after remove b1");

        assert!(snapshot.remove(&key2(0x11, 0x00)));
        expected_entries.remove(&key2(0x11, 0x00));
        assert_map_matches_entries(&mut snapshot, &expected_entries, "after remove b0");

        snapshot.insert(key2(0x11, 0x20), b"b2".to_vec());
        expected_entries.insert(key2(0x11, 0x20), b"b2".to_vec());
        assert_map_matches_entries(&mut snapshot, &expected_entries, "after insert b2");

        assert!(snapshot.remove(&key2(0x10, 0x00)));
        expected_entries.remove(&key2(0x10, 0x00));
        assert_map_matches_entries(&mut snapshot, &expected_entries, "after remove a0");

        snapshot.insert(key2(0x20, 0x00), b"d0-updated".to_vec());
        expected_entries.insert(key2(0x20, 0x00), b"d0-updated".to_vec());
        assert_map_matches_entries(&mut snapshot, &expected_entries, "after update d0");

        assert!(snapshot.remove(&key2(0x12, 0x00)));
        expected_entries.remove(&key2(0x12, 0x00));
        assert_map_matches_entries(&mut snapshot, &expected_entries, "after remove c0");
    }

    #[test]
    fn test_remove_prunes_empty_backend_inner_branch() {
        use crate::ledger::node_store::MemNodeStore;

        let backend = Arc::new(MemNodeStore::new());

        let branch_a0 = key2(0x10, 0x00);
        let branch_a1 = key2(0x10, 0x10);
        let sibling = key2(0x20, 0x00);

        let mut seeded = SHAMap::with_backend(MapType::AccountState, backend.clone());
        seeded.insert(branch_a0, b"a0".to_vec());
        seeded.insert(branch_a1, b"a1".to_vec());
        seeded.insert(sibling, b"sibling".to_vec());
        let root_hash = seeded.root_hash();
        seeded.flush_dirty().unwrap();

        let mut restarted = SHAMap::with_backend(MapType::AccountState, backend);
        assert!(restarted.load_root_from_hash(root_hash).unwrap());
        restarted.count = 3;

        assert!(restarted.remove(&branch_a0));
        assert!(restarted.remove(&branch_a1));

        let mut expected = SHAMap::new_state();
        expected.insert(sibling, b"sibling".to_vec());

        assert_eq!(
            restarted.root_hash(),
            expected.root_hash(),
            "deleting the final leaves beneath a backend-backed inner branch must prune the empty branch",
        );
        assert_eq!(restarted.get(&branch_a0), None);
        assert_eq!(restarted.get(&branch_a1), None);
        assert_eq!(restarted.get(&sibling), Some(b"sibling".to_vec()));
    }

    #[test]
    fn test_remove_collapses_single_remaining_backend_inner_chain() {
        use crate::ledger::node_store::MemNodeStore;

        let backend = Arc::new(MemNodeStore::new());

        let deep_a = Key::from_hex(
            "1111100000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let deep_b = Key::from_hex(
            "1111200000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let sibling = Key::from_hex(
            "2000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let mut seeded = SHAMap::with_backend(MapType::AccountState, backend.clone());
        seeded.insert(deep_a, b"deep-a".to_vec());
        seeded.insert(deep_b, b"deep-b".to_vec());
        seeded.insert(sibling, b"sibling".to_vec());
        let root_hash = seeded.root_hash();
        seeded.flush_dirty().unwrap();

        let mut restarted = SHAMap::with_backend(MapType::AccountState, backend);
        assert!(restarted.load_root_from_hash(root_hash).unwrap());
        restarted.count = 3;

        assert!(restarted.remove(&deep_b));

        let mut expected = SHAMap::new_state();
        expected.insert(deep_a, b"deep-a".to_vec());
        expected.insert(sibling, b"sibling".to_vec());

        assert_eq!(
            restarted.root_hash(),
            expected.root_hash(),
            "deleting one of two deep-prefix siblings must collapse the surviving inner chain canonically",
        );
        assert_eq!(restarted.get(&deep_a), Some(b"deep-a".to_vec()));
        assert_eq!(restarted.get(&deep_b), None);
        assert_eq!(restarted.get(&sibling), Some(b"sibling".to_vec()));
    }

    #[test]
    fn test_remove_keeps_shared_prefix_inner_when_survivors_still_branch() {
        use crate::ledger::node_store::MemNodeStore;

        let backend = Arc::new(MemNodeStore::new());

        let doomed = Key::from_hex(
            "C1982E87F97F45AC54171A28A0B6EFE4C8B8FFFEB68CDB9FF596AB6EF5347FC2",
        )
        .unwrap();
        let survivor_a = Key::from_hex(
            "C983A10F71A7C5CA46369F106060ABEAA2B49D2FB077B07A7E7C1152D93DE241",
        )
        .unwrap();
        let survivor_b = Key::from_hex(
            "C9CAFB2F3644B459A7CCB49AF8ED40C7008C907DA056DAAA13334AD3DBAB010F",
        )
        .unwrap();

        let mut seeded = SHAMap::with_backend(MapType::AccountState, backend.clone());
        seeded.insert(doomed, b"doomed".to_vec());
        seeded.insert(survivor_a, b"survivor-a".to_vec());
        seeded.insert(survivor_b, b"survivor-b".to_vec());
        let root_hash = seeded.root_hash();
        seeded.flush_dirty().unwrap();

        let mut restarted = SHAMap::with_backend(MapType::AccountState, backend);
        assert!(restarted.load_root_from_hash(root_hash).unwrap());
        restarted.count = 3;

        assert!(restarted.remove(&doomed));

        let mut expected = SHAMap::new_state();
        expected.insert(survivor_a, b"survivor-a".to_vec());
        expected.insert(survivor_b, b"survivor-b".to_vec());

        assert_eq!(
            restarted.root_hash(),
            expected.root_hash(),
            "deleting a sibling must not hoist a surviving branched inner node to the wrong depth",
        );
        assert_eq!(restarted.get(&doomed), None);
        assert_eq!(restarted.get(&survivor_a), Some(b"survivor-a".to_vec()));
        assert_eq!(restarted.get(&survivor_b), Some(b"survivor-b".to_vec()));
    }

    fn next_rand(state: &mut u64) -> u64 {
        // Deterministic xorshift64* for reproducible mutation traces.
        let mut x = *state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn rand_key(state: &mut u64) -> Key {
        let mut k = [0u8; 32];
        for chunk in k.chunks_mut(8) {
            chunk.copy_from_slice(&next_rand(state).to_be_bytes());
        }
        Key(k)
    }

    #[test]
    fn test_backend_snapshot_randomized_mutations_match_fresh_map() {
        use crate::ledger::node_store::MemNodeStore;

        for seed in 0u64..16 {
            let backend = Arc::new(MemNodeStore::new());
            let mut rng = 0x9E37_79B9_7F4A_7C15u64 ^ seed;
            let mut trace = Vec::new();

            let mut seeded = SHAMap::with_backend(MapType::AccountState, backend.clone());
            let mut expected_entries = std::collections::BTreeMap::new();
            let mut known_keys = Vec::new();

            while expected_entries.len() < 48 {
                let key = rand_key(&mut rng);
                if expected_entries.contains_key(&key) {
                    continue;
                }
                let value = next_rand(&mut rng).to_be_bytes().repeat(3);
                seeded.insert(key, value.clone());
                expected_entries.insert(key, value);
                known_keys.push(key);
            }

            let root_hash = seeded.root_hash();
            seeded.flush_dirty().unwrap();

            let mut restarted = SHAMap::with_backend(MapType::AccountState, backend);
            assert!(
                restarted.load_root_from_hash(root_hash).unwrap(),
                "seed {seed}: backend root should reload",
            );
            restarted.count = expected_entries.len();
            let mut snapshot = restarted.snapshot();

            for step in 0..256 {
                let op = (next_rand(&mut rng) % 3) as u8;
                let mut focus_key: Option<Key> = None;
                match op {
                    0 => {
                        let key = known_keys[(next_rand(&mut rng) as usize) % known_keys.len()];
                        let value = next_rand(&mut rng).to_be_bytes().repeat(2);
                        snapshot.insert(key, value.clone());
                        expected_entries.insert(key, value);
                        trace.push(format!("step {step}: update {}", key.to_hex()));
                        focus_key = Some(key);
                    }
                    1 => {
                        let mut key = rand_key(&mut rng);
                        while expected_entries.contains_key(&key) {
                            key = rand_key(&mut rng);
                        }
                        let value = next_rand(&mut rng).to_be_bytes().repeat(4);
                        snapshot.insert(key, value.clone());
                        expected_entries.insert(key, value);
                        known_keys.push(key);
                        trace.push(format!("step {step}: insert {}", key.to_hex()));
                        focus_key = Some(key);
                    }
                    _ => {
                        if expected_entries.is_empty() {
                            continue;
                        }
                        let key = known_keys[(next_rand(&mut rng) as usize) % known_keys.len()];
                        if expected_entries.remove(&key).is_some() {
                            assert!(
                                snapshot.remove(&key),
                                "seed {seed} step {step}: delete should succeed for existing key {}",
                                key.to_hex(),
                            );
                            trace.push(format!("step {step}: delete {}", key.to_hex()));
                            focus_key = Some(key);
                        }
                    }
                }

                let mut expected = SHAMap::new_state();
                for (key, value) in &expected_entries {
                    expected.insert(*key, value.clone());
                }

                let prefix_debug = focus_key.map(|key| {
                    let nibble0 = key.nibble(0);
                    let related: Vec<String> = expected_entries
                        .keys()
                        .filter(|k| k.nibble(0) == nibble0)
                        .map(|k| k.to_hex())
                        .collect();
                    format!(
                        "focus_key={} first_nibble={} related_keys={:?}",
                        key.to_hex(),
                        nibble0,
                        related,
                    )
                }).unwrap_or_default();
                assert_eq!(
                    snapshot.root_hash(),
                    expected.root_hash(),
                    "seed {seed} step {step}: randomized backend snapshot mutations diverged from canonical root\n{}\ntrace:\n{}",
                    prefix_debug,
                    trace.join("\n"),
                );
            }
        }
    }

    #[test]
    fn test_get_wire_node_by_id_serves_root_and_leaf() {
        let mut map = SHAMap::new_state();
        let key_a = key(0xA0);
        let key_b = key(0xB0);
        map.insert(key_a, b"alpha".to_vec());
        map.insert(key_b, b"beta".to_vec());

        let root_wire = map.get_wire_node_by_id(&SHAMapNodeID::root()).unwrap();
        assert_eq!(root_wire.len(), 16 * 32 + 1);
        assert_eq!(root_wire.last().copied(), Some(WIRE_TYPE_INNER));

        let leaf_wire = map.get_wire_node_by_id(&SHAMapNodeID::from_key(&key_a.0)).unwrap();
        assert_eq!(leaf_wire.last().copied(), Some(WIRE_TYPE_ACCOUNT_STATE));
        assert_eq!(&leaf_wire[..5], b"alpha");
        assert_eq!(&leaf_wire[5..37], &key_a.0);
    }

    #[test]
    fn test_get_wire_nodes_for_query_depth_includes_descendants() {
        let mut map = SHAMap::new_state();
        let key_a = key(0x10);
        let key_b = key(0x11);
        let key_c = key(0x20);
        map.insert(key_a, b"alpha".to_vec());
        map.insert(key_b, b"beta".to_vec());
        map.insert(key_c, b"gamma".to_vec());

        let nodes = map.get_wire_nodes_for_query(&SHAMapNodeID::root(), 1);
        assert_eq!(nodes.len(), 3);

        let root = nodes.iter().find(|(id, _)| id[32] == 0).expect("root node");
        assert_eq!(root.1.last().copied(), Some(WIRE_TYPE_INNER));

        let branch_one = nodes
            .iter()
            .find(|(id, _)| SHAMapNodeID::from_wire(id).map(|nid| nid.depth() == 1 && nid.id()[0] == 0x10).unwrap_or(false))
            .expect("branch-one child");
        assert_eq!(branch_one.1.last().copied(), Some(WIRE_TYPE_INNER));

        let branch_two = nodes
            .iter()
            .find(|(id, _)| SHAMapNodeID::from_wire(id).map(|nid| nid.depth() == 1 && nid.id()[0] == 0x20).unwrap_or(false))
            .expect("branch-two child");
        assert_eq!(branch_two.1.last().copied(), Some(WIRE_TYPE_ACCOUNT_STATE));
    }

    #[test]
    fn test_get_wire_nodes_for_query_preserves_full_leaf_request_id() {
        let mut map = SHAMap::new_state();
        let key_a = key(0xA0);
        let key_b = key(0xB0);
        map.insert(key_a, b"alpha".to_vec());
        map.insert(key_b, b"beta".to_vec());

        let target = SHAMapNodeID::from_key(&key_a.0);
        let nodes = map.get_wire_nodes_for_query(&target, 3);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].0, target.to_wire());
        assert_eq!(nodes[0].1.last().copied(), Some(WIRE_TYPE_ACCOUNT_STATE));
    }

    #[test]
    fn test_transaction_wire_nodes_use_transaction_leaf_type() {
        let mut map = SHAMap::new_transaction();
        let tx_key = key(0xCC);
        map.insert(tx_key, b"tx+meta".to_vec());

        let leaf_wire = map.get_wire_node_by_id(&SHAMapNodeID::from_key(&tx_key.0)).unwrap();
        assert_eq!(leaf_wire.last().copied(), Some(WIRE_TYPE_TRANSACTION));
    }
}
