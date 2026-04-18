//! SHAMap sync methods — addKnownNode + getMissingNodes.
//!
//! These implement the sync algorithm matching rippled's InboundLedger:
//! - addKnownNode: integrate a downloaded node into the tree
//! - `getMissingNodes`: walk the tree to find nodes still needed
//!
//! The tree is backed by NuDB for O(1) hash lookups. Inner nodes track
//! child hashes from wire data, enabling navigation even when children
//! haven't been downloaded yet.

use std::sync::Arc;

use crate::crypto::sha512_first_half;
use crate::ledger::full_below_cache::FullBelowCache;
use crate::ledger::node_store::NodeStore;
use crate::ledger::shamap::{PREFIX_INNER_NODE, PREFIX_LEAF_STATE, PREFIX_LEAF_TX};
use crate::ledger::shamap::{InnerNode, Key, LeafNode, MapType, Node};
use crate::ledger::shamap_id::SHAMapNodeID;

/// Result of adding a known node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddNodeResult {
    /// Node was new and successfully integrated.
    Useful,
    /// Node was already present.
    Duplicate,
    /// Node data was invalid (hash mismatch, wrong position, etc.)
    Invalid,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MissingNodesReport {
    pub missing: Vec<(SHAMapNodeID, [u8; 32])>,
    pub backend_fetch_errors: usize,
}

enum StoredNode {
    Inner(InnerNode),
    Leaf,
}

// ── Wire format constants ───────────────────────────────────────────────────

const WIRE_LEAF_ACCOUNT_STATE: u8 = 0x01;
const WIRE_INNER_FULL: u8 = 0x02;
const WIRE_INNER_COMPRESSED: u8 = 0x03;

// ── addKnownNode ────────────────────────────────────────────────────────────

/// Integrate a node received from a peer into the SHAMap.
pub(crate) fn add_known_node(
    root: &mut InnerNode,
    node_id: &SHAMapNodeID,
    raw_node: &[u8],
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
    full_below: &mut FullBelowCache,
) -> AddNodeResult {
    if raw_node.is_empty() {
        return AddNodeResult::Invalid;
    }

    // Parse wire type (last byte)
    let wire_type = raw_node[raw_node.len() - 1];
    let node_data = &raw_node[..raw_node.len() - 1];

    let generation = full_below.generation();

    // Special case: root node (depth 0)
    if node_id.is_root() {
        return add_root_node(root, node_data, wire_type, map_type, backend);
    }

    // Navigate from root toward node_id
    let mut current = root as *mut InnerNode;
    let mut current_id = SHAMapNodeID::root();

    while current_id.depth() < node_id.depth() {
        let inner = unsafe { &mut *current };

        if inner.is_full_below(generation) {
            return AddNodeResult::Duplicate;
        }

        let branch = current_id.select_branch(node_id);

        if !inner.has_branch(branch) {
            tracing::warn!("add_known_node: INVALID at has_branch depth={} branch={} is_branch={:#06x} node_id_depth={}",
                current_id.depth(), branch, inner.is_branch, node_id.depth());
            return AddNodeResult::Invalid;
        }

        let expected_hash = inner.child_hash(branch);

        if full_below.touch_if_exists(&expected_hash) {
            return AddNodeResult::Duplicate;
        }

        // Try to descend to child
        if current_id.depth() + 1 == node_id.depth() {
            // The traversal is at the parent, so insert the new node here.
            let new_node = parse_wire_node(node_data, wire_type, map_type);
            let new_node = match new_node {
                Some(n) => n,
                None => return AddNodeResult::Invalid,
            };

            // Verify hash matches parent's expected child hash
            let mut new_node = new_node;
            let computed_hash = new_node.hash(map_type);
            if computed_hash != expected_hash {
                tracing::warn!(
                    "add_known_node: INVALID hash mismatch depth={} computed={} expected={}",
                    node_id.depth(),
                    hex::encode_upper(&computed_hash[..8]),
                    hex::encode_upper(&expected_hash[..8])
                );
                return AddNodeResult::Invalid;
            }

            // Store inner nodes immediately so future tree walks can reload
            // intermediate structure from disk. Leaf writes are deferred to the
            // sync data processor and flushed in batches outside the sync lock.
            if let (Some(backend), Node::Inner(_)) = (backend, &new_node) {
                let store_data = serialize_for_store(&new_node, map_type);
                let _ = backend.store(&computed_hash, &store_data);
            }

            // Hook into parent's child array
            if inner.children[branch].is_some() {
                return AddNodeResult::Duplicate;
            }
            inner.children[branch] = Some(Box::new(new_node));
            inner.invalidate();
            return AddNodeResult::Useful;
        }

        // Descend deeper — need the child to be an inner node
        match &mut inner.children[branch] {
            Some(child) => match child.as_mut() {
                Node::Inner(child_inner) => {
                    current = child_inner as *mut InnerNode;
                    current_id = current_id.child_id(branch as u8);
                }
                _ => {
                    tracing::warn!(
                        "add_known_node: INVALID child not inner at depth={}",
                        current_id.depth()
                    );
                    return AddNodeResult::Invalid;
                }
            },
            None => {
                // Try loading from NuDB
                if let Some(ref backend) = backend {
                    if let Ok(Some(stored)) = backend.fetch(&expected_hash) {
                        if let Some(StoredNode::Inner(ci)) =
                            decode_validated_store_node(&expected_hash, &stored)
                        {
                            inner.children[branch] = Some(Box::new(Node::Inner(ci)));
                            if let Some(child) = &mut inner.children[branch] {
                                if let Node::Inner(ci) = child.as_mut() {
                                    current = ci as *mut InnerNode;
                                    current_id = current_id.child_id(branch as u8);
                                    continue;
                                }
                            }
                        }
                    }
                }
                tracing::warn!("add_known_node: INVALID can't load intermediate depth={} hash={} fetch_result={}",
                    current_id.depth(), hex::encode_upper(&expected_hash[..8]),
                    backend.as_ref().map_or("no_backend".to_string(), |be| {
                        match be.fetch(&expected_hash) {
                            Ok(Some(d)) => format!("found_{}bytes", d.len()),
                            Ok(None) => "not_found".to_string(),
                            Err(e) => format!("err:{}", e),
                        }
                    }));
                return AddNodeResult::Invalid;
            }
        }
    }

    AddNodeResult::Duplicate
}

/// Add the root node (depth 0).
fn add_root_node(
    root: &mut InnerNode,
    node_data: &[u8],
    wire_type: u8,
    _map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
) -> AddNodeResult {
    if wire_type != WIRE_INNER_FULL && wire_type != WIRE_INNER_COMPRESSED {
        return AddNodeResult::Invalid;
    }
    if root.is_branch != 0 {
        return AddNodeResult::Duplicate;
    }

    let hashes = parse_inner_hashes(node_data, wire_type);
    let hashes = match hashes {
        Some(h) => h,
        None => return AddNodeResult::Invalid,
    };

    for (i, hash) in hashes.iter().enumerate() {
        root.set_child_hash(i, *hash);
    }
    root.invalidate();

    // Store root in NuDB
    if let Some(backend) = backend {
        let mut store_data = Vec::with_capacity(16 * 32);
        for h in &hashes {
            store_data.extend_from_slice(h);
        }
        let content_hash = {
            let mut payload = Vec::with_capacity(4 + 16 * 32);
            payload.extend_from_slice(&PREFIX_INNER_NODE);
            payload.extend_from_slice(&store_data);
            sha512_first_half(&payload)
        };
        let _ = backend.store(&content_hash, &store_data);
    }

    AddNodeResult::Useful
}

// ── getMissingNodes (matching rippled's gmn_ProcessNodes exactly) ────────────

/// Find missing nodes by walking the tree and returning the hashes needed from peers.
/// Returns up to `max` entries of (SHAMapNodeID, content_hash).
///
/// Matches rippled's gmn_ProcessNodes algorithm:
/// - Iterative stack-based traversal (not recursive)
/// - Parent suspended on stack when descending into child
/// - fullBelow = fullBelow && was on unwind (parent only full if ALL children full)
/// - Only marks full_below when ALL descendants to leaf level verified
#[cfg(test)]
pub(crate) fn get_missing_nodes(
    root: &mut InnerNode,
    max: usize,
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
    full_below: &mut FullBelowCache,
) -> Vec<(SHAMapNodeID, [u8; 32])> {
    get_missing_nodes_report(root, max, map_type, backend, full_below).missing
}

/// Same traversal as `get_missing_nodes`, but also reports backend fetch faults
/// separately so callers can distinguish local storage problems from genuine
/// network-missing nodes.
pub(crate) fn get_missing_nodes_report(
    root: &mut InnerNode,
    max: usize,
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
    full_below: &mut FullBelowCache,
) -> MissingNodesReport {
    let generation = full_below.generation();
    let mut report = MissingNodesReport::default();
    let mut remaining = max;

    if root.is_branch == 0 {
        return report;
    }
    if root.is_full_below(generation) {
        return report;
    }

    // Current node being processed
    let mut node: *mut InnerNode = root as *mut InnerNode;
    let mut node_id = SHAMapNodeID::root();
    let mut first_child: usize = random_start_child();
    let mut current_child: usize = 0;
    let mut full_below_flag = true;

    // Stack: (node_ptr, node_id, first_child, next_child_to_process, full_below_flag)
    // When descending into a child, parent is pushed with current_child
    // pointing to the NEXT branch to process on resume.
    let mut stack: Vec<(*mut InnerNode, SHAMapNodeID, usize, usize, bool)> = Vec::new();

    loop {
        // Process children of current node
        while current_child < 16 {
            if remaining == 0 {
                break;
            }

            let branch = (first_child + current_child) % 16;
            current_child += 1;

            let inner = unsafe { &mut *node };
            if !inner.has_branch(branch) {
                continue;
            }

            let child_hash = inner.child_hash(branch);
            if child_hash == [0u8; 32] {
                continue;
            }

            // Already known complete in cache?
            if full_below.touch_if_exists(&child_hash) {
                continue;
            }

            let child_id = node_id.child_id(branch as u8);

            // Try to access the child — determine if it's present, missing, or needs descent
            let descend_target: Option<*mut InnerNode> = {
                match &mut inner.children[branch] {
                    Some(child) => match child.as_mut() {
                        Node::Inner(ci) => {
                            if ci.is_full_below(generation) {
                                None // Already verified complete
                            } else {
                                Some(ci as *mut InnerNode) // Descend
                            }
                        }
                        Node::Leaf(_) => None, // Present = complete
                        Node::Stub { content_hash, .. } => {
                            // Check if data exists in NuDB
                            if let Some(ref be) = backend {
                                match be.fetch(content_hash) {
                                    Ok(Some(stored)) => {
                                        if decode_validated_store_node(content_hash, &stored)
                                            .is_some()
                                        {
                                            full_below.insert(*content_hash);
                                        } else {
                                            tracing::warn!(
                                                "shamap sync cached stub failed typed decode for child {}",
                                                hex::encode_upper(&content_hash[..8]),
                                            );
                                            report.backend_fetch_errors += 1;
                                            report.missing.push((child_id, *content_hash));
                                            full_below_flag = false;
                                            remaining -= 1;
                                        }
                                    }
                                    Ok(None) => {
                                        report.missing.push((child_id, *content_hash));
                                        full_below_flag = false;
                                        remaining -= 1;
                                    }
                                    Err(err) => {
                                        tracing::warn!(
                                            "shamap sync fetch failed for stub {}: {}",
                                            hex::encode_upper(&content_hash[..8]),
                                            err
                                        );
                                        report.backend_fetch_errors += 1;
                                        full_below_flag = false;
                                    }
                                }
                            } else {
                                report.missing.push((child_id, *content_hash));
                                full_below_flag = false;
                                remaining -= 1;
                            }
                            None
                        }
                    },
                    None => {
                        // Not in memory — try NuDB
                        if let Some(ref be) = backend {
                            match be.fetch(&child_hash) {
                                Ok(Some(stored)) => {
                                    match decode_validated_store_node(&child_hash, &stored) {
                                        Some(StoredNode::Inner(ci)) => {
                                            inner.children[branch] =
                                                Some(Box::new(Node::Inner(ci)));
                                            // Now access the loaded node
                                            if let Some(child) = &mut inner.children[branch] {
                                                if let Node::Inner(loaded) = child.as_mut() {
                                                    if loaded.is_full_below(generation) {
                                                        None
                                                    } else {
                                                        Some(loaded as *mut InnerNode)
                                                    }
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        }
                                        Some(StoredNode::Leaf) => {
                                            // Valid typed leaf in NuDB = complete.
                                            full_below.insert(child_hash);
                                            None
                                        }
                                        None => {
                                            tracing::warn!(
                                                "shamap sync typed decode failed for child {}",
                                                hex::encode_upper(&child_hash[..8]),
                                            );
                                            report.backend_fetch_errors += 1;
                                            report.missing.push((child_id, child_hash));
                                            full_below_flag = false;
                                            remaining -= 1;
                                            None
                                        }
                                    }
                                }
                                Ok(None) => {
                                    // Not in NuDB = missing
                                    report.missing.push((child_id, child_hash));
                                    full_below_flag = false;
                                    remaining -= 1;
                                    None
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        "shamap sync fetch failed for child {}: {}",
                                        hex::encode_upper(&child_hash[..8]),
                                        err
                                    );
                                    report.backend_fetch_errors += 1;
                                    full_below_flag = false;
                                    None
                                }
                            }
                        } else {
                            report.missing.push((child_id, child_hash));
                            full_below_flag = false;
                            remaining -= 1;
                            None
                        }
                    }
                }
            };

            // If an inner child is available for descent, suspend the parent.
            if let Some(child_ptr) = descend_target {
                stack.push((node, node_id, first_child, current_child, full_below_flag));
                node = child_ptr;
                node_id = child_id;
                first_child = random_start_child();
                current_child = 0;
                full_below_flag = true; // Reset for child subtree
            }
        }

        // Finished all children of current node
        if full_below_flag {
            let inner = unsafe { &mut *node };
            inner.set_full_below(generation);
            let h = inner.hash(map_type);
            full_below.insert(h);
        }

        // Unwind: resume parent with AND logic
        if let Some((parent_ptr, parent_id, parent_first_child, parent_child, parent_full)) =
            stack.pop()
        {
            let child_was_full = full_below_flag;
            node = parent_ptr;
            node_id = parent_id;
            first_child = parent_first_child;
            current_child = parent_child;
            // Parent is full ONLY if parent was full AND child was full
            full_below_flag = parent_full && child_was_full;
        } else {
            break; // Stack empty
        }
    }

    report
}

fn random_start_child() -> usize {
    rand::random::<u8>() as usize
}

// ── Wire format parsing ──────────────────────────────────────────────────────

/// Parse 16 child hashes from inner node wire data.
fn parse_inner_hashes(data: &[u8], wire_type: u8) -> Option<[[u8; 32]; 16]> {
    match wire_type {
        WIRE_INNER_FULL => {
            // Full format: 16 × 32 bytes = 512 bytes
            if data.len() < 16 * 32 {
                return None;
            }
            let mut hashes = [[0u8; 32]; 16];
            for i in 0..16 {
                hashes[i].copy_from_slice(&data[i * 32..(i + 1) * 32]);
            }
            Some(hashes)
        }
        WIRE_INNER_COMPRESSED => {
            // Compressed format (matching rippled SHAMapInnerNode::serializeForWire):
            // N × [hash(32) + position(1)] — no bitmap, each entry is 33 bytes.
            let mut hashes = [[0u8; 32]; 16];
            let mut pos = 0;
            while pos + 33 <= data.len() {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[pos..pos + 32]);
                let branch = data[pos + 32] as usize;
                if branch >= 16 {
                    return None;
                }
                hashes[branch] = hash;
                pos += 33;
            }
            Some(hashes)
        }
        _ => None,
    }
}

/// Parse a node from wire format.
fn parse_wire_node(data: &[u8], wire_type: u8, _map_type: MapType) -> Option<Node> {
    match wire_type {
        WIRE_INNER_FULL | WIRE_INNER_COMPRESSED => {
            let hashes = parse_inner_hashes(data, wire_type)?;
            let mut inner = InnerNode::new();
            for (i, hash) in hashes.iter().enumerate() {
                inner.set_child_hash(i, *hash);
            }
            inner.dirty = false;
            Some(Node::Inner(inner))
        }
        WIRE_LEAF_ACCOUNT_STATE => {
            if data.len() <= 32 {
                return None;
            }
            let key_start = data.len() - 32;
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[key_start..]);
            let sle_data = data[..key_start].to_vec();
            Some(Node::Leaf(LeafNode {
                key: Key(key),
                data: sle_data,
                cached_hash: None,
                dirty: false,
            }))
        }
        _ => None,
    }
}

/// Serialize a node for NuDB storage.
fn serialize_for_store(node: &Node, _map_type: MapType) -> Vec<u8> {
    match node {
        Node::Inner(inner) => {
            let mut data = Vec::with_capacity(16 * 32);
            for hash in &inner.child_hashes {
                data.extend_from_slice(hash);
            }
            data
        }
        Node::Leaf(leaf) => {
            let mut data = Vec::with_capacity(leaf.data.len() + 32);
            data.extend_from_slice(&leaf.data);
            data.extend_from_slice(&leaf.key.0);
            data
        }
        Node::Stub { .. } => Vec::new(),
    }
}

/// Stash a wire-format SHAMap node into the content-addressed backend so a
/// later acquisition can reuse it, matching rippled's stale-data fetch-pack
/// behavior for liAS_NODE replies that arrive after an acquisition moved on.
pub(crate) fn prepare_wire_node_for_reuse(
    raw_node: &[u8],
    map_type: MapType,
) -> std::io::Result<Option<([u8; 32], Vec<u8>)>> {
    if raw_node.is_empty() {
        return Ok(None);
    }
    let wire_type = raw_node[raw_node.len() - 1];
    let node_data = &raw_node[..raw_node.len() - 1];
    let Some(mut node) = parse_wire_node(node_data, wire_type, map_type) else {
        return Ok(None);
    };
    let hash = node.hash(map_type);
    let store_data = serialize_for_store(&node, map_type);
    Ok(Some((hash, store_data)))
}

#[cfg(test)]
pub(crate) fn store_wire_node_for_reuse(
    backend: &Arc<dyn NodeStore>,
    raw_node: &[u8],
    map_type: MapType,
) -> std::io::Result<bool> {
    let Some((hash, store_data)) = prepare_wire_node_for_reuse(raw_node, map_type)? else {
        return Ok(false);
    };
    backend.store(&hash, &store_data)?;
    Ok(true)
}

/// Deserialize an inner node from NuDB stored format (16 × 32-byte child hashes).
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

fn decode_validated_store_node(expected_hash: &[u8; 32], data: &[u8]) -> Option<StoredNode> {
    if data.len() == 16 * 32 {
        let mut inner = deserialize_inner_from_store(data)?;
        let mut payload = Vec::with_capacity(PREFIX_INNER_NODE.len() + data.len());
        payload.extend_from_slice(&PREFIX_INNER_NODE);
        payload.extend_from_slice(data);
        let computed = sha512_first_half(&payload);
        if computed != *expected_hash {
            tracing::warn!(
                "shamap sync backend inner node hash mismatch: expected={} computed={}",
                hex::encode_upper(&expected_hash[..8]),
                hex::encode_upper(&computed[..8]),
            );
            return None;
        }
        inner.cached_hash = Some(computed);
        inner.dirty = false;
        return Some(StoredNode::Inner(inner));
    }

    if data.len() < 32 {
        tracing::warn!(
            "shamap sync backend object too short for typed decode: expected={} len={}",
            hex::encode_upper(&expected_hash[..8]),
            data.len(),
        );
        return None;
    }

    let mut stored_key = [0u8; 32];
    stored_key.copy_from_slice(&data[data.len() - 32..]);
    let key = Key(stored_key);
    let leaf_data = data[..data.len() - 32].to_vec();

    let state_leaf = build_validated_leaf(&key, &leaf_data, &PREFIX_LEAF_STATE, expected_hash);
    if state_leaf.is_some() {
        return Some(StoredNode::Leaf);
    }

    let tx_leaf = build_validated_leaf(&key, &leaf_data, &PREFIX_LEAF_TX, expected_hash);
    if tx_leaf.is_some() {
        return Some(StoredNode::Leaf);
    }

    let mut state_payload = Vec::with_capacity(PREFIX_LEAF_STATE.len() + leaf_data.len() + 32);
    state_payload.extend_from_slice(&PREFIX_LEAF_STATE);
    state_payload.extend_from_slice(&leaf_data);
    state_payload.extend_from_slice(&stored_key);
    let state_hash = sha512_first_half(&state_payload);

    let mut tx_payload = Vec::with_capacity(PREFIX_LEAF_TX.len() + leaf_data.len() + 32);
    tx_payload.extend_from_slice(&PREFIX_LEAF_TX);
    tx_payload.extend_from_slice(&leaf_data);
    tx_payload.extend_from_slice(&stored_key);
    let tx_hash = sha512_first_half(&tx_payload);

    tracing::warn!(
        "shamap sync backend leaf hash mismatch: expected={} state={} tx={}",
        hex::encode_upper(&expected_hash[..8]),
        hex::encode_upper(&state_hash[..8]),
        hex::encode_upper(&tx_hash[..8]),
    );
    None
}

fn build_validated_leaf(
    key: &Key,
    data: &[u8],
    prefix: &[u8; 4],
    expected_hash: &[u8; 32],
) -> Option<LeafNode> {
    let mut payload = Vec::with_capacity(prefix.len() + data.len() + 32);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(data);
    payload.extend_from_slice(&key.0);
    let computed = sha512_first_half(&payload);
    if computed != *expected_hash {
        return None;
    }

    Some(LeafNode {
        key: *key,
        data: data.to_vec(),
        cached_hash: Some(computed),
        dirty: false,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ledger::full_below_cache::FullBelowCache;
    use std::sync::Arc;

    fn make_leaf_wire(key: [u8; 32], data: &[u8]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(data.len() + 32 + 1);
        wire.extend_from_slice(data);
        wire.extend_from_slice(&key);
        wire.push(WIRE_LEAF_ACCOUNT_STATE);
        wire
    }

    fn make_inner_wire(hashes: &[[u8; 32]; 16]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(16 * 32 + 1);
        for h in hashes {
            wire.extend_from_slice(h);
        }
        wire.push(WIRE_INNER_FULL);
        wire
    }

    #[test]
    fn store_wire_node_for_reuse_roundtrips_leaf() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let key = [0xAB; 32];
        let data = b"stale leaf";
        let wire = make_leaf_wire(key, data);

        assert!(
            store_wire_node_for_reuse(&store, &wire, MapType::AccountState).unwrap(),
            "leaf should be stored for reuse"
        );

        let expected_hash = {
            let mut payload = Vec::with_capacity(4 + data.len() + 32);
            payload.extend_from_slice(&crate::ledger::shamap::PREFIX_LEAF_STATE);
            payload.extend_from_slice(data);
            payload.extend_from_slice(&key);
            crate::crypto::sha512_first_half(&payload)
        };
        let stored = store.fetch(&expected_hash).unwrap().expect("stored leaf");
        assert_eq!(&stored[..data.len()], data);
        assert_eq!(&stored[data.len()..], &key);
    }

    #[test]
    fn store_wire_node_for_reuse_roundtrips_inner() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut hashes = [[0u8; 32]; 16];
        hashes[3] = [0x33; 32];
        hashes[9] = [0x99; 32];
        let wire = make_inner_wire(&hashes);

        assert!(
            store_wire_node_for_reuse(&store, &wire, MapType::AccountState).unwrap(),
            "inner node should be stored for reuse"
        );

        let expected_hash = {
            let mut payload = Vec::with_capacity(4 + 16 * 32);
            payload.extend_from_slice(&crate::ledger::shamap::PREFIX_INNER_NODE);
            for hash in &hashes {
                payload.extend_from_slice(hash);
            }
            crate::crypto::sha512_first_half(&payload)
        };
        let stored = store.fetch(&expected_hash).unwrap().expect("stored inner");
        assert_eq!(stored.len(), 16 * 32);
        assert_eq!(&stored[3 * 32..4 * 32], &[0x33; 32]);
        assert_eq!(&stored[9 * 32..10 * 32], &[0x99; 32]);
    }

    #[test]
    fn add_root_node_works() {
        let mut root = InnerNode::new();
        let mut hashes = [[0u8; 32]; 16];
        hashes[0] = [0xAA; 32];
        hashes[5] = [0xBB; 32];
        let wire = make_inner_wire(&hashes);
        let root_id = SHAMapNodeID::root();
        let mut fb = FullBelowCache::new(1000);

        let result = add_known_node(
            &mut root,
            &root_id,
            &wire,
            MapType::AccountState,
            None,
            &mut fb,
        );
        assert_eq!(result, AddNodeResult::Useful);
        assert!(root.has_branch(0));
        assert!(root.has_branch(5));
        assert!(!root.has_branch(1));
    }

    #[test]
    fn add_child_node_works() {
        let mut root = InnerNode::new();
        let mut fb = FullBelowCache::new(1000);

        // Add root with one child hash at branch 0xA
        let mut root_hashes = [[0u8; 32]; 16];
        let leaf_key = [0xA0; 32]; // nibble 0 = 0xA
        let leaf_data = b"test leaf data";
        let leaf_wire = make_leaf_wire(leaf_key, leaf_data);
        let leaf_node = parse_wire_node(
            &leaf_wire[..leaf_wire.len() - 1],
            WIRE_LEAF_ACCOUNT_STATE,
            MapType::AccountState,
        )
        .unwrap();
        let mut leaf_node_clone = leaf_node;
        let leaf_hash = leaf_node_clone.hash(MapType::AccountState);
        root_hashes[0xA] = leaf_hash;

        let root_wire = make_inner_wire(&root_hashes);
        let root_id = SHAMapNodeID::root();
        add_known_node(
            &mut root,
            &root_id,
            &root_wire,
            MapType::AccountState,
            None,
            &mut fb,
        );

        // Now add the leaf at depth 1, branch 0xA
        let leaf_id = root_id.child_id(0xA);
        let result = add_known_node(
            &mut root,
            &leaf_id,
            &leaf_wire,
            MapType::AccountState,
            None,
            &mut fb,
        );
        assert_eq!(result, AddNodeResult::Useful);
        assert!(root.children[0xA].is_some());
    }

    #[test]
    fn add_leaf_defers_backend_store_until_batch_flush() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut root = InnerNode::new();
        let mut fb = FullBelowCache::new(1000);

        let mut root_hashes = [[0u8; 32]; 16];
        let leaf_key = [0xB0; 32];
        let leaf_data = b"batched leaf";
        let leaf_wire = make_leaf_wire(leaf_key, leaf_data);
        let leaf_node = parse_wire_node(
            &leaf_wire[..leaf_wire.len() - 1],
            WIRE_LEAF_ACCOUNT_STATE,
            MapType::AccountState,
        )
        .unwrap();
        let mut leaf_node_clone = leaf_node;
        let leaf_hash = leaf_node_clone.hash(MapType::AccountState);
        root_hashes[0xB] = leaf_hash;

        let root_wire = make_inner_wire(&root_hashes);
        add_known_node(
            &mut root,
            &SHAMapNodeID::root(),
            &root_wire,
            MapType::AccountState,
            Some(&store),
            &mut fb,
        );

        let leaf_id = SHAMapNodeID::root().child_id(0xB);
        let result = add_known_node(
            &mut root,
            &leaf_id,
            &leaf_wire,
            MapType::AccountState,
            Some(&store),
            &mut fb,
        );
        assert_eq!(result, AddNodeResult::Useful);
        assert!(
            store.fetch(&leaf_hash).unwrap().is_none(),
            "leaf persistence should be deferred out of add_known_node"
        );
    }

    #[test]
    fn get_missing_finds_gaps() {
        let mut root = InnerNode::new();
        let mut fb = FullBelowCache::new(1000);

        // Set up root with 2 child hashes but no children loaded
        root.set_child_hash(3, [0x33; 32]);
        root.set_child_hash(7, [0x77; 32]);

        let missing = get_missing_nodes(&mut root, 256, MapType::AccountState, None, &mut fb);
        assert_eq!(missing.len(), 2);
    }

    #[test]
    fn get_missing_skips_full_below() {
        let mut root = InnerNode::new();
        let mut fb = FullBelowCache::new(1000);

        root.set_child_hash(0, [0x11; 32]);
        root.set_child_hash(1, [0x22; 32]);

        // Mark child 0 as full_below
        fb.insert([0x11; 32]);

        let missing = get_missing_nodes(&mut root, 256, MapType::AccountState, None, &mut fb);
        // Only child 1 should be missing
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].1, [0x22; 32]);
    }

    struct ErrorStore;

    impl NodeStore for ErrorStore {
        fn store(&self, _hash: &[u8; 32], _data: &[u8]) -> std::io::Result<()> {
            Ok(())
        }

        fn fetch(&self, _hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
            Err(std::io::Error::other("forced backend fault"))
        }
    }

    #[test]
    fn get_missing_reports_backend_fetch_faults_separately() {
        let store: Arc<dyn NodeStore> = Arc::new(ErrorStore);
        let mut root = InnerNode::new();
        let mut fb = FullBelowCache::new(1000);
        root.set_child_hash(4, [0x44; 32]);

        let report =
            get_missing_nodes_report(&mut root, 256, MapType::AccountState, Some(&store), &mut fb);
        assert!(report.missing.is_empty());
        assert_eq!(report.backend_fetch_errors, 1);
    }

    #[test]
    fn get_missing_reports_corrupt_backend_rows_as_missing_and_faults() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut root = InnerNode::new();
        let mut fb = FullBelowCache::new(1000);
        let expected_hash = [0x55; 32];
        root.set_child_hash(5, expected_hash);

        store
            .store(&expected_hash, &vec![0u8; 16 * 32])
            .expect("store corrupt row");

        let report =
            get_missing_nodes_report(&mut root, 256, MapType::AccountState, Some(&store), &mut fb);
        assert_eq!(report.missing.len(), 1);
        assert_eq!(report.missing[0].1, expected_hash);
        assert_eq!(report.backend_fetch_errors, 1);
    }

    #[test]
    fn corrupt_cached_stub_is_rerequested_from_the_network() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut root = InnerNode::new();
        let mut fb = FullBelowCache::new(1000);

        let key = [0xAB; 32];
        let leaf_data = b"leaf";
        let wire = make_leaf_wire(key, leaf_data);
        let Some((expected_hash, mut store_data)) =
            prepare_wire_node_for_reuse(&wire, MapType::AccountState).unwrap()
        else {
            panic!("expected reusable wire node");
        };
        store_data[0] ^= 0xFF;
        store.store(&expected_hash, &store_data).expect("store corrupt row");

        root.children[2] = Some(Box::new(Node::Stub {
            key: Key(key),
            content_hash: expected_hash,
        }));
        root.set_child_hash(2, expected_hash);

        let report =
            get_missing_nodes_report(&mut root, 256, MapType::AccountState, Some(&store), &mut fb);
        assert_eq!(report.missing.len(), 1);
        assert_eq!(report.missing[0].1, expected_hash);
        assert_eq!(report.backend_fetch_errors, 1);
    }
}
