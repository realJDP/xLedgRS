//! SHAMap sync methods — addKnownNode + getMissingNodes.
//!
//! These implement the sync algorithm matching rippled's InboundLedger:
//! - addKnownNode: integrate a downloaded node into the tree
//! - `getMissingNodes`: walk the tree to find nodes still needed
//!
//! The tree is backed by NuDB for O(1) hash lookups. Inner nodes track
//! child hashes from wire data, enabling navigation even when children
//! haven't been downloaded yet.

use std::collections::HashMap;
use std::sync::Arc;

use crate::crypto::sha512_first_half;
use crate::ledger::full_below_cache::FullBelowCache;
use crate::ledger::node_store::NodeStore;
use crate::ledger::shamap::{InnerNode, Key, LeafNode, MapType, Node};
use crate::ledger::shamap::{PREFIX_INNER_NODE, PREFIX_LEAF_STATE, PREFIX_LEAF_TX};
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
    pub budget_hint: Option<(SHAMapNodeID, [u8; 32])>,
    pub backend_fetch_errors: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeferredBackendReadKind {
    Child,
    Stub,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeferredBackendRead {
    pub node_id: SHAMapNodeID,
    pub hash: [u8; 32],
    pub kind: DeferredBackendReadKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DeferredMissingNodesReport {
    pub report: MissingNodesReport,
    pub deferred_reads: Vec<DeferredBackendRead>,
}

struct DeferredReadQueue {
    capacity: usize,
    reads: Vec<DeferredBackendRead>,
}

impl DeferredReadQueue {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            reads: Vec::new(),
        }
    }

    fn is_full(&self) -> bool {
        self.reads.len() >= self.capacity
    }

    fn push(&mut self, read: DeferredBackendRead) -> bool {
        if self.is_full() {
            return false;
        }
        self.reads.push(read);
        true
    }

    fn into_vec(self) -> Vec<DeferredBackendRead> {
        self.reads
    }
}

enum StoredNode {
    Inner(InnerNode),
    Leaf,
}

// ── Wire format constants ───────────────────────────────────────────────────

const WIRE_LEAF_ACCOUNT_STATE: u8 = 0x01;
const WIRE_LEAF_TRANSACTION: u8 = 0x00;
const WIRE_LEAF_TRANSACTION_WITH_META: u8 = 0x04;
const WIRE_INNER_FULL: u8 = 0x02;
const WIRE_INNER_COMPRESSED: u8 = 0x03;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CandidateTxSetWireImport {
    Complete(Vec<Vec<u8>>),
    Incomplete { missing: Vec<SHAMapNodeID> },
    Invalid(CandidateTxSetWireError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateTxSetWireError {
    Empty,
    MalformedNode,
    RootHashMismatch,
    NodeHashMismatch,
    CandidateHashMismatch,
}

#[derive(Default)]
pub(crate) struct CandidateTxSetWireAccumulator {
    nodes: HashMap<SHAMapNodeID, Vec<u8>>,
}

impl CandidateTxSetWireAccumulator {
    pub(crate) fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.nodes.len()
    }
}

#[derive(Clone)]
enum CandidateTxSetNode {
    Inner {
        children: [Option<Box<CandidateTxSetNode>>; 16],
        cached_hash: Option<[u8; 32]>,
    },
    Leaf {
        tx_id: [u8; 32],
        blob: Vec<u8>,
    },
}

#[derive(Clone)]
enum ParsedCandidateWireNode {
    Inner {
        child_hashes: [[u8; 32]; 16],
        hash: [u8; 32],
    },
    Leaf {
        tx_id: [u8; 32],
        blob: Vec<u8>,
    },
}

impl CandidateTxSetNode {
    fn new_inner() -> Self {
        Self::Inner {
            children: Default::default(),
            cached_hash: None,
        }
    }

    fn hash(&mut self) -> [u8; 32] {
        match self {
            Self::Leaf { tx_id, .. } => *tx_id,
            Self::Inner {
                children,
                cached_hash,
            } => {
                if let Some(hash) = *cached_hash {
                    return hash;
                }
                let mut payload = Vec::with_capacity(PREFIX_INNER_NODE.len() + 16 * 32);
                payload.extend_from_slice(&PREFIX_INNER_NODE);
                for child in children {
                    let child_hash = child.as_mut().map_or([0u8; 32], |child| child.hash());
                    payload.extend_from_slice(&child_hash);
                }
                let hash = sha512_first_half(&payload);
                *cached_hash = Some(hash);
                hash
            }
        }
    }

    fn branch_count(&self) -> usize {
        match self {
            Self::Inner { children, .. } => children.iter().filter(|child| child.is_some()).count(),
            Self::Leaf { .. } => 0,
        }
    }

    fn serialize_wire(&mut self) -> Vec<u8> {
        match self {
            Self::Leaf { blob, .. } => {
                let mut wire = Vec::with_capacity(blob.len() + 1);
                wire.extend_from_slice(blob);
                wire.push(WIRE_LEAF_TRANSACTION);
                wire
            }
            Self::Inner { children, .. } => {
                let mut wire = Vec::with_capacity(16 * 32 + 1);
                for child in children {
                    let child_hash = child.as_mut().map_or([0u8; 32], |child| child.hash());
                    wire.extend_from_slice(&child_hash);
                }
                wire.push(WIRE_INNER_FULL);
                wire
            }
        }
    }
}

impl ParsedCandidateWireNode {
    fn hash(&self) -> [u8; 32] {
        match self {
            Self::Inner { hash, .. } => *hash,
            Self::Leaf { tx_id, .. } => *tx_id,
        }
    }
}

/// Build rippled-compatible wire nodes for a consensus tx-set SHAMap.
///
/// Candidate leaves are serialized as `raw_tx_blob || 0x00`; their content hash
/// is the transaction ID itself. This is intentionally separate from the
/// ledger transaction SHAMap, whose leaves carry metadata.
pub(crate) fn build_candidate_tx_set_wire_nodes<'a>(
    blobs: impl IntoIterator<Item = &'a [u8]>,
    node_ids: &[SHAMapNodeID],
    query_depth: u32,
) -> (Vec<(SHAMapNodeID, Vec<u8>)>, [u8; 32]) {
    let mut root = CandidateTxSetNode::new_inner();
    let mut inserted = 0usize;
    for blob in blobs {
        let tx_id = crate::transaction::serialize::tx_blob_hash(blob);
        if insert_candidate_tx_set_leaf(&mut root, tx_id, blob.to_vec(), 0) {
            inserted += 1;
        }
    }
    let root_hash = if inserted == 0 {
        [0u8; 32]
    } else {
        root.hash()
    };
    let mut out = Vec::new();
    for node_id in node_ids {
        if let Some((node, actual_id)) = find_candidate_tx_set_node(&mut root, node_id) {
            collect_candidate_tx_set_fat_nodes(node, actual_id, query_depth, false, &mut out);
        }
    }
    (out, root_hash)
}

/// Import a batch of rippled-compatible candidate SHAMap wire nodes.
///
/// Returns `Incomplete` when the batch only advances acquisition and identifies
/// child node IDs to request next, matching rippled TransactionAcquire's
/// root/inner first, leaves later flow.
pub(crate) fn import_candidate_tx_set_wire_nodes<'a>(
    expected_hash: [u8; 32],
    nodes: impl IntoIterator<Item = (SHAMapNodeID, &'a [u8])>,
) -> CandidateTxSetWireImport {
    let mut parsed = HashMap::new();
    for (node_id, raw_node) in nodes {
        let Some(node) = parse_candidate_wire_node(&node_id, raw_node) else {
            return CandidateTxSetWireImport::Invalid(CandidateTxSetWireError::MalformedNode);
        };
        parsed.insert(node_id, node);
    }

    if parsed.is_empty() {
        return CandidateTxSetWireImport::Invalid(CandidateTxSetWireError::Empty);
    }

    if let Some(root) = parsed.get(&SHAMapNodeID::root()) {
        if root.hash() != expected_hash {
            return CandidateTxSetWireImport::Invalid(CandidateTxSetWireError::RootHashMismatch);
        }
        let mut blobs = Vec::new();
        let mut missing = Vec::new();
        if let Err(err) = walk_candidate_wire_tree(
            SHAMapNodeID::root(),
            expected_hash,
            &parsed,
            &mut blobs,
            &mut missing,
        ) {
            return CandidateTxSetWireImport::Invalid(err);
        }
        if !missing.is_empty() {
            missing.sort_by(|a, b| a.to_wire().cmp(&b.to_wire()));
            missing.dedup();
            return CandidateTxSetWireImport::Incomplete { missing };
        }
        return complete_candidate_wire_import(expected_hash, blobs);
    }

    let blobs = parsed
        .values()
        .filter_map(|node| match node {
            ParsedCandidateWireNode::Leaf { blob, .. } => Some(blob.clone()),
            ParsedCandidateWireNode::Inner { .. } => None,
        })
        .collect::<Vec<_>>();
    if blobs.is_empty() {
        let mut missing = Vec::new();
        for (node_id, node) in &parsed {
            collect_candidate_child_requests(*node_id, node, &mut missing);
        }
        if missing.is_empty() {
            CandidateTxSetWireImport::Invalid(CandidateTxSetWireError::MalformedNode)
        } else {
            missing.sort_by(|a, b| a.to_wire().cmp(&b.to_wire()));
            missing.dedup();
            CandidateTxSetWireImport::Incomplete { missing }
        }
    } else {
        complete_candidate_wire_import(expected_hash, blobs)
    }
}

/// Merge a response batch into an in-progress candidate tx-set acquisition.
///
/// Peers may split root/inner and leaf responses across multiple
/// liTS_CANDIDATE batches.  This cache keeps verified wire nodes by SHAMap node
/// ID so each new batch can be validated against the accumulated tree.
pub(crate) fn import_candidate_tx_set_wire_nodes_accumulated<'a>(
    expected_hash: [u8; 32],
    accumulator: &mut CandidateTxSetWireAccumulator,
    nodes: impl IntoIterator<Item = (SHAMapNodeID, &'a [u8])>,
) -> CandidateTxSetWireImport {
    let mut staged = accumulator.nodes.clone();
    let mut saw_node = false;
    for (node_id, raw_node) in nodes {
        saw_node = true;
        if parse_candidate_wire_node(&node_id, raw_node).is_none() {
            return CandidateTxSetWireImport::Invalid(CandidateTxSetWireError::MalformedNode);
        }
        if let Some(existing) = staged.get(&node_id) {
            if existing.as_slice() != raw_node {
                return CandidateTxSetWireImport::Invalid(
                    CandidateTxSetWireError::NodeHashMismatch,
                );
            }
        } else {
            staged.insert(node_id, raw_node.to_vec());
        }
    }

    if !saw_node && staged.is_empty() {
        return CandidateTxSetWireImport::Invalid(CandidateTxSetWireError::Empty);
    }

    let imported = import_candidate_tx_set_wire_nodes(
        expected_hash,
        staged
            .iter()
            .map(|(node_id, raw_node)| (*node_id, raw_node.as_slice())),
    );

    match imported {
        CandidateTxSetWireImport::Complete(blobs) => {
            accumulator.nodes.clear();
            CandidateTxSetWireImport::Complete(blobs)
        }
        CandidateTxSetWireImport::Incomplete { missing } => {
            accumulator.nodes = staged;
            CandidateTxSetWireImport::Incomplete { missing }
        }
        CandidateTxSetWireImport::Invalid(CandidateTxSetWireError::CandidateHashMismatch)
            if !staged.contains_key(&SHAMapNodeID::root()) =>
        {
            accumulator.nodes = staged;
            CandidateTxSetWireImport::Incomplete {
                missing: vec![SHAMapNodeID::root()],
            }
        }
        CandidateTxSetWireImport::Invalid(err) => CandidateTxSetWireImport::Invalid(err),
    }
}

fn insert_candidate_tx_set_leaf(
    node: &mut CandidateTxSetNode,
    tx_id: [u8; 32],
    blob: Vec<u8>,
    depth: usize,
) -> bool {
    match node {
        CandidateTxSetNode::Leaf { tx_id: old_id, .. } if old_id == &tx_id => {
            *node = CandidateTxSetNode::Leaf { tx_id, blob };
            false
        }
        CandidateTxSetNode::Leaf { .. } => false,
        CandidateTxSetNode::Inner {
            children,
            cached_hash,
        } => {
            *cached_hash = None;
            let branch = nibble_at(&tx_id, depth);
            match children[branch].as_mut() {
                None => {
                    children[branch] = Some(Box::new(CandidateTxSetNode::Leaf { tx_id, blob }));
                    true
                }
                Some(child) => match child.as_mut() {
                    CandidateTxSetNode::Leaf {
                        tx_id: old_id,
                        blob: old_blob,
                    } if old_id == &tx_id => {
                        *old_blob = blob;
                        false
                    }
                    CandidateTxSetNode::Leaf { .. } => {
                        let old = children[branch].take().expect("child checked above");
                        let mut inner = CandidateTxSetNode::new_inner();
                        if let CandidateTxSetNode::Leaf {
                            tx_id: old_id,
                            blob: old_blob,
                        } = *old
                        {
                            insert_candidate_tx_set_leaf(&mut inner, old_id, old_blob, depth + 1);
                            insert_candidate_tx_set_leaf(&mut inner, tx_id, blob, depth + 1);
                            children[branch] = Some(Box::new(inner));
                            true
                        } else {
                            unreachable!()
                        }
                    }
                    CandidateTxSetNode::Inner { .. } => {
                        insert_candidate_tx_set_leaf(child, tx_id, blob, depth + 1)
                    }
                },
            }
        }
    }
}

fn find_candidate_tx_set_node<'a>(
    node: &'a mut CandidateTxSetNode,
    wanted: &SHAMapNodeID,
) -> Option<(&'a mut CandidateTxSetNode, SHAMapNodeID)> {
    find_candidate_tx_set_node_inner(node, SHAMapNodeID::root(), wanted)
}

fn find_candidate_tx_set_node_inner<'a>(
    node: &'a mut CandidateTxSetNode,
    current_id: SHAMapNodeID,
    wanted: &SHAMapNodeID,
) -> Option<(&'a mut CandidateTxSetNode, SHAMapNodeID)> {
    if current_id == *wanted {
        return Some((node, current_id));
    }
    match node {
        CandidateTxSetNode::Inner { children, .. } if current_id.depth() < wanted.depth() => {
            let branch = current_id.select_branch(wanted);
            let child = children[branch].as_mut()?;
            find_candidate_tx_set_node_inner(child, current_id.child_id(branch as u8), wanted)
        }
        _ => None,
    }
}

fn collect_candidate_tx_set_fat_nodes(
    node: &mut CandidateTxSetNode,
    node_id: SHAMapNodeID,
    depth: u32,
    fat_leaves: bool,
    out: &mut Vec<(SHAMapNodeID, Vec<u8>)>,
) {
    let wire = node.serialize_wire();
    out.push((node_id, wire));

    let branch_count = node.branch_count();
    let CandidateTxSetNode::Inner { children, .. } = node else {
        return;
    };
    if depth == 0 && branch_count != 1 {
        return;
    }
    for branch in 0..16 {
        let Some(child) = children[branch].as_mut() else {
            continue;
        };
        let child_id = node_id.child_id(branch as u8);
        let child_is_inner = matches!(child.as_ref(), CandidateTxSetNode::Inner { .. });
        if child_is_inner && (depth > 1 || branch_count == 1) {
            let next_depth = if branch_count > 1 {
                depth.saturating_sub(1)
            } else {
                depth
            };
            collect_candidate_tx_set_fat_nodes(child, child_id, next_depth, fat_leaves, out);
        } else if child_is_inner || fat_leaves {
            let wire = child.serialize_wire();
            out.push((child_id, wire));
        }
    }
}

fn parse_candidate_wire_node(
    node_id: &SHAMapNodeID,
    raw_node: &[u8],
) -> Option<ParsedCandidateWireNode> {
    let (&wire_type, data) = raw_node.split_last()?;
    match wire_type {
        WIRE_LEAF_TRANSACTION => {
            let tx_blob = candidate_tx_blob_from_wire_leaf(data)?;
            let tx_id = crate::transaction::serialize::tx_blob_hash(tx_blob);
            if SHAMapNodeID::new(node_id.depth(), tx_id) != *node_id {
                return None;
            }
            Some(ParsedCandidateWireNode::Leaf {
                tx_id,
                blob: tx_blob.to_vec(),
            })
        }
        WIRE_INNER_FULL | WIRE_INNER_COMPRESSED => {
            let child_hashes = parse_inner_hashes(data, wire_type)?;
            let hash = candidate_inner_hash(&child_hashes);
            Some(ParsedCandidateWireNode::Inner { child_hashes, hash })
        }
        _ => None,
    }
}

fn candidate_tx_blob_from_wire_leaf(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() {
        return None;
    }
    if let Some(stripped) = data.strip_prefix(&crate::transaction::serialize::PREFIX_TX_ID) {
        return (!stripped.is_empty()).then_some(stripped);
    }
    Some(data)
}

fn candidate_inner_hash(child_hashes: &[[u8; 32]; 16]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(PREFIX_INNER_NODE.len() + 16 * 32);
    payload.extend_from_slice(&PREFIX_INNER_NODE);
    for hash in child_hashes {
        payload.extend_from_slice(hash);
    }
    sha512_first_half(&payload)
}

fn nibble_at(data: &[u8; 32], depth: usize) -> usize {
    if depth >= 64 {
        return 0;
    }
    let byte = data[depth / 2];
    if depth % 2 == 0 {
        (byte >> 4) as usize
    } else {
        (byte & 0x0F) as usize
    }
}

fn walk_candidate_wire_tree(
    node_id: SHAMapNodeID,
    expected_hash: [u8; 32],
    nodes: &HashMap<SHAMapNodeID, ParsedCandidateWireNode>,
    blobs: &mut Vec<Vec<u8>>,
    missing: &mut Vec<SHAMapNodeID>,
) -> Result<(), CandidateTxSetWireError> {
    let Some(node) = nodes.get(&node_id) else {
        missing.push(node_id);
        return Ok(());
    };
    if node.hash() != expected_hash {
        return Err(CandidateTxSetWireError::NodeHashMismatch);
    }
    match node {
        ParsedCandidateWireNode::Leaf { blob, .. } => {
            blobs.push(blob.clone());
            Ok(())
        }
        ParsedCandidateWireNode::Inner { child_hashes, .. } => {
            for (branch, child_hash) in child_hashes.iter().enumerate() {
                if *child_hash == [0u8; 32] {
                    continue;
                }
                walk_candidate_wire_tree(
                    node_id.child_id(branch as u8),
                    *child_hash,
                    nodes,
                    blobs,
                    missing,
                )?;
            }
            Ok(())
        }
    }
}

fn collect_candidate_child_requests(
    node_id: SHAMapNodeID,
    node: &ParsedCandidateWireNode,
    missing: &mut Vec<SHAMapNodeID>,
) {
    if let ParsedCandidateWireNode::Inner { child_hashes, .. } = node {
        for (branch, child_hash) in child_hashes.iter().enumerate() {
            if *child_hash != [0u8; 32] {
                missing.push(node_id.child_id(branch as u8));
            }
        }
    }
}

fn complete_candidate_wire_import(
    expected_hash: [u8; 32],
    blobs: Vec<Vec<u8>>,
) -> CandidateTxSetWireImport {
    let computed =
        crate::ledger::pool::canonical_set_hash_from_blobs(blobs.iter().map(Vec::as_slice));
    if computed == expected_hash {
        CandidateTxSetWireImport::Complete(blobs)
    } else {
        CandidateTxSetWireImport::Invalid(CandidateTxSetWireError::CandidateHashMismatch)
    }
}

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
    add_known_node_with_store_mode(root, node_id, raw_node, map_type, backend, full_below, true).0
}

pub(crate) fn add_known_node_deferred_inner_store(
    root: &mut InnerNode,
    node_id: &SHAMapNodeID,
    raw_node: &[u8],
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
    full_below: &mut FullBelowCache,
) -> (AddNodeResult, Option<([u8; 32], Vec<u8>)>) {
    add_known_node_with_store_mode(
        root, node_id, raw_node, map_type, backend, full_below, false,
    )
}

fn add_known_node_with_store_mode(
    root: &mut InnerNode,
    node_id: &SHAMapNodeID,
    raw_node: &[u8],
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
    full_below: &mut FullBelowCache,
    persist_inner_inline: bool,
) -> (AddNodeResult, Option<([u8; 32], Vec<u8>)>) {
    if raw_node.is_empty() {
        return (AddNodeResult::Invalid, None);
    }

    // Parse wire type (last byte)
    let wire_type = raw_node[raw_node.len() - 1];
    let node_data = &raw_node[..raw_node.len() - 1];

    let generation = full_below.generation();

    // Special case: root node (depth 0)
    if node_id.is_root() {
        return (
            add_root_node(root, node_data, wire_type, map_type, backend),
            None,
        );
    }

    // Navigate from root toward node_id
    let mut current = root as *mut InnerNode;
    let mut current_id = SHAMapNodeID::root();

    while current_id.depth() < node_id.depth() {
        let inner = unsafe { &mut *current };

        if inner.is_full_below(generation) {
            return (AddNodeResult::Duplicate, None);
        }

        let branch = current_id.select_branch(node_id);

        if !inner.has_branch(branch) {
            tracing::warn!("add_known_node: INVALID at has_branch depth={} branch={} is_branch={:#06x} node_id_depth={}",
                current_id.depth(), branch, inner.is_branch, node_id.depth());
            return (AddNodeResult::Invalid, None);
        }

        let expected_hash = inner.child_hash(branch);

        if full_below.touch_if_exists(&expected_hash) {
            return (AddNodeResult::Duplicate, None);
        }

        // Try to descend to child
        if current_id.depth() + 1 == node_id.depth() {
            // The traversal is at the parent, so insert the new node here.
            let new_node = parse_wire_node(node_data, wire_type, map_type);
            let new_node = match new_node {
                Some(n) => n,
                None => return (AddNodeResult::Invalid, None),
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
                return (AddNodeResult::Invalid, None);
            }

            match (&backend, &new_node) {
                // Store inner nodes immediately so future tree walks can reload
                // intermediate structure from disk.
                (Some(backend), Node::Inner(_)) if persist_inner_inline => {
                    let store_data = serialize_for_store(&new_node, map_type);
                    if let Err(err) = backend.store(&computed_hash, &store_data) {
                        tracing::warn!(
                            "add_known_node: failed to persist inner node {}: {}",
                            hex::encode_upper(&computed_hash[..8]),
                            err
                        );
                        return (AddNodeResult::Invalid, None);
                    }
                }
                // In backend-backed state sync, leaves are queued for batched
                // NuDB writes by the caller. Do not attach millions of boxed
                // leaf/stub nodes to the RAM tree; the parent hash plus NuDB
                // row is enough to prove this child when the walker revisits it.
                (Some(_), Node::Leaf(_)) => {
                    full_below.insert(computed_hash);
                    return (AddNodeResult::Useful, None);
                }
                _ => {}
            }
            let deferred_inner_store =
                if backend.is_some() && !persist_inner_inline && matches!(new_node, Node::Inner(_))
                {
                    Some((computed_hash, serialize_for_store(&new_node, map_type)))
                } else {
                    None
                };

            // Hook into parent's child array
            if inner.children[branch].is_some() {
                return (AddNodeResult::Duplicate, None);
            }
            inner.children[branch] = Some(Box::new(new_node));
            inner.invalidate();
            return (AddNodeResult::Useful, deferred_inner_store);
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
                    return (AddNodeResult::Invalid, None);
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
                return (AddNodeResult::Invalid, None);
            }
        }
    }

    (AddNodeResult::Duplicate, None)
}

/// Mark a verified leaf hash complete without materializing the leaf payload.
pub(crate) fn add_known_leaf_hash(
    root: &mut InnerNode,
    node_id: &SHAMapNodeID,
    content_hash: [u8; 32],
    backend: Option<&Arc<dyn NodeStore>>,
    full_below: &mut FullBelowCache,
) -> AddNodeResult {
    if node_id.is_root() {
        return AddNodeResult::Invalid;
    }
    if full_below.touch_if_exists(&content_hash) {
        return AddNodeResult::Duplicate;
    }

    let mut current = root as *mut InnerNode;
    let mut current_id = SHAMapNodeID::root();

    while current_id.depth() < node_id.depth() {
        let inner = unsafe { &mut *current };
        let branch = current_id.select_branch(node_id);
        if !inner.has_branch(branch) {
            return AddNodeResult::Invalid;
        }

        let expected_hash = inner.child_hash(branch);
        if current_id.depth() + 1 == node_id.depth() {
            if expected_hash != content_hash {
                tracing::warn!(
                    "add_known_leaf_hash: INVALID hash mismatch depth={} computed={} expected={}",
                    node_id.depth(),
                    hex::encode_upper(&content_hash[..8]),
                    hex::encode_upper(&expected_hash[..8])
                );
                return AddNodeResult::Invalid;
            }
            if inner.children[branch].is_some() {
                return AddNodeResult::Duplicate;
            }
            full_below.insert(content_hash);
            return AddNodeResult::Useful;
        }

        match &mut inner.children[branch] {
            Some(child) => match child.as_mut() {
                Node::Inner(child_inner) => {
                    current = child_inner as *mut InnerNode;
                    current_id = current_id.child_id(branch as u8);
                }
                _ => return AddNodeResult::Invalid,
            },
            None => {
                if let Some(ref backend) = backend {
                    if let Ok(Some(stored)) = backend.fetch(&expected_hash) {
                        if let Some(StoredNode::Inner(ci)) =
                            decode_validated_store_node(&expected_hash, &stored)
                        {
                            inner.children[branch] = Some(Box::new(Node::Inner(ci)));
                            if let Some(child) = &mut inner.children[branch] {
                                if let Node::Inner(child_inner) = child.as_mut() {
                                    current = child_inner as *mut InnerNode;
                                    current_id = current_id.child_id(branch as u8);
                                    continue;
                                }
                            }
                        }
                    }
                }
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
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
) -> AddNodeResult {
    if wire_type != WIRE_INNER_FULL && wire_type != WIRE_INNER_COMPRESSED {
        return AddNodeResult::Invalid;
    }

    let hashes = parse_inner_hashes(node_data, wire_type);
    let hashes = match hashes {
        Some(h) => h,
        None => return AddNodeResult::Invalid,
    };

    let content_hash = {
        let mut payload = Vec::with_capacity(4 + 16 * 32);
        payload.extend_from_slice(&PREFIX_INNER_NODE);
        for h in &hashes {
            payload.extend_from_slice(h);
        }
        sha512_first_half(&payload)
    };

    if root.is_branch != 0 {
        let existing_hash = root.hash(map_type);
        if existing_hash == content_hash {
            return AddNodeResult::Duplicate;
        }
        tracing::info!(
            "add_root_node: replacing root {} with {}",
            hex::encode_upper(&existing_hash[..8]),
            hex::encode_upper(&content_hash[..8])
        );
    }

    // Store root in NuDB
    if let Some(backend) = backend {
        let mut store_data = Vec::with_capacity(16 * 32);
        for h in &hashes {
            store_data.extend_from_slice(h);
        }
        if let Err(err) = backend.store(&content_hash, &store_data) {
            tracing::warn!(
                "add_root_node: failed to persist root node {}: {}",
                hex::encode_upper(&content_hash[..8]),
                err
            );
            return AddNodeResult::Invalid;
        }
    }

    // A changed root invalidates all loaded child pointers from the previous
    // target. Keep only the advertised child hashes for the new acquisition.
    *root = InnerNode::new();
    for (i, hash) in hashes.iter().enumerate() {
        root.set_child_hash(i, *hash);
    }
    root.cached_hash = Some(content_hash);
    root.dirty = false;

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
    get_missing_nodes_report_limited(root, max, map_type, backend, full_below, None)
}

pub(crate) fn get_missing_nodes_report_limited(
    root: &mut InnerNode,
    max: usize,
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
    full_below: &mut FullBelowCache,
    max_visits: Option<usize>,
) -> MissingNodesReport {
    let generation = full_below.generation();
    let mut report = MissingNodesReport::default();
    let mut remaining = max;
    let mut visits = 0usize;

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

    // Stack: (node_ptr, node_id, first_child, next_child_to_process, branch, full_below_flag)
    // When descending into a child, parent is pushed with current_child
    // pointing to the NEXT branch to process on resume.
    let mut stack: Vec<(*mut InnerNode, SHAMapNodeID, usize, usize, usize, bool)> = Vec::new();

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
                if backend.is_some() {
                    inner.children[branch] = None;
                }
                continue;
            }

            let child_id = node_id.child_id(branch as u8);
            visits = visits.saturating_add(1);
            if max_visits.is_some_and(|limit| visits > limit) {
                report.budget_hint = Some((child_id, child_hash));
                return report;
            }

            // Try to access the child — determine if it's present, missing, or needs descent
            let descend_target: Option<*mut InnerNode> = {
                match &mut inner.children[branch] {
                    Some(child) => match child.as_mut() {
                        Node::Inner(ci) => {
                            if ci.is_full_below(generation) {
                                if backend.is_some() {
                                    inner.children[branch] = None;
                                }
                                None // Already verified complete
                            } else {
                                Some(ci as *mut InnerNode) // Descend
                            }
                        }
                        Node::Leaf(_) => None, // Present = complete
                        Node::Stub { content_hash, .. } => {
                            // Fetch and validate stubs here. A key-only check
                            // would be faster, but it could hide corrupt rows
                            // and incorrectly mark a missing/corrupt leaf full.
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
                                            be.mark_corrupt(content_hash);
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
                                                        if backend.is_some() {
                                                            inner.children[branch] = None;
                                                        }
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
                                            be.mark_corrupt(&child_hash);
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
                stack.push((
                    node,
                    node_id,
                    first_child,
                    current_child,
                    branch,
                    full_below_flag,
                ));
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
        if let Some((
            parent_ptr,
            parent_id,
            parent_first_child,
            parent_child,
            parent_branch,
            parent_full,
        )) = stack.pop()
        {
            let child_was_full = full_below_flag;
            if child_was_full && backend.is_some() {
                let parent = unsafe { &mut *parent_ptr };
                parent.children[parent_branch] = None;
            }
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

pub(crate) fn get_missing_nodes_report_deferred_limited(
    root: &mut InnerNode,
    max: usize,
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
    full_below: &mut FullBelowCache,
    max_visits: Option<usize>,
    read_window: usize,
) -> DeferredMissingNodesReport {
    let generation = full_below.generation();
    let mut report = MissingNodesReport::default();
    let mut queue = DeferredReadQueue::new(read_window);
    let mut remaining = max;
    let mut visits = 0usize;

    if root.is_branch == 0 || root.is_full_below(generation) {
        return DeferredMissingNodesReport::default();
    }

    let mut node: *mut InnerNode = root as *mut InnerNode;
    let mut node_id = SHAMapNodeID::root();
    let mut first_child: usize = random_start_child();
    let mut current_child: usize = 0;
    let mut full_below_flag = true;
    let mut stack: Vec<(*mut InnerNode, SHAMapNodeID, usize, usize, usize, bool)> = Vec::new();

    loop {
        while current_child < 16 {
            if remaining == 0 || queue.is_full() {
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

            if full_below.touch_if_exists(&child_hash) {
                if backend.is_some() {
                    inner.children[branch] = None;
                }
                continue;
            }

            let child_id = node_id.child_id(branch as u8);
            visits = visits.saturating_add(1);
            if max_visits.is_some_and(|limit| visits > limit) {
                report.budget_hint = Some((child_id, child_hash));
                return DeferredMissingNodesReport {
                    report,
                    deferred_reads: queue.into_vec(),
                };
            }

            let descend_target: Option<*mut InnerNode> = match &mut inner.children[branch] {
                Some(child) => match child.as_mut() {
                    Node::Inner(ci) => {
                        if ci.is_full_below(generation) {
                            if backend.is_some() {
                                inner.children[branch] = None;
                            }
                            None
                        } else {
                            Some(ci as *mut InnerNode)
                        }
                    }
                    Node::Leaf(_) => None,
                    Node::Stub { content_hash, .. } => {
                        if backend.is_some() {
                            queue.push(DeferredBackendRead {
                                node_id: child_id,
                                hash: *content_hash,
                                kind: DeferredBackendReadKind::Stub,
                            });
                        } else {
                            report.missing.push((child_id, *content_hash));
                            remaining -= 1;
                        }
                        full_below_flag = false;
                        None
                    }
                },
                None => {
                    if backend.is_some() {
                        queue.push(DeferredBackendRead {
                            node_id: child_id,
                            hash: child_hash,
                            kind: DeferredBackendReadKind::Child,
                        });
                    } else {
                        report.missing.push((child_id, child_hash));
                        remaining -= 1;
                    }
                    full_below_flag = false;
                    None
                }
            };

            if let Some(child_ptr) = descend_target {
                stack.push((
                    node,
                    node_id,
                    first_child,
                    current_child,
                    branch,
                    full_below_flag,
                ));
                node = child_ptr;
                node_id = child_id;
                first_child = random_start_child();
                current_child = 0;
                full_below_flag = true;
            }
        }

        if current_child >= 16 && full_below_flag {
            let inner = unsafe { &mut *node };
            inner.set_full_below(generation);
            let h = inner.hash(map_type);
            full_below.insert(h);
        }

        if remaining == 0 || queue.is_full() {
            return DeferredMissingNodesReport {
                report,
                deferred_reads: queue.into_vec(),
            };
        }

        if let Some((
            parent_ptr,
            parent_id,
            parent_first_child,
            parent_child,
            parent_branch,
            parent_full,
        )) = stack.pop()
        {
            let child_was_full = full_below_flag;
            if child_was_full && backend.is_some() {
                let parent = unsafe { &mut *parent_ptr };
                parent.children[parent_branch] = None;
            }
            node = parent_ptr;
            node_id = parent_id;
            first_child = parent_first_child;
            current_child = parent_child;
            full_below_flag = parent_full && child_was_full;
        } else {
            break;
        }
    }

    DeferredMissingNodesReport {
        report,
        deferred_reads: queue.into_vec(),
    }
}

pub(crate) fn get_missing_nodes_report_windowed_limited(
    root: &mut InnerNode,
    max: usize,
    map_type: MapType,
    backend: Option<&Arc<dyn NodeStore>>,
    full_below: &mut FullBelowCache,
    max_visits: Option<usize>,
    read_window: usize,
) -> MissingNodesReport {
    let Some(backend) = backend else {
        return get_missing_nodes_report_limited(root, max, map_type, None, full_below, max_visits);
    };
    let window = read_window.max(1);
    loop {
        let mut deferred = get_missing_nodes_report_deferred_limited(
            root,
            max,
            map_type,
            Some(backend),
            full_below,
            max_visits,
            window,
        );
        if deferred.deferred_reads.is_empty() {
            return deferred.report;
        }
        let hashes: Vec<[u8; 32]> = deferred
            .deferred_reads
            .iter()
            .map(|read| read.hash)
            .collect();
        let results = backend.fetch_window(&hashes);
        apply_deferred_backend_reads(
            root,
            backend,
            &deferred.deferred_reads,
            results,
            full_below,
            &mut deferred.report,
        );
        if !deferred.report.missing.is_empty()
            || deferred.report.backend_fetch_errors > 0
            || deferred.report.budget_hint.is_some()
        {
            return deferred.report;
        }
    }
}

fn apply_deferred_backend_reads(
    root: &mut InnerNode,
    backend: &Arc<dyn NodeStore>,
    reads: &[DeferredBackendRead],
    results: Vec<([u8; 32], std::io::Result<Option<Vec<u8>>>)>,
    full_below: &mut FullBelowCache,
    report: &mut MissingNodesReport,
) {
    for (read, (_, result)) in reads.iter().zip(results.into_iter()) {
        match result {
            Ok(Some(stored)) => match decode_validated_store_node(&read.hash, &stored) {
                Some(StoredNode::Inner(inner)) if read.kind == DeferredBackendReadKind::Child => {
                    let _ = attach_inner_at(root, read.node_id, read.hash, inner);
                }
                Some(StoredNode::Inner(_)) | Some(StoredNode::Leaf) => {
                    full_below.insert(read.hash);
                }
                None => {
                    tracing::warn!(
                        "shamap sync deferred typed decode failed for child {}",
                        hex::encode_upper(&read.hash[..8]),
                    );
                    backend.mark_corrupt(&read.hash);
                    report.backend_fetch_errors += 1;
                    report.missing.push((read.node_id, read.hash));
                }
            },
            Ok(None) => {
                report.missing.push((read.node_id, read.hash));
            }
            Err(err) => {
                tracing::warn!(
                    "shamap sync deferred fetch failed for child {}: {}",
                    hex::encode_upper(&read.hash[..8]),
                    err
                );
                report.backend_fetch_errors += 1;
            }
        }
    }
}

fn attach_inner_at(
    root: &mut InnerNode,
    node_id: SHAMapNodeID,
    expected_hash: [u8; 32],
    inner_node: InnerNode,
) -> bool {
    if node_id.is_root() {
        return false;
    }
    let mut current = root;
    let mut current_id = SHAMapNodeID::root();
    while current_id.depth() + 1 < node_id.depth() {
        let branch = current_id.select_branch(&node_id);
        let Some(child) = current.children[branch].as_mut() else {
            return false;
        };
        let Node::Inner(next) = child.as_mut() else {
            return false;
        };
        current = next;
        current_id = current_id.child_id(branch as u8);
    }
    let branch = current_id.select_branch(&node_id);
    if current.child_hash(branch) != expected_hash {
        return false;
    }
    if current.children[branch].is_none() {
        current.children[branch] = Some(Box::new(Node::Inner(inner_node)));
        current.invalidate();
    }
    true
}

fn random_start_child() -> usize {
    (rand::random::<u8>() & 0x0F) as usize
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
        WIRE_LEAF_TRANSACTION | WIRE_LEAF_TRANSACTION_WITH_META | WIRE_LEAF_ACCOUNT_STATE => {
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
    let mut inner_hash = None;
    if data.len() == 16 * 32 {
        let mut inner = deserialize_inner_from_store(data)?;
        let mut payload = Vec::with_capacity(PREFIX_INNER_NODE.len() + data.len());
        payload.extend_from_slice(&PREFIX_INNER_NODE);
        payload.extend_from_slice(data);
        let computed = sha512_first_half(&payload);
        if computed == *expected_hash {
            inner.cached_hash = Some(computed);
            inner.dirty = false;
            return Some(StoredNode::Inner(inner));
        }
        // A persisted leaf can also be exactly 512 bytes long (480-byte payload
        // plus the 32-byte key). Fall through and validate the leaf forms
        // before rejecting the backend row.
        inner_hash = Some(computed);
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
    let leaf_data = &data[..data.len() - 32];

    let state_hash = validated_leaf_hash(&key, leaf_data, &PREFIX_LEAF_STATE);
    if state_hash == *expected_hash {
        return Some(StoredNode::Leaf);
    }

    let tx_hash = validated_leaf_hash(&key, leaf_data, &PREFIX_LEAF_TX);
    if tx_hash == *expected_hash {
        return Some(StoredNode::Leaf);
    }

    if data.len() >= 33 {
        let wire_type = data[data.len() - 1];
        let prefix = match wire_type {
            WIRE_LEAF_ACCOUNT_STATE => Some(&PREFIX_LEAF_STATE),
            WIRE_LEAF_TRANSACTION | WIRE_LEAF_TRANSACTION_WITH_META => Some(&PREFIX_LEAF_TX),
            _ => None,
        };
        if let Some(prefix) = prefix {
            let payload_end = data.len() - 33;
            let mut wire_key = [0u8; 32];
            wire_key.copy_from_slice(&data[payload_end..data.len() - 1]);
            if validated_leaf_hash(&Key(wire_key), &data[..payload_end], prefix) == *expected_hash {
                return Some(StoredNode::Leaf);
            }
        }
    }

    if let Some(inner_hash) = inner_hash {
        tracing::warn!(
            "shamap sync backend 512-byte object hash mismatch: expected={} inner={} state={} tx={}",
            hex::encode_upper(&expected_hash[..8]),
            hex::encode_upper(&inner_hash[..8]),
            hex::encode_upper(&state_hash[..8]),
            hex::encode_upper(&tx_hash[..8]),
        );
    } else {
        tracing::warn!(
            "shamap sync backend leaf hash mismatch: expected={} state={} tx={}",
            hex::encode_upper(&expected_hash[..8]),
            hex::encode_upper(&state_hash[..8]),
            hex::encode_upper(&tx_hash[..8]),
        );
    }
    None
}

fn validated_leaf_hash(key: &Key, data: &[u8], prefix: &[u8; 4]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(prefix.len() + data.len() + 32);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(data);
    payload.extend_from_slice(&key.0);
    sha512_first_half(&payload)
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
    fn candidate_reply_root_then_leaf_imports_with_root_validation() {
        let tx_a = b"candidate tx a".as_slice();
        let tx_b = b"candidate tx b".as_slice();
        let root_id = SHAMapNodeID::root();
        let (root_nodes, root_hash) =
            build_candidate_tx_set_wire_nodes([tx_a, tx_b], &[root_id], 0);

        assert_eq!(root_nodes.len(), 1);
        assert_eq!(root_nodes[0].0, root_id);
        assert_eq!(root_nodes[0].1.last().copied(), Some(WIRE_INNER_FULL));

        let incomplete = import_candidate_tx_set_wire_nodes(
            root_hash,
            root_nodes
                .iter()
                .map(|(node_id, data)| (*node_id, data.as_slice())),
        );
        let missing = match incomplete {
            CandidateTxSetWireImport::Incomplete { missing } => missing,
            other => panic!("root-only candidate import should be incomplete: {other:?}"),
        };
        assert_eq!(missing.len(), 2);

        let (leaf_nodes, _) = build_candidate_tx_set_wire_nodes([tx_a, tx_b], &missing, 0);
        assert_eq!(leaf_nodes.len(), 2);
        assert!(leaf_nodes
            .iter()
            .all(|(_, data)| data.last().copied() == Some(WIRE_LEAF_TRANSACTION)));

        let imported = import_candidate_tx_set_wire_nodes(
            root_hash,
            leaf_nodes
                .iter()
                .map(|(node_id, data)| (*node_id, data.as_slice())),
        );
        match imported {
            CandidateTxSetWireImport::Complete(blobs) => {
                assert_eq!(blobs.len(), 2);
                assert!(blobs.iter().any(|blob| blob.as_slice() == tx_a));
                assert!(blobs.iter().any(|blob| blob.as_slice() == tx_b));
            }
            other => panic!("leaf candidate import should complete: {other:?}"),
        }
    }

    #[test]
    fn candidate_accumulator_merges_split_leaf_batches() {
        let tx_a = b"split candidate tx a".as_slice();
        let tx_b = b"split candidate tx b".as_slice();
        let root_id = SHAMapNodeID::root();
        let (root_nodes, root_hash) =
            build_candidate_tx_set_wire_nodes([tx_a, tx_b], &[root_id], 0);
        let mut accumulator = CandidateTxSetWireAccumulator::default();

        let root_result = import_candidate_tx_set_wire_nodes_accumulated(
            root_hash,
            &mut accumulator,
            root_nodes
                .iter()
                .map(|(node_id, data)| (*node_id, data.as_slice())),
        );
        let missing = match root_result {
            CandidateTxSetWireImport::Incomplete { missing } => missing,
            other => panic!("root-only candidate import should be incomplete: {other:?}"),
        };
        assert_eq!(missing.len(), 2);
        assert_eq!(accumulator.len(), root_nodes.len());

        let (leaf_nodes, _) = build_candidate_tx_set_wire_nodes([tx_a, tx_b], &missing, 0);
        assert_eq!(leaf_nodes.len(), 2);

        let first_leaf = import_candidate_tx_set_wire_nodes_accumulated(
            root_hash,
            &mut accumulator,
            leaf_nodes
                .iter()
                .take(1)
                .map(|(node_id, data)| (*node_id, data.as_slice())),
        );
        match first_leaf {
            CandidateTxSetWireImport::Incomplete { missing } => assert_eq!(missing.len(), 1),
            other => panic!("one split leaf should leave acquisition incomplete: {other:?}"),
        }
        assert_eq!(accumulator.len(), root_nodes.len() + 1);

        let second_leaf = import_candidate_tx_set_wire_nodes_accumulated(
            root_hash,
            &mut accumulator,
            leaf_nodes
                .iter()
                .skip(1)
                .map(|(node_id, data)| (*node_id, data.as_slice())),
        );
        match second_leaf {
            CandidateTxSetWireImport::Complete(blobs) => {
                assert_eq!(blobs.len(), 2);
                assert!(blobs.iter().any(|blob| blob.as_slice() == tx_a));
                assert!(blobs.iter().any(|blob| blob.as_slice() == tx_b));
            }
            other => panic!("second split leaf should complete acquisition: {other:?}"),
        }
        assert_eq!(accumulator.len(), 0);
    }

    #[test]
    fn candidate_import_rejects_tampered_root_hash() {
        let tx = b"candidate tx";
        let (nodes, mut root_hash) =
            build_candidate_tx_set_wire_nodes([tx.as_slice()], &[SHAMapNodeID::root()], 0);
        root_hash[0] ^= 0xFF;

        let imported = import_candidate_tx_set_wire_nodes(
            root_hash,
            nodes
                .iter()
                .map(|(node_id, data)| (*node_id, data.as_slice())),
        );

        assert_eq!(
            imported,
            CandidateTxSetWireImport::Invalid(CandidateTxSetWireError::RootHashMismatch)
        );
    }

    #[test]
    fn candidate_import_rejects_leaf_at_wrong_node_id() {
        let tx = b"candidate tx";
        let tx_id = crate::transaction::serialize::tx_blob_hash(tx);
        let wrong_id = SHAMapNodeID::new(1, [0xFF; 32]);
        assert_ne!(wrong_id, SHAMapNodeID::new(1, tx_id));
        let mut leaf = tx.to_vec();
        leaf.push(WIRE_LEAF_TRANSACTION);

        let imported = import_candidate_tx_set_wire_nodes([0u8; 32], [(wrong_id, leaf.as_slice())]);

        assert_eq!(
            imported,
            CandidateTxSetWireImport::Invalid(CandidateTxSetWireError::MalformedNode)
        );
    }

    #[test]
    fn limited_missing_report_returns_budget_hint() {
        let mut root = InnerNode::new();
        root.set_child_hash(7, [0x77; 32]);
        let mut full_below = FullBelowCache::new(16);

        let report = get_missing_nodes_report_limited(
            &mut root,
            16,
            MapType::AccountState,
            None,
            &mut full_below,
            Some(0),
        );

        assert!(report.missing.is_empty());
        assert_eq!(
            report.budget_hint,
            Some((SHAMapNodeID::root().child_id(7), [0x77; 32]))
        );
    }

    #[test]
    fn random_start_child_stays_inside_branch_range() {
        for _ in 0..256 {
            assert!(random_start_child() < 16);
        }
    }

    #[test]
    fn randomized_missing_reports_preserve_root_hash() {
        let mut root = InnerNode::new();
        for branch in 0..16 {
            let mut hash = [0u8; 32];
            hash[31] = branch as u8 + 1;
            root.set_child_hash(branch, hash);
        }
        let expected = root.hash(MapType::AccountState);

        for _ in 0..16 {
            let mut full_below = FullBelowCache::new(16);
            let _ = get_missing_nodes_report_limited(
                &mut root,
                4,
                MapType::AccountState,
                None,
                &mut full_below,
                None,
            );
            assert_eq!(root.hash(MapType::AccountState), expected);
        }
    }

    #[test]
    fn deferred_missing_report_returns_backend_read_window() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut child_hashes = [[0u8; 32]; 16];
        child_hashes[4] = [0x44; 32];
        let child_wire = make_inner_wire(&child_hashes);
        let child_hash = {
            let mut payload = Vec::with_capacity(PREFIX_INNER_NODE.len() + 16 * 32);
            payload.extend_from_slice(&PREFIX_INNER_NODE);
            payload.extend_from_slice(&child_wire[..16 * 32]);
            sha512_first_half(&payload)
        };
        store
            .store(&child_hash, &child_wire[..16 * 32])
            .expect("child inner should store");

        let mut root = InnerNode::new();
        root.set_child_hash(0, child_hash);
        let mut full_below = FullBelowCache::new(16);

        let deferred = get_missing_nodes_report_deferred_limited(
            &mut root,
            16,
            MapType::AccountState,
            Some(&store),
            &mut full_below,
            None,
            8,
        );

        assert!(deferred.report.missing.is_empty());
        assert_eq!(
            deferred.deferred_reads,
            vec![DeferredBackendRead {
                node_id: SHAMapNodeID::root().child_id(0),
                hash: child_hash,
                kind: DeferredBackendReadKind::Child,
            }]
        );
    }

    #[test]
    fn deferred_read_queue_caps_backend_reads_without_reporting_missing() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut root = InnerNode::new();
        root.set_child_hash(0, [0x10; 32]);
        root.set_child_hash(1, [0x11; 32]);
        let mut full_below = FullBelowCache::new(16);

        let deferred = get_missing_nodes_report_deferred_limited(
            &mut root,
            16,
            MapType::AccountState,
            Some(&store),
            &mut full_below,
            None,
            1,
        );

        assert_eq!(deferred.deferred_reads.len(), 1);
        assert!(deferred.report.missing.is_empty());
        assert_eq!(deferred.report.backend_fetch_errors, 0);
    }

    #[test]
    fn windowed_missing_report_resumes_after_backend_inner_hit() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut child_hashes = [[0u8; 32]; 16];
        child_hashes[4] = [0x44; 32];
        let child_wire = make_inner_wire(&child_hashes);
        let child_hash = {
            let mut payload = Vec::with_capacity(PREFIX_INNER_NODE.len() + 16 * 32);
            payload.extend_from_slice(&PREFIX_INNER_NODE);
            payload.extend_from_slice(&child_wire[..16 * 32]);
            sha512_first_half(&payload)
        };
        store
            .store(&child_hash, &child_wire[..16 * 32])
            .expect("child inner should store");

        let mut root = InnerNode::new();
        root.set_child_hash(0, child_hash);
        let mut full_below = FullBelowCache::new(16);

        let report = get_missing_nodes_report_windowed_limited(
            &mut root,
            16,
            MapType::AccountState,
            Some(&store),
            &mut full_below,
            None,
            8,
        );

        assert_eq!(
            report.missing,
            vec![(SHAMapNodeID::root().child_id(0).child_id(4), [0x44; 32])]
        );
        assert_eq!(report.backend_fetch_errors, 0);
    }

    #[test]
    fn windowed_missing_report_accepts_backend_leaf_hit() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let key = [0xAB; 32];
        let data = b"deferred leaf";
        let leaf_wire = make_leaf_wire(key, data);
        let leaf_hash = {
            let mut payload = Vec::with_capacity(PREFIX_LEAF_STATE.len() + data.len() + 32);
            payload.extend_from_slice(&PREFIX_LEAF_STATE);
            payload.extend_from_slice(data);
            payload.extend_from_slice(&key);
            sha512_first_half(&payload)
        };
        store
            .store(&leaf_hash, &leaf_wire[..leaf_wire.len() - 1])
            .expect("leaf should store");

        let mut root = InnerNode::new();
        root.set_child_hash(0, leaf_hash);
        let mut full_below = FullBelowCache::new(16);

        let report = get_missing_nodes_report_windowed_limited(
            &mut root,
            16,
            MapType::AccountState,
            Some(&store),
            &mut full_below,
            None,
            8,
        );

        assert!(report.missing.is_empty());
        assert_eq!(report.backend_fetch_errors, 0);
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
    fn add_root_node_replaces_stale_root_for_retarget() {
        let mut root = InnerNode::new();
        let mut fb = FullBelowCache::new(1000);
        let root_id = SHAMapNodeID::root();

        let mut old_hashes = [[0u8; 32]; 16];
        old_hashes[0] = [0xAA; 32];
        let old_wire = make_inner_wire(&old_hashes);
        assert_eq!(
            add_known_node(
                &mut root,
                &root_id,
                &old_wire,
                MapType::AccountState,
                None,
                &mut fb,
            ),
            AddNodeResult::Useful
        );
        root.children[0] = Some(Box::new(Node::Inner(InnerNode::new())));

        let mut new_hashes = [[0u8; 32]; 16];
        new_hashes[7] = [0x77; 32];
        let new_wire = make_inner_wire(&new_hashes);
        assert_eq!(
            add_known_node(
                &mut root,
                &root_id,
                &new_wire,
                MapType::AccountState,
                None,
                &mut fb,
            ),
            AddNodeResult::Useful
        );

        assert!(!root.has_branch(0));
        assert!(root.has_branch(7));
        assert!(root.children.iter().all(|child| child.is_none()));
        assert_eq!(
            add_known_node(
                &mut root,
                &root_id,
                &new_wire,
                MapType::AccountState,
                None,
                &mut fb,
            ),
            AddNodeResult::Duplicate
        );
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
    fn add_inner_can_defer_backend_store_until_persistence_lane() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut root = InnerNode::new();
        let mut fb = FullBelowCache::new(1000);

        let mut child_hashes = [[0u8; 32]; 16];
        child_hashes[3] = [0x33; 32];
        let child_wire = make_inner_wire(&child_hashes);
        let child_hash = {
            let mut payload = Vec::with_capacity(PREFIX_INNER_NODE.len() + 16 * 32);
            payload.extend_from_slice(&PREFIX_INNER_NODE);
            payload.extend_from_slice(&child_wire[..16 * 32]);
            sha512_first_half(&payload)
        };
        root.set_child_hash(0, child_hash);

        let (result, deferred) = add_known_node_deferred_inner_store(
            &mut root,
            &SHAMapNodeID::root().child_id(0),
            &child_wire,
            MapType::AccountState,
            Some(&store),
            &mut fb,
        );

        assert_eq!(result, AddNodeResult::Useful);
        let (hash, data) = deferred.expect("inner store row should be deferred");
        assert_eq!(hash, child_hash);
        assert_eq!(data, child_wire[..16 * 32]);
        assert!(
            store.fetch(&child_hash).unwrap().is_none(),
            "inner persistence should be deferred out of add_known_node"
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
        store
            .store(&expected_hash, &store_data)
            .expect("store corrupt row");

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

    #[test]
    fn exact_512_byte_leaf_in_backend_is_not_misclassified_as_inner() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut root = InnerNode::new();
        let mut fb = FullBelowCache::new(1000);

        let key = [0xCD; 32];
        let leaf_data = vec![0x5A; 480];
        let wire = make_leaf_wire(key, &leaf_data);
        let Some((expected_hash, store_data)) =
            prepare_wire_node_for_reuse(&wire, MapType::AccountState).unwrap()
        else {
            panic!("expected reusable 512-byte leaf");
        };
        assert_eq!(
            store_data.len(),
            16 * 32,
            "fixture must be exactly 512 bytes"
        );

        store
            .store(&expected_hash, &store_data)
            .expect("store exact-size leaf");
        root.set_child_hash(6, expected_hash);

        let report =
            get_missing_nodes_report(&mut root, 256, MapType::AccountState, Some(&store), &mut fb);
        assert!(
            report.missing.is_empty(),
            "exact-size leaf should be satisfied from backend"
        );
        assert_eq!(report.backend_fetch_errors, 0);
    }

    #[test]
    fn exact_512_byte_wire_leaf_in_backend_is_not_misclassified_as_inner() {
        let store: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut root = InnerNode::new();
        let mut fb = FullBelowCache::new(1000);

        let key = [0xCE; 32];
        let leaf_data = vec![0x5B; 479];
        let wire = make_leaf_wire(key, &leaf_data);
        assert_eq!(wire.len(), 16 * 32, "fixture must be exactly 512 bytes");

        let mut payload = Vec::with_capacity(4 + leaf_data.len() + 32);
        payload.extend_from_slice(&crate::ledger::shamap::PREFIX_LEAF_STATE);
        payload.extend_from_slice(&leaf_data);
        payload.extend_from_slice(&key);
        let expected_hash = crate::crypto::sha512_first_half(&payload);

        store
            .store(&expected_hash, &wire)
            .expect("store wire leaf row");
        root.set_child_hash(7, expected_hash);

        let report =
            get_missing_nodes_report(&mut root, 256, MapType::AccountState, Some(&store), &mut fb);
        assert!(
            report.missing.is_empty(),
            "wire-format exact-size leaf should be satisfied from backend"
        );
        assert_eq!(report.backend_fetch_errors, 0);
    }
}
