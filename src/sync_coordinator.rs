//! SyncCoordinator — orchestrates state tree sync.
//!
//! Owns the SHAMap during sync (matching rippled's InboundLedger model).
//! When sync completes, the SHAMap is handed off to LedgerState.
//! No cross-locking, no &LedgerState parameters.

use std::sync::Arc;

use crate::ledger::full_below_cache::FullBelowCache;
use crate::ledger::node_store::NodeStore;
use crate::ledger::shamap::{SHAMap, MapType};
use crate::ledger::shamap_sync::AddNodeResult;
use crate::network::message::RtxpMessage;
use crate::sync::{PeerSyncManager, SyncRequestReason};

/// Progress report from processing responses.
pub struct SyncProgress {
    pub inner_received: usize,
    pub leaf_received: usize,
    pub pending: usize,
    pub total_inner: usize,
    pub total_leaf: usize,
    pub leaves: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Orchestrates state tree sync. Owns the SHAMap exclusively during sync.
pub struct SyncCoordinator {
    /// Peer coordination — requests, cookies, stall detection.
    pub peer: PeerSyncManager,
    /// THE tree — owned exclusively by the coordinator during sync.
    shamap: SHAMap,
    /// Subtree completion tracking.
    full_below: FullBelowCache,
    /// Direct NuDB backend for lock-free leaf writes.
    backend: Option<Arc<dyn NodeStore>>,
    /// The full header of the ledger we're syncing to.
    /// Preserved for follower handoff so it has a real parent header.
    pub sync_header: crate::ledger::LedgerHeader,
    /// Hash → SHAMapNodeID lookup for GetObjects responses.
    /// Populated by build_timeout_object_request(), consumed by the
    /// response handler to supply correct tree positions.
    pub pending_object_nodeids: std::collections::HashMap<[u8; 32], [u8; 33]>,
    /// Cookie → ordered wire node IDs for GetObjects requests.
    /// Used when peers omit hash/index/node_id in responses.
    pub pending_object_cookies: std::collections::HashMap<u32, Vec<[u8; 33]>>,
    /// Leaf count at last retarget — used to detect stale tail loops.
    retarget_leaf_count: usize,
    /// Consecutive retargets with no leaf progress.
    pub stale_retarget_count: u32,
}

impl SyncCoordinator {
    pub fn new(
        seq: u32,
        hash: [u8; 32],
        account_hash: [u8; 32],
        backend: Option<Arc<dyn NodeStore>>,
        header: crate::ledger::LedgerHeader,
    ) -> Self {
        let shamap = match &backend {
            Some(b) => SHAMap::with_backend(MapType::AccountState, b.clone()),
            None => SHAMap::new_state(),
        };
        Self {
            peer: PeerSyncManager::new(seq, hash, account_hash),
            shamap,
            full_below: FullBelowCache::new(524_288),
            backend,
            sync_header: header,
            pending_object_nodeids: std::collections::HashMap::new(),
            pending_object_cookies: std::collections::HashMap::new(),
            retarget_leaf_count: 0,
            stale_retarget_count: 0,
        }
    }

    /// Process a single peer response.
    pub fn process_response(
        &mut self,
        ld: &crate::proto::TmLedgerData,
    ) -> SyncProgress {
        let parsed = self.peer.parse_response(ld);
        let mut inner_count = 0;
        let mut leaf_count = 0;

        // Insert nodes into our SHAMap
        let mut dup_count = 0usize;
        let mut inv_count = 0usize;
        for (node_id, wire_data) in &parsed.nodes {
            let wire_type = wire_data.last().copied().unwrap_or(0);
            let result = sync_shamap::add_known_node(
                &mut self.shamap.root, node_id, wire_data,
                MapType::AccountState, self.backend.as_ref(), &mut self.full_below,
            );
            match result {
                AddNodeResult::Useful => {
                    if wire_type == 0x02 || wire_type == 0x03 {
                        inner_count += 1;
                    } else {
                        leaf_count += 1;
                    }
                }
                AddNodeResult::Duplicate => dup_count += 1,
                AddNodeResult::Invalid => inv_count += 1,
            }
        }
        if inv_count > 0 || inner_count > 0 || dup_count > parsed.nodes.len() / 2 {
            tracing::info!(
                "process_response: {} nodes, {} useful ({}i {}l), {} dup, {} inv",
                parsed.nodes.len(), inner_count + leaf_count, inner_count, leaf_count, dup_count, inv_count,
            );
        }

        // NuDB leaf writes deferred — returned in SyncProgress.leaves
        // for the caller to write OUTSIDE the sync lock.

        SyncProgress {
            inner_received: inner_count,
            leaf_received: leaf_count,
            pending: 0,
            total_inner: self.peer.inner_count,
            total_leaf: self.peer.leaf_count,
            leaves: parsed.leaves,
        }
    }

    /// Build next sync request from missing nodes.
    pub fn build_next_request(&mut self, reason: SyncRequestReason) -> Vec<RtxpMessage> {
        let missing = self.get_missing(256);
        self.peer.build_requests_from_missing(&missing, reason)
    }

    /// Build up to `n` separate requests, each with different missing nodes.
    /// Matches rippled's pattern: trigger() called once per peer, each gets
    /// a unique set of ~128 missing node IDs.
    ///
    /// rippled calls getMissingNodes(256) per trigger, filters to 128 via
    /// filterNodes, leaving 128 unfiltered for the next trigger's call.
    /// We replicate this by fetching 256*n missing nodes in one walk,
    /// then chunking into 128-node requests distributed across peers.
    pub fn build_multi_requests(&mut self, n: usize, reason: SyncRequestReason) -> Vec<RtxpMessage> {
        let max_nodes = 256 * n;
        let missing = self.get_missing(max_nodes);
        if missing.is_empty() { return vec![]; }
        self.peer.build_requests_from_missing(&missing, reason)
    }

    /// Build timeout request.
    pub fn build_timeout_request(&mut self) -> Vec<RtxpMessage> {
        self.build_next_request(SyncRequestReason::Timeout)
    }

    /// Build timeout object request (GetObjects for stuck nodes).
    /// Stores hash→nodeid mapping for response handling.
    pub fn build_timeout_object_request(&mut self) -> Option<RtxpMessage> {
        let missing = self.get_missing(256);
        if missing.is_empty() { return None; }

        // Store hash → wire nodeid for response processing.
        // Clear stale mappings first (bounded to current request set).
        self.pending_object_nodeids.clear();
        let nodes: Vec<([u8; 32], [u8; 33])> = missing.iter()
            .map(|(nid, hash)| {
                self.pending_object_nodeids.insert(*hash, nid.to_wire());
                (*hash, nid.to_wire())
            })
            .collect();
        let seq = crate::sync::next_cookie() as u32;
        self.peer.outstanding_object_queries.insert(seq);
        self.pending_object_cookies.insert(
            seq,
            nodes.iter().map(|(_, nid)| *nid).collect(),
        );

        Some(crate::network::relay::encode_get_state_nodes_by_hash(
            &self.peer.ledger_hash, &nodes, self.peer.ledger_seq, seq,
        ))
    }

    /// Find missing nodes in the SHAMap.
    pub fn get_missing(&mut self, max: usize) -> Vec<(crate::ledger::shamap_id::SHAMapNodeID, [u8; 32])> {
        sync_shamap::get_missing_nodes(
            &mut self.shamap.root, max, MapType::AccountState,
            self.backend.as_ref(), &mut self.full_below,
        )
    }

    /// Retarget to a new ledger without dropping the tree structure.
    /// The SHAMap inner nodes are 99.99% the same across ledgers — only
    /// changed branches differ. Retargeting avoids re-downloading the
    /// entire tree structure from scratch.
    pub fn retarget(&mut self, seq: u32, hash: [u8; 32], account_hash: [u8; 32], header: crate::ledger::LedgerHeader) {
        // Track stale retargets: if leaf count hasn't grown since last retarget,
        // increment stale counter. After 3 stale retargets, switch to ltCLOSED
        // mode — use zero ledger_hash so peers serve from their current tree.
        let current_leaves = self.peer.leaf_count;
        if current_leaves <= self.retarget_leaf_count && self.retarget_leaf_count > 0 {
            self.stale_retarget_count += 1;
        } else {
            self.stale_retarget_count = 0;
        }
        self.retarget_leaf_count = current_leaves;

        let use_ltclosed = self.stale_retarget_count >= 3;
        if use_ltclosed {
            tracing::warn!(
                "sync retarget: {} → {} — STALE TAIL ({} retargets with no leaf progress) — switching to ltCLOSED mode (keeping {} inner nodes)",
                self.peer.ledger_seq, seq, self.stale_retarget_count, self.peer.inner_count,
            );
            // Zero the ledger_hash so all requests use ltCLOSED.
            // Peers will serve from their current validated tree.
            self.peer.ledger_hash = [0u8; 32];
        } else {
            tracing::info!(
                "sync retarget: {} → {} (keeping {} inner nodes, stale_count={})",
                self.peer.ledger_seq, seq, self.peer.inner_count, self.stale_retarget_count,
            );
            self.peer.ledger_hash = hash;
        }
        self.peer.ledger_seq = seq;
        self.peer.account_hash = account_hash;
        self.peer.active = true;
        self.peer.stalled_retries = 0;
        self.peer.recent_nodes.clear();
        self.peer.outstanding_cookies.clear();
        self.peer.responded_cookies.clear();
        self.peer.last_response = std::time::Instant::now();
        self.peer.last_new_nodes = std::time::Instant::now();
        self.peer.tail_stuck_hash = [0u8; 32];
        self.peer.tail_stuck_retries = 0;
        self.pending_object_nodeids.clear();
        self.pending_object_cookies.clear();
        // Clear full_below cache — subtree completeness changes with new root hash
        self.full_below = FullBelowCache::new(524_288);
        // Keep the SHAMap tree — inner nodes are reusable
        self.sync_header = header;
    }

    /// Check if sync is complete.
    ///
    /// In normal mode: root hash must match `account_hash` from the target header.
    /// In ltCLOSED mode (`ledger_hash == [0;32]`): tree is filled from peers'
    /// current validated ledger. Completion requires a fresh validated header
    /// whose `account_hash` matches our computed root. The caller must supply
    /// this via `offer_validated_header()` before `is_complete` can return true.
    pub fn is_complete(&mut self) -> bool {
        // A tree with no branches is empty — not complete
        if self.shamap.root.is_branch == 0 {
            return false;
        }
        // Must have downloaded at least SOME leaf data
        if self.peer.leaf_count == 0 {
            return false;
        }
        // Must have no missing nodes
        let missing = self.get_missing(16);
        if !missing.is_empty() {
            tracing::debug!("is_complete: {} missing nodes (first: {})",
                missing.len(),
                hex::encode_upper(&missing[0].1[..8]));
            return false;
        }
        // Verify root hash matches the target account_hash
        let root = self.root_hash();
        let matches = root == self.peer.account_hash;
        if matches {
            tracing::info!("is_complete: missing=0 root={} target={} match=true",
                hex::encode_upper(&root[..8]),
                hex::encode_upper(&self.peer.account_hash[..8]));
        } else if self.peer.ledger_hash == [0u8; 32] {
            // ltCLOSED mode: tree was filled from peers' current validated tree.
            // Root won't match original target — need a validated header for
            // this root. is_complete stays false until offer_validated_header()
            // rebinds the target atomically.
            tracing::info!(
                "is_complete: ltCLOSED mode, missing=0, root={} (target mismatch — awaiting validated header rebind)",
                hex::encode_upper(&root[..8]),
            );
        } else {
            tracing::info!("is_complete: missing=0 root={} target={} match=false",
                hex::encode_upper(&root[..8]),
                hex::encode_upper(&self.peer.account_hash[..8]));
        }
        matches
    }

    /// In ltCLOSED mode, offer a validated header to rebind the sync target.
    /// If the header's `account_hash` matches our computed root hash,
    /// atomically update all target metadata and return true.
    /// Called by the liBASE/validation handler when new validated headers arrive.
    pub fn offer_validated_header(&mut self, header: &crate::ledger::LedgerHeader) -> bool {
        // Only relevant in ltCLOSED mode
        if self.peer.ledger_hash != [0u8; 32] {
            return false;
        }
        // Must have no missing nodes
        let missing = self.get_missing(1);
        if !missing.is_empty() {
            return false;
        }
        let root = self.root_hash();
        if root != header.account_hash {
            return false;
        }
        // Match! Atomically rebind all target metadata.
        let old_seq = self.peer.ledger_seq;
        tracing::warn!(
            "stale-target rollover accepted: seq {} → {}, hash {} → {}, account_hash {} (ltCLOSED → exact)",
            old_seq, header.sequence,
            hex::encode_upper(&self.peer.ledger_hash[..8]),
            hex::encode_upper(&header.hash[..8]),
            hex::encode_upper(&root[..8]),
        );
        self.peer.ledger_seq = header.sequence;
        self.peer.ledger_hash = header.hash;
        self.peer.account_hash = header.account_hash;
        self.sync_header = header.clone();
        self.stale_retarget_count = 0;
        true
    }

    /// Check if current pass is stalled.
    pub fn is_pass_complete(&mut self) -> bool {
        if self.is_complete() { return true; }
        self.peer.new_objects_this_pass() == 0
            && self.peer.last_new_nodes.elapsed().as_secs() > 10
    }

    /// Count of missing nodes (diagnostics).
    pub fn pending_count(&mut self) -> usize {
        self.get_missing(256).len()
    }

    /// Restart for a new ledger.
    pub fn restart(&mut self, seq: u32, hash: [u8; 32], account_hash: [u8; 32]) {
        self.peer = PeerSyncManager::new(seq, hash, account_hash);
        self.shamap = match &self.backend {
            Some(b) => SHAMap::with_backend(MapType::AccountState, b.clone()),
            None => SHAMap::new_state(),
        };
        self.full_below.next_generation();
    }

    /// Take the SHAMap out of the coordinator (handoff to LedgerState).
    /// After this call, the coordinator no longer has a tree.
    pub fn take_shamap(&mut self) -> SHAMap {
        let replacement = match &self.backend {
            Some(b) => SHAMap::with_backend(MapType::AccountState, b.clone()),
            None => SHAMap::new_state(),
        };
        std::mem::replace(&mut self.shamap, replacement)
    }

    /// Root hash of the SHAMap.
    pub fn root_hash(&mut self) -> [u8; 32] {
        self.shamap.root_hash()
    }

    // ── Convenience accessors ────────────────────────────────────────────────

    pub fn ledger_seq(&self) -> u32 { self.peer.ledger_seq }
    pub fn ledger_hash(&self) -> &[u8; 32] { &self.peer.ledger_hash }
    pub fn active(&self) -> bool { self.peer.active }
    pub fn set_active(&mut self, v: bool) { self.peer.active = v; }
    pub fn in_flight(&self) -> usize {
        self.peer.outstanding_cookie_count() + self.peer.outstanding_object_query_count()
    }
    pub fn inner_count(&self) -> usize { self.peer.inner_count }
    pub fn leaf_count(&self) -> usize { self.peer.leaf_count }
    pub fn set_leaf_count(&mut self, v: usize) { self.peer.leaf_count = v; }
    pub fn pass_number(&self) -> u32 { self.peer.pass_number }
    pub fn new_objects_this_pass(&self) -> usize { self.peer.new_objects_this_pass() }
    pub fn stalled_retries(&self) -> u32 { self.peer.stalled_retries }
    pub fn set_stalled_retries(&mut self, v: u32) { self.peer.stalled_retries = v; }
    pub fn tail_stuck_hash(&self) -> [u8; 32] { self.peer.tail_stuck_hash }
    pub fn set_tail_stuck_hash(&mut self, v: [u8; 32]) { self.peer.tail_stuck_hash = v; }
    pub fn tail_stuck_retries(&self) -> u32 { self.peer.tail_stuck_retries }
    pub fn set_tail_stuck_retries(&mut self, v: u32) { self.peer.tail_stuck_retries = v; }
}

// Use shamap_sync module
use crate::ledger::shamap_sync as sync_shamap;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn timeout_object_request_records_hash_and_cookie_mappings() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);

        let request = coordinator
            .build_timeout_object_request()
            .expect("missing child hash should produce a GetObjects request");

        assert_eq!(request.msg_type, crate::network::message::MessageType::GetObjects);

        let pb = crate::proto::TmGetObjectByHash::decode(request.payload.as_slice())
            .expect("GetObjects request should decode");
        let seq = pb.seq.expect("request should include a cookie");
        let cookie_nodeids = coordinator
            .pending_object_cookies
            .get(&(seq as u32))
            .expect("cookie mapping should be retained");

        assert!(!pb.objects.is_empty());
        assert_eq!(pb.objects.len(), cookie_nodeids.len());
        assert_eq!(pb.objects.len(), coordinator.pending_object_nodeids.len());

        for (index, object) in pb.objects.iter().enumerate() {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(object.hash.as_ref().expect("object should carry hash"));
            let node_id = object.node_id.as_ref().expect("object should carry node id");

            assert_eq!(&cookie_nodeids[index][..], node_id.as_slice());
            assert_eq!(
                &coordinator.pending_object_nodeids.get(&hash).expect("hash mapping must exist")[..],
                node_id.as_slice(),
            );
        }
    }
}
