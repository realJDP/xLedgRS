//! State-tree synchronization coordinator.
//!
//! The coordinator owns the SHAMap for the duration of sync and hands it off
//! once acquisition completes.

use std::sync::Arc;

use crate::ledger::full_below_cache::FullBelowCache;
use crate::ledger::node_store::NodeStore;
use crate::ledger::shamap::{MapType, SHAMap};
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

pub struct ObjectResponseHandling {
    pub accepted: bool,
    pub followup_reqs: Vec<RtxpMessage>,
    pub sync_seq: u32,
}

pub enum TimeoutHandling {
    Progress,
    RestartPass {
        progress_this_pass: usize,
        timeout_count: u32,
    },
    Deactivate {
        timeout_count: u32,
    },
    Request {
        timeout_count: u32,
        use_object_fallback: bool,
        reqs: Vec<RtxpMessage>,
    },
    NoRequest {
        timeout_count: u32,
        use_object_fallback: bool,
    },
}

/// Orchestrates state tree sync. Owns the SHAMap exclusively during sync.
pub struct SyncCoordinator {
    /// Peer coordination — requests, cookies, stall detection.
    pub peer: PeerSyncManager,
    /// SHAMap owned exclusively by the coordinator during sync.
    shamap: SHAMap,
    /// Tracks subtree completion.
    full_below: FullBelowCache,
    /// Direct NuDB backend used for leaf writes outside the sync lock.
    backend: Option<Arc<dyn NodeStore>>,
    /// Full header for the ledger currently being synchronized.
    /// Preserved for follower handoff so it has a concrete parent header.
    pub sync_header: crate::ledger::LedgerHeader,
    /// Maps node hashes to SHAMapNodeID values for GetObjects responses.
    /// Populated by `build_timeout_object_request()` and consumed by the
    /// response handler to reconstruct tree positions.
    pub pending_object_nodeids: std::collections::HashMap<[u8; 32], [u8; 33]>,
    /// Maps request cookies to ordered wire node IDs for GetObjects requests.
    /// Used when peers omit hash, index, or node_id fields in responses.
    pub pending_object_cookies: std::collections::HashMap<u32, Vec<[u8; 33]>>,
    /// Useful-node count observed at the last retarget.
    retarget_progress_count: usize,
    /// Consecutive retargets without leaf progress.
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
            retarget_progress_count: 0,
            stale_retarget_count: 0,
        }
    }

    /// Process a single peer response.
    pub fn process_response(&mut self, ld: &crate::proto::TmLedgerData) -> SyncProgress {
        let parsed = self.peer.parse_response(ld);
        self.process_parsed_response(parsed)
    }

    /// Apply a previously parsed peer response to the SHAMap.
    pub fn process_parsed_response(
        &mut self,
        parsed: crate::sync::ParsedSyncResponse,
    ) -> SyncProgress {
        let mut inner_count = 0;
        let mut leaf_count = 0;

        // Insert nodes into the SHAMap.
        let mut dup_count = 0usize;
        let mut inv_count = 0usize;
        for (node_id, wire_data) in &parsed.nodes {
            let wire_type = wire_data.last().copied().unwrap_or(0);
            let result = sync_shamap::add_known_node(
                &mut self.shamap.root,
                node_id,
                wire_data,
                MapType::AccountState,
                self.backend.as_ref(),
                &mut self.full_below,
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
                parsed.nodes.len(),
                inner_count + leaf_count,
                inner_count,
                leaf_count,
                dup_count,
                inv_count,
            );
        }

        self.peer.inner_count += inner_count;
        self.peer.leaf_count += leaf_count;
        if inner_count + leaf_count > 0 {
            self.peer.note_progress();
        }

        // NuDB leaf writes are deferred and returned in SyncProgress.leaves
        // so the caller can persist them outside the sync lock.

        SyncProgress {
            inner_received: inner_count,
            leaf_received: leaf_count,
            pending: 0,
            total_inner: self.peer.inner_count,
            total_leaf: self.peer.leaf_count,
            leaves: parsed.leaves,
        }
    }

    /// Build the next sync request from missing nodes.
    pub fn build_next_request(&mut self, reason: SyncRequestReason) -> Vec<RtxpMessage> {
        let missing = self.get_missing(crate::ledger::inbound::MISSING_NODES_FIND);
        self.peer.build_requests_from_missing(&missing, reason)
    }

    /// Build up to `n` separate requests, each with different missing nodes.
    /// Matches rippled's trigger pattern: each peer request performs its own
    /// `getMissingNodes(256)` walk plus filtering.
    pub fn build_multi_requests(
        &mut self,
        n: usize,
        reason: SyncRequestReason,
    ) -> Vec<RtxpMessage> {
        let mut reqs = Vec::new();
        for _ in 0..n {
            let next = self.build_next_request(reason);
            if next.is_empty() {
                break;
            }
            reqs.extend(next);
        }
        reqs
    }

    /// Build timeout request.
    pub fn build_timeout_request(&mut self) -> Vec<RtxpMessage> {
        // Keep timeout recovery cheap. The timer path should not hold the
        // sync mutex across another full-tree scan just to emit a 12-node
        // request.
        let missing = self.get_missing(crate::ledger::inbound::REQ_NODES_TIMEOUT);
        self.peer
            .build_requests_from_missing(&missing, SyncRequestReason::Timeout)
    }

    /// Build a timeout object request (`GetObjects` for stuck nodes).
    /// Stores hash-to-node ID mappings for response handling.
    pub fn build_timeout_object_request(&mut self) -> Option<RtxpMessage> {
        // Request only a small set of missing state-node hashes rather than
        // the full tail frontier.
        let missing = self.get_missing(usize::from(
            crate::ledger::inbound::LEDGER_BECOME_AGGRESSIVE_THRESHOLD,
        ));
        if missing.is_empty() {
            tracing::info!("timeout getobjects request: no missing hashes available");
            return None;
        }

        // Store hash-to-wire-node mappings for response processing.
        // Clear stale mappings first; the map is bounded to the current
        // request set.
        self.pending_object_nodeids.clear();
        let nodes: Vec<([u8; 32], [u8; 33])> = missing
            .iter()
            .map(|(nid, hash)| {
                self.pending_object_nodeids.insert(*hash, nid.to_wire());
                (*hash, nid.to_wire())
            })
            .collect();
        let seq = crate::sync::next_cookie() as u32;
        self.peer.outstanding_object_queries.insert(seq);
        self.pending_object_cookies
            .insert(seq, nodes.iter().map(|(_, nid)| *nid).collect());
        let preview: Vec<String> = nodes
            .iter()
            .take(4)
            .map(|(hash, nid)| format!("{}@d{}", hex::encode_upper(&hash[..8]), nid[32]))
            .collect();
        tracing::info!(
            "timeout getobjects request: seq={} count={} preview=[{}]",
            seq,
            nodes.len(),
            preview.join(", ")
        );

        Some(crate::network::relay::encode_get_state_nodes_by_hash(
            &self.peer.ledger_hash,
            &nodes,
            self.peer.ledger_seq,
            seq,
        ))
    }

    fn clear_request_tracking(&mut self) {
        self.peer.outstanding_cookies.clear();
        self.peer.outstanding_object_queries.clear();
        self.peer.responded_cookies.clear();
        self.peer.responded_object_queries.clear();
        self.pending_object_nodeids.clear();
        self.pending_object_cookies.clear();
    }

    pub fn handle_object_response(
        &mut self,
        ledger_hash: &[u8],
        request_cookie: Option<u32>,
        imported_count: usize,
    ) -> ObjectResponseHandling {
        let accepted = self
            .peer
            .accept_object_response(ledger_hash, request_cookie);
        if !accepted {
            return ObjectResponseHandling {
                accepted: false,
                followup_reqs: Vec::new(),
                sync_seq: 0,
            };
        }

        if let Some(seq) = request_cookie {
            self.pending_object_cookies.remove(&seq);
        }
        if imported_count > 0 {
            self.peer.note_object_rescue_progress();
        }
        if !self.active() || imported_count == 0 {
            return ObjectResponseHandling {
                accepted: true,
                followup_reqs: Vec::new(),
                sync_seq: 0,
            };
        }

        ObjectResponseHandling {
            accepted: true,
            followup_reqs: self.build_multi_requests(3, crate::sync::SyncRequestReason::Reply),
            sync_seq: self.ledger_seq(),
        }
    }

    pub fn handle_timeout_tick(&mut self, max_stalled_retries: u32) -> TimeoutHandling {
        let timeout_count = match self.peer.on_timer_tick() {
            Some(crate::ledger::inbound::TimeoutTick::Progress) => {
                return TimeoutHandling::Progress;
            }
            Some(crate::ledger::inbound::TimeoutTick::Timeout(timeouts)) => timeouts,
            None => return TimeoutHandling::Progress,
        };

        if self.is_pass_complete() {
            let progress_this_pass = self.new_objects_this_pass();
            self.peer.start_new_pass();
            self.reset_pass_pressure();
            self.clear_request_tracking();
            self.peer.clear_recent();
            return TimeoutHandling::RestartPass {
                progress_this_pass,
                timeout_count,
            };
        }

        if timeout_count > max_stalled_retries {
            self.set_active(false);
            self.peer.mark_failed();
            self.peer.by_hash_armed = false;
            self.peer.clear_recent();
            self.peer.reset_in_flight();
            self.clear_request_tracking();
            return TimeoutHandling::Deactivate { timeout_count };
        }

        self.set_stalled_retries(timeout_count);
        self.peer.by_hash_armed = true;
        let use_object_fallback =
            self.peer.by_hash_armed && timeout_count > 4 && *self.ledger_hash() != [0u8; 32];
        let reqs = if use_object_fallback {
            self.peer.by_hash_armed = false;
            self.build_timeout_object_request().into_iter().collect()
        } else {
            self.build_timeout_request()
        };
        if reqs.is_empty() {
            TimeoutHandling::NoRequest {
                timeout_count,
                use_object_fallback,
            }
        } else {
            TimeoutHandling::Request {
                timeout_count,
                use_object_fallback,
                reqs,
            }
        }
    }

    /// Find missing nodes in the SHAMap.
    pub fn get_missing(
        &mut self,
    max: usize,
    ) -> Vec<(crate::ledger::shamap_id::SHAMapNodeID, [u8; 32])> {
        self.get_missing_report(max).missing
    }

    pub(crate) fn get_missing_report(
        &mut self,
        max: usize,
    ) -> crate::ledger::shamap_sync::MissingNodesReport {
        sync_shamap::get_missing_nodes_report(
            &mut self.shamap.root,
            max,
            MapType::AccountState,
            self.backend.as_ref(),
            &mut self.full_below,
        )
    }

    /// Retarget to a new ledger without dropping the tree structure.
    /// The SHAMap inner nodes are 99.99% the same across ledgers — only
    /// changed branches differ. Retargeting avoids re-downloading the
    /// entire tree structure from scratch.
    pub fn retarget(
        &mut self,
        seq: u32,
        hash: [u8; 32],
        account_hash: [u8; 32],
        header: crate::ledger::LedgerHeader,
    ) {
        // Track stale retargets using useful-node progress rather than leaves
        // alone.
        let current_progress = self.peer.inner_count + self.peer.leaf_count;
        if current_progress <= self.retarget_progress_count && self.retarget_progress_count > 0 {
            self.stale_retarget_count += 1;
        } else {
            self.stale_retarget_count = 0;
        }
        self.retarget_progress_count = current_progress;

        tracing::info!(
            "sync retarget: {} → {} (keeping {} inner nodes, stale_count={})",
            self.peer.ledger_seq,
            seq,
            self.peer.inner_count,
            self.stale_retarget_count,
        );
        self.peer.ledger_hash = hash;
        self.peer.ledger_seq = seq;
        self.peer.account_hash = account_hash;
        self.peer.active = true;
        self.peer.stalled_retries = 0;
        self.peer.recent_nodes.clear();
        self.clear_request_tracking();
        self.peer.last_response = std::time::Instant::now();
        self.peer.last_new_nodes = std::time::Instant::now();
        self.peer.tail_stuck_hash = [0u8; 32];
        self.peer.tail_stuck_retries = 0;
        // Clear the full_below cache because subtree completeness changes with
        // the new root hash.
        self.full_below = FullBelowCache::new(524_288);
        // Retain the SHAMap tree; inner nodes remain reusable.
        self.sync_header = header;
    }

    /// Check if sync is complete.
    ///
    /// In normal mode: root hash must match `account_hash` from the target header.
    /// In ltCLOSED mode (`ledger_hash == [0;32]`): the tree is filled from peers'
    /// current validated ledger. Completion requires a fresh validated header
    /// whose `account_hash` matches the computed root. The caller must supply
    /// this via `offer_validated_header()` before `is_complete` can return true.
    pub fn is_complete(&mut self) -> bool {
        // A tree with no branches is empty, not complete.
        if self.shamap.root.is_branch == 0 {
            return false;
        }
        // At least one leaf must have been downloaded.
        if self.peer.leaf_count == 0 {
            return false;
        }
        // No nodes may remain missing.
        let report = self.get_missing_report(16);
        if report.backend_fetch_errors > 0 {
            tracing::warn!(
                "is_complete: blocked by {} backend fetch error(s)",
                report.backend_fetch_errors
            );
            return false;
        }
        if !report.missing.is_empty() {
            tracing::debug!(
                "is_complete: {} missing nodes (first: {})",
                report.missing.len(),
                hex::encode_upper(&report.missing[0].1[..8])
            );
            return false;
        }
        // Verify that the root hash matches the target account hash.
        let root = self.root_hash();
        let matches = root == self.peer.account_hash;
        if matches {
            tracing::info!(
                "is_complete: missing=0 root={} target={} match=true",
                hex::encode_upper(&root[..8]),
                hex::encode_upper(&self.peer.account_hash[..8])
            );
        } else if self.peer.ledger_hash == [0u8; 32] {
            // In ltCLOSED mode, the tree is filled from peers' current validated
            // ledger. The root will not match the original target, so completion
            // remains false until offer_validated_header() rebinds the target.
            tracing::info!(
                "is_complete: ltCLOSED mode, missing=0, root={} (target mismatch — awaiting validated header rebind)",
                hex::encode_upper(&root[..8]),
            );
        } else {
            tracing::info!(
                "is_complete: missing=0 root={} target={} match=false",
                hex::encode_upper(&root[..8]),
                hex::encode_upper(&self.peer.account_hash[..8])
            );
        }
        matches
    }

    /// In ltCLOSED mode, offer a validated header to rebind the sync target.
    /// If the header's `account_hash` matches the computed root hash,
    /// atomically update all target metadata and return true.
    /// Called by the liBASE/validation handler when new validated headers arrive.
    pub fn offer_validated_header(&mut self, header: &crate::ledger::LedgerHeader) -> bool {
        // Only relevant in ltCLOSED mode.
        if self.peer.ledger_hash != [0u8; 32] {
            return false;
        }
        // No nodes may remain missing.
        let report = self.get_missing_report(1);
        if report.backend_fetch_errors > 0 || !report.missing.is_empty() {
            return false;
        }
        let root = self.root_hash();
        if root != header.account_hash {
            return false;
        }
        // Match: atomically rebind all target metadata.
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
        if self.is_complete() {
            return true;
        }
        if self.get_missing_report(1).backend_fetch_errors > 0 {
            return false;
        }
        self.peer.new_objects_this_pass() == 0 && self.peer.last_new_nodes.elapsed().as_secs() > 10
    }

    /// Count of missing nodes (diagnostics).
    pub fn pending_count(&mut self) -> usize {
        let report = self.get_missing_report(256);
        report.missing.len().saturating_add(report.backend_fetch_errors)
    }

    /// Restart for a new ledger.
    pub fn restart(&mut self, seq: u32, hash: [u8; 32], account_hash: [u8; 32]) {
        self.peer = PeerSyncManager::new(seq, hash, account_hash);
        self.shamap = match &self.backend {
            Some(b) => SHAMap::with_backend(MapType::AccountState, b.clone()),
            None => SHAMap::new_state(),
        };
        self.full_below.next_generation();
        self.pending_object_nodeids.clear();
        self.pending_object_cookies.clear();
        self.retarget_progress_count = 0;
        self.stale_retarget_count = 0;
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

    pub fn ledger_seq(&self) -> u32 {
        self.peer.ledger_seq
    }
    pub fn ledger_hash(&self) -> &[u8; 32] {
        &self.peer.ledger_hash
    }
    pub fn account_hash(&self) -> [u8; 32] {
        self.peer.account_hash
    }
    pub fn active(&self) -> bool {
        self.peer.active
    }
    pub fn set_active(&mut self, v: bool) {
        self.peer.active = v;
    }
    pub fn in_flight(&self) -> usize {
        self.peer.in_flight
            + self.peer.outstanding_cookie_count()
            + self.peer.outstanding_object_query_count()
    }
    pub fn inner_count(&self) -> usize {
        self.peer.inner_count
    }
    pub fn leaf_count(&self) -> usize {
        self.peer.leaf_count
    }
    pub fn set_leaf_count(&mut self, v: usize) {
        self.peer.leaf_count = v;
    }
    pub fn pass_number(&self) -> u32 {
        self.peer.pass_number
    }
    pub fn new_objects_this_pass(&self) -> usize {
        self.peer.new_objects_this_pass()
    }
    pub fn stalled_retries(&self) -> u32 {
        self.peer.stalled_retries
    }
    pub fn set_stalled_retries(&mut self, v: u32) {
        self.peer.stalled_retries = v;
    }
    pub fn tail_stuck_hash(&self) -> [u8; 32] {
        self.peer.tail_stuck_hash
    }
    pub fn set_tail_stuck_hash(&mut self, v: [u8; 32]) {
        self.peer.tail_stuck_hash = v;
    }
    pub fn tail_stuck_retries(&self) -> u32 {
        self.peer.tail_stuck_retries
    }
    pub fn set_tail_stuck_retries(&mut self, v: u32) {
        self.peer.tail_stuck_retries = v;
    }

    fn reset_pass_pressure(&mut self) {
        self.peer.stalled_retries = 0;
        self.peer.by_hash_armed = false;
        self.peer.tail_stuck_hash = [0u8; 32];
        self.peer.tail_stuck_retries = 0;
        self.peer.timeout.timeouts = 0;
    }

    /// Stop the current sync session and clear all transient request state.
    /// This is the explicit abort path, separate from restart().
    pub fn stop(&mut self) {
        self.set_active(false);
        self.peer.mark_failed();
        self.peer.by_hash_armed = false;
        self.peer.clear_recent();
        self.peer.reset_in_flight();
        self.clear_request_tracking();
        self.peer.timeout.timeouts = 0;
        self.peer.stalled_retries = 0;
        self.peer.tail_stuck_hash = [0u8; 32];
        self.peer.tail_stuck_retries = 0;
        self.retarget_progress_count = 0;
        self.stale_retarget_count = 0;
    }
}

// Sync tree mutation helpers live in shamap_sync.
use crate::ledger::shamap_sync as sync_shamap;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::sync::Arc;

    fn make_inner_wire(hashes: &[[u8; 32]; 16]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(16 * 32 + 1);
        for h in hashes {
            wire.extend_from_slice(h);
        }
        wire.push(0x02);
        wire
    }

    #[test]
    fn timeout_object_request_matches_rippled_shape_and_keeps_local_mappings() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);

        let request = coordinator
            .build_timeout_object_request()
            .expect("missing child hash should produce a GetObjects request");

        assert_eq!(
            request.msg_type,
            crate::network::message::MessageType::GetObjects
        );

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
        assert!(pb.objects.len() <= 4);

        for (index, object) in pb.objects.iter().enumerate() {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(object.hash.as_ref().expect("object should carry hash"));
            assert!(
                object.node_id.is_none(),
                "rippled's GetObjects requests carry hashes, not node IDs"
            );
            assert_eq!(
                &coordinator
                    .pending_object_nodeids
                    .get(&hash)
                    .expect("hash mapping must exist")[..],
                &cookie_nodeids[index][..],
            );
        }
    }

    #[test]
    fn build_multi_requests_splits_reply_work_across_multiple_requests() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);

        let mut root_hashes = [[0u8; 32]; 16];
        for branch in 0..16u8 {
            let mut child_hashes = [[0u8; 32]; 16];
            for child_branch in 0..16u8 {
                let mut grandchild_hash = [0u8; 32];
                grandchild_hash[30] = branch;
                grandchild_hash[31] = child_branch + 1;
                child_hashes[child_branch as usize] = grandchild_hash;
            }
            let child_wire = make_inner_wire(&child_hashes);
            let mut payload = Vec::with_capacity(4 + 16 * 32);
            payload.extend_from_slice(&crate::ledger::shamap::PREFIX_INNER_NODE);
            payload.extend_from_slice(&child_wire[..child_wire.len() - 1]);
            let child_hash = crate::crypto::sha512_first_half(&payload);
            root_hashes[branch as usize] = child_hash;
        }
        let root_wire = make_inner_wire(&root_hashes);
        assert_eq!(
            crate::ledger::shamap_sync::add_known_node(
                &mut coordinator.shamap.root,
                &crate::ledger::shamap_id::SHAMapNodeID::root(),
                &root_wire,
                MapType::AccountState,
                None,
                &mut coordinator.full_below,
            ),
            crate::ledger::shamap_sync::AddNodeResult::Useful
        );

        for branch in 0..16u8 {
            let mut child_hashes = [[0u8; 32]; 16];
            for child_branch in 0..16u8 {
                let mut grandchild_hash = [0u8; 32];
                grandchild_hash[30] = branch;
                grandchild_hash[31] = child_branch + 1;
                child_hashes[child_branch as usize] = grandchild_hash;
            }
            let child_wire = make_inner_wire(&child_hashes);
            assert_eq!(
                crate::ledger::shamap_sync::add_known_node(
                    &mut coordinator.shamap.root,
                    &crate::ledger::shamap_id::SHAMapNodeID::root().child_id(branch),
                    &child_wire,
                    MapType::AccountState,
                    None,
                    &mut coordinator.full_below,
                ),
                crate::ledger::shamap_sync::AddNodeResult::Useful
            );
        }

        let reqs = coordinator.build_multi_requests(3, SyncRequestReason::Reply);
        assert_eq!(reqs.len(), 2);

        let mut seen = std::collections::HashSet::new();
        for req in reqs {
            let pb = crate::proto::TmGetLedger::decode(req.payload.as_slice())
                .expect("GetLedger request should decode");
            assert_eq!(pb.node_i_ds.len(), 128);
            for node_id in pb.node_i_ds {
                assert!(
                    seen.insert(node_id),
                    "each request should target distinct node IDs"
                );
            }
        }
    }

    struct ErrorStore;

    impl crate::ledger::node_store::NodeStore for ErrorStore {
        fn store(&self, _hash: &[u8; 32], _data: &[u8]) -> std::io::Result<()> {
            Ok(())
        }

        fn fetch(&self, _hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
            Err(std::io::Error::other("forced backend fault"))
        }
    }

    #[test]
    fn is_complete_stays_false_when_backend_fetch_faults_block_tree_walk() {
        let header = crate::ledger::LedgerHeader::default();
        let backend: Arc<dyn crate::ledger::node_store::NodeStore> = Arc::new(ErrorStore);
        let mut coordinator =
            SyncCoordinator::new(10, [0x11; 32], [0x22; 32], Some(backend), header);
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);
        coordinator.peer.leaf_count = 1;

        let report = coordinator.get_missing_report(16);
        assert!(report.missing.is_empty());
        assert_eq!(report.backend_fetch_errors, 1);
        assert!(!coordinator.is_complete());
    }

    #[test]
    fn pending_count_treats_backend_fetch_faults_as_unresolved_work() {
        let header = crate::ledger::LedgerHeader::default();
        let backend: Arc<dyn crate::ledger::node_store::NodeStore> = Arc::new(ErrorStore);
        let mut coordinator =
            SyncCoordinator::new(10, [0x11; 32], [0x22; 32], Some(backend), header);
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);

        assert_eq!(coordinator.pending_count(), 1);
    }

    #[test]
    fn handle_object_response_removes_cookie_and_accepts_progress() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        let cookie = crate::sync::next_cookie() as u32;
        coordinator.peer.outstanding_object_queries.insert(cookie);
        coordinator.pending_object_cookies.insert(cookie, vec![[0; 33]]);

        let outcome = coordinator.handle_object_response(&[0x11; 32], Some(cookie), 1);
        assert!(outcome.accepted);
        assert_eq!(outcome.sync_seq, 10);
        assert!(!coordinator.pending_object_cookies.contains_key(&cookie));
    }

    #[test]
    fn handle_object_response_rejects_wrong_hash() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        let cookie = crate::sync::next_cookie() as u32;
        coordinator.peer.outstanding_object_queries.insert(cookie);

        let outcome = coordinator.handle_object_response(&[0x99; 32], Some(cookie), 1);
        assert!(!outcome.accepted);
        assert_eq!(outcome.sync_seq, 0);
        assert!(outcome.followup_reqs.is_empty());
    }

    #[test]
    fn handle_timeout_tick_deactivates_after_max_retries() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        let mut outcome = TimeoutHandling::Progress;
        for _ in 0..7 {
            outcome = coordinator.handle_timeout_tick(6);
        }
        match outcome {
            TimeoutHandling::Deactivate { timeout_count } => assert_eq!(timeout_count, 7),
            _ => panic!("expected deactivate outcome"),
        }
        assert!(!coordinator.active());
    }

    #[test]
    fn handle_timeout_tick_arms_object_fallback_on_historical_target() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);
        let mut outcome = TimeoutHandling::Progress;
        for _ in 0..5 {
            outcome = coordinator.handle_timeout_tick(6);
        }
        match outcome {
            TimeoutHandling::Request {
                timeout_count,
                use_object_fallback,
                ..
            } => {
                assert_eq!(timeout_count, 5);
                assert!(use_object_fallback);
            }
            _ => panic!("expected timeout request outcome"),
        }
    }

    #[test]
    fn handle_timeout_tick_restart_pass_clears_stale_object_query_state() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        let cookie = crate::sync::next_cookie() as u32;
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);
        coordinator.peer.stalled_retries = 4;
        coordinator.peer.by_hash_armed = true;
        coordinator.peer.tail_stuck_hash = [0xCC; 32];
        coordinator.peer.tail_stuck_retries = 3;
        coordinator.peer.timeout.timeouts = 5;
        coordinator.peer.last_new_nodes -= std::time::Duration::from_secs(11);
        coordinator.peer.outstanding_cookies.insert(cookie);
        coordinator.peer.outstanding_object_queries.insert(cookie);
        coordinator.peer.responded_cookies.insert(cookie.wrapping_add(1));
        coordinator.peer.responded_object_queries.insert(cookie);
        coordinator
            .pending_object_nodeids
            .insert([0xAA; 32], [0xBB; 33]);
        coordinator
            .pending_object_cookies
            .insert(cookie, vec![[0xBB; 33]]);

        let outcome = coordinator.handle_timeout_tick(6);
        match outcome {
            TimeoutHandling::RestartPass { .. } => {}
            _ => panic!("expected restart pass outcome"),
        }

        assert!(coordinator.peer.outstanding_cookies.is_empty());
        assert!(coordinator.peer.outstanding_object_queries.is_empty());
        assert!(coordinator.peer.responded_cookies.is_empty());
        assert!(coordinator.peer.responded_object_queries.is_empty());
        assert_eq!(coordinator.peer.stalled_retries, 0);
        assert!(!coordinator.peer.by_hash_armed);
        assert_eq!(coordinator.peer.tail_stuck_hash, [0u8; 32]);
        assert_eq!(coordinator.peer.tail_stuck_retries, 0);
        assert_eq!(coordinator.peer.timeout.timeouts, 0);
        assert!(coordinator.pending_object_nodeids.is_empty());
        assert!(coordinator.pending_object_cookies.is_empty());
    }

    #[test]
    fn restart_clears_stale_object_cookie_mappings() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        let cookie = crate::sync::next_cookie() as u32;
        coordinator
            .pending_object_nodeids
            .insert([0xAA; 32], [0xBB; 33]);
        coordinator
            .pending_object_cookies
            .insert(cookie, vec![[0xBB; 33]]);

        coordinator.restart(11, [0x33; 32], [0x44; 32]);

        assert!(coordinator.pending_object_nodeids.is_empty());
        assert!(coordinator.pending_object_cookies.is_empty());
        assert_eq!(coordinator.retarget_progress_count, 0);
        assert_eq!(coordinator.stale_retarget_count, 0);
    }

    #[test]
    fn stop_clears_stale_object_cookie_mappings_and_deactivates() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        let cookie = crate::sync::next_cookie() as u32;
        coordinator.peer.by_hash_armed = true;
        coordinator.peer.stalled_retries = 3;
        coordinator.peer.tail_stuck_hash = [0xCC; 32];
        coordinator.peer.tail_stuck_retries = 2;
        coordinator.peer.outstanding_cookies.insert(cookie);
        coordinator.peer.outstanding_object_queries.insert(cookie);
        coordinator.pending_object_nodeids.insert([0xAA; 32], [0xBB; 33]);
        coordinator
            .pending_object_cookies
            .insert(cookie, vec![[0xBB; 33]]);

        coordinator.stop();

        assert!(!coordinator.active());
        assert!(coordinator.peer.timeout.failed);
        assert!(coordinator.peer.outstanding_cookies.is_empty());
        assert!(coordinator.peer.outstanding_object_queries.is_empty());
        assert!(coordinator.pending_object_nodeids.is_empty());
        assert!(coordinator.pending_object_cookies.is_empty());
        assert_eq!(coordinator.peer.stalled_retries, 0);
        assert_eq!(coordinator.peer.tail_stuck_hash, [0u8; 32]);
        assert_eq!(coordinator.peer.tail_stuck_retries, 0);
    }
}
