//! State-tree synchronization coordinator.
//!
//! The coordinator owns the SHAMap for the duration of sync and hands it off
//! once acquisition completes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ledger::full_below_cache::FullBelowCache;
use crate::ledger::node_store::NodeStore;
use crate::ledger::shamap::{MapType, SHAMap};
use crate::ledger::shamap_sync::AddNodeResult;
use crate::network::message::RtxpMessage;
use crate::sync::{PeerSyncManager, SyncRequestReason};

const REQUEST_WALK_VISIT_BUDGET: usize = 16_384;
const OBJECT_REQUEST_WALK_VISIT_BUDGET: usize = 65_536;
const BACKEND_READ_WINDOW: usize = 64;

/// Progress report from processing responses.
pub struct SyncProgress {
    pub inner_received: usize,
    pub leaf_received: usize,
    pub pending: usize,
    pub total_inner: usize,
    pub total_leaf: usize,
    pub inner_nodes: Vec<([u8; 32], Vec<u8>)>,
    pub leaves: Vec<(Vec<u8>, Vec<u8>)>,
}

pub struct ObjectResponseHandling {
    pub accepted: bool,
    pub followup_reqs: Vec<RtxpMessage>,
    pub sync_seq: u32,
}

pub struct CompletionCheckSnapshot {
    pub ledger_seq: u32,
    pub ledger_hash: [u8; 32],
    pub account_hash: [u8; 32],
    pub acquisition_epoch: u64,
    shamap: SHAMap,
}

pub struct CompletionCheckResult {
    pub ledger_seq: u32,
    pub ledger_hash: [u8; 32],
    pub account_hash: [u8; 32],
    pub acquisition_epoch: u64,
    pub blocker: Option<CompletionBlocker>,
}

pub struct ReplyFollowupFrontierSnapshot {
    ledger_seq: u32,
    ledger_hash: [u8; 32],
    account_hash: [u8; 32],
    acquisition_epoch: u64,
    shamap: SHAMap,
    request_count: usize,
}

pub struct ReplyFollowupFrontier {
    ledger_seq: u32,
    ledger_hash: [u8; 32],
    account_hash: [u8; 32],
    acquisition_epoch: u64,
    missing: Vec<(crate::ledger::shamap_id::SHAMapNodeID, [u8; 32])>,
    request_count: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SyncCoordinatorStats {
    pub full_below: usize,
    pub recent_nodes: usize,
    pub outstanding_cookies: usize,
    pub outstanding_object_queries: usize,
    pub responded_cookies: usize,
    pub responded_object_queries: usize,
    pub pending_object_nodeids: usize,
    pub pending_object_cookies: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionBlocker {
    EmptyTree,
    BackendFetchErrors {
        count: usize,
    },
    MissingNodes {
        count: usize,
        first_hash: [u8; 32],
        first_depth: u8,
    },
    RootMismatch {
        root: [u8; 32],
        target: [u8; 32],
    },
}

pub enum TimeoutHandling {
    Progress,
    RestartPass {
        progress_this_pass: usize,
        timeout_count: u32,
        reqs: Vec<RtxpMessage>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutRequestKind {
    Ledger,
    Objects,
}

pub struct TimeoutRequestSnapshot {
    pub ledger_seq: u32,
    pub ledger_hash: [u8; 32],
    pub account_hash: [u8; 32],
    pub acquisition_epoch: u64,
    pub request_kind: TimeoutRequestKind,
    pub object_batch_size: usize,
    shamap: SHAMap,
}

pub struct TimeoutRequestFrontier {
    pub ledger_seq: u32,
    pub ledger_hash: [u8; 32],
    pub account_hash: [u8; 32],
    pub acquisition_epoch: u64,
    pub request_kind: TimeoutRequestKind,
    missing: Vec<(crate::ledger::shamap_id::SHAMapNodeID, [u8; 32])>,
}

pub enum TimeoutPlan {
    Progress,
    RestartPass {
        progress_this_pass: usize,
        timeout_count: u32,
        request: Option<TimeoutRequestSnapshot>,
    },
    Deactivate {
        timeout_count: u32,
    },
    Request {
        timeout_count: u32,
        use_object_fallback: bool,
        request: Option<TimeoutRequestSnapshot>,
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
    /// Legacy diagnostics map for old object-query cookies. Current rippled
    /// peers do not send object cookies, so response matching is ledger/hash
    /// based and this stays empty for new requests.
    pub pending_object_cookies: std::collections::HashMap<u32, Vec<[u8; 33]>>,
    /// Useful-node count observed at the last retarget.
    retarget_progress_count: usize,
    /// Consecutive retargets without leaf progress.
    pub stale_retarget_count: u32,
    /// Monotonic identity for the current acquisition attempt.
    acquisition_epoch: u64,
    /// Last time we allowed the expensive disk-backed completion walk.
    last_completion_check: Instant,
}

impl SyncCoordinator {
    fn new_state_map_from_backend(
        backend: Option<&Arc<dyn NodeStore>>,
        account_hash: [u8; 32],
    ) -> SHAMap {
        let mut shamap = match backend {
            Some(b) => SHAMap::with_backend(MapType::AccountState, b.clone()),
            None => SHAMap::new_state(),
        };
        if backend.is_some() && account_hash != [0u8; 32] {
            match shamap.load_root_from_hash(account_hash) {
                Ok(true) => tracing::info!(
                    "sync resume: rehydrated SHAMap root {} from backend",
                    hex::encode_upper(&account_hash[..8])
                ),
                Ok(false) => tracing::debug!(
                    "sync resume: SHAMap root {} not present in backend",
                    hex::encode_upper(&account_hash[..8])
                ),
                Err(err) => tracing::warn!(
                    "sync resume: failed to rehydrate SHAMap root {} from backend: {}",
                    hex::encode_upper(&account_hash[..8]),
                    err
                ),
            }
        }
        shamap
    }

    pub fn new(
        seq: u32,
        hash: [u8; 32],
        account_hash: [u8; 32],
        backend: Option<Arc<dyn NodeStore>>,
        header: crate::ledger::LedgerHeader,
    ) -> Self {
        let shamap = Self::new_state_map_from_backend(backend.as_ref(), account_hash);
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
            acquisition_epoch: 0,
            last_completion_check: Instant::now() - Duration::from_secs(60),
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
        let crate::sync::ParsedSyncResponse {
            nodes,
            leaf_nodes,
            leaves,
        } = parsed;
        let mut inner_count = 0;
        let mut leaf_count = 0;
        let mut inner_nodes = Vec::new();
        let mut valid_leaves = Vec::with_capacity(leaves.len());
        let mut pending_leaves = leaves.into_iter();

        // Insert nodes into the SHAMap.
        let mut dup_count = 0usize;
        let mut inv_count = 0usize;
        for (node_id, wire_data) in &nodes {
            let wire_type = wire_data.last().copied().unwrap_or(0);
            let (result, deferred_inner_store) = sync_shamap::add_known_node_deferred_inner_store(
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
                        if let Some(node) = deferred_inner_store {
                            inner_nodes.push(node);
                        }
                    } else {
                        leaf_count += 1;
                    }
                }
                AddNodeResult::Duplicate => dup_count += 1,
                AddNodeResult::Invalid => inv_count += 1,
            }
        }
        for (node_id, content_hash) in &leaf_nodes {
            let pending_leaf = pending_leaves.next();
            let result = sync_shamap::add_known_leaf_hash(
                &mut self.shamap.root,
                node_id,
                *content_hash,
                self.backend.as_ref(),
                &mut self.full_below,
            );
            match result {
                AddNodeResult::Useful => {
                    leaf_count += 1;
                    if let Some(leaf) = pending_leaf {
                        valid_leaves.push(leaf);
                    }
                }
                AddNodeResult::Duplicate => {
                    dup_count += 1;
                    if let Some(leaf) = pending_leaf {
                        valid_leaves.push(leaf);
                    }
                }
                AddNodeResult::Invalid => inv_count += 1,
            }
        }
        let parsed_node_count = nodes.len() + leaf_nodes.len();
        if inv_count > 0 || inner_count > 0 || dup_count > parsed_node_count / 2 {
            tracing::info!(
                "process_response: {} nodes, {} useful ({}i {}l), {} dup, {} inv",
                parsed_node_count,
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
            inner_nodes,
            leaves: valid_leaves,
        }
    }

    /// Build the next sync request from missing nodes.
    pub fn build_next_request(&mut self, reason: SyncRequestReason) -> Vec<RtxpMessage> {
        let missing = self.get_missing_for_request(crate::ledger::inbound::MISSING_NODES_FIND);
        self.peer.build_requests_from_missing(&missing, reason)
    }

    /// Build up to `n` separate requests, each with different missing nodes.
    /// A single larger frontier walk is cheaper than repeating the same
    /// NuDB-backed tree walk once per peer while holding the sync mutex.
    pub fn build_multi_requests(
        &mut self,
        n: usize,
        reason: SyncRequestReason,
    ) -> Vec<RtxpMessage> {
        if n == 0 {
            return Vec::new();
        }

        let per_request = match reason {
            SyncRequestReason::Reply => crate::ledger::inbound::REQ_NODES_REPLY,
            SyncRequestReason::Timeout => crate::ledger::inbound::REQ_NODES_TIMEOUT,
        };
        let max_missing = n
            .saturating_mul(per_request)
            .max(crate::ledger::inbound::MISSING_NODES_FIND);
        let report = self.get_missing_report_for_request(max_missing);
        let mut missing = report.missing;
        if missing.is_empty() {
            let Some(hint) = report.budget_hint else {
                return Vec::new();
            };

            // The bounded NuDB-backed walk can spend its whole visit budget
            // proving local subtrees before it reaches the missing frontier. A
            // budget hint is not proof that the hinted hash is missing, so do
            // one full disk-backed pass before putting anything on the wire.
            tracing::info!(
                "reply request walk hit budget at depth={} hash={} — confirming missing frontier from NuDB",
                hint.0.depth(),
                hex::encode_upper(&hint.1[..8])
            );
            missing = self.get_missing_report(max_missing).missing;
            if missing.is_empty() {
                return Vec::new();
            }
        }

        let mut reqs = Vec::new();
        for chunk in missing.chunks(per_request) {
            let next = self.peer.build_requests_from_missing(chunk, reason);
            if !next.is_empty() {
                reqs.extend(next);
                if reqs.len() >= n {
                    break;
                }
            }
        }
        reqs
    }

    fn build_requests_from_missing_chunks(
        &mut self,
        missing: &[(crate::ledger::shamap_id::SHAMapNodeID, [u8; 32])],
        n: usize,
        reason: SyncRequestReason,
    ) -> Vec<RtxpMessage> {
        if n == 0 {
            return Vec::new();
        }
        let per_request = match reason {
            SyncRequestReason::Reply => crate::ledger::inbound::REQ_NODES_REPLY,
            SyncRequestReason::Timeout => crate::ledger::inbound::REQ_NODES_TIMEOUT,
        };
        let mut reqs = Vec::new();
        for chunk in missing.chunks(per_request) {
            let next = self.peer.build_requests_from_missing(chunk, reason);
            if !next.is_empty() {
                reqs.extend(next);
                if reqs.len() >= n {
                    break;
                }
            }
        }
        reqs
    }

    pub fn reply_followup_frontier_snapshot(
        &self,
        n: usize,
    ) -> Option<ReplyFollowupFrontierSnapshot> {
        if n == 0 || !self.active() {
            return None;
        }
        Some(ReplyFollowupFrontierSnapshot {
            ledger_seq: self.ledger_seq(),
            ledger_hash: *self.ledger_hash(),
            account_hash: self.account_hash(),
            acquisition_epoch: self.acquisition_epoch,
            shamap: self.shamap.clone(),
            request_count: n,
        })
    }

    pub fn walk_reply_followup_frontier(
        mut snapshot: ReplyFollowupFrontierSnapshot,
    ) -> ReplyFollowupFrontier {
        let max_missing = snapshot
            .request_count
            .saturating_mul(crate::ledger::inbound::REQ_NODES_REPLY)
            .max(crate::ledger::inbound::MISSING_NODES_FIND);
        let mut full_below = FullBelowCache::new(524_288);
        let backend = snapshot.shamap.backend().cloned();
        let report = sync_shamap::get_missing_nodes_report_windowed_limited(
            &mut snapshot.shamap.root,
            max_missing,
            MapType::AccountState,
            backend.as_ref(),
            &mut full_below,
            Some(REQUEST_WALK_VISIT_BUDGET),
            BACKEND_READ_WINDOW,
        );
        let mut missing = report.missing;
        if missing.is_empty() {
            if let Some((node_id, hash)) = report.budget_hint {
                tracing::info!(
                    "reply request snapshot walk hit budget at depth={} hash={} — confirming missing frontier from NuDB",
                    node_id.depth(),
                    hex::encode_upper(&hash[..8])
                );
                missing = sync_shamap::get_missing_nodes_report_windowed_limited(
                    &mut snapshot.shamap.root,
                    max_missing,
                    MapType::AccountState,
                    backend.as_ref(),
                    &mut full_below,
                    None,
                    BACKEND_READ_WINDOW,
                )
                .missing;
            }
        }

        ReplyFollowupFrontier {
            ledger_seq: snapshot.ledger_seq,
            ledger_hash: snapshot.ledger_hash,
            account_hash: snapshot.account_hash,
            acquisition_epoch: snapshot.acquisition_epoch,
            missing,
            request_count: snapshot.request_count,
        }
    }

    pub fn build_reply_followup_requests_from_frontier(
        &mut self,
        frontier: ReplyFollowupFrontier,
    ) -> Vec<RtxpMessage> {
        if !self.active()
            || self.ledger_seq() != frontier.ledger_seq
            || *self.ledger_hash() != frontier.ledger_hash
            || self.account_hash() != frontier.account_hash
            || self.acquisition_epoch != frontier.acquisition_epoch
        {
            return Vec::new();
        }

        let reqs = self.build_requests_from_missing_chunks(
            &frontier.missing,
            frontier.request_count,
            SyncRequestReason::Reply,
        );
        if !reqs.is_empty()
            || self.state_request_in_flight() != 0
            || self.peer.recent_node_count() == 0
        {
            return reqs;
        }

        self.peer.clear_recent();
        self.build_requests_from_missing_chunks(
            &frontier.missing,
            frontier.request_count,
            SyncRequestReason::Reply,
        )
    }

    pub fn timeout_request_snapshot(
        &self,
        request_kind: TimeoutRequestKind,
    ) -> Option<TimeoutRequestSnapshot> {
        if !self.active() {
            return None;
        }
        Some(TimeoutRequestSnapshot {
            ledger_seq: self.ledger_seq(),
            ledger_hash: *self.ledger_hash(),
            account_hash: self.account_hash(),
            acquisition_epoch: self.acquisition_epoch,
            request_kind,
            object_batch_size: crate::ledger::inbound::REQ_OBJECTS_TIMEOUT,
            shamap: self.shamap.clone(),
        })
    }

    pub fn timeout_request_snapshot_tuned(
        &self,
        request_kind: TimeoutRequestKind,
        object_batch_size: usize,
    ) -> Option<TimeoutRequestSnapshot> {
        self.timeout_request_snapshot(request_kind)
            .map(|mut snapshot| {
                snapshot.object_batch_size = object_batch_size.clamp(1, 4096);
                snapshot
            })
    }

    pub fn walk_timeout_request_frontier(
        mut snapshot: TimeoutRequestSnapshot,
    ) -> TimeoutRequestFrontier {
        let (max_missing, visit_budget) = match snapshot.request_kind {
            TimeoutRequestKind::Ledger => (
                crate::ledger::inbound::REQ_NODES_TIMEOUT,
                REQUEST_WALK_VISIT_BUDGET,
            ),
            TimeoutRequestKind::Objects => {
                (snapshot.object_batch_size, OBJECT_REQUEST_WALK_VISIT_BUDGET)
            }
        };
        let mut full_below = FullBelowCache::new(524_288);
        let backend = snapshot.shamap.backend().cloned();
        let report = sync_shamap::get_missing_nodes_report_windowed_limited(
            &mut snapshot.shamap.root,
            max_missing,
            MapType::AccountState,
            backend.as_ref(),
            &mut full_below,
            Some(visit_budget),
            BACKEND_READ_WINDOW,
        );
        let mut missing = report.missing;
        if missing.is_empty() {
            if let Some((node_id, hash)) = report.budget_hint {
                tracing::info!(
                    "timeout {:?} snapshot walk hit budget at depth={} hash={} — confirming missing frontier from NuDB",
                    snapshot.request_kind,
                    node_id.depth(),
                    hex::encode_upper(&hash[..8])
                );
                missing = sync_shamap::get_missing_nodes_report_windowed_limited(
                    &mut snapshot.shamap.root,
                    max_missing,
                    MapType::AccountState,
                    backend.as_ref(),
                    &mut full_below,
                    None,
                    BACKEND_READ_WINDOW,
                )
                .missing;
            }
        }

        TimeoutRequestFrontier {
            ledger_seq: snapshot.ledger_seq,
            ledger_hash: snapshot.ledger_hash,
            account_hash: snapshot.account_hash,
            acquisition_epoch: snapshot.acquisition_epoch,
            request_kind: snapshot.request_kind,
            missing,
        }
    }

    pub fn build_timeout_requests_from_frontier(
        &mut self,
        frontier: TimeoutRequestFrontier,
    ) -> Vec<RtxpMessage> {
        if !self.active()
            || self.ledger_seq() != frontier.ledger_seq
            || *self.ledger_hash() != frontier.ledger_hash
            || self.account_hash() != frontier.account_hash
            || self.acquisition_epoch != frontier.acquisition_epoch
        {
            return Vec::new();
        }
        if frontier.missing.is_empty() {
            if frontier.request_kind == TimeoutRequestKind::Objects {
                tracing::info!("timeout getobjects request: no missing hashes available");
            }
            return Vec::new();
        }

        match frontier.request_kind {
            TimeoutRequestKind::Ledger => self.build_requests_from_missing_chunks(
                &frontier.missing,
                1,
                SyncRequestReason::Timeout,
            ),
            TimeoutRequestKind::Objects => {
                let nodes: Vec<([u8; 32], [u8; 33])> = frontier
                    .missing
                    .iter()
                    .map(|(nid, hash)| {
                        self.pending_object_nodeids.insert(*hash, nid.to_wire());
                        (*hash, nid.to_wire())
                    })
                    .collect();
                let preview: Vec<String> = nodes
                    .iter()
                    .take(4)
                    .map(|(hash, nid)| format!("{}@d{}", hex::encode_upper(&hash[..8]), nid[32]))
                    .collect();
                tracing::info!(
                    "timeout getobjects request: count={} preview=[{}]",
                    nodes.len(),
                    preview.join(", ")
                );
                vec![crate::network::relay::encode_get_state_nodes_by_hash(
                    &self.peer.ledger_hash,
                    &nodes,
                    self.peer.ledger_seq,
                )]
            }
        }
    }

    pub fn completion_check_snapshot(&self) -> Option<CompletionCheckSnapshot> {
        if !self.active() {
            return None;
        }
        Some(CompletionCheckSnapshot {
            ledger_seq: self.ledger_seq(),
            ledger_hash: *self.ledger_hash(),
            account_hash: self.account_hash(),
            acquisition_epoch: self.acquisition_epoch,
            shamap: self.shamap.clone(),
        })
    }

    pub fn check_completion_snapshot(
        mut snapshot: CompletionCheckSnapshot,
    ) -> CompletionCheckResult {
        let blocker = if snapshot.shamap.root.is_branch == 0 {
            Some(CompletionBlocker::EmptyTree)
        } else {
            let mut full_below = FullBelowCache::new(524_288);
            let backend = snapshot.shamap.backend().cloned();
            let report = sync_shamap::get_missing_nodes_report_windowed_limited(
                &mut snapshot.shamap.root,
                16,
                MapType::AccountState,
                backend.as_ref(),
                &mut full_below,
                None,
                BACKEND_READ_WINDOW,
            );
            if report.backend_fetch_errors > 0 {
                tracing::warn!(
                    "is_complete snapshot: blocked by {} backend fetch error(s)",
                    report.backend_fetch_errors
                );
                Some(CompletionBlocker::BackendFetchErrors {
                    count: report.backend_fetch_errors,
                })
            } else if !report.missing.is_empty() {
                tracing::info!(
                    "is_complete snapshot: blocked by {} missing node(s), first={} depth={}",
                    report.missing.len(),
                    hex::encode_upper(&report.missing[0].1[..8]),
                    report.missing[0].0.depth(),
                );
                Some(CompletionBlocker::MissingNodes {
                    count: report.missing.len(),
                    first_hash: report.missing[0].1,
                    first_depth: report.missing[0].0.depth(),
                })
            } else {
                let root = snapshot.shamap.root_hash();
                if root == snapshot.account_hash {
                    tracing::info!(
                        "is_complete snapshot: missing=0 root={} target={} match=true",
                        hex::encode_upper(&root[..8]),
                        hex::encode_upper(&snapshot.account_hash[..8])
                    );
                    None
                } else if snapshot.ledger_hash == [0u8; 32] {
                    tracing::info!(
                        "is_complete snapshot: ltCLOSED mode, missing=0, root={} (target mismatch — awaiting validated header rebind)",
                        hex::encode_upper(&root[..8]),
                    );
                    Some(CompletionBlocker::RootMismatch {
                        root,
                        target: snapshot.account_hash,
                    })
                } else {
                    tracing::info!(
                        "is_complete snapshot: missing=0 root={} target={} match=false",
                        hex::encode_upper(&root[..8]),
                        hex::encode_upper(&snapshot.account_hash[..8])
                    );
                    Some(CompletionBlocker::RootMismatch {
                        root,
                        target: snapshot.account_hash,
                    })
                }
            }
        };

        CompletionCheckResult {
            ledger_seq: snapshot.ledger_seq,
            ledger_hash: snapshot.ledger_hash,
            account_hash: snapshot.account_hash,
            acquisition_epoch: snapshot.acquisition_epoch,
            blocker,
        }
    }

    pub fn completion_result_is_plausible(result: &CompletionCheckResult) -> bool {
        !matches!(
            result.blocker,
            Some(CompletionBlocker::BackendFetchErrors { .. })
                | Some(CompletionBlocker::MissingNodes { .. })
        )
    }

    pub fn apply_completion_check_result(
        &mut self,
        result: CompletionCheckResult,
    ) -> Option<(
        SHAMap,
        crate::ledger::LedgerHeader,
        (usize, usize, u32, u32, usize),
    )> {
        if !self.active()
            || self.ledger_seq() != result.ledger_seq
            || *self.ledger_hash() != result.ledger_hash
            || self.account_hash() != result.account_hash
            || self.acquisition_epoch != result.acquisition_epoch
            || result.blocker.is_some()
        {
            return None;
        }

        let sync_info = (
            self.inner_count(),
            self.leaf_count(),
            self.ledger_seq(),
            self.pass_number(),
            self.new_objects_this_pass(),
        );
        let sync_header = self.sync_header.clone();
        self.set_active(false);
        let completed_shamap = self.take_shamap();
        Some((completed_shamap, sync_header, sync_info))
    }

    /// Build reply-triggered follow-ups and keep the pipe warm when the only
    /// blocker is the short duplicate-suppression window.
    pub fn build_reply_followup_requests(&mut self, n: usize) -> Vec<RtxpMessage> {
        let reqs = self.build_multi_requests(n, SyncRequestReason::Reply);
        if !reqs.is_empty()
            || self.state_request_in_flight() != 0
            || self.peer.recent_node_count() == 0
        {
            return reqs;
        }

        self.peer.clear_recent();
        self.build_multi_requests(n, SyncRequestReason::Reply)
    }

    /// Build timeout request.
    pub fn build_timeout_request(&mut self) -> Vec<RtxpMessage> {
        // Keep timeout recovery cheap. The timer path should not hold the
        // sync mutex across another full-tree scan just to emit a 12-node
        // request.
        let report = self.get_missing_report_for_request(crate::ledger::inbound::REQ_NODES_TIMEOUT);
        if !report.missing.is_empty() {
            return self
                .peer
                .build_requests_from_missing(&report.missing, SyncRequestReason::Timeout);
        }

        let Some(hint) = report.budget_hint else {
            return Vec::new();
        };

        // A bounded NuDB walk can spend its whole budget proving already-local
        // nodes before it reaches the missing frontier. Confirm against NuDB
        // before requesting; the hinted node may already be present locally.
        tracing::info!(
            "timeout request walk hit budget at depth={} hash={} — confirming missing frontier from NuDB",
            hint.0.depth(),
            hex::encode_upper(&hint.1[..8])
        );
        let report = self.get_missing_report(crate::ledger::inbound::REQ_NODES_TIMEOUT);
        if report.missing.is_empty() {
            return Vec::new();
        }
        self.peer
            .build_requests_from_missing(&report.missing, SyncRequestReason::Timeout)
    }

    /// Build a timeout object request (`GetObjects` for stuck nodes).
    /// Stores hash-to-node ID mappings for response handling.
    pub fn build_timeout_object_request(&mut self) -> Option<RtxpMessage> {
        // Request only a small set of missing state-node hashes rather than
        // the full tail frontier.
        let mut report =
            self.get_missing_report_for_object_request(crate::ledger::inbound::REQ_OBJECTS_TIMEOUT);
        if report.missing.is_empty() && report.budget_hint.is_some() {
            if let Some((node_id, hash)) = report.budget_hint {
                tracing::info!(
                    "timeout getobjects request: bounded walk hit budget at depth={} hash={} — running full missing walk",
                    node_id.depth(),
                    hex::encode_upper(&hash[..8])
                );
            }
            report = self.get_missing_report(crate::ledger::inbound::REQ_OBJECTS_TIMEOUT);
        }
        let missing = report.missing;
        if missing.is_empty() {
            tracing::info!("timeout getobjects request: no missing hashes available");
            return None;
        }

        // Store hash-to-wire-node mappings for diagnostics and cookie cleanup.
        // Keep existing mappings while older object requests are still in
        // flight; overlapping timeout probes are expected in sparse tail sync.
        let nodes: Vec<([u8; 32], [u8; 33])> = missing
            .iter()
            .map(|(nid, hash)| {
                self.pending_object_nodeids.insert(*hash, nid.to_wire());
                (*hash, nid.to_wire())
            })
            .collect();
        let preview: Vec<String> = nodes
            .iter()
            .take(4)
            .map(|(hash, nid)| format!("{}@d{}", hex::encode_upper(&hash[..8]), nid[32]))
            .collect();
        tracing::info!(
            "timeout getobjects request: count={} preview=[{}]",
            nodes.len(),
            preview.join(", ")
        );

        Some(crate::network::relay::encode_get_state_nodes_by_hash(
            &self.peer.ledger_hash,
            &nodes,
            self.peer.ledger_seq,
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
        let same_ledger_object_response = request_cookie.is_none()
            && ledger_hash.len() == 32
            && ledger_hash == self.peer.ledger_hash;
        let accepted = same_ledger_object_response
            || self
                .peer
                .accept_object_response(ledger_hash, request_cookie)
            || self.peer.accept_useful_stale_object_response(
                ledger_hash,
                request_cookie,
                imported_count,
            );
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
            self.pending_object_nodeids.clear();
            self.pending_object_cookies.clear();
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
            followup_reqs: Vec::new(),
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
            let reqs = self.build_timeout_request();
            return TimeoutHandling::RestartPass {
                progress_this_pass,
                timeout_count,
                reqs,
            };
        }

        if timeout_count > max_stalled_retries {
            let progress_this_pass = self.new_objects_this_pass();
            if progress_this_pass > 0 {
                self.peer.start_new_pass();
                self.reset_pass_pressure();
                self.clear_request_tracking();
                self.peer.clear_recent();
                let reqs = self.build_timeout_request();
                return TimeoutHandling::RestartPass {
                    progress_this_pass,
                    timeout_count,
                    reqs,
                };
            }
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
            self.peer.by_hash_armed && timeout_count >= 3 && *self.ledger_hash() != [0u8; 32];
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

    pub fn plan_timeout_tick(&mut self, max_stalled_retries: u32) -> TimeoutPlan {
        self.plan_timeout_tick_tuned(
            max_stalled_retries,
            5,
            crate::ledger::inbound::REQ_OBJECTS_TIMEOUT,
        )
    }

    pub fn plan_timeout_tick_tuned(
        &mut self,
        max_stalled_retries: u32,
        object_fallback_after_timeouts: u32,
        object_batch_size: usize,
    ) -> TimeoutPlan {
        let timeout_count = match self.peer.on_timer_tick() {
            Some(crate::ledger::inbound::TimeoutTick::Progress) => {
                return TimeoutPlan::Progress;
            }
            Some(crate::ledger::inbound::TimeoutTick::Timeout(timeouts)) => timeouts,
            None => return TimeoutPlan::Progress,
        };

        if self.is_pass_complete() {
            let progress_this_pass = self.new_objects_this_pass();
            self.peer.start_new_pass();
            self.reset_pass_pressure();
            self.clear_request_tracking();
            self.peer.clear_recent();
            let request = self.timeout_request_snapshot(TimeoutRequestKind::Ledger);
            return TimeoutPlan::RestartPass {
                progress_this_pass,
                timeout_count,
                request,
            };
        }

        if timeout_count > max_stalled_retries {
            let progress_this_pass = self.new_objects_this_pass();
            if progress_this_pass > 0 {
                self.peer.start_new_pass();
                self.reset_pass_pressure();
                self.clear_request_tracking();
                self.peer.clear_recent();
                let request = self.timeout_request_snapshot(TimeoutRequestKind::Ledger);
                return TimeoutPlan::RestartPass {
                    progress_this_pass,
                    timeout_count,
                    request,
                };
            }
            self.set_active(false);
            self.peer.mark_failed();
            self.peer.by_hash_armed = false;
            self.peer.clear_recent();
            self.peer.reset_in_flight();
            self.clear_request_tracking();
            return TimeoutPlan::Deactivate { timeout_count };
        }

        self.set_stalled_retries(timeout_count);
        self.peer.by_hash_armed = true;
        let use_object_fallback = self.peer.by_hash_armed
            && timeout_count >= object_fallback_after_timeouts
            && *self.ledger_hash() != [0u8; 32];
        let request_kind = if use_object_fallback {
            self.peer.by_hash_armed = false;
            TimeoutRequestKind::Objects
        } else {
            TimeoutRequestKind::Ledger
        };
        TimeoutPlan::Request {
            timeout_count,
            use_object_fallback,
            request: self.timeout_request_snapshot_tuned(request_kind, object_batch_size),
        }
    }

    /// Find missing nodes in the SHAMap.
    pub fn get_missing(
        &mut self,
        max: usize,
    ) -> Vec<(crate::ledger::shamap_id::SHAMapNodeID, [u8; 32])> {
        self.get_missing_report(max).missing
    }

    fn get_missing_for_request(
        &mut self,
        max: usize,
    ) -> Vec<(crate::ledger::shamap_id::SHAMapNodeID, [u8; 32])> {
        self.get_missing_report_for_request(max).missing
    }

    fn get_missing_report_for_request(
        &mut self,
        max: usize,
    ) -> crate::ledger::shamap_sync::MissingNodesReport {
        sync_shamap::get_missing_nodes_report_limited(
            &mut self.shamap.root,
            max,
            MapType::AccountState,
            self.backend.as_ref(),
            &mut self.full_below,
            Some(REQUEST_WALK_VISIT_BUDGET),
        )
    }

    fn get_missing_report_for_object_request(
        &mut self,
        max: usize,
    ) -> crate::ledger::shamap_sync::MissingNodesReport {
        sync_shamap::get_missing_nodes_report_limited(
            &mut self.shamap.root,
            max,
            MapType::AccountState,
            self.backend.as_ref(),
            &mut self.full_below,
            Some(OBJECT_REQUEST_WALK_VISIT_BUDGET),
        )
    }

    fn has_obvious_missing(&mut self, max: usize) -> bool {
        let report = self.get_missing_report_for_request(max);
        if Self::completion_report_has_obvious_missing(&report) {
            return true;
        }
        if let Some((node_id, hash)) = report.budget_hint {
            tracing::info!(
                "completion probe reached bounded walk budget at depth={} hash={} — running full completion check",
                node_id.depth(),
                hex::encode_upper(&hash[..8])
            );
        }
        false
    }

    fn completion_report_has_obvious_missing(
        report: &crate::ledger::shamap_sync::MissingNodesReport,
    ) -> bool {
        report.backend_fetch_errors > 0 || !report.missing.is_empty()
    }

    pub fn completion_is_plausible(&mut self) -> bool {
        !self.has_obvious_missing(16)
    }

    pub fn should_check_completion(&mut self, interval: Duration) -> bool {
        if self.last_completion_check.elapsed() < interval {
            return false;
        }
        self.last_completion_check = Instant::now();
        true
    }

    pub fn useful_idle(&self) -> Duration {
        self.peer.last_new_nodes.elapsed()
    }

    pub fn response_idle(&self) -> Duration {
        self.peer.last_response.elapsed()
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
        self.acquisition_epoch = self.acquisition_epoch.wrapping_add(1);
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
        self.completion_blocker().is_none()
    }

    pub fn completion_blocker(&mut self) -> Option<CompletionBlocker> {
        // A tree with no branches is empty, not complete.
        if self.shamap.root.is_branch == 0 {
            return Some(CompletionBlocker::EmptyTree);
        }
        // No nodes may remain missing.
        let report = self.get_missing_report(16);
        if report.backend_fetch_errors > 0 {
            tracing::warn!(
                "is_complete: blocked by {} backend fetch error(s)",
                report.backend_fetch_errors
            );
            return Some(CompletionBlocker::BackendFetchErrors {
                count: report.backend_fetch_errors,
            });
        }
        if !report.missing.is_empty() {
            tracing::info!(
                "is_complete: blocked by {} missing node(s), first={} depth={}",
                report.missing.len(),
                hex::encode_upper(&report.missing[0].1[..8]),
                report.missing[0].0.depth(),
            );
            return Some(CompletionBlocker::MissingNodes {
                count: report.missing.len(),
                first_hash: report.missing[0].1,
                first_depth: report.missing[0].0.depth(),
            });
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
        if matches {
            None
        } else {
            Some(CompletionBlocker::RootMismatch {
                root,
                target: self.peer.account_hash,
            })
        }
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
        self.acquisition_epoch = self.acquisition_epoch.wrapping_add(1);
        true
    }

    /// Check if current pass is stalled.
    pub fn is_pass_complete(&mut self) -> bool {
        self.peer.new_objects_this_pass() == 0 && self.peer.last_new_nodes.elapsed().as_secs() > 10
    }

    /// Count of missing nodes (diagnostics).
    pub fn pending_count(&mut self) -> usize {
        let report = self.get_missing_report(256);
        report
            .missing
            .len()
            .saturating_add(report.backend_fetch_errors)
    }

    /// Restart for a new ledger.
    pub fn restart(&mut self, seq: u32, hash: [u8; 32], account_hash: [u8; 32]) {
        self.peer = PeerSyncManager::new(seq, hash, account_hash);
        self.shamap = Self::new_state_map_from_backend(self.backend.as_ref(), account_hash);
        self.full_below = FullBelowCache::new(524_288);
        self.pending_object_nodeids.clear();
        self.pending_object_cookies.clear();
        self.retarget_progress_count = 0;
        self.stale_retarget_count = 0;
        self.acquisition_epoch = self.acquisition_epoch.wrapping_add(1);
    }

    /// Take the SHAMap out of the coordinator (handoff to LedgerState).
    /// After this call, the coordinator no longer has a tree.
    pub fn take_shamap(&mut self) -> SHAMap {
        let replacement = match &self.backend {
            Some(b) => SHAMap::with_backend(MapType::AccountState, b.clone()),
            None => SHAMap::new_state(),
        };
        self.acquisition_epoch = self.acquisition_epoch.wrapping_add(1);
        std::mem::replace(&mut self.shamap, replacement)
    }

    /// Evict persisted leaf payloads from the in-memory sync tree.
    pub fn evict_clean_leaves(&mut self) -> usize {
        self.shamap.evict_clean_leaves()
    }

    pub fn stats(&self) -> SyncCoordinatorStats {
        SyncCoordinatorStats {
            full_below: self.full_below.len(),
            recent_nodes: self.peer.recent_nodes.len(),
            outstanding_cookies: self.peer.outstanding_cookies.len(),
            outstanding_object_queries: self.peer.outstanding_object_queries.len(),
            responded_cookies: self.peer.responded_cookies.len(),
            responded_object_queries: self.peer.responded_object_queries.len(),
            pending_object_nodeids: self.pending_object_nodeids.len(),
            pending_object_cookies: self.pending_object_cookies.len(),
        }
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
        if self.peer.active != v {
            self.acquisition_epoch = self.acquisition_epoch.wrapping_add(1);
        }
        self.peer.active = v;
    }
    pub fn in_flight(&self) -> usize {
        self.peer.in_flight
            + self.peer.outstanding_cookie_count()
            + self.peer.outstanding_object_query_count()
    }
    pub fn state_request_in_flight(&self) -> usize {
        self.peer.in_flight + self.peer.outstanding_cookie_count()
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
    pub fn seed_persisted_leaf_count(&mut self, v: usize) {
        if v > self.peer.leaf_count {
            self.peer.leaf_count = v;
        }
        self.peer.pass_start_useful_count = self.peer.inner_count + self.peer.leaf_count;
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

    fn flushed_backend_with_state_root() -> (Arc<dyn crate::ledger::node_store::NodeStore>, [u8; 32])
    {
        let backend: Arc<dyn crate::ledger::node_store::NodeStore> =
            Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut map = SHAMap::with_backend(MapType::AccountState, backend.clone());
        for i in 0u8..32 {
            let mut key = [0u8; 32];
            key[0] = i;
            map.insert(crate::ledger::shamap::Key(key), vec![i; 48]);
        }
        let root_hash = map.root_hash();
        assert!(map.flush_dirty().expect("state tree should flush") > 0);
        (backend, root_hash)
    }

    #[test]
    fn constructor_rehydrates_persisted_root_from_backend() {
        let header = crate::ledger::LedgerHeader::default();
        let (backend, root_hash) = flushed_backend_with_state_root();

        let mut coordinator =
            SyncCoordinator::new(10, [0x11; 32], root_hash, Some(backend), header);

        assert_ne!(coordinator.shamap.root.is_branch, 0);
        assert_eq!(coordinator.root_hash(), root_hash);
        assert!(coordinator.get_missing_report(16).missing.is_empty());
        assert!(coordinator.is_complete());
    }

    #[test]
    fn restart_rehydrates_persisted_root_from_backend() {
        let header = crate::ledger::LedgerHeader::default();
        let (backend, root_hash) = flushed_backend_with_state_root();
        let mut coordinator =
            SyncCoordinator::new(10, [0x11; 32], [0x22; 32], Some(backend), header);
        assert_eq!(coordinator.shamap.root.is_branch, 0);

        coordinator.restart(11, [0x33; 32], root_hash);

        assert_ne!(coordinator.shamap.root.is_branch, 0);
        assert_eq!(coordinator.root_hash(), root_hash);
        assert!(coordinator.get_missing_report(16).missing.is_empty());
        assert!(coordinator.is_complete());
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

        assert!(!pb.objects.is_empty());
        assert_eq!(pb.objects.len(), coordinator.pending_object_nodeids.len());
        assert!(coordinator.pending_object_cookies.is_empty());
        assert!(pb.objects.len() <= 4);

        for object in pb.objects.iter() {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(object.hash.as_ref().expect("object should carry hash"));
            assert!(
                object.node_id.is_none(),
                "rippled's GetObjects requests carry hashes, not node IDs"
            );
            assert!(coordinator.pending_object_nodeids.contains_key(&hash));
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

    #[test]
    fn reply_followup_recycles_recent_window_when_pipe_is_empty() {
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
            root_hashes[branch as usize] = crate::crypto::sha512_first_half(&payload);
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

        let first = coordinator.build_multi_requests(1, SyncRequestReason::Reply);
        assert_eq!(first.len(), 1);

        let suppressed = coordinator.build_multi_requests(1, SyncRequestReason::Reply);
        assert!(suppressed.is_empty());

        coordinator.peer.outstanding_object_queries.insert(99);
        let recycled = coordinator.build_reply_followup_requests(1);
        assert_eq!(recycled.len(), 1);
        let pb = crate::proto::TmGetLedger::decode(recycled[0].payload.as_slice())
            .expect("recycled reply request should decode");
        assert_eq!(pb.node_i_ds.len(), 16);
    }

    #[test]
    fn is_complete_allows_backend_satisfied_tree_with_zero_new_leaves() {
        let header = crate::ledger::LedgerHeader::default();
        let backend: Arc<dyn crate::ledger::node_store::NodeStore> =
            Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut coordinator =
            SyncCoordinator::new(10, [0x11; 32], [0x22; 32], Some(backend.clone()), header);

        let child_wire = make_inner_wire(&[[0u8; 32]; 16]);
        let mut child_payload = Vec::with_capacity(4 + 16 * 32);
        child_payload.extend_from_slice(&crate::ledger::shamap::PREFIX_INNER_NODE);
        child_payload.extend_from_slice(&child_wire[..child_wire.len() - 1]);
        let child_hash = crate::crypto::sha512_first_half(&child_payload);
        backend
            .store(&child_hash, &child_wire[..child_wire.len() - 1])
            .expect("child inner should store");

        let mut root_hashes = [[0u8; 32]; 16];
        root_hashes[0] = child_hash;
        let root_wire = make_inner_wire(&root_hashes);
        assert_eq!(
            crate::ledger::shamap_sync::add_known_node(
                &mut coordinator.shamap.root,
                &crate::ledger::shamap_id::SHAMapNodeID::root(),
                &root_wire,
                MapType::AccountState,
                Some(&backend),
                &mut coordinator.full_below,
            ),
            crate::ledger::shamap_sync::AddNodeResult::Useful
        );

        coordinator.peer.account_hash = coordinator.root_hash();
        coordinator.peer.leaf_count = 0;

        assert!(coordinator.get_missing_report(16).missing.is_empty());
        assert!(coordinator.is_complete());
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
    fn completion_probe_budget_hint_does_not_block_full_check() {
        let report = crate::ledger::shamap_sync::MissingNodesReport {
            missing: Vec::new(),
            budget_hint: Some((
                crate::ledger::shamap_id::SHAMapNodeID::root().child_id(7),
                [0x77; 32],
            )),
            backend_fetch_errors: 0,
        };

        assert!(!SyncCoordinator::completion_report_has_obvious_missing(
            &report
        ));
    }

    #[test]
    fn completion_probe_still_blocks_real_missing_or_fetch_errors() {
        let mut report = crate::ledger::shamap_sync::MissingNodesReport {
            missing: vec![(
                crate::ledger::shamap_id::SHAMapNodeID::root().child_id(3),
                [0x33; 32],
            )],
            budget_hint: None,
            backend_fetch_errors: 0,
        };
        assert!(SyncCoordinator::completion_report_has_obvious_missing(
            &report
        ));

        report.missing.clear();
        report.backend_fetch_errors = 1;
        assert!(SyncCoordinator::completion_report_has_obvious_missing(
            &report
        ));
    }

    #[test]
    fn request_generation_requests_backend_missing_node() {
        let header = crate::ledger::LedgerHeader::default();
        let backend: Arc<dyn crate::ledger::node_store::NodeStore> =
            Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut coordinator =
            SyncCoordinator::new(10, [0x11; 32], [0x22; 32], Some(backend), header);
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);

        let request = coordinator.build_timeout_request();

        assert_eq!(request.len(), 1);
        let pb = crate::proto::TmGetLedger::decode(request[0].payload.as_slice())
            .expect("GetLedger request should decode");
        assert_eq!(pb.node_i_ds.len(), 1);
    }

    #[test]
    fn timeout_frontier_build_drops_stale_retargeted_target() {
        let header = crate::ledger::LedgerHeader::default();
        let backend: Arc<dyn crate::ledger::node_store::NodeStore> =
            Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut coordinator =
            SyncCoordinator::new(10, [0x11; 32], [0x22; 32], Some(backend), header.clone());
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);

        let snapshot = coordinator
            .timeout_request_snapshot(TimeoutRequestKind::Ledger)
            .expect("active syncer should snapshot");
        let frontier = SyncCoordinator::walk_timeout_request_frontier(snapshot);

        coordinator.retarget(11, [0x33; 32], [0x44; 32], header);

        assert!(coordinator
            .build_timeout_requests_from_frontier(frontier)
            .is_empty());
    }

    #[test]
    fn reply_frontier_build_drops_same_target_restart_epoch() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);

        let snapshot = coordinator
            .reply_followup_frontier_snapshot(1)
            .expect("active syncer should snapshot");
        let frontier = SyncCoordinator::walk_reply_followup_frontier(snapshot);

        coordinator.restart(10, [0x11; 32], [0x22; 32]);

        assert!(coordinator
            .build_reply_followup_requests_from_frontier(frontier)
            .is_empty());
    }

    #[test]
    fn completion_handoff_drops_same_target_restart_epoch() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);

        let snapshot = coordinator
            .completion_check_snapshot()
            .expect("active syncer should snapshot");
        let result = CompletionCheckResult {
            ledger_seq: snapshot.ledger_seq,
            ledger_hash: snapshot.ledger_hash,
            account_hash: snapshot.account_hash,
            acquisition_epoch: snapshot.acquisition_epoch,
            blocker: None,
        };

        coordinator.restart(10, [0x11; 32], [0x22; 32]);

        assert!(coordinator.apply_completion_check_result(result).is_none());
    }

    #[test]
    fn request_generation_skips_backend_satisfied_leaf() {
        let header = crate::ledger::LedgerHeader::default();
        let backend: Arc<dyn crate::ledger::node_store::NodeStore> =
            Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut coordinator =
            SyncCoordinator::new(10, [0x11; 32], [0x22; 32], Some(backend.clone()), header);

        let key = [0x33; 32];
        let leaf_data = vec![0x44, 0x55, 0x66];
        let leaf_hash = crate::ledger::sparse_shamap::leaf_hash(&leaf_data, &key);
        let mut stored = leaf_data;
        stored.extend_from_slice(&key);
        backend
            .store(&leaf_hash, &stored)
            .expect("leaf should store");
        coordinator.shamap.root.set_child_hash(0, leaf_hash);

        assert!(coordinator.build_timeout_request().is_empty());
    }

    #[test]
    fn process_parsed_response_drops_leaves_with_invalid_known_leaf_hash() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        let node_id = crate::ledger::shamap_id::SHAMapNodeID::root().child_id(0);

        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);
        let progress = coordinator.process_parsed_response(crate::sync::ParsedSyncResponse {
            nodes: Vec::new(),
            leaf_nodes: vec![(node_id, [0xBB; 32])],
            leaves: vec![(vec![0x01; 32], vec![0x02, 0x03])],
        });

        assert_eq!(progress.leaf_received, 0);
        assert!(progress.leaves.is_empty());
    }

    #[test]
    fn process_parsed_response_keeps_leaves_with_valid_known_leaf_hash() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        let node_id = crate::ledger::shamap_id::SHAMapNodeID::root().child_id(0);
        let leaf = (vec![0x01; 32], vec![0x02, 0x03]);

        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);
        let progress = coordinator.process_parsed_response(crate::sync::ParsedSyncResponse {
            nodes: Vec::new(),
            leaf_nodes: vec![(node_id, [0xAA; 32])],
            leaves: vec![leaf.clone()],
        });

        assert_eq!(progress.leaf_received, 1);
        assert_eq!(progress.leaves, vec![leaf]);
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
        coordinator
            .pending_object_cookies
            .insert(cookie, vec![[0; 33]]);

        let outcome = coordinator.handle_object_response(&[0x11; 32], Some(cookie), 1);
        assert!(outcome.accepted);
        assert_eq!(outcome.sync_seq, 10);
        assert!(!coordinator.pending_object_cookies.contains_key(&cookie));
    }

    #[test]
    fn handle_object_response_progress_clears_stale_object_tracking() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        let cookie = crate::sync::next_cookie() as u32;
        coordinator.peer.outstanding_object_queries.insert(cookie);
        coordinator
            .pending_object_nodeids
            .insert([0xAA; 32], [0xBB; 33]);
        coordinator
            .pending_object_cookies
            .insert(cookie, vec![[0xBB; 33]]);

        let outcome = coordinator.handle_object_response(&[0x11; 32], Some(cookie), 1);

        assert!(outcome.accepted);
        assert!(coordinator.pending_object_nodeids.is_empty());
        assert!(coordinator.pending_object_cookies.is_empty());
        assert!(coordinator.peer.outstanding_object_queries.is_empty());
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
    fn handle_object_response_accepts_useful_cookieless_same_ledger_reply_after_request() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);
        let _request = coordinator
            .build_timeout_object_request()
            .expect("missing child hash should produce a GetObjects request");

        coordinator.peer.outstanding_object_queries.clear();

        let outcome = coordinator.handle_object_response(&[0x11; 32], None, 2);
        assert!(outcome.accepted);
        assert_eq!(outcome.sync_seq, 10);
    }

    #[test]
    fn handle_object_response_accepts_useful_cookieless_same_ledger_reply() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);

        let outcome = coordinator.handle_object_response(&[0x11; 32], None, 2);

        assert!(outcome.accepted);
        assert_eq!(outcome.sync_seq, 10);
        assert_eq!(coordinator.peer.pass_number, 1);
    }

    #[test]
    fn handle_object_response_accepts_empty_cookieless_same_ledger_without_followup() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);
        let _request = coordinator
            .build_timeout_object_request()
            .expect("missing child hash should produce a GetObjects request");

        coordinator.peer.outstanding_object_queries.clear();

        let outcome = coordinator.handle_object_response(&[0x11; 32], None, 0);
        assert!(outcome.accepted);
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
    fn handle_timeout_tick_restarts_pass_after_useful_progress() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);
        coordinator.peer.inner_count = 3;
        coordinator.peer.pass_start_useful_count = 0;

        let mut outcome = TimeoutHandling::Progress;
        for _ in 0..7 {
            outcome = coordinator.handle_timeout_tick(6);
        }

        match outcome {
            TimeoutHandling::RestartPass {
                progress_this_pass,
                timeout_count,
                reqs,
            } => {
                assert_eq!(progress_this_pass, 3);
                assert_eq!(timeout_count, 7);
                assert!(!reqs.is_empty());
            }
            _ => panic!("expected restart pass instead of dropping useful sync progress"),
        }
        assert!(coordinator.active());
        assert_eq!(coordinator.peer.pass_start_useful_count, 3);
    }

    #[test]
    fn seed_persisted_leaf_count_does_not_create_new_pass_progress() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);

        coordinator.seed_persisted_leaf_count(42);

        assert_eq!(coordinator.leaf_count(), 42);
        assert_eq!(coordinator.new_objects_this_pass(), 0);
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
    fn plan_timeout_tick_uses_tuned_object_fallback_threshold_and_batch() {
        let header = crate::ledger::LedgerHeader::default();
        let mut coordinator = SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        coordinator.shamap.root.set_child_hash(0, [0xAA; 32]);
        let outcome = coordinator.plan_timeout_tick_tuned(6, 1, 2);

        match outcome {
            TimeoutPlan::Request {
                timeout_count,
                use_object_fallback,
                request: Some(snapshot),
            } => {
                assert_eq!(timeout_count, 1);
                assert!(use_object_fallback);
                assert_eq!(snapshot.request_kind, TimeoutRequestKind::Objects);
                assert_eq!(snapshot.object_batch_size, 2);
            }
            _ => panic!("expected tuned object fallback request"),
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
        coordinator
            .peer
            .responded_cookies
            .insert(cookie.wrapping_add(1));
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
        coordinator
            .pending_object_nodeids
            .insert([0xAA; 32], [0xBB; 33]);
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
