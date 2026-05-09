use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use tokio::sync::Notify;

use crate::network::message::RtxpMessage;
use crate::network::peer::PeerId;

#[derive(Default)]
struct SyncDataQueue {
    items: VecDeque<SyncDataQueueItem>,
    bytes: usize,
}

struct SyncDataQueueItem {
    peer_id: PeerId,
    msg: crate::proto::TmLedgerData,
    bytes: usize,
}

struct SyncDataKeepContext {
    target_hash: [u8; 32],
    outstanding_cookies: Option<HashSet<u32>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteMessageMetricsSnapshot {
    pub message_type: String,
    pub total: u64,
    pub slow_total: u64,
    pub max_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteQueuePeerMetricsSnapshot {
    pub peer_id: String,
    pub message_type: String,
    pub full_total: u64,
    pub inline_retry_total: u64,
    pub dropped_total: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncWorkerLaneMetricsSnapshot {
    pub lane: String,
    pub enqueued_total: u64,
    pub started_total: u64,
    pub completed_total: u64,
    pub failed_total: u64,
    pub in_flight: u64,
    pub max_in_flight: u64,
    pub queue_capacity: u64,
    pub max_queue_depth: u64,
    pub backpressure_total: u64,
    pub max_backpressure_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncMetricsSnapshot {
    pub queued_responses_total: u64,
    pub queued_response_bytes_total: u64,
    pub max_queue_len: u64,
    pub max_queue_bytes: u64,
    pub dequeued_responses_total: u64,
    pub dropped_responses_total: u64,
    pub dropped_response_bytes_total: u64,
    pub cleared_responses_total: u64,
    pub cleared_response_bytes_total: u64,
    pub gate_accept_total: u64,
    pub gate_reject_total: u64,
    pub gate_invalid_total: u64,
    pub gate_lock_busy_total: u64,
    pub malformed_responses_total: u64,
    pub stale_responses_total: u64,
    pub processed_responses_total: u64,
    pub useful_nodes_total: u64,
    pub completed_sync_total: u64,
    pub completion_checks_total: u64,
    pub completion_plausible_total: u64,
    pub completion_true_total: u64,
    pub completion_false_total: u64,
    pub completion_disk_complete_total: u64,
    pub completion_anchor_blocked_total: u64,
    pub pass_complete_total: u64,
    pub hit_cap_total: u64,
    pub inactive_batch_total: u64,
    pub batches_total: u64,
    pub last_batch_responses: u64,
    pub last_batch_useful_nodes: u64,
    pub last_batch_ms: u64,
    pub last_batch_outcome: String,
    pub total_lock_wait_ms: u64,
    pub total_hold_ms: u64,
    pub total_batch_ms: u64,
    pub max_lock_wait_ms: u64,
    pub max_hold_ms: u64,
    pub max_batch_ms: u64,
    pub route_messages_total: u64,
    pub slow_route_messages_total: u64,
    pub max_route_ms: u64,
    pub route_queue_enqueued_total: u64,
    pub route_queue_full_total: u64,
    pub route_queue_inline_total: u64,
    pub route_queue_dropped_total: u64,
    pub route_queue_max_len: u64,
    pub route_queue_capacity: u64,
    pub route_message_types: Vec<RouteMessageMetricsSnapshot>,
    pub route_queue_peers: Vec<RouteQueuePeerMetricsSnapshot>,
    pub worker_lanes: Vec<SyncWorkerLaneMetricsSnapshot>,
    pub diff_sync_queued_total: u64,
    pub diff_sync_queue_fail_total: u64,
    pub diff_sync_discarded_total: u64,
    pub object_fallback_requests_total: u64,
    pub object_fallback_no_request_total: u64,
    pub object_fallback_responses_total: u64,
    pub object_fallback_accepted_total: u64,
    pub object_fallback_rejected_total: u64,
    pub object_fallback_stored_total: u64,
    pub object_fallback_duplicate_total: u64,
    pub object_fallback_empty_total: u64,
}

#[derive(Debug, Default)]
struct RouteMessageMetrics {
    total: u64,
    slow_total: u64,
    max_ms: u64,
}

#[derive(Debug, Default)]
struct RouteQueuePeerMetrics {
    full_total: u64,
    inline_retry_total: u64,
    dropped_total: u64,
}

#[derive(Debug, Default)]
struct SyncWorkerLaneMetrics {
    enqueued_total: u64,
    started_total: u64,
    completed_total: u64,
    failed_total: u64,
    in_flight: u64,
    max_in_flight: u64,
    queue_capacity: u64,
    max_queue_depth: u64,
    backpressure_total: u64,
    max_backpressure_ms: u64,
}

#[derive(Debug, Default)]
pub struct SyncMetrics {
    queued_responses_total: AtomicU64,
    queued_response_bytes_total: AtomicU64,
    max_queue_len: AtomicU64,
    max_queue_bytes: AtomicU64,
    dequeued_responses_total: AtomicU64,
    dropped_responses_total: AtomicU64,
    dropped_response_bytes_total: AtomicU64,
    cleared_responses_total: AtomicU64,
    cleared_response_bytes_total: AtomicU64,
    gate_accept_total: AtomicU64,
    gate_reject_total: AtomicU64,
    gate_invalid_total: AtomicU64,
    gate_lock_busy_total: AtomicU64,
    malformed_responses_total: AtomicU64,
    stale_responses_total: AtomicU64,
    processed_responses_total: AtomicU64,
    useful_nodes_total: AtomicU64,
    completed_sync_total: AtomicU64,
    completion_checks_total: AtomicU64,
    completion_plausible_total: AtomicU64,
    completion_true_total: AtomicU64,
    completion_false_total: AtomicU64,
    completion_disk_complete_total: AtomicU64,
    completion_anchor_blocked_total: AtomicU64,
    pass_complete_total: AtomicU64,
    hit_cap_total: AtomicU64,
    inactive_batch_total: AtomicU64,
    batches_total: AtomicU64,
    last_batch_responses: AtomicU64,
    last_batch_useful_nodes: AtomicU64,
    last_batch_ms: AtomicU64,
    last_batch_outcome: Mutex<String>,
    total_lock_wait_ms: AtomicU64,
    total_hold_ms: AtomicU64,
    total_batch_ms: AtomicU64,
    max_lock_wait_ms: AtomicU64,
    max_hold_ms: AtomicU64,
    max_batch_ms: AtomicU64,
    route_messages_total: AtomicU64,
    slow_route_messages_total: AtomicU64,
    max_route_ms: AtomicU64,
    route_queue_enqueued_total: AtomicU64,
    route_queue_full_total: AtomicU64,
    route_queue_inline_total: AtomicU64,
    route_queue_dropped_total: AtomicU64,
    route_queue_max_len: AtomicU64,
    route_queue_capacity: AtomicU64,
    route_message_types: Mutex<BTreeMap<String, RouteMessageMetrics>>,
    route_queue_peers: Mutex<BTreeMap<(String, String), RouteQueuePeerMetrics>>,
    worker_lanes: Mutex<BTreeMap<String, SyncWorkerLaneMetrics>>,
    diff_sync_queued_total: AtomicU64,
    diff_sync_queue_fail_total: AtomicU64,
    diff_sync_discarded_total: AtomicU64,
    object_fallback_requests_total: AtomicU64,
    object_fallback_no_request_total: AtomicU64,
    object_fallback_responses_total: AtomicU64,
    object_fallback_accepted_total: AtomicU64,
    object_fallback_rejected_total: AtomicU64,
    object_fallback_stored_total: AtomicU64,
    object_fallback_duplicate_total: AtomicU64,
    object_fallback_empty_total: AtomicU64,
}

impl SyncMetrics {
    fn set_max(slot: &AtomicU64, value: u64) {
        let mut current = slot.load(Ordering::Relaxed);
        while value > current {
            match slot.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    pub fn note_batch(
        &self,
        processed: u64,
        useful_nodes: u64,
        total_lock_ms: u64,
        total_hold_ms: u64,
        batch_ms: u64,
        lock_ms: u64,
        hold_ms: u64,
        max_batch_ms: u64,
        outcome: &str,
    ) {
        self.batches_total.fetch_add(1, Ordering::Relaxed);
        self.last_batch_responses
            .store(processed, Ordering::Relaxed);
        self.last_batch_useful_nodes
            .store(useful_nodes, Ordering::Relaxed);
        self.last_batch_ms.store(batch_ms, Ordering::Relaxed);
        *self
            .last_batch_outcome
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = outcome.to_string();
        self.processed_responses_total
            .fetch_add(processed, Ordering::Relaxed);
        self.useful_nodes_total
            .fetch_add(useful_nodes, Ordering::Relaxed);
        self.total_lock_wait_ms
            .fetch_add(total_lock_ms, Ordering::Relaxed);
        self.total_hold_ms
            .fetch_add(total_hold_ms, Ordering::Relaxed);
        self.total_batch_ms.fetch_add(batch_ms, Ordering::Relaxed);
        Self::set_max(&self.max_lock_wait_ms, lock_ms);
        Self::set_max(&self.max_hold_ms, hold_ms);
        Self::set_max(&self.max_batch_ms, max_batch_ms);
        match outcome {
            "TrulyComplete" => {
                self.completed_sync_total.fetch_add(1, Ordering::Relaxed);
            }
            "PassComplete" => {
                self.pass_complete_total.fetch_add(1, Ordering::Relaxed);
            }
            "HitCap" => {
                self.hit_cap_total.fetch_add(1, Ordering::Relaxed);
            }
            "Inactive" => {
                self.inactive_batch_total.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn note_malformed(&self) {
        self.malformed_responses_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_completion_check(&self, plausible: bool, complete: bool) {
        self.completion_checks_total.fetch_add(1, Ordering::Relaxed);
        if plausible {
            self.completion_plausible_total
                .fetch_add(1, Ordering::Relaxed);
        }
        if complete {
            self.completion_true_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.completion_false_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn note_completion_disk_complete(&self) {
        self.completion_disk_complete_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_completion_anchor_blocked(&self) {
        self.completion_anchor_blocked_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_stale(&self) {
        self.stale_responses_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_route_message(&self, message_type: &str, elapsed_ms: u64, slow: bool) {
        self.route_messages_total.fetch_add(1, Ordering::Relaxed);
        if slow {
            self.slow_route_messages_total
                .fetch_add(1, Ordering::Relaxed);
        }
        Self::set_max(&self.max_route_ms, elapsed_ms);
        let mut by_type = self
            .route_message_types
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = by_type.entry(message_type.to_string()).or_default();
        entry.total = entry.total.saturating_add(1);
        if slow {
            entry.slow_total = entry.slow_total.saturating_add(1);
        }
        entry.max_ms = entry.max_ms.max(elapsed_ms);
    }

    pub fn note_route_queue_enqueued(&self, len: usize, capacity: usize) {
        self.route_queue_enqueued_total
            .fetch_add(1, Ordering::Relaxed);
        Self::set_max(&self.route_queue_max_len, len as u64);
        self.route_queue_capacity
            .store(capacity as u64, Ordering::Relaxed);
    }

    pub fn note_route_queue_full(&self, capacity: usize) {
        self.route_queue_full_total.fetch_add(1, Ordering::Relaxed);
        self.route_queue_capacity
            .store(capacity as u64, Ordering::Relaxed);
    }

    pub fn note_route_queue_full_for(&self, peer_id: PeerId, message_type: &str, capacity: usize) {
        self.note_route_queue_full(capacity);
        let mut peers = self
            .route_queue_peers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = peers
            .entry((peer_id.0.to_string(), message_type.to_string()))
            .or_default();
        entry.full_total = entry.full_total.saturating_add(1);
    }

    pub fn note_route_queue_inline(&self) {
        self.route_queue_inline_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_route_queue_inline_for(&self, peer_id: PeerId, message_type: &str) {
        self.note_route_queue_inline();
        let mut peers = self
            .route_queue_peers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = peers
            .entry((peer_id.0.to_string(), message_type.to_string()))
            .or_default();
        entry.inline_retry_total = entry.inline_retry_total.saturating_add(1);
    }

    pub fn note_route_queue_dropped_for(&self, peer_id: PeerId, message_type: &str) {
        self.route_queue_dropped_total
            .fetch_add(1, Ordering::Relaxed);
        let mut peers = self
            .route_queue_peers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = peers
            .entry((peer_id.0.to_string(), message_type.to_string()))
            .or_default();
        entry.dropped_total = entry.dropped_total.saturating_add(1);
    }

    pub fn note_worker_lane_enqueued(&self, lane: &str, queue_depth: usize) {
        let mut lanes = self.worker_lanes.lock().unwrap_or_else(|e| e.into_inner());
        let lane = lanes.entry(lane.to_string()).or_default();
        lane.enqueued_total = lane.enqueued_total.saturating_add(1);
        lane.max_queue_depth = lane.max_queue_depth.max(queue_depth as u64);
    }

    pub fn note_worker_lane_capacity(&self, lane: &str, queue_capacity: usize) {
        let mut lanes = self.worker_lanes.lock().unwrap_or_else(|e| e.into_inner());
        let lane = lanes.entry(lane.to_string()).or_default();
        lane.queue_capacity = lane.queue_capacity.max(queue_capacity as u64);
    }

    pub fn note_worker_lane_backpressure(&self, lane: &str, wait_ms: u64) {
        let mut lanes = self.worker_lanes.lock().unwrap_or_else(|e| e.into_inner());
        let lane = lanes.entry(lane.to_string()).or_default();
        lane.backpressure_total = lane.backpressure_total.saturating_add(1);
        lane.max_backpressure_ms = lane.max_backpressure_ms.max(wait_ms);
    }

    pub fn note_worker_lane_started(&self, lane: &str) {
        let mut lanes = self.worker_lanes.lock().unwrap_or_else(|e| e.into_inner());
        let lane = lanes.entry(lane.to_string()).or_default();
        lane.started_total = lane.started_total.saturating_add(1);
        lane.in_flight = lane.in_flight.saturating_add(1);
        lane.max_in_flight = lane.max_in_flight.max(lane.in_flight);
    }

    pub fn note_worker_lane_finished(&self, lane: &str, success: bool) {
        let mut lanes = self.worker_lanes.lock().unwrap_or_else(|e| e.into_inner());
        let lane = lanes.entry(lane.to_string()).or_default();
        lane.in_flight = lane.in_flight.saturating_sub(1);
        if success {
            lane.completed_total = lane.completed_total.saturating_add(1);
        } else {
            lane.failed_total = lane.failed_total.saturating_add(1);
        }
    }

    pub fn note_diff_sync_queued(&self) {
        self.diff_sync_queued_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_diff_sync_queue_failed(&self) {
        self.diff_sync_queue_fail_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_diff_sync_discarded(&self) {
        self.diff_sync_discarded_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_object_fallback_request(&self, request_count: usize) {
        self.object_fallback_requests_total
            .fetch_add(request_count as u64, Ordering::Relaxed);
    }

    pub fn note_object_fallback_no_request(&self) {
        self.object_fallback_no_request_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_object_fallback_response(
        &self,
        accepted: bool,
        stored: usize,
        duplicates: usize,
        raw_objects: usize,
    ) {
        self.object_fallback_responses_total
            .fetch_add(1, Ordering::Relaxed);
        if accepted {
            self.object_fallback_accepted_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.object_fallback_rejected_total
                .fetch_add(1, Ordering::Relaxed);
        }
        self.object_fallback_stored_total
            .fetch_add(stored as u64, Ordering::Relaxed);
        self.object_fallback_duplicate_total
            .fetch_add(duplicates as u64, Ordering::Relaxed);
        if raw_objects == 0 {
            self.object_fallback_empty_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> SyncMetricsSnapshot {
        let route_message_types = self
            .route_message_types
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(message_type, metrics)| RouteMessageMetricsSnapshot {
                message_type: message_type.clone(),
                total: metrics.total,
                slow_total: metrics.slow_total,
                max_ms: metrics.max_ms,
            })
            .collect();
        let route_queue_peers = self
            .route_queue_peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(
                |((peer_id, message_type), metrics)| RouteQueuePeerMetricsSnapshot {
                    peer_id: peer_id.clone(),
                    message_type: message_type.clone(),
                    full_total: metrics.full_total,
                    inline_retry_total: metrics.inline_retry_total,
                    dropped_total: metrics.dropped_total,
                },
            )
            .collect();
        let worker_lanes = self
            .worker_lanes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(lane, metrics)| SyncWorkerLaneMetricsSnapshot {
                lane: lane.clone(),
                enqueued_total: metrics.enqueued_total,
                started_total: metrics.started_total,
                completed_total: metrics.completed_total,
                failed_total: metrics.failed_total,
                in_flight: metrics.in_flight,
                max_in_flight: metrics.max_in_flight,
                queue_capacity: metrics.queue_capacity,
                max_queue_depth: metrics.max_queue_depth,
                backpressure_total: metrics.backpressure_total,
                max_backpressure_ms: metrics.max_backpressure_ms,
            })
            .collect();

        SyncMetricsSnapshot {
            queued_responses_total: self.queued_responses_total.load(Ordering::Relaxed),
            queued_response_bytes_total: self.queued_response_bytes_total.load(Ordering::Relaxed),
            max_queue_len: self.max_queue_len.load(Ordering::Relaxed),
            max_queue_bytes: self.max_queue_bytes.load(Ordering::Relaxed),
            dequeued_responses_total: self.dequeued_responses_total.load(Ordering::Relaxed),
            dropped_responses_total: self.dropped_responses_total.load(Ordering::Relaxed),
            dropped_response_bytes_total: self.dropped_response_bytes_total.load(Ordering::Relaxed),
            cleared_responses_total: self.cleared_responses_total.load(Ordering::Relaxed),
            cleared_response_bytes_total: self.cleared_response_bytes_total.load(Ordering::Relaxed),
            gate_accept_total: self.gate_accept_total.load(Ordering::Relaxed),
            gate_reject_total: self.gate_reject_total.load(Ordering::Relaxed),
            gate_invalid_total: self.gate_invalid_total.load(Ordering::Relaxed),
            gate_lock_busy_total: self.gate_lock_busy_total.load(Ordering::Relaxed),
            malformed_responses_total: self.malformed_responses_total.load(Ordering::Relaxed),
            stale_responses_total: self.stale_responses_total.load(Ordering::Relaxed),
            processed_responses_total: self.processed_responses_total.load(Ordering::Relaxed),
            useful_nodes_total: self.useful_nodes_total.load(Ordering::Relaxed),
            completed_sync_total: self.completed_sync_total.load(Ordering::Relaxed),
            completion_checks_total: self.completion_checks_total.load(Ordering::Relaxed),
            completion_plausible_total: self.completion_plausible_total.load(Ordering::Relaxed),
            completion_true_total: self.completion_true_total.load(Ordering::Relaxed),
            completion_false_total: self.completion_false_total.load(Ordering::Relaxed),
            completion_disk_complete_total: self
                .completion_disk_complete_total
                .load(Ordering::Relaxed),
            completion_anchor_blocked_total: self
                .completion_anchor_blocked_total
                .load(Ordering::Relaxed),
            pass_complete_total: self.pass_complete_total.load(Ordering::Relaxed),
            hit_cap_total: self.hit_cap_total.load(Ordering::Relaxed),
            inactive_batch_total: self.inactive_batch_total.load(Ordering::Relaxed),
            batches_total: self.batches_total.load(Ordering::Relaxed),
            last_batch_responses: self.last_batch_responses.load(Ordering::Relaxed),
            last_batch_useful_nodes: self.last_batch_useful_nodes.load(Ordering::Relaxed),
            last_batch_ms: self.last_batch_ms.load(Ordering::Relaxed),
            last_batch_outcome: self
                .last_batch_outcome
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            total_lock_wait_ms: self.total_lock_wait_ms.load(Ordering::Relaxed),
            total_hold_ms: self.total_hold_ms.load(Ordering::Relaxed),
            total_batch_ms: self.total_batch_ms.load(Ordering::Relaxed),
            max_lock_wait_ms: self.max_lock_wait_ms.load(Ordering::Relaxed),
            max_hold_ms: self.max_hold_ms.load(Ordering::Relaxed),
            max_batch_ms: self.max_batch_ms.load(Ordering::Relaxed),
            route_messages_total: self.route_messages_total.load(Ordering::Relaxed),
            slow_route_messages_total: self.slow_route_messages_total.load(Ordering::Relaxed),
            max_route_ms: self.max_route_ms.load(Ordering::Relaxed),
            route_queue_enqueued_total: self.route_queue_enqueued_total.load(Ordering::Relaxed),
            route_queue_full_total: self.route_queue_full_total.load(Ordering::Relaxed),
            route_queue_inline_total: self.route_queue_inline_total.load(Ordering::Relaxed),
            route_queue_dropped_total: self.route_queue_dropped_total.load(Ordering::Relaxed),
            route_queue_max_len: self.route_queue_max_len.load(Ordering::Relaxed),
            route_queue_capacity: self.route_queue_capacity.load(Ordering::Relaxed),
            route_message_types,
            route_queue_peers,
            worker_lanes,
            diff_sync_queued_total: self.diff_sync_queued_total.load(Ordering::Relaxed),
            diff_sync_queue_fail_total: self.diff_sync_queue_fail_total.load(Ordering::Relaxed),
            diff_sync_discarded_total: self.diff_sync_discarded_total.load(Ordering::Relaxed),
            object_fallback_requests_total: self
                .object_fallback_requests_total
                .load(Ordering::Relaxed),
            object_fallback_no_request_total: self
                .object_fallback_no_request_total
                .load(Ordering::Relaxed),
            object_fallback_responses_total: self
                .object_fallback_responses_total
                .load(Ordering::Relaxed),
            object_fallback_accepted_total: self
                .object_fallback_accepted_total
                .load(Ordering::Relaxed),
            object_fallback_rejected_total: self
                .object_fallback_rejected_total
                .load(Ordering::Relaxed),
            object_fallback_stored_total: self.object_fallback_stored_total.load(Ordering::Relaxed),
            object_fallback_duplicate_total: self
                .object_fallback_duplicate_total
                .load(Ordering::Relaxed),
            object_fallback_empty_total: self.object_fallback_empty_total.load(Ordering::Relaxed),
        }
    }
}

pub struct HeaderBootstrapPlan {
    pub progress: crate::sync_coordinator::SyncProgress,
    pub reqs: Vec<RtxpMessage>,
    pub seed_count: usize,
    pub restarted: bool,
}

pub type CompletedSync = (
    crate::ledger::shamap::SHAMap,
    crate::ledger::LedgerHeader,
    (usize, usize, u32, u32, usize),
);

pub struct HeaderTriggerPlan {
    pub ignore_mismatched_fixed_target: Option<(u32, [u8; 32])>,
    pub restart_fixed_target: bool,
    pub retarget_fixed_target: bool,
    pub installed_syncer: bool,
    pub sync_lock_busy: bool,
    pub sync_completed_from_disk: bool,
    pub completed_from_disk: Option<CompletedSync>,
    pub bootstrap: Option<HeaderBootstrapPlan>,
}

pub struct SyncTimeoutResult {
    pub reqs: Vec<RtxpMessage>,
    pub sync_seq: u32,
    pub abandon: bool,
    pub completed: Option<CompletedSync>,
}

pub struct SyncRuntime {
    sync: Arc<Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
    bootstrap_active: Arc<AtomicBool>,
    target_hash: Arc<Mutex<[u8; 32]>>,
    gate_accepts_ltclosed: Arc<AtomicBool>,
    round_robin: Arc<AtomicUsize>,
    data_queue: Arc<Mutex<SyncDataQueue>>,
    data_notify: Arc<Notify>,
    metrics: Arc<SyncMetrics>,
    tuning: crate::node::SyncTuningConfig,
}

impl SyncRuntime {
    pub fn new() -> Self {
        Self::with_tuning(crate::node::SyncTuningConfig::default())
    }

    pub fn with_tuning(tuning: crate::node::SyncTuningConfig) -> Self {
        Self {
            sync: Arc::new(Mutex::new(None)),
            bootstrap_active: Arc::new(AtomicBool::new(false)),
            target_hash: Arc::new(Mutex::new([0u8; 32])),
            gate_accepts_ltclosed: Arc::new(AtomicBool::new(false)),
            round_robin: Arc::new(AtomicUsize::new(0)),
            data_queue: Arc::new(Mutex::new(SyncDataQueue::default())),
            data_notify: Arc::new(Notify::new()),
            metrics: Arc::new(SyncMetrics::default()),
            tuning: tuning.clamped(),
        }
    }

    pub fn tuning(&self) -> &crate::node::SyncTuningConfig {
        &self.tuning
    }

    pub fn metrics(&self) -> Arc<SyncMetrics> {
        self.metrics.clone()
    }

    pub fn metrics_snapshot(&self) -> SyncMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn note_route_message(&self, message_type: &str, elapsed_ms: u64, slow: bool) {
        self.metrics
            .note_route_message(message_type, elapsed_ms, slow);
    }

    pub fn note_route_queue_enqueued(&self, len: usize, capacity: usize) {
        self.metrics.note_route_queue_enqueued(len, capacity);
    }

    pub fn note_route_queue_full(&self, capacity: usize) {
        self.metrics.note_route_queue_full(capacity);
    }

    pub fn note_route_queue_full_for(&self, peer_id: PeerId, message_type: &str, capacity: usize) {
        self.metrics
            .note_route_queue_full_for(peer_id, message_type, capacity);
    }

    pub fn note_route_queue_inline(&self) {
        self.metrics.note_route_queue_inline();
    }

    pub fn note_route_queue_inline_for(&self, peer_id: PeerId, message_type: &str) {
        self.metrics
            .note_route_queue_inline_for(peer_id, message_type);
    }

    pub fn note_route_queue_dropped_for(&self, peer_id: PeerId, message_type: &str) {
        self.metrics
            .note_route_queue_dropped_for(peer_id, message_type);
    }

    pub fn note_worker_lane_enqueued(&self, lane: &str, queue_depth: usize) {
        self.metrics.note_worker_lane_enqueued(lane, queue_depth);
    }

    pub fn note_worker_lane_capacity(&self, lane: &str, queue_capacity: usize) {
        self.metrics.note_worker_lane_capacity(lane, queue_capacity);
    }

    pub fn note_worker_lane_backpressure(&self, lane: &str, wait_ms: u64) {
        self.metrics.note_worker_lane_backpressure(lane, wait_ms);
    }

    pub fn note_worker_lane_started(&self, lane: &str) {
        self.metrics.note_worker_lane_started(lane);
    }

    pub fn note_worker_lane_finished(&self, lane: &str, success: bool) {
        self.metrics.note_worker_lane_finished(lane, success);
    }

    pub fn note_diff_sync_queued(&self) {
        self.metrics.note_diff_sync_queued();
    }

    pub fn note_diff_sync_queue_failed(&self) {
        self.metrics.note_diff_sync_queue_failed();
    }

    pub fn note_diff_sync_discarded(&self) {
        self.metrics.note_diff_sync_discarded();
    }

    pub fn note_object_fallback_response(
        &self,
        accepted: bool,
        stored: usize,
        duplicates: usize,
        raw_objects: usize,
    ) {
        self.metrics
            .note_object_fallback_response(accepted, stored, duplicates, raw_objects);
    }

    pub fn note_completion_anchor_blocked(&self) {
        self.metrics.note_completion_anchor_blocked();
    }

    pub fn lock_sync(&self) -> MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>> {
        self.sync.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn try_lock_sync(
        &self,
    ) -> Result<
        MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>>,
        TryLockError<MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>>>,
    > {
        self.sync.try_lock()
    }

    pub fn sync_arc(&self) -> Arc<Mutex<Option<crate::sync_coordinator::SyncCoordinator>>> {
        self.sync.clone()
    }

    pub fn clear_syncer(&self) {
        let mut guard = self.lock_sync();
        if let Some(syncer) = guard.as_mut() {
            syncer.stop();
        }
        *guard = None;
        drop(guard);
        self.clear_sync_data_queue();
        self.set_bootstrap_active(false);
        self.set_target_hash([0u8; 32]);
        self.set_gate_accepts_ltclosed(false);
    }

    pub fn has_syncer(&self) -> bool {
        self.try_lock_sync()
            .ok()
            .is_some_and(|guard| guard.is_some())
    }

    pub fn sync_active(&self) -> bool {
        self.try_lock_sync()
            .ok()
            .and_then(|guard| guard.as_ref().map(|syncer| syncer.active()))
            .unwrap_or(false)
    }

    pub fn inactive_target(&self) -> Option<(u32, [u8; 32])> {
        self.try_lock_sync().ok().and_then(|guard| {
            guard.as_ref().and_then(|syncer| {
                (!syncer.active()).then_some((syncer.ledger_seq(), *syncer.ledger_hash()))
            })
        })
    }

    fn bootstrap_plan_from_wire(
        syncer: &mut crate::sync_coordinator::SyncCoordinator,
        ld: &crate::proto::TmLedgerData,
        seed_count: usize,
        restarted: bool,
    ) -> Option<HeaderBootstrapPlan> {
        let root = ld.nodes.get(1)?;
        let fake_ld = crate::proto::TmLedgerData {
            ledger_hash: ld.ledger_hash.clone(),
            ledger_seq: ld.ledger_seq,
            r#type: crate::proto::TmLedgerInfoType::LiAsNode as i32,
            nodes: vec![crate::proto::TmLedgerNode {
                nodedata: root.nodedata.clone(),
                nodeid: root.nodeid.clone(),
            }],
            request_cookie: None,
            error: None,
        };
        let progress = syncer.process_response(&fake_ld);
        let reqs = {
            let reqs = crate::sync_bootstrap::build_root_bootstrap_requests(
                syncer,
                &root.nodedata,
                seed_count,
            );
            if reqs.is_empty() {
                syncer.build_multi_requests(seed_count, crate::sync::SyncRequestReason::Reply)
            } else {
                reqs
            }
        };
        Some(HeaderBootstrapPlan {
            progress,
            reqs,
            seed_count,
            restarted,
        })
    }

    fn complete_from_disk_if_ready(
        syncer: &mut crate::sync_coordinator::SyncCoordinator,
        leaf_count: Option<usize>,
        metrics: &SyncMetrics,
    ) -> Option<CompletedSync> {
        let plausible = syncer.completion_is_plausible();
        let complete = plausible && syncer.is_complete();
        metrics.note_completion_check(plausible, complete);
        if !complete {
            return None;
        }
        metrics.note_completion_disk_complete();

        let sync_info = (
            syncer.inner_count(),
            leaf_count.unwrap_or_else(|| syncer.leaf_count()),
            syncer.ledger_seq(),
            syncer.pass_number(),
            syncer.new_objects_this_pass(),
        );
        let sync_header = syncer.sync_header.clone();
        syncer.set_active(false);
        tracing::info!(
            "sync startup: NuDB already has complete state tree for ledger {} root={} — finalizing disk handoff",
            sync_header.sequence,
            hex::encode_upper(&sync_header.account_hash[..8]),
        );
        Some((syncer.take_shamap(), sync_header, sync_info))
    }

    pub fn plan_header_trigger(
        &self,
        header: crate::ledger::LedgerHeader,
        ld: &crate::proto::TmLedgerData,
        backend: Option<Arc<dyn crate::ledger::node_store::NodeStore>>,
        leaf_count: Option<usize>,
        open_peers: usize,
        already_syncing: bool,
        sync_in_progress: bool,
        is_current: bool,
    ) -> HeaderTriggerPlan {
        let mut plan = HeaderTriggerPlan {
            ignore_mismatched_fixed_target: None,
            restart_fixed_target: false,
            retarget_fixed_target: false,
            installed_syncer: false,
            sync_lock_busy: false,
            sync_completed_from_disk: false,
            completed_from_disk: None,
            bootstrap: None,
        };

        let mut guard = match self.try_lock_sync_for_header_trigger() {
            Some(guard) => guard,
            None => {
                plan.sync_lock_busy = true;
                return plan;
            }
        };

        if !already_syncing {
            if let Some(syncer) = guard.as_mut() {
                if !syncer.active() {
                    let target_hash = *syncer.ledger_hash();
                    let target_seq = syncer.ledger_seq();
                    if header.hash != target_hash {
                        if is_current && header.sequence > target_seq {
                            syncer.retarget(
                                header.sequence,
                                header.hash,
                                header.account_hash,
                                header.clone(),
                            );
                            let seed_count = open_peers.max(1);
                            plan.bootstrap =
                                Self::bootstrap_plan_from_wire(syncer, ld, seed_count, true);
                            self.set_bootstrap_active(true);
                            self.set_target_hash(header.hash);
                            self.set_gate_accepts_ltclosed(false);
                            plan.restart_fixed_target = true;
                            plan.retarget_fixed_target = true;
                            return plan;
                        }
                        plan.ignore_mismatched_fixed_target = Some((target_seq, target_hash));
                        return plan;
                    }
                    let target_header = syncer.sync_header.clone();
                    drop(guard);
                    let mut restarted = crate::sync_coordinator::SyncCoordinator::new(
                        target_header.sequence,
                        target_header.hash,
                        target_header.account_hash,
                        backend.clone(),
                        target_header.clone(),
                    );
                    if let Some(count) = leaf_count {
                        restarted.seed_persisted_leaf_count(count);
                    }
                    if let Some(completed) =
                        Self::complete_from_disk_if_ready(&mut restarted, leaf_count, &self.metrics)
                    {
                        let mut guard = match self.try_lock_sync_for_header_trigger() {
                            Some(guard) => guard,
                            None => {
                                plan.sync_lock_busy = true;
                                return plan;
                            }
                        };
                        let target_still_waiting = guard.as_ref().is_some_and(|syncer| {
                            !syncer.active()
                                && syncer.ledger_seq() == target_header.sequence
                                && syncer.ledger_hash() == &target_header.hash
                        });
                        if !target_still_waiting {
                            return plan;
                        }
                        self.set_bootstrap_active(false);
                        self.set_target_hash([0u8; 32]);
                        self.set_gate_accepts_ltclosed(false);
                        *guard = None;
                        plan.restart_fixed_target = true;
                        plan.sync_completed_from_disk = true;
                        plan.completed_from_disk = Some(completed);
                        return plan;
                    }
                    let seed_count = open_peers.max(1);
                    plan.bootstrap =
                        Self::bootstrap_plan_from_wire(&mut restarted, ld, seed_count, true);
                    let mut guard = match self.try_lock_sync_for_header_trigger() {
                        Some(guard) => guard,
                        None => {
                            plan.sync_lock_busy = true;
                            return plan;
                        }
                    };
                    let target_still_waiting = guard.as_ref().is_some_and(|syncer| {
                        !syncer.active()
                            && syncer.ledger_seq() == target_header.sequence
                            && syncer.ledger_hash() == &target_header.hash
                    });
                    if !target_still_waiting {
                        return plan;
                    }
                    self.set_bootstrap_active(true);
                    self.set_target_hash(target_hash);
                    self.set_gate_accepts_ltclosed(target_hash == [0u8; 32]);
                    *guard = Some(restarted);
                    plan.restart_fixed_target = true;
                    return plan;
                }
            }
        }

        if guard.is_none() && !(already_syncing || sync_in_progress) {
            drop(guard);
            let mut syncer = crate::sync_coordinator::SyncCoordinator::new(
                header.sequence,
                header.hash,
                header.account_hash,
                backend,
                header,
            );
            if let Some(count) = leaf_count {
                syncer.seed_persisted_leaf_count(count);
            }
            if let Some(completed) =
                Self::complete_from_disk_if_ready(&mut syncer, leaf_count, &self.metrics)
            {
                let guard = match self.try_lock_sync_for_header_trigger() {
                    Some(guard) => guard,
                    None => {
                        plan.sync_lock_busy = true;
                        return plan;
                    }
                };
                if guard.is_some() {
                    return plan;
                }
                drop(guard);
                self.set_bootstrap_active(false);
                self.set_target_hash([0u8; 32]);
                self.set_gate_accepts_ltclosed(false);
                plan.sync_completed_from_disk = true;
                plan.completed_from_disk = Some(completed);
                return plan;
            }
            if plan.bootstrap.is_none() {
                plan.bootstrap = Self::bootstrap_plan_from_wire(&mut syncer, ld, 6, false);
            }
            let target_hash = *syncer.ledger_hash();
            let mut guard = match self.try_lock_sync_for_header_trigger() {
                Some(guard) => guard,
                None => {
                    plan.sync_lock_busy = true;
                    return plan;
                }
            };
            if guard.is_some() {
                return plan;
            }
            self.set_bootstrap_active(true);
            self.set_target_hash(target_hash);
            self.set_gate_accepts_ltclosed(target_hash == [0u8; 32]);
            *guard = Some(syncer);
            plan.installed_syncer = true;
            return plan;
        }

        if plan.bootstrap.is_none() {
            if !already_syncing {
                let seed_count = if plan.restart_fixed_target {
                    open_peers.max(1)
                } else {
                    6
                };
                if let Some(syncer) = guard.as_mut() {
                    plan.bootstrap = Self::bootstrap_plan_from_wire(
                        syncer,
                        ld,
                        seed_count,
                        plan.restart_fixed_target,
                    );
                }
            }
        }

        plan
    }

    pub fn install_syncer(&self, syncer: crate::sync_coordinator::SyncCoordinator) -> bool {
        let target_hash = *syncer.ledger_hash();
        let accepts_ltclosed = syncer.peer.accepts_ltclosed_responses();
        if let Ok(mut guard) = self.try_lock_sync() {
            *guard = Some(syncer);
            self.set_bootstrap_active(true);
            self.set_target_hash(target_hash);
            self.set_gate_accepts_ltclosed(accepts_ltclosed);
            true
        } else {
            false
        }
    }

    fn try_lock_sync_for_header_trigger(
        &self,
    ) -> Option<MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>>> {
        const HEADER_TRIGGER_LOCK_RETRIES: usize = 4;

        for attempt in 0..HEADER_TRIGGER_LOCK_RETRIES {
            match self.try_lock_sync() {
                Ok(guard) => return Some(guard),
                Err(TryLockError::Poisoned(err)) => return Some(err.into_inner()),
                Err(TryLockError::WouldBlock) if attempt + 1 < HEADER_TRIGGER_LOCK_RETRIES => {
                    std::thread::yield_now();
                }
                Err(TryLockError::WouldBlock) => return None,
            }
        }

        None
    }

    pub fn trigger_timeout_blocking(
        &self,
        storage: &Option<Arc<crate::storage::Storage>>,
    ) -> SyncTimeoutResult {
        let lock_wait = std::time::Instant::now();
        let mut guard = self.sync.lock().unwrap_or_else(|e| e.into_inner());
        let lock_wait_ms = lock_wait.elapsed().as_millis();
        let hold_start = std::time::Instant::now();
        let _store_ref = storage.as_ref().map(|s| s.as_ref());

        let syncer = match guard.as_mut() {
            Some(s) if s.active() => s,
            _ => {
                drop(guard);
                return SyncTimeoutResult {
                    reqs: vec![],
                    sync_seq: 0,
                    abandon: false,
                    completed: None,
                };
            }
        };

        let sync_seq = syncer.ledger_seq();
        let response_idle_secs = syncer.peer.last_response.elapsed().as_secs();
        let useful_idle_secs = syncer.peer.last_new_nodes.elapsed().as_secs();
        let cookies_out = syncer.peer.outstanding_cookie_count();
        let recent_count = syncer.peer.recent_node_count();
        let inner_count = syncer.inner_count();
        let leaf_count = syncer.leaf_count();
        let in_flight_count = syncer.in_flight();

        tracing::info!(
            "sync tick: active={} in_flight={} inner={} leaf={} pass={} cookies={} recent={} useful-idle={}s response-idle={}s",
            syncer.active(), in_flight_count,
            inner_count, leaf_count, syncer.pass_number(),
            cookies_out, recent_count, useful_idle_secs, response_idle_secs,
        );

        let hold_ms = hold_start.elapsed().as_millis();
        if lock_wait_ms > 5 || hold_ms > 20 {
            tracing::info!(
                "sync trigger(timeout): lock_wait={}ms hold={}ms",
                lock_wait_ms,
                hold_ms
            );
        }
        drop(guard);

        let completion = crate::sync_epoch::check_sync_completion(
            self.sync.clone(),
            self.tuning.completion_check_interval(),
        );
        if completion.checked {
            let complete = completion.completed.is_some();
            self.metrics
                .note_completion_check(completion.plausible, complete);
        }
        if let Some((completed_shamap, sync_header, sync_info)) = completion.completed {
            tracing::info!(
                "sync timer: complete tree detected on timeout path for ledger {} — finalizing handoff",
                completion.sync_seq,
            );
            return SyncTimeoutResult {
                reqs: vec![],
                sync_seq: completion.sync_seq,
                abandon: false,
                completed: Some((completed_shamap, sync_header, sync_info)),
            };
        }

        let mut guard = self.sync.lock().unwrap_or_else(|e| e.into_inner());
        let syncer = match guard.as_mut() {
            Some(s) if s.active() => s,
            _ => {
                drop(guard);
                return SyncTimeoutResult {
                    reqs: vec![],
                    sync_seq,
                    abandon: false,
                    completed: None,
                };
            }
        };
        let sync_seq = syncer.ledger_seq();
        let timeout_plan = syncer.plan_timeout_tick_tuned(
            self.tuning.sync_timeout_retries,
            self.tuning.object_fallback_after_timeouts,
            self.tuning.object_fallback_batch_size,
        );
        match timeout_plan {
            crate::sync_coordinator::TimeoutPlan::Progress => {
                let should_idle_pump = syncer.state_request_in_flight() == 0
                    && (syncer.useful_idle() >= self.tuning.idle_pump_after()
                        || syncer.response_idle() >= self.tuning.idle_pump_after());
                drop(guard);
                let idle_pump_reqs = if should_idle_pump {
                    crate::sync_epoch::build_reply_followup_requests(
                        self.sync.clone(),
                        self.tuning.sync_reply_followup_peers,
                    )
                    .reqs
                } else {
                    Vec::new()
                };
                if !idle_pump_reqs.is_empty() {
                    tracing::info!(
                        "sync timer: idle pump issued {} reply request(s) (inner={} leaf={} useful-idle={}s response-idle={}s)",
                        idle_pump_reqs.len(),
                        inner_count,
                        leaf_count,
                        useful_idle_secs,
                        response_idle_secs,
                    );
                }
                if useful_idle_secs >= 3 || response_idle_secs >= 3 {
                    tracing::info!(
                        "sync timer: progress tick (in_flight={} inner={} leaf={} useful-idle={}s response-idle={}s)",
                        in_flight_count,
                        inner_count,
                        leaf_count,
                        useful_idle_secs,
                        response_idle_secs,
                    );
                }
                SyncTimeoutResult {
                    reqs: idle_pump_reqs,
                    sync_seq,
                    abandon: false,
                    completed: None,
                }
            }
            crate::sync_coordinator::TimeoutPlan::RestartPass {
                progress_this_pass,
                timeout_count,
                request,
            } => {
                let pass_number = syncer.pass_number();
                let in_flight = syncer.in_flight();
                drop(guard);
                let reqs = crate::sync_epoch::build_timeout_requests(self.sync.clone(), request);
                tracing::info!(
                    "sync timer: restarting stalled pass {} ({} new this pass, in_flight={}, retries={}, followup_reqs={})",
                    pass_number,
                    progress_this_pass,
                    in_flight,
                    timeout_count,
                    reqs.len(),
                );
                SyncTimeoutResult {
                    reqs,
                    sync_seq,
                    abandon: false,
                    completed: None,
                }
            }
            crate::sync_coordinator::TimeoutPlan::Deactivate { timeout_count } => {
                let in_flight = syncer.in_flight();
                tracing::warn!(
                    "sync timer: marking fixed target inactive after {} timeouts (in_flight={}); awaiting reacquire or current-ledger retarget",
                    timeout_count,
                    in_flight,
                );
                drop(guard);
                SyncTimeoutResult {
                    reqs: vec![],
                    sync_seq,
                    abandon: false,
                    completed: None,
                }
            }
            crate::sync_coordinator::TimeoutPlan::Request {
                timeout_count,
                use_object_fallback,
                request,
            } => {
                let in_flight = syncer.in_flight();
                let state_request_in_flight = syncer.state_request_in_flight();
                drop(guard);
                let reqs = crate::sync_epoch::build_timeout_requests(self.sync.clone(), request);
                if use_object_fallback {
                    if reqs.is_empty() {
                        self.metrics.note_object_fallback_no_request();
                    } else {
                        self.metrics.note_object_fallback_request(reqs.len());
                    }
                }
                if reqs.is_empty() {
                    let fallback_reqs = if state_request_in_flight == 0 {
                        crate::sync_epoch::build_reply_followup_requests(
                            self.sync.clone(),
                            crate::ledger::inbound::REPLY_FOLLOWUP_PEERS,
                        )
                        .reqs
                    } else {
                        Vec::new()
                    };
                    tracing::warn!(
                        "sync timeout produced no request (attempt #{} in_flight={} cookies={} recent={} mode={} fallback_reqs={})",
                        timeout_count,
                        in_flight,
                        cookies_out,
                        recent_count,
                        if use_object_fallback { "getobjects" } else { "getledger" },
                        fallback_reqs.len(),
                    );
                    return SyncTimeoutResult {
                        reqs: fallback_reqs,
                        sync_seq,
                        abandon: false,
                        completed: None,
                    };
                }
                tracing::info!(
                    "sync stall ({}s useful-idle, {}s response-idle) — timeout-retrying (attempt #{}, mode={})",
                    useful_idle_secs,
                    response_idle_secs,
                    timeout_count,
                    if use_object_fallback { "getobjects" } else { "getledger" },
                );
                SyncTimeoutResult {
                    reqs,
                    sync_seq,
                    abandon: false,
                    completed: None,
                }
            }
        }
    }

    pub fn round_robin(&self) -> &AtomicUsize {
        &self.round_robin
    }

    pub fn set_target_hash(&self, hash: [u8; 32]) {
        *self.target_hash.lock().unwrap_or_else(|e| e.into_inner()) = hash;
    }

    pub fn target_hash(&self) -> [u8; 32] {
        *self.target_hash.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_gate_accepts_ltclosed(&self, accepts: bool) {
        self.gate_accepts_ltclosed.store(accepts, Ordering::Relaxed);
    }

    fn sync_data_keep_context(&self) -> SyncDataKeepContext {
        let outstanding_cookies = match self.sync.try_lock() {
            Ok(guard) => guard
                .as_ref()
                .map(|syncer| syncer.peer.outstanding_cookies.clone()),
            Err(TryLockError::Poisoned(err)) => err
                .into_inner()
                .as_ref()
                .map(|syncer| syncer.peer.outstanding_cookies.clone()),
            Err(TryLockError::WouldBlock) => None,
        };
        SyncDataKeepContext {
            target_hash: self.target_hash(),
            outstanding_cookies,
        }
    }

    #[cfg(test)]
    pub fn target_hash8(&self) -> u64 {
        u64::from_be_bytes(self.target_hash()[..8].try_into().unwrap_or([0; 8]))
    }

    pub fn set_bootstrap_active(&self, active: bool) {
        self.bootstrap_active.store(active, Ordering::Relaxed);
    }

    pub fn bootstrap_active(&self) -> bool {
        self.bootstrap_active.load(Ordering::Relaxed)
    }

    pub fn queue_sync_data(&self, peer_id: PeerId, msg: crate::proto::TmLedgerData) {
        let keep_context = self.sync_data_keep_context();
        let mut q = self.data_queue.lock().unwrap_or_else(|e| e.into_inner());
        let msg_bytes = estimate_ledger_data_bytes(&msg);
        q.bytes = q.bytes.saturating_add(msg_bytes);
        q.items.push_back(SyncDataQueueItem {
            peer_id,
            msg,
            bytes: msg_bytes,
        });
        let mut dropped = 0usize;
        let mut dropped_bytes = 0usize;
        while sync_data_peer_partition_len(&q.items, q.items.len().saturating_sub(1))
            > self.tuning.sync_data_queue_per_peer
        {
            let newest_index = q.items.len().saturating_sub(1);
            let Some(drop_index) =
                choose_sync_data_peer_drop_index(&q.items, newest_index, &keep_context)
            else {
                break;
            };
            let Some(item) = q.items.remove(drop_index) else {
                break;
            };
            let bytes = item.bytes;
            q.bytes = q.bytes.saturating_sub(bytes);
            dropped += 1;
            dropped_bytes = dropped_bytes.saturating_add(bytes);
        }
        while sync_data_partition_len(&q.items, q.items.len().saturating_sub(1))
            > self.tuning.sync_data_queue_per_ledger
        {
            let newest_index = q.items.len().saturating_sub(1);
            let Some(drop_index) =
                choose_sync_data_partition_drop_index(&q.items, newest_index, &keep_context)
            else {
                break;
            };
            let Some(item) = q.items.remove(drop_index) else {
                break;
            };
            let bytes = item.bytes;
            q.bytes = q.bytes.saturating_sub(bytes);
            dropped += 1;
            dropped_bytes = dropped_bytes.saturating_add(bytes);
        }
        while q.items.len() > self.tuning.sync_data_queue_max
            || q.bytes > self.tuning.sync_data_queue_bytes
        {
            let Some(drop_index) = choose_sync_data_drop_index(&q.items, &keep_context) else {
                q.bytes = 0;
                break;
            };
            let Some(item) = q.items.remove(drop_index) else {
                break;
            };
            let bytes = item.bytes;
            q.bytes = q.bytes.saturating_sub(bytes);
            dropped += 1;
            dropped_bytes = dropped_bytes.saturating_add(bytes);
        }
        self.metrics
            .queued_responses_total
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .queued_response_bytes_total
            .fetch_add(msg_bytes as u64, Ordering::Relaxed);
        SyncMetrics::set_max(&self.metrics.max_queue_len, q.items.len() as u64);
        SyncMetrics::set_max(&self.metrics.max_queue_bytes, q.bytes as u64);
        if dropped > 0 {
            self.metrics
                .dropped_responses_total
                .fetch_add(dropped as u64, Ordering::Relaxed);
            self.metrics
                .dropped_response_bytes_total
                .fetch_add(dropped_bytes as u64, Ordering::Relaxed);
            tracing::warn!(
                "sync data queue capped: dropped {} stale queued response(s) ({} bytes), remaining={} ({} bytes)",
                dropped,
                dropped_bytes,
                q.items.len(),
                q.bytes,
            );
        }
        drop(q);
        self.data_notify.notify_one();
    }

    pub fn take_sync_data_batch(&self) -> Vec<(PeerId, crate::proto::TmLedgerData)> {
        let mut q = self.data_queue.lock().unwrap_or_else(|e| e.into_inner());
        let batch_len = q.items.len().min(self.tuning.sync_data_batch_size);
        let mut batch = Vec::with_capacity(batch_len);
        for _ in 0..batch_len {
            if let Some(item) = q.items.pop_front() {
                q.bytes = q.bytes.saturating_sub(item.bytes);
                batch.push((item.peer_id, item.msg));
            }
        }
        if !batch.is_empty() {
            self.metrics
                .dequeued_responses_total
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
        }
        batch
    }

    pub fn clear_sync_data_queue(&self) {
        let mut q = self.data_queue.lock().unwrap_or_else(|e| e.into_inner());
        let dropped = q.items.len();
        let dropped_bytes = q.bytes;
        q.items.clear();
        q.bytes = 0;
        if dropped > 0 {
            self.metrics
                .cleared_responses_total
                .fetch_add(dropped as u64, Ordering::Relaxed);
            self.metrics
                .cleared_response_bytes_total
                .fetch_add(dropped_bytes as u64, Ordering::Relaxed);
            tracing::info!(
                "sync data queue cleared: dropped {} queued response(s) ({} bytes)",
                dropped,
                dropped_bytes
            );
        }
    }

    pub fn sync_data_queue_stats(&self) -> (usize, usize) {
        let q = self.data_queue.lock().unwrap_or_else(|e| e.into_inner());
        (q.items.len(), q.bytes)
    }

    pub fn data_notify(&self) -> Arc<Notify> {
        self.data_notify.clone()
    }

    pub fn gate_accepts_response(
        &self,
        resp_hash: Option<&[u8]>,
        _object_seq: Option<u32>,
        is_object_response: bool,
    ) -> bool {
        let target_hash = self.target_hash();
        let hash_matches_target = resp_hash.is_some_and(|hash| {
            hash.len() == 32 && target_hash != [0u8; 32] && hash == target_hash
        });

        if hash_matches_target {
            self.metrics
                .gate_accept_total
                .fetch_add(1, Ordering::Relaxed);
            return true;
        }

        if self.gate_accepts_ltclosed.load(Ordering::Relaxed)
            && resp_hash.is_some_and(|hash| hash.len() == 32)
        {
            self.metrics
                .gate_accept_total
                .fetch_add(1, Ordering::Relaxed);
            return true;
        }

        let Ok(guard) = self.sync.try_lock() else {
            self.metrics
                .gate_lock_busy_total
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let Some(syncer) = guard.as_ref() else {
            self.metrics
                .gate_reject_total
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .gate_invalid_total
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let accepted = if is_object_response {
            if syncer.peer.accepts_ltclosed_responses() {
                resp_hash.is_some_and(|hash| hash.len() == 32)
            } else {
                hash_matches_target
            }
        } else if !syncer.peer.accepts_ltclosed_responses() {
            false
        } else {
            resp_hash.is_some_and(|hash| hash.len() == 32)
        };
        if accepted {
            self.metrics
                .gate_accept_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics
                .gate_reject_total
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .gate_invalid_total
                .fetch_add(1, Ordering::Relaxed);
        }
        accepted
    }
}

fn estimate_ledger_data_bytes(msg: &crate::proto::TmLedgerData) -> usize {
    msg.ledger_hash.len()
        + msg
            .nodes
            .iter()
            .map(|node| {
                node.nodedata.len() + node.nodeid.as_ref().map_or(0, |node_id| node_id.len()) + 64
            })
            .sum::<usize>()
        + 128
}

fn choose_sync_data_drop_index(
    items: &VecDeque<SyncDataQueueItem>,
    keep_context: &SyncDataKeepContext,
) -> Option<usize> {
    items
        .iter()
        .enumerate()
        .min_by_key(|(_, item)| sync_data_keep_score(item, keep_context))
        .map(|(index, _)| index)
}

fn choose_sync_data_partition_drop_index(
    items: &VecDeque<SyncDataQueueItem>,
    partition_index: usize,
    keep_context: &SyncDataKeepContext,
) -> Option<usize> {
    let partition = sync_data_ledger_key(&items.get(partition_index)?.msg);
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| sync_data_ledger_key(&item.msg) == partition)
        .min_by_key(|(_, item)| sync_data_keep_score(item, keep_context))
        .map(|(index, _)| index)
}

fn choose_sync_data_peer_drop_index(
    items: &VecDeque<SyncDataQueueItem>,
    partition_index: usize,
    keep_context: &SyncDataKeepContext,
) -> Option<usize> {
    let partition = items
        .get(partition_index)
        .map(|item| (item.peer_id, sync_data_ledger_key(&item.msg)))?;
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| (item.peer_id, sync_data_ledger_key(&item.msg)) == partition)
        .min_by_key(|(_, item)| sync_data_keep_score(item, keep_context))
        .map(|(index, _)| index)
}

fn sync_data_partition_len(items: &VecDeque<SyncDataQueueItem>, partition_index: usize) -> usize {
    let Some(partition) = items
        .get(partition_index)
        .map(|item| sync_data_ledger_key(&item.msg))
    else {
        return 0;
    };
    items
        .iter()
        .filter(|item| sync_data_ledger_key(&item.msg) == partition)
        .count()
}

fn sync_data_peer_partition_len(
    items: &VecDeque<SyncDataQueueItem>,
    partition_index: usize,
) -> usize {
    let Some(partition) = items
        .get(partition_index)
        .map(|item| (item.peer_id, sync_data_ledger_key(&item.msg)))
    else {
        return 0;
    };
    items
        .iter()
        .filter(|item| (item.peer_id, sync_data_ledger_key(&item.msg)) == partition)
        .count()
}

fn sync_data_ledger_key(msg: &crate::proto::TmLedgerData) -> Option<[u8; 32]> {
    if msg.ledger_hash.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&msg.ledger_hash);
    Some(hash)
}

fn sync_data_keep_score(item: &SyncDataQueueItem, keep_context: &SyncDataKeepContext) -> u8 {
    let hash_matches = item.msg.ledger_hash.len() == 32
        && (keep_context.target_hash == [0u8; 32]
            || item.msg.ledger_hash.as_slice() == keep_context.target_hash);
    if !hash_matches {
        return 0;
    }
    match (
        item.msg.request_cookie,
        keep_context.outstanding_cookies.as_ref(),
    ) {
        (Some(cookie), Some(outstanding)) if outstanding.contains(&cookie) => 3,
        (None, Some(_)) => 2,
        (Some(_), Some(_)) => 1,
        (Some(_), None) => 2,
        (None, None) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::SyncRuntime;
    use std::sync::Arc;

    fn test_header(seq: u32, byte: u8) -> crate::ledger::LedgerHeader {
        crate::ledger::LedgerHeader {
            sequence: seq,
            hash: [byte; 32],
            parent_hash: [byte.wrapping_sub(1); 32],
            close_time: seq as u64,
            total_coins: 100_000_000_000,
            account_hash: [byte.wrapping_add(1); 32],
            transaction_hash: [byte.wrapping_add(2); 32],
            parent_close_time: seq.saturating_sub(1),
            close_time_resolution: 30,
            close_flags: 0,
        }
    }

    fn test_state_wire() -> crate::proto::TmLedgerData {
        crate::proto::TmLedgerData {
            ledger_hash: vec![0x11; 32],
            ledger_seq: 100,
            r#type: crate::proto::TmLedgerInfoType::LiBase as i32,
            nodes: vec![
                crate::proto::TmLedgerNode {
                    nodedata: vec![0u8; 32],
                    nodeid: None,
                },
                crate::proto::TmLedgerNode {
                    nodedata: {
                        let mut root = vec![0u8; 516];
                        root[0..4].copy_from_slice(b"MIN\0");
                        for branch in 0..16usize {
                            let off = 4 + branch * 32;
                            root[off..off + 32].fill((branch as u8) + 1);
                        }
                        root
                    },
                    nodeid: None,
                },
            ],
            request_cookie: None,
            error: None,
        }
    }

    fn test_state_wire_for(hash_byte: u8, cookie: Option<u32>) -> crate::proto::TmLedgerData {
        let mut msg = test_state_wire();
        msg.ledger_hash = vec![hash_byte; 32];
        msg.request_cookie = cookie;
        msg
    }

    fn flushed_backend_with_state_root() -> (Arc<dyn crate::ledger::node_store::NodeStore>, [u8; 32])
    {
        let backend: Arc<dyn crate::ledger::node_store::NodeStore> =
            Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let mut map = crate::ledger::shamap::SHAMap::with_backend(
            crate::ledger::MapType::AccountState,
            backend.clone(),
        );
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
    fn plan_header_trigger_ignores_wrong_fixed_target_hash() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let mut syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            header.hash,
            header.account_hash,
            None,
            header.clone(),
        );
        syncer.set_active(false);
        assert!(runtime.install_syncer(syncer));

        let wrong = test_header(100, 0x22);
        let plan = runtime.plan_header_trigger(
            wrong,
            &test_state_wire(),
            None,
            None,
            4,
            false,
            false,
            false,
        );
        assert_eq!(plan.ignore_mismatched_fixed_target, Some((100, [0x11; 32])));
        assert!(!plan.restart_fixed_target);
        assert!(plan.bootstrap.is_none());
    }

    #[test]
    fn sync_metrics_track_queue_drop_and_gate_busy() {
        let runtime = SyncRuntime::new();
        for _ in 0..130 {
            runtime.queue_sync_data(super::PeerId(1), test_state_wire());
        }
        let snap = runtime.metrics_snapshot();
        assert_eq!(snap.queued_responses_total, 130);
        assert!(snap.dropped_responses_total > 0);
        assert!(snap.queued_response_bytes_total > 0);
        assert!(snap.max_queue_len > 0);
        assert!(snap.max_queue_bytes > 0);

        let _guard = runtime.lock_sync();
        assert!(!runtime.gate_accepts_response(Some(&[0x22; 32]), None, false));
        let snap = runtime.metrics_snapshot();
        assert_eq!(snap.gate_lock_busy_total, 1);
        assert_eq!(snap.gate_reject_total, 0);
        assert_eq!(snap.gate_invalid_total, 0);

        runtime.note_route_message("LedgerData", 25, false);
        runtime.note_route_message("LedgerData", 125, true);
        runtime.note_route_queue_enqueued(3, 256);
        runtime.note_route_queue_full(256);
        runtime.note_route_queue_inline();
        runtime.note_route_queue_full_for(super::PeerId(7), "LedgerData", 256);
        runtime.note_route_queue_inline_for(super::PeerId(7), "LedgerData");
        runtime.note_route_queue_dropped_for(super::PeerId(7), "LedgerData");
        let snap = runtime.metrics_snapshot();
        let ledger_data = snap
            .route_message_types
            .iter()
            .find(|entry| entry.message_type == "LedgerData")
            .expect("LedgerData route metrics");
        assert_eq!(ledger_data.total, 2);
        assert_eq!(ledger_data.slow_total, 1);
        assert_eq!(ledger_data.max_ms, 125);
        assert_eq!(snap.route_queue_enqueued_total, 1);
        assert_eq!(snap.route_queue_full_total, 2);
        assert_eq!(snap.route_queue_inline_total, 2);
        assert_eq!(snap.route_queue_dropped_total, 1);
        assert_eq!(snap.route_queue_max_len, 3);
        assert_eq!(snap.route_queue_capacity, 256);
        assert_eq!(snap.route_queue_peers.len(), 1);
        assert_eq!(snap.route_queue_peers[0].peer_id, "7");
        assert_eq!(snap.route_queue_peers[0].message_type, "LedgerData");
        assert_eq!(snap.route_queue_peers[0].full_total, 1);
        assert_eq!(snap.route_queue_peers[0].inline_retry_total, 1);
        assert_eq!(snap.route_queue_peers[0].dropped_total, 1);

        runtime.note_worker_lane_enqueued("sync_parse", 2);
        runtime.note_worker_lane_capacity("sync_parse", 4);
        runtime.note_worker_lane_started("sync_parse");
        runtime.note_worker_lane_enqueued("sync_parse", 4);
        runtime.note_worker_lane_started("sync_parse");
        runtime.note_worker_lane_backpressure("sync_parse", 25);
        runtime.note_worker_lane_finished("sync_parse", true);
        runtime.note_worker_lane_finished("sync_parse", false);
        let snap = runtime.metrics_snapshot();
        let parse_lane = snap
            .worker_lanes
            .iter()
            .find(|entry| entry.lane == "sync_parse")
            .expect("sync_parse worker lane metrics");
        assert_eq!(parse_lane.enqueued_total, 2);
        assert_eq!(parse_lane.started_total, 2);
        assert_eq!(parse_lane.completed_total, 1);
        assert_eq!(parse_lane.failed_total, 1);
        assert_eq!(parse_lane.in_flight, 0);
        assert_eq!(parse_lane.max_in_flight, 2);
        assert_eq!(parse_lane.queue_capacity, 4);
        assert_eq!(parse_lane.max_queue_depth, 4);
        assert_eq!(parse_lane.backpressure_total, 1);
        assert_eq!(parse_lane.max_backpressure_ms, 25);

        runtime.metrics().note_object_fallback_request(3);
        runtime.metrics().note_object_fallback_no_request();
        runtime.note_object_fallback_response(true, 7, 2, 9);
        runtime.note_object_fallback_response(false, 0, 0, 0);
        let snap = runtime.metrics_snapshot();
        assert_eq!(snap.object_fallback_requests_total, 3);
        assert_eq!(snap.object_fallback_no_request_total, 1);
        assert_eq!(snap.object_fallback_responses_total, 2);
        assert_eq!(snap.object_fallback_accepted_total, 1);
        assert_eq!(snap.object_fallback_rejected_total, 1);
        assert_eq!(snap.object_fallback_stored_total, 7);
        assert_eq!(snap.object_fallback_duplicate_total, 2);
        assert_eq!(snap.object_fallback_empty_total, 1);

        runtime.metrics().note_completion_check(false, false);
        runtime.metrics().note_completion_check(true, false);
        runtime.metrics().note_completion_check(true, true);
        runtime.metrics().note_completion_disk_complete();
        runtime.note_completion_anchor_blocked();
        runtime.note_diff_sync_discarded();
        let snap = runtime.metrics_snapshot();
        assert_eq!(snap.completion_checks_total, 3);
        assert_eq!(snap.completion_plausible_total, 2);
        assert_eq!(snap.completion_true_total, 1);
        assert_eq!(snap.completion_false_total, 2);
        assert_eq!(snap.completion_disk_complete_total, 1);
        assert_eq!(snap.completion_anchor_blocked_total, 1);
        assert_eq!(snap.diff_sync_discarded_total, 1);
    }

    #[test]
    fn sync_data_queue_drops_stale_before_cookie_matched_responses() {
        let runtime = SyncRuntime::new();
        runtime.set_target_hash([0x11; 32]);
        let tuning = runtime.tuning().clone();

        for i in 0..tuning.sync_data_queue_max {
            runtime.queue_sync_data(
                super::PeerId(i as u64),
                test_state_wire_for(0x11, Some(i as u32)),
            );
        }
        runtime.queue_sync_data(super::PeerId(999), test_state_wire_for(0x22, None));

        let batch = runtime.take_sync_data_batch();
        assert_eq!(batch.len(), tuning.sync_data_batch_size);
        assert!(batch
            .iter()
            .all(|(_, msg)| msg.ledger_hash == vec![0x11; 32] && msg.request_cookie.is_some()));
        assert!(runtime.metrics_snapshot().dropped_responses_total > 0);
    }

    #[test]
    fn sync_runtime_uses_operator_queue_and_batch_tuning() {
        let runtime = SyncRuntime::with_tuning(crate::node::SyncTuningConfig {
            sync_data_queue_max: 3,
            sync_data_queue_per_ledger: 3,
            sync_data_queue_per_peer: 3,
            sync_data_batch_size: 2,
            ..crate::node::SyncTuningConfig::default()
        });

        for i in 0..5 {
            runtime.queue_sync_data(
                super::PeerId(i as u64),
                test_state_wire_for(0x11, Some(i as u32)),
            );
        }

        let batch = runtime.take_sync_data_batch();
        assert_eq!(batch.len(), 2);
        assert!(runtime.metrics_snapshot().dropped_responses_total >= 2);
    }

    #[test]
    fn sync_data_queue_caps_each_ledger_partition() {
        let runtime = SyncRuntime::new();
        let per_ledger = runtime.tuning().sync_data_queue_per_ledger;

        for i in 0..(per_ledger + 8) {
            runtime.queue_sync_data(
                super::PeerId(i as u64),
                test_state_wire_for(0x11, Some(i as u32)),
            );
        }
        for i in 0..8 {
            runtime.queue_sync_data(
                super::PeerId((1000 + i) as u64),
                test_state_wire_for(0x22, Some(i as u32)),
            );
        }

        let mut seen_hashes = std::collections::BTreeSet::new();
        loop {
            let batch = runtime.take_sync_data_batch();
            if batch.is_empty() {
                break;
            }
            for (_, msg) in batch {
                seen_hashes.insert(msg.ledger_hash[0]);
            }
        }

        assert!(seen_hashes.contains(&0x11));
        assert!(seen_hashes.contains(&0x22));
        assert!(runtime.metrics_snapshot().dropped_responses_total > 0);
    }

    #[test]
    fn sync_data_queue_caps_each_peer_partition() {
        let runtime = SyncRuntime::new();
        let per_peer = runtime.tuning().sync_data_queue_per_peer;

        for i in 0..(per_peer + 8) {
            runtime.queue_sync_data(super::PeerId(1), test_state_wire_for(0x11, Some(i as u32)));
        }
        for i in 0..8 {
            runtime.queue_sync_data(
                super::PeerId(2),
                test_state_wire_for(0x11, Some((1000 + i) as u32)),
            );
        }

        let mut seen_peers = Vec::new();
        loop {
            let batch = runtime.take_sync_data_batch();
            if batch.is_empty() {
                break;
            }
            for (peer_id, _) in batch {
                seen_peers.push(peer_id);
            }
        }

        assert!(seen_peers.contains(&super::PeerId(1)));
        assert!(seen_peers.contains(&super::PeerId(2)));
        assert!(runtime.metrics_snapshot().dropped_responses_total > 0);
    }

    #[test]
    fn sync_data_queue_keeps_outstanding_cookie_before_fallback_response() {
        let runtime = SyncRuntime::new();
        let mut syncer = crate::sync_coordinator::SyncCoordinator::new(
            100,
            [0x11; 32],
            [0x22; 32],
            None,
            test_header(100, 0x11),
        );
        syncer.peer.outstanding_cookies.insert(777);
        assert!(runtime.install_syncer(syncer));

        for i in 0..runtime.tuning().sync_data_queue_per_ledger {
            runtime.queue_sync_data(super::PeerId(i as u64), test_state_wire_for(0x11, None));
        }
        runtime.queue_sync_data(super::PeerId(999), test_state_wire_for(0x11, Some(777)));

        let mut saw_outstanding_cookie = false;
        loop {
            let batch = runtime.take_sync_data_batch();
            if batch.is_empty() {
                break;
            }
            saw_outstanding_cookie |= batch.iter().any(|(_, msg)| msg.request_cookie == Some(777));
        }

        assert!(saw_outstanding_cookie);
        assert!(runtime.metrics_snapshot().dropped_responses_total > 0);
    }

    #[test]
    fn sync_data_queue_drops_stale_cookie_before_same_ledger_fallback_response() {
        let runtime = SyncRuntime::new();
        let mut syncer = crate::sync_coordinator::SyncCoordinator::new(
            100,
            [0x11; 32],
            [0x22; 32],
            None,
            test_header(100, 0x11),
        );
        syncer.peer.outstanding_cookies.insert(777);
        assert!(runtime.install_syncer(syncer));

        for i in 0..runtime.tuning().sync_data_queue_per_ledger {
            runtime.queue_sync_data(super::PeerId(i as u64), test_state_wire_for(0x11, None));
        }
        runtime.queue_sync_data(super::PeerId(999), test_state_wire_for(0x11, Some(778)));

        let mut saw_stale_cookie = false;
        let mut saw_fallback = false;
        loop {
            let batch = runtime.take_sync_data_batch();
            if batch.is_empty() {
                break;
            }
            saw_stale_cookie |= batch.iter().any(|(_, msg)| msg.request_cookie == Some(778));
            saw_fallback |= batch.iter().any(|(_, msg)| msg.request_cookie.is_none());
        }

        assert!(!saw_stale_cookie);
        assert!(saw_fallback);
        assert!(runtime.metrics_snapshot().dropped_responses_total > 0);
    }

    #[test]
    fn plan_header_trigger_retargets_stale_inactive_fixed_target_to_current_header() {
        let runtime = SyncRuntime::new();
        let old_header = test_header(100, 0x11);
        let mut syncer = crate::sync_coordinator::SyncCoordinator::new(
            old_header.sequence,
            old_header.hash,
            old_header.account_hash,
            None,
            old_header,
        );
        syncer.set_active(false);
        assert!(runtime.install_syncer(syncer));

        let current = test_header(101, 0x22);
        let plan = runtime.plan_header_trigger(
            current.clone(),
            &test_state_wire(),
            None,
            None,
            4,
            false,
            false,
            true,
        );

        assert!(plan.restart_fixed_target);
        assert!(plan.retarget_fixed_target);
        assert!(plan.bootstrap.is_some());
        assert_eq!(plan.ignore_mismatched_fixed_target, None);

        let guard = runtime.lock_sync();
        let syncer = guard.as_ref().expect("syncer should remain installed");
        assert!(syncer.active());
        assert_eq!(syncer.ledger_seq(), current.sequence);
        assert_eq!(*syncer.ledger_hash(), current.hash);
    }

    #[test]
    fn plan_header_trigger_installs_new_syncer_and_bootstraps() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let plan = runtime.plan_header_trigger(
            header.clone(),
            &test_state_wire(),
            None,
            None,
            6,
            false,
            false,
            true,
        );
        assert!(plan.installed_syncer);
        assert!(plan.bootstrap.is_some());
        assert!(runtime.has_syncer());
        assert_eq!(
            runtime.target_hash8(),
            u64::from_be_bytes(header.hash[..8].try_into().unwrap())
        );
    }

    #[test]
    fn plan_header_trigger_seeds_persisted_leaf_count_for_resume_metrics() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);

        let plan = runtime.plan_header_trigger(
            header,
            &test_state_wire(),
            None,
            Some(5726),
            6,
            false,
            false,
            true,
        );

        assert!(plan.installed_syncer);
        let guard = runtime.lock_sync();
        let syncer = guard.as_ref().expect("syncer should remain installed");
        assert_eq!(syncer.leaf_count(), 5726);
        assert_eq!(syncer.new_objects_this_pass(), 0);
    }

    #[test]
    fn plan_header_trigger_completes_from_disk_without_bootstrap() {
        let runtime = SyncRuntime::new();
        let (backend, root_hash) = flushed_backend_with_state_root();
        let mut header = test_header(100, 0x11);
        header.account_hash = root_hash;

        let plan = runtime.plan_header_trigger(
            header.clone(),
            &test_state_wire(),
            Some(backend),
            Some(32),
            6,
            false,
            false,
            true,
        );

        assert!(plan.sync_completed_from_disk);
        assert!(plan.completed_from_disk.is_some());
        assert!(plan.bootstrap.is_none());
        assert!(!runtime.has_syncer());
        assert_eq!(runtime.target_hash8(), 0);
    }

    #[test]
    fn clear_syncer_removes_installed_syncer_and_resets_target_hash() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            header.hash,
            header.account_hash,
            None,
            header.clone(),
        );
        assert!(runtime.install_syncer(syncer));
        assert!(runtime.has_syncer());
        assert_ne!(runtime.target_hash8(), 0);

        runtime.clear_syncer();

        assert!(!runtime.has_syncer());
        assert_eq!(runtime.target_hash8(), 0);
    }

    #[test]
    fn gate_accepts_matching_state_response_while_sync_lock_is_busy() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let ledger_hash = header.hash;
        let syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            ledger_hash,
            header.account_hash,
            None,
            header,
        );
        assert!(runtime.install_syncer(syncer));

        let _held = runtime.lock_sync();
        assert!(runtime.gate_accepts_response(Some(&ledger_hash), None, false));
    }

    #[test]
    fn gate_rejects_prefix_only_state_response_while_sync_lock_is_busy() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let ledger_hash = header.hash;
        let syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            ledger_hash,
            header.account_hash,
            None,
            header,
        );
        assert!(runtime.install_syncer(syncer));

        let mut prefix_only = ledger_hash;
        prefix_only[31] = 0x22;
        let _held = runtime.lock_sync();

        assert!(!runtime.gate_accepts_response(Some(&prefix_only), None, false));
    }

    #[test]
    fn gate_accepts_cookieless_object_response_for_target_hash() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let ledger_hash = header.hash;
        let syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            ledger_hash,
            header.account_hash,
            None,
            header,
        );
        assert!(runtime.install_syncer(syncer));

        assert!(runtime.gate_accepts_response(Some(&ledger_hash), None, true));
    }

    #[test]
    fn gate_accepts_matching_object_response_while_sync_lock_is_busy() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let ledger_hash = header.hash;
        let syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            ledger_hash,
            header.account_hash,
            None,
            header,
        );
        assert!(runtime.install_syncer(syncer));

        let _held = runtime.lock_sync();
        assert!(runtime.gate_accepts_response(Some(&ledger_hash), None, true));
    }

    #[test]
    fn gate_rejects_prefix_only_object_response_for_target_hash() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let ledger_hash = header.hash;
        let syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            ledger_hash,
            header.account_hash,
            None,
            header,
        );
        assert!(runtime.install_syncer(syncer));

        let mut prefix_only = ledger_hash;
        prefix_only[31] = 0x22;

        assert!(!runtime.gate_accepts_response(Some(&prefix_only), None, true));
    }

    #[test]
    fn gate_accepts_ltclosed_state_response_while_sync_lock_is_busy() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            [0u8; 32],
            header.account_hash,
            None,
            header,
        );
        assert!(runtime.install_syncer(syncer));

        let _held = runtime.lock_sync();
        assert!(runtime.gate_accepts_response(Some(&[0x44; 32]), None, false));
    }

    #[test]
    fn gate_accepts_ltclosed_object_response_while_sync_lock_is_busy() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            [0u8; 32],
            header.account_hash,
            None,
            header,
        );
        assert!(runtime.install_syncer(syncer));

        let _held = runtime.lock_sync();
        assert!(runtime.gate_accepts_response(Some(&[0x55; 32]), None, true));
    }

    #[test]
    fn plan_header_trigger_restarts_matching_inactive_fixed_target() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let mut syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            header.hash,
            header.account_hash,
            None,
            header.clone(),
        );
        syncer.set_active(false);
        assert!(runtime.install_syncer(syncer));

        let plan = runtime.plan_header_trigger(
            header.clone(),
            &test_state_wire(),
            None,
            Some(123),
            4,
            false,
            false,
            true,
        );

        assert!(plan.restart_fixed_target);
        assert!(plan.bootstrap.is_some());
        assert!(!plan.installed_syncer);

        let guard = runtime.lock_sync();
        let syncer = guard.as_ref().expect("syncer should remain installed");
        assert!(syncer.active());
        assert_eq!(syncer.ledger_seq(), header.sequence);
    }

    #[test]
    fn plan_header_trigger_reports_busy_sync_lock_without_partial_install() {
        let runtime = SyncRuntime::new();
        let _guard = runtime.lock_sync();
        let header = test_header(100, 0x11);

        let plan = runtime.plan_header_trigger(
            header,
            &test_state_wire(),
            None,
            None,
            4,
            false,
            false,
            true,
        );

        assert!(plan.sync_lock_busy);
        assert!(!plan.installed_syncer);
        assert!(!plan.restart_fixed_target);
        assert!(plan.bootstrap.is_none());
    }
}
