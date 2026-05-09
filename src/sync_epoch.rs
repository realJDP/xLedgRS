use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::network::message::RtxpMessage;
use crate::network::peer::PeerId;

pub type CompletedSync = (
    crate::ledger::shamap::SHAMap,
    crate::ledger::LedgerHeader,
    (usize, usize, u32, u32, usize),
);

pub struct ReplyFollowupBuildResult {
    pub reqs: Vec<RtxpMessage>,
    pub sync_seq: u32,
}

pub struct CompletionCheckBuildResult {
    pub checked: bool,
    pub plausible: bool,
    pub completed: Option<CompletedSync>,
    pub sync_seq: u32,
}

pub fn check_sync_completion(
    sync_arc: Arc<Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
    interval: Duration,
) -> CompletionCheckBuildResult {
    let snapshot = {
        let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
        let Some(ref mut syncer) = *guard else {
            return CompletionCheckBuildResult {
                checked: false,
                plausible: false,
                completed: None,
                sync_seq: 0,
            };
        };
        let sync_seq = syncer.ledger_seq();
        if !syncer.active() || !syncer.should_check_completion(interval) {
            return CompletionCheckBuildResult {
                checked: false,
                plausible: false,
                completed: None,
                sync_seq,
            };
        }
        let Some(snapshot) = syncer.completion_check_snapshot() else {
            return CompletionCheckBuildResult {
                checked: false,
                plausible: false,
                completed: None,
                sync_seq,
            };
        };
        snapshot
    };

    let result = crate::sync_coordinator::SyncCoordinator::check_completion_snapshot(snapshot);
    let sync_seq = result.ledger_seq;
    let plausible =
        crate::sync_coordinator::SyncCoordinator::completion_result_is_plausible(&result);

    let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
    let completed = guard
        .as_mut()
        .and_then(|syncer| syncer.apply_completion_check_result(result));
    CompletionCheckBuildResult {
        checked: true,
        plausible,
        completed,
        sync_seq,
    }
}

pub fn build_timeout_requests(
    sync_arc: Arc<Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
    snapshot: Option<crate::sync_coordinator::TimeoutRequestSnapshot>,
) -> Vec<RtxpMessage> {
    let Some(snapshot) = snapshot else {
        return Vec::new();
    };
    let frontier =
        crate::sync_coordinator::SyncCoordinator::walk_timeout_request_frontier(snapshot);
    let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
    let Some(ref mut syncer) = *guard else {
        return Vec::new();
    };
    syncer.build_timeout_requests_from_frontier(frontier)
}

pub fn decay_merge_useful_score(existing: u32, useful: u32) -> u32 {
    existing.saturating_mul(7) / 8 + useful
}

pub fn should_bench_duplicate_sync_peer(duplicate_score: u32, useful_score: u32) -> bool {
    duplicate_score >= 24 && useful_score.saturating_mul(4) <= duplicate_score
}

pub fn apply_useful_peer_counts(
    state: &mut crate::node::SharedState,
    counts: &HashMap<PeerId, u32>,
    now: std::time::Instant,
) {
    for (peer_id, useful) in counts {
        let entry = state.peer_sync_useful.entry(*peer_id).or_insert(0);
        *entry = decay_merge_useful_score(*entry, *useful);
        if let Some(duplicate_score) = state.peer_sync_duplicates.get_mut(peer_id) {
            *duplicate_score = duplicate_score.saturating_mul(3) / 4;
        }
        let total = state.peer_sync_useful_total.entry(*peer_id).or_insert(0);
        *total = total.saturating_add(*useful as u64);
        state.peer_sync_last_useful.insert(*peer_id, now);
    }
}

pub fn apply_duplicate_peer_counts(
    state: &mut crate::node::SharedState,
    counts: &HashMap<PeerId, u32>,
    now: std::time::Instant,
) {
    for (peer_id, duplicates) in counts {
        let entry = state.peer_sync_duplicates.entry(*peer_id).or_insert(0);
        *entry = decay_merge_useful_score(*entry, *duplicates);
        let total = state
            .peer_sync_duplicates_total
            .entry(*peer_id)
            .or_insert(0);
        *total = total.saturating_add(*duplicates as u64);

        let useful_score = state.peer_sync_useful.get(peer_id).copied().unwrap_or(0);
        if should_bench_duplicate_sync_peer(*entry, useful_score) {
            let expires = now + std::time::Duration::from_secs(90);
            state.sync_peer_cooldown.insert(*peer_id, expires);
            tracing::info!(
                "benched duplicate-heavy sync peer {:?}: duplicate_score={} useful_score={}",
                peer_id,
                *entry,
                useful_score,
            );
        }
    }
}

pub fn build_reply_followup_requests(
    sync_arc: Arc<Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
    num_peers: usize,
) -> ReplyFollowupBuildResult {
    let snapshot = {
        let guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
        let Some(ref syncer) = *guard else {
            return ReplyFollowupBuildResult {
                reqs: vec![],
                sync_seq: 0,
            };
        };
        let Some(snapshot) = syncer.reply_followup_frontier_snapshot(num_peers) else {
            return ReplyFollowupBuildResult {
                reqs: vec![],
                sync_seq: 0,
            };
        };
        snapshot
    };

    let frontier = crate::sync_coordinator::SyncCoordinator::walk_reply_followup_frontier(snapshot);

    let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
    let Some(ref mut syncer) = *guard else {
        return ReplyFollowupBuildResult {
            reqs: vec![],
            sync_seq: 0,
        };
    };
    let sync_seq = syncer.ledger_seq();
    let reqs = syncer.build_reply_followup_requests_from_frontier(frontier);
    ReplyFollowupBuildResult { reqs, sync_seq }
}

pub fn processed_debug_line(
    sync_info: (usize, usize, u32, u32, usize),
    walk_ms: u128,
    trigger_ms: u128,
    total_reqs: usize,
    peer_count: usize,
) -> String {
    format!(
        "PROCESSED: {} inner + {} leaf, processData={}ms, trigger={}ms, {} reqs to {} peers",
        sync_info.0, sync_info.1, walk_ms, trigger_ms, total_reqs, peer_count,
    )
}

pub fn sync_progress_info_line(
    nudb_objects: usize,
    sync_info: (usize, usize, u32, u32, usize),
    batch_len: usize,
) -> String {
    let peer_nodes = sync_info.0 + sync_info.1;
    let db_extra = nudb_objects.saturating_sub(peer_nodes);
    format!(
        "sync: {} unique nodes in NuDB | accepted {} peer nodes ({}i {}l) | db_extra={} pass_new={} batch={}",
        nudb_objects,
        peer_nodes,
        sync_info.0,
        sync_info.1,
        db_extra,
        sync_info.4,
        batch_len,
    )
}

pub fn summary_debug_line(
    rate_k_per_min: u64,
    active_peers: usize,
    benched_peers: usize,
    latencies: &[String],
    sync_info: (usize, usize, u32, u32, usize),
) -> String {
    format!(
        "SUMMARY: rate={}K/min, peers={} active/{} benched, latencies=[{}], inner={}, leaf={}, redb=~{}K_objs",
        rate_k_per_min,
        active_peers,
        benched_peers,
        latencies.join(", "),
        sync_info.0,
        sync_info.1,
        0u64,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        build_reply_followup_requests, decay_merge_useful_score, should_bench_duplicate_sync_peer,
    };
    use std::sync::{Arc, Mutex};

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

    #[test]
    fn decay_merge_useful_score_blends_old_and_new() {
        assert_eq!(decay_merge_useful_score(100, 20), 107);
        assert_eq!(decay_merge_useful_score(0, 20), 20);
    }

    #[test]
    fn duplicate_heavy_peer_bench_threshold_requires_low_usefulness() {
        assert!(!should_bench_duplicate_sync_peer(23, 0));
        assert!(should_bench_duplicate_sync_peer(24, 0));
        assert!(should_bench_duplicate_sync_peer(40, 10));
        assert!(!should_bench_duplicate_sync_peer(40, 11));
    }

    #[test]
    fn build_reply_followup_requests_returns_empty_without_active_syncer() {
        let sync_arc = Arc::new(Mutex::new(None));
        let result = build_reply_followup_requests(sync_arc, 4);
        assert!(result.reqs.is_empty());
        assert_eq!(result.sync_seq, 0);

        let header = test_header(100, 0x11);
        let mut syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            header.hash,
            header.account_hash,
            None,
            header,
        );
        syncer.set_active(false);
        let sync_arc = Arc::new(Mutex::new(Some(syncer)));
        let result = build_reply_followup_requests(sync_arc, 4);
        assert!(result.reqs.is_empty());
        assert_eq!(result.sync_seq, 0);
    }
}
