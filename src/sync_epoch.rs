use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::network::message::RtxpMessage;
use crate::network::peer::PeerId;

pub struct ReplyFollowupBuildResult {
    pub reqs: Vec<RtxpMessage>,
    pub sync_seq: u32,
}

pub fn decay_merge_useful_score(existing: u32, useful: u32) -> u32 {
    existing.saturating_mul(3) / 4 + useful
}

pub fn apply_useful_peer_counts(
    state: &mut crate::node::SharedState,
    counts: &HashMap<PeerId, u32>,
    now: std::time::Instant,
) {
    for (peer_id, useful) in counts {
        let entry = state.peer_sync_useful.entry(*peer_id).or_insert(0);
        *entry = decay_merge_useful_score(*entry, *useful);
        state.peer_sync_last_useful.insert(*peer_id, now);
    }
}

pub fn build_reply_followup_requests(
    sync_arc: Arc<Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
    num_peers: usize,
) -> ReplyFollowupBuildResult {
    let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref mut syncer) = *guard {
        if !syncer.active() {
            return ReplyFollowupBuildResult {
                reqs: vec![],
                sync_seq: 0,
            };
        }
        let reqs = syncer.build_multi_requests(num_peers, crate::sync::SyncRequestReason::Reply);
        let sync_seq = syncer.ledger_seq();
        ReplyFollowupBuildResult { reqs, sync_seq }
    } else {
        ReplyFollowupBuildResult {
            reqs: vec![],
            sync_seq: 0,
        }
    }
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
    format!(
        "sync: {} unique nodes in NuDB | received {} from peers ({}i {}l, {:.0}% dup) | batch: {}",
        nudb_objects,
        sync_info.0 + sync_info.1,
        sync_info.0,
        sync_info.1,
        if nudb_objects > 0 {
            ((sync_info.0 + sync_info.1) as f64 / nudb_objects as f64 - 1.0) * 100.0
        } else {
            0.0
        },
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
    use super::{build_reply_followup_requests, decay_merge_useful_score};
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
        assert_eq!(decay_merge_useful_score(100, 20), 95);
        assert_eq!(decay_merge_useful_score(0, 20), 20);
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
