use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::network::peer::PeerId;

const SYNC_PARSE_WORKERS: usize = 4;
#[cfg(test)]
const COMPLETION_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

struct AcceptedSyncJob {
    ordinal: usize,
    peer_id: PeerId,
    log_initial_nodes: bool,
    ld: crate::proto::TmLedgerData,
}

struct ParsedSyncJob {
    ordinal: usize,
    peer_id: PeerId,
    parsed: crate::sync::ParsedSyncResponse,
}

fn parse_accepted_sync_jobs(
    jobs: Vec<AcceptedSyncJob>,
    metrics: Arc<crate::sync_runtime::SyncMetrics>,
    parse_workers: usize,
) -> Vec<ParsedSyncJob> {
    let parse_workers = parse_workers.clamp(1, 32);
    metrics.note_worker_lane_capacity("sync_parse", parse_workers);
    if jobs.len() <= 1 {
        return jobs
            .into_iter()
            .map(|job| {
                metrics.note_worker_lane_started("sync_parse");
                let parsed = ParsedSyncJob {
                    ordinal: job.ordinal,
                    peer_id: job.peer_id,
                    parsed: crate::sync::parse_sync_response(&job.ld, job.log_initial_nodes),
                };
                metrics.note_worker_lane_finished("sync_parse", true);
                parsed
            })
            .collect();
    }

    let work = Arc::new(Mutex::new(VecDeque::from(jobs)));
    let parsed = Arc::new(Mutex::new(Vec::new()));
    let worker_count =
        parse_workers.min(work.lock().unwrap_or_else(|e| e.into_inner()).len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            let work = work.clone();
            let parsed = parsed.clone();
            let metrics = metrics.clone();
            scope.spawn(move || loop {
                let job = {
                    let mut work = work.lock().unwrap_or_else(|e| e.into_inner());
                    work.pop_front()
                };
                let Some(job) = job else {
                    break;
                };
                metrics.note_worker_lane_started("sync_parse");
                let parsed_job = ParsedSyncJob {
                    ordinal: job.ordinal,
                    peer_id: job.peer_id,
                    parsed: crate::sync::parse_sync_response(&job.ld, job.log_initial_nodes),
                };
                metrics.note_worker_lane_finished("sync_parse", true);
                parsed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(parsed_job);
            });
        }
    });

    let mut parsed = Arc::try_unwrap(parsed)
        .ok()
        .expect("parse workers released parsed results")
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    parsed.sort_by_key(|job| job.ordinal);
    parsed
}

pub struct SyncBatchProcessResult {
    pub outcome: &'static str,
    pub sync_info: (usize, usize, u32, u32, usize),
    pub peer_useful_counts: HashMap<PeerId, u32>,
    pub peer_duplicate_counts: HashMap<PeerId, u32>,
    pub completed_shamap: Option<(crate::ledger::shamap::SHAMap, crate::ledger::LedgerHeader)>,
    pub synced_inner_nodes: Vec<([u8; 32], Vec<u8>)>,
    pub synced_leaves: Vec<(Vec<u8>, Vec<u8>)>,
}

pub fn process_sync_batch_blocking(
    sync_arc: Arc<Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
    batch: Vec<(PeerId, crate::proto::TmLedgerData)>,
    max_sync: u64,
    metrics: Arc<crate::sync_runtime::SyncMetrics>,
    parse_workers: usize,
    completion_check_interval: std::time::Duration,
) -> Option<SyncBatchProcessResult> {
    let proc_start = std::time::Instant::now();
    let mut peer_useful_counts: HashMap<PeerId, u32> = HashMap::new();
    let mut peer_duplicate_counts: HashMap<PeerId, u32> = HashMap::new();
    let mut all_inner_nodes: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let mut all_leaves: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut max_lock_wait_ms = 0u128;
    let mut max_hold_ms = 0u128;
    let mut total_lock_wait_ms = 0u128;
    let mut total_hold_ms = 0u128;
    let mut processed_responses = 0usize;
    let mut accepted_jobs = Vec::new();

    for (ordinal, (peer_id, ld)) in batch.into_iter().enumerate() {
        if ld.error != Some(1) {
            if let Err(reason) = crate::sync::validate_ledger_data_nodes(
                &ld,
                crate::proto::TmLedgerInfoType::LiAsNode as i32,
            ) {
                tracing::debug!(
                    "sync: dropping malformed liAS_NODE response from {:?}: {}",
                    peer_id,
                    reason
                );
                metrics.note_malformed();
                processed_responses += 1;
                continue;
            }
        }

        let lock_wait = std::time::Instant::now();
        let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
        let lock_wait_ms = lock_wait.elapsed().as_millis();
        max_lock_wait_ms = max_lock_wait_ms.max(lock_wait_ms);
        total_lock_wait_ms = total_lock_wait_ms.saturating_add(lock_wait_ms);
        let hold_start = std::time::Instant::now();

        let Some(ref mut syncer) = *guard else {
            drop(guard);
            return None;
        };

        let is_object_response = ld.error == Some(1);
        let accepted = if is_object_response {
            let accepted = syncer
                .peer
                .accept_object_response(&ld.ledger_hash, ld.request_cookie.map(|c| c as u32));
            if accepted {
                if let Some(seq) = ld.request_cookie {
                    syncer.pending_object_cookies.remove(&(seq as u32));
                }
            }
            accepted
        } else {
            syncer
                .peer
                .accept_response(&ld.ledger_hash, ld.request_cookie)
        };
        let log_initial_nodes = accepted && syncer.inner_count() < 100;
        let hold_ms = hold_start.elapsed().as_millis();
        max_hold_ms = max_hold_ms.max(hold_ms);
        total_hold_ms = total_hold_ms.saturating_add(hold_ms);
        drop(guard);

        if !accepted {
            metrics.note_stale();
            processed_responses += 1;
            continue;
        }

        accepted_jobs.push(AcceptedSyncJob {
            ordinal,
            peer_id,
            log_initial_nodes,
            ld,
        });
        processed_responses += 1;
    }

    metrics.note_worker_lane_capacity("sync_parse", SYNC_PARSE_WORKERS);
    for depth in 1..=accepted_jobs.len() {
        metrics.note_worker_lane_enqueued("sync_parse", depth);
    }
    let parsed_jobs = parse_accepted_sync_jobs(accepted_jobs, metrics.clone(), parse_workers);

    // Controlled apply lane: this is the only SHAMap mutation path for the
    // parsed batch, and it must remain in FIFO ordinal order.
    let mut last_applied_ordinal = None;
    for job in parsed_jobs {
        let ParsedSyncJob {
            ordinal,
            peer_id,
            parsed,
        } = job;
        debug_assert!(
            last_applied_ordinal.is_none_or(|last| ordinal > last),
            "parsed sync jobs must be applied in FIFO order"
        );
        last_applied_ordinal = Some(ordinal);

        let lock_wait = std::time::Instant::now();
        let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
        let lock_wait_ms = lock_wait.elapsed().as_millis();
        max_lock_wait_ms = max_lock_wait_ms.max(lock_wait_ms);
        total_lock_wait_ms = total_lock_wait_ms.saturating_add(lock_wait_ms);
        let hold_start = std::time::Instant::now();

        let Some(ref mut syncer) = *guard else {
            drop(guard);
            return None;
        };

        let progress = syncer.process_parsed_response(parsed);
        let hold_ms = hold_start.elapsed().as_millis();
        max_hold_ms = max_hold_ms.max(hold_ms);
        total_hold_ms = total_hold_ms.saturating_add(hold_ms);
        drop(guard);

        let useful = (progress.inner_received + progress.leaf_received) as u32;
        if !progress.inner_nodes.is_empty() {
            all_inner_nodes.extend(progress.inner_nodes);
        }
        if !progress.leaves.is_empty() {
            all_leaves.extend(progress.leaves);
        }
        if useful > 0 {
            *peer_useful_counts.entry(peer_id).or_insert(0) += useful;
        } else {
            *peer_duplicate_counts.entry(peer_id).or_insert(0) += 1;
        }
    }

    let completion =
        crate::sync_epoch::check_sync_completion(sync_arc.clone(), completion_check_interval);
    if completion.checked {
        let complete = completion.completed.is_some();
        metrics.note_completion_check(completion.plausible, complete);
    }
    let mut completed_shamap = completion
        .completed
        .map(|(shamap, header, info)| ((shamap, header), info));

    let lock_wait = std::time::Instant::now();
    let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
    let final_lock_wait_ms = lock_wait.elapsed().as_millis();
    max_lock_wait_ms = max_lock_wait_ms.max(final_lock_wait_ms);
    total_lock_wait_ms = total_lock_wait_ms.saturating_add(final_lock_wait_ms);
    let final_hold_start = std::time::Instant::now();

    let Some(ref mut syncer) = *guard else {
        let Some(((completed_shamap, sync_header), sync_info)) = completed_shamap else {
            drop(guard);
            return None;
        };
        drop(guard);
        return Some(SyncBatchProcessResult {
            outcome: "TrulyComplete",
            sync_info,
            peer_useful_counts,
            peer_duplicate_counts,
            completed_shamap: Some((completed_shamap, sync_header)),
            synced_inner_nodes: all_inner_nodes,
            synced_leaves: all_leaves,
        });
    };

    let current_info = (
        syncer.inner_count(),
        syncer.leaf_count(),
        syncer.ledger_seq(),
        syncer.pass_number(),
        syncer.new_objects_this_pass(),
    );

    let hit_cap = max_sync > 0 && syncer.leaf_count() as u64 >= max_sync;

    let outcome = if completed_shamap.is_some() {
        let root = syncer.root_hash();
        let target = syncer.peer.account_hash;
        tracing::info!(
            "sync is_complete=true root={} target={} match={}",
            hex::encode_upper(&root[..8]),
            hex::encode_upper(&target[..8]),
            root == target,
        );
        "TrulyComplete"
    } else if !syncer.active() {
        "Inactive"
    } else if hit_cap {
        syncer.set_active(false);
        "HitCap"
    } else if syncer.is_pass_complete() {
        syncer.peer.start_new_pass();
        "PassComplete"
    } else {
        "Continue"
    };

    let info = completed_shamap
        .as_ref()
        .map(|(_, info)| *info)
        .unwrap_or(current_info);
    let completed_shamap = completed_shamap.take().map(|(completed, _)| completed);

    let final_hold_ms = final_hold_start.elapsed().as_millis();
    max_hold_ms = max_hold_ms.max(final_hold_ms);
    total_hold_ms = total_hold_ms.saturating_add(final_hold_ms);
    drop(guard);

    let batch_hold_ms = proc_start.elapsed().as_millis();
    let useful_nodes = peer_useful_counts
        .values()
        .fold(0u64, |sum, value| sum.saturating_add(*value as u64));
    metrics.note_batch(
        processed_responses as u64,
        useful_nodes,
        total_lock_wait_ms.min(u64::MAX as u128) as u64,
        total_hold_ms.min(u64::MAX as u128) as u64,
        batch_hold_ms.min(u64::MAX as u128) as u64,
        max_lock_wait_ms.min(u64::MAX as u128) as u64,
        max_hold_ms.min(u64::MAX as u128) as u64,
        batch_hold_ms.min(u64::MAX as u128) as u64,
        outcome,
    );
    if max_lock_wait_ms > 5 || max_hold_ms > 20 || batch_hold_ms > 20 {
        tracing::info!(
            "sync processData: lock_wait={}ms hold={}ms batch_hold={}ms responses={} outcome={}",
            max_lock_wait_ms,
            max_hold_ms,
            batch_hold_ms,
            processed_responses,
            outcome,
        );
    }

    Some(SyncBatchProcessResult {
        outcome,
        sync_info: info,
        peer_useful_counts,
        peer_duplicate_counts,
        completed_shamap,
        synced_inner_nodes: all_inner_nodes,
        synced_leaves: all_leaves,
    })
}

#[cfg(test)]
mod tests {
    use super::process_sync_batch_blocking;
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
    fn process_sync_batch_returns_none_without_syncer() {
        let sync_arc = Arc::new(Mutex::new(None));
        let out = process_sync_batch_blocking(
            sync_arc,
            Vec::new(),
            0,
            Arc::new(crate::sync_runtime::SyncMetrics::default()),
            super::SYNC_PARSE_WORKERS,
            super::COMPLETION_CHECK_INTERVAL,
        );
        assert!(out.is_none());
    }

    #[test]
    fn process_sync_batch_reports_inactive_syncer() {
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
        let out = process_sync_batch_blocking(
            sync_arc,
            Vec::new(),
            0,
            Arc::new(crate::sync_runtime::SyncMetrics::default()),
            super::SYNC_PARSE_WORKERS,
            super::COMPLETION_CHECK_INTERVAL,
        )
        .unwrap();
        assert_eq!(out.outcome, "Inactive");
    }

    #[test]
    fn parse_accepted_sync_jobs_preserves_fifo_ordinals() {
        let jobs = vec![
            super::AcceptedSyncJob {
                ordinal: 2,
                peer_id: crate::network::peer::PeerId(2),
                log_initial_nodes: false,
                ld: crate::proto::TmLedgerData::default(),
            },
            super::AcceptedSyncJob {
                ordinal: 1,
                peer_id: crate::network::peer::PeerId(1),
                log_initial_nodes: false,
                ld: crate::proto::TmLedgerData::default(),
            },
        ];

        let metrics = Arc::new(crate::sync_runtime::SyncMetrics::default());
        let parsed =
            super::parse_accepted_sync_jobs(jobs, metrics.clone(), super::SYNC_PARSE_WORKERS);

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].ordinal, 1);
        assert_eq!(parsed[0].peer_id, crate::network::peer::PeerId(1));
        assert_eq!(parsed[1].ordinal, 2);
        assert_eq!(parsed[1].peer_id, crate::network::peer::PeerId(2));
        let snap = metrics.snapshot();
        let parse_lane = snap
            .worker_lanes
            .iter()
            .find(|lane| lane.lane == "sync_parse")
            .expect("sync parse lane metrics");
        assert_eq!(parse_lane.started_total, 2);
        assert_eq!(parse_lane.completed_total, 2);
        assert_eq!(parse_lane.failed_total, 0);
        assert_eq!(parse_lane.queue_capacity, super::SYNC_PARSE_WORKERS as u64);
    }
}
