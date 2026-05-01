//! Background processor for downloaded sync nodes.
//!
//! Persists acquired SHAMap nodes, detects tree completion, flushes NuDB, and
//! prepares the verified ledger handoff to the follower.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::network::peer::PeerId;

pub struct SyncBatchProcessResult {
    pub outcome: &'static str,
    pub sync_info: (usize, usize, u32, u32, usize),
    pub peer_useful_counts: HashMap<PeerId, u32>,
    pub completed_shamap: Option<(crate::ledger::shamap::SHAMap, crate::ledger::LedgerHeader)>,
    pub synced_leaves: Vec<(Vec<u8>, Vec<u8>)>,
}

pub fn process_sync_batch_blocking(
    sync_arc: Arc<Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
    batch: Vec<(PeerId, crate::proto::TmLedgerData)>,
    max_sync: u64,
) -> Option<SyncBatchProcessResult> {
    let proc_start = std::time::Instant::now();
    let mut peer_useful_counts: HashMap<PeerId, u32> = HashMap::new();
    let mut all_leaves: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let missing_before = 999usize;
    let mut max_lock_wait_ms = 0u128;
    let mut max_hold_ms = 0u128;
    let mut processed_responses = 0usize;

    for (peer_id, ld) in &batch {
        let lock_wait = std::time::Instant::now();
        let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
        let lock_wait_ms = lock_wait.elapsed().as_millis();
        max_lock_wait_ms = max_lock_wait_ms.max(lock_wait_ms);
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
        if !accepted {
            if missing_before <= 5 {
                let hash_match =
                    ld.ledger_hash.len() >= 8 && ld.ledger_hash[..8] == syncer.ledger_hash()[..8];
                tracing::info!(
                    "RESPONSE DROPPED: peer={:?} is_obj={} cookie={:?} hash_match={} nodes={} our_hash={}",
                    peer_id,
                    is_object_response,
                    ld.request_cookie,
                    hash_match,
                    ld.nodes.len(),
                    hex::encode_upper(&syncer.ledger_hash()[..8]),
                );
            }
            let hold_ms = hold_start.elapsed().as_millis();
            max_hold_ms = max_hold_ms.max(hold_ms);
            drop(guard);
            processed_responses += 1;
            continue;
        }

        let log_initial_nodes = syncer.inner_count() < 100;
        drop(guard);

        let parsed = crate::sync::parse_sync_response(ld, log_initial_nodes);

        let lock_wait = std::time::Instant::now();
        let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
        let lock_wait_ms = lock_wait.elapsed().as_millis();
        max_lock_wait_ms = max_lock_wait_ms.max(lock_wait_ms);
        let hold_start = std::time::Instant::now();

        let Some(ref mut syncer) = *guard else {
            drop(guard);
            return None;
        };

        let progress = syncer.process_parsed_response(parsed);
        let useful = (progress.inner_received + progress.leaf_received) as u32;
        if !progress.leaves.is_empty() {
            all_leaves.extend(progress.leaves);
        }
        if missing_before <= 5 {
            tracing::info!(
                "RESPONSE ACCEPTED: peer={:?} is_obj={} inner={} leaf={} nodes_in_msg={}",
                peer_id,
                is_object_response,
                progress.inner_received,
                progress.leaf_received,
                ld.nodes.len(),
            );
        }
        if useful > 0 {
            *peer_useful_counts.entry(*peer_id).or_insert(0) += useful;
        }

        let hold_ms = hold_start.elapsed().as_millis();
        max_hold_ms = max_hold_ms.max(hold_ms);
        drop(guard);
        processed_responses += 1;
    }

    let lock_wait = std::time::Instant::now();
    let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
    let final_lock_wait_ms = lock_wait.elapsed().as_millis();
    max_lock_wait_ms = max_lock_wait_ms.max(final_lock_wait_ms);
    let final_hold_start = std::time::Instant::now();

    let Some(ref mut syncer) = *guard else {
        drop(guard);
        return None;
    };

    let info = (
        syncer.inner_count(),
        syncer.leaf_count(),
        syncer.ledger_seq(),
        syncer.pass_number(),
        syncer.new_objects_this_pass(),
    );

    let hit_cap = max_sync > 0 && syncer.leaf_count() as u64 >= max_sync;

    let outcome = if !syncer.active() {
        "Inactive"
    } else if hit_cap {
        syncer.set_active(false);
        "HitCap"
    } else if syncer.is_complete() {
        let root = syncer.root_hash();
        let target = syncer.peer.account_hash;
        tracing::info!(
            "sync is_complete=true root={} target={} match={}",
            hex::encode_upper(&root[..8]),
            hex::encode_upper(&target[..8]),
            root == target,
        );
        syncer.set_active(false);
        "TrulyComplete"
    } else if syncer.is_pass_complete() {
        syncer.peer.start_new_pass();
        "PassComplete"
    } else {
        "Continue"
    };

    let completed_shamap = if outcome == "TrulyComplete" {
        let sync_header = syncer.sync_header.clone();
        Some((syncer.take_shamap(), sync_header))
    } else {
        None
    };

    let final_hold_ms = final_hold_start.elapsed().as_millis();
    max_hold_ms = max_hold_ms.max(final_hold_ms);
    drop(guard);

    let batch_hold_ms = proc_start.elapsed().as_millis();
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
        completed_shamap,
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
        let out = process_sync_batch_blocking(sync_arc, Vec::new(), 0);
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
        let out = process_sync_batch_blocking(sync_arc, Vec::new(), 0).unwrap();
        assert_eq!(out.outcome, "Inactive");
    }
}
