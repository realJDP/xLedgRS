use super::*;

impl Node {
    #[cfg(test)]
    pub(super) fn sync_trigger_blocking(
        sync_arc: &Arc<std::sync::Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
        storage: &Option<Arc<crate::storage::Storage>>,
        reason: TriggerReason,
    ) -> (Vec<RtxpMessage>, u32, bool) {
        const MAX_SYNC_STALLED_RETRIES: u32 =
            crate::ledger::inbound::LEDGER_TIMEOUT_RETRIES_MAX as u32;

        let lock_wait = std::time::Instant::now();
        let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
        let lock_wait_ms = lock_wait.elapsed().as_millis();
        let hold_start = std::time::Instant::now();
        let _store_ref = storage.as_ref().map(|s| s.as_ref());

        let syncer = match guard.as_mut() {
            Some(s) if s.active() => s,
            _ => {
                drop(guard);
                return (vec![], 0, false);
            }
        };

        let sync_seq = syncer.ledger_seq();

        if reason == TriggerReason::Timeout {
            let response_idle_secs = syncer.peer.last_response.elapsed().as_secs();
            let useful_idle_secs = syncer.peer.last_new_nodes.elapsed().as_secs();
            let cookies_out = syncer.peer.outstanding_cookie_count();
            let recent_count = syncer.peer.recent_node_count();

            info!(
                "sync tick: active={} in_flight={} inner={} leaf={} pass={} cookies={} recent={} useful-idle={}s response-idle={}s",
                syncer.active(), syncer.in_flight(),
                syncer.inner_count(), syncer.leaf_count(), syncer.pass_number(),
                cookies_out, recent_count, useful_idle_secs, response_idle_secs,
            );

            match syncer.handle_timeout_tick(MAX_SYNC_STALLED_RETRIES) {
                crate::sync_coordinator::TimeoutHandling::Progress => {
                    if useful_idle_secs >= 3 || response_idle_secs >= 3 {
                        info!(
                            "sync timer: progress tick (in_flight={} inner={} leaf={} useful-idle={}s response-idle={}s)",
                            syncer.in_flight(),
                            syncer.inner_count(),
                            syncer.leaf_count(),
                            useful_idle_secs,
                            response_idle_secs,
                        );
                    }
                    let hold_ms = hold_start.elapsed().as_millis();
                    if lock_wait_ms > 5 || hold_ms > 20 {
                        info!(
                            "sync trigger(timeout): lock_wait={}ms hold={}ms",
                            lock_wait_ms, hold_ms
                        );
                    }
                    drop(guard);
                    return (vec![], sync_seq, false);
                }
                crate::sync_coordinator::TimeoutHandling::RestartPass {
                    progress_this_pass,
                    timeout_count,
                } => {
                    info!(
                        "sync timer: restarting stalled pass {} ({} new this pass, in_flight={}, retries={})",
                        syncer.pass_number(),
                        progress_this_pass,
                        syncer.in_flight(),
                        timeout_count,
                    );
                    let hold_ms = hold_start.elapsed().as_millis();
                    if lock_wait_ms > 5 || hold_ms > 20 {
                        info!(
                            "sync trigger(timeout): lock_wait={}ms hold={}ms",
                            lock_wait_ms, hold_ms
                        );
                    }
                    drop(guard);
                    return (vec![], sync_seq, false);
                }
                crate::sync_coordinator::TimeoutHandling::Deactivate { timeout_count } => {
                    warn!(
                        "sync timer: marking fixed target inactive after {} timeouts (in_flight={}); awaiting same-ledger reacquire",
                        timeout_count,
                        syncer.in_flight(),
                    );
                    let hold_ms = hold_start.elapsed().as_millis();
                    if lock_wait_ms > 5 || hold_ms > 20 {
                        info!(
                            "sync trigger(timeout): lock_wait={}ms hold={}ms",
                            lock_wait_ms, hold_ms
                        );
                    }
                    drop(guard);
                    return (vec![], sync_seq, false);
                }
                crate::sync_coordinator::TimeoutHandling::Request {
                    timeout_count,
                    use_object_fallback,
                    reqs,
                } => {
                    info!(
                        "sync stall ({}s useful-idle, {}s response-idle) — timeout-retrying (attempt #{}, mode={})",
                        useful_idle_secs,
                        response_idle_secs,
                        timeout_count,
                        if use_object_fallback {
                            "getobjects"
                        } else {
                            "getledger"
                        },
                    );
                    let hold_ms = hold_start.elapsed().as_millis();
                    if lock_wait_ms > 5 || hold_ms > 20 {
                        info!(
                            "sync trigger(timeout): lock_wait={}ms hold={}ms",
                            lock_wait_ms, hold_ms
                        );
                    }
                    drop(guard);
                    return (reqs, sync_seq, false);
                }
                crate::sync_coordinator::TimeoutHandling::NoRequest {
                    timeout_count,
                    use_object_fallback,
                } => {
                    warn!(
                        "sync timeout produced no request (attempt #{} in_flight={} cookies={} recent={} mode={})",
                        timeout_count,
                        syncer.in_flight(),
                        cookies_out,
                        recent_count,
                        if use_object_fallback {
                            "getobjects"
                        } else {
                            "getledger"
                        },
                    );
                }
            }
        }

        let reqs = Vec::new();
        let has_req = false;
        let req_count = 0usize;
        let hold_ms = hold_start.elapsed().as_millis();
        if lock_wait_ms > 5 || hold_ms > 20 {
            info!(
                "sync trigger({:?}): lock_wait={}ms hold={}ms has_req={} n_reqs={}",
                reason, lock_wait_ms, hold_ms, has_req, req_count
            );
        }
        drop(guard);
        (reqs, sync_seq, false)
    }

    pub(super) async fn sync_send_request(
        &self,
        req: &RtxpMessage,
        _sync_seq: u32,
        target_peer: Option<PeerId>,
    ) {
        let state = self.state.read().await;
        match target_peer {
            Some(peer_id) => {
                if let Some(tx) = state.peer_txs.get(&peer_id) {
                    let outbound = tune_sync_request_for_peer_latency(
                        req,
                        state.peer_latency.get(&peer_id).copied(),
                    )
                    .unwrap_or_else(|| req.clone());
                    let _ = tx.try_send(outbound);
                }
            }
            None => {
                state.broadcast(req, None);
            }
        }
    }

    pub(super) async fn flush_sync_leaves_to_nudb(
        &self,
        pending_leaves: &mut Vec<(Vec<u8>, Vec<u8>)>,
        final_flush: bool,
    ) {
        if pending_leaves.is_empty() {
            return;
        }

        let Some(backend) = self.nudb_backend.clone() else {
            pending_leaves.clear();
            return;
        };

        let mut batch: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(pending_leaves.len());
        for (key_bytes, data) in pending_leaves.iter() {
            if key_bytes.len() != 32 {
                continue;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(key_bytes);
            let leaf_hash = crate::ledger::sparse_shamap::leaf_hash(data, &key);
            let mut store_data = Vec::with_capacity(data.len() + 32);
            store_data.extend_from_slice(data);
            store_data.extend_from_slice(&key);
            batch.push((leaf_hash, store_data));
        }

        pending_leaves.clear();
        if batch.is_empty() {
            return;
        }

        let flush_kind = if final_flush { "final " } else { "" };
        let flushed = batch.len();
        match tokio::task::spawn_blocking(move || backend.store_batch(&batch)).await {
            Ok(Ok(())) => {
                info!(
                    "sync data processor: flushed {}{}leaves to NuDB",
                    flush_kind, flushed,
                );
            }
            Ok(Err(e)) => {
                error!(
                    "sync data processor: failed to flush {}{}leaves to NuDB: {}",
                    flush_kind, flushed, e,
                );
            }
            Err(e) => {
                error!(
                    "sync data processor: leaf flush task panicked for {}{}leaves: {}",
                    flush_kind, flushed, e,
                );
            }
        }
    }

    pub(super) async fn finalize_completed_sync_epoch(
        &self,
        shamap: crate::ledger::shamap::SHAMap,
        sync_header: crate::ledger::LedgerHeader,
        sync_info: (usize, usize, u32, u32, usize),
        pending_leaves: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> bool {
        if !pending_leaves.is_empty() {
            self.flush_sync_leaves_to_nudb(pending_leaves, true).await;
        }
        info!("sync data processor: tree complete — flushing NuDB to disk");
        if let Some(ref backend) = self.nudb_backend {
            match backend.flush_to_disk() {
                Ok(()) => info!("NuDB flush complete"),
                Err(e) => error!("NuDB flush FAILED: {}", e),
            }
        }
        let mut handoff_shamap = shamap;
        let verified_root_hash = handoff_shamap.root_hash();
        let completion = plan_sync_completion_outcome(verified_root_hash, sync_header.account_hash);

        if completion.verified {
            info!(
                "sync verification PASSED: hash={} matches target",
                hex::encode_upper(&verified_root_hash[..8]),
            );
            let anchor_verified = self.acquire_sync_anchor_transactions(&sync_header).await;
            info!("sync data processor: handing off SHAMap to LedgerState");
            {
                let state = self.state.read().await;
                let mut ls = state
                    .ctx
                    .ledger_state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                ls.set_nudb_shamap(handoff_shamap);
                ls.enable_sparse();
            }
            {
                let mut state = self.state.write().await;
                if completion.clear_sync_in_progress {
                    state.sync_in_progress = false;
                }
                state.sync_done = anchor_verified && completion.mark_sync_done;
            }
            if !anchor_verified {
                warn!(
                    "sync completion aborted: anchor tx acquisition failed for seq={} hash={}",
                    sync_header.sequence,
                    hex::encode_upper(&sync_header.hash[..8]),
                );
                return false;
            }

            if let Some(ref store) = self.storage {
                let _ = store.save_leaf_count(sync_info.1 as u64);
                if completion.persist_anchor {
                    let _ = store.persist_sync_anchor(&sync_header);
                }
                let _ = store.flush();
            }

            self.run_post_sync_checkpoint(&sync_header).await;

            if completion.broadcast_connected {
                let state = self.state.read().await;
                let status_msg = crate::network::relay::encode_status_change(
                    crate::proto::NodeStatus::NsConnected,
                    crate::proto::NodeEvent::NeAcceptedLedger,
                    sync_header.sequence,
                    &sync_header.hash,
                );
                state.broadcast(&status_msg, None);
                info!(
                    "broadcast nsConnected status to {} peers for synced ledger {}",
                    state.peer_count(),
                    sync_header.sequence,
                );
            }

            info!(
                "sync complete — synced_ledger={} hash={} — handoff persisted, starting follower",
                sync_header.sequence,
                hex::encode_upper(&sync_header.hash[..8]),
            );
            if completion.start_follower {
                self.start_follower().await;
            }
        } else {
            {
                let mut state = self.state.write().await;
                if completion.clear_sync_in_progress {
                    state.sync_in_progress = false;
                }
                state.sync_done = false;
            }
            warn!(
                "sync verification FAILED: ours={} target={} — not persisting anchor or starting follower",
                hex::encode_upper(&verified_root_hash[..8]),
                hex::encode_upper(&sync_header.account_hash[..8]),
            );
        }

        true
    }

    pub(super) async fn handle_sync_epoch_followup(
        &self,
        outcome: &'static str,
        sync_info: (usize, usize, u32, u32, usize),
        epoch_peer_useful_counts: &HashMap<PeerId, u32>,
        batch_len: usize,
        epoch_batch_count: usize,
        walk_ms: u128,
    ) {
        if !epoch_peer_useful_counts.is_empty() {
            let mut state = self.state.write().await;
            crate::sync_epoch::apply_useful_peer_counts(
                &mut state,
                epoch_peer_useful_counts,
                std::time::Instant::now(),
            );
        }

        let trigger_start = std::time::Instant::now();
        let had_useful_epoch = !epoch_peer_useful_counts.is_empty();
        let (target_peers, total_reqs, _trigger_sync_seq) = if should_issue_reply_followup(
            outcome,
            had_useful_epoch,
        ) {
            let target_peers = {
                let state = self.state.read().await;
                self.select_reply_sync_peers(&state, sync_info.2, epoch_peer_useful_counts, 6)
            };
            let num_peers = target_peers.len().max(1);

            let sync_arc_trigger = self.sync_runtime.sync_arc();
            let trigger_result = tokio::task::spawn_blocking(move || {
                crate::sync_epoch::build_reply_followup_requests(sync_arc_trigger, num_peers)
            })
            .await;
            let crate::sync_epoch::ReplyFollowupBuildResult { reqs, sync_seq } =
                match trigger_result {
                    Ok(r) => r,
                    Err(e) => {
                        error!("sync trigger(Reply) panicked: {}", e);
                        crate::sync_epoch::ReplyFollowupBuildResult {
                            reqs: vec![],
                            sync_seq: 0,
                        }
                    }
                };

            let mut total_reqs = 0usize;
            if !reqs.is_empty() {
                if target_peers.is_empty() {
                    self.sync_send_request(&reqs[0], sync_seq, None).await;
                    total_reqs = 1;
                } else {
                    for (i, req) in reqs.iter().enumerate() {
                        let peer_idx = i % target_peers.len();
                        let pid = target_peers[peer_idx];
                        self.sync_send_request(req, sync_seq, Some(pid)).await;
                        total_reqs += 1;
                    }
                }
            }
            (target_peers, total_reqs, sync_seq)
        } else {
            if matches!(outcome, "Continue" | "PassComplete") {
                info!(
                        "reply follow-up skipped after zero-useful epoch: responses={} batches={} walk={}ms",
                        batch_len,
                        epoch_batch_count,
                        walk_ms,
                    );
            }
            (Vec::new(), 0usize, 0u32)
        };
        let trigger_ms = trigger_start.elapsed().as_millis();

        self.debug_log(&crate::sync_epoch::processed_debug_line(
            sync_info,
            walk_ms,
            trigger_ms,
            total_reqs,
            target_peers.len(),
        ));

        tokio::task::yield_now().await;

        match outcome {
            "TrulyComplete" => {
                self.debug_log(&format!(
                    "SYNC COMPLETE: {} inner + {} leaf",
                    sync_info.0, sync_info.1,
                ));
                info!(
                    "state sync TRULY COMPLETE: {} total objects across {} passes",
                    sync_info.1, sync_info.3,
                );
            }
            "HitCap" => {
                info!(
                    "state sync hit max_sync cap: {} leaf + {} inner nodes",
                    sync_info.1, sync_info.0,
                );
            }
            _ => {}
        }

        {
            static LAST_LOG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let prev = LAST_LOG.load(std::sync::atomic::Ordering::Relaxed);
            if now >= prev + 10 {
                LAST_LOG.store(now, std::sync::atomic::Ordering::Relaxed);
                let nudb_objects = self.nudb_backend.as_ref().map_or(0, |b| b.count() as usize);
                info!(
                    "{}",
                    crate::sync_epoch::sync_progress_info_line(nudb_objects, sync_info, batch_len)
                );
            }
        }

        {
            static LAST_SUMMARY: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            static PREV_LEAF_COUNT: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let prev = LAST_SUMMARY.load(std::sync::atomic::Ordering::Relaxed);
            if now >= prev + 30 {
                LAST_SUMMARY.store(now, std::sync::atomic::Ordering::Relaxed);
                let prev_leaves =
                    PREV_LEAF_COUNT.swap(sync_info.1 as u64, std::sync::atomic::Ordering::Relaxed);
                let delta = (sync_info.1 as u64).saturating_sub(prev_leaves);
                let rate_k_per_min = (delta * 2) / 1000;
                let state = self.state.read().await;
                let active_peers = state.peer_count();
                let benched_peers = state.sync_peer_cooldown.len();
                let latencies: Vec<_> = state
                    .peer_latency
                    .iter()
                    .map(|(pid, lat)| format!("{:?}={}ms", pid, lat))
                    .collect();
                self.debug_log(&crate::sync_epoch::summary_debug_line(
                    rate_k_per_min,
                    active_peers,
                    benched_peers,
                    &latencies,
                    sync_info,
                ));
            }
        }

        {
            static LAST_INNER_SAVE: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let total = sync_info.1 as u64;
            let prev_inner = LAST_INNER_SAVE.load(std::sync::atomic::Ordering::Relaxed);
            if total >= prev_inner + 100_000 {
                LAST_INNER_SAVE.store(total, std::sync::atomic::Ordering::Relaxed);
                if let Some(ref store) = self.storage {
                    let leaf_count = match self.sync_runtime.try_lock_sync() {
                        Ok(guard) => {
                            if let Some(ref syncer) = *guard {
                                syncer.leaf_count() as u64
                            } else {
                                0
                            }
                        }
                        Err(_) => {
                            debug!("leaf count save deferred: sync lock busy");
                            0
                        }
                    };
                    let _ = store.save_leaf_count(leaf_count);
                    info!("periodic save: {total} leaves total");
                }
            }
        }
    }

    pub(super) async fn run_sync_data_processor(self: Arc<Self>) {
        let shutdown = self.shutdown.clone();
        const NUDB_FLUSH_THRESHOLD: usize = 4000;
        let mut pending_leaves: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        loop {
            let sync_data_notify = self.sync_runtime.data_notify();
            tokio::select! {
                _ = sync_data_notify.notified() => {},
                _ = async {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        if shutdown.load(std::sync::atomic::Ordering::Relaxed) { return; }
                    }
                } => {
                    info!("data processor: shutdown");
                    return;
                }
            }

            let mut epoch_peer_useful_counts: HashMap<PeerId, u32> = HashMap::new();
            let mut epoch_sync_info: Option<(usize, usize, u32, u32, usize)> = None;
            let mut epoch_completed_shamap = None;
            let mut epoch_outcome = "Continue";
            let mut epoch_response_count = 0usize;
            let mut epoch_batch_count = 0usize;
            let mut epoch_walk_ms = 0u128;

            loop {
                let batch: Vec<(PeerId, crate::proto::TmLedgerData)> =
                    self.sync_runtime.take_sync_data_batch();
                if batch.is_empty() {
                    break;
                }
                let batch_len = batch.len();
                epoch_batch_count += 1;
                epoch_response_count += batch_len;

                self.debug_log(&format!(
                    "BATCH: {} responses, collecting leaves",
                    batch_len
                ));

                let sync_arc = self.sync_runtime.sync_arc();
                let max_sync = self.config.max_sync;
                let walk_start = std::time::Instant::now();
                let blocking_result = tokio::task::spawn_blocking(move || {
                    crate::sync_processor::process_sync_batch_blocking(sync_arc, batch, max_sync)
                })
                .await;
                let result = match blocking_result {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        epoch_sync_info = None;
                        break;
                    }
                    Err(e) => {
                        error!("sync data processor spawn_blocking panicked: {}", e);
                        epoch_sync_info = None;
                        break;
                    }
                };
                let crate::sync_processor::SyncBatchProcessResult {
                    outcome,
                    sync_info,
                    peer_useful_counts,
                    completed_shamap,
                    synced_leaves,
                } = result;
                let walk_ms = walk_start.elapsed().as_millis();
                epoch_walk_ms = epoch_walk_ms.saturating_add(walk_ms);
                epoch_sync_info = Some(sync_info);

                if !synced_leaves.is_empty() {
                    pending_leaves.extend(synced_leaves);
                    if pending_leaves.len() >= NUDB_FLUSH_THRESHOLD {
                        self.flush_sync_leaves_to_nudb(&mut pending_leaves, false)
                            .await;
                    }
                }

                for (peer_id, useful) in peer_useful_counts {
                    let entry = epoch_peer_useful_counts.entry(peer_id).or_insert(0);
                    *entry = entry.saturating_add(useful);
                }

                epoch_outcome = outcome;
                if let Some(completed) = completed_shamap {
                    epoch_completed_shamap = Some(completed);
                    break;
                }
                if matches!(outcome, "HitCap" | "Inactive") {
                    break;
                }
            }

            let Some(sync_info) = epoch_sync_info else {
                continue;
            };
            let completed_shamap = epoch_completed_shamap;
            let outcome = epoch_outcome;
            let batch_len = epoch_response_count;
            let walk_ms = epoch_walk_ms;

            if let Some((shamap, sync_header)) = completed_shamap {
                if !self
                    .finalize_completed_sync_epoch(
                        shamap,
                        sync_header,
                        sync_info,
                        &mut pending_leaves,
                    )
                    .await
                {
                    continue;
                }
            }

            self.handle_sync_epoch_followup(
                outcome,
                sync_info,
                &epoch_peer_useful_counts,
                batch_len,
                epoch_batch_count,
                walk_ms,
            )
            .await;
        }
    }
}
