use super::*;

fn sync_anchor_gate_satisfied(
    sync_header: &crate::ledger::LedgerHeader,
    anchor_verified: bool,
) -> bool {
    sync_header.transaction_hash == [0u8; 32] || anchor_verified
}

struct SyncDataPipelineWork {
    sync_arc: Arc<std::sync::Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
    batch: Vec<(PeerId, crate::proto::TmLedgerData)>,
    max_sync: u64,
    metrics: Arc<crate::sync_runtime::SyncMetrics>,
    parse_workers: usize,
    completion_check_interval: std::time::Duration,
}

struct SyncDataPipelineResult {
    walk_ms: u128,
    result: Option<crate::sync_processor::SyncBatchProcessResult>,
    panic: Option<String>,
}

struct SyncRequestGenerationWork {
    sync_arc: Arc<std::sync::Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
    num_peers: usize,
    metrics: Arc<crate::sync_runtime::SyncMetrics>,
}

struct SyncRequestGenerationResult {
    result: crate::sync_epoch::ReplyFollowupBuildResult,
    panic: Option<String>,
}

struct SyncPersistenceWork {
    backend: Arc<dyn crate::ledger::node_store::NodeStore>,
    batch: Vec<([u8; 32], Vec<u8>)>,
    chunk_len: usize,
    chunk_bytes: usize,
    metrics: Arc<crate::sync_runtime::SyncMetrics>,
}

struct SyncPersistenceResult {
    chunk_len: usize,
    chunk_bytes: usize,
    result: Result<(), String>,
}

async fn send_bounded_worker_lane<T>(
    tx: &tokio::sync::mpsc::Sender<T>,
    work: T,
    metrics: &crate::sync_runtime::SyncMetrics,
    lane: &'static str,
    capacity: usize,
) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
    metrics.note_worker_lane_capacity(lane, capacity);
    let queue_depth = capacity
        .saturating_sub(tx.capacity())
        .saturating_add(1)
        .min(capacity);
    metrics.note_worker_lane_enqueued(lane, queue_depth);

    match tx.try_send(work) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(work)) => {
            let wait_start = std::time::Instant::now();
            let result = tx.send(work).await;
            metrics.note_worker_lane_backpressure(
                lane,
                wait_start
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
            );
            result
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(work)) => {
            Err(tokio::sync::mpsc::error::SendError(work))
        }
    }
}

async fn run_sync_data_pipeline_worker(
    mut work_rx: tokio::sync::mpsc::Receiver<SyncDataPipelineWork>,
    result_tx: tokio::sync::mpsc::Sender<SyncDataPipelineResult>,
) {
    while let Some(work) = work_rx.recv().await {
        work.metrics.note_worker_lane_started("sync_data_apply");
        let walk_start = std::time::Instant::now();
        let metrics = work.metrics.clone();
        let blocking_result = tokio::task::spawn_blocking(move || {
            crate::sync_processor::process_sync_batch_blocking(
                work.sync_arc,
                work.batch,
                work.max_sync,
                work.metrics,
                work.parse_workers,
                work.completion_check_interval,
            )
        })
        .await;
        let (result, panic) = match blocking_result {
            Ok(result) => (result, None),
            Err(e) => (None, Some(e.to_string())),
        };
        metrics.note_worker_lane_finished("sync_data_apply", panic.is_none());
        let pipeline_result = SyncDataPipelineResult {
            walk_ms: walk_start.elapsed().as_millis(),
            result,
            panic,
        };
        if result_tx.send(pipeline_result).await.is_err() {
            break;
        }
    }
}

async fn run_sync_request_generation_worker(
    mut work_rx: tokio::sync::mpsc::Receiver<SyncRequestGenerationWork>,
    result_tx: tokio::sync::mpsc::Sender<SyncRequestGenerationResult>,
) {
    while let Some(work) = work_rx.recv().await {
        work.metrics
            .note_worker_lane_started("sync_request_generation");
        let metrics = work.metrics.clone();
        let blocking_result = tokio::task::spawn_blocking(move || {
            crate::sync_epoch::build_reply_followup_requests(work.sync_arc, work.num_peers)
        })
        .await;
        let (result, panic) = match blocking_result {
            Ok(result) => (result, None),
            Err(e) => (
                crate::sync_epoch::ReplyFollowupBuildResult {
                    reqs: vec![],
                    sync_seq: 0,
                },
                Some(e.to_string()),
            ),
        };
        metrics.note_worker_lane_finished("sync_request_generation", panic.is_none());
        if result_tx
            .send(SyncRequestGenerationResult { result, panic })
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn run_sync_persistence_worker(
    mut work_rx: tokio::sync::mpsc::Receiver<SyncPersistenceWork>,
    result_tx: tokio::sync::mpsc::Sender<SyncPersistenceResult>,
) {
    while let Some(work) = work_rx.recv().await {
        let SyncPersistenceWork {
            backend,
            batch,
            chunk_len,
            chunk_bytes,
            metrics,
        } = work;
        metrics.note_worker_lane_started("sync_persistence");
        let result = tokio::task::spawn_blocking(move || {
            backend.store_batch(&batch)?;
            backend.flush_to_disk()
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|store_result| store_result.map_err(|e| e.to_string()));
        metrics.note_worker_lane_finished("sync_persistence", result.is_ok());
        if result_tx
            .send(SyncPersistenceResult {
                chunk_len,
                chunk_bytes,
                result,
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

fn spawn_sync_data_pipeline_lane(
    capacity: usize,
) -> (
    tokio::sync::mpsc::Sender<SyncDataPipelineWork>,
    tokio::sync::mpsc::Receiver<SyncDataPipelineResult>,
    tokio::task::JoinHandle<()>,
) {
    let (work_tx, work_rx) = tokio::sync::mpsc::channel(capacity);
    let (result_tx, result_rx) = tokio::sync::mpsc::channel(capacity);
    let worker = tokio::spawn(run_sync_data_pipeline_worker(work_rx, result_tx));
    (work_tx, result_rx, worker)
}

fn spawn_sync_request_generation_lane(
    capacity: usize,
) -> (
    tokio::sync::mpsc::Sender<SyncRequestGenerationWork>,
    tokio::sync::mpsc::Receiver<SyncRequestGenerationResult>,
    tokio::task::JoinHandle<()>,
) {
    let (work_tx, work_rx) = tokio::sync::mpsc::channel(capacity);
    let (result_tx, result_rx) = tokio::sync::mpsc::channel(capacity);
    let worker = tokio::spawn(run_sync_request_generation_worker(work_rx, result_tx));
    (work_tx, result_rx, worker)
}

fn spawn_sync_persistence_lane(
    capacity: usize,
) -> (
    tokio::sync::mpsc::Sender<SyncPersistenceWork>,
    tokio::sync::mpsc::Receiver<SyncPersistenceResult>,
    tokio::task::JoinHandle<()>,
) {
    let (work_tx, work_rx) = tokio::sync::mpsc::channel(capacity);
    let (result_tx, result_rx) = tokio::sync::mpsc::channel(capacity);
    let worker = tokio::spawn(run_sync_persistence_worker(work_rx, result_tx));
    (work_tx, result_rx, worker)
}

impl Node {
    const NUDB_FLUSH_CHUNK_LEAVES: usize = 1024;
    const NUDB_FLUSH_CHUNK_BYTES: usize = 8 * 1024 * 1024;

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
            let in_flight = syncer.in_flight();
            let state_request_in_flight = syncer.state_request_in_flight();
            let inner_count = syncer.inner_count();
            let leaf_count = syncer.leaf_count();
            let pass_number = syncer.pass_number();

            info!(
                "sync tick: active={} in_flight={} inner={} leaf={} pass={} cookies={} recent={} useful-idle={}s response-idle={}s",
                syncer.active(), in_flight,
                inner_count, leaf_count, pass_number,
                cookies_out, recent_count, useful_idle_secs, response_idle_secs,
            );

            match syncer.plan_timeout_tick(MAX_SYNC_STALLED_RETRIES) {
                crate::sync_coordinator::TimeoutPlan::Progress => {
                    let should_idle_pump = state_request_in_flight == 0
                        && (useful_idle_secs >= 1 || response_idle_secs >= 1);
                    let hold_ms = hold_start.elapsed().as_millis();
                    if lock_wait_ms > 5 || hold_ms > 20 {
                        info!(
                            "sync trigger(timeout): lock_wait={}ms hold={}ms",
                            lock_wait_ms, hold_ms
                        );
                    }
                    drop(guard);
                    let idle_pump_reqs = if should_idle_pump {
                        crate::sync_epoch::build_reply_followup_requests(
                            sync_arc.clone(),
                            crate::ledger::inbound::REPLY_FOLLOWUP_PEERS,
                        )
                        .reqs
                    } else {
                        Vec::new()
                    };
                    if !idle_pump_reqs.is_empty() {
                        info!(
                            "sync timer: idle pump issued {} reply request(s) (inner={} leaf={} useful-idle={}s response-idle={}s)",
                            idle_pump_reqs.len(),
                            inner_count,
                            leaf_count,
                            useful_idle_secs,
                            response_idle_secs,
                        );
                    }
                    if useful_idle_secs >= 3 || response_idle_secs >= 3 {
                        info!(
                            "sync timer: progress tick (in_flight={} inner={} leaf={} useful-idle={}s response-idle={}s)",
                            in_flight,
                            inner_count,
                            leaf_count,
                            useful_idle_secs,
                            response_idle_secs,
                        );
                    }
                    return (idle_pump_reqs, sync_seq, false);
                }
                crate::sync_coordinator::TimeoutPlan::RestartPass {
                    progress_this_pass,
                    timeout_count,
                    request,
                } => {
                    let hold_ms = hold_start.elapsed().as_millis();
                    if lock_wait_ms > 5 || hold_ms > 20 {
                        info!(
                            "sync trigger(timeout): lock_wait={}ms hold={}ms",
                            lock_wait_ms, hold_ms
                        );
                    }
                    drop(guard);
                    let reqs = crate::sync_epoch::build_timeout_requests(sync_arc.clone(), request);
                    info!(
                        "sync timer: restarting stalled pass {} ({} new this pass, in_flight={}, retries={}, followup_reqs={})",
                        pass_number,
                        progress_this_pass,
                        in_flight,
                        timeout_count,
                        reqs.len(),
                    );
                    return (reqs, sync_seq, false);
                }
                crate::sync_coordinator::TimeoutPlan::Deactivate { timeout_count } => {
                    warn!(
                        "sync timer: marking fixed target inactive after {} timeouts (in_flight={}); awaiting reacquire or current-ledger retarget",
                        timeout_count,
                        in_flight,
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
                crate::sync_coordinator::TimeoutPlan::Request {
                    timeout_count,
                    use_object_fallback,
                    request,
                } => {
                    let hold_ms = hold_start.elapsed().as_millis();
                    if lock_wait_ms > 5 || hold_ms > 20 {
                        info!(
                            "sync trigger(timeout): lock_wait={}ms hold={}ms",
                            lock_wait_ms, hold_ms
                        );
                    }
                    drop(guard);
                    let reqs = crate::sync_epoch::build_timeout_requests(sync_arc.clone(), request);
                    if reqs.is_empty() {
                        warn!(
                            "sync timeout produced no request (attempt #{} in_flight={} cookies={} recent={} mode={})",
                            timeout_count,
                            in_flight,
                            cookies_out,
                            recent_count,
                            if use_object_fallback {
                                "getobjects"
                            } else {
                                "getledger"
                            },
                        );
                        return (vec![], sync_seq, false);
                    }
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
                    return (reqs, sync_seq, false);
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
    ) -> usize {
        match target_peer {
            Some(peer_id) => {
                let target = {
                    let state = self.state.read().await;
                    state
                        .peer_txs
                        .get(&peer_id)
                        .cloned()
                        .map(|tx| (tx, state.peer_latency.get(&peer_id).copied()))
                };
                if let Some((tx, latency)) = target {
                    let outbound = tune_sync_request_for_peer_latency(req, latency)
                        .unwrap_or_else(|| req.clone());
                    if tx.try_send(outbound).is_ok() {
                        return 1;
                    }
                    tracing::warn!(
                        "sync request dropped: outbound queue full for {:?}",
                        peer_id
                    );
                }
                0
            }
            None => {
                let peers = {
                    let state = self.state.read().await;
                    state.peer_txs.values().cloned().collect::<Vec<_>>()
                };
                let mut sent = 0usize;
                for tx in peers {
                    if tx.try_send(req.clone()).is_ok() {
                        sent += 1;
                    }
                }
                if sent == 0 {
                    tracing::warn!("sync request broadcast dropped: no peer accepted request");
                }
                sent
            }
        }
    }

    async fn flush_sync_leaves_to_nudb(
        &self,
        pending_leaves: &mut Vec<(Vec<u8>, Vec<u8>)>,
        final_flush: bool,
        persistence_work_tx: &tokio::sync::mpsc::Sender<SyncPersistenceWork>,
        persistence_result_rx: &mut tokio::sync::mpsc::Receiver<SyncPersistenceResult>,
    ) -> bool {
        if pending_leaves.is_empty() {
            return true;
        }

        let Some(backend) = self.nudb_backend.clone() else {
            error!("sync data processor: cannot flush leaves because NuDB backend is unavailable");
            return false;
        };

        let flush_kind = if final_flush { "final " } else { "" };
        let mut total_staged = 0usize;
        let mut total_bytes = 0usize;

        let mut submitted_leaves = 0usize;
        let mut submitted_chunks = 0usize;
        while submitted_leaves < pending_leaves.len() {
            let mut chunk_len = 0usize;
            let mut chunk_bytes = 0usize;
            let mut batch: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(
                Self::NUDB_FLUSH_CHUNK_LEAVES
                    .min(pending_leaves.len().saturating_sub(submitted_leaves)),
            );

            for (key_bytes, data) in pending_leaves.iter().skip(submitted_leaves) {
                if key_bytes.len() != 32 {
                    error!(
                        "sync data processor: refused to flush leaf with invalid key len {}",
                        key_bytes.len()
                    );
                    return false;
                }

                let next_bytes = data.len().saturating_add(32);
                if chunk_len > 0
                    && (chunk_len >= Self::NUDB_FLUSH_CHUNK_LEAVES
                        || chunk_bytes.saturating_add(next_bytes) > Self::NUDB_FLUSH_CHUNK_BYTES)
                {
                    break;
                }

                let mut key = [0u8; 32];
                key.copy_from_slice(key_bytes);
                let leaf_hash = crate::ledger::sparse_shamap::leaf_hash(data, &key);
                let mut store_data = Vec::with_capacity(next_bytes);
                store_data.extend_from_slice(data);
                store_data.extend_from_slice(&key);
                batch.push((leaf_hash, store_data));
                chunk_len += 1;
                chunk_bytes = chunk_bytes.saturating_add(next_bytes);
            }

            if batch.is_empty() {
                pending_leaves.clear();
                return true;
            }

            let metrics = self.sync_runtime.metrics();
            if send_bounded_worker_lane(
                persistence_work_tx,
                SyncPersistenceWork {
                    backend: backend.clone(),
                    batch,
                    chunk_len,
                    chunk_bytes,
                    metrics: metrics.clone(),
                },
                &metrics,
                "sync_persistence",
                self.config.sync_tuning.sync_persistence_capacity,
            )
            .await
            .is_err()
            {
                error!("sync data processor: persistence worker stopped");
                return false;
            }
            submitted_leaves = submitted_leaves.saturating_add(chunk_len);
            submitted_chunks = submitted_chunks.saturating_add(1);
        }

        for _ in 0..submitted_chunks {
            match persistence_result_rx.recv().await {
                Some(SyncPersistenceResult {
                    chunk_len,
                    chunk_bytes,
                    result: Ok(()),
                }) => {
                    total_staged = total_staged.saturating_add(chunk_len);
                    total_bytes = total_bytes.saturating_add(chunk_bytes);
                    maybe_trim_allocator_after_sync_flush(chunk_bytes);
                }
                Some(SyncPersistenceResult {
                    chunk_len, result, ..
                }) => {
                    error!(
                        "sync data processor: failed to flush {}{}leaves to NuDB: {}",
                        flush_kind,
                        chunk_len,
                        result.err().unwrap_or_else(|| "unknown error".to_string()),
                    );
                    return false;
                }
                None => {
                    error!("sync data processor: persistence result channel closed");
                    return false;
                }
            }
        }
        pending_leaves.drain(..submitted_leaves);

        pending_leaves.shrink_to(Self::NUDB_FLUSH_CHUNK_LEAVES);
        info!(
            "sync data processor: durably flushed {}{}leaves to NuDB ({} bytes)",
            flush_kind, total_staged, total_bytes,
        );
        true
    }

    fn evict_synced_leaves_from_memory(&self, reason: &str) {
        let mut sync_guard = self.sync_runtime.lock_sync();
        let Some(syncer) = sync_guard.as_mut() else {
            return;
        };
        let evicted = syncer.evict_clean_leaves();
        if evicted > 0 {
            info!(
                "sync data processor: evicted {} persisted leaves from memory ({})",
                evicted, reason
            );
        }
    }

    pub(super) async fn finalize_completed_sync_epoch(
        &self,
        shamap: crate::ledger::shamap::SHAMap,
        sync_header: crate::ledger::LedgerHeader,
        sync_info: (usize, usize, u32, u32, usize),
        pending_leaves: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> bool {
        let persistence_capacity = self.config.sync_tuning.sync_persistence_capacity;
        let (persistence_work_tx, mut persistence_result_rx, persistence_worker) =
            spawn_sync_persistence_lane(persistence_capacity);
        let finalized = self
            .finalize_completed_sync_epoch_with_persistence_lane(
                shamap,
                sync_header,
                sync_info,
                pending_leaves,
                &persistence_work_tx,
                &mut persistence_result_rx,
            )
            .await;
        persistence_worker.abort();
        finalized
    }

    async fn finalize_completed_sync_epoch_with_persistence_lane(
        &self,
        shamap: crate::ledger::shamap::SHAMap,
        sync_header: crate::ledger::LedgerHeader,
        sync_info: (usize, usize, u32, u32, usize),
        pending_leaves: &mut Vec<(Vec<u8>, Vec<u8>)>,
        persistence_work_tx: &tokio::sync::mpsc::Sender<SyncPersistenceWork>,
        persistence_result_rx: &mut tokio::sync::mpsc::Receiver<SyncPersistenceResult>,
    ) -> bool {
        if !pending_leaves.is_empty()
            && !self
                .flush_sync_leaves_to_nudb(
                    pending_leaves,
                    true,
                    persistence_work_tx,
                    persistence_result_rx,
                )
                .await
        {
            error!("sync completion aborted: final leaf flush to NuDB failed");
            return false;
        }
        info!("sync data processor: tree complete — flushing NuDB to disk");
        if let Some(ref backend) = self.nudb_backend {
            match backend.flush_to_disk() {
                Ok(()) => info!("NuDB flush complete"),
                Err(e) => {
                    error!("NuDB flush FAILED: {}", e);
                    return false;
                }
            }
        }
        let mut handoff_shamap = shamap;
        let evicted = handoff_shamap.evict_clean_leaves();
        if evicted > 0 {
            info!(
                "sync data processor: evicted {} persisted leaves before handoff",
                evicted
            );
        }
        let verified_root_hash = handoff_shamap.root_hash();
        let completion = plan_sync_completion_outcome(verified_root_hash, sync_header.account_hash);

        if completion.verified {
            info!(
                "sync verification PASSED: hash={} matches target",
                hex::encode_upper(&verified_root_hash[..8]),
            );
            match handoff_shamap.flush_dirty() {
                Ok(flushed) => {
                    if flushed > 0 {
                        info!(
                            "sync data processor: persisted {} handoff SHAMap node(s) before anchor",
                            flushed,
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "sync data processor: failed to persist handoff SHAMap: {}",
                        e
                    );
                    return false;
                }
            }
            if let Some(ref backend) = self.nudb_backend {
                match backend.flush_to_disk() {
                    Ok(()) => info!("NuDB handoff root flush complete"),
                    Err(e) => {
                        error!("NuDB handoff root flush FAILED: {}", e);
                        return false;
                    }
                }
            }
            info!("sync data processor: handing off SHAMap to LedgerState");
            let ledger_state = {
                let state = self.state.read().await;
                state.ctx.ledger_state.clone()
            };
            {
                let mut ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                ls.set_nudb_shamap(handoff_shamap);
                ls.enable_sparse();
            }

            self.run_post_sync_checkpoint(&sync_header).await;

            let anchor_verified = self.acquire_sync_anchor_transactions(&sync_header).await;
            if !sync_anchor_gate_satisfied(&sync_header, anchor_verified) {
                self.sync_runtime.note_completion_anchor_blocked();
                {
                    let mut state = self.state.write().await;
                    if completion.clear_sync_in_progress {
                        state.sync_in_progress = false;
                    }
                    state.sync_done = false;
                }
                self.sync_runtime.set_bootstrap_active(false);
                warn!(
                    "sync anchor acquisition failed for seq={} hash={} with nonzero tx root — not persisting anchor or marking sync complete",
                    sync_header.sequence,
                    hex::encode_upper(&sync_header.hash[..8]),
                );
                return false;
            }
            if !anchor_verified {
                warn!(
                    "sync anchor acquisition failed for seq={} hash={} with zero tx root — allowing state sync completion",
                    sync_header.sequence,
                    hex::encode_upper(&sync_header.hash[..8]),
                );
            }

            if let Some(ref store) = self.storage {
                let _ = store.save_leaf_count(sync_info.1 as u64);
                if completion.persist_anchor {
                    let _ = store.persist_sync_anchor(&sync_header);
                }
                let _ = store.flush();
            }

            {
                let mut state = self.state.write().await;
                if completion.clear_sync_in_progress {
                    state.sync_in_progress = false;
                }
                state.sync_done = completion.mark_sync_done;
            }
            if completion.mark_sync_done {
                self.sync_runtime.set_bootstrap_active(false);
            }

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
            self.sync_runtime.set_bootstrap_active(false);
            warn!(
                "sync verification FAILED: ours={} target={} — not persisting anchor or starting follower",
                hex::encode_upper(&verified_root_hash[..8]),
                hex::encode_upper(&sync_header.account_hash[..8]),
            );
        }

        true
    }

    async fn handle_sync_epoch_followup(
        &self,
        outcome: &'static str,
        sync_info: (usize, usize, u32, u32, usize),
        epoch_peer_useful_counts: &HashMap<PeerId, u32>,
        epoch_peer_duplicate_counts: &HashMap<PeerId, u32>,
        batch_len: usize,
        epoch_batch_count: usize,
        walk_ms: u128,
        request_work_tx: &tokio::sync::mpsc::Sender<SyncRequestGenerationWork>,
        request_result_rx: &mut tokio::sync::mpsc::Receiver<SyncRequestGenerationResult>,
    ) -> bool {
        if !epoch_peer_useful_counts.is_empty() {
            let mut state = self.state.write().await;
            crate::sync_epoch::apply_useful_peer_counts(
                &mut state,
                epoch_peer_useful_counts,
                std::time::Instant::now(),
            );
        }
        if !epoch_peer_duplicate_counts.is_empty() {
            let mut state = self.state.write().await;
            crate::sync_epoch::apply_duplicate_peer_counts(
                &mut state,
                epoch_peer_duplicate_counts,
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
                self.select_reply_sync_peers(
                    &state,
                    sync_info.2,
                    epoch_peer_useful_counts,
                    self.config.sync_tuning.sync_reply_followup_peers,
                )
            };
            let num_peers = target_peers.len().max(1);

            let work = SyncRequestGenerationWork {
                sync_arc: self.sync_runtime.sync_arc(),
                num_peers,
                metrics: self.sync_runtime.metrics(),
            };
            let metrics = self.sync_runtime.metrics();
            if send_bounded_worker_lane(
                request_work_tx,
                work,
                &metrics,
                "sync_request_generation",
                self.config.sync_tuning.sync_request_generation_capacity,
            )
            .await
            .is_err()
            {
                error!("sync request generation worker stopped");
                return false;
            }
            let crate::sync_epoch::ReplyFollowupBuildResult { reqs, sync_seq } =
                match request_result_rx.recv().await {
                    Some(SyncRequestGenerationResult { result, panic }) => {
                        if let Some(panic) = panic {
                            error!("sync trigger(Reply) panicked: {}", panic);
                        }
                        result
                    }
                    None => {
                        error!("sync request generation result channel closed");
                        return false;
                    }
                };

            let mut total_reqs = 0usize;
            if !reqs.is_empty() {
                if target_peers.is_empty() {
                    for req in &reqs {
                        total_reqs += self.sync_send_request(req, sync_seq, None).await;
                    }
                } else if reqs.len() < target_peers.len() {
                    info!(
                        "sync reply follow-up: replicating {} tail request(s) across {} peer(s)",
                        reqs.len(),
                        target_peers.len(),
                    );
                    for req in &reqs {
                        let mut sent_for_req = 0usize;
                        for pid in &target_peers {
                            sent_for_req += self.sync_send_request(req, sync_seq, Some(*pid)).await;
                        }
                        if sent_for_req == 0 {
                            total_reqs += self.sync_send_request(req, sync_seq, None).await;
                        } else {
                            total_reqs += sent_for_req;
                        }
                    }
                } else {
                    for (i, req) in reqs.iter().enumerate() {
                        let peer_idx = i % target_peers.len();
                        let pid = target_peers[peer_idx];
                        let sent = self.sync_send_request(req, sync_seq, Some(pid)).await;
                        if sent == 0 {
                            total_reqs += self.sync_send_request(req, sync_seq, None).await;
                        } else {
                            total_reqs += sent;
                        }
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
                let (queue_len, queue_bytes) = self.sync_runtime.sync_data_queue_stats();
                let sync_stats = self
                    .sync_runtime
                    .try_lock_sync()
                    .ok()
                    .and_then(|guard| guard.as_ref().map(|syncer| syncer.stats()));
                let latencies: Vec<_> = state
                    .peer_latency
                    .iter()
                    .map(|(pid, lat)| format!("{:?}={}ms", pid, lat))
                    .collect();
                if let Some(stats) = sync_stats {
                    info!(
                        "sync memory counters: queue={} ({} bytes) full_below={} recent={} outstanding={} object_out={} responded={} object_resp={} pending_obj={} pending_cookies={}",
                        queue_len,
                        queue_bytes,
                        stats.full_below,
                        stats.recent_nodes,
                        stats.outstanding_cookies,
                        stats.outstanding_object_queries,
                        stats.responded_cookies,
                        stats.responded_object_queries,
                        stats.pending_object_nodeids,
                        stats.pending_object_cookies,
                    );
                } else {
                    info!(
                        "sync memory counters: queue={} ({} bytes), sync lock busy",
                        queue_len, queue_bytes,
                    );
                }
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
        true
    }

    pub(super) async fn run_sync_data_processor(self: Arc<Self>) {
        let shutdown = self.shutdown.clone();
        const NUDB_FLUSH_THRESHOLD: usize = 4000;
        let mut pending_leaves: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let tuning = self.config.sync_tuning.clone();
        let (mut pipeline_work_tx, mut pipeline_result_rx, mut pipeline_worker) =
            spawn_sync_data_pipeline_lane(tuning.sync_data_pipeline_capacity);
        let (mut request_work_tx, mut request_result_rx, mut request_generation_worker) =
            spawn_sync_request_generation_lane(tuning.sync_request_generation_capacity);
        let (mut persistence_work_tx, mut persistence_result_rx, mut persistence_worker) =
            spawn_sync_persistence_lane(tuning.sync_persistence_capacity);
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
                    pipeline_worker.abort();
                    request_generation_worker.abort();
                    persistence_worker.abort();
                    return;
                }
            }

            if pipeline_worker.is_finished() {
                error!("sync data processor pipeline worker exited; restarting lane");
                (pipeline_work_tx, pipeline_result_rx, pipeline_worker) =
                    spawn_sync_data_pipeline_lane(tuning.sync_data_pipeline_capacity);
            }
            if request_generation_worker.is_finished() {
                error!("sync request generation worker exited; restarting lane");
                (
                    request_work_tx,
                    request_result_rx,
                    request_generation_worker,
                ) = spawn_sync_request_generation_lane(tuning.sync_request_generation_capacity);
            }
            if persistence_worker.is_finished() {
                error!("sync persistence worker exited; restarting lane");
                (
                    persistence_work_tx,
                    persistence_result_rx,
                    persistence_worker,
                ) = spawn_sync_persistence_lane(tuning.sync_persistence_capacity);
            }

            let mut epoch_peer_useful_counts: HashMap<PeerId, u32> = HashMap::new();
            let mut epoch_peer_duplicate_counts: HashMap<PeerId, u32> = HashMap::new();
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

                let work = SyncDataPipelineWork {
                    sync_arc: self.sync_runtime.sync_arc(),
                    batch,
                    max_sync: self.config.max_sync,
                    metrics: self.sync_runtime.metrics(),
                    parse_workers: tuning.sync_parse_workers,
                    completion_check_interval: tuning.completion_check_interval(),
                };
                let metrics = self.sync_runtime.metrics();
                if send_bounded_worker_lane(
                    &pipeline_work_tx,
                    work,
                    &metrics,
                    "sync_data_apply",
                    tuning.sync_data_pipeline_capacity,
                )
                .await
                .is_err()
                {
                    error!("sync data processor pipeline worker stopped");
                    pipeline_worker.abort();
                    (pipeline_work_tx, pipeline_result_rx, pipeline_worker) =
                        spawn_sync_data_pipeline_lane(tuning.sync_data_pipeline_capacity);
                    epoch_sync_info = None;
                    break;
                }

                let pipeline_result = match pipeline_result_rx.recv().await {
                    Some(result) => result,
                    None => {
                        error!("sync data processor pipeline result channel closed");
                        pipeline_worker.abort();
                        (pipeline_work_tx, pipeline_result_rx, pipeline_worker) =
                            spawn_sync_data_pipeline_lane(tuning.sync_data_pipeline_capacity);
                        epoch_sync_info = None;
                        break;
                    }
                };
                if let Some(panic) = pipeline_result.panic {
                    error!("sync data processor worker panicked: {}", panic);
                    epoch_sync_info = None;
                    break;
                }
                let result = match pipeline_result.result {
                    Some(r) => r,
                    None => {
                        epoch_sync_info = None;
                        break;
                    }
                };
                let crate::sync_processor::SyncBatchProcessResult {
                    outcome,
                    sync_info,
                    peer_useful_counts,
                    peer_duplicate_counts,
                    completed_shamap,
                    synced_inner_nodes,
                    synced_leaves,
                } = result;
                epoch_walk_ms = epoch_walk_ms.saturating_add(pipeline_result.walk_ms);
                epoch_sync_info = Some(sync_info);

                if !synced_inner_nodes.is_empty() {
                    if let Some(backend) = self.nudb_backend.clone() {
                        let chunk_len = synced_inner_nodes.len();
                        let chunk_bytes = synced_inner_nodes
                            .iter()
                            .fold(0usize, |sum, (_, data)| sum.saturating_add(data.len()));
                        let metrics = self.sync_runtime.metrics();
                        if send_bounded_worker_lane(
                            &persistence_work_tx,
                            SyncPersistenceWork {
                                backend,
                                batch: synced_inner_nodes,
                                chunk_len,
                                chunk_bytes,
                                metrics: metrics.clone(),
                            },
                            &metrics,
                            "sync_persistence",
                            tuning.sync_persistence_capacity,
                        )
                        .await
                        .is_err()
                        {
                            error!("sync data processor: persistence worker stopped");
                            epoch_sync_info = None;
                            break;
                        } else {
                            match persistence_result_rx.recv().await {
                                Some(SyncPersistenceResult { result: Ok(()), .. }) => {}
                                Some(SyncPersistenceResult {
                                    result: Err(err), ..
                                }) => {
                                    error!(
                                        "sync data processor: inner-node persistence failed: {}",
                                        err
                                    );
                                    epoch_sync_info = None;
                                    break;
                                }
                                None => {
                                    error!(
                                        "sync data processor: inner-node persistence result channel closed"
                                    );
                                    epoch_sync_info = None;
                                    break;
                                }
                            }
                        }
                    }
                }

                if !synced_leaves.is_empty() {
                    pending_leaves.extend(synced_leaves);
                    if pending_leaves.len() >= NUDB_FLUSH_THRESHOLD {
                        if self
                            .flush_sync_leaves_to_nudb(
                                &mut pending_leaves,
                                false,
                                &persistence_work_tx,
                                &mut persistence_result_rx,
                            )
                            .await
                        {
                            self.evict_synced_leaves_from_memory("periodic NuDB flush");
                        } else {
                            persistence_worker.abort();
                            (
                                persistence_work_tx,
                                persistence_result_rx,
                                persistence_worker,
                            ) = spawn_sync_persistence_lane(tuning.sync_persistence_capacity);
                        }
                    }
                }

                for (peer_id, useful) in peer_useful_counts {
                    let entry = epoch_peer_useful_counts.entry(peer_id).or_insert(0);
                    *entry = entry.saturating_add(useful);
                }
                for (peer_id, duplicates) in peer_duplicate_counts {
                    let entry = epoch_peer_duplicate_counts.entry(peer_id).or_insert(0);
                    *entry = entry.saturating_add(duplicates);
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

            let Some(mut sync_info) = epoch_sync_info else {
                continue;
            };
            let mut completed_shamap = epoch_completed_shamap;
            let outcome = epoch_outcome;
            let batch_len = epoch_response_count;
            let walk_ms = epoch_walk_ms;

            if completed_shamap.is_none() && !pending_leaves.is_empty() {
                if self
                    .flush_sync_leaves_to_nudb(
                        &mut pending_leaves,
                        false,
                        &persistence_work_tx,
                        &mut persistence_result_rx,
                    )
                    .await
                {
                    self.evict_synced_leaves_from_memory("pre-completion NuDB checkpoint");
                    let completion = crate::sync_epoch::check_sync_completion(
                        self.sync_runtime.sync_arc(),
                        std::time::Duration::ZERO,
                    );
                    if completion.checked {
                        let complete = completion.completed.is_some();
                        self.sync_runtime
                            .metrics()
                            .note_completion_check(completion.plausible, complete);
                    }
                    if completion.completed.is_some() {
                        info!(
                            "sync data processor: completion succeeded after durable leaf checkpoint"
                        );
                    }
                    if let Some((shamap, header, completed_sync_info)) = completion.completed {
                        sync_info = completed_sync_info;
                        completed_shamap = Some((shamap, header));
                    }
                } else {
                    persistence_worker.abort();
                    (
                        persistence_work_tx,
                        persistence_result_rx,
                        persistence_worker,
                    ) = spawn_sync_persistence_lane(tuning.sync_persistence_capacity);
                    continue;
                }
            }

            if let Some((shamap, sync_header)) = completed_shamap {
                if !self
                    .finalize_completed_sync_epoch_with_persistence_lane(
                        shamap,
                        sync_header,
                        sync_info,
                        &mut pending_leaves,
                        &persistence_work_tx,
                        &mut persistence_result_rx,
                    )
                    .await
                {
                    persistence_worker.abort();
                    (
                        persistence_work_tx,
                        persistence_result_rx,
                        persistence_worker,
                    ) = spawn_sync_persistence_lane(tuning.sync_persistence_capacity);
                    continue;
                }
            }

            if !self
                .handle_sync_epoch_followup(
                    outcome,
                    sync_info,
                    &epoch_peer_useful_counts,
                    &epoch_peer_duplicate_counts,
                    batch_len,
                    epoch_batch_count,
                    walk_ms,
                    &request_work_tx,
                    &mut request_result_rx,
                )
                .await
            {
                request_generation_worker.abort();
                (
                    request_work_tx,
                    request_result_rx,
                    request_generation_worker,
                ) = spawn_sync_request_generation_lane(tuning.sync_request_generation_capacity);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct RecordingNodeStore {
        stored_first_bytes: Mutex<Vec<u8>>,
        flush_count: std::sync::atomic::AtomicUsize,
    }

    impl crate::ledger::node_store::NodeStore for RecordingNodeStore {
        fn store(&self, hash: &[u8; 32], _data: &[u8]) -> std::io::Result<()> {
            self.stored_first_bytes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(hash[0]);
            Ok(())
        }

        fn fetch(&self, _hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
            Ok(None)
        }

        fn flush_to_disk(&self) -> std::io::Result<()> {
            self.flush_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    fn header_with_tx_hash(tx_hash: [u8; 32]) -> crate::ledger::LedgerHeader {
        crate::ledger::LedgerHeader {
            transaction_hash: tx_hash,
            ..Default::default()
        }
    }

    #[test]
    fn anchor_gate_requires_success_for_nonzero_transaction_hash() {
        let header = header_with_tx_hash([0xAA; 32]);

        assert!(!super::sync_anchor_gate_satisfied(&header, false));
        assert!(super::sync_anchor_gate_satisfied(&header, true));
    }

    #[test]
    fn anchor_gate_allows_missing_acquisition_for_empty_transaction_hash() {
        let header = header_with_tx_hash([0u8; 32]);

        assert!(super::sync_anchor_gate_satisfied(&header, false));
    }

    #[tokio::test]
    async fn bounded_worker_lane_records_backpressure_when_full() {
        let metrics = std::sync::Arc::new(crate::sync_runtime::SyncMetrics::default());
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.send(1u8).await.unwrap();

        let send_tx = tx.clone();
        let send_metrics = metrics.clone();
        let send = tokio::spawn(async move {
            super::send_bounded_worker_lane(&send_tx, 2u8, &send_metrics, "test_lane", 1).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        assert_eq!(rx.recv().await, Some(1));
        send.await.unwrap().unwrap();
        assert_eq!(rx.recv().await, Some(2));

        let snap = metrics.snapshot();
        let lane = snap
            .worker_lanes
            .iter()
            .find(|lane| lane.lane == "test_lane")
            .expect("test lane metrics");
        assert_eq!(lane.queue_capacity, 1);
        assert_eq!(lane.max_queue_depth, 1);
        assert_eq!(lane.enqueued_total, 1);
        assert_eq!(lane.backpressure_total, 1);
    }

    #[tokio::test]
    async fn persistence_worker_preserves_fifo_result_and_store_order() {
        let backend = Arc::new(RecordingNodeStore::default());
        let metrics = Arc::new(crate::sync_runtime::SyncMetrics::default());
        let (work_tx, mut result_rx, worker) = super::spawn_sync_persistence_lane(4);

        work_tx
            .send(super::SyncPersistenceWork {
                backend: backend.clone(),
                batch: vec![([1u8; 32], vec![1])],
                chunk_len: 1,
                chunk_bytes: 33,
                metrics: metrics.clone(),
            })
            .await
            .unwrap();
        work_tx
            .send(super::SyncPersistenceWork {
                backend: backend.clone(),
                batch: vec![([2u8; 32], vec![2])],
                chunk_len: 2,
                chunk_bytes: 34,
                metrics,
            })
            .await
            .unwrap();

        let first = result_rx.recv().await.expect("first persistence result");
        let second = result_rx.recv().await.expect("second persistence result");
        worker.abort();

        assert_eq!(first.chunk_len, 1);
        assert!(first.result.is_ok());
        assert_eq!(second.chunk_len, 2);
        assert!(second.result.is_ok());
        assert_eq!(
            *backend
                .stored_first_bytes
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            vec![1, 2]
        );
        assert_eq!(
            backend
                .flush_count
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }
}

#[cfg(target_os = "linux")]
fn maybe_trim_allocator_after_sync_flush(freed_bytes: usize) {
    const MALLOC_TRIM_MIN_BYTES: usize = 512 * 1024;
    if freed_bytes < MALLOC_TRIM_MIN_BYTES {
        return;
    }
    if std::env::var_os("XLEDGRSV2BETA_MALLOC_TRIM").is_none() {
        return;
    }
    unsafe {
        libc::malloc_trim(0);
    }
}

#[cfg(not(target_os = "linux"))]
fn maybe_trim_allocator_after_sync_flush(_freed_bytes: usize) {}
