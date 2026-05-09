use super::*;
use prost::Message as ProstMessage;

impl Node {
    pub(super) fn lock_sync(
        &self,
    ) -> std::sync::MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>> {
        self.sync_runtime.lock_sync()
    }

    pub fn storage(&self) -> Option<&Arc<crate::storage::Storage>> {
        self.storage.as_ref()
    }

    pub fn sync_lock(
        &self,
    ) -> Option<std::sync::MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>>> {
        Some(self.lock_sync())
    }

    pub(super) fn follower_healthy_for_status(state: &SharedState) -> bool {
        if !state.sync_done || state.ctx.standalone_mode {
            return true;
        }
        state.follower_state.as_ref().is_some_and(|fs| {
            fs.running.load(std::sync::atomic::Ordering::Relaxed)
                && !fs
                    .resync_requested
                    .load(std::sync::atomic::Ordering::Relaxed)
        })
    }

    pub(super) fn rpc_object_count(&self) -> usize {
        if let Some(ref backend) = self.nudb_backend {
            return backend.count() as usize;
        }
        0
    }

    pub fn state_ref(&self) -> &Arc<tokio::sync::RwLock<SharedState>> {
        &self.state
    }

    pub fn signal_shutdown(&self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn shutdown_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown.clone()
    }

    pub(super) fn track_background_task(
        &self,
        name: &'static str,
        handle: tokio::task::JoinHandle<()>,
    ) {
        let mut tasks = self
            .background_tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        tasks.retain(|task| !task.handle.is_finished());
        tasks.push(BackgroundTask { name, handle });
    }

    pub async fn join_background_tasks(
        &self,
        timeout: std::time::Duration,
    ) -> BackgroundTaskJoinSummary {
        let mut tasks = {
            let mut guard = self
                .background_tasks
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        };
        let deadline = tokio::time::Instant::now() + timeout;
        let mut summary = BackgroundTaskJoinSummary::default();

        for task in &mut tasks {
            let now = tokio::time::Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            match tokio::time::timeout(remaining, &mut task.handle).await {
                Ok(Ok(())) => {
                    summary.completed = summary.completed.saturating_add(1);
                }
                Ok(Err(err)) => {
                    summary.failed = summary.failed.saturating_add(1);
                    tracing::warn!("background task {} ended with error: {}", task.name, err);
                }
                Err(_) => {
                    summary.aborted = summary.aborted.saturating_add(1);
                    tracing::warn!(
                        "background task {} did not stop within shutdown grace; aborting",
                        task.name
                    );
                    task.handle.abort();
                    let _ = (&mut task.handle).await;
                }
            }
        }

        summary
    }

    pub(super) fn is_shutting_down(&self) -> bool {
        self.shutdown.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(super) async fn consensus_close_loop_pause_reason(&self) -> Option<&'static str> {
        if self.is_shutting_down() {
            return Some("shutdown requested");
        }

        let state = self.state.read().await;
        if !state.sync_done {
            return Some("state sync still in progress");
        }
        if self.config.standalone
            && (self.validator_key.is_some() || self.config.allow_node_key_consensus)
        {
            return None;
        }
        if self.validator_key.is_none() {
            return Some("validator signing key unavailable");
        }
        if self
            .unl
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
        {
            return Some("trusted validator list is not loaded");
        }
        match state.follower_state.as_ref() {
            None => Some("ledger follower not started"),
            Some(fs)
                if fs
                    .resync_requested
                    .load(std::sync::atomic::Ordering::Relaxed) =>
            {
                Some("ledger follower requested resync")
            }
            Some(fs) if !fs.running.load(std::sync::atomic::Ordering::Relaxed) => {
                Some("ledger follower is not running")
            }
            Some(fs) if fs.hash_matches.load(std::sync::atomic::Ordering::Relaxed) == 0 => {
                Some("waiting for first post-sync follower hash match")
            }
            Some(fs) => {
                const FOLLOWER_CATCHUP_TOLERANCE_LEDGERS: u32 = 4;
                let follower_seq = fs
                    .current_seq
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .max(state.ctx.ledger_seq);
                let observed_tip = state
                    .peer_ledger_range
                    .values()
                    .map(|(_, last)| *last)
                    .max()
                    .or_else(|| state.validated_hashes.keys().copied().max());
                if observed_tip.is_some_and(|tip| {
                    follower_seq.saturating_add(FOLLOWER_CATCHUP_TOLERANCE_LEDGERS) < tip
                }) {
                    Some("ledger follower is catching up to network tip")
                } else {
                    None
                }
            }
        }
    }

    pub async fn update_rpc_snapshot(&self) {
        let fetch_info_sync = self.snapshot_sync_fetch();
        let object_count = self.rpc_object_count();
        let leaf_count = fetch_info_sync
            .as_ref()
            .map(|sync| sync.state_nodes())
            .unwrap_or(object_count as usize);
        let state = self.state.read().await;
        let fetch_info = fetch_info_sync.map(|sync| Self::build_fetch_info_snapshot(&state, sync));
        let snap = Self::build_rpc_snapshot(
            &state,
            object_count,
            leaf_count,
            &self.node_key,
            self.validator_key.as_ref(),
        );
        let mut ctx = Self::build_rpc_read_context(&state, object_count, fetch_info);
        ctx.sync_metrics = Some(self.sync_runtime.metrics_snapshot());
        self.rpc_snapshot.store(Arc::new(snap));
        self.rpc_read_ctx.store(Arc::new(ctx));
    }

    pub fn rpc_snapshot(&self) -> arc_swap::Guard<Arc<crate::rpc::RpcSnapshot>> {
        self.rpc_snapshot.load()
    }

    pub fn rpc_read_context(&self) -> arc_swap::Guard<Arc<crate::rpc::NodeContext>> {
        self.rpc_read_ctx.load()
    }

    pub async fn dispatch_write_rpc(&self, req: crate::rpc::RpcRequest) -> crate::rpc::RpcResponse {
        let mut state = self.state.write().await;
        state.ctx.peer_count = state.peer_count();
        state.ctx.follower_state = state.follower_state.clone();
        state.refresh_runtime_health(std::time::Instant::now());
        state.ctx.load_snapshot = state.services.load_manager.snapshot();
        let reply = crate::rpc::dispatch(req, &mut state.ctx);
        let (queued_transactions, candidate_set_hash, metrics, pool_snapshot) = {
            let pool = state.ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
            (
                pool.len(),
                pool.canonical_set_hash(),
                pool.metrics.clone(),
                pool.clone(),
            )
        };
        if let Some(closed_ledger) = state.ctx.closed_ledger.clone() {
            state.services.open_ledger.sync_with_pool(
                closed_ledger,
                &pool_snapshot,
                queued_transactions,
                candidate_set_hash,
                &metrics,
            );
        } else {
            state.services.open_ledger.note_queue_state(
                queued_transactions,
                candidate_set_hash,
                &metrics,
            );
        }
        let pending: Vec<_> = state.ctx.broadcast_queue.drain(..).collect();
        state.services.note_local_broadcasts(&pending);
        for msg in &pending {
            state.broadcast(msg, None);
        }
        reply
    }

    pub(super) fn message_is_new(&self, msg_type: MessageType, payload: &[u8]) -> bool {
        let hash: [u8; 32] = match msg_type {
            MessageType::Validation => {
                if let Ok(val) = crate::proto::TmValidation::decode(payload) {
                    crate::crypto::sha512_first_half(&val.validation)
                } else {
                    crate::crypto::sha256(payload)
                }
            }
            MessageType::Transaction => {
                if let Ok(tx) = crate::proto::TmTransaction::decode(payload) {
                    let mut data = vec![0x54, 0x58, 0x4E, 0x00];
                    data.extend_from_slice(&tx.raw_transaction);
                    crate::crypto::sha512_first_half(&data)
                } else {
                    crate::crypto::sha256(payload)
                }
            }
            MessageType::ProposeLedger => {
                if let Ok(prop) = crate::proto::TmProposeSet::decode(payload) {
                    let mut data = Vec::new();
                    data.extend_from_slice(&prop.current_tx_hash);
                    data.extend_from_slice(&prop.previousledger);
                    data.extend_from_slice(&prop.propose_seq.to_be_bytes());
                    data.extend_from_slice(&prop.close_time.to_be_bytes());
                    data.extend_from_slice(&prop.node_pub_key);
                    crate::crypto::sha256(&data)
                } else {
                    crate::crypto::sha256(payload)
                }
            }
            _ => crate::crypto::sha256(payload),
        };
        let mut guard = self.msg_dedup.lock().unwrap_or_else(|e| e.into_inner());
        if guard.1.elapsed().as_secs() >= 300 || guard.0.len() >= 65_536 {
            guard.0.clear();
            guard.1 = std::time::Instant::now();
        }
        guard.0.insert(hash)
    }

    pub(super) fn bootstrap_syncing_fast(&self) -> bool {
        if self.sync_runtime.bootstrap_active() {
            return true;
        }
        if let Ok(state) = self.state.try_read() {
            if state.sync_done {
                return false;
            }
            if state.sync_in_progress {
                return true;
            }
        }
        self.sync_runtime.sync_active()
    }

    pub(super) fn debug_log(&self, msg: &str) {
        if let Ok(mut guard) = self.debug_log.lock() {
            if let Some(ref mut file) = *guard {
                use std::io::Write;
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let _ = writeln!(file, "[{}] {}", ts, msg);
            }
        }
    }

    pub(super) async fn sync_peer_state_snapshot(&self, peer: &Peer) {
        let mut state = self.state.write().await;
        state.peers.insert(peer.id, peer.state.clone());
    }
}
