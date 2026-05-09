use super::*;

pub(super) struct PeerRouteJob {
    pub(super) seq: u64,
    peer: Peer,
    msg: RtxpMessage,
}

pub(super) struct PeerRouteResult {
    pub seq: u64,
    pub msg_type: MessageType,
    pub event: PeerEvent,
    pub route_ms: u128,
}

impl Node {
    pub(super) fn peer_route_channel(
        &self,
    ) -> (
        mpsc::Sender<PeerRouteJob>,
        mpsc::Receiver<PeerRouteJob>,
        mpsc::Sender<PeerRouteResult>,
        mpsc::Receiver<PeerRouteResult>,
    ) {
        let capacity = self.config.sync_tuning.peer_route_queue;
        let (route_tx, route_rx) = mpsc::channel(capacity);
        let (result_tx, result_rx) = mpsc::channel(capacity);
        (route_tx, route_rx, result_tx, result_rx)
    }

    pub(super) async fn run_peer_route_worker(
        self: Arc<Self>,
        peer_id: PeerId,
        mut route_rx: mpsc::Receiver<PeerRouteJob>,
        result_tx: mpsc::Sender<PeerRouteResult>,
    ) {
        while let Some(job) = route_rx.recv().await {
            let _permit = match self.route_work_permits.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => break,
            };
            let result = self.process_routed_peer_message(job.peer, job.msg).await;
            let result = PeerRouteResult {
                seq: job.seq,
                ..result
            };
            if result_tx.send(result).await.is_err() {
                break;
            }
        }
        trace!("peer {peer_id:?} route worker stopped");
    }

    async fn process_routed_peer_message(
        self: &Arc<Self>,
        peer: Peer,
        msg: RtxpMessage,
    ) -> PeerRouteResult {
        let msg_type = msg.msg_type;
        let rm_t0 = std::time::Instant::now();
        let event = self.route_message(&peer, msg).await;
        let rm_ms = rm_t0.elapsed().as_millis();
        PeerRouteResult {
            seq: 0,
            msg_type,
            event,
            route_ms: rm_ms,
        }
    }

    async fn charge_peer_protocol_drop(self: &Arc<Self>, peer: &Peer, reason: impl Into<String>) {
        let reason = reason.into();
        let mut state = self.state.write().await;
        let _ = state.services.resource_manager.charge_consumer(
            &peer.resource_consumer,
            6_000,
            reason,
            std::time::Instant::now(),
        );
    }

    fn log_slow_route_message(
        msg_type: MessageType,
        peer: PeerId,
        rm_ms: u128,
        severe_route_ms: u128,
    ) {
        static SLOW_ROUTE_SUPPRESSED: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        static LAST_SLOW_ROUTE_SUMMARY: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);

        let severe = matches!(msg_type, MessageType::Manifests) || rm_ms >= severe_route_ms;
        if severe {
            warn!(
                "SLOW route_message: {:?} from {:?} took {}ms",
                msg_type, peer, rm_ms,
            );
            return;
        }

        let count = SLOW_ROUTE_SUPPRESSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let prev = LAST_SLOW_ROUTE_SUMMARY.load(std::sync::atomic::Ordering::Relaxed);
        if now_secs >= prev + 30 {
            LAST_SLOW_ROUTE_SUMMARY.store(now_secs, std::sync::atomic::Ordering::Relaxed);
            info!(
                "suppressed {} moderately slow route_message warnings in last 30s",
                count
            );
            SLOW_ROUTE_SUPPRESSED.store(0, std::sync::atomic::Ordering::Relaxed);
        }
    }

    async fn record_route_message_latency(
        self: &Arc<Self>,
        msg_type: MessageType,
        peer_id: PeerId,
        rm_ms: u128,
    ) {
        let slow_threshold_ms = match msg_type {
            MessageType::Manifests => self.config.sync_tuning.slow_manifest_route_ms,
            _ => self.config.sync_tuning.slow_route_ms,
        };
        let slow = rm_ms > u128::from(slow_threshold_ms);
        let msg_type_label = format!("{msg_type:?}");
        self.sync_runtime.note_route_message(
            &msg_type_label,
            rm_ms.min(u64::MAX as u128) as u64,
            slow,
        );
        if slow {
            Self::log_slow_route_message(
                msg_type,
                peer_id,
                rm_ms,
                u128::from(self.config.sync_tuning.severe_route_ms),
            );
            let mut state = self.state.write().await;
            state.services.load_manager.note_slow_operation(
                std::time::Duration::from_millis(rm_ms as u64),
                format!("route_{msg_type:?}"),
                std::time::Instant::now(),
            );
        }
    }

    fn route_off_read_loop(msg_type: MessageType) -> bool {
        matches!(
            msg_type,
            MessageType::LedgerData | MessageType::GetLedger | MessageType::GetObjects
        )
    }

    pub(super) async fn process_peer_frames<S>(
        self: &Arc<Self>,
        stream: &mut S,
        peer: &mut Peer,
        dec: &mut FrameDecoder,
        bytes: &[u8],
        session_hash: &[u8; 32],
        route_tx: &mpsc::Sender<PeerRouteJob>,
        route_seq: &mut u64,
        next_route_result_seq: u64,
    ) -> bool
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    {
        if dec.feed(bytes).is_err() {
            warn!("peer {:?} buffer overflow — disconnecting", peer.id);
            self.charge_peer_protocol_drop(peer, "frame_buffer_overflow")
                .await;
            return true;
        }

        loop {
            match dec.drain_messages() {
                Err(e) => {
                    warn!("peer {:?} frame error: {e}", peer.id);
                    self.charge_peer_protocol_drop(peer, format!("frame_error:{e}"))
                        .await;
                    peer.handle(PeerEvent::Error(e.to_string()));
                    return true;
                }
                Ok(msgs) => {
                    if msgs.is_empty() {
                        break;
                    }
                    for msg in msgs {
                        let msg_type = msg.msg_type;
                        let has_pending_route_work = *route_seq > next_route_result_seq;
                        if Self::route_off_read_loop(msg_type) || has_pending_route_work {
                            let seq = *route_seq;
                            let job = PeerRouteJob {
                                seq,
                                peer: peer.clone(),
                                msg,
                            };
                            let capacity = route_tx.max_capacity();
                            match route_tx.try_send(job) {
                                Ok(()) => {
                                    *route_seq = route_seq.saturating_add(1);
                                    let len = capacity.saturating_sub(route_tx.capacity());
                                    self.sync_runtime.note_route_queue_enqueued(len, capacity);
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Full(job)) => {
                                    let msg_type_label = format!("{msg_type:?}");
                                    self.sync_runtime.note_route_queue_full_for(
                                        peer.id,
                                        &msg_type_label,
                                        capacity,
                                    );
                                    warn!(
                                        "peer {:?} route queue full for {:?}; applying bounded backpressure",
                                        peer.id, msg_type
                                    );
                                    match tokio::time::timeout(
                                        self.config.sync_tuning.peer_route_drain_timeout(),
                                        route_tx.send(job),
                                    )
                                    .await
                                    {
                                        Ok(Ok(())) => {
                                            *route_seq = route_seq.saturating_add(1);
                                            let len = capacity.saturating_sub(route_tx.capacity());
                                            self.sync_runtime
                                                .note_route_queue_enqueued(len, capacity);
                                        }
                                        Ok(Err(_)) => {
                                            warn!(
                                                "peer {:?} route queue closed for {:?}; disconnecting",
                                                peer.id, msg_type
                                            );
                                            return true;
                                        }
                                        Err(_) => {
                                            warn!(
                                                "peer {:?} route queue stayed full for {:?}; disconnecting before dropping ordered sync work",
                                                peer.id, msg_type
                                            );
                                            self.sync_runtime.note_route_queue_dropped_for(
                                                peer.id,
                                                &msg_type_label,
                                            );
                                            return true;
                                        }
                                    }
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_job)) => {
                                    let msg_type_label = format!("{msg_type:?}");
                                    self.sync_runtime.note_route_queue_full_for(
                                        peer.id,
                                        &msg_type_label,
                                        capacity,
                                    );
                                    warn!(
                                        "peer {:?} route queue closed for {:?}; dropping routed work",
                                        peer.id, msg_type
                                    );
                                    self.sync_runtime
                                        .note_route_queue_dropped_for(peer.id, &msg_type_label);
                                    return true;
                                }
                            }
                            continue;
                        }

                        let rm_t0 = std::time::Instant::now();
                        let event = self.route_message(peer, msg).await;
                        let rm_ms = rm_t0.elapsed().as_millis();
                        self.record_route_message_latency(msg_type, peer.id, rm_ms)
                            .await;
                        let action = peer.handle(event);
                        self.sync_peer_state_snapshot(peer).await;
                        if let Err(e) = self
                            .execute_action(stream, peer, action, session_hash)
                            .await
                        {
                            warn!("peer {:?} action error: {e}", peer.id);
                        }
                    }
                }
            }
            if dec.buffered_bytes() < HEADER_SIZE {
                break;
            }
        }

        false
    }

    pub(super) async fn apply_peer_route_result<S>(
        self: &Arc<Self>,
        stream: &mut S,
        peer: &mut Peer,
        result: PeerRouteResult,
        session_hash: &[u8; 32],
    ) where
        S: AsyncWriteExt + Unpin + Send,
    {
        self.record_route_message_latency(result.msg_type, peer.id, result.route_ms)
            .await;
        let action = peer.handle(result.event);
        self.sync_peer_state_snapshot(peer).await;
        if let Err(e) = self
            .execute_action(stream, peer, action, session_hash)
            .await
        {
            warn!("peer {:?} action error: {e}", peer.id);
        }
    }
}
