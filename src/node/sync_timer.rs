use super::*;

impl Node {
    pub(super) async fn run_sync_timer(self: Arc<Self>) {
        use std::time::Duration;
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if self.is_shutting_down() {
                info!("sync timer: shutdown");
                return;
            }

            self.update_rpc_snapshot().await;

            {
                let state = self.state.read().await;
                if let Some(ref fs) = state.follower_state {
                    if fs
                        .resync_requested
                        .swap(false, std::sync::atomic::Ordering::SeqCst)
                    {
                        drop(state);
                        info!("sync timer: follower requested re-sync — triggering state re-sync");
                        self.trigger_resync().await;
                        continue;
                    }
                }
            }

            {
                let state = self.state.read().await;
                if state
                    .ctx
                    .sync_clear_requested
                    .as_ref()
                    .is_some_and(|flag| flag.swap(false, std::sync::atomic::Ordering::SeqCst))
                {
                    drop(state);
                    info!("sync timer: RPC requested fetch clear — triggering state re-sync");
                    self.trigger_resync().await;
                    continue;
                }
            }

            {
                let (peers_low, sync_active) = {
                    let state = self.state.read().await;
                    let sync_active = state.sync_in_progress || self.sync_runtime.sync_active();
                    (
                        state.peer_count() < crate::ledger::inbound::REPLY_FOLLOWUP_PEERS,
                        sync_active,
                    )
                };
                if peers_low && sync_active {
                    let mut state = self.state.write().await;
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let candidates = state.services.peerfinder.autoconnect(now_unix);
                    let mut dialed = 0;
                    for addr in candidates {
                        if dialed >= crate::ledger::inbound::REPLY_FOLLOWUP_PEERS {
                            break;
                        }
                        let cooled = state
                            .peer_cooldowns
                            .get(&addr)
                            .map_or(false, |exp| std::time::Instant::now() < *exp);
                        if cooled || state.connected_addrs.contains(&addr) {
                            continue;
                        }
                        drop(state);
                        info!("sync timer: low peers during sync, dialing {}", addr);
                        let node = self.clone();
                        tokio::spawn(async move {
                            let _ = node.dial(addr).await;
                        });
                        dialed += 1;
                        state = self.state.write().await;
                    }
                }
            }

            {
                static LAST_PING_ROUND: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let prev = LAST_PING_ROUND.load(std::sync::atomic::Ordering::Relaxed);
                if now_secs >= prev + 30 {
                    LAST_PING_ROUND.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                    let mut state = self.state.write().await;
                    let open_pids: Vec<PeerId> = state
                        .peers
                        .iter()
                        .filter(|(_, ps)| ps.is_open())
                        .map(|(id, _)| *id)
                        .collect();
                    for pid in open_pids {
                        let seq = rand::random::<u32>();
                        state
                            .peer_ping_sent
                            .insert(pid, (seq, std::time::Instant::now()));
                        if let Some(tx) = state.peer_txs.get(&pid) {
                            let ping_msg = crate::network::relay::encode_ping(seq);
                            let _ = tx.try_send(ping_msg);
                        }
                    }
                }
            }

            {
                static LAST_STATUS_BROADCAST: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let prev = LAST_STATUS_BROADCAST.load(std::sync::atomic::Ordering::Relaxed);
                if now_secs >= prev + 15 {
                    LAST_STATUS_BROADCAST.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                    let state = self.state.read().await;
                    let status_msg = crate::network::relay::encode_status_change(
                        crate::proto::NodeStatus::NsConnected,
                        crate::proto::NodeEvent::NeAcceptedLedger,
                        state.ctx.ledger_seq,
                        &state.ctx.ledger_header.hash,
                    );
                    state.broadcast(&status_msg, None);
                    if state.services.cluster.snapshot(1).configured > 0 {
                        let public_key = crate::crypto::base58::encode(
                            crate::crypto::base58::PREFIX_NODE_PUBLIC,
                            &self.node_key.public_key_bytes(),
                        );
                        let blocked_peers = state
                            .services
                            .resource_manager
                            .snapshot(std::time::Instant::now(), 0)
                            .blocked as u32;
                        let cluster_msg = crate::network::relay::encode_cluster(
                            &public_key,
                            state.services.load_manager.snapshot().load_factor_server(),
                            Some(&self.config.peer_addr.to_string()),
                            blocked_peers,
                        );
                        state.broadcast(&cluster_msg, None);
                    }
                }
            }

            {
                static LAST_COOLDOWN_PRUNE: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let prev = LAST_COOLDOWN_PRUNE.load(std::sync::atomic::Ordering::Relaxed);
                if now_secs >= prev + 60 {
                    LAST_COOLDOWN_PRUNE.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                    let mut state = self.state.write().await;
                    let before = state.sync_peer_cooldown.len();
                    state.sync_peer_cooldown.retain(|pid, expires| {
                        let still_active = std::time::Instant::now() < *expires;
                        if !still_active {
                            self.debug_log(&format!("UNBENCHED: peer {:?}", pid));
                        }
                        still_active
                    });
                    let removed = before - state.sync_peer_cooldown.len();
                    if removed > 0 {
                        self.debug_log(&format!(
                            "cooldown prune: removed {} expired entries",
                            removed
                        ));
                    }
                    if let Some(store) = self.storage.as_ref() {
                        let _ = store.save_peerfinder_bootcache(
                            &state.services.peerfinder.persisted_entries(),
                        );
                    }
                }
            }

            {
                let inactive_target = self.sync_runtime.inactive_target();
                let needs_kickstart = inactive_target.is_some() || !self.sync_runtime.has_syncer();
                if needs_kickstart {
                    let state = self.state.read().await;
                    let have_validated_target =
                        state.ctx.ledger_seq > 1 && state.ctx.ledger_header.hash != [0u8; 32];
                    if !state.sync_done
                        && state.peer_count() >= 1
                        && self.storage.is_some()
                        && have_validated_target
                    {
                        static LAST_KICKSTART: std::sync::atomic::AtomicU64 =
                            std::sync::atomic::AtomicU64::new(0);
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let prev = LAST_KICKSTART.load(std::sync::atomic::Ordering::Relaxed);
                        if now_secs >= prev + 15 {
                            LAST_KICKSTART.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                            let cookie = crate::sync::next_cookie();
                            let latest_hash = state
                                .validated_hashes
                                .get(&state.ctx.ledger_seq)
                                .copied()
                                .unwrap_or(state.ctx.ledger_header.hash);
                            let (target_seq, target_hash, reason) =
                                crate::sync_bootstrap::choose_sync_kickstart_target(
                                    inactive_target,
                                    state.ctx.ledger_seq,
                                    latest_hash,
                                );
                            let max_peers = if inactive_target.is_some() {
                                usize::MAX
                            } else {
                                3
                            };
                            let get_msg = crate::network::relay::encode_get_ledger_base(
                                &target_hash,
                                cookie,
                            );
                            let mut sent = 0;
                            for (pid, ps) in &state.peers {
                                if !ps.is_open() {
                                    continue;
                                }
                                if let Some(tx) = state.peer_txs.get(pid) {
                                    let _ = tx.try_send(get_msg.clone());
                                    sent += 1;
                                    if sent >= max_peers {
                                        break;
                                    }
                                }
                            }
                            if sent > 0 {
                                info!(
                                    "sync timer: {reason}, sent liBASE kickstart for ledger {} ({}) to {sent} peers",
                                    target_seq,
                                    hex::encode_upper(&target_hash[..8]),
                                );
                            }
                        }
                    }
                }
            }

            {
                if let Ok(mut guard) = self.sync_runtime.try_lock_sync() {
                    if let Some(ref mut syncer) = *guard {
                        syncer.peer.clear_recent();
                    }
                }
            }

            let sync_active = self.sync_runtime.sync_active();
            if !sync_active {
                continue;
            }

            let storage_clone = self.storage.clone();
            let sync_runtime = self.sync_runtime.clone();
            let trigger_result = tokio::task::spawn_blocking(move || {
                sync_runtime.trigger_timeout_blocking(&storage_clone)
            })
            .await;
            let (reqs, sync_seq, abandon) = match trigger_result {
                Ok(r) => r,
                Err(e) => {
                    error!("sync timer spawn_blocking panicked: {}", e);
                    continue;
                }
            };

            if abandon {
                let mut state = self.state.write().await;
                state.sync_in_progress = false;
                let best_peer = state
                    .peer_ledger_range
                    .iter()
                    .max_by_key(|(_, (_, last))| *last)
                    .map(|(pid, (_, last))| (*pid, *last));
                if let Some((pid, latest_seq)) = best_peer {
                    let cookie = crate::sync::next_cookie();
                    let req =
                        crate::network::relay::encode_get_ledger_base_by_seq(latest_seq, cookie);
                    if let Some(tx) = state.peer_txs.get(&pid) {
                        let _ = tx.try_send(req);
                        info!(
                            "sync timer: sent liBASE re-acquire for ledger {} to peer {:?}",
                            latest_seq, pid
                        );
                    }
                }
                continue;
            }

            if !reqs.is_empty() {
                let is_stalled = {
                    self.sync_runtime
                        .try_lock_sync()
                        .ok()
                        .and_then(|g| g.as_ref().map(|s| s.peer.stalled_retries > 0))
                        .unwrap_or(false)
                };
                if is_stalled {
                    {
                        let mut state = self.state.write().await;
                        state.services.load_manager.note_sync_stall(
                            format!("sync_timeout_ledger_{sync_seq}"),
                            std::time::Instant::now(),
                        );
                    }
                    for (i, req) in reqs.iter().enumerate() {
                        if req.msg_type == MessageType::GetObjects {
                            self.sync_send_request(req, sync_seq, None).await;
                            continue;
                        }
                        let state = self.state.read().await;
                        let timeout_peers = self.select_timeout_sync_peers(
                            &state,
                            sync_seq,
                            crate::ledger::inbound::TIMEOUT_FOLLOWUP_PEERS,
                        );
                        drop(state);
                        if timeout_peers.is_empty() {
                            self.sync_send_request(req, sync_seq, None).await;
                        } else {
                            let pid = timeout_peers[i % timeout_peers.len()];
                            self.sync_send_request(req, sync_seq, Some(pid)).await;
                        }
                    }
                } else {
                    let state = self.state.read().await;
                    let peer_ids = self.select_sync_peers(&state, sync_seq, reqs.len().max(1));
                    drop(state);
                    for (i, req) in reqs.iter().enumerate() {
                        if peer_ids.is_empty() {
                            self.sync_send_request(req, sync_seq, None).await;
                        } else {
                            let pid = peer_ids[i % peer_ids.len()];
                            self.sync_send_request(req, sync_seq, Some(pid)).await;
                        }
                    }
                }
            }
        }
    }
}
