use super::*;

impl Node {
    pub(super) async fn handle_sync_header_trigger(
        self: Arc<Self>,
        peer_id: PeerId,
        header: crate::ledger::LedgerHeader,
        ld: crate::proto::TmLedgerData,
        is_current: bool,
        inactive_sync_target: Option<(u32, [u8; 32])>,
    ) {
        if !crate::sync_bootstrap::should_start_sync_from_header(
            is_current,
            header.sequence,
            header.hash,
            inactive_sync_target,
        ) {
            return;
        }

        let already_syncing = self.sync_runtime.sync_active();
        let (sync_done, open_peers, sync_in_progress, pending_sync_anchor) = {
            let state = self.state.read().await;
            (
                state.sync_done,
                state.peer_count(),
                state.sync_in_progress,
                state.pending_sync_anchor,
            )
        };
        if sync_done || self.storage.is_none() || open_peers < 1 {
            return;
        }
        if let Some((anchor_seq, anchor_hash)) = pending_sync_anchor {
            info!(
                "ignoring liBASE for ledger {} while sync anchor {} ({}) is pending",
                header.sequence,
                anchor_seq,
                hex::encode_upper(&anchor_hash[..8]),
            );
            return;
        }

        let leaf_count = self
            .storage
            .as_ref()
            .and_then(|store| store.get_leaf_count())
            .map(|lc| lc as usize);
        let plan = self.sync_runtime.plan_header_trigger(
            header.clone(),
            &ld,
            self.nudb_backend.clone(),
            leaf_count,
            open_peers,
            already_syncing,
            sync_in_progress,
        );

        if let Some((target_seq, target_hash)) = plan.ignore_mismatched_fixed_target {
            info!(
                "ignoring liBASE for ledger {} while waiting to restart fixed target {} ({})",
                header.sequence,
                target_seq,
                hex::encode_upper(&target_hash[..8]),
            );
            return;
        }

        if !already_syncing
            && !sync_in_progress
            && !plan.restart_fixed_target
            && !plan.installed_syncer
        {
            info!(
                "starting state sync for ledger {} account_hash={} ({} peers ready)",
                header.sequence,
                &hex::encode_upper(header.account_hash)[..16],
                open_peers,
            );
        }

        if plan.restart_fixed_target || plan.installed_syncer {
            let mut state = self.state.write().await;
            state.sync_in_progress = true;
            if plan.sync_completed_from_disk {
                state.sync_done = true;
                state.sync_in_progress = false;
            }
        }

        if plan.sync_lock_busy && !already_syncing && !sync_in_progress {
            warn!("sync lock busy during syncer install — will retry on next liBASE");
        }

        if let Some(bootstrap) = plan.bootstrap {
            info!(
                "state sync bootstrap: {} inner + {} leaf",
                bootstrap.progress.total_inner, bootstrap.progress.total_leaf,
            );

            if !bootstrap.reqs.is_empty() {
                let state = self.state.read().await;
                let mut target_peers = Vec::with_capacity(bootstrap.seed_count);
                target_peers.push(peer_id);
                for pid in self.select_sync_peers(&state, header.sequence, bootstrap.seed_count) {
                    if pid != peer_id && !target_peers.contains(&pid) {
                        target_peers.push(pid);
                    }
                }
                if bootstrap.restarted {
                    info!("fixed-target restart: distributing initial liAS requests across seed peers");
                }
                if target_peers.is_empty() {
                    state.broadcast(&bootstrap.reqs[0], None);
                } else {
                    for (idx, req) in bootstrap.reqs.iter().enumerate() {
                        let pid = target_peers[idx % target_peers.len()];
                        if let Some(tx) = state.peer_txs.get(&pid) {
                            let _ = tx.try_send(req.clone());
                        }
                    }
                    if bootstrap.reqs.len() > 1 || target_peers.len() > 1 {
                        info!(
                            "seeded {} initial liAS request(s) across {} peer(s)",
                            bootstrap.reqs.len(),
                            target_peers.len(),
                        );
                    }
                }
            }

            let _ = self.ws_events.send(crate::rpc::ws::WsEvent::PeerMessage {
                msg_type: "sync".into(),
                detail: format!("state sync started for ledger {}", header.sequence),
            });
        }
    }

    pub(super) async fn seed_fresh_sync_requests_from_base(
        &self,
        peer_id: PeerId,
        header: &crate::ledger::LedgerHeader,
        ld: &crate::proto::TmLedgerData,
    ) {
        let fresh_reqs = if let Ok(mut guard) = self.sync_runtime.try_lock_sync() {
            if let Some(ref mut syncer) = *guard {
                if syncer.active()
                    && syncer.pending_count() == 0
                    && syncer.peer.last_response.elapsed().as_secs() > 2
                {
                    syncer.peer.start_new_pass();
                    if ld.nodes.len() > 1 {
                        let root_data = &ld.nodes[1].nodedata;
                        let hash_start = if root_data.len() == 513 {
                            1
                        } else if root_data.len() == 512 {
                            0
                        } else {
                            4
                        };
                        if root_data.len() >= hash_start + 512 {
                            let mut children = Vec::new();
                            for i in 0..16u8 {
                                let off = hash_start + (i as usize) * 32;
                                let child = &root_data[off..off + 32];
                                if child.iter().any(|&b| b != 0) {
                                    let mut id = vec![0u8; 32];
                                    id[0] = i << 4;
                                    id.push(1);
                                    children.push(id);
                                }
                            }
                            let count = children.len();
                            let _ = children;
                            info!(
                                "starting pass {} with {} children from ledger {}",
                                syncer.pass_number(),
                                count,
                                header.sequence,
                            );
                        }
                    }
                    syncer.build_multi_requests(3, crate::sync::SyncRequestReason::Reply)
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        if !fresh_reqs.is_empty() {
            let (target_peers, peer_txs) = {
                let state = self.state.read().await;
                let secondary_peers = self.select_sync_peers(&state, header.sequence, 3);
                let mut target_peers = vec![peer_id];
                target_peers.extend(secondary_peers.into_iter().filter(|pid| *pid != peer_id));
                let peer_txs = target_peers
                    .iter()
                    .filter_map(|pid| state.peer_txs.get(pid).cloned())
                    .collect::<Vec<_>>();
                (target_peers, peer_txs)
            };
            if peer_txs.is_empty() {
                let state = self.state.read().await;
                state.broadcast(&fresh_reqs[0], None);
            } else {
                for (idx, req) in fresh_reqs.iter().enumerate() {
                    let tx = &peer_txs[idx % peer_txs.len()];
                    let _ = tx.try_send(req.clone());
                }
                if fresh_reqs.len() > 1 || target_peers.len() > 1 {
                    info!(
                        "fresh liBASE seeded {} liAS request(s) across {} peer(s)",
                        fresh_reqs.len(),
                        peer_txs.len(),
                    );
                }
            }
        }
    }

    pub(super) async fn handle_base_ledger_data(
        self: &Arc<Self>,
        peer: &Peer,
        ld: &crate::proto::TmLedgerData,
    ) {
        if let Some(node) = ld.nodes.first() {
            if let Some(header) = crate::sync::parse_ledger_header_from_base(&node.nodedata) {
                info!(
                    "received ledger header from peer {:?}: seq={} hash={}",
                    peer.id,
                    header.sequence,
                    &hex::encode_upper(header.hash)[..16],
                );
                {
                    let mut guard = self
                        .inbound_ledgers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    guard.got_header(&header.hash, header.clone());
                }
                let inactive_sync_target = match self.sync_runtime.try_lock_sync() {
                    Ok(guard) => guard
                        .as_ref()
                        .and_then(|s| (!s.active()).then_some((s.ledger_seq(), *s.ledger_hash()))),
                    Err(_) => None,
                };
                let is_current = {
                    let mut state = self.state.write().await;
                    if header.sequence >= state.ctx.ledger_seq {
                        state.ctx.ledger_header = header.clone();
                        state.ctx.ledger_seq = header.sequence;
                        state.ctx.ledger_hash = hex::encode_upper(header.hash);
                        state
                            .ctx
                            .history
                            .write()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert_ledger(header.clone(), vec![]);
                        true
                    } else {
                        false
                    }
                };

                if is_current {
                    if let Some(ref store) = self.storage {
                        let store2 = store.clone();
                        let header2 = header.clone();
                        let online_delete = self.config.online_delete;
                        let can_delete_target = self.can_delete_target.clone();
                        tokio::task::spawn_blocking(move || {
                            let _ = store2.save_ledger(&header2, &[]);
                            let _ = store2.save_meta(
                                header2.sequence,
                                &hex::encode_upper(header2.hash),
                                &header2,
                            );
                            let _ = store2.flush();
                            if header2.sequence % 256 == 0 {
                                if let Some(keep) = online_delete.filter(|k| *k > 0) {
                                    if header2.sequence % keep == 0 {
                                        let target = can_delete_target
                                            .load(std::sync::atomic::Ordering::Relaxed);
                                        let max_delete = match target {
                                            0 => None,
                                            u32::MAX => None,
                                            value => Some(value),
                                        };
                                        if target != 0 {
                                            match store2.prune_history_to(
                                                header2.sequence,
                                                keep,
                                                max_delete,
                                            ) {
                                                Ok(n) if n > 0 => tracing::info!(
                                                    "pruned {n} old ledger headers (keeping last {keep})"
                                                ),
                                                _ => {}
                                            }
                                        }
                                        let _before_seq = header2.sequence.saturating_sub(keep);
                                    }
                                }
                            }
                        });
                    }
                }

                if crate::sync_bootstrap::should_start_sync_from_header(
                    is_current,
                    header.sequence,
                    header.hash,
                    inactive_sync_target,
                ) {
                    let node = Arc::clone(self);
                    let header_for_sync = header.clone();
                    let ld_for_sync = ld.clone();
                    let peer_id = peer.id;
                    tokio::spawn(async move {
                        node.handle_sync_header_trigger(
                            peer_id,
                            header_for_sync,
                            ld_for_sync,
                            is_current,
                            inactive_sync_target,
                        )
                        .await;
                    });
                }

                let base_snapshot_ready = {
                    let state = self.state.read().await;
                    state.sync_done || self.storage.is_none()
                };
                if base_snapshot_ready {
                    let cookie = crate::sync::next_cookie();
                    let tx_req = crate::network::relay::encode_get_ledger_txs(cookie);
                    let state = self.state.read().await;
                    if let Some(tx) = state.peer_txs.get(&peer.id) {
                        let _ = tx.try_send(tx_req);
                    }
                    drop(state);
                    self.seed_fresh_sync_requests_from_base(peer.id, &header, ld)
                        .await;
                }
            } else {
                warn!(
                    "failed to parse ledger header from peer {:?} ({} bytes)",
                    peer.id,
                    node.nodedata.len(),
                );
            }
        }
    }

    pub(super) async fn handle_state_node_message(
        self: &Arc<Self>,
        peer: &Peer,
        ld: &crate::proto::TmLedgerData,
    ) {
        let sync_done = {
            let state = self.state.read().await;
            state.sync_done
        };
        if sync_done {
            if self
                .sync_runtime
                .diff_sync_sender()
                .send(ld.clone())
                .await
                .is_err()
            {
                warn!("diff sync response channel closed");
            }
        } else {
            let accepted_by_gate =
                self.sync_runtime
                    .gate_accepts_response(Some(&ld.ledger_hash), None, false);
            if accepted_by_gate {
                self.sync_runtime.queue_sync_data(peer.id, ld.clone());
            } else {
                let mut stashed = 0usize;
                let fetch_pack = {
                    let state = self.state.read().await;
                    state.services.fetch_pack.clone()
                };
                if let Some(fetch_pack) = fetch_pack {
                    for node in &ld.nodes {
                        match fetch_pack
                            .stash_wire_node(&node.nodedata, crate::ledger::MapType::AccountState)
                        {
                            Ok(true) => stashed += 1,
                            Ok(false) => {}
                            Err(e) => {
                                debug!("failed to stash stale liAS_NODE for reuse: {}", e)
                            }
                        }
                    }
                }
                debug!(
                    "dropping liAS_NODE at gate: accepted={} cookie={:?} hash={} stashed={}",
                    accepted_by_gate,
                    ld.request_cookie,
                    hex::encode_upper(&ld.ledger_hash[..std::cmp::min(8, ld.ledger_hash.len())]),
                    stashed,
                );
            }
        }
        {
            let state = self.state.read().await;
            if let Some(ref fs) = state.follower_state {
                let _ = fs.prefetch_tx.try_send(ld.clone());
            }
        }
    }
}
