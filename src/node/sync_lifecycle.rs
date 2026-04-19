use super::*;

impl Node {
    pub(super) async fn start_follower(&self) {
        if let Some(ref storage) = self.storage {
            let storage = storage.clone();
            let state_ref = self.state.clone();
            let follower = Arc::new(crate::ledger::follow::FollowerState::new());
            let follower2 = follower.clone();
            let diff_rx = self.sync_runtime.diff_sync_receiver();
            let (rpc_host, rpc_port) = if let Some(ref ep) = self.config.rpc_sync {
                parse_host_port(ep)
            } else {
                ("127.0.0.1".to_string(), 0u16)
            };
            let il = self.inbound_ledgers.clone();
            tokio::spawn(async move {
                crate::ledger::follow::run_follower(
                    rpc_host, rpc_port, storage, follower2, state_ref, diff_rx, il,
                )
                .await;
            });
            {
                let mut ss = self.state.write().await;
                ss.follower_state = Some(follower);
            }
            info!("follower started");
        }
    }

    pub(super) async fn acquire_sync_anchor_transactions(
        &self,
        sync_header: &crate::ledger::LedgerHeader,
    ) -> bool {
        const ANCHOR_REQUEST_PEERS: usize = 8;
        const ANCHOR_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
        const ANCHOR_ACQUIRE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

        {
            let mut state = self.state.write().await;
            state.pending_sync_anchor = Some((sync_header.sequence, sync_header.hash));
        }

        let result = async {
            let mut watch_rx = {
                let mut guard = self
                    .inbound_ledgers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let rx = guard.acquire(
                    sync_header.hash,
                    sync_header.sequence,
                    crate::ledger::inbound::InboundReason::History,
                );
                let _ = guard.got_header(&sync_header.hash, sync_header.clone());
                rx
            };

            let deadline = tokio::time::Instant::now() + ANCHOR_ACQUIRE_DEADLINE;
            let mut attempt = 0u32;
            loop {
                let (sent_base, sent_tx, missing_tx_nodes) = {
                    let missing_tx_nodes = {
                        let guard = self
                            .inbound_ledgers
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        guard.missing_tx_node_ids(&sync_header.hash, 64)
                    };
                    let cookie_base = crate::sync::next_cookie();
                    let base_req = crate::network::relay::encode_get_ledger_base(
                        &sync_header.hash,
                        cookie_base,
                    );
                    let use_root_tx_request = missing_tx_nodes.is_empty()
                        || missing_tx_nodes
                            == vec![crate::ledger::shamap_id::SHAMapNodeID::root()
                                .to_wire()
                                .to_vec()];
                    let tx_req = if use_root_tx_request {
                        crate::network::relay::encode_get_ledger_txs_for_hash(
                            &sync_header.hash,
                            crate::sync::next_cookie(),
                        )
                    } else {
                        crate::network::relay::encode_get_ledger_txs_for_hash_nodes(
                            &sync_header.hash,
                            &missing_tx_nodes,
                            crate::sync::next_cookie(),
                        )
                    };
                    let mut state = self.state.write().await;
                    let sent_base = state.send_to_peers_with_ledger(
                        &base_req,
                        sync_header.sequence,
                        ANCHOR_REQUEST_PEERS,
                    );
                    let sent_tx = if sync_header.transaction_hash == [0u8; 32] {
                        0
                    } else {
                            state.send_to_peers_with_ledger(
                                &tx_req,
                                sync_header.sequence,
                                ANCHOR_REQUEST_PEERS,
                            )
                    };
                    (sent_base, sent_tx, missing_tx_nodes.len())
                };
                if attempt == 0 {
                    info!(
                        "sync anchor acquisition: requesting seq={} hash={} base_peers={} tx_peers={} missing_tx_nodes={}",
                        sync_header.sequence,
                        hex::encode_upper(&sync_header.hash[..8]),
                        sent_base,
                        sent_tx,
                        missing_tx_nodes,
                    );
                } else {
                    info!(
                        "sync anchor acquisition retry #{}: seq={} hash={} base_peers={} tx_peers={} missing_tx_nodes={}",
                        attempt,
                        sync_header.sequence,
                        hex::encode_upper(&sync_header.hash[..8]),
                        sent_base,
                        sent_tx,
                        missing_tx_nodes,
                    );
                }

                if *watch_rx.borrow() {
                    break;
                }
                let next_wait = (tokio::time::Instant::now() + ANCHOR_RETRY_INTERVAL).min(deadline);
                attempt = attempt.saturating_add(1);
                match tokio::time::timeout_at(next_wait, watch_rx.changed()).await {
                    Ok(Ok(())) => {
                        if *watch_rx.borrow() {
                            break;
                        }
                    }
                    Err(_) if tokio::time::Instant::now() < deadline => continue,
                    _ => break,
                }
            }

            let result = {
                let mut guard = self
                    .inbound_ledgers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let result = guard.take(&sync_header.hash);
                guard.sweep(std::time::Duration::from_secs(60));
                result
            };

            let Some((header, tx_blobs, acquired_tx_root)) = result else {
                warn!(
                    "sync anchor acquisition incomplete for seq={} hash={}",
                    sync_header.sequence,
                    hex::encode_upper(&sync_header.hash[..8]),
                );
                return false;
            };

            if header.hash != sync_header.hash || header.sequence != sync_header.sequence {
                warn!(
                    "sync anchor acquisition returned wrong header: expected seq={} hash={} got seq={} hash={}",
                    sync_header.sequence,
                    hex::encode_upper(&sync_header.hash[..8]),
                    header.sequence,
                    hex::encode_upper(&header.hash[..8]),
                );
                return false;
            }

            let tx_root = acquired_tx_root.unwrap_or_else(|| compute_acquired_tx_root(&tx_blobs));
            if tx_root != sync_header.transaction_hash {
                warn!(
                    "sync anchor tx hash mismatch: seq={} expected={} got={} txs={}",
                    sync_header.sequence,
                    hex::encode_upper(&sync_header.transaction_hash[..8]),
                    hex::encode_upper(&tx_root[..8]),
                    tx_blobs.len(),
                );
                return false;
            }

            info!(
                "sync anchor acquisition verified: seq={} hash={} tx_root={} txs={}",
                sync_header.sequence,
                hex::encode_upper(&sync_header.hash[..8]),
                hex::encode_upper(&tx_root[..8]),
                tx_blobs.len(),
            );
            true
        }
        .await;

        let mut state = self.state.write().await;
        if state.pending_sync_anchor == Some((sync_header.sequence, sync_header.hash)) {
            state.pending_sync_anchor = None;
        }

        result
    }

    pub async fn trigger_resync(&self) {
        info!("trigger_resync: clearing sync state and re-entering sync mode");

        let inbound_ledgers = {
            let state = self.state.read().await;
            state.services.inbound_ledgers.clone()
        };

        {
            let state = self.state.read().await;
            if let Some(ref fs) = state.follower_state {
                fs.running.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }

        self.sync_runtime.clear_syncer();

        if let Some(inbound_ledgers) = inbound_ledgers {
            let cleared = inbound_ledgers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .stop();
            if cleared > 0 {
                info!(
                    "trigger_resync: stopped {} inbound ledger acquisition(s)",
                    cleared
                );
            }
        }

        if let Some(ref store) = self.storage {
            let _ = store.clear_sync_handoff();
        }

        if let Some(ref backend) = self.nudb_backend {
            backend.clear_in_memory();
        }

        {
            let mut state = self.state.write().await;
            state.sync_done = false;
            state.sync_in_progress = false;
            state.follower_state = None;
        }

        info!("trigger_resync: sync state cleared — will re-sync to current validated ledger");
    }

    pub(super) async fn run_post_sync_checkpoint(&self, sync_header: &crate::ledger::LedgerHeader) {
        let Some(script) = self.config.post_sync_checkpoint_script.clone() else {
            return;
        };
        let Some(data_dir) = self.config.data_dir.clone() else {
            warn!("post-sync checkpoint skipped: no data_dir configured");
            return;
        };

        let seq = sync_header.sequence.to_string();
        let ledger_hash = hex::encode_upper(sync_header.hash);
        let account_hash = hex::encode_upper(sync_header.account_hash);
        info!(
            "post-sync checkpoint: running {} for seq={} hash={}",
            script.display(),
            sync_header.sequence,
            hex::encode_upper(&sync_header.hash[..8]),
        );

        let script_for_cmd = script.clone();
        let data_dir_for_cmd = data_dir.clone();
        let run = tokio::task::spawn_blocking(move || {
            std::process::Command::new(&script_for_cmd)
                .env("XLEDGRS_SYNC_LEDGER_SEQ", &seq)
                .env("XLEDGRS_SYNC_LEDGER_HASH", &ledger_hash)
                .env("XLEDGRS_SYNC_ACCOUNT_HASH", &account_hash)
                .env("XLEDGRS_SYNC_DATA_DIR", &data_dir_for_cmd)
                .output()
        })
        .await;

        match run {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if output.status.success() {
                    if stdout.is_empty() {
                        info!("post-sync checkpoint complete");
                    } else {
                        info!("post-sync checkpoint complete: {}", stdout);
                    }
                } else {
                    error!(
                        "post-sync checkpoint failed: status={} stdout='{}' stderr='{}'",
                        output.status, stdout, stderr,
                    );
                }
            }
            Ok(Err(e)) => {
                error!(
                    "post-sync checkpoint failed to launch {}: {}",
                    script.display(),
                    e,
                );
            }
            Err(e) => {
                error!("post-sync checkpoint task join failed: {}", e);
            }
        }
    }
}
