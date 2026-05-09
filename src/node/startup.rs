use super::*;

impl Node {
    async fn run_consensus_close_loop_supervisor(self: Arc<Self>) {
        let mut last_reason: Option<&'static str> = None;
        loop {
            if self.is_shutting_down() {
                info!("consensus close loop supervisor: shutdown");
                return;
            }

            if let Some(reason) = self.consensus_close_loop_pause_reason().await {
                if last_reason != Some(reason) {
                    info!("consensus close loop waiting: {reason}");
                    last_reason = Some(reason);
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            if last_reason.take().is_some() {
                info!("consensus close loop ready");
            } else {
                info!("consensus close loop enabled");
            }

            self.clone().run_ledger_close_loop().await;

            if self.is_shutting_down() {
                info!("consensus close loop supervisor: shutdown");
                return;
            }

            info!("consensus close loop paused; waiting for healthy restart conditions");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }

    /// Start the node: peer listener, RPC server, and bootstrap dialing.
    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        info!(
            "xLedgRSv2Beta node starting — peer={} rpc={} tls={} standalone={}",
            self.config.peer_addr,
            self.config.rpc_addr,
            self.config.use_tls,
            self.config.standalone
        );

        if !self.config.full_history_peers.is_empty() {
            let mut ss = self.state.write().await;
            ss.full_history_peers = self.config.full_history_peers.clone();
            info!(
                "registered {} full-history peers for diff sync",
                ss.full_history_peers.len()
            );
        }

        if !self.config.standalone {
            let node1 = self.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = node1.run_peer_listener().await {
                    error!("peer listener error: {e}");
                }
            });
            self.track_background_task("peer_listener", handle);
        }

        let node2 = self.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = node2.run_rpc_server().await {
                error!("RPC server error: {e}");
            }
        });
        self.track_background_task("rpc_server", handle);

        if !self.config.standalone {
            let mut state = self.state.write().await;
            for addr in &self.config.bootstrap {
                state.add_static_peer(*addr);
            }
            for addr in &self.config.full_history_peers {
                state.add_static_peer(*addr);
            }
        }

        if !self.config.standalone {
            let mut initial_count = 0;
            for addr in &self.config.bootstrap.clone() {
                let is_local = addr.ip().is_loopback();
                if !is_local && initial_count >= 2 {
                    continue;
                }
                if !is_local {
                    initial_count += 1;
                }
                let node3 = self.clone();
                let addr = *addr;
                let handle = tokio::spawn(async move {
                    if let Err(e) = node3.dial(addr).await {
                        warn!("failed to dial bootstrap peer {addr}: {e}");
                    }
                });
                self.track_background_task("bootstrap_dial", handle);
            }
            info!(
                "initial dial: localhost + {} bootstrap peers (rest via discovery ramp)",
                initial_count
            );
        }

        if !self.config.standalone && !self.config.full_history_peers.is_empty() {
            let count = self.config.full_history_peers.len();
            for addr in &self.config.full_history_peers {
                let node_dh = self.clone();
                let addr = *addr;
                let handle = tokio::spawn(async move {
                    if let Err(e) = node_dh.dial(addr).await {
                        warn!("failed to dial deep-history peer {addr}: {e}");
                    }
                });
                self.track_background_task("deep_history_dial", handle);
            }
            info!("dialing {} deep-history peers for sync", count);
        }

        if self.config.enable_consensus_close_loop {
            let node4 = self.clone();
            let handle = tokio::spawn(async move {
                node4.run_consensus_close_loop_supervisor().await;
            });
            self.track_background_task("consensus_close_loop", handle);
        } else {
            info!("consensus close loop disabled; running in follower mode");
        }

        if !self.config.standalone && !self.validator_list_config.sites.is_empty() {
            let sites = self.validator_list_config.sites.clone();
            let pub_keys = self.validator_list_config.publisher_keys.clone();
            let manager = self.validator_list_state.clone();
            let unl = self.unl.clone();
            let site_statuses = self
                .state
                .try_read()
                .ok()
                .and_then(|state| state.ctx.validator_site_statuses.clone());
            let shutdown = self.shutdown.clone();
            let handle = tokio::spawn(async move {
                let Some(site_statuses) = site_statuses else {
                    tracing::warn!("validator list site status tracking unavailable");
                    return;
                };
                crate::validator_list::run_validator_list_fetch(
                    sites,
                    pub_keys,
                    manager,
                    unl,
                    site_statuses,
                    shutdown,
                )
                .await;
            });
            self.track_background_task("validator_list_fetch", handle);
        }

        let ws_addr = self.config.ws_addr;
        let ws_tls = self.config.use_tls;
        let ws_state = self.state.clone();
        let ws_tx = self.ws_events.clone();
        let handle = tokio::spawn(async move {
            crate::rpc::ws::run_ws_server_with_sender(ws_addr, ws_tls, ws_state, ws_tx).await;
        });
        self.track_background_task("ws_server", handle);

        if !self.config.standalone {
            let node5 = self.clone();
            let handle = tokio::spawn(async move {
                node5.run_discovery_loop().await;
            });
            self.track_background_task("discovery_loop", handle);
        } else {
            info!("standalone mode enabled; peer listener, dialing, discovery, and validator list fetch are disabled");
        }

        {
            let sync_done = {
                let state = self.state.read().await;
                state.sync_done
            };
            if !sync_done {
                if let Some(ref ep) = self.config.rpc_sync {
                    let (host, port) = parse_host_port(ep);
                    if port > 0 {
                        info!("RPC bootstrap: downloading state from {}:{}", host, port);
                        let store = self
                            .storage
                            .as_ref()
                            .expect("storage required for RPC bootstrap");
                        let rpc_state = Arc::new(crate::rpc_sync::RpcSyncState::new());
                        crate::rpc_sync::run_rpc_sync(host, port, store.clone(), rpc_state.clone())
                            .await;

                        if rpc_state.complete.load(std::sync::atomic::Ordering::SeqCst) {
                            info!("RPC bootstrap complete — loading SparseSHAMap");
                            {
                                let state = self.state.read().await;
                                let mut ls = state
                                    .ctx
                                    .ledger_state
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                ls.enable_sparse();
                                let warm_t0 = std::time::Instant::now();
                                let h = ls.state_hash();
                                info!(
                                    "SparseSHAMap hash warmup: {}ms root={}",
                                    warm_t0.elapsed().as_millis(),
                                    hex::encode_upper(&h[..8]),
                                );
                            }
                            let mut state = self.state.write().await;
                            state.sync_done = true;
                            info!(
                                "RPC bootstrap: sync_done=true — follower will report hash matches"
                            );
                        } else {
                            warn!("RPC bootstrap failed — falling through to peer sync");
                        }
                    }
                }
            } else {
                info!("sync already complete — skipping RPC bootstrap");
            }
        }

        {
            if !RESOURCE_MANAGER_LOOP_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let node_resource = self.clone();
                let handle = tokio::spawn(async move {
                    node_resource.run_resource_manager_loop().await;
                });
                self.track_background_task("resource_manager", handle);
            } else {
                warn!("resource manager loop already started; skipping duplicate spawn");
            }

            if !LOAD_MANAGER_LOOP_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let node_load = self.clone();
                let handle = tokio::spawn(async move {
                    node_load.run_load_manager_loop().await;
                });
                self.track_background_task("load_manager", handle);
            } else {
                warn!("load manager loop already started; skipping duplicate spawn");
            }

            if !SYNC_STALL_CHECKER_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let node6 = self.clone();
                let handle = tokio::spawn(async move {
                    node6.run_sync_timer().await;
                });
                self.track_background_task("sync_timer", handle);
            } else {
                warn!("sync timer already started; skipping duplicate spawn");
            }

            if !SYNC_BATCH_PROCESSOR_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let node_batch = self.clone();
                let handle = tokio::spawn(async move {
                    node_batch.run_sync_data_processor().await;
                });
                self.track_background_task("sync_data_processor", handle);
            } else {
                warn!("sync data processor already started; skipping duplicate spawn");
            }
        }

        let sync_done = { self.state.read().await.sync_done };
        if sync_done {
            self.start_follower().await;
        }

        Ok(())
    }
}
