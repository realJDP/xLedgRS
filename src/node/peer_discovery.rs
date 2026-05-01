//! xLedgRS purpose: Peer Discovery piece of the live node runtime.
use super::*;

impl Node {
    pub(super) async fn run_discovery_loop(self: Arc<Self>) {
        let start_time = std::time::Instant::now();
        loop {
            let delay = {
                let state = self.state.read().await;
                if state.peer_txs.is_empty() {
                    1
                } else {
                    5
                }
            };
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            {
                let state = self.state.read().await;
                if state
                    .ctx
                    .shutdown_requested
                    .as_ref()
                    .map(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
                    .unwrap_or(false)
                {
                    drop(state);
                    self.signal_shutdown();
                }
            }
            if self.is_shutting_down() {
                info!("discovery loop: shutdown");
                return;
            }
            let to_dial: Vec<SocketAddr> = {
                let mut state = self.state.write().await;
                let now = std::time::Instant::now();
                state.peer_cooldowns.retain(|_, expires| *expires > now);
                state
                    .services
                    .inbound_transactions
                    .prune(crate::ledger::inbound_transactions::unix_now());
                state
                    .services
                    .tx_master
                    .prune(crate::transaction::master::unix_now());
                state.refresh_runtime_health(now);

                let elapsed_secs = start_time.elapsed().as_secs();
                let max_out = self.config.max_outbound();
                let target_outbound = (3 + (elapsed_secs / 30) * 3).min(max_out as u64) as usize;

                if let Some(queue) = state.ctx.connect_requests.clone() {
                    let mut pending = queue.lock().unwrap_or_else(|e| e.into_inner());
                    for addr in pending.drain(..) {
                        state.add_known_peer_with_source(addr, "rpc_connect");
                    }
                }

                let mut addrs: Vec<SocketAddr> = Vec::new();
                for addr in state.known_peers.iter() {
                    if addr.ip().is_loopback() && !state.connected_addrs.contains(addr) {
                        addrs.push(*addr);
                    }
                }

                if state.outbound_count() < target_outbound {
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let candidates = state.services.peerfinder.autoconnect(now_unix);
                    for addr in candidates.into_iter().take(3) {
                        if state.allow_outbound_candidate(addr, now) && !addrs.contains(&addr) {
                            addrs.push(addr);
                        }
                    }
                }
                addrs
            };

            for addr in to_dial {
                let node = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = node.dial(addr).await {
                        debug!("discovery dial to {addr} failed: {e}");
                    }
                });
            }
        }
    }
}
