use super::*;

impl Node {
    pub(super) async fn run_load_manager_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if self.is_shutting_down() {
                info!("load manager loop: shutdown");
                return;
            }

            let event = {
                let mut state = self.state.write().await;
                let before = state.services.load_manager.snapshot();
                let now = std::time::Instant::now();
                state.services.load_manager.heartbeat(now);
                state.refresh_runtime_health(now);
                let _ = state.services.load_manager.run_cycle(now);
                let after = state.services.load_manager.snapshot();
                let fee_changed = before.local_fee != after.local_fee
                    || before.queue_fee != after.queue_fee
                    || before.remote_fee != after.remote_fee
                    || before.cluster_fee != after.cluster_fee;
                if !fee_changed {
                    None
                } else {
                    let validated_ledgers = state
                        .ctx
                        .history
                        .read()
                        .unwrap_or_else(|e| e.into_inner())
                        .complete_ledgers();
                    let peer_count = state.peer_count();
                    let server_status = if state.sync_done {
                        "full"
                    } else if peer_count > 0 {
                        "syncing"
                    } else {
                        "disconnected"
                    };
                    Some(crate::rpc::ws::WsEvent::ServerStatus {
                        ledger_seq: state.ctx.ledger_seq,
                        ledger_hash: hex::encode_upper(state.ctx.ledger_header.hash),
                        network_id: self.config.network_id,
                        peer_count,
                        validated_ledgers,
                        server_status: server_status.to_string(),
                        load_snapshot: after,
                        base_fee: state.ctx.fees.base,
                    })
                }
            };

            if let Some(event) = event {
                self.update_rpc_snapshot().await;
                let _ = self.ws_events.send(event);
            }
        }
    }
}
