//! xLedgRS purpose: Peer Control piece of the live node runtime.
use super::*;

impl Node {
    pub(super) async fn handle_ping_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Some((is_ping, seq)) = crate::network::relay::decode_ping(&msg.payload) {
            if is_ping {
                let pong = crate::network::relay::encode_pong(seq);
                if let Some(tx) = self.state.read().await.peer_txs.get(&peer.id) {
                    let _ = tx.try_send(pong);
                }
            } else {
                let mut state = self.state.write().await;
                if let Some((sent_seq, sent_at)) = state.peer_ping_sent.remove(&peer.id) {
                    if sent_seq == seq {
                        let latency = sent_at.elapsed().as_millis() as u32;
                        state.peer_latency.insert(peer.id, latency);
                        if latency > 10000 {
                            let expires =
                                std::time::Instant::now() + std::time::Duration::from_secs(1200);
                            state.sync_peer_cooldown.insert(peer.id, expires);
                            let _ = state.services.resource_manager.charge_consumer(
                                &peer.resource_consumer,
                                6_000,
                                "excessive_latency",
                                std::time::Instant::now(),
                            );
                            self.debug_log(&format!(
                                "LATENCY+BENCHED-SLOW: peer {:?} = {}ms (>10s, 20min)",
                                peer.id, latency
                            ));
                        } else if latency > 5000 {
                            let expires =
                                std::time::Instant::now() + std::time::Duration::from_secs(300);
                            state.sync_peer_cooldown.insert(peer.id, expires);
                            let _ = state.services.resource_manager.charge_consumer(
                                &peer.resource_consumer,
                                4_000,
                                "high_latency",
                                std::time::Instant::now(),
                            );
                            self.debug_log(&format!(
                                "LATENCY+BENCHED-MODERATE: peer {:?} = {}ms (>5s, 5min)",
                                peer.id, latency
                            ));
                        } else {
                            self.debug_log(&format!("LATENCY: peer {:?} = {}ms", peer.id, latency));
                        }
                    }
                }
            }
        }
        PeerEvent::MessageReceived(MessageType::Ping, msg.payload.clone())
    }

    pub(super) async fn handle_cluster_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        let cluster_peer = if let Some(info) = peer.info.as_ref() {
            let state = self.state.read().await;
            peer_is_reserved(state.ctx.peer_reservations.as_ref(), &info.node_pubkey)
                || peer.addr.ip().is_loopback()
        } else {
            false
        };
        if cluster_peer {
            if let Ok(cluster_msg) =
                <crate::proto::TmCluster as ProstMessage>::decode(msg.payload.as_slice())
            {
                let mut state = self.state.write().await;
                for entry in cluster_msg.cluster_nodes {
                    if entry.public_key.is_empty() {
                        continue;
                    }
                    state.services.cluster.note_gossip(
                        entry.public_key,
                        entry.report_time as u64,
                        entry.node_load,
                        entry.node_name,
                        entry.address,
                    );
                }
                state.refresh_runtime_health(std::time::Instant::now());
            }
        }
        PeerEvent::MessageReceived(MessageType::Cluster, msg.payload.clone())
    }

    pub(super) async fn handle_status_change_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Ok(sc) =
            <crate::proto::TmStatusChange as ProstMessage>::decode(msg.payload.as_slice())
        {
            let ledger_range = match (sc.first_seq, sc.last_seq) {
                (Some(first), Some(last)) if first > 0 && last >= first => Some((first, last)),
                _ => None,
            };
            let status_label = sc
                .new_status
                .and_then(node_status_label)
                .map(str::to_string);
            let action_label = sc.new_event.and_then(node_event_label).map(str::to_string);
            if let (Some(first), Some(last)) = (sc.first_seq, sc.last_seq) {
                if first > 0 && last >= first {
                    let mut state = self.state.write().await;
                    let old = state.peer_ledger_range.insert(peer.id, (first, last));
                    if old.is_none() {
                        let span = last - first;
                        info!(
                            "peer {:?} ledger range: {}-{} (span={})",
                            peer.id, first, last, span,
                        );
                    }
                }
            }
            let cluster_peer = if let Some(info) = peer.info.as_ref() {
                let state = self.state.read().await;
                peer_is_reserved(state.ctx.peer_reservations.as_ref(), &info.node_pubkey)
                    || peer.addr.ip().is_loopback()
            } else {
                false
            };
            if cluster_peer {
                let public_key = peer.info.as_ref().map(|info| {
                    crate::crypto::base58::encode(
                        crate::crypto::base58::PREFIX_NODE_PUBLIC,
                        &info.node_pubkey,
                    )
                });
                let mut state = self.state.write().await;
                state.services.cluster.note_status(
                    peer.addr,
                    public_key,
                    status_label.clone(),
                    action_label.clone(),
                    sc.ledger_seq,
                    ledger_range,
                );
            }
            let mut payload = serde_json::json!({
                "type": "peerStatusChange",
                "address": peer.addr.to_string(),
                "inbound": matches!(peer.direction, Direction::Inbound),
            });
            if let Some(status) = status_label.as_ref() {
                payload["status"] = serde_json::json!(status);
            }
            if let Some(action) = action_label.as_ref() {
                payload["action"] = serde_json::json!(action);
            }
            if let Some(ledger_seq) = sc.ledger_seq {
                payload["ledger_index"] = serde_json::json!(ledger_seq);
            }
            if let Some(ledger_hash) = sc.ledger_hash.as_ref() {
                payload["ledger_hash"] = serde_json::json!(hex::encode_upper(ledger_hash));
            }
            if let Some(network_time) = sc.network_time {
                payload["date"] = serde_json::json!(network_time);
            }
            if let Some(first_seq) = sc.first_seq {
                payload["ledger_index_min"] = serde_json::json!(first_seq);
            }
            if let Some(last_seq) = sc.last_seq {
                payload["ledger_index_max"] = serde_json::json!(last_seq);
            }
            if let Some(info) = peer.info.as_ref() {
                payload["public_key"] = serde_json::json!(crate::crypto::base58::encode(
                    crate::crypto::base58::PREFIX_NODE_PUBLIC,
                    &info.node_pubkey,
                ));
            }
            let _ = self
                .ws_events
                .send(crate::rpc::ws::WsEvent::PeerStatusChange { payload });
        }
        PeerEvent::MessageReceived(MessageType::StatusChange, msg.payload.clone())
    }

    pub(super) async fn handle_endpoints_message(
        &self,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        let addrs = crate::network::relay::decode_endpoints(&msg.payload);
        {
            let mut state = self.state.write().await;
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if let Some(slot) = peer.peerfinder_slot.as_ref() {
                state
                    .services
                    .peerfinder
                    .on_endpoints(slot, &addrs, now_unix);
            } else {
                state
                    .services
                    .peerfinder
                    .note_endpoints(peer.addr, &addrs, now_unix);
            }
            for a in addrs {
                state.add_known_peer_with_source(a, "peer_endpoints");
            }
        }
        PeerEvent::MessageReceived(MessageType::Endpoints, msg.payload.clone())
    }
}
