use super::*;

impl Node {
    pub(super) async fn finalize_peer_handshake<S>(
        &self,
        stream: &mut S,
        peer: &mut Peer,
        id: PeerId,
        addr: SocketAddr,
        dir: Direction,
        session_hash: [u8; 32],
        handshake_info: crate::network::handshake::HandshakeInfo,
    ) -> Option<bool>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    {
        if handshake_info.session_signature.is_empty() {
            warn!("peer {id:?} ({addr}) missing session signature — rejecting");
            let mut s = self.state.write().await;
            let _ = s.services.resource_manager.charge_consumer(
                &peer.resource_consumer,
                6_000,
                "missing_session_signature",
                std::time::Instant::now(),
            );
            s.peers.remove(&id);
            s.peer_txs.remove(&id);
            s.note_peer_connect_failure(addr, "missing_session_signature");
            return None;
        }
        if !crate::crypto::keys::verify_secp256k1_digest(
            &handshake_info.node_pubkey,
            &session_hash,
            &handshake_info.session_signature,
        ) {
            warn!("peer {id:?} ({addr}) session signature verification failed — rejecting");
            let mut s = self.state.write().await;
            let _ = s.services.resource_manager.charge_consumer(
                &peer.resource_consumer,
                6_000,
                "bad_session_signature",
                std::time::Instant::now(),
            );
            s.peers.remove(&id);
            s.peer_txs.remove(&id);
            s.note_peer_connect_failure(addr, "bad_session_signature");
            return None;
        }
        if handshake_info.node_pubkey == self.node_key.public_key_bytes() {
            warn!("peer {id:?} ({addr}) is ourselves — rejecting self-connection");
            let mut s = self.state.write().await;
            s.peers.remove(&id);
            s.peer_txs.remove(&id);
            s.note_peer_connect_failure(addr, "self_connection");
            return None;
        }

        if let Some(peer_net_id) = handshake_info.network_id {
            if peer_net_id != self.config.network_id {
                warn!(
                    "peer {id:?} ({addr}) network-id mismatch: ours={} theirs={} — rejecting",
                    self.config.network_id, peer_net_id
                );
                let mut s = self.state.write().await;
                let _ = s.services.resource_manager.charge_consumer(
                    &peer.resource_consumer,
                    6_000,
                    "network_id_mismatch",
                    std::time::Instant::now(),
                );
                s.peers.remove(&id);
                s.peer_txs.remove(&id);
                s.note_peer_connect_failure(addr, "network_id_mismatch");
                return None;
            }
        }

        let peer_reserved = {
            let state = self.state.read().await;
            peer_is_reserved(
                state.ctx.peer_reservations.as_ref(),
                &handshake_info.node_pubkey,
            )
        };
        if peer_reserved {
            info!("peer {id:?} ({addr}) matched a persistent peer reservation");
        }
        if !peer_reserved {
            let mut state = self.state.write().await;
            let peer_public_key = Some(crate::crypto::base58::encode(
                crate::crypto::base58::PREFIX_NODE_PUBLIC,
                &handshake_info.node_pubkey,
            ));
            let now = std::time::Instant::now();
            if let Some(blocked) = state
                .services
                .resource_manager
                .blocked_peer_status_for_logging(
                    addr,
                    peer_public_key.as_deref(),
                    now,
                )
            {
                let reason = if blocked.last_reason.is_empty() {
                    "resource pressure"
                } else {
                    blocked.last_reason.as_str()
                };
                if blocked.should_log {
                    warn!(
                        "peer {id:?} ({addr}) is temporarily resource-blocked for {}ms (reason={reason}) — rejecting",
                        blocked.remaining_ms
                    );
                } else {
                    debug!(
                        "peer {id:?} ({addr}) remains temporarily resource-blocked for {}ms (reason={reason})",
                        blocked.remaining_ms
                    );
                }
                state.peers.remove(&id);
                state.peer_txs.remove(&id);
                state.peer_direction.remove(&id);
                state.note_peer_connect_failure(addr, "resource_blocked");
                return None;
            }
        }

        let handshake_snapshot = handshake_info.clone();
        let action = peer.handle(PeerEvent::HandshakeAccepted(handshake_info));
        self.sync_peer_state_snapshot(peer).await;
        if let Err(e) = self
            .execute_action(stream, peer, action, &session_hash)
            .await
        {
            warn!("peer {id:?} ({addr}) post-handshake action error: {e}");
            let mut s = self.state.write().await;
            let _ = s.services.resource_manager.charge_consumer(
                &peer.resource_consumer,
                4_000,
                "post_handshake_error",
                std::time::Instant::now(),
            );
            s.peers.remove(&id);
            s.peer_txs.remove(&id);
            s.note_peer_connect_failure(addr, "post_handshake_error");
            return None;
        }

        {
            let mut s = self.state.write().await;
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let now = std::time::Instant::now();
            let public_key = crate::crypto::base58::encode(
                crate::crypto::base58::PREFIX_NODE_PUBLIC,
                &handshake_snapshot.node_pubkey,
            );
            s.services
                .resource_manager
                .set_consumer_public_key(&mut peer.resource_consumer, &public_key, now);
            if !peer_reserved
                && dir == Direction::Inbound
                && s.inbound_count() > self.config.max_inbound()
            {
                warn!(
                    "peer {id:?} ({addr}) exceeded inbound slot limit after handshake — rejecting unreserved peer"
                );
                let _ = s.services.resource_manager.charge_consumer(
                    &peer.resource_consumer,
                    4_000,
                    "too_many_inbound_peers",
                    std::time::Instant::now(),
                );
                s.peers.remove(&id);
                s.peer_txs.remove(&id);
                s.peer_direction.remove(&id);
                if let Some(slot) = s.peerfinder_slots.remove(&id) {
                    s.services
                        .peerfinder
                        .on_failure(&slot, "too_many_inbound_peers", now_unix);
                } else {
                    s.note_peer_connect_failure(addr, "too_many_inbound_peers");
                    return None;
                }
                s.rebuild_known_peers();
                s.refresh_runtime_health(std::time::Instant::now());
                return None;
            }
            if !peer_reserved && s.peer_count() > self.config.max_peers {
                warn!(
                    "peer {id:?} ({addr}) exceeded max peer limit after handshake — rejecting unreserved peer"
                );
                let _ = s.services.resource_manager.charge_consumer(
                    &peer.resource_consumer,
                    4_000,
                    "too_many_peers",
                    std::time::Instant::now(),
                );
                s.peers.remove(&id);
                s.peer_txs.remove(&id);
                s.peer_direction.remove(&id);
                if let Some(slot) = s.peerfinder_slots.remove(&id) {
                    s.services.peerfinder.on_failure(&slot, "too_many_peers", now_unix);
                } else {
                    s.note_peer_connect_failure(addr, "too_many_peers");
                    return None;
                }
                s.rebuild_known_peers();
                s.refresh_runtime_health(std::time::Instant::now());
                return None;
            }
            if let Some(slot) = peer.peerfinder_slot.as_mut() {
                s.services.peerfinder.activate(
                    slot,
                    Some(public_key.clone()),
                    peer_reserved || addr.ip().is_loopback(),
                    now_unix,
                );
                let _ = s.services.peerfinder.on_connected(slot, None, now_unix);
            }
            if peer_reserved || addr.ip().is_loopback() {
                let tag = peer_reservation_description(s.ctx.peer_reservations.as_ref(), &public_key)
                    .or_else(|| addr.ip().is_loopback().then_some("loopback".to_string()));
                s.services.cluster.note_connected(
                    addr,
                    Some(public_key),
                    peer_reserved,
                    addr.ip().is_loopback(),
                    tag,
                );
            }
            s.peer_handshakes.insert(id, handshake_snapshot);
            s.rebuild_known_peers();
            s.refresh_runtime_health(std::time::Instant::now());
        }

        info!("peer {id:?} ({addr}) handshake complete — entering RTXP loop");

        let status_msg = {
            let state = self.state.read().await;
            crate::network::relay::encode_status_change(
                crate::proto::NodeStatus::NsConnected,
                crate::proto::NodeEvent::NeAcceptedLedger,
                state.ctx.ledger_seq,
                &state.ctx.ledger_header.hash,
            )
        };
        let _ = stream.write_all(&status_msg.encode()).await;

        if peer_reserved || addr.ip().is_loopback() {
            let cluster_msg = {
                let state = self.state.read().await;
                let public_key = crate::crypto::base58::encode(
                    crate::crypto::base58::PREFIX_NODE_PUBLIC,
                    &self.node_key.public_key_bytes(),
                );
                let blocked_peers = state
                    .services
                    .resource_manager
                    .snapshot(std::time::Instant::now(), 0)
                    .blocked as u32;
                crate::network::relay::encode_cluster(
                    &public_key,
                    state.services.load_manager.snapshot().load_factor_server(),
                    Some(&self.config.peer_addr.to_string()),
                    blocked_peers,
                )
            };
            let _ = stream.write_all(&cluster_msg.encode()).await;
        }

        let endpoints_msg = {
            let state = self.state.read().await;
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut endpoints = state
                .services
                .peerfinder
                .build_endpoints_for_peer(addr, now_unix, 32);
            endpoints.push(self.config.peer_addr);
            crate::network::relay::encode_endpoints(&endpoints)
        };
        let _ = stream.write_all(&endpoints_msg.encode()).await;

        let ping_msg = {
            let mut state = self.state.write().await;
            state.add_known_peer_with_source(addr, "connected");
            state.connected_addrs.insert(addr);
            state.peer_addrs.insert(id, addr);
            let seq = rand::random::<u32>();
            state
                .peer_ping_sent
                .insert(id, (seq, std::time::Instant::now()));
            crate::network::relay::encode_ping(seq)
        };
        let _ = stream.write_all(&ping_msg.encode()).await;

        let use_compression = peer
            .info
            .as_ref()
            .and_then(|i| i.features.as_ref())
            .map(|f| f.contains("lz4"))
            .unwrap_or(false);

        Some(use_compression)
    }
}
