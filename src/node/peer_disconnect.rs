use super::*;

impl Node {
    pub(super) async fn deregister_peer(&self, id: PeerId, addr: SocketAddr) -> bool {
        let mut s = self.state.write().await;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let public_key = s.peer_handshakes.get(&id).map(|info| {
            crate::crypto::base58::encode(
                crate::crypto::base58::PREFIX_NODE_PUBLIC,
                &info.node_pubkey,
            )
        });
        let peer_reserved = s
            .peer_handshakes
            .get(&id)
            .map(|info| peer_is_reserved(s.ctx.peer_reservations.as_ref(), &info.node_pubkey))
            .unwrap_or(false);
        s.services
            .cluster
            .note_disconnected(addr, public_key.as_deref());
        s.peers.remove(&id);
        s.peer_txs.remove(&id);
        s.peer_addrs.remove(&id);
        s.peer_handshakes.remove(&id);
        s.peer_latency.remove(&id);
        s.peer_ping_sent.remove(&id);
        s.sync_peer_cooldown.remove(&id);
        s.peer_sync_useful.remove(&id);
        s.peer_sync_last_useful.remove(&id);
        s.implausible_validation_state.remove(&id);
        s.peer_direction.remove(&id);
        s.peer_squelch.remove(&id);
        s.peer_ledger_range.remove(&id);
        s.connected_addrs.remove(&addr);
        if let Some(slot) = s.peerfinder_slots.remove(&id) {
            s.services.peerfinder.on_closed(&slot, now_unix);
        } else {
            s.services.peerfinder.note_closed(addr, now_unix);
        }
        if !peer_reserved && !addr.ip().is_loopback() {
            s.peer_cooldowns.insert(
                addr,
                std::time::Instant::now() + std::time::Duration::from_secs(130),
            );
        }
        s.refresh_runtime_health(std::time::Instant::now());
        peer_reserved
    }
}
