use super::*;

pub(super) fn peer_reservations_map(
    reservations: Option<
        &std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>,
    >,
) -> std::collections::BTreeMap<String, String> {
    reservations
        .map(|reservations| {
            reservations
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        })
        .unwrap_or_default()
}

pub(super) fn peer_is_reserved(
    reservations: Option<
        &std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>,
    >,
    node_pubkey: &[u8],
) -> bool {
    let public_key =
        crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, node_pubkey);
    reservations
        .map(|reservations| {
            reservations
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&public_key)
        })
        .unwrap_or(false)
}

pub(super) fn peer_reservation_description(
    reservations: Option<
        &std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>,
    >,
    public_key: &str,
) -> Option<String> {
    reservations.and_then(|reservations| {
        reservations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(public_key)
            .cloned()
    })
}

pub(super) fn peer_reservation_headroom(
    reservations: Option<
        &std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>,
    >,
) -> usize {
    peer_reservations_map(reservations).len().min(4)
}

impl SharedState {
    pub(super) fn next_peer_id(&mut self) -> PeerId {
        self.peer_counter += 1;
        PeerId(self.peer_counter)
    }

    pub(super) fn can_accept_inbound_peer(
        &mut self,
        addr: SocketAddr,
        max_inbound: usize,
    ) -> Result<(), &'static str> {
        if addr.ip().is_loopback() {
            return Ok(());
        }
        if self
            .services
            .resource_manager
            .is_blocked(addr, std::time::Instant::now())
        {
            self.note_peer_connect_failure(addr, "resource_blocked");
            return Err("resource_blocked");
        }
        let reservation_headroom = peer_reservation_headroom(self.ctx.peer_reservations.as_ref());
        if self.inbound_count() >= max_inbound + reservation_headroom {
            self.note_peer_connect_failure(addr, "inbound_slots_full");
            return Err("inbound_slots_full");
        }
        Ok(())
    }

    pub(super) fn allow_outbound_candidate(
        &mut self,
        addr: SocketAddr,
        now: std::time::Instant,
    ) -> bool {
        if addr.ip().is_loopback() {
            return !self.connected_addrs.contains(&addr)
                && !self.services.peerfinder.has_live_slot(addr);
        }
        if self.connected_addrs.contains(&addr) {
            return false;
        }
        if self.services.peerfinder.has_live_slot(addr) {
            return false;
        }
        if self.peer_cooldowns.contains_key(&addr) {
            self.note_peer_connect_failure(addr, "cooldown");
            return false;
        }
        if self.services.resource_manager.is_blocked(addr, now) {
            self.note_peer_connect_failure(addr, "resource_blocked");
            return false;
        }
        true
    }

    pub(super) fn rebuild_known_peers(&mut self) {
        let mut ordered = self.services.peerfinder.ordered_addrs_at(Self::now_unix());
        if ordered.len() > 1000 {
            ordered.truncate(1000);
        }
        self.known_peers = ordered.into_iter().collect();
    }

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub(super) fn refresh_runtime_health(&mut self, now: std::time::Instant) {
        self.services.refresh_health(
            self.peer_count(),
            peer_reservations_map(self.ctx.peer_reservations.as_ref()).len(),
            now,
        );
        self.rebuild_known_peers();
    }

    /// Add a peer address to known_peers if not already present.
    /// Capped at 1000 entries to prevent unbounded growth.
    pub fn add_known_peer(&mut self, addr: SocketAddr) {
        self.add_known_peer_with_source(addr, "peer");
    }

    pub fn add_known_peer_with_source(&mut self, addr: SocketAddr, source: &str) {
        self.services
            .peerfinder
            .note_discovered(addr, source, Self::now_unix());
        self.rebuild_known_peers();
        self.refresh_runtime_health(std::time::Instant::now());
    }

    pub fn add_static_peer(&mut self, addr: SocketAddr) {
        self.services
            .peerfinder
            .insert_static(addr, Self::now_unix());
        self.rebuild_known_peers();
        self.refresh_runtime_health(std::time::Instant::now());
    }

    pub fn note_peer_connect_success(&mut self, addr: SocketAddr) {
        self.services
            .peerfinder
            .note_connected(addr, Self::now_unix());
        self.rebuild_known_peers();
        self.refresh_runtime_health(std::time::Instant::now());
    }

    pub fn note_peer_connect_failure(&mut self, addr: SocketAddr, reason: &str) {
        self.services
            .peerfinder
            .note_failure(addr, reason, Self::now_unix());
        self.rebuild_known_peers();
        self.refresh_runtime_health(std::time::Instant::now());
    }
}
