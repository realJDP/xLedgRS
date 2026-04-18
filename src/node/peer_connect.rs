use super::*;

impl Node {
    pub(super) async fn register_connecting_peer(
        &self,
        outbound_tx: mpsc::Sender<RtxpMessage>,
        dir: Direction,
    ) -> PeerId {
        let mut s = self.state.write().await;
        let id = s.next_peer_id();
        s.peers.insert(id, PeerState::Connecting);
        s.peer_txs.insert(id, outbound_tx);
        s.peer_direction.insert(id, dir);
        id
    }

    pub(super) async fn handle_failed_handshake(
        &self,
        id: PeerId,
        addr: SocketAddr,
        err_str: &str,
    ) {
        let is_503 = err_str.contains("503");
        let cooldown = if is_503 { 60 } else { 130 };
        warn!("peer {id:?} ({addr}) handshake failed (cooldown {cooldown}s)");
        let mut s = self.state.write().await;
        let now = std::time::Instant::now();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if !is_503 {
            let _ = s.services.resource_manager.charge_addr(
                addr,
                4_000,
                "handshake_failed",
                now,
            );
        }
        s.peers.remove(&id);
        s.peer_txs.remove(&id);
        s.peer_ledger_range.remove(&id);
        s.peer_direction.remove(&id);
        if let Some(slot) = s.peerfinder_slots.remove(&id) {
            if is_503 {
                s.services.peerfinder.on_closed(&slot, now_unix);
            } else {
                s.services
                    .peerfinder
                    .on_failure(&slot, "handshake_failed", now_unix);
            }
        }
        s.peer_cooldowns.insert(
            addr,
            now + std::time::Duration::from_secs(cooldown),
        );
        if is_503 {
            self.learn_redirect_peers(&mut s, addr, err_str);
        } else {
            s.rebuild_known_peers();
            s.refresh_runtime_health(now);
        }
        if is_503 {
            s.refresh_runtime_health(now);
        }
    }

    fn learn_redirect_peers(
        &self,
        state: &mut SharedState,
        redirect_from: SocketAddr,
        err_str: &str,
    ) {
        let Some(body_start) = err_str.find("body=") else {
            return;
        };
        let body = &err_str[body_start + 5..];
        let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
            return;
        };
        let Some(ips) = json["peer-ips"].as_array() else {
            return;
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut redirected = false;
        for ip in ips {
            let Some(ip_str) = ip.as_str() else {
                continue;
            };
            if let Ok(addr) = ip_str.parse::<std::net::SocketAddr>() {
                if !redirected {
                    state
                        .services
                        .peerfinder
                        .note_redirect(redirect_from, addr, now_unix);
                    redirected = true;
                } else {
                    state
                        .services
                        .peerfinder
                        .note_discovered(addr, format!("redirect:{redirect_from}"), now_unix);
                }
                state.add_known_peer_with_source(addr, "redirect");
            } else if let Ok(ip_addr) = ip_str.parse::<std::net::IpAddr>() {
                let addr = std::net::SocketAddr::new(ip_addr, 51235);
                if !redirected {
                    state
                        .services
                        .peerfinder
                        .note_redirect(redirect_from, addr, now_unix);
                    redirected = true;
                } else {
                    state
                        .services
                        .peerfinder
                        .note_discovered(addr, format!("redirect:{redirect_from}"), now_unix);
                }
                state.add_known_peer_with_source(addr, "redirect");
            }
        }
        info!("503 redirect: discovered {} peer IPs", ips.len());
    }
}
