use super::http_io::read_http_headers;
use super::*;

impl Node {
    pub(super) async fn handle_peer<S>(
        self: Arc<Self>,
        mut stream: S,
        session_hash: [u8; 32],
        addr: SocketAddr,
        dir: Direction,
    ) where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    {
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<RtxpMessage>(256);
        let id = self.register_connecting_peer(outbound_tx, dir).await;
        let peerfinder_slot = {
            let mut state = self.state.write().await;
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let slot = if matches!(dir, Direction::Inbound) {
                state.services.peerfinder.new_inbound_slot(addr, now_unix)
            } else {
                state.services.peerfinder.new_outbound_slot(addr, now_unix)
            };
            state.peerfinder_slots.insert(id, slot.clone());
            state.refresh_runtime_health(std::time::Instant::now());
            slot
        };

        let resource_consumer = {
            let state = self.state.read().await;
            match dir {
                Direction::Inbound => state
                    .services
                    .resource_manager
                    .new_inbound_endpoint(addr, false, None),
                Direction::Outbound => state.services.resource_manager.new_outbound_endpoint(addr),
            }
        };
        let mut peer = Peer::new(id, addr, dir, resource_consumer);
        peer.idle_timeout = self.config.sync_tuning.peer_idle_timeout();
        peer.set_peerfinder_slot(peerfinder_slot);

        peer.handle(PeerEvent::TlsEstablished);
        self.sync_peer_state_snapshot(&peer).await;

        let (handshake_info, leftover) = match self
            .perform_handshake(&mut stream, &session_hash, dir)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.handle_failed_handshake(id, addr, &format!("{e}"))
                    .await;
                return;
            }
        };

        let _use_compression = match self
            .finalize_peer_handshake(
                &mut stream,
                &mut peer,
                id,
                addr,
                dir,
                session_hash,
                handshake_info,
            )
            .await
        {
            Some(use_compression) => use_compression,
            None => return,
        };

        let mut dec = FrameDecoder::new();
        if !leftover.is_empty() {
            let _ = dec.feed(&leftover);
        }
        let mut buf = vec![0u8; 8192];
        let (route_tx, route_rx, route_result_tx, mut route_result_rx) = self.peer_route_channel();
        let route_worker = tokio::spawn(self.clone().run_peer_route_worker(
            id,
            route_rx,
            route_result_tx,
        ));
        let mut route_seq = 0u64;
        let mut next_route_result_seq = 0u64;
        let mut pending_route_results = std::collections::BTreeMap::new();
        let mut idle_check = tokio::time::interval(std::time::Duration::from_secs(1));
        idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = idle_check.tick() => {
                    let action = peer.check_idle();
                    if let Err(e) = self
                        .execute_action(&mut stream, &mut peer, action, &session_hash)
                        .await
                    {
                        warn!("peer {id:?} idle action error: {e}");
                        break;
                    }
                    self.sync_peer_state_snapshot(&peer).await;
                }

                result = stream.read(&mut buf) => {
                    let n = match result {
                        Ok(0) => {
                            info!("peer {id:?} closed connection");
                            peer.handle(PeerEvent::RemoteClosed);
                            break;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            warn!("peer {id:?} read error: {e}");
                            peer.handle(PeerEvent::Error(e.to_string()));
                            break;
                        }
                    };

                    if self
                        .process_peer_frames(
                            &mut stream,
                            &mut peer,
                            &mut dec,
                            &buf[..n],
                            &session_hash,
                            &route_tx,
                            &mut route_seq,
                            next_route_result_seq,
                        )
                        .await
                    {
                        break;
                    }
                }

                Some(msg) = outbound_rx.recv() => {
                    // Keep outbound frames uncompressed for now. We still accept
                    // compressed inbound RTXP frames, but some mainnet peers reset
                    // immediately after our first compressed post-handshake frame.
                    let wire = msg.encode();
                    if let Err(e) = stream.write_all(&wire).await {
                        warn!("peer {id:?} write error: {e}");
                        break;
                    }
                }

                Some(result) = route_result_rx.recv() => {
                    pending_route_results.insert(result.seq, result);
                    while let Some(result) = pending_route_results.remove(&next_route_result_seq) {
                        next_route_result_seq = next_route_result_seq.saturating_add(1);
                        self.apply_peer_route_result(
                            &mut stream,
                            &mut peer,
                            result,
                            &session_hash,
                        ).await;
                    }
                }
            }

            if peer.state.is_closed() {
                break;
            }
        }

        drop(route_tx);
        loop {
            match tokio::time::timeout(
                self.config.sync_tuning.peer_route_drain_timeout(),
                route_result_rx.recv(),
            )
            .await
            {
                Ok(Some(result)) => {
                    pending_route_results.insert(result.seq, result);
                    while let Some(result) = pending_route_results.remove(&next_route_result_seq) {
                        next_route_result_seq = next_route_result_seq.saturating_add(1);
                        self.apply_peer_route_result(&mut stream, &mut peer, result, &session_hash)
                            .await;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    warn!("peer {id:?} route worker drain timed out during disconnect");
                    break;
                }
            }
        }
        if !route_worker.is_finished() {
            route_worker.abort();
        }

        let peer_reserved = self.deregister_peer(id, addr).await;
        info!(
            "peer {id:?} ({addr}) disconnected{}",
            if addr.ip().is_loopback() {
                ""
            } else if peer_reserved {
                " — reserved peer"
            } else {
                " — cooldown 130s"
            }
        );
    }

    pub(super) async fn perform_handshake<S>(
        &self,
        stream: &mut S,
        session_hash: &[u8; 32],
        dir: Direction,
    ) -> anyhow::Result<(crate::network::handshake::HandshakeInfo, Vec<u8>)>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        match dir {
            Direction::Outbound => {
                let pubkey = self.node_key.public_key_bytes();
                let sig = self.node_key.sign_digest(session_hash);
                let (ledger_hash, parent_hash) = {
                    let state = self.state.read().await;
                    let lh = state.ctx.ledger_hash.clone();
                    let ph = hex::encode_upper(state.ctx.ledger_header.parent_hash);
                    (lh, ph)
                };
                let req = crate::network::handshake::build_request(
                    &pubkey,
                    &sig,
                    self.config.network_id,
                    &ledger_hash,
                    &parent_hash,
                );
                stream.write_all(req.as_bytes()).await?;

                let (raw, leftover) = read_http_headers(stream).await?;
                match crate::network::handshake::parse_response(&raw) {
                    Ok(Some((info, _))) => Ok((info, leftover)),
                    Ok(None) => anyhow::bail!("incomplete handshake response"),
                    Err(e) => {
                        let body = String::from_utf8_lossy(&leftover);
                        anyhow::bail!("{e} body={body}")
                    }
                }
            }
            Direction::Inbound => {
                let (raw, leftover) = read_http_headers(stream).await?;
                let info = match crate::network::handshake::parse_request(&raw)? {
                    Some((info, _)) => info,
                    None => anyhow::bail!("incomplete handshake request"),
                };
                Ok((info, leftover))
            }
        }
    }

    pub(super) async fn execute_action<S>(
        &self,
        stream: &mut S,
        peer: &mut Peer,
        action: PeerAction,
        session_hash: &[u8; 32],
    ) -> anyhow::Result<()>
    where
        S: AsyncWriteExt + Unpin + Send,
    {
        match action {
            PeerAction::SendHandshakeRequest => {
                let pubkey = self.node_key.public_key_bytes();
                let sig = self.node_key.sign_digest(session_hash);
                let req = crate::network::handshake::build_request_simple(&pubkey, &sig);
                stream.write_all(req.as_bytes()).await?;
            }
            PeerAction::SendHandshakeResponse => {
                let pubkey = self.node_key.public_key_bytes();
                let sig = self.node_key.sign_digest(session_hash);
                let resp = crate::network::handshake::build_response(&pubkey, &sig);
                stream.write_all(resp.as_bytes()).await?;
            }
            PeerAction::SendMessage(msg_type, payload) => {
                let msg = RtxpMessage::new(msg_type, payload);
                stream.write_all(&msg.encode()).await?;
            }
            PeerAction::CloseSocket => {
                let _ = stream.shutdown().await;
            }
            PeerAction::Warn(msg) => {
                warn!("peer {:?}: {msg}", peer.id);
            }
            PeerAction::None => {}
        }
        Ok(())
    }
}
