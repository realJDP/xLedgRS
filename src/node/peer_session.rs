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
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<RtxpMessage>(64);
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

        let use_compression = match self
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

        loop {
            tokio::select! {
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
                        )
                        .await
                    {
                        break;
                    }
                }

                Some(msg) = outbound_rx.recv() => {
                    let wire = if use_compression { msg.encode_compressed() } else { msg.encode() };
                    if let Err(e) = stream.write_all(&wire).await {
                        warn!("peer {id:?} write error: {e}");
                        break;
                    }
                }
            }

            if peer.state.is_closed() {
                break;
            }
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
