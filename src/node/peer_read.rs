use super::*;

impl Node {
    async fn charge_peer_protocol_drop(self: &Arc<Self>, peer: &Peer, reason: impl Into<String>) {
        let reason = reason.into();
        let mut state = self.state.write().await;
        let _ = state.services.resource_manager.charge_consumer(
            &peer.resource_consumer,
            6_000,
            reason,
            std::time::Instant::now(),
        );
    }

    pub(super) async fn process_peer_frames<S>(
        self: &Arc<Self>,
        stream: &mut S,
        peer: &mut Peer,
        dec: &mut FrameDecoder,
        bytes: &[u8],
        session_hash: &[u8; 32],
    ) -> bool
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    {
        if dec.feed(bytes).is_err() {
            warn!("peer {:?} buffer overflow — disconnecting", peer.id);
            self.charge_peer_protocol_drop(peer, "frame_buffer_overflow").await;
            return true;
        }

        loop {
            match dec.drain_messages() {
                Err(e) => {
                    warn!("peer {:?} frame error: {e}", peer.id);
                    self.charge_peer_protocol_drop(peer, format!("frame_error:{e}"))
                        .await;
                    peer.handle(PeerEvent::Error(e.to_string()));
                    return true;
                }
                Ok(msgs) => {
                    if msgs.is_empty() {
                        break;
                    }
                    for msg in msgs {
                        let msg_type = msg.msg_type;
                        let rm_t0 = std::time::Instant::now();
                        let event = self.route_message(peer, msg).await;
                        let rm_ms = rm_t0.elapsed().as_millis();
                        let slow_threshold_ms = match msg_type {
                            MessageType::Manifests => 300,
                            _ => 100,
                        };
                        if rm_ms > slow_threshold_ms {
                            warn!(
                                "SLOW route_message: {:?} from {:?} took {}ms",
                                msg_type, peer.id, rm_ms,
                            );
                            let mut state = self.state.write().await;
                            state.services.load_manager.note_slow_operation(
                                std::time::Duration::from_millis(rm_ms as u64),
                                format!("route_{msg_type:?}"),
                                std::time::Instant::now(),
                            );
                        }
                        let action = peer.handle(event);
                        self.sync_peer_state_snapshot(peer).await;
                        if let Err(e) = self.execute_action(stream, peer, action, session_hash).await
                        {
                            warn!("peer {:?} action error: {e}", peer.id);
                        }
                    }
                }
            }
            if dec.buffered_bytes() < HEADER_SIZE {
                break;
            }
        }

        false
    }
}
