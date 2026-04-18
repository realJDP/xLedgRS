use super::*;

impl Node {
    pub(super) async fn handle_snapshot_request_message(
        &self,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Some(seq) = crate::network::relay::decode_get_snapshot(&msg.payload) {
            info!("peer {:?} requested snapshot (seq={})", peer.id, seq);
            let state = self.state.read().await;
            let tx = state.peer_txs.get(&peer.id).cloned();
            if let Some(tx) = tx {
                let _ = tx.try_send(crate::network::relay::encode_snapshot_header(
                    &state.ctx.ledger_header,
                ));
                let ls = state
                    .ctx
                    .ledger_state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let accounts: Vec<_> = ls.iter_accounts().map(|(_, a)| a.clone()).collect();
                drop(ls);
                if !accounts.is_empty() {
                    let data = bincode::serialize(&accounts).unwrap_or_default();
                    let _ = tx.try_send(crate::network::relay::encode_snapshot_chunk(0, data));
                }
                let _ = tx.try_send(crate::network::relay::encode_snapshot_end(
                    state.ctx.ledger_seq,
                    &state.ctx.ledger_header.account_hash,
                ));
            }
        }
        PeerEvent::MessageReceived(msg.msg_type, msg.payload.clone())
    }

    pub(super) async fn handle_snapshot_header_message(
        &self,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Some(header) = crate::network::relay::decode_snapshot_header(&msg.payload) {
            info!("received snapshot header: ledger {}", header.sequence);
            let mut state = self.state.write().await;
            state.ctx.ledger_header = header.clone();
            state.ctx.ledger_seq = header.sequence;
            state.ctx.ledger_hash = hex::encode_upper(header.hash);
            state
                .ctx
                .history
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert_ledger(header, vec![]);
        }
        PeerEvent::MessageReceived(msg.msg_type, msg.payload.clone())
    }

    pub(super) async fn handle_snapshot_chunk_message(
        &self,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if !msg.payload.is_empty() {
            let obj_type = msg.payload[0];
            let data = &msg.payload[1..];
            let state = self.state.read().await;
            if obj_type == 0 {
                if let Ok(accounts) = bincode::deserialize::<Vec<crate::ledger::AccountRoot>>(data)
                {
                    let mut ls = state
                        .ctx
                        .ledger_state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    for a in accounts {
                        ls.insert_account(a);
                    }
                }
            }
        }
        PeerEvent::MessageReceived(msg.msg_type, msg.payload.clone())
    }

    pub(super) async fn handle_snapshot_end_message(
        &self,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Some((seq, hash)) = crate::network::relay::decode_snapshot_end(&msg.payload) {
            let mut state = self.state.write().await;
            let local_hash = {
                let mut ls = state
                    .ctx
                    .ledger_state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                ls.state_hash()
            };
            if local_hash == hash {
                info!("snapshot verified: ledger {seq} state hash matches");
            } else {
                warn!("snapshot hash MISMATCH for ledger {seq}");
            }
            state.sync_in_progress = false;
        }
        PeerEvent::MessageReceived(msg.msg_type, msg.payload.clone())
    }

    pub(super) async fn handle_get_history_message(
        &self,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Some((start, end)) = crate::network::relay::decode_get_history(&msg.payload) {
            info!("peer {:?} requested history {start}..{end}", peer.id);
            let state = self.state.read().await;
            let tx = state.peer_txs.get(&peer.id).cloned();
            if let Some(tx) = tx {
                let capped_end = end.min(start + 255);
                let history = state.ctx.history.read().unwrap_or_else(|e| e.into_inner());
                for seq in start..=capped_end {
                    if let Some(rec) = history.get_ledger(seq) {
                        let tx_records: Vec<_> = rec
                            .tx_hashes
                            .iter()
                            .filter_map(|h| history.get_tx(h).cloned())
                            .collect();
                        let _ = tx.try_send(crate::network::relay::encode_history_ledger(
                            &rec.header,
                            &tx_records,
                        ));
                    }
                }
                let _ = tx.try_send(crate::network::relay::encode_history_end(start, capped_end));
            }
        }
        PeerEvent::MessageReceived(msg.msg_type, msg.payload.clone())
    }

    pub(super) async fn handle_history_ledger_message(
        &self,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Some((header, tx_records)) =
            crate::network::relay::decode_history_ledger(&msg.payload)
        {
            if header.compute_hash() == header.hash {
                info!("received history ledger {}", header.sequence);
                let state = self.state.write().await;
                state
                    .ctx
                    .history
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert_ledger(header, tx_records);
            } else {
                warn!("rejected history ledger: hash mismatch");
            }
        }
        PeerEvent::MessageReceived(msg.msg_type, msg.payload.clone())
    }

    pub(super) async fn handle_history_end_message(
        &self,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        info!("history download complete");
        let mut state = self.state.write().await;
        state.sync_in_progress = false;
        PeerEvent::MessageReceived(msg.msg_type, msg.payload.clone())
    }

    pub(super) async fn handle_squelch_message(
        &self,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Some(sq) = crate::network::relay::decode_squelch(&msg.payload) {
            let mut state = self.state.write().await;
            if sq.squelch {
                let duration = sq.duration_secs.unwrap_or(600);
                let expiry =
                    std::time::Instant::now() + std::time::Duration::from_secs(duration as u64);
                state
                    .peer_squelch
                    .entry(peer.id)
                    .or_default()
                    .insert(sq.validator_pubkey.clone(), expiry);
                tracing::debug!(
                    "squelch received: peer={} validator={}... duration={}s",
                    peer.id.0,
                    hex::encode_upper(&sq.validator_pubkey[..8.min(sq.validator_pubkey.len())]),
                    duration,
                );
            } else if let Some(map) = state.peer_squelch.get_mut(&peer.id) {
                map.remove(&sq.validator_pubkey);
                tracing::debug!(
                    "unsquelch received: peer={} validator={}...",
                    peer.id.0,
                    hex::encode_upper(&sq.validator_pubkey[..8.min(sq.validator_pubkey.len())]),
                );
            }
        }
        PeerEvent::MessageReceived(MessageType::Squelch, msg.payload.clone())
    }
}
