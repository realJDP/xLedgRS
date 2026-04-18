use super::*;

impl Node {
    pub(super) async fn handle_transaction_message(
        &self,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        let decoded_tx =
            <crate::proto::TmTransaction as ProstMessage>::decode(msg.payload.as_slice()).ok();
        let tx_info = decoded_tx.as_ref().map(|pb| {
            let blob = pb.raw_transaction.clone();
            let hash = crate::transaction::serialize::tx_blob_hash(&blob);
            (blob, hash)
        });

        if let Some((blob, hash)) = tx_info.as_ref() {
            let ledger_seq = { self.state.read().await.ctx.ledger_seq };
            let is_new_inbound = {
                let mut state = self.state.write().await;
                let is_new = state.services.inbound_transactions.observe(
                    *hash,
                    blob.len(),
                    peer.addr.to_string(),
                    crate::ledger::inbound_transactions::unix_now(),
                );
                state.services.tx_master.observe_proposed(
                    *hash,
                    blob.len(),
                    peer.addr.to_string(),
                    crate::transaction::master::unix_now(),
                );
                is_new
            };

            if is_new_inbound {
                if let Some(ref store) = self.storage {
                    let store2 = store.clone();
                    let blob2 = blob.clone();
                    let hash2 = *hash;
                    {
                        let mut state = self.state.write().await;
                        state.services.inbound_transactions.note_persisted(hash);
                    }
                    tokio::task::spawn_blocking(move || {
                        let rec = crate::ledger::history::TxRecord {
                            blob: blob2,
                            meta: vec![],
                            hash: hash2,
                            ledger_seq,
                            tx_index: 0,
                            result: "pending".into(),
                        };
                        let _ = store2.save_transaction(&rec);
                    });
                }

                let state = self.state.read().await;
                if let Ok(_parsed) = crate::transaction::parse_blob(blob) {
                    state
                        .ctx
                        .history
                        .write()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert_tx(crate::ledger::history::TxRecord {
                            blob: blob.clone(),
                            meta: vec![],
                            hash: *hash,
                            ledger_seq,
                            tx_index: 0,
                            result: "pending".into(),
                        });
                }
            }
        }

        if !self.message_is_new(MessageType::Transaction, &msg.payload) {
            return PeerEvent::MessageReceived(MessageType::Transaction, msg.payload.clone());
        }

        let relay_msg = RtxpMessage::new(MessageType::Transaction, msg.payload.clone());
        self.state.read().await.broadcast(&relay_msg, Some(peer.id));
        if let Some((blob, hash)) = tx_info.as_ref() {
            {
                let mut state = self.state.write().await;
                state.services.inbound_transactions.note_relayed(hash);
                state
                    .services
                    .tx_master
                    .note_relayed(hash, crate::transaction::master::unix_now());
            }
            let _ = self
                .ws_events
                .send(crate::rpc::ws::WsEvent::ProposedTransaction {
                    tx_blob: blob.clone(),
                    network_id: self.config.network_id,
                    accounts: transaction_accounts_from_blob(blob),
                });
        }
        let _ = self.ws_events.send(crate::rpc::ws::WsEvent::PeerMessage {
            msg_type: "transaction".into(),
            detail: format!("from {:?}", peer.id),
        });
        PeerEvent::MessageReceived(MessageType::Transaction, msg.payload.clone())
    }
}
