use super::*;

impl Node {
    pub(super) async fn route_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: RtxpMessage,
    ) -> PeerEvent {
        use crate::network::relay;

        match msg.msg_type {
            MessageType::Ping
            | MessageType::Validation
            | MessageType::Transaction
            | MessageType::GetLedger
            | MessageType::LedgerData
            | MessageType::ProposeLedger => {}
            _ => {
                trace!(
                    "msg type {:?} from {:?} ({} bytes)",
                    msg.msg_type,
                    peer.id,
                    msg.payload.len()
                );
            }
        }

        match msg.msg_type {
            MessageType::Ping => self.handle_ping_message(peer, &msg).await,
            MessageType::Cluster => self.handle_cluster_message(peer, &msg).await,
            MessageType::StatusChange => self.handle_status_change_message(peer, &msg).await,
            MessageType::Transaction => self.handle_transaction_message(peer, &msg).await,
            MessageType::ProposeLedger => self.handle_proposal_message(peer, &msg).await,
            MessageType::LedgerData => {
                if let Some(ld) = relay::decode_ledger_data(&msg.payload) {
                    debug!(
                        "LedgerData response: type={} seq={} nodes={} error={:?} from {:?}",
                        ld.r#type,
                        ld.ledger_seq,
                        ld.nodes.len(),
                        ld.error,
                        peer.id,
                    );
                    if ld.r#type == crate::proto::TmLedgerInfoType::LiBase as i32 {
                        self.handle_base_ledger_data(peer, &ld).await;
                    } else if ld.r#type == crate::proto::TmLedgerInfoType::LiAsNode as i32 {
                        self.handle_state_node_message(peer, &ld).await;
                    } else if ld.r#type == crate::proto::TmLedgerInfoType::LiTxNode as i32 {
                        self.handle_tx_node_message(peer, &ld).await;
                    } else {
                        debug!(
                            "received LedgerData type={} seq={} nodes={} from peer {:?}",
                            ld.r#type,
                            ld.ledger_seq,
                            ld.nodes.len(),
                            peer.id,
                        );
                    }
                }
                PeerEvent::MessageReceived(MessageType::LedgerData, msg.payload)
            }
            MessageType::Validation => self.handle_validation_message(peer, &msg).await,
            MessageType::Manifests => self.handle_manifests_message(peer, &msg).await,
            MessageType::ValidatorList => self.handle_validator_list_message(peer, &msg).await,
            MessageType::ValidatorListCollection => {
                self.handle_validator_list_collection_message(peer, &msg)
                    .await
            }
            MessageType::Endpoints => self.handle_endpoints_message(peer, &msg).await,
            MessageType::Unknown(200) => self.handle_snapshot_request_message(peer, &msg).await,
            MessageType::Unknown(201) => self.handle_snapshot_header_message(&msg).await,
            MessageType::Unknown(202) => self.handle_snapshot_chunk_message(&msg).await,
            MessageType::Unknown(203) => self.handle_snapshot_end_message(&msg).await,
            MessageType::Unknown(204) => self.handle_get_history_message(peer, &msg).await,
            MessageType::Unknown(205) => self.handle_history_ledger_message(&msg).await,
            MessageType::Unknown(206) => self.handle_history_end_message(&msg).await,
            MessageType::GetLedger => self.handle_get_ledger_message(peer, &msg).await,
            MessageType::GetObjects => self.handle_get_objects_message(peer, &msg).await,
            MessageType::Squelch => self.handle_squelch_message(peer, &msg).await,
            other => PeerEvent::MessageReceived(other, msg.payload),
        }
    }
}
