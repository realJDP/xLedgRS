use super::*;

fn infer_inbound_proposal_ledger_seq(
    prop: &crate::consensus::Proposal,
    current_seq: u32,
    current_hash: [u8; 32],
    active_round: Option<(u32, [u8; 32])>,
) -> Option<u32> {
    if prop.ledger_seq != 0 {
        let matches_active_round = active_round.is_some_and(|(round_seq, round_prev_hash)| {
            prop.ledger_seq == round_seq && prop.previous_ledger == round_prev_hash
        });
        let matches_next_round = prop.ledger_seq == current_seq.saturating_add(1)
            && prop.previous_ledger == current_hash;
        return (matches_active_round || matches_next_round).then_some(prop.ledger_seq);
    }
    if let Some((round_seq, round_prev_hash)) = active_round {
        if prop.previous_ledger == round_prev_hash {
            return Some(round_seq);
        }
    }
    if prop.previous_ledger == current_hash {
        return Some(current_seq.saturating_add(1));
    }
    None
}

fn extract_candidate_tx_blobs(nodes: &[crate::proto::TmLedgerNode]) -> Vec<Vec<u8>> {
    nodes
        .iter()
        .filter_map(|node| {
            let data = node.nodedata.as_slice();
            let (&wire_type, payload) = data.split_last()?;
            (wire_type == 0x00 && !payload.is_empty()).then(|| payload.to_vec())
        })
        .collect()
}

const MAX_CANDIDATE_TX_SET_PARTIALS: usize = 64;
const CANDIDATE_TX_SET_INITIAL_FANOUT: usize = 8;
const CANDIDATE_TX_SET_MISSING_NODE_FANOUT: usize = 4;
const MAX_CANDIDATE_TX_SET_MISSING_NODES_PER_REQUEST: usize = 256;

static CANDIDATE_TX_SET_PARTIALS: std::sync::OnceLock<
    std::sync::Mutex<
        std::collections::HashMap<
            [u8; 32],
            crate::ledger::shamap_sync::CandidateTxSetWireAccumulator,
        >,
    >,
> = std::sync::OnceLock::new();

fn candidate_tx_set_partials() -> &'static std::sync::Mutex<
    std::collections::HashMap<[u8; 32], crate::ledger::shamap_sync::CandidateTxSetWireAccumulator>,
> {
    CANDIDATE_TX_SET_PARTIALS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn import_candidate_tx_set_wire_nodes_with_partial_cache<'a>(
    expected_hash: [u8; 32],
    wire_nodes: Vec<(crate::ledger::shamap_id::SHAMapNodeID, &'a [u8])>,
) -> crate::ledger::shamap_sync::CandidateTxSetWireImport {
    let mut partials = candidate_tx_set_partials()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if partials.len() >= MAX_CANDIDATE_TX_SET_PARTIALS && !partials.contains_key(&expected_hash) {
        if let Some(evicted_hash) = partials.keys().next().copied() {
            partials.remove(&evicted_hash);
        }
    }

    let accumulator = partials.entry(expected_hash).or_default();
    let result = crate::ledger::shamap_sync::import_candidate_tx_set_wire_nodes_accumulated(
        expected_hash,
        accumulator,
        wire_nodes,
    );
    if matches!(
        result,
        crate::ledger::shamap_sync::CandidateTxSetWireImport::Complete(_)
    ) || accumulator.is_empty()
    {
        partials.remove(&expected_hash);
    }
    result
}

fn select_candidate_tx_set_followup_peers(
    mut peer_ids: Vec<PeerId>,
    preferred_peer: PeerId,
    limit: usize,
    rotation_start: usize,
) -> Vec<PeerId> {
    if limit == 0 {
        return Vec::new();
    }

    peer_ids.sort_by_key(|peer_id| peer_id.0);
    peer_ids.dedup();

    let mut selected = Vec::with_capacity(limit.min(peer_ids.len()));
    if peer_ids.contains(&preferred_peer) {
        selected.push(preferred_peer);
    }

    peer_ids.retain(|peer_id| *peer_id != preferred_peer);
    if !peer_ids.is_empty() {
        let offset = rotation_start % peer_ids.len();
        peer_ids.rotate_left(offset);
    }

    for peer_id in peer_ids {
        if selected.len() >= limit {
            break;
        }
        selected.push(peer_id);
    }

    selected
}

impl Node {
    pub(super) async fn request_candidate_tx_set(&self, tx_set_hash: [u8; 32]) {
        {
            let state = self.state.read().await;
            state
                .ctx
                .consensus_tx_sets
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .expect(tx_set_hash);
        }
        let req = crate::network::relay::encode_get_tx_set(&tx_set_hash, 0);
        let sent = {
            let state = self.state.read().await;
            let mut sent = 0usize;
            for tx in state.peer_txs.values() {
                let _ = tx.try_send(req.clone());
                sent += 1;
                if sent >= CANDIDATE_TX_SET_INITIAL_FANOUT {
                    break;
                }
            }
            sent
        };
        info!(
            "consensus: requested liTS_CANDIDATE tx_set={} from {} peer(s)",
            hex::encode_upper(&tx_set_hash[..8]),
            sent,
        );
    }

    async fn send_candidate_tx_set_missing_node_requests(
        &self,
        tx_set_hash: [u8; 32],
        responding_peer: PeerId,
        missing: Vec<crate::ledger::shamap_id::SHAMapNodeID>,
    ) {
        let node_i_ds = missing
            .into_iter()
            .take(MAX_CANDIDATE_TX_SET_MISSING_NODES_PER_REQUEST)
            .map(|node_id| node_id.to_wire().to_vec())
            .collect::<Vec<_>>();
        if node_i_ds.is_empty() {
            return;
        }

        let req = crate::network::relay::encode_get_tx_set_nodes(&tx_set_hash, &node_i_ds, 0, 3);
        let rotation_start = self
            .sync_runtime
            .round_robin()
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let sent_peers = {
            let state = self.state.read().await;
            let now = std::time::Instant::now();
            let peer_ids = state
                .peer_txs
                .keys()
                .copied()
                .filter(|peer_id| {
                    state
                        .peers
                        .get(peer_id)
                        .map(|ps| ps.is_open())
                        .unwrap_or(true)
                })
                .filter(|peer_id| {
                    state
                        .sync_peer_cooldown
                        .get(peer_id)
                        .map(|expires| now >= *expires)
                        .unwrap_or(true)
                })
                .collect::<Vec<_>>();
            let target_peers = select_candidate_tx_set_followup_peers(
                peer_ids,
                responding_peer,
                CANDIDATE_TX_SET_MISSING_NODE_FANOUT,
                rotation_start,
            );

            target_peers
                .into_iter()
                .filter(|peer_id| {
                    state
                        .peer_txs
                        .get(peer_id)
                        .map(|tx| tx.try_send(req.clone()).is_ok())
                        .unwrap_or(false)
                })
                .collect::<Vec<_>>()
        };

        debug!(
            "liTS_CANDIDATE from {:?} advanced SHAMap acquisition: requested {} missing node(s) from {} peer(s): {:?}",
            responding_peer,
            node_i_ds.len(),
            sent_peers.len(),
            sent_peers,
        );
    }

    pub(super) fn trusted_validation_master_without_round(
        &self,
        manifest_cache: Option<&std::sync::Arc<std::sync::Mutex<crate::consensus::ManifestCache>>>,
        val: &crate::consensus::Validation,
        effective_unl: &[Vec<u8>],
    ) -> Option<Vec<u8>> {
        let master_key = manifest_cache
            .and_then(|cache| {
                let cache = cache.lock().unwrap_or_else(|e| e.into_inner());
                let master = cache.master_key(&val.node_pubkey);
                if cache.is_revoked(&master) {
                    None
                } else {
                    Some(master)
                }
            })
            .unwrap_or_else(|| val.node_pubkey.clone());

        let trusted = effective_unl.iter().any(|key| key == &master_key) && val.verify_signature();
        trusted.then_some(master_key)
    }

    pub(super) async fn handle_validation_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if self.bootstrap_syncing_fast() {
            return PeerEvent::MessageReceived(MessageType::Validation, Vec::new());
        }

        if let Some(val) = crate::network::relay::decode_validation(&msg.payload) {
            debug!(
                "received validation ledger_seq={} from peer {:?}",
                val.ledger_seq, peer.id
            );

            let (round_validation_trusted, manifest_cache, effective_unl, original_unl_size) = {
                let state = self.state.read().await;
                let (mut effective_unl, original_unl_size) =
                    self.effective_unl_for_parent_ledger(&state);
                if effective_unl.is_empty() {
                    effective_unl = self.unl.read().unwrap_or_else(|e| e.into_inner()).clone();
                }
                (
                    state
                        .current_round
                        .as_ref()
                        .map(|round| round.validation_is_trusted(&val))
                        .unwrap_or(false),
                    state.ctx.manifest_cache.clone(),
                    effective_unl,
                    original_unl_size,
                )
            };
            let outside_round_master = if round_validation_trusted {
                None
            } else {
                self.trusted_validation_master_without_round(
                    manifest_cache.as_ref(),
                    &val,
                    &effective_unl,
                )
            };
            let validation_trusted = round_validation_trusted || outside_round_master.is_some();
            let mut should_request_base = false;
            let mut should_register_acquisition = false;
            {
                let mut state = self.state.write().await;
                state.implausible_validation_state.remove(&peer.id);

                let mut quorum_validated: Option<(u32, [u8; 32])> = None;
                let is_trusted = if let Some(ref mut round) = state.current_round {
                    let t = if validation_trusted {
                        if let Some(master_key) = outside_round_master.clone() {
                            round.add_prevalidated_validation_from_master(val.clone(), master_key)
                        } else {
                            round.add_prevalidated_validation(val.clone())
                        }
                    } else {
                        false
                    };
                    if t {
                        info!(
                            "consensus: accepted trusted validation for ledger {}",
                            val.ledger_seq
                        );
                        if let Some(hash) = round.check_validated_for(val.ledger_seq) {
                            quorum_validated = Some((val.ledger_seq, hash));
                        }
                    }
                    t
                } else {
                    if let Some(master_key) = outside_round_master.clone() {
                        let quorum = crate::consensus::validation_quorum_count(
                            effective_unl.len(),
                            Some(original_unl_size),
                        );
                        if let Some(decision) =
                            state.outside_round_validations.observe_trusted_validation(
                                master_key,
                                val.ledger_seq,
                                val.ledger_hash,
                                val.is_full(),
                                quorum,
                            )
                        {
                            quorum_validated = Some((decision.ledger_seq, decision.ledger_hash));
                        }
                        true
                    } else {
                        false
                    }
                };

                if let Some((seq, hash)) = quorum_validated {
                    state.record_validated_hash(seq, hash);
                } else if is_trusted {
                    debug!(
                        "consensus: observed trusted validation for ledger {} hash={} but not recording as validated without quorum",
                        val.ledger_seq,
                        hex::encode_upper(&val.ledger_hash[..8]),
                    );
                }

                if is_trusted && val.ledger_seq > state.ctx.ledger_seq {
                    should_register_acquisition = true;
                    if state.sync_done {
                        static LAST_BASE_REQ: std::sync::atomic::AtomicU64 =
                            std::sync::atomic::AtomicU64::new(0);
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let prev = LAST_BASE_REQ.load(std::sync::atomic::Ordering::Relaxed);
                        if now_secs >= prev + 3 {
                            LAST_BASE_REQ.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                            should_request_base = true;
                        }
                    }
                }
            }

            if should_register_acquisition {
                let mut guard = self
                    .inbound_ledgers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                guard.acquire(
                    val.ledger_hash,
                    val.ledger_seq,
                    crate::ledger::inbound::InboundReason::Consensus,
                );
            }

            if should_request_base {
                info!(
                    "peer {:?} validated ledger {} — requesting header",
                    peer.id, val.ledger_seq,
                );
                let cookie = crate::sync::next_cookie();
                let get_msg =
                    crate::network::relay::encode_get_ledger_base(&val.ledger_hash, cookie);
                let sent = {
                    let state = self.state.read().await;
                    let mut sent = 0;
                    if let Some(tx) = state.peer_txs.get(&peer.id) {
                        let _ = tx.try_send(get_msg.clone());
                        sent += 1;
                    }
                    for _ in 0..2 {
                        if let Some(pid) = self.next_sync_peer(&state) {
                            if pid != peer.id {
                                if let Some(tx) = state.peer_txs.get(&pid) {
                                    let _ = tx.try_send(get_msg.clone());
                                    sent += 1;
                                }
                            }
                        }
                    }
                    let tx_cookie = crate::sync::next_cookie();
                    let tx_msg = crate::network::relay::encode_get_ledger_txs_for_hash(
                        &val.ledger_hash,
                        tx_cookie,
                    );
                    for (&pid, ptx) in &state.peer_txs {
                        if sent >= 3 {
                            break;
                        }
                        let _ = ptx.try_send(tx_msg.clone());
                        sent += 1;
                        let _ = pid;
                    }
                    sent
                };
                info!(
                    "sent liBASE+liTX_NODE to {sent} peers for ledger {}",
                    val.ledger_seq
                );
                self.update_rpc_snapshot().await;
            }

            if !self.message_is_new(MessageType::Validation, &msg.payload) {
                return PeerEvent::MessageReceived(MessageType::Validation, msg.payload.clone());
            }
            let relay_msg = crate::network::relay::encode_validation(&val);
            let squelch_skipped = {
                let mut state = self.state.write().await;
                state.broadcast_with_squelch(&relay_msg, Some(peer.id), &val.node_pubkey)
            };
            if squelch_skipped > 0 {
                tracing::debug!(
                    "validation relay: skipped {} squelched peer(s) for validator {}...",
                    squelch_skipped,
                    &hex::encode_upper(&val.node_pubkey[..8.min(val.node_pubkey.len())]),
                );
            }
            let _ = self
                .ws_events
                .send(crate::rpc::ws::WsEvent::ValidationReceived {
                    validation: val.clone(),
                    network_id: self.config.network_id,
                });
            let _ = self.ws_events.send(crate::rpc::ws::WsEvent::PeerMessage {
                msg_type: "validation".into(),
                detail: format!("ledger_seq={} from {:?}", val.ledger_seq, peer.id),
            });
        }
        PeerEvent::MessageReceived(MessageType::Validation, msg.payload.clone())
    }

    pub(super) async fn handle_proposal_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if self.bootstrap_syncing_fast() {
            return PeerEvent::MessageReceived(MessageType::ProposeLedger, Vec::new());
        }

        if !self.message_is_new(MessageType::ProposeLedger, &msg.payload) {
            return PeerEvent::MessageReceived(MessageType::ProposeLedger, msg.payload.clone());
        }
        if let Some(mut prop) = crate::network::relay::decode_proposal(&msg.payload) {
            debug!(
                "received proposal seq={} from peer {:?}",
                prop.prop_seq, peer.id
            );
            let mut request_candidate: Option<[u8; 32]> = None;
            {
                let mut state = self.state.write().await;
                let next_seq = state.ctx.ledger_seq + 1;
                let staged_key = hex::encode(&prop.node_pubkey);
                let active_round = state
                    .current_round
                    .as_ref()
                    .map(|round| (round.ledger_seq, round.prev_ledger));
                let Some(inferred_ledger_seq) = infer_inbound_proposal_ledger_seq(
                    &prop,
                    state.ctx.ledger_seq,
                    state.ctx.ledger_header.hash,
                    active_round,
                ) else {
                    debug!(
                        "consensus: dropping proposal with parent {} outside active/current ledger",
                        hex::encode_upper(prop.previous_ledger)
                    );
                    return PeerEvent::MessageReceived(
                        MessageType::ProposeLedger,
                        msg.payload.clone(),
                    );
                };
                prop.ledger_seq = inferred_ledger_seq;
                if prop.prop_seq == crate::consensus::round::SEQ_LEAVE {
                    if let Some(round) = state.current_round.as_mut() {
                        let node_id = hex::encode(&prop.node_pubkey);
                        round.peer_bowed_out(&node_id);
                        info!("consensus: peer {} bowed out", &node_id[..16]);
                    } else {
                        info!("consensus: ignoring bow-out outside an active round");
                    }
                } else if state.current_round.as_ref().map(|round| round.ledger_seq)
                    == Some(prop.ledger_seq)
                {
                    if let Some(round) = state.current_round.as_mut() {
                        let local_candidate_hash = round.our_position;
                        let trusted = round.add_proposal(prop.clone());
                        if trusted {
                            round.add_close_time_vote(prop.close_time as u64);
                            if Some(prop.tx_set_hash) != local_candidate_hash {
                                request_candidate = Some(prop.tx_set_hash);
                            }
                        }
                    }
                } else if prop.ledger_seq == next_seq {
                    match state.staged_proposals.get(&staged_key) {
                        Some(existing) if existing.prop_seq >= prop.prop_seq => {}
                        _ => {
                            state.staged_proposals.insert(staged_key, prop.clone());
                        }
                    }
                }
            }
            if let Some(tx_set_hash) = request_candidate {
                self.request_candidate_tx_set(tx_set_hash).await;
            }
            let relay_msg = crate::network::relay::encode_proposal(&prop);
            self.state.read().await.broadcast(&relay_msg, Some(peer.id));
            let _ = self.ws_events.send(crate::rpc::ws::WsEvent::PeerMessage {
                msg_type: "proposal".into(),
                detail: format!("seq={} from {:?}", prop.prop_seq, peer.id),
            });
        }
        PeerEvent::MessageReceived(MessageType::ProposeLedger, msg.payload.clone())
    }

    pub(super) async fn handle_tx_set_candidate_message(
        self: &Arc<Self>,
        peer: &Peer,
        ld: &crate::proto::TmLedgerData,
    ) {
        if ld.r#type != crate::proto::TmLedgerInfoType::LiTsCandidate as i32 {
            return;
        }
        if ld.ledger_hash.len() != 32 {
            debug!(
                "dropping malformed liTS_CANDIDATE from {:?}: missing hash",
                peer.id
            );
            return;
        }

        let mut expected_hash = [0u8; 32];
        expected_hash.copy_from_slice(&ld.ledger_hash);
        let mut wire_nodes = Vec::with_capacity(ld.nodes.len());
        let mut wire_nodes_well_formed = true;
        for node in &ld.nodes {
            let Some(node_id) = node
                .nodeid
                .as_deref()
                .and_then(crate::ledger::shamap_id::SHAMapNodeID::from_wire)
            else {
                wire_nodes_well_formed = false;
                break;
            };
            wire_nodes.push((node_id, node.nodedata.as_slice()));
        }

        let blobs = if wire_nodes_well_formed && !wire_nodes.is_empty() {
            match import_candidate_tx_set_wire_nodes_with_partial_cache(expected_hash, wire_nodes) {
                crate::ledger::shamap_sync::CandidateTxSetWireImport::Complete(blobs) => blobs,
                crate::ledger::shamap_sync::CandidateTxSetWireImport::Incomplete { missing } => {
                    self.send_candidate_tx_set_missing_node_requests(
                        expected_hash,
                        peer.id,
                        missing,
                    )
                    .await;
                    return;
                }
                crate::ledger::shamap_sync::CandidateTxSetWireImport::Invalid(err) => {
                    debug!(
                        "liTS_CANDIDATE SHAMap import from {:?} failed validation: {:?}",
                        peer.id, err,
                    );
                    extract_candidate_tx_blobs(&ld.nodes)
                }
            }
        } else {
            extract_candidate_tx_blobs(&ld.nodes)
        };
        if blobs.is_empty() {
            debug!(
                "liTS_CANDIDATE from {:?} contained no raw transaction leaves",
                peer.id
            );
            return;
        }

        let computed =
            crate::ledger::pool::canonical_set_hash_from_blobs(blobs.iter().map(Vec::as_slice));
        if computed != expected_hash {
            debug!(
                "liTS_CANDIDATE hash mismatch from {:?}: expected={} computed={} leaves={}",
                peer.id,
                hex::encode_upper(&expected_hash[..8]),
                hex::encode_upper(&computed[..8]),
                blobs.len(),
            );
            return;
        }

        let imported = {
            let state = self.state.read().await;
            let result = state
                .ctx
                .consensus_tx_sets
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .import_acquired(expected_hash, blobs);
            result
        };
        let Ok(set) = imported else {
            debug!(
                "liTS_CANDIDATE import failed from {:?} after hash precheck",
                peer.id
            );
            return;
        };
        info!(
            "consensus: imported liTS_CANDIDATE tx_set={} txs={} from {:?}",
            hex::encode_upper(&expected_hash[..8]),
            set.len(),
            peer.id,
        );
    }

    pub(super) async fn handle_manifests_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if self.sync_runtime.bootstrap_active() || self.sync_runtime.sync_active() {
            return PeerEvent::MessageReceived(MessageType::Manifests, msg.payload.clone());
        }
        if !self.message_is_new(MessageType::Manifests, &msg.payload) {
            return PeerEvent::MessageReceived(MessageType::Manifests, msg.payload.clone());
        }
        let manifest_cache = {
            let state = self.state.read().await;
            state.ctx.manifest_cache.clone()
        };
        let raw_manifest_blobs = crate::network::relay::decode_manifest_blobs(&msg.payload);
        let total_manifests = raw_manifest_blobs.len();
        let manifests = if let Some(cache) = manifest_cache.as_ref() {
            let fresh_blobs = {
                let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
                raw_manifest_blobs
                    .into_iter()
                    .filter(|blob| cache.mark_blob_seen(blob))
                    .collect::<Vec<_>>()
            };
            collapse_manifest_batch(
                fresh_blobs
                    .into_iter()
                    .filter_map(|blob| crate::consensus::Manifest::from_bytes(&blob).ok())
                    .collect(),
            )
        } else {
            collapse_manifest_batch(crate::network::relay::decode_manifests(&msg.payload))
        };
        let mut accepted_manifests = Vec::with_capacity(manifests.len());
        if let Some(cache) = manifest_cache.as_ref() {
            let candidates = {
                let cache = cache.lock().unwrap_or_else(|e| e.into_inner());
                manifests
                    .into_iter()
                    .filter(|manifest| {
                        manifest.sequence
                            > cache.current_sequence_for_master(&manifest.master_pubkey)
                    })
                    .collect::<Vec<_>>()
            };
            let verified = candidates
                .into_iter()
                .filter(|manifest| manifest.verify())
                .collect::<Vec<_>>();
            let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
            for manifest in verified {
                if cache.add_prevalidated(manifest.clone()) {
                    accepted_manifests.push(manifest);
                }
            }
        } else {
            accepted_manifests.extend(manifests);
        }
        let suppressed = total_manifests.saturating_sub(accepted_manifests.len());
        let ws_has_receivers = self.ws_events.receiver_count() > 0;
        if !accepted_manifests.is_empty() {
            let mut state = self.state.write().await;
            if let Some(ref mut round) = state.current_round {
                for manifest in &accepted_manifests {
                    let _ = round.add_prevalidated_manifest(manifest.clone());
                }
            }
        }
        if !accepted_manifests.is_empty() {
            debug!(
                "accepted {}/{} manifests from peer {:?}",
                accepted_manifests.len(),
                total_manifests,
                peer.id
            );
        }
        if suppressed > 0 {
            debug!(
                "suppressed {} stale/duplicate/invalid manifests from peer {:?}",
                suppressed, peer.id
            );
        }
        if ws_has_receivers {
            for manifest in &accepted_manifests {
                let _ = self
                    .ws_events
                    .send(crate::rpc::ws::WsEvent::ManifestReceived {
                        manifest: manifest.clone(),
                    });
            }
        }
        if !accepted_manifests.is_empty() {
            let relay_msg = crate::network::relay::encode_manifests(&accepted_manifests);
            self.state.read().await.broadcast(&relay_msg, Some(peer.id));
            if ws_has_receivers {
                let _ = self.ws_events.send(crate::rpc::ws::WsEvent::PeerMessage {
                    msg_type: "manifest".into(),
                    detail: format!("accepted={} from {:?}", accepted_manifests.len(), peer.id),
                });
            }
        }
        PeerEvent::MessageReceived(MessageType::Manifests, msg.payload.clone())
    }

    pub(super) async fn handle_validator_list_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if self.sync_runtime.bootstrap_active() || self.sync_runtime.sync_active() {
            return PeerEvent::MessageReceived(MessageType::ValidatorList, msg.payload.clone());
        }
        if let Some(vl) = crate::network::relay::decode_validator_list(&msg.payload) {
            let publisher_keys: Vec<String> = self.validator_list_config.publisher_keys.clone();
            match crate::validator_list::verify_peer_validator_list(
                &vl.manifest,
                &vl.blob,
                &vl.signature,
                &publisher_keys,
            ) {
                Ok(list) => {
                    if let Some(update) = crate::validator_list::install_validator_list(
                        &self.validator_list_state,
                        &self.unl,
                        list,
                    ) {
                        info!(
                            "updated UNL from peer validator list (seq={}, {} validators, active_publishers={}, publisher={})",
                            update.sequence,
                            update.effective_unl.len(),
                            update.active_publishers,
                            &update.publisher_key[..16.min(update.publisher_key.len())],
                        );
                    } else {
                        debug!("peer validator list ignored (stale sequence or expired list)");
                    }
                }
                Err(e) => {
                    debug!("peer validator list rejected: {e}");
                }
            }
            let relay_msg = RtxpMessage::new(MessageType::ValidatorList, msg.payload.clone());
            self.state.read().await.broadcast(&relay_msg, Some(peer.id));
        }
        PeerEvent::MessageReceived(MessageType::ValidatorList, msg.payload.clone())
    }

    pub(super) async fn handle_validator_list_collection_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if self.sync_runtime.bootstrap_active() || self.sync_runtime.sync_active() {
            return PeerEvent::MessageReceived(
                MessageType::ValidatorListCollection,
                msg.payload.clone(),
            );
        }
        if let Some((shared_manifest, blobs)) =
            crate::network::relay::decode_validator_list_collection(&msg.payload)
        {
            let publisher_keys: Vec<String> = self.validator_list_config.publisher_keys.clone();
            for vl_blob in &blobs {
                let manifest = vl_blob.manifest.as_deref().unwrap_or(&shared_manifest);
                match crate::validator_list::verify_peer_validator_list(
                    manifest,
                    &vl_blob.blob,
                    &vl_blob.signature,
                    &publisher_keys,
                ) {
                    Ok(list) => {
                        if let Some(update) = crate::validator_list::install_validator_list(
                            &self.validator_list_state,
                            &self.unl,
                            list,
                        ) {
                            info!(
                                "updated UNL from peer validator list collection (seq={}, {} validators, active_publishers={}, publisher={})",
                                update.sequence,
                                update.effective_unl.len(),
                                update.active_publishers,
                                &update.publisher_key[..16.min(update.publisher_key.len())],
                            );
                        } else {
                            debug!(
                                "peer validator list collection blob ignored (stale sequence or expired list)"
                            );
                        }
                    }
                    Err(e) => {
                        debug!("peer validator list collection blob rejected: {e}");
                    }
                }
            }
            let relay_msg =
                RtxpMessage::new(MessageType::ValidatorListCollection, msg.payload.clone());
            self.state.read().await.broadcast(&relay_msg, Some(peer.id));
        }
        PeerEvent::MessageReceived(MessageType::ValidatorListCollection, msg.payload.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        infer_inbound_proposal_ledger_seq, select_candidate_tx_set_followup_peers,
        CANDIDATE_TX_SET_MISSING_NODE_FANOUT,
    };
    use crate::network::peer::PeerId;

    fn proposal_with_parent(previous_ledger: [u8; 32]) -> crate::consensus::Proposal {
        crate::consensus::Proposal::new_unsigned(
            0,
            [0xAA; 32],
            previous_ledger,
            1,
            0,
            vec![0x02; 33],
        )
    }

    #[test]
    fn infers_decoded_proposal_for_active_round_from_previous_ledger() {
        let current_hash = [0x11; 32];
        let active_parent = [0x22; 32];
        let prop = proposal_with_parent(active_parent);

        assert_eq!(
            infer_inbound_proposal_ledger_seq(&prop, 9, current_hash, Some((9, active_parent))),
            Some(9)
        );
    }

    #[test]
    fn stages_decoded_proposal_for_next_round_when_parent_is_current_head() {
        let current_hash = [0x11; 32];
        let active_parent = [0x22; 32];
        let prop = proposal_with_parent(current_hash);

        assert_eq!(
            infer_inbound_proposal_ledger_seq(&prop, 9, current_hash, Some((9, active_parent))),
            Some(10)
        );
    }

    #[test]
    fn rejects_decoded_proposal_for_unknown_parent() {
        let current_hash = [0x11; 32];
        let active_parent = [0x22; 32];
        let prop = proposal_with_parent([0x33; 32]);

        assert_eq!(
            infer_inbound_proposal_ledger_seq(&prop, 9, current_hash, Some((9, active_parent))),
            None
        );
    }

    #[test]
    fn decoded_proposal_with_inferred_seq_is_accepted_by_active_round() {
        let validator = crate::crypto::keys::Secp256k1KeyPair::generate();
        let active_parent = [0x22; 32];
        let original =
            crate::consensus::Proposal::new_signed(10, [0xAA; 32], active_parent, 1, 0, &validator);
        let msg = crate::network::relay::encode_proposal(&original);
        let mut decoded =
            crate::network::relay::decode_proposal(&msg.payload).expect("proposal decodes");
        assert_eq!(decoded.ledger_seq, 0);

        decoded.ledger_seq =
            infer_inbound_proposal_ledger_seq(&decoded, 9, [0x11; 32], Some((10, active_parent)))
                .expect("active round sequence inferred");
        let mut round = crate::consensus::ConsensusRound::new(
            10,
            vec![validator.public_key_bytes()],
            active_parent,
            true,
            std::time::Duration::from_secs(4),
            0,
        );

        assert!(round.add_proposal(decoded));
    }

    #[test]
    fn candidate_followup_peers_prefer_responder_then_rotated_fanout() {
        let peers = vec![PeerId(4), PeerId(1), PeerId(3), PeerId(2), PeerId(5)];

        let selected = select_candidate_tx_set_followup_peers(
            peers,
            PeerId(3),
            CANDIDATE_TX_SET_MISSING_NODE_FANOUT,
            2,
        );

        assert_eq!(selected, vec![PeerId(3), PeerId(4), PeerId(5), PeerId(1)]);
    }

    #[test]
    fn candidate_followup_peers_dedup_and_skip_missing_responder() {
        let peers = vec![PeerId(2), PeerId(2), PeerId(4), PeerId(1)];

        let selected = select_candidate_tx_set_followup_peers(peers, PeerId(9), 3, 1);

        assert_eq!(selected, vec![PeerId(2), PeerId(4), PeerId(1)]);
    }
}

fn collapse_manifest_batch(
    manifests: Vec<crate::consensus::Manifest>,
) -> Vec<crate::consensus::Manifest> {
    let mut newest_by_master = std::collections::HashMap::<Vec<u8>, usize>::new();
    let mut collapsed: Vec<crate::consensus::Manifest> = Vec::with_capacity(manifests.len());
    for manifest in manifests {
        match newest_by_master.get(&manifest.master_pubkey).copied() {
            Some(existing_index) => {
                if manifest.sequence > collapsed[existing_index].sequence {
                    collapsed[existing_index] = manifest;
                }
            }
            None => {
                newest_by_master.insert(manifest.master_pubkey.clone(), collapsed.len());
                collapsed.push(manifest);
            }
        }
    }
    collapsed
}
