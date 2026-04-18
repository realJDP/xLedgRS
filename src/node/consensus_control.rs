use super::*;

impl Node {
    pub(super) async fn handle_validation_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Some(val) = crate::network::relay::decode_validation(&msg.payload) {
            debug!(
                "received validation ledger_seq={} from peer {:?}",
                val.ledger_seq, peer.id
            );

            let round_validation_trusted = {
                let state = self.state.read().await;
                state
                    .current_round
                    .as_ref()
                    .map(|round| round.validation_is_trusted(&val))
                    .unwrap_or(false)
            };
            let mut should_request_base = false;
            let mut should_register_acquisition = false;
            {
                let mut state = self.state.write().await;

                let peer_range_ok = state
                    .peer_ledger_range
                    .get(&peer.id)
                    .map(|(first, last)| {
                        let lower = first.saturating_sub(1024);
                        let upper = last.saturating_add(1024);
                        val.ledger_seq >= lower && val.ledger_seq <= upper
                    })
                    .unwrap_or(true);
                let follower_anchor = state
                    .follower_state
                    .as_ref()
                    .map(|fs| fs.current_seq.load(std::sync::atomic::Ordering::Relaxed))
                    .unwrap_or(0);
                let history_anchor = state
                    .ctx
                    .history
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .latest_ledger()
                    .map(|l| l.header.sequence)
                    .unwrap_or(0);
                let peer_anchor = state
                    .peer_ledger_range
                    .values()
                    .map(|(_, last)| *last)
                    .max()
                    .unwrap_or(0);
                let anchor = peer_anchor.max(follower_anchor).max(history_anchor);
                let anchor_ok = if anchor > 0 {
                    val.ledger_seq >= anchor.saturating_sub(100_000)
                        && val.ledger_seq <= anchor.saturating_add(100_000)
                } else {
                    true
                };
                let plausible = peer_range_ok && anchor_ok;
                if !plausible {
                    let now = std::time::Instant::now();
                    let entry = state
                        .implausible_validation_state
                        .entry(peer.id)
                        .or_insert((now, 0));
                    if now.duration_since(entry.0) > std::time::Duration::from_secs(30) {
                        *entry = (now, 1);
                    } else {
                        entry.0 = now;
                        entry.1 = entry.1.saturating_add(1);
                    }
                    let repeats = entry.1;
                    debug!(
                        "ignoring implausible validation seq={} from peer {:?} (peer_range_ok={} anchor={} follower={} history={} repeats={})",
                        val.ledger_seq, peer.id, peer_range_ok, anchor, follower_anchor, history_anchor, repeats,
                    );
                    {
                        static IMPLAUSIBLE_COUNT: std::sync::atomic::AtomicU64 =
                            std::sync::atomic::AtomicU64::new(0);
                        static LAST_SUMMARY: std::sync::atomic::AtomicU64 =
                            std::sync::atomic::AtomicU64::new(0);
                        let count =
                            IMPLAUSIBLE_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                                + 1;
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let prev = LAST_SUMMARY.load(std::sync::atomic::Ordering::Relaxed);
                        if now_secs >= prev + 30 {
                            LAST_SUMMARY.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                            info!("suppressed {} implausible validations in last 30s", count);
                            IMPLAUSIBLE_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    if repeats >= 10 {
                        let expires = now + std::time::Duration::from_secs(600);
                        state.sync_peer_cooldown.insert(peer.id, expires);
                        let _ = state.services.resource_manager.charge_consumer(
                            &peer.resource_consumer,
                            6_000,
                            "implausible_validation",
                            now,
                        );
                    } else if repeats >= 5 {
                        let _ = state.services.resource_manager.charge_consumer(
                            &peer.resource_consumer,
                            4_000,
                            "implausible_validation",
                            now,
                        );
                    }
                } else {
                    state.implausible_validation_state.remove(&peer.id);
                }

                let is_trusted = if let Some(ref mut round) = state.current_round {
                    let t = if round_validation_trusted {
                        round.add_prevalidated_validation(val.clone())
                    } else {
                        false
                    };
                    if t {
                        info!(
                            "consensus: accepted trusted validation for ledger {}",
                            val.ledger_seq
                        );
                    }
                    t && plausible
                } else {
                    plausible
                };

                if is_trusted {
                    state.record_validated_hash(val.ledger_seq, val.ledger_hash);
                }

                if is_trusted && val.ledger_seq > state.ctx.ledger_seq {
                    state.ctx.ledger_seq = val.ledger_seq;
                    state.ctx.ledger_hash = hex::encode_upper(val.ledger_hash);
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
        if !self.message_is_new(MessageType::ProposeLedger, &msg.payload) {
            return PeerEvent::MessageReceived(MessageType::ProposeLedger, msg.payload.clone());
        }
        if let Some(prop) = crate::network::relay::decode_proposal(&msg.payload) {
            debug!(
                "received proposal seq={} from peer {:?}",
                prop.prop_seq, peer.id
            );
            {
                let mut state = self.state.write().await;
                let next_seq = state.ctx.ledger_seq + 1;
                let staged_key = hex::encode(&prop.node_pubkey);
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
                        let trusted = round.add_proposal(prop.clone());
                        if trusted {
                            round.add_close_time_vote(prop.close_time as u64);
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
            let relay_msg = crate::network::relay::encode_proposal(&prop);
            self.state.read().await.broadcast(&relay_msg, Some(peer.id));
            let _ = self.ws_events.send(crate::rpc::ws::WsEvent::PeerMessage {
                msg_type: "proposal".into(),
                detail: format!("seq={} from {:?}", prop.prop_seq, peer.id),
            });
        }
        PeerEvent::MessageReceived(MessageType::ProposeLedger, msg.payload.clone())
    }

    pub(super) async fn handle_manifests_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
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
                suppressed,
                peer.id
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
                    detail: format!(
                        "accepted={} from {:?}",
                        accepted_manifests.len(),
                        peer.id
                    ),
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
