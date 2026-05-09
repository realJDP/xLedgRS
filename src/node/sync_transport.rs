use super::*;

impl Node {
    pub(super) async fn handle_get_ledger_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Ok(req) = <crate::proto::TmGetLedger as ProstMessage>::decode(msg.payload.as_slice())
        {
            let (
                current,
                peer_tx,
                history_arc,
                ledger_state_arc,
                tx_pool_arc,
                tx_sets_arc,
                load_snapshot,
            ) = {
                let state = self.state.read().await;
                (
                    state.ctx.ledger_header.clone(),
                    state.peer_txs.get(&peer.id).cloned(),
                    state.ctx.history.clone(),
                    state.ctx.ledger_state.clone(),
                    state.ctx.tx_pool.clone(),
                    state.ctx.consensus_tx_sets.clone(),
                    state.services.load_manager.snapshot(),
                )
            };
            let cookie = req.request_cookie.map(|c| c as u32);
            let requested_hash = requested_get_ledger_hash(&req)
                .ok()
                .flatten()
                .unwrap_or([0u8; 32]);
            let requested_seq = req.ledger_seq.unwrap_or(0);

            if let Some(tx) = peer_tx {
                if req.itype == crate::proto::TmLedgerInfoType::LiTsCandidate as i32 {
                    let reply = build_tx_set_candidate_reply(&tx_sets_arc, &tx_pool_arc, &req);
                    let _ = tx.try_send(reply);
                    return PeerEvent::MessageReceived(MessageType::GetLedger, msg.payload.clone());
                }
                if should_refuse_get_ledger_for_load(&load_snapshot, Some(tx.capacity()), req.itype)
                {
                    let reply = crate::network::relay::encode_ledger_data_error(
                        &requested_hash,
                        requested_seq,
                        req.itype,
                        cookie,
                        crate::proto::TmReplyError::ReNoLedger,
                    );
                    let _ = tx.try_send(reply);
                    debug!(
                        "GetLedger load-refused from {:?}: type={} seq={} hash={} local_fee={} queue_overloaded={} send_capacity={}",
                        peer.id,
                        req.itype,
                        requested_seq,
                        hex::encode_upper(&requested_hash[..8]),
                        load_snapshot.local_fee,
                        load_snapshot.queue_overloaded,
                        tx.capacity(),
                    );
                    return PeerEvent::MessageReceived(MessageType::GetLedger, msg.payload.clone());
                }

                let history = history_arc.read().unwrap_or_else(|e| e.into_inner());
                let header = match resolve_get_ledger_header(&req, &current, &history) {
                    Ok(header) => header,
                    Err(err) => {
                        if should_send_ledger_data_error(err) {
                            let reply = crate::network::relay::encode_ledger_data_error(
                                &requested_hash,
                                requested_seq,
                                req.itype,
                                cookie,
                                err,
                            );
                            let _ = tx.try_send(reply);
                        }
                        debug!(
                            "GetLedger bad request from {:?}: type={} ltype={:?} seq={} hash_len={}",
                            peer.id,
                            req.itype,
                            req.ltype,
                            requested_seq,
                            req.ledger_hash.as_ref().map(|hash| hash.len()).unwrap_or(0),
                        );
                        return PeerEvent::MessageReceived(
                            MessageType::GetLedger,
                            msg.payload.clone(),
                        );
                    }
                };
                if header.sequence <= 1 {
                    debug!(
                        "GetLedger miss from {:?}: type={} seq={} hash={}",
                        peer.id,
                        req.itype,
                        requested_seq,
                        hex::encode_upper(&requested_hash[..8]),
                    );
                    return PeerEvent::MessageReceived(MessageType::GetLedger, msg.payload.clone());
                }

                match req.itype {
                    x if x == crate::proto::TmLedgerInfoType::LiBase as i32 => {
                        let state_root_wire = {
                            let mut ledger_state =
                                ledger_state_arc.lock().unwrap_or_else(|e| e.into_inner());
                            let mut state_map = if header.hash == current.hash
                                && header.sequence == current.sequence
                            {
                                Some(ledger_state.peer_state_map_snapshot())
                            } else {
                                ledger_state.historical_state_map_from_root(header.account_hash)
                            };
                            state_map.as_mut().and_then(|map| {
                                map.get_wire_node_by_id(
                                    &crate::ledger::shamap_id::SHAMapNodeID::root(),
                                )
                            })
                        };

                        let tx_root_wire = if header.transaction_hash == [0u8; 32] {
                            None
                        } else {
                            let tx_records = history_arc
                                .read()
                                .unwrap_or_else(|e| e.into_inner())
                                .ledger_txs(header.sequence);
                            let mut tx_map = build_transaction_shamap_from_history(tx_records);
                            tx_map.get_wire_node_by_id(
                                &crate::ledger::shamap_id::SHAMapNodeID::root(),
                            )
                        };

                        let response = crate::proto::TmLedgerData {
                            ledger_hash: header.hash.to_vec(),
                            ledger_seq: header.sequence,
                            r#type: crate::proto::TmLedgerInfoType::LiBase as i32,
                            nodes: build_li_base_nodes(&header, state_root_wire, tx_root_wire),
                            request_cookie: cookie,
                            error: None,
                        };

                        let reply =
                            RtxpMessage::new(MessageType::LedgerData, response.encode_to_vec());
                        let _ = tx.try_send(reply);
                        info!(
                            "served liBASE to {:?} (ledger {})",
                            peer.id, header.sequence
                        );
                    }
                    x if x == crate::proto::TmLedgerInfoType::LiTxNode as i32 => {
                        let tx_records = history_arc
                            .read()
                            .unwrap_or_else(|e| e.into_inner())
                            .ledger_txs(header.sequence);
                        let node_ids: Vec<Vec<u8>> = if req.node_i_ds.is_empty() {
                            vec![vec![0u8; 33]]
                        } else {
                            req.node_i_ds.clone()
                        };
                        let query_depth = req.query_depth.unwrap_or(0);
                        let mut tx_map = build_transaction_shamap_from_history(tx_records);
                        let (nodes, invalid_node_ids) =
                            collect_shamap_ledger_nodes(&mut tx_map, &node_ids, query_depth);

                        if !nodes.is_empty() {
                            let response = crate::proto::TmLedgerData {
                                ledger_hash: header.hash.to_vec(),
                                ledger_seq: header.sequence,
                                r#type: crate::proto::TmLedgerInfoType::LiTxNode as i32,
                                nodes,
                                request_cookie: cookie,
                                error: None,
                            };

                            let reply =
                                RtxpMessage::new(MessageType::LedgerData, response.encode_to_vec());
                            let _ = tx.try_send(reply);
                            info!(
                                "served liTX_NODE to {:?} (ledger {})",
                                peer.id, header.sequence
                            );
                        } else {
                            if invalid_node_ids == node_ids.len() {
                                let reply = crate::network::relay::encode_ledger_data_error(
                                    &header.hash,
                                    header.sequence,
                                    crate::proto::TmLedgerInfoType::LiTxNode as i32,
                                    cookie,
                                    crate::proto::TmReplyError::ReBadRequest,
                                );
                                let _ = tx.try_send(reply);
                            }
                        }
                    }
                    x if x == crate::proto::TmLedgerInfoType::LiAsNode as i32 => {
                        let is_current =
                            header.hash == current.hash && header.sequence == current.sequence;
                        let node_ids: Vec<Vec<u8>> = if req.node_i_ds.is_empty() {
                            vec![vec![0u8; 33]]
                        } else {
                            req.node_i_ds.clone()
                        };
                        let query_depth = req.query_depth.unwrap_or(0);
                        let Some(mut requested_state_map) = ({
                            let mut ls = ledger_state_arc.lock().unwrap_or_else(|e| e.into_inner());
                            if is_current {
                                Some(ls.peer_state_map_snapshot())
                            } else {
                                ls.historical_state_map_from_root(header.account_hash)
                            }
                        }) else {
                            debug!(
                                "GetLedger liAS_NODE unavailable for ledger {} from {:?}",
                                header.sequence, peer.id,
                            );
                            return PeerEvent::MessageReceived(
                                MessageType::GetLedger,
                                msg.payload.clone(),
                            );
                        };
                        let (nodes, invalid_node_ids) = collect_shamap_ledger_nodes(
                            &mut requested_state_map,
                            &node_ids,
                            query_depth,
                        );

                        if !nodes.is_empty() {
                            let response = crate::proto::TmLedgerData {
                                ledger_hash: header.hash.to_vec(),
                                ledger_seq: header.sequence,
                                r#type: crate::proto::TmLedgerInfoType::LiAsNode as i32,
                                nodes,
                                request_cookie: cookie,
                                error: None,
                            };

                            let reply =
                                RtxpMessage::new(MessageType::LedgerData, response.encode_to_vec());
                            let _ = tx.try_send(reply);
                            info!(
                                "served liAS_NODE to {:?} (ledger {}, {})",
                                peer.id,
                                header.sequence,
                                if is_current { "current" } else { "historical" },
                            );
                        } else {
                            if invalid_node_ids == node_ids.len() {
                                let reply = crate::network::relay::encode_ledger_data_error(
                                    &header.hash,
                                    header.sequence,
                                    crate::proto::TmLedgerInfoType::LiAsNode as i32,
                                    cookie,
                                    crate::proto::TmReplyError::ReBadRequest,
                                );
                                let _ = tx.try_send(reply);
                            }
                        }
                    }
                    _ => {
                        let reply = crate::network::relay::encode_ledger_data_error(
                            &requested_hash,
                            requested_seq,
                            req.itype,
                            cookie,
                            crate::proto::TmReplyError::ReBadRequest,
                        );
                        let _ = tx.try_send(reply);
                    }
                }
            }
        }
        PeerEvent::MessageReceived(MessageType::GetLedger, msg.payload.clone())
    }

    pub(super) async fn handle_get_objects_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Ok(pb) =
            <crate::proto::TmGetObjectByHash as ProstMessage>::decode(msg.payload.as_slice())
        {
            if pb.query {
                let mut reply_objects = Vec::new();
                let object_type = get_objects_node_type(pb.r#type);

                for obj in &pb.objects {
                    let Some(ref hash) = obj.hash else {
                        continue;
                    };
                    if hash.len() != 32 {
                        continue;
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(hash);

                    let data = match object_type {
                        Some(object_type) => {
                            let fetched = if matches!(
                                crate::proto::tm_get_object_by_hash::ObjectType::try_from(
                                    pb.r#type
                                ),
                                Ok(crate::proto::tm_get_object_by_hash::ObjectType::OtFetchPack)
                            ) {
                                let state = self.state.read().await;
                                state.services.fetch_pack.as_ref().and_then(|fetch_pack| {
                                    crate::ledger::node_store::NodeStore::fetch(
                                        fetch_pack.as_ref(),
                                        &key,
                                    )
                                    .ok()
                                    .flatten()
                                })
                            } else {
                                None
                            };
                            fetched
                                .or_else(|| {
                                    self.nudb_backend
                                        .as_ref()
                                        .and_then(|backend| backend.fetch(&key).ok().flatten())
                                })
                                .and_then(|data| {
                                    crate::sync::store_to_object_reply_typed(object_type, &data)
                                })
                        }
                        None => self
                            .storage
                            .as_ref()
                            .and_then(|store| store.lookup_raw_tx(hash)),
                    };

                    if let Some(data) = data {
                        reply_objects.push(crate::proto::TmIndexedObject {
                            hash: Some(hash.clone()),
                            data: Some(data),
                            node_id: None,
                            index: obj.node_id.clone().or_else(|| obj.index.clone()),
                            ledger_seq: obj.ledger_seq,
                        });
                    }
                }

                let served = reply_objects.len();
                let reply = crate::proto::TmGetObjectByHash {
                    r#type: pb.r#type,
                    query: false,
                    ledger_hash: pb.ledger_hash.clone(),
                    fat: None,
                    objects: reply_objects,
                };

                let reply_msg = RtxpMessage::new(MessageType::GetObjects, reply.encode_to_vec());
                let state = self.state.read().await;
                if let Some(tx) = state.peer_txs.get(&peer.id) {
                    let _ = tx.try_send(reply_msg);
                }
                info!(
                    "served {}/{} objects to {:?}",
                    served,
                    pb.objects.len(),
                    peer.id
                );
            } else {
                let fetch_pack = {
                    let state = self.state.read().await;
                    state.services.fetch_pack.clone()
                };
                let inbound_ledgers = {
                    let state = self.state.read().await;
                    state.services.inbound_ledgers.clone()
                };
                let object_type = get_objects_node_type(pb.r#type);
                let backend = self.nudb_backend.clone();
                let objects_for_import = pb.objects.clone();
                let import_outcome = match tokio::task::spawn_blocking(move || {
                    import_get_objects_reply(fetch_pack, backend, object_type, objects_for_import)
                })
                .await
                {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        warn!("GetObjects import worker panicked: {}", err);
                        GetObjectsImportOutcome::default()
                    }
                };
                let import_result = import_outcome.summary;
                if import_result.imported > 0 {
                    if let Some(inbound_ledgers) = inbound_ledgers {
                        inbound_ledgers
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .got_fetch_pack();
                    };
                }
                if let Some(result) = import_outcome.breakdown.as_ref() {
                    if result.normalize_reject > 0
                        || result.hash_mismatch > 0
                        || result.missing_hash > 0
                        || result.bad_hash_len > 0
                        || result.missing_data > 0
                    {
                        warn!(
                            "GetObjects decode/store breakdown: raw={} missing_hash={} bad_hash_len={} missing_data={} normalize_reject={} hash_mismatch={} store_errors={} unchecked_fallbacks={} peer={:?}",
                            result.raw_objects,
                            result.missing_hash,
                            result.bad_hash_len,
                            result.missing_data,
                            result.normalize_reject,
                            result.hash_mismatch,
                            result.persist_errors,
                            result.unchecked_fallbacks,
                            peer.id,
                        );
                    }
                }
                let stored_count = import_result.persisted;
                let duplicate_count = import_result.duplicates;
                let store_errors = import_result.persist_errors;
                let unchecked_fallbacks = import_result.unchecked_fallbacks;
                if unchecked_fallbacks > 0 {
                    warn!(
                        "GetObjects import used {} unchecked fallback(s) for peer {:?}",
                        unchecked_fallbacks, peer.id,
                    );
                }
                if store_errors > 0 {
                    warn!(
                        "GetObjects import saw {} persistence error(s) for peer {:?}",
                        store_errors, peer.id,
                    );
                } else if let Some(err) = import_result.last_error.as_ref() {
                    debug!("GetObjects import last error: {}", err);
                }

                let accepted_by_gate =
                    self.sync_runtime
                        .gate_accepts_response(pb.ledger_hash.as_deref(), None, true);

                if accepted_by_gate {
                    info!(
                        "queuing object response from {:?}: count={}",
                        peer.id,
                        pb.objects.len(),
                    );

                    let sync_arc_object = self.sync_runtime.sync_arc();
                    let object_resp_hash = pb.ledger_hash.clone();
                    let stored_count_for_followup = stored_count;
                    let (accepted_object, object_followup_reqs, object_followup_seq) =
                        match tokio::task::spawn_blocking(move || {
                            let outcome = {
                                let mut guard =
                                    sync_arc_object.lock().unwrap_or_else(|e| e.into_inner());
                                let Some(syncer) = guard.as_mut() else {
                                    return (false, Vec::new(), 0u32);
                                };
                                syncer.handle_object_response(
                                    object_resp_hash.as_deref().unwrap_or_default(),
                                    None,
                                    stored_count_for_followup,
                                )
                            };
                            if !outcome.accepted || stored_count_for_followup == 0 {
                                return (outcome.accepted, Vec::new(), outcome.sync_seq);
                            };
                            let followup = crate::sync_epoch::build_reply_followup_requests(
                                sync_arc_object,
                                crate::ledger::inbound::REPLY_FOLLOWUP_PEERS,
                            );
                            (outcome.accepted, followup.reqs, followup.sync_seq)
                        })
                        .await
                        {
                            Ok(result) => result,
                            Err(err) => {
                                warn!("GetObjects follow-up worker panicked: {}", err);
                                (false, Vec::new(), 0u32)
                            }
                        };

                    info!(
                        "GetObjects response: accepted={} stored={} duplicates={} raw_objects={} from {:?}",
                        accepted_object,
                        stored_count,
                        duplicate_count,
                        pb.objects.len(),
                        peer.id,
                    );
                    self.sync_runtime.note_object_fallback_response(
                        accepted_object,
                        stored_count,
                        duplicate_count,
                        pb.objects.len(),
                    );
                    if accepted_object && stored_count == 0 && pb.objects.is_empty() {
                        let mut state = self.state.write().await;
                        let expires = std::time::Instant::now()
                            + std::time::Duration::from_millis(
                                self.config
                                    .sync_tuning
                                    .object_fallback_empty_peer_cooldown_ms,
                            );
                        state.sync_peer_cooldown.insert(peer.id, expires);
                        info!(
                            "GetObjects empty response: benched {:?} for {}ms to rotate timeout rescue peers",
                            peer.id,
                            self.config
                                .sync_tuning
                                .object_fallback_empty_peer_cooldown_ms,
                        );
                    }
                    if !object_followup_reqs.is_empty() {
                        let target_peers = {
                            let state = self.state.read().await;
                            self.select_sync_peers(
                                &state,
                                object_followup_seq,
                                object_followup_reqs.len(),
                            )
                        };

                        if target_peers.is_empty() {
                            for req in &object_followup_reqs {
                                self.sync_send_request(req, object_followup_seq, None).await;
                            }
                        } else {
                            for (i, req) in object_followup_reqs.iter().enumerate() {
                                let pid = target_peers[i % target_peers.len()];
                                self.sync_send_request(req, object_followup_seq, Some(pid))
                                    .await;
                            }
                        }

                        info!(
                            "GetObjects follow-up: reqs={} peers={} sync_seq={}",
                            object_followup_reqs.len(),
                            target_peers.len(),
                            object_followup_seq,
                        );
                    }
                } else {
                    self.sync_runtime.note_object_fallback_response(
                        false,
                        stored_count,
                        duplicate_count,
                        pb.objects.len(),
                    );
                    debug!(
                        "ignoring object response from {:?}: accepted={} count={} stored={} duplicates={}",
                        peer.id,
                        accepted_by_gate,
                        pb.objects.len(),
                        stored_count,
                        duplicate_count,
                    );
                }
            }
        }
        PeerEvent::MessageReceived(MessageType::GetObjects, msg.payload.clone())
    }

    pub(super) async fn handle_tx_node_message(
        self: &Arc<Self>,
        peer: &Peer,
        ld: &crate::proto::TmLedgerData,
    ) {
        if let Err(reason) = crate::sync::validate_ledger_data_nodes(
            ld,
            crate::proto::TmLedgerInfoType::LiTxNode as i32,
        ) {
            debug!(
                "dropping malformed liTX_NODE from {:?}: {} nodes={}",
                peer.id,
                reason,
                ld.nodes.len()
            );
            return;
        }

        let hash: [u8; 32] = if ld.ledger_hash.len() == 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&ld.ledger_hash);
            h
        } else {
            [0u8; 32]
        };
        {
            let mut guard = self
                .inbound_ledgers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let had_acquisition = guard.find(&hash).is_some();
            let routed = guard.got_tx_data(&hash, &ld.nodes);
            if !had_acquisition && !ld.nodes.is_empty() {
                debug!(
                    "liTX_NODE buffered before header/acquire: hash={} seq={} nodes={} pending_acquisitions={}",
                    hex::encode_upper(&hash[..8]), ld.ledger_seq, ld.nodes.len(), guard.len(),
                );
            } else if !routed && !ld.nodes.is_empty() {
                debug!(
                    "liTX_NODE merged but acquisition still incomplete: hash={} seq={} nodes={} pending_acquisitions={}",
                    hex::encode_upper(&hash[..8]), ld.ledger_seq, ld.nodes.len(), guard.len(),
                );
            }
        }

        let mut tx_blobs: Vec<Vec<u8>> = Vec::new();
        for node in &ld.nodes {
            let data = &node.nodedata;
            if data.len() < 10 {
                continue;
            }

            let wire_type = data[data.len() - 1];
            let payload = &data[..data.len() - 1];
            if wire_type == 0x02 || wire_type == 0x03 {
                continue;
            }

            if wire_type == 0x04 && payload.len() > 32 {
                let item_data = &payload[..payload.len() - 32];
                let (tx_len, vl_bytes) = crate::transaction::serialize::decode_length(item_data);
                let tx_start = vl_bytes;
                let tx_end = tx_start + tx_len;
                if tx_end <= item_data.len() {
                    tx_blobs.push(item_data[tx_start..tx_end].to_vec());
                }
            } else if wire_type == 0x00 {
                tx_blobs.push(payload.to_vec());
            }
        }

        let (ledger_seq, sync_complete, pending_sync_anchor) = {
            let state = self.state.read().await;
            (
                state.ctx.ledger_seq,
                state.sync_done,
                state.pending_sync_anchor,
            )
        };
        let tx_ledger_seq = if ld.ledger_seq > 0 {
            ld.ledger_seq
        } else {
            ledger_seq
        };

        let mut failed_parse = 0usize;
        let mut parsed_count = 0usize;
        let mut tx_records: Vec<crate::ledger::history::TxRecord> = Vec::new();

        for tx_blob in &tx_blobs {
            match crate::transaction::parse_blob(tx_blob) {
                Ok(_parsed) => {
                    parsed_count += 1;
                    let hash = crate::transaction::serialize::tx_blob_hash(tx_blob);
                    tx_records.push(crate::ledger::history::TxRecord {
                        blob: tx_blob.clone(),
                        meta: vec![],
                        hash,
                        ledger_seq: tx_ledger_seq,
                        tx_index: 0,
                        result: "pending".to_string(),
                    });
                }
                Err(e) => {
                    failed_parse += 1;
                    debug!("liTX_NODE parse fail seq={}: {}", tx_ledger_seq, e);
                }
            }
        }

        if !tx_records.is_empty() {
            if let Some(ref store) = self.storage {
                for rec in &tx_records {
                    let _ = store.save_transaction(rec);
                }
            }
        }

        {
            let mut state = self.state.write().await;
            for rec in &tx_records {
                state.services.tx_master.observe_buffered(
                    rec.hash,
                    rec.blob.len(),
                    format!("liTX_NODE:{:?}", peer.id),
                    rec.ledger_seq,
                    crate::transaction::master::unix_now(),
                );
            }
            let mut history = state.ctx.history.write().unwrap_or_else(|e| e.into_inner());
            for rec in tx_records {
                history.insert_tx(rec);
            }
        }

        let total = tx_blobs.len();
        info!(
            "ledger {}: buffered {}/{} txs (no direct state apply) parse_fail={} sync_done={} pending_anchor={}",
            tx_ledger_seq,
            parsed_count,
            total,
            failed_parse,
            sync_complete,
            is_pending_sync_anchor(pending_sync_anchor, ld.ledger_seq, &hash),
        );
    }
}

fn get_objects_node_type(object_type: i32) -> Option<crate::ledger::node_store::NodeObjectType> {
    use crate::ledger::node_store::NodeObjectType;
    use crate::proto::tm_get_object_by_hash::ObjectType;

    match ObjectType::try_from(object_type).ok()? {
        ObjectType::OtLedger => Some(NodeObjectType::Ledger),
        ObjectType::OtStateNode => Some(NodeObjectType::AccountNode),
        ObjectType::OtTransactionNode => Some(NodeObjectType::TransactionNode),
        ObjectType::OtFetchPack => Some(NodeObjectType::AccountNode),
        _ => None,
    }
}

fn build_transaction_shamap_from_history(
    tx_records: Vec<crate::ledger::history::TxRecord>,
) -> crate::ledger::shamap::SHAMap {
    let mut tx_map = crate::ledger::shamap::SHAMap::new_transaction();
    for rec in tx_records {
        let mut data = Vec::with_capacity(rec.blob.len() + rec.meta.len() + 8);
        crate::transaction::serialize::encode_length(rec.blob.len(), &mut data);
        data.extend_from_slice(&rec.blob);
        crate::transaction::serialize::encode_length(rec.meta.len(), &mut data);
        data.extend_from_slice(&rec.meta);
        tx_map.insert(crate::ledger::Key(rec.hash), data);
    }
    tx_map
}

#[derive(Default)]
struct GetObjectsImportOutcome {
    summary: crate::ledger::fetch_pack::FetchPackImportResult,
    breakdown: Option<crate::ledger::fetch_pack::FetchPackObjectReplyImportResult>,
}

fn import_get_objects_reply(
    fetch_pack: Option<std::sync::Arc<crate::ledger::fetch_pack::FetchPackStore>>,
    backend: Option<std::sync::Arc<dyn crate::ledger::node_store::NodeStore>>,
    object_type: Option<crate::ledger::node_store::NodeObjectType>,
    objects: Vec<crate::proto::TmIndexedObject>,
) -> GetObjectsImportOutcome {
    if let Some(fetch_pack) = fetch_pack {
        let result = if let Some(object_type) = object_type {
            fetch_pack.import_object_reply_objects_typed(object_type, &objects)
        } else {
            fetch_pack.import_object_reply_objects(&objects)
        };
        return GetObjectsImportOutcome {
            summary: crate::ledger::fetch_pack::FetchPackImportResult {
                imported: result.verified_objects,
                persisted: result.persisted,
                duplicates: result.duplicates,
                persist_errors: result.persist_errors,
                unchecked_fallbacks: result.unchecked_fallbacks,
                last_error: result.last_error.clone(),
            },
            breakdown: Some(result),
        };
    }

    let mut summary = crate::ledger::fetch_pack::FetchPackImportResult::default();
    let Some(backend) = backend else {
        return GetObjectsImportOutcome {
            summary,
            breakdown: None,
        };
    };
    let Some(object_type) = object_type else {
        return GetObjectsImportOutcome {
            summary,
            breakdown: None,
        };
    };

    for obj in &objects {
        let Some(hash) = obj.hash.as_ref() else {
            continue;
        };
        let Some(data) = obj.data.as_ref() else {
            continue;
        };
        if hash.len() != 32 {
            continue;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(hash);
        let Some(store_data) =
            crate::sync::object_reply_to_verified_store_typed(object_type, &key, data)
        else {
            continue;
        };
        summary.imported += 1;
        match backend.contains(&key) {
            Ok(true) => {
                summary.duplicates += 1;
                continue;
            }
            Ok(false) => {}
            Err(err) => {
                summary.persist_errors += 1;
                summary.last_error = Some(err.to_string());
                continue;
            }
        }
        match backend.store_typed(object_type, &key, &store_data) {
            Ok(()) => summary.persisted += 1,
            Err(err) => {
                summary.persist_errors += 1;
                summary.last_error = Some(err.to_string());
            }
        }
    }

    GetObjectsImportOutcome {
        summary,
        breakdown: None,
    }
}

fn should_send_ledger_data_error(error: crate::proto::TmReplyError) -> bool {
    matches!(
        error,
        crate::proto::TmReplyError::ReNoLedger
            | crate::proto::TmReplyError::ReNoNode
            | crate::proto::TmReplyError::ReBadRequest
    )
}

fn build_tx_set_candidate_reply(
    tx_sets: &std::sync::Arc<std::sync::Mutex<crate::consensus::ConsensusTxSets>>,
    tx_pool: &std::sync::Arc<std::sync::RwLock<crate::ledger::TxPool>>,
    req: &crate::proto::TmGetLedger,
) -> RtxpMessage {
    let cookie = req.request_cookie.map(|c| c as u32);
    let Some(hash_bytes) = req.ledger_hash.as_ref().filter(|hash| hash.len() == 32) else {
        return crate::network::relay::encode_ledger_data_error(
            &[0u8; 32],
            0,
            crate::proto::TmLedgerInfoType::LiTsCandidate as i32,
            cookie,
            crate::proto::TmReplyError::ReBadRequest,
        );
    };

    let mut requested_hash = [0u8; 32];
    requested_hash.copy_from_slice(hash_bytes);
    let entries = {
        if let Some(entries) = tx_sets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .accepted_pool_entries(&requested_hash)
        {
            entries
        } else {
            let pool = tx_pool.read().unwrap_or_else(|e| e.into_inner());
            if pool.canonical_set_hash() == requested_hash {
                pool.snapshot_entries()
            } else {
                Vec::new()
            }
        }
    };
    let nodes = {
        if entries.is_empty() && requested_hash != [0u8; 32] {
            return crate::network::relay::encode_ledger_data_error(
                &requested_hash,
                0,
                crate::proto::TmLedgerInfoType::LiTsCandidate as i32,
                cookie,
                crate::proto::TmReplyError::ReNoLedger,
            );
        }
        let requested_nodes = if req.node_i_ds.is_empty() {
            vec![crate::ledger::shamap_id::SHAMapNodeID::root()]
        } else {
            req.node_i_ds
                .iter()
                .filter_map(|raw| crate::ledger::shamap_id::SHAMapNodeID::from_wire(raw))
                .collect::<Vec<_>>()
        };
        let query_depth = req.query_depth.unwrap_or(1);
        let (wire_nodes, computed_hash) =
            crate::ledger::shamap_sync::build_candidate_tx_set_wire_nodes(
                entries.iter().map(|entry| entry.blob.as_slice()),
                &requested_nodes,
                query_depth,
            );
        if computed_hash != requested_hash {
            return crate::network::relay::encode_ledger_data_error(
                &requested_hash,
                0,
                crate::proto::TmLedgerInfoType::LiTsCandidate as i32,
                cookie,
                crate::proto::TmReplyError::ReNoLedger,
            );
        }
        wire_nodes
            .into_iter()
            .map(|(node_id, nodedata)| crate::proto::TmLedgerNode {
                nodedata,
                nodeid: Some(node_id.to_wire().to_vec()),
            })
            .collect::<Vec<_>>()
    };

    if nodes.is_empty() {
        return crate::network::relay::encode_ledger_data_error(
            &requested_hash,
            0,
            crate::proto::TmLedgerInfoType::LiTsCandidate as i32,
            cookie,
            crate::proto::TmReplyError::ReNoNode,
        );
    }

    let response = crate::proto::TmLedgerData {
        ledger_hash: requested_hash.to_vec(),
        ledger_seq: 0,
        r#type: crate::proto::TmLedgerInfoType::LiTsCandidate as i32,
        nodes,
        request_cookie: cookie,
        error: None,
    };
    RtxpMessage::new(MessageType::LedgerData, response.encode_to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indexed_state_leaf_object() -> ([u8; 32], crate::proto::TmIndexedObject) {
        let key = [0xAB; 32];
        let mut leaf = b"leaf".to_vec();
        leaf.extend_from_slice(&key);
        let hash = {
            let mut payload = Vec::with_capacity(4 + leaf.len());
            payload.extend_from_slice(&crate::ledger::shamap::PREFIX_LEAF_STATE);
            payload.extend_from_slice(&leaf);
            crate::crypto::sha512_first_half(&payload)
        };
        (
            hash,
            crate::proto::TmIndexedObject {
                hash: Some(hash.to_vec()),
                data: Some(leaf),
                index: None,
                ledger_seq: Some(1),
                node_id: None,
            },
        )
    }

    #[test]
    fn get_objects_import_preserves_verified_reply_before_gate_decision() {
        let inner: std::sync::Arc<dyn crate::ledger::node_store::NodeStore> =
            std::sync::Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (_backend, fetch_pack) = crate::ledger::fetch_pack::FetchPackStore::wrap(inner);
        let (hash, object) = indexed_state_leaf_object();

        let outcome = import_get_objects_reply(
            Some(fetch_pack.clone()),
            None,
            Some(crate::ledger::node_store::NodeObjectType::AccountNode),
            vec![object],
        );

        assert_eq!(outcome.summary.imported, 1);
        assert_eq!(outcome.summary.persisted, 1);
        assert_eq!(
            outcome.breakdown.as_ref().map(|result| result.raw_objects),
            Some(1)
        );
        assert!(
            crate::ledger::node_store::NodeStore::fetch(fetch_pack.as_ref(), &hash)
                .expect("fetch-pack fetch should succeed")
                .is_some()
        );
    }
}
