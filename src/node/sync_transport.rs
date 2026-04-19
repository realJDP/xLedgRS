use super::*;

impl Node {
    pub(super) async fn handle_get_ledger_message(
        self: &Arc<Self>,
        peer: &Peer,
        msg: &RtxpMessage,
    ) -> PeerEvent {
        if let Ok(req) = <crate::proto::TmGetLedger as ProstMessage>::decode(msg.payload.as_slice())
        {
            let state = self.state.read().await;
            let current = state.ctx.ledger_header.clone();
            let peer_tx = state.peer_txs.get(&peer.id).cloned();
            let cookie = req.request_cookie.map(|c| c as u32);
            let requested_hash = requested_get_ledger_hash(&req)
                .ok()
                .flatten()
                .unwrap_or([0u8; 32]);
            let requested_seq = req.ledger_seq.unwrap_or(0);

            let history = state.ctx.history.read().unwrap_or_else(|e| e.into_inner());

            if let Some(tx) = peer_tx {
                let header = match resolve_get_ledger_header(&req, &current, &history) {
                    Ok(header) => header,
                    Err(err) => {
                        let reply = crate::network::relay::encode_ledger_data_error(
                            &requested_hash,
                            requested_seq,
                            req.itype,
                            cookie,
                            err,
                        );
                        let _ = tx.try_send(reply);
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
                    let reply = crate::network::relay::encode_ledger_data_error(
                        &requested_hash,
                        requested_seq,
                        req.itype,
                        cookie,
                        crate::proto::TmReplyError::ReNoLedger,
                    );
                    let _ = tx.try_send(reply);
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
                            let mut ledger_state = state
                                .ctx
                                .ledger_state
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
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

                        let response = crate::proto::TmLedgerData {
                            ledger_hash: header.hash.to_vec(),
                            ledger_seq: header.sequence,
                            r#type: crate::proto::TmLedgerInfoType::LiBase as i32,
                            nodes: build_li_base_nodes(&header, state_root_wire),
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
                        let tx_records = state
                            .ctx
                            .history
                            .read()
                            .unwrap_or_else(|e| e.into_inner())
                            .ledger_txs(header.sequence);
                        let node_ids: Vec<Vec<u8>> = if req.node_i_ds.is_empty() {
                            vec![vec![0u8; 33]]
                        } else {
                            req.node_i_ds.clone()
                        };
                        let query_depth = req.query_depth.unwrap_or(0);
                        let mut tx_map = crate::ledger::shamap::SHAMap::new_transaction();
                        for rec in tx_records {
                            let mut data = Vec::with_capacity(rec.blob.len() + rec.meta.len() + 8);
                            crate::transaction::serialize::encode_length(rec.blob.len(), &mut data);
                            data.extend_from_slice(&rec.blob);
                            crate::transaction::serialize::encode_length(rec.meta.len(), &mut data);
                            data.extend_from_slice(&rec.meta);
                            tx_map.insert(crate::ledger::Key(rec.hash), data);
                        }
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
                            let reply = crate::network::relay::encode_ledger_data_error(
                                &header.hash,
                                header.sequence,
                                crate::proto::TmLedgerInfoType::LiTxNode as i32,
                                cookie,
                                if invalid_node_ids == node_ids.len() {
                                    crate::proto::TmReplyError::ReBadRequest
                                } else {
                                    crate::proto::TmReplyError::ReNoNode
                                },
                            );
                            let _ = tx.try_send(reply);
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
                            let mut ls = state
                                .ctx
                                .ledger_state
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            if is_current {
                                Some(ls.peer_state_map_snapshot())
                            } else {
                                ls.historical_state_map_from_root(header.account_hash)
                            }
                        }) else {
                            let reply = crate::network::relay::encode_ledger_data_error(
                                &header.hash,
                                header.sequence,
                                crate::proto::TmLedgerInfoType::LiAsNode as i32,
                                cookie,
                                crate::proto::TmReplyError::ReNoNode,
                            );
                            let _ = tx.try_send(reply);
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
                            let reply = crate::network::relay::encode_ledger_data_error(
                                &header.hash,
                                header.sequence,
                                crate::proto::TmLedgerInfoType::LiAsNode as i32,
                                cookie,
                                if invalid_node_ids == node_ids.len() {
                                    crate::proto::TmReplyError::ReBadRequest
                                } else {
                                    crate::proto::TmReplyError::ReNoNode
                                },
                            );
                            let _ = tx.try_send(reply);
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

                for obj in &pb.objects {
                    let Some(ref hash) = obj.hash else {
                        continue;
                    };
                    if hash.len() != 32 {
                        continue;
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(hash);

                    let data = if pb.r#type
                        == crate::proto::tm_get_object_by_hash::ObjectType::OtStateNode as i32
                    {
                        self.nudb_backend
                            .as_ref()
                            .and_then(|backend| backend.fetch(&key).ok().flatten())
                            .and_then(|data| crate::sync::store_to_object_reply(&data))
                    } else {
                        self.storage
                            .as_ref()
                            .and_then(|store| store.lookup_raw_tx(hash))
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

                if !reply_objects.is_empty() {
                    let reply = crate::proto::TmGetObjectByHash {
                        r#type: pb.r#type,
                        query: false,
                        seq: pb.seq,
                        ledger_hash: pb.ledger_hash.clone(),
                        fat: None,
                        objects: reply_objects.clone(),
                    };

                    let reply_msg =
                        RtxpMessage::new(MessageType::GetObjects, reply.encode_to_vec());
                    let state = self.state.read().await;
                    if let Some(tx) = state.peer_txs.get(&peer.id) {
                        let _ = tx.try_send(reply_msg);
                    }
                    info!(
                        "served {}/{} objects to {:?}",
                        reply_objects.len(),
                        pb.objects.len(),
                        peer.id,
                    );
                }
            } else {
                let accepted_by_gate = self.sync_runtime.gate_accepts_response(
                    pb.ledger_hash.as_deref(),
                    pb.seq.map(|seq| seq as u32),
                    true,
                );

                if accepted_by_gate {
                    info!(
                        "queuing object response from {:?}: seq={:?} count={}",
                        peer.id,
                        pb.seq,
                        pb.objects.len(),
                    );
                    let fetch_pack = {
                        let state = self.state.read().await;
                        state.services.fetch_pack.clone()
                    };
                    let import_result = if let Some(fetch_pack) = fetch_pack {
                        let result = fetch_pack.import_object_reply_objects(&pb.objects);
                        if result.verified_objects > 0 {
                            let inbound_ledgers = {
                                let state = self.state.read().await;
                                state.services.inbound_ledgers.clone()
                            };
                            if let Some(inbound_ledgers) = inbound_ledgers {
                                inbound_ledgers
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .got_fetch_pack();
                            }
                        }
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
                        crate::ledger::fetch_pack::FetchPackImportResult {
                            imported: result.verified_objects,
                            persisted: result.persisted,
                            persist_errors: result.persist_errors,
                            unchecked_fallbacks: result.unchecked_fallbacks,
                            last_error: result.last_error,
                        }
                    } else {
                        let mut fallback = crate::ledger::fetch_pack::FetchPackImportResult {
                            imported: 0,
                            ..crate::ledger::fetch_pack::FetchPackImportResult::default()
                        };
                        let mut verified_objects = 0usize;
                        if let Some(ref backend) = self.nudb_backend {
                            for obj in &pb.objects {
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
                                    crate::sync::object_reply_to_verified_store(&key, data)
                                else {
                                    continue;
                                };
                                verified_objects += 1;
                                match backend.store(&key, &store_data) {
                                    Ok(()) => fallback.persisted += 1,
                                    Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
                                        fallback.persist_errors += 1;
                                        fallback.last_error = Some(err.to_string());
                                    }
                                    Err(err) => {
                                        fallback.persist_errors += 1;
                                        fallback.last_error = Some(err.to_string());
                                    }
                                }
                            }
                        }
                        fallback.imported = verified_objects;
                        fallback
                    };
                    let stored_count = import_result.persisted;
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

                    let sync_arc_object = self.sync_runtime.sync_arc();
                    let object_resp_hash = pb.ledger_hash.clone();
                    let object_resp_seq = pb.seq.map(|seq| seq as u32);
                    let stored_count_for_followup = stored_count;
                    let (accepted_object, object_followup_reqs, object_followup_seq) =
                        match tokio::task::spawn_blocking(move || {
                            let mut guard =
                                sync_arc_object.lock().unwrap_or_else(|e| e.into_inner());
                            let Some(syncer) = guard.as_mut() else {
                                return (false, Vec::new(), 0u32);
                            };
                            let outcome = syncer.handle_object_response(
                                object_resp_hash.as_deref().unwrap_or_default(),
                                object_resp_seq,
                                stored_count_for_followup,
                            );
                            (outcome.accepted, outcome.followup_reqs, outcome.sync_seq)
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
                        "GetObjects response: accepted={} stored={} raw_objects={} from {:?}",
                        accepted_object,
                        stored_count,
                        pb.objects.len(),
                        peer.id,
                    );
                    if accepted_object && stored_count == 0 && pb.objects.is_empty() {
                        let mut state = self.state.write().await;
                        let expires =
                            std::time::Instant::now() + std::time::Duration::from_secs(60);
                        state.sync_peer_cooldown.insert(peer.id, expires);
                        info!(
                            "GetObjects empty response: benched {:?} for 60s to rotate timeout rescue peers",
                            peer.id,
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
                            self.sync_send_request(
                                &object_followup_reqs[0],
                                object_followup_seq,
                                None,
                            )
                            .await;
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
                    debug!(
                        "ignoring object response from {:?}: accepted={} seq={:?} count={}",
                        peer.id,
                        accepted_by_gate,
                        pb.seq,
                        pb.objects.len(),
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
