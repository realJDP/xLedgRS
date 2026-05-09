use super::*;

pub(super) struct FetchInfoSyncSnapshot {
    ledger_seq: u32,
    hash: String,
    sync_active: bool,
    target_account_hash: String,
    computed_root_hash: String,
    root_matches: bool,
    have_header: bool,
    have_state: bool,
    needed_state_hashes: Vec<String>,
    backend_fetch_errors: usize,
    timeouts: u32,
    in_flight: usize,
    outstanding_cookies: usize,
    outstanding_object_queries: usize,
    recent_nodes: usize,
    useful_idle_secs: u64,
    response_idle_secs: u64,
    queue_len: usize,
    queue_bytes: usize,
    inner_nodes: usize,
    state_nodes: usize,
    pass: u32,
    new_objects: usize,
    tail_stuck_hash: Option<String>,
    tail_stuck_retries: u32,
}

impl FetchInfoSyncSnapshot {
    pub(super) fn state_nodes(&self) -> usize {
        self.state_nodes
    }
}

fn snapshot_validation_quorum(
    manager: Option<&std::sync::Arc<std::sync::Mutex<crate::validator_list::ValidatorListManager>>>,
    fallback: u32,
    now_unix: u64,
) -> u32 {
    manager
        .map(|manager| {
            manager
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot(now_unix)
                .validation_quorum
        })
        .unwrap_or(fallback)
}

fn readiness_blockers(state: &SharedState, sync: &FetchInfoSyncSnapshot) -> Vec<String> {
    let mut blockers = Vec::new();
    if !sync.have_header {
        blockers.push("missing_header".to_string());
    }
    if !sync.have_state {
        if !sync.root_matches {
            blockers.push("state_root_mismatch".to_string());
        } else if sync.backend_fetch_errors > 0 {
            blockers.push("backend_fetch_errors".to_string());
        } else if !sync.needed_state_hashes.is_empty() {
            blockers.push("missing_state".to_string());
        } else {
            blockers.push("state_not_complete".to_string());
        }
    }
    if sync.in_flight > 0 {
        blockers.push("state_requests_in_flight".to_string());
    }
    if sync.queue_len > 0 {
        blockers.push("queued_state_responses".to_string());
    }
    if state.pending_sync_anchor.is_some() {
        blockers.push("pending_sync_anchor".to_string());
    }
    if !state.sync_done {
        blockers.push("sync_not_done".to_string());
    }
    blockers
}

impl Node {
    pub(super) fn snapshot_sync_fetch(&self) -> Option<FetchInfoSyncSnapshot> {
        let (
            ledger_seq,
            hash,
            sync_active,
            account_hash,
            computed_root_hash,
            timeouts,
            in_flight,
            outstanding_cookies,
            outstanding_object_queries,
            recent_nodes,
            useful_idle_secs,
            response_idle_secs,
            inner_nodes,
            state_nodes,
            pass,
            new_objects,
            tail_stuck_hash,
            tail_stuck_retries,
            completion_snapshot,
        ) = {
            let mut guard = self.lock_sync();
            let syncer = guard.as_mut()?;
            (
                syncer.ledger_seq(),
                hex::encode_upper(syncer.ledger_hash()),
                syncer.active(),
                syncer.account_hash(),
                syncer.root_hash(),
                syncer.stalled_retries(),
                syncer.in_flight(),
                syncer.peer.outstanding_cookie_count(),
                syncer.peer.outstanding_object_query_count(),
                syncer.peer.recent_node_count(),
                syncer.peer.last_new_nodes.elapsed().as_secs(),
                syncer.peer.last_response.elapsed().as_secs(),
                syncer.inner_count(),
                syncer.leaf_count(),
                syncer.pass_number(),
                syncer.new_objects_this_pass(),
                syncer.tail_stuck_hash(),
                syncer.tail_stuck_retries(),
                syncer.completion_check_snapshot(),
            )
        };
        let completion = completion_snapshot
            .map(crate::sync_coordinator::SyncCoordinator::check_completion_snapshot);
        let (needed_state_hashes, backend_fetch_errors, missing_clear) = match completion
            .as_ref()
            .and_then(|result| result.blocker.as_ref())
        {
            Some(crate::sync_coordinator::CompletionBlocker::BackendFetchErrors { count }) => {
                (Vec::new(), *count, false)
            }
            Some(crate::sync_coordinator::CompletionBlocker::MissingNodes {
                first_hash, ..
            }) => (vec![hex::encode_upper(first_hash)], 0, false),
            Some(_) => (Vec::new(), 0, false),
            None => (Vec::new(), 0, true),
        };
        let have_state = state_nodes > 0
            && missing_clear
            && backend_fetch_errors == 0
            && computed_root_hash == account_hash;
        let (queue_len, queue_bytes) = self.sync_runtime.sync_data_queue_stats();

        Some(FetchInfoSyncSnapshot {
            ledger_seq,
            hash,
            sync_active,
            target_account_hash: hex::encode_upper(account_hash),
            computed_root_hash: hex::encode_upper(computed_root_hash),
            root_matches: computed_root_hash == account_hash,
            have_header: true,
            have_state,
            needed_state_hashes,
            backend_fetch_errors,
            timeouts,
            in_flight,
            outstanding_cookies,
            outstanding_object_queries,
            recent_nodes,
            useful_idle_secs,
            response_idle_secs,
            queue_len,
            queue_bytes,
            inner_nodes,
            state_nodes,
            pass,
            new_objects,
            tail_stuck_hash: if tail_stuck_hash.iter().any(|&b| b != 0) {
                Some(hex::encode_upper(tail_stuck_hash))
            } else {
                None
            },
            tail_stuck_retries,
        })
    }

    pub(super) fn build_fetch_info_snapshot(
        state: &SharedState,
        sync: FetchInfoSyncSnapshot,
    ) -> crate::rpc::FetchInfoSnapshot {
        let peers = state
            .peer_txs
            .keys()
            .filter(|pid| state.peers.get(pid).map(|ps| ps.is_open()).unwrap_or(false))
            .filter(|pid| {
                state
                    .sync_peer_cooldown
                    .get(pid)
                    .map(|expires| std::time::Instant::now() >= *expires)
                    .unwrap_or(true)
            })
            .filter(|pid| {
                state.peer_ledger_range.get(pid).map_or_else(
                    || {
                        state
                            .peer_addrs
                            .get(pid)
                            .map(|addr| state.full_history_peers.contains(addr))
                            .unwrap_or(false)
                    },
                    |&(min, max)| {
                        (sync.ledger_seq >= min && sync.ledger_seq <= max)
                            || state
                                .peer_addrs
                                .get(pid)
                                .map(|addr| state.full_history_peers.contains(addr))
                                .unwrap_or(false)
                    },
                )
            })
            .count();
        let readiness_blockers = readiness_blockers(state, &sync);
        let ready = readiness_blockers.is_empty();

        crate::rpc::FetchInfoSnapshot {
            key: sync.ledger_seq.to_string(),
            hash: sync.hash.clone(),
            sync_active: sync.sync_active,
            sync_in_progress: state.sync_in_progress,
            sync_done: state.sync_done,
            pending_sync_anchor: state
                .pending_sync_anchor
                .map(|(seq, hash)| format!("{}:{}", seq, hex::encode_upper(hash))),
            target_seq: sync.ledger_seq,
            target_hash: sync.hash,
            target_account_hash: sync.target_account_hash,
            computed_root_hash: sync.computed_root_hash,
            root_matches: sync.root_matches,
            ready,
            readiness: if ready {
                "ready".to_string()
            } else {
                "blocked".to_string()
            },
            readiness_blockers,
            have_header: sync.have_header,
            have_state: sync.have_state,
            have_transactions: state.pending_sync_anchor.is_none() && state.sync_done,
            needed_state_hashes: sync.needed_state_hashes,
            backend_fetch_errors: sync.backend_fetch_errors,
            peers,
            timeouts: sync.timeouts,
            in_flight: sync.in_flight,
            outstanding_cookies: sync.outstanding_cookies,
            outstanding_object_queries: sync.outstanding_object_queries,
            recent_nodes: sync.recent_nodes,
            useful_idle_secs: sync.useful_idle_secs,
            response_idle_secs: sync.response_idle_secs,
            queue_len: sync.queue_len,
            queue_bytes: sync.queue_bytes,
            inner_nodes: sync.inner_nodes,
            state_nodes: sync.state_nodes,
            pass: sync.pass,
            new_objects: sync.new_objects,
            tail_stuck_hash: sync.tail_stuck_hash,
            tail_stuck_retries: sync.tail_stuck_retries,
        }
    }

    pub(super) fn build_rpc_read_context(
        state: &SharedState,
        object_count: usize,
        fetch_info: Option<crate::rpc::FetchInfoSnapshot>,
    ) -> NodeContext {
        let consensus_info = state.current_round.as_ref().map(|round| {
            let phase = match &round.phase {
                crate::consensus::ConsensusPhase::Open => "open",
                crate::consensus::ConsensusPhase::Establish => "establish",
                crate::consensus::ConsensusPhase::Accepted => "accepted",
                crate::consensus::ConsensusPhase::Validated => "validated",
            };
            let mode = match round.mode {
                crate::consensus::ConsensusMode::Proposing => "proposing",
                crate::consensus::ConsensusMode::Observing => "observing",
                crate::consensus::ConsensusMode::WrongLedger => "wrong_ledger",
                crate::consensus::ConsensusMode::SwitchedLedger => "switched_ledger",
            };
            let consensus = match round.consensus_state {
                crate::consensus::round::ConsensusState::No => "no",
                crate::consensus::round::ConsensusState::Yes => "yes",
                crate::consensus::round::ConsensusState::MovedOn => "moved_on",
                crate::consensus::round::ConsensusState::Expired => "expired",
            };
            crate::rpc::ConsensusInfoSnapshot {
                ledger_seq: round.ledger_seq,
                phase: phase.to_string(),
                mode: mode.to_string(),
                consensus: consensus.to_string(),
                proposers: round.proposal_count(),
                validations: round.validation_count(),
                disputes: round.dispute_count(),
                quorum: round.quorum(),
                converge_percent: round.converge_percent(),
                elapsed_ms: round.establish_elapsed().as_millis() as u64,
                previous_ledger: hex::encode_upper(round.prev_ledger),
                our_position: round.our_position.map(hex::encode_upper),
            }
        });
        let peer_summaries = state
            .peer_txs
            .keys()
            .map(|pid| {
                let address = state
                    .peer_addrs
                    .get(pid)
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let public_key = state.peer_handshakes.get(pid).map(|info| {
                    crate::crypto::base58::encode(
                        crate::crypto::base58::PREFIX_NODE_PUBLIC,
                        &info.node_pubkey,
                    )
                });
                let cluster = state.peer_addrs.get(pid).and_then(|addr| {
                    state
                        .services
                        .cluster
                        .summary_for(*addr, public_key.as_deref())
                });
                crate::rpc::PeerSummary {
                    address,
                    status: match state.peers.get(pid) {
                        Some(crate::network::peer::PeerState::Connecting) => {
                            "connecting".to_string()
                        }
                        Some(crate::network::peer::PeerState::Handshaking) => {
                            "handshaking".to_string()
                        }
                        Some(crate::network::peer::PeerState::Active) => "active".to_string(),
                        Some(crate::network::peer::PeerState::Closing { .. }) => {
                            "closing".to_string()
                        }
                        Some(crate::network::peer::PeerState::Closed { .. }) => {
                            "closed".to_string()
                        }
                        None => "unknown".to_string(),
                    },
                    inbound: match state.peer_direction.get(pid) {
                        Some(crate::network::peer::Direction::Inbound) => Some(true),
                        Some(crate::network::peer::Direction::Outbound) => Some(false),
                        None => None,
                    },
                    latency: state.peer_latency.get(pid).copied(),
                    ledger: state
                        .peer_handshakes
                        .get(pid)
                        .and_then(|info| info.closed_ledger.clone()),
                    protocol: state
                        .peer_handshakes
                        .get(pid)
                        .map(|info| info.protocol.clone()),
                    public_key,
                    version: state
                        .peer_handshakes
                        .get(pid)
                        .and_then(|info| info.user_agent.clone()),
                    cluster,
                }
            })
            .collect();
        let now = std::time::Instant::now();
        let mut blacklist_entries = Vec::new();
        for (addr, expires) in &state.peer_cooldowns {
            if *expires > now {
                blacklist_entries.push(crate::rpc::BlacklistEntry {
                    address: addr.to_string(),
                    reason: "dial_cooldown".to_string(),
                    expires_in_ms: expires.saturating_duration_since(now).as_millis() as u64,
                });
            }
        }
        for (pid, expires) in &state.sync_peer_cooldown {
            if *expires > now {
                let address = state
                    .peer_addrs
                    .get(pid)
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| format!("peer:{pid:?}"));
                blacklist_entries.push(crate::rpc::BlacklistEntry {
                    address,
                    reason: "sync_benched".to_string(),
                    expires_in_ms: expires.saturating_duration_since(now).as_millis() as u64,
                });
            }
        }
        blacklist_entries.extend(state.services.resource_manager.blacklist_entries(now));
        blacklist_entries.sort_by(|a, b| a.address.cmp(&b.address).then(a.reason.cmp(&b.reason)));
        let tx_relay_metrics = {
            let pool = state.ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
            let inbound_snapshot = state.services.inbound_transactions.snapshot(16);
            let tx_master_snapshot = state.services.tx_master.snapshot(16);
            crate::rpc::TxRelayMetricsSnapshot {
                queued_transactions: pool.len(),
                peer_count: state.peer_count(),
                max_queue_size: pool.metrics.max_queue_size(),
                escalation_multiplier: pool.metrics.escalation_multiplier,
                txns_expected: pool.metrics.txns_expected,
                candidate_set_hash: hex::encode_upper(pool.canonical_set_hash()),
                tracked_transactions: tx_master_snapshot.tracked,
                submitted_transactions: tx_master_snapshot.submitted_total,
                inbound_tracked: inbound_snapshot.tracked,
                accepted_transactions: inbound_snapshot.accepted_total,
                duplicate_transactions: inbound_snapshot.duplicate_total,
                relayed_transactions: inbound_snapshot.relayed_total,
                persisted_transactions: inbound_snapshot.persisted_total,
            }
        };
        let inbound_transactions_snapshot = state.services.inbound_transactions.snapshot(32);
        let tx_master_snapshot = state.services.tx_master.snapshot(32);
        let complete_ledgers = state
            .ctx
            .history
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .complete_ledgers();
        let (queued_transactions, candidate_set_hash, metrics) = {
            let pool = state.ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
            (pool.len(), pool.canonical_set_hash(), pool.metrics.clone())
        };
        let mut ledger_master_snapshot = state.services.ledger_master.snapshot();
        ledger_master_snapshot.complete_ledgers = complete_ledgers.clone();
        ledger_master_snapshot.queued_transactions = queued_transactions;
        ledger_master_snapshot.candidate_set_hash = hex::encode_upper(candidate_set_hash);
        let mut open_ledger_snapshot = state.services.open_ledger.snapshot();
        if open_ledger_snapshot.ledger_current_index == 0 {
            open_ledger_snapshot.parent_ledger_index = state.ctx.ledger_header.sequence;
            open_ledger_snapshot.ledger_current_index =
                state.ctx.ledger_header.sequence.saturating_add(1);
            open_ledger_snapshot.parent_hash = hex::encode_upper(state.ctx.ledger_header.hash);
            open_ledger_snapshot.last_close_time = state.ctx.ledger_header.close_time;
        }
        open_ledger_snapshot.queued_transactions = queued_transactions;
        open_ledger_snapshot.candidate_set_hash = hex::encode_upper(candidate_set_hash);
        open_ledger_snapshot.escalation_multiplier = metrics.escalation_multiplier;
        open_ledger_snapshot.txns_expected = metrics.txns_expected;
        open_ledger_snapshot.max_queue_size = metrics.max_queue_size();
        open_ledger_snapshot.open_fee_level =
            metrics.escalated_fee_level(queued_transactions as u64 + 1);
        let mut cluster_snapshot = state.services.cluster.snapshot(32);
        cluster_snapshot.configured = cluster_snapshot
            .configured
            .max(peer_reservations_map(state.ctx.peer_reservations.as_ref()).len());
        let resource_snapshot = state.services.resource_manager.snapshot(now, 32);
        let path_request_snapshot = state.services.path_request_snapshot();
        let mut sync_peer_ids: Vec<_> = state
            .peer_sync_useful
            .keys()
            .chain(state.peer_sync_duplicates.keys())
            .copied()
            .collect();
        sync_peer_ids.sort_by_key(|pid| pid.0);
        sync_peer_ids.dedup();
        let mut sync_peer_usefulness: Vec<_> = sync_peer_ids
            .into_iter()
            .map(|pid| {
                let address = state
                    .peer_addrs
                    .get(&pid)
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| format!("peer:{}", pid.0));
                crate::rpc::SyncPeerUsefulnessSnapshot {
                    peer_id: pid.0.to_string(),
                    address,
                    useful_score: state.peer_sync_useful.get(&pid).copied().unwrap_or(0),
                    useful_nodes_total: state
                        .peer_sync_useful_total
                        .get(&pid)
                        .copied()
                        .unwrap_or(0),
                    duplicate_score: state.peer_sync_duplicates.get(&pid).copied().unwrap_or(0),
                    duplicate_responses_total: state
                        .peer_sync_duplicates_total
                        .get(&pid)
                        .copied()
                        .unwrap_or(0),
                    last_useful_secs: state
                        .peer_sync_last_useful
                        .get(&pid)
                        .map(|at| now.saturating_duration_since(*at).as_secs()),
                    latency: state.peer_latency.get(&pid).copied(),
                    ledger_range: state.peer_ledger_range.get(&pid).copied(),
                }
            })
            .collect();
        sync_peer_usefulness.sort_by(|a, b| {
            b.useful_score
                .cmp(&a.useful_score)
                .then_with(|| b.useful_nodes_total.cmp(&a.useful_nodes_total))
                .then_with(|| a.peer_id.cmp(&b.peer_id))
        });
        let mut ctx = NodeContext {
            network: state.ctx.network,
            network_id: state.ctx.network_id,
            build_version: state.ctx.build_version,
            start_time: state.ctx.start_time,
            ledger_seq: state.ctx.ledger_seq,
            ledger_hash: state.ctx.ledger_hash.clone(),
            fees: state.ctx.fees,
            ledger_state: state.ctx.ledger_state.clone(),
            tx_pool: state.ctx.tx_pool.clone(),
            consensus_tx_sets: state.ctx.consensus_tx_sets.clone(),
            ledger_header: state.ctx.ledger_header.clone(),
            history: state.ctx.history.clone(),
            broadcast_queue: Vec::new(),
            amendments: state.ctx.amendments.clone(),
            peer_count: state.peer_count(),
            object_count,
            pubkey_node: state.ctx.pubkey_node.clone(),
            validator_key: state.ctx.validator_key.clone(),
            peer_summaries,
            fetch_info,
            sync_metrics: None,
            sync_peer_usefulness,
            consensus_info,
            sync_clear_requested: state.ctx.sync_clear_requested.clone(),
            connect_requests: state.ctx.connect_requests.clone(),
            shutdown_requested: state.ctx.shutdown_requested.clone(),
            force_ledger_accept: state.ctx.force_ledger_accept.clone(),
            ledger_accept_service: state.ctx.ledger_accept_service.clone(),
            online_delete: state.ctx.online_delete,
            can_delete_target: state.ctx.can_delete_target.clone(),
            ledger_cleaner: state.ctx.ledger_cleaner.clone(),
            standalone_mode: state.ctx.standalone_mode,
            admin_rpc_enabled: state.ctx.admin_rpc_enabled,
            storage: state.ctx.storage.clone(),
            rpc_sync_state: state.rpc_sync_state.clone(),
            follower_state: state.follower_state.clone(),
            validator_list_manager: state.ctx.validator_list_manager.clone(),
            manifest_cache: state.ctx.manifest_cache.clone(),
            validator_list_sites: state.ctx.validator_list_sites.clone(),
            validator_site_statuses: state.ctx.validator_site_statuses.clone(),
            peer_reservations: state.ctx.peer_reservations.clone(),
            peerfinder_snapshot: Some(state.services.peerfinder.snapshot(32)),
            cluster_snapshot: Some(cluster_snapshot),
            resource_snapshot: Some(resource_snapshot),
            path_requests: state.services.path_requests.clone(),
            path_request_snapshot,
            debug_log: state.ctx.debug_log.clone(),
            debug_log_path: state.ctx.debug_log_path.clone(),
            blacklist_entries,
            tx_relay_metrics: Some(tx_relay_metrics),
            load_snapshot: state.services.load_manager.snapshot(),
            state_accounting_snapshot: None,
            inbound_transactions_snapshot: Some(inbound_transactions_snapshot),
            inbound_ledgers_snapshot: state.services.inbound_ledgers_snapshot(),
            tx_master_snapshot: Some(tx_master_snapshot),
            ledger_master_snapshot: Some(ledger_master_snapshot),
            open_ledger_snapshot: Some(open_ledger_snapshot),
            ledger_cleaner_snapshot: state.services.ledger_cleaner_snapshot(),
            node_store_snapshot: state.services.node_store_snapshot(),
            fetch_pack_snapshot: state.services.fetch_pack_snapshot(),
            network_ops_snapshot: None,
            closed_ledger: state.ctx.closed_ledger.clone(),
        };
        ctx.network_ops_snapshot =
            Some(crate::network::ops::NetworkOpsSnapshot::from_context(&ctx));
        if let Some(snapshot) = ctx.network_ops_snapshot.as_ref() {
            ctx.state_accounting_snapshot = Some(
                state
                    .services
                    .state_accounting
                    .snapshot(&snapshot.server_state, now),
            );
        }
        ctx
    }

    pub(super) fn build_rpc_snapshot(
        state: &SharedState,
        object_count: usize,
        leaf_count: usize,
        node_key: &Secp256k1KeyPair,
        validator_key: Option<&Secp256k1KeyPair>,
    ) -> crate::rpc::RpcSnapshot {
        let pubkey_node = crate::crypto::base58::encode(
            crate::crypto::base58::PREFIX_NODE_PUBLIC,
            &node_key.public_key_bytes(),
        );
        let validator_key_b58 = validator_key
            .map(|vk| {
                crate::crypto::base58::encode(
                    crate::crypto::base58::PREFIX_NODE_PUBLIC,
                    &vk.public_key_bytes(),
                )
            })
            .unwrap_or_default();

        let now = std::time::Instant::now();
        let load_snapshot = state.services.load_manager.snapshot();
        const XRPL_EPOCH_OFFSET: u64 = 946_684_800;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ledger_unix = state.ctx.ledger_header.close_time as u64 + XRPL_EPOCH_OFFSET;
        let age = now_unix.saturating_sub(ledger_unix);
        let follower_healthy = Self::follower_healthy_for_status(state);
        let server_state = crate::network::ops::snapshot_server_state_label(
            state.sync_done,
            follower_healthy,
            age,
            state.peer_txs.len(),
        );
        let fallback_quorum = state
            .current_round
            .as_ref()
            .map(|r| r.quorum())
            .unwrap_or(0);
        let ledger_master_snapshot = state.services.ledger_master.snapshot();
        let has_validated_head = ledger_master_snapshot.validated_seq > 0
            && ledger_master_snapshot
                .validated_hash
                .chars()
                .any(|c| c != '0');
        let (validated_seq, validated_hash, validated_header) = if has_validated_head {
            let seq = ledger_master_snapshot.validated_seq;
            let hash = ledger_master_snapshot.validated_hash.clone();
            let header = if seq == state.ctx.ledger_header.sequence
                && hex::encode_upper(state.ctx.ledger_header.hash).eq_ignore_ascii_case(&hash)
            {
                state.ctx.ledger_header.clone()
            } else {
                state
                    .ctx
                    .history
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_ledger(seq)
                    .filter(|record| {
                        hex::encode_upper(record.header.hash).eq_ignore_ascii_case(&hash)
                    })
                    .map(|record| record.header.clone())
                    .unwrap_or_default()
            };
            (seq, hash, header)
        } else {
            (0, "0".repeat(64), crate::ledger::LedgerHeader::default())
        };

        crate::rpc::RpcSnapshot {
            ledger_seq: validated_seq,
            ledger_hash: validated_hash,
            ledger_header: validated_header,
            fees: state.ctx.fees,
            peer_count: state.peer_txs.len(),
            object_count,
            leaf_count,
            build_version: state.ctx.build_version,
            network_id: state.ctx.network_id,
            standalone_mode: state.ctx.standalone_mode,
            start_time: state.ctx.start_time,
            memory_mb: crate::rpc::handlers::get_memory_mb() as usize,
            complete_ledgers: state
                .ctx
                .history
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .complete_ledgers(),
            sync_done: state.sync_done,
            follower_healthy,
            validation_quorum: snapshot_validation_quorum(
                state.ctx.validator_list_manager.as_ref(),
                fallback_quorum,
                now_unix,
            ),
            load_snapshot,
            state_accounting_snapshot: Some(
                state.services.state_accounting.snapshot(server_state, now),
            ),
            pubkey_node,
            validator_key: validator_key_b58,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::snapshot_validation_quorum;

    fn validator_key_bytes() -> Vec<u8> {
        crate::crypto::keys::Secp256k1KeyPair::generate().public_key_bytes()
    }

    #[test]
    fn snapshot_validation_quorum_prefers_validator_list_manager() {
        let first = validator_key_bytes();
        let second = validator_key_bytes();
        let manager = std::sync::Arc::new(std::sync::Mutex::new(
            crate::validator_list::ValidatorListManager::new(vec![first, second], 1),
        ));

        assert_eq!(snapshot_validation_quorum(Some(&manager), 0, 1_000), 2);
    }

    #[test]
    fn snapshot_validation_quorum_falls_back_when_manager_missing() {
        assert_eq!(snapshot_validation_quorum(None, 7, 1_000), 7);
    }
}
