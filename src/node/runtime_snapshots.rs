use super::*;

pub(super) struct FetchInfoSyncSnapshot {
    ledger_seq: u32,
    hash: String,
    have_header: bool,
    have_state: bool,
    needed_state_hashes: Vec<String>,
    backend_fetch_errors: usize,
    timeouts: u32,
    in_flight: usize,
    inner_nodes: usize,
    state_nodes: usize,
    pass: u32,
    new_objects: usize,
    tail_stuck_hash: Option<String>,
    tail_stuck_retries: u32,
}

impl Node {
    pub(super) fn snapshot_sync_fetch(&self) -> Option<FetchInfoSyncSnapshot> {
        let mut guard = self.lock_sync();
        let syncer = guard.as_mut()?;

        let report = syncer.get_missing_report(16);
        let missing = report.missing;
        let have_state = syncer.leaf_count() > 0
            && missing.is_empty()
            && report.backend_fetch_errors == 0
            && syncer.root_hash() == syncer.account_hash();
        let needed_state_hashes: Vec<String> = missing
            .into_iter()
            .map(|(_, hash)| hex::encode_upper(hash))
            .collect();
        let tail_stuck_hash = syncer.tail_stuck_hash();

        Some(FetchInfoSyncSnapshot {
            ledger_seq: syncer.ledger_seq(),
            hash: hex::encode_upper(syncer.ledger_hash()),
            have_header: true,
            have_state,
            needed_state_hashes,
            backend_fetch_errors: report.backend_fetch_errors,
            timeouts: syncer.stalled_retries(),
            in_flight: syncer.in_flight(),
            inner_nodes: syncer.inner_count(),
            state_nodes: syncer.leaf_count(),
            pass: syncer.pass_number(),
            new_objects: syncer.new_objects_this_pass(),
            tail_stuck_hash: if tail_stuck_hash.iter().any(|&b| b != 0) {
                Some(hex::encode_upper(tail_stuck_hash))
            } else {
                None
            },
            tail_stuck_retries: syncer.tail_stuck_retries(),
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

        crate::rpc::FetchInfoSnapshot {
            key: sync.ledger_seq.to_string(),
            hash: sync.hash,
            have_header: sync.have_header,
            have_state: sync.have_state,
            have_transactions: state.pending_sync_anchor.is_none() && state.sync_done,
            needed_state_hashes: sync.needed_state_hashes,
            backend_fetch_errors: sync.backend_fetch_errors,
            peers,
            timeouts: sync.timeouts,
            in_flight: sync.in_flight,
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
        if ledger_master_snapshot.validated_seq == 0 {
            ledger_master_snapshot.validated_seq = state.ctx.ledger_header.sequence;
            ledger_master_snapshot.validated_hash = hex::encode_upper(state.ctx.ledger_header.hash);
            ledger_master_snapshot.open_ledger_seq =
                state.ctx.ledger_header.sequence.saturating_add(1);
            ledger_master_snapshot.complete_ledgers = complete_ledgers.clone();
            ledger_master_snapshot.last_close_time = state.ctx.ledger_header.close_time;
            ledger_master_snapshot.queued_transactions = queued_transactions;
            ledger_master_snapshot.candidate_set_hash = hex::encode_upper(candidate_set_hash);
        }
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
        let server_state = crate::network::ops::snapshot_server_state_label(
            state.sync_done,
            age,
            state.peer_txs.len(),
        );

        crate::rpc::RpcSnapshot {
            ledger_seq: state.ctx.ledger_seq,
            ledger_hash: state.ctx.ledger_hash.clone(),
            ledger_header: state.ctx.ledger_header.clone(),
            fees: state.ctx.fees,
            peer_count: state.peer_txs.len(),
            object_count,
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
            validation_quorum: state
                .current_round
                .as_ref()
                .map(|r| r.quorum())
                .unwrap_or(0),
            load_snapshot,
            state_accounting_snapshot: Some(
                state
                    .services
                    .state_accounting
                    .snapshot(server_state, now),
            ),
            pubkey_node,
            validator_key: validator_key_b58,
        }
    }
}
