use super::*;
use crate::consensus::{ConsensusMode, Proposal, Validation};
use crate::network::relay;
use std::time::{Duration, SystemTime};

pub(super) struct ConsensusRoundStart {
    pub next_seq: u32,
    pub prev_hash: [u8; 32],
    pub close_time: u32,
    pub should_propose: bool,
}

pub(super) struct ConsensusEstablishOutcome {
    pub wrong_ledger_hash: Option<[u8; 32]>,
}

pub(super) struct ClosedLedgerRound {
    pub seq: u32,
    pub applied: usize,
    pub ledger_hash_hex: String,
    pub tx_records: Vec<crate::ledger::history::TxRecord>,
    pub close_time_u64: u64,
}

impl Node {
    async fn pause_consensus_close_loop(&self, reason: &'static str) {
        info!("consensus close loop paused: {reason}");
        let mut state = self.state.write().await;
        state.current_round = None;
    }

    pub(super) fn signing_key(&self) -> &Secp256k1KeyPair {
        self.validator_key.as_ref().unwrap_or(&self.node_key)
    }

    /// Consensus-driven ledger close loop.
    ///
    /// Phases per round:
    /// 1. **Open** (1s): collect transactions in the pool.
    /// 2. **Propose**: broadcast the local tx-set hash to peers.
    /// 3. **Establish** (3s): collect peer proposals, converge.
    /// 4. **Accept**: apply the agreed tx set, close the ledger.
    /// 5. **Validate**: broadcast a validation of the new ledger hash.
    pub(super) async fn run_ledger_close_loop(self: Arc<Self>) {
        use std::time::Duration;

        tokio::time::sleep(Duration::from_secs(2)).await;

        let mut prev_round_time = Duration::from_secs(4);
        let mut prev_proposers: usize = 0;
        let mut persistent_mode = crate::consensus::ConsensusMode::Proposing;

        loop {
            if let Some(reason) = self.consensus_close_loop_pause_reason().await {
                self.pause_consensus_close_loop(reason).await;
                return;
            }

            if !self.await_open_phase(prev_round_time).await {
                return;
            }
            let round_start = self
                .start_consensus_round(prev_round_time, prev_proposers, persistent_mode)
                .await;
            let close_time = round_start.close_time;

            let Some(establish) = self.run_consensus_establish_phase(&round_start).await else {
                return;
            };

            if let Some(correct_hash) = establish.wrong_ledger_hash {
                self.handle_wrong_ledger_recovery(correct_hash).await;
                persistent_mode = crate::consensus::ConsensusMode::WrongLedger;
                continue;
            }

            if let Some(reason) = self.consensus_close_loop_pause_reason().await {
                self.pause_consensus_close_loop(reason).await;
                return;
            }

            let closed = self
                .accept_and_close_current_round(
                    close_time,
                    &mut prev_round_time,
                    &mut prev_proposers,
                )
                .await;
            self.finalize_validation_round(closed.seq, &mut persistent_mode)
                .await;
            self.emit_closed_ledger_events(&closed, close_time).await;
        }
    }

    pub(super) async fn await_open_phase(&self, prev_round_time: Duration) -> bool {
        let open_start = tokio::time::Instant::now();
        loop {
            if let Some(reason) = self.consensus_close_loop_pause_reason().await {
                self.pause_consensus_close_loop(reason).await;
                return false;
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
            let open_time = open_start.elapsed();
            let (has_txs, prev_proposers, proposers_closed, proposers_validated) = {
                let state = self.state.read().await;
                let next_seq = state.ctx.ledger_seq + 1;
                let prev_proposers = state
                    .current_round
                    .as_ref()
                    .map(|round| round.proposal_count())
                    .unwrap_or(0);
                let proposers_validated = state
                    .current_round
                    .as_ref()
                    .map(|round| round.validation_count())
                    .unwrap_or(0);
                let pool_guard = state.ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
                let has_txs = !pool_guard.is_empty();
                drop(pool_guard);
                (
                    has_txs,
                    prev_proposers,
                    state
                        .staged_proposals
                        .values()
                        .filter(|p| p.ledger_seq == next_seq)
                        .count(),
                    proposers_validated,
                )
            };
            let force_close = {
                let state = self.state.read().await;
                let requested_via_service = state
                    .ctx
                    .ledger_accept_service
                    .as_ref()
                    .map(|service| service.take_requested())
                    .unwrap_or(false);
                let requested_via_flag = state
                    .ctx
                    .force_ledger_accept
                    .as_ref()
                    .map(|flag| flag.swap(false, std::sync::atomic::Ordering::SeqCst))
                    .unwrap_or(false);
                requested_via_service || requested_via_flag
            };
            if force_close
                || should_close_ledger(
                    has_txs,
                    prev_proposers,
                    proposers_closed,
                    proposers_validated,
                    prev_round_time,
                    open_time,
                    open_time,
                    Duration::from_secs(15),
                )
            {
                if force_close {
                    info!("ledger_accept requested: forcing ledger close");
                }
                return true;
            }
        }
    }

    pub(super) async fn start_consensus_round(
        &self,
        prev_round_time: Duration,
        prev_proposers: usize,
        persistent_mode: ConsensusMode,
    ) -> ConsensusRoundStart {
        let next_seq = {
            let state = self.state.read().await;
            state.ctx.ledger_seq + 1
        };

        let tx_set_hash = {
            let state = self.state.read().await;
            let pool_guard = state.ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
            let hash = pool_guard.canonical_set_hash();
            drop(pool_guard);
            hash
        };

        let close_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs().saturating_sub(946684800) as u32)
            .unwrap_or(0);

        let prev_hash = {
            let state = self.state.read().await;
            state.ctx.ledger_header.hash
        };
        let proposal = Proposal::new_signed(
            next_seq,
            tx_set_hash,
            prev_hash,
            close_time,
            0,
            self.signing_key(),
        );
        let prop_msg = relay::encode_proposal(&proposal);

        let should_propose = persistent_mode == ConsensusMode::Proposing
            && !self
                .unl
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty();
        {
            let mut state = self.state.write().await;
            let unl_snapshot = self.unl.read().unwrap_or_else(|e| e.into_inner()).clone();
            let mut round = crate::consensus::ConsensusRound::new(
                next_seq,
                unl_snapshot,
                prev_hash,
                should_propose,
                prev_round_time,
                prev_proposers,
            );
            round.mode = persistent_mode;
            round.our_close_time = close_time as u64;
            round.close_ledger(tx_set_hash);
            let staged = std::mem::take(&mut state.staged_proposals);
            for (key, prop) in staged {
                if prop.ledger_seq == next_seq
                    && prop.prop_seq != crate::consensus::round::SEQ_LEAVE
                {
                    if round.add_proposal(prop.clone()) {
                        round.add_close_time_vote(prop.close_time as u64);
                    }
                } else if prop.ledger_seq > next_seq {
                    state.staged_proposals.insert(key, prop);
                }
            }
            state.current_round = Some(round);
            if should_propose {
                state.broadcast(&prop_msg, None);
            }
        }
        let _ = self
            .ws_events
            .send(crate::rpc::ws::WsEvent::ConsensusPhase {
                consensus: "establish".to_string(),
            });
        if should_propose {
            info!(
                "proposed ledger {next_seq} tx_set={}...",
                &hex::encode_upper(tx_set_hash)[..16]
            );
        } else {
            info!("observing ledger {next_seq} (mode={:?})", persistent_mode);
        }

        ConsensusRoundStart {
            next_seq,
            prev_hash,
            close_time,
            should_propose,
        }
    }

    pub(super) async fn run_consensus_establish_phase(
        &self,
        round_start: &ConsensusRoundStart,
    ) -> Option<ConsensusEstablishOutcome> {
        let phase_start = tokio::time::Instant::now();
        let mut prop_seq = 0u32;
        let mut last_propose_time = tokio::time::Instant::now();
        let mut wrong_ledger_hash: Option<[u8; 32]> = None;
        loop {
            if let Some(reason) = self.consensus_close_loop_pause_reason().await {
                self.pause_consensus_close_loop(reason).await;
                return None;
            }

            tokio::time::sleep(Duration::from_millis(250)).await;

            {
                let mut state = self.state.write().await;
                if let Some(ref mut round) = state.current_round {
                    if let Some(correct_parent) = round.check_wrong_ledger() {
                        warn!(
                            "consensus: wrong ledger! majority on {} but we're on {} — bowing out",
                            &hex::encode_upper(correct_parent)[..16],
                            &hex::encode_upper(round_start.prev_hash)[..16],
                        );
                        round.handle_wrong_ledger();
                        wrong_ledger_hash = Some(correct_parent);
                        break;
                    }
                }
            }

            let new_position = {
                let mut state = self.state.write().await;
                if let Some(ref mut round) = state.current_round {
                    let cp = round.converge_percent();
                    let changed = round.update_disputes(cp);
                    if changed.is_empty() {
                        round.tick_unchanged();
                    } else {
                        round.reset_unchanged();
                    }
                    round.check_close_time_consensus();
                    round.try_converge()
                } else {
                    None
                }
            };

            if let Some(new_hash) = new_position {
                prop_seq += 1;
                let updated = Proposal::new_signed(
                    round_start.next_seq,
                    new_hash,
                    round_start.prev_hash,
                    round_start.close_time,
                    prop_seq,
                    self.signing_key(),
                );
                let msg = relay::encode_proposal(&updated);
                let state = self.state.read().await;
                state.broadcast(&msg, None);
                info!(
                    "consensus: updated position prop_seq={} tx_set={}...",
                    prop_seq,
                    &hex::encode_upper(new_hash)[..16],
                );
            }

            let cs = {
                let mut state = self.state.write().await;
                if let Some(ref mut round) = state.current_round {
                    if round.unl_size() == 0 {
                        if round.establish_elapsed() >= crate::consensus::round::MIN_CONSENSUS {
                            crate::consensus::round::ConsensusState::Yes
                        } else {
                            crate::consensus::round::ConsensusState::No
                        }
                    } else {
                        round.check_consensus()
                    }
                } else {
                    crate::consensus::round::ConsensusState::Yes
                }
            };

            match cs {
                crate::consensus::round::ConsensusState::Yes => {
                    let elapsed = phase_start.elapsed();
                    info!(
                        "consensus: reached after {:.1}s (TX + close time agreement)",
                        elapsed.as_secs_f64()
                    );
                    break;
                }
                crate::consensus::round::ConsensusState::MovedOn => {
                    let elapsed = phase_start.elapsed();
                    warn!(
                        "consensus: network moved on without us after {:.1}s",
                        elapsed.as_secs_f64()
                    );
                    break;
                }
                crate::consensus::round::ConsensusState::Expired => {
                    let elapsed = phase_start.elapsed();
                    warn!(
                        "consensus: expired after {:.1}s — force accepting",
                        elapsed.as_secs_f64()
                    );
                    break;
                }
                crate::consensus::round::ConsensusState::No => {}
            }

            if round_start.should_propose && last_propose_time.elapsed() > Duration::from_secs(12) {
                last_propose_time = tokio::time::Instant::now();
                if let Some(pos) = {
                    let state = self.state.read().await;
                    state.current_round.as_ref().and_then(|r| r.our_position)
                } {
                    prop_seq += 1;
                    let refreshed = Proposal::new_signed(
                        round_start.next_seq,
                        pos,
                        round_start.prev_hash,
                        round_start.close_time,
                        prop_seq,
                        self.signing_key(),
                    );
                    let msg = relay::encode_proposal(&refreshed);
                    let state = self.state.read().await;
                    state.broadcast(&msg, None);
                    info!("consensus: refreshed proposal prop_seq={}", prop_seq);
                }
            }
        }

        Some(ConsensusEstablishOutcome { wrong_ledger_hash })
    }

    pub(super) async fn handle_wrong_ledger_recovery(&self, correct_hash: [u8; 32]) {
        info!(
            "consensus: wrong-ledger recovery — requesting correct parent {}...",
            &hex::encode_upper(correct_hash)[..16],
        );

        {
            let mut guard = self
                .inbound_ledgers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.acquire(
                correct_hash,
                0,
                crate::ledger::inbound::InboundReason::Consensus,
            );
        }

        let cookie = rand::random::<u64>();
        let base_req = relay::encode_get_ledger_base(&correct_hash, cookie);
        {
            let state = self.state.read().await;
            state.broadcast(&base_req, None);
        }

        warn!("consensus: staying in WrongLedger — follower will acquire correct branch");

        {
            let mut state = self.state.write().await;
            state.current_round = None;
        }
    }

    pub(super) async fn accept_and_close_current_round(
        &self,
        close_time: u32,
        prev_round_time: &mut Duration,
        prev_proposers: &mut usize,
    ) -> ClosedLedgerRound {
        let (consensus_close_time, have_ct_consensus) = {
            let state = self.state.read().await;
            if let Some(ref round) = state.current_round {
                (round.our_close_time, round.have_close_time_consensus)
            } else {
                (0u64, false)
            }
        };
        {
            let mut state = self.state.write().await;
            if let Some(ref mut round) = state.current_round {
                if let Some(result) = round.accept() {
                    let state_label = match result.state {
                        crate::consensus::round::ConsensusState::Yes => "Yes",
                        crate::consensus::round::ConsensusState::MovedOn => "MovedOn",
                        crate::consensus::round::ConsensusState::Expired => "Expired",
                        crate::consensus::round::ConsensusState::No => "No",
                    };
                    info!(
                        "consensus: accepted ledger {} — {}/{} agree ({:.0}%) state={} round_time={:.1}s close_time_consensus={}",
                        result.ledger_seq,
                        result.agree_count,
                        result.unl_size,
                        result.agreement_pct() * 100.0,
                        state_label,
                        result.round_time.as_secs_f64(),
                        have_ct_consensus,
                    );
                    *prev_round_time = result.round_time;
                    *prev_proposers = result.proposers;
                }
            }
        }
        let _ = self
            .ws_events
            .send(crate::rpc::ws::WsEvent::ConsensusPhase {
                consensus: "accepted".to_string(),
            });

        let close_time_u64 = if have_ct_consensus && consensus_close_time > 0 {
            consensus_close_time
        } else {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        };

        let (prev_header, ls_arc, mut tx_pool) = {
            let state = self.state.write().await;
            let prev_header = state.ctx.ledger_header.clone();
            let ls_arc = state.ctx.ledger_state.clone();
            let tx_pool =
                std::mem::take(&mut *state.ctx.tx_pool.write().unwrap_or_else(|e| e.into_inner()));
            (prev_header, ls_arc, tx_pool)
        };

        let result = {
            let mut ls = ls_arc.lock().unwrap_or_else(|e| e.into_inner());
            crate::ledger::close::close_ledger(
                &prev_header,
                &mut ls,
                &mut tx_pool,
                close_time_u64,
                have_ct_consensus,
            )
        };

        let seq = result.header.sequence;
        let hash = result.header.hash;
        let applied = result.applied_count;
        let failed = result.failed_count;
        let skipped = result.skipped_count;
        let tx_records = result.tx_records.clone();
        let close_time_u64 = result.header.close_time;
        let ledger_hash_hex = hex::encode_upper(hash);

        let updated_fees = {
            let ls = ls_arc.lock().unwrap_or_else(|e| e.into_inner());
            crate::ledger::read_fees(&ls)
        };

        {
            let mut state = self.state.write().await;
            state.ctx.ledger_header = result.header.clone();
            state.ctx.ledger_seq = seq;
            state.ctx.ledger_hash = ledger_hash_hex.clone();
            state.ctx.fees = updated_fees;
            for rec in &tx_records {
                state
                    .services
                    .tx_master
                    .observe_accepted(rec, crate::transaction::master::unix_now());
            }
            if !tx_pool.is_empty() {
                *state.ctx.tx_pool.write().unwrap_or_else(|e| e.into_inner()) = tx_pool;
            }
            let queued_transactions = state
                .ctx
                .tx_pool
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .len();
            let candidate_set_hash = {
                let pool = state.ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
                pool.canonical_set_hash()
            };
            state
                .ctx
                .history
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert_ledger(result.header.clone(), result.tx_records.clone());
            let complete_ledgers = state
                .ctx
                .history
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .complete_ledgers();
            state.services.ledger_master.note_closed(
                &result.header,
                complete_ledgers,
                queued_transactions,
                candidate_set_hash,
            );
        }

        let closed_ledger = {
            let mut ls = ls_arc.lock().unwrap_or_else(|e| e.into_inner());
            let state_map = ls.snapshot_state_map();
            let tx_map = crate::ledger::shamap::SHAMap::new_transaction();
            std::sync::Arc::new(crate::ledger::ledger_core::ClosedLedger::new(
                crate::ledger::views::LedgerInfo {
                    seq,
                    hash,
                    close_time: close_time_u64,
                    account_hash: result.header.account_hash,
                    tx_hash: result.header.transaction_hash,
                    total_coins: result.header.total_coins,
                    ..Default::default()
                },
                state_map,
                tx_map,
                crate::ledger::fees::Fees {
                    base_fee: updated_fees.base,
                    reserve_base: updated_fees.reserve,
                    reserve_inc: updated_fees.increment,
                },
                crate::ledger::rules::Rules::new(),
            ))
        };
        {
            let mut state = self.state.write().await;
            state.ctx.closed_ledger = Some(closed_ledger.clone());
            let (queued_transactions, candidate_set_hash, metrics, pool_snapshot) = {
                let pool = state.ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
                (
                    pool.len(),
                    pool.canonical_set_hash(),
                    pool.metrics.clone(),
                    pool.clone(),
                )
            };
            state.services.open_ledger.accept(
                closed_ledger,
                &result.header,
                &pool_snapshot,
                queued_transactions,
                candidate_set_hash,
                &metrics,
            );
        }

        if let Some(ref store) = self.storage {
            let _ = store.save_ledger(&result.header, &result.tx_records);
            let _ = store.save_meta(seq, &ledger_hash_hex, &result.header);
            let _ = store.flush();
        }

        if let Some(service) = {
            let state = self.state.read().await;
            state.ctx.ledger_accept_service.clone()
        } {
            service.complete(seq.saturating_add(1));
        }

        info!(
            "ledger {seq} closed — applied={applied} failed={failed} skipped={skipped} hash={}...",
            &hex::encode_upper(hash)[..16],
        );

        self.update_rpc_snapshot().await;

        let validation = Validation::new_signed(seq, hash, close_time, true, self.signing_key());
        let _ = self
            .ws_events
            .send(crate::rpc::ws::WsEvent::ValidationReceived {
                validation: validation.clone(),
                network_id: self.config.network_id,
            });
        let val_msg = relay::encode_validation(&validation);
        {
            let state = self.state.read().await;
            state.broadcast(&val_msg, None);
        }
        info!("validated ledger {seq}");

        ClosedLedgerRound {
            seq,
            applied,
            ledger_hash_hex,
            tx_records,
            close_time_u64,
        }
    }

    pub(super) async fn finalize_validation_round(
        &self,
        seq: u32,
        persistent_mode: &mut ConsensusMode,
    ) {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut state = self.state.write().await;
        if let Some(ref mut round) = state.current_round {
            if let Some(validated_hash) = round.check_validated() {
                info!(
                    "consensus: ledger {} fully validated (80%+ quorum) hash={}...",
                    seq,
                    &hex::encode_upper(validated_hash)[..16],
                );
                *persistent_mode = ConsensusMode::Proposing;
                let _ = self
                    .ws_events
                    .send(crate::rpc::ws::WsEvent::ConsensusPhase {
                        consensus: "validated".to_string(),
                    });
            }
            if round.mode == ConsensusMode::WrongLedger {
                *persistent_mode = ConsensusMode::WrongLedger;
            } else if round.mode == ConsensusMode::SwitchedLedger {
                *persistent_mode = ConsensusMode::Observing;
            }
        }
        state.current_round = None;
    }

    pub(super) async fn emit_closed_ledger_events(
        &self,
        closed: &ClosedLedgerRound,
        close_time: u32,
    ) {
        let (validated_ledgers, peer_count, ws_fees, load_snapshot, server_status) = {
            let st = self.state.read().await;
            let validated_ledgers = st
                .ctx
                .history
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .complete_ledgers();
            let peer_count = st.peer_count();
            let follower_healthy = Self::follower_healthy_for_status(&st);
            let age = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .saturating_sub(st.ctx.ledger_header.close_time as u64 + 946_684_800);
            let server_status = crate::network::ops::snapshot_server_state_label(
                st.sync_done,
                follower_healthy,
                age,
                peer_count,
            );
            (
                validated_ledgers,
                peer_count,
                st.ctx.fees,
                st.services.load_manager.snapshot(),
                server_status.to_string(),
            )
        };
        let _ = self.ws_events.send(crate::rpc::ws::WsEvent::LedgerClosed {
            ledger_seq: closed.seq,
            ledger_hash: closed.ledger_hash_hex.clone(),
            tx_count: closed.applied,
            ledger_time: close_time as u64,
            network_id: self.config.network_id,
            validated_ledgers: validated_ledgers.clone(),
            fee_base: ws_fees.base,
            reserve_base: ws_fees.reserve,
            reserve_inc: ws_fees.increment,
        });
        let _ = self.ws_events.send(crate::rpc::ws::WsEvent::ServerStatus {
            ledger_seq: closed.seq,
            ledger_hash: closed.ledger_hash_hex.clone(),
            network_id: self.config.network_id,
            peer_count,
            validated_ledgers: validated_ledgers.clone(),
            server_status,
            load_snapshot,
            base_fee: ws_fees.base,
        });
        {
            let book_changes_ctx = {
                let st = self.state.read().await;
                Self::build_rpc_read_context(&st, 0, None)
            };
            if let Ok(payload) = crate::rpc::handlers::book_changes(
                &serde_json::json!({"ledger_index": closed.seq}),
                &book_changes_ctx,
            ) {
                let _ = self
                    .ws_events
                    .send(crate::rpc::ws::WsEvent::BookChanges { payload });
            }
        }
        for rec in &closed.tx_records {
            let accounts = transaction_accounts_from_blob(&rec.blob);
            let _ = self.ws_events.send(crate::rpc::ws::WsEvent::Transaction {
                tx_record: rec.clone(),
                ledger_hash: closed.ledger_hash_hex.clone(),
                close_time: closed.close_time_u64,
                network_id: self.config.network_id,
                accounts,
            });
        }
    }
}
