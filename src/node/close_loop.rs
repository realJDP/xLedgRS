use super::*;
use crate::consensus::round::ConsensusState;
use crate::consensus::{ConsensusMode, Proposal, Validation};
use crate::network::relay;
use std::time::{Duration, SystemTime};

const RIPPLE_EPOCH_UNIX_OFFSET: u64 = 946_684_800;

pub(super) struct ConsensusRoundStart {
    pub next_seq: u32,
    pub prev_hash: [u8; 32],
    pub close_time: u32,
    pub should_propose: bool,
}

pub(super) struct ConsensusEstablishOutcome {
    pub wrong_ledger_hash: Option<[u8; 32]>,
    pub terminal_state: ConsensusState,
}

pub(super) struct ClosedLedgerRound {
    pub seq: u32,
    pub applied: usize,
    pub ledger_hash_hex: String,
    pub tx_records: Vec<crate::ledger::history::TxRecord>,
    pub close_time_u64: u64,
}

impl Node {
    pub(super) fn effective_unl_for_parent_ledger(
        &self,
        state: &SharedState,
    ) -> (Vec<Vec<u8>>, usize) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let original_unl = if let Some(manager) = state.ctx.validator_list_manager.as_ref() {
            manager
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot(now)
                .effective_unl
        } else {
            self.unl.read().unwrap_or_else(|e| e.into_inner()).clone()
        };
        let negative_unl_key = crate::ledger::keylet::negative_unl().key;
        let negative_unl_raw = state
            .ctx
            .closed_ledger
            .as_ref()
            .and_then(|closed| closed.get_raw(&negative_unl_key))
            .or_else(|| {
                state
                    .ctx
                    .ledger_state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_raw(&negative_unl_key)
                    .map(|raw| raw.to_vec())
            });
        let disabled = crate::validator_list::disabled_validators_from_negative_unl_raw(
            negative_unl_raw.as_deref(),
        );
        let effective = crate::validator_list::apply_negative_unl(&original_unl, &disabled);
        (effective, original_unl.len())
    }

    async fn pause_consensus_close_loop(&self, reason: &'static str) {
        info!("consensus close loop paused: {reason}");
        let mut state = self.state.write().await;
        state.current_round = None;
    }

    pub(super) fn consensus_signing_key(&self) -> Option<&Secp256k1KeyPair> {
        self.validator_key.as_ref().or_else(|| {
            self.config
                .allow_node_key_consensus
                .then_some(&self.node_key)
        })
    }

    pub(super) fn broadcast_local_validator_manifests(&self, state: &SharedState) {
        if self.local_validator_manifests.is_empty() {
            return;
        }
        let msg = relay::encode_manifests(&self.local_validator_manifests);
        state.broadcast(&msg, None);
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

            if establish.terminal_state != ConsensusState::Yes {
                warn!(
                    "consensus: not closing local ledger after {:?}; observing/acquiring network tip instead",
                    establish.terminal_state
                );
                persistent_mode = ConsensusMode::Observing;
                let mut state = self.state.write().await;
                state.current_round = None;
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
            let Some(closed) = closed else {
                persistent_mode = ConsensusMode::Observing;
                continue;
            };
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
            let hash = state
                .ctx
                .consensus_tx_sets
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert_local_pool_snapshot(&pool_guard)
                .hash();
            drop(pool_guard);
            hash
        };

        let close_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs().saturating_sub(RIPPLE_EPOCH_UNIX_OFFSET) as u32)
            .unwrap_or(0);

        let prev_hash = {
            let state = self.state.read().await;
            state.ctx.ledger_header.hash
        };
        let (unl_snapshot, original_unl_size) = {
            let state = self.state.read().await;
            self.effective_unl_for_parent_ledger(&state)
        };
        let should_propose = persistent_mode == ConsensusMode::Proposing
            && self.consensus_signing_key().is_some()
            && !unl_snapshot.is_empty();
        let prop_msg = if should_propose {
            self.consensus_signing_key().map(|key| {
                relay::encode_proposal(&Proposal::new_signed(
                    next_seq,
                    tx_set_hash,
                    prev_hash,
                    close_time,
                    0,
                    key,
                ))
            })
        } else {
            None
        };
        {
            let mut state = self.state.write().await;
            let prevalidated_manifests = state
                .ctx
                .manifest_cache
                .as_ref()
                .map(|cache| {
                    cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .active_manifests()
                })
                .unwrap_or_default();
            let trust = crate::consensus::round::RoundTrustSnapshot::new(
                unl_snapshot,
                prevalidated_manifests,
                Some(original_unl_size),
            );
            let mut round = crate::consensus::ConsensusRound::new_with_trust_snapshot(
                next_seq,
                trust,
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
                self.broadcast_local_validator_manifests(&state);
            }
            if let Some(prop_msg) = prop_msg.as_ref() {
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
        let mut terminal_state = ConsensusState::Yes;
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
                let Some(signing_key) = self.consensus_signing_key() else {
                    warn!("consensus: cannot update proposal without validator signing key");
                    continue;
                };
                prop_seq += 1;
                let updated = Proposal::new_signed(
                    round_start.next_seq,
                    new_hash,
                    round_start.prev_hash,
                    round_start.close_time,
                    prop_seq,
                    signing_key,
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
                    round.check_consensus()
                } else {
                    crate::consensus::round::ConsensusState::Yes
                }
            };

            match cs {
                crate::consensus::round::ConsensusState::Yes => {
                    terminal_state = ConsensusState::Yes;
                    let elapsed = phase_start.elapsed();
                    info!(
                        "consensus: reached after {:.1}s (TX + close time agreement)",
                        elapsed.as_secs_f64()
                    );
                    break;
                }
                crate::consensus::round::ConsensusState::MovedOn => {
                    terminal_state = ConsensusState::MovedOn;
                    let elapsed = phase_start.elapsed();
                    warn!(
                        "consensus: network moved on without us after {:.1}s",
                        elapsed.as_secs_f64()
                    );
                    break;
                }
                crate::consensus::round::ConsensusState::Expired => {
                    terminal_state = ConsensusState::Expired;
                    let elapsed = phase_start.elapsed();
                    warn!(
                        "consensus: expired after {:.1}s — not force accepting on live consensus",
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
                    let Some(signing_key) = self.consensus_signing_key() else {
                        warn!("consensus: cannot refresh proposal without validator signing key");
                        continue;
                    };
                    prop_seq += 1;
                    let refreshed = Proposal::new_signed(
                        round_start.next_seq,
                        pos,
                        round_start.prev_hash,
                        round_start.close_time,
                        prop_seq,
                        signing_key,
                    );
                    let msg = relay::encode_proposal(&refreshed);
                    let state = self.state.read().await;
                    state.broadcast(&msg, None);
                    info!("consensus: refreshed proposal prop_seq={}", prop_seq);
                }
            }
        }

        Some(ConsensusEstablishOutcome {
            wrong_ledger_hash,
            terminal_state,
        })
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
    ) -> Option<ClosedLedgerRound> {
        let (consensus_close_time, have_ct_consensus) = {
            let state = self.state.read().await;
            if let Some(ref round) = state.current_round {
                (round.our_close_time, round.have_close_time_consensus)
            } else {
                (0u64, false)
            }
        };
        let accepted_result = {
            let mut state = self.state.write().await;
            let result = state
                .current_round
                .as_mut()
                .and_then(|round| round.accept());
            if let Some(ref result) = result {
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
            result
        };
        let Some(accepted_result) = accepted_result else {
            warn!("consensus: accept requested without an accepted round");
            return None;
        };
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
                .map(|d| d.as_secs().saturating_sub(RIPPLE_EPOCH_UNIX_OFFSET))
                .unwrap_or(0)
        };

        let (prev_header, ls_arc, live_tx_pool) = {
            let state = self.state.write().await;
            let prev_header = state.ctx.ledger_header.clone();
            let ls_arc = state.ctx.ledger_state.clone();
            let tx_pool =
                std::mem::take(&mut *state.ctx.tx_pool.write().unwrap_or_else(|e| e.into_inner()));
            (prev_header, ls_arc, tx_pool)
        };

        let accepted_entries = {
            let state = self.state.read().await;
            let entries = state
                .ctx
                .consensus_tx_sets
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .accepted_pool_entries(&accepted_result.tx_set_hash);
            entries
        };
        let Some(accepted_entries) = accepted_entries else {
            {
                let state = self.state.write().await;
                *state.ctx.tx_pool.write().unwrap_or_else(|e| e.into_inner()) = live_tx_pool;
            }
            warn!(
                "consensus: accepted tx set {} is not available as an immutable candidate — requesting liTS_CANDIDATE and refusing to close/validate",
                hex::encode_upper(&accepted_result.tx_set_hash[..8]),
            );
            self.request_candidate_tx_set(accepted_result.tx_set_hash)
                .await;
            let mut state = self.state.write().await;
            state.current_round = None;
            return None;
        };
        let (mut tx_pool, mut requeue_pool) = {
            let accepted_hashes: std::collections::HashSet<[u8; 32]> =
                accepted_entries.iter().map(|entry| entry.hash).collect();
            let mut remaining = live_tx_pool.clone();
            for hash in &accepted_hashes {
                remaining.remove(hash);
            }
            let metrics = live_tx_pool.metrics.clone();
            (
                crate::ledger::TxPool::from_entries_with_metrics(accepted_entries, metrics),
                Some(remaining),
            )
        };

        let result = {
            let mut ls = ls_arc.lock().unwrap_or_else(|e| e.into_inner());
            crate::ledger::close::close_ledger_with_network_id(
                &prev_header,
                &mut ls,
                &mut tx_pool,
                close_time_u64,
                have_ct_consensus,
                self.config.network_id,
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
            if let Some(mut remaining) = requeue_pool.take() {
                if !tx_pool.is_empty() {
                    remaining.extend_entries(tx_pool.snapshot_entries());
                }
                *state.ctx.tx_pool.write().unwrap_or_else(|e| e.into_inner()) = remaining;
            } else if !tx_pool.is_empty() {
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
            let mut tx_map = crate::ledger::shamap::SHAMap::new_transaction();
            for rec in &tx_records {
                tx_map.insert(
                    crate::ledger::Key(rec.hash),
                    crate::ledger::close::encode_tx_leaf_data(&rec.blob, &rec.meta),
                );
            }
            let rules =
                crate::ledger::rules::Rules::from_amendments(crate::ledger::read_amendments(&ls));
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
                rules,
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

        if let Some(validator_key) = self.validator_key.as_ref() {
            let sign_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs().saturating_sub(RIPPLE_EPOCH_UNIX_OFFSET) as u32)
                .unwrap_or(close_time);
            let validation = Validation::new_signed_with_close_time(
                seq,
                hash,
                sign_time,
                close_time_u64 as u32,
                true,
                validator_key,
            );
            let _ = self
                .ws_events
                .send(crate::rpc::ws::WsEvent::ValidationReceived {
                    validation: validation.clone(),
                    network_id: self.config.network_id,
                });
            let val_msg = relay::encode_validation(&validation);
            {
                let state = self.state.read().await;
                self.broadcast_local_validator_manifests(&state);
                state.broadcast(&val_msg, None);
            }
            info!("broadcast validation candidate for ledger {seq}");
        } else {
            info!("not broadcasting validation for ledger {seq}: validator key unavailable");
        }

        Some(ClosedLedgerRound {
            seq,
            applied,
            ledger_hash_hex,
            tx_records,
            close_time_u64,
        })
    }

    pub(super) async fn finalize_validation_round(
        &self,
        seq: u32,
        persistent_mode: &mut ConsensusMode,
    ) {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut acquire_mismatch: Option<[u8; 32]> = None;
        let mut promote_validated: Option<[u8; 32]> = None;
        let mut state = self.state.write().await;
        let local_seq = state.ctx.ledger_header.sequence;
        let local_hash = state.ctx.ledger_header.hash;
        if let Some(ref mut round) = state.current_round {
            if let Some(validated_hash) = round.check_validated_for(seq) {
                info!(
                    "consensus: ledger {} fully validated (80%+ quorum) hash={}...",
                    seq,
                    &hex::encode_upper(validated_hash)[..16],
                );
                if local_seq == seq && local_hash == validated_hash {
                    promote_validated = Some(validated_hash);
                } else {
                    warn!(
                        "consensus: quorum validated ledger {} hash={} but local head is seq={} hash={} — acquiring instead of promoting",
                        seq,
                        &hex::encode_upper(validated_hash)[..16],
                        local_seq,
                        &hex::encode_upper(local_hash)[..16],
                    );
                    acquire_mismatch = Some(validated_hash);
                }
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
        if let Some(validated_hash) = promote_validated {
            state
                .services
                .ledger_master
                .note_validated_head(seq, validated_hash);
        }
        state.current_round = None;
        drop(state);

        if let Some(hash) = acquire_mismatch {
            self.handle_wrong_ledger_recovery(hash).await;
            *persistent_mode = ConsensusMode::WrongLedger;
        }
    }

    pub(super) async fn emit_closed_ledger_events(
        &self,
        closed: &ClosedLedgerRound,
        _round_start_close_time: u32,
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
            ledger_time: closed.close_time_u64,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header(seq: u32, hash: [u8; 32]) -> crate::ledger::LedgerHeader {
        crate::ledger::LedgerHeader {
            sequence: seq,
            hash,
            parent_hash: [0x10; 32],
            close_time: seq as u64,
            total_coins: 100_000_000_000,
            account_hash: [0x12; 32],
            transaction_hash: [0x13; 32],
            parent_close_time: seq.saturating_sub(1),
            close_time_resolution: 30,
            close_flags: 0,
        }
    }

    #[tokio::test]
    async fn finalize_validation_round_acquires_same_seq_different_hash_quorum() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let validators = (0..10)
            .map(|_| crate::crypto::keys::Secp256k1KeyPair::generate())
            .collect::<Vec<_>>();
        let unl = validators
            .iter()
            .map(|kp| kp.public_key_bytes())
            .collect::<Vec<_>>();
        let local_hash = [0x21; 32];
        let network_hash = [0x42; 32];
        let mut round = crate::consensus::ConsensusRound::new(
            7,
            unl,
            [0x10; 32],
            true,
            Duration::from_secs(4),
            0,
        );
        for validator in &validators[..8] {
            round.add_validation(crate::consensus::Validation::new_signed(
                7,
                network_hash,
                0,
                true,
                validator,
            ));
        }

        {
            let mut state = node.state.write().await;
            state.ctx.ledger_header = test_header(7, local_hash);
            state.ctx.ledger_seq = 7;
            state.current_round = Some(round);
        }

        let mut persistent_mode = ConsensusMode::Proposing;
        node.finalize_validation_round(7, &mut persistent_mode)
            .await;

        assert_eq!(persistent_mode, ConsensusMode::WrongLedger);
        let guard = node
            .inbound_ledgers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let acquisition = guard
            .get(&network_hash)
            .expect("different-hash quorum should trigger acquisition");
        assert_eq!(acquisition.ledger_seq, 0);
    }
}
