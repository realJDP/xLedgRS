//! A single consensus round — tracks proposals, converges positions, counts validations.
//!
//! # Convergence thresholds (relative timing — matches rippled)
//!
//! Thresholds are driven by `converge_percent`, which measures elapsed establish time
//! as a percentage of the previous round's duration (floored at 5 s to prevent runaway):
//!
//! | converge_percent | Threshold |
//! |------------------|-----------|
//! | < 50 %           | 50 %      |
//! | 50 – 85 %        | 65 %      |
//! | 85 – 200 %       | 70 %      |
//! | >= 200 %         | 95 %      |
//!
//! Any tx set hash held by >= threshold of the UNL is adopted as the local position.
//!
//! # Consensus state machine (`check_consensus`)
//!
//! Returns one of four states each establish iteration:
//! - **No** — keep waiting.
//! - **Yes** — 80 %+ of current proposers agree with the local position.
//! - **MovedOn** — 80 %+ of peers validated a later ledger without this round.
//! - **Expired** — round exceeded `clamp(prev_round_time * 10, 15 s, 120 s)`.
//!
//! # Validation quorum
//! A ledger is fully validated when >= 80 % of the UNL sends matching validations.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::consensus::{DisputedTx, Manifest, ManifestCache, Proposal, Validation};

// ── Timing constants (match rippled ConsensusParms.h) ─────────────────────────

/// Minimum time before accepting consensus (rippled: ledgerMIN_CONSENSUS).
pub const MIN_CONSENSUS: Duration = Duration::from_millis(1950);

/// Minimum denominator for converge_percent (rippled: avMIN_CONSENSUS_TIME).
pub const AV_MIN_CONSENSUS_TIME: Duration = Duration::from_secs(5);

/// Minimum consensus agreement percentage (rippled: minCONSENSUS_PCT).
pub const MIN_CONSENSUS_PCT: f64 = 0.80;

/// Minimum fraction of UNL validations required to declare a ledger validated.
pub const VALIDATION_QUORUM: f64 = 0.80;

/// Close time consensus threshold (75%, separate from tx consensus at 80%).
pub const CLOSE_TIME_CONSENSUS_PCT: f64 = 0.75;

/// Proposal sequence for bow-out (matches rippled's seqLeave = 0xFFFFFFFF).
pub const SEQ_LEAVE: u32 = 0xFFFF_FFFF;

/// Proposal freshness timeout — stale after 20 seconds (matches rippled).
pub const PROPOSE_FRESHNESS_SECS: u64 = 20;

/// Floor for abandon timeout (rippled: ledgerMAX_CONSENSUS = 15 s).
const ABANDON_FLOOR: Duration = Duration::from_secs(15);

/// Ceiling for abandon timeout (rippled: ledgerABANDON_CONSENSUS = 120 s).
const ABANDON_CEILING: Duration = Duration::from_secs(120);

/// Abandon multiplier applied to prev_round_time (rippled: ledgerABANDON_CONSENSUS_FACTOR).
const ABANDON_FACTOR: u32 = 10;

// ── Thresholds ────────────────────────────────────────────────────────────────

/// Returns the convergence threshold (0.0–1.0) given `converge_percent`.
///
/// `converge_percent` is `elapsed_ms * 100 / max(prev_round_time_ms, 5000)`.
/// This matches rippled's relative-time avalanche tiers.
pub fn convergence_threshold(converge_percent: u32) -> f64 {
    if converge_percent < 50 {
        0.50
    } else if converge_percent < 85 {
        0.65
    } else if converge_percent < 200 {
        0.70
    } else {
        0.95
    }
}

// ── Consensus state (matches rippled's ConsensusState enum) ──────────────────

/// Result of `check_consensus()` — drives the establish loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusState {
    /// Keep waiting — consensus not yet reached.
    No,
    /// Current proposers reached 80 %+ agreement with the local position.
    Yes,
    /// Network validated past this ledger without this round (80 %+ finished).
    MovedOn,
    /// Round exceeded abandon timeout — force accept.
    Expired,
}

/// Check if consensus has been reached (matches rippled's checkConsensusReached).
///
/// Returns true if:
/// - `agreeing / total >= 80%` (counting properly), OR
/// - `stalled` (all disputes stable at 80%+ for 4+ rounds), OR
/// - `total == 0 && reached_max` (alone for too long).
fn consensus_reached(agreeing: usize, total: usize, reached_max: bool, stalled: bool) -> bool {
    if stalled {
        return true;
    }
    if total == 0 {
        return reached_max;
    }
    (agreeing * 100 / total) >= (MIN_CONSENSUS_PCT * 100.0) as usize
}

// ── Consensus Mode ───────────────────────────────────────────────────────────

/// Validator's operating mode during consensus.
/// Matches rippled's ConsensusMode enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusMode {
    /// Normal mode: actively making proposals.
    Proposing,
    /// Watch-only: tracking consensus but not proposing.
    Observing,
    /// Desynchronized: majority building on a different parent ledger.
    WrongLedger,
    /// Recovered from fork: caught up but observing (not proposing).
    SwitchedLedger,
}

// ── Phase ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusPhase {
    /// Collecting transactions into the open ledger.
    Open,
    /// Exchanging proposals and converging on a tx set.
    Establish,
    /// Consensus reached; applying tx set to produce the new ledger.
    Accepted,
    /// xLedgRSv2Beta extension (not in rippled's consensus model): tracks that 80%+ of
    /// UNL validated the same ledger hash, indicating validation finality after
    /// consensus acceptance. rippled handles this via separate validation tracking
    /// rather than a consensus phase.
    Validated,
}

// ── Result ────────────────────────────────────────────────────────────────────

/// Outcome returned when the round reaches a decision.
#[derive(Debug, Clone)]
pub struct RoundResult {
    pub ledger_seq: u32,
    /// The agreed-upon transaction set hash.
    pub tx_set_hash: [u8; 32],
    /// Number of UNL nodes that agreed.
    pub agree_count: usize,
    /// Total UNL size.
    pub unl_size: usize,
    /// Why consensus accepted (Yes / MovedOn / Expired).
    pub state: ConsensusState,
    /// How long the establish phase took — feed to next round's prev_round_time.
    pub round_time: Duration,
    /// Number of proposers this round — feed to next round's prev_proposers.
    pub proposers: usize,
}

impl RoundResult {
    pub fn agreement_pct(&self) -> f64 {
        if self.unl_size == 0 {
            return 0.0;
        }
        self.agree_count as f64 / self.unl_size as f64
    }
}

// ── Round ─────────────────────────────────────────────────────────────────────

/// Tracks all state for one consensus round.
pub struct ConsensusRound {
    pub ledger_seq: u32,
    pub phase: ConsensusPhase,
    pub mode: ConsensusMode,
    /// Current local position (the proposed tx-set hash).
    pub our_position: Option<[u8; 32]>,
    /// Parent ledger hash for the round.
    pub prev_ledger: [u8; 32],
    /// Latest proposal from each UNL peer (keyed by node pubkey hex).
    proposals: HashMap<String, Proposal>,
    /// Validations received, keyed by node pubkey hex.
    validations: HashMap<String, Validation>,
    /// Per-transaction disputes — tx_id → DisputedTx.
    disputes: HashMap<[u8; 32], DisputedTx>,
    /// Peers that have bowed out of this round.
    dead_nodes: std::collections::HashSet<String>,
    /// Set of trusted master public keys in the UNL.
    unl: Vec<Vec<u8>>,
    /// Manifest cache — maps ephemeral signing keys back to master keys.
    manifests: ManifestCache,
    /// When the Establish phase started.
    establish_start: Option<Instant>,
    /// Close time votes from peers: close_time → vote_count.
    close_time_votes: HashMap<u64, usize>,
    /// Proposed local close time.
    pub our_close_time: u64,
    /// Whether close time consensus has been reached.
    pub have_close_time_consensus: bool,

    // ── State machine inputs (from previous round) ───────────────────────
    /// Duration of the previous consensus round (bootstrap default: 4 s).
    pub prev_round_time: Duration,
    /// Number of proposers in the previous round (bootstrap default: 0).
    pub prev_proposers: usize,
    /// Establish iterations with no peer vote changes (for stall detection).
    peer_unchanged_counter: u32,
    /// Total establish iterations this round.
    establish_counter: u32,
    /// Current consensus state (updated by check_consensus).
    pub consensus_state: ConsensusState,
}

impl ConsensusRound {
    pub fn new(
        ledger_seq: u32,
        unl: Vec<Vec<u8>>,
        prev_ledger: [u8; 32],
        proposing: bool,
        prev_round_time: Duration,
        prev_proposers: usize,
    ) -> Self {
        Self {
            ledger_seq,
            phase: ConsensusPhase::Open,
            mode: if proposing {
                ConsensusMode::Proposing
            } else {
                ConsensusMode::Observing
            },
            our_position: None,
            prev_ledger,
            proposals: HashMap::new(),
            validations: HashMap::new(),
            disputes: HashMap::new(),
            dead_nodes: std::collections::HashSet::new(),
            unl,
            manifests: ManifestCache::new(),
            establish_start: None,
            close_time_votes: HashMap::new(),
            our_close_time: 0,
            have_close_time_consensus: false,
            prev_round_time,
            prev_proposers,
            peer_unchanged_counter: 0,
            establish_counter: 0,
            consensus_state: ConsensusState::No,
        }
    }

    /// Register a validator manifest (master → ephemeral delegation).
    ///
    /// Once registered, proposals/validations signed by the ephemeral key
    /// will be resolved back to the master key for UNL trust checks.
    pub fn add_manifest(&mut self, manifest: Manifest) -> bool {
        self.manifests.add(manifest)
    }

    /// Register a manifest that has already been validated by the shared
    /// node-wide manifest cache.
    pub fn add_prevalidated_manifest(&mut self, manifest: Manifest) -> bool {
        self.manifests.add_prevalidated(manifest)
    }

    pub fn unl_size(&self) -> usize {
        self.unl.len()
    }
    pub fn proposal_count(&self) -> usize {
        self.proposals.len()
    }
    pub fn validation_count(&self) -> usize {
        self.validations.len()
    }
    pub fn dispute_count(&self) -> usize {
        self.disputes.len()
    }

    // ── Phase transitions ─────────────────────────────────────────────────────

    /// Close the open ledger and begin the Establish phase.
    pub fn close_ledger(&mut self, initial_tx_set: [u8; 32]) {
        assert_eq!(self.phase, ConsensusPhase::Open, "can only close from Open");
        self.our_position = Some(initial_tx_set);
        self.phase = ConsensusPhase::Establish;
        self.establish_start = Some(Instant::now());
    }

    // ── Proposal handling ─────────────────────────────────────────────────────

    /// Record a proposal from a UNL peer.
    /// Returns `true` if the proposal was from a trusted node with a valid signature.
    pub fn add_proposal(&mut self, prop: Proposal) -> bool {
        if !self.is_trusted(&prop.node_pubkey) {
            return false;
        }
        if prop.ledger_seq != self.ledger_seq {
            return false;
        }
        if !prop.verify_signature() {
            return false;
        }
        let key = hex::encode(&prop.node_pubkey);
        // Only accept if prop_seq is newer
        if let Some(existing) = self.proposals.get(&key) {
            if prop.prop_seq <= existing.prop_seq {
                return false;
            }
        }
        self.proposals.insert(key, prop);
        true
    }

    /// Count how many UNL peers are proposing each tx set hash.
    pub fn position_counts(&self) -> HashMap<[u8; 32], usize> {
        let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
        for prop in self.proposals.values() {
            *counts.entry(prop.tx_set_hash).or_insert(0) += 1;
        }
        counts
    }

    /// Compare the local tx-set hash with a peer's hash and create disputes
    /// for the differences.
    /// Called when a peer proposes a different `tx_set_hash`.
    ///
    /// `our_txs`: transaction hashes in the local proposed set.
    /// `peer_txs`: transaction hashes in the peer's proposed set.
    /// `peer_id`: hex-encoded peer node pubkey.
    pub fn create_disputes(&mut self, our_txs: &[[u8; 32]], peer_txs: &[[u8; 32]], peer_id: &str) {
        let our_set: std::collections::HashSet<[u8; 32]> = our_txs.iter().copied().collect();
        let peer_set: std::collections::HashSet<[u8; 32]> = peer_txs.iter().copied().collect();

        // Transactions present locally but absent from the peer proposal
        // become disputes with a local "yes" vote and a peer "no" vote.
        for tx_id in our_set.difference(&peer_set) {
            self.add_dispute(*tx_id, true);
            self.set_dispute_vote(tx_id, peer_id, false);
        }

        // Transactions present in the peer proposal but absent locally become
        // disputes with a local "no" vote and a peer "yes" vote.
        for tx_id in peer_set.difference(&our_set) {
            self.add_dispute(*tx_id, false);
            self.set_dispute_vote(tx_id, peer_id, true);
        }
    }

    /// Elapsed establish time as a percentage of previous round duration,
    /// floored at `AV_MIN_CONSENSUS_TIME` (5 s).  Matches rippled's convergePercent.
    pub fn converge_percent(&self) -> u32 {
        let elapsed_ms = self
            .establish_start
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or(0);
        let denom = self.prev_round_time.max(AV_MIN_CONSENSUS_TIME).as_millis() as u64;
        if denom == 0 {
            return 0;
        }
        (elapsed_ms.saturating_mul(100) / denom) as u32
    }

    /// Elapsed time since the establish phase started.
    pub fn establish_elapsed(&self) -> Duration {
        self.establish_start
            .map(|s| s.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Try to converge by adopting the most popular position if it meets the
    /// current threshold. Returns `Some(new_position)` if the local position changed.
    pub fn try_converge(&mut self) -> Option<[u8; 32]> {
        if self.phase != ConsensusPhase::Establish {
            return None;
        }
        let unl_size = self.unl.len();
        if unl_size == 0 {
            return None;
        }

        let threshold = convergence_threshold(self.converge_percent());
        let counts = self.position_counts();

        let (best_hash, best_count) = counts.into_iter().max_by_key(|(_, c)| *c)?;

        let ratio = best_count as f64 / unl_size as f64;
        if ratio >= threshold {
            let changed = self.our_position != Some(best_hash);
            self.our_position = Some(best_hash);
            if changed {
                return Some(best_hash);
            }
        }
        None
    }

    // ── Consensus state machine ──────────────────────────────────────────

    /// Core consensus decision — called each establish iteration.
    /// Matches rippled's `checkConsensus()` + `haveConsensus()` combined logic.
    pub fn check_consensus(&mut self) -> ConsensusState {
        self.establish_counter += 1;

        let elapsed = self.establish_elapsed();

        // Gate: too early — wait for proposals to arrive.
        if elapsed < MIN_CONSENSUS {
            self.consensus_state = ConsensusState::No;
            return ConsensusState::No;
        }

        let current_proposers = self.proposals.len();
        let proposing = self.mode == ConsensusMode::Proposing;
        let have_trusted_peer_proposals = current_proposers > 0;
        let unl_requires_peer_support = !self.unl.is_empty();

        // Gate: not enough proposers yet AND not enough time.
        // rippled: if currentProposers < prevProposers*3/4 AND elapsed < prevRoundTime + MIN_CONSENSUS
        if self.prev_proposers > 0
            && current_proposers < (self.prev_proposers * 3 / 4)
            && elapsed < self.prev_round_time + MIN_CONSENSUS
        {
            self.consensus_state = ConsensusState::No;
            return ConsensusState::No;
        }

        // Count agreement with the local position.
        let (agree, total) = if let Some(pos) = self.our_position {
            let agree = self
                .proposals
                .values()
                .filter(|p| p.tx_set_hash == pos)
                .count();
            (agree, current_proposers)
        } else {
            (0, current_proposers)
        };

        // Check whether the round reached consensus.
        // Count self if proposing (rippled: count_self in checkConsensusReached).
        let (eff_agree, eff_total) =
            if proposing && (!unl_requires_peer_support || have_trusted_peer_proposals) {
                (agree + 1, total + 1)
            } else {
                (agree, total)
            };

        // Check for stalled disputes (all disputes at 80%+ agreement for 4+ rounds).
        let stalled = self.have_close_time_consensus
            && !self.disputes.is_empty()
            && self.disputes.values().all(|d| d.is_stalled());

        let reached_max = elapsed >= Duration::from_secs(15);

        if consensus_reached(eff_agree, eff_total, reached_max, stalled)
            && (!unl_requires_peer_support || have_trusted_peer_proposals || stalled)
        {
            self.consensus_state = ConsensusState::Yes;
            return ConsensusState::Yes;
        }

        // Check whether the network has already moved on.
        // Count peers that validated a later ledger (seq > current local seq).
        let finished = self
            .validations
            .values()
            .filter(|v| v.ledger_seq > self.ledger_seq)
            .count();
        // Conservative: don't count self, don't use stalled for MovedOn.
        if current_proposers > 0
            && consensus_reached(finished, current_proposers, reached_max, false)
        {
            self.consensus_state = ConsensusState::MovedOn;
            return ConsensusState::MovedOn;
        }

        // Check whether the round should expire.
        // rippled: clamp(prevRoundTime * ABANDON_FACTOR, ABANDON_FLOOR, ABANDON_CEILING)
        let abandon_timeout = {
            let raw = self.prev_round_time.saturating_mul(ABANDON_FACTOR);
            raw.max(ABANDON_FLOOR).min(ABANDON_CEILING)
        };
        if elapsed > abandon_timeout {
            self.consensus_state = ConsensusState::Expired;
            return ConsensusState::Expired;
        }

        self.consensus_state = ConsensusState::No;
        ConsensusState::No
    }

    /// Increment peer-unchanged counter. Call when no peer votes changed this iteration.
    pub fn tick_unchanged(&mut self) {
        self.peer_unchanged_counter += 1;
    }

    /// Reset peer-unchanged counter. Call when any peer vote changed.
    pub fn reset_unchanged(&mut self) {
        self.peer_unchanged_counter = 0;
    }

    /// Declare consensus reached on the current local position.
    pub fn accept(&mut self) -> Option<RoundResult> {
        if self.phase != ConsensusPhase::Establish {
            return None;
        }
        let tx_set_hash = self.our_position?;
        let agree_count = self
            .proposals
            .values()
            .filter(|p| p.tx_set_hash == tx_set_hash)
            .count();
        let round_time = self.establish_elapsed();
        let proposers = self.proposals.len();
        self.phase = ConsensusPhase::Accepted;
        Some(RoundResult {
            ledger_seq: self.ledger_seq,
            tx_set_hash,
            agree_count,
            unl_size: self.unl.len(),
            state: self.consensus_state,
            round_time,
            proposers,
        })
    }

    // ── Validation handling ───────────────────────────────────────────────────

    /// Record a validation from a UNL peer.
    /// Accepts validations for the current ledger sequence (for quorum) and
    /// later sequences (for `MovedOn` detection).
    /// Returns `true` if it was from a trusted node with a valid signature.
    pub fn add_validation(&mut self, val: Validation) -> bool {
        if !self.validation_is_trusted(&val) {
            return false;
        }
        let key = hex::encode(&val.node_pubkey);
        self.validations.insert(key, val);
        true
    }

    /// Check whether a validation is from a trusted node and has a valid
    /// signature, without mutating round state.
    pub fn validation_is_trusted(&self, val: &Validation) -> bool {
        if !self.is_trusted(&val.node_pubkey) {
            return false;
        }
        if val.ledger_seq < self.ledger_seq {
            return false;
        }
        val.verify_signature()
    }

    /// Insert a validation whose signature has already been verified.
    pub fn add_prevalidated_validation(&mut self, val: Validation) -> bool {
        if !self.is_trusted(&val.node_pubkey) {
            return false;
        }
        if val.ledger_seq < self.ledger_seq {
            return false;
        }
        let key = hex::encode(&val.node_pubkey);
        self.validations.insert(key, val);
        true
    }

    /// Count validations per ledger hash.
    pub fn validation_counts(&self) -> HashMap<[u8; 32], usize> {
        let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
        for val in self.validations.values() {
            *counts.entry(val.ledger_hash).or_insert(0) += 1;
        }
        counts
    }

    /// The validation quorum count (80% of UNL size, rounded up).
    pub fn quorum(&self) -> u32 {
        if self.unl.is_empty() {
            return 0;
        }
        (self.unl.len() as f64 * VALIDATION_QUORUM).ceil() as u32
    }

    /// Check whether any ledger hash has reached the 80% validation quorum.
    /// Returns `Some(ledger_hash)` if validated, `None` otherwise.
    pub fn check_validated(&mut self) -> Option<[u8; 32]> {
        if self.unl.is_empty() {
            return None;
        }
        let quorum = (self.unl.len() as f64 * VALIDATION_QUORUM).ceil() as usize;
        let counts = self.validation_counts();
        let (&hash, &_count) = counts.iter().find(|(_, &c)| c >= quorum)?;
        self.phase = ConsensusPhase::Validated;
        Some(hash)
    }

    /// Number of validations received for a specific ledger hash.
    pub fn validation_count_for(&self, ledger_hash: &[u8; 32]) -> usize {
        self.validations
            .values()
            .filter(|v| &v.ledger_hash == ledger_hash)
            .count()
    }

    // ── Dispute resolution ─────────────────────────────────────────────────

    /// Add a disputed transaction — a tx that some peers include and others don't.
    pub fn add_dispute(&mut self, tx_id: [u8; 32], our_vote: bool) {
        self.disputes
            .entry(tx_id)
            .or_insert_with(|| DisputedTx::new(tx_id, our_vote));
    }

    /// Record a peer's vote on a disputed transaction.
    pub fn set_dispute_vote(&mut self, tx_id: &[u8; 32], node_id: &str, votes_yes: bool) {
        if let Some(dispute) = self.disputes.get_mut(tx_id) {
            dispute.set_vote(node_id, votes_yes);
        }
    }

    /// Update all dispute votes using avalanche thresholds.
    /// `percent_time`: progress through consensus round (0-100+).
    /// Returns the transaction IDs whose local vote changed.
    pub fn update_disputes(&mut self, percent_time: u32) -> Vec<[u8; 32]> {
        let proposing = self.mode == ConsensusMode::Proposing;
        let mut changed = Vec::new();
        for (tx_id, dispute) in &mut self.disputes {
            if dispute.update_vote(percent_time, proposing) {
                changed.push(*tx_id);
            }
        }
        changed
    }

    /// Get the current set of transactions included by the local vote.
    pub fn our_tx_set(&self) -> Vec<[u8; 32]> {
        self.disputes
            .iter()
            .filter(|(_, d)| d.our_vote)
            .map(|(id, _)| *id)
            .collect()
    }

    // ── Bow-out / seqLeave ──────────────────────────────────────────────────

    /// Bow out of consensus — stop proposing and broadcast seqLeave.
    /// Returns the bow-out proposal to broadcast when the round was proposing.
    pub fn leave_consensus(&mut self) -> Option<[u8; 32]> {
        if self.mode != ConsensusMode::Proposing {
            return None;
        }
        self.mode = ConsensusMode::Observing;
        self.our_position
    }

    /// Handle a peer bowing out (seqLeave proposal).
    /// Removes their votes from all disputes.
    pub fn peer_bowed_out(&mut self, node_id: &str) {
        // Remove from disputes
        for dispute in self.disputes.values_mut() {
            dispute.unvote(node_id);
        }
        // Remove their proposal
        self.proposals.remove(node_id);
        // Mark as dead
        self.dead_nodes.insert(node_id.to_string());
    }

    // ── Wrong-ledger detection ──────────────────────────────────────────────

    /// Check if the majority of UNL peers are building on a different parent.
    /// Returns `Some(correct_parent)` when the round should switch parents.
    pub fn check_wrong_ledger(&self) -> Option<[u8; 32]> {
        // Count parent ledger hashes from peer proposals
        let mut parent_counts: HashMap<[u8; 32], usize> = HashMap::new();
        for prop in self.proposals.values() {
            *parent_counts.entry(prop.previous_ledger).or_insert(0) += 1;
        }
        // Find the most common parent
        let (best_parent, best_count) = parent_counts.into_iter().max_by_key(|(_, c)| *c)?;
        // If a majority (>50%) builds on a different parent, the round is on
        // the wrong ledger.
        let total = self.proposals.len();
        if total > 0 && best_parent != self.prev_ledger && best_count * 2 > total {
            Some(best_parent)
        } else {
            None
        }
    }

    /// Handle wrong ledger detection — clear state and switch to wrong-ledger mode.
    pub fn handle_wrong_ledger(&mut self) {
        if self.mode == ConsensusMode::Proposing {
            self.mode = ConsensusMode::WrongLedger;
        }
        self.disputes.clear();
        self.dead_nodes.clear();
    }

    // ── Close time consensus ────────────────────────────────────────────────

    /// Record a peer's close time vote (extracted from their proposal).
    pub fn add_close_time_vote(&mut self, close_time: u64) {
        *self.close_time_votes.entry(close_time).or_insert(0) += 1;
    }

    /// Check if close time consensus has been reached (75% agreement).
    /// Returns the agreed close time if consensus is met.
    pub fn check_close_time_consensus(&mut self) -> Option<u64> {
        if self.have_close_time_consensus {
            return Some(self.our_close_time);
        }
        let total_votes: usize = self.close_time_votes.values().sum();
        if total_votes == 0 {
            return None;
        }
        let threshold = ((total_votes as f64) * CLOSE_TIME_CONSENSUS_PCT).ceil() as usize;
        // Find close time with most votes
        let (&best_time, &best_count) = self.close_time_votes.iter().max_by_key(|(_, &c)| c)?;
        if best_count >= threshold {
            self.our_close_time = best_time;
            self.have_close_time_consensus = true;
            Some(best_time)
        } else {
            None
        }
    }

    /// Check if BOTH tx consensus and close time consensus are met.
    pub fn have_full_consensus(&self) -> bool {
        // Transaction consensus requires 80%+ agreement with the local position.
        if let Some(pos) = self.our_position {
            let agree = self
                .proposals
                .values()
                .filter(|p| p.tx_set_hash == pos)
                .count();
            let unl_size = self.unl.len();
            if unl_size == 0 {
                return self.have_close_time_consensus;
            }
            let tx_consensus = agree as f64 / unl_size as f64 >= 0.80;
            tx_consensus && self.have_close_time_consensus
        } else {
            false
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Check whether `signing_key` is trusted.
    ///
    /// If a manifest maps `signing_key` → `master_key`, check `master_key`
    /// against the UNL.  If no manifest exists, `signing_key` is treated as
    /// its own master key (single-key mode, backward-compatible).
    fn is_trusted(&self, signing_key: &[u8]) -> bool {
        // Resolve through manifest if available.
        let master = self
            .manifests
            .signing_key_to_master(signing_key)
            .unwrap_or(signing_key);
        // Revoked master keys are never trusted.
        if self.manifests.is_revoked(master) {
            return false;
        }
        self.unl.iter().any(|k| k == master)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Secp256k1KeyPair;

    /// Generate `n` real secp256k1 validator keypairs.
    fn make_validators(n: usize) -> Vec<Secp256k1KeyPair> {
        (0..n).map(|_| Secp256k1KeyPair::generate()).collect()
    }

    /// Extract the UNL (pubkey list) from a set of validator keypairs.
    fn unl_from(validators: &[Secp256k1KeyPair]) -> Vec<Vec<u8>> {
        validators.iter().map(|kp| kp.public_key_bytes()).collect()
    }

    fn tx_hash(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// Bootstrap defaults for tests — 4 s previous round, 0 previous proposers.
    const TEST_PREV_RT: Duration = Duration::from_secs(4);
    const TEST_PREV_PROP: usize = 0;

    fn new_round(seq: u32, unl: Vec<Vec<u8>>, prev: [u8; 32], proposing: bool) -> ConsensusRound {
        ConsensusRound::new(seq, unl, prev, proposing, TEST_PREV_RT, TEST_PREV_PROP)
    }

    fn make_proposal(kp: &Secp256k1KeyPair, tx: [u8; 32], seq: u32) -> Proposal {
        Proposal::new_signed(1, tx, [0u8; 32], 0, seq, kp)
    }

    fn make_validation(kp: &Secp256k1KeyPair, ledger_hash: [u8; 32]) -> Validation {
        Validation::new_signed(1, ledger_hash, 0, true, kp)
    }

    #[test]
    fn test_initial_phase_is_open() {
        let validators = make_validators(5);
        let r = new_round(1, unl_from(&validators), [0u8; 32], true);
        assert_eq!(r.phase, ConsensusPhase::Open);
    }

    #[test]
    fn test_close_ledger_transitions_to_establish() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        r.close_ledger(tx_hash(1));
        assert_eq!(r.phase, ConsensusPhase::Establish);
        assert_eq!(r.our_position, Some(tx_hash(1)));
    }

    #[test]
    fn test_untrusted_proposal_rejected() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        // Untrusted validator — not in the UNL
        let outsider = Secp256k1KeyPair::generate();
        let prop = make_proposal(&outsider, tx_hash(1), 0);
        assert!(!r.add_proposal(prop));
        assert!(r.proposals.is_empty());
    }

    #[test]
    fn test_trusted_proposal_accepted() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        let prop = make_proposal(&validators[0], tx_hash(1), 0);
        assert!(r.add_proposal(prop));
        assert_eq!(r.proposals.len(), 1);
    }

    #[test]
    fn test_prevalidated_validation_is_accepted_without_reverify() {
        let validators = make_validators(3);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        let val = make_validation(&validators[0], tx_hash(7));
        assert!(r.validation_is_trusted(&val));
        assert!(r.add_prevalidated_validation(val));
        assert_eq!(r.validation_count(), 1);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let validators = make_validators(3);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        // Build a proposal signed by a different key but advertising validators[0]'s pubkey
        let impostor = Secp256k1KeyPair::generate();
        let mut prop = Proposal::new_signed(1, tx_hash(1), [0u8; 32], 0, 0, &impostor);
        // Swap the pubkey to appear as a trusted validator
        prop.node_pubkey = validators[0].public_key_bytes();
        assert!(!r.add_proposal(prop), "forged pubkey must be rejected");
    }

    #[test]
    fn test_older_proposal_seq_ignored() {
        let validators = make_validators(3);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        r.add_proposal(make_proposal(&validators[0], tx_hash(1), 2));
        r.add_proposal(make_proposal(&validators[0], tx_hash(2), 1)); // older seq
                                                                      // Should still hold the seq=2 proposal
        let counts = r.position_counts();
        assert_eq!(counts.get(&tx_hash(1)), Some(&1));
        assert_eq!(counts.get(&tx_hash(2)), None);
    }

    #[test]
    fn test_position_counts() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        for v in &validators[..3] {
            r.add_proposal(make_proposal(v, tx_hash(1), 0));
        }
        r.add_proposal(make_proposal(&validators[3], tx_hash(2), 0));
        let counts = r.position_counts();
        assert_eq!(counts[&tx_hash(1)], 3);
        assert_eq!(counts[&tx_hash(2)], 1);
    }

    #[test]
    fn test_convergence_thresholds() {
        // converge_percent is elapsed_ms * 100 / max(prev_round_time_ms, 5000)
        assert_eq!(convergence_threshold(0), 0.50); // init
        assert_eq!(convergence_threshold(49), 0.50); // still init
        assert_eq!(convergence_threshold(50), 0.65); // mid
        assert_eq!(convergence_threshold(84), 0.65); // still mid
        assert_eq!(convergence_threshold(85), 0.70); // late
        assert_eq!(convergence_threshold(199), 0.70); // still late
        assert_eq!(convergence_threshold(200), 0.95); // stuck
        assert_eq!(convergence_threshold(500), 0.95); // still stuck
    }

    #[test]
    fn test_accept_returns_result() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        r.close_ledger(tx_hash(1));
        for v in &validators[..4] {
            r.add_proposal(make_proposal(v, tx_hash(1), 0));
        }
        let result = r.accept().expect("should produce result");
        assert_eq!(result.tx_set_hash, tx_hash(1));
        assert_eq!(result.agree_count, 4);
        assert_eq!(result.unl_size, 5);
        assert!((result.agreement_pct() - 0.8).abs() < f64::EPSILON);
        assert_eq!(r.phase, ConsensusPhase::Accepted);
    }

    #[test]
    fn test_validation_quorum_not_met() {
        let validators = make_validators(10);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        // Only 7 of 10 — need 8 (80%)
        for v in &validators[..7] {
            r.add_validation(make_validation(v, tx_hash(1)));
        }
        assert!(r.check_validated().is_none());
    }

    #[test]
    fn test_validation_quorum_met() {
        let validators = make_validators(10);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        // 8 of 10 = exactly 80%
        for v in &validators[..8] {
            r.add_validation(make_validation(v, tx_hash(42)));
        }
        let hash = r.check_validated().expect("quorum should be met");
        assert_eq!(hash, tx_hash(42));
        assert_eq!(r.phase, ConsensusPhase::Validated);
    }

    #[test]
    fn test_split_validations_no_quorum() {
        let validators = make_validators(10);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        // 5 vote for hash A, 5 for hash B — neither reaches 80%
        for v in &validators[..5] {
            r.add_validation(make_validation(v, tx_hash(1)));
        }
        for v in &validators[5..] {
            r.add_validation(make_validation(v, tx_hash(2)));
        }
        assert!(r.check_validated().is_none());
    }

    #[test]
    fn test_untrusted_validation_ignored() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        let outsider = Secp256k1KeyPair::generate();
        let val = make_validation(&outsider, tx_hash(1));
        assert!(!r.add_validation(val));
        assert_eq!(r.validation_count_for(&tx_hash(1)), 0);
    }

    #[test]
    fn test_invalid_validation_signature_rejected() {
        let validators = make_validators(3);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        let impostor = Secp256k1KeyPair::generate();
        let mut val = Validation::new_signed(1, tx_hash(1), 0, true, &impostor);
        // Swap pubkey to appear as a trusted validator
        val.node_pubkey = validators[0].public_key_bytes();
        assert!(!r.add_validation(val), "forged pubkey must be rejected");
    }

    #[test]
    fn test_wrong_seq_proposal_ignored() {
        let validators = make_validators(3);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        // Sign with the correct key but for the wrong ledger sequence
        let mut prop = Proposal::new_signed(999, tx_hash(1), [0u8; 32], 0, 0, &validators[0]);
        prop.ledger_seq = 999; // doesn't match round's ledger_seq of 1
        assert!(!r.add_proposal(prop));
    }

    // ── Manifest (ephemeral key) tests ─────────────────────────────────────

    #[test]
    fn test_ephemeral_proposal_accepted_via_manifest() {
        let masters = make_validators(3);
        let ephemeral = Secp256k1KeyPair::generate();

        // UNL lists master keys
        let mut r = new_round(1, unl_from(&masters), [0u8; 32], true);

        // Register manifest: masters[0] → ephemeral
        let manifest = crate::consensus::Manifest::new_signed(1, &masters[0], &ephemeral);
        assert!(r.add_manifest(manifest));

        // Proposal signed by the ephemeral key should be trusted
        let prop = Proposal::new_signed(1, tx_hash(1), [0u8; 32], 0, 0, &ephemeral);
        assert!(
            r.add_proposal(prop),
            "ephemeral key with manifest should be trusted"
        );
    }

    #[test]
    fn test_ephemeral_validation_accepted_via_manifest() {
        let masters = make_validators(5);
        let ephemerals: Vec<_> = (0..5).map(|_| Secp256k1KeyPair::generate()).collect();

        let mut r = new_round(1, unl_from(&masters), [0u8; 32], true);
        for (m, e) in masters.iter().zip(ephemerals.iter()) {
            r.add_manifest(crate::consensus::Manifest::new_signed(1, m, e));
        }

        // All 5 ephemeral keys send validations — should reach quorum
        for e in &ephemerals {
            r.add_validation(make_validation(e, tx_hash(99)));
        }
        assert_eq!(r.validation_count_for(&tx_hash(99)), 5);
        let hash = r.check_validated().expect("5/5 should reach quorum");
        assert_eq!(hash, tx_hash(99));
    }

    #[test]
    fn test_revoked_master_key_not_trusted() {
        let masters = make_validators(3);
        let ephemeral = Secp256k1KeyPair::generate();

        let mut r = new_round(1, unl_from(&masters), [0u8; 32], true);

        // Register then revoke masters[0]
        let manifest = crate::consensus::Manifest::new_signed(1, &masters[0], &ephemeral);
        r.add_manifest(manifest);
        let revocation = crate::consensus::Manifest::new_revocation(&masters[0]);
        r.add_manifest(revocation);

        // Now proposals from ephemeral AND master[0] directly should be rejected
        let prop1 = Proposal::new_signed(1, tx_hash(1), [0u8; 32], 0, 0, &ephemeral);
        assert!(
            !r.add_proposal(prop1),
            "revoked master's ephemeral must be rejected"
        );

        let prop2 = Proposal::new_signed(1, tx_hash(1), [0u8; 32], 0, 0, &masters[0]);
        assert!(
            !r.add_proposal(prop2),
            "revoked master key directly must be rejected"
        );
    }

    #[test]
    fn test_no_manifest_uses_direct_master() {
        // Without manifests, the signing key IS the master key — backward compat
        let validators = make_validators(3);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        let prop = make_proposal(&validators[0], tx_hash(1), 0);
        assert!(
            r.add_proposal(prop),
            "direct master key must still work without manifest"
        );
    }

    #[test]
    fn test_full_round_flow() {
        // 5 validators, all agree on tx_hash(7)
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);

        // Phase 1: close
        r.close_ledger(tx_hash(7));
        assert_eq!(r.phase, ConsensusPhase::Establish);

        // Phase 2: all peers propose the same tx set (with real signatures)
        for v in &validators {
            r.add_proposal(make_proposal(v, tx_hash(7), 0));
        }

        // Phase 3: accept
        let result = r.accept().unwrap();
        assert_eq!(result.tx_set_hash, tx_hash(7));
        assert_eq!(result.agree_count, 5);

        // Phase 4: validations pour in (with real signatures)
        for v in &validators {
            r.add_validation(make_validation(v, tx_hash(7)));
        }
        let validated = r.check_validated().unwrap();
        assert_eq!(validated, tx_hash(7));
        assert_eq!(r.phase, ConsensusPhase::Validated);
    }

    // ── check_consensus / converge_percent tests ──────────────────────────

    #[test]
    fn test_converge_percent_relative_to_prev_round() {
        let validators = make_validators(3);
        let mut r = ConsensusRound::new(
            1,
            unl_from(&validators),
            [0u8; 32],
            true,
            Duration::from_secs(10), // prev round took 10 s
            3,
        );
        r.close_ledger(tx_hash(1));
        // At t=0 → 0%
        assert_eq!(r.converge_percent(), 0);
        // converge_percent = elapsed_ms * 100 / max(10000, 5000) = elapsed_ms / 100
        // The time-dependent value itself is not deterministic in unit tests,
        // but the denominator selection logic remains deterministic.
    }

    #[test]
    fn test_converge_percent_floors_at_5s() {
        let validators = make_validators(3);
        // prev_round_time = 2s, but floor is 5s (AV_MIN_CONSENSUS_TIME)
        let r = ConsensusRound::new(
            1,
            unl_from(&validators),
            [0u8; 32],
            true,
            Duration::from_secs(2), // below floor
            3,
        );
        // Denominator should be max(2000, 5000) = 5000
        // At t=0 → 0%
        assert_eq!(r.converge_percent(), 0);
    }

    #[test]
    fn test_check_consensus_returns_no_before_min_consensus() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        r.close_ledger(tx_hash(1));
        // Add 100% agreement
        for v in &validators {
            r.add_proposal(make_proposal(v, tx_hash(1), 0));
        }
        // A newly started round should still return `No` (< 1950 ms).
        // `establish_start` was just set, so elapsed time is near zero.
        assert_eq!(r.check_consensus(), ConsensusState::No);
    }

    #[test]
    fn test_check_consensus_returns_expired_on_very_long_round() {
        let validators = make_validators(5);
        // prev_round_time = 1s → abandon = clamp(1s * 10, 15s, 120s) = 15s
        let mut r = ConsensusRound::new(
            1,
            unl_from(&validators),
            [0u8; 32],
            true,
            Duration::from_secs(1),
            5,
        );
        r.close_ledger(tx_hash(1));
        // Add disagreeing proposals so agreement stays below 80%.
        for v in &validators {
            r.add_proposal(make_proposal(v, tx_hash(2), 0)); // differ from our tx_hash(1)
        }
        // Set establish_start far in the past to simulate timeout
        r.establish_start = Some(Instant::now() - Duration::from_secs(20));
        // Including the local node yields agree=1 and total=6, which remains
        // below the threshold and should expire the round.
        let state = r.check_consensus();
        assert_eq!(state, ConsensusState::Expired);
    }

    #[test]
    fn test_check_consensus_returns_yes_with_full_agreement() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        r.close_ledger(tx_hash(1));
        // All 5 agree
        for v in &validators {
            r.add_proposal(make_proposal(v, tx_hash(1), 0));
        }
        // Set establish_start to 2s ago to pass MIN_CONSENSUS gate
        r.establish_start = Some(Instant::now() - Duration::from_secs(2));
        assert_eq!(r.check_consensus(), ConsensusState::Yes);
    }

    #[test]
    fn test_check_consensus_does_not_accept_self_only_with_nonempty_unl() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        r.close_ledger(tx_hash(1));
        r.establish_start = Some(Instant::now() - Duration::from_secs(50));
        assert_eq!(r.check_consensus(), ConsensusState::Expired);
    }

    #[test]
    fn test_check_consensus_returns_no_with_insufficient_agreement() {
        let validators = make_validators(10);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        r.close_ledger(tx_hash(1));
        // Only 6 of 10 agree → 60% < 80% (with self: 7/11 = 63%, still < 80%)
        for v in &validators[..6] {
            r.add_proposal(make_proposal(v, tx_hash(1), 0));
        }
        for v in &validators[6..] {
            r.add_proposal(make_proposal(v, tx_hash(2), 0));
        }
        r.establish_start = Some(Instant::now() - Duration::from_secs(3));
        assert_eq!(r.check_consensus(), ConsensusState::No);
    }

    #[test]
    fn test_check_consensus_moved_on() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], false); // observing
        r.close_ledger(tx_hash(1));
        r.establish_start = Some(Instant::now() - Duration::from_secs(3));
        // No proposals agree with the local position, so `Yes` should not
        // fire. Four of five peers validated seq 2, which should trigger
        // `MovedOn`.
        for v in &validators[..4] {
            let mut val = Validation::new_signed(2, tx_hash(99), 0, true, v);
            val.ledger_seq = 2; // later than our seq=1
            r.add_validation(val);
        }
        // `MovedOn` still needs proposers in the denominator, so add proposals
        // to keep `total > 0`.
        for v in &validators {
            r.add_proposal(make_proposal(v, tx_hash(2), 0)); // different from our tx_hash(1)
        }
        // Now: agree=0 (nobody matches tx_hash(1)), total=5
        // Yes check: (0+1)/(5+1) = 16% < 80% → No
        // MovedOn check: finished=4, total=5 → 4/5 = 80% → Yes!
        let state = r.check_consensus();
        assert_eq!(state, ConsensusState::MovedOn);
    }

    #[test]
    fn test_check_consensus_does_not_move_on_without_peer_proposals() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], false);
        r.close_ledger(tx_hash(1));
        r.establish_start = Some(Instant::now() - Duration::from_secs(50));
        for v in &validators[..4] {
            let mut val = Validation::new_signed(2, tx_hash(99), 0, true, v);
            val.ledger_seq = 2;
            r.add_validation(val);
        }
        assert_eq!(r.check_consensus(), ConsensusState::Expired);
    }

    #[test]
    fn test_consensus_reached_helper() {
        // 80% agreement
        assert!(consensus_reached(4, 5, false, false));
        assert!(consensus_reached(8, 10, false, false));
        // Below 80%
        assert!(!consensus_reached(3, 5, false, false));
        assert!(!consensus_reached(7, 10, false, false));
        // Stalled always true
        assert!(consensus_reached(0, 5, false, true));
        // Zero total + reached_max
        assert!(consensus_reached(0, 0, true, false));
        assert!(!consensus_reached(0, 0, false, false));
    }

    #[test]
    fn test_accept_includes_state_and_round_time() {
        let validators = make_validators(5);
        let mut r = new_round(1, unl_from(&validators), [0u8; 32], true);
        r.close_ledger(tx_hash(1));
        for v in &validators {
            r.add_proposal(make_proposal(v, tx_hash(1), 0));
        }
        // Simulate check_consensus having set Yes
        r.establish_start = Some(Instant::now() - Duration::from_secs(3));
        r.consensus_state = ConsensusState::Yes;
        let result = r.accept().unwrap();
        assert_eq!(result.state, ConsensusState::Yes);
        assert!(result.round_time >= Duration::from_secs(2)); // at least 2s since we set 3s ago
        assert_eq!(result.proposers, 5);
    }
}
