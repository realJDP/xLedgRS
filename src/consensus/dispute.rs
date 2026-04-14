//! Per-transaction dispute resolution — avalanche voting on individual transactions.
//!
//! When validators have overlapping but non-identical transaction sets, each
//! differing transaction is "disputed." Validators vote yes/no on each disputed
//! transaction, and the voting threshold increases over time (avalanche) to force
//! convergence.
//!
//! Matches rippled's DisputedTx (DisputedTx.h).

use std::collections::HashMap;

/// Avalanche state — voting thresholds increase over time to force convergence.
/// Matches rippled's AvalancheState enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvalancheState {
    /// 0-50% of round time: 50% threshold
    Init,
    /// 50-85% of round time: 65% threshold
    Mid,
    /// 85-200% of round time: 70% threshold
    Late,
    /// >200% of round time: 95% threshold (force convergence)
    Stuck,
}

impl AvalancheState {
    /// Voting threshold for this state (percentage, 0-100).
    pub fn threshold(&self) -> u32 {
        match self {
            Self::Init  => 50,
            Self::Mid   => 65,
            Self::Late  => 70,
            Self::Stuck => 95,
        }
    }

    /// Advance to next state based on elapsed percentage of round time.
    /// `percent_time`: 0-100+ representing progress through consensus round.
    pub fn next(self, percent_time: u32) -> Self {
        match self {
            Self::Init  if percent_time >= 50  => Self::Mid,
            Self::Mid   if percent_time >= 85  => Self::Late,
            Self::Late  if percent_time >= 200 => Self::Stuck,
            other => other,
        }
    }
}

/// A single disputed transaction — tracks per-peer votes.
///
/// Matches rippled's DisputedTx class.
#[derive(Debug, Clone)]
pub struct DisputedTx {
    /// Transaction ID (32-byte hash).
    pub tx_id: [u8; 32],
    /// Whether our current position includes this tx.
    pub our_vote: bool,
    /// Peer votes: node_pubkey_hex → votes_yes
    votes: HashMap<String, bool>,
    /// Count of yes votes.
    yays: usize,
    /// Count of no votes.
    nays: usize,
    /// Current avalanche state for this dispute.
    pub state: AvalancheState,
    /// Number of rounds at current avalanche state.
    rounds_at_state: u32,
}

/// Minimum rounds to stay in an avalanche state before advancing.
const AV_MIN_ROUNDS: u32 = 2;

/// Rounds without any vote changes → consider stalled.
const AV_STALLED_ROUNDS: u32 = 4;

impl DisputedTx {
    pub fn new(tx_id: [u8; 32], our_vote: bool) -> Self {
        Self {
            tx_id,
            our_vote,
            votes: HashMap::new(),
            yays: 0,
            nays: 0,
            state: AvalancheState::Init,
            rounds_at_state: 0,
        }
    }

    /// Record a peer's vote. Returns true if the peer changed their vote.
    pub fn set_vote(&mut self, node_id: &str, votes_yes: bool) -> bool {
        if let Some(existing) = self.votes.get(node_id) {
            if *existing == votes_yes {
                return false; // No change
            }
            // Vote changed
            if *existing {
                self.yays -= 1;
                self.nays += 1;
            } else {
                self.nays -= 1;
                self.yays += 1;
            }
            self.votes.insert(node_id.to_string(), votes_yes);
            true
        } else {
            // New vote
            if votes_yes { self.yays += 1; } else { self.nays += 1; }
            self.votes.insert(node_id.to_string(), votes_yes);
            true
        }
    }

    /// Remove a peer's vote (peer bowed out or disconnected).
    pub fn unvote(&mut self, node_id: &str) {
        if let Some(votes_yes) = self.votes.remove(node_id) {
            if votes_yes { self.yays -= 1; } else { self.nays -= 1; }
        }
    }

    /// Update our vote based on avalanche threshold.
    /// `percent_time`: progress through consensus round (0-100+).
    /// `proposing`: whether we're actively proposing (affects threshold).
    /// Returns true if our vote changed.
    pub fn update_vote(&mut self, percent_time: u32, proposing: bool) -> bool {
        // Advance avalanche state if enough rounds have passed
        self.rounds_at_state += 1;
        if self.rounds_at_state >= AV_MIN_ROUNDS {
            let new_state = self.state.next(percent_time);
            if new_state != self.state {
                self.state = new_state;
                self.rounds_at_state = 0;
            }
        }

        // Calculate weight — matches rippled DisputedTx::updateVote
        let new_vote = if proposing {
            // When proposing: weighted average including our own vote
            // rippled: weight = (yays * 100 + (ourVote ? 100 : 0)) / (nays + yays + 1)
            if self.yays + self.nays == 0 {
                self.our_vote // No peer votes → keep current position
            } else {
                let self_weight: u32 = if self.our_vote { 100 } else { 0 };
                let weight = ((self.yays as u32 * 100) + self_weight) / (self.nays as u32 + self.yays as u32 + 1);
                let threshold = self.state.threshold();
                weight > threshold // rippled uses strict >
            }
        } else {
            // When observing: simple majority (rippled uses yays > nays, no threshold)
            self.yays > self.nays
        };
        if new_vote != self.our_vote {
            self.our_vote = new_vote;
            true
        } else {
            false
        }
    }

    /// Check if this dispute is stalled (>80% agreement, no changes).
    pub fn is_stalled(&self) -> bool {
        if self.yays + self.nays == 0 { return false; }
        let weight = (self.yays as u32 * 100) / (self.yays as u32 + self.nays as u32);
        let min_consensus = 80u32;
        (weight > min_consensus || weight < (100 - min_consensus))
            && self.rounds_at_state >= AV_STALLED_ROUNDS
    }

    pub fn yay_count(&self) -> usize { self.yays }
    pub fn nay_count(&self) -> usize { self.nays }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_dispute_no_votes() {
        let d = DisputedTx::new([1u8; 32], true);
        assert_eq!(d.yay_count(), 0);
        assert_eq!(d.nay_count(), 0);
        assert!(d.our_vote);
    }

    #[test]
    fn test_vote_counting() {
        let mut d = DisputedTx::new([1u8; 32], true);
        d.set_vote("peer1", true);
        d.set_vote("peer2", false);
        d.set_vote("peer3", true);
        assert_eq!(d.yay_count(), 2);
        assert_eq!(d.nay_count(), 1);
    }

    #[test]
    fn test_vote_change() {
        let mut d = DisputedTx::new([1u8; 32], true);
        d.set_vote("peer1", true);
        assert_eq!(d.yay_count(), 1);
        assert!(d.set_vote("peer1", false)); // changed
        assert_eq!(d.yay_count(), 0);
        assert_eq!(d.nay_count(), 1);
    }

    #[test]
    fn test_unvote() {
        let mut d = DisputedTx::new([1u8; 32], true);
        d.set_vote("peer1", true);
        d.set_vote("peer2", false);
        d.unvote("peer1");
        assert_eq!(d.yay_count(), 0);
        assert_eq!(d.nay_count(), 1);
    }

    #[test]
    fn test_avalanche_state_progression() {
        let s = AvalancheState::Init;
        assert_eq!(s.next(30), AvalancheState::Init);
        assert_eq!(s.next(50), AvalancheState::Mid);
        let s = AvalancheState::Mid;
        assert_eq!(s.next(80), AvalancheState::Mid);
        assert_eq!(s.next(85), AvalancheState::Late);
        let s = AvalancheState::Late;
        assert_eq!(s.next(199), AvalancheState::Late);
        assert_eq!(s.next(200), AvalancheState::Stuck);
    }

    #[test]
    fn test_update_vote_flips_on_majority() {
        let mut d = DisputedTx::new([1u8; 32], true);
        // 4 nays, 1 yay → weight = (1*100+100)/(4+1+1) = 33 < 50 → flip to false
        d.set_vote("p1", false);
        d.set_vote("p2", false);
        d.set_vote("p3", false);
        d.set_vote("p4", false);
        d.set_vote("p5", true);
        let changed = d.update_vote(0, true);
        assert!(changed);
        assert!(!d.our_vote);
    }
}
