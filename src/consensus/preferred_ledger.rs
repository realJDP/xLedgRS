//! Preferred-ledger tracking derived from trusted validations.
//!
//! This module intentionally separates observed validations from validated
//! ledger decisions: one trusted validation can be useful evidence, but it
//! must not steer the local validated head unless the hash reaches quorum.

use std::collections::{BTreeMap, HashMap, HashSet};

/// Integer `ceil(count * pct / 100)`.
pub fn ceil_percent(count: usize, pct: usize) -> usize {
    if count == 0 {
        return 0;
    }
    count.saturating_mul(pct).saturating_add(99) / 100
}

/// Rippled-style validation quorum.
///
/// When the original UNL size is known, require the stricter of:
/// - 80% of the current/effective UNL
/// - 60% of the original UNL
pub fn validation_quorum_count(effective_unl: usize, original_unl: Option<usize>) -> usize {
    let effective = ceil_percent(effective_unl, 80);
    let original = original_unl
        .map(|count| ceil_percent(count, 60))
        .unwrap_or(0);
    effective.max(original)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedLedgerDecision {
    pub ledger_seq: u32,
    pub ledger_hash: [u8; 32],
    pub trusted_full_count: usize,
}

#[derive(Debug, Default, Clone)]
pub struct PreferredLedgerTracker {
    full_validations: HashMap<(u32, [u8; 32]), HashSet<Vec<u8>>>,
    latest_full_by_validator: HashMap<(Vec<u8>, u32), [u8; 32]>,
    validated_by_seq: BTreeMap<u32, ValidatedLedgerDecision>,
}

impl PreferredLedgerTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a trusted validation from a resolved validator master key.
    ///
    /// Partial validations are tracked by callers as observations, but only
    /// full validations participate in validated-ledger decisions.
    pub fn observe_trusted_validation(
        &mut self,
        master_key: Vec<u8>,
        ledger_seq: u32,
        ledger_hash: [u8; 32],
        full: bool,
        quorum: usize,
    ) -> Option<ValidatedLedgerDecision> {
        let latest_key = (master_key.clone(), ledger_seq);
        if let Some(previous_hash) = self.latest_full_by_validator.remove(&latest_key) {
            if previous_hash != ledger_hash {
                if let Some(validators) =
                    self.full_validations.get_mut(&(ledger_seq, previous_hash))
                {
                    validators.remove(&master_key);
                }
            }
        }

        if !full || quorum == 0 {
            return None;
        }

        self.latest_full_by_validator
            .insert(latest_key, ledger_hash);
        let validators = self
            .full_validations
            .entry((ledger_seq, ledger_hash))
            .or_default();
        validators.insert(master_key);
        let count = validators.len();
        if count < quorum {
            return None;
        }

        let decision = ValidatedLedgerDecision {
            ledger_seq,
            ledger_hash,
            trusted_full_count: count,
        };
        self.validated_by_seq.entry(ledger_seq).or_insert(decision);
        Some(decision)
    }

    pub fn full_count_for(&self, ledger_seq: u32, ledger_hash: &[u8; 32]) -> usize {
        self.full_validations
            .get(&(ledger_seq, *ledger_hash))
            .map(HashSet::len)
            .unwrap_or(0)
    }

    pub fn validated_for(&self, ledger_seq: u32) -> Option<ValidatedLedgerDecision> {
        self.validated_by_seq.get(&ledger_seq).copied()
    }

    pub fn validated_for_hash(
        &self,
        ledger_seq: u32,
        ledger_hash: &[u8; 32],
    ) -> Option<ValidatedLedgerDecision> {
        self.validated_for(ledger_seq)
            .filter(|decision| &decision.ledger_hash == ledger_hash)
    }

    /// Highest-sequence validated ledger. Returns `None` until quorum exists.
    pub fn preferred_head(&self) -> Option<ValidatedLedgerDecision> {
        self.validated_by_seq.values().next_back().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn quorum_uses_effective_80_percent_without_original_context() {
        assert_eq!(validation_quorum_count(0, None), 0);
        assert_eq!(validation_quorum_count(1, None), 1);
        assert_eq!(validation_quorum_count(5, None), 4);
        assert_eq!(validation_quorum_count(10, None), 8);
    }

    #[test]
    fn quorum_uses_stricter_original_unl_floor_when_present() {
        assert_eq!(validation_quorum_count(7, Some(10)), 6);
        assert_eq!(validation_quorum_count(5, Some(10)), 6);
        assert_eq!(validation_quorum_count(10, Some(5)), 8);
    }

    #[test]
    fn preferred_head_requires_quorum_not_single_validation() {
        let mut tracker = PreferredLedgerTracker::new();
        assert_eq!(
            tracker.observe_trusted_validation(vec![1], 4, hash(4), true, 2),
            None
        );
        assert_eq!(tracker.preferred_head(), None);

        let decision = tracker
            .observe_trusted_validation(vec![2], 4, hash(4), true, 2)
            .expect("second trusted full validation reaches quorum");
        assert_eq!(decision.ledger_seq, 4);
        assert_eq!(tracker.preferred_head(), Some(decision));
    }

    #[test]
    fn partial_validation_does_not_advance_preferred_head() {
        let mut tracker = PreferredLedgerTracker::new();
        assert_eq!(
            tracker.observe_trusted_validation(vec![1], 4, hash(4), false, 1),
            None
        );
        assert_eq!(tracker.preferred_head(), None);
    }

    #[test]
    fn validator_revalidation_moves_count_between_hashes() {
        let mut tracker = PreferredLedgerTracker::new();
        tracker.observe_trusted_validation(vec![1], 4, hash(1), true, 2);
        tracker.observe_trusted_validation(vec![1], 4, hash(2), true, 2);

        assert_eq!(tracker.full_count_for(4, &hash(1)), 0);
        assert_eq!(tracker.full_count_for(4, &hash(2)), 1);
        assert_eq!(tracker.preferred_head(), None);
    }
}
