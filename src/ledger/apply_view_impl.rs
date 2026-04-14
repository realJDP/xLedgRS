//! ApplyViewImpl — per-transaction view wrapping an OpenView.
//!
//! Buffers mutations in ApplyStateTable, which tracks before/after state
//! for metadata generation. On success, apply() flushes changes to the
//! OpenView and generates TxMeta (AffectedNodes).
//!
//! Matches rippled's ApplyViewImpl.

use std::sync::Arc;
use crate::ledger::Key;
use crate::ledger::keylet::Keylet;
use crate::ledger::sle::{SLE, LedgerEntryType};
use crate::ledger::fees::Fees;
use crate::ledger::rules::Rules;
use crate::ledger::views::{ReadView, ApplyView, ApplyFlags, LedgerInfo};
use crate::ledger::state_table::{ApplyStateTable, ApplyAction};
use crate::ledger::open_view::OpenView;

/// Per-transaction view. Wraps an OpenView and buffers mutations in
/// ApplyStateTable for before/after tracking and metadata generation.
pub struct ApplyViewImpl<'a> {
    /// The open ledger view we're applying to.
    open_view: &'a mut OpenView,
    /// Per-transaction mutation buffer.
    state_table: ApplyStateTable,
    /// Apply flags for this transaction.
    flags: ApplyFlags,
}

/// Result of applying a transaction.
pub struct ApplyResult {
    /// The affected nodes (for metadata serialization).
    pub affected_nodes: Vec<AffectedNodeInfo>,
}

/// Information about a single affected node (for TxMeta generation).
#[derive(Debug)]
pub struct AffectedNodeInfo {
    pub key: Key,
    pub entry_type: LedgerEntryType,
    pub action: AffectedAction,
    /// The SLE before this transaction (for ModifiedNode and DeletedNode).
    pub before: Option<Vec<u8>>,
    /// The SLE after this transaction (for CreatedNode and ModifiedNode).
    pub after: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffectedAction {
    Created,
    Modified,
    Deleted,
}

impl<'a> ApplyViewImpl<'a> {
    pub fn new(open_view: &'a mut OpenView, flags: ApplyFlags) -> Self {
        Self {
            open_view,
            state_table: ApplyStateTable::new(),
            flags,
        }
    }

    /// Apply this transaction's changes to the OpenView.
    /// Generates metadata (affected nodes) and flushes to the OpenView.
    /// After this call, the ApplyViewImpl should be dropped.
    pub fn apply(self) -> ApplyResult {
        // Collect affected nodes for metadata
        let mut affected = Vec::new();
        for (key, entry) in self.state_table.iter_changes() {
            let entry_type = entry.sle.as_ref()
                .or(entry.original.as_ref())
                .map(|s| s.entry_type())
                .unwrap_or(LedgerEntryType::AccountRoot);

            let info = AffectedNodeInfo {
                key: *key,
                entry_type,
                action: match entry.action {
                    ApplyAction::Insert => AffectedAction::Created,
                    ApplyAction::Modify => AffectedAction::Modified,
                    ApplyAction::Erase => AffectedAction::Deleted,
                    ApplyAction::Cache => continue, // shouldn't happen in iter_changes
                },
                before: entry.original.as_ref().map(|s| s.data().to_vec()),
                after: entry.sle.as_ref().map(|s| s.data().to_vec()),
            };
            affected.push(info);
        }

        // Flush changes to the OpenView
        self.state_table.apply_raw(self.open_view);

        ApplyResult { affected_nodes: affected }
    }

    /// Discard all changes (transaction failed).
    pub fn discard(self) {
        // Just drop — state_table is not applied
    }

    /// Number of actual changes (excludes cached reads).
    pub fn change_count(&self) -> usize {
        self.state_table.change_count()
    }
}

impl<'a> ReadView for ApplyViewImpl<'a> {
    fn read(&self, keylet: &Keylet) -> Option<Arc<SLE>> {
        // Check our buffer first
        match self.state_table.read(&keylet.key) {
            Some(entry) => match entry.action {
                ApplyAction::Erase => return None,
                _ => {
                    if let Some(ref sle) = entry.sle {
                        if keylet.check(sle) {
                            return Some(Arc::clone(sle));
                        }
                    }
                    return None;
                }
            },
            None => {} // fall through
        }
        // Fall through to OpenView
        self.open_view.read(keylet)
    }

    fn exists(&self, keylet: &Keylet) -> bool {
        match self.state_table.exists(&keylet.key) {
            Some(exists) => exists,
            None => self.open_view.exists(keylet),
        }
    }

    fn succ(&self, key: &Key, last: Option<&Key>) -> Option<Key> {
        // Delegate to OpenView (ApplyStateTable succ not needed for now)
        self.open_view.succ(key, last)
    }

    fn info(&self) -> &LedgerInfo { self.open_view.info() }
    fn fees(&self) -> &Fees { self.open_view.fees() }
    fn rules(&self) -> &Rules { self.open_view.rules() }
}

impl<'a> ApplyView for ApplyViewImpl<'a> {
    fn peek(&mut self, keylet: &Keylet) -> Option<Arc<SLE>> {
        self.state_table.peek(keylet, self.open_view)
    }

    fn insert(&mut self, sle: Arc<SLE>) {
        self.state_table.insert(sle);
    }

    fn update(&mut self, sle: Arc<SLE>) {
        self.state_table.update(sle);
    }

    fn erase(&mut self, key: &Key) {
        self.state_table.erase(key);
    }

    fn apply_flags(&self) -> ApplyFlags {
        self.flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::ledger_core::ClosedLedger;
    use crate::ledger::views::RawView;

    #[test]
    fn test_apply_view_peek_and_update() {
        let mut base = ClosedLedger::genesis();

        // Insert an account into the base ledger
        let account_id = [0xAA; 20];
        let keylet = crate::ledger::keylet::account(&account_id);
        let mut data = vec![0x11, 0x00, 0x61]; // LedgerEntryType
        data.extend_from_slice(&[0x24, 0x00, 0x00, 0x00, 0x01]); // Sequence=1
        let sle = Arc::new(SLE::new(keylet.key, LedgerEntryType::AccountRoot, data));
        base.raw_insert(sle);

        let mut open = OpenView::new(Arc::new(base));
        let mut view = ApplyViewImpl::new(&mut open, ApplyFlags::NONE);

        // Peek the account
        let sle = view.peek(&keylet).unwrap();
        assert_eq!(sle.sequence(), Some(1));

        // Modify and update
        let mut modified = (*sle).clone();
        modified.set_sequence(2);
        view.update(Arc::new(modified));

        // Read should reflect the update
        let updated = view.read(&keylet).unwrap();
        assert_eq!(updated.sequence(), Some(2));

        // Apply to OpenView
        let result = view.apply();
        assert_eq!(result.affected_nodes.len(), 1);
        assert_eq!(result.affected_nodes[0].action, AffectedAction::Modified);
    }

    #[test]
    fn test_apply_view_insert_and_erase() {
        let base = ClosedLedger::genesis();
        let mut open = OpenView::new(Arc::new(base));
        let mut view = ApplyViewImpl::new(&mut open, ApplyFlags::NONE);

        let account_id = [0xCC; 20];
        let keylet = crate::ledger::keylet::account(&account_id);
        let data = vec![0x11, 0x00, 0x61];
        let sle = Arc::new(SLE::new(keylet.key, LedgerEntryType::AccountRoot, data));

        // Insert
        view.insert(sle);
        assert!(view.exists(&keylet));

        // Erase
        view.erase(&keylet.key);
        assert!(!view.exists(&keylet));

        // Apply — insert+erase in same tx should cancel out
        let result = view.apply();
        assert_eq!(result.affected_nodes.len(), 0);
    }
}
