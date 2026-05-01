//! xLedgRS purpose: State Table support for XRPL ledger state and SHAMap logic.
//! State tables — mutation buffers for the view stack.
//!
//! RawStateTable: simple insert/replace/erase buffer (used by OpenView).
//! ApplyStateTable: richer buffer with before/after tracking (used by ApplyViewImpl).

use crate::ledger::keylet::Keylet;
use crate::ledger::sle::SLE;
use crate::ledger::views::{RawView, ReadView};
use crate::ledger::Key;
use std::collections::BTreeMap;
use std::sync::Arc;

// ═════════════════════════════════════════════════════════════════════════════
// RawStateTable — used by OpenView
// ═════════════════════════════════════════════════════════════════════════════

/// Action tracked by RawStateTable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawAction {
    Insert,
    Replace,
    Erase,
}

/// Simple mutation buffer: tracks insert/replace/erase operations on SLEs.
/// Used by OpenView to accumulate a ledger's worth of changes.
#[derive(Clone)]
pub struct RawStateTable {
    items: BTreeMap<Key, (RawAction, Option<Arc<SLE>>)>,
    xrp_destroyed: u64,
}

impl RawStateTable {
    pub fn new() -> Self {
        Self {
            items: BTreeMap::new(),
            xrp_destroyed: 0,
        }
    }

    pub fn insert(&mut self, sle: Arc<SLE>) {
        self.items
            .insert(*sle.key(), (RawAction::Insert, Some(sle)));
    }

    pub fn replace(&mut self, sle: Arc<SLE>) {
        self.items
            .insert(*sle.key(), (RawAction::Replace, Some(sle)));
    }

    pub fn erase(&mut self, key: &Key) {
        self.items.insert(*key, (RawAction::Erase, None));
    }

    pub fn destroy_xrp(&mut self, drops: u64) {
        self.xrp_destroyed += drops;
    }

    /// Look up a buffered item. Returns None if this key isn't in the buffer
    /// (meaning fall through to the base view).
    pub fn get(&self, key: &Key) -> Option<&(RawAction, Option<Arc<SLE>>)> {
        self.items.get(key)
    }

    /// Check if a key exists in the buffer (for exists() queries).
    /// Returns Some(true) if inserted/replaced, Some(false) if erased,
    /// None if not in buffer (fall through to base).
    pub fn exists(&self, key: &Key) -> Option<bool> {
        match self.items.get(key) {
            Some((RawAction::Erase, _)) => Some(false),
            Some(_) => Some(true),
            None => None,
        }
    }

    /// Find the successor key in the buffer. This must be merged with
    /// the base view's succ() for a complete answer.
    pub fn succ(&self, key: &Key) -> Option<Key> {
        use std::ops::Bound;
        self.items
            .range((Bound::Excluded(key), Bound::Unbounded))
            .find(|(_, (action, _))| *action != RawAction::Erase)
            .map(|(k, _)| *k)
    }

    /// Apply all buffered changes to a target RawView.
    pub fn apply(&self, target: &mut dyn RawView) {
        for (key, (action, sle)) in &self.items {
            match action {
                RawAction::Insert => {
                    if let Some(sle) = sle {
                        target.raw_insert(Arc::clone(sle));
                    }
                }
                RawAction::Replace => {
                    if let Some(sle) = sle {
                        target.raw_replace(Arc::clone(sle));
                    }
                }
                RawAction::Erase => {
                    target.raw_erase(key);
                }
            }
        }
        if self.xrp_destroyed > 0 {
            target.raw_destroy_xrp(self.xrp_destroyed);
        }
    }

    pub fn xrp_destroyed(&self) -> u64 {
        self.xrp_destroyed
    }

    /// Iterate all entries (for debugging / invariant checking).
    pub fn iter(&self) -> impl Iterator<Item = (&Key, &(RawAction, Option<Arc<SLE>>))> {
        self.items.iter()
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ApplyStateTable — used by ApplyViewImpl
// ═════════════════════════════════════════════════════════════════════════════

/// Action tracked by ApplyStateTable (richer than RawAction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyAction {
    /// Read but not modified. Used to cache SLEs for peek().
    Cache,
    /// Newly created object.
    Insert,
    /// Existing object was modified.
    Modify,
    /// Existing object was removed.
    Erase,
}

/// An entry in the ApplyStateTable.
#[derive(Clone)]
pub struct ApplyEntry {
    pub action: ApplyAction,
    /// The SLE in its current state (after modification).
    /// None for Erase actions.
    pub sle: Option<Arc<SLE>>,
    /// The original SLE before this transaction touched it.
    /// Present for Modify and Erase actions (used for TxMeta generation).
    pub original: Option<Arc<SLE>>,
}

/// Per-transaction mutation buffer with before/after tracking for metadata.
/// Used by ApplyViewImpl. Matches rippled's ApplyStateTable.
pub struct ApplyStateTable {
    items: BTreeMap<Key, ApplyEntry>,
    xrp_destroyed: u64,
}

impl ApplyStateTable {
    pub fn new() -> Self {
        Self {
            items: BTreeMap::new(),
            xrp_destroyed: 0,
        }
    }

    /// Peek: load from base view and cache for potential modification.
    /// If already cached, return the cached version.
    pub fn peek(&mut self, keylet: &Keylet, base: &dyn ReadView) -> Option<Arc<SLE>> {
        if let Some(entry) = self.items.get(&keylet.key) {
            match entry.action {
                ApplyAction::Erase => return None,
                _ => return entry.sle.clone(),
            }
        }

        // The entry is not staged in the buffer, so fetch it from the base view.
        let sle = base.read(keylet)?;

        // Cache it (Action::Cache means "read but not yet modified")
        self.items.insert(
            keylet.key,
            ApplyEntry {
                action: ApplyAction::Cache,
                sle: Some(Arc::clone(&sle)),
                original: Some(Arc::clone(&sle)),
            },
        );

        Some(sle)
    }

    /// Read without caching (for exists/succ checks).
    pub fn read(&self, key: &Key) -> Option<&ApplyEntry> {
        self.items.get(key)
    }

    /// Check if a key exists in this table.
    /// Returns Some(true/false) if known, None to fall through to base.
    pub fn exists(&self, key: &Key) -> Option<bool> {
        match self.items.get(key) {
            Some(entry) => match entry.action {
                ApplyAction::Erase => Some(false),
                _ => Some(true),
            },
            None => None,
        }
    }

    /// Mark as newly inserted.
    pub fn insert(&mut self, sle: Arc<SLE>) {
        self.items.insert(
            *sle.key(),
            ApplyEntry {
                action: ApplyAction::Insert,
                sle: Some(sle),
                original: None,
            },
        );
    }

    /// Mark as modified. Must have been peek'd first (will be in Cache state).
    pub fn update(&mut self, sle: Arc<SLE>) {
        let key = *sle.key();
        if let Some(entry) = self.items.get_mut(&key) {
            // Preserve original, update action and current SLE
            if entry.action == ApplyAction::Cache {
                entry.action = ApplyAction::Modify;
            }
            // If already Modify or Insert, keep that action
            entry.sle = Some(sle);
        } else {
            // Shouldn't happen (must peek first), but handle gracefully
            self.items.insert(
                key,
                ApplyEntry {
                    action: ApplyAction::Modify,
                    sle: Some(sle),
                    original: None,
                },
            );
        }
    }

    /// Mark as erased.
    pub fn erase(&mut self, key: &Key) {
        if let Some(entry) = self.items.get_mut(key) {
            if entry.action == ApplyAction::Insert {
                // Inserted then erased in same tx — remove entirely
                self.items.remove(key);
                return;
            }
            entry.action = ApplyAction::Erase;
            entry.sle = None;
        } else {
            self.items.insert(
                *key,
                ApplyEntry {
                    action: ApplyAction::Erase,
                    sle: None,
                    original: None,
                },
            );
        }
    }

    pub fn destroy_xrp(&mut self, drops: u64) {
        self.xrp_destroyed += drops;
    }

    /// Apply all changes to a target RawView (typically OpenView).
    /// Only applies non-Cache entries (Cache means "read but not modified").
    pub fn apply_raw(&self, target: &mut dyn RawView) {
        for (key, entry) in &self.items {
            match entry.action {
                ApplyAction::Cache => {
                    // No change — don't apply
                }
                ApplyAction::Insert => {
                    if let Some(ref sle) = entry.sle {
                        target.raw_insert(Arc::clone(sle));
                    }
                }
                ApplyAction::Modify => {
                    if let Some(ref sle) = entry.sle {
                        target.raw_replace(Arc::clone(sle));
                    }
                }
                ApplyAction::Erase => {
                    target.raw_erase(key);
                }
            }
        }
        if self.xrp_destroyed > 0 {
            target.raw_destroy_xrp(self.xrp_destroyed);
        }
    }

    /// Iterate all touched entries for metadata generation.
    /// Only yields non-Cache entries (actual changes).
    pub fn iter_changes(&self) -> impl Iterator<Item = (&Key, &ApplyEntry)> {
        self.items
            .iter()
            .filter(|(_, e)| e.action != ApplyAction::Cache)
    }

    /// Iterate ALL entries including cached (for invariant checking).
    pub fn iter_all(&self) -> impl Iterator<Item = (&Key, &ApplyEntry)> {
        self.items.iter()
    }

    /// Discard all changes.
    pub fn clear(&mut self) {
        self.items.clear();
        self.xrp_destroyed = 0;
    }

    /// Number of actual changes (excludes Cache).
    pub fn change_count(&self) -> usize {
        self.items
            .values()
            .filter(|e| e.action != ApplyAction::Cache)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::sle::LedgerEntryType;

    fn make_sle(key_byte: u8) -> Arc<SLE> {
        let key = Key([key_byte; 32]);
        let data = vec![0x11, 0x00, 0x61]; // AccountRoot
        Arc::new(SLE::new(key, LedgerEntryType::AccountRoot, data))
    }

    #[test]
    fn test_raw_state_table_insert_erase() {
        let mut table = RawStateTable::new();
        let sle = make_sle(0xAA);
        let key = *sle.key();

        table.insert(sle);
        assert_eq!(table.exists(&key), Some(true));

        table.erase(&key);
        assert_eq!(table.exists(&key), Some(false));
    }

    #[test]
    fn test_raw_state_table_succ() {
        let mut table = RawStateTable::new();
        table.insert(make_sle(0x10));
        table.insert(make_sle(0x20));
        table.insert(make_sle(0x30));

        let key_10 = Key([0x10; 32]);
        let next = table.succ(&key_10);
        assert_eq!(next, Some(Key([0x20; 32])));
    }

    #[test]
    fn test_apply_state_table_insert_then_erase() {
        let mut table = ApplyStateTable::new();
        let sle = make_sle(0xBB);
        let key = *sle.key();

        table.insert(sle);
        assert_eq!(table.exists(&key), Some(true));

        // Erasing an entry inserted in the same table should remove it entirely.
        table.erase(&key);
        assert_eq!(table.exists(&key), None); // removed from table
    }

    #[test]
    fn test_apply_state_table_change_count() {
        let mut table = ApplyStateTable::new();
        let sle = make_sle(0xCC);
        let key = *sle.key();

        // Cache entry (simulating a peek)
        table.items.insert(
            key,
            ApplyEntry {
                action: ApplyAction::Cache,
                sle: Some(make_sle(0xCC)),
                original: Some(make_sle(0xCC)),
            },
        );

        assert_eq!(table.change_count(), 0); // Cache doesn't count

        // Update it
        table.update(make_sle(0xCC));
        assert_eq!(table.change_count(), 1); // Now it's a Modify
    }
}
