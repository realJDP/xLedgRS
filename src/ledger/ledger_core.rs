//! Ledger — a closed, immutable ledger implementing ReadView + RawView.
//!
//! The Ledger owns the account state SHAMap and transaction SHAMap,
//! both backed by persistent storage (NodeStore). All state reads go
//! through the SHAMap, which resolves stubs from storage on demand.

use std::sync::{Arc, Mutex, MutexGuard};
use crate::ledger::Key;
use crate::ledger::keylet::Keylet;
use crate::ledger::sle::SLE;
use crate::ledger::fees::Fees;
use crate::ledger::rules::Rules;
use crate::ledger::views::{ReadView, RawView, LedgerInfo};
use crate::ledger::shamap::SHAMap;

/// A closed ledger. Implements ReadView backed by SHAMap.
///
/// SHAMaps are behind Mutex for interior mutability — lazy stub resolution
/// is a structural mutation (loading data from NuDB) but not a semantic one
/// (the logical state doesn't change).
pub struct ClosedLedger {
    info: LedgerInfo,
    /// Account state SHAMap (backed by persistent storage).
    state_map: Mutex<SHAMap>,
    /// Transaction SHAMap.
    tx_map: Mutex<SHAMap>,
    /// Fee settings parsed from the FeeSettings SLE.
    fees: Fees,
    /// Active amendment rules.
    rules: Rules,
}

impl ClosedLedger {
    /// Create a new closed ledger from components.
    pub fn new(
        info: LedgerInfo,
        state_map: SHAMap,
        tx_map: SHAMap,
        fees: Fees,
        rules: Rules,
    ) -> Self {
        Self {
            info,
            state_map: Mutex::new(state_map),
            tx_map: Mutex::new(tx_map),
            fees,
            rules,
        }
    }

    /// Create a minimal genesis ledger.
    pub fn genesis() -> Self {
        Self {
            info: LedgerInfo::default(),
            state_map: Mutex::new(SHAMap::new_state()),
            tx_map: Mutex::new(SHAMap::new_transaction()),
            fees: Fees::default(),
            rules: Rules::new(),
        }
    }

    fn state_map_guard(&self) -> MutexGuard<'_, SHAMap> {
        self.state_map.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn tx_map_guard(&self) -> MutexGuard<'_, SHAMap> {
        self.tx_map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Compute the state root hash.
    pub fn state_hash(&self) -> [u8; 32] {
        self.state_map_guard().root_hash()
    }

    /// Compute the transaction root hash.
    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx_map_guard().root_hash()
    }

    /// Access the ledger info mutably.
    pub fn info_mut(&mut self) -> &mut LedgerInfo {
        &mut self.info
    }

    /// Create a mutable snapshot of the state SHAMap.
    /// The snapshot shares the NuDB backend but has its own tree structure.
    /// Leaves become stubs (key + hash only) — data loaded from backend on demand.
    /// Matches rippled's SHAMap copy constructor (copy-on-write).
    pub fn clone_state_map(&self) -> SHAMap {
        self.state_map_guard().snapshot()
    }

    /// Get raw SLE data by key (type-unchecked). Used by ledger_entry for
    /// generic lookups where the caller handles type interpretation.
    pub fn get_raw(&self, key: &Key) -> Option<Vec<u8>> {
        self.state_map_guard().get(key)
    }
}

impl ReadView for ClosedLedger {
    fn read(&self, keylet: &Keylet) -> Option<Arc<SLE>> {
        let data = self.state_map_guard().get(&keylet.key)?;
        let sle = SLE::from_raw(keylet.key, data)?;
        if sle.entry_type() == keylet.entry_type {
            Some(Arc::new(sle))
        } else {
            None
        }
    }

    fn exists(&self, keylet: &Keylet) -> bool {
        self.state_map_guard().get(&keylet.key).is_some()
    }

    fn succ(&self, key: &Key, last: Option<&Key>) -> Option<Key> {
        let next = self.state_map_guard().upper_bound(key)?;
        if let Some(last) = last {
            if &next >= last { return None; }
        }
        Some(next)
    }

    fn info(&self) -> &LedgerInfo { &self.info }
    fn fees(&self) -> &Fees { &self.fees }
    fn rules(&self) -> &Rules { &self.rules }
}

impl RawView for ClosedLedger {
    fn raw_insert(&mut self, sle: Arc<SLE>) {
        self.state_map_guard().insert(*sle.key(), sle.data().to_vec());
    }

    fn raw_replace(&mut self, sle: Arc<SLE>) {
        self.state_map_guard().insert(*sle.key(), sle.data().to_vec());
    }

    fn raw_erase(&mut self, key: &Key) {
        self.state_map_guard().remove(key);
    }

    fn raw_destroy_xrp(&mut self, drops: u64) {
        self.info.total_coins = self.info.total_coins.saturating_sub(drops);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::sle::LedgerEntryType;

    #[test]
    fn test_genesis_ledger() {
        let ledger = ClosedLedger::genesis();
        assert_eq!(ledger.info().seq, 0);
    }

    #[test]
    fn test_raw_insert_and_read() {
        let mut ledger = ClosedLedger::genesis();

        let account_id = [0xAA; 20];
        let keylet = crate::ledger::keylet::account(&account_id);
        let data = vec![0x11, 0x00, 0x61, 0x22, 0x00, 0x00, 0x00, 0x00];
        let sle = Arc::new(SLE::new(keylet.key, LedgerEntryType::AccountRoot, data));

        ledger.raw_insert(sle);

        let read_back = ledger.read(&keylet);
        assert!(read_back.is_some());
        assert_eq!(read_back.unwrap().entry_type(), LedgerEntryType::AccountRoot);
    }

    #[test]
    fn test_raw_erase() {
        let mut ledger = ClosedLedger::genesis();
        let account_id = [0xBB; 20];
        let keylet = crate::ledger::keylet::account(&account_id);
        let data = vec![0x11, 0x00, 0x61];
        let sle = Arc::new(SLE::new(keylet.key, LedgerEntryType::AccountRoot, data));

        ledger.raw_insert(sle);
        assert!(ledger.exists(&keylet));

        ledger.raw_erase(&keylet.key);
        assert!(!ledger.exists(&keylet));
    }

    #[test]
    fn test_type_mismatch_returns_none() {
        let mut ledger = ClosedLedger::genesis();
        let account_id = [0xCC; 20];
        let keylet = crate::ledger::keylet::account(&account_id);
        let data = vec![0x11, 0x00, 0x61];
        let sle = Arc::new(SLE::new(keylet.key, LedgerEntryType::AccountRoot, data));

        ledger.raw_insert(sle);

        let wrong_keylet = Keylet::new(keylet.key, LedgerEntryType::Offer);
        assert!(ledger.read(&wrong_keylet).is_none());
    }
}
