//! xLedgRS purpose: Open View support for XRPL ledger state and SHAMap logic.
//! OpenView — per-ledger mutable view wrapping a closed Ledger.
//!
//! Buffers all mutations in a RawStateTable. Also owns the transaction
//! SHAMap for the new ledger being built.
//!
//! Matches rippled's OpenView.

use crate::ledger::fees::Fees;
use crate::ledger::keylet::Keylet;
use crate::ledger::rules::Rules;
use crate::ledger::shamap::SHAMap;
use crate::ledger::sle::SLE;
use crate::ledger::state_table::{RawAction, RawStateTable};
use crate::ledger::views::{LedgerInfo, RawView, ReadView, TxsRawView};
use crate::ledger::Key;
use std::sync::Arc;

/// Per-ledger mutable view. Wraps a closed Ledger (the base ReadView)
/// and buffers all mutations in a RawStateTable.
#[derive(Clone)]
pub struct OpenView {
    /// The base (closed) ledger — read-only.
    base: Arc<dyn ReadView + Send + Sync>,
    /// Buffered state mutations.
    state_table: RawStateTable,
    /// Transaction SHAMap for this open ledger.
    tx_map: SHAMap,
    /// Ledger info copied from the base view and updated as changes are staged.
    info: LedgerInfo,
    /// Fee settings (inherited from base).
    fees: Fees,
    /// Rules (inherited from base).
    rules: Rules,
    /// Transaction count.
    tx_count: u32,
}

impl OpenView {
    /// Create a new open view wrapping a closed ledger.
    pub fn new(base: Arc<dyn ReadView + Send + Sync>) -> Self {
        let info = base.info().clone();
        let fees = base.fees().clone();
        let rules = base.rules().clone();
        Self {
            base,
            state_table: RawStateTable::new(),
            tx_map: SHAMap::new_transaction(),
            info,
            fees,
            rules,
            tx_count: 0,
        }
    }

    /// Apply all buffered changes to a target RawView (typically the new ClosedLedger).
    pub fn apply(&self, target: &mut dyn RawView) {
        self.state_table.apply(target);
    }

    /// Access the buffered state table (for ApplyViewImpl to delegate reads).
    pub fn state_table(&self) -> &RawStateTable {
        &self.state_table
    }

    /// Mutable access to info (for close_time, etc.).
    pub fn info_mut(&mut self) -> &mut LedgerInfo {
        &mut self.info
    }

    /// Transaction count in this open ledger.
    pub fn tx_count(&self) -> u32 {
        self.tx_count
    }

    /// Apply buffered state changes to a SHAMap and return the new root hash.
    /// This is the state_hash for the new ledger.
    pub fn apply_to_shamap(&self, shamap: &mut crate::ledger::shamap::SHAMap) -> [u8; 32] {
        use crate::ledger::state_table::RawAction;
        for (key, (action, sle_opt)) in self.state_table.iter() {
            match action {
                RawAction::Insert | RawAction::Replace => {
                    if let Some(sle) = sle_opt {
                        shamap.insert(*key, sle.data().to_vec());
                    }
                }
                RawAction::Erase => {
                    shamap.remove(key);
                }
            }
        }
        shamap.root_hash()
    }

    /// Get the transaction SHAMap root hash.
    pub fn tx_hash(&mut self) -> [u8; 32] {
        self.tx_map.root_hash()
    }

    /// Return the raw transaction blobs currently staged in this open view.
    pub fn tx_blobs(&self) -> Vec<(crate::ledger::Key, Vec<u8>)> {
        self.tx_map
            .iter_leaves()
            .into_iter()
            .filter_map(|(key, payload)| {
                let (tx_len, prefix_len) = crate::transaction::serialize::decode_length(payload);
                if prefix_len == 0 || payload.len() < prefix_len.saturating_add(tx_len) {
                    return None;
                }
                Some((key, payload[prefix_len..prefix_len + tx_len].to_vec()))
            })
            .collect()
    }
}

impl ReadView for OpenView {
    fn read(&self, keylet: &Keylet) -> Option<Arc<SLE>> {
        // Check the staged buffer first.
        match self.state_table.get(&keylet.key) {
            Some((RawAction::Erase, _)) => return None,
            Some((_, Some(sle))) => {
                if keylet.check(sle) {
                    return Some(Arc::clone(sle));
                } else {
                    return None; // type mismatch
                }
            }
            Some((_, None)) => return None,
            None => {} // fall through to base
        }
        self.base.read(keylet)
    }

    fn exists(&self, keylet: &Keylet) -> bool {
        match self.state_table.exists(&keylet.key) {
            Some(exists) => exists,
            None => self.base.exists(keylet),
        }
    }

    fn succ(&self, key: &Key, last: Option<&Key>) -> Option<Key> {
        // Merge the staged buffer's successor with the base successor.
        let buf_succ = self.state_table.succ(key);
        let base_succ = self.base.succ(key, last);

        match (buf_succ, base_succ) {
            (Some(a), Some(b)) => {
                let candidate = if a < b { a } else { b };
                if let Some(last) = last {
                    if &candidate >= last {
                        None
                    } else {
                        Some(candidate)
                    }
                } else {
                    Some(candidate)
                }
            }
            (Some(a), None) => {
                if let Some(last) = last {
                    if &a >= last {
                        None
                    } else {
                        Some(a)
                    }
                } else {
                    Some(a)
                }
            }
            (None, Some(b)) => Some(b), // base already applied last filter
            (None, None) => None,
        }
    }

    fn info(&self) -> &LedgerInfo {
        &self.info
    }
    fn fees(&self) -> &Fees {
        &self.fees
    }
    fn rules(&self) -> &Rules {
        &self.rules
    }
}

impl RawView for OpenView {
    fn raw_insert(&mut self, sle: Arc<SLE>) {
        self.state_table.insert(sle);
    }

    fn raw_replace(&mut self, sle: Arc<SLE>) {
        self.state_table.replace(sle);
    }

    fn raw_erase(&mut self, key: &Key) {
        self.state_table.erase(key);
    }

    fn raw_destroy_xrp(&mut self, drops: u64) {
        self.state_table.destroy_xrp(drops);
        self.info.total_coins = self.info.total_coins.saturating_sub(drops);
    }
}

impl TxsRawView for OpenView {
    fn raw_tx_insert(&mut self, key: Key, tx_blob: Vec<u8>, meta_blob: Vec<u8>) {
        // Combine tx + meta in VL-encoded format matching rippled's tx tree leaf:
        // VL(tx_blob) + VL(meta_blob)
        let mut combined = Vec::with_capacity(tx_blob.len() + meta_blob.len() + 8);
        crate::ledger::meta::encode_vl_length(&mut combined, tx_blob.len());
        combined.extend_from_slice(&tx_blob);
        crate::ledger::meta::encode_vl_length(&mut combined, meta_blob.len());
        combined.extend_from_slice(&meta_blob);

        self.tx_map.insert(key, combined);
        self.tx_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::ledger_core::ClosedLedger;
    use crate::ledger::sle::LedgerEntryType;

    #[test]
    fn test_open_view_read_through() {
        let mut base = ClosedLedger::genesis();
        let account_id = [0xAA; 20];
        let keylet = crate::ledger::keylet::account(&account_id);
        let data = vec![0x11, 0x00, 0x61, 0x22, 0x00, 0x00, 0x00, 0x00];
        base.raw_insert(Arc::new(SLE::new(
            keylet.key,
            LedgerEntryType::AccountRoot,
            data,
        )));

        let view = OpenView::new(Arc::new(base));

        // Should read through to base
        let sle = view.read(&keylet);
        assert!(sle.is_some());
    }

    #[test]
    fn test_open_view_buffer_overrides() {
        let base = ClosedLedger::genesis();
        let mut view = OpenView::new(Arc::new(base));

        let account_id = [0xBB; 20];
        let keylet = crate::ledger::keylet::account(&account_id);
        let data = vec![0x11, 0x00, 0x61, 0x22, 0x00, 0x00, 0x00, 0x01]; // flags=1
        let sle = Arc::new(SLE::new(keylet.key, LedgerEntryType::AccountRoot, data));

        view.raw_insert(sle);
        assert!(view.exists(&keylet));

        view.raw_erase(&keylet.key);
        assert!(!view.exists(&keylet));
    }
}
