//! Open-ledger queue state and transaction application tracking.

use crate::crypto::sha512_first_half;
use crate::ledger::ledger_core::ClosedLedger;
use crate::ledger::open_view::OpenView;
use crate::ledger::pool::{FeeMetrics, TxPool};
use crate::ledger::transact::{self, TER};
use crate::ledger::views::{ApplyFlags, ReadView, TxsRawView};
use std::sync::Arc;

const OPEN_LEDGER_TOTAL_PASSES: usize = 3;
const OPEN_LEDGER_RETRY_PASSES: usize = 1;

#[derive(Debug, Clone, Default)]
pub struct OpenLedgerSnapshot {
    pub ledger_current_index: u32,
    pub parent_ledger_index: u32,
    pub parent_hash: String,
    pub last_close_time: u64,
    pub queued_transactions: usize,
    pub candidate_set_hash: String,
    pub escalation_multiplier: u64,
    pub txns_expected: u64,
    pub max_queue_size: usize,
    pub open_fee_level: u64,
    pub revision: u64,
    pub modify_count: u64,
    pub accept_count: u64,
    pub last_modified_unix: u64,
    pub last_accept_unix: u64,
    pub has_open_view: bool,
    pub open_view_base_ledger_index: u32,
    pub open_view_applied_transactions: usize,
    pub open_view_failed_transactions: usize,
    pub open_view_skipped_transactions: usize,
    pub open_view_tx_count: u32,
    pub open_view_state_hash: String,
    pub open_view_tx_hash: String,
}

struct CanonicalEntry {
    salted_account: [u8; 32],
    sequence: u32,
    hash: [u8; 32],
    blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenLedgerTx {
    pub hash: [u8; 32],
    pub blob: Vec<u8>,
}

impl CanonicalEntry {
    fn new(
        account: &[u8; 20],
        sequence: u32,
        hash: [u8; 32],
        blob: Vec<u8>,
        salt: &[u8; 32],
    ) -> Self {
        let mut salted = [0u8; 32];
        salted[..20].copy_from_slice(account);
        for (slot, salt_byte) in salted.iter_mut().zip(salt.iter()) {
            *slot ^= *salt_byte;
        }
        Self {
            salted_account: salted,
            sequence,
            hash,
            blob,
        }
    }
}

impl Ord for CanonicalEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.salted_account
            .cmp(&other.salted_account)
            .then(self.sequence.cmp(&other.sequence))
            .then(self.hash.cmp(&other.hash))
    }
}

impl PartialOrd for CanonicalEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for CanonicalEntry {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for CanonicalEntry {}

pub struct OpenLedger {
    base_ledger: Option<Arc<ClosedLedger>>,
    parent_ledger_index: u32,
    parent_hash: [u8; 32],
    last_close_time: u64,
    queued_transactions: usize,
    candidate_set_hash: [u8; 32],
    escalation_multiplier: u64,
    txns_expected: u64,
    max_queue_size: usize,
    open_fee_level: u64,
    revision: u64,
    modify_count: u64,
    accept_count: u64,
    last_modified_unix: u64,
    last_accept_unix: u64,
    open_view: Option<OpenView>,
    open_view_base_ledger_index: u32,
    open_view_applied_transactions: usize,
    open_view_failed_transactions: usize,
    open_view_skipped_transactions: usize,
    open_view_tx_count: u32,
    open_view_state_hash: [u8; 32],
    open_view_tx_hash: [u8; 32],
}

impl Default for OpenLedger {
    fn default() -> Self {
        Self {
            parent_ledger_index: 0,
            base_ledger: None,
            parent_hash: [0; 32],
            last_close_time: 0,
            queued_transactions: 0,
            candidate_set_hash: [0; 32],
            escalation_multiplier: 0,
            txns_expected: 0,
            max_queue_size: 0,
            open_fee_level: 0,
            revision: 0,
            modify_count: 0,
            accept_count: 0,
            last_modified_unix: 0,
            last_accept_unix: 0,
            open_view: None,
            open_view_base_ledger_index: 0,
            open_view_applied_transactions: 0,
            open_view_failed_transactions: 0,
            open_view_skipped_transactions: 0,
            open_view_tx_count: 0,
            open_view_state_hash: [0; 32],
            open_view_tx_hash: [0; 32],
        }
    }
}

impl OpenLedger {
    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn note_mutation(&mut self) {
        self.revision = self.revision.saturating_add(1);
        self.modify_count = self.modify_count.saturating_add(1);
        self.last_modified_unix = Self::unix_now();
    }

    fn note_accept(&mut self) {
        self.revision = self.revision.saturating_add(1);
        self.accept_count = self.accept_count.saturating_add(1);
        self.last_accept_unix = Self::unix_now();
    }

    fn has_live_view(&self) -> bool {
        self.open_view.is_some()
    }

    fn queue_state_changed(
        &self,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
        metrics: &FeeMetrics,
    ) -> bool {
        let next_open_fee_level = metrics.escalated_fee_level(queued_transactions as u64 + 1);
        self.queued_transactions != queued_transactions
            || self.candidate_set_hash != candidate_set_hash
            || self.escalation_multiplier != metrics.escalation_multiplier
            || self.txns_expected != metrics.txns_expected
            || self.max_queue_size != metrics.max_queue_size()
            || self.open_fee_level != next_open_fee_level
    }

    fn apply_queue_state_without_note(
        &mut self,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
        metrics: &FeeMetrics,
    ) -> bool {
        let changed = self.queue_state_changed(queued_transactions, candidate_set_hash, metrics);
        self.queued_transactions = queued_transactions;
        self.candidate_set_hash = candidate_set_hash;
        self.escalation_multiplier = metrics.escalation_multiplier;
        self.txns_expected = metrics.txns_expected;
        self.max_queue_size = metrics.max_queue_size();
        self.open_fee_level = metrics.escalated_fee_level(queued_transactions as u64 + 1);
        changed
    }

    fn apply_queue_state(
        &mut self,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
        metrics: &FeeMetrics,
    ) -> bool {
        let changed =
            self.apply_queue_state_without_note(queued_transactions, candidate_set_hash, metrics);
        if changed {
            self.note_mutation();
        }
        changed
    }

    fn live_view_changed(
        &self,
        base_ledger_index: u32,
        applied_transactions: usize,
        failed_transactions: usize,
        skipped_transactions: usize,
        tx_count: u32,
        state_hash: [u8; 32],
        tx_hash: [u8; 32],
    ) -> bool {
        !self.has_live_view()
            || self.open_view_base_ledger_index != base_ledger_index
            || self.open_view_applied_transactions != applied_transactions
            || self.open_view_failed_transactions != failed_transactions
            || self.open_view_skipped_transactions != skipped_transactions
            || self.open_view_tx_count != tx_count
            || self.open_view_state_hash != state_hash
            || self.open_view_tx_hash != tx_hash
    }

    fn store_live_view(
        &mut self,
        open_view: OpenView,
        base_ledger_index: u32,
        applied_transactions: usize,
        failed_transactions: usize,
        skipped_transactions: usize,
        tx_count: u32,
        state_hash: [u8; 32],
        tx_hash: [u8; 32],
    ) -> bool {
        let changed = self.live_view_changed(
            base_ledger_index,
            applied_transactions,
            failed_transactions,
            skipped_transactions,
            tx_count,
            state_hash,
            tx_hash,
        );
        self.open_view = Some(open_view);
        self.open_view_base_ledger_index = base_ledger_index;
        self.open_view_applied_transactions = applied_transactions;
        self.open_view_failed_transactions = failed_transactions;
        self.open_view_skipped_transactions = skipped_transactions;
        self.open_view_tx_count = tx_count;
        self.open_view_state_hash = state_hash;
        self.open_view_tx_hash = tx_hash;
        changed
    }

    fn commit_live_view(
        &mut self,
        base: &ClosedLedger,
        mut open_view: OpenView,
        applied_transactions: usize,
        failed_transactions: usize,
        skipped_transactions: usize,
    ) -> bool {
        let base_info = base.info().clone();
        let mut state_map = base.clone_state_map();
        let state_hash = open_view.apply_to_shamap(&mut state_map);
        let tx_hash = open_view.tx_hash();
        let tx_count = open_view.tx_count();
        open_view.info_mut().account_hash = state_hash;
        open_view.info_mut().tx_hash = tx_hash;
        self.store_live_view(
            open_view,
            base_info.seq,
            applied_transactions,
            failed_transactions,
            skipped_transactions,
            tx_count,
            state_hash,
            tx_hash,
        )
    }

    fn refresh_live_view_from_current(&mut self, open_view: OpenView) -> bool {
        let Some(base) = self.base_ledger.clone() else {
            return false;
        };
        self.commit_live_view(
            base.as_ref(),
            open_view,
            self.open_view_applied_transactions,
            self.open_view_failed_transactions,
            self.open_view_skipped_transactions,
        )
    }

    fn canonical_salt(sources: &[&[OpenLedgerTx]]) -> [u8; 32] {
        let salt = {
            let total = sources.iter().map(|entries| entries.len()).sum::<usize>();
            let mut data = Vec::with_capacity(total * 32);
            for entries in sources {
                for entry in *entries {
                    data.extend_from_slice(&entry.hash);
                }
            }
            if data.is_empty() {
                [0u8; 32]
            } else {
                sha512_first_half(&data)
            }
        };
        salt
    }

    fn canonical_entries_from_transactions(
        entries: &[OpenLedgerTx],
        salt: &[u8; 32],
    ) -> (Vec<CanonicalEntry>, usize) {
        let mut skipped = 0usize;
        let mut canonical = Vec::with_capacity(entries.len());
        for entry in entries {
            let parsed = match crate::transaction::parse_blob(&entry.blob) {
                Ok(parsed) => parsed,
                Err(_) => {
                    skipped = skipped.saturating_add(1);
                    continue;
                }
            };
            canonical.push(CanonicalEntry::new(
                &parsed.account,
                parsed.sequence,
                entry.hash,
                entry.blob.clone(),
                &salt,
            ));
        }
        canonical.sort();
        (canonical, skipped)
    }

    fn pool_transactions(pool: &TxPool) -> Vec<OpenLedgerTx> {
        let mut snapshot = pool.clone();
        snapshot
            .drain_sorted()
            .into_iter()
            .map(|entry| OpenLedgerTx {
                hash: entry.hash,
                blob: entry.blob,
            })
            .collect()
    }

    fn dedup_transactions(
        entries: &[OpenLedgerTx],
        seen: &mut std::collections::HashSet<[u8; 32]>,
    ) -> Vec<OpenLedgerTx> {
        let mut unique = Vec::with_capacity(entries.len());
        for entry in entries {
            if seen.insert(entry.hash) {
                unique.push(entry.clone());
            }
        }
        unique
    }

    fn is_permanent_failure(ter: &TER) -> bool {
        matches!(ter, TER::Malformed(_) | TER::LocalFail(_))
    }

    fn apply_canonical_entries(
        open: &mut OpenView,
        mut txns: Vec<CanonicalEntry>,
        applied_transactions: &mut usize,
        failed_transactions: &mut usize,
        skipped_transactions: &mut usize,
    ) {
        if txns.is_empty() {
            return;
        }

        let mut certain_retry = true;
        let mut failed_set: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

        for pass in 0..OPEN_LEDGER_TOTAL_PASSES {
            let flags = if certain_retry {
                ApplyFlags::RETRY
            } else {
                ApplyFlags::NONE
            };
            let mut changes = 0usize;
            let mut kept = Vec::new();

            for entry in txns {
                if failed_set.contains(&entry.hash) {
                    continue;
                }

                let parsed = match crate::transaction::parse_blob(&entry.blob) {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        *skipped_transactions = skipped_transactions.saturating_add(1);
                        continue;
                    }
                };

                let handler = transact::handler_for_type(parsed.tx_type);
                let result = transact::apply_transaction(
                    open,
                    &parsed,
                    &entry.hash,
                    handler.as_ref(),
                    flags,
                );

                if result.ter.is_success() || result.ter.claims_fee() {
                    if result.ter.is_success() {
                        *applied_transactions = applied_transactions.saturating_add(1);
                    } else {
                        *failed_transactions = failed_transactions.saturating_add(1);
                    }
                    open.raw_tx_insert(crate::ledger::Key(entry.hash), entry.blob.clone(), Vec::new());
                    changes = changes.saturating_add(1);
                } else if Self::is_permanent_failure(&result.ter) {
                    failed_set.insert(entry.hash);
                } else {
                    kept.push(entry);
                }
            }

            txns = kept;
            if changes == 0 && !certain_retry {
                break;
            }
            if changes == 0 || pass >= OPEN_LEDGER_RETRY_PASSES {
                certain_retry = false;
            }
        }

        *skipped_transactions = skipped_transactions.saturating_add(txns.len());
    }

    fn build_base_open_view(base: Arc<ClosedLedger>) -> OpenView {
        let base_info = base.info().clone();
        let mut open = OpenView::new(base.clone());
        open.info_mut().seq = base_info.seq.saturating_add(1);
        open.info_mut().parent_hash = base_info.hash;
        open.info_mut().hash = [0; 32];
        open.info_mut().tx_hash = [0; 32];
        open.info_mut().account_hash = base_info.account_hash;
        open.info_mut().close_time = base_info.close_time;
        open.info_mut().parent_close_time = base_info.close_time;
        open
    }

    fn build_live_candidate_from_sources(
        base: Arc<ClosedLedger>,
        current: &[OpenLedgerTx],
        locals: &[OpenLedgerTx],
        retries: &[OpenLedgerTx],
        retries_first: bool,
    ) -> (OpenView, usize, usize, usize) {
        let mut open = Self::build_base_open_view(base);
        let mut seen = std::collections::HashSet::new();
        let unique_retries = if retries_first {
            Self::dedup_transactions(retries, &mut seen)
        } else {
            Vec::new()
        };
        let unique_current = Self::dedup_transactions(current, &mut seen);
        let unique_locals = Self::dedup_transactions(locals, &mut seen);
        let salt = Self::canonical_salt(&[
            unique_retries.as_slice(),
            unique_current.as_slice(),
            unique_locals.as_slice(),
        ]);

        let mut applied_transactions = 0usize;
        let mut failed_transactions = 0usize;
        let mut skipped_transactions = 0usize;

        if retries_first {
            let (ordered_retries, retry_skipped) =
                Self::canonical_entries_from_transactions(&unique_retries, &salt);
            skipped_transactions = skipped_transactions.saturating_add(retry_skipped);
            Self::apply_canonical_entries(
                &mut open,
                ordered_retries,
                &mut applied_transactions,
                &mut failed_transactions,
                &mut skipped_transactions,
            );
        }

        let (ordered_current, current_skipped) =
            Self::canonical_entries_from_transactions(&unique_current, &salt);
        skipped_transactions = skipped_transactions.saturating_add(current_skipped);
        Self::apply_canonical_entries(
            &mut open,
            ordered_current,
            &mut applied_transactions,
            &mut failed_transactions,
            &mut skipped_transactions,
        );

        let (ordered_locals, local_skipped) =
            Self::canonical_entries_from_transactions(&unique_locals, &salt);
        skipped_transactions = skipped_transactions.saturating_add(local_skipped);
        Self::apply_canonical_entries(
            &mut open,
            ordered_locals,
            &mut applied_transactions,
            &mut failed_transactions,
            &mut skipped_transactions,
        );

        (open, applied_transactions, failed_transactions, skipped_transactions)
    }

    fn build_live_candidate(
        base: Arc<ClosedLedger>,
        pool: &TxPool,
    ) -> (OpenView, usize, usize, usize) {
        let locals = Self::pool_transactions(pool);
        Self::build_live_candidate_from_sources(base, &[], &locals, &[], false)
    }

    fn rebuild_live_view(&mut self, base: Arc<ClosedLedger>, pool: &TxPool) -> bool {
        let (open, applied_transactions, failed_transactions, skipped_transactions) =
            Self::build_live_candidate(base.clone(), pool);
        self.commit_live_view(
            base.as_ref(),
            open,
            applied_transactions,
            failed_transactions,
            skipped_transactions,
        )
    }

    pub fn empty(&self) -> bool {
        self.open_view
            .as_ref()
            .map(|open_view| open_view.tx_count() == 0)
            .unwrap_or(true)
    }

    pub fn current(&self) -> Option<OpenView> {
        self.current_view()
    }

    pub fn current_snapshot(&self) -> OpenLedgerSnapshot {
        self.snapshot()
    }

    pub fn current_view(&self) -> Option<OpenView> {
        self.open_view.clone()
    }

    pub fn current_transactions(&self) -> Vec<OpenLedgerTx> {
        self.open_view
            .as_ref()
            .map(|open_view| {
                open_view
                    .tx_blobs()
                    .into_iter()
                    .map(|(hash, blob)| OpenLedgerTx { hash: hash.0, blob })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn note_closed(
        &mut self,
        header: &crate::ledger::LedgerHeader,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
    ) {
        self.parent_ledger_index = header.sequence;
        self.parent_hash = header.hash;
        self.last_close_time = header.close_time;
        self.queued_transactions = queued_transactions;
        self.candidate_set_hash = candidate_set_hash;
        self.note_accept();
    }

    pub fn accept_closed_ledger(
        &mut self,
        header: &crate::ledger::LedgerHeader,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
        metrics: &FeeMetrics,
    ) -> bool {
        let same_closed_ledger = self.parent_ledger_index == header.sequence
            && self.parent_hash == header.hash
            && self.last_close_time == header.close_time;
        let queue_changed =
            self.apply_queue_state_without_note(queued_transactions, candidate_set_hash, metrics);
        self.parent_ledger_index = header.sequence;
        self.parent_hash = header.hash;
        self.last_close_time = header.close_time;
        if !same_closed_ledger {
            if queue_changed {
                self.note_mutation();
            }
            self.note_accept();
            return true;
        }
        if queue_changed {
            self.note_mutation();
        }
        queue_changed
    }

    pub fn modify<F>(&mut self, f: F) -> bool
    where
        F: FnOnce(&mut OpenView) -> bool,
    {
        let Some(mut next) = self.current_view() else {
            return false;
        };
        if !f(&mut next) {
            return false;
        }
        let changed = self.refresh_live_view_from_current(next);
        if changed {
            self.note_mutation();
        }
        changed
    }

    pub fn modify_queue_state(
        &mut self,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
        metrics: &FeeMetrics,
    ) -> bool {
        self.apply_queue_state(queued_transactions, candidate_set_hash, metrics)
    }

    pub fn note_queue_state(
        &mut self,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
        metrics: &FeeMetrics,
    ) {
        let _ = self.modify_queue_state(queued_transactions, candidate_set_hash, metrics);
    }

    pub fn sync_with_pool(
        &mut self,
        base: Arc<ClosedLedger>,
        pool: &TxPool,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
        metrics: &FeeMetrics,
    ) -> bool {
        self.base_ledger = Some(base.clone());
        let queue_changed =
            self.apply_queue_state_without_note(queued_transactions, candidate_set_hash, metrics);
        let view_changed = self.rebuild_live_view(base, pool);
        if queue_changed || view_changed {
            self.note_mutation();
        }
        queue_changed || view_changed
    }

    pub fn accept(
        &mut self,
        base: Arc<ClosedLedger>,
        header: &crate::ledger::LedgerHeader,
        pool: &TxPool,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
        metrics: &FeeMetrics,
    ) -> bool {
        self.accept_with_modify(
            base,
            header,
            pool,
            queued_transactions,
            candidate_set_hash,
            metrics,
            |_| false,
        )
    }

    pub fn accept_with_modify<F>(
        &mut self,
        base: Arc<ClosedLedger>,
        header: &crate::ledger::LedgerHeader,
        pool: &TxPool,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
        metrics: &FeeMetrics,
        f: F,
    ) -> bool
    where
        F: FnOnce(&mut OpenView) -> bool,
    {
        let locals = Self::pool_transactions(pool);
        self.accept_with_sources(
            base,
            header,
            &[],
            &locals,
            &[],
            false,
            queued_transactions,
            candidate_set_hash,
            metrics,
            f,
        )
    }

    pub fn accept_with_sources<F>(
        &mut self,
        base: Arc<ClosedLedger>,
        header: &crate::ledger::LedgerHeader,
        current: &[OpenLedgerTx],
        locals: &[OpenLedgerTx],
        retries: &[OpenLedgerTx],
        retries_first: bool,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
        metrics: &FeeMetrics,
        f: F,
    ) -> bool
    where
        F: FnOnce(&mut OpenView) -> bool,
    {
        let parent_changed =
            self.accept_closed_ledger(header, queued_transactions, candidate_set_hash, metrics);
        self.base_ledger = Some(base.clone());
        let (mut open, applied_transactions, failed_transactions, skipped_transactions) =
            Self::build_live_candidate_from_sources(base.clone(), current, locals, retries, retries_first);
        let modifier_changed = f(&mut open);
        let view_changed = self.commit_live_view(
            base.as_ref(),
            open,
            applied_transactions,
            failed_transactions,
            skipped_transactions,
        );
        if view_changed || modifier_changed {
            self.note_mutation();
        }
        parent_changed || view_changed || modifier_changed
    }

    pub fn snapshot(&self) -> OpenLedgerSnapshot {
        OpenLedgerSnapshot {
            ledger_current_index: self.parent_ledger_index.saturating_add(1),
            parent_ledger_index: self.parent_ledger_index,
            parent_hash: hex::encode_upper(self.parent_hash),
            last_close_time: self.last_close_time,
            queued_transactions: self.queued_transactions,
            candidate_set_hash: hex::encode_upper(self.candidate_set_hash),
            escalation_multiplier: self.escalation_multiplier,
            txns_expected: self.txns_expected,
            max_queue_size: self.max_queue_size,
            open_fee_level: self.open_fee_level,
            revision: self.revision,
            modify_count: self.modify_count,
            accept_count: self.accept_count,
            last_modified_unix: self.last_modified_unix,
            last_accept_unix: self.last_accept_unix,
            has_open_view: self.has_live_view(),
            open_view_base_ledger_index: self.open_view_base_ledger_index,
            open_view_applied_transactions: self.open_view_applied_transactions,
            open_view_failed_transactions: self.open_view_failed_transactions,
            open_view_skipped_transactions: self.open_view_skipped_transactions,
            open_view_tx_count: self.open_view_tx_count,
            open_view_state_hash: hex::encode_upper(self.open_view_state_hash),
            open_view_tx_hash: hex::encode_upper(self.open_view_tx_hash),
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn modify_count(&self) -> u64 {
        self.modify_count
    }

    pub fn accept_count(&self) -> u64 {
        self.accept_count
    }

    pub fn last_modified_unix(&self) -> u64 {
        self.last_modified_unix
    }

    pub fn last_accept_unix(&self) -> u64 {
        self.last_accept_unix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
    use crate::ledger::keylet;
    use crate::ledger::sle::{LedgerEntryType, SLE};
    use crate::ledger::views::RawView;
    use crate::transaction::{builder::TxBuilder, parse_blob, Amount};

    fn make_account_data(account_id: &[u8; 20], balance: u64, sequence: u32) -> Vec<u8> {
        let mut data = Vec::new();
        crate::ledger::meta::write_field_header(&mut data, 1, 1);
        data.extend_from_slice(&0x0061u16.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 2, 2);
        data.extend_from_slice(&0u32.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 2, 4);
        data.extend_from_slice(&sequence.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 2, 13);
        data.extend_from_slice(&0u32.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 6, 2);
        let balance_wire = balance | 0x4000_0000_0000_0000;
        data.extend_from_slice(&balance_wire.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 8, 1);
        crate::ledger::meta::encode_vl_length(&mut data, 20);
        data.extend_from_slice(account_id);
        data
    }

    fn setup_ledger_with_account(account_id: &[u8; 20], balance: u64) -> ClosedLedger {
        let mut ledger = ClosedLedger::genesis();
        let kl = keylet::account(account_id);
        let data = make_account_data(account_id, balance, 1);
        ledger.raw_insert(Arc::new(SLE::new(
            kl.key,
            LedgerEntryType::AccountRoot,
            data,
        )));
        ledger
    }

    fn genesis_kp() -> KeyPair {
        KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap(),
        )
    }

    #[test]
    fn open_ledger_tracks_parent_and_queue_state() {
        let mut open = OpenLedger::default();
        let header = crate::ledger::LedgerHeader {
            sequence: 77,
            hash: [0xAA; 32],
            parent_hash: [0xBB; 32],
            close_time: 1234,
            total_coins: 0,
            account_hash: [0; 32],
            transaction_hash: [0; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };
        open.note_closed(&header, 5, [0xCC; 32]);
        let metrics = FeeMetrics::default();
        open.note_queue_state(6, [0xDD; 32], &metrics);
        let snapshot = open.snapshot();
        assert_eq!(snapshot.parent_ledger_index, 77);
        assert_eq!(snapshot.ledger_current_index, 78);
        assert_eq!(snapshot.queued_transactions, 6);
        assert_eq!(snapshot.parent_hash, hex::encode_upper([0xAA; 32]));
        assert_eq!(snapshot.candidate_set_hash, hex::encode_upper([0xDD; 32]));
        assert_eq!(snapshot.escalation_multiplier, metrics.escalation_multiplier);
        assert_eq!(snapshot.txns_expected, metrics.txns_expected);
        assert_eq!(snapshot.max_queue_size, metrics.max_queue_size());
        assert_eq!(snapshot.open_fee_level, metrics.escalated_fee_level(7));
    }

    #[test]
    fn open_ledger_tracks_mutations_and_accepts() {
        let mut open = OpenLedger::default();
        let metrics = FeeMetrics::default();

        let _ = open.modify_queue_state(0, [0u8; 32], &metrics);
        let rev_after_initial = open.revision();
        let mod_after_initial = open.modify_count();

        assert!(!open.modify_queue_state(0, [0u8; 32], &metrics));
        assert_eq!(open.revision(), rev_after_initial);
        assert_eq!(open.modify_count(), mod_after_initial);

        assert!(open.modify_queue_state(2, [0xDD; 32], &metrics));
        assert!(open.revision() > rev_after_initial);
        assert!(open.modify_count() > mod_after_initial);

        assert_eq!(open.accept_count(), 0);
        open.note_closed(
            &crate::ledger::LedgerHeader {
                sequence: 78,
                hash: [0xAB; 32],
                parent_hash: [0xBC; 32],
                close_time: 5678,
                total_coins: 0,
                account_hash: [0; 32],
                transaction_hash: [0; 32],
                parent_close_time: 0,
                close_time_resolution: 10,
                close_flags: 0,
            },
            3,
            [0xEE; 32],
        );
        assert_eq!(open.accept_count(), 1);
        assert!(open.last_accept_unix() > 0);
        assert!(open.revision() > rev_after_initial);
        assert_eq!(open.current_snapshot().parent_ledger_index, 78);
    }

    #[test]
    fn open_ledger_accept_closed_ledger_rebases_state_atomically() {
        let mut open = OpenLedger::default();
        let metrics = FeeMetrics::default();
        let header = crate::ledger::LedgerHeader {
            sequence: 80,
            hash: [0xCC; 32],
            parent_hash: [0xDD; 32],
            close_time: 9012,
            total_coins: 0,
            account_hash: [0; 32],
            transaction_hash: [0; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };

        open.accept_closed_ledger(&header, 4, [0xEE; 32], &metrics);
        let first = open.snapshot();
        assert_eq!(first.parent_ledger_index, 80);
        assert_eq!(first.ledger_current_index, 81);
        assert_eq!(first.queued_transactions, 4);
        assert_eq!(first.candidate_set_hash, hex::encode_upper([0xEE; 32]));
        assert_eq!(first.accept_count, 1);
        assert_eq!(first.modify_count, 1);
        assert!(first.revision >= 2);
        assert!(first.last_modified_unix > 0);
        assert!(first.last_accept_unix > 0);

        let rev_after_first = open.revision();
        let mod_after_first = open.modify_count();
        let accept_after_first = open.accept_count();
        let modified = open.modify_queue_state(4, [0xEE; 32], &metrics);
        assert!(!modified);

        let next_header = crate::ledger::LedgerHeader {
            sequence: 81,
            hash: [0xAB; 32],
            parent_hash: [0xBC; 32],
            close_time: 9123,
            total_coins: 0,
            account_hash: [0; 32],
            transaction_hash: [0; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };
        open.accept_closed_ledger(&next_header, 4, [0xEE; 32], &metrics);
        assert!(open.revision() > rev_after_first);
        assert_eq!(open.modify_count(), mod_after_first);
        assert_eq!(open.accept_count(), accept_after_first + 1);
        assert_eq!(open.current_snapshot().parent_ledger_index, 81);
        assert_eq!(open.current_snapshot().ledger_current_index, 82);
    }

    #[test]
    fn open_ledger_duplicate_accept_is_idempotent_for_accept_count() {
        let mut open = OpenLedger::default();
        let metrics = FeeMetrics::default();
        let header = crate::ledger::LedgerHeader {
            sequence: 90,
            hash: [0x11; 32],
            parent_hash: [0x22; 32],
            close_time: 7777,
            total_coins: 0,
            account_hash: [0; 32],
            transaction_hash: [0; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };

        assert!(open.accept_closed_ledger(&header, 1, [0x33; 32], &metrics));
        let accept_after_first = open.accept_count();
        let revision_after_first = open.revision();
        let modified_after_first = open.modify_count();

        assert!(!open.accept_closed_ledger(&header, 1, [0x33; 32], &metrics));
        assert_eq!(open.accept_count(), accept_after_first);
        assert_eq!(open.revision(), revision_after_first);
        assert_eq!(open.modify_count(), modified_after_first);
        assert_eq!(open.current_snapshot().parent_ledger_index, 90);
        assert_eq!(open.current_snapshot().ledger_current_index, 91);
    }

    #[test]
    fn open_ledger_sync_with_pool_builds_live_open_view_candidate() {
        let alice = genesis_kp();
        let alice_id = crate::crypto::account_id(&alice.public_key_bytes());
        let bob_addr = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
        let bob_id = crate::crypto::base58::decode_account(bob_addr).unwrap();

        let mut base = setup_ledger_with_account(&alice_id, 100_000_000);
        let bob_kl = keylet::account(&bob_id);
        let bob_data = make_account_data(&bob_id, 50_000_000, 1);
        base.raw_insert(Arc::new(SLE::new(
            bob_kl.key,
            LedgerEntryType::AccountRoot,
            bob_data,
        )));
        base.info_mut().seq = 10;
        base.info_mut().hash = [0xAB; 32];
        base.info_mut().close_time = 1234;
        let base_state_hash = base.state_hash();
        let base = Arc::new(base);

        let signed = TxBuilder::payment()
            .account(&alice)
            .destination(bob_addr)
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(10)
            .sequence(1)
            .sign(&alice)
            .unwrap();
        let parsed = parse_blob(&signed.blob).unwrap();
        let mut pool = TxPool::default();
        assert!(pool.insert(signed.hash, signed.blob.clone(), &parsed));
        let metrics = pool.metrics.clone();

        let mut open = OpenLedger::default();
        assert!(open.sync_with_pool(
            base,
            &pool,
            pool.len(),
            pool.canonical_set_hash(),
            &metrics,
        ));

        let snapshot = open.snapshot();
        assert!(snapshot.has_open_view);
        assert_eq!(snapshot.open_view_base_ledger_index, 10);
        assert_eq!(snapshot.open_view_applied_transactions, 1);
        assert_eq!(snapshot.open_view_failed_transactions, 0);
        assert_eq!(snapshot.open_view_skipped_transactions, 0);
        assert_eq!(snapshot.open_view_tx_count, 1);
        assert_ne!(snapshot.open_view_state_hash, hex::encode_upper(base_state_hash));
        assert_ne!(snapshot.open_view_tx_hash, hex::encode_upper([0u8; 32]));
    }

    #[test]
    fn open_ledger_current_transactions_exposes_live_candidate_txs() {
        let alice = genesis_kp();
        let alice_id = crate::crypto::account_id(&alice.public_key_bytes());
        let bob_addr = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
        let bob_id = crate::crypto::base58::decode_account(bob_addr).unwrap();

        let mut base = setup_ledger_with_account(&alice_id, 100_000_000);
        let bob_kl = keylet::account(&bob_id);
        let bob_data = make_account_data(&bob_id, 50_000_000, 1);
        base.raw_insert(Arc::new(SLE::new(
            bob_kl.key,
            LedgerEntryType::AccountRoot,
            bob_data,
        )));
        base.info_mut().seq = 14;
        base.info_mut().hash = [0xAC; 32];
        let base = Arc::new(base);

        let signed = TxBuilder::payment()
            .account(&alice)
            .destination(bob_addr)
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(10)
            .sequence(1)
            .sign(&alice)
            .unwrap();
        let parsed = parse_blob(&signed.blob).unwrap();
        let mut pool = TxPool::default();
        assert!(pool.insert(signed.hash, signed.blob.clone(), &parsed));
        let metrics = pool.metrics.clone();

        let mut open = OpenLedger::default();
        assert!(open.sync_with_pool(
            base,
            &pool,
            pool.len(),
            pool.canonical_set_hash(),
            &metrics,
        ));

        let txs = open.current_transactions();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].hash, signed.hash);
        assert_eq!(txs[0].blob, signed.blob);
    }

    #[test]
    fn open_ledger_modify_updates_the_live_open_view() {
        let account = genesis_kp();
        let account_id = crate::crypto::account_id(&account.public_key_bytes());
        let mut base = setup_ledger_with_account(&account_id, 10_000_000);
        base.info_mut().seq = 22;
        base.info_mut().hash = [0xBC; 32];
        let base = Arc::new(base);
        let pool = TxPool::default();
        let metrics = FeeMetrics::default();
        let mut open = OpenLedger::default();

        assert!(open.sync_with_pool(base.clone(), &pool, 0, [0; 32], &metrics));
        let before = open.snapshot();

        let extra = [0x44; 20];
        let extra_keylet = keylet::account(&extra);
        let extra_data = make_account_data(&extra, 5_000_000, 1);
        assert!(open.modify(|view| {
            view.raw_insert(Arc::new(SLE::new(
                extra_keylet.key,
                LedgerEntryType::AccountRoot,
                extra_data.clone(),
            )));
            true
        }));

        let after = open.snapshot();
        assert!(after.has_open_view);
        assert_eq!(after.open_view_base_ledger_index, 22);
        assert_ne!(after.open_view_state_hash, before.open_view_state_hash);
        assert!(open.empty());
        assert!(open.current().is_some());
        assert!(open.current_view().is_some());
    }

    #[test]
    fn open_ledger_accept_with_modify_applies_atomic_open_view_changes() {
        let account = genesis_kp();
        let account_id = crate::crypto::account_id(&account.public_key_bytes());
        let mut base = setup_ledger_with_account(&account_id, 10_000_000);
        base.info_mut().seq = 25;
        base.info_mut().hash = [0xCD; 32];
        base.info_mut().close_time = 2222;
        let base = Arc::new(base);
        let pool = TxPool::default();
        let metrics = FeeMetrics::default();
        let header = crate::ledger::LedgerHeader {
            sequence: 25,
            hash: [0xCD; 32],
            parent_hash: [0xEF; 32],
            close_time: 2222,
            total_coins: 0,
            account_hash: [0; 32],
            transaction_hash: [0; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };
        let mut open = OpenLedger::default();
        let extra = [0x55; 20];
        let extra_keylet = keylet::account(&extra);
        let extra_data = make_account_data(&extra, 5_000_000, 1);

        assert!(open.accept_with_modify(
            base,
            &header,
            &pool,
            0,
            [0; 32],
            &metrics,
            |view| {
                view.raw_insert(Arc::new(SLE::new(
                    extra_keylet.key,
                    LedgerEntryType::AccountRoot,
                    extra_data.clone(),
                )));
                true
            },
        ));

        let snapshot = open.snapshot();
        assert!(snapshot.has_open_view);
        assert_eq!(snapshot.parent_ledger_index, 25);
        assert_eq!(snapshot.ledger_current_index, 26);
        assert_eq!(snapshot.accept_count, 1);
        assert!(snapshot.modify_count >= 1);
        assert!(open.current().is_some());
        assert!(open.empty());
    }

    #[test]
    fn open_ledger_accept_with_sources_applies_retries_before_locals() {
        let alice = genesis_kp();
        let alice_id = crate::crypto::account_id(&alice.public_key_bytes());
        let bob_addr = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
        let bob_id = crate::crypto::base58::decode_account(bob_addr).unwrap();

        let mut base = setup_ledger_with_account(&alice_id, 100_000_000);
        let bob_kl = keylet::account(&bob_id);
        let bob_data = make_account_data(&bob_id, 50_000_000, 1);
        base.raw_insert(Arc::new(SLE::new(
            bob_kl.key,
            LedgerEntryType::AccountRoot,
            bob_data,
        )));
        base.info_mut().seq = 26;
        base.info_mut().hash = [0xCE; 32];
        base.info_mut().close_time = 3333;
        let base = Arc::new(base);

        let signed_one = TxBuilder::payment()
            .account(&alice)
            .destination(bob_addr)
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(10)
            .sequence(1)
            .sign(&alice)
            .unwrap();
        let signed_two = TxBuilder::payment()
            .account(&alice)
            .destination(bob_addr)
            .unwrap()
            .amount(Amount::Xrp(2_000_000))
            .fee(10)
            .sequence(2)
            .sign(&alice)
            .unwrap();
        let metrics = FeeMetrics::default();
        let header = crate::ledger::LedgerHeader {
            sequence: 26,
            hash: [0xCE; 32],
            parent_hash: [0xEF; 32],
            close_time: 3333,
            total_coins: 0,
            account_hash: [0; 32],
            transaction_hash: [0; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };
        let retries = vec![OpenLedgerTx {
            hash: signed_one.hash,
            blob: signed_one.blob.clone(),
        }];
        let locals = vec![OpenLedgerTx {
            hash: signed_two.hash,
            blob: signed_two.blob.clone(),
        }];
        let mut open = OpenLedger::default();

        assert!(open.accept_with_sources(
            base,
            &header,
            &[],
            &locals,
            &retries,
            true,
            locals.len() + retries.len(),
            [0xDD; 32],
            &metrics,
            |_| false,
        ));

        let snapshot = open.snapshot();
        assert!(snapshot.has_open_view);
        assert_eq!(snapshot.parent_ledger_index, 26);
        assert_eq!(snapshot.open_view_applied_transactions, 2);
        assert_eq!(snapshot.open_view_failed_transactions, 0);
        assert_eq!(snapshot.open_view_skipped_transactions, 0);
        assert_eq!(snapshot.open_view_tx_count, 2);
        let current = open.current_transactions();
        assert_eq!(current.len(), 2);
    }
}
