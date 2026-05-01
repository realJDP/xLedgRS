//! xLedgRS purpose: Master support for transaction parsing and submission.
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_TRACKED_TXS: usize = 8192;
const TX_RETENTION_SECS: u64 = 60 * 60;

#[derive(Debug, Clone)]
pub struct TxMasterEntrySummary {
    pub hash: String,
    pub status: String,
    pub size: usize,
    pub first_seen_unix: u64,
    pub updated_unix: u64,
    pub source: String,
    pub ledger_seq: Option<u32>,
    pub result: Option<String>,
    pub relayed_count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct TxMasterSnapshot {
    pub tracked: usize,
    pub proposed_total: u64,
    pub submitted_total: u64,
    pub buffered_total: u64,
    pub accepted_total: u64,
    pub validated_total: u64,
    pub relayed_total: u64,
    pub entries: Vec<TxMasterEntrySummary>,
}

#[derive(Debug, Clone)]
struct TxMasterEntry {
    status: &'static str,
    size: usize,
    first_seen_unix: u64,
    updated_unix: u64,
    source: String,
    ledger_seq: Option<u32>,
    result: Option<String>,
    relayed_count: u32,
}

#[derive(Debug, Default)]
pub struct TransactionMaster {
    entries: HashMap<[u8; 32], TxMasterEntry>,
    order: VecDeque<[u8; 32]>,
    pub proposed_total: u64,
    pub submitted_total: u64,
    pub buffered_total: u64,
    pub accepted_total: u64,
    pub validated_total: u64,
    pub relayed_total: u64,
}

impl TransactionMaster {
    pub fn observe_proposed(
        &mut self,
        hash: [u8; 32],
        size: usize,
        source: impl Into<String>,
        now_unix: u64,
    ) {
        self.upsert(hash, size, source.into(), now_unix, "proposed", None, None);
        self.proposed_total = self.proposed_total.saturating_add(1);
    }

    pub fn observe_submitted(
        &mut self,
        hash: [u8; 32],
        size: usize,
        source: impl Into<String>,
        now_unix: u64,
    ) {
        self.upsert(hash, size, source.into(), now_unix, "submitted", None, None);
        self.submitted_total = self.submitted_total.saturating_add(1);
    }

    pub fn observe_buffered(
        &mut self,
        hash: [u8; 32],
        size: usize,
        source: impl Into<String>,
        ledger_seq: u32,
        now_unix: u64,
    ) {
        self.upsert(
            hash,
            size,
            source.into(),
            now_unix,
            "buffered",
            Some(ledger_seq),
            Some("pending".to_string()),
        );
        self.buffered_total = self.buffered_total.saturating_add(1);
    }

    pub fn observe_accepted(&mut self, record: &crate::ledger::history::TxRecord, now_unix: u64) {
        self.upsert(
            record.hash,
            record.blob.len(),
            "consensus_close".to_string(),
            now_unix,
            "accepted",
            Some(record.ledger_seq),
            Some(record.result.clone()),
        );
        self.accepted_total = self.accepted_total.saturating_add(1);
    }

    pub fn observe_validated(&mut self, record: &crate::ledger::history::TxRecord, now_unix: u64) {
        self.upsert(
            record.hash,
            record.blob.len(),
            "validated".to_string(),
            now_unix,
            "validated",
            Some(record.ledger_seq),
            Some(record.result.clone()),
        );
        self.validated_total = self.validated_total.saturating_add(1);
    }

    pub fn note_relayed(&mut self, hash: &[u8; 32], now_unix: u64) {
        if let Some(entry) = self.entries.get_mut(hash) {
            entry.relayed_count = entry.relayed_count.saturating_add(1);
            entry.updated_unix = now_unix;
            self.relayed_total = self.relayed_total.saturating_add(1);
        }
    }

    pub fn prune(&mut self, now_unix: u64) {
        while self.entries.len() > MAX_TRACKED_TXS {
            if let Some(hash) = self.order.pop_front() {
                self.entries.remove(&hash);
            }
        }
        while let Some(hash) = self.order.front().copied() {
            let remove = self
                .entries
                .get(&hash)
                .map(|entry| now_unix.saturating_sub(entry.updated_unix) > TX_RETENTION_SECS)
                .unwrap_or(true);
            if !remove {
                break;
            }
            self.order.pop_front();
            self.entries.remove(&hash);
        }
    }

    pub fn snapshot(&self, limit: usize) -> TxMasterSnapshot {
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .map(|(hash, entry)| TxMasterEntrySummary {
                hash: hex::encode_upper(hash),
                status: entry.status.to_string(),
                size: entry.size,
                first_seen_unix: entry.first_seen_unix,
                updated_unix: entry.updated_unix,
                source: entry.source.clone(),
                ledger_seq: entry.ledger_seq,
                result: entry.result.clone(),
                relayed_count: entry.relayed_count,
            })
            .collect();
        entries.sort_by(|a, b| {
            b.updated_unix
                .cmp(&a.updated_unix)
                .then_with(|| a.hash.cmp(&b.hash))
        });
        entries.truncate(limit);
        TxMasterSnapshot {
            tracked: self.entries.len(),
            proposed_total: self.proposed_total,
            submitted_total: self.submitted_total,
            buffered_total: self.buffered_total,
            accepted_total: self.accepted_total,
            validated_total: self.validated_total,
            relayed_total: self.relayed_total,
            entries,
        }
    }

    fn upsert(
        &mut self,
        hash: [u8; 32],
        size: usize,
        source: String,
        now_unix: u64,
        status: &'static str,
        ledger_seq: Option<u32>,
        result: Option<String>,
    ) {
        match self.entries.get_mut(&hash) {
            Some(entry) => {
                entry.status = status;
                entry.size = size;
                entry.updated_unix = now_unix;
                entry.source = source;
                entry.ledger_seq = ledger_seq.or(entry.ledger_seq);
                if result.is_some() {
                    entry.result = result;
                }
            }
            None => {
                self.entries.insert(
                    hash,
                    TxMasterEntry {
                        status,
                        size,
                        first_seen_unix: now_unix,
                        updated_unix: now_unix,
                        source,
                        ledger_seq,
                        result,
                        relayed_count: 0,
                    },
                );
                self.order.push_back(hash);
            }
        }
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx_record(
        hash: [u8; 32],
        ledger_seq: u32,
        result: &str,
    ) -> crate::ledger::history::TxRecord {
        crate::ledger::history::TxRecord {
            blob: vec![1, 2, 3],
            meta: vec![],
            hash,
            ledger_seq,
            tx_index: 0,
            result: result.to_string(),
        }
    }

    #[test]
    fn tracks_lifecycle_progression() {
        let mut master = TransactionMaster::default();
        let hash = [0x11; 32];
        master.observe_proposed(hash, 120, "peer:1", 10);
        master.note_relayed(&hash, 11);
        master.observe_buffered(hash, 120, "history", 22, 12);
        master.observe_accepted(&tx_record(hash, 22, "tesSUCCESS"), 13);
        master.observe_validated(&tx_record(hash, 22, "tesSUCCESS"), 14);
        let snapshot = master.snapshot(4);
        assert_eq!(snapshot.proposed_total, 1);
        assert_eq!(snapshot.accepted_total, 1);
        assert_eq!(snapshot.validated_total, 1);
        assert_eq!(snapshot.entries[0].status, "validated");
        assert_eq!(snapshot.entries[0].ledger_seq, Some(22));
        assert_eq!(snapshot.entries[0].relayed_count, 1);
    }

    #[test]
    fn tracks_local_submit_and_relay() {
        let mut master = TransactionMaster::default();
        let hash = [0x22; 32];
        master.observe_submitted(hash, 88, "rpc_submit", 100);
        master.note_relayed(&hash, 101);
        let snapshot = master.snapshot(4);
        assert_eq!(snapshot.submitted_total, 1);
        assert_eq!(snapshot.relayed_total, 1);
        assert_eq!(snapshot.entries[0].status, "submitted");
        assert_eq!(snapshot.entries[0].source, "rpc_submit");
        assert_eq!(snapshot.entries[0].relayed_count, 1);
    }
}
