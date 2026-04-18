use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_TRACKED_TRANSACTIONS: usize = 4096;
const TRACK_RETENTION_SECS: u64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct InboundTransactionSummary {
    pub hash: String,
    pub size: usize,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub first_source: String,
    pub last_source: String,
    pub seen_count: u32,
    pub relayed_count: u32,
    pub persisted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct InboundTransactionsSnapshot {
    pub tracked: usize,
    pub accepted_total: u64,
    pub duplicate_total: u64,
    pub relayed_total: u64,
    pub persisted_total: u64,
    pub entries: Vec<InboundTransactionSummary>,
}

#[derive(Debug, Clone)]
struct InboundTransactionEntry {
    size: usize,
    first_seen_unix: u64,
    last_seen_unix: u64,
    first_source: String,
    last_source: String,
    seen_count: u32,
    relayed_count: u32,
    persisted: bool,
}

#[derive(Debug, Default)]
pub struct InboundTransactions {
    entries: HashMap<[u8; 32], InboundTransactionEntry>,
    order: VecDeque<[u8; 32]>,
    accepted_total: u64,
    duplicate_total: u64,
    relayed_total: u64,
    persisted_total: u64,
}

impl InboundTransactions {
    pub fn observe(
        &mut self,
        hash: [u8; 32],
        size: usize,
        source: impl Into<String>,
        now_unix: u64,
    ) -> bool {
        let source = source.into();
        match self.entries.get_mut(&hash) {
            Some(entry) => {
                entry.last_seen_unix = now_unix;
                entry.last_source = source;
                entry.seen_count = entry.seen_count.saturating_add(1);
                self.duplicate_total = self.duplicate_total.saturating_add(1);
                false
            }
            None => {
                self.accepted_total = self.accepted_total.saturating_add(1);
                self.entries.insert(
                    hash,
                    InboundTransactionEntry {
                        size,
                        first_seen_unix: now_unix,
                        last_seen_unix: now_unix,
                        first_source: source.clone(),
                        last_source: source,
                        seen_count: 1,
                        relayed_count: 0,
                        persisted: false,
                    },
                );
                self.order.push_back(hash);
                self.trim(now_unix);
                true
            }
        }
    }

    pub fn note_relayed(&mut self, hash: &[u8; 32]) {
        if let Some(entry) = self.entries.get_mut(hash) {
            entry.relayed_count = entry.relayed_count.saturating_add(1);
            self.relayed_total = self.relayed_total.saturating_add(1);
        }
    }

    pub fn note_persisted(&mut self, hash: &[u8; 32]) {
        if let Some(entry) = self.entries.get_mut(hash) {
            if !entry.persisted {
                entry.persisted = true;
                self.persisted_total = self.persisted_total.saturating_add(1);
            }
        }
    }

    pub fn prune(&mut self, now_unix: u64) {
        self.trim(now_unix);
    }

    pub fn snapshot(&self, limit: usize) -> InboundTransactionsSnapshot {
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .map(|(hash, entry)| InboundTransactionSummary {
                hash: hex::encode_upper(hash),
                size: entry.size,
                first_seen_unix: entry.first_seen_unix,
                last_seen_unix: entry.last_seen_unix,
                first_source: entry.first_source.clone(),
                last_source: entry.last_source.clone(),
                seen_count: entry.seen_count,
                relayed_count: entry.relayed_count,
                persisted: entry.persisted,
            })
            .collect();
        entries.sort_by(|a, b| {
            b.last_seen_unix
                .cmp(&a.last_seen_unix)
                .then_with(|| a.hash.cmp(&b.hash))
        });
        entries.truncate(limit);
        InboundTransactionsSnapshot {
            tracked: self.entries.len(),
            accepted_total: self.accepted_total,
            duplicate_total: self.duplicate_total,
            relayed_total: self.relayed_total,
            persisted_total: self.persisted_total,
            entries,
        }
    }

    fn trim(&mut self, now_unix: u64) {
        while self.entries.len() > MAX_TRACKED_TRANSACTIONS {
            if let Some(hash) = self.order.pop_front() {
                self.entries.remove(&hash);
            }
        }
        while let Some(oldest) = self.order.front().copied() {
            let remove = self
                .entries
                .get(&oldest)
                .map(|entry| now_unix.saturating_sub(entry.last_seen_unix) > TRACK_RETENTION_SECS)
                .unwrap_or(true);
            if !remove {
                break;
            }
            self.order.pop_front();
            self.entries.remove(&oldest);
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

    #[test]
    fn observe_counts_new_and_duplicate_transactions() {
        let mut inbound = InboundTransactions::default();
        let hash = [0x11; 32];
        assert!(inbound.observe(hash, 128, "peer:1", 100));
        assert!(!inbound.observe(hash, 128, "peer:2", 101));

        let snapshot = inbound.snapshot(4);
        assert_eq!(snapshot.accepted_total, 1);
        assert_eq!(snapshot.duplicate_total, 1);
        assert_eq!(snapshot.entries[0].first_source, "peer:1");
        assert_eq!(snapshot.entries[0].last_source, "peer:2");
        assert_eq!(snapshot.entries[0].seen_count, 2);
    }

    #[test]
    fn note_relayed_and_persisted_are_tracked() {
        let mut inbound = InboundTransactions::default();
        let hash = [0x22; 32];
        inbound.observe(hash, 64, "peer:1", 200);
        inbound.note_relayed(&hash);
        inbound.note_persisted(&hash);
        inbound.note_persisted(&hash);
        let snapshot = inbound.snapshot(4);
        assert_eq!(snapshot.relayed_total, 1);
        assert_eq!(snapshot.persisted_total, 1);
        assert!(snapshot.entries[0].persisted);
        assert_eq!(snapshot.entries[0].relayed_count, 1);
    }
}
