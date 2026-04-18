//! Validated-ledger bookkeeping and recent validation history.

use std::collections::{HashMap, VecDeque};

const RECENT_VALIDATED_CAPACITY: usize = 256;

#[derive(Debug, Clone)]
pub struct RecentValidatedLedger {
    pub seq: u32,
    pub hash: String,
}

#[derive(Debug, Clone, Default)]
pub struct LedgerMasterSnapshot {
    pub validated_seq: u32,
    pub validated_hash: String,
    pub open_ledger_seq: u32,
    pub complete_ledgers: String,
    pub last_close_time: u64,
    pub queued_transactions: usize,
    pub candidate_set_hash: String,
    pub recent_validated: Vec<RecentValidatedLedger>,
}

#[derive(Debug, Default)]
pub struct LedgerMaster {
    validated_seq: u32,
    validated_hash: [u8; 32],
    last_close_time: u64,
    complete_ledgers: String,
    queued_transactions: usize,
    candidate_set_hash: [u8; 32],
    validated_hashes: HashMap<u32, [u8; 32]>,
    validated_order: VecDeque<u32>,
}

impl LedgerMaster {
    pub fn note_closed(
        &mut self,
        header: &crate::ledger::LedgerHeader,
        complete_ledgers: String,
        queued_transactions: usize,
        candidate_set_hash: [u8; 32],
    ) {
        self.validated_seq = header.sequence;
        self.validated_hash = header.hash;
        self.last_close_time = header.close_time;
        self.complete_ledgers = complete_ledgers;
        self.queued_transactions = queued_transactions;
        self.candidate_set_hash = candidate_set_hash;
    }

    pub fn note_validated_head(&mut self, seq: u32, hash: [u8; 32]) {
        if seq >= self.validated_seq {
            self.validated_seq = seq;
            self.validated_hash = hash;
        }
    }

    pub fn record_validated_hash(&mut self, seq: u32, hash: [u8; 32]) {
        self.note_validated_head(seq, hash);
        if !self.validated_hashes.contains_key(&seq) {
            self.validated_order.push_back(seq);
            while self.validated_order.len() > RECENT_VALIDATED_CAPACITY {
                if let Some(oldest) = self.validated_order.pop_front() {
                    self.validated_hashes.remove(&oldest);
                }
            }
        }
        self.validated_hashes.insert(seq, hash);
    }

    pub fn hash_for_seq(&self, seq: u32) -> Option<[u8; 32]> {
        self.validated_hashes.get(&seq).copied()
    }

    pub fn snapshot(&self) -> LedgerMasterSnapshot {
        let mut recent_validated: Vec<_> = self
            .validated_order
            .iter()
            .rev()
            .filter_map(|seq| {
                self.validated_hashes
                    .get(seq)
                    .map(|hash| RecentValidatedLedger {
                        seq: *seq,
                        hash: hex::encode_upper(hash),
                    })
            })
            .collect();
        recent_validated.truncate(16);
        LedgerMasterSnapshot {
            validated_seq: self.validated_seq,
            validated_hash: hex::encode_upper(self.validated_hash),
            open_ledger_seq: self.validated_seq.saturating_add(1),
            complete_ledgers: self.complete_ledgers.clone(),
            last_close_time: self.last_close_time,
            queued_transactions: self.queued_transactions,
            candidate_set_hash: hex::encode_upper(self.candidate_set_hash),
            recent_validated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_recent_validated_hashes() {
        let mut master = LedgerMaster::default();
        let header = crate::ledger::LedgerHeader {
            sequence: 22,
            hash: [0xAB; 32],
            parent_hash: [0; 32],
            close_time: 33,
            total_coins: 0,
            account_hash: [0; 32],
            transaction_hash: [0; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };
        master.note_closed(&header, "1-22".into(), 7, [0xCC; 32]);
        master.record_validated_hash(22, [0xAB; 32]);
        let snapshot = master.snapshot();
        assert_eq!(snapshot.validated_seq, 22);
        assert_eq!(snapshot.open_ledger_seq, 23);
        assert_eq!(snapshot.complete_ledgers, "1-22");
        assert_eq!(snapshot.queued_transactions, 7);
        assert_eq!(snapshot.recent_validated[0].seq, 22);
        assert_eq!(master.hash_for_seq(22), Some([0xAB; 32]));
    }
}
