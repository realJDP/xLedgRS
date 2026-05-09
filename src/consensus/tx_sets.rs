//! Immutable consensus transaction-set cache.
//!
//! The open [`TxPool`](crate::ledger::pool::TxPool) is a mutable mempool. Consensus
//! needs immutable candidate sets keyed by their canonical tx-set root so that an
//! accepted hash can be closed exactly, even if the live pool changes meanwhile.

use std::collections::{hash_map::Entry, HashMap};
use std::sync::Arc;

use crate::ledger::pool::{canonical_set_hash_from_blobs, PoolEntry, PoolTxInfo, TxPool};
use crate::transaction::{parse_blob, serialize::tx_blob_hash};

/// One transaction inside an immutable consensus candidate set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateTx {
    pub id: [u8; 32],
    pub blob: Vec<u8>,
    pub parsed: PoolTxInfo,
}

impl CandidateTx {
    fn from_pool_entry(entry: &PoolEntry) -> Self {
        Self {
            id: entry.hash,
            blob: entry.blob.clone(),
            parsed: entry.parsed.clone(),
        }
    }

    fn from_blob(blob: Vec<u8>) -> Result<Self, TxSetImportError> {
        let parsed = parse_blob(&blob).map_err(|_| TxSetImportError::MalformedTransaction)?;
        Ok(Self {
            id: tx_blob_hash(&blob),
            blob,
            parsed: PoolTxInfo {
                account: parsed.account,
                sequence: parsed.sequence,
                fee: parsed.fee,
            },
        })
    }

    fn to_pool_entry(&self) -> PoolEntry {
        PoolEntry {
            hash: self.id,
            blob: self.blob.clone(),
            parsed: self.parsed.clone(),
        }
    }
}

/// Immutable transaction candidate proposed or acquired during consensus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusTxSet {
    hash: [u8; 32],
    txs: Box<[CandidateTx]>,
}

impl ConsensusTxSet {
    /// Snapshot the current local pool into an immutable candidate set.
    pub fn from_pool_snapshot(pool: &TxPool) -> Self {
        Self::from_pool_entries(pool.snapshot_entries())
    }

    /// Build an acquired peer candidate from raw transaction blobs.
    pub fn from_blobs(blobs: impl IntoIterator<Item = Vec<u8>>) -> Result<Self, TxSetImportError> {
        let mut txs = Vec::new();
        for blob in blobs {
            txs.push(CandidateTx::from_blob(blob)?);
        }
        Ok(Self::from_candidate_txs(txs))
    }

    fn from_pool_entries(entries: Vec<PoolEntry>) -> Self {
        Self::from_candidate_txs(entries.iter().map(CandidateTx::from_pool_entry).collect())
    }

    fn from_candidate_txs(mut txs: Vec<CandidateTx>) -> Self {
        txs.sort_by(|a, b| a.id.cmp(&b.id));
        txs.dedup_by(|a, b| a.id == b.id);
        let hash = canonical_set_hash_from_blobs(txs.iter().map(|tx| tx.blob.as_slice()));
        Self {
            hash,
            txs: txs.into_boxed_slice(),
        }
    }

    /// Canonical tx-set root hash.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn transactions(&self) -> &[CandidateTx] {
        &self.txs
    }

    pub fn tx_ids(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.txs.iter().map(|tx| tx.id)
    }

    pub fn contains_tx_id(&self, tx_id: &[u8; 32]) -> bool {
        self.txs.binary_search_by(|tx| tx.id.cmp(tx_id)).is_ok()
    }

    /// Clone entries in exact candidate-set membership for ledger close.
    pub fn to_pool_entries(&self) -> Vec<PoolEntry> {
        self.txs.iter().map(CandidateTx::to_pool_entry).collect()
    }

    /// Compare two candidate sets by transaction ID only.
    pub fn diff_by_tx_id(&self, other: &Self) -> TxSetDiff {
        let mut only_self = Vec::new();
        let mut only_other = Vec::new();
        let mut left = 0usize;
        let mut right = 0usize;

        while left < self.txs.len() && right < other.txs.len() {
            match self.txs[left].id.cmp(&other.txs[right].id) {
                std::cmp::Ordering::Less => {
                    only_self.push(self.txs[left].id);
                    left += 1;
                }
                std::cmp::Ordering::Greater => {
                    only_other.push(other.txs[right].id);
                    right += 1;
                }
                std::cmp::Ordering::Equal => {
                    left += 1;
                    right += 1;
                }
            }
        }

        only_self.extend(self.txs[left..].iter().map(|tx| tx.id));
        only_other.extend(other.txs[right..].iter().map(|tx| tx.id));
        TxSetDiff {
            only_self,
            only_other,
        }
    }
}

/// Difference between two candidate sets by transaction ID.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxSetDiff {
    pub only_self: Vec<[u8; 32]>,
    pub only_other: Vec<[u8; 32]>,
}

impl TxSetDiff {
    pub fn is_empty(&self) -> bool {
        self.only_self.is_empty() && self.only_other.is_empty()
    }
}

enum TxSetState {
    Acquiring,
    Complete(Arc<ConsensusTxSet>),
}

/// TransactionAcquire-like cache keyed by canonical tx-set hash.
#[derive(Default)]
pub struct ConsensusTxSets {
    sets: HashMap<[u8; 32], TxSetState>,
}

impl ConsensusTxSets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register interest in a set hash before the blobs have arrived.
    pub fn expect(&mut self, hash: [u8; 32]) {
        self.sets.entry(hash).or_insert(TxSetState::Acquiring);
    }

    /// Store an immutable local-pool snapshot and return its cache entry.
    pub fn insert_local_pool_snapshot(&mut self, pool: &TxPool) -> Arc<ConsensusTxSet> {
        self.insert_complete(ConsensusTxSet::from_pool_snapshot(pool))
    }

    /// Import a fully acquired peer candidate and validate its root hash.
    pub fn import_acquired(
        &mut self,
        expected_hash: [u8; 32],
        blobs: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<Arc<ConsensusTxSet>, TxSetImportError> {
        let set = ConsensusTxSet::from_blobs(blobs)?;
        if set.hash() != expected_hash {
            return Err(TxSetImportError::HashMismatch {
                expected: expected_hash,
                actual: set.hash(),
            });
        }
        Ok(self.insert_complete(set))
    }

    fn insert_complete(&mut self, set: ConsensusTxSet) -> Arc<ConsensusTxSet> {
        let hash = set.hash();
        match self.sets.entry(hash) {
            Entry::Occupied(mut occupied) => match occupied.get() {
                TxSetState::Complete(existing) => existing.clone(),
                TxSetState::Acquiring => {
                    let set = Arc::new(set);
                    occupied.insert(TxSetState::Complete(set.clone()));
                    set
                }
            },
            Entry::Vacant(vacant) => {
                let set = Arc::new(set);
                vacant.insert(TxSetState::Complete(set.clone()));
                set
            }
        }
    }

    pub fn is_complete(&self, hash: &[u8; 32]) -> bool {
        matches!(self.sets.get(hash), Some(TxSetState::Complete(_)))
    }

    pub fn root_hash(&self, hash: &[u8; 32]) -> Option<[u8; 32]> {
        self.get(hash).map(|set| set.hash())
    }

    pub fn get(&self, hash: &[u8; 32]) -> Option<Arc<ConsensusTxSet>> {
        match self.sets.get(hash) {
            Some(TxSetState::Complete(set)) => Some(set.clone()),
            _ => None,
        }
    }

    /// Retrieve the exact accepted candidate entries for close.
    pub fn accepted_pool_entries(&self, hash: &[u8; 32]) -> Option<Vec<PoolEntry>> {
        self.get(hash).map(|set| set.to_pool_entries())
    }

    /// Compare two completed cached candidates by transaction ID.
    pub fn diff_by_hashes(&self, left: &[u8; 32], right: &[u8; 32]) -> Option<TxSetDiff> {
        let left = self.get(left)?;
        let right = self.get(right)?;
        Some(left.diff_by_tx_id(&right))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxSetImportError {
    MalformedTransaction,
    HashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
    use crate::transaction::{builder::TxBuilder, parse_blob, Amount};

    fn genesis_kp() -> KeyPair {
        KeyPair::Secp256k1(Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap())
    }

    fn make_signed_tx(seq: u32) -> (Vec<u8>, [u8; 32]) {
        let kp = genesis_kp();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(seq)
            .sign(&kp)
            .unwrap();
        (signed.blob, signed.hash)
    }

    fn insert_tx(pool: &mut TxPool, seq: u32) -> (Vec<u8>, [u8; 32]) {
        let (blob, hash) = make_signed_tx(seq);
        let parsed = parse_blob(&blob).unwrap();
        assert!(pool.insert(hash, blob.clone(), &parsed));
        (blob, hash)
    }

    #[test]
    fn candidate_set_hash_identity_matches_pool_and_peer_import() {
        let mut pool = TxPool::new();
        let (blob1, _) = insert_tx(&mut pool, 1);
        let (blob2, _) = insert_tx(&mut pool, 2);

        let mut cache = ConsensusTxSets::new();
        let local = cache.insert_local_pool_snapshot(&pool);
        assert_eq!(local.hash(), pool.canonical_set_hash());

        let peer = cache
            .import_acquired(local.hash(), vec![blob2, blob1])
            .expect("peer candidate should hash to same root");
        assert_eq!(peer.hash(), local.hash());
        assert!(cache.is_complete(&local.hash()));
        assert_eq!(cache.root_hash(&local.hash()), Some(local.hash()));
    }

    #[test]
    fn accepted_retrieval_is_immutable_after_pool_mutation() {
        let mut pool = TxPool::new();
        let (_, hash1) = insert_tx(&mut pool, 1);

        let mut cache = ConsensusTxSets::new();
        let accepted_hash = cache.insert_local_pool_snapshot(&pool).hash();

        insert_tx(&mut pool, 2);
        assert_ne!(pool.canonical_set_hash(), accepted_hash);

        let accepted = cache
            .accepted_pool_entries(&accepted_hash)
            .expect("accepted set should remain cached");
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].hash, hash1);
    }

    #[test]
    fn acquired_candidate_does_not_conflate_with_tx_pool() {
        let mut local_pool = TxPool::new();
        insert_tx(&mut local_pool, 1);

        let (peer_blob, peer_hash) = make_signed_tx(7);
        let expected = canonical_set_hash_from_blobs([peer_blob.as_slice()]);

        let mut cache = ConsensusTxSets::new();
        let peer = cache
            .import_acquired(expected, vec![peer_blob])
            .expect("peer set should import");

        assert_eq!(local_pool.len(), 1);
        assert!(!local_pool.peek_hashes().contains(&peer_hash));
        assert_eq!(peer.tx_ids().collect::<Vec<_>>(), vec![peer_hash]);
    }

    #[test]
    fn candidate_sets_compare_by_tx_id_for_disputes() {
        let mut local_pool = TxPool::new();
        let (_, shared) = insert_tx(&mut local_pool, 1);
        let (_, local_only) = insert_tx(&mut local_pool, 2);
        let local = ConsensusTxSet::from_pool_snapshot(&local_pool);

        let (peer_blob_shared, _) = make_signed_tx(1);
        let (peer_blob_only, peer_only) = make_signed_tx(3);
        let peer = ConsensusTxSet::from_blobs(vec![peer_blob_only, peer_blob_shared]).unwrap();

        let diff = local.diff_by_tx_id(&peer);
        assert_eq!(diff.only_self, vec![local_only]);
        assert_eq!(diff.only_other, vec![peer_only]);
        assert!(local.contains_tx_id(&shared));
    }

    #[test]
    fn cache_compares_completed_sets_by_hash() {
        let mut local_pool = TxPool::new();
        let (_, local_only) = insert_tx(&mut local_pool, 2);

        let (peer_blob, peer_only) = make_signed_tx(3);
        let peer_hash = canonical_set_hash_from_blobs([peer_blob.as_slice()]);

        let mut cache = ConsensusTxSets::new();
        let local_hash = cache.insert_local_pool_snapshot(&local_pool).hash();
        cache.import_acquired(peer_hash, vec![peer_blob]).unwrap();

        let diff = cache
            .diff_by_hashes(&local_hash, &peer_hash)
            .expect("both candidate sets should be complete");
        assert_eq!(diff.only_self, vec![local_only]);
        assert_eq!(diff.only_other, vec![peer_only]);
    }

    #[test]
    fn expected_hash_mismatch_stays_incomplete() {
        let (blob, _) = make_signed_tx(1);
        let mut cache = ConsensusTxSets::new();
        let expected = [9u8; 32];
        cache.expect(expected);

        let err = cache.import_acquired(expected, vec![blob]).unwrap_err();
        assert!(matches!(err, TxSetImportError::HashMismatch { .. }));
        assert!(!cache.is_complete(&expected));
        assert!(cache.get(&expected).is_none());
    }
}
