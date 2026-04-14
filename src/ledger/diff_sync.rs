//! SHAMap differential sync — follow new validated ledgers by downloading
//! only the changed nodes from peers.
//!
//! For each new ledger:
//! 1. Compare new root inner node against previous root
//! 2. Unchanged subtrees (same hash) are skipped entirely
//! 3. Changed subtrees are walked, downloading new inner nodes and leaves
//! 4. Deleted branches are detected and leaf keys enumerated
//! 5. Changed leaves + deletions applied to SparseSHAMap + storage
//! 6. Root hash verified against network's account_hash
//!
//! Typically completes in 1-3 peer round trips (~200 changed objects per ledger).

use crate::sync::{StateSyncer, DiffDeletion};

/// Result of applying one ledger via differential sync.
pub struct DiffResult {
    /// New/changed leaves: (32-byte key, STObject data).
    pub changed_leaves: Vec<([u8; 32], Vec<u8>)>,
    /// Deleted leaf keys.
    pub deleted_keys: Vec<[u8; 32]>,
    /// True if sync completed for this ledger.
    pub complete: bool,
    /// Number of inner nodes downloaded.
    pub inner_count: usize,
    /// Number of leaf nodes downloaded.
    pub leaf_count: usize,
}

/// Manages differential sync state across ledgers.
pub struct DiffSyncer {
    syncer: StateSyncer,
    /// Accumulated deletions for the current ledger.
    pending_deletions: Vec<DiffDeletion>,
    /// Accumulated changed leaves for the current ledger.
    pending_leaves: Vec<([u8; 32], Vec<u8>)>,
    /// Inner/leaf counts for the current ledger diff.
    diff_inner: usize,
    diff_leaf: usize,
}

impl DiffSyncer {
    /// Create a new DiffSyncer with an existing StateSyncer (from initial sync or loaded from storage).
    pub fn new(syncer: StateSyncer) -> Self {
        Self {
            syncer,
            pending_deletions: Vec::new(),
            pending_leaves: Vec::new(),
            diff_inner: 0,
            diff_leaf: 0,
        }
    }

    /// Create a DiffSyncer with an empty StateSyncer for a given ledger.
    /// The first diff sync will download the entire inner node tree.
    pub fn new_empty(seq: u32, hash: [u8; 32], account_hash: [u8; 32]) -> Self {
        Self::new(StateSyncer::new(seq, hash, account_hash, None))
    }

    /// Start differential sync for a new ledger.
    /// Compares the new root against the old, marks unchanged subtrees,
    /// and prepares to download only the changed parts.
    ///
    /// `new_root_data` is the raw inner node data for the new state tree root
    /// (512 bytes for full, or compressed format).
    pub fn start_diff(
        &mut self,
        new_root_data: &[u8],
        new_ledger_hash: [u8; 32],
        new_account_hash: [u8; 32],
        new_seq: u32,
    ) -> Vec<DiffDeletion> {
        // Reset per-ledger state
        self.pending_deletions.clear();
        self.pending_leaves.clear();
        self.diff_inner = 0;
        self.diff_leaf = 0;

        // Update root and detect unchanged/deleted branches
        let root_deletions = self.syncer.update_root_for_diff(
            new_root_data,
            new_ledger_hash,
            new_account_hash,
            new_seq,
        );
        self.pending_deletions.extend(
            root_deletions.iter().map(|(branch, _)| DiffDeletion {
                parent_nid: [0u8; 33], // root
                branch: *branch,
            })
        );
        self.pending_deletions.clone()
    }

    /// Process a TMLedgerData response from a peer.
    pub fn process_response(&mut self, ld: &crate::proto::TmLedgerData) -> usize {
        let progress = self.syncer.process_response(ld);
        self.diff_inner += progress.inner_received;
        self.diff_leaf += progress.leaf_received;

        // Collect changed leaves
        for (key, data) in progress.leaves {
            if key.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key);
                self.pending_leaves.push((k, data));
            }
        }

        // Collect deletions discovered in inner nodes
        self.pending_deletions.extend(progress.diff_deletions);

        progress.inner_received + progress.leaf_received
    }

    /// Build the next batch of requests.
    /// Returns None when sync is complete for this ledger.
    pub fn build_next_request(&mut self) -> Option<crate::network::message::RtxpMessage> {
        self.syncer.build_next_request(None)
    }

    /// Build multiple request batches from a single tree walk.
    pub fn build_batch_requests(&mut self, count: usize) -> Vec<crate::network::message::RtxpMessage> {
        self.syncer.build_batch_requests(count, None)
    }

    /// Check if the differential sync for the current ledger is complete.
    pub fn is_complete(&self) -> bool {
        self.syncer.is_truly_complete(None)
    }

    /// Whether we have a root inner node (i.e., have synced at least once).
    pub fn has_root(&self) -> bool {
        self.syncer.has_root()
    }

    /// Take the accumulated results for the current ledger.
    pub fn take_results(&mut self) -> DiffResult {
        DiffResult {
            changed_leaves: std::mem::take(&mut self.pending_leaves),
            deleted_keys: Vec::new(), // caller resolves deletions via SparseSHAMap
            complete: self.is_complete(),
            inner_count: self.diff_inner,
            leaf_count: self.diff_leaf,
        }
    }

    /// Take pending deletions (caller will resolve to leaf keys via SparseSHAMap).
    pub fn take_deletions(&mut self) -> Vec<DiffDeletion> {
        std::mem::take(&mut self.pending_deletions)
    }

    /// Get the current target ledger sequence.
    pub fn target_seq(&self) -> u32 {
        self.syncer.ledger_seq
    }

    /// Get the target ledger hash.
    pub fn target_hash(&self) -> [u8; 32] {
        self.syncer.ledger_hash
    }

    /// Clear recently-requested nodes (call periodically).
    pub fn clear_recent(&mut self) {
        self.syncer.clear_recent();
    }

    /// Access the underlying StateSyncer (for persistence, etc.)
    pub fn syncer(&self) -> &StateSyncer {
        &self.syncer
    }

    pub fn syncer_mut(&mut self) -> &mut StateSyncer {
        &mut self.syncer
    }
}
