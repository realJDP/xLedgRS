//! View traits — the layered state access interface matching rippled.
//!
//! ReadView: read-only ledger state access
//! RawView: unconditional mutation primitives
//! ApplyView: transactional mutation (extends ReadView)
//! TxsRawView: extends RawView with transaction insertion

use crate::ledger::fees::Fees;
use crate::ledger::keylet::Keylet;
use crate::ledger::rules::Rules;
use crate::ledger::sle::SLE;
use crate::ledger::Key;
use std::sync::Arc;

// ── LedgerHeader (minimal — will expand later) ─────────────────────────────

/// Ledger header fields needed by the view stack.
#[derive(Debug, Clone, Default)]
pub struct LedgerInfo {
    pub seq: u32,
    pub parent_hash: [u8; 32],
    pub tx_hash: [u8; 32],
    pub account_hash: [u8; 32],
    pub close_time: u64,
    pub parent_close_time: u64,
    pub close_time_resolution: u8,
    pub close_flags: u8,
    pub total_coins: u64,
    pub hash: [u8; 32],
}

// ── ApplyFlags ──────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling how a transaction is applied.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ApplyFlags: u32 {
        const NONE       = 0x00;
        const FAIL_HARD  = 0x10;
        const RETRY      = 0x20;
        const UNLIMITED  = 0x400;
        const BATCH      = 0x800;
        const DRY_RUN    = 0x1000;
    }
}

// ── ReadView ────────────────────────────────────────────────────────────────

/// Read-only view of ledger state. Matches rippled's ReadView.
pub trait ReadView {
    /// Read an SLE by keylet. Returns None if not found or type mismatch.
    fn read(&self, keylet: &Keylet) -> Option<Arc<SLE>>;

    /// Check existence by keylet.
    fn exists(&self, keylet: &Keylet) -> bool {
        self.read(keylet).is_some()
    }

    /// Find the next key strictly greater than `key`.
    /// If `last` is Some, return None if the result would be >= last.
    /// Used for directory iteration.
    fn succ(&self, key: &Key, last: Option<&Key>) -> Option<Key>;

    /// Ledger header info.
    fn info(&self) -> &LedgerInfo;

    /// Fee settings for this ledger.
    fn fees(&self) -> &Fees;

    /// Active amendment rules.
    fn rules(&self) -> &Rules;
}

// ── RawView ─────────────────────────────────────────────────────────────────

/// Unconditional raw mutation — the primitive used by state tables.
/// Matches rippled's RawView.
pub trait RawView {
    /// Insert a new SLE. The key must not already exist.
    fn raw_insert(&mut self, sle: Arc<SLE>);

    /// Replace an existing SLE. The key must already exist.
    fn raw_replace(&mut self, sle: Arc<SLE>);

    /// Erase an existing SLE.
    fn raw_erase(&mut self, key: &Key);

    /// Destroy XRP (for fee consumption). Reduces total_coins.
    fn raw_destroy_xrp(&mut self, drops: u64);
}

// ── TxsRawView ──────────────────────────────────────────────────────────────

/// Extends RawView with transaction insertion (for the tx SHAMap).
/// Matches rippled's TxsRawView.
pub trait TxsRawView: RawView {
    /// Insert a transaction + metadata into the transaction tree.
    fn raw_tx_insert(&mut self, key: Key, tx_blob: Vec<u8>, meta_blob: Vec<u8>);
}

// ── ApplyView ───────────────────────────────────────────────────────────────

/// Transactional mutation view — used by transaction handlers.
/// Extends ReadView with mutation operations.
/// Matches rippled's ApplyView.
pub trait ApplyView: ReadView {
    /// Get a mutable copy of an SLE. The SLE is cloned from the base view
    /// and cached; subsequent peeks return the cached copy.
    fn peek(&mut self, keylet: &Keylet) -> Option<Arc<SLE>>;

    /// Insert a new SLE into the view.
    fn insert(&mut self, sle: Arc<SLE>);

    /// Mark an SLE as modified. Must have been peek'd first.
    /// The SLE should be a modified clone of what peek() returned.
    fn update(&mut self, sle: Arc<SLE>);

    /// Remove an SLE from the view.
    fn erase(&mut self, key: &Key);

    /// Apply flags for this transaction context.
    fn apply_flags(&self) -> ApplyFlags;
}
