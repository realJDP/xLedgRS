//! xLedgRS purpose: Batch transaction engine logic for ledger replay.
//! Batch transaction (type 71) — execute multiple inner transactions.
//!
//! The Batch amendment is NOT active on mainnet (Supported::no in rippled).
//! When it activates, inner transactions will need full parsing and execution.
//!
//! Four execution modes (from tx flags):
//! - tfAllOrNothing  (0x00010000): All must succeed or entire batch fails
//! - tfOnlyOne       (0x00020000): Execute only first successful inner tx
//! - tfUntilFailure  (0x00040000): Execute until first failure
//! - tfIndependent   (0x00080000): Execute all independently
//!
//! (rippled: Batch.cpp, apply.cpp — applyBatchTransactions)

use super::{bridge_metadata_only_tx, ApplyResult, TxContext};

/// Type 71: Batch.
///
/// Amendment-gated by featureBatch (not active on mainnet as of 2026-04).
/// When the amendment activates, this will need inner transaction parsing
/// from the STArray embedded in the outer transaction blob.
///
/// This handler is replay-only. Validator-mode or local apply rejects it unless
/// authoritative validated metadata is present.
pub(crate) fn apply_batch(ctx: &TxContext) -> ApplyResult {
    bridge_metadata_only_tx(ctx, 71, "Batch", "temUNKNOWN")
}
