//! XChain bridge types — types 41-48.
//!
//! XChainBridge amendment is NOT active on mainnet (March 2026), so these
//! transactions won't appear in validated ledgers. Implemented for completeness.
//!
//! Structural operations:
//!   Type 48 (XChainCreateBridge): creates Bridge SLE, dir_add, owner_count++
//!   Type 47 (BridgeModify): modifies existing Bridge SLE, no directory changes
//!   Type 41 (XChainCreateClaimID): creates ClaimID SLE, dir_add, owner_count++
//!   Type 43 (XChainClaim): may delete ClaimID SLE, dir_remove, owner_count--
//!   Types 42, 44, 45, 46: modify existing SLEs, no directory changes
//!
//! All SLE content handled by metadata/diff sync.
//!
//! (rippled: XChainBridge.cpp)

use super::{bridge_metadata_only_tx, ApplyResult, TxContext};

/// Types 41-48: XChain bridge operations.
///
/// Not active on mainnet. All structural operations (directory membership,
/// owner_count) are handled by metadata application for ModifiedNode/
/// CreatedNode/DeletedNode entries.
pub(crate) fn apply_xchain(ctx: &TxContext) -> ApplyResult {
    bridge_metadata_only_tx(ctx, 41, "XChain", "temUNKNOWN")
}
