//! NFTokenModify — type 61 (amendment: DynamicNFT).
//!
//! Modifies the URI on an existing mutable NFToken within its NFTokenPage.
//! The NFToken must have been minted with the tfMutable flag (0x0010).
//!
//! Fields:
//!   - NFTokenID (required, uint256): the token to modify
//!   - URI (optional, VL): new URI (1-256 bytes), or absent to clear
//!   - Owner (optional, Account): the token owner (must differ from sender)
//!
//! Validation (rippled NFTokenModify.cpp):
//!   - Sender must be the issuer, or the issuer's authorized NFTokenMinter
//!   - NFToken must have tfMutable flag set
//!   - URI must be 1-256 bytes if present
//!
//! No directory or owner_count changes. The NFTokenPage SLE update is
//! handled by metadata/diff sync.
//!
//! (rippled: NFTokenModify.cpp — doApply calls nft::changeTokenURI)

use super::{bridge_metadata_only_tx, ApplyResult, TxContext};

/// Type 61: NFTokenModify — update URI on a mutable NFToken.
///
/// No structural changes: no SLEs created/deleted, no directory or owner_count
/// modifications. The NFTokenPage SLE update is handled by metadata application.
pub(crate) fn apply_nftoken_modify(ctx: &TxContext) -> ApplyResult {
    bridge_metadata_only_tx(ctx, 61, "NFTokenModify", "temUNKNOWN")
}
