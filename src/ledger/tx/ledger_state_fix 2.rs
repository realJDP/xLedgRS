//! LedgerStateFix — type 53 (amendment: fixNFTokenPageLinks).
//!
//! User-submitted transaction that repairs broken NFTokenPage directory links
//! (sfNextPageMin, sfPreviousPageMin). Introduced as part of fixNFTokenPageLinks.
//!
//! Fields:
//!   - LedgerFixType (required, uint16): which fix to apply
//!     - 1 = nfTokenPageLink: repair NFToken page directory links
//!   - Owner (optional, Account): the account whose state needs fixing
//!
//! Fee: requires owner reserve fee (same as AccountDelete).
//!
//! The actual page repairs (creating corrected pages, deleting malformed ones)
//! are complex and involve walking all NFTokenPages for the owner.
//! Metadata application handles all the CreatedNode/ModifiedNode/DeletedNode
//! entries that result from the repair.
//!
//! (rippled: LedgerStateFix.cpp — doApply calls nft::repairNFTokenDirectoryLinks)

use super::ApplyResult;

/// Type 53: LedgerStateFix — repair NFToken page links.
pub(crate) fn apply_ledger_state_fix() -> ApplyResult {
    ApplyResult::Success
}
