//! LedgerStateFix — type 53 (amendment: fixNFTokenPageLinks).
//!
//! User-submitted transaction that repairs broken NFTokenPage directory links
//! (sfNextPageMin, sfPreviousPageMin). Introduced as part of fixNFTokenPageLinks.
//!
//! Fields:
//!   - LedgerFixType (required, uint16): which fix to apply
//!     - 1 = nfTokenPageLink: repair NFToken page directory links
//!   - Owner (required, Account): the account whose state needs fixing
//!
//! Fee: requires owner reserve fee (same as AccountDelete).
//!
//! (rippled: LedgerStateFix.cpp — doApply calls nft::repairNFTokenDirectoryLinks)

use super::ApplyResult;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

/// Type 53: LedgerStateFix — repair NFToken page links.
pub(crate) fn apply_ledger_state_fix(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    match tx.ledger_fix_type {
        Some(1) => {}
        _ => return ApplyResult::ClaimedCost("tefINVALID_LEDGER_FIX_TYPE"),
    }

    let Some(owner) = tx.owner else {
        return ApplyResult::ClaimedCost("temINVALID");
    };
    if state.get_account(&owner).is_none() {
        return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND");
    }
    if state.repair_nft_page_links(&owner) == 0 {
        return ApplyResult::ClaimedCost("tecFAILED_PROCESSING");
    }

    ApplyResult::Success
}
