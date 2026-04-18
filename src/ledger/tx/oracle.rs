//! Oracle transaction handlers — OracleSet (51) and OracleDelete (52).
//!
//! OracleSet creates or updates an Oracle SLE.  OracleDelete removes one.
//!
//! This module does not construct full binary SLEs directly. The diff-sync and
//! follow paths handle actual SLE content while this handler maintains owner
//! directory membership and `owner_count` on the AccountRoot.
//!
//! SHAMap key: SHA-512-half(0x0052 || AccountID || OracleDocumentID)
//!   namespace 'R' = 0x52  (from rippled Indexes.cpp LedgerNameSpace::ORACLE)

use crate::crypto::sha512_first_half;
use crate::ledger::{directory, Key, LedgerState};
use crate::transaction::ParsedTx;

use super::ApplyResult;

/// Namespace for Oracle SLE keys: 'R' = 0x52.
const ORACLE_SPACE: [u8; 2] = [0x00, 0x52];

/// Compute the SHAMap key for an Oracle SLE.
/// `SHA-512-half(0x0052 || account_id || oracle_document_id)`
fn oracle_key(account: &[u8; 20], document_id: u32) -> Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&ORACLE_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(&document_id.to_be_bytes());
    Key(sha512_first_half(&data))
}

/// Type 51: OracleSet — create or update an Oracle object.
///
/// On create: add to owner directory, increment owner_count.
/// On update: no directory/owner_count changes (the SLE already exists).
///
/// The actual SLE binary content is applied by diff-sync. This handler only
/// maintains directory membership and `owner_count`.
pub(crate) fn apply_oracle_set(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let doc_id = match tx.oracle_document_id {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = oracle_key(&tx.account, doc_id);

    // Check if oracle already exists (update path).
    let exists = state.get_raw(&key).is_some();

    if !exists {
        // Create path: add to the owner directory and increment `owner_count`.
        // rippled uses one reserve slot for <= 5 price data entries and two
        // for larger entries. Use the smaller value here and let diff-sync
        // correct it when needed.
        directory::dir_add(state, &tx.account, key.0);
        new_sender.owner_count += 1;
    }
    // For both create and update, diff-sync and metadata application provide
    // the authoritative SLE content.

    ApplyResult::Success
}

/// Type 52: OracleDelete — remove an Oracle object.
///
/// Removes from owner directory, decrements owner_count.
pub(crate) fn apply_oracle_delete(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let doc_id = match tx.oracle_document_id {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = oracle_key(&tx.account, doc_id);

    // Remove from owner directory.
    let removed = directory::dir_remove(state, &tx.account, &key.0);

    if removed {
        // Decrement owner_count (1 slot; diff-sync corrects for 2-slot oracles).
        new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
        // Remove the raw SLE from the SHAMap.
        state.remove_raw(&key);
    }
    // If the oracle did not exist, rippled would return `tecNO_ENTRY` during
    // preclaim. Validated transactions are expected to succeed at this stage.

    ApplyResult::Success
}
