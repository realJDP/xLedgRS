//! DID — DIDSet (type 49) and DIDDelete (type 50).
//!
//! Implements state effects per rippled DIDSet.cpp and DIDDelete.cpp.

use super::ApplyResult;
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

/// Type 49: DIDSet — create or update a DID SLE for the sender's account.
///
/// If no DID exists for the account, creates one with the provided fields
/// (DIDDocument, URI, Data), adds it to the owner directory, and increments
/// owner_count.
///
/// If a DID already exists, updates the fields: non-empty values are set,
/// empty values (present but zero-length) clear the field. If all three
/// fields end up absent after update, returns tecEMPTY_DID.
pub(crate) fn apply_did_set(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let key = crate::ledger::did::shamap_key(&tx.account);

    if state.has_did(&key) {
        // ── Update existing DID ──────────────────────────────────────────
        let did = match state.get_did_mut(&key) {
            Some(d) => d,
            None => return ApplyResult::ClaimedCost("tecINTERNAL"),
        };

        // Update each optional field: if present in tx, set or clear.
        if let Some(ref uri) = tx.uri {
            if uri.is_empty() {
                did.uri = None;
            } else {
                did.uri = Some(uri.clone());
            }
        }
        if let Some(ref doc) = tx.did_document {
            if doc.is_empty() {
                did.did_document = None;
            } else {
                did.did_document = Some(doc.clone());
            }
        }
        if let Some(ref data) = tx.did_data {
            if data.is_empty() {
                did.data = None;
            } else {
                did.data = Some(data.clone());
            }
        }

        // If all three fields are now absent, return tecEMPTY_DID.
        if did.uri.is_none() && did.did_document.is_none() && did.data.is_none() {
            return ApplyResult::ClaimedCost("tecEMPTY_DID");
        }

        // Mark dirty (re-insert to update SHAMap + dirty tracking).
        let updated = did.clone();
        state.insert_did(updated);

        ApplyResult::Success
    } else {
        // ── Create new DID ───────────────────────────────────────────────
        let uri = match tx.uri {
            Some(ref v) if !v.is_empty() => Some(v.clone()),
            _ => None,
        };
        let did_document = match tx.did_document {
            Some(ref v) if !v.is_empty() => Some(v.clone()),
            _ => None,
        };
        let data = match tx.did_data {
            Some(ref v) if !v.is_empty() => Some(v.clone()),
            _ => None,
        };

        // fixEmptyDID check: if creating and all fields end up absent,
        // return tecEMPTY_DID.
        if uri.is_none() && did_document.is_none() && data.is_none() {
            return ApplyResult::ClaimedCost("tecEMPTY_DID");
        }

        let owner_node = directory::dir_add(state, &tx.account, key.0);

        let did = crate::ledger::Did {
            account: tx.account,
            did_document,
            uri,
            data,
            owner_node,
            previous_txn_id: [0u8; 32],
            previous_txn_lgrseq: 0,
            raw_sle: None,
        };
        state.insert_did(did);
        new_sender.owner_count += 1;

        ApplyResult::Success
    }
}

/// Type 50: DIDDelete — remove the sender's DID SLE.
///
/// Removes the DID from the state tree, removes from the owner directory,
/// and decrements owner_count.
pub(crate) fn apply_did_delete(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let key = crate::ledger::did::shamap_key(&tx.account);

    if !state.has_did(&key) {
        return ApplyResult::ClaimedCost("tecNO_ENTRY");
    }

    // Remove from owner directory.
    directory::dir_remove(state, &tx.account, &key.0);

    // Remove the DID SLE.
    state.remove_did(&key);

    // Decrement owner count.
    new_sender.owner_count = new_sender.owner_count.saturating_sub(1);

    ApplyResult::Success
}
