//! DID — DIDSet (type 49) and DIDDelete (type 50).
//!
//! Implements state effects per rippled DIDSet.cpp and DIDDelete.cpp.

use super::{balance_before_fee, owner_reserve_requirement, ApplyResult};
use crate::ledger::directory;
use crate::ledger::ter::{self, TxResult};
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

const MAX_DID_URI_LENGTH: usize = 256;
const MAX_DID_DOCUMENT_LENGTH: usize = 256;
const MAX_DID_DATA_LENGTH: usize = 256;
const TF_UNIVERSAL: u32 = 0xC000_0000;

pub(crate) fn preflight(tx: &ParsedTx) -> Result<(), TxResult> {
    if (tx.flags & !TF_UNIVERSAL) != 0 {
        return Err(ter::TEM_INVALID_FLAG);
    }

    if tx.tx_type != 49 {
        return Ok(());
    }

    if tx.uri.is_none() && tx.did_document.is_none() && tx.did_data.is_none() {
        return Err(ter::TEM_EMPTY_DID);
    }

    if matches!(
        (&tx.uri, &tx.did_document, &tx.did_data),
        (Some(uri), Some(document), Some(data))
            if uri.is_empty() && document.is_empty() && data.is_empty()
    ) {
        return Err(ter::TEM_EMPTY_DID);
    }

    if tx
        .uri
        .as_ref()
        .is_some_and(|uri| uri.len() > MAX_DID_URI_LENGTH)
        || tx
            .did_document
            .as_ref()
            .is_some_and(|document| document.len() > MAX_DID_DOCUMENT_LENGTH)
        || tx
            .did_data
            .as_ref()
            .is_some_and(|data| data.len() > MAX_DID_DATA_LENGTH)
    {
        return Err(ter::TEM_MALFORMED);
    }

    Ok(())
}

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

    if did_exists(state, &key) {
        if !state.has_did(&key) {
            if let Some(did) = load_did_from_raw(state, &key, tx.account) {
                state.hydrate_did(did);
            } else {
                return ApplyResult::ClaimedCost("tecINTERNAL");
            }
        }
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

        let required = owner_reserve_requirement(state, new_sender.owner_count, 1);
        if balance_before_fee(new_sender.balance, tx.fee) < required {
            return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
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

    if !did_exists(state, &key) {
        return ApplyResult::ClaimedCost("tecNO_ENTRY");
    }

    let owner_node = state
        .get_did(&key)
        .map(|did| did.owner_node)
        .or_else(|| load_did_from_raw(state, &key, tx.account).map(|did| did.owner_node))
        .unwrap_or(0);

    // Remove from owner directory.
    directory::dir_remove_owner_page(state, &tx.account, owner_node, &key.0);

    // Remove the DID SLE.
    state.remove_did(&key);
    state.remove_raw(&key);

    // Decrement owner count.
    new_sender.owner_count = new_sender.owner_count.saturating_sub(1);

    ApplyResult::Success
}

fn did_exists(state: &LedgerState, key: &crate::ledger::Key) -> bool {
    state.has_did(key)
        || state.get_raw_owned(key).is_some()
        || state.get_committed_raw_owned(key).is_some()
}

fn load_did_from_raw(
    state: &LedgerState,
    key: &crate::ledger::Key,
    account: [u8; 20],
) -> Option<crate::ledger::Did> {
    let raw = state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))?;
    let sle = crate::ledger::meta::parse_sle(&raw)?;
    if sle.entry_type != 0x0049 {
        return None;
    }

    let mut did = crate::ledger::Did {
        account,
        did_document: None,
        uri: None,
        data: None,
        owner_node: 0,
        previous_txn_id: [0u8; 32],
        previous_txn_lgrseq: 0,
        raw_sle: Some(raw.clone()),
    };

    for field in sle.fields {
        match (field.type_code, field.field_code) {
            (3, 4) if field.data.len() == 8 => {
                did.owner_node = u64::from_be_bytes(field.data.try_into().ok()?);
            }
            (5, 5) if field.data.len() == 32 => {
                did.previous_txn_id = field.data.try_into().ok()?;
            }
            (2, 6) if field.data.len() == 4 => {
                did.previous_txn_lgrseq = u32::from_be_bytes(field.data.try_into().ok()?);
            }
            (7, 5) => did.uri = Some(field.data),
            (7, 26) => did.did_document = Some(field.data),
            (7, 27) => did.data = Some(field.data),
            _ => {}
        }
    }

    Some(did)
}
