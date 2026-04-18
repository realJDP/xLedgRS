//! PermissionedDomain — PermissionedDomainSet (type 62) and PermissionedDomainDelete (type 63).
//!
//! Implements directory maintenance and owner_count accounting per rippled
//! PermissionedDomainSet.cpp and PermissionedDomainDelete.cpp.
//!
//! SHAMap key (create): `SHA-512-half(0x006D || account || sequence)`
//!   where 0x006D is LedgerNameSpace::PERMISSIONED_DOMAIN = 'm' = 0x6D.
//! SHAMap key (update/delete by DomainID): the DomainID itself is the key.

use super::ApplyResult;
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

/// LedgerNameSpace::PERMISSIONED_DOMAIN = 'm' = 0x6D, stored as big-endian u16.
const PD_SPACE: [u8; 2] = [0x00, 0x6D];

/// Compute the SHAMap key for a new PermissionedDomain SLE.
/// `sha512Half(0x006D || account || sequence)`
fn pd_key_create(account: &[u8; 20], sequence: u32) -> crate::ledger::Key {
    let mut data = Vec::with_capacity(2 + 20 + 4);
    data.extend_from_slice(&PD_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(&sequence.to_be_bytes());
    crate::ledger::Key(crate::crypto::sha512_first_half(&data))
}

fn build_permissioned_domain_sle(
    owner: &[u8; 20],
    sequence: u32,
    accepted_credentials_raw: &[u8],
) -> Vec<u8> {
    crate::ledger::meta::build_sle(
        0x0082,
        &[
            crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 2,
                data: owner.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 4,
                data: sequence.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 15,
                field_code: 28,
                data: accepted_credentials_raw.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 4,
                data: 0u64.to_be_bytes().to_vec(),
            },
        ],
        None,
        None,
    )
}

/// Type 62: PermissionedDomainSet.
///
/// If `DomainID` is present in the tx, this is an update of an existing
/// PermissionedDomain — the SLE content (AcceptedCredentials) is handled by
/// metadata and diff sync, so this handler only verifies that the SLE exists.
///
/// If `DomainID` is absent, this is a create: compute key from account+sequence,
/// insert a raw SLE, add to owner directory, and increment owner_count.
///
/// (rippled: PermissionedDomainSet.cpp — doApply)
pub(crate) fn apply_permissioned_domain_set(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let accepted_credentials = match &tx.accepted_credentials_raw {
        Some(raw) => raw,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    if let Some(domain_id) = tx.domain_id {
        // ── Update existing PermissionedDomain ──────────────────────────
        let key = crate::ledger::Key(domain_id);
        let existing = match state.get_raw(&key) {
            Some(raw) => raw.to_vec(),
            None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
        };
        let patched = crate::ledger::meta::patch_sle(
            &existing,
            &[crate::ledger::meta::ParsedField {
                type_code: 15,
                field_code: 28,
                data: accepted_credentials.clone(),
            }],
            None,
            None,
            &[],
        );
        state.insert_raw(key, patched);
        ApplyResult::Success
    } else {
        // ── Create new PermissionedDomain ───────────────────────────────
        let sequence = super::sequence_proxy(tx);
        let key = pd_key_create(&tx.account, sequence);

        // Add to owner directory
        directory::dir_add(state, &tx.account, key.0);

        let sle = build_permissioned_domain_sle(&tx.account, sequence, accepted_credentials);
        state.insert_raw(key, sle);

        new_sender.owner_count += 1;

        ApplyResult::Success
    }
}

/// Type 63: PermissionedDomainDelete.
///
/// Removes the PermissionedDomain SLE identified by DomainID, removes from
/// owner directory, and decrements owner_count.
///
/// (rippled: PermissionedDomainDelete.cpp — doApply)
pub(crate) fn apply_permissioned_domain_delete(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let domain_id = match tx.domain_id {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = crate::ledger::Key(domain_id);

    if state.get_raw(&key).is_none() {
        return ApplyResult::ClaimedCost("tecNO_ENTRY");
    }

    // Remove from owner directory
    directory::dir_remove(state, &tx.account, &key.0);

    // Remove the SLE
    state.remove_raw(&key);

    // Decrement owner count
    new_sender.owner_count = new_sender.owner_count.saturating_sub(1);

    ApplyResult::Success
}
