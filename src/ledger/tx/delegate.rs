//! Delegate — DelegateSet (type 64).
//!
//! Implements directory maintenance and owner_count accounting per rippled
//! DelegateSet.cpp.
//!
//! SHAMap key: `SHA-512-half(0x0045 || account || authorizedAccount)`
//!   where 0x0045 is LedgerNameSpace::DELEGATE = 'E' = 0x45.

use crate::ledger::LedgerState;
use crate::ledger::directory;
use crate::transaction::ParsedTx;
use super::ApplyResult;

/// LedgerNameSpace::DELEGATE = 'E' = 0x45, stored as big-endian u16.
const DELEGATE_SPACE: [u8; 2] = [0x00, 0x45];

/// Compute the SHAMap key for a Delegate SLE.
/// `sha512Half(0x0045 || account || authorizedAccount)`
fn delegate_key(account: &[u8; 20], authorize: &[u8; 20]) -> crate::ledger::Key {
    let mut data = Vec::with_capacity(2 + 20 + 20);
    data.extend_from_slice(&DELEGATE_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(authorize);
    crate::ledger::Key(crate::crypto::sha512_first_half(&data))
}

fn build_delegate_sle(account: &[u8; 20], authorize: &[u8; 20], permissions_raw: &[u8]) -> Vec<u8> {
    crate::ledger::meta::build_sle(
        0x0083,
        &[
            crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 1,
                data: account.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 5,
                data: authorize.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 15,
                field_code: 29,
                data: permissions_raw.to_vec(),
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

/// Type 64: DelegateSet.
///
/// - If the Delegate SLE already exists and sfPermissions is empty: delete it
///   (dir_remove, owner_count--, remove_raw).
/// - If the Delegate SLE already exists and sfPermissions is non-empty: update
///   (actual content handled by metadata/diff sync).
/// - If the Delegate SLE does not exist: create it (insert_raw, dir_add,
///   owner_count++).
///
/// We cannot easily parse the STArray sfPermissions from the raw tx blob, but
/// we can detect the "delete" case: rippled requires that when deleting, the
/// sfPermissions array is empty AND the SLE must already exist (preclaim).
/// The SignerQuorum field is not present on DelegateSet, so we use a simpler
/// heuristic: if the SLE exists, it's an update (or delete); if not, create.
///
/// Since we don't parse sfPermissions, we rely on the fact that:
/// - On mainnet, DelegateSet with empty permissions on a non-existent SLE
///   would fail preclaim (tecNO_ENTRY) and never reach doApply.
/// - The metadata/diff sync handles the actual SLE content.
///
/// Strategy: always try create-or-update. Deletion is handled by metadata.
/// For owner_count: +1 on create only.
///
/// (rippled: DelegateSet.cpp — doApply)
pub(crate) fn apply_delegate_set(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let authorize = match tx.authorize {
        Some(a) => a,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let permissions = match &tx.permissions_raw {
        Some(raw) => raw,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let is_delete = permissions == &[0xF1];

    let key = delegate_key(&tx.account, &authorize);

    if let Some(existing) = state.get_raw(&key).map(|raw| raw.to_vec()) {
        if is_delete {
            directory::dir_remove(state, &tx.account, &key.0);
            state.remove_raw(&key);
            new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
        } else {
            let patched = crate::ledger::meta::patch_sle(
                &existing,
                &[crate::ledger::meta::ParsedField {
                    type_code: 15,
                    field_code: 29,
                    data: permissions.clone(),
                }],
                None,
                None,
                &[],
            );
            state.insert_raw(key, patched);
        }
        ApplyResult::Success
    } else {
        if is_delete {
            return ApplyResult::ClaimedCost("tecNO_ENTRY");
        }

        // ── Create new Delegate SLE ─────────────────────────────────────
        // Add to owner directory
        directory::dir_add(state, &tx.account, key.0);

        let sle = build_delegate_sle(&tx.account, &authorize, permissions);
        state.insert_raw(key, sle);

        new_sender.owner_count += 1;

        ApplyResult::Success
    }
}
