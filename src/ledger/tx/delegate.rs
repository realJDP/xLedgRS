//! xLedgRS purpose: Delegate transaction engine logic for ledger replay.
//! Delegate — DelegateSet (type 64).
//!
//! Implements directory maintenance and owner_count accounting per rippled
//! DelegateSet.cpp.
//!
//! SHAMap key: `SHA-512-half(0x0045 || account || authorizedAccount)`
//!   where 0x0045 is LedgerNameSpace::DELEGATE = 'E' = 0x45.

use super::ApplyResult;
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

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

/// Type 64: `DelegateSet`.
///
/// - If the Delegate SLE already exists and `sfPermissions` is empty, delete
///   it (`dir_remove`, `owner_count--`, `remove_raw`).
/// - If the Delegate SLE already exists and `sfPermissions` is non-empty,
///   update it (actual content handled by metadata and diff sync).
/// - If the Delegate SLE does not exist, create it (`insert_raw`, `dir_add`,
///   `owner_count++`).
///
/// The raw transaction blob does not expose a convenient parser for the
/// `sfPermissions` STArray, so this handler uses SLE presence as the primary
/// heuristic: existing entries are treated as update-or-delete paths and
/// missing entries as create paths. Metadata and diff sync provide the
/// authoritative SLE content.
///
/// (rippled: DelegateSet.cpp — doApply)
pub(crate) fn apply_delegate_set(
    state: &mut LedgerState,
    tx: &ParsedTx,
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
