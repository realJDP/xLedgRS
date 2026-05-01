//! xLedgRS purpose: Signer List Set transaction engine logic for ledger replay.
//! SignerListSet (type 12) — create, replace, or destroy a SignerList SLE.
//!
//! Implements directory maintenance and owner_count accounting per rippled
//! SignerListSet.cpp.
//!
//! SHAMap key: `SHA-512-half(0x0053 || account || signerListID)`
//!   where 0x0053 is LedgerNameSpace::SIGNER_LIST = 'S' = 0x53,
//!   and signerListID is always 0 (u32 big-endian).
//!
//! Operation:
//!   - SignerQuorum > 0: create or replace the signer list.
//!     On replace: first remove old (dir_remove, owner_count--), then create new.
//!     On create: dir_add, owner_count++ (post-MultiSignReserve: always +1).
//!   - SignerQuorum == 0: destroy the signer list.
//!     dir_remove, owner_count-- (post-MultiSignReserve: always -1).

use super::ApplyResult;
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

/// LedgerNameSpace::SIGNER_LIST = 'S' = 0x53, stored as big-endian u16.
const SIGNER_LIST_SPACE: [u8; 2] = [0x00, 0x53];

/// The default (and currently only) SignerListID.
const DEFAULT_SIGNER_LIST_ID: u32 = 0;

/// Compute the SHAMap key for a SignerList SLE.
/// `sha512Half(0x0053 || account || signerListID)`
fn signers_key(account: &[u8; 20]) -> crate::ledger::Key {
    let mut data = Vec::with_capacity(2 + 20 + 4);
    data.extend_from_slice(&SIGNER_LIST_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(&DEFAULT_SIGNER_LIST_ID.to_be_bytes());
    crate::ledger::Key(crate::crypto::sha512_first_half(&data))
}

fn build_signer_list_sle(account: &[u8; 20], quorum: u32, signer_entries_raw: &[u8]) -> Vec<u8> {
    crate::ledger::meta::build_sle(
        0x0053,
        &[
            crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 2,
                data: account.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 4,
                data: 0u64.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 35,
                data: quorum.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 15,
                field_code: 4,
                data: signer_entries_raw.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 38,
                data: DEFAULT_SIGNER_LIST_ID.to_be_bytes().to_vec(),
            },
        ],
        None,
        None,
    )
}

/// Type 12: SignerListSet.
///
/// If `SignerQuorum` > 0: create or replace the signer list.
///   - If an old signer list exists, remove it first (dir_remove, owner_count -1).
///   - Then create the new one (dir_add, owner_count +1, insert_raw).
///   - Net effect on owner_count when replacing: 0. When creating: +1.
///
/// If `SignerQuorum` == 0: destroy the signer list.
///   - dir_remove, owner_count -1, remove_raw.
///
/// Note: post-MultiSignReserve amendment (long since active on mainnet),
/// the owner_count delta is always +1/-1. The `lsfOneOwnerCount` flag on the
/// SLE indicates this. All signer lists are treated as post-amendment.
///
/// (rippled: SignerListSet.cpp — replaceSignerList, destroySignerList,
///  removeSignersFromLedger)
pub(crate) fn apply_signer_list_set(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let quorum = match tx.signer_quorum {
        Some(q) => q,
        // If quorum is not present, treat as a no-op (shouldn't happen for
        // well-formed txs, but be defensive).
        None => return ApplyResult::Success,
    };

    let key = signers_key(&tx.account);
    let exists = state.get_raw(&key).is_some();

    if quorum > 0 {
        let signer_entries = match &tx.signer_entries_raw {
            Some(entries) if entries != &[0xF1] => entries,
            _ => return ApplyResult::ClaimedCost("temMALFORMED"),
        };

        // ── Create or replace ───────────────────────────────────────────
        // If the old signer list exists, remove it first.
        if exists {
            directory::dir_remove(state, &tx.account, &key.0);
            state.remove_raw(&key);
            // owner_count -1 for the removed old list
            new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
        }

        // Create the new signer list.
        directory::dir_add(state, &tx.account, key.0);
        let sle = build_signer_list_sle(&tx.account, quorum, signer_entries);
        state.insert_raw(key, sle);
        new_sender.owner_count += 1;

        ApplyResult::Success
    } else {
        // ── Destroy ─────────────────────────────────────────────────────
        if !exists {
            // Already gone — rippled returns tesSUCCESS in this case.
            return ApplyResult::Success;
        }

        directory::dir_remove(state, &tx.account, &key.0);
        state.remove_raw(&key);
        new_sender.owner_count = new_sender.owner_count.saturating_sub(1);

        ApplyResult::Success
    }
}
