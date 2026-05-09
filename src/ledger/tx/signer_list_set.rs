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

use super::{balance_before_fee, owner_reserve_requirement, ApplyResult};
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

/// LedgerNameSpace::SIGNER_LIST = 'S' = 0x53, stored as big-endian u16.
const SIGNER_LIST_SPACE: [u8; 2] = [0x00, 0x53];

/// The default (and currently only) SignerListID.
const DEFAULT_SIGNER_LIST_ID: u32 = 0;
const MAX_SIGNER_ENTRIES: usize = 32;
const LSF_ONE_OWNER_COUNT: u32 = 0x0001_0000;

#[derive(Debug, Clone, Copy)]
struct SignerListEntrySpec {
    account: [u8; 20],
    weight: u16,
    wallet_locator: Option<[u8; 32]>,
}

/// Compute the SHAMap key for a SignerList SLE.
/// `sha512Half(0x0053 || account || signerListID)`
fn signers_key(account: &[u8; 20]) -> crate::ledger::Key {
    let mut data = Vec::with_capacity(2 + 20 + 4);
    data.extend_from_slice(&SIGNER_LIST_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(&DEFAULT_SIGNER_LIST_ID.to_be_bytes());
    crate::ledger::Key(crate::crypto::sha512_first_half(&data))
}

fn build_signer_entries_raw(entries: &[SignerListEntrySpec]) -> Vec<u8> {
    let mut raw = Vec::new();
    for entry in entries {
        raw.push(0xE4); // sfSignerEntry
        raw.push(0x13); // sfSignerWeight
        raw.extend_from_slice(&entry.weight.to_be_bytes());
        if let Some(wallet_locator) = entry.wallet_locator {
            raw.push(0x57); // sfWalletLocator
            raw.extend_from_slice(&wallet_locator);
        }
        raw.push(0x81); // sfAccount
        crate::transaction::serialize::encode_length(20, &mut raw);
        raw.extend_from_slice(&entry.account);
        raw.push(0xE1);
    }
    raw.push(0xF1);
    raw
}

fn build_signer_list_sle(
    account: &[u8; 20],
    quorum: u32,
    signer_entries: &[SignerListEntrySpec],
    owner_node: u64,
) -> Vec<u8> {
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
                data: owner_node.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 2,
                data: LSF_ONE_OWNER_COUNT.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 35,
                data: quorum.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 15,
                field_code: 4,
                data: build_signer_entries_raw(signer_entries),
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

pub(crate) fn preflight(tx: &ParsedTx) -> Result<(), crate::ledger::ter::TxResult> {
    const TF_UNIVERSAL: u32 = 0xC000_0000;

    if (tx.flags & !TF_UNIVERSAL) != 0 {
        return Err(crate::ledger::ter::TEM_INVALID_FLAG);
    }

    let quorum = tx.signer_quorum.ok_or(crate::ledger::ter::TEM_MALFORMED)?;
    match (quorum, tx.signer_entries_raw.as_deref()) {
        (0, None) => Ok(()),
        (0, Some(_)) => Err(crate::ledger::ter::TEM_MALFORMED),
        (_, Some(raw)) => {
            let mut entries =
                parse_signer_entries_for_set(raw).map_err(super::tx_result_from_token)?;
            entries.sort_by_key(|entry| entry.account);
            if let Some(ter) = validate_signer_entries(&tx.account, quorum, &entries) {
                return Err(super::tx_result_from_token(ter));
            }
            Ok(())
        }
        (_, None) => Err(crate::ledger::ter::TEM_MALFORMED),
    }
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
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = signers_key(&tx.account);
    let existing_raw = load_signer_list_raw(state, &key);
    let exists = existing_raw.is_some();

    if quorum > 0 {
        let signer_entries = match &tx.signer_entries_raw {
            Some(entries) if entries != &[0xF1] => entries,
            _ => return ApplyResult::ClaimedCost("temMALFORMED"),
        };
        let mut parsed_entries = match parse_signer_entries_for_set(signer_entries) {
            Ok(entries) => entries,
            Err(ter) => return ApplyResult::ClaimedCost(ter),
        };
        parsed_entries.sort_by_key(|entry| entry.account);
        if let Some(ter) = validate_signer_entries(&tx.account, quorum, &parsed_entries) {
            return ApplyResult::ClaimedCost(ter);
        }
        let removed_owner_count = existing_raw
            .as_deref()
            .map(signer_list_owner_count_delta)
            .unwrap_or(0);
        let owner_count_after_remove = new_sender.owner_count.saturating_sub(removed_owner_count);
        let required = owner_reserve_requirement(state, owner_count_after_remove, 1);
        if balance_before_fee(new_sender.balance, tx.fee) < required {
            return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
        }

        // ── Create or replace ───────────────────────────────────────────
        // If the old signer list exists, remove it first.
        if exists {
            remove_signer_list_from_owner_dir(state, &tx.account, &key, existing_raw.as_deref());
            state.remove_raw(&key);
            new_sender.owner_count = owner_count_after_remove;
        }

        // Create the new signer list.
        let owner_node = directory::dir_add(state, &tx.account, key.0);
        let sle = build_signer_list_sle(&tx.account, quorum, &parsed_entries, owner_node);
        state.insert_raw(key, sle);
        new_sender.owner_count += 1;

        ApplyResult::Success
    } else {
        // ── Destroy ─────────────────────────────────────────────────────
        if tx.signer_entries_raw.is_some() {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
        if (new_sender.flags & crate::ledger::account::LSF_DISABLE_MASTER) != 0
            && new_sender.regular_key.is_none()
        {
            return ApplyResult::ClaimedCost("tecNO_ALTERNATIVE_KEY");
        }
        if !exists {
            // Already gone — rippled returns tesSUCCESS in this case.
            return ApplyResult::Success;
        }

        let removed_owner_count = existing_raw
            .as_deref()
            .map(signer_list_owner_count_delta)
            .unwrap_or(1);
        remove_signer_list_from_owner_dir(state, &tx.account, &key, existing_raw.as_deref());
        state.remove_raw(&key);
        new_sender.owner_count = new_sender.owner_count.saturating_sub(removed_owner_count);

        ApplyResult::Success
    }
}

fn load_signer_list_raw(state: &LedgerState, key: &crate::ledger::Key) -> Option<Vec<u8>> {
    if let Some(raw) = state.get_raw(key) {
        return Some(raw.to_vec());
    }
    state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))
}

fn signer_list_owner_node(raw: &[u8]) -> u64 {
    crate::ledger::meta::parse_sle(raw)
        .and_then(|sle| {
            sle.fields.into_iter().find_map(|field| {
                (field.type_code == 3 && field.field_code == 4 && field.data.len() >= 8).then(
                    || {
                        u64::from_be_bytes([
                            field.data[0],
                            field.data[1],
                            field.data[2],
                            field.data[3],
                            field.data[4],
                            field.data[5],
                            field.data[6],
                            field.data[7],
                        ])
                    },
                )
            })
        })
        .unwrap_or(0)
}

fn remove_signer_list_from_owner_dir(
    state: &mut LedgerState,
    account: &[u8; 20],
    key: &crate::ledger::Key,
    existing_raw: Option<&[u8]>,
) -> bool {
    let owner_node = existing_raw.map(signer_list_owner_node).unwrap_or(0);
    let owner_root = directory::owner_dir_key(account);
    directory::dir_remove_root_page(state, &owner_root, owner_node, &key.0)
}

fn signer_list_owner_count_delta(raw: &[u8]) -> u32 {
    let Some(sle) = crate::ledger::meta::parse_sle(raw) else {
        return 1;
    };
    let flags = sle
        .fields
        .iter()
        .find(|field| field.type_code == 2 && field.field_code == 2 && field.data.len() >= 4)
        .map(|field| {
            u32::from_be_bytes([field.data[0], field.data[1], field.data[2], field.data[3]])
        })
        .unwrap_or(0);
    if (flags & LSF_ONE_OWNER_COUNT) != 0 {
        return 1;
    }
    let signer_count = sle
        .fields
        .iter()
        .find(|field| field.type_code == 15 && field.field_code == 4)
        .and_then(|field| parse_signer_entries_for_set(&field.data).ok())
        .map(|entries| entries.len() as u32)
        .unwrap_or(0);
    2u32.saturating_add(signer_count)
}

fn validate_signer_entries(
    account: &[u8; 20],
    quorum: u32,
    entries: &[SignerListEntrySpec],
) -> Option<&'static str> {
    if entries.is_empty() || entries.len() > MAX_SIGNER_ENTRIES {
        return Some("temMALFORMED");
    }

    let mut previous = None::<[u8; 20]>;
    let mut weight_sum = 0u32;
    for entry in entries {
        if &entry.account == account {
            return Some("temBAD_SIGNER");
        }
        if entry.weight == 0 {
            return Some("temBAD_WEIGHT");
        }
        if previous
            .map(|previous_account| previous_account >= entry.account)
            .unwrap_or(false)
        {
            return Some("temBAD_SIGNER");
        }
        previous = Some(entry.account);
        weight_sum = weight_sum.saturating_add(entry.weight as u32);
    }

    if quorum == 0 || weight_sum < quorum {
        Some("temBAD_QUORUM")
    } else {
        None
    }
}

fn parse_signer_entries_for_set(data: &[u8]) -> Result<Vec<SignerListEntrySpec>, &'static str> {
    let mut pos = 0usize;
    let mut entries = Vec::new();

    while pos < data.len() {
        if data[pos] == 0xF1 {
            return Ok(entries);
        }

        let (type_code, field_code, new_pos) = crate::ledger::meta::read_field_header(data, pos);
        if new_pos > data.len() || type_code != 14 || field_code != 4 {
            return Err("temMALFORMED");
        }
        pos = new_pos;

        let mut account = None::<[u8; 20]>;
        let mut weight = None::<u16>;
        let mut wallet_locator = None::<[u8; 32]>;

        while pos < data.len() && data[pos] != 0xE1 {
            let (inner_type, inner_field, inner_pos) =
                crate::ledger::meta::read_field_header(data, pos);
            if inner_pos > data.len() {
                return Err("temMALFORMED");
            }
            pos = inner_pos;

            match (inner_type, inner_field) {
                (1, 3) => {
                    if pos + 2 > data.len() {
                        return Err("temMALFORMED");
                    }
                    weight = Some(u16::from_be_bytes([data[pos], data[pos + 1]]));
                    pos += 2;
                }
                (8, 1) => {
                    let (vlen, ladv) = crate::transaction::serialize::decode_length(&data[pos..]);
                    if ladv == 0 || vlen != 20 || pos + ladv + vlen > data.len() {
                        return Err("temMALFORMED");
                    }
                    pos += ladv;
                    let mut id = [0u8; 20];
                    id.copy_from_slice(&data[pos..pos + 20]);
                    account = Some(id);
                    pos += 20;
                }
                (5, 7) => {
                    if pos + 32 > data.len() {
                        return Err("temMALFORMED");
                    }
                    let mut locator = [0u8; 32];
                    locator.copy_from_slice(&data[pos..pos + 32]);
                    wallet_locator = Some(locator);
                    pos += 32;
                }
                _ => {
                    let next = crate::ledger::meta::skip_field_raw(data, pos, inner_type);
                    if next <= pos || next > data.len() {
                        return Err("temMALFORMED");
                    }
                    pos = next;
                }
            }
        }

        if pos >= data.len() || data[pos] != 0xE1 {
            return Err("temMALFORMED");
        }
        pos += 1;

        entries.push(SignerListEntrySpec {
            account: account.ok_or("temMALFORMED")?,
            weight: weight.ok_or("temMALFORMED")?,
            wallet_locator,
        });
    }

    Err("temMALFORMED")
}
