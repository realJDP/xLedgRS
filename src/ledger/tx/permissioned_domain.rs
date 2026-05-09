//! PermissionedDomain — PermissionedDomainSet (type 62) and PermissionedDomainDelete (type 63).
//!
//! Implements directory maintenance and owner_count accounting per rippled
//! PermissionedDomainSet.cpp and PermissionedDomainDelete.cpp.
//!
//! SHAMap key (create): `SHA-512-half(0x006D || account || sequence)`
//!   where 0x006D is LedgerNameSpace::PERMISSIONED_DOMAIN = 'm' = 0x6D.
//! SHAMap key (update/delete by DomainID): the DomainID itself is the key.

use super::ApplyResult;
use super::{balance_before_fee, owner_reserve_requirement};
use crate::ledger::directory;
use crate::ledger::{Key, LedgerState};
use crate::transaction::ParsedTx;
use std::collections::BTreeSet;

/// LedgerNameSpace::PERMISSIONED_DOMAIN = 'm' = 0x6D, stored as big-endian u16.
const PD_SPACE: [u8; 2] = [0x00, 0x6D];
const MAX_PERMISSIONED_DOMAIN_CREDENTIALS_ARRAY_SIZE: usize = 10;
const MAX_CREDENTIAL_TYPE_LENGTH: usize = 64;

pub(crate) fn account_in_domain(
    state: &LedgerState,
    account: &[u8; 20],
    domain_id: &[u8; 32],
    close_time: u64,
) -> bool {
    let Some(raw) = load_raw_entry(state, &Key(*domain_id)) else {
        return false;
    };
    let Some(parsed) = crate::ledger::meta::parse_sle(&raw) else {
        return false;
    };
    if parsed.entry_type != 0x0082 {
        return false;
    }

    if parsed
        .fields
        .iter()
        .find_map(|field| {
            if field.type_code == 8 && field.field_code == 2 && field.data.len() == 20 {
                Some(field.data.as_slice())
            } else {
                None
            }
        })
        .is_some_and(|owner| owner == account)
    {
        return true;
    }

    let Some(credentials) = parsed
        .fields
        .iter()
        .find(|field| field.type_code == 15 && field.field_code == 28)
    else {
        return false;
    };

    parse_credential_array(&credentials.data)
        .unwrap_or_default()
        .into_iter()
        .any(|(issuer, credential_type)| {
            let key = super::credential::credential_key(account, &issuer, &credential_type);
            let Some(raw) = load_raw_entry(state, &key) else {
                return false;
            };
            super::credential::credential_sle_accepted_and_not_expired(&raw, close_time)
        })
}

fn load_raw_entry(state: &LedgerState, key: &Key) -> Option<Vec<u8>> {
    state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))
}

fn sorted_accepted_credentials(raw: &[u8]) -> Result<Vec<([u8; 20], Vec<u8>)>, &'static str> {
    let mut credentials = parse_credential_array(raw)?;
    if credentials.is_empty() {
        return Err("temARRAY_EMPTY");
    }
    if credentials.len() > MAX_PERMISSIONED_DOMAIN_CREDENTIALS_ARRAY_SIZE {
        return Err("temARRAY_TOO_LARGE");
    }
    for (issuer, credential_type) in &credentials {
        if *issuer == [0u8; 20] {
            return Err("temINVALID_ACCOUNT_ID");
        }
        if credential_type.is_empty() || credential_type.len() > MAX_CREDENTIAL_TYPE_LENGTH {
            return Err("temMALFORMED");
        }
    }

    credentials.sort();
    let mut seen = BTreeSet::new();
    if credentials
        .iter()
        .any(|(issuer, credential_type)| !seen.insert((*issuer, credential_type.clone())))
    {
        return Err("temMALFORMED");
    }
    Ok(credentials)
}

fn parse_credential_array(raw: &[u8]) -> Result<Vec<([u8; 20], Vec<u8>)>, &'static str> {
    let mut pos = 0usize;
    let mut credentials = Vec::new();

    while pos < raw.len() {
        if raw[pos] == 0xF1 {
            break;
        }

        let (type_code, field_code, new_pos) = crate::ledger::meta::read_field_header(raw, pos);
        if new_pos > raw.len() {
            return Err("temMALFORMED");
        }
        pos = new_pos;
        if type_code != 14 || field_code != 33 {
            return Err("temMALFORMED");
        }

        let mut issuer = None::<[u8; 20]>;
        let mut credential_type = None::<Vec<u8>>;
        while pos < raw.len() && raw[pos] != 0xE1 {
            let (inner_type, inner_field, inner_pos) =
                crate::ledger::meta::read_field_header(raw, pos);
            if inner_pos > raw.len() {
                return Err("temMALFORMED");
            }
            pos = inner_pos;
            match (inner_type, inner_field) {
                (8, 4) => {
                    let (len, len_bytes) =
                        crate::transaction::serialize::decode_length(&raw[pos..]);
                    if len_bytes == 0 || len != 20 || pos + len_bytes + len > raw.len() {
                        return Err("temINVALID_ACCOUNT_ID");
                    }
                    let mut value = [0u8; 20];
                    value.copy_from_slice(&raw[pos + len_bytes..pos + len_bytes + len]);
                    issuer = Some(value);
                    pos += len_bytes + len;
                }
                (7, 31) => {
                    let (len, len_bytes) =
                        crate::transaction::serialize::decode_length(&raw[pos..]);
                    if len_bytes == 0 || pos + len_bytes + len > raw.len() {
                        return Err("temMALFORMED");
                    }
                    credential_type = Some(raw[pos + len_bytes..pos + len_bytes + len].to_vec());
                    pos += len_bytes + len;
                }
                _ => {
                    pos = crate::ledger::meta::skip_field_raw(raw, pos, inner_type);
                }
            }
        }

        if pos >= raw.len() || raw[pos] != 0xE1 {
            return Err("temMALFORMED");
        }
        pos += 1;
        let (Some(issuer), Some(credential_type)) = (issuer, credential_type) else {
            return Err("temMALFORMED");
        };
        credentials.push((issuer, credential_type));
    }

    Ok(credentials)
}

fn build_credentials_array(credentials: &[([u8; 20], Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (issuer, credential_type) in credentials {
        crate::ledger::meta::write_field_header_pub(&mut out, 14, 33); // sfCredential
        crate::ledger::meta::write_field_header_pub(&mut out, 8, 4); // sfIssuer
        crate::transaction::serialize::encode_length(20, &mut out);
        out.extend_from_slice(issuer);
        crate::ledger::meta::write_field_header_pub(&mut out, 7, 31); // sfCredentialType
        crate::transaction::serialize::encode_length(credential_type.len(), &mut out);
        out.extend_from_slice(credential_type);
        out.push(0xE1);
    }
    out.push(0xF1);
    out
}

fn permissioned_domain_owner(raw: &[u8]) -> Option<[u8; 20]> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    if parsed.entry_type != 0x0082 {
        return None;
    }
    parsed.fields.iter().find_map(|field| {
        (field.type_code == 8 && field.field_code == 2 && field.data.len() == 20).then(|| {
            let mut owner = [0u8; 20];
            owner.copy_from_slice(&field.data);
            owner
        })
    })
}

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
    accepted_credentials_raw: Vec<u8>,
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
                data: accepted_credentials_raw,
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
    let accepted_credentials = match sorted_accepted_credentials(accepted_credentials) {
        Ok(credentials) => credentials,
        Err(code) => return ApplyResult::ClaimedCost(code),
    };
    for (issuer, _) in &accepted_credentials {
        if super::load_existing_account(state, issuer).is_none() {
            return ApplyResult::ClaimedCost("tecNO_ISSUER");
        }
    }
    let accepted_credentials_raw = build_credentials_array(&accepted_credentials);

    if let Some(domain_id) = tx.domain_id {
        if domain_id == [0u8; 32] {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
        // ── Update existing PermissionedDomain ──────────────────────────
        let key = crate::ledger::Key(domain_id);
        let existing = match load_raw_entry(state, &key) {
            Some(raw) => raw,
            None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
        };
        if permissioned_domain_owner(&existing) != Some(tx.account) {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
        let patched = crate::ledger::meta::patch_sle(
            &existing,
            &[crate::ledger::meta::ParsedField {
                type_code: 15,
                field_code: 28,
                data: accepted_credentials_raw,
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

        let required = owner_reserve_requirement(state, new_sender.owner_count, 1);
        if balance_before_fee(new_sender.balance, tx.fee) < required {
            return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
        }

        // Add to owner directory
        directory::dir_add(state, &tx.account, key.0);

        let sle = build_permissioned_domain_sle(&tx.account, sequence, accepted_credentials_raw);
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
        Some(d) if d != [0u8; 32] => d,
        Some(_) => return ApplyResult::ClaimedCost("temMALFORMED"),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = crate::ledger::Key(domain_id);

    let existing = match load_raw_entry(state, &key) {
        Some(raw) => raw,
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    if permissioned_domain_owner(&existing) != Some(tx.account) {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    // Remove from owner directory
    directory::dir_remove(state, &tx.account, &key.0);

    // Remove the SLE
    state.remove_raw(&key);

    // Decrement owner count
    new_sender.owner_count = new_sender.owner_count.saturating_sub(1);

    ApplyResult::Success
}
