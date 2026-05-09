//! DepositPreauth — add or remove a deposit authorization.

use super::{balance_before_fee, owner_reserve_requirement, ApplyResult};
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::parse::{
    parsed_authorize_credentials_raw, parsed_unauthorize_credentials_raw,
};
use crate::transaction::ParsedTx;

const MAX_CREDENTIALS_ARRAY_SIZE: usize = 8;
const MAX_CREDENTIAL_TYPE_LENGTH: usize = 64;

/// Apply DepositPreauth.
///
/// rippled requires exactly one of `sfAuthorize`, `sfUnauthorize`,
/// `sfAuthorizeCredentials`, or `sfUnauthorizeCredentials`. Creating a duplicate
/// preauth and removing a missing preauth are fee-claimed tec results, not
/// silent successes.
pub(crate) fn apply_deposit_preauth(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let authorize_credentials = parsed_authorize_credentials_raw(tx);
    let unauthorize_credentials = parsed_unauthorize_credentials_raw(tx);
    let operation_count = tx.authorize.is_some() as u8
        + tx.unauthorize.is_some() as u8
        + authorize_credentials.is_some() as u8
        + unauthorize_credentials.is_some() as u8;

    if operation_count != 1 {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    if let Some(authorized) = tx.authorize {
        return apply_deposit_preauth_authorize(state, tx, new_sender, authorized);
    }
    if let Some(authorized) = tx.unauthorize {
        return apply_deposit_preauth_unauthorize(state, tx, new_sender, authorized);
    }
    if let Some(raw) = authorize_credentials {
        return apply_deposit_preauth_authorize_credentials(state, tx, new_sender, &raw);
    }
    if let Some(raw) = unauthorize_credentials {
        return apply_deposit_preauth_unauthorize_credentials(state, tx, new_sender, &raw);
    }

    ApplyResult::ClaimedCost("temMALFORMED")
}

fn apply_deposit_preauth_authorize(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    authorized: [u8; 20],
) -> ApplyResult {
    if authorized == [0u8; 20] {
        return ApplyResult::ClaimedCost("temINVALID_ACCOUNT_ID");
    }
    if authorized == tx.account {
        return ApplyResult::ClaimedCost("temCANNOT_PREAUTH_SELF");
    }
    let key = crate::ledger::deposit_preauth::shamap_key(&tx.account, &authorized);

    if super::load_existing_account(state, &authorized).is_none() {
        return ApplyResult::ClaimedCost("tecNO_TARGET");
    }

    if deposit_preauth_exists(state, &key) {
        return ApplyResult::ClaimedCost("tecDUPLICATE");
    }

    let required = owner_reserve_requirement(state, new_sender.owner_count, 1);
    if balance_before_fee(new_sender.balance, tx.fee) < required {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
    }

    let owner_node = directory::dir_add(state, &tx.account, key.0);
    let dp = crate::ledger::DepositPreauth {
        account: tx.account,
        authorized,
        owner_node,
        previous_txn_id: [0u8; 32],
        previous_txn_lgrseq: 0,
        raw_sle: None,
    };
    state.insert_deposit_preauth(dp);
    new_sender.owner_count += 1;

    ApplyResult::Success
}

fn apply_deposit_preauth_unauthorize(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    authorized: [u8; 20],
) -> ApplyResult {
    if authorized == [0u8; 20] {
        return ApplyResult::ClaimedCost("temINVALID_ACCOUNT_ID");
    }
    let key = crate::ledger::deposit_preauth::shamap_key(&tx.account, &authorized);
    if !deposit_preauth_exists(state, &key) {
        return ApplyResult::ClaimedCost("tecNO_ENTRY");
    }

    let owner_node = sle_uint64_from_state(state, &key, 4).unwrap_or(0);
    directory::dir_remove_owner_page(state, &tx.account, owner_node, &key.0);
    state.remove_deposit_preauth(&key);
    state.remove_raw(&key);
    new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
    ApplyResult::Success
}

fn apply_deposit_preauth_authorize_credentials(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    raw: &[u8],
) -> ApplyResult {
    let credentials = match sorted_credential_array(raw) {
        Ok(credentials) => credentials,
        Err(code) => return ApplyResult::ClaimedCost(code),
    };

    for (issuer, _) in &credentials {
        if super::load_existing_account(state, issuer).is_none() {
            return ApplyResult::ClaimedCost("tecNO_ISSUER");
        }
    }

    let key = crate::ledger::deposit_preauth::credential_shamap_key(&tx.account, &credentials);
    if deposit_preauth_exists(state, &key) {
        return ApplyResult::ClaimedCost("tecDUPLICATE");
    }

    let required = owner_reserve_requirement(state, new_sender.owner_count, 1);
    if balance_before_fee(new_sender.balance, tx.fee) < required {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
    }

    let owner_node = directory::dir_add(state, &tx.account, key.0);
    let sorted_array = build_credentials_array(&credentials);
    let sle = build_credential_deposit_preauth_sle(&tx.account, owner_node, sorted_array);
    state.insert_raw(key, sle);
    new_sender.owner_count += 1;

    ApplyResult::Success
}

fn apply_deposit_preauth_unauthorize_credentials(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    raw: &[u8],
) -> ApplyResult {
    let credentials = match sorted_credential_array(raw) {
        Ok(credentials) => credentials,
        Err(code) => return ApplyResult::ClaimedCost(code),
    };
    let key = crate::ledger::deposit_preauth::credential_shamap_key(&tx.account, &credentials);
    if !deposit_preauth_exists(state, &key) {
        return ApplyResult::ClaimedCost("tecNO_ENTRY");
    }

    let owner_node = sle_uint64_from_state(state, &key, 4).unwrap_or(0);
    directory::dir_remove_owner_page(state, &tx.account, owner_node, &key.0);
    state.remove_raw(&key);
    new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
    ApplyResult::Success
}

fn deposit_preauth_exists(state: &LedgerState, key: &crate::ledger::Key) -> bool {
    state.has_deposit_preauth(key)
        || state.get_raw_owned(key).is_some()
        || state.get_committed_raw_owned(key).is_some()
}

fn sle_uint64_from_state(
    state: &LedgerState,
    key: &crate::ledger::Key,
    field_code: u16,
) -> Option<u64> {
    let raw = state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))?;
    let parsed = crate::ledger::meta::parse_sle(&raw)?;
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 3 && field.field_code == field_code)
        .and_then(|field| field.data.as_slice().try_into().ok())
        .map(u64::from_be_bytes)
}

fn sorted_credential_array(raw: &[u8]) -> Result<Vec<([u8; 20], Vec<u8>)>, &'static str> {
    let mut credentials = parse_credential_array(raw)?;
    if credentials.is_empty() {
        return Err("temARRAY_EMPTY");
    }
    if credentials.len() > MAX_CREDENTIALS_ARRAY_SIZE {
        return Err("temARRAY_TOO_LARGE");
    }
    credentials.sort();
    if credentials.windows(2).any(|window| window[0] == window[1]) {
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

        let (type_code, _field_code, new_pos) = crate::ledger::meta::read_field_header(raw, pos);
        if new_pos > raw.len() {
            return Err("temMALFORMED");
        }
        pos = new_pos;
        if type_code != 14 {
            pos = crate::ledger::meta::skip_field_raw(raw, pos, type_code);
            continue;
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
                        return Err("temMALFORMED");
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

        if pos < raw.len() && raw[pos] == 0xE1 {
            pos += 1;
        } else {
            return Err("temMALFORMED");
        }
        let issuer = issuer.ok_or("temMALFORMED")?;
        if issuer == [0u8; 20] {
            return Err("temINVALID_ACCOUNT_ID");
        }
        let credential_type = credential_type.ok_or("temMALFORMED")?;
        if credential_type.is_empty() || credential_type.len() > MAX_CREDENTIAL_TYPE_LENGTH {
            return Err("temMALFORMED");
        }
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

fn build_credential_deposit_preauth_sle(
    account: &[u8; 20],
    owner_node: u64,
    credentials_raw: Vec<u8>,
) -> Vec<u8> {
    crate::ledger::meta::build_sle(
        0x0070,
        &[
            crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 1,
                data: account.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 4,
                data: owner_node.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 15,
                field_code: 26,
                data: credentials_raw,
            },
        ],
        None,
        None,
    )
}
