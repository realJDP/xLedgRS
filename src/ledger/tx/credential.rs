//! Credential — CredentialCreate (58), CredentialAccept (59), CredentialDelete (60)
//!
//! Implements directory maintenance and owner_count accounting per rippled
//! CredentialCreate.cpp, CredentialAccept.cpp, CredentialDelete.cpp, and
//! CredentialHelpers.cpp.

use super::{balance_before_fee, owner_reserve_requirement, ApplyResult};
use crate::ledger::directory;
use crate::ledger::ter::TxResult;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;
use std::collections::BTreeSet;

/// SHAMap key space for Credential: LedgerNameSpace::CREDENTIAL = 'D' = 0x44.
const CREDENTIAL_SPACE: [u8; 2] = [0x00, 0x44];

/// lsfAccepted — flag on the Credential SLE indicating the subject accepted it.
/// (rippled: LedgerFormats.h — 0x00010000)
pub(crate) const LSF_ACCEPTED: u32 = 0x0001_0000;
const MAX_CREDENTIAL_URI_LENGTH: usize = 256;
const MAX_CREDENTIAL_TYPE_LENGTH: usize = 64;
const TF_UNIVERSAL: u32 = 0xC000_0000;

pub(crate) fn preflight(tx: &ParsedTx) -> Result<(), TxResult> {
    if (tx.flags & !TF_UNIVERSAL) != 0 {
        return Err(crate::ledger::ter::TEM_INVALID_FLAG);
    }

    match tx.tx_type {
        58 => preflight_credential_create(tx),
        59 => preflight_credential_accept(tx),
        60 => preflight_credential_delete(tx),
        _ => Ok(()),
    }
}

fn valid_credential_type(tx: &ParsedTx) -> bool {
    matches!(
        tx.credential_type.as_ref(),
        Some(credential_type)
            if !credential_type.is_empty()
                && credential_type.len() <= MAX_CREDENTIAL_TYPE_LENGTH
    )
}

fn preflight_credential_create(tx: &ParsedTx) -> Result<(), TxResult> {
    if tx.subject.is_none() || tx.subject == Some([0u8; 20]) {
        return Err(crate::ledger::ter::TEM_MALFORMED);
    }
    if matches!(tx.uri.as_ref(), Some(uri) if uri.is_empty() || uri.len() > MAX_CREDENTIAL_URI_LENGTH)
    {
        return Err(crate::ledger::ter::TEM_MALFORMED);
    }
    if !valid_credential_type(tx) {
        return Err(crate::ledger::ter::TEM_MALFORMED);
    }
    Ok(())
}

fn preflight_credential_accept(tx: &ParsedTx) -> Result<(), TxResult> {
    match tx.issuer {
        Some(issuer) if issuer == [0u8; 20] => {
            return Err(crate::ledger::ter::TEM_INVALID_ACCOUNT_ID);
        }
        Some(_) => {}
        None => return Err(crate::ledger::ter::TEM_MALFORMED),
    }
    if !valid_credential_type(tx) {
        return Err(crate::ledger::ter::TEM_MALFORMED);
    }
    Ok(())
}

fn preflight_credential_delete(tx: &ParsedTx) -> Result<(), TxResult> {
    if tx.subject.is_none() && tx.issuer.is_none() {
        return Err(crate::ledger::ter::TEM_MALFORMED);
    }
    if matches!(tx.subject, Some(subject) if subject == [0u8; 20])
        || matches!(tx.issuer, Some(issuer) if issuer == [0u8; 20])
    {
        return Err(crate::ledger::ter::TEM_INVALID_ACCOUNT_ID);
    }
    if !valid_credential_type(tx) {
        return Err(crate::ledger::ter::TEM_MALFORMED);
    }
    Ok(())
}

/// Compute the SHAMap key for a Credential SLE.
/// `sha512Half(0x0044 || subject || issuer || credential_type)`
/// (rippled: Indexes.cpp — keylet::credential)
pub(crate) fn credential_key(
    subject: &[u8; 20],
    issuer: &[u8; 20],
    credential_type: &[u8],
) -> crate::ledger::Key {
    let mut data = Vec::with_capacity(2 + 20 + 20 + credential_type.len());
    data.extend_from_slice(&CREDENTIAL_SPACE);
    data.extend_from_slice(subject);
    data.extend_from_slice(issuer);
    data.extend_from_slice(credential_type);
    crate::ledger::Key(crate::crypto::sha512_first_half(&data))
}

fn build_credential_sle(
    subject: &[u8; 20],
    issuer: &[u8; 20],
    credential_type: &[u8],
    flags: u32,
    expiration: Option<u32>,
    uri: Option<&[u8]>,
    issuer_node: u64,
    subject_node: Option<u64>,
) -> Vec<u8> {
    let mut fields = vec![
        crate::ledger::meta::ParsedField {
            type_code: 8,
            field_code: 24,
            data: subject.to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 8,
            field_code: 4,
            data: issuer.to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 7,
            field_code: 31,
            data: credential_type.to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code: 2,
            data: flags.to_be_bytes().to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 3,
            field_code: 27,
            data: issuer_node.to_be_bytes().to_vec(),
        },
    ];

    if let Some(subject_node) = subject_node {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 3,
            field_code: 28,
            data: subject_node.to_be_bytes().to_vec(),
        });
    }
    if let Some(expiration) = expiration {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code: 10,
            data: expiration.to_be_bytes().to_vec(),
        });
    }
    if let Some(uri) = uri {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 7,
            field_code: 5,
            data: uri.to_vec(),
        });
    }

    crate::ledger::meta::build_sle(0x0081, &fields, None, None)
}

fn sle_flags(sle: &crate::ledger::meta::ParsedSLE) -> u32 {
    sle.fields
        .iter()
        .find(|field| field.type_code == 2 && field.field_code == 2 && field.data.len() >= 4)
        .map(|field| {
            u32::from_be_bytes([field.data[0], field.data[1], field.data[2], field.data[3]])
        })
        .unwrap_or(0)
}

fn credential_expired(raw: &[u8], close_time: u64) -> bool {
    crate::ledger::meta::parse_sle(raw)
        .and_then(|sle| {
            sle.fields.into_iter().find_map(|field| {
                (field.type_code == 2 && field.field_code == 10 && field.data.len() >= 4).then(
                    || {
                        u32::from_be_bytes([
                            field.data[0],
                            field.data[1],
                            field.data[2],
                            field.data[3],
                        ])
                    },
                )
            })
        })
        .map(|expiration| close_time > expiration as u64)
        .unwrap_or(false)
}

pub(crate) fn credential_sle_accepted_and_not_expired(raw: &[u8], close_time: u64) -> bool {
    let Some(parsed) = crate::ledger::meta::parse_sle(raw) else {
        return false;
    };
    parsed.entry_type == 0x0081
        && (sle_flags(&parsed) & LSF_ACCEPTED) != 0
        && !credential_expired(raw, close_time)
}

pub(crate) fn check_credential_id_fields(tx: &ParsedTx) -> Option<&'static str> {
    if !crate::transaction::parse::parsed_credential_ids_present(tx) {
        return None;
    }
    let ids = crate::transaction::parse::parsed_credential_ids(tx);
    if ids.is_empty() || ids.len() > 8 {
        return Some("temMALFORMED");
    }
    let mut seen = BTreeSet::new();
    if ids.iter().any(|id| !seen.insert(*id)) {
        return Some("temMALFORMED");
    }
    None
}

pub(crate) fn validate_credential_ids(
    state: &LedgerState,
    subject: &[u8; 20],
    tx: &ParsedTx,
) -> Result<(), &'static str> {
    let ids = crate::transaction::parse::parsed_credential_ids(tx);
    for id in ids {
        let key = crate::ledger::Key(id);
        let raw = load_raw_credential(state, &key).ok_or("tecBAD_CREDENTIALS")?;
        let parsed = crate::ledger::meta::parse_sle(&raw).ok_or("tecBAD_CREDENTIALS")?;
        let parsed_subject =
            parsed_account_field(&parsed.fields, 24).ok_or("tecBAD_CREDENTIALS")?;
        if parsed_subject != *subject {
            return Err("tecBAD_CREDENTIALS");
        }
        if (sle_flags(&parsed) & LSF_ACCEPTED) == 0 {
            return Err("tecBAD_CREDENTIALS");
        }
    }
    Ok(())
}

pub(crate) fn remove_expired_credential_ids(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> bool {
    let ids = crate::transaction::parse::parsed_credential_ids(tx);
    let mut found_expired = false;
    for id in ids {
        let key = crate::ledger::Key(id);
        let Some(raw) = load_raw_credential(state, &key) else {
            continue;
        };
        if credential_expired(&raw, close_time) {
            delete_credential_sle(state, &key, &raw);
            found_expired = true;
        }
    }
    found_expired
}

pub(crate) fn credential_pairs_for_ids(
    state: &LedgerState,
    subject: &[u8; 20],
    tx: &ParsedTx,
    close_time: u64,
) -> Result<Vec<([u8; 20], Vec<u8>)>, &'static str> {
    let ids = crate::transaction::parse::parsed_credential_ids(tx);
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut pairs = Vec::with_capacity(ids.len());
    for id in ids {
        let key = crate::ledger::Key(id);
        let raw = load_raw_credential(state, &key).ok_or("tecBAD_CREDENTIALS")?;
        let parsed = crate::ledger::meta::parse_sle(&raw).ok_or("tecBAD_CREDENTIALS")?;
        let parsed_subject =
            parsed_account_field(&parsed.fields, 24).ok_or("tecBAD_CREDENTIALS")?;
        if parsed_subject != *subject {
            return Err("tecBAD_CREDENTIALS");
        }
        if (sle_flags(&parsed) & LSF_ACCEPTED) == 0 {
            return Err("tecBAD_CREDENTIALS");
        }
        if credential_expired(&raw, close_time) {
            return Err("tecEXPIRED");
        }
        let issuer = parsed_account_field(&parsed.fields, 4).ok_or("tecBAD_CREDENTIALS")?;
        let credential_type = parsed_blob_field(&parsed.fields, 31).ok_or("tecBAD_CREDENTIALS")?;
        pairs.push((issuer, credential_type));
    }
    pairs.sort();
    Ok(pairs)
}

pub(crate) fn credential_deposit_preauth_authorized(
    state: &LedgerState,
    destination: &[u8; 20],
    subject: &[u8; 20],
    tx: &ParsedTx,
    close_time: u64,
) -> Result<bool, &'static str> {
    let pairs = credential_pairs_for_ids(state, subject, tx, close_time)?;
    if pairs.is_empty() {
        return Ok(false);
    }
    let key = crate::ledger::deposit_preauth::credential_shamap_key(destination, &pairs);
    Ok(state.get_raw(&key).is_some()
        || state.get_raw_owned(&key).is_some()
        || state.get_committed_raw_owned(&key).is_some())
}

fn parsed_account_field(
    fields: &[crate::ledger::meta::ParsedField],
    field_code: u16,
) -> Option<[u8; 20]> {
    fields
        .iter()
        .find(|field| field.type_code == 8 && field.field_code == field_code)
        .and_then(|field| {
            if field.data.len() == 20 {
                let mut account = [0u8; 20];
                account.copy_from_slice(&field.data);
                Some(account)
            } else {
                None
            }
        })
}

fn parsed_blob_field(
    fields: &[crate::ledger::meta::ParsedField],
    field_code: u16,
) -> Option<Vec<u8>> {
    fields
        .iter()
        .find(|field| field.type_code == 7 && field.field_code == field_code)
        .map(|field| field.data.clone())
}

fn parsed_u64_field(fields: &[crate::ledger::meta::ParsedField], field_code: u16) -> Option<u64> {
    fields
        .iter()
        .find(|field| field.type_code == 3 && field.field_code == field_code)
        .and_then(|field| {
            field
                .data
                .get(..8)
                .map(|data| u64::from_be_bytes(data.try_into().expect("u64 field length checked")))
        })
}

/// Type 58: CredentialCreate.
///
/// Creates a Credential SLE, adds it to the issuer's owner directory, and
/// increments the issuer's owner_count.  If subject == issuer (self-issued),
/// the credential is auto-accepted (lsfAccepted set, no subject dir entry).
/// Otherwise it is also inserted into the subject's owner directory (but the
/// subject's owner_count is NOT bumped until CredentialAccept).
///
/// (rippled: CredentialCreate.cpp — doApply)
pub(crate) fn apply_credential_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    close_time: u64,
) -> ApplyResult {
    let subject = match tx.subject {
        Some(s) => s,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let cred_type = match &tx.credential_type {
        Some(ct) if !ct.is_empty() && ct.len() <= MAX_CREDENTIAL_TYPE_LENGTH => ct,
        _ => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    if matches!(tx.uri.as_ref(), Some(uri) if uri.is_empty() || uri.len() > MAX_CREDENTIAL_URI_LENGTH)
    {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if matches!(tx.expiration, Some(expiration) if close_time > expiration as u64) {
        return ApplyResult::ClaimedCost("tecEXPIRED");
    }

    let key = credential_key(&subject, &tx.account, cred_type);

    // Duplicate check — if SLE already exists, tecDUPLICATE
    if credential_exists(state, &key) {
        return ApplyResult::ClaimedCost("tecDUPLICATE");
    }

    // Subject account must exist
    if super::load_existing_account(state, &subject).is_none() {
        return ApplyResult::ClaimedCost("tecNO_TARGET");
    }

    let required = owner_reserve_requirement(state, new_sender.owner_count, 1);
    if balance_before_fee(new_sender.balance, tx.fee) < required {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
    }

    // Add to issuer's (sender's) owner directory
    let issuer_node = directory::dir_add(state, &tx.account, key.0);
    new_sender.owner_count += 1;

    // If subject != issuer, also add to subject's owner directory
    // (but subject's owner_count is NOT incremented until Accept).
    let subject_node = if subject != tx.account {
        Some(directory::dir_add(state, &subject, key.0))
    } else {
        None
    };

    let flags: u32 = if subject == tx.account {
        LSF_ACCEPTED
    } else {
        0
    };
    let sle = build_credential_sle(
        &subject,
        &tx.account,
        cred_type,
        flags,
        tx.expiration,
        tx.uri.as_deref(),
        issuer_node,
        subject_node,
    );
    state.insert_raw(key, sle);

    ApplyResult::Success
}

/// Type 59: CredentialAccept.
///
/// Sets the lsfAccepted flag on the credential.  Transfers ownership from
/// issuer to subject: decrements issuer's owner_count, increments subject's.
///
/// (rippled: CredentialAccept.cpp — doApply)
pub(crate) fn apply_credential_accept(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    let issuer = match tx.issuer {
        Some(i) if i != [0u8; 20] => i,
        Some(_) => return ApplyResult::ClaimedCost("temINVALID_ACCOUNT_ID"),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let cred_type = match &tx.credential_type {
        Some(ct) if !ct.is_empty() && ct.len() <= MAX_CREDENTIAL_TYPE_LENGTH => ct,
        _ => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    // subject = tx sender (Account)
    let subject = tx.account;
    if state.get_account(&issuer).is_none() {
        return ApplyResult::ClaimedCost("tecNO_ISSUER");
    }
    let key = credential_key(&subject, &issuer, cred_type);

    let sle = match load_raw_credential(state, &key) {
        Some(data) => data,
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    let parsed = match crate::ledger::meta::parse_sle(&sle) {
        Some(parsed) => parsed,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // Must not already be accepted
    let flags = sle_flags(&parsed);
    if flags & LSF_ACCEPTED != 0 {
        return ApplyResult::ClaimedCost("tecDUPLICATE");
    }
    if credential_expired(&sle, close_time) {
        delete_credential_sle(state, &key, &sle);
        return ApplyResult::ClaimedCost("tecEXPIRED");
    }
    if let Some(subject_acct) = state.get_account(&subject).cloned() {
        let required = owner_reserve_requirement(state, subject_acct.owner_count, 1);
        if balance_before_fee(subject_acct.balance, tx.fee) < required {
            return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
        }
    }

    let new_sle = crate::ledger::meta::patch_sle(
        &sle,
        &[crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code: 2,
            data: (flags | LSF_ACCEPTED).to_be_bytes().to_vec(),
        }],
        None,
        None,
        &[],
    );
    state.insert_raw(key, new_sle);

    // Transfer ownership: issuer -1, subject +1
    // (rippled: CredentialAccept.cpp:107-108)
    if let Some(mut issuer_acct) = state.get_account(&issuer).cloned() {
        issuer_acct.owner_count = issuer_acct.owner_count.saturating_sub(1);
        state.insert_account(issuer_acct);
    }
    if let Some(mut subject_acct) = state.get_account(&subject).cloned() {
        subject_acct.owner_count += 1;
        state.insert_account(subject_acct);
    }

    ApplyResult::Success
}

/// Type 60: CredentialDelete.
///
/// Removes the Credential SLE.  Removes from issuer's owner directory (always)
/// and from subject's owner directory (if subject != issuer).  Decrements
/// owner_count of the actual owner(s) depending on the accepted flag.
///
/// Owner rules (from CredentialHelpers.cpp — deleteSLE):
///   - issuer is owner if NOT accepted, OR if subject == issuer
///   - subject is owner if accepted
///
/// (rippled: CredentialDelete.cpp — doApply, CredentialHelpers.cpp — deleteSLE)
pub(crate) fn apply_credential_delete(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    if tx.subject.is_none() && tx.issuer.is_none() {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if matches!(tx.subject, Some(subject) if subject == [0u8; 20])
        || matches!(tx.issuer, Some(issuer) if issuer == [0u8; 20])
    {
        return ApplyResult::ClaimedCost("temINVALID_ACCOUNT_ID");
    }
    // Subject and Issuer default to the sender if not specified.
    // (rippled: CredentialDelete.cpp:72-73 — value_or(account_))
    let subject = tx.subject.unwrap_or(tx.account);
    let issuer = tx.issuer.unwrap_or(tx.account);
    let cred_type = match &tx.credential_type {
        Some(ct) if !ct.is_empty() && ct.len() <= MAX_CREDENTIAL_TYPE_LENGTH => ct,
        _ => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = credential_key(&subject, &issuer, cred_type);

    let sle = match load_raw_credential(state, &key) {
        Some(data) => data,
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    let _parsed = match crate::ledger::meta::parse_sle(&sle) {
        Some(parsed) => parsed,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    if subject != tx.account && issuer != tx.account && !credential_expired(&sle, close_time) {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    delete_credential_sle(state, &key, &sle);
    ApplyResult::Success
}

fn delete_credential_sle(state: &mut LedgerState, key: &crate::ledger::Key, sle: &[u8]) {
    let Some(parsed) = crate::ledger::meta::parse_sle(sle) else {
        state.remove_raw(key);
        return;
    };
    let accepted = sle_flags(&parsed) & LSF_ACCEPTED != 0;
    let issuer = parsed.fields.iter().find_map(|field| {
        (field.type_code == 8 && field.field_code == 4 && field.data.len() == 20).then(|| {
            let mut account = [0u8; 20];
            account.copy_from_slice(&field.data);
            account
        })
    });
    let subject = parsed.fields.iter().find_map(|field| {
        (field.type_code == 8 && field.field_code == 24 && field.data.len() == 20).then(|| {
            let mut account = [0u8; 20];
            account.copy_from_slice(&field.data);
            account
        })
    });
    let (Some(issuer), Some(subject)) = (issuer, subject) else {
        state.remove_raw(key);
        return;
    };
    let issuer_node = parsed_u64_field(&parsed.fields, 27).unwrap_or(0);
    let subject_node = parsed_u64_field(&parsed.fields, 28).unwrap_or(0);

    // Remove from issuer's owner directory and decrement if issuer is owner.
    // Issuer is owner if: !accepted || subject == issuer
    // (rippled: CredentialHelpers.cpp:83)
    let issuer_root = directory::owner_dir_key(&issuer);
    directory::dir_remove_root_page(state, &issuer_root, issuer_node, &key.0);
    if !accepted || subject == issuer {
        if let Some(mut issuer_acct) = state.get_account(&issuer).cloned() {
            issuer_acct.owner_count = issuer_acct.owner_count.saturating_sub(1);
            state.insert_account(issuer_acct);
        }
    }

    // Remove from subject's owner directory (if subject != issuer).
    // Subject is owner if accepted.
    // (rippled: CredentialHelpers.cpp:87-92)
    if subject != issuer {
        let subject_root = directory::owner_dir_key(&subject);
        directory::dir_remove_root_page(state, &subject_root, subject_node, &key.0);
        if accepted {
            if let Some(mut subject_acct) = state.get_account(&subject).cloned() {
                subject_acct.owner_count = subject_acct.owner_count.saturating_sub(1);
                state.insert_account(subject_acct);
            }
        }
    }

    // Remove the SLE from the ledger
    state.remove_raw(key);
}

fn credential_exists(state: &LedgerState, key: &crate::ledger::Key) -> bool {
    state.get_raw(key).is_some()
        || state.get_raw_owned(key).is_some()
        || state.get_committed_raw_owned(key).is_some()
}

fn load_raw_credential(state: &LedgerState, key: &crate::ledger::Key) -> Option<Vec<u8>> {
    state
        .get_raw(key)
        .map(|raw| raw.to_vec())
        .or_else(|| state.get_raw_owned(key))
        .or_else(|| state.get_committed_raw_owned(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::AccountRoot;

    fn account(account_id: [u8; 20], owner_count: u32) -> AccountRoot {
        AccountRoot {
            account_id,
            balance: 100_000_000,
            sequence: 1,
            owner_count,
            flags: 0,
            regular_key: None,
            minted_nftokens: 0,
            first_nftoken_sequence: 0,
            burned_nftokens: 0,
            transfer_rate: 0,
            domain: Vec::new(),
            tick_size: 0,
            ticket_count: 0,
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        }
    }

    fn credential_tx(account: [u8; 20], subject: [u8; 20]) -> ParsedTx {
        ParsedTx {
            tx_type: 58,
            account,
            subject: Some(subject),
            credential_type: Some(b"KYC".to_vec()),
            fee: 10,
            ..ParsedTx::default()
        }
    }

    #[test]
    fn credential_create_accept_and_delete_tracks_owner_counts() {
        let issuer = [0x11; 20];
        let subject = [0x22; 20];
        let credential_type = b"KYC".to_vec();
        let mut state = LedgerState::new();
        state.insert_account(account(issuer, 0));
        state.insert_account(account(subject, 0));

        let create = credential_tx(issuer, subject);
        let mut issuer_root = state.get_account(&issuer).unwrap().clone();
        assert_eq!(
            apply_credential_create(&mut state, &create, &mut issuer_root, 100),
            ApplyResult::Success
        );
        state.insert_account(issuer_root.clone());
        assert_eq!(issuer_root.owner_count, 1);

        let key = credential_key(&subject, &issuer, &credential_type);
        let created = load_raw_credential(&state, &key).expect("credential SLE exists");
        let parsed = crate::ledger::meta::parse_sle(&created).unwrap();
        assert_eq!(sle_flags(&parsed) & LSF_ACCEPTED, 0);

        let accept = ParsedTx {
            tx_type: 59,
            account: subject,
            issuer: Some(issuer),
            credential_type: Some(credential_type.clone()),
            fee: 10,
            ..ParsedTx::default()
        };
        assert_eq!(
            apply_credential_accept(&mut state, &accept, 100),
            ApplyResult::Success
        );
        assert_eq!(state.get_account(&issuer).unwrap().owner_count, 0);
        assert_eq!(state.get_account(&subject).unwrap().owner_count, 1);

        let accepted = load_raw_credential(&state, &key).expect("credential remains");
        let parsed = crate::ledger::meta::parse_sle(&accepted).unwrap();
        assert_ne!(sle_flags(&parsed) & LSF_ACCEPTED, 0);

        let delete = ParsedTx {
            tx_type: 60,
            account: subject,
            issuer: Some(issuer),
            subject: Some(subject),
            credential_type: Some(credential_type),
            fee: 10,
            ..ParsedTx::default()
        };
        assert_eq!(
            apply_credential_delete(&mut state, &delete, 100),
            ApplyResult::Success
        );
        assert!(load_raw_credential(&state, &key).is_none());
        assert_eq!(state.get_account(&subject).unwrap().owner_count, 0);
    }

    #[test]
    fn credential_accept_deletes_expired_credential() {
        let issuer = [0x33; 20];
        let subject = [0x44; 20];
        let credential_type = b"KYC".to_vec();
        let mut state = LedgerState::new();
        state.insert_account(account(issuer, 0));
        state.insert_account(account(subject, 0));

        let mut create = credential_tx(issuer, subject);
        create.expiration = Some(50);
        let mut issuer_root = state.get_account(&issuer).unwrap().clone();
        assert_eq!(
            apply_credential_create(&mut state, &create, &mut issuer_root, 40),
            ApplyResult::Success
        );
        state.insert_account(issuer_root);

        let accept = ParsedTx {
            tx_type: 59,
            account: subject,
            issuer: Some(issuer),
            credential_type: Some(credential_type.clone()),
            fee: 10,
            ..ParsedTx::default()
        };
        assert_eq!(
            apply_credential_accept(&mut state, &accept, 51),
            ApplyResult::ClaimedCost("tecEXPIRED")
        );
        assert!(
            load_raw_credential(&state, &credential_key(&subject, &issuer, &credential_type))
                .is_none()
        );
        assert_eq!(state.get_account(&issuer).unwrap().owner_count, 0);
    }
}
