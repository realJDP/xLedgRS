//! Credential — CredentialCreate (58), CredentialAccept (59), CredentialDelete (60)
//!
//! Implements directory maintenance and owner_count accounting per rippled
//! CredentialCreate.cpp, CredentialAccept.cpp, CredentialDelete.cpp, and
//! CredentialHelpers.cpp.

use super::ApplyResult;
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

/// SHAMap key space for Credential: LedgerNameSpace::CREDENTIAL = 'D' = 0x44.
const CREDENTIAL_SPACE: [u8; 2] = [0x00, 0x44];

/// lsfAccepted — flag on the Credential SLE indicating the subject accepted it.
/// (rippled: LedgerFormats.h — 0x00010000)
const LSF_ACCEPTED: u32 = 0x0001_0000;

/// Compute the SHAMap key for a Credential SLE.
/// `sha512Half(0x0044 || subject || issuer || credential_type)`
/// (rippled: Indexes.cpp — keylet::credential)
fn credential_key(
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
) -> ApplyResult {
    let subject = match tx.subject {
        Some(s) => s,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let cred_type = match &tx.credential_type {
        Some(ct) if !ct.is_empty() => ct,
        _ => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = credential_key(&subject, &tx.account, cred_type);

    // Duplicate check — if SLE already exists, tecDUPLICATE
    if state.get_raw(&key).is_some() {
        return ApplyResult::ClaimedCost("tecDUPLICATE");
    }

    // Subject account must exist
    if state.get_account(&subject).is_none() {
        return ApplyResult::ClaimedCost("tecNO_TARGET");
    }

    // Add to issuer's (sender's) owner directory
    directory::dir_add(state, &tx.account, key.0);
    new_sender.owner_count += 1;

    // If subject != issuer, also add to subject's owner directory
    // (but subject's owner_count is NOT incremented until Accept).
    if subject != tx.account {
        directory::dir_add(state, &subject, key.0);
    }

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
        0,
        (subject != tx.account).then_some(0),
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
pub(crate) fn apply_credential_accept(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    let issuer = match tx.issuer {
        Some(i) => i,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let cred_type = match &tx.credential_type {
        Some(ct) if !ct.is_empty() => ct,
        _ => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    // subject = tx sender (Account)
    let subject = tx.account;
    let key = credential_key(&subject, &issuer, cred_type);

    let sle = match state.get_raw(&key) {
        Some(data) => data.to_vec(),
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
pub(crate) fn apply_credential_delete(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    // Subject and Issuer default to the sender if not specified.
    // (rippled: CredentialDelete.cpp:72-73 — value_or(account_))
    let subject = tx.subject.unwrap_or(tx.account);
    let issuer = tx.issuer.unwrap_or(tx.account);
    let cred_type = match &tx.credential_type {
        Some(ct) if !ct.is_empty() => ct,
        _ => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = credential_key(&subject, &issuer, cred_type);

    let sle = match state.get_raw(&key) {
        Some(data) => data.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    let parsed = match crate::ledger::meta::parse_sle(&sle) {
        Some(parsed) => parsed,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    let accepted = sle_flags(&parsed) & LSF_ACCEPTED != 0;

    // Remove from issuer's owner directory and decrement if issuer is owner.
    // Issuer is owner if: !accepted || subject == issuer
    // (rippled: CredentialHelpers.cpp:83)
    directory::dir_remove(state, &issuer, &key.0);
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
        directory::dir_remove(state, &subject, &key.0);
        if accepted {
            if let Some(mut subject_acct) = state.get_account(&subject).cloned() {
                subject_acct.owner_count = subject_acct.owner_count.saturating_sub(1);
                state.insert_account(subject_acct);
            }
        }
    }

    // Remove the SLE from the ledger
    state.remove_raw(&key);

    ApplyResult::Success
}
