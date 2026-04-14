//! MPToken — MPTokenIssuanceCreate (54), MPTokenIssuanceDestroy (55),
//!           MPTokenIssuanceSet (56), MPTokenAuthorize (57).
//!
//! Implements directory maintenance and owner_count accounting per rippled
//! MPTokenIssuanceCreate.cpp, MPTokenIssuanceDestroy.cpp,
//! MPTokenIssuanceSet.cpp, MPTokenAuthorize.cpp.
//!
//! SHAMap keys:
//!   MPTokenIssuance: SHA-512-half(0x007E || MPTID)
//!     where MPTID = BE(sequence) || account  (24 bytes)
//!     namespace '~' = 0x7E
//!   MPToken: SHA-512-half(0x0074 || issuance_key || holder)
//!     namespace 't' = 0x74

use crate::crypto::sha512_first_half;
use crate::ledger::{directory, Key, LedgerState};
use crate::transaction::{amount::Amount, ParsedTx};

use super::ApplyResult;

/// LedgerNameSpace::MPTOKEN_ISSUANCE = '~' = 0x7E.
const MPT_ISSUANCE_SPACE: [u8; 2] = [0x00, 0x7E];

/// LedgerNameSpace::MPTOKEN = 't' = 0x74.
const MPTOKEN_SPACE: [u8; 2] = [0x00, 0x74];

const DEFAULT_MAXIMUM_AMOUNT: u64 = 0x7FFF_FFFF_FFFF_FFFF;
const MAX_TRANSFER_FEE: u16 = 50_000;

pub(crate) const LSF_MPT_LOCKED: u32 = 0x0000_0001;
pub(crate) const LSF_MPT_CAN_LOCK: u32 = 0x0000_0002;
pub(crate) const LSF_MPT_AUTHORIZED: u32 = 0x0000_0002;
pub(crate) const LSF_MPT_REQUIRE_AUTH: u32 = 0x0000_0004;
pub(crate) const LSF_MPT_CAN_ESCROW: u32 = 0x0000_0008;
pub(crate) const LSF_MPT_CAN_TRADE: u32 = 0x0000_0010;
pub(crate) const LSF_MPT_CAN_TRANSFER: u32 = 0x0000_0020;
pub(crate) const LSF_MPT_CAN_CLAWBACK: u32 = 0x0000_0040;

const TF_MPT_UNAUTHORIZE: u32 = 0x0000_0001;
const TF_MPT_UNLOCK: u32 = 0x0000_0002;

const CREATE_FLAG_MASK: u32 = LSF_MPT_CAN_LOCK
    | LSF_MPT_REQUIRE_AUTH
    | LSF_MPT_CAN_ESCROW
    | LSF_MPT_CAN_TRADE
    | LSF_MPT_CAN_TRANSFER
    | LSF_MPT_CAN_CLAWBACK;

/// Construct a 24-byte MPTID from sequence + account.
/// MPTID = BE(sequence) || account_id  (4 + 20 = 24 bytes)
pub(crate) fn make_mptid(sequence: u32, account: &[u8; 20]) -> [u8; 24] {
    let mut id = [0u8; 24];
    id[0..4].copy_from_slice(&sequence.to_be_bytes());
    id[4..24].copy_from_slice(account);
    id
}

/// Compute the SHAMap key for an MPTokenIssuance SLE.
/// `SHA-512-half(0x007E || MPTID)`
pub(crate) fn mpt_issuance_key(mptid: &[u8; 24]) -> Key {
    let mut data = Vec::with_capacity(2 + 24);
    data.extend_from_slice(&MPT_ISSUANCE_SPACE);
    data.extend_from_slice(mptid);
    Key(sha512_first_half(&data))
}

/// Compute the SHAMap key for an MPToken SLE.
/// `SHA-512-half(0x0074 || issuance_key || holder)`
pub(crate) fn mptoken_key(issuance_key: &[u8; 32], holder: &[u8; 20]) -> Key {
    let mut data = Vec::with_capacity(2 + 32 + 20);
    data.extend_from_slice(&MPTOKEN_SPACE);
    data.extend_from_slice(issuance_key);
    data.extend_from_slice(holder);
    Key(sha512_first_half(&data))
}

pub(crate) fn mpt_issuer(mptid: &[u8; 24]) -> [u8; 20] {
    let mut issuer = [0u8; 20];
    issuer.copy_from_slice(&mptid[4..24]);
    issuer
}

pub(crate) fn mpt_amount_parts(amount: &Amount) -> Option<(u64, [u8; 24])> {
    amount.mpt_parts()
}

pub(crate) fn sle_uint64(raw: &[u8], field_code: u16) -> u64 {
    crate::ledger::meta::parse_sle(raw)
        .and_then(|sle| {
            sle.fields.into_iter().find_map(|field| {
                (field.type_code == 3 && field.field_code == field_code && field.data.len() >= 8)
                    .then(|| {
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
                    })
            })
        })
        .unwrap_or(0)
}

fn sle_u32(raw: &[u8], type_code: u16, field_code: u16) -> Option<u32> {
    crate::ledger::meta::parse_sle(raw).and_then(|sle| {
        sle.fields.into_iter().find_map(|field| {
            (field.type_code == type_code && field.field_code == field_code && field.data.len() >= 4)
                .then(|| u32::from_be_bytes([field.data[0], field.data[1], field.data[2], field.data[3]]))
        })
    })
}

fn sle_u16(raw: &[u8], field_code: u16) -> Option<u16> {
    crate::ledger::meta::parse_sle(raw).and_then(|sle| {
        sle.fields.into_iter().find_map(|field| {
            (field.type_code == 1 && field.field_code == field_code && field.data.len() >= 2)
                .then(|| u16::from_be_bytes([field.data[0], field.data[1]]))
        })
    })
}

pub(crate) fn sle_flags(raw: &[u8]) -> u32 {
    sle_u32(raw, 2, 2).unwrap_or(0)
}

pub(crate) fn patch_uint64_fields(raw: &[u8], fields: &[(u16, u64)]) -> Vec<u8> {
    let updates = fields
        .iter()
        .map(|(field_code, value)| crate::ledger::meta::ParsedField {
            type_code: 3,
            field_code: *field_code,
            data: value.to_be_bytes().to_vec(),
        })
        .collect::<Vec<_>>();
    crate::ledger::meta::patch_sle(raw, &updates, None, None, &[])
}

fn patch_flags(raw: &[u8], flags: u32) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code: 2,
            data: flags.to_be_bytes().to_vec(),
        }],
        None,
        None,
        &[],
    )
}

fn issuance_transfer_fee(raw: &[u8]) -> u16 {
    sle_u16(raw, 4).unwrap_or(0)
}

fn issuance_maximum_amount(raw: &[u8]) -> u64 {
    let maximum = sle_uint64(raw, 24);
    if maximum == 0 {
        DEFAULT_MAXIMUM_AMOUNT
    } else {
        maximum
    }
}

fn checked_transfer_fee(value: u64, fee: u16) -> Option<u64> {
    if value == 0 || fee == 0 {
        return Some(0);
    }
    let rounded = ((value as u128).saturating_mul(fee as u128) + 50_000) / 100_000;
    (rounded <= u64::MAX as u128).then_some(rounded as u64)
}

fn build_mptoken_issuance_sle(tx: &ParsedTx) -> Vec<u8> {
    let issuance_flags = tx.flags & CREATE_FLAG_MASK;
    let mut fields = vec![
        crate::ledger::meta::ParsedField {
            type_code: 8,
            field_code: 4,
            data: tx.account.to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code: 2,
            data: issuance_flags.to_be_bytes().to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code: 4,
            data: tx.sequence.to_be_bytes().to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 3,
            field_code: 4,
            data: 0u64.to_be_bytes().to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 3,
            field_code: 25,
            data: 0u64.to_be_bytes().to_vec(),
        },
    ];

    if let Some(transfer_fee) = tx.transfer_fee_field {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 1,
            field_code: 4,
            data: transfer_fee.to_be_bytes().to_vec(),
        });
    }
    if let Some(asset_scale) = tx.asset_scale {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 16,
            field_code: 5,
            data: vec![asset_scale],
        });
    }
    if let Some(maximum_amount) = tx.maximum_amount {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 3,
            field_code: 24,
            data: maximum_amount.to_be_bytes().to_vec(),
        });
    }
    if let Some(metadata) = &tx.mptoken_metadata {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 7,
            field_code: 30,
            data: metadata.clone(),
        });
    }
    if let Some(domain_id) = tx.domain_id {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 5,
            field_code: 34,
            data: domain_id.to_vec(),
        });
    }
    if let Some(mutable_flags) = tx.mutable_flags {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code: 53,
            data: mutable_flags.to_be_bytes().to_vec(),
        });
    }

    crate::ledger::meta::build_sle(0x007e, &fields, None, None)
}

fn build_mptoken_sle(account: &[u8; 20], mptid: &[u8; 24], flags: u32) -> Vec<u8> {
    crate::ledger::meta::build_sle(
        0x007f,
        &[
            crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 1,
                data: account.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 21,
                field_code: 1,
                data: mptid.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 26,
                data: 0u64.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 4,
                data: 0u64.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 2,
                data: flags.to_be_bytes().to_vec(),
            },
        ],
        None,
        None,
    )
}

fn create_holder_token(state: &mut LedgerState, issuance_key: &Key, mptid: &[u8; 24], holder: &[u8; 20], flags: u32) -> Vec<u8> {
    let holder_key = mptoken_key(&issuance_key.0, holder);
    directory::dir_add(state, holder, holder_key.0);
    let token_raw = build_mptoken_sle(holder, mptid, flags);
    state.insert_raw(holder_key, token_raw.clone());
    if let Some(account) = state.get_account(holder) {
        let mut account = account.clone();
        account.owner_count += 1;
        state.insert_account(account);
    }
    token_raw
}

/// Apply a direct MPT payment. MPTokensV1 only supports direct account-to-account
/// payments; pathfinding and cross-currency conversions are not available.
pub(crate) fn apply_direct_mpt_payment(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    let destination = match tx.destination {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };
    if destination == tx.account {
        return ApplyResult::ClaimedCost("temREDUNDANT");
    }
    if !tx.paths.is_empty() {
        return ApplyResult::ClaimedCost("temBAD_PATH");
    }

    let amount = match tx.amount.as_ref() {
        Some(amount) => amount,
        None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    let (deliver_value, mptid) = match mpt_amount_parts(amount) {
        Some(parts) => parts,
        None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    if deliver_value == 0 {
        return ApplyResult::ClaimedCost("temBAD_AMOUNT");
    }

    let issuance_key = mpt_issuance_key(&mptid);
    let issuance_raw = match state.get_raw(&issuance_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
    };
    let issuance_flags = sle_flags(&issuance_raw);
    let issuer = mpt_issuer(&mptid);

    let sender_is_issuer = tx.account == issuer;
    let destination_is_issuer = destination == issuer;

    if issuance_flags & LSF_MPT_LOCKED != 0 && !(!sender_is_issuer && destination_is_issuer) {
        return ApplyResult::ClaimedCost("tecLOCKED");
    }

    if !sender_is_issuer && !destination_is_issuer && issuance_flags & LSF_MPT_CAN_TRANSFER == 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let transfer_fee = if !sender_is_issuer && !destination_is_issuer {
        issuance_transfer_fee(&issuance_raw)
    } else {
        0
    };
    let fee_value = match checked_transfer_fee(deliver_value, transfer_fee) {
        Some(value) => value,
        None => return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED"),
    };
    let total_debit = match deliver_value.checked_add(fee_value) {
        Some(value) => value,
        None => return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED"),
    };

    if let Some(send_max) = tx.send_max.as_ref() {
        let Some((send_max_value, send_max_id)) = mpt_amount_parts(send_max) else {
            return ApplyResult::ClaimedCost("temBAD_AMOUNT");
        };
        if send_max_id != mptid || send_max_value < total_debit {
            return ApplyResult::ClaimedCost("tecPATH_DRY");
        }
    }

    let outstanding = sle_uint64(&issuance_raw, 4);
    let maximum_amount = issuance_maximum_amount(&issuance_raw);

    let source_key = (!sender_is_issuer).then(|| mptoken_key(&issuance_key.0, &tx.account));
    let source_raw = match source_key.as_ref() {
        Some(key) => match state.get_raw(key) {
            Some(raw) => Some(raw.to_vec()),
            None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
        },
        None => None,
    };
    if let Some(raw) = source_raw.as_ref() {
        let flags = sle_flags(raw);
        if flags & LSF_MPT_LOCKED != 0 && !destination_is_issuer {
            return ApplyResult::ClaimedCost("tecLOCKED");
        }
        if issuance_flags & LSF_MPT_REQUIRE_AUTH != 0
            && flags & LSF_MPT_AUTHORIZED == 0
            && !destination_is_issuer
        {
            return ApplyResult::ClaimedCost("tecNO_AUTH");
        }
        if sle_uint64(raw, 26) < total_debit {
            return ApplyResult::ClaimedCost("tecUNFUNDED_PAYMENT");
        }
    }

    let destination_key = (!destination_is_issuer).then(|| mptoken_key(&issuance_key.0, &destination));
    let existing_destination_raw = match destination_key.as_ref() {
        Some(key) => state.get_raw(key).map(|raw| raw.to_vec()),
        None => None,
    };
    let create_destination_holder = !destination_is_issuer && existing_destination_raw.is_none();
    if create_destination_holder && state.get_account(&destination).is_none() {
        return ApplyResult::ClaimedCost("tecNO_DST");
    }
    if !destination_is_issuer {
        if issuance_flags & LSF_MPT_REQUIRE_AUTH != 0 {
            match existing_destination_raw.as_ref() {
                Some(raw) if sle_flags(raw) & LSF_MPT_AUTHORIZED != 0 => {}
                _ => return ApplyResult::ClaimedCost("tecNO_AUTH"),
            }
        }
        if let Some(raw) = existing_destination_raw.as_ref() {
            if sle_flags(raw) & LSF_MPT_LOCKED != 0 {
                return ApplyResult::ClaimedCost("tecLOCKED");
            }
        }
    }

    let new_outstanding = if sender_is_issuer && !destination_is_issuer {
        match outstanding.checked_add(deliver_value) {
            Some(value) if value <= maximum_amount => value,
            _ => return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED"),
        }
    } else if !sender_is_issuer && destination_is_issuer {
        outstanding.saturating_sub(deliver_value)
    } else if !sender_is_issuer && !destination_is_issuer {
        outstanding.saturating_sub(fee_value)
    } else {
        outstanding
    };

    if let (Some(source_key), Some(source_raw)) = (source_key.as_ref(), source_raw.as_ref()) {
        let source_amount = sle_uint64(source_raw, 26);
        state.insert_raw(
            *source_key,
            patch_uint64_fields(source_raw, &[(26, source_amount - total_debit)]),
        );
    }

    if let Some(destination_key) = destination_key.as_ref() {
        let destination_raw = if let Some(raw) = existing_destination_raw.as_ref() {
            raw.clone()
        } else {
            create_holder_token(
                state,
                &issuance_key,
                &mptid,
                &destination,
                0,
            )
        };
        let destination_amount = sle_uint64(&destination_raw, 26);
        state.insert_raw(
            *destination_key,
            patch_uint64_fields(&destination_raw, &[(26, destination_amount + deliver_value)]),
        );
    }

    if new_outstanding != outstanding {
        state.insert_raw(
            issuance_key,
            patch_uint64_fields(&issuance_raw, &[(4, new_outstanding)]),
        );
    }

    ApplyResult::Success
}

/// Apply MPT clawback through the existing Clawback transaction.
pub(crate) fn apply_mpt_clawback(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    let amount = match tx.amount.as_ref() {
        Some(amount) => amount,
        None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    let (requested, mptid) = match mpt_amount_parts(amount) {
        Some(parts) => parts,
        None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    if requested == 0 {
        return ApplyResult::ClaimedCost("temBAD_AMOUNT");
    }

    let holder = match tx.holder {
        Some(holder) => holder,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let issuer = mpt_issuer(&mptid);
    if tx.account != issuer || holder == issuer {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let issuance_key = mpt_issuance_key(&mptid);
    let issuance_raw = match state.get_raw(&issuance_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
    };
    if sle_flags(&issuance_raw) & LSF_MPT_CAN_CLAWBACK == 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let holder_key = mptoken_key(&issuance_key.0, &holder);
    let holder_raw = match state.get_raw(&holder_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
    };
    let holder_amount = sle_uint64(&holder_raw, 26);
    if holder_amount == 0 {
        return ApplyResult::ClaimedCost("tecUNFUNDED");
    }

    let clawed = requested.min(holder_amount);
    let outstanding = sle_uint64(&issuance_raw, 4);
    state.insert_raw(
        holder_key,
        patch_uint64_fields(&holder_raw, &[(26, holder_amount - clawed)]),
    );
    state.insert_raw(
        issuance_key,
        patch_uint64_fields(&issuance_raw, &[(4, outstanding.saturating_sub(clawed))]),
    );

    ApplyResult::Success
}

/// Type 54: MPTokenIssuanceCreate — create a new MPToken issuance.
///
/// Creates MPTokenIssuance SLE, adds to owner directory, increments owner_count.
/// Actual SLE content is handled by metadata/diff sync.
///
/// (rippled: MPTokenIssuanceCreate.cpp — doApply)
pub(crate) fn apply_mptoken_issuance_create(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    if let Some(transfer_fee) = tx.transfer_fee_field {
        if transfer_fee > MAX_TRANSFER_FEE {
            return ApplyResult::ClaimedCost("temBAD_TRANSFER_FEE");
        }
        if tx.flags & LSF_MPT_CAN_TRANSFER == 0 {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
    }

    let mptid = make_mptid(tx.sequence, &tx.account);
    let key = mpt_issuance_key(&mptid);

    // Add to owner directory
    directory::dir_add(state, &tx.account, key.0);

    state.insert_raw(key, build_mptoken_issuance_sle(tx));

    new_sender.owner_count += 1;

    ApplyResult::Success
}

/// Type 55: MPTokenIssuanceDestroy — destroy an MPToken issuance.
///
/// Removes MPTokenIssuance SLE, removes from owner directory, decrements owner_count.
///
/// (rippled: MPTokenIssuanceDestroy.cpp — doApply)
pub(crate) fn apply_mptoken_issuance_destroy(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let mptid = match &tx.mptoken_issuance_id {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = mpt_issuance_key(mptid);
    let issuer = mpt_issuer(mptid);
    if tx.account != issuer {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    // Verify issuance exists (rippled: MPTokenIssuanceDestroy.cpp — preclaim)
    let issuance_raw = match state.get_raw(&key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
    };
    if sle_uint64(&issuance_raw, 4) != 0 || sle_uint64(&issuance_raw, 25) != 0 {
        return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
    }

    // Remove from owner directory
    directory::dir_remove(state, &tx.account, &key.0);

    // Remove the SLE
    state.remove_raw(&key);

    new_sender.owner_count = new_sender.owner_count.saturating_sub(1);

    ApplyResult::Success
}

/// Type 56: MPTokenIssuanceSet — modify flags/metadata on an MPToken issuance or holder's MPToken.
///
/// No directory or owner_count changes. Actual SLE content handled by metadata.
///
/// (rippled: MPTokenIssuanceSet.cpp — doApply)
pub(crate) fn apply_mptoken_issuance_set(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    _new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    const TF_MPT_LOCK: u32 = 0x0000_0001;
    let mptid = match &tx.mptoken_issuance_id {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    if tx.account != mpt_issuer(mptid) {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    let key = mpt_issuance_key(mptid);
    let existing = match state.get_raw(&key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    let existing_flags = sle_flags(&existing);

    let mut replacements = Vec::new();
    if let Some(transfer_fee) = tx.transfer_fee_field {
        if transfer_fee > MAX_TRANSFER_FEE {
            return ApplyResult::ClaimedCost("temBAD_TRANSFER_FEE");
        }
        if existing_flags & LSF_MPT_CAN_TRANSFER == 0 {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
        replacements.push(crate::ledger::meta::ParsedField {
            type_code: 1,
            field_code: 4,
            data: transfer_fee.to_be_bytes().to_vec(),
        });
    }
    if let Some(domain_id) = tx.domain_id {
        replacements.push(crate::ledger::meta::ParsedField {
            type_code: 5,
            field_code: 34,
            data: domain_id.to_vec(),
        });
    }
    if let Some(metadata) = &tx.mptoken_metadata {
        replacements.push(crate::ledger::meta::ParsedField {
            type_code: 7,
            field_code: 30,
            data: metadata.clone(),
        });
    }
    if let Some(mutable_flags) = tx.mutable_flags {
        replacements.push(crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code: 53,
            data: mutable_flags.to_be_bytes().to_vec(),
        });
    }

    if tx.flags & TF_MPT_LOCK != 0 && tx.flags & TF_MPT_UNLOCK != 0 {
        return ApplyResult::ClaimedCost("temINVALID_FLAG");
    }
    let wants_lock_change = tx.flags & (TF_MPT_LOCK | TF_MPT_UNLOCK) != 0;
    if wants_lock_change && existing_flags & LSF_MPT_CAN_LOCK == 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let mut issuance_base = existing.clone();

    if let Some(holder) = tx.holder {
        let holder_key = mptoken_key(&key.0, &holder);
        let holder_raw = match state.get_raw(&holder_key) {
            Some(raw) => raw.to_vec(),
            None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
        };
        let mut holder_flags = sle_flags(&holder_raw);
        if tx.flags & TF_MPT_LOCK != 0 {
            holder_flags |= LSF_MPT_LOCKED;
        }
        if tx.flags & TF_MPT_UNLOCK != 0 {
            holder_flags &= !LSF_MPT_LOCKED;
        }
        if holder_flags != sle_flags(&holder_raw) {
            state.insert_raw(holder_key, patch_flags(&holder_raw, holder_flags));
        }
    } else if wants_lock_change {
        let mut issuance_flags = existing_flags;
        if tx.flags & TF_MPT_LOCK != 0 {
            issuance_flags |= LSF_MPT_LOCKED;
        }
        if tx.flags & TF_MPT_UNLOCK != 0 {
            issuance_flags &= !LSF_MPT_LOCKED;
        }
        if issuance_flags != existing_flags {
            issuance_base = patch_flags(&existing, issuance_flags);
        }
    }

    if replacements.is_empty() {
        if issuance_base != existing {
            state.insert_raw(key, issuance_base);
        }
        return if wants_lock_change {
            ApplyResult::Success
        } else {
            ApplyResult::ClaimedCost("temMALFORMED")
        };
    }

    let patched = crate::ledger::meta::patch_sle(&issuance_base, &replacements, None, None, &[]);
    state.insert_raw(key, patched);
    ApplyResult::Success
}

/// Type 57: MPTokenAuthorize — holder creates/destroys MPToken, or issuer authorizes holder.
///
/// When holder (no sfHolder field):
///   - Without tfMPTUnauthorize: create MPToken SLE, dir_add, owner_count++
///   - With tfMPTUnauthorize (0x01): destroy MPToken SLE, dir_remove, owner_count--
/// When issuer (sfHolder present):
///   - Sets/clears lsfMPTAuthorized flag on holder's MPToken (no directory changes)
///
/// (rippled: MPTokenAuthorize.cpp — doApply, authorizeMPToken)
pub(crate) fn apply_mptoken_authorize(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let mptid = match &tx.mptoken_issuance_id {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let issuance_key = mpt_issuance_key(mptid);
    let issuer = mpt_issuer(mptid);
    let issuance_raw = match state.get_raw(&issuance_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
    };
    let issuance_flags = sle_flags(&issuance_raw);

    if let Some(holder) = tx.holder {
        // ── Issuer path: authorize/unauthorize a holder ─────────────────
        if tx.account != issuer {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
        if issuance_flags & LSF_MPT_REQUIRE_AUTH == 0 {
            return ApplyResult::ClaimedCost("tefNO_AUTH_REQUIRED");
        }
        let holder_key = mptoken_key(&issuance_key.0, &holder);
        let existing = match state.get_raw(&holder_key) {
            Some(raw) => raw.to_vec(),
            None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
        };
        let flags = sle_flags(&existing);
        let new_flags = if tx.flags & TF_MPT_UNAUTHORIZE != 0 {
            flags & !LSF_MPT_AUTHORIZED
        } else {
            flags | LSF_MPT_AUTHORIZED
        };
        let patched = crate::ledger::meta::patch_sle(
            &existing,
            &[crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 2,
                data: new_flags.to_be_bytes().to_vec(),
            }],
            None,
            None,
            &[],
        );
        state.insert_raw(holder_key, patched);
        ApplyResult::Success
    } else {
        // ── Holder path: create or destroy own MPToken ──────────────────
        if tx.account == issuer {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
        let holder_key = mptoken_key(&issuance_key.0, &tx.account);

        if tx.flags & TF_MPT_UNAUTHORIZE != 0 {
            // Destroy MPToken
            let existing = match state.get_raw(&holder_key) {
                Some(raw) => raw.to_vec(),
                None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
            };
            if sle_uint64(&existing, 26) != 0 || sle_uint64(&existing, 4) != 0 {
                return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
            }
            directory::dir_remove(state, &tx.account, &holder_key.0);
            state.remove_raw(&holder_key);
            new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
        } else {
            // Create MPToken
            if state.get_raw(&holder_key).is_some() {
                return ApplyResult::ClaimedCost("tecDUPLICATE");
            }
            directory::dir_add(state, &tx.account, holder_key.0);
            state.insert_raw(holder_key, build_mptoken_sle(&tx.account, mptid, 0));
            new_sender.owner_count += 1;
        }

        ApplyResult::Success
    }
}
