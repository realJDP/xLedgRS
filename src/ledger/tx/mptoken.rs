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

use super::{balance_before_fee, owner_reserve_requirement, ApplyResult};

/// LedgerNameSpace::MPTOKEN_ISSUANCE = '~' = 0x7E.
const MPT_ISSUANCE_SPACE: [u8; 2] = [0x00, 0x7E];

/// LedgerNameSpace::MPTOKEN = 't' = 0x74.
const MPTOKEN_SPACE: [u8; 2] = [0x00, 0x74];

const DEFAULT_MAXIMUM_AMOUNT: u64 = 0x7FFF_FFFF_FFFF_FFFF;
const MAX_TRANSFER_FEE: u16 = 50_000;
const MAX_MPTOKEN_METADATA_LENGTH: usize = 1024;

const SF_OWNER_NODE: u16 = 4;
const SF_OUTSTANDING_AMOUNT: u16 = 25;
const SF_MPT_AMOUNT: u16 = 26;
const SF_LOCKED_AMOUNT: u16 = 29;

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
const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

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
            (field.type_code == type_code
                && field.field_code == field_code
                && field.data.len() >= 4)
                .then(|| {
                    u32::from_be_bytes([field.data[0], field.data[1], field.data[2], field.data[3]])
                })
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

pub(crate) fn can_debit_mpt_amount(
    state: &LedgerState,
    account: &[u8; 20],
    amount: &Amount,
) -> bool {
    let Some((value, mptid)) = mpt_amount_parts(amount) else {
        return false;
    };
    if value == 0 {
        return true;
    }

    let issuer = mpt_issuer(&mptid);
    if *account == issuer {
        return true;
    }

    let issuance_key = mpt_issuance_key(&mptid);
    let holder_key = mptoken_key(&issuance_key.0, account);
    state
        .get_raw_owned(&holder_key)
        .map(|raw| sle_uint64(&raw, SF_MPT_AMOUNT) >= value)
        .unwrap_or(false)
}

pub(crate) fn apply_mpt_amount_delta(
    state: &mut LedgerState,
    account: &[u8; 20],
    credit: bool,
    amount: &Amount,
) -> bool {
    let Some((value, mptid)) = mpt_amount_parts(amount) else {
        return false;
    };
    if value == 0 {
        return true;
    }

    let issuance_key = mpt_issuance_key(&mptid);
    let Some(issuance_raw) = state.get_raw_owned(&issuance_key) else {
        return false;
    };
    let issuer = mpt_issuer(&mptid);
    let outstanding = sle_uint64(&issuance_raw, SF_OUTSTANDING_AMOUNT);

    if *account == issuer {
        let next_outstanding = if credit {
            let Some(next) = outstanding.checked_sub(value) else {
                return false;
            };
            next
        } else {
            let maximum = issuance_maximum_amount(&issuance_raw);
            let Some(next) = outstanding.checked_add(value) else {
                return false;
            };
            if next > maximum {
                return false;
            }
            next
        };
        state.insert_raw(
            issuance_key,
            patch_uint64_fields(&issuance_raw, &[(SF_OUTSTANDING_AMOUNT, next_outstanding)]),
        );
        return true;
    }

    let holder_key = mptoken_key(&issuance_key.0, account);
    let holder_raw = match state.get_raw_owned(&holder_key) {
        Some(raw) => raw,
        None => return false,
    };
    let holder_amount = sle_uint64(&holder_raw, SF_MPT_AMOUNT);
    let next_holder_amount = if credit {
        let Some(next) = holder_amount.checked_add(value) else {
            return false;
        };
        next
    } else {
        if holder_amount < value {
            return false;
        }
        holder_amount - value
    };

    state.insert_raw(
        holder_key,
        patch_uint64_fields(&holder_raw, &[(SF_MPT_AMOUNT, next_holder_amount)]),
    );
    true
}

fn checked_transfer_fee(value: u64, fee: u16) -> Option<u64> {
    if value == 0 || fee == 0 {
        return Some(0);
    }
    let rounded = ((value as u128).saturating_mul(fee as u128) + 50_000) / 100_000;
    (rounded <= u64::MAX as u128).then_some(rounded as u64)
}

fn checked_transfer_debit(value: u64, fee: u16) -> Option<u64> {
    value.checked_add(checked_transfer_fee(value, fee)?)
}

fn divide_by_transfer_rate(source: u64, fee: u16) -> Option<u64> {
    if fee == 0 {
        return Some(source);
    }
    let rate = 100_000u128 + fee as u128;
    let mut deliver = ((source as u128).saturating_mul(100_000) + (rate / 2)) / rate;
    if deliver > u64::MAX as u128 {
        return None;
    }

    while deliver > 0 && checked_transfer_debit(deliver as u64, fee)? > source {
        deliver -= 1;
    }

    Some(deliver as u64)
}

fn build_mptoken_issuance_sle(tx: &ParsedTx, owner_node: u64) -> Vec<u8> {
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
            field_code: SF_OWNER_NODE,
            data: owner_node.to_be_bytes().to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 3,
            field_code: SF_OUTSTANDING_AMOUNT,
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

fn build_mptoken_sle(account: &[u8; 20], mptid: &[u8; 24], flags: u32, owner_node: u64) -> Vec<u8> {
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
                field_code: SF_MPT_AMOUNT,
                data: 0u64.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: SF_OWNER_NODE,
                data: owner_node.to_be_bytes().to_vec(),
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

/// Apply a direct MPT payment. MPTokensV1 only supports direct account-to-account
/// payments; pathfinding and cross-currency conversions are not available.
pub(crate) fn apply_direct_mpt_payment(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
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

    let holder_to_holder = !sender_is_issuer && !destination_is_issuer;

    if holder_to_holder && issuance_flags & LSF_MPT_LOCKED != 0 {
        return ApplyResult::ClaimedCost("tecLOCKED");
    }

    if holder_to_holder && issuance_flags & LSF_MPT_CAN_TRANSFER == 0 {
        return ApplyResult::ClaimedCost("tecNO_AUTH");
    }

    let transfer_fee = if holder_to_holder {
        issuance_transfer_fee(&issuance_raw)
    } else {
        0
    };

    let max_source_value = if let Some(send_max) = tx.send_max.as_ref() {
        let Some((value, send_max_id)) = mpt_amount_parts(send_max) else {
            return ApplyResult::ClaimedCost("temBAD_AMOUNT");
        };
        if send_max_id != mptid {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
        value
    } else {
        deliver_value
    };

    let mut actual_deliver = deliver_value;
    let mut total_debit = match checked_transfer_debit(actual_deliver, transfer_fee) {
        Some(value) => value,
        None => return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED"),
    };
    if total_debit > max_source_value {
        if tx.flags & TF_PARTIAL_PAYMENT == 0 {
            return ApplyResult::ClaimedCost("tecPATH_PARTIAL");
        }
        actual_deliver = match divide_by_transfer_rate(max_source_value, transfer_fee) {
            Some(value) if value > 0 => value,
            Some(_) => return ApplyResult::ClaimedCost("tecPATH_PARTIAL"),
            None => return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED"),
        };
        total_debit = match checked_transfer_debit(actual_deliver, transfer_fee) {
            Some(value) => value,
            None => return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED"),
        };
    }

    if let Some(deliver_min) = tx.deliver_min.as_ref() {
        let Some((deliver_min_value, deliver_min_id)) = mpt_amount_parts(deliver_min) else {
            return ApplyResult::ClaimedCost("temBAD_AMOUNT");
        };
        if deliver_min_id != mptid || actual_deliver < deliver_min_value {
            return ApplyResult::ClaimedCost("tecPATH_PARTIAL");
        }
    }

    let fee_value = match checked_transfer_fee(actual_deliver, transfer_fee) {
        Some(value) => value,
        None => return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED"),
    };

    let outstanding = sle_uint64(&issuance_raw, SF_OUTSTANDING_AMOUNT);
    let maximum_amount = issuance_maximum_amount(&issuance_raw);

    let source_key = (!sender_is_issuer).then(|| mptoken_key(&issuance_key.0, &tx.account));
    let source_raw = match source_key.as_ref() {
        Some(key) => match state.get_raw(key) {
            Some(raw) => Some(raw.to_vec()),
            None => return ApplyResult::ClaimedCost("tecNO_AUTH"),
        },
        None => None,
    };
    if let Some(raw) = source_raw.as_ref() {
        let flags = sle_flags(raw);
        if holder_to_holder && flags & LSF_MPT_LOCKED != 0 {
            return ApplyResult::ClaimedCost("tecLOCKED");
        }
        if issuance_flags & LSF_MPT_REQUIRE_AUTH != 0 && flags & LSF_MPT_AUTHORIZED == 0 {
            return ApplyResult::ClaimedCost("tecNO_AUTH");
        }
        if sle_uint64(raw, SF_MPT_AMOUNT) < total_debit {
            return ApplyResult::ClaimedCost("tecPATH_PARTIAL");
        }
    }

    let destination_key =
        (!destination_is_issuer).then(|| mptoken_key(&issuance_key.0, &destination));
    let existing_destination_raw = match destination_key.as_ref() {
        Some(key) => state.get_raw(key).map(|raw| raw.to_vec()),
        None => None,
    };
    if !destination_is_issuer {
        if existing_destination_raw.is_none() {
            return if state.get_account(&destination).is_none() {
                ApplyResult::ClaimedCost("tecNO_DST")
            } else {
                ApplyResult::ClaimedCost("tecNO_AUTH")
            };
        }
        if issuance_flags & LSF_MPT_REQUIRE_AUTH != 0 {
            match existing_destination_raw.as_ref() {
                Some(raw) if sle_flags(raw) & LSF_MPT_AUTHORIZED != 0 => {}
                _ => return ApplyResult::ClaimedCost("tecNO_AUTH"),
            }
        }
        if let Some(raw) = existing_destination_raw.as_ref() {
            if holder_to_holder && sle_flags(raw) & LSF_MPT_LOCKED != 0 {
                return ApplyResult::ClaimedCost("tecLOCKED");
            }
        }
    }

    let new_outstanding = if sender_is_issuer && !destination_is_issuer {
        match outstanding.checked_add(actual_deliver) {
            Some(value) if value <= maximum_amount => value,
            _ => return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED"),
        }
    } else if !sender_is_issuer && destination_is_issuer {
        match outstanding.checked_sub(actual_deliver) {
            Some(value) => value,
            None => return ApplyResult::ClaimedCost("tecINTERNAL"),
        }
    } else if !sender_is_issuer && !destination_is_issuer {
        match outstanding.checked_sub(fee_value) {
            Some(value) => value,
            None => return ApplyResult::ClaimedCost("tecINTERNAL"),
        }
    } else {
        outstanding
    };

    if let (Some(source_key), Some(source_raw)) = (source_key.as_ref(), source_raw.as_ref()) {
        let source_amount = sle_uint64(source_raw, SF_MPT_AMOUNT);
        state.insert_raw(
            *source_key,
            patch_uint64_fields(source_raw, &[(SF_MPT_AMOUNT, source_amount - total_debit)]),
        );
    }

    if let Some(destination_key) = destination_key.as_ref() {
        let Some(destination_raw) = existing_destination_raw.as_ref() else {
            return ApplyResult::ClaimedCost("tecNO_AUTH");
        };
        let destination_amount = sle_uint64(&destination_raw, SF_MPT_AMOUNT);
        let Some(next_destination_amount) = destination_amount.checked_add(actual_deliver) else {
            return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED");
        };
        state.insert_raw(
            *destination_key,
            patch_uint64_fields(destination_raw, &[(SF_MPT_AMOUNT, next_destination_amount)]),
        );
    }

    if new_outstanding != outstanding {
        state.insert_raw(
            issuance_key,
            patch_uint64_fields(&issuance_raw, &[(SF_OUTSTANDING_AMOUNT, new_outstanding)]),
        );
    }

    ApplyResult::Success
}

/// Apply MPT clawback through the existing Clawback transaction.
pub(crate) fn apply_mpt_clawback(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
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
    if tx.account == holder {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if holder == issuer {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if tx.account != issuer {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if state.get_account(&holder).is_none() || state.get_account(&tx.account).is_none() {
        return ApplyResult::ClaimedCost("terNO_ACCOUNT");
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
    let holder_amount = sle_uint64(&holder_raw, SF_MPT_AMOUNT);
    if holder_amount == 0 {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }

    let clawed = requested.min(holder_amount);
    let outstanding = sle_uint64(&issuance_raw, SF_OUTSTANDING_AMOUNT);
    if outstanding < clawed {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    }
    state.insert_raw(
        holder_key,
        patch_uint64_fields(&holder_raw, &[(SF_MPT_AMOUNT, holder_amount - clawed)]),
    );
    state.insert_raw(
        issuance_key,
        patch_uint64_fields(
            &issuance_raw,
            &[(SF_OUTSTANDING_AMOUNT, outstanding - clawed)],
        ),
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
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    if let Some(transfer_fee) = tx.transfer_fee_field {
        if transfer_fee > MAX_TRANSFER_FEE {
            return ApplyResult::ClaimedCost("temBAD_TRANSFER_FEE");
        }
        if transfer_fee > 0 && tx.flags & LSF_MPT_CAN_TRANSFER == 0 {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
    }
    if matches!(tx.maximum_amount, Some(0)) {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if let Some(maximum_amount) = tx.maximum_amount {
        if maximum_amount > DEFAULT_MAXIMUM_AMOUNT {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
    }
    if matches!(tx.mptoken_metadata.as_ref(), Some(metadata) if metadata.is_empty() || metadata.len() > MAX_MPTOKEN_METADATA_LENGTH)
    {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    let mptid = make_mptid(tx.sequence, &tx.account);
    let key = mpt_issuance_key(&mptid);

    let required = owner_reserve_requirement(state, new_sender.owner_count, 1);
    if balance_before_fee(new_sender.balance, tx.fee) < required {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
    }

    let owner_node = directory::dir_add(state, &tx.account, key.0);

    state.insert_raw(key, build_mptoken_issuance_sle(tx, owner_node));

    new_sender.owner_count += 1;

    ApplyResult::Success
}

/// Type 55: MPTokenIssuanceDestroy — destroy an MPToken issuance.
///
/// Removes MPTokenIssuance SLE, removes from owner directory, decrements owner_count.
///
/// (rippled: MPTokenIssuanceDestroy.cpp — doApply)
pub(crate) fn apply_mptoken_issuance_destroy(
    state: &mut LedgerState,
    tx: &ParsedTx,
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
    if sle_uint64(&issuance_raw, SF_OUTSTANDING_AMOUNT) != 0
        || sle_uint64(&issuance_raw, SF_LOCKED_AMOUNT) != 0
    {
        return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
    }

    let owner_node = sle_uint64(&issuance_raw, SF_OWNER_NODE);
    let owner_root = directory::owner_dir_key(&tx.account);
    directory::dir_remove_root_page(state, &owner_root, owner_node, &key.0);

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
    state: &mut LedgerState,
    tx: &ParsedTx,
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
        None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
    };
    let existing_flags = sle_flags(&existing);

    let mut replacements = Vec::new();
    if let Some(transfer_fee) = tx.transfer_fee_field {
        if transfer_fee > MAX_TRANSFER_FEE {
            return ApplyResult::ClaimedCost("temBAD_TRANSFER_FEE");
        }
        if transfer_fee > 0 && existing_flags & LSF_MPT_CAN_TRANSFER == 0 {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
        if transfer_fee > 0 {
            replacements.push(crate::ledger::meta::ParsedField {
                type_code: 1,
                field_code: 4,
                data: transfer_fee.to_be_bytes().to_vec(),
            });
        }
    }
    if let Some(domain_id) = tx.domain_id {
        replacements.push(crate::ledger::meta::ParsedField {
            type_code: 5,
            field_code: 34,
            data: domain_id.to_vec(),
        });
    }
    if let Some(metadata) = &tx.mptoken_metadata {
        if metadata.is_empty() || metadata.len() > MAX_MPTOKEN_METADATA_LENGTH {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
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
        if holder == tx.account {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
        if !replacements.is_empty()
            || tx.transfer_fee_field == Some(0)
            || tx.domain_id.is_some()
            || tx.mptoken_metadata.is_some()
            || tx.mutable_flags.is_some()
        {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
        if state.get_account(&holder).is_none() {
            return ApplyResult::ClaimedCost("tecNO_DST");
        }
        let holder_key = mptoken_key(&key.0, &holder);
        let holder_raw = match state.get_raw(&holder_key) {
            Some(raw) => raw.to_vec(),
            None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
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

    let deletes_transfer_fee = tx.transfer_fee_field == Some(0);

    if replacements.is_empty() && !deletes_transfer_fee {
        if issuance_base != existing {
            state.insert_raw(key, issuance_base);
        }
        return if wants_lock_change {
            ApplyResult::Success
        } else {
            ApplyResult::ClaimedCost("temMALFORMED")
        };
    }

    let deleted_fields = if deletes_transfer_fee {
        &[(1u16, 4u16)][..]
    } else {
        &[][..]
    };
    let patched =
        crate::ledger::meta::patch_sle(&issuance_base, &replacements, None, None, deleted_fields);
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
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let mptid = match &tx.mptoken_issuance_id {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    if matches!(tx.holder, Some(holder) if holder == tx.account) {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    let issuance_key = mpt_issuance_key(mptid);
    let issuer = mpt_issuer(mptid);
    let holder_key = mptoken_key(&issuance_key.0, &tx.account);

    if tx.holder.is_none() && (tx.flags & TF_MPT_UNAUTHORIZE) != 0 {
        let existing = match state.get_raw(&holder_key) {
            Some(raw) => raw.to_vec(),
            None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
        };
        if sle_uint64(&existing, SF_MPT_AMOUNT) != 0 || sle_uint64(&existing, SF_LOCKED_AMOUNT) != 0
        {
            if state.get_raw(&issuance_key).is_none() {
                return ApplyResult::ClaimedCost("tecINTERNAL");
            }
            return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
        }
        let owner_node = sle_uint64(&existing, SF_OWNER_NODE);
        let owner_root = directory::owner_dir_key(&tx.account);
        directory::dir_remove_root_page(state, &owner_root, owner_node, &holder_key.0);
        state.remove_raw(&holder_key);
        new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
        return ApplyResult::Success;
    }

    let issuance_raw = match state.get_raw(&issuance_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
    };
    let issuance_flags = sle_flags(&issuance_raw);

    if let Some(holder) = tx.holder {
        // ── Issuer path: authorize/unauthorize a holder ─────────────────
        if state.get_account(&holder).is_none() {
            return ApplyResult::ClaimedCost("tecNO_DST");
        }
        if tx.account != issuer {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
        if issuance_flags & LSF_MPT_REQUIRE_AUTH == 0 {
            return ApplyResult::ClaimedCost("tecNO_AUTH");
        }
        let holder_key = mptoken_key(&issuance_key.0, &holder);
        let existing = match state.get_raw(&holder_key) {
            Some(raw) => raw.to_vec(),
            None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
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
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }

        if tx.flags & TF_MPT_UNAUTHORIZE != 0 {
            // Destroy MPToken
            let existing = match state.get_raw(&holder_key) {
                Some(raw) => raw.to_vec(),
                None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
            };
            if sle_uint64(&existing, SF_MPT_AMOUNT) != 0
                || sle_uint64(&existing, SF_LOCKED_AMOUNT) != 0
            {
                return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
            }
            let owner_node = sle_uint64(&existing, SF_OWNER_NODE);
            let owner_root = directory::owner_dir_key(&tx.account);
            directory::dir_remove_root_page(state, &owner_root, owner_node, &holder_key.0);
            state.remove_raw(&holder_key);
            new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
        } else {
            // Create MPToken
            if state.get_raw(&holder_key).is_some() {
                return ApplyResult::ClaimedCost("tecDUPLICATE");
            }
            if new_sender.owner_count >= 2 {
                let required = owner_reserve_requirement(state, new_sender.owner_count, 1);
                if balance_before_fee(new_sender.balance, tx.fee) < required {
                    return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
                }
            }
            let owner_node = directory::dir_add(state, &tx.account, holder_key.0);
            state.insert_raw(
                holder_key,
                build_mptoken_sle(&tx.account, mptid, 0, owner_node),
            );
            new_sender.owner_count += 1;
        }

        ApplyResult::Success
    }
}
