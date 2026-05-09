//! Escrow — IMPLEMENTED
//!
//! Supports XRP escrows natively, IOU escrows via trust-line adjustments, and
//! MPT escrows via direct holder / issuance balance updates.

use super::{balance_before_fee, owner_reserve_requirement, ApplyResult};
use crate::crypto::sha512_first_half;
use crate::ledger::account::{
    LSF_ALLOW_TRUST_LINE_LOCKING, LSF_DEPOSIT_AUTH, LSF_REQUIRE_AUTH, LSF_REQUIRE_DEST_TAG,
};
use crate::ledger::directory;
use crate::ledger::Key;
use crate::ledger::LedgerState;
use crate::transaction::amount::{Currency, IouValue};
use crate::transaction::{Amount, ParsedTx};

const MPT_ISSUANCE_SPACE: [u8; 2] = [0x00, 0x7E];
const MPTOKEN_SPACE: [u8; 2] = [0x00, 0x74];
const LSF_MPT_LOCKED: u32 = 0x0000_0001;
const LSF_MPT_AUTHORIZED: u32 = 0x0000_0002;
const LSF_MPT_REQUIRE_AUTH: u32 = 0x0000_0004;
const LSF_MPT_CAN_ESCROW: u32 = 0x0000_0008;
const LSF_MPT_CAN_TRANSFER: u32 = 0x0000_0020;

const SF_OWNER_NODE: u16 = 4;
const SF_OUTSTANDING_AMOUNT: u16 = 25;
const SF_MPT_AMOUNT: u16 = 26;
const SF_LOCKED_AMOUNT: u16 = 29;

fn mpt_issuance_key(mptid: &[u8; 24]) -> Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&MPT_ISSUANCE_SPACE);
    data.extend_from_slice(mptid);
    Key(sha512_first_half(&data))
}

fn mptoken_key(issuance_key: &[u8; 32], holder: &[u8; 20]) -> Key {
    let mut data = Vec::with_capacity(54);
    data.extend_from_slice(&MPTOKEN_SPACE);
    data.extend_from_slice(issuance_key);
    data.extend_from_slice(holder);
    Key(sha512_first_half(&data))
}

fn has_deposit_preauth(state: &LedgerState, destination: &[u8; 20], sender: &[u8; 20]) -> bool {
    let key = crate::ledger::deposit_preauth::shamap_key(destination, sender);
    state.has_deposit_preauth(&key)
        || state.get_raw_owned(&key).is_some()
        || state.get_committed_raw_owned(&key).is_some()
}

fn remove_escrow_from_owner_dir(
    state: &mut LedgerState,
    owner: &[u8; 20],
    key: &Key,
    node: u64,
) -> ApplyResult {
    let root = directory::owner_dir_key(owner);
    if directory::dir_remove_root_page(state, &root, node, &key.0) {
        ApplyResult::Success
    } else if state.get_directory(&root).is_none()
        && state.get_raw(&root).is_none()
        && state.get_committed_raw_owned(&root).is_none()
    {
        ApplyResult::Success
    } else {
        ApplyResult::ClaimedCost("tefBAD_LEDGER")
    }
}

fn remove_escrow_directories(
    state: &mut LedgerState,
    key: &Key,
    escrow: &crate::ledger::Escrow,
) -> ApplyResult {
    let result = remove_escrow_from_owner_dir(state, &escrow.account, key, escrow.owner_node);
    if result != ApplyResult::Success {
        return result;
    }
    if escrow.destination != escrow.account {
        let result =
            remove_escrow_from_owner_dir(state, &escrow.destination, key, escrow.destination_node);
        if result != ApplyResult::Success {
            return result;
        }
    }
    ApplyResult::Success
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
                field_code: SF_MPT_AMOUNT,
                data: 0u64.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: SF_OWNER_NODE,
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

fn sle_uint64(raw: &[u8], field_code: u16) -> u64 {
    let Some(parsed) = crate::ledger::meta::parse_sle(raw) else {
        return 0;
    };
    for field in parsed.fields {
        if field.type_code == 3 && field.field_code == field_code && field.data.len() == 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&field.data[..8]);
            return u64::from_be_bytes(bytes);
        }
    }
    0
}

fn sle_flags(raw: &[u8]) -> u32 {
    let Some(parsed) = crate::ledger::meta::parse_sle(raw) else {
        return 0;
    };
    for field in parsed.fields {
        if field.type_code == 2 && field.field_code == 2 && field.data.len() == 4 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&field.data[..4]);
            return u32::from_be_bytes(bytes);
        }
    }
    0
}

fn patch_uint64_fields(raw: &[u8], fields: &[(u16, u64)]) -> Vec<u8> {
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

fn mpt_issuer(mptid: &[u8; 24]) -> [u8; 20] {
    let mut issuer = [0u8; 20];
    issuer.copy_from_slice(&mptid[4..24]);
    issuer
}

fn mpt_amount_parts(amount: &Amount) -> Option<(u64, [u8; 24])> {
    amount.mpt_parts()
}

fn trustline_auth_flag_for(line: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &line.low_account {
        crate::ledger::trustline::LSF_LOW_AUTH
    } else {
        crate::ledger::trustline::LSF_HIGH_AUTH
    }
}

fn trustline_freeze_flag_for(line: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &line.low_account {
        crate::ledger::trustline::LSF_LOW_FREEZE
    } else {
        crate::ledger::trustline::LSF_HIGH_FREEZE
    }
}

fn load_escrow_trustline(
    state: &mut LedgerState,
    account: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
) -> Option<crate::ledger::RippleState> {
    let key = crate::ledger::trustline::shamap_key(account, issuer, currency);
    if let Some(line) = state.get_trustline(&key) {
        return Some(line.clone());
    }
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    let decoded = crate::ledger::RippleState::decode_from_sle(&raw)?;
    state.hydrate_trustline(decoded.clone());
    Some(decoded)
}

fn escrow_iou_amount_preflight(amount: &Amount) -> Result<(), &'static str> {
    match amount {
        Amount::Iou {
            value, currency, ..
        } => {
            if !value.is_positive() {
                return Err("temBAD_AMOUNT");
            }
            if currency.is_bad_currency() {
                return Err("temBAD_CURRENCY");
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_iou_escrow_create_preclaim(
    state: &mut LedgerState,
    account: &[u8; 20],
    destination: &[u8; 20],
    value: &IouValue,
    currency: &Currency,
    issuer: &[u8; 20],
) -> Result<(), ApplyResult> {
    if issuer == account {
        return Err(ApplyResult::ClaimedCost("tecNO_PERMISSION"));
    }
    let issuer_account = match super::load_existing_account(state, issuer) {
        Some(account) => account,
        None => return Err(ApplyResult::ClaimedCost("tecNO_ISSUER")),
    };
    if (issuer_account.flags & LSF_ALLOW_TRUST_LINE_LOCKING) == 0 {
        return Err(ApplyResult::ClaimedCost("tecNO_PERMISSION"));
    }

    let sender_line = match load_escrow_trustline(state, account, issuer, currency) {
        Some(line) => line,
        None => return Err(ApplyResult::ClaimedCost("tecNO_LINE")),
    };
    if (issuer_account.flags & LSF_REQUIRE_AUTH) != 0 {
        if (sender_line.flags & trustline_auth_flag_for(&sender_line, account)) == 0 {
            return Err(ApplyResult::ClaimedCost("tecNO_AUTH"));
        }
        if destination != issuer {
            let Some(destination_line) =
                load_escrow_trustline(state, destination, issuer, currency)
            else {
                return Err(ApplyResult::ClaimedCost("tecNO_AUTH"));
            };
            if (destination_line.flags & trustline_auth_flag_for(&destination_line, destination))
                == 0
            {
                return Err(ApplyResult::ClaimedCost("tecNO_AUTH"));
            }
        }
    }
    if (sender_line.flags & trustline_freeze_flag_for(&sender_line, issuer)) != 0 {
        return Err(ApplyResult::ClaimedCost("tecFROZEN"));
    }
    if destination != issuer {
        if let Some(destination_line) = load_escrow_trustline(state, destination, issuer, currency)
        {
            if (destination_line.flags & trustline_freeze_flag_for(&destination_line, issuer)) != 0
            {
                return Err(ApplyResult::ClaimedCost("tecFROZEN"));
            }
        }
    }

    let spendable = sender_line.balance_for(account);
    if !spendable.is_positive()
        || super::flow::compare_iou_values(&spendable, value) == std::cmp::Ordering::Less
    {
        return Err(ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS"));
    }
    Ok(())
}

fn ensure_mpt_holder(
    state: &mut LedgerState,
    issuance_key: &Key,
    holder: &[u8; 20],
    mptid: &[u8; 24],
    require_auth: bool,
) -> Result<Vec<u8>, ApplyResult> {
    let holder_key = mptoken_key(&issuance_key.0, holder);
    if let Some(raw) = state.get_raw(&holder_key) {
        let raw = raw.to_vec();
        if require_auth && sle_flags(&raw) & LSF_MPT_AUTHORIZED == 0 {
            return Err(ApplyResult::ClaimedCost("tecNO_AUTH"));
        }
        return Ok(raw);
    }

    if require_auth {
        return Err(ApplyResult::ClaimedCost("tecNO_AUTH"));
    }

    if state.get_account(holder).is_none() {
        return Err(ApplyResult::ClaimedCost("tecNO_DST"));
    }

    directory::dir_add(state, holder, holder_key.0);
    let token_raw = build_mptoken_sle(holder, mptid, 0);
    state.insert_raw(holder_key, token_raw.clone());
    if let Some(account) = state.get_account(holder) {
        let mut account = account.clone();
        account.owner_count += 1;
        state.insert_account(account);
    }
    Ok(token_raw)
}

fn apply_mpt_escrow_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    destination: [u8; 20],
) -> ApplyResult {
    let Some(amount) = tx.amount.as_ref() else {
        return ApplyResult::ClaimedCost("temBAD_AMOUNT");
    };
    let Some((value, mptid)) = mpt_amount_parts(amount) else {
        return ApplyResult::ClaimedCost("temBAD_AMOUNT");
    };
    if value == 0 {
        return ApplyResult::ClaimedCost("temBAD_AMOUNT");
    }

    let issuer = mpt_issuer(&mptid);
    if tx.account == issuer {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let issuance_key = mpt_issuance_key(&mptid);
    let issuance_raw = match state.get_raw(&issuance_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
    };
    let issuance_flags = sle_flags(&issuance_raw);
    if issuance_flags & LSF_MPT_CAN_ESCROW == 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if destination != issuer && issuance_flags & LSF_MPT_CAN_TRANSFER == 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if issuance_flags & LSF_MPT_LOCKED != 0 {
        return ApplyResult::ClaimedCost("tecFROZEN");
    }

    let holder_key = mptoken_key(&issuance_key.0, &tx.account);
    let holder_raw = match state.get_raw(&holder_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
    };
    if sle_flags(&holder_raw) & LSF_MPT_LOCKED != 0 {
        return ApplyResult::ClaimedCost("tecFROZEN");
    }
    let holder_amount = sle_uint64(&holder_raw, SF_MPT_AMOUNT);
    if holder_amount < value {
        return ApplyResult::ClaimedCost("tecUNFUNDED");
    }
    let holder_locked = sle_uint64(&holder_raw, SF_LOCKED_AMOUNT);
    state.insert_raw(
        holder_key,
        patch_uint64_fields(
            &holder_raw,
            &[
                (SF_MPT_AMOUNT, holder_amount - value),
                (SF_LOCKED_AMOUNT, holder_locked + value),
            ],
        ),
    );

    let issuance_locked = sle_uint64(&issuance_raw, SF_LOCKED_AMOUNT);
    state.insert_raw(
        issuance_key,
        patch_uint64_fields(
            &issuance_raw,
            &[(SF_LOCKED_AMOUNT, issuance_locked + value)],
        ),
    );

    ApplyResult::Success
}

fn apply_mpt_escrow_finish(state: &mut LedgerState, escrow: &crate::ledger::Escrow) -> ApplyResult {
    let Some(amount) = escrow.held_amount.as_ref() else {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    };
    let Some((value, mptid)) = mpt_amount_parts(amount) else {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    };
    let issuer = mpt_issuer(&mptid);
    let issuance_key = mpt_issuance_key(&mptid);
    let issuance_raw = match state.get_raw(&issuance_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    let issuance_flags = sle_flags(&issuance_raw);
    if issuance_flags & LSF_MPT_LOCKED != 0 {
        return ApplyResult::ClaimedCost("tecFROZEN");
    }

    let owner_key = mptoken_key(&issuance_key.0, &escrow.account);
    let owner_raw = match state.get_raw(&owner_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    let owner_locked = sle_uint64(&owner_raw, SF_LOCKED_AMOUNT);
    if owner_locked < value {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    }
    state.insert_raw(
        owner_key,
        patch_uint64_fields(&owner_raw, &[(SF_LOCKED_AMOUNT, owner_locked - value)]),
    );

    let issuance_locked = sle_uint64(&issuance_raw, SF_LOCKED_AMOUNT);
    let issuance_outstanding = sle_uint64(&issuance_raw, SF_OUTSTANDING_AMOUNT);
    if issuance_locked < value {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    }

    if escrow.destination == issuer {
        state.insert_raw(
            issuance_key,
            patch_uint64_fields(
                &issuance_raw,
                &[
                    (SF_LOCKED_AMOUNT, issuance_locked - value),
                    (
                        SF_OUTSTANDING_AMOUNT,
                        issuance_outstanding.saturating_sub(value),
                    ),
                ],
            ),
        );
    } else {
        let require_auth = issuance_flags & LSF_MPT_REQUIRE_AUTH != 0;
        let dest_key = mptoken_key(&issuance_key.0, &escrow.destination);
        let dest_raw = match ensure_mpt_holder(
            state,
            &issuance_key,
            &escrow.destination,
            &mptid,
            require_auth,
        ) {
            Ok(raw) => raw,
            Err(err) => return err,
        };
        if sle_flags(&dest_raw) & LSF_MPT_LOCKED != 0 {
            return ApplyResult::ClaimedCost("tecFROZEN");
        }
        let dest_amount = sle_uint64(&dest_raw, SF_MPT_AMOUNT);
        state.insert_raw(
            dest_key,
            patch_uint64_fields(&dest_raw, &[(SF_MPT_AMOUNT, dest_amount + value)]),
        );
        state.insert_raw(
            issuance_key,
            patch_uint64_fields(
                &issuance_raw,
                &[(SF_LOCKED_AMOUNT, issuance_locked - value)],
            ),
        );
    }

    ApplyResult::Success
}

fn load_escrow_for_tx(state: &mut LedgerState, key: &Key) -> Option<crate::ledger::Escrow> {
    if let Some(escrow) = state.get_escrow(key) {
        return Some(escrow.clone());
    }

    let raw = state.get_raw_owned(key)?;
    let escrow = crate::ledger::Escrow::decode_from_sle(&raw)?;
    state.hydrate_escrow(escrow.clone());
    Some(escrow)
}

fn check_iou_escrow_finish_limit(
    state: &LedgerState,
    escrow: &crate::ledger::Escrow,
) -> Option<ApplyResult> {
    let Amount::Iou {
        value,
        currency,
        issuer,
    } = escrow.held_amount.as_ref()?
    else {
        return None;
    };

    if &escrow.destination == issuer {
        return None;
    }

    if state.get_account(&escrow.destination).is_none() {
        return Some(ApplyResult::ClaimedCost("tecNO_DST"));
    }

    let line_key = crate::ledger::trustline::shamap_key(&escrow.destination, issuer, currency);
    let line = match state
        .get_raw_owned(&line_key)
        .and_then(|raw| crate::ledger::RippleState::decode_from_sle(&raw))
        .or_else(|| state.get_trustline(&line_key).cloned())
    {
        Some(line) => line,
        None => return Some(ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED")),
    };

    let dest_balance = line.balance_for(&escrow.destination);
    let dest_limit = if escrow.destination == line.low_account {
        line.low_limit
    } else {
        line.high_limit
    };
    if dest_limit.sub(&dest_balance).sub(value).is_negative() {
        return Some(ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED"));
    }

    None
}

fn apply_mpt_escrow_cancel(state: &mut LedgerState, escrow: &crate::ledger::Escrow) -> ApplyResult {
    let Some(amount) = escrow.held_amount.as_ref() else {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    };
    let Some((value, mptid)) = mpt_amount_parts(amount) else {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    };

    let issuance_key = mpt_issuance_key(&mptid);
    let issuance_raw = match state.get_raw(&issuance_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    let holder_key = mptoken_key(&issuance_key.0, &escrow.account);
    let holder_raw = match state.get_raw(&holder_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    let holder_amount = sle_uint64(&holder_raw, SF_MPT_AMOUNT);
    let holder_locked = sle_uint64(&holder_raw, SF_LOCKED_AMOUNT);
    let issuance_locked = sle_uint64(&issuance_raw, SF_LOCKED_AMOUNT);
    if holder_locked < value || issuance_locked < value {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    }

    state.insert_raw(
        holder_key,
        patch_uint64_fields(
            &holder_raw,
            &[
                (SF_MPT_AMOUNT, holder_amount + value),
                (SF_LOCKED_AMOUNT, holder_locked - value),
            ],
        ),
    );
    state.insert_raw(
        issuance_key,
        patch_uint64_fields(
            &issuance_raw,
            &[(SF_LOCKED_AMOUNT, issuance_locked - value)],
        ),
    );

    ApplyResult::Success
}

/// Apply EscrowCreate: lock funds in a time-locked escrow object.
/// Supports XRP (native), IOU trust-line escrows, and MPT balance locking.
pub(crate) fn apply_escrow_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    close_time: u64,
) -> ApplyResult {
    let sequence = super::sequence_proxy(tx);
    let condition = crate::transaction::parse::parsed_condition(tx);
    // TokenEscrow: Amount can be XRP, IOU, or MPT.
    // For XRP: deduct from sender balance here.
    // For IOU: deduct from the sender's trust line.
    // For MPT: deduct from the holder balance and move into locked balance.
    let xrp_amount: Option<u64> = match (&tx.amount, tx.amount_drops) {
        (Some(Amount::Xrp(d)), _) if *d > 0 => Some(*d),
        (_, Some(d)) if d > 0 => Some(d),
        (Some(Amount::Iou { .. }), _) | (Some(Amount::Mpt { .. }), _) => None,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    if let Some(amount) = &tx.amount {
        if let Err(code) = escrow_iou_amount_preflight(amount) {
            return ApplyResult::ClaimedCost(code);
        }
    }
    let destination = match tx.destination {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };
    if tx.cancel_after.is_none() && tx.finish_after.is_none() {
        return ApplyResult::ClaimedCost("temBAD_EXPIRATION");
    }
    if tx.finish_after.is_none() && condition.is_none() {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if matches!((tx.cancel_after, tx.finish_after), (Some(cancel), Some(finish)) if cancel <= finish)
    {
        return ApplyResult::ClaimedCost("temBAD_EXPIRATION");
    }
    if let Some(condition) = condition.as_deref() {
        if crate::ledger::escrow::parse_preimage_sha256_condition(condition).is_none() {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
    }
    if matches!(tx.cancel_after, Some(cancel_after) if close_time as u32 > cancel_after)
        || matches!(tx.finish_after, Some(finish_after) if close_time as u32 > finish_after)
    {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    let destination_account = match super::load_existing_account(state, &destination) {
        Some(account) => account,
        None => return ApplyResult::ClaimedCost("tecNO_DST"),
    };
    if destination_account.sequence == 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if let Some(Amount::Iou {
        value,
        currency,
        issuer,
    }) = &tx.amount
    {
        if let Err(result) = validate_iou_escrow_create_preclaim(
            state,
            &tx.account,
            &destination,
            value,
            currency,
            issuer,
        ) {
            return result;
        }
    }
    if (destination_account.flags & LSF_REQUIRE_DEST_TAG) != 0 && tx.destination_tag.is_none() {
        return ApplyResult::ClaimedCost("tecDST_TAG_NEEDED");
    }

    let pre_fee_balance = balance_before_fee(new_sender.balance, tx.fee);
    let required = owner_reserve_requirement(state, new_sender.owner_count, 1);
    if pre_fee_balance < required {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
    }
    if let Some(drops) = xrp_amount {
        if pre_fee_balance < required.saturating_add(drops) {
            return ApplyResult::ClaimedCost("tecUNFUNDED");
        }
    }

    // Deduct the escrowed funds from sender
    if let Some(drops) = xrp_amount {
        new_sender.balance = new_sender.balance.saturating_sub(drops);
    } else if let Some(Amount::Iou {
        value,
        currency,
        issuer,
    }) = &tx.amount
    {
        // IOU escrow (TokenEscrow amendment): lock funds on sender's trust line
        let key = crate::ledger::trustline::shamap_key(&tx.account, issuer, currency);
        let mut tl = super::ripple_calc::load_or_create_trustline(
            state,
            &key,
            &tx.account,
            issuer,
            currency,
        );
        tl.transfer(&tx.account, value);
        state.insert_trustline(tl);
    } else if let Some(Amount::Mpt(_)) = &tx.amount {
        let result = apply_mpt_escrow_create(state, tx, destination);
        if result != ApplyResult::Success {
            return result;
        }
    }
    new_sender.owner_count += 1;

    let escrow_key = crate::ledger::escrow::shamap_key(&tx.account, sequence);
    let owner_node = directory::dir_add(state, &tx.account, escrow_key.0);
    // Also add to destination's directory (rippled EscrowCreate.cpp:462)
    let destination_node = if destination != tx.account {
        directory::dir_add(state, &destination, escrow_key.0)
    } else {
        0
    };
    let escrow = crate::ledger::Escrow {
        account: tx.account,
        destination,
        amount: xrp_amount.unwrap_or(0),
        held_amount: tx
            .amount
            .clone()
            .filter(|amount| !matches!(amount, Amount::Xrp(_))),
        sequence,
        finish_after: tx.finish_after.unwrap_or(0),
        cancel_after: tx.cancel_after.unwrap_or(0),
        condition,
        owner_node,
        destination_node,
        source_tag: crate::transaction::parse::parsed_source_tag(tx),
        destination_tag: tx.destination_tag,
        raw_sle: None,
    };
    state.insert_escrow(escrow);

    ApplyResult::Success
}

/// Apply EscrowFinish: release escrowed funds to the destination.
/// XRP credit is handled here directly. IOU finish still relies on
/// authoritative metadata, while MPT finish updates holder/issuance state.
pub(crate) fn apply_escrow_finish(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    if let Some(code) = super::credential::check_credential_id_fields(tx) {
        return ApplyResult::ClaimedCost(code);
    }
    if let Err(code) = super::credential::validate_credential_ids(state, &tx.account, tx) {
        return ApplyResult::ClaimedCost(code);
    }
    if super::credential::remove_expired_credential_ids(state, tx, close_time) {
        return ApplyResult::ClaimedCost("tecEXPIRED");
    }
    let tx_condition = crate::transaction::parse::parsed_condition(tx);
    let tx_fulfillment = crate::transaction::parse::parsed_fulfillment(tx);
    if tx_condition.is_some() != tx_fulfillment.is_some() {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    let escrow_seq = match tx.offer_sequence {
        Some(s) => s,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let owner = tx.owner.unwrap_or(tx.account);

    let key = crate::ledger::escrow::shamap_key(&owner, escrow_seq);
    let escrow = match load_escrow_for_tx(state, &key) {
        Some(e) => e,
        None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // Check finish_after time condition
    if escrow.finish_after > 0 && (close_time as u32) <= escrow.finish_after {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if escrow.cancel_after > 0 && (close_time as u32) > escrow.cancel_after {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    match (&escrow.condition, &tx_condition, &tx_fulfillment) {
        (Some(escrow_condition), Some(tx_condition), Some(fulfillment)) => {
            if escrow_condition != tx_condition
                || !crate::ledger::escrow::validate_preimage_sha256_fulfillment(
                    fulfillment,
                    tx_condition,
                )
            {
                return ApplyResult::ClaimedCost("tecCRYPTOCONDITION_ERROR");
            }
        }
        (Some(_), _, _) | (None, Some(_), _) => {
            return ApplyResult::ClaimedCost("tecCRYPTOCONDITION_ERROR");
        }
        (None, None, None) => {}
        (None, None, Some(_)) => {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
    }

    if let Some(result) = check_iou_escrow_finish_limit(state, &escrow) {
        return result;
    }
    if let Some(destination) = state.get_account(&escrow.destination) {
        if destination.flags & LSF_DEPOSIT_AUTH != 0
            && tx.account != escrow.destination
            && !has_deposit_preauth(state, &escrow.destination, &tx.account)
            && match super::credential::credential_deposit_preauth_authorized(
                state,
                &escrow.destination,
                &tx.account,
                tx,
                close_time,
            ) {
                Ok(authorized) => !authorized,
                Err(code) => return ApplyResult::ClaimedCost(code),
            }
        {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
    } else if escrow.amount > 0 {
        return ApplyResult::ClaimedCost("tecNO_DST");
    }

    if matches!(escrow.held_amount, Some(Amount::Mpt(_))) {
        let result = apply_mpt_escrow_finish(state, &escrow);
        if result != ApplyResult::Success {
            return result;
        }
    }

    // Credit destination with XRP (IOU finish still handled by metadata patches)
    if escrow.amount > 0 {
        if let Some(dest) = state.get_account(&escrow.destination) {
            let mut dest = dest.clone();
            dest.balance = dest.balance.saturating_add(escrow.amount);
            state.insert_account(dest);
        } else {
            // Create destination account if it doesn't exist
            state.insert_account(crate::ledger::AccountRoot {
                account_id: escrow.destination,
                balance: escrow.amount,
                sequence: 1,
                owner_count: 0,
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
            });
        }
    }

    let result = remove_escrow_directories(state, &key, &escrow);
    if result != ApplyResult::Success {
        return result;
    }

    // Remove escrow and decrement owner's owner_count
    state.remove_escrow(&key);
    if let Some(owner_acct) = state.get_account(&escrow.account) {
        let mut owner_acct = owner_acct.clone();
        owner_acct.owner_count = owner_acct.owner_count.saturating_sub(1);
        state.insert_account(owner_acct);
    }

    ApplyResult::Success
}

/// Apply EscrowCancel: return escrowed funds to the sender.
/// XRP refund is handled here directly. IOU cancel still relies on
/// authoritative metadata, while MPT cancel unlocks the holder balance.
pub(crate) fn apply_escrow_cancel(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    let escrow_seq = match tx.offer_sequence {
        Some(s) => s,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let owner = tx.owner.unwrap_or(tx.account);

    let key = crate::ledger::escrow::shamap_key(&owner, escrow_seq);
    let escrow = match load_escrow_for_tx(state, &key) {
        Some(e) => e,
        None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // rippled EscrowCancel requires CancelAfter and a close time strictly after it.
    if escrow.cancel_after == 0 || (close_time as u32) <= escrow.cancel_after {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    if matches!(escrow.held_amount, Some(Amount::Mpt(_))) {
        let result = apply_mpt_escrow_cancel(state, &escrow);
        if result != ApplyResult::Success {
            return result;
        }
    }

    let result = remove_escrow_directories(state, &key, &escrow);
    if result != ApplyResult::Success {
        return result;
    }

    // Refund the escrow creator (XRP only; IOU cancel still handled by metadata patches)
    if let Some(creator) = state.get_account(&escrow.account) {
        let mut creator = creator.clone();
        if escrow.amount > 0 {
            creator.balance = creator.balance.saturating_add(escrow.amount);
        }
        creator.owner_count = creator.owner_count.saturating_sub(1);
        state.insert_account(creator);
    }

    state.remove_escrow(&key);

    ApplyResult::Success
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn preimage_condition(preimage: &[u8]) -> Vec<u8> {
        let fingerprint = crate::crypto::sha256(preimage);
        let cost = preimage.len() as u8;
        let mut out = vec![0xa0, 37, 0x80, 32];
        out.extend_from_slice(&fingerprint);
        out.extend_from_slice(&[0x81, 1, cost]);
        out
    }

    fn preimage_condition_with_cost(preimage: &[u8], cost: u32) -> Vec<u8> {
        let fingerprint = crate::crypto::sha256(preimage);
        let cost_bytes = if cost < 0x80 {
            vec![cost as u8]
        } else {
            vec![0, cost as u8]
        };
        let mut out = vec![0xa0, (36 + cost_bytes.len()) as u8, 0x80, 32];
        out.extend_from_slice(&fingerprint);
        out.push(0x81);
        out.push(cost_bytes.len() as u8);
        out.extend_from_slice(&cost_bytes);
        out
    }

    fn preimage_fulfillment(preimage: &[u8]) -> Vec<u8> {
        let mut out = vec![0xa0, (preimage.len() + 2) as u8, 0x80, preimage.len() as u8];
        out.extend_from_slice(preimage);
        out
    }

    fn account(id: [u8; 20]) -> crate::ledger::AccountRoot {
        crate::ledger::AccountRoot {
            account_id: id,
            balance: 10_000_000,
            sequence: 1,
            owner_count: 0,
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

    fn insert_owner_dir_page(
        state: &mut LedgerState,
        owner: &[u8; 20],
        page_num: u64,
        indexes: Vec<[u8; 32]>,
    ) {
        let root = directory::owner_dir_key(owner);
        let mut dir = if page_num == 0 {
            directory::DirectoryNode::new_owner_root(owner)
        } else {
            directory::DirectoryNode::new_page(&root.0, page_num, Some(*owner))
        };
        dir.indexes = indexes;
        state.insert_directory(dir);
    }

    fn build_issuance(account: &[u8; 20], sequence: u32, flags: u32) -> ([u8; 24], Key, Vec<u8>) {
        let mut mptid = [0u8; 24];
        mptid[..4].copy_from_slice(&sequence.to_be_bytes());
        mptid[4..].copy_from_slice(account);
        let key = mpt_issuance_key(&mptid);
        let raw = crate::ledger::meta::build_sle(
            0x007e,
            &[
                crate::ledger::meta::ParsedField {
                    type_code: 8,
                    field_code: 4,
                    data: account.to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 2,
                    field_code: 4,
                    data: sequence.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 3,
                    field_code: SF_OWNER_NODE,
                    data: 0u64.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 3,
                    field_code: SF_OUTSTANDING_AMOUNT,
                    data: 500u64.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 3,
                    field_code: SF_LOCKED_AMOUNT,
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
        );
        (mptid, key, raw)
    }

    fn holder_raw(
        holder: &[u8; 20],
        mptid: &[u8; 24],
        amount: u64,
        locked: u64,
        flags: u32,
    ) -> Vec<u8> {
        let issuance_key = mpt_issuance_key(mptid);
        let raw = build_mptoken_sle(holder, mptid, flags);
        let raw = patch_uint64_fields(&raw, &[(SF_MPT_AMOUNT, amount), (SF_LOCKED_AMOUNT, locked)]);
        let key = mptoken_key(&issuance_key.0, holder);
        let _ = key;
        raw
    }

    fn iou(currency: crate::transaction::amount::Currency, issuer: [u8; 20], value: f64) -> Amount {
        Amount::Iou {
            value: crate::transaction::amount::IouValue::from_f64(value),
            currency,
            issuer,
        }
    }

    fn insert_iou_escrow(
        state: &mut LedgerState,
        owner: [u8; 20],
        dest: [u8; 20],
        issuer: [u8; 20],
        currency: crate::transaction::amount::Currency,
        value: f64,
        sequence: u32,
    ) -> Key {
        let escrow = crate::ledger::Escrow {
            account: owner,
            destination: dest,
            amount: 0,
            held_amount: Some(iou(currency, issuer, value)),
            sequence,
            finish_after: 0,
            cancel_after: 0,
            condition: None,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };
        let key = escrow.key();
        state.insert_escrow(escrow);
        key
    }

    #[test]
    fn escrow_create_locks_mpt_balance() {
        let issuer = acct(9);
        let owner = acct(1);
        let dest = acct(2);
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));

        let (mptid, issuance_key, issuance_raw) =
            build_issuance(&issuer, 77, LSF_MPT_CAN_ESCROW | LSF_MPT_CAN_TRANSFER);
        state.insert_raw(issuance_key, issuance_raw);
        let holder_key = mptoken_key(&mpt_issuance_key(&mptid).0, &owner);
        state.insert_raw(holder_key, holder_raw(&owner, &mptid, 100, 0, 0));

        let tx = ParsedTx {
            account: owner,
            destination: Some(dest),
            sequence: 5,
            cancel_after: Some(100),
            finish_after: Some(50),
            amount: Some(Amount::from_mpt_value(40, mptid)),
            ..Default::default()
        };
        let mut sender = account(owner);
        let result = apply_escrow_create(&mut state, &tx, &mut sender, 1);
        assert_eq!(result, ApplyResult::Success);

        let holder = state.get_raw_owned(&holder_key).unwrap();
        assert_eq!(sle_uint64(&holder, SF_MPT_AMOUNT), 60);
        assert_eq!(sle_uint64(&holder, SF_LOCKED_AMOUNT), 40);

        let issuance = state.get_raw_owned(&mpt_issuance_key(&mptid)).unwrap();
        assert_eq!(sle_uint64(&issuance, SF_LOCKED_AMOUNT), 40);

        let escrow_key = crate::ledger::escrow::shamap_key(&owner, 5);
        let escrow = state.get_escrow(&escrow_key).unwrap();
        assert_eq!(
            escrow.held_amount.as_ref().and_then(Amount::mpt_parts),
            Some((40, mptid))
        );
    }

    #[test]
    fn escrow_create_stores_valid_condition() {
        let owner = acct(1);
        let dest = acct(2);
        let condition = preimage_condition(b"release");
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));
        crate::transaction::parse::remember_escrow_crypto_for_test(
            [1u8; 32],
            Some(condition.clone()),
            None,
        );

        let tx = ParsedTx {
            tx_id: [1u8; 32],
            account: owner,
            destination: Some(dest),
            sequence: 5,
            cancel_after: Some(100),
            amount: Some(Amount::Xrp(1_000)),
            amount_drops: Some(1_000),
            ..Default::default()
        };
        let mut sender = account(owner);
        let result = apply_escrow_create(&mut state, &tx, &mut sender, 1);

        assert_eq!(result, ApplyResult::Success);
        let escrow_key = crate::ledger::escrow::shamap_key(&owner, 5);
        let escrow = state.get_escrow(&escrow_key).unwrap();
        assert_eq!(escrow.condition, Some(condition));
    }

    #[test]
    fn escrow_create_rejects_cancel_only_without_condition() {
        let owner = acct(1);
        let dest = acct(2);
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));

        let tx = ParsedTx {
            account: owner,
            destination: Some(dest),
            sequence: 5,
            cancel_after: Some(100),
            amount: Some(Amount::Xrp(1_000)),
            amount_drops: Some(1_000),
            ..Default::default()
        };
        let mut sender = account(owner);

        assert_eq!(
            apply_escrow_create(&mut state, &tx, &mut sender, 1),
            ApplyResult::ClaimedCost("temMALFORMED")
        );
    }

    #[test]
    fn escrow_create_rejects_malformed_condition() {
        let owner = acct(1);
        let dest = acct(2);
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));
        crate::transaction::parse::remember_escrow_crypto_for_test(
            [2u8; 32],
            Some(vec![0xa0, 0x01, 0x00]),
            None,
        );

        let tx = ParsedTx {
            tx_id: [2u8; 32],
            account: owner,
            destination: Some(dest),
            sequence: 5,
            finish_after: Some(50),
            amount: Some(Amount::Xrp(1_000)),
            amount_drops: Some(1_000),
            ..Default::default()
        };
        let mut sender = account(owner);

        assert_eq!(
            apply_escrow_create(&mut state, &tx, &mut sender, 1),
            ApplyResult::ClaimedCost("temMALFORMED")
        );
    }

    #[test]
    fn escrow_create_rejects_preimage_condition_over_rippled_cost_limit() {
        let owner = acct(1);
        let dest = acct(2);
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));
        crate::transaction::parse::remember_escrow_crypto_for_test(
            [9u8; 32],
            Some(preimage_condition_with_cost(b"release", 129)),
            None,
        );

        let tx = ParsedTx {
            tx_id: [9u8; 32],
            account: owner,
            destination: Some(dest),
            sequence: 5,
            finish_after: Some(50),
            amount: Some(Amount::Xrp(1_000)),
            amount_drops: Some(1_000),
            ..Default::default()
        };
        let mut sender = account(owner);

        assert_eq!(
            apply_escrow_create(&mut state, &tx, &mut sender, 1),
            ApplyResult::ClaimedCost("temMALFORMED")
        );
    }

    #[test]
    fn escrow_finish_moves_mpt_to_destination() {
        let issuer = acct(9);
        let owner = acct(1);
        let dest = acct(2);
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));

        let (mptid, issuance_key, issuance_raw) =
            build_issuance(&issuer, 88, LSF_MPT_CAN_ESCROW | LSF_MPT_CAN_TRANSFER);
        state.insert_raw(
            issuance_key,
            patch_uint64_fields(&issuance_raw, &[(SF_LOCKED_AMOUNT, 40)]),
        );
        let owner_key = mptoken_key(&mpt_issuance_key(&mptid).0, &owner);
        state.insert_raw(owner_key, holder_raw(&owner, &mptid, 60, 40, 0));
        let dest_key = mptoken_key(&mpt_issuance_key(&mptid).0, &dest);
        state.insert_raw(dest_key, holder_raw(&dest, &mptid, 10, 0, 0));
        state.insert_escrow(crate::ledger::Escrow {
            account: owner,
            destination: dest,
            amount: 0,
            held_amount: Some(Amount::from_mpt_value(40, mptid)),
            sequence: 5,
            finish_after: 0,
            cancel_after: 0,
            condition: None,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        });

        let tx = ParsedTx {
            account: dest,
            owner: Some(owner),
            offer_sequence: Some(5),
            ..Default::default()
        };
        let result = apply_escrow_finish(&mut state, &tx, 10);
        assert_eq!(result, ApplyResult::Success);

        let owner = state.get_raw_owned(&owner_key).unwrap();
        assert_eq!(sle_uint64(&owner, SF_LOCKED_AMOUNT), 0);
        let dest = state.get_raw_owned(&dest_key).unwrap();
        assert_eq!(sle_uint64(&dest, SF_MPT_AMOUNT), 50);
        let issuance = state.get_raw_owned(&mpt_issuance_key(&mptid)).unwrap();
        assert_eq!(sle_uint64(&issuance, SF_LOCKED_AMOUNT), 0);
    }

    #[test]
    fn escrow_cancel_uses_owner_node_hint_with_duplicate_directory_entry() {
        let owner = acct(1);
        let dest = owner;
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        let escrow = crate::ledger::Escrow {
            account: owner,
            destination: dest,
            amount: 1_000,
            held_amount: None,
            sequence: 7,
            finish_after: 0,
            cancel_after: 9,
            condition: None,
            owner_node: 1,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };
        let key = escrow.key();
        state.insert_escrow(escrow);

        let root = directory::owner_dir_key(&owner);
        let mut root_dir = directory::DirectoryNode::new_owner_root(&owner);
        root_dir.indexes.push(key.0);
        root_dir.index_next = 1;
        root_dir.index_previous = 1;
        state.insert_directory(root_dir);
        insert_owner_dir_page(&mut state, &owner, 1, vec![key.0]);

        let tx = ParsedTx {
            account: owner,
            offer_sequence: Some(7),
            ..Default::default()
        };
        assert_eq!(
            apply_escrow_cancel(&mut state, &tx, 10),
            ApplyResult::Success
        );

        assert!(state.get_escrow(&key).is_none());
        assert!(directory::load_directory_fresh(&state, &root)
            .unwrap()
            .indexes
            .contains(&key.0));
        assert!(
            directory::load_directory_fresh(&state, &directory::page_key(&root.0, 1)).is_none()
        );
    }

    #[test]
    fn escrow_cancel_rejects_stale_owner_node_hint_as_bad_ledger() {
        let owner = acct(1);
        let dest = owner;
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        let escrow = crate::ledger::Escrow {
            account: owner,
            destination: dest,
            amount: 1_000,
            held_amount: None,
            sequence: 7,
            finish_after: 0,
            cancel_after: 9,
            condition: None,
            owner_node: 1,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };
        let key = escrow.key();
        state.insert_escrow(escrow);
        insert_owner_dir_page(&mut state, &owner, 0, vec![key.0]);

        let tx = ParsedTx {
            account: owner,
            offer_sequence: Some(7),
            ..Default::default()
        };
        assert_eq!(
            apply_escrow_cancel(&mut state, &tx, 10),
            ApplyResult::ClaimedCost("tefBAD_LEDGER")
        );
        assert!(state.get_escrow(&key).is_some());
    }

    #[test]
    fn escrow_finish_hydrates_raw_escrow_before_target_check() {
        let owner = acct(1);
        let dest = acct(2);
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));

        let escrow = crate::ledger::Escrow {
            account: owner,
            destination: dest,
            amount: 1_000,
            held_amount: Some(Amount::Xrp(1_000)),
            sequence: 7,
            finish_after: 0,
            cancel_after: 0,
            condition: None,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };
        let key = escrow.key();
        state.insert_raw(key, escrow.to_sle_binary());

        let tx = ParsedTx {
            account: dest,
            owner: Some(owner),
            offer_sequence: Some(7),
            ..Default::default()
        };
        let result = apply_escrow_finish(&mut state, &tx, 10);
        assert_eq!(result, ApplyResult::Success);
        assert!(state.get_escrow(&key).is_none());
        assert!(state.get_raw_owned(&key).is_none());
    }

    #[test]
    fn escrow_finish_requires_matching_fulfillment_for_condition() {
        let owner = acct(1);
        let dest = acct(2);
        let condition = preimage_condition(b"secret");
        let fulfillment = preimage_fulfillment(b"secret");
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));
        state.insert_escrow(crate::ledger::Escrow {
            account: owner,
            destination: dest,
            amount: 1_000,
            held_amount: Some(Amount::Xrp(1_000)),
            sequence: 7,
            finish_after: 0,
            cancel_after: 100,
            condition: Some(condition.clone()),
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        });

        let missing = ParsedTx {
            account: dest,
            owner: Some(owner),
            offer_sequence: Some(7),
            ..Default::default()
        };
        assert_eq!(
            apply_escrow_finish(&mut state, &missing, 10),
            ApplyResult::ClaimedCost("tecCRYPTOCONDITION_ERROR")
        );

        let wrong = ParsedTx {
            tx_id: [3u8; 32],
            account: dest,
            owner: Some(owner),
            offer_sequence: Some(7),
            ..Default::default()
        };
        crate::transaction::parse::remember_escrow_crypto_for_test(
            wrong.tx_id,
            Some(condition.clone()),
            Some(preimage_fulfillment(b"wrong")),
        );
        assert_eq!(
            apply_escrow_finish(&mut state, &wrong, 10),
            ApplyResult::ClaimedCost("tecCRYPTOCONDITION_ERROR")
        );

        let valid = ParsedTx {
            tx_id: [4u8; 32],
            account: dest,
            owner: Some(owner),
            offer_sequence: Some(7),
            ..Default::default()
        };
        crate::transaction::parse::remember_escrow_crypto_for_test(
            valid.tx_id,
            Some(condition),
            Some(fulfillment),
        );
        assert_eq!(
            apply_escrow_finish(&mut state, &valid, 10),
            ApplyResult::Success
        );
    }

    #[test]
    fn escrow_finish_rejects_preimage_condition_cost_mismatch() {
        let owner = acct(1);
        let dest = acct(2);
        let condition = preimage_condition_with_cost(b"secret", 7);
        let fulfillment = preimage_fulfillment(b"secret");
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));
        state.insert_escrow(crate::ledger::Escrow {
            account: owner,
            destination: dest,
            amount: 1_000,
            held_amount: Some(Amount::Xrp(1_000)),
            sequence: 17,
            finish_after: 0,
            cancel_after: 100,
            condition: Some(condition.clone()),
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        });

        let tx = ParsedTx {
            tx_id: [7u8; 32],
            account: dest,
            owner: Some(owner),
            offer_sequence: Some(17),
            ..Default::default()
        };
        crate::transaction::parse::remember_escrow_crypto_for_test(
            tx.tx_id,
            Some(condition),
            Some(fulfillment),
        );

        assert_eq!(
            apply_escrow_finish(&mut state, &tx, 10),
            ApplyResult::ClaimedCost("tecCRYPTOCONDITION_ERROR")
        );
    }

    #[test]
    fn escrow_finish_rejects_expired_condition() {
        let owner = acct(1);
        let dest = acct(2);
        let condition = preimage_condition(b"secret");
        let fulfillment = preimage_fulfillment(b"secret");
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));
        state.insert_escrow(crate::ledger::Escrow {
            account: owner,
            destination: dest,
            amount: 1_000,
            held_amount: Some(Amount::Xrp(1_000)),
            sequence: 8,
            finish_after: 0,
            cancel_after: 10,
            condition: Some(condition.clone()),
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        });

        let tx = ParsedTx {
            tx_id: [5u8; 32],
            account: dest,
            owner: Some(owner),
            offer_sequence: Some(8),
            ..Default::default()
        };
        crate::transaction::parse::remember_escrow_crypto_for_test(
            tx.tx_id,
            Some(condition),
            Some(fulfillment),
        );

        assert_eq!(
            apply_escrow_finish(&mut state, &tx, 11),
            ApplyResult::ClaimedCost("tecNO_PERMISSION")
        );
    }

    #[test]
    fn escrow_finish_iou_fails_when_destination_line_missing() {
        let issuer = acct(9);
        let owner = acct(1);
        let dest = acct(2);
        let currency = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));

        let key = insert_iou_escrow(&mut state, owner, dest, issuer, currency, 10.0, 8);
        let tx = ParsedTx {
            account: dest,
            owner: Some(owner),
            offer_sequence: Some(8),
            ..Default::default()
        };

        let result = apply_escrow_finish(&mut state, &tx, 10);
        assert_eq!(result, ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED"));
        assert!(state.get_escrow(&key).is_some());
    }

    #[test]
    fn escrow_finish_iou_fails_when_destination_limit_is_too_low() {
        let issuer = acct(9);
        let owner = acct(1);
        let dest = acct(2);
        let currency = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));

        let mut line = crate::ledger::RippleState::new(&dest, &issuer, currency.clone());
        line.set_limit_for(&dest, crate::transaction::amount::IouValue::from_f64(5.0));
        state.insert_trustline(line);

        let key = insert_iou_escrow(&mut state, owner, dest, issuer, currency, 10.0, 9);
        let tx = ParsedTx {
            account: dest,
            owner: Some(owner),
            offer_sequence: Some(9),
            ..Default::default()
        };

        let result = apply_escrow_finish(&mut state, &tx, 10);
        assert_eq!(result, ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED"));
        assert!(state.get_escrow(&key).is_some());
    }

    #[test]
    fn escrow_cancel_unlocks_mpt_balance_back_to_owner() {
        let issuer = acct(9);
        let owner = acct(1);
        let dest = acct(2);
        let mut state = LedgerState::new();
        state.insert_account(account(owner));
        state.insert_account(account(dest));

        let (mptid, issuance_key, issuance_raw) =
            build_issuance(&issuer, 99, LSF_MPT_CAN_ESCROW | LSF_MPT_CAN_TRANSFER);
        state.insert_raw(
            issuance_key,
            patch_uint64_fields(&issuance_raw, &[(SF_LOCKED_AMOUNT, 35)]),
        );
        let owner_key = mptoken_key(&mpt_issuance_key(&mptid).0, &owner);
        state.insert_raw(owner_key, holder_raw(&owner, &mptid, 65, 35, 0));
        state.insert_escrow(crate::ledger::Escrow {
            account: owner,
            destination: dest,
            amount: 0,
            held_amount: Some(Amount::from_mpt_value(35, mptid)),
            sequence: 6,
            finish_after: 0,
            cancel_after: 9,
            condition: None,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        });

        let tx = ParsedTx {
            account: owner,
            offer_sequence: Some(6),
            ..Default::default()
        };
        let result = apply_escrow_cancel(&mut state, &tx, 10);
        assert_eq!(result, ApplyResult::Success);

        let owner = state.get_raw_owned(&owner_key).unwrap();
        assert_eq!(sle_uint64(&owner, SF_MPT_AMOUNT), 100);
        assert_eq!(sle_uint64(&owner, SF_LOCKED_AMOUNT), 0);
        let issuance = state.get_raw_owned(&mpt_issuance_key(&mptid)).unwrap();
        assert_eq!(sle_uint64(&issuance, SF_LOCKED_AMOUNT), 0);
    }
}
