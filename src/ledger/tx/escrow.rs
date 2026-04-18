//! Escrow — IMPLEMENTED
//!
//! Supports XRP escrows natively, IOU escrows via trust-line adjustments, and
//! MPT escrows via direct holder / issuance balance updates.

use super::ApplyResult;
use crate::crypto::sha512_first_half;
use crate::ledger::directory;
use crate::ledger::Key;
use crate::ledger::LedgerState;
use crate::transaction::{Amount, ParsedTx};

const MPT_ISSUANCE_SPACE: [u8; 2] = [0x00, 0x7E];
const MPTOKEN_SPACE: [u8; 2] = [0x00, 0x74];
const LSF_MPT_LOCKED: u32 = 0x0000_0001;
const LSF_MPT_AUTHORIZED: u32 = 0x0000_0002;
const LSF_MPT_REQUIRE_AUTH: u32 = 0x0000_0004;
const LSF_MPT_CAN_ESCROW: u32 = 0x0000_0008;
const LSF_MPT_CAN_TRANSFER: u32 = 0x0000_0020;

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
    let holder_amount = sle_uint64(&holder_raw, 26);
    if holder_amount < value {
        return ApplyResult::ClaimedCost("tecUNFUNDED");
    }
    let holder_locked = sle_uint64(&holder_raw, 4);
    state.insert_raw(
        holder_key,
        patch_uint64_fields(
            &holder_raw,
            &[(26, holder_amount - value), (4, holder_locked + value)],
        ),
    );

    let issuance_locked = sle_uint64(&issuance_raw, 25);
    state.insert_raw(
        issuance_key,
        patch_uint64_fields(&issuance_raw, &[(25, issuance_locked + value)]),
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
    let owner_locked = sle_uint64(&owner_raw, 4);
    if owner_locked < value {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    }
    state.insert_raw(
        owner_key,
        patch_uint64_fields(&owner_raw, &[(4, owner_locked - value)]),
    );

    let issuance_locked = sle_uint64(&issuance_raw, 25);
    let issuance_outstanding = sle_uint64(&issuance_raw, 4);
    if issuance_locked < value {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    }

    if escrow.destination == issuer {
        state.insert_raw(
            issuance_key,
            patch_uint64_fields(
                &issuance_raw,
                &[
                    (25, issuance_locked - value),
                    (4, issuance_outstanding.saturating_sub(value)),
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
        let dest_amount = sle_uint64(&dest_raw, 26);
        state.insert_raw(
            dest_key,
            patch_uint64_fields(&dest_raw, &[(26, dest_amount + value)]),
        );
        state.insert_raw(
            issuance_key,
            patch_uint64_fields(&issuance_raw, &[(25, issuance_locked - value)]),
        );
    }

    ApplyResult::Success
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

    let holder_amount = sle_uint64(&holder_raw, 26);
    let holder_locked = sle_uint64(&holder_raw, 4);
    let issuance_locked = sle_uint64(&issuance_raw, 25);
    if holder_locked < value || issuance_locked < value {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    }

    state.insert_raw(
        holder_key,
        patch_uint64_fields(
            &holder_raw,
            &[(26, holder_amount + value), (4, holder_locked - value)],
        ),
    );
    state.insert_raw(
        issuance_key,
        patch_uint64_fields(&issuance_raw, &[(25, issuance_locked - value)]),
    );

    ApplyResult::Success
}

/// Apply EscrowCreate: lock funds in a time-locked escrow object.
/// Supports XRP (native), IOU trust-line escrows, and MPT balance locking.
pub(crate) fn apply_escrow_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let sequence = super::sequence_proxy(tx);
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
    let destination = match tx.destination {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };

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
        condition: None,
        owner_node,
        destination_node,
        source_tag: None,
        destination_tag: None,
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
    let escrow_seq = match tx.offer_sequence {
        Some(s) => s,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let owner = tx.owner.unwrap_or(tx.account);

    let key = crate::ledger::escrow::shamap_key(&owner, escrow_seq);
    let escrow = match state.get_escrow(&key) {
        Some(e) => e.clone(),
        None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // Check finish_after time condition
    if escrow.finish_after > 0 && (close_time as u32) < escrow.finish_after {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
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

    // Remove escrow from owner directory
    directory::dir_remove(state, &escrow.account, &key.0);
    // Remove from destination directory if present (rippled EscrowFinish.cpp:317)
    if escrow.destination != escrow.account {
        directory::dir_remove(state, &escrow.destination, &key.0);
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
    let escrow = match state.get_escrow(&key) {
        Some(e) => e.clone(),
        None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // Check cancel_after time condition
    if escrow.cancel_after > 0 && (close_time as u32) < escrow.cancel_after {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    if matches!(escrow.held_amount, Some(Amount::Mpt(_))) {
        let result = apply_mpt_escrow_cancel(state, &escrow);
        if result != ApplyResult::Success {
            return result;
        }
    }

    // Remove escrow from owner directory
    directory::dir_remove(state, &escrow.account, &key.0);
    // Remove from destination directory if present (rippled EscrowCancel.cpp:143)
    if escrow.destination != escrow.account {
        directory::dir_remove(state, &escrow.destination, &key.0);
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

    fn account(id: [u8; 20]) -> crate::ledger::AccountRoot {
        crate::ledger::AccountRoot {
            account_id: id,
            balance: 10_000_000,
            sequence: 1,
            owner_count: 0,
            flags: 0,
            regular_key: None,
            minted_nftokens: 0,
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
                    field_code: 4,
                    data: 500u64.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 3,
                    field_code: 25,
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
        let raw = patch_uint64_fields(&raw, &[(26, amount), (4, locked)]);
        let key = mptoken_key(&issuance_key.0, holder);
        let _ = key;
        raw
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
            amount: Some(Amount::from_mpt_value(40, mptid)),
            ..Default::default()
        };
        let mut sender = account(owner);
        let result = apply_escrow_create(&mut state, &tx, &mut sender);
        assert_eq!(result, ApplyResult::Success);

        let holder = state.get_raw_owned(&holder_key).unwrap();
        assert_eq!(sle_uint64(&holder, 26), 60);
        assert_eq!(sle_uint64(&holder, 4), 40);

        let issuance = state.get_raw_owned(&mpt_issuance_key(&mptid)).unwrap();
        assert_eq!(sle_uint64(&issuance, 25), 40);

        let escrow_key = crate::ledger::escrow::shamap_key(&owner, 5);
        let escrow = state.get_escrow(&escrow_key).unwrap();
        assert_eq!(
            escrow.held_amount.as_ref().and_then(Amount::mpt_parts),
            Some((40, mptid))
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
            patch_uint64_fields(&issuance_raw, &[(25, 40)]),
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
        assert_eq!(sle_uint64(&owner, 4), 0);
        let dest = state.get_raw_owned(&dest_key).unwrap();
        assert_eq!(sle_uint64(&dest, 26), 50);
        let issuance = state.get_raw_owned(&mpt_issuance_key(&mptid)).unwrap();
        assert_eq!(sle_uint64(&issuance, 25), 0);
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
            patch_uint64_fields(&issuance_raw, &[(25, 35)]),
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
            cancel_after: 0,
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
        assert_eq!(sle_uint64(&owner, 26), 100);
        assert_eq!(sle_uint64(&owner, 4), 0);
        let issuance = state.get_raw_owned(&mpt_issuance_key(&mptid)).unwrap();
        assert_eq!(sle_uint64(&issuance, 25), 0);
    }
}
