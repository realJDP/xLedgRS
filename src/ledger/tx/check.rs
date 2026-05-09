//! Check — IMPLEMENTED

use super::{balance_before_fee, owner_reserve_requirement, ApplyResult};
use crate::ledger::account::{
    LSF_DEFAULT_RIPPLE, LSF_DEPOSIT_AUTH, LSF_DISABLE_MASTER, LSF_GLOBAL_FREEZE, LSF_REQUIRE_AUTH,
    LSF_REQUIRE_DEST_TAG,
};
use crate::ledger::directory;
use crate::ledger::ter;
use crate::ledger::LedgerState;
use crate::transaction::amount::{Currency, IouValue};
use crate::transaction::{Amount, ParsedTx};

const LSF_DISALLOW_INCOMING_CHECK: u32 = 0x0800_0000;

fn xrp_drops(amount: &Amount) -> Option<u64> {
    match amount {
        Amount::Xrp(drops) => Some(*drops),
        _ => None,
    }
}

fn xrp_liquid_after_check_removal(
    state: &LedgerState,
    account: &crate::ledger::AccountRoot,
) -> u64 {
    let fees = crate::ledger::read_fees(state);
    let owner_count_after = account.owner_count.saturating_sub(1);
    let reserve_after = fees
        .reserve
        .saturating_add((owner_count_after as u64).saturating_mul(fees.increment));
    account.balance.saturating_sub(reserve_after)
}

fn remove_check_from_owner_dir(
    state: &mut LedgerState,
    owner: &[u8; 20],
    key: &crate::ledger::Key,
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

fn remove_check_directories(
    state: &mut LedgerState,
    key: &crate::ledger::Key,
    check: &crate::ledger::Check,
) -> ApplyResult {
    let result = remove_check_from_owner_dir(state, &check.account, key, check.owner_node);
    if result != ApplyResult::Success {
        return result;
    }
    if check.destination != check.account {
        let result =
            remove_check_from_owner_dir(state, &check.destination, key, check.destination_node);
        if result != ApplyResult::Success {
            return result;
        }
    }
    ApplyResult::Success
}

fn checked_xrp_amount(amount: &Amount) -> Result<u64, ApplyResult> {
    match xrp_drops(amount) {
        Some(drops) if drops > 0 => Ok(drops),
        Some(_) => Err(ApplyResult::ClaimedCost("temBAD_AMOUNT")),
        None => Err(ApplyResult::ClaimedCost("temMALFORMED")),
    }
}

fn same_check_issue(left: &Amount, right: &Amount) -> bool {
    match (left, right) {
        (Amount::Xrp(_), Amount::Xrp(_)) => true,
        (
            Amount::Iou {
                currency: left_currency,
                issuer: left_issuer,
                ..
            },
            Amount::Iou {
                currency: right_currency,
                issuer: right_issuer,
                ..
            },
        ) => left_currency == right_currency && left_issuer == right_issuer,
        (Amount::Mpt(left), Amount::Mpt(right)) => {
            match (
                Amount::decode_mpt_bytes(left),
                Amount::decode_mpt_bytes(right),
            ) {
                (Some((_, left_id)), Some((_, right_id))) => left_id == right_id,
                _ => false,
            }
        }
        _ => false,
    }
}

fn compare_iou(lhs: &IouValue, rhs: &IouValue) -> std::cmp::Ordering {
    super::flow::compare_iou_values(lhs, rhs)
}

fn max_iou_value() -> IouValue {
    IouValue {
        mantissa: 9_999_999_999_999_999,
        exponent: 80,
    }
}

fn max_iou_value_half() -> IouValue {
    IouValue {
        mantissa: 4_999_999_999_999_999,
        exponent: 80,
    }
}

fn checked_iou_amount(amount: &Amount) -> Result<(IouValue, Currency, [u8; 20]), ApplyResult> {
    match amount {
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            if !value.is_positive() {
                return Err(ApplyResult::ClaimedCost("temBAD_AMOUNT"));
            }
            if currency.is_bad_currency() {
                return Err(ApplyResult::ClaimedCost("temBAD_CURRENCY"));
            }
            Ok((*value, currency.clone(), *issuer))
        }
        _ => Err(ApplyResult::ClaimedCost("temMALFORMED")),
    }
}

pub(crate) fn preflight(tx: &ParsedTx) -> Result<(), ter::TxResult> {
    const TF_UNIVERSAL: u32 = 0xC000_0000;
    if (tx.flags & !TF_UNIVERSAL) != 0 {
        return Err(ter::TEM_INVALID_FLAG);
    }

    match tx.tx_type {
        16 => check_create_preflight(tx),
        17 => check_cash_preflight(tx),
        18 => check_cancel_preflight(tx),
        _ => Ok(()),
    }
}

fn check_create_preflight(tx: &ParsedTx) -> Result<(), ter::TxResult> {
    let destination = tx.destination.ok_or(ter::TEM_DST_NEEDED)?;
    if destination == tx.account {
        return Err(ter::TEM_REDUNDANT);
    }
    check_create_send_max_preflight(tx.send_max.as_ref())?;
    if matches!(tx.expiration, Some(0)) {
        return Err(ter::TEM_BAD_EXPIRATION);
    }
    Ok(())
}

fn check_create_send_max_preflight(amount: Option<&Amount>) -> Result<(), ter::TxResult> {
    match amount {
        Some(Amount::Xrp(drops)) if *drops > 0 => Ok(()),
        Some(Amount::Xrp(_)) => Err(ter::TEM_BAD_AMOUNT),
        Some(Amount::Iou {
            value, currency, ..
        }) => {
            if !value.is_positive() {
                return Err(ter::TEM_BAD_AMOUNT);
            }
            if currency.is_bad_currency() {
                return Err(ter::TEM_BAD_CURRENCY);
            }
            Ok(())
        }
        Some(Amount::Mpt(_)) => Err(ter::TEM_BAD_AMOUNT),
        None => Err(ter::TEM_BAD_AMOUNT),
    }
}

fn check_cash_preflight(tx: &ParsedTx) -> Result<(), ter::TxResult> {
    if crate::transaction::parse::parsed_check_id(tx).is_none() {
        return Err(ter::TEM_MALFORMED);
    }
    if tx.amount.is_some() == tx.deliver_min.is_some() {
        return Err(ter::TEM_MALFORMED);
    }
    let amount = tx.amount.as_ref().or(tx.deliver_min.as_ref()).unwrap();
    check_cash_amount_preflight(amount)
}

fn check_cash_amount_preflight(amount: &Amount) -> Result<(), ter::TxResult> {
    match amount {
        Amount::Xrp(drops) if *drops > 0 => Ok(()),
        Amount::Xrp(_) => Err(ter::TEM_BAD_AMOUNT),
        Amount::Iou {
            value, currency, ..
        } => {
            if !value.is_positive() {
                return Err(ter::TEM_BAD_AMOUNT);
            }
            if currency.is_bad_currency() {
                return Err(ter::TEM_BAD_CURRENCY);
            }
            Ok(())
        }
        // Check fields do not support MPT on mainnet, but parsed replay can
        // still surface one. Defer positive MPT issue mismatch to apply, which
        // preserves the existing rippled-shaped malformed path for this model.
        Amount::Mpt(raw) => Amount::decode_mpt_bytes(raw)
            .filter(|(value, _)| *value > 0)
            .map(|_| ())
            .ok_or(ter::TEM_BAD_AMOUNT),
    }
}

fn check_cancel_preflight(tx: &ParsedTx) -> Result<(), ter::TxResult> {
    if crate::transaction::parse::parsed_check_id(tx).is_none() {
        return Err(ter::TEM_MALFORMED);
    }
    Ok(())
}

fn load_trustline(
    state: &mut LedgerState,
    account: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
) -> Option<crate::ledger::RippleState> {
    let key = crate::ledger::trustline::shamap_key(account, issuer, currency);
    if let Some(existing) = state.get_trustline(&key) {
        return Some(existing.clone());
    }
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    let decoded = crate::ledger::RippleState::decode_from_sle(&raw)?;
    state.hydrate_trustline(decoded.clone());
    Some(decoded)
}

fn load_check(state: &mut LedgerState, key: &crate::ledger::Key) -> Option<crate::ledger::Check> {
    if let Some(existing) = state.get_check(key) {
        return Some(existing.clone());
    }
    let raw = state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))?;
    let decoded = crate::ledger::Check::from_sle(key, raw)?;
    state.hydrate_check(decoded.clone());
    Some(decoded)
}

fn reserve_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        crate::ledger::trustline::LSF_LOW_RESERVE
    } else {
        crate::ledger::trustline::LSF_HIGH_RESERVE
    }
}

fn auth_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        crate::ledger::trustline::LSF_LOW_AUTH
    } else {
        crate::ledger::trustline::LSF_HIGH_AUTH
    }
}

fn freeze_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        crate::ledger::trustline::LSF_LOW_FREEZE
    } else {
        crate::ledger::trustline::LSF_HIGH_FREEZE
    }
}

fn no_ripple_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        crate::ledger::trustline::LSF_LOW_NO_RIPPLE
    } else {
        crate::ledger::trustline::LSF_HIGH_NO_RIPPLE
    }
}

fn account_sle_has_hash256_field(account: &crate::ledger::AccountRoot, field: u8) -> bool {
    let Some(raw) = account.raw_sle.as_ref() else {
        return false;
    };
    if field < 16 {
        raw.windows(33).any(|window| window[0] == (0x50 | field))
    } else {
        raw.windows(34)
            .any(|window| window[0] == 0x50 && window[1] == field)
    }
}

fn is_pseudo_account(account: &crate::ledger::AccountRoot) -> bool {
    account_sle_has_hash256_field(account, 14)
        || account_sle_has_hash256_field(account, 35)
        || account_sle_has_hash256_field(account, 37)
        || (account.sequence == 0
            && (account.flags & (LSF_DISABLE_MASTER | LSF_DEFAULT_RIPPLE | LSF_DEPOSIT_AUTH))
                == (LSF_DISABLE_MASTER | LSF_DEFAULT_RIPPLE | LSF_DEPOSIT_AUTH))
}

fn set_owner_node_for(tl: &mut crate::ledger::RippleState, account: &[u8; 20], node: u64) {
    if account == &tl.low_account {
        tl.low_node = node;
    } else {
        tl.high_node = node;
    }
}

fn iou_available(
    state: &mut LedgerState,
    holder: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
) -> IouValue {
    if holder == issuer {
        return IouValue::from_f64(1.0e30);
    }
    if super::load_existing_account(state, issuer)
        .is_some_and(|issuer_account| (issuer_account.flags & LSF_GLOBAL_FREEZE) != 0)
    {
        return IouValue::ZERO;
    }
    let Some(line) = load_trustline(state, holder, issuer, currency) else {
        return IouValue::ZERO;
    };
    if (line.flags & freeze_flag_for(&line, issuer)) != 0 {
        return IouValue::ZERO;
    }
    line.balance_for(holder)
}

fn validate_iou_destination_auth(
    state: &mut LedgerState,
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
) -> Result<(), ApplyResult> {
    if destination == issuer {
        return Ok(());
    }
    let issuer_account = match super::load_existing_account(state, issuer) {
        Some(account) => account,
        None => return Err(ApplyResult::ClaimedCost("tecNO_ISSUER")),
    };
    let line = load_trustline(state, destination, issuer, currency);
    if (issuer_account.flags & LSF_REQUIRE_AUTH) != 0 {
        let Some(line) = line.as_ref() else {
            return Err(ApplyResult::ClaimedCost("tecNO_AUTH"));
        };
        if (line.flags & auth_flag_for(line, destination)) == 0 {
            return Err(ApplyResult::ClaimedCost("tecNO_AUTH"));
        }
    }
    if let Some(line) = line.as_ref() {
        if (line.flags & freeze_flag_for(line, destination)) != 0 {
            return Err(ApplyResult::ClaimedCost("tecFROZEN"));
        }
    }
    Ok(())
}

fn create_destination_trustline_if_needed(
    state: &mut LedgerState,
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
    pre_fee_balance: u64,
) -> Result<(), ApplyResult> {
    if destination == issuer || load_trustline(state, destination, issuer, currency).is_some() {
        return Ok(());
    }
    let destination_account = match state.get_account(destination) {
        Some(account) => account.clone(),
        None => return Err(ApplyResult::ClaimedCost("tecNO_ENTRY")),
    };
    let required = owner_reserve_requirement(state, destination_account.owner_count, 1);
    if pre_fee_balance < required {
        return Err(ApplyResult::ClaimedCost("tecNO_LINE_INSUF_RESERVE"));
    }

    let key = crate::ledger::trustline::shamap_key(destination, issuer, currency);
    let mut line = crate::ledger::RippleState::new(destination, issuer, currency.clone());
    let destination_node = directory::dir_add(state, destination, key.0);
    let issuer_node = directory::dir_add(state, issuer, key.0);
    set_owner_node_for(&mut line, destination, destination_node);
    set_owner_node_for(&mut line, issuer, issuer_node);
    line.flags |= reserve_flag_for(&line, destination);
    if (destination_account.flags & LSF_DEFAULT_RIPPLE) == 0 {
        line.flags |= no_ripple_flag_for(&line, destination);
    }
    if super::load_existing_account(state, issuer)
        .is_some_and(|issuer_account| (issuer_account.flags & LSF_DEFAULT_RIPPLE) == 0)
    {
        line.flags |= no_ripple_flag_for(&line, issuer);
    }

    if let Some(mut destination_account) = state.get_account(destination).cloned() {
        destination_account.owner_count += 1;
        state.insert_account(destination_account);
    }
    state.insert_trustline(line);
    Ok(())
}

fn set_destination_trustline_limit(
    state: &mut LedgerState,
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
    limit: IouValue,
) -> Result<IouValue, ApplyResult> {
    if destination == issuer {
        return Ok(IouValue::ZERO);
    }
    let mut line = load_trustline(state, destination, issuer, currency)
        .ok_or(ApplyResult::ClaimedCost("tecNO_LINE"))?;
    let saved = if destination == &line.low_account {
        let saved = line.low_limit;
        line.low_limit = limit;
        saved
    } else {
        let saved = line.high_limit;
        line.high_limit = limit;
        saved
    };
    state.insert_trustline(line);
    Ok(saved)
}

fn cash_iou_through_flow(
    state: &mut LedgerState,
    check: &crate::ledger::Check,
    requested: IouValue,
    max_value: IouValue,
    currency: &Currency,
    issuer: &[u8; 20],
    is_deliver_min: bool,
    destination_pre_fee_balance: u64,
) -> Result<(), ApplyResult> {
    let deliver = Amount::Iou {
        value: if is_deliver_min {
            max_iou_value_half()
        } else {
            requested
        },
        currency: currency.clone(),
        issuer: *issuer,
    };
    let send_max = Amount::Iou {
        value: max_value,
        currency: currency.clone(),
        issuer: *issuer,
    };
    let deliver_min = is_deliver_min.then_some(Amount::Iou {
        value: requested,
        currency: currency.clone(),
        issuer: *issuer,
    });

    state.begin_tx();
    if let Err(result) = create_destination_trustline_if_needed(
        state,
        &check.destination,
        issuer,
        currency,
        destination_pre_fee_balance,
    ) {
        state.discard_tx();
        return Err(result);
    }
    let saved_limit = match set_destination_trustline_limit(
        state,
        &check.destination,
        issuer,
        currency,
        max_iou_value(),
    ) {
        Ok(limit) => limit,
        Err(result) => {
            state.discard_tx();
            return Err(result);
        }
    };
    let result = super::ripple_calc::ripple_calculate_with_domain(
        state,
        &check.account,
        &check.destination,
        &deliver,
        Some(&send_max),
        deliver_min.as_ref(),
        &[],
        0,
        None,
        0,
    );
    if result.success {
        if let Err(result) = set_destination_trustline_limit(
            state,
            &check.destination,
            issuer,
            currency,
            saved_limit,
        ) {
            state.discard_tx();
            return Err(result);
        }
        let _commit = state.commit_tx();
        Ok(())
    } else {
        state.discard_tx();
        Err(ApplyResult::ClaimedCost(result.ter))
    }
}

/// Apply CheckCreate: create a deferred payment (does NOT lock funds).
pub(crate) fn apply_check_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    close_time: u64,
) -> ApplyResult {
    let sequence = super::sequence_proxy(tx);
    let destination = match tx.destination {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };
    if destination == tx.account {
        return ApplyResult::ClaimedCost("temREDUNDANT");
    }
    let send_max = match &tx.send_max {
        Some(Amount::Xrp(drops)) if *drops > 0 => Amount::Xrp(*drops),
        Some(Amount::Xrp(_)) => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
        Some(Amount::Iou {
            value,
            currency,
            issuer,
        }) => {
            if !value.is_positive() {
                return ApplyResult::ClaimedCost("temBAD_AMOUNT");
            }
            if currency.is_bad_currency() {
                return ApplyResult::ClaimedCost("temBAD_CURRENCY");
            }
            Amount::Iou {
                value: *value,
                currency: currency.clone(),
                issuer: *issuer,
            }
        }
        Some(Amount::Mpt(_)) => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
        None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    if matches!(tx.expiration, Some(0)) {
        return ApplyResult::ClaimedCost("temBAD_EXPIRATION");
    }
    let destination_account = match super::load_existing_account(state, &destination) {
        Some(account) => account,
        None => return ApplyResult::ClaimedCost("tecNO_DST"),
    };
    if (destination_account.flags & LSF_DISALLOW_INCOMING_CHECK) != 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if is_pseudo_account(&destination_account) {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if (destination_account.flags & LSF_REQUIRE_DEST_TAG) != 0 && tx.destination_tag.is_none() {
        return ApplyResult::ClaimedCost("tecDST_TAG_NEEDED");
    }
    if let Amount::Iou {
        currency, issuer, ..
    } = &send_max
    {
        if super::load_existing_account(state, issuer)
            .is_some_and(|issuer_account| (issuer_account.flags & LSF_GLOBAL_FREEZE) != 0)
        {
            return ApplyResult::ClaimedCost("tecFROZEN");
        }
        if *issuer != tx.account {
            if let Some(line) = load_trustline(state, &tx.account, issuer, currency) {
                if (line.flags & freeze_flag_for(&line, issuer)) != 0 {
                    return ApplyResult::ClaimedCost("tecFROZEN");
                }
            }
        }
        if *issuer != destination {
            if let Some(line) = load_trustline(state, issuer, &destination, currency) {
                if (line.flags & freeze_flag_for(&line, &destination)) != 0 {
                    return ApplyResult::ClaimedCost("tecFROZEN");
                }
            }
        }
    }
    if matches!(tx.expiration, Some(expiration) if close_time as u32 >= expiration) {
        return ApplyResult::ClaimedCost("tecEXPIRED");
    }

    let pre_fee_balance = balance_before_fee(new_sender.balance, tx.fee);
    let required = owner_reserve_requirement(state, new_sender.owner_count, 1);
    if pre_fee_balance < required {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
    }

    new_sender.owner_count += 1;

    let check_key = crate::ledger::check::shamap_key(&tx.account, sequence);
    let owner_node = directory::dir_add(state, &tx.account, check_key.0);
    // Also add to destination's directory (rippled CheckCreate.cpp:190)
    let destination_node = if destination != tx.account {
        directory::dir_add(state, &destination, check_key.0)
    } else {
        0
    };
    let check = crate::ledger::Check {
        account: tx.account,
        destination,
        send_max,
        sequence,
        expiration: tx.expiration.unwrap_or(0),
        owner_node,
        destination_node,
        source_tag: crate::transaction::parse::parsed_source_tag(tx),
        destination_tag: tx.destination_tag,
        invoice_id: crate::transaction::parse::parsed_invoice_id(tx),
        raw_sle: None,
    };
    state.insert_check(check);

    ApplyResult::Success
}

/// Apply CheckCash: destination claims the check (debits creator at cash time).
pub(crate) fn apply_check_cash(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    let has_amount = tx.amount.is_some();
    let has_deliver_min = tx.deliver_min.is_some();
    if has_amount == has_deliver_min {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    let requested_amount = tx.amount.as_ref().or(tx.deliver_min.as_ref()).unwrap();
    if let Err(result) = checked_check_cash_amount(requested_amount) {
        return result;
    }

    let key = match crate::transaction::parse::parsed_check_id(tx) {
        Some(id) => crate::ledger::Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let check = match load_check(state, &key) {
        Some(c) => c,
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    // Only the destination can cash
    if tx.account != check.destination {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let destination = match state.get_account(&check.destination) {
        Some(account) => account.clone(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    if (destination.flags & LSF_REQUIRE_DEST_TAG) != 0 && check.destination_tag.is_none() {
        return ApplyResult::ClaimedCost("tecDST_TAG_NEEDED");
    }

    if check.expiration > 0 && (close_time as u32) >= check.expiration {
        return ApplyResult::ClaimedCost("tecEXPIRED");
    }

    match &check.send_max {
        Amount::Xrp(max_drops) => {
            let requested = if let Some(amount) = &tx.amount {
                match checked_xrp_amount(amount) {
                    Ok(drops) => drops,
                    Err(result) => return result,
                }
            } else {
                match tx.deliver_min.as_ref().map(checked_xrp_amount) {
                    Some(Ok(drops)) => drops,
                    Some(Err(result)) => return result,
                    None => return ApplyResult::ClaimedCost("temMALFORMED"),
                }
            };
            if requested > *max_drops {
                return ApplyResult::ClaimedCost("tecPATH_PARTIAL");
            }

            // Verify creator has sufficient liquid balance after freeing the check reserve.
            let creator = match state.get_account(&check.account) {
                Some(a) => a.clone(),
                None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
            };
            let liquid = xrp_liquid_after_check_removal(state, &creator);

            let cash_amount = if has_amount {
                requested
            } else {
                std::cmp::min(*max_drops, liquid)
            };
            if cash_amount < requested || cash_amount > liquid {
                return ApplyResult::ClaimedCost(if has_amount {
                    "tecUNFUNDED_PAYMENT"
                } else {
                    "tecPATH_PARTIAL"
                });
            }

            // Debit creator
            let mut creator = creator;
            creator.balance = creator.balance.saturating_sub(cash_amount);
            creator.owner_count = creator.owner_count.saturating_sub(1);
            state.insert_account(creator);

            // Credit destination (tx.account)
            if let Some(dest) = state.get_account(&tx.account) {
                let mut dest = dest.clone();
                dest.balance = dest.balance.saturating_add(cash_amount);
                state.insert_account(dest);
            }
        }
        Amount::Iou {
            value: max_value,
            currency,
            issuer,
        } => {
            let requested_amount = tx.amount.as_ref().or(tx.deliver_min.as_ref()).unwrap();
            if !same_check_issue(requested_amount, &check.send_max) {
                return ApplyResult::ClaimedCost("temMALFORMED");
            }
            let (requested, _, _) = match checked_iou_amount(requested_amount) {
                Ok(parts) => parts,
                Err(result) => return result,
            };
            if compare_iou(&requested, max_value) == std::cmp::Ordering::Greater {
                return ApplyResult::ClaimedCost("tecPATH_PARTIAL");
            }
            if compare_iou(
                &iou_available(state, &check.account, issuer, currency),
                &requested,
            ) == std::cmp::Ordering::Less
            {
                return ApplyResult::ClaimedCost("tecPATH_PARTIAL");
            }
            if let Err(result) =
                validate_iou_destination_auth(state, &check.destination, issuer, currency)
            {
                return result;
            }
            let destination_pre_fee_balance = destination.balance.saturating_add(tx.fee);
            if let Err(result) = cash_iou_through_flow(
                state,
                &check,
                requested,
                *max_value,
                currency,
                issuer,
                has_deliver_min,
                destination_pre_fee_balance,
            ) {
                return result;
            }
            if let Some(creator) = state.get_account(&check.account) {
                let mut creator = creator.clone();
                creator.owner_count = creator.owner_count.saturating_sub(1);
                state.insert_account(creator);
            }
        }
        Amount::Mpt(_) => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    }

    let result = remove_check_directories(state, &key, &check);
    if result != ApplyResult::Success {
        return result;
    }

    state.remove_check(&key);
    ApplyResult::Success
}

fn checked_check_cash_amount(amount: &Amount) -> Result<(), ApplyResult> {
    match amount {
        Amount::Xrp(drops) => {
            if *drops == 0 {
                Err(ApplyResult::ClaimedCost("temBAD_AMOUNT"))
            } else {
                Ok(())
            }
        }
        Amount::Iou {
            value, currency, ..
        } => {
            if !value.is_positive() {
                return Err(ApplyResult::ClaimedCost("temBAD_AMOUNT"));
            }
            if currency.is_bad_currency() {
                return Err(ApplyResult::ClaimedCost("temBAD_CURRENCY"));
            }
            Ok(())
        }
        Amount::Mpt(raw) => Amount::decode_mpt_bytes(raw)
            .filter(|(value, _)| *value > 0)
            .map(|_| ())
            .ok_or(ApplyResult::ClaimedCost("temBAD_AMOUNT")),
    }
}

/// Apply CheckCancel: remove a check without cashing it.
pub(crate) fn apply_check_cancel(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    let key = match crate::transaction::parse::parsed_check_id(tx) {
        Some(id) => crate::ledger::Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let check = match load_check(state, &key) {
        Some(c) => c,
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    // Creator or destination can cancel, OR anyone can cancel if expired
    let is_participant = tx.account == check.account || tx.account == check.destination;
    let is_expired = check.expiration > 0 && (close_time as u32) >= check.expiration;
    if !is_participant && !is_expired {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let result = remove_check_directories(state, &key, &check);
    if result != ApplyResult::Success {
        return result;
    }

    // Decrement creator's owner_count
    if let Some(creator) = state.get_account(&check.account) {
        let mut creator = creator.clone();
        creator.owner_count = creator.owner_count.saturating_sub(1);
        state.insert_account(creator);
    }

    state.remove_check(&key);
    ApplyResult::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::directory::DirectoryNode;

    fn acct(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn account(id: [u8; 20], owner_count: u32) -> crate::ledger::AccountRoot {
        crate::ledger::AccountRoot {
            account_id: id,
            balance: 10_000_000,
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

    fn check(owner: [u8; 20], dest: [u8; 20], owner_node: u64) -> crate::ledger::Check {
        crate::ledger::Check {
            account: owner,
            destination: dest,
            send_max: Amount::Xrp(1_000),
            sequence: 7,
            expiration: 0,
            owner_node,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            invoice_id: None,
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
            DirectoryNode::new_owner_root(owner)
        } else {
            DirectoryNode::new_page(&root.0, page_num, Some(*owner))
        };
        dir.indexes = indexes;
        state.insert_directory(dir);
    }

    #[test]
    fn check_cancel_uses_owner_node_hint_with_duplicate_directory_entry() {
        let owner = acct(1);
        let dest = owner;
        let mut state = LedgerState::new();
        state.insert_account(account(owner, 1));
        let chk = check(owner, dest, 1);
        let key = chk.key();
        state.insert_check(chk);

        let root = directory::owner_dir_key(&owner);
        let mut root_dir = DirectoryNode::new_owner_root(&owner);
        root_dir.indexes.push(key.0);
        root_dir.index_next = 1;
        root_dir.index_previous = 1;
        state.insert_directory(root_dir);
        insert_owner_dir_page(&mut state, &owner, 1, vec![key.0]);

        let chk = state.get_check(&key).unwrap().clone();
        assert_eq!(
            remove_check_directories(&mut state, &key, &chk),
            ApplyResult::Success
        );

        assert!(directory::load_directory_fresh(&state, &root)
            .unwrap()
            .indexes
            .contains(&key.0));
        assert!(
            directory::load_directory_fresh(&state, &directory::page_key(&root.0, 1)).is_none()
        );
    }

    #[test]
    fn check_cancel_rejects_stale_owner_node_hint_as_bad_ledger() {
        let owner = acct(1);
        let dest = owner;
        let mut state = LedgerState::new();
        state.insert_account(account(owner, 1));
        let chk = check(owner, dest, 1);
        let key = chk.key();
        state.insert_check(chk);
        insert_owner_dir_page(&mut state, &owner, 0, vec![key.0]);

        let chk = state.get_check(&key).unwrap().clone();
        assert_eq!(
            remove_check_directories(&mut state, &key, &chk),
            ApplyResult::ClaimedCost("tefBAD_LEDGER")
        );
    }

    #[test]
    fn check_lookup_hydrates_from_raw_sle() {
        let owner = acct(1);
        let dest = acct(2);
        let mut state = LedgerState::new();
        let chk = check(owner, dest, 0);
        let key = chk.key();
        state.insert_raw(key, chk.to_sle_binary());

        let loaded = load_check(&mut state, &key).expect("raw check hydrates");

        assert_eq!(loaded.account, owner);
        assert_eq!(loaded.destination, dest);
        assert!(state.get_check(&key).is_some());
    }
}
