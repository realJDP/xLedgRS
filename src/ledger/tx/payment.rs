//! Payment — XRP direct + IOU/cross-currency via RippleCalc flow engine.

use super::amm_step;
use super::asset_flow::{apply_amount_delta, AssetDelta};
use super::credential;
use super::flow::compare_iou_values;
use super::mptoken;
use super::ripple_calc;
use super::{load_existing_account, ApplyResult, TxContext};
use crate::ledger::account::{
    AccountRoot, LSF_DEFAULT_RIPPLE, LSF_DEPOSIT_AUTH, LSF_DISABLE_MASTER, LSF_PASSWORD_SPENT,
    LSF_REQUIRE_DEST_TAG,
};
use crate::ledger::ter;
use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, Currency, Issue};
use crate::transaction::ParsedTx;

const TF_NO_RIPPLE_DIRECT: u32 = 0x0001_0000;
const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;
const TF_LIMIT_QUALITY: u32 = 0x0004_0000;
const MAX_PATH_SIZE: usize = 6;
const MAX_PATH_LENGTH: usize = 8;

fn debug_payment_enabled(seq: u32) -> bool {
    std::env::var("XLEDGRSV2BETA_DEBUG_PAYMENT_SEQS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|entry| entry.trim().parse::<u32>().ok())
                .any(|target| target == seq)
        })
        .unwrap_or(false)
}

pub(crate) fn apply_payment(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    ctx: &TxContext,
) -> ApplyResult {
    let dest_id = match tx.destination {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };

    let deliver = match &tx.amount {
        Some(amt) => amt.clone(),
        None => match tx.amount_drops {
            Some(d) => Amount::Xrp(d),
            None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
        },
    };

    if let Some(ter) = payment_preflight(tx, &deliver) {
        return ApplyResult::ClaimedCost(ter);
    }
    if let Some(ter) = credential::check_credential_id_fields(tx) {
        return ApplyResult::ClaimedCost(ter);
    }

    if is_redundant_self_payment(tx, &dest_id, &deliver) {
        return ApplyResult::ClaimedCost("temREDUNDANT");
    }

    if destination_requires_tag_without_one(state, tx, &dest_id) {
        return ApplyResult::ClaimedCost("tecDST_TAG_NEEDED");
    }
    if let Some(domain_id) = tx.domain_id {
        if !super::permissioned_domain::account_in_domain(
            state,
            &tx.account,
            &domain_id,
            ctx.close_time,
        ) || !super::permissioned_domain::account_in_domain(
            state,
            &dest_id,
            &domain_id,
            ctx.close_time,
        ) {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
    }

    let has_paths = !tx.paths.is_empty();
    let has_send_max = tx.send_max.is_some();
    let is_iou_amount = matches!(&tx.amount, Some(Amount::Iou { .. }));
    let use_ripple = has_paths || has_send_max || is_iou_amount;

    if let Some(ter) =
        destination_receive_preclaim(state, tx, &dest_id, &deliver, use_ripple, ctx.close_time)
    {
        return ApplyResult::ClaimedCost(ter);
    }
    if let Err(ter) = credential::validate_credential_ids(state, &tx.account, tx) {
        return ApplyResult::ClaimedCost(ter);
    }
    if credential::remove_expired_credential_ids(state, tx, ctx.close_time) {
        return ApplyResult::ClaimedCost("tecEXPIRED");
    }

    if let Some(result) =
        apply_validated_replay_amm_self_swap_hint(state, tx, &dest_id, &deliver, new_sender, ctx)
    {
        return result;
    }

    if let Some(result) = apply_validated_replay_payment_bridge(tx, ctx) {
        return result;
    }

    if matches!(&deliver, Amount::Mpt(_)) {
        if let Some(ter) = direct_mpt_deposit_auth_result(state, tx, &dest_id, ctx.close_time) {
            return ApplyResult::ClaimedCost(ter);
        }
        return mptoken::apply_direct_mpt_payment(state, tx);
    }

    // Determine if this is a ripple payment (IOU or cross-currency)
    if use_ripple {
        // Flow engines mutate LedgerState directly. Publish the fee/sequence
        // adjusted sender first so XRP debits start from the same account state
        // that the outer transaction runner will eventually persist.
        state.insert_account(new_sender.clone());

        // IOU / cross-currency payment — use the flow engine
        let result = ripple_calc::ripple_calculate_with_domain(
            state,
            &tx.account,
            &dest_id,
            &deliver,
            tx.send_max.as_ref(),
            tx.deliver_min.as_ref(),
            &tx.paths,
            tx.flags,
            tx.domain_id,
            ctx.close_time,
        );

        if result.success {
            // Flow paths may debit/credit the sender through LedgerState
            // directly. Refresh before the outer transaction runner persists
            // `new_sender`, otherwise XRP-side flow mutations can be clobbered.
            if let Some(updated) = load_existing_account(state, &tx.account) {
                *new_sender = updated.clone();
            }
            ApplyResult::Success
        } else {
            ApplyResult::ClaimedCost(result.ter)
        }
    } else {
        // Direct XRP payment
        let drops = match tx.amount_drops {
            Some(d) if d > 0 => d,
            _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
        };

        let fees = crate::ledger::read_fees(state);
        let existing_dest = load_existing_account(state, &dest_id);
        let pre_fee_balance = new_sender.balance.saturating_add(tx.fee);
        let reserve = fees.reserve + (new_sender.owner_count as u64 * fees.increment);
        if debug_payment_enabled(tx.sequence) {
            tracing::warn!(
                "debug direct-xrp payment: seq={} acct={} dest={} pre_fee_balance={} post_fee_balance={} fee={} drops={} reserve={} owner_count={} dest_exists={}",
                tx.sequence,
                hex::encode_upper(&tx.account[..4]),
                hex::encode_upper(&dest_id[..4]),
                pre_fee_balance,
                new_sender.balance,
                tx.fee,
                drops,
                reserve,
                new_sender.owner_count,
                existing_dest.is_some(),
            );
        }
        if existing_dest.is_none() && drops < fees.reserve {
            return ApplyResult::ClaimedCost("tecNO_DST_INSUF_XRP");
        }
        let min_required_funds = reserve.max(tx.fee);
        if pre_fee_balance < drops.saturating_add(min_required_funds) {
            if debug_payment_enabled(tx.sequence) {
                tracing::warn!(
                    "debug direct-xrp payment unfunded: seq={} acct={} pre_fee_balance={} needed={} reserve={} fee={}",
                    tx.sequence,
                    hex::encode_upper(&tx.account[..4]),
                    pre_fee_balance,
                    drops.saturating_add(min_required_funds),
                    reserve,
                    tx.fee,
                );
            }
            return ApplyResult::ClaimedCost("tecUNFUNDED_PAYMENT");
        }

        if existing_dest.as_ref().is_some_and(is_pseudo_account) {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
        if let Some(ter) =
            direct_xrp_deposit_auth_result(state, tx, &dest_id, drops, ctx.close_time)
        {
            return ApplyResult::ClaimedCost(ter);
        }

        new_sender.balance -= drops;

        match existing_dest {
            Some(mut dest) => {
                dest.balance = dest.balance.saturating_add(drops);
                dest.flags &= !LSF_PASSWORD_SPENT;
                state.insert_account(dest);
            }
            None => {
                state.insert_account(crate::ledger::AccountRoot {
                    account_id: dest_id,
                    balance: drops,
                    sequence: new_account_sequence(ctx),
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
        ApplyResult::Success
    }
}

pub(crate) fn preflight(tx: &ParsedTx) -> Result<(), ter::TxResult> {
    const TF_UNIVERSAL: u32 = 0xC000_0000;
    const PAYMENT_FLAGS: u32 = TF_NO_RIPPLE_DIRECT | TF_PARTIAL_PAYMENT | TF_LIMIT_QUALITY;
    const MPT_PAYMENT_FLAGS: u32 = TF_PARTIAL_PAYMENT;

    let deliver = tx
        .amount
        .as_ref()
        .cloned()
        .or_else(|| tx.amount_drops.map(Amount::Xrp))
        .ok_or(ter::TEM_BAD_AMOUNT)?;
    let mpt_direct = matches!(deliver, Amount::Mpt(_));
    let allowed_flags = if mpt_direct {
        TF_UNIVERSAL | MPT_PAYMENT_FLAGS
    } else {
        TF_UNIVERSAL | PAYMENT_FLAGS
    };
    if (tx.flags & !allowed_flags) != 0 {
        return Err(ter::TEM_INVALID_FLAG);
    }

    if (mpt_direct
        && tx
            .send_max
            .as_ref()
            .is_some_and(|send_max| !same_asset(send_max, &deliver)))
        || (!mpt_direct && matches!(tx.send_max.as_ref(), Some(Amount::Mpt(_))))
    {
        return Err(ter::TEM_MALFORMED);
    }
    if mpt_direct && !tx.paths.is_empty() {
        return Err(ter::TEM_MALFORMED);
    }

    let Some(destination) = tx.destination else {
        return Err(ter::TEM_DST_NEEDED);
    };

    if !amount_is_positive(&deliver)
        || tx
            .send_max
            .as_ref()
            .is_some_and(|send_max| !amount_is_positive(send_max))
    {
        return Err(ter::TEM_BAD_AMOUNT);
    }

    if amount_has_bad_currency(&deliver)
        || tx.send_max.as_ref().is_some_and(amount_has_bad_currency)
    {
        return Err(ter::TEM_BAD_CURRENCY);
    }
    if is_redundant_self_payment(tx, &destination, &deliver) {
        return Err(ter::TEM_REDUNDANT);
    }

    let xrp_direct = is_xrp_direct_payment(tx, &deliver);
    if xrp_direct && tx.send_max.is_some() {
        return Err(ter::TEM_BAD_SEND_XRP_MAX);
    }
    if xrp_direct && !tx.paths.is_empty() {
        return Err(ter::TEM_BAD_SEND_XRP_PATHS);
    }
    if xrp_direct && (tx.flags & TF_PARTIAL_PAYMENT) != 0 {
        return Err(ter::TEM_BAD_SEND_XRP_PARTIAL);
    }
    if (xrp_direct || mpt_direct) && (tx.flags & TF_LIMIT_QUALITY) != 0 {
        return Err(ter::TEM_BAD_SEND_XRP_LIMIT);
    }
    if (xrp_direct || mpt_direct) && (tx.flags & TF_NO_RIPPLE_DIRECT) != 0 {
        return Err(ter::TEM_BAD_SEND_XRP_NO_DIRECT);
    }

    if let Some(deliver_min) = &tx.deliver_min {
        if (tx.flags & TF_PARTIAL_PAYMENT) == 0
            || !amount_is_positive(deliver_min)
            || !same_asset(deliver_min, &deliver)
            || amount_greater_than(deliver_min, &deliver)
        {
            return Err(ter::TEM_BAD_AMOUNT);
        }
    }
    if let Some(token) = credential::check_credential_id_fields(tx) {
        return Err(super::tx_result_from_token(token));
    }
    Ok(())
}

fn payment_preflight(tx: &ParsedTx, deliver: &Amount) -> Option<&'static str> {
    if !amount_is_positive(deliver) {
        return Some("temBAD_AMOUNT");
    }

    if let Some(send_max) = &tx.send_max {
        if !amount_is_positive(send_max) {
            return Some("temBAD_AMOUNT");
        }
    }

    let mpt_direct = matches!(deliver, Amount::Mpt(_));
    if (mpt_direct
        && tx
            .send_max
            .as_ref()
            .is_some_and(|send_max| !same_asset(send_max, deliver)))
        || (!mpt_direct && matches!(tx.send_max.as_ref(), Some(Amount::Mpt(_))))
    {
        return Some("temMALFORMED");
    }
    if mpt_direct && !tx.paths.is_empty() {
        return Some("temMALFORMED");
    }

    if amount_has_bad_currency(deliver) || tx.send_max.as_ref().is_some_and(amount_has_bad_currency)
    {
        return Some("temBAD_CURRENCY");
    }

    if let Some(destination) = tx.destination {
        if is_redundant_self_payment(tx, &destination, deliver) {
            return Some("temREDUNDANT");
        }
    }

    let xrp_direct = is_xrp_direct_payment(tx, deliver);
    if xrp_direct && tx.send_max.is_some() {
        return Some("temBAD_SEND_XRP_MAX");
    }
    if xrp_direct && !tx.paths.is_empty() {
        return Some("temBAD_SEND_XRP_PATHS");
    }
    if xrp_direct && (tx.flags & TF_PARTIAL_PAYMENT) != 0 {
        return Some("temBAD_SEND_XRP_PARTIAL");
    }
    if xrp_direct && (tx.flags & TF_LIMIT_QUALITY) != 0 {
        return Some("temBAD_SEND_XRP_LIMIT");
    }
    if mpt_direct && (tx.flags & TF_LIMIT_QUALITY) != 0 {
        return Some("temBAD_SEND_XRP_LIMIT");
    }
    if xrp_direct && (tx.flags & TF_NO_RIPPLE_DIRECT) != 0 {
        return Some("temBAD_SEND_XRP_NO_DIRECT");
    }
    if mpt_direct && (tx.flags & TF_NO_RIPPLE_DIRECT) != 0 {
        return Some("temBAD_SEND_XRP_NO_DIRECT");
    }

    if let Some(deliver_min) = &tx.deliver_min {
        if (tx.flags & TF_PARTIAL_PAYMENT) == 0
            || !amount_is_positive(deliver_min)
            || !same_asset(deliver_min, deliver)
            || amount_greater_than(deliver_min, deliver)
        {
            return Some("temBAD_AMOUNT");
        }
    }

    None
}

fn amount_has_bad_currency(amount: &Amount) -> bool {
    matches!(
        amount,
        Amount::Iou { currency, .. } if currency.is_bad_currency()
    )
}

fn amount_is_positive(amount: &Amount) -> bool {
    match amount {
        Amount::Xrp(drops) => *drops > 0,
        Amount::Iou { value, .. } => value.is_positive(),
        Amount::Mpt(raw) => Amount::Mpt(raw.clone())
            .mpt_parts()
            .map(|(value, _)| value > 0)
            .unwrap_or(false),
    }
}

fn amount_greater_than(lhs: &Amount, rhs: &Amount) -> bool {
    match (lhs, rhs) {
        (Amount::Xrp(a), Amount::Xrp(b)) => a > b,
        (Amount::Iou { value: a, .. }, Amount::Iou { value: b, .. }) => {
            compare_iou_values(a, b) == std::cmp::Ordering::Greater
        }
        (Amount::Mpt(a), Amount::Mpt(b)) => {
            let left = Amount::Mpt(a.clone()).mpt_parts().map(|(value, _)| value);
            let right = Amount::Mpt(b.clone()).mpt_parts().map(|(value, _)| value);
            left > right
        }
        _ => false,
    }
}

fn is_xrp_direct_payment(tx: &ParsedTx, deliver: &Amount) -> bool {
    if !matches!(deliver, Amount::Xrp(_)) {
        return false;
    }

    tx.send_max
        .as_ref()
        .map(|send_max| matches!(send_max, Amount::Xrp(_)))
        .unwrap_or(true)
}

fn new_account_sequence(ctx: &TxContext) -> u32 {
    // rippled initializes newly funded accounts to the current ledger sequence.
    // Tests and direct apply helpers may use a zero-valued context.
    ctx.ledger_seq.max(1)
}

fn same_asset(a: &Amount, b: &Amount) -> bool {
    match (a, b) {
        (Amount::Xrp(_), Amount::Xrp(_)) => true,
        (
            Amount::Iou {
                currency, issuer, ..
            },
            Amount::Iou {
                currency: other_currency,
                issuer: other_issuer,
                ..
            },
        ) => currency == other_currency && issuer == other_issuer,
        (Amount::Mpt(_), Amount::Mpt(_)) => match (mpt_issue_id(a), mpt_issue_id(b)) {
            (Some(issue), Some(other_issue)) => issue == other_issue,
            _ => false,
        },
        _ => false,
    }
}

fn mpt_issue_id(amount: &Amount) -> Option<[u8; 24]> {
    amount.mpt_parts().map(|(_, issue_id)| issue_id)
}

fn self_payment_source_asset(tx: &ParsedTx, deliver: &Amount) -> Amount {
    if let Some(send_max) = &tx.send_max {
        return send_max.clone();
    }

    match deliver {
        Amount::Iou {
            value, currency, ..
        } => Amount::Iou {
            value: *value,
            currency: currency.clone(),
            issuer: tx.account,
        },
        _ => deliver.clone(),
    }
}

fn is_redundant_self_payment(tx: &ParsedTx, destination: &[u8; 20], deliver: &Amount) -> bool {
    if tx.account != *destination || !tx.paths.is_empty() {
        return false;
    }

    let source = self_payment_source_asset(tx, deliver);
    same_asset(&source, deliver)
}

fn destination_requires_tag_without_one(
    state: &mut LedgerState,
    tx: &ParsedTx,
    dest_id: &[u8; 20],
) -> bool {
    tx.destination_tag.is_none()
        && load_existing_account(state, dest_id)
            .map(|dest| (dest.flags & LSF_REQUIRE_DEST_TAG) != 0)
            .unwrap_or(false)
}

fn destination_receive_preclaim(
    state: &mut LedgerState,
    tx: &ParsedTx,
    dest_id: &[u8; 20],
    deliver: &Amount,
    use_ripple: bool,
    close_time: u64,
) -> Option<&'static str> {
    let Some(dest) = load_existing_account(state, dest_id) else {
        // rippled Payment::preclaim delays IOU/MPT destinations until another
        // transaction creates the AccountRoot. Native payments may create it.
        if !matches!(deliver, Amount::Xrp(_)) {
            return Some("tecNO_DST");
        }
        if (tx.flags & TF_PARTIAL_PAYMENT) != 0 {
            return Some("telNO_DST_PARTIAL");
        }
        if matches!(deliver, Amount::Xrp(drops) if *drops < crate::ledger::read_fees(state).reserve)
        {
            return Some("tecNO_DST_INSUF_XRP");
        }
        if use_ripple
            && (tx.paths.len() > MAX_PATH_SIZE
                || tx.paths.iter().any(|path| path.len() > MAX_PATH_LENGTH))
        {
            return Some("telBAD_PATH_COUNT");
        }
        return None;
    };

    if use_ripple
        && (tx.paths.len() > MAX_PATH_SIZE
            || tx.paths.iter().any(|path| path.len() > MAX_PATH_LENGTH))
    {
        return Some("telBAD_PATH_COUNT");
    }

    if !use_ripple {
        return None;
    }

    if (dest.flags & LSF_DEPOSIT_AUTH) == 0 || tx.account == *dest_id {
        return None;
    }

    if has_deposit_preauth(state, dest_id, &tx.account) {
        None
    } else if crate::transaction::parse::parsed_credential_ids_present(tx) {
        match credential::credential_deposit_preauth_authorized(
            state,
            dest_id,
            &tx.account,
            tx,
            close_time,
        ) {
            Ok(true) => None,
            Ok(false) => Some("tecNO_PERMISSION"),
            Err(code) => Some(code),
        }
    } else {
        Some("tecNO_PERMISSION")
    }
}

fn direct_xrp_deposit_auth_result(
    state: &mut LedgerState,
    tx: &ParsedTx,
    dest_id: &[u8; 20],
    drops: u64,
    close_time: u64,
) -> Option<&'static str> {
    let dest = load_existing_account(state, dest_id)?;
    if (dest.flags & LSF_DEPOSIT_AUTH) == 0 || tx.account == *dest_id {
        return None;
    }

    let reserve = crate::ledger::read_fees(state).reserve;
    if dest.balance <= reserve && drops <= reserve {
        return None;
    }

    if has_deposit_preauth(state, dest_id, &tx.account) {
        None
    } else if crate::transaction::parse::parsed_credential_ids_present(tx) {
        match credential::credential_deposit_preauth_authorized(
            state,
            dest_id,
            &tx.account,
            tx,
            close_time,
        ) {
            Ok(true) => None,
            Ok(false) => Some("tecNO_PERMISSION"),
            Err(code) => Some(code),
        }
    } else {
        Some("tecNO_PERMISSION")
    }
}

fn direct_mpt_deposit_auth_result(
    state: &mut LedgerState,
    tx: &ParsedTx,
    dest_id: &[u8; 20],
    close_time: u64,
) -> Option<&'static str> {
    let dest = load_existing_account(state, dest_id)?;
    if (dest.flags & LSF_DEPOSIT_AUTH) == 0 || tx.account == *dest_id {
        return None;
    }

    if has_deposit_preauth(state, dest_id, &tx.account) {
        None
    } else if crate::transaction::parse::parsed_credential_ids_present(tx) {
        match credential::credential_deposit_preauth_authorized(
            state,
            dest_id,
            &tx.account,
            tx,
            close_time,
        ) {
            Ok(true) => None,
            Ok(false) => Some("tecNO_PERMISSION"),
            Err(code) => Some(code),
        }
    } else {
        Some("tecNO_PERMISSION")
    }
}

fn is_pseudo_account(account: &AccountRoot) -> bool {
    const PSEUDO_FLAGS: u32 = LSF_DISABLE_MASTER | LSF_DEFAULT_RIPPLE | LSF_DEPOSIT_AUTH;
    account.sequence == 0 && (account.flags & PSEUDO_FLAGS) == PSEUDO_FLAGS
}

fn has_deposit_preauth(state: &LedgerState, destination: &[u8; 20], sender: &[u8; 20]) -> bool {
    let key = crate::ledger::deposit_preauth::shamap_key(destination, sender);
    state.has_deposit_preauth(&key)
        || state.get_raw_owned(&key).is_some()
        || state.get_committed_raw_owned(&key).is_some()
}

fn apply_validated_replay_payment_bridge(tx: &ParsedTx, ctx: &TxContext) -> Option<ApplyResult> {
    if !ctx.trusted_validated_replay {
        return None;
    }

    let validated = ctx.validated_result?;
    if !payment_requires_authoritative_replay_bridge(tx) {
        return None;
    }

    if validated.is_tes_success() {
        return None;
    }

    Some(ApplyResult::ClaimedCost(validated.token()))
}

fn payment_requires_authoritative_replay_bridge(tx: &ParsedTx) -> bool {
    !tx.paths.is_empty() || tx.send_max.is_some() || tx.deliver_min.is_some()
}

fn apply_validated_replay_amm_self_swap_hint(
    state: &mut LedgerState,
    tx: &ParsedTx,
    destination: &[u8; 20],
    deliver: &Amount,
    new_sender: &mut AccountRoot,
    ctx: &TxContext,
) -> Option<ApplyResult> {
    let debug = debug_payment_enabled(tx.sequence);
    if debug {
        tracing::warn!(
            "debug payment amm bridge guard: seq={} bridge={} result={:?} self_payment={} paths={} send_max={} delivered_hint={}",
            tx.sequence,
            ctx.validated_payment_amm_self_swap_bridge,
            ctx.validated_result,
            tx.account == *destination,
            tx.paths.len(),
            tx.send_max.is_some(),
            ctx.validated_delivered_amount.is_some(),
        );
    }
    let replay_hint = ctx.trusted_validated_replay
        && ctx.validated_payment_amm_self_swap_bridge
        && ctx.validated_result == Some(ter::TES_SUCCESS);
    let independent_amm_path = !ctx.trusted_validated_replay
        && tx.send_max.is_some()
        && !tx.paths.is_empty()
        && (tx.flags & TF_PARTIAL_PAYMENT) == 0;
    if !replay_hint && !independent_amm_path {
        return None;
    }

    let spend_limit = tx.send_max.as_ref()?;
    let delivered = if replay_hint {
        ctx.validated_delivered_amount.as_ref().unwrap_or(deliver)
    } else {
        deliver
    };
    let issue_chain = amm_path_issue_chain(tx, spend_limit, delivered)?;
    if issue_chain.len() < 2 {
        return None;
    }

    let mut wanted = delivered.clone();
    let mut reverse_hops = Vec::new();
    for pair in issue_chain.windows(2).rev() {
        let pool = match amm_step::load_amm_pool(state, &pair[0], &pair[1]) {
            Some(pool) => pool,
            None => {
                if debug {
                    tracing::warn!(
                        "debug payment amm bridge no pool: seq={} asset_in={:?} asset_out={:?}",
                        tx.sequence,
                        pair[0],
                        pair[1],
                    );
                }
                return None;
            }
        };
        let quote = amm_step::quote_exact_out(&pool, &wanted)?;
        wanted = quote.spent_in.clone();
        reverse_hops.push((pool, quote));
    }
    if !amm_step::amount_leq(&wanted, spend_limit).unwrap_or(false) {
        return None;
    }
    reverse_hops.reverse();
    if debug {
        tracing::warn!(
            "debug payment amm bridge apply: seq={} hops={} spent={:?} spend_limit={:?} delivered={:?}",
            tx.sequence,
            reverse_hops.len(),
            wanted,
            spend_limit,
            delivered,
        );
    }

    match &wanted {
        Amount::Xrp(drops) => {
            new_sender.balance = new_sender.balance.saturating_sub(*drops);
        }
        Amount::Iou { .. } => {
            apply_amount_delta(state, &tx.account, AssetDelta::Debit, &wanted);
        }
        Amount::Mpt(_) => return None,
    }
    for (pool, quote) in &reverse_hops {
        apply_amount_delta(
            state,
            &pool.pseudo_account,
            AssetDelta::Credit,
            &quote.spent_in,
        );
        apply_amount_delta(
            state,
            &pool.pseudo_account,
            AssetDelta::Debit,
            &quote.delivered_out,
        );
    }

    match delivered {
        Amount::Xrp(drops) => {
            if tx.account == *destination {
                new_sender.balance = new_sender.balance.saturating_add(*drops);
            } else {
                let mut dest_account = load_existing_account(state, destination)?;
                dest_account.balance = dest_account.balance.saturating_add(*drops);
                state.insert_account(dest_account);
            }
        }
        Amount::Iou { .. } => {
            apply_amount_delta(state, destination, AssetDelta::Credit, delivered);
        }
        Amount::Mpt(_) => return None,
    }

    Some(ApplyResult::Success)
}

fn amm_path_issue_chain(
    tx: &ParsedTx,
    spend_limit: &Amount,
    delivered: &Amount,
) -> Option<Vec<Issue>> {
    let mut chain = Vec::new();
    push_distinct_issue(&mut chain, amm_step::issue_from_amount(spend_limit)?);
    if tx.paths.len() > 1 {
        return None;
    }
    for path in &tx.paths {
        for step in path {
            if let Some(issue) = issue_from_path_step(step) {
                push_distinct_issue(&mut chain, issue);
            }
        }
    }
    push_distinct_issue(&mut chain, amm_step::issue_from_amount(delivered)?);
    Some(chain)
}

fn push_distinct_issue(chain: &mut Vec<Issue>, issue: Issue) {
    if chain.last() != Some(&issue) {
        chain.push(issue);
    }
}

fn issue_from_path_step(step: &crate::transaction::parse::PathStep) -> Option<Issue> {
    let currency = Currency {
        code: step.currency?,
    };
    if currency.is_xrp() {
        return Some(Issue::Xrp);
    }
    let issuer = step.issuer.or(step.account)?;
    Some(Issue::Iou { currency, issuer })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::amount::IouValue;
    use crate::transaction::parse::PathStep;

    fn payment_tx(deliver: Amount) -> ParsedTx {
        ParsedTx {
            account: [1u8; 20],
            destination: Some([2u8; 20]),
            amount: Some(deliver),
            ..ParsedTx::default()
        }
    }

    fn mpt(value: u64, issue_byte: u8) -> Amount {
        Amount::from_mpt_value(value, [issue_byte; 24])
    }

    fn iou(value: i64, currency_byte: u8, issuer_byte: u8) -> Amount {
        Amount::Iou {
            value: IouValue {
                mantissa: value,
                exponent: 0,
            },
            currency: Currency {
                code: [currency_byte; 20],
            },
            issuer: [issuer_byte; 20],
        }
    }

    #[test]
    fn mpt_payment_with_paths_is_malformed() {
        let deliver = mpt(10, 3);
        let mut tx = payment_tx(deliver.clone());
        tx.paths = vec![vec![PathStep {
            account: Some([4u8; 20]),
            currency: None,
            issuer: None,
        }]];

        assert_eq!(payment_preflight(&tx, &deliver), Some("temMALFORMED"));
    }

    #[test]
    fn mpt_payment_rejects_limit_quality_and_no_direct_flags() {
        let deliver = mpt(10, 3);
        let mut tx = payment_tx(deliver.clone());
        tx.flags = TF_LIMIT_QUALITY;
        assert_eq!(
            payment_preflight(&tx, &deliver),
            Some("temBAD_SEND_XRP_LIMIT")
        );

        tx.flags = TF_NO_RIPPLE_DIRECT;
        assert_eq!(
            payment_preflight(&tx, &deliver),
            Some("temBAD_SEND_XRP_NO_DIRECT")
        );
    }

    #[test]
    fn mpt_send_max_must_match_delivery_issue_not_value() {
        let deliver = mpt(10, 3);
        let mut tx = payment_tx(deliver.clone());
        tx.send_max = Some(mpt(12, 3));

        assert_eq!(payment_preflight(&tx, &deliver), None);

        tx.send_max = Some(mpt(12, 4));
        assert_eq!(payment_preflight(&tx, &deliver), Some("temMALFORMED"));
    }

    #[test]
    fn mpt_deliver_min_uses_issue_identity_and_value_ordering() {
        let deliver = mpt(10, 3);
        let mut tx = payment_tx(deliver.clone());
        tx.flags = TF_PARTIAL_PAYMENT;
        tx.deliver_min = Some(mpt(5, 3));
        assert_eq!(payment_preflight(&tx, &deliver), None);

        tx.deliver_min = Some(mpt(11, 3));
        assert_eq!(payment_preflight(&tx, &deliver), Some("temBAD_AMOUNT"));

        tx.deliver_min = Some(mpt(5, 4));
        assert_eq!(payment_preflight(&tx, &deliver), Some("temBAD_AMOUNT"));
    }

    #[test]
    fn malformed_mpt_amount_is_bad_amount() {
        let deliver = Amount::Mpt(vec![0x60, 1, 2, 3]);
        let tx = payment_tx(deliver.clone());

        assert_eq!(payment_preflight(&tx, &deliver), Some("temBAD_AMOUNT"));
    }

    #[test]
    fn non_mpt_payment_with_mpt_send_max_is_malformed() {
        let deliver = iou(10, 3, 4);
        let mut tx = payment_tx(deliver.clone());
        tx.send_max = Some(mpt(10, 5));

        assert_eq!(payment_preflight(&tx, &deliver), Some("temMALFORMED"));
    }
}
