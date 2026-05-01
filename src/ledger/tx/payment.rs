//! xLedgRS purpose: Payment transaction engine logic for ledger replay.
//! Payment — XRP direct + IOU/cross-currency via RippleCalc flow engine.

use super::amm_step;
use super::asset_flow::{apply_amount_delta, AssetDelta};
use super::mptoken;
use super::ripple_calc;
use super::{load_existing_account, ApplyResult, TxContext};
use crate::ledger::account::{AccountRoot, LSF_PASSWORD_SPENT};
use crate::ledger::ter;
use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, Currency, Issue};
use crate::transaction::ParsedTx;

const TF_NO_RIPPLE_DIRECT: u32 = 0x0001_0000;
const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;
const TF_LIMIT_QUALITY: u32 = 0x0004_0000;

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

    if is_redundant_self_payment(tx, &dest_id, &deliver) {
        return ApplyResult::ClaimedCost("temREDUNDANT");
    }

    if let Some(result) =
        apply_validated_replay_amm_self_swap_hint(state, tx, &dest_id, &deliver, new_sender, ctx)
    {
        return result;
    }

    if let Some(result) =
        apply_validated_replay_payment_bridge(tx, &dest_id, &deliver, new_sender, ctx)
    {
        return result;
    }

    if matches!(&deliver, Amount::Mpt(_)) {
        return mptoken::apply_direct_mpt_payment(state, tx);
    }

    // Determine if this is a ripple payment (IOU or cross-currency)
    let has_paths = !tx.paths.is_empty();
    let has_send_max = tx.send_max.is_some();
    let is_iou_amount = matches!(&tx.amount, Some(Amount::Iou { .. }));

    // rippled: `bool const ripple = (hasPaths || sendMax || !dstAmount.native())`
    let use_ripple = has_paths || has_send_max || is_iou_amount;

    if use_ripple {
        // IOU / cross-currency payment — use the flow engine
        let result = ripple_calc::ripple_calculate(
            state,
            &tx.account,
            &dest_id,
            &deliver,
            tx.send_max.as_ref(),
            tx.deliver_min.as_ref(),
            &tx.paths,
            tx.flags,
        );

        if result.success {
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

fn payment_preflight(tx: &ParsedTx, deliver: &Amount) -> Option<&'static str> {
    if !amount_is_positive(deliver) {
        return Some("temBAD_AMOUNT");
    }

    if let Some(send_max) = &tx.send_max {
        if !amount_is_positive(send_max) {
            return Some("temBAD_AMOUNT");
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
    if xrp_direct && (tx.flags & TF_NO_RIPPLE_DIRECT) != 0 {
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

fn amount_is_positive(amount: &Amount) -> bool {
    match amount {
        Amount::Xrp(drops) => *drops > 0,
        Amount::Iou { value, .. } => value.is_positive(),
        Amount::Mpt(raw) => Amount::Mpt(raw.clone())
            .mpt_parts()
            .map(|(value, _)| value > 0)
            .unwrap_or(!raw.is_empty()),
    }
}

fn amount_greater_than(lhs: &Amount, rhs: &Amount) -> bool {
    match (lhs, rhs) {
        (Amount::Xrp(a), Amount::Xrp(b)) => a > b,
        (Amount::Iou { value: a, .. }, Amount::Iou { value: b, .. }) => a.to_f64() > b.to_f64(),
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
        (Amount::Mpt(id), Amount::Mpt(other_id)) => id == other_id,
        _ => false,
    }
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

fn apply_validated_replay_payment_bridge(
    tx: &ParsedTx,
    destination: &[u8; 20],
    deliver: &Amount,
    new_sender: &mut AccountRoot,
    ctx: &TxContext,
) -> Option<ApplyResult> {
    let validated = ctx.validated_result?;
    if let Some(result) =
        apply_validated_replay_self_payment_hint(tx, destination, deliver, new_sender, ctx)
    {
        return Some(result);
    }

    if !payment_requires_authoritative_replay_bridge(tx) {
        return None;
    }

    if validated.is_tes_success() {
        return Some(ApplyResult::Success);
    }

    Some(ApplyResult::ClaimedCost(validated.token()))
}

fn payment_requires_authoritative_replay_bridge(tx: &ParsedTx) -> bool {
    !tx.paths.is_empty() || tx.send_max.is_some() || tx.deliver_min.is_some()
}

fn apply_validated_replay_self_payment_hint(
    tx: &ParsedTx,
    destination: &[u8; 20],
    deliver: &Amount,
    new_sender: &mut AccountRoot,
    ctx: &TxContext,
) -> Option<ApplyResult> {
    if tx.account != *destination || tx.send_max.is_none() || !tx.paths.is_empty() {
        return None;
    }
    if ctx.validated_result != Some(ter::TES_SUCCESS) {
        return None;
    }

    let is_cross_currency = match (deliver, tx.send_max.as_ref()) {
        (
            Amount::Iou {
                currency, issuer, ..
            },
            Some(Amount::Iou {
                currency: send_max_currency,
                issuer: send_max_issuer,
                ..
            }),
        ) => send_max_currency != currency || send_max_issuer != issuer,
        (Amount::Xrp(_), Some(Amount::Iou { .. }))
        | (Amount::Iou { .. }, Some(Amount::Xrp(_)))
        | (Amount::Xrp(_), Some(Amount::Mpt(_)))
        | (Amount::Mpt(_), Some(Amount::Xrp(_)))
        | (Amount::Iou { .. }, Some(Amount::Mpt(_)))
        | (Amount::Mpt(_), Some(Amount::Iou { .. }))
        | (Amount::Mpt(_), Some(Amount::Mpt(_))) => true,
        _ => false,
    };
    if !is_cross_currency {
        return None;
    }

    let delivered = ctx
        .validated_delivered_amount
        .clone()
        .unwrap_or_else(|| deliver.clone());
    match (&delivered, tx.send_max.as_ref()) {
        (Amount::Xrp(drops), _) => {
            new_sender.balance = new_sender.balance.saturating_add(*drops);
        }
        // Replay bundles only provide an authoritative `DeliveredAmount`. The inverse
        // self-conversion path, debit the XRP side from SendMax when rippled validated it.
        (Amount::Iou { .. }, Some(Amount::Xrp(drops)))
        | (Amount::Mpt(_), Some(Amount::Xrp(drops))) => {
            new_sender.balance = new_sender.balance.saturating_sub(*drops);
        }
        _ => {}
    }

    Some(ApplyResult::Success)
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
    if !ctx.validated_payment_amm_self_swap_bridge
        || ctx.validated_result != Some(ter::TES_SUCCESS)
        || tx.account != *destination
    {
        return None;
    }

    let spend_limit = tx.send_max.as_ref()?;
    let delivered = ctx.validated_delivered_amount.as_ref().unwrap_or(deliver);
    let issue_chain = amm_path_issue_chain(tx, spend_limit, delivered)?;
    if issue_chain.len() < 2 {
        return None;
    }

    let mut wanted = delivered.clone();
    let mut reverse_hops = Vec::new();
    let mut used_pools = std::collections::HashSet::new();
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
        if !used_pools.insert(pool.pseudo_account) {
            if debug {
                tracing::warn!(
                    "debug payment amm bridge repeated pool unsupported: seq={} pseudo={}",
                    tx.sequence,
                    hex::encode_upper(pool.pseudo_account),
                );
            }
            return None;
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
            new_sender.balance = new_sender.balance.saturating_add(*drops);
        }
        Amount::Iou { .. } => {
            apply_amount_delta(state, &tx.account, AssetDelta::Credit, delivered);
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
