//! Offer — IMPLEMENTED

use super::amm_step;
use super::asset_flow::{
    apply_amount_delta, can_debit_amount, transfer_rate_gross_debit_amount, AssetDelta,
};
use super::flow::{
    amount_to_iou_value, apply_book_partial_fill_plan, ceil_in_strict_via_quality,
    ceil_out_strict_via_quality, compare_amounts, compare_iou_values, delete_offer_from_dirs,
    flow_with_input, iou_value_to_amount, offer_fully_consumed_by_output,
    plan_book_exact_in_all_qualities_for_taker, plan_book_exact_out_all_qualities_for_taker,
    quality_rate_from_u64, quote_offer_create_crossing_fill, quote_offer_for_desired_output,
    rewrite_partial_offer_after_output_fill, zero_amount_like, BookFillPlan, BookStep, FlowAmount,
    FlowBook, Strand,
};
use super::{balance_before_fee, load_existing_account, ApplyResult};
use crate::ledger::account::{LSF_GLOBAL_FREEZE, LSF_REQUIRE_AUTH};
use crate::ledger::directory;
use crate::ledger::offer::{amount_is_zero, rate_gte, subtract_amount, BookKey};
use crate::ledger::trustline::{
    LSF_HIGH_AUTH, LSF_HIGH_DEEP_FREEZE, LSF_HIGH_FREEZE, LSF_LOW_AUTH, LSF_LOW_DEEP_FREEZE,
    LSF_LOW_FREEZE,
};
use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, IouValue, Issue, QUALITY_ONE};
use crate::transaction::serialize::PREFIX_TX_SIGN;
use crate::transaction::ParsedTx;

const TF_PASSIVE: u32 = 0x00010000;
const TF_SELL: u32 = 0x00080000;
const TF_HYBRID: u32 = 0x00100000;

fn round_quality_to_tick_size(quality: u64, tick_size: u8) -> u64 {
    const MOD: [u64; 17] = [
        10_000_000_000_000_000,
        1_000_000_000_000_000,
        100_000_000_000_000,
        10_000_000_000_000,
        1_000_000_000_000,
        100_000_000_000,
        10_000_000_000,
        1_000_000_000,
        100_000_000,
        10_000_000,
        1_000_000,
        100_000,
        10_000,
        1_000,
        100,
        10,
        1,
    ];
    let digits = (tick_size as usize).min(16);
    let exponent = quality >> 56;
    let mut mantissa = quality & 0x00FF_FFFF_FFFF_FFFF;
    mantissa = mantissa.saturating_add(MOD[digits].saturating_sub(1));
    mantissa -= mantissa % MOD[digits];
    (exponent << 56) | mantissa
}

fn amount_issue_tick_size(state: &mut LedgerState, amount: &Amount) -> u8 {
    let Amount::Iou { issuer, .. } = amount else {
        return 16;
    };
    load_existing_account(state, issuer)
        .and_then(|account| {
            if account.tick_size > 0 {
                Some(account.tick_size)
            } else {
                None
            }
        })
        .unwrap_or(16)
}

fn issue_from_amount(amount: &Amount) -> Option<Issue> {
    match amount {
        Amount::Xrp(_) => Some(Issue::Xrp),
        Amount::Iou {
            currency, issuer, ..
        } => Some(Issue::Iou {
            currency: currency.clone(),
            issuer: *issuer,
        }),
        Amount::Mpt(raw) => {
            let (_, issuance) = Amount::Mpt(raw.clone()).mpt_parts()?;
            Some(Issue::Mpt(issuance))
        }
    }
}

fn try_offer_create_xrp_autobridge_sell(
    state: &mut LedgerState,
    taker: [u8; 20],
    remaining_gets: &Amount,
    remaining_pays: &Amount,
    close_time: u64,
    domain_id: Option<[u8; 32]>,
) -> Option<(FlowAmount, FlowAmount)> {
    if !matches!(remaining_gets, Amount::Iou { .. })
        || !matches!(remaining_pays, Amount::Iou { .. })
    {
        return None;
    }

    let in_issue = issue_from_amount(remaining_gets)?;
    let out_issue = issue_from_amount(remaining_pays)?;
    let first = BookStep::new(
        FlowBook::with_domain(in_issue, Issue::Xrp, domain_id),
        taker,
        taker,
    )
    .with_close_time(close_time)
    .with_all_qualities(true)
    .with_offer_crossing(true);
    let second = BookStep::new(
        FlowBook::with_domain(Issue::Xrp, out_issue, domain_id),
        taker,
        taker,
    )
    .with_close_time(close_time)
    .with_all_qualities(true)
    .with_offer_crossing(true);
    let mut strand = Strand::new(vec![Box::new(first), Box::new(second)]);
    state.begin_tx();
    let result = flow_with_input(state, &mut strand, FlowAmount::new(remaining_gets.clone()));
    if !result.success {
        state.discard_tx();
        return None;
    }
    let (Some(input), Some(output)) = (result.input, result.output) else {
        state.discard_tx();
        return None;
    };
    if !rate_gte(
        output.as_amount(),
        input.as_amount(),
        remaining_pays,
        remaining_gets,
    ) {
        state.discard_tx();
        return None;
    }
    let _commit = state.commit_tx();
    Some((input, output))
}

fn try_offer_create_xrp_autobridge_buy(
    state: &mut LedgerState,
    taker: [u8; 20],
    remaining_gets: &Amount,
    remaining_pays: &Amount,
    close_time: u64,
    domain_id: Option<[u8; 32]>,
) -> Option<(FlowAmount, FlowAmount)> {
    if !matches!(remaining_gets, Amount::Iou { .. })
        || !matches!(remaining_pays, Amount::Iou { .. })
    {
        return None;
    }

    let in_issue = issue_from_amount(remaining_gets)?;
    let out_issue = issue_from_amount(remaining_pays)?;
    let first_book = FlowBook::with_domain(in_issue, Issue::Xrp, domain_id);
    let second_book = FlowBook::with_domain(Issue::Xrp, out_issue, domain_id);

    let second_plan = plan_book_exact_out_all_qualities_for_taker(
        state,
        &second_book,
        &FlowAmount::new(remaining_pays.clone()),
        close_time,
        super::flow::RIPPLE_MAX_OFFERS_CONSIDERED,
        taker,
        taker,
    );
    if !second_plan.complete {
        return None;
    }
    let xrp_needed = second_plan.input.clone()?;

    let first_plan = plan_book_exact_out_all_qualities_for_taker(
        state,
        &first_book,
        &xrp_needed,
        close_time,
        super::flow::RIPPLE_MAX_OFFERS_CONSIDERED,
        taker,
        taker,
    );
    if !first_plan.complete {
        return None;
    }
    let spent_input = first_plan.input.clone()?;
    if compare_amounts(spent_input.as_amount(), remaining_gets) == std::cmp::Ordering::Greater {
        return None;
    }

    let first_result = super::flow::apply_book_fill_plan(state, &first_plan, taker, taker).ok()?;
    let second_result =
        super::flow::apply_book_fill_plan(state, &second_plan, taker, taker).ok()?;
    Some((first_result.input, second_result.output))
}

fn multiply_amount_by_rate(amount: &Amount, rate: &IouValue) -> Amount {
    let value = amount_to_iou_value(amount).mul_round(rate, false);
    iou_value_to_amount(&value, amount)
}

fn divide_amount_by_rate(amount: &Amount, rate: &IouValue) -> Amount {
    let value = amount_to_iou_value(amount).div_round(rate, false);
    iou_value_to_amount(&value, amount)
}

fn apply_offer_tick_size_rounding(
    state: &mut LedgerState,
    tx_flags: u32,
    pays: &mut Amount,
    gets: &mut Amount,
) {
    let tick_size = amount_issue_tick_size(state, pays).min(amount_issue_tick_size(state, gets));
    if tick_size >= 16 {
        return;
    }

    let quality = directory::offer_quality(gets, pays);
    let rounded_quality = round_quality_to_tick_size(quality, tick_size);
    let rate = quality_rate_from_u64(rounded_quality);
    if rate.is_zero() {
        return;
    }

    // Match rippled OfferCreate.cpp: after tick rounding, adjust the side
    // that is not exact. For tfSell the exact side is TakerGets; otherwise
    // the exact side is TakerPays.
    if (tx_flags & TF_SELL) != 0 {
        *pays = multiply_amount_by_rate(gets, &rate);
    } else {
        *gets = divide_amount_by_rate(pays, &rate);
    }
}

fn quality_rate_to_iou_value(rate: u32) -> IouValue {
    let mut value = IouValue {
        mantissa: rate as i64,
        exponent: -9,
    };
    value.normalize();
    value
}

fn transfer_rate_adjusted_send_max(
    state: &mut LedgerState,
    taker: &[u8; 20],
    send_max: &Amount,
) -> Amount {
    let Amount::Iou {
        value,
        currency,
        issuer,
    } = send_max
    else {
        return send_max.clone();
    };
    if taker == issuer {
        return send_max.clone();
    }

    let transfer_rate = load_existing_account(state, issuer)
        .map(|account| {
            if account.transfer_rate == 0 {
                QUALITY_ONE
            } else {
                account.transfer_rate
            }
        })
        .unwrap_or(QUALITY_ONE);
    if transfer_rate == QUALITY_ONE {
        return send_max.clone();
    }

    // rippled builds the crossing threshold from sendMax inflated by the
    // input issuer transfer rate: multiplyRound(..., roundUp=true).
    let rate = quality_rate_to_iou_value(transfer_rate);
    Amount::Iou {
        value: value.mul_round(&rate, true),
        currency: currency.clone(),
        issuer: *issuer,
    }
}

fn spendable_iou_funds_for_offer(
    state: &mut LedgerState,
    account: &[u8; 20],
    issuer: &[u8; 20],
    currency: &crate::transaction::amount::Currency,
) -> IouValue {
    if load_existing_account(state, issuer)
        .map(|issuer_account| (issuer_account.flags & LSF_GLOBAL_FREEZE) != 0)
        .unwrap_or(false)
    {
        return IouValue::ZERO;
    }
    if lp_token_underlying_frozen_for_offer(state, account, issuer) {
        return IouValue::ZERO;
    }

    let trustline = load_trustline_for_offer_funds(state, account, issuer, currency);

    let Some(trustline) = trustline else {
        return IouValue::ZERO;
    };

    if trustline_is_frozen_by_issuer(&trustline, issuer)
        || (trustline.flags & (LSF_LOW_DEEP_FREEZE | LSF_HIGH_DEEP_FREEZE)) != 0
    {
        return IouValue::ZERO;
    }
    if !trustline_authorized_by_issuer_for_offer(state, account, issuer, &trustline) {
        return IouValue::ZERO;
    }

    let balance = trustline.balance_for(account);
    let opposite_limit = if account == &trustline.low_account {
        trustline.high_limit
    } else {
        trustline.low_limit
    };
    balance.add(&opposite_limit)
}

fn lp_token_underlying_frozen_for_offer(
    state: &mut LedgerState,
    account: &[u8; 20],
    lp_issuer: &[u8; 20],
) -> bool {
    let Some(lp_issuer_account) = load_existing_account(state, lp_issuer) else {
        return false;
    };
    let Some(amm_id) = account_amm_id(&lp_issuer_account) else {
        return false;
    };
    let Some((asset1, asset2)) = load_amm_assets(state, &amm_id) else {
        return true;
    };
    issue_frozen_for_offer(state, account, &asset1)
        || issue_frozen_for_offer(state, account, &asset2)
}

fn account_amm_id(account: &crate::ledger::account::AccountRoot) -> Option<[u8; 32]> {
    let raw = account.raw_sle.as_ref()?;
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    let field = parsed
        .fields
        .iter()
        .find(|field| field.type_code == 5 && field.field_code == 14)?;
    if field.data.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&field.data);
    Some(id)
}

fn load_amm_assets(state: &LedgerState, amm_id: &[u8; 32]) -> Option<(Issue, Issue)> {
    let key = crate::ledger::keylet::amm_id(*amm_id).key;
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    let parsed = crate::ledger::meta::parse_sle(&raw)?;
    if parsed.entry_type != 0x0079 {
        return None;
    }
    let asset1 = parsed_issue(&parsed.fields, 24, 3)?;
    let asset2 = parsed_issue(&parsed.fields, 24, 4)?;
    Some((asset1, asset2))
}

fn parsed_issue(
    fields: &[crate::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<Issue> {
    let data = fields
        .iter()
        .find(|field| field.type_code == type_code && field.field_code == field_code)
        .map(|field| field.data.as_slice())?;
    Issue::from_bytes(data).map(|(issue, _)| issue)
}

fn issue_frozen_for_offer(state: &mut LedgerState, account: &[u8; 20], issue: &Issue) -> bool {
    let Issue::Iou { currency, issuer } = issue else {
        return false;
    };

    if load_existing_account(state, issuer)
        .map(|issuer_account| (issuer_account.flags & LSF_GLOBAL_FREEZE) != 0)
        .unwrap_or(false)
    {
        return true;
    }

    let Some(line) = load_trustline_for_offer_funds(state, account, issuer, currency) else {
        return false;
    };
    trustline_is_frozen_by_issuer(&line, issuer)
}

fn trustline_is_frozen_by_issuer(
    trustline: &crate::ledger::RippleState,
    issuer: &[u8; 20],
) -> bool {
    if issuer == &trustline.low_account {
        (trustline.flags & LSF_LOW_FREEZE) != 0
    } else if issuer == &trustline.high_account {
        (trustline.flags & LSF_HIGH_FREEZE) != 0
    } else {
        false
    }
}

fn load_trustline_for_offer_funds(
    state: &mut LedgerState,
    account: &[u8; 20],
    issuer: &[u8; 20],
    currency: &crate::transaction::amount::Currency,
) -> Option<crate::ledger::RippleState> {
    let key = crate::ledger::trustline::shamap_key(account, issuer, currency);
    if let Some(tl) = state.get_trustline(&key) {
        return Some(tl.clone());
    }
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    let tl = crate::ledger::RippleState::decode_from_sle(&raw)?;
    state.hydrate_trustline(tl.clone());
    Some(tl)
}

fn auth_flag_for_issuer(issuer: &[u8; 20], trustline: &crate::ledger::RippleState) -> Option<u32> {
    if issuer == &trustline.low_account {
        Some(LSF_LOW_AUTH)
    } else if issuer == &trustline.high_account {
        Some(LSF_HIGH_AUTH)
    } else {
        None
    }
}

fn trustline_authorized_by_issuer_for_offer(
    state: &mut LedgerState,
    holder: &[u8; 20],
    issuer: &[u8; 20],
    trustline: &crate::ledger::RippleState,
) -> bool {
    if holder == issuer {
        return true;
    }
    let Some(issuer_account) = load_existing_account(state, issuer) else {
        return true;
    };
    if (issuer_account.flags & LSF_REQUIRE_AUTH) == 0 {
        return true;
    }
    auth_flag_for_issuer(issuer, trustline)
        .map(|flag| (trustline.flags & flag) != 0)
        .unwrap_or(false)
}

fn check_offer_global_freeze(state: &mut LedgerState, amount: &Amount) -> Option<ApplyResult> {
    let Amount::Iou { issuer, .. } = amount else {
        return None;
    };
    let issuer_acct = load_existing_account(state, issuer)?;
    if (issuer_acct.flags & LSF_GLOBAL_FREEZE) != 0 {
        Some(ApplyResult::ClaimedCost("tecFROZEN"))
    } else {
        None
    }
}

fn check_offer_accept_asset(
    state: &mut LedgerState,
    account: &[u8; 20],
    amount: &Amount,
) -> Option<ApplyResult> {
    let Amount::Iou {
        currency, issuer, ..
    } = amount
    else {
        return None;
    };

    let issuer_acct = match load_existing_account(state, issuer) {
        Some(account) => account,
        None => return Some(ApplyResult::ClaimedCost("tecNO_ISSUER")),
    };

    if issuer == account {
        return None;
    }

    let trustline = load_trustline_for_offer_funds(state, account, issuer, currency);
    if (issuer_acct.flags & LSF_REQUIRE_AUTH) != 0 {
        let Some(trustline) = trustline.as_ref() else {
            return Some(ApplyResult::ClaimedCost("tecNO_LINE"));
        };
        let Some(auth_flag) = auth_flag_for_issuer(issuer, trustline) else {
            return Some(ApplyResult::ClaimedCost("tecNO_LINE"));
        };
        if (trustline.flags & auth_flag) == 0 {
            return Some(ApplyResult::ClaimedCost("tecNO_AUTH"));
        }
    }

    if let Some(trustline) = trustline {
        if trustline_is_frozen_by_issuer(&trustline, issuer)
            || (trustline.flags & (LSF_LOW_DEEP_FREEZE | LSF_HIGH_DEEP_FREEZE)) != 0
        {
            return Some(ApplyResult::ClaimedCost("tecFROZEN"));
        }
    }

    None
}

fn debug_offer_funding_enabled(seq: u32) -> bool {
    std::env::var("XLEDGRSV2BETA_DEBUG_OFFER_SEQS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|entry| entry.trim().parse::<u32>().ok())
                .any(|target| target == seq)
        })
        .unwrap_or(false)
}

fn rate_gt(a_pays: &Amount, a_gets: &Amount, b_pays: &Amount, b_gets: &Amount) -> bool {
    rate_gte(a_pays, a_gets, b_pays, b_gets) && !rate_gte(b_pays, b_gets, a_pays, a_gets)
}

fn extract_additional_books_from_signing_payload(payload: &[u8]) -> Vec<[u8; 32]> {
    if payload.len() < PREFIX_TX_SIGN.len() || payload[..PREFIX_TX_SIGN.len()] != PREFIX_TX_SIGN {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut pos = PREFIX_TX_SIGN.len();
    while pos < payload.len() {
        if payload[pos] == 0xE1 {
            break;
        }

        let (tc, fc, header_end) = crate::ledger::meta::read_field_header(payload, pos);
        if header_end > payload.len() {
            break;
        }
        pos = header_end;

        if tc == 19 && fc == 13 {
            let (vl_len, vl_bytes) = crate::transaction::serialize::decode_length(&payload[pos..]);
            if vl_bytes == 0 || pos + vl_bytes + vl_len > payload.len() {
                break;
            }
            pos += vl_bytes;
            let raw = &payload[pos..pos + vl_len];
            for chunk in raw.chunks_exact(32) {
                if let Ok(book) = chunk.try_into() {
                    out.push(book);
                }
            }
            pos += vl_len;
            continue;
        }

        let next = crate::ledger::meta::skip_field_raw(payload, pos, tc);
        if next <= pos {
            break;
        }
        pos = next;
    }

    out
}

fn build_standing_offer(
    tx: &ParsedTx,
    offer_seq: u32,
    remaining_pays: Amount,
    remaining_gets: Amount,
    book_directory: [u8; 32],
    book_node: u64,
    owner_node: u64,
    additional_books: Vec<[u8; 32]>,
) -> crate::ledger::Offer {
    let mut sle_flags: u32 = 0;
    if (tx.flags & TF_PASSIVE) != 0 {
        sle_flags |= crate::ledger::offer::LSF_PASSIVE;
    }
    if (tx.flags & TF_SELL) != 0 {
        sle_flags |= crate::ledger::offer::LSF_SELL;
    }
    if (tx.flags & TF_HYBRID) != 0 {
        sle_flags |= crate::ledger::offer::LSF_HYBRID;
    }

    crate::ledger::Offer {
        account: tx.account,
        sequence: offer_seq,
        taker_pays: remaining_pays,
        taker_gets: remaining_gets,
        flags: sle_flags,
        book_directory,
        book_node,
        owner_node,
        expiration: tx.expiration,
        domain_id: tx.domain_id,
        additional_books,
        previous_txn_id: [0u8; 32],
        previous_txn_lgr_seq: 0,
        raw_sle: None,
    }
}

fn try_offer_create_amm_cross(
    state: &mut LedgerState,
    taker: [u8; 20],
    remaining_gets: &Amount,
    remaining_pays: &Amount,
    is_sell: bool,
    domain_id: Option<[u8; 32]>,
) -> Option<(FlowAmount, FlowAmount)> {
    if domain_id.is_some() {
        return None;
    }
    let asset_in = amm_step::issue_from_amount(remaining_gets)?;
    let asset_out = amm_step::issue_from_amount(remaining_pays)?;
    if asset_in == asset_out {
        return None;
    }
    let funded_gets = offer_funded_input(state, &taker, remaining_gets)?;
    let pool = amm_step::load_amm_pool(state, &asset_in, &asset_out)?;

    let quote = if is_sell {
        amm_step::quote_exact_in(&pool, &funded_gets)?
    } else {
        match amm_step::quote_exact_out(&pool, remaining_pays) {
            Some(exact_out) if amm_step::amount_leq(&exact_out.spent_in, &funded_gets)? => {
                exact_out
            }
            _ => amm_step::quote_exact_in(&pool, &funded_gets)?,
        }
    };

    if amount_is_zero(&quote.spent_in) || amount_is_zero(&quote.delivered_out) {
        return None;
    }
    if compare_amounts(&quote.spent_in, remaining_gets) == std::cmp::Ordering::Greater {
        return None;
    }
    if !is_sell
        && compare_amounts(&quote.delivered_out, remaining_pays) == std::cmp::Ordering::Greater
    {
        return None;
    }
    if !rate_gte(
        &quote.delivered_out,
        &quote.spent_in,
        remaining_pays,
        remaining_gets,
    ) {
        return None;
    }

    state.begin_tx();
    if !amm_step::apply_swap_to_state(state, &pool, &quote, &taker, &taker) {
        state.discard_tx();
        return None;
    }
    let _commit = state.commit_tx();
    Some((
        FlowAmount::new(quote.spent_in),
        FlowAmount::new(quote.delivered_out),
    ))
}

fn offer_funded_input(
    state: &mut LedgerState,
    account: &[u8; 20],
    amount: &Amount,
) -> Option<Amount> {
    match amount {
        Amount::Xrp(requested) => {
            let fees = crate::ledger::read_fees(state);
            let acct = load_existing_account(state, account)?;
            let reserve = fees.reserve + (acct.owner_count as u64 * fees.increment);
            let available = acct.balance.saturating_sub(reserve);
            if available == 0 {
                return None;
            }
            Some(Amount::Xrp((*requested).min(available)))
        }
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            if account == issuer {
                return Some(amount.clone());
            }

            let available = spendable_iou_funds_for_offer(state, account, issuer, currency);
            if !available.is_positive() {
                return None;
            }
            if compare_iou_values(&available, value) == std::cmp::Ordering::Less {
                Some(Amount::Iou {
                    value: available,
                    currency: currency.clone(),
                    issuer: *issuer,
                })
            } else {
                Some(amount.clone())
            }
        }
        Amount::Mpt(_) => None,
    }
}

fn offer_create_should_remove_tiny_reduced_quality_offer(
    offer: &crate::ledger::Offer,
    owner_funds: &Amount,
) -> bool {
    let in_is_xrp = matches!(offer.taker_pays, Amount::Xrp(_));
    let out_is_xrp = matches!(offer.taker_gets, Amount::Xrp(_));

    if out_is_xrp {
        return false;
    }
    if !in_is_xrp
        && compare_amounts(&offer.taker_pays, &offer.taker_gets) != std::cmp::Ordering::Less
    {
        return false;
    }

    let (effective_in, effective_out) = match &offer.taker_gets {
        Amount::Iou { issuer, .. } if offer.account != *issuer => {
            if compare_amounts(owner_funds, &offer.taker_gets) == std::cmp::Ordering::Less {
                let Some(quote) = quote_offer_for_desired_output(offer, owner_funds, false) else {
                    return true;
                };
                (quote.input, quote.output)
            } else {
                (offer.taker_pays.clone(), offer.taker_gets.clone())
            }
        }
        _ => (offer.taker_pays.clone(), offer.taker_gets.clone()),
    };

    if amount_is_zero(&effective_in) || amount_is_zero(&effective_out) {
        return true;
    }
    if amount_gt_min_positive(&effective_in) {
        return false;
    }

    let effective_quality = directory::offer_quality(&effective_out, &effective_in);
    effective_quality < stored_offer_quality(offer)
}

fn amount_gt_min_positive(amount: &Amount) -> bool {
    match amount {
        Amount::Xrp(drops) => *drops > 1,
        Amount::Iou { value, .. } => value.mantissa > 1_000_000_000_000_000 || value.exponent > -96,
        Amount::Mpt(_) => false,
    }
}

fn stored_offer_quality(offer: &crate::ledger::Offer) -> u64 {
    if offer.book_directory != [0u8; 32] {
        let mut q = [0u8; 8];
        q.copy_from_slice(&offer.book_directory[24..32]);
        u64::from_be_bytes(q)
    } else {
        directory::offer_quality(&offer.taker_gets, &offer.taker_pays)
    }
}

fn offer_book_has_self_cross_candidate(
    state: &LedgerState,
    book_key: &BookKey,
    account: &[u8; 20],
) -> bool {
    state
        .get_book(book_key)
        .map(|book| {
            book.iter_by_quality().any(|key| {
                state
                    .get_offer(key)
                    .map(|offer| &offer.account == account)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn offer_create_plan_crosses_threshold(
    plan: &BookFillPlan,
    threshold_pays: &Amount,
    threshold_gets: &Amount,
    passive: bool,
) -> bool {
    !plan.fills.is_empty()
        && plan.fills.iter().all(|fill| {
            if passive {
                rate_gt(&fill.output, &fill.input, threshold_pays, threshold_gets)
            } else {
                rate_gte(&fill.output, &fill.input, threshold_pays, threshold_gets)
            }
        })
}

fn try_offer_create_book_amm_flow_cross(
    state: &mut LedgerState,
    taker: [u8; 20],
    remaining_gets: &Amount,
    remaining_pays: &Amount,
    threshold_gets: &Amount,
    threshold_pays: &Amount,
    is_sell: bool,
    passive: bool,
    close_time: u64,
    domain_id: Option<[u8; 32]>,
) -> Option<(FlowAmount, FlowAmount)> {
    let in_issue = issue_from_amount(remaining_gets)?;
    let out_issue = issue_from_amount(remaining_pays)?;
    if in_issue == out_issue {
        return None;
    }
    let book = FlowBook::with_domain(in_issue, out_issue, domain_id);
    let book_key = BookKey::from_amounts_with_domain(remaining_gets, remaining_pays, domain_id);
    if offer_book_has_self_cross_candidate(state, &book_key, &taker) {
        return None;
    }

    let funded_gets = offer_funded_input(state, &taker, remaining_gets)?;
    let plan = if is_sell {
        plan_book_exact_in_all_qualities_for_taker(
            state,
            &book,
            &FlowAmount::new(funded_gets),
            close_time,
            850,
            taker,
            taker,
        )
    } else {
        plan_book_exact_out_all_qualities_for_taker(
            state,
            &book,
            &FlowAmount::new(remaining_pays.clone()),
            close_time,
            850,
            taker,
            taker,
        )
    };
    if !offer_create_plan_crosses_threshold(&plan, threshold_pays, threshold_gets, passive) {
        return None;
    }
    if let Some(input) = plan.input.as_ref() {
        if compare_amounts(input.as_amount(), remaining_gets) == std::cmp::Ordering::Greater {
            return None;
        }
    }
    if !is_sell {
        if let Some(output) = plan.output.as_ref() {
            if compare_amounts(output.as_amount(), remaining_pays) == std::cmp::Ordering::Greater {
                return None;
            }
        }
    }

    let result = apply_book_partial_fill_plan(state, &plan, taker, taker).ok()?;
    Some((result.input, result.output))
}

/// Apply an OfferCreate: attempt to cross against the opposite book,
/// then place any unfilled remainder as a standing order.
pub(crate) fn apply_offer_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    const TF_IMMEDIATE_OR_CANCEL: u32 = 0x0002_0000;
    const TF_FILL_OR_KILL: u32 = 0x0004_0000;

    if (tx.flags & TF_IMMEDIATE_OR_CANCEL) != 0 && (tx.flags & TF_FILL_OR_KILL) != 0 {
        return ApplyResult::ClaimedCost("temINVALID_FLAG");
    }
    if (tx.flags & TF_HYBRID) != 0 && tx.domain_id.is_none() {
        return ApplyResult::ClaimedCost("temINVALID_FLAG");
    }
    if let Some(domain_id) = tx.domain_id {
        if !super::permissioned_domain::account_in_domain(
            state,
            &tx.account,
            &domain_id,
            close_time,
        ) {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
    }
    if tx.expiration == Some(0) {
        return ApplyResult::ClaimedCost("temBAD_EXPIRATION");
    }

    let mut owner_count_deltas: std::collections::BTreeMap<[u8; 20], i32> =
        std::collections::BTreeMap::new();
    let mut released_gets_from_cancel: Option<Amount> = None;

    let mut remaining_pays = match &tx.taker_pays {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temBAD_OFFER"),
    };
    let mut remaining_gets = match &tx.taker_gets {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temBAD_OFFER"),
    };
    let offer_seq = super::sequence_proxy(tx);
    let pre_fee_balance = load_existing_account(state, &tx.account)
        .map(|account| balance_before_fee(account.balance, tx.fee))
        .unwrap_or(0);

    // Validate offer amounts are non-zero
    if amount_is_zero(&remaining_pays) || amount_is_zero(&remaining_gets) {
        return ApplyResult::ClaimedCost("temBAD_OFFER");
    }

    if let Some(expiration) = tx.expiration {
        if close_time >= expiration as u64 {
            return ApplyResult::ClaimedCost("tecEXPIRED");
        }
    }

    // rippled OfferCreate::preclaim rejects offers involving globally frozen
    // issues and verifies the maker can receive TakerPays before crossing.
    if let Some(result) = check_offer_global_freeze(state, &remaining_pays)
        .or_else(|| check_offer_global_freeze(state, &remaining_gets))
    {
        return result;
    }
    if let Some(result) = check_offer_accept_asset(state, &tx.account, &remaining_pays) {
        return result;
    }

    if let Some(cancel_seq) = tx.offer_sequence {
        if cancel_seq == 0 {
            return ApplyResult::ClaimedCost("temBAD_SEQUENCE");
        }
        // The sender AccountRoot has already had Sequence applied by the
        // legacy apply path, so use the transaction's original Sequence for
        // non-ticketed OfferCreate preclaim parity.
        if tx.ticket_sequence.is_none() && tx.sequence <= cancel_seq {
            return ApplyResult::ClaimedCost("temBAD_SEQUENCE");
        }
    }

    // Explicit cancellation: if OfferSequence is set, cancel that specific old offer
    // before processing the new one (rippled OfferCreate.cpp behavior).
    if let Some(cancel_seq) = tx.offer_sequence {
        let cancel_key = crate::ledger::offer::shamap_key(&tx.account, cancel_seq);
        // Hydrate from NuDB if not in typed map — offers from earlier ledgers
        // live only in NuDB until explicitly loaded. Without this, remove_offer
        // returns None and the cancellation is silently skipped, leaving a
        // stale offer + book directory entry. This was Bug C.
        if let Some(deleted) = delete_offer_from_dirs(state, &cancel_key) {
            let old = deleted.offer;
            *owner_count_deltas.entry(old.account).or_insert(0) -= 1;
            released_gets_from_cancel = Some(old.taker_gets.clone());
        }
    }

    // rippled rounds the initial offer rate to the smallest TickSize set by
    // either non-XRP issuer before crossing and before standing placement.
    apply_offer_tick_size_rounding(state, tx.flags, &mut remaining_pays, &mut remaining_gets);
    if amount_is_zero(&remaining_pays) || amount_is_zero(&remaining_gets) {
        return ApplyResult::Success;
    }

    let original_pays = remaining_pays.clone();
    let original_gets = remaining_gets.clone();
    let threshold_pays = original_pays.clone();
    let threshold_gets = transfer_rate_adjusted_send_max(state, &tx.account, &original_gets);
    let original_book_key =
        BookKey::from_amounts_with_domain(&original_pays, &original_gets, tx.domain_id);
    let original_book_quality = directory::offer_quality(&original_gets, &original_pays);
    let original_book_directory =
        directory::book_dir_quality_key(&original_book_key, original_book_quality);

    // Funding check: does the account have enough of TakerGets to back the offer?
    // rippled returns tecUNFUNDED_OFFER if the account can't fund the offer.
    let funded = match &remaining_gets {
        Amount::Xrp(_) => {
            // Rippled only rejects as unfunded when spendable XRP is zero.
            // The offer amount itself may exceed the current liquid balance.
            let fees = crate::ledger::read_fees(state);
            let acct = load_existing_account(state, &tx.account);
            let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
            let owner_count = acct.as_ref().map(|a| a.owner_count).unwrap_or(0);
            let owner_delta = owner_count_deltas.get(&tx.account).copied().unwrap_or(0) as i64;
            let effective_owner_count = (owner_count as i64 + owner_delta).max(0) as u64;
            let reserve = fees.reserve + (effective_owner_count * fees.increment);
            let released = match released_gets_from_cancel.as_ref() {
                Some(Amount::Xrp(d)) => *d,
                _ => 0,
            };
            balance.saturating_add(released).saturating_sub(reserve) > 0
        }
        Amount::Iou {
            currency, issuer, ..
        } => {
            if &tx.account == issuer {
                true
            } else {
                // For IOU: spendable funds include the counterparty's credit
                // headroom on the trust line, not just a currently-positive
                // balance.
                let mut available =
                    spendable_iou_funds_for_offer(state, &tx.account, issuer, currency);

                if let Some(Amount::Iou {
                    value: released,
                    currency: rel_currency,
                    issuer: rel_issuer,
                }) = released_gets_from_cancel.as_ref()
                {
                    if rel_currency == currency && rel_issuer == issuer {
                        available = available.add(released);
                    }
                }

                available.is_positive()
            }
        }
        _ => true,
    };
    if !funded {
        if debug_offer_funding_enabled(tx.sequence) {
            if let Amount::Iou {
                currency, issuer, ..
            } = &remaining_gets
            {
                let trustline =
                    load_trustline_for_offer_funds(state, &tx.account, issuer, currency);
                let available = spendable_iou_funds_for_offer(state, &tx.account, issuer, currency);
                if let Some(tl) = trustline {
                    let balance = tl.balance_for(&tx.account);
                    let opposite_limit = if tx.account == tl.low_account {
                        tl.high_limit
                    } else {
                        tl.low_limit
                    };
                    tracing::warn!(
                        "offer funding debug: seq={} acct={} issuer={} balance={}e{} low_limit={}e{} high_limit={}e{} opposite_limit={}e{} available={}e{}",
                        tx.sequence,
                        hex::encode_upper(tx.account),
                        hex::encode_upper(issuer),
                        balance.mantissa,
                        balance.exponent,
                        tl.low_limit.mantissa,
                        tl.low_limit.exponent,
                        tl.high_limit.mantissa,
                        tl.high_limit.exponent,
                        opposite_limit.mantissa,
                        opposite_limit.exponent,
                        available.mantissa,
                        available.exponent,
                    );
                } else {
                    tracing::warn!(
                        "offer funding debug: seq={} acct={} issuer={} trustline=missing available={}e{}",
                        tx.sequence,
                        hex::encode_upper(tx.account),
                        hex::encode_upper(issuer),
                        available.mantissa,
                        available.exponent,
                    );
                }
            }
        }
        return ApplyResult::ClaimedCost("tecUNFUNDED_OFFER");
    }

    // ── Cross against the opposite book ──────────────────────────────────────
    let opposite_key =
        BookKey::from_amounts_with_domain(&remaining_gets, &remaining_pays, tx.domain_id);

    // Collect crossing offer keys (can't mutate state while iterating)
    let crossing_keys: Vec<crate::ledger::Key> = state
        .get_book(&opposite_key)
        .map(|book| book.iter_by_quality().cloned().collect())
        .unwrap_or_default();

    let mut offers_to_remove = Vec::new();
    let mut fok_preserve_removals = Vec::new();
    const MAX_CROSSING_STEPS: usize = 850; // matches rippled
    let mut steps = 0;
    let mut crossed_any = false;
    let fok_atomic_crossing = (tx.flags & TF_FILL_OR_KILL) != 0;
    let mut direct_flow_crossed = false;
    if fok_atomic_crossing {
        state.begin_tx();
    }

    if !fok_atomic_crossing {
        if let Some((spent, delivered)) = try_offer_create_book_amm_flow_cross(
            state,
            tx.account,
            &remaining_gets,
            &remaining_pays,
            &threshold_gets,
            &threshold_pays,
            (tx.flags & TF_SELL) != 0,
            (tx.flags & TF_PASSIVE) != 0,
            close_time,
            tx.domain_id,
        ) {
            remaining_gets = subtract_amount(&remaining_gets, spent.as_amount());
            remaining_pays = subtract_amount(&remaining_pays, delivered.as_amount());
            crossed_any = true;
            direct_flow_crossed = true;
        }
    }

    if !direct_flow_crossed {
        for key in &crossing_keys {
            if steps >= MAX_CROSSING_STEPS {
                break;
            }
            steps += 1;
            let book_offer = match state.get_offer(key) {
                Some(o) => o.clone(),
                None => continue,
            };
            // Track that this account's owner count may change (consumed offer = -1)

            if amount_is_zero(&book_offer.taker_gets) {
                continue;
            }
            if amount_is_zero(&remaining_gets) {
                break;
            }
            // Skip expired offers (rippled: OfferCreate.cpp removes expired offers during crossing)
            if let Some(expiration) = book_offer.expiration {
                if close_time >= expiration as u64 {
                    offers_to_remove.push(*key);
                    fok_preserve_removals.push(*key);
                    continue;
                }
            }
            // Quality gate: stop crossing when the book offer's quality is worse
            // than what the taker specified. tfSell does NOT bypass this check —
            // it only affects which side constrains the fill (confirmed: rippled
            // with tfSell still respects quality and rejects worse-rate offers).
            //
            // This gate must be evaluated BEFORE the self-owned check: rippled's
            // BookStep::limitSelfCrossQuality (src/libxrpl/tx/paths/BookStep.cpp
            // :404-409) only removes self-owned offers when `offer.quality() >=
            // `qualityThreshold_`. Reversing the order previously caused the engine to
            // silently cancel a previous same-account offer in the opposite book
            // whenever the new offer walked the book, even when the prices
            // didn't actually overlap.
            let crosses = if (tx.flags & TF_PASSIVE) != 0 {
                // rippled increments the flow quality threshold for tfPassive,
                // so passive offers only cross strictly better book qualities.
                rate_gt(
                    &book_offer.taker_gets,
                    &book_offer.taker_pays,
                    &threshold_pays,
                    &threshold_gets,
                )
            } else {
                rate_gte(
                    &book_offer.taker_gets,
                    &book_offer.taker_pays,
                    &threshold_pays,
                    &threshold_gets,
                )
            };
            if !crosses {
                break;
            }

            // Self-owned offers at a crossing quality: rippled's
            // limitSelfCrossQuality removes them even though no actual trade
            // happens. Same-account "trade" would be meaningless, so the old
            // Offer is cancelled and book traversal continues.
            if book_offer.account == tx.account {
                offers_to_remove.push(*key);
                fok_preserve_removals.push(*key);
                continue;
            }

            let funded_offer_gets =
                match offer_funded_input(state, &book_offer.account, &book_offer.taker_gets) {
                    Some(amount) if !amount_is_zero(&amount) => amount,
                    _ => {
                        offers_to_remove.push(*key);
                        fok_preserve_removals.push(*key);
                        continue;
                    }
                };
            if offer_create_should_remove_tiny_reduced_quality_offer(
                &book_offer,
                &funded_offer_gets,
            ) {
                offers_to_remove.push(*key);
                fok_preserve_removals.push(*key);
                continue;
            }
            let remaining_send_max =
                transfer_rate_adjusted_send_max(state, &tx.account, &remaining_gets);
            let funded_taker_gets =
                match offer_funded_input(state, &tx.account, &remaining_send_max) {
                    Some(amount) if !amount_is_zero(&amount) => amount,
                    _ => break,
                };

            let is_sell = (tx.flags & TF_SELL) != 0;
            let Some(quote) = quote_offer_create_crossing_fill(
                &book_offer,
                &remaining_pays,
                &funded_taker_gets,
                &funded_offer_gets,
                is_sell,
            ) else {
                continue;
            };
            let (filled_pay, filled_receive) = (quote.input, quote.output);

            if amount_is_zero(&filled_pay) || amount_is_zero(&filled_receive) {
                continue;
            }

            let taker_debit = filled_pay.clone();
            let maker_debit = transfer_rate_gross_debit_amount(
                state,
                &book_offer.account,
                &tx.account,
                &filled_receive,
            );

            if !can_debit_amount(state, &book_offer.account, &maker_debit) {
                offers_to_remove.push(*key);
                fok_preserve_removals.push(*key);
                continue;
            }
            if !can_debit_amount(state, &tx.account, &taker_debit) {
                if fok_atomic_crossing {
                    state.discard_tx();
                    remove_offer_keys_and_decrement_owners(state, &fok_preserve_removals);
                }
                return ApplyResult::ClaimedCost("tecUNFUNDED_OFFER");
            }

            // Transfer assets between the two parties
            let _ = apply_amount_delta(state, &tx.account, AssetDelta::Credit, &filled_receive);
            let _ = apply_amount_delta(state, &tx.account, AssetDelta::Debit, &taker_debit);
            let _ = apply_amount_delta(state, &book_offer.account, AssetDelta::Credit, &filled_pay);
            let _ = apply_amount_delta(state, &book_offer.account, AssetDelta::Debit, &maker_debit);

            // Update the remaining want/give values.
            remaining_pays = subtract_amount(&remaining_pays, &filled_receive);
            remaining_gets = subtract_amount(&remaining_gets, &filled_pay);
            crossed_any = true;

            if offer_fully_consumed_by_output(&book_offer, &filled_receive, &funded_offer_gets) {
                offers_to_remove.push(*key);
            } else {
                state.remove_offer(key);
                if let Some(updated) =
                    rewrite_partial_offer_after_output_fill(&book_offer, &filled_receive)
                {
                    state.insert_offer(updated);
                } else {
                    // Offer fully consumed (remainder is zero) — remove from owner and book directories
                    let offer_key =
                        crate::ledger::offer::shamap_key(&book_offer.account, book_offer.sequence);
                    let removed_owner = directory::dir_remove_owner_page(
                        state,
                        &book_offer.account,
                        book_offer.owner_node,
                        &offer_key.0,
                    );
                    *owner_count_deltas.entry(book_offer.account).or_insert(0) -= 1;
                    if book_offer.book_directory != [0u8; 32] {
                        let removed_book = directory::dir_remove_root(
                            state,
                            &crate::ledger::Key(book_offer.book_directory),
                            &offer_key.0,
                        );
                        if !removed_owner || !removed_book {
                            let owner_still_has_entry = directory::owner_dir_contains_entry(
                                state,
                                &book_offer.account,
                                &offer_key.0,
                            );
                            tracing::warn!(
                            "offer replay remove miss (zero remainder): account={} seq={} owner_removed={} book_removed={} owner_has_entry={}",
                            hex::encode_upper(book_offer.account),
                            book_offer.sequence,
                            removed_owner,
                            removed_book,
                            owner_still_has_entry,
                        );
                        }
                    } else if !removed_owner {
                        let owner_still_has_entry = directory::owner_dir_contains_entry(
                            state,
                            &book_offer.account,
                            &offer_key.0,
                        );
                        tracing::warn!(
                        "offer replay owner-dir remove miss (zero remainder): account={} seq={} owner_has_entry={}",
                        hex::encode_upper(book_offer.account),
                        book_offer.sequence,
                        owner_still_has_entry,
                    );
                    }
                }
            }

            if amount_is_zero(&remaining_pays) {
                break;
            }
        }
    }

    // Remove consumed offers and decrement their owners' counts
    for key in &offers_to_remove {
        if let Some(deleted) = delete_offer_from_dirs(state, key) {
            let removed = deleted.offer;
            *owner_count_deltas.entry(removed.account).or_insert(0) -= 1;
            if !deleted.owner_removed || !deleted.book_removed {
                let offer_key =
                    crate::ledger::offer::shamap_key(&removed.account, removed.sequence);
                let owner_still_has_entry =
                    directory::owner_dir_contains_entry(state, &removed.account, &offer_key.0);
                tracing::warn!(
                    "offer replay remove miss (consumed): account={} seq={} owner_removed={} book_removed={} owner_has_entry={}",
                    hex::encode_upper(removed.account),
                    removed.sequence,
                    deleted.owner_removed,
                    deleted.book_removed,
                    owner_still_has_entry,
                );
            }
        }
    }

    if (tx.flags & TF_PASSIVE) == 0
        && !amount_is_zero(&remaining_gets)
        && !amount_is_zero(&remaining_pays)
    {
        let bridge_result = if (tx.flags & TF_SELL) != 0 {
            try_offer_create_xrp_autobridge_sell(
                state,
                tx.account,
                &remaining_gets,
                &remaining_pays,
                close_time,
                tx.domain_id,
            )
        } else {
            try_offer_create_xrp_autobridge_buy(
                state,
                tx.account,
                &remaining_gets,
                &remaining_pays,
                close_time,
                tx.domain_id,
            )
        };
        if let Some((spent, delivered)) = bridge_result {
            remaining_gets = subtract_amount(&remaining_gets, spent.as_amount());
            remaining_pays = subtract_amount(&remaining_pays, delivered.as_amount());
            crossed_any = true;
        }
    }

    if (tx.flags & TF_PASSIVE) == 0
        && !amount_is_zero(&remaining_gets)
        && !amount_is_zero(&remaining_pays)
    {
        if let Some((spent, delivered)) = try_offer_create_amm_cross(
            state,
            tx.account,
            &remaining_gets,
            &remaining_pays,
            (tx.flags & TF_SELL) != 0,
            tx.domain_id,
        ) {
            remaining_gets = subtract_amount(&remaining_gets, spent.as_amount());
            remaining_pays = subtract_amount(&remaining_pays, delivered.as_amount());
            crossed_any = true;
        }
    }

    if crossed_any
        && (tx.flags & TF_FILL_OR_KILL) == 0
        && offer_funded_input(state, &tx.account, &remaining_gets).is_none()
    {
        remaining_pays = zero_amount_like(&remaining_pays);
        remaining_gets = zero_amount_like(&remaining_gets);
    }

    if crossed_any && !amount_is_zero(&remaining_pays) && !amount_is_zero(&remaining_gets) {
        if (tx.flags & TF_SELL) != 0 {
            let (recomputed_pays, _) = ceil_out_strict_via_quality(
                &original_pays,
                &original_gets,
                &remaining_gets,
                &original_book_directory.0,
                true,
            );
            remaining_pays = recomputed_pays;
        } else {
            let (_, recomputed_gets) = ceil_in_strict_via_quality(
                &original_pays,
                &original_gets,
                &remaining_pays,
                &original_book_directory.0,
                false,
            );
            remaining_gets = recomputed_gets;
        }
    }

    // tfFillOrKill: cancel entire offer if any remainder (must be fully filled)
    if (tx.flags & TF_FILL_OR_KILL) != 0
        && (!amount_is_zero(&remaining_pays) || !amount_is_zero(&remaining_gets))
    {
        // Offer not fully filled — return tecKILLED (fee claimed, no offer placed)
        if fok_atomic_crossing {
            state.discard_tx();
            remove_offer_keys_and_decrement_owners(state, &fok_preserve_removals);
        }
        return ApplyResult::ClaimedCost("tecKILLED");
    }

    if (tx.flags & TF_IMMEDIATE_OR_CANCEL) != 0 && !crossed_any {
        return ApplyResult::ClaimedCost("tecKILLED");
    }

    // tfImmediateOrCancel: don't place remainder as standing offer
    let place_remainder = (tx.flags & TF_IMMEDIATE_OR_CANCEL) == 0;

    // ── Place remainder as standing offer ────────────────────────────────────
    if place_remainder && !amount_is_zero(&remaining_pays) && !amount_is_zero(&remaining_gets) {
        let fees = crate::ledger::read_fees(state);
        let acct = load_existing_account(state, &tx.account);
        let owner_count = acct.as_ref().map(|a| a.owner_count).unwrap_or(0);
        let owner_delta = owner_count_deltas.get(&tx.account).copied().unwrap_or(0) as i64;
        let effective_owner_count = (owner_count as i64 + owner_delta).max(0) as u64;
        let required = fees
            .reserve
            .saturating_add((effective_owner_count + 1).saturating_mul(fees.increment));
        if pre_fee_balance < required {
            if crossed_any {
                remaining_pays = zero_amount_like(&remaining_pays);
                remaining_gets = zero_amount_like(&remaining_gets);
            } else {
                return ApplyResult::ClaimedCost("tecINSUF_RESERVE_OFFER");
            }
        }

        if !amount_is_zero(&remaining_pays) && !amount_is_zero(&remaining_gets) {
            let offer_key = crate::ledger::offer::shamap_key(&tx.account, offer_seq);
            let owner_node = directory::dir_add(state, &tx.account, offer_key.0);
            let book_key =
                BookKey::from_amounts_with_domain(&remaining_pays, &remaining_gets, tx.domain_id);
            // rippled preserves the offer's original uRate for the standing
            // remainder. Recomputing from partially-filled amounts moves the
            // residual offer into the wrong quality directory.
            let book_quality = original_book_quality;
            let (book_directory, book_node) =
                directory::dir_add_book(state, &book_key, book_quality, offer_key.0);
            let mut additional_books =
                extract_additional_books_from_signing_payload(&tx.signing_payload);
            if (tx.flags & TF_HYBRID) != 0 && tx.domain_id.is_some() {
                let open_book_key = BookKey::from_amounts(&remaining_pays, &remaining_gets);
                let (open_book_directory, _) =
                    directory::dir_add_book(state, &open_book_key, book_quality, offer_key.0);
                if !additional_books.contains(&open_book_directory.0) {
                    additional_books.push(open_book_directory.0);
                }
            }
            let offer = build_standing_offer(
                tx,
                offer_seq,
                remaining_pays,
                remaining_gets,
                book_directory.0,
                book_node,
                owner_node,
                additional_books,
            );
            state.insert_offer(offer);
            *owner_count_deltas.entry(tx.account).or_insert(0) += 1;
        }
    }

    // Update owner counts via explicit deltas — NOT by recomputing from
    // directory entry count. rippled's adjustOwnerCount is called exactly
    // once per object add/remove: +1 for offers placed, -1 for offers
    // cancelled or consumed. Recomputing from the raw directory entry count
    // produces wrong results because some directory entries (trust lines,
    // tickets, etc. from other tx types) don't map 1:1 with OwnerCount.
    for (account, delta) in owner_count_deltas {
        if delta == 0 {
            continue;
        }
        if let Some(acct) = load_existing_account(state, &account) {
            let mut updated = acct.clone();
            updated.owner_count = if delta > 0 {
                updated.owner_count.saturating_add(delta as u32)
            } else {
                updated.owner_count.saturating_sub((-delta) as u32)
            };
            state.insert_account(updated);
        }
    }

    if fok_atomic_crossing {
        let _commit = state.commit_tx();
    }

    ApplyResult::Success
}

fn remove_offer_keys_and_decrement_owners(state: &mut LedgerState, keys: &[crate::ledger::Key]) {
    for key in keys {
        if let Some(deleted) = delete_offer_from_dirs(state, key) {
            decrement_account_owner_count(state, &deleted.offer.account);
        }
    }
}

fn decrement_account_owner_count(state: &mut LedgerState, account: &[u8; 20]) {
    if let Some(acct) = load_existing_account(state, account) {
        let mut updated = acct.clone();
        updated.owner_count = updated.owner_count.saturating_sub(1);
        state.insert_account(updated);
    }
}

/// Apply an OfferCancel: remove a standing offer from the DEX.
pub(crate) fn apply_offer_cancel(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    let target_seq = match tx.offer_sequence {
        Some(0) | None => return ApplyResult::ClaimedCost("temBAD_SEQUENCE"),
        Some(s) => s,
    };

    if let Some(acct) = load_existing_account(state, &tx.account) {
        if acct.sequence <= target_seq {
            return ApplyResult::ClaimedCost("temBAD_SEQUENCE");
        }
    }

    let key = crate::ledger::offer::shamap_key(&tx.account, target_seq);
    if state.get_offer(&key).is_none() {
        if let Some(raw) = state
            .get_raw_owned(&key)
            .or_else(|| state.get_committed_raw_owned(&key))
        {
            if let Some(decoded) = crate::ledger::Offer::decode_from_sle(&raw) {
                state.hydrate_offer(decoded);
            }
        }
    }
    if let Some(deleted) = delete_offer_from_dirs(state, &key) {
        let removed = deleted.offer;
        if !deleted.owner_removed {
            let owner_still_has_entry =
                directory::owner_dir_contains_entry(state, &tx.account, &key.0);
            tracing::warn!(
                "offer cancel owner-dir remove miss: account={} seq={} owner_has_entry={}",
                hex::encode_upper(tx.account),
                target_seq,
                owner_still_has_entry,
            );
        }
        if !deleted.book_removed {
            let owner_still_has_entry =
                directory::owner_dir_contains_entry(state, &tx.account, &key.0);
            tracing::warn!(
                "offer cancel book-dir remove miss: account={} seq={} owner_has_entry={}",
                hex::encode_upper(tx.account),
                target_seq,
                owner_still_has_entry,
            );
        }

        decrement_account_owner_count(state, &removed.account);
    }

    ApplyResult::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{AccountRoot, Offer, RippleState};
    use crate::transaction::amount::Currency;

    fn account(account_id: [u8; 20], balance: u64) -> AccountRoot {
        AccountRoot {
            account_id,
            balance,
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

    fn iou(currency: Currency, issuer: [u8; 20], value: f64) -> Amount {
        Amount::Iou {
            value: IouValue::from_f64(value),
            currency,
            issuer,
        }
    }

    fn offer(account: [u8; 20], sequence: u32, pays: Amount, gets: Amount) -> Offer {
        let book_key = BookKey::from_amounts(&pays, &gets);
        let quality = directory::offer_quality(&gets, &pays);
        let book_directory = directory::book_dir_quality_key(&book_key, quality).0;
        Offer {
            account,
            sequence,
            taker_pays: pays,
            taker_gets: gets,
            flags: 0,
            book_directory,
            book_node: 0,
            owner_node: 0,
            expiration: None,
            domain_id: None,
            additional_books: Vec::new(),
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        }
    }

    fn allow_iou(
        state: &mut LedgerState,
        holder: [u8; 20],
        issuer: [u8; 20],
        currency: Currency,
        limit: f64,
    ) {
        let mut line = state
            .get_trustline(&crate::ledger::trustline::shamap_key(
                &holder, &issuer, &currency,
            ))
            .cloned()
            .unwrap_or_else(|| RippleState::new(&holder, &issuer, currency));
        line.set_limit_for(&holder, IouValue::from_f64(limit));
        state.insert_trustline(line);
    }

    fn fund_iou(
        state: &mut LedgerState,
        holder: [u8; 20],
        issuer: [u8; 20],
        currency: Currency,
        value: f64,
    ) {
        let mut line = state
            .get_trustline(&crate::ledger::trustline::shamap_key(
                &holder, &issuer, &currency,
            ))
            .cloned()
            .unwrap_or_else(|| RippleState::new(&holder, &issuer, currency));
        line.transfer(&issuer, &IouValue::from_f64(value));
        state.insert_trustline(line);
    }

    fn insert_xrp_iou_amm_pool(
        state: &mut LedgerState,
        amm_account: [u8; 20],
        issuer: [u8; 20],
        currency: Currency,
        xrp_reserve: u64,
        iou_reserve: f64,
    ) {
        let issue = Issue::Iou {
            currency: currency.clone(),
            issuer,
        };
        let amm_id = crate::ledger::tx::amm::amm_key(&Issue::Xrp, &issue);
        let mut pseudo = account(amm_account, xrp_reserve);
        pseudo.raw_sle = Some(crate::ledger::meta::patch_sle(
            &pseudo.encode(),
            &[crate::ledger::meta::ParsedField {
                type_code: 5,
                field_code: 14,
                data: amm_id.0.to_vec(),
            }],
            None,
            None,
            &[],
        ));
        state.insert_account(pseudo);
        state.insert_raw(
            amm_id,
            crate::ledger::meta::build_sle(
                0x0079,
                &[
                    crate::ledger::meta::ParsedField {
                        type_code: 8,
                        field_code: 1,
                        data: amm_account.to_vec(),
                    },
                    crate::ledger::meta::ParsedField {
                        type_code: 24,
                        field_code: 3,
                        data: Issue::Xrp.to_bytes(),
                    },
                    crate::ledger::meta::ParsedField {
                        type_code: 24,
                        field_code: 4,
                        data: issue.to_bytes(),
                    },
                ],
                None,
                None,
            ),
        );
        fund_iou(state, amm_account, issuer, currency, iou_reserve);
    }

    fn build_additional_books_payload(books: &[[u8; 32]]) -> Vec<u8> {
        let mut payload = PREFIX_TX_SIGN.to_vec();
        crate::ledger::meta::write_field_header_pub(&mut payload, 19, 13);
        let mut raw = Vec::with_capacity(books.len() * 32);
        for book in books {
            raw.extend_from_slice(book);
        }
        crate::transaction::serialize::encode_length(raw.len(), &mut payload);
        payload.extend_from_slice(&raw);
        payload.push(0xE1);
        payload
    }

    #[test]
    fn offer_funding_requires_issuer_side_auth_for_taker_gets() {
        let holder = [1u8; 20];
        let issuer = [2u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(holder, 2_000_000));
        let mut issuer_account = account(issuer, 2_000_000);
        issuer_account.flags |= LSF_REQUIRE_AUTH;
        state.insert_account(issuer_account);

        let mut line = RippleState::new(&holder, &issuer, usd.clone());
        line.transfer(&issuer, &IouValue::from_f64(10.0));
        state.insert_trustline(line.clone());

        assert_eq!(
            spendable_iou_funds_for_offer(&mut state, &holder, &issuer, &usd),
            IouValue::ZERO
        );

        line.flags |= auth_flag_for_issuer(&issuer, &line).unwrap();
        state.insert_trustline(line);

        assert_eq!(
            spendable_iou_funds_for_offer(&mut state, &holder, &issuer, &usd),
            IouValue::from_f64(10.0)
        );
    }

    fn permissioned_domain_sle(owner: [u8; 20]) -> Vec<u8> {
        crate::ledger::meta::build_sle(
            0x0082,
            &[
                crate::ledger::meta::ParsedField {
                    type_code: 8,
                    field_code: 2,
                    data: owner.to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 15,
                    field_code: 28,
                    data: vec![0xF1],
                },
            ],
            None,
            None,
        )
    }

    #[test]
    fn extracts_additional_books_from_signing_payload() {
        let books = [[0x11; 32], [0x22; 32]];
        let payload = build_additional_books_payload(&books);

        assert_eq!(
            extract_additional_books_from_signing_payload(&payload),
            books
        );
    }

    #[test]
    fn standing_remainder_uses_original_offer_quality() {
        let original_pays = Amount::Xrp(20);
        let original_gets = Amount::Xrp(10);
        let remaining_pays = Amount::Xrp(15);
        let remaining_gets = Amount::Xrp(10);

        let original_quality = directory::offer_quality(&original_gets, &original_pays);
        let recomputed_quality = directory::offer_quality(&remaining_gets, &remaining_pays);

        assert_ne!(original_quality, recomputed_quality);
        assert_eq!(
            original_quality,
            directory::offer_quality(&original_gets, &original_pays)
        );
    }

    #[test]
    fn build_standing_offer_preserves_tx_metadata() {
        let books = [[0x33; 32]];
        let tx = ParsedTx {
            domain_id: Some([0x44; 32]),
            signing_payload: build_additional_books_payload(&books),
            ..ParsedTx::default()
        };

        let offer = build_standing_offer(
            &tx,
            42,
            Amount::Xrp(15),
            Amount::Xrp(10),
            [0x55; 32],
            7,
            9,
            extract_additional_books_from_signing_payload(&tx.signing_payload),
        );

        assert_eq!(offer.account, tx.account);
        assert_eq!(offer.sequence, 42);
        assert_eq!(offer.book_directory, [0x55; 32]);
        assert_eq!(offer.book_node, 7);
        assert_eq!(offer.owner_node, 9);
        assert_eq!(offer.domain_id, Some([0x44; 32]));
        assert_eq!(offer.additional_books, books);
    }

    #[test]
    fn offer_create_rejects_zero_offer_sequence() {
        let mut state = LedgerState::new();
        let tx = ParsedTx {
            tx_type: 7,
            account: [1u8; 20],
            sequence: 1,
            offer_sequence: Some(0),
            taker_pays: Some(Amount::Xrp(1)),
            taker_gets: Some(Amount::Xrp(2)),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_offer_create(&mut state, &tx, 0),
            ApplyResult::ClaimedCost("temBAD_SEQUENCE")
        );
    }

    #[test]
    fn offer_create_rejects_hybrid_without_domain_id() {
        let mut state = LedgerState::new();
        let tx = ParsedTx {
            tx_type: 7,
            account: [1u8; 20],
            sequence: 1,
            flags: TF_HYBRID,
            taker_pays: Some(Amount::Xrp(1)),
            taker_gets: Some(Amount::Xrp(2)),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_offer_create(&mut state, &tx, 0),
            ApplyResult::ClaimedCost("temINVALID_FLAG")
        );
    }

    #[test]
    fn offer_create_rejects_unknown_permissioned_domain() {
        let mut state = LedgerState::new();
        let tx = ParsedTx {
            tx_type: 7,
            account: [1u8; 20],
            sequence: 1,
            domain_id: Some([0x44; 32]),
            taker_pays: Some(Amount::Xrp(1)),
            taker_gets: Some(iou(Currency::from_code("USD").unwrap(), [1u8; 20], 1.0)),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_offer_create(&mut state, &tx, 0),
            ApplyResult::ClaimedCost("tecNO_PERMISSION")
        );
    }

    #[test]
    fn offer_create_allows_permissioned_domain_owner() {
        let owner = [1u8; 20];
        let domain_id = [0x44; 32];
        let mut state = LedgerState::new();
        state.insert_account(account(owner, 50_000_000));
        state.insert_raw(
            crate::ledger::Key(domain_id),
            permissioned_domain_sle(owner),
        );
        let tx = ParsedTx {
            tx_type: 7,
            account: owner,
            sequence: 1,
            domain_id: Some(domain_id),
            taker_pays: Some(Amount::Xrp(1_000)),
            taker_gets: Some(iou(Currency::from_code("USD").unwrap(), owner, 1.0)),
            ..ParsedTx::default()
        };

        assert_eq!(apply_offer_create(&mut state, &tx, 0), ApplyResult::Success);
    }

    #[test]
    fn offer_create_treats_issuer_frozen_taker_gets_as_unfunded() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000_000));
        state.insert_account(account(issuer, 1_000_000));

        let mut line = RippleState::new(&maker, &issuer, usd.clone());
        line.transfer(&issuer, &IouValue::from_f64(10.0));
        if issuer == line.low_account {
            line.flags |= LSF_LOW_FREEZE;
        } else {
            line.flags |= LSF_HIGH_FREEZE;
        }
        state.insert_trustline(line);

        let tx = ParsedTx {
            tx_type: 7,
            account: maker,
            sequence: 1,
            taker_pays: Some(Amount::Xrp(1_000)),
            taker_gets: Some(iou(usd, issuer, 10.0)),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_offer_create(&mut state, &tx, 0),
            ApplyResult::ClaimedCost("tecUNFUNDED_OFFER")
        );
    }

    #[test]
    fn offer_create_treats_frozen_underlying_lp_taker_gets_as_unfunded() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let amm_account = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let usd_issue = Issue::Iou {
            currency: usd.clone(),
            issuer,
        };
        let lp_currency = crate::ledger::tx::amm::amm_lp_currency(&Currency::xrp(), &usd);
        let amm_id = crate::ledger::tx::amm::amm_key(&Issue::Xrp, &usd_issue);

        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000_000));
        let mut frozen_issuer = account(issuer, 1_000_000);
        frozen_issuer.flags |= LSF_GLOBAL_FREEZE;
        state.insert_account(frozen_issuer);
        let mut pseudo = account(amm_account, 0);
        pseudo.raw_sle = Some(crate::ledger::meta::patch_sle(
            &pseudo.encode(),
            &[crate::ledger::meta::ParsedField {
                type_code: 5,
                field_code: 14,
                data: amm_id.0.to_vec(),
            }],
            None,
            None,
            &[],
        ));
        state.insert_account(pseudo);
        state.insert_raw(
            amm_id,
            crate::ledger::meta::build_sle(
                0x0079,
                &[
                    crate::ledger::meta::ParsedField {
                        type_code: 8,
                        field_code: 1,
                        data: amm_account.to_vec(),
                    },
                    crate::ledger::meta::ParsedField {
                        type_code: 24,
                        field_code: 3,
                        data: Issue::Xrp.to_bytes(),
                    },
                    crate::ledger::meta::ParsedField {
                        type_code: 24,
                        field_code: 4,
                        data: usd_issue.to_bytes(),
                    },
                ],
                None,
                None,
            ),
        );

        let mut lp_line = RippleState::new(&maker, &amm_account, lp_currency.clone());
        lp_line.transfer(&amm_account, &IouValue::from_f64(10.0));
        state.insert_trustline(lp_line);

        let tx = ParsedTx {
            tx_type: 7,
            account: maker,
            sequence: 1,
            taker_pays: Some(Amount::Xrp(1_000)),
            taker_gets: Some(iou(lp_currency, amm_account, 10.0)),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_offer_create(&mut state, &tx, 0),
            ApplyResult::ClaimedCost("tecUNFUNDED_OFFER")
        );
    }

    #[test]
    fn offer_create_prefers_better_amm_over_worse_clob_offer() {
        let taker = [9u8; 20];
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let amm_account = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 100_000_000));
        state.insert_account(account(maker, 1_000_000));
        state.insert_account(account(issuer, 0));
        allow_iou(&mut state, taker, issuer, usd.clone(), 100.0);
        fund_iou(&mut state, maker, issuer, usd.clone(), 10.0);
        insert_xrp_iou_amm_pool(
            &mut state,
            amm_account,
            issuer,
            usd.clone(),
            1_000_000,
            100.0,
        );

        let clob = offer(
            maker,
            1,
            Amount::Xrp(150_000),
            iou(usd.clone(), issuer, 10.0),
        );
        let clob_key = clob.key();
        state.insert_offer(clob);

        let tx = ParsedTx {
            tx_type: 7,
            account: taker,
            sequence: 1,
            taker_pays: Some(iou(usd.clone(), issuer, 10.0)),
            taker_gets: Some(Amount::Xrp(200_000)),
            ..ParsedTx::default()
        };

        assert_eq!(apply_offer_create(&mut state, &tx, 0), ApplyResult::Success);
        assert!(
            state.get_offer(&clob_key).is_some(),
            "worse CLOB liquidity must not block a better AMM fill"
        );
        assert!(
            state.get_account(&amm_account).unwrap().balance > 1_000_000,
            "AMM should receive the taker's XRP input"
        );
        let line = state
            .get_trustline_for(&taker, &issuer, &usd)
            .expect("taker trustline");
        assert_eq!(line.balance_for(&taker), IouValue::from_f64(10.0));
    }

    #[test]
    fn fok_killed_preserves_stale_frozen_offer_removal() {
        const TF_FILL_OR_KILL: u32 = 0x0004_0000;

        let maker = [1u8; 20];
        let taker = [3u8; 20];
        let issuer = [2u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000_000));
        state.insert_account(account(taker, 100_000_000));
        state.insert_account(account(issuer, 1_000_000));

        let mut line = RippleState::new(&maker, &issuer, usd.clone());
        line.transfer(&issuer, &IouValue::from_f64(10.0));
        if issuer == line.low_account {
            line.flags |= LSF_LOW_FREEZE;
        } else {
            line.flags |= LSF_HIGH_FREEZE;
        }
        state.insert_trustline(line);

        let stale = offer(maker, 1, Amount::Xrp(1_000), iou(usd.clone(), issuer, 10.0));
        let stale_key = stale.key();
        state.insert_offer(stale);

        let tx = ParsedTx {
            tx_type: 7,
            account: taker,
            sequence: 1,
            flags: TF_FILL_OR_KILL,
            taker_pays: Some(iou(usd, issuer, 10.0)),
            taker_gets: Some(Amount::Xrp(1_000)),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_offer_create(&mut state, &tx, 0),
            ApplyResult::ClaimedCost("tecKILLED")
        );
        assert!(
            state.get_offer(&stale_key).is_none(),
            "FOK rollback should preserve stale frozen offer deletion"
        );
        assert!(
            state.offers_by_account(&taker).is_empty(),
            "killed FOK must not place a taker remainder"
        );
        assert_eq!(state.get_account(&taker).unwrap().balance, 100_000_000);
    }

    #[test]
    fn sell_offer_create_can_autobridge_iou_to_iou_through_xrp() {
        let taker = [9u8; 20];
        let usd_issuer = [1u8; 20];
        let eur_issuer = [2u8; 20];
        let xrp_maker = [3u8; 20];
        let eur_maker = [4u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let eur = Currency::from_code("EUR").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(taker, 1_001_000));
        state.insert_account(account(usd_issuer, 1_000));
        state.insert_account(account(eur_issuer, 1_000));
        state.insert_account(account(xrp_maker, 2_000_000));
        state.insert_account(account(eur_maker, 1_001_000));

        let mut taker_usd = RippleState::new(&taker, &usd_issuer, usd.clone());
        taker_usd.transfer(&usd_issuer, &IouValue::from_f64(10.0));
        state.insert_trustline(taker_usd);

        let mut xrp_maker_usd = RippleState::new(&xrp_maker, &usd_issuer, usd.clone());
        xrp_maker_usd.set_limit_for(&xrp_maker, IouValue::from_f64(20.0));
        state.insert_trustline(xrp_maker_usd);

        let mut taker_eur = RippleState::new(&taker, &eur_issuer, eur.clone());
        taker_eur.set_limit_for(&taker, IouValue::from_f64(20.0));
        state.insert_trustline(taker_eur);

        let mut maker_eur = RippleState::new(&eur_maker, &eur_issuer, eur.clone());
        maker_eur.transfer(&eur_issuer, &IouValue::from_f64(10.0));
        state.insert_trustline(maker_eur);

        state.insert_offer(offer(
            xrp_maker,
            1,
            iou(usd.clone(), usd_issuer, 10.0),
            Amount::Xrp(100),
        ));
        state.insert_offer(offer(
            eur_maker,
            1,
            Amount::Xrp(100),
            iou(eur.clone(), eur_issuer, 10.0),
        ));

        let result = try_offer_create_xrp_autobridge_sell(
            &mut state,
            taker,
            &iou(usd.clone(), usd_issuer, 10.0),
            &iou(eur.clone(), eur_issuer, 10.0),
            0,
            None,
        )
        .expect("autobridge should cross");

        assert_eq!(result.0, FlowAmount::new(iou(usd, usd_issuer, 10.0)));
        assert_eq!(
            result.1,
            FlowAmount::new(iou(eur.clone(), eur_issuer, 10.0))
        );
        let taker_eur = state
            .get_trustline_for(&taker, &eur_issuer, &eur)
            .expect("taker eur line");
        assert_eq!(taker_eur.balance_for(&taker), IouValue::from_f64(10.0));
        assert_eq!(state.get_account(&taker).unwrap().balance, 1_001_000);
    }

    #[test]
    fn apply_offer_create_uses_sell_iou_iou_xrp_autobridge() {
        let taker = [9u8; 20];
        let usd_issuer = [1u8; 20];
        let eur_issuer = [2u8; 20];
        let xrp_maker = [3u8; 20];
        let eur_maker = [4u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let eur = Currency::from_code("EUR").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(taker, 50_000_000));
        state.insert_account(account(usd_issuer, 1_000));
        state.insert_account(account(eur_issuer, 1_000));
        state.insert_account(account(xrp_maker, 2_000_000));
        state.insert_account(account(eur_maker, 1_001_000));

        let mut taker_usd = RippleState::new(&taker, &usd_issuer, usd.clone());
        taker_usd.transfer(&usd_issuer, &IouValue::from_f64(10.0));
        state.insert_trustline(taker_usd);

        let mut xrp_maker_usd = RippleState::new(&xrp_maker, &usd_issuer, usd.clone());
        xrp_maker_usd.set_limit_for(&xrp_maker, IouValue::from_f64(20.0));
        state.insert_trustline(xrp_maker_usd);

        let mut taker_eur = RippleState::new(&taker, &eur_issuer, eur.clone());
        taker_eur.set_limit_for(&taker, IouValue::from_f64(20.0));
        state.insert_trustline(taker_eur);

        let mut maker_eur = RippleState::new(&eur_maker, &eur_issuer, eur.clone());
        maker_eur.transfer(&eur_issuer, &IouValue::from_f64(10.0));
        state.insert_trustline(maker_eur);

        state.insert_offer(offer(
            xrp_maker,
            1,
            iou(usd.clone(), usd_issuer, 10.0),
            Amount::Xrp(100),
        ));
        state.insert_offer(offer(
            eur_maker,
            1,
            Amount::Xrp(100),
            iou(eur.clone(), eur_issuer, 10.0),
        ));

        let tx = ParsedTx {
            tx_type: 7,
            account: taker,
            sequence: 1,
            flags: TF_SELL,
            taker_pays: Some(iou(eur.clone(), eur_issuer, 10.0)),
            taker_gets: Some(iou(usd.clone(), usd_issuer, 10.0)),
            ..ParsedTx::default()
        };

        assert_eq!(apply_offer_create(&mut state, &tx, 0), ApplyResult::Success);
        assert!(
            state.offers_by_account(&taker).is_empty(),
            "fully sold autobridged offer must not leave a standing remainder"
        );
        let taker_usd = state
            .get_trustline_for(&taker, &usd_issuer, &usd)
            .expect("taker usd line");
        let taker_eur = state
            .get_trustline_for(&taker, &eur_issuer, &eur)
            .expect("taker eur line");
        assert_eq!(taker_usd.balance_for(&taker), IouValue::ZERO);
        assert_eq!(taker_eur.balance_for(&taker), IouValue::from_f64(10.0));
    }

    #[test]
    fn buy_offer_create_can_autobridge_iou_to_iou_through_xrp() {
        let taker = [9u8; 20];
        let usd_issuer = [1u8; 20];
        let eur_issuer = [2u8; 20];
        let xrp_maker = [3u8; 20];
        let eur_maker = [4u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let eur = Currency::from_code("EUR").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(taker, 1_001_000));
        state.insert_account(account(usd_issuer, 1_000));
        state.insert_account(account(eur_issuer, 1_000));
        state.insert_account(account(xrp_maker, 2_000_000));
        state.insert_account(account(eur_maker, 1_001_000));

        let mut taker_usd = RippleState::new(&taker, &usd_issuer, usd.clone());
        taker_usd.transfer(&usd_issuer, &IouValue::from_f64(10.0));
        state.insert_trustline(taker_usd);

        let mut xrp_maker_usd = RippleState::new(&xrp_maker, &usd_issuer, usd.clone());
        xrp_maker_usd.set_limit_for(&xrp_maker, IouValue::from_f64(20.0));
        state.insert_trustline(xrp_maker_usd);

        let mut taker_eur = RippleState::new(&taker, &eur_issuer, eur.clone());
        taker_eur.set_limit_for(&taker, IouValue::from_f64(20.0));
        state.insert_trustline(taker_eur);

        let mut maker_eur = RippleState::new(&eur_maker, &eur_issuer, eur.clone());
        maker_eur.transfer(&eur_issuer, &IouValue::from_f64(10.0));
        state.insert_trustline(maker_eur);

        state.insert_offer(offer(
            xrp_maker,
            1,
            iou(usd.clone(), usd_issuer, 10.0),
            Amount::Xrp(100),
        ));
        state.insert_offer(offer(
            eur_maker,
            1,
            Amount::Xrp(100),
            iou(eur.clone(), eur_issuer, 10.0),
        ));

        let result = try_offer_create_xrp_autobridge_buy(
            &mut state,
            taker,
            &iou(usd.clone(), usd_issuer, 10.0),
            &iou(eur.clone(), eur_issuer, 10.0),
            0,
            None,
        )
        .expect("autobridge should cross exact output");

        assert_eq!(result.0, FlowAmount::new(iou(usd, usd_issuer, 10.0)));
        assert_eq!(
            result.1,
            FlowAmount::new(iou(eur.clone(), eur_issuer, 10.0))
        );
        let taker_eur = state
            .get_trustline_for(&taker, &eur_issuer, &eur)
            .expect("taker eur line");
        assert_eq!(taker_eur.balance_for(&taker), IouValue::from_f64(10.0));
    }

    #[test]
    fn apply_offer_create_uses_buy_iou_iou_xrp_autobridge() {
        let taker = [9u8; 20];
        let usd_issuer = [1u8; 20];
        let eur_issuer = [2u8; 20];
        let xrp_maker = [3u8; 20];
        let eur_maker = [4u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let eur = Currency::from_code("EUR").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(taker, 50_000_000));
        state.insert_account(account(usd_issuer, 1_000));
        state.insert_account(account(eur_issuer, 1_000));
        state.insert_account(account(xrp_maker, 2_000_000));
        state.insert_account(account(eur_maker, 1_000));

        let mut taker_usd = RippleState::new(&taker, &usd_issuer, usd.clone());
        taker_usd.transfer(&usd_issuer, &IouValue::from_f64(10.0));
        state.insert_trustline(taker_usd);

        let mut xrp_maker_usd = RippleState::new(&xrp_maker, &usd_issuer, usd.clone());
        xrp_maker_usd.set_limit_for(&xrp_maker, IouValue::from_f64(20.0));
        state.insert_trustline(xrp_maker_usd);

        let mut taker_eur = RippleState::new(&taker, &eur_issuer, eur.clone());
        taker_eur.set_limit_for(&taker, IouValue::from_f64(20.0));
        state.insert_trustline(taker_eur);

        let mut maker_eur = RippleState::new(&eur_maker, &eur_issuer, eur.clone());
        maker_eur.transfer(&eur_issuer, &IouValue::from_f64(10.0));
        state.insert_trustline(maker_eur);

        state.insert_offer(offer(
            xrp_maker,
            1,
            iou(usd.clone(), usd_issuer, 10.0),
            Amount::Xrp(100),
        ));
        state.insert_offer(offer(
            eur_maker,
            1,
            Amount::Xrp(100),
            iou(eur.clone(), eur_issuer, 10.0),
        ));

        let tx = ParsedTx {
            tx_type: 7,
            account: taker,
            sequence: 1,
            taker_pays: Some(iou(eur.clone(), eur_issuer, 10.0)),
            taker_gets: Some(iou(usd.clone(), usd_issuer, 10.0)),
            ..ParsedTx::default()
        };

        assert_eq!(apply_offer_create(&mut state, &tx, 0), ApplyResult::Success);
        assert!(
            state.offers_by_account(&taker).is_empty(),
            "fully bought autobridged offer must not leave a standing remainder"
        );
        let taker_usd = state
            .get_trustline_for(&taker, &usd_issuer, &usd)
            .expect("taker usd line");
        let taker_eur = state
            .get_trustline_for(&taker, &eur_issuer, &eur)
            .expect("taker eur line");
        assert_eq!(taker_usd.balance_for(&taker), IouValue::ZERO);
        assert_eq!(taker_eur.balance_for(&taker), IouValue::from_f64(10.0));
    }
}
