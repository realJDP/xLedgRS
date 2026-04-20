//! Payment — XRP direct + IOU/cross-currency via RippleCalc flow engine.

use super::mptoken;
use super::ripple_calc;
use super::{ApplyResult, TxContext};
use crate::ledger::account::AccountRoot;
use crate::ledger::ter;
use crate::ledger::LedgerState;
use crate::transaction::amount::Amount;
use crate::transaction::ParsedTx;

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
        if existing_dest.is_none() && drops < fees.reserve {
            return ApplyResult::ClaimedCost("tecNO_DST_INSUF_XRP");
        }
        let reserve = fees.reserve + (new_sender.owner_count as u64 * fees.increment);
        let pre_fee_balance = new_sender.balance.saturating_add(tx.fee);
        let min_required_funds = reserve.max(tx.fee);
        if pre_fee_balance < drops.saturating_add(min_required_funds) {
            return ApplyResult::ClaimedCost("tecUNFUNDED_PAYMENT");
        }

        new_sender.balance -= drops;

        match existing_dest {
            Some(mut dest) => {
                dest.balance = dest.balance.saturating_add(drops);
                state.insert_account(dest);
            }
            None => {
                state.insert_account(crate::ledger::AccountRoot {
                    account_id: dest_id,
                    balance: drops,
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
        ApplyResult::Success
    }
}

fn load_existing_account(state: &mut LedgerState, account_id: &[u8; 20]) -> Option<AccountRoot> {
    if let Some(existing) = state.get_account(account_id).cloned() {
        return Some(existing);
    }

    let key = crate::ledger::account::shamap_key(account_id);
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    let account = crate::ledger::account::AccountRoot::decode(&raw).ok()?;
    state.hydrate_account(account.clone());
    Some(account)
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
            Amount::Iou { currency, .. },
            Some(Amount::Iou {
                currency: send_max_currency,
                ..
            }),
        ) => send_max_currency != currency,
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
