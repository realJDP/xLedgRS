//! Payment — XRP direct + IOU/cross-currency via RippleCalc flow engine.

use crate::ledger::LedgerState;
use crate::transaction::amount::Amount;
use crate::transaction::ParsedTx;
use super::ApplyResult;
use super::ripple_calc;

pub(crate) fn apply_payment(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let dest_id = match tx.destination {
        Some(d) => d,
        None    => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };

    // Determine if this is a ripple payment (IOU or cross-currency)
    let has_paths = !tx.paths.is_empty();
    let has_send_max = tx.send_max.is_some();
    let is_iou_amount = matches!(&tx.amount, Some(Amount::Iou { .. }));

    // rippled: `bool const ripple = (hasPaths || sendMax || !dstAmount.native())`
    let use_ripple = has_paths || has_send_max || is_iou_amount;

    if use_ripple {
        // IOU / cross-currency payment — use the flow engine
        let deliver = match &tx.amount {
            Some(amt) => amt.clone(),
            None => {
                // amount_drops as XRP deliver amount
                match tx.amount_drops {
                    Some(d) => Amount::Xrp(d),
                    None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
                }
            }
        };

        let result = ripple_calc::ripple_calculate(
            state,
            &tx.account,
            &dest_id,
            &deliver,
            tx.send_max.as_ref(),
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

        new_sender.balance = new_sender.balance.saturating_sub(drops);

        match state.get_account(&dest_id) {
            Some(existing) => {
                let mut dest = existing.clone();
                dest.balance = dest.balance.saturating_add(drops);
                state.insert_account(dest);
            }
            None => {
                state.insert_account(crate::ledger::AccountRoot {
                    account_id: dest_id, balance: drops, sequence: 1,
                    owner_count: 0, flags: 0, regular_key: None, minted_nftokens: 0, burned_nftokens: 0,
                    transfer_rate: 0, domain: Vec::new(), tick_size: 0, ticket_count: 0,
                    previous_txn_id: [0u8; 32], previous_txn_lgr_seq: 0, raw_sle: None,
                });
            }
        }
        ApplyResult::Success
    }
}
