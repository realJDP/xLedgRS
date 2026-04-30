//! Shared asset balance mutations for transaction liquidity steps.

use super::load_existing_account;
use crate::ledger::LedgerState;
use crate::transaction::amount::Amount;

pub(crate) enum AssetDelta {
    Credit,
    Debit,
}

/// Credit or debit an account by an XRP/IOU amount.
///
/// This is intentionally small: it preserves the existing OfferCreate balance
/// mutation semantics while giving Payment/BookStep/AMMStep one shared seam.
pub(crate) fn apply_amount_delta(
    state: &mut LedgerState,
    account: &[u8; 20],
    delta: AssetDelta,
    amount: &Amount,
) {
    match amount {
        Amount::Xrp(drops) => {
            if let Some(acct) = load_existing_account(state, account) {
                let mut acct = acct.clone();
                match delta {
                    AssetDelta::Credit => acct.balance = acct.balance.saturating_add(*drops),
                    AssetDelta::Debit => acct.balance = acct.balance.saturating_sub(*drops),
                }
                state.insert_account(acct);
            }
        }
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            let key = crate::ledger::trustline::shamap_key(account, issuer, currency);
            let mut tl = if let Some(existing) = state.get_trustline(&key) {
                existing.clone()
            } else if let Some(raw) = state
                .get_raw_owned(&key)
                .or_else(|| state.get_committed_raw_owned(&key))
            {
                if let Some(decoded) = crate::ledger::RippleState::decode_from_sle(&raw) {
                    state.hydrate_trustline(decoded.clone());
                    decoded
                } else {
                    crate::ledger::RippleState::new(account, issuer, currency.clone())
                }
            } else {
                crate::ledger::RippleState::new(account, issuer, currency.clone())
            };
            match delta {
                AssetDelta::Credit => tl.transfer(issuer, value),
                AssetDelta::Debit => tl.transfer(account, value),
            }
            state.insert_trustline(tl);
        }
        Amount::Mpt(_) => {
            // MPT amounts not yet supported for balance transfers.
        }
    }
}
