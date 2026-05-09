//! Shared asset balance mutations for transaction liquidity steps.

use super::load_existing_account;
use super::mptoken;
use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, IouValue, QUALITY_ONE};

pub(crate) enum AssetDelta {
    Credit,
    Debit,
}

pub(crate) fn spendable_xrp_balance(state: &LedgerState, account: &[u8; 20]) -> u64 {
    let acct = state.get_account(account).cloned().or_else(|| {
        let key = crate::ledger::account::shamap_key(account);
        state
            .get_raw_owned(&key)
            .or_else(|| state.get_committed_raw_owned(&key))
            .and_then(|raw| crate::ledger::account::AccountRoot::decode(&raw).ok())
    });
    let Some(acct) = acct else {
        return 0;
    };
    let fees = crate::ledger::read_fees(state);
    let reserve = fees
        .reserve
        .saturating_add((acct.owner_count as u64).saturating_mul(fees.increment));
    acct.balance.saturating_sub(reserve)
}

/// Credit or debit an account by an XRP/IOU amount.
///
/// This is intentionally small: it preserves the existing OfferCreate balance
/// mutation semantics while giving Payment/BookStep/AMMStep one shared seam.
pub(crate) fn can_debit_amount(
    state: &mut LedgerState,
    account: &[u8; 20],
    amount: &Amount,
) -> bool {
    match amount {
        Amount::Xrp(drops) => load_existing_account(state, account)
            .map(|acct| acct.balance >= *drops)
            .unwrap_or(false),
        Amount::Iou { .. } => true,
        Amount::Mpt(_) => mptoken::can_debit_mpt_amount(state, account, amount),
    }
}

pub(crate) fn apply_amount_delta(
    state: &mut LedgerState,
    account: &[u8; 20],
    delta: AssetDelta,
    amount: &Amount,
) -> bool {
    match amount {
        Amount::Xrp(drops) => {
            if let Some(acct) = load_existing_account(state, account) {
                let mut acct = acct.clone();
                match delta {
                    AssetDelta::Credit => acct.balance = acct.balance.saturating_add(*drops),
                    AssetDelta::Debit => {
                        if acct.balance < *drops {
                            return false;
                        }
                        acct.balance -= *drops;
                    }
                }
                state.insert_account(acct);
                true
            } else {
                false
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
            true
        }
        Amount::Mpt(_) => mptoken::apply_mpt_amount_delta(
            state,
            account,
            matches!(delta, AssetDelta::Credit),
            amount,
        ),
    }
}

/// Amount the sender must actually debit to deliver `amount` to `receiver`.
///
/// XRPL issuer transfer fees are paid by the sender when an IOU moves between
/// two non-issuer accounts. The receiver is still credited the net amount.
pub(crate) fn transfer_rate_gross_debit_amount(
    state: &LedgerState,
    sender: &[u8; 20],
    receiver: &[u8; 20],
    amount: &Amount,
) -> Amount {
    let Amount::Iou { issuer, .. } = amount else {
        return amount.clone();
    };
    if sender == issuer || receiver == issuer {
        return amount.clone();
    }

    let transfer_rate = account_transfer_rate(state, issuer);
    if transfer_rate <= QUALITY_ONE {
        return amount.clone();
    }

    issuer_transfer_rate_gross_amount(amount, transfer_rate)
}

pub(crate) fn issuer_transfer_rate_gross_amount(amount: &Amount, transfer_rate: u32) -> Amount {
    let Amount::Iou {
        value,
        currency,
        issuer,
    } = amount
    else {
        return amount.clone();
    };
    if transfer_rate <= QUALITY_ONE {
        return amount.clone();
    }

    Amount::Iou {
        value: mul_ratio_iou(value, transfer_rate, QUALITY_ONE, true),
        currency: currency.clone(),
        issuer: *issuer,
    }
}

/// Net amount a receiver can get when `sender` has at most `funded_amount`
/// available and issuer transfer fees may gross up the debit.
pub(crate) fn transfer_rate_net_deliverable_amount(
    state: &LedgerState,
    sender: &[u8; 20],
    receiver: &[u8; 20],
    funded_amount: &Amount,
) -> Amount {
    let Amount::Iou { issuer, .. } = funded_amount else {
        return funded_amount.clone();
    };
    if sender == issuer || receiver == issuer {
        return funded_amount.clone();
    }

    let transfer_rate = account_transfer_rate(state, issuer);
    if transfer_rate <= QUALITY_ONE {
        return funded_amount.clone();
    }

    issuer_transfer_rate_net_amount(funded_amount, transfer_rate)
}

pub(crate) fn issuer_transfer_rate_net_amount(amount: &Amount, transfer_rate: u32) -> Amount {
    let Amount::Iou {
        value,
        currency,
        issuer,
    } = amount
    else {
        return amount.clone();
    };
    if transfer_rate <= QUALITY_ONE {
        return amount.clone();
    }

    Amount::Iou {
        value: mul_ratio_iou(value, QUALITY_ONE, transfer_rate, false),
        currency: currency.clone(),
        issuer: *issuer,
    }
}

pub(crate) fn account_transfer_rate(state: &LedgerState, issuer: &[u8; 20]) -> u32 {
    if let Some(account) = state.get_account(issuer) {
        return if account.transfer_rate > 0 {
            account.transfer_rate
        } else {
            QUALITY_ONE
        };
    }

    let key = crate::ledger::account::shamap_key(issuer);
    state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))
        .and_then(|raw| crate::ledger::account::AccountRoot::decode(&raw).ok())
        .map(|account| {
            if account.transfer_rate > 0 {
                account.transfer_rate
            } else {
                QUALITY_ONE
            }
        })
        .unwrap_or(QUALITY_ONE)
}

pub(crate) fn mul_ratio_iou(value: &IouValue, num: u32, den: u32, round_up: bool) -> IouValue {
    if den == 0 || value.mantissa == 0 {
        return IouValue::ZERO;
    }
    if num == den {
        return *value;
    }

    let negative = value.mantissa < 0;
    let den = den as u128;
    let mut low = (value.mantissa.unsigned_abs() as u128).saturating_mul(num as u128) / den;
    let mut rem = (value.mantissa.unsigned_abs() as u128).saturating_mul(num as u128) % den;
    let mut exponent = value.exponent;

    while rem != 0 && low <= 999_999_999_999_999_999 {
        low *= 10;
        rem *= 10;
        let add = rem / den;
        low += add;
        rem -= add * den;
        exponent -= 1;
    }

    let mut signed = if negative {
        -(low as i128)
    } else {
        low as i128
    };

    while signed.unsigned_abs() > 9_999_999_999_999_999 {
        signed /= 10;
        exponent += 1;
    }
    while signed != 0 && signed.unsigned_abs() < 1_000_000_000_000_000 {
        signed *= 10;
        exponent -= 1;
    }

    let mut result = IouValue {
        mantissa: signed as i64,
        exponent,
    };
    result.normalize();

    if rem != 0 {
        if round_up && !negative {
            if result.mantissa == 0 {
                return IouValue {
                    mantissa: 1_000_000_000_000_000,
                    exponent: -96,
                };
            }
            result.mantissa += 1;
        } else if !round_up && negative {
            if result.mantissa == 0 {
                return IouValue {
                    mantissa: -1_000_000_000_000_000,
                    exponent: -96,
                };
            }
            result.mantissa -= 1;
        }
    }

    result.normalize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_ratio_iou_rounds_positive_remainder_up() {
        let value = IouValue {
            mantissa: 1_234_567_890_123_456,
            exponent: -15,
        };

        let down = mul_ratio_iou(&value, 1_000_000_001, QUALITY_ONE, false);
        let up = mul_ratio_iou(&value, 1_000_000_001, QUALITY_ONE, true);

        assert_eq!(up.exponent, down.exponent);
        assert_eq!(up.mantissa, down.mantissa + 1);
    }

    #[test]
    fn mul_ratio_iou_rounds_positive_remainder_down() {
        let one = IouValue {
            mantissa: 1_000_000_000_000_000,
            exponent: -15,
        };

        assert_eq!(
            mul_ratio_iou(&one, QUALITY_ONE, 1_200_000_000, false),
            IouValue {
                mantissa: 8_333_333_333_333_333,
                exponent: -16,
            }
        );
    }
}
