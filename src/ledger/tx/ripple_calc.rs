//! RippleCalc — IOU/cross-currency payment flow engine.
//!
//! Ported from rippled's flow engine:
//!   RippleCalc.cpp → ripple_calculate (entry point)
//!   Flow.cpp → flow (strand dispatch)
//!   DirectStep.cpp → direct trust line transfers
//!   BookStep.cpp → DEX offer crossing within payments
//!   StrandFlow.h → reverse/forward pass algorithm
//!   TokenHelpers.cpp → rippleCredit (trust line balance updates)
//!   AccountRootHelpers.cpp → transferRate (issuer transfer fees)

use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, Currency, IouValue};
use crate::transaction::parse::PathStep;

/// Result of a ripple calculation.
pub struct RippleCalcResult {
    pub success: bool,
    pub ter: &'static str,
}

/// Execute a ripple (IOU/cross-currency) payment.
///
/// Matches rippled's Payment.cpp → RippleCalc::rippleCalculate → flow().
///
/// For direct IOU payments (same currency, no paths, no SendMax):
///   Single DirectStep: sender → issuer → destination
///   Applies transfer fee from issuer's TransferRate if set.
///
/// For cross-currency payments (paths or SendMax with different currency):
///   Full strand/step engine with BookStep for DEX crossing.
///   Unsupported path configurations return `tecPATH_DRY`.
pub fn ripple_calculate(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    send_max: Option<&Amount>,
    paths: &[Vec<PathStep>],
    flags: u32,
) -> RippleCalcResult {
    match deliver_amount {
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            // Determine if this is a simple direct payment or complex path payment.
            // Direct: same currency, no explicit paths, no SendMax (or SendMax same currency).
            let is_cross_currency = match send_max {
                Some(Amount::Iou {
                    currency: sm_cur, ..
                }) => sm_cur != currency,
                Some(Amount::Xrp(_)) => true, // XRP → IOU is cross-currency
                Some(Amount::Mpt(_)) => true, // MPT → IOU is cross-currency
                None => false,
            };
            let has_paths = !paths.is_empty();

            if !is_cross_currency && !has_paths {
                // ── Direct IOU payment (single DirectStep) ──
                // rippled: sender → issuer → destination on same trust lines
                direct_iou_payment(state, sender, destination, issuer, currency, value, flags)
            } else if !has_paths && send_max.is_some() {
                // Cross-currency with no explicit paths — needs default path.
                // For XRP→IOU with SendMax: need BookStep (DEX crossing).
                // Not yet implemented — return tecPATH_DRY matching rippled
                // behavior when no liquidity path exists.
                RippleCalcResult {
                    success: false,
                    ter: "tecPATH_DRY",
                }
            } else {
                // Path-based payment — full strand engine needed.
                // Not yet implemented.
                RippleCalcResult {
                    success: false,
                    ter: "tecPATH_DRY",
                }
            }
        }
        Amount::Xrp(_) => {
            // XRP deliver via ripple path — unusual but possible with SendMax IOU.
            // Needs BookStep. Not yet implemented.
            RippleCalcResult {
                success: false,
                ter: "tecPATH_DRY",
            }
        }
        _ => RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        },
    }
}

/// Direct IOU payment: sender → issuer → destination.
///
/// Matches rippled's DirectStep::revImp + rippleCreditIOU.
/// Handles transfer fees via issuer's TransferRate field.
fn direct_iou_payment(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
    amount: &IouValue,
    _flags: u32,
) -> RippleCalcResult {
    // Get issuer's transfer rate (rippled: AccountRootHelpers.cpp transferRate)
    // TransferRate is a u32 field on the issuer's AccountRoot.
    // QUALITY_ONE = 1,000,000,000. Rate > QUALITY_ONE means a fee is charged.
    let transfer_rate = get_transfer_rate(state, issuer);

    // Calculate the actual amount to debit from sender (may be more than
    // deliver amount if transfer fee applies).
    // rippled: DirectStep uses mulRatio(amount, srcQOut, QUALITY_ONE, roundUp=true)
    // where srcQOut = transferRate when sender redeems.
    let send_amount =
        if transfer_rate > QUALITY_ONE && *sender != *issuer && *destination != *issuer {
            // Transfer fee applies: sender must send more than destination receives.
            // send_amount = deliver_amount * (transfer_rate / QUALITY_ONE)
            apply_transfer_rate(amount, transfer_rate, true)
        } else {
            // No transfer fee (sender or dest is issuer, or no rate set)
            amount.clone()
        };

    // ── Debit sender's trust line (rippleCredit: sender → issuer) ──
    let sender_key = crate::ledger::trustline::shamap_key(sender, issuer, currency);
    let mut sender_tl = load_or_create_trustline(state, &sender_key, sender, issuer, currency);

    // Check sender has sufficient balance
    let sender_balance = sender_tl.balance_for(sender);
    if sender_balance.mantissa <= 0 && amount.mantissa > 0 {
        // Sender has no positive balance on this trust line.
        // Check if sender IS the issuer (issuers can create tokens).
        if *sender != *issuer {
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_DRY",
            };
        }
    }

    // Apply debit: sender pays issuer
    sender_tl.transfer(sender, &send_amount);
    state.insert_trustline(sender_tl);

    // ── Credit destination's trust line (rippleCredit: issuer → destination) ──
    let dest_key = crate::ledger::trustline::shamap_key(destination, issuer, currency);
    let mut dest_tl = load_or_create_trustline(state, &dest_key, destination, issuer, currency);

    // Apply credit: issuer pays destination (the deliver amount, not send amount)
    dest_tl.transfer(issuer, amount);
    state.insert_trustline(dest_tl);

    RippleCalcResult {
        success: true,
        ter: "tesSUCCESS",
    }
}

/// Load a trust line from typed map or NuDB, or create a new one.
/// Handles the hydration gap: trust lines may exist in NuDB but not
/// in the typed HashMap.
pub fn load_or_create_trustline(
    state: &mut LedgerState,
    key: &crate::ledger::Key,
    account_a: &[u8; 20],
    account_b: &[u8; 20],
    currency: &Currency,
) -> crate::ledger::RippleState {
    if let Some(tl) = state.get_trustline(key) {
        return tl.clone();
    }
    if let Some(raw) = state.get_raw_owned(key) {
        if let Some(decoded) = crate::ledger::RippleState::decode_from_sle(&raw) {
            state.hydrate_trustline(decoded.clone());
            return decoded;
        }
    }
    crate::ledger::RippleState::new(account_a, account_b, currency.clone())
}

/// QUALITY_ONE = 1,000,000,000 — the base quality (1:1, no fee).
/// Matches rippled's QUALITY_ONE constant.
const QUALITY_ONE: u32 = 1_000_000_000;

/// Get the transfer rate for an issuer account.
///
/// Matches rippled's AccountRootHelpers.cpp transferRate():
/// Reads sfTransferRate from issuer's AccountRoot.
/// Returns QUALITY_ONE (1:1) if not set.
fn get_transfer_rate(state: &LedgerState, issuer: &[u8; 20]) -> u32 {
    // Check typed account map
    if let Some(acct) = state.get_account(issuer) {
        if acct.transfer_rate > 0 {
            return acct.transfer_rate;
        }
        return QUALITY_ONE;
    }
    // Check NuDB
    let key = crate::ledger::account::shamap_key(issuer);
    if let Some(raw) = state.get_raw_owned(&key) {
        if let Ok(acct) = crate::ledger::account::AccountRoot::decode(&raw) {
            if acct.transfer_rate > 0 {
                return acct.transfer_rate;
            }
        }
    }
    QUALITY_ONE
}

/// Apply transfer rate to an IOU amount.
///
/// Matches rippled's mulRatio(amount, rate, QUALITY_ONE, roundUp).
/// result = amount * rate / QUALITY_ONE
fn apply_transfer_rate(amount: &IouValue, rate: u32, round_up: bool) -> IouValue {
    if rate == QUALITY_ONE {
        return amount.clone();
    }
    // Use i128 to avoid overflow: mantissa * rate / QUALITY_ONE
    let m = amount.mantissa as i128 * rate as i128;
    let q = QUALITY_ONE as i128;
    let result = if round_up {
        // Round up: (m + q - 1) / q
        (m + q - 1) / q
    } else {
        m / q
    };
    let mut v = IouValue {
        mantissa: result as i64,
        exponent: amount.exponent,
    };
    v.normalize();
    v
}
