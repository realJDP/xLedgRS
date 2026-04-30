//! RippleCalc — IOU payment flow helpers.
//!
//! Modeled after portions of rippled's flow engine:
//!   RippleCalc.cpp → ripple_calculate (entry point)
//!   DirectStep.cpp → direct trust line transfers
//!   TokenHelpers.cpp → rippleCredit (trust line balance updates)
//!   AccountRootHelpers.cpp → transferRate (issuer transfer fees)
//!
//! Direct IOU flow is partially implemented. Cross-currency, explicit path, and
//! BookStep flows are not complete and return `tecPATH_DRY` where unsupported.

use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, Currency, IouValue};
use crate::transaction::parse::PathStep;

const TF_NO_RIPPLE_DIRECT: u32 = 0x0001_0000;

/// Result of a ripple calculation.
pub struct RippleCalcResult {
    pub success: bool,
    pub ter: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectStep {
    source: [u8; 20],
    destination: [u8; 20],
    issuer: [u8; 20],
    currency: Currency,
    is_last: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectStrand {
    steps: Vec<DirectStep>,
}

/// Execute a supported ripple (IOU) payment flow.
///
/// For direct IOU payments (same currency, no paths, no SendMax):
///   Single DirectStep: sender → issuer → destination
///   Applies transfer fee from issuer's TransferRate if set.
///
/// Unsupported cross-currency/path/BookStep configurations return
/// `tecPATH_DRY`.
pub fn ripple_calculate(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    send_max: Option<&Amount>,
    deliver_min: Option<&Amount>,
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
            let has_deliver_min = deliver_min.is_some();

            if !is_cross_currency && !has_paths && send_max.is_none() && !has_deliver_min {
                execute_direct_iou_flow(state, sender, destination, issuer, currency, value, flags)
            } else if !has_paths && (send_max.is_some() || has_deliver_min) {
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

fn execute_direct_iou_flow(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
    amount: &IouValue,
    flags: u32,
) -> RippleCalcResult {
    match to_strands_direct_only(sender, destination, issuer, currency, flags) {
        Ok(strands) if strands.len() == 1 => {
            // The direct-only strand builder gives us the rippled-shaped seam.
            // Execution still delegates to the established direct IOU mutation
            // path until StrandFlow reverse/forward passes are ported.
            direct_iou_payment(state, sender, destination, issuer, currency, amount, flags)
        }
        Ok(_) => RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        },
        Err(ter) => RippleCalcResult {
            success: false,
            ter,
        },
    }
}

fn to_strands_direct_only(
    sender: &[u8; 20],
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
    flags: u32,
) -> Result<Vec<DirectStrand>, &'static str> {
    if (flags & TF_NO_RIPPLE_DIRECT) != 0 {
        return Err("temRIPPLE_EMPTY");
    }

    let mut steps = Vec::new();
    if sender != issuer {
        steps.push(DirectStep {
            source: *sender,
            destination: *issuer,
            issuer: *issuer,
            currency: currency.clone(),
            is_last: *destination == *issuer,
        });
    }

    if destination != issuer {
        steps.push(DirectStep {
            source: *issuer,
            destination: *destination,
            issuer: *issuer,
            currency: currency.clone(),
            is_last: true,
        });
    }

    if steps.is_empty() {
        return Err("temREDUNDANT");
    }

    if let Some((last, rest)) = steps.split_last_mut() {
        for step in rest {
            step.is_last = false;
        }
        last.is_last = true;
    }

    Ok(vec![DirectStrand { steps }])
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
    if super::load_existing_account(state, destination).is_none() {
        return RippleCalcResult {
            success: false,
            ter: "tecNO_DST",
        };
    }

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

    let mut sender_tl_to_write = None;
    let mut dest_tl_to_write = None;

    if *sender != *issuer {
        // ── Debit sender's trust line (rippleCredit: sender → issuer) ──
        let sender_key = crate::ledger::trustline::shamap_key(sender, issuer, currency);
        let Some(sender_tl) = load_existing_trustline(state, &sender_key) else {
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_DRY",
            };
        };

        let sender_balance = sender_tl.balance_for(sender);
        if sender_balance.sub(&send_amount).is_negative() {
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_DRY",
            };
        }

        sender_tl_to_write = Some(sender_tl);
    }

    if *destination != *issuer {
        // ── Credit destination's trust line (rippleCredit: issuer → destination) ──
        let dest_key = crate::ledger::trustline::shamap_key(destination, issuer, currency);
        let Some(dest_tl) = load_existing_trustline(state, &dest_key) else {
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_DRY",
            };
        };

        if issuer_requires_auth_without_line_auth(state, issuer, destination, &dest_tl) {
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_DRY",
            };
        }

        let dest_balance = dest_tl.balance_for(destination);
        let dest_limit = trustline_limit_for(&dest_tl, destination);
        if dest_limit.sub(&dest_balance).sub(amount).is_negative() {
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_DRY",
            };
        }

        dest_tl_to_write = Some(dest_tl);
    }

    if let Some(mut sender_tl) = sender_tl_to_write {
        // Apply debit: sender pays issuer
        sender_tl.transfer(sender, &send_amount);
        state.insert_trustline(sender_tl);
    }

    if let Some(mut dest_tl) = dest_tl_to_write {
        // Apply credit: issuer pays destination (the deliver amount, not send amount)
        dest_tl.transfer(issuer, amount);
        state.insert_trustline(dest_tl);
    }

    RippleCalcResult {
        success: true,
        ter: "tesSUCCESS",
    }
}

fn trustline_limit_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> IouValue {
    if account == &tl.low_account {
        tl.low_limit
    } else {
        tl.high_limit
    }
}

fn trustline_auth_flag_for(source: &[u8; 20], destination: &[u8; 20]) -> u32 {
    if source > destination {
        crate::ledger::trustline::LSF_HIGH_AUTH
    } else {
        crate::ledger::trustline::LSF_LOW_AUTH
    }
}

fn issuer_requires_auth_without_line_auth(
    state: &mut LedgerState,
    issuer: &[u8; 20],
    destination: &[u8; 20],
    tl: &crate::ledger::RippleState,
) -> bool {
    let Some(issuer_account) = super::load_existing_account(state, issuer) else {
        return false;
    };
    (issuer_account.flags & crate::ledger::account::LSF_REQUIRE_AUTH) != 0
        && (tl.flags & trustline_auth_flag_for(issuer, destination)) == 0
        && tl.balance.is_zero()
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
    if let Some(raw) = state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))
    {
        if let Some(decoded) = crate::ledger::RippleState::decode_from_sle(&raw) {
            state.hydrate_trustline(decoded.clone());
            return decoded;
        }
    }
    crate::ledger::RippleState::new(account_a, account_b, currency.clone())
}

fn load_existing_trustline(
    state: &mut LedgerState,
    key: &crate::ledger::Key,
) -> Option<crate::ledger::RippleState> {
    if let Some(tl) = state.get_trustline(key) {
        return Some(tl.clone());
    }
    let raw = state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))?;
    let decoded = crate::ledger::RippleState::decode_from_sle(&raw)?;
    state.hydrate_trustline(decoded.clone());
    Some(decoded)
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
    if let Some(raw) = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))
    {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{ter, AccountRoot, RippleState};
    use crate::transaction::amount::Amount;
    use crate::transaction::builder::TxBuilder;
    use crate::transaction::parse::parse_blob;
    use crate::{
        crypto::keys::{KeyPair, Secp256k1KeyPair},
        ledger::tx::{run_tx, ApplyFlags, TxContext},
    };

    fn genesis_kp() -> KeyPair {
        KeyPair::Secp256k1(Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap())
    }

    fn genesis_id() -> [u8; 20] {
        let kp = genesis_kp();
        crate::crypto::account_id(&kp.public_key_bytes())
    }

    fn dest_id() -> [u8; 20] {
        crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap()
    }

    fn issuer_id() -> [u8; 20] {
        [0x42; 20]
    }

    fn usd_currency() -> Currency {
        Currency::from_code("USD").unwrap()
    }

    fn account(account_id: [u8; 20], balance: u64, flags: u32) -> AccountRoot {
        AccountRoot {
            account_id,
            balance,
            sequence: 1,
            owner_count: 0,
            flags,
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

    fn state_with_accounts(issuer_flags: u32) -> LedgerState {
        let mut state = LedgerState::new();
        state.insert_account(account(genesis_id(), 100_000_000, issuer_flags));
        state.insert_account(account(dest_id(), 0, 0));
        state
    }

    fn sign_iou_payment(seq: u32, issuer: &[u8; 20], value: f64) -> crate::transaction::ParsedTx {
        let kp = genesis_kp();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Iou {
                value: IouValue::from_f64(value),
                currency: usd_currency(),
                issuer: *issuer,
            })
            .fee(12)
            .sequence(seq)
            .sign(&kp)
            .unwrap();
        parse_blob(&signed.blob).unwrap()
    }

    #[test]
    fn to_strands_default_direct_iou_builds_sender_issuer_destination() {
        let usd = usd_currency();
        let issuer = issuer_id();

        let strands = to_strands_direct_only(&genesis_id(), &dest_id(), &issuer, &usd, 0).unwrap();

        assert_eq!(strands.len(), 1);
        assert_eq!(strands[0].steps.len(), 2);
        assert_eq!(strands[0].steps[0].source, genesis_id());
        assert_eq!(strands[0].steps[0].destination, issuer);
        assert!(!strands[0].steps[0].is_last);
        assert_eq!(strands[0].steps[1].source, issuer);
        assert_eq!(strands[0].steps[1].destination, dest_id());
        assert!(strands[0].steps[1].is_last);
    }

    #[test]
    fn to_strands_default_direct_iou_collapses_when_endpoint_is_issuer() {
        let usd = usd_currency();
        let issuer = genesis_id();

        let source_is_issuer =
            to_strands_direct_only(&genesis_id(), &dest_id(), &issuer, &usd, 0).unwrap();
        assert_eq!(source_is_issuer[0].steps.len(), 1);
        assert_eq!(source_is_issuer[0].steps[0].source, issuer);
        assert_eq!(source_is_issuer[0].steps[0].destination, dest_id());
        assert!(source_is_issuer[0].steps[0].is_last);

        let destination_is_issuer =
            to_strands_direct_only(&genesis_id(), &dest_id(), &dest_id(), &usd, 0).unwrap();
        assert_eq!(destination_is_issuer[0].steps.len(), 1);
        assert_eq!(destination_is_issuer[0].steps[0].source, genesis_id());
        assert_eq!(destination_is_issuer[0].steps[0].destination, dest_id());
        assert!(destination_is_issuer[0].steps[0].is_last);
    }

    #[test]
    fn to_strands_no_ripple_direct_without_paths_returns_tem_ripple_empty() {
        let usd = usd_currency();
        let result = to_strands_direct_only(
            &genesis_id(),
            &dest_id(),
            &issuer_id(),
            &usd,
            TF_NO_RIPPLE_DIRECT,
        );
        assert_eq!(result.unwrap_err(), "temRIPPLE_EMPTY");
    }

    #[test]
    fn direct_iou_no_ripple_direct_without_paths_returns_tem_ripple_empty() {
        let mut state = state_with_accounts(0);
        let usd = usd_currency();
        let mut line = RippleState::new(&genesis_id(), &dest_id(), usd);
        line.set_limit_for(&dest_id(), IouValue::from_f64(100.0));
        state.insert_trustline(line);

        let mut tx = sign_iou_payment(1, &genesis_id(), 5.0);
        tx.flags = TF_NO_RIPPLE_DIRECT;

        let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEM_RIPPLE_EMPTY);
        assert!(!result.applied);
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 100_000_000);
        assert_eq!(sender.sequence, 1);
    }

    #[test]
    fn direct_iou_payment_to_missing_destination_returns_tec_no_dst() {
        let mut state = LedgerState::new();
        state.insert_account(account(genesis_id(), 100_000_000, 0));
        assert!(state.get_account(&dest_id()).is_none());

        let iou_payment = sign_iou_payment(1, &genesis_id(), 5.0);
        let iou_result = run_tx(
            &mut state,
            &iou_payment,
            &TxContext::default(),
            ApplyFlags::NONE,
        );
        assert_eq!(iou_result.ter.token(), "tecNO_DST");
        assert!(state.get_account(&dest_id()).is_none());
    }

    #[test]
    fn direct_iou_payment_from_holder_cannot_exceed_balance() {
        let mut state = state_with_accounts(0);
        let usd = usd_currency();
        let mut line = RippleState::new(&genesis_id(), &dest_id(), usd.clone());
        line.set_limit_for(&genesis_id(), IouValue::from_f64(100.0));
        line.transfer(&dest_id(), &IouValue::from_f64(10.0));
        assert_eq!(line.balance_for(&genesis_id()), IouValue::from_f64(10.0));
        state.insert_trustline(line);

        let tx = sign_iou_payment(1, &dest_id(), 50.0);
        let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_PATH_DRY);
        assert!(result.applied, "tecPATH_DRY claims fee only");
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 100_000_000 - 12);
        assert_eq!(sender.sequence, 2);
        let line = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .unwrap();
        assert_eq!(line.balance_for(&genesis_id()), IouValue::from_f64(10.0));
    }

    #[test]
    fn direct_iou_payment_from_issuer_respects_destination_limit() {
        let mut state = state_with_accounts(0);
        let usd = usd_currency();
        let mut line = RippleState::new(&genesis_id(), &dest_id(), usd.clone());
        line.set_limit_for(&dest_id(), IouValue::from_f64(10.0));
        state.insert_trustline(line);

        let tx = sign_iou_payment(1, &genesis_id(), 50.0);
        let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_PATH_DRY);
        assert!(result.applied, "tecPATH_DRY claims fee only");
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 100_000_000 - 12);
        assert_eq!(sender.sequence, 2);
        let line = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .unwrap();
        assert!(line.balance_for(&dest_id()).is_zero());
    }

    #[test]
    fn direct_iou_payment_from_issuer_requires_destination_auth() {
        let mut state = state_with_accounts(crate::ledger::account::LSF_REQUIRE_AUTH);
        let usd = usd_currency();
        let mut line = RippleState::new(&genesis_id(), &dest_id(), usd.clone());
        line.set_limit_for(&dest_id(), IouValue::from_f64(100.0));
        state.insert_trustline(line);

        let tx = sign_iou_payment(1, &genesis_id(), 5.0);
        let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_PATH_DRY);
        assert!(result.applied, "tecPATH_DRY claims fee only");
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 100_000_000 - 12);
        assert_eq!(sender.sequence, 2);
        let line = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .unwrap();
        assert!(line.balance_for(&dest_id()).is_zero());
    }

    #[test]
    fn direct_iou_payment_from_issuer_succeeds_with_auth_and_limit() {
        let mut state = state_with_accounts(crate::ledger::account::LSF_REQUIRE_AUTH);
        let usd = usd_currency();
        let mut line = RippleState::new(&genesis_id(), &dest_id(), usd.clone());
        line.set_limit_for(&dest_id(), IouValue::from_f64(100.0));
        line.flags |= trustline_auth_flag_for(&genesis_id(), &dest_id());
        state.insert_trustline(line);

        let tx = sign_iou_payment(1, &genesis_id(), 5.0);
        let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert!(result.applied);
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 100_000_000 - 12);
        assert_eq!(sender.sequence, 2);
        let line = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .unwrap();
        assert_eq!(line.balance_for(&dest_id()), IouValue::from_f64(5.0));
    }

    #[test]
    fn direct_iou_missing_destination_line_does_not_mutate_sender_line() {
        let mut state = state_with_accounts(0);
        let issuer = issuer_id();
        state.insert_account(account(issuer, 0, 0));

        let usd = usd_currency();
        let mut sender_line = RippleState::new(&genesis_id(), &issuer, usd.clone());
        sender_line.set_limit_for(&genesis_id(), IouValue::from_f64(100.0));
        sender_line.transfer(&issuer, &IouValue::from_f64(10.0));
        state.insert_trustline(sender_line);

        let result = direct_iou_payment(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &issuer,
            &usd,
            &IouValue::from_f64(5.0),
            0,
        );

        assert!(!result.success);
        assert_eq!(result.ter, "tecPATH_DRY");
        let line = state
            .get_trustline_for(&genesis_id(), &issuer, &usd)
            .unwrap();
        assert_eq!(line.balance_for(&genesis_id()), IouValue::from_f64(10.0));
        assert!(state.get_trustline_for(&dest_id(), &issuer, &usd).is_none());
    }
}
