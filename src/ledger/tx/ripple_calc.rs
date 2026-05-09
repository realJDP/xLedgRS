//! RippleCalc — IOU payment flow helpers.
//!
//! Modeled after portions of rippled's flow engine:
//!   RippleCalc.cpp → ripple_calculate (entry point)
//!   DirectStep.cpp → direct trust line transfers
//!   TokenHelpers.cpp → rippleCredit (trust line balance updates)
//!   AccountRootHelpers.cpp → transferRate (issuer transfer fees)
//!
//! Direct IOU, default CLOB/AMM cross-currency, and explicit DirectStep/BookStep
//! path shapes are implemented. Partial payments can aggregate liquidity across
//! supported explicit strands before falling back to single-book legacy handling.

use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, Currency, IouValue, Issue, QUALITY_ONE};
use crate::transaction::parse::PathStep;
use std::collections::HashSet;

const TF_NO_RIPPLE_DIRECT: u32 = 0x0001_0000;
const TF_LIMIT_QUALITY: u32 = 0x0004_0000;

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
#[allow(dead_code)]
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
    ripple_calculate_with_domain(
        state,
        sender,
        destination,
        deliver_amount,
        send_max,
        deliver_min,
        paths,
        flags,
        None,
        0,
    )
}

pub fn ripple_calculate_with_domain(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    send_max: Option<&Amount>,
    deliver_min: Option<&Amount>,
    paths: &[Vec<PathStep>],
    flags: u32,
    domain_id: Option<[u8; 32]>,
    close_time: u64,
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
            let same_asset_send_max = match send_max {
                Some(Amount::Iou {
                    value,
                    currency: sm_currency,
                    issuer: sm_issuer,
                }) if sm_currency == currency && sm_issuer == issuer => Some(value),
                _ => None,
            };

            if !is_cross_currency
                && !has_paths
                && (send_max.is_none() || same_asset_send_max.is_some())
            {
                let full = execute_direct_iou_flow(
                    state,
                    sender,
                    destination,
                    issuer,
                    currency,
                    value,
                    same_asset_send_max,
                    flags,
                );
                if full.success || !has_deliver_min {
                    full
                } else if let Some(Amount::Iou {
                    value: min_value, ..
                }) = deliver_min
                {
                    execute_direct_iou_partial_flow(
                        state,
                        sender,
                        destination,
                        issuer,
                        currency,
                        value,
                        min_value,
                        same_asset_send_max,
                        flags,
                    )
                } else {
                    RippleCalcResult {
                        success: false,
                        ter: "tecPATH_DRY",
                    }
                }
            } else if !has_paths && send_max.is_some() {
                if no_ripple_direct_without_explicit_paths(flags, paths) {
                    return RippleCalcResult {
                        success: false,
                        ter: "temRIPPLE_EMPTY",
                    };
                }
                let send_limit = send_max.expect("checked is_some");
                let full = execute_default_book_flow(
                    state,
                    sender,
                    destination,
                    deliver_amount,
                    send_max,
                    flags,
                    domain_id,
                    close_time,
                );
                if full.success || !has_deliver_min {
                    full
                } else if let Some(min_amount) = deliver_min {
                    execute_default_book_partial_flow(
                        state,
                        sender,
                        destination,
                        deliver_amount,
                        min_amount,
                        send_limit,
                        flags,
                        domain_id,
                        close_time,
                    )
                } else {
                    RippleCalcResult {
                        success: false,
                        ter: "tecPATH_DRY",
                    }
                }
            } else if !has_paths && has_deliver_min {
                RippleCalcResult {
                    success: false,
                    ter: "tecPATH_DRY",
                }
            } else if has_paths {
                if let Err(ter) = super::flow::validate_payment_paths(sender, destination, paths) {
                    return RippleCalcResult {
                        success: false,
                        ter,
                    };
                }
                let full = execute_explicit_path_flow(
                    state,
                    sender,
                    destination,
                    deliver_amount,
                    send_max,
                    paths,
                    flags,
                    domain_id,
                    close_time,
                );
                if full.success || !has_deliver_min {
                    full
                } else if let Some(min_amount) = deliver_min {
                    let partial = execute_explicit_path_partial_flow(
                        state,
                        sender,
                        destination,
                        deliver_amount,
                        min_amount,
                        send_max,
                        paths,
                        flags,
                        domain_id,
                        close_time,
                    );
                    if partial.success {
                        partial
                    } else {
                        let min_full = execute_explicit_path_flow(
                            state,
                            sender,
                            destination,
                            min_amount,
                            send_max,
                            paths,
                            flags,
                            domain_id,
                            close_time,
                        );
                        if min_full.success {
                            min_full
                        } else {
                            partial
                        }
                    }
                } else {
                    RippleCalcResult {
                        success: false,
                        ter: "tecPATH_DRY",
                    }
                }
            } else {
                if let Err(ter) = super::flow::validate_payment_paths(sender, destination, paths) {
                    return RippleCalcResult {
                        success: false,
                        ter,
                    };
                }
                RippleCalcResult {
                    success: false,
                    ter: "tecPATH_DRY",
                }
            }
        }
        Amount::Xrp(_) => {
            if send_max.is_some() {
                if paths.is_empty() && no_ripple_direct_without_explicit_paths(flags, paths) {
                    return RippleCalcResult {
                        success: false,
                        ter: "temRIPPLE_EMPTY",
                    };
                }
                let send_limit = send_max.expect("checked is_some");
                let full = if paths.is_empty() {
                    execute_default_book_flow(
                        state,
                        sender,
                        destination,
                        deliver_amount,
                        send_max,
                        flags,
                        domain_id,
                        close_time,
                    )
                } else {
                    if let Err(ter) =
                        super::flow::validate_payment_paths(sender, destination, paths)
                    {
                        return RippleCalcResult {
                            success: false,
                            ter,
                        };
                    }
                    execute_explicit_path_flow(
                        state,
                        sender,
                        destination,
                        deliver_amount,
                        send_max,
                        paths,
                        flags,
                        domain_id,
                        close_time,
                    )
                };
                if full.success || deliver_min.is_none() {
                    full
                } else if let Some(min_amount) = deliver_min {
                    if paths.is_empty() {
                        execute_default_book_partial_flow(
                            state,
                            sender,
                            destination,
                            deliver_amount,
                            min_amount,
                            send_limit,
                            flags,
                            domain_id,
                            close_time,
                        )
                    } else {
                        let partial = execute_explicit_path_partial_flow(
                            state,
                            sender,
                            destination,
                            deliver_amount,
                            min_amount,
                            send_max,
                            paths,
                            flags,
                            domain_id,
                            close_time,
                        );
                        if partial.success {
                            partial
                        } else {
                            let min_full = execute_explicit_path_flow(
                                state,
                                sender,
                                destination,
                                min_amount,
                                send_max,
                                paths,
                                flags,
                                domain_id,
                                close_time,
                            );
                            if min_full.success {
                                min_full
                            } else {
                                partial
                            }
                        }
                    }
                } else {
                    RippleCalcResult {
                        success: false,
                        ter: "tecPATH_DRY",
                    }
                }
            } else {
                RippleCalcResult {
                    success: false,
                    ter: "tecPATH_DRY",
                }
            }
        }
        _ => RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        },
    }
}

fn no_ripple_direct_without_explicit_paths(flags: u32, paths: &[Vec<PathStep>]) -> bool {
    (flags & TF_NO_RIPPLE_DIRECT) != 0 && paths.is_empty()
}

fn execute_default_book_partial_flow(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    deliver_min: &Amount,
    send_max: &Amount,
    flags: u32,
    domain_id: Option<[u8; 32]>,
    close_time: u64,
) -> RippleCalcResult {
    let Some(in_issue) = issue_from_amount(send_max) else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    let Some(out_issue) = issue_from_amount(deliver_amount) else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    if Some(out_issue.clone()) != issue_from_amount(deliver_min) || in_issue == out_issue {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    }

    let book = super::flow::FlowBook::with_domain(in_issue, out_issue, domain_id);
    let offered_in = super::flow::FlowAmount::new(send_max.clone());
    let plan = super::flow::plan_book_partial_in_all_qualities(
        state,
        &book,
        &offered_in,
        close_time,
        super::flow::RIPPLE_MAX_OFFERS_CONSIDERED,
    );
    let Some(output) = plan.output.as_ref() else {
        let min_full = execute_default_book_flow(
            state,
            sender,
            destination,
            deliver_min,
            Some(send_max),
            flags,
            domain_id,
            close_time,
        );
        return if min_full.success {
            min_full
        } else {
            RippleCalcResult {
                success: false,
                ter: "tecPATH_DRY",
            }
        };
    };
    if super::flow::compare_amounts(output.as_amount(), deliver_min) == std::cmp::Ordering::Less {
        let min_full = execute_default_book_flow(
            state,
            sender,
            destination,
            deliver_min,
            Some(send_max),
            flags,
            domain_id,
            close_time,
        );
        return if min_full.success {
            min_full
        } else {
            RippleCalcResult {
                success: false,
                ter: "tecPATH_PARTIAL",
            }
        };
    }
    if super::flow::compare_amounts(output.as_amount(), deliver_amount)
        == std::cmp::Ordering::Greater
    {
        return execute_default_book_flow(
            state,
            sender,
            destination,
            deliver_amount,
            Some(send_max),
            flags,
            domain_id,
            close_time,
        );
    }
    let Some(input) = plan.input.as_ref() else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    if !limit_quality_allows(
        flags,
        input.as_amount(),
        output.as_amount(),
        send_max,
        deliver_amount,
    ) {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_PARTIAL",
        };
    }

    match super::flow::apply_book_partial_fill_plan(state, &plan, *sender, *destination) {
        Ok(_) => RippleCalcResult {
            success: true,
            ter: "tesSUCCESS",
        },
        Err(ter) => RippleCalcResult {
            success: false,
            ter,
        },
    }
}

fn execute_default_book_flow(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    send_max: Option<&Amount>,
    flags: u32,
    domain_id: Option<[u8; 32]>,
    close_time: u64,
) -> RippleCalcResult {
    let Some(send_max) = send_max else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    let Some(in_issue) = issue_from_amount(send_max) else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    let Some(out_issue) = issue_from_amount(deliver_amount) else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    if in_issue == out_issue {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    }

    if domain_id.is_none() {
        if let Some(result) = execute_default_book_amm_aggregate_flow(
            state,
            sender,
            destination,
            deliver_amount,
            send_max,
            flags,
            close_time,
        ) {
            return result;
        }
    }

    execute_default_book_only_flow(
        state,
        sender,
        destination,
        deliver_amount,
        Some(send_max),
        flags,
        domain_id,
        close_time,
        in_issue,
        out_issue,
    )
}

fn execute_default_book_only_flow(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    send_max: Option<&Amount>,
    flags: u32,
    domain_id: Option<[u8; 32]>,
    close_time: u64,
    in_issue: Issue,
    out_issue: Issue,
) -> RippleCalcResult {
    let Some(send_max) = send_max else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    let book = super::flow::FlowBook::with_domain(in_issue, out_issue, domain_id);
    let requested_out = super::flow::FlowAmount::new(deliver_amount.clone());
    let plan = super::flow::plan_book_exact_out_all_qualities(
        state,
        &book,
        &requested_out,
        close_time,
        super::flow::RIPPLE_MAX_OFFERS_CONSIDERED,
    );
    if !plan.complete {
        return RippleCalcResult {
            success: false,
            ter: if plan.output.as_ref().is_some_and(|output| !output.is_zero()) {
                "tecPATH_PARTIAL"
            } else {
                "tecPATH_DRY"
            },
        };
    }
    if let Some(input) = &plan.input {
        if super::flow::compare_amounts(input.as_amount(), send_max) == std::cmp::Ordering::Greater
        {
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_PARTIAL",
            };
        }
        if !limit_quality_allows(
            flags,
            input.as_amount(),
            deliver_amount,
            send_max,
            deliver_amount,
        ) {
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_PARTIAL",
            };
        }
    }

    match super::flow::apply_book_fill_plan(state, &plan, *sender, *destination) {
        Ok(_) => RippleCalcResult {
            success: true,
            ter: "tesSUCCESS",
        },
        Err(ter) => RippleCalcResult {
            success: false,
            ter,
        },
    }
}

fn execute_default_book_amm_aggregate_flow(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    send_max: &Amount,
    flags: u32,
    close_time: u64,
) -> Option<RippleCalcResult> {
    let send_issue = issue_from_amount(send_max)?;
    let deliver_issue = issue_from_amount(deliver_amount)?;
    let specs = [super::flow::FlowStrandSpec {
        steps: vec![super::flow::FlowStepSpec::Book(super::flow::FlowBook::new(
            send_issue,
            deliver_issue,
        ))],
    }];
    let plans = executable_path_plans(sender, &specs).ok()?;
    execute_explicit_path_aggregate_flow(
        state,
        sender,
        destination,
        deliver_amount,
        send_max,
        &plans,
        flags,
        close_time,
    )
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

fn execute_direct_iou_flow(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
    amount: &IouValue,
    send_max: Option<&IouValue>,
    flags: u32,
) -> RippleCalcResult {
    match to_strands_direct_only(sender, destination, issuer, currency, flags) {
        Ok(strands) if strands.len() == 1 => {
            let requested_out = Amount::Iou {
                value: *amount,
                currency: currency.clone(),
                issuer: *issuer,
            };
            execute_direct_only_strand(state, &strands[0], &requested_out, send_max)
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

fn execute_direct_iou_partial_flow(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
    deliver_amount: &IouValue,
    deliver_min: &IouValue,
    send_max: Option<&IouValue>,
    flags: u32,
) -> RippleCalcResult {
    let Some(best) = direct_iou_best_partial_amount(
        state,
        sender,
        destination,
        issuer,
        currency,
        deliver_amount,
        send_max,
    ) else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    if super::flow::compare_iou_values(&best, deliver_min) == std::cmp::Ordering::Less {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_PARTIAL",
        };
    }
    if let Some(send_limit) = send_max {
        let Some(quote) =
            direct_iou_quote_for_output(state, sender, destination, issuer, currency, &best)
        else {
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_DRY",
            };
        };
        let actual_in = Amount::Iou {
            value: quote.input,
            currency: currency.clone(),
            issuer: *issuer,
        };
        let actual_out = Amount::Iou {
            value: quote.output,
            currency: currency.clone(),
            issuer: *issuer,
        };
        let send_limit = Amount::Iou {
            value: *send_limit,
            currency: currency.clone(),
            issuer: *issuer,
        };
        let requested_out = Amount::Iou {
            value: *deliver_amount,
            currency: currency.clone(),
            issuer: *issuer,
        };
        if !limit_quality_allows(flags, &actual_in, &actual_out, &send_limit, &requested_out) {
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_PARTIAL",
            };
        }
    }
    execute_direct_iou_flow(
        state,
        sender,
        destination,
        issuer,
        currency,
        &best,
        send_max,
        flags,
    )
}

fn direct_iou_best_partial_amount(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
    deliver_amount: &IouValue,
    send_max: Option<&IouValue>,
) -> Option<IouValue> {
    if crate::ledger::tx::load_existing_account(state, destination).is_none() {
        return None;
    }

    let (src_quality_out, dst_quality_in) =
        direct_iou_qualities(state, sender, destination, issuer, currency);
    let src_quality_out = quality_rate_to_iou_value(src_quality_out);
    let dst_quality_in = quality_rate_to_iou_value(dst_quality_in);

    let mut best = *deliver_amount;
    if let Some(limit) = send_max {
        let send_limited = limit
            .div_round(&src_quality_out, false)
            .mul_round(&dst_quality_in, false);
        best = min_iou_value(&best, &send_limited);
    }

    if sender != issuer {
        let sender_line = load_existing_direct_trustline(state, sender, issuer, currency)?;
        let sender_funds = sender_line.balance_for(sender);
        if !sender_funds.is_positive() {
            return None;
        }
        let sender_limited = sender_funds
            .div_round(&src_quality_out, false)
            .mul_round(&dst_quality_in, false);
        best = min_iou_value(&best, &sender_limited);
    }

    if destination != issuer {
        let dest_line = load_existing_direct_trustline(state, destination, issuer, currency)?;
        let dest_balance = dest_line.balance_for(destination);
        let dest_limit = if destination == &dest_line.low_account {
            dest_line.low_limit
        } else {
            dest_line.high_limit
        };
        let dest_room = dest_limit.sub(&dest_balance);
        if !dest_room.is_positive() {
            return None;
        }
        let dest_limited = dest_room.mul_round(&dst_quality_in, false);
        best = min_iou_value(&best, &dest_limited);
    }

    if best.is_positive() {
        Some(best)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy)]
struct DirectIouQuote {
    input: IouValue,
    output: IouValue,
}

fn direct_iou_quote_for_output(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
    output: &IouValue,
) -> Option<DirectIouQuote> {
    if !output.is_positive() {
        return None;
    }
    let (src_quality_out, dst_quality_in) =
        direct_iou_qualities(state, sender, destination, issuer, currency);
    let src_to_dst = output.div_round(&quality_rate_to_iou_value(dst_quality_in), true);
    if !src_to_dst.is_positive() {
        return None;
    }
    let input = src_to_dst.mul_round(&quality_rate_to_iou_value(src_quality_out), true);
    if input.is_positive() {
        Some(DirectIouQuote {
            input,
            output: *output,
        })
    } else {
        None
    }
}

fn direct_iou_qualities(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
) -> (u32, u32) {
    let src_quality_out = if sender != issuer && destination != issuer {
        direct_transfer_rate(state, issuer)
    } else {
        QUALITY_ONE
    };
    let mut dst_quality_in = if destination != issuer {
        load_existing_direct_trustline(state, destination, issuer, currency)
            .map(|line| trustline_quality_in_for_account(&line, destination))
            .unwrap_or(QUALITY_ONE)
    } else {
        QUALITY_ONE
    };
    if dst_quality_in > QUALITY_ONE {
        dst_quality_in = QUALITY_ONE;
    }
    (
        normalize_quality(src_quality_out),
        normalize_quality(dst_quality_in),
    )
}

fn trustline_quality_in_for_account(line: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &line.low_account {
        normalize_quality(line.low_quality_in)
    } else {
        normalize_quality(line.high_quality_in)
    }
}

fn normalize_quality(quality: u32) -> u32 {
    if quality == 0 {
        QUALITY_ONE
    } else {
        quality
    }
}

fn min_iou_value(a: &IouValue, b: &IouValue) -> IouValue {
    if super::flow::compare_iou_values(a, b) == std::cmp::Ordering::Greater {
        *b
    } else {
        *a
    }
}

fn direct_transfer_rate(state: &mut LedgerState, issuer: &[u8; 20]) -> u32 {
    crate::ledger::tx::load_existing_account(state, issuer)
        .map(|account| {
            if account.transfer_rate == 0 {
                QUALITY_ONE
            } else {
                account.transfer_rate
            }
        })
        .unwrap_or(QUALITY_ONE)
}

fn quality_rate_to_iou_value(rate: u32) -> IouValue {
    let mut value = IouValue {
        mantissa: rate as i64,
        exponent: -9,
    };
    value.normalize();
    value
}

fn load_existing_direct_trustline(
    state: &mut LedgerState,
    account: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
) -> Option<crate::ledger::RippleState> {
    let key = crate::ledger::trustline::shamap_key(account, issuer, currency);
    if let Some(tl) = state.get_trustline(&key) {
        return Some(tl.clone());
    }
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    let decoded = crate::ledger::RippleState::decode_from_sle(&raw)?;
    state.hydrate_trustline(decoded.clone());
    Some(decoded)
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
#[allow(dead_code)]
fn direct_iou_payment(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
    amount: &IouValue,
    send_max: Option<&IouValue>,
    _flags: u32,
) -> RippleCalcResult {
    let strands = match to_strands_direct_only(sender, destination, issuer, currency, 0) {
        Ok(strands) => strands,
        Err(ter) => {
            return RippleCalcResult {
                success: false,
                ter,
            }
        }
    };
    let requested_amount = Amount::Iou {
        value: *amount,
        currency: currency.clone(),
        issuer: *issuer,
    };
    let requested_out = super::flow::FlowAmount::new(requested_amount.clone());

    let Some(mut strand) = executable_direct_only_strand(&strands[0], send_max) else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    state.begin_tx();
    let result = super::flow::flow_exact_out(state, &mut strand, requested_out);
    if result.success {
        if result.output.as_ref().is_some_and(|output| {
            super::flow::compare_amounts(output.as_amount(), &requested_amount)
                == std::cmp::Ordering::Less
        }) {
            state.discard_tx();
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_PARTIAL",
            };
        }
        let _commit = state.commit_tx();
        RippleCalcResult {
            success: true,
            ter: "tesSUCCESS",
        }
    } else {
        state.discard_tx();
        RippleCalcResult {
            success: false,
            ter: result.ter,
        }
    }
}

fn execute_direct_only_strand(
    state: &mut LedgerState,
    direct: &DirectStrand,
    requested_out: &Amount,
    send_max: Option<&IouValue>,
) -> RippleCalcResult {
    let Some(mut strand) = executable_direct_only_strand(direct, send_max) else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    state.begin_tx();
    let result = super::flow::flow_exact_out(
        state,
        &mut strand,
        super::flow::FlowAmount::new(requested_out.clone()),
    );
    if result.success {
        if result.output.as_ref().is_some_and(|output| {
            super::flow::compare_amounts(output.as_amount(), requested_out)
                == std::cmp::Ordering::Less
        }) {
            state.discard_tx();
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_PARTIAL",
            };
        }
        let _commit = state.commit_tx();
        RippleCalcResult {
            success: true,
            ter: "tesSUCCESS",
        }
    } else {
        state.discard_tx();
        RippleCalcResult {
            success: false,
            ter: result.ter,
        }
    }
}

fn executable_direct_only_strand(
    direct: &DirectStrand,
    send_max: Option<&IouValue>,
) -> Option<super::flow::Strand> {
    if direct.steps.is_empty() {
        return None;
    }
    let mut steps: Vec<Box<dyn super::flow::FlowStep>> = Vec::with_capacity(direct.steps.len());
    let mut prev_source = None;
    for (idx, step) in direct.steps.iter().enumerate() {
        let mut flow_step = super::flow::DirectStep::new(
            step.source,
            step.destination,
            step.issuer,
            step.currency.clone(),
        )
        .with_path_context(prev_source, false, idx == 0, step.is_last);
        if idx == 0 {
            flow_step = flow_step.with_send_max(send_max.copied());
        }
        steps.push(Box::new(flow_step));
        prev_source = Some(step.source);
    }
    Some(super::flow::Strand::new(steps))
}

fn execute_explicit_path_flow(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    send_max: Option<&Amount>,
    paths: &[Vec<PathStep>],
    flags: u32,
    domain_id: Option<[u8; 32]>,
    close_time: u64,
) -> RippleCalcResult {
    let Some(send_issue) = payment_source_issue(sender, deliver_amount, send_max) else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    let Some(deliver_issue) = issue_from_amount(deliver_amount) else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    let specs = match super::flow::build_payment_strands_with_domain(
        sender,
        destination,
        send_issue,
        deliver_issue,
        paths,
        flags,
        domain_id,
    ) {
        Ok(specs) => specs,
        Err(ter) => {
            return RippleCalcResult {
                success: false,
                ter,
            }
        }
    };

    let plans = match executable_path_plans(sender, &specs) {
        Ok(plans) => plans,
        Err(ter) => {
            return RippleCalcResult {
                success: false,
                ter,
            }
        }
    };
    if plans.is_empty() {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    }

    let mut aggregate_failure: Option<RippleCalcResult> = None;
    if let Some(send_limit) = send_max {
        if let Some(aggregate) = execute_explicit_path_aggregate_flow(
            state,
            sender,
            destination,
            deliver_amount,
            send_limit,
            &plans,
            flags,
            close_time,
        ) {
            if aggregate.success {
                return aggregate;
            }
            aggregate_failure = Some(aggregate);
        }
    }

    let mut best_plan: Option<ExecutablePathPlan> = None;
    let mut best_input: Option<Amount> = None;
    let mut saw_too_expensive = false;
    let mut last_ter = "tecPATH_DRY";
    let limit_quality =
        send_max.and_then(|send_limit| limit_quality_threshold(flags, send_limit, deliver_amount));
    for plan in &plans {
        let Some(mut strand) = executable_strand_from_plan(
            sender,
            destination,
            plan,
            close_time,
            plans.len() > 1,
            0,
            &[],
        ) else {
            continue;
        };

        state.begin_tx();
        let requested = limit_quality
            .map(|limit| {
                strand.limit_output_for_quality(
                    state,
                    &super::flow::FlowAmount::new(deliver_amount.clone()),
                    limit,
                )
            })
            .unwrap_or_else(|| super::flow::FlowAmount::new(deliver_amount.clone()));
        let result = super::flow::flow_exact_out(state, &mut strand, requested);

        if result.success {
            let input_within_limit = send_max.is_none_or(|send_limit| {
                result.input.as_ref().is_some_and(|input| {
                    super::flow::compare_amounts(input.as_amount(), send_limit)
                        != std::cmp::Ordering::Greater
                })
            });
            let quality_within_limit = send_max.is_none_or(|send_limit| {
                result.input.as_ref().is_some_and(|input| {
                    limit_quality_allows(
                        flags,
                        input.as_amount(),
                        deliver_amount,
                        send_limit,
                        deliver_amount,
                    )
                })
            });
            if input_within_limit && quality_within_limit {
                if let Some(input) = result.input.as_ref() {
                    let candidate_input = input.as_amount().clone();
                    let is_better = best_input.as_ref().is_none_or(|current_best| {
                        super::flow::compare_amounts(&candidate_input, current_best)
                            == std::cmp::Ordering::Less
                    });
                    if is_better {
                        best_input = Some(candidate_input);
                        best_plan = Some(plan.clone());
                    }
                }
            } else {
                saw_too_expensive = true;
            }
        } else {
            last_ter = result.ter;
        }
        state.discard_tx();
    }

    if let Some(plan) = best_plan {
        let Some(mut strand) = executable_strand_from_plan(
            sender,
            destination,
            &plan,
            close_time,
            plans.len() > 1,
            0,
            &[],
        ) else {
            return RippleCalcResult {
                success: false,
                ter: "tecPATH_DRY",
            };
        };
        state.begin_tx();
        let result = super::flow::flow_exact_out(
            state,
            &mut strand,
            super::flow::FlowAmount::new(deliver_amount.clone()),
        );
        let replay_ok = result.success
            && send_max.is_none_or(|send_limit| {
                result.input.as_ref().is_some_and(|input| {
                    super::flow::compare_amounts(input.as_amount(), send_limit)
                        != std::cmp::Ordering::Greater
                        && limit_quality_allows(
                            flags,
                            input.as_amount(),
                            deliver_amount,
                            send_limit,
                            deliver_amount,
                        )
                })
            });
        if replay_ok {
            let _commit = state.commit_tx();
            return RippleCalcResult {
                success: true,
                ter: "tesSUCCESS",
            };
        }
        state.discard_tx();
        last_ter = result.ter;
    }

    if let Some(aggregate) = aggregate_failure {
        return aggregate;
    }

    RippleCalcResult {
        success: false,
        ter: if saw_too_expensive {
            "tecPATH_PARTIAL"
        } else {
            last_ter
        },
    }
}

fn execute_explicit_path_aggregate_flow(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    send_limit: &Amount,
    plans: &[ExecutablePathPlan],
    flags: u32,
    close_time: u64,
) -> Option<RippleCalcResult> {
    execute_explicit_path_aggregate_flow_inner(
        state,
        sender,
        destination,
        deliver_amount,
        None,
        send_limit,
        plans,
        flags,
        close_time,
    )
}

fn execute_explicit_path_aggregate_partial_flow(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    deliver_min: &Amount,
    send_limit: &Amount,
    plans: &[ExecutablePathPlan],
    flags: u32,
    close_time: u64,
) -> Option<RippleCalcResult> {
    execute_explicit_path_aggregate_flow_inner(
        state,
        sender,
        destination,
        deliver_amount,
        Some(deliver_min),
        send_limit,
        plans,
        flags,
        close_time,
    )
}

fn execute_explicit_path_aggregate_flow_inner(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    deliver_min: Option<&Amount>,
    send_limit: &Amount,
    plans: &[ExecutablePathPlan],
    flags: u32,
    close_time: u64,
) -> Option<RippleCalcResult> {
    if issue_from_amount(deliver_amount).is_none()
        || issue_from_amount(send_limit).is_none()
        || deliver_min
            .is_some_and(|min| issue_from_amount(deliver_amount) != issue_from_amount(min))
    {
        return None;
    }

    let mut remaining_in = super::flow::FlowAmount::new(send_limit.clone());
    let mut remaining_out = super::flow::FlowAmount::new(deliver_amount.clone());
    let mut delivered_any = false;
    let mut saw_blocked_liquidity = false;
    let mut active: Vec<usize> = (0..plans.len()).collect();
    let multi_path = plans.len() > 1;
    let amm_initial_pools = if multi_path {
        capture_initial_amm_pools(state, sender, &plans, close_time)
    } else {
        Vec::new()
    };
    let mut amm_iteration = 0u16;
    let limit_quality = limit_quality_threshold(flags, send_limit, deliver_amount);
    state.begin_tx();

    for _ in 0..super::flow::RIPPLE_MAX_OFFERS_CONSIDERED {
        if remaining_out.is_zero() || remaining_in.is_zero() || active.is_empty() {
            break;
        }

        sort_active_by_theoretical_quality(
            state,
            sender,
            destination,
            plans,
            &mut active,
            close_time,
            multi_path,
            amm_iteration,
            &amm_initial_pools,
            limit_quality,
        );

        let mut best: Option<AggregateCandidate> = None;
        let mut next_active = Vec::with_capacity(active.len());

        for spec_idx in active.iter().copied() {
            let Some(plan) = plans.get(spec_idx) else {
                continue;
            };

            let mut spec_useful = false;
            if let Some(mut exact_strand) = executable_strand_from_plan(
                sender,
                destination,
                plan,
                close_time,
                multi_path,
                amm_iteration,
                &amm_initial_pools,
            ) {
                state.begin_tx();
                let requested_out = limit_quality
                    .map(|limit| {
                        exact_strand.limit_output_for_quality(state, &remaining_out, limit)
                    })
                    .unwrap_or_else(|| remaining_out.clone());
                let exact =
                    super::flow::flow_exact_out(state, &mut exact_strand, requested_out.clone());
                if exact.success {
                    if let (Some(input), Some(output)) =
                        (exact.input.as_ref(), exact.output.as_ref())
                    {
                        let input_within_remaining = super::flow::compare_amounts(
                            input.as_amount(),
                            remaining_in.as_amount(),
                        ) != std::cmp::Ordering::Greater;
                        let quality_ok = limit_quality_allows(
                            flags,
                            input.as_amount(),
                            output.as_amount(),
                            send_limit,
                            deliver_amount,
                        );
                        let output_within_remaining = super::flow::compare_amounts(
                            output.as_amount(),
                            remaining_out.as_amount(),
                        ) != std::cmp::Ordering::Greater;
                        if input_within_remaining && output_within_remaining && quality_ok {
                            spec_useful = true;
                            let candidate = AggregateCandidate {
                                spec_idx,
                                input: input.clone(),
                                output: output.clone(),
                                inactive: exact.inactive,
                            };
                            if aggregate_candidate_better(&candidate, best.as_ref()) {
                                best = Some(candidate);
                            }
                        } else if !input.is_zero() {
                            saw_blocked_liquidity = true;
                        }
                    }
                }
                state.discard_tx();
            }

            let Some(mut input_strand) = executable_strand_from_plan(
                sender,
                destination,
                plan,
                close_time,
                multi_path,
                amm_iteration,
                &amm_initial_pools,
            ) else {
                if spec_useful {
                    next_active.push(spec_idx);
                }
                continue;
            };
            state.begin_tx();
            let forward =
                super::flow::flow_with_input(state, &mut input_strand, remaining_in.clone());
            if forward.success {
                let Some(input) = forward.input.as_ref() else {
                    state.discard_tx();
                    if spec_useful {
                        next_active.push(spec_idx);
                    }
                    continue;
                };
                let Some(output) = forward.output.as_ref() else {
                    state.discard_tx();
                    if spec_useful {
                        next_active.push(spec_idx);
                    }
                    continue;
                };
                let output_within_remaining =
                    super::flow::compare_amounts(output.as_amount(), remaining_out.as_amount())
                        != std::cmp::Ordering::Greater;
                let input_within_remaining =
                    super::flow::compare_amounts(input.as_amount(), remaining_in.as_amount())
                        != std::cmp::Ordering::Greater;
                let quality_ok = limit_quality_allows(
                    flags,
                    input.as_amount(),
                    output.as_amount(),
                    send_limit,
                    deliver_amount,
                );
                if output_within_remaining
                    && input_within_remaining
                    && quality_ok
                    && !input.is_zero()
                    && !output.is_zero()
                    && remaining_in.checked_sub_same_issue(input).is_some()
                    && remaining_out.checked_sub_same_issue(output).is_some()
                {
                    spec_useful = true;
                    let candidate = AggregateCandidate {
                        spec_idx,
                        input: input.clone(),
                        output: output.clone(),
                        inactive: forward.inactive,
                    };
                    if aggregate_candidate_better(&candidate, best.as_ref()) {
                        best = Some(candidate);
                    }
                } else if !input.is_zero()
                    && !output.is_zero()
                    && (!input_within_remaining || !quality_ok)
                {
                    saw_blocked_liquidity = true;
                }
                state.discard_tx();
            } else {
                state.discard_tx();
            }

            if spec_useful {
                next_active.push(spec_idx);
            }
        }

        let Some(best) = best else { break };
        let Some(plan) = plans.get(best.spec_idx) else {
            break;
        };
        let Some(mut strand) = executable_strand_from_plan(
            sender,
            destination,
            plan,
            close_time,
            multi_path,
            amm_iteration,
            &amm_initial_pools,
        ) else {
            active = next_active;
            continue;
        };

        state.begin_tx();
        // Forward probes are useful for discovering how much a strand can
        // deliver, but committing them directly can over-debit early endpoint
        // steps when later liquidity only consumes part of the offered input.
        // Commit the selected output through the normal reverse-quote replay so
        // the charged input is the amount actually needed for that output.
        let committed = super::flow::flow_exact_out(state, &mut strand, best.output.clone());
        if committed.success {
            let input = committed.input.as_ref().unwrap_or(&best.input);
            let output = committed.output.as_ref().unwrap_or(&best.output);
            let input_ok =
                super::flow::compare_amounts(input.as_amount(), remaining_in.as_amount())
                    != std::cmp::Ordering::Greater;
            let output_ok =
                super::flow::compare_amounts(output.as_amount(), remaining_out.as_amount())
                    != std::cmp::Ordering::Greater;
            let quality_ok = limit_quality_allows(
                flags,
                input.as_amount(),
                output.as_amount(),
                send_limit,
                deliver_amount,
            );
            if !input_ok || !output_ok || !quality_ok || input.is_zero() || output.is_zero() {
                state.discard_tx();
                active = next_active;
                continue;
            }
            let Some(next_remaining_in) = remaining_in.checked_sub_same_issue(input) else {
                state.discard_tx();
                active = next_active;
                continue;
            };
            let Some(next_remaining_out) = remaining_out.checked_sub_same_issue(output) else {
                state.discard_tx();
                active = next_active;
                continue;
            };
            remaining_in = next_remaining_in;
            remaining_out = next_remaining_out;
            delivered_any = true;
            if committed.used_amm {
                amm_iteration = amm_iteration.saturating_add(1);
            }
            state.commit_tx();
        } else {
            state.discard_tx();
        }

        if best.inactive {
            next_active.retain(|idx| *idx != best.spec_idx);
        }
        active = next_active;
    }

    if remaining_out.is_zero() {
        state.commit_tx();
        Some(RippleCalcResult {
            success: true,
            ter: "tesSUCCESS",
        })
    } else if let Some(deliver_min) = deliver_min {
        let Some(delivered) = super::flow::FlowAmount::new(deliver_amount.clone())
            .checked_sub_same_issue(&remaining_out)
        else {
            state.discard_tx();
            return None;
        };
        if !delivered.is_zero()
            && super::flow::compare_amounts(delivered.as_amount(), deliver_min)
                != std::cmp::Ordering::Less
        {
            state.commit_tx();
            Some(RippleCalcResult {
                success: true,
                ter: "tesSUCCESS",
            })
        } else {
            state.discard_tx();
            if delivered_any || saw_blocked_liquidity {
                Some(RippleCalcResult {
                    success: false,
                    ter: "tecPATH_PARTIAL",
                })
            } else {
                None
            }
        }
    } else {
        state.discard_tx();
        if delivered_any || saw_blocked_liquidity {
            Some(RippleCalcResult {
                success: false,
                ter: "tecPATH_PARTIAL",
            })
        } else {
            None
        }
    }
}

#[derive(Clone)]
struct AggregateCandidate {
    spec_idx: usize,
    input: super::flow::FlowAmount,
    output: super::flow::FlowAmount,
    inactive: bool,
}

fn limit_quality_threshold(
    flags: u32,
    send_limit: &Amount,
    deliver_amount: &Amount,
) -> Option<super::flow::FlowQuality> {
    if (flags & TF_LIMIT_QUALITY) == 0 {
        return None;
    }
    super::flow::FlowQuality::from_amounts(send_limit, deliver_amount, true)
}

#[allow(clippy::too_many_arguments)]
fn sort_active_by_theoretical_quality(
    state: &LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    plans: &[ExecutablePathPlan],
    active: &mut Vec<usize>,
    close_time: u64,
    multi_path: bool,
    amm_iteration: u16,
    amm_initial_pools: &[InitialAmmPool],
    limit_quality: Option<super::flow::FlowQuality>,
) {
    let mut scored = Vec::with_capacity(active.len());
    for spec_idx in active.drain(..) {
        let Some(plan) = plans.get(spec_idx) else {
            continue;
        };
        let Some(strand) = executable_strand_from_plan(
            sender,
            destination,
            plan,
            close_time,
            multi_path,
            amm_iteration,
            amm_initial_pools,
        ) else {
            continue;
        };
        let Some(quality) = strand.quality_upper_bound(state) else {
            continue;
        };
        if limit_quality.is_some_and(|limit| !quality.not_worse_than(limit)) {
            continue;
        }
        scored.push((spec_idx, quality));
    }

    scored.sort_by(|(_, lhs), (_, rhs)| super::flow::compare_iou_values(&lhs.rate(), &rhs.rate()));
    active.extend(scored.into_iter().map(|(idx, _)| idx));
}

#[derive(Clone)]
struct ExecutablePathPlan {
    spec: super::flow::FlowStrandSpec,
}

#[derive(Clone)]
struct InitialAmmPool {
    book: super::flow::FlowBook,
    taker: [u8; 20],
    pool: crate::ledger::tx::amm_step::AmmPool,
}

fn capture_initial_amm_pools(
    state: &LedgerState,
    sender: &[u8; 20],
    plans: &[ExecutablePathPlan],
    close_time: u64,
) -> Vec<InitialAmmPool> {
    let mut out = Vec::new();
    for plan in plans {
        let mut current = *sender;
        for step in &plan.spec.steps {
            match step {
                super::flow::FlowStepSpec::Direct { account, .. } => current = *account,
                super::flow::FlowStepSpec::Book(book) => {
                    if book.domain_id.is_none()
                        && !out.iter().any(|existing: &InitialAmmPool| {
                            existing.book == *book && existing.taker == current
                        })
                    {
                        if let Some(pool) = crate::ledger::tx::amm_step::load_amm_pool_for_account(
                            state,
                            &book.in_issue,
                            &book.out_issue,
                            &current,
                            close_time,
                        )
                        .or_else(|| {
                            crate::ledger::tx::amm_step::load_amm_pool(
                                state,
                                &book.in_issue,
                                &book.out_issue,
                            )
                        }) {
                            out.push(InitialAmmPool {
                                book: book.clone(),
                                taker: current,
                                pool,
                            });
                        }
                    }
                    current = book_step_output_holder(&book.out_issue, current);
                }
            }
        }
    }
    out
}

fn executable_path_plans(
    sender: &[u8; 20],
    specs: &[super::flow::FlowStrandSpec],
) -> Result<Vec<ExecutablePathPlan>, &'static str> {
    let mut plans = Vec::new();
    for spec in specs {
        validate_executable_path_spec(*sender, spec)?;
        plans.push(ExecutablePathPlan { spec: spec.clone() });
    }
    Ok(plans)
}

fn validate_executable_path_spec(
    sender: [u8; 20],
    spec: &super::flow::FlowStrandSpec,
) -> Result<(), &'static str> {
    let mut current_account = sender;
    let mut direct_sources = HashSet::<Issue>::new();
    let mut direct_destinations = HashSet::<Issue>::new();
    let mut first_book_input: Option<Issue> = None;
    let mut book_outputs = HashSet::<Issue>::new();
    let mut previous_book_output: Option<Issue> = None;

    for step in &spec.steps {
        match step {
            super::flow::FlowStepSpec::Direct { account, issue } => {
                if *account == current_account {
                    return Err("temBAD_PATH");
                }
                if let Issue::Iou { currency, .. } = issue {
                    let src_issue = Issue::Iou {
                        currency: currency.clone(),
                        issuer: current_account,
                    };
                    let dst_issue = Issue::Iou {
                        currency: currency.clone(),
                        issuer: *account,
                    };
                    if book_outputs.contains(&src_issue)
                        && previous_book_output.as_ref() != Some(&src_issue)
                    {
                        return Err("temBAD_PATH_LOOP");
                    }
                    if !direct_sources.insert(src_issue) || !direct_destinations.insert(dst_issue) {
                        return Err("temBAD_PATH_LOOP");
                    }
                }
                current_account = *account;
                previous_book_output = None;
            }
            super::flow::FlowStepSpec::Book(book) => {
                if book.in_issue == book.out_issue {
                    return Err("temBAD_PATH");
                }
                if first_book_input.as_ref() == Some(&book.out_issue) {
                    return Err("temBAD_PATH_LOOP");
                }
                if !book_outputs.insert(book.out_issue.clone())
                    || direct_sources.contains(&book.out_issue)
                    || direct_destinations.contains(&book.out_issue)
                {
                    return Err("temBAD_PATH_LOOP");
                }
                if first_book_input.is_none() {
                    first_book_input = Some(book.in_issue.clone());
                }
                if let Issue::Iou { issuer, .. } = &book.out_issue {
                    current_account = *issuer;
                }
                previous_book_output = Some(book.out_issue.clone());
            }
        }
    }

    Ok(())
}

fn aggregate_candidate_better(
    candidate: &AggregateCandidate,
    current: Option<&AggregateCandidate>,
) -> bool {
    let Some(current) = current else {
        return true;
    };

    let candidate_in = super::flow::amount_to_iou_value(candidate.input.as_amount());
    let candidate_out = super::flow::amount_to_iou_value(candidate.output.as_amount());
    let current_in = super::flow::amount_to_iou_value(current.input.as_amount());
    let current_out = super::flow::amount_to_iou_value(current.output.as_amount());
    if !candidate_in.is_positive()
        || !candidate_out.is_positive()
        || !current_in.is_positive()
        || !current_out.is_positive()
    {
        return false;
    }

    let candidate_cross = candidate_in.mul_round(&current_out, false);
    let current_cross = current_in.mul_round(&candidate_out, false);
    match super::flow::compare_iou_values(&candidate_cross, &current_cross) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => {
            super::flow::compare_amounts(candidate.output.as_amount(), current.output.as_amount())
                == std::cmp::Ordering::Greater
        }
    }
}

fn execute_explicit_path_partial_flow(
    state: &mut LedgerState,
    sender: &[u8; 20],
    destination: &[u8; 20],
    deliver_amount: &Amount,
    deliver_min: &Amount,
    send_max: Option<&Amount>,
    paths: &[Vec<PathStep>],
    flags: u32,
    domain_id: Option<[u8; 32]>,
    close_time: u64,
) -> RippleCalcResult {
    if issue_from_amount(deliver_amount) != issue_from_amount(deliver_min) {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    }
    let Some(send_max) = send_max else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    let Some(send_issue) = issue_from_amount(send_max) else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    let Some(deliver_issue) = issue_from_amount(deliver_amount) else {
        return RippleCalcResult {
            success: false,
            ter: "tecPATH_DRY",
        };
    };
    let specs = match super::flow::build_payment_strands_with_domain(
        sender,
        destination,
        send_issue,
        deliver_issue,
        paths,
        flags,
        domain_id,
    ) {
        Ok(specs) => specs,
        Err(ter) => {
            return RippleCalcResult {
                success: false,
                ter,
            }
        }
    };

    let plans = match executable_path_plans(sender, &specs) {
        Ok(plans) => plans,
        Err(ter) => {
            return RippleCalcResult {
                success: false,
                ter,
            }
        }
    };
    if let Some(result) = execute_explicit_path_aggregate_partial_flow(
        state,
        sender,
        destination,
        deliver_amount,
        deliver_min,
        send_max,
        &plans,
        flags,
        close_time,
    ) {
        return result;
    }

    let mut saw_supported_partial_path = false;
    for spec in specs {
        let Some((book, output_recipient)) = single_book_path_from_spec(destination, &spec) else {
            continue;
        };
        saw_supported_partial_path = true;
        state.begin_tx();
        let offered_in = super::flow::FlowAmount::new(send_max.clone());
        let plan = super::flow::plan_book_partial_in_all_qualities(
            state,
            &book,
            &offered_in,
            close_time,
            super::flow::RIPPLE_MAX_OFFERS_CONSIDERED,
        );
        let output_ok = plan.output.as_ref().is_some_and(|output| {
            super::flow::compare_amounts(output.as_amount(), deliver_min)
                != std::cmp::Ordering::Less
                && super::flow::compare_amounts(output.as_amount(), deliver_amount)
                    != std::cmp::Ordering::Greater
        });
        let quality_ok = match (plan.input.as_ref(), plan.output.as_ref()) {
            (Some(input), Some(output)) => limit_quality_allows(
                flags,
                input.as_amount(),
                output.as_amount(),
                send_max,
                deliver_amount,
            ),
            _ => false,
        };
        if output_ok && quality_ok {
            match super::flow::apply_book_partial_fill_plan(state, &plan, *sender, output_recipient)
            {
                Ok(_) => {
                    let _commit = state.commit_tx();
                    return RippleCalcResult {
                        success: true,
                        ter: "tesSUCCESS",
                    };
                }
                Err(ter) => {
                    state.discard_tx();
                    return RippleCalcResult {
                        success: false,
                        ter,
                    };
                }
            }
        }
        state.discard_tx();
    }

    RippleCalcResult {
        success: false,
        ter: if saw_supported_partial_path {
            "tecPATH_PARTIAL"
        } else {
            "tecPATH_DRY"
        },
    }
}

fn limit_quality_allows(
    flags: u32,
    actual_in: &Amount,
    actual_out: &Amount,
    send_max: &Amount,
    deliver_amount: &Amount,
) -> bool {
    if (flags & TF_LIMIT_QUALITY) == 0 {
        return true;
    }

    let actual_in_value = super::flow::amount_to_iou_value(actual_in);
    let actual_out_value = super::flow::amount_to_iou_value(actual_out);
    let send_max_value = super::flow::amount_to_iou_value(send_max);
    let deliver_value = super::flow::amount_to_iou_value(deliver_amount);
    if !actual_in_value.is_positive()
        || !actual_out_value.is_positive()
        || !send_max_value.is_positive()
        || !deliver_value.is_positive()
    {
        return false;
    }

    let actual_cross = actual_in_value.mul_round(&deliver_value, false);
    let limit_cross = send_max_value.mul_round(&actual_out_value, false);
    super::flow::compare_iou_values(&actual_cross, &limit_cross) != std::cmp::Ordering::Greater
}

fn executable_strand_from_plan(
    sender: &[u8; 20],
    destination: &[u8; 20],
    plan: &ExecutablePathPlan,
    close_time: u64,
    amm_multi_path: bool,
    amm_iteration: u16,
    amm_initial_pools: &[InitialAmmPool],
) -> Option<super::flow::Strand> {
    let mut current = *sender;
    let mut steps: Vec<Box<dyn super::flow::FlowStep>> = Vec::new();
    let mut idx = 0usize;
    let mut prev_direct_source: Option<[u8; 20]> = None;
    let mut prev_is_book = false;
    let spec = &plan.spec;
    while idx < spec.steps.len() {
        match &spec.steps[idx] {
            super::flow::FlowStepSpec::Direct { account, issue } => {
                let source = current;
                let is_first = steps.is_empty();
                let is_last = idx == spec.steps.len() - 1;
                match issue {
                    Issue::Xrp => {
                        steps.push(Box::new(super::flow::XrpEndpointStep::new(
                            current, *account,
                        )));
                        prev_direct_source = None;
                        prev_is_book = false;
                    }
                    Issue::Iou { currency, issuer } => {
                        steps.push(Box::new(
                            super::flow::DirectStep::new(
                                current,
                                *account,
                                *issuer,
                                currency.clone(),
                            )
                            .with_path_context(
                                prev_direct_source,
                                prev_is_book,
                                is_first,
                                is_last,
                            ),
                        ));
                        prev_direct_source = Some(source);
                        prev_is_book = false;
                    }
                    Issue::Mpt(_) => return None,
                }
                current = *account;
            }
            super::flow::FlowStepSpec::Book(book) => {
                let output_recipient = match spec.steps.get(idx + 1) {
                    Some(super::flow::FlowStepSpec::Direct { account, issue })
                        if Some(issue.clone()) == Some(book.out_issue.clone()) =>
                    {
                        book_step_output_holder(&book.out_issue, *account)
                    }
                    Some(super::flow::FlowStepSpec::Book(_)) => {
                        book_step_output_holder(&book.out_issue, current)
                    }
                    _ => *destination,
                };
                steps.push(Box::new(
                    super::flow::BookStep::new(book.clone(), current, output_recipient)
                        .with_close_time(close_time)
                        .with_all_qualities(true)
                        .with_amm_context(amm_multi_path, amm_iteration)
                        .with_amm_initial_pool(
                            amm_initial_pools
                                .iter()
                                .find(|initial| initial.book == *book && initial.taker == current)
                                .map(|initial| initial.pool.clone()),
                        ),
                ));
                current = output_recipient;
                prev_direct_source = None;
                prev_is_book = true;
            }
        }
        idx += 1;
    }
    if steps.is_empty() {
        None
    } else {
        Some(super::flow::Strand::new(steps))
    }
}

fn book_step_output_holder(issue: &Issue, fallback: [u8; 20]) -> [u8; 20] {
    match issue {
        Issue::Iou { issuer, .. } => *issuer,
        Issue::Xrp | Issue::Mpt(_) => fallback,
    }
}

fn payment_source_issue(
    sender: &[u8; 20],
    deliver_amount: &Amount,
    send_max: Option<&Amount>,
) -> Option<Issue> {
    if let Some(send_max) = send_max {
        return issue_from_amount(send_max);
    }

    match deliver_amount {
        Amount::Xrp(_) => Some(Issue::Xrp),
        Amount::Iou { currency, .. } => Some(Issue::Iou {
            currency: currency.clone(),
            issuer: *sender,
        }),
        Amount::Mpt(_) => issue_from_amount(deliver_amount),
    }
}

fn single_book_path_from_spec(
    destination: &[u8; 20],
    spec: &super::flow::FlowStrandSpec,
) -> Option<(super::flow::FlowBook, [u8; 20])> {
    match spec.steps.as_slice() {
        [super::flow::FlowStepSpec::Book(book)] => Some((book.clone(), *destination)),
        [super::flow::FlowStepSpec::Book(book), super::flow::FlowStepSpec::Direct { account, issue }]
            if Some(issue.clone()) == Some(book.out_issue.clone()) =>
        {
            Some((book.clone(), *account))
        }
        _ => None,
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

#[cfg(test)]
fn trustline_auth_flag_for(source: &[u8; 20], destination: &[u8; 20]) -> u32 {
    if source > destination {
        crate::ledger::trustline::LSF_HIGH_AUTH
    } else {
        crate::ledger::trustline::LSF_LOW_AUTH
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{directory, ter, AccountRoot, BookKey, Offer, RippleState};
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

    fn book_offer(account: [u8; 20], sequence: u32, pays: Amount, gets: Amount) -> Offer {
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

    fn fund_iou_holder(
        state: &mut LedgerState,
        holder: [u8; 20],
        issuer: [u8; 20],
        currency: Currency,
        value: f64,
    ) {
        let mut line = RippleState::new(&holder, &issuer, currency);
        line.transfer(&issuer, &IouValue::from_f64(value));
        state.insert_trustline(line);
    }

    fn allow_iou_holder(
        state: &mut LedgerState,
        holder: [u8; 20],
        issuer: [u8; 20],
        currency: Currency,
        limit: f64,
    ) {
        let key = crate::ledger::trustline::shamap_key(&holder, &issuer, &currency);
        let mut line = state
            .get_trustline(&key)
            .cloned()
            .unwrap_or_else(|| RippleState::new(&holder, &issuer, currency));
        line.set_limit_for(&holder, IouValue::from_f64(limit));
        state.insert_trustline(line);
    }

    fn insert_amm_pool(
        state: &mut LedgerState,
        pseudo: [u8; 20],
        issuer: [u8; 20],
        currency: Currency,
        xrp_reserve: u64,
        iou_reserve: f64,
    ) {
        use crate::ledger::meta::ParsedField;

        let usd_issue = Issue::Iou {
            currency: currency.clone(),
            issuer,
        };
        state.insert_account(account(issuer, 0, 0));
        state.insert_account(account(pseudo, xrp_reserve, 0));

        let mut pool_line = RippleState::new(&pseudo, &issuer, currency);
        pool_line.transfer(&issuer, &IouValue::from_f64(iou_reserve));
        state.insert_trustline(pool_line);

        let amm_fields = vec![
            ParsedField {
                type_code: 8,
                field_code: 1,
                data: pseudo.to_vec(),
            },
            ParsedField {
                type_code: 1,
                field_code: 2,
                data: 0u16.to_be_bytes().to_vec(),
            },
            ParsedField {
                type_code: 24,
                field_code: 3,
                data: Issue::Xrp.to_bytes(),
            },
            ParsedField {
                type_code: 24,
                field_code: 4,
                data: usd_issue.to_bytes(),
            },
        ];
        state.insert_raw(
            crate::ledger::tx::amm_key(&Issue::Xrp, &usd_issue),
            crate::ledger::meta::build_sle(0x0079, &amm_fields, None, None),
        );
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
    fn direct_iou_payment_from_holder_reports_partial_when_balance_is_insufficient() {
        let mut state = state_with_accounts(0);
        let usd = usd_currency();
        let mut line = RippleState::new(&genesis_id(), &dest_id(), usd.clone());
        line.set_limit_for(&genesis_id(), IouValue::from_f64(100.0));
        line.transfer(&dest_id(), &IouValue::from_f64(10.0));
        assert_eq!(line.balance_for(&genesis_id()), IouValue::from_f64(10.0));
        state.insert_trustline(line);

        let tx = sign_iou_payment(1, &dest_id(), 50.0);
        let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_PATH_PARTIAL);
        assert!(result.applied, "tecPATH_PARTIAL claims fee only");
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 100_000_000 - 12);
        assert_eq!(sender.sequence, 2);
        let line = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .unwrap();
        assert_eq!(line.balance_for(&genesis_id()), IouValue::from_f64(10.0));
    }

    #[test]
    fn direct_iou_partial_payment_delivers_best_available_when_full_amount_is_dry() {
        const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

        let mut state = LedgerState::new();
        let sender = genesis_id();
        let destination = dest_id();
        let issuer = issuer_id();
        let usd = usd_currency();
        state.insert_account(account(sender, 100_000_000, 0));
        state.insert_account(account(destination, 0, 0));
        state.insert_account(account(issuer, 0, 0));

        let mut sender_line = RippleState::new(&sender, &issuer, usd.clone());
        sender_line.transfer(&issuer, &IouValue::from_f64(5.0));
        state.insert_trustline(sender_line);

        let mut dest_line = RippleState::new(&destination, &issuer, usd.clone());
        dest_line.set_limit_for(&destination, IouValue::from_f64(100.0));
        state.insert_trustline(dest_line);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let deliver_min = Amount::Iou {
            value: IouValue::from_f64(4.0),
            currency: usd.clone(),
            issuer,
        };
        let result = ripple_calculate(
            &mut state,
            &sender,
            &destination,
            &deliver,
            None,
            Some(&deliver_min),
            &[],
            TF_PARTIAL_PAYMENT,
        );

        assert!(result.success, "unexpected TER: {}", result.ter);
        assert_eq!(result.ter, "tesSUCCESS");
        let sender_line = state.get_trustline_for(&sender, &issuer, &usd).unwrap();
        assert!(sender_line.balance_for(&sender).is_zero());
        let dest_line = state
            .get_trustline_for(&destination, &issuer, &usd)
            .unwrap();
        assert_eq!(dest_line.balance_for(&destination), IouValue::from_f64(5.0));
    }

    #[test]
    fn direct_iou_partial_payment_respects_limit_quality_with_transfer_rate() {
        const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

        let mut state = LedgerState::new();
        let sender = genesis_id();
        let destination = dest_id();
        let issuer = issuer_id();
        let usd = usd_currency();
        state.insert_account(account(sender, 100_000_000, 0));
        state.insert_account(account(destination, 0, 0));
        let mut issuer_account = account(issuer, 0, 0);
        issuer_account.transfer_rate = 2_000_000_000;
        state.insert_account(issuer_account);

        let mut sender_line = RippleState::new(&sender, &issuer, usd.clone());
        sender_line.transfer(&issuer, &IouValue::from_f64(20.0));
        state.insert_trustline(sender_line);

        let mut dest_line = RippleState::new(&destination, &issuer, usd.clone());
        dest_line.set_limit_for(&destination, IouValue::from_f64(100.0));
        state.insert_trustline(dest_line);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let deliver_min = Amount::Iou {
            value: IouValue::from_f64(5.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Iou {
            value: IouValue::from_f64(11.0),
            currency: usd.clone(),
            issuer,
        };
        let result = ripple_calculate(
            &mut state,
            &sender,
            &destination,
            &deliver,
            Some(&send_max),
            Some(&deliver_min),
            &[],
            TF_PARTIAL_PAYMENT | TF_LIMIT_QUALITY,
        );

        assert!(!result.success);
        assert_eq!(result.ter, "tecPATH_PARTIAL");
        let sender_line = state.get_trustline_for(&sender, &issuer, &usd).unwrap();
        assert_eq!(sender_line.balance_for(&sender), IouValue::from_f64(20.0));
        let dest_line = state
            .get_trustline_for(&destination, &issuer, &usd)
            .unwrap();
        assert!(dest_line.balance_for(&destination).is_zero());
    }

    #[test]
    fn direct_iou_partial_payment_respects_destination_quality_in_limit_room() {
        const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

        let mut state = LedgerState::new();
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let destination = [3u8; 20];
        let usd = usd_currency();
        state.insert_account(account(sender, 100_000_000, 0));
        state.insert_account(account(destination, 0, 0));
        state.insert_account(account(issuer, 0, 0));

        let mut sender_line = RippleState::new(&sender, &issuer, usd.clone());
        sender_line.transfer(&issuer, &IouValue::from_f64(20.0));
        state.insert_trustline(sender_line);

        let mut dest_line = RippleState::new(&destination, &issuer, usd.clone());
        dest_line.set_limit_for(&destination, IouValue::from_f64(8.0));
        if destination == dest_line.low_account {
            dest_line.low_quality_in = 500_000_000;
        } else {
            dest_line.high_quality_in = 500_000_000;
        }
        state.insert_trustline(dest_line);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let deliver_min = Amount::Iou {
            value: IouValue::from_f64(4.0),
            currency: usd.clone(),
            issuer,
        };
        let result = ripple_calculate(
            &mut state,
            &sender,
            &destination,
            &deliver,
            None,
            Some(&deliver_min),
            &[],
            TF_PARTIAL_PAYMENT,
        );

        assert!(result.success, "unexpected TER: {}", result.ter);
        let sender_line = state.get_trustline_for(&sender, &issuer, &usd).unwrap();
        assert_eq!(sender_line.balance_for(&sender), IouValue::from_f64(12.0));
        let dest_line = state
            .get_trustline_for(&destination, &issuer, &usd)
            .unwrap();
        assert_eq!(dest_line.balance_for(&destination), IouValue::from_f64(8.0));
    }

    #[test]
    fn direct_iou_payment_from_issuer_reports_partial_when_destination_limit_is_insufficient() {
        let mut state = state_with_accounts(0);
        let usd = usd_currency();
        let mut line = RippleState::new(&genesis_id(), &dest_id(), usd.clone());
        line.set_limit_for(&dest_id(), IouValue::from_f64(10.0));
        state.insert_trustline(line);

        let tx = sign_iou_payment(1, &genesis_id(), 50.0);
        let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_PATH_PARTIAL);
        assert!(result.applied, "tecPATH_PARTIAL claims fee only");
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

        assert_eq!(result.ter, ter::TER_NO_AUTH);
        assert!(!result.applied, "terNO_AUTH does not claim a fee");
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 100_000_000);
        assert_eq!(sender.sequence, 1);
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
    fn direct_iou_same_asset_sendmax_uses_direct_flow() {
        let mut state = state_with_accounts(0);
        let usd = usd_currency();
        let mut line = RippleState::new(&genesis_id(), &dest_id(), usd.clone());
        line.set_limit_for(&dest_id(), IouValue::from_f64(100.0));
        state.insert_trustline(line);

        let mut tx = sign_iou_payment(1, &genesis_id(), 5.0);
        tx.send_max = Some(Amount::Iou {
            value: IouValue::from_f64(5.0),
            currency: usd.clone(),
            issuer: genesis_id(),
        });

        let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TES_SUCCESS);
        let line = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .unwrap();
        assert_eq!(line.balance_for(&dest_id()), IouValue::from_f64(5.0));
    }

    #[test]
    fn explicit_iou_account_path_executes_via_forward_replay() {
        let issuer = genesis_id();
        let intermediate = [0x55; 20];
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(intermediate, 0, 0));

        let mut intermediate_line = RippleState::new(&intermediate, &issuer, usd.clone());
        intermediate_line.set_limit_for(&intermediate, IouValue::from_f64(100.0));
        state.insert_trustline(intermediate_line);

        let mut dest_line = RippleState::new(&dest_id(), &intermediate, usd.clone());
        dest_line.set_limit_for(&dest_id(), IouValue::from_f64(100.0));
        state.insert_trustline(dest_line);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(5.0),
            currency: usd.clone(),
            issuer,
        };
        let paths = vec![vec![PathStep {
            account: Some(intermediate),
            currency: None,
            issuer: None,
        }]];
        let result = ripple_calculate(
            &mut state,
            &issuer,
            &dest_id(),
            &deliver,
            None,
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success, "unexpected TER: {}", result.ter);
        assert_eq!(result.ter, "tesSUCCESS");
        let intermediate_line = state
            .get_trustline_for(&intermediate, &issuer, &usd)
            .expect("intermediate trustline remains");
        assert_eq!(
            intermediate_line.balance_for(&intermediate),
            IouValue::from_f64(5.0)
        );
        let dest_line = state
            .get_trustline_for(&dest_id(), &intermediate, &usd)
            .expect("destination receives through explicit path");
        assert_eq!(dest_line.balance_for(&dest_id()), IouValue::from_f64(5.0));
    }

    #[test]
    fn explicit_book_path_xrp_to_iou_executes_through_strand() {
        let maker = [0x77; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(issuer, 0, 0));
        state.insert_account(account(maker, 2_000_000, 0));
        fund_iou_holder(&mut state, maker, issuer, usd.clone(), 10.0);
        allow_iou_holder(&mut state, dest_id(), issuer, usd.clone(), 20.0);
        state.insert_offer(book_offer(
            maker,
            1,
            Amount::Xrp(100),
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(4.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(50);
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some(usd.code),
            issuer: Some(issuer),
        }]];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success, "unexpected TER: {}", result.ter);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000 - 40
        );
        assert_eq!(state.get_account(&maker).unwrap().balance, 2_000_040);
        let line = state
            .get_trustline_for(&dest_id(), &issuer, &usd)
            .expect("destination receives book output");
        assert_eq!(line.balance_for(&dest_id()), IouValue::from_f64(4.0));
    }

    #[test]
    fn explicit_book_path_can_consume_multiple_quality_directories() {
        let cheap_maker = [0x86; 20];
        let expensive_maker = [0x87; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(issuer, 0, 0));
        state.insert_account(account(cheap_maker, 1_000, 0));
        state.insert_account(account(expensive_maker, 1_000, 0));
        fund_iou_holder(&mut state, cheap_maker, issuer, usd.clone(), 2.0);
        fund_iou_holder(&mut state, expensive_maker, issuer, usd.clone(), 2.0);
        allow_iou_holder(&mut state, dest_id(), issuer, usd.clone(), 20.0);
        state.insert_offer(book_offer(
            cheap_maker,
            1,
            Amount::Xrp(20),
            Amount::Iou {
                value: IouValue::from_f64(2.0),
                currency: usd.clone(),
                issuer,
            },
        ));
        state.insert_offer(book_offer(
            expensive_maker,
            1,
            Amount::Xrp(30),
            Amount::Iou {
                value: IouValue::from_f64(2.0),
                currency: usd.clone(),
                issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(4.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(60);
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some(usd.code),
            issuer: Some(issuer),
        }]];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000 - 50
        );
        assert_eq!(state.get_account(&cheap_maker).unwrap().balance, 1_020);
        assert_eq!(state.get_account(&expensive_maker).unwrap().balance, 1_030);
        let line = state
            .get_trustline_for(&dest_id(), &issuer, &usd)
            .expect("destination receives output from both quality levels");
        assert_eq!(line.balance_for(&dest_id()), IouValue::from_f64(4.0));
    }

    #[test]
    fn explicit_book_path_iou_to_xrp_executes_through_strand() {
        let maker = [0x78; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(issuer, 0, 0));
        state.insert_account(account(maker, 2_000_000, 0));
        fund_iou_holder(&mut state, genesis_id(), issuer, usd.clone(), 10.0);
        allow_iou_holder(&mut state, maker, issuer, usd.clone(), 20.0);
        state.insert_offer(book_offer(
            maker,
            1,
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            },
            Amount::Xrp(100),
        ));

        let deliver = Amount::Xrp(40);
        let send_max = Amount::Iou {
            value: IouValue::from_f64(5.0),
            currency: usd.clone(),
            issuer,
        };
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some([0u8; 20]),
            issuer: None,
        }]];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(state.get_account(&dest_id()).unwrap().balance, 40);
        assert_eq!(state.get_account(&maker).unwrap().balance, 1_999_960);
        let sender_line = state
            .get_trustline_for(&genesis_id(), &issuer, &usd)
            .expect("sender trustline debited");
        assert_eq!(
            sender_line.balance_for(&genesis_id()),
            IouValue::from_f64(6.0)
        );
    }

    #[test]
    fn explicit_book_path_iou_to_xrp_rejects_unfunded_sender_input() {
        let maker = [0x7B; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(issuer, 0, 0));
        state.insert_account(account(maker, 2_000_000, 0));
        state.insert_offer(book_offer(
            maker,
            1,
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            },
            Amount::Xrp(100),
        ));

        let deliver = Amount::Xrp(40);
        let send_max = Amount::Iou {
            value: IouValue::from_f64(5.0),
            currency: usd.clone(),
            issuer,
        };
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some([0u8; 20]),
            issuer: None,
        }]];

        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(!result.success);
        assert_eq!(result.ter, "tecPATH_DRY");
        assert_eq!(state.get_account(&dest_id()).unwrap().balance, 0);
        assert_eq!(state.get_account(&maker).unwrap().balance, 2_000_000);
        assert!(state
            .get_trustline_for(&genesis_id(), &issuer, &usd)
            .is_none());
    }

    #[test]
    fn default_book_iou_to_xrp_payment_consumes_offer() {
        let maker = [0x79; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(issuer, 0, 0));
        state.insert_account(account(maker, 2_000_000, 0));
        fund_iou_holder(&mut state, genesis_id(), issuer, usd.clone(), 10.0);
        allow_iou_holder(&mut state, maker, issuer, usd.clone(), 20.0);
        state.insert_offer(book_offer(
            maker,
            1,
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            },
            Amount::Xrp(100),
        ));

        let deliver = Amount::Xrp(40);
        let send_max = Amount::Iou {
            value: IouValue::from_f64(5.0),
            currency: usd.clone(),
            issuer,
        };
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &[],
            0,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(state.get_account(&dest_id()).unwrap().balance, 40);
        assert_eq!(state.get_account(&maker).unwrap().balance, 1_999_960);
    }

    #[test]
    fn explicit_book_path_iou_to_iou_executes_through_strand() {
        let maker = [0x7A; 20];
        let usd_issuer = issuer_id();
        let eur_issuer = [0x43; 20];
        let usd = usd_currency();
        let eur = Currency::from_code("EUR").unwrap();
        let mut state = state_with_accounts(0);
        state.insert_account(account(usd_issuer, 0, 0));
        state.insert_account(account(eur_issuer, 0, 0));
        state.insert_account(account(maker, 2_000_000, 0));
        fund_iou_holder(&mut state, genesis_id(), usd_issuer, usd.clone(), 10.0);
        fund_iou_holder(&mut state, maker, eur_issuer, eur.clone(), 10.0);
        allow_iou_holder(&mut state, maker, usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, dest_id(), eur_issuer, eur.clone(), 20.0);
        state.insert_offer(book_offer(
            maker,
            1,
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(20.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(8.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let send_max = Amount::Iou {
            value: IouValue::from_f64(5.0),
            currency: usd.clone(),
            issuer: usd_issuer,
        };
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some(eur.code),
            issuer: Some(eur_issuer),
        }]];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        let dest_line = state
            .get_trustline_for(&dest_id(), &eur_issuer, &eur)
            .expect("destination receives EUR");
        assert_eq!(dest_line.balance_for(&dest_id()), IouValue::from_f64(8.0));
        let sender_line = state
            .get_trustline_for(&genesis_id(), &usd_issuer, &usd)
            .expect("sender spends USD");
        assert_eq!(
            sender_line.balance_for(&genesis_id()),
            IouValue::from_f64(6.0)
        );
    }

    #[test]
    fn explicit_two_book_path_executes_with_transient_bridge_balance() {
        let usd_maker = [0x81; 20];
        let eur_maker = [0x82; 20];
        let usd_issuer = issuer_id();
        let eur_issuer = [0x44; 20];
        let usd = usd_currency();
        let eur = Currency::from_code("EUR").unwrap();
        let mut state = state_with_accounts(0);
        state.insert_account(account(usd_issuer, 0, 0));
        state.insert_account(account(eur_issuer, 0, 0));
        state.insert_account(account(usd_maker, 1_000, 0));
        state.insert_account(account(eur_maker, 1_000, 0));
        fund_iou_holder(&mut state, usd_maker, usd_issuer, usd.clone(), 10.0);
        fund_iou_holder(&mut state, eur_maker, eur_issuer, eur.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker, usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, dest_id(), eur_issuer, eur.clone(), 20.0);
        state.insert_offer(book_offer(
            usd_maker,
            1,
            Amount::Xrp(25),
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
        ));
        state.insert_offer(book_offer(
            eur_maker,
            1,
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(20.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(8.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let send_max = Amount::Xrp(50);
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some(usd.code),
            issuer: Some(usd_issuer),
        }]];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000 - 10
        );
        let dest_line = state
            .get_trustline_for(&dest_id(), &eur_issuer, &eur)
            .expect("destination receives EUR through two books");
        assert_eq!(dest_line.balance_for(&dest_id()), IouValue::from_f64(8.0));
        assert!(
            state
                .get_trustline_for(&genesis_id(), &usd_issuer, &usd)
                .is_none(),
            "book-to-book bridge liquidity must not create a sender USD line"
        );
    }

    #[test]
    fn explicit_path_rejects_book_loop_back_to_source_issue() {
        let usd_issuer = issuer_id();
        let eur_issuer = [0x96; 20];
        let usd = usd_currency();
        let eur = Currency::from_code("EUR").unwrap();
        let mut state = state_with_accounts(0);
        state.insert_account(account(usd_issuer, 0, 0));
        state.insert_account(account(eur_issuer, 0, 0));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(1.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let send_max = Amount::Xrp(1);
        let paths = vec![vec![
            PathStep {
                account: None,
                currency: Some(usd.code),
                issuer: Some(usd_issuer),
            },
            PathStep {
                account: None,
                currency: Some([0u8; 20]),
                issuer: None,
            },
            PathStep {
                account: None,
                currency: Some(eur.code),
                issuer: Some(eur_issuer),
            },
        ]];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(!result.success);
        assert_eq!(result.ter, "temBAD_PATH_LOOP");
    }

    #[test]
    fn executable_path_allows_book_output_that_was_earlier_book_input() {
        let usd = usd_currency();
        let eur = Currency::from_code("EUR").unwrap();
        let issuer_a = [0xA1; 20];
        let issuer_b = [0xA2; 20];
        let issuer_c = [0xA3; 20];
        let issuer_d = [0xA4; 20];
        let usd_a = Issue::Iou {
            currency: usd,
            issuer: issuer_a,
        };
        let eur_b = Issue::Iou {
            currency: eur,
            issuer: issuer_b,
        };
        let jpy_c = Issue::Iou {
            currency: Currency::from_code("JPY").unwrap(),
            issuer: issuer_c,
        };
        let cad_d = Issue::Iou {
            currency: Currency::from_code("CAD").unwrap(),
            issuer: issuer_d,
        };
        let spec = crate::ledger::tx::flow::FlowStrandSpec {
            steps: vec![
                crate::ledger::tx::flow::FlowStepSpec::Book(
                    crate::ledger::tx::flow::FlowBook::new(usd_a.clone(), eur_b.clone()),
                ),
                crate::ledger::tx::flow::FlowStepSpec::Book(
                    crate::ledger::tx::flow::FlowBook::new(jpy_c.clone(), cad_d.clone()),
                ),
                crate::ledger::tx::flow::FlowStepSpec::Book(
                    crate::ledger::tx::flow::FlowBook::new(cad_d, jpy_c),
                ),
            ],
        };

        assert_eq!(validate_executable_path_spec(genesis_id(), &spec), Ok(()));
    }

    #[test]
    fn explicit_two_book_partial_falls_back_to_deliver_min_exact_flow() {
        const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

        let usd_maker = [0x88; 20];
        let eur_maker = [0x89; 20];
        let usd_issuer = issuer_id();
        let eur_issuer = [0x46; 20];
        let usd = usd_currency();
        let eur = Currency::from_code("EUR").unwrap();
        let mut state = state_with_accounts(0);
        state.insert_account(account(usd_issuer, 0, 0));
        state.insert_account(account(eur_issuer, 0, 0));
        state.insert_account(account(usd_maker, 1_000, 0));
        state.insert_account(account(eur_maker, 1_000, 0));
        fund_iou_holder(&mut state, usd_maker, usd_issuer, usd.clone(), 10.0);
        fund_iou_holder(&mut state, eur_maker, eur_issuer, eur.clone(), 4.0);
        allow_iou_holder(&mut state, genesis_id(), usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker, usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, dest_id(), eur_issuer, eur.clone(), 20.0);
        state.insert_offer(book_offer(
            usd_maker,
            1,
            Amount::Xrp(25),
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
        ));
        state.insert_offer(book_offer(
            eur_maker,
            1,
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(4.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(8.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let deliver_min = Amount::Iou {
            value: IouValue::from_f64(4.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let send_max = Amount::Xrp(30);
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some(usd.code),
            issuer: Some(usd_issuer),
        }]];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            Some(&deliver_min),
            &paths,
            TF_PARTIAL_PAYMENT | TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000 - 25
        );
        let dest_line = state
            .get_trustline_for(&dest_id(), &eur_issuer, &eur)
            .expect("destination receives DeliverMin through two-book fallback");
        assert_eq!(dest_line.balance_for(&dest_id()), IouValue::from_f64(4.0));
    }

    #[test]
    fn explicit_path_chooses_cheaper_viable_strand_over_default() {
        let direct_maker = [0x83; 20];
        let usd_maker = [0x84; 20];
        let eur_maker = [0x85; 20];
        let usd_issuer = issuer_id();
        let eur_issuer = [0x45; 20];
        let usd = usd_currency();
        let eur = Currency::from_code("EUR").unwrap();
        let mut state = state_with_accounts(0);
        state.insert_account(account(usd_issuer, 0, 0));
        state.insert_account(account(eur_issuer, 0, 0));
        state.insert_account(account(direct_maker, 1_000, 0));
        state.insert_account(account(usd_maker, 1_000, 0));
        state.insert_account(account(eur_maker, 1_000, 0));
        fund_iou_holder(&mut state, direct_maker, eur_issuer, eur.clone(), 8.0);
        fund_iou_holder(&mut state, usd_maker, usd_issuer, usd.clone(), 10.0);
        fund_iou_holder(&mut state, eur_maker, eur_issuer, eur.clone(), 20.0);
        allow_iou_holder(&mut state, genesis_id(), usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker, usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, dest_id(), eur_issuer, eur.clone(), 20.0);

        let expensive_offer = book_offer(
            direct_maker,
            1,
            Amount::Xrp(100),
            Amount::Iou {
                value: IouValue::from_f64(8.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        );
        let expensive_offer_key = expensive_offer.key();
        state.insert_offer(expensive_offer);
        state.insert_offer(book_offer(
            usd_maker,
            1,
            Amount::Xrp(100),
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
        ));
        state.insert_offer(book_offer(
            eur_maker,
            1,
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(20.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(8.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let send_max = Amount::Xrp(120);
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some(usd.code),
            issuer: Some(usd_issuer),
        }]];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            0,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000 - 40,
            "engine should prefer the cheaper explicit strand, not first default strand"
        );
        assert!(
            state.get_offer(&expensive_offer_key).is_some(),
            "worse default-path offer must remain untouched"
        );
        assert_eq!(state.get_account(&direct_maker).unwrap().balance, 1_000);
        let dest_line = state
            .get_trustline_for(&dest_id(), &eur_issuer, &eur)
            .expect("destination receives EUR through cheaper path");
        assert_eq!(dest_line.balance_for(&dest_id()), IouValue::from_f64(8.0));
    }

    #[test]
    fn explicit_paths_aggregate_liquidity_across_two_strands() {
        let usd_maker = [0x8A; 20];
        let eur_maker_1 = [0x8B; 20];
        let jpy_maker = [0x8C; 20];
        let eur_maker_2 = [0x8D; 20];
        let usd_issuer = issuer_id();
        let jpy_issuer = [0x47; 20];
        let eur_issuer = [0x48; 20];
        let usd = usd_currency();
        let jpy = Currency::from_code("JPY").unwrap();
        let eur = Currency::from_code("EUR").unwrap();
        let mut state = state_with_accounts(0);
        for account_id in [
            usd_issuer,
            jpy_issuer,
            eur_issuer,
            usd_maker,
            eur_maker_1,
            jpy_maker,
            eur_maker_2,
        ] {
            state.insert_account(account(account_id, 1_000, 0));
        }

        fund_iou_holder(&mut state, usd_maker, usd_issuer, usd.clone(), 5.0);
        fund_iou_holder(&mut state, eur_maker_1, eur_issuer, eur.clone(), 5.0);
        fund_iou_holder(&mut state, jpy_maker, jpy_issuer, jpy.clone(), 5.0);
        fund_iou_holder(&mut state, eur_maker_2, eur_issuer, eur.clone(), 5.0);
        allow_iou_holder(&mut state, genesis_id(), usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, genesis_id(), jpy_issuer, jpy.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker_1, usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker_2, jpy_issuer, jpy.clone(), 20.0);
        allow_iou_holder(&mut state, dest_id(), eur_issuer, eur.clone(), 20.0);

        state.insert_offer(book_offer(
            usd_maker,
            1,
            Amount::Xrp(50),
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
        ));
        state.insert_offer(book_offer(
            eur_maker_1,
            1,
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));
        state.insert_offer(book_offer(
            jpy_maker,
            1,
            Amount::Xrp(50),
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: jpy.clone(),
                issuer: jpy_issuer,
            },
        ));
        state.insert_offer(book_offer(
            eur_maker_2,
            1,
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: jpy.clone(),
                issuer: jpy_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let send_max = Amount::Xrp(120);
        let paths = vec![
            vec![PathStep {
                account: None,
                currency: Some(usd.code),
                issuer: Some(usd_issuer),
            }],
            vec![PathStep {
                account: None,
                currency: Some(jpy.code),
                issuer: Some(jpy_issuer),
            }],
        ];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success, "unexpected TER: {}", result.ter);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000 - 100
        );
        let dest_line = state
            .get_trustline_for(&dest_id(), &eur_issuer, &eur)
            .expect("destination receives aggregated EUR");
        assert_eq!(dest_line.balance_for(&dest_id()), IouValue::from_f64(10.0));
    }

    #[test]
    fn explicit_path_aggregation_uses_better_later_strand_first() {
        let usd_maker = [0x8E; 20];
        let eur_maker_1 = [0x8F; 20];
        let jpy_maker = [0x90; 20];
        let eur_maker_2 = [0x91; 20];
        let usd_issuer = issuer_id();
        let jpy_issuer = [0x49; 20];
        let eur_issuer = [0x4A; 20];
        let usd = usd_currency();
        let jpy = Currency::from_code("JPY").unwrap();
        let eur = Currency::from_code("EUR").unwrap();
        let mut state = state_with_accounts(0);
        for account_id in [
            usd_issuer,
            jpy_issuer,
            eur_issuer,
            usd_maker,
            eur_maker_1,
            jpy_maker,
            eur_maker_2,
        ] {
            state.insert_account(account(account_id, 1_000, 0));
        }

        fund_iou_holder(&mut state, usd_maker, usd_issuer, usd.clone(), 5.0);
        fund_iou_holder(&mut state, eur_maker_1, eur_issuer, eur.clone(), 5.0);
        fund_iou_holder(&mut state, jpy_maker, jpy_issuer, jpy.clone(), 7.0);
        fund_iou_holder(&mut state, eur_maker_2, eur_issuer, eur.clone(), 7.0);
        allow_iou_holder(&mut state, genesis_id(), usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, genesis_id(), jpy_issuer, jpy.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker_1, usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker_2, jpy_issuer, jpy.clone(), 20.0);
        allow_iou_holder(&mut state, dest_id(), eur_issuer, eur.clone(), 20.0);

        let worse_offer = book_offer(
            usd_maker,
            1,
            Amount::Xrp(100),
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
        );
        let worse_offer_key = worse_offer.key();
        state.insert_offer(worse_offer);
        state.insert_offer(book_offer(
            eur_maker_1,
            1,
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));
        state.insert_offer(book_offer(
            jpy_maker,
            1,
            Amount::Xrp(70),
            Amount::Iou {
                value: IouValue::from_f64(7.0),
                currency: jpy.clone(),
                issuer: jpy_issuer,
            },
        ));
        state.insert_offer(book_offer(
            eur_maker_2,
            1,
            Amount::Iou {
                value: IouValue::from_f64(7.0),
                currency: jpy.clone(),
                issuer: jpy_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(7.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let send_max = Amount::Xrp(150);
        let paths = vec![
            vec![PathStep {
                account: None,
                currency: Some(usd.code),
                issuer: Some(usd_issuer),
            }],
            vec![PathStep {
                account: None,
                currency: Some(jpy.code),
                issuer: Some(jpy_issuer),
            }],
        ];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success, "unexpected TER: {}", result.ter);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000 - 130,
            "scheduler should take the better later JPY strand before partially using USD"
        );
        let dest_line = state
            .get_trustline_for(&dest_id(), &eur_issuer, &eur)
            .expect("destination receives aggregated EUR");
        assert_eq!(dest_line.balance_for(&dest_id()), IouValue::from_f64(10.0));
        let remaining_worse = state
            .get_offer(&worse_offer_key)
            .expect("worse strand is only partially consumed");
        assert_eq!(remaining_worse.taker_pays, Amount::Xrp(40));
    }

    #[test]
    fn explicit_full_payment_aggregates_cheaper_partial_before_full_strand() {
        let usd_maker = [0xA0; 20];
        let eur_maker_1 = [0xA1; 20];
        let jpy_maker = [0xA2; 20];
        let eur_maker_2 = [0xA3; 20];
        let usd_issuer = issuer_id();
        let jpy_issuer = [0xA4; 20];
        let eur_issuer = [0xA5; 20];
        let usd = usd_currency();
        let jpy = Currency::from_code("JPY").unwrap();
        let eur = Currency::from_code("EUR").unwrap();
        let mut state = state_with_accounts(0);
        for account_id in [
            usd_issuer,
            jpy_issuer,
            eur_issuer,
            usd_maker,
            eur_maker_1,
            jpy_maker,
            eur_maker_2,
        ] {
            state.insert_account(account(account_id, 1_000, 0));
        }

        fund_iou_holder(&mut state, usd_maker, usd_issuer, usd.clone(), 6.0);
        fund_iou_holder(&mut state, eur_maker_1, eur_issuer, eur.clone(), 6.0);
        fund_iou_holder(&mut state, jpy_maker, jpy_issuer, jpy.clone(), 10.0);
        fund_iou_holder(&mut state, eur_maker_2, eur_issuer, eur.clone(), 10.0);
        allow_iou_holder(&mut state, genesis_id(), usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, genesis_id(), jpy_issuer, jpy.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker_1, usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker_2, jpy_issuer, jpy.clone(), 20.0);
        allow_iou_holder(&mut state, dest_id(), eur_issuer, eur.clone(), 20.0);

        state.insert_offer(book_offer(
            usd_maker,
            1,
            Amount::Xrp(60),
            Amount::Iou {
                value: IouValue::from_f64(6.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
        ));
        state.insert_offer(book_offer(
            eur_maker_1,
            1,
            Amount::Iou {
                value: IouValue::from_f64(6.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(6.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));
        let expensive_offer = book_offer(
            jpy_maker,
            1,
            Amount::Xrp(200),
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: jpy.clone(),
                issuer: jpy_issuer,
            },
        );
        let expensive_offer_key = expensive_offer.key();
        state.insert_offer(expensive_offer);
        state.insert_offer(book_offer(
            eur_maker_2,
            1,
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: jpy.clone(),
                issuer: jpy_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let send_max = Amount::Xrp(220);
        let paths = vec![
            vec![PathStep {
                account: None,
                currency: Some(usd.code),
                issuer: Some(usd_issuer),
            }],
            vec![PathStep {
                account: None,
                currency: Some(jpy.code),
                issuer: Some(jpy_issuer),
            }],
        ];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success, "unexpected TER: {}", result.ter);
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000 - 140,
            "full explicit payments must not ignore cheaper partial strand liquidity"
        );
        let remaining_expensive = state
            .get_offer(&expensive_offer_key)
            .expect("expensive full strand should be partially consumed");
        assert_eq!(remaining_expensive.taker_pays, Amount::Xrp(120));
        let dest_line = state
            .get_trustline_for(&dest_id(), &eur_issuer, &eur)
            .expect("destination receives full EUR delivery");
        assert_eq!(dest_line.balance_for(&dest_id()), IouValue::from_f64(10.0));
    }

    #[test]
    fn explicit_path_aggregation_rolls_back_when_later_strand_breaks_limit_quality() {
        let usd_maker = [0x97; 20];
        let eur_maker_1 = [0x98; 20];
        let jpy_maker = [0x99; 20];
        let eur_maker_2 = [0x9A; 20];
        let usd_issuer = issuer_id();
        let jpy_issuer = [0x9B; 20];
        let eur_issuer = [0x9C; 20];
        let usd = usd_currency();
        let jpy = Currency::from_code("JPY").unwrap();
        let eur = Currency::from_code("EUR").unwrap();
        let mut state = state_with_accounts(0);
        for account_id in [
            usd_issuer,
            jpy_issuer,
            eur_issuer,
            usd_maker,
            eur_maker_1,
            jpy_maker,
            eur_maker_2,
        ] {
            state.insert_account(account(account_id, 1_000, 0));
        }

        fund_iou_holder(&mut state, usd_maker, usd_issuer, usd.clone(), 3.0);
        fund_iou_holder(&mut state, eur_maker_1, eur_issuer, eur.clone(), 3.0);
        fund_iou_holder(&mut state, jpy_maker, jpy_issuer, jpy.clone(), 7.0);
        fund_iou_holder(&mut state, eur_maker_2, eur_issuer, eur.clone(), 7.0);
        allow_iou_holder(&mut state, genesis_id(), usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, genesis_id(), jpy_issuer, jpy.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker_1, usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker_2, jpy_issuer, jpy.clone(), 20.0);
        allow_iou_holder(&mut state, dest_id(), eur_issuer, eur.clone(), 20.0);

        let expensive_offer = book_offer(
            usd_maker,
            1,
            Amount::Xrp(60),
            Amount::Iou {
                value: IouValue::from_f64(3.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
        );
        let expensive_offer_key = expensive_offer.key();
        state.insert_offer(expensive_offer);
        state.insert_offer(book_offer(
            eur_maker_1,
            1,
            Amount::Iou {
                value: IouValue::from_f64(3.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(3.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));
        state.insert_offer(book_offer(
            jpy_maker,
            1,
            Amount::Xrp(70),
            Amount::Iou {
                value: IouValue::from_f64(7.0),
                currency: jpy.clone(),
                issuer: jpy_issuer,
            },
        ));
        state.insert_offer(book_offer(
            eur_maker_2,
            1,
            Amount::Iou {
                value: IouValue::from_f64(7.0),
                currency: jpy.clone(),
                issuer: jpy_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(7.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let send_max = Amount::Xrp(100);
        let paths = vec![
            vec![PathStep {
                account: None,
                currency: Some(usd.code),
                issuer: Some(usd_issuer),
            }],
            vec![PathStep {
                account: None,
                currency: Some(jpy.code),
                issuer: Some(jpy_issuer),
            }],
        ];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_LIMIT_QUALITY | TF_NO_RIPPLE_DIRECT,
        );

        assert!(!result.success);
        assert_eq!(result.ter, "tecPATH_PARTIAL");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000,
            "quality-limited aggregate failure must roll back earlier fills"
        );
        assert!(state.get_offer(&expensive_offer_key).is_some());
        let dest_line = state
            .get_trustline_for(&dest_id(), &eur_issuer, &eur)
            .expect("destination limit line remains after rollback");
        assert!(
            dest_line.balance_for(&dest_id()).is_zero(),
            "destination must not receive a partial fill without tfPartialPayment"
        );
    }

    #[test]
    fn explicit_partial_paths_deliver_best_available_across_deeper_strands() {
        const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

        let usd_maker = [0x92; 20];
        let eur_maker_1 = [0x93; 20];
        let jpy_maker = [0x94; 20];
        let eur_maker_2 = [0x95; 20];
        let usd_issuer = issuer_id();
        let jpy_issuer = [0x4B; 20];
        let eur_issuer = [0x4C; 20];
        let usd = usd_currency();
        let jpy = Currency::from_code("JPY").unwrap();
        let eur = Currency::from_code("EUR").unwrap();
        let mut state = state_with_accounts(0);
        for account_id in [
            usd_issuer,
            jpy_issuer,
            eur_issuer,
            usd_maker,
            eur_maker_1,
            jpy_maker,
            eur_maker_2,
        ] {
            state.insert_account(account(account_id, 1_000, 0));
        }

        fund_iou_holder(&mut state, usd_maker, usd_issuer, usd.clone(), 5.0);
        fund_iou_holder(&mut state, eur_maker_1, eur_issuer, eur.clone(), 5.0);
        fund_iou_holder(&mut state, jpy_maker, jpy_issuer, jpy.clone(), 7.0);
        fund_iou_holder(&mut state, eur_maker_2, eur_issuer, eur.clone(), 7.0);
        allow_iou_holder(&mut state, genesis_id(), usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, genesis_id(), jpy_issuer, jpy.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker_1, usd_issuer, usd.clone(), 20.0);
        allow_iou_holder(&mut state, eur_maker_2, jpy_issuer, jpy.clone(), 20.0);
        allow_iou_holder(&mut state, dest_id(), eur_issuer, eur.clone(), 20.0);

        state.insert_offer(book_offer(
            usd_maker,
            1,
            Amount::Xrp(100),
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
        ));
        state.insert_offer(book_offer(
            eur_maker_1,
            1,
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer: usd_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));
        state.insert_offer(book_offer(
            jpy_maker,
            1,
            Amount::Xrp(70),
            Amount::Iou {
                value: IouValue::from_f64(7.0),
                currency: jpy.clone(),
                issuer: jpy_issuer,
            },
        ));
        state.insert_offer(book_offer(
            eur_maker_2,
            1,
            Amount::Iou {
                value: IouValue::from_f64(7.0),
                currency: jpy.clone(),
                issuer: jpy_issuer,
            },
            Amount::Iou {
                value: IouValue::from_f64(7.0),
                currency: eur.clone(),
                issuer: eur_issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let deliver_min = Amount::Iou {
            value: IouValue::from_f64(6.0),
            currency: eur.clone(),
            issuer: eur_issuer,
        };
        let send_max = Amount::Xrp(80);
        let paths = vec![
            vec![PathStep {
                account: None,
                currency: Some(usd.code),
                issuer: Some(usd_issuer),
            }],
            vec![PathStep {
                account: None,
                currency: Some(jpy.code),
                issuer: Some(jpy_issuer),
            }],
        ];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            Some(&deliver_min),
            &paths,
            TF_PARTIAL_PAYMENT | TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success, "unexpected TER: {}", result.ter);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000 - 80
        );
        let dest_line = state
            .get_trustline_for(&dest_id(), &eur_issuer, &eur)
            .expect("destination receives best available partial EUR");
        assert_eq!(dest_line.balance_for(&dest_id()), IouValue::from_f64(7.5));
    }

    #[test]
    fn explicit_book_path_rolls_back_when_sendmax_is_too_low() {
        let maker = [0x7B; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(issuer, 0, 0));
        state.insert_account(account(maker, 2_000_000, 0));
        fund_iou_holder(&mut state, genesis_id(), issuer, usd.clone(), 10.0);
        allow_iou_holder(&mut state, maker, issuer, usd.clone(), 20.0);
        let offer = book_offer(
            maker,
            1,
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            },
            Amount::Xrp(100),
        );
        let offer_key = offer.key();
        state.insert_offer(offer);

        let deliver = Amount::Xrp(40);
        let send_max = Amount::Iou {
            value: IouValue::from_f64(3.0),
            currency: usd.clone(),
            issuer,
        };
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some([0u8; 20]),
            issuer: None,
        }]];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &paths,
            TF_NO_RIPPLE_DIRECT,
        );

        assert!(!result.success);
        assert_eq!(result.ter, "tecPATH_PARTIAL");
        assert_eq!(state.get_account(&dest_id()).unwrap().balance, 0);
        assert_eq!(state.get_account(&maker).unwrap().balance, 2_000_000);
        assert!(state.get_offer(&offer_key).is_some());
        let sender_line = state
            .get_trustline_for(&genesis_id(), &issuer, &usd)
            .expect("sender funds unchanged");
        assert_eq!(
            sender_line.balance_for(&genesis_id()),
            IouValue::from_f64(10.0)
        );
    }

    #[test]
    fn explicit_book_partial_payment_delivers_best_available_when_full_path_is_dry() {
        const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

        let maker = [0x7D; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(maker, 1_000, 0));
        fund_iou_holder(&mut state, maker, issuer, usd.clone(), 4.0);
        allow_iou_holder(&mut state, dest_id(), issuer, usd.clone(), 20.0);
        state.insert_offer(book_offer(
            maker,
            1,
            Amount::Xrp(40),
            Amount::Iou {
                value: IouValue::from_f64(4.0),
                currency: usd.clone(),
                issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let deliver_min = Amount::Iou {
            value: IouValue::from_f64(3.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(100);
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some(usd.code),
            issuer: Some(issuer),
        }]];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            Some(&deliver_min),
            &paths,
            TF_PARTIAL_PAYMENT | TF_NO_RIPPLE_DIRECT,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        let line = state
            .get_trustline_for(&dest_id(), &issuer, &usd)
            .expect("destination receives best available partial");
        assert_eq!(line.balance_for(&dest_id()), IouValue::from_f64(4.0));
    }

    #[test]
    fn explicit_book_partial_payment_respects_limit_quality() {
        const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

        let maker = [0x7E; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(maker, 1_000, 0));
        fund_iou_holder(&mut state, maker, issuer, usd.clone(), 4.0);
        let offer = book_offer(
            maker,
            1,
            Amount::Xrp(80),
            Amount::Iou {
                value: IouValue::from_f64(4.0),
                currency: usd.clone(),
                issuer,
            },
        );
        let offer_key = offer.key();
        state.insert_offer(offer);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let deliver_min = Amount::Iou {
            value: IouValue::from_f64(3.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(100);
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some(usd.code),
            issuer: Some(issuer),
        }]];
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            Some(&deliver_min),
            &paths,
            TF_PARTIAL_PAYMENT | TF_LIMIT_QUALITY | TF_NO_RIPPLE_DIRECT,
        );

        assert!(!result.success);
        assert_eq!(result.ter, "tecPATH_PARTIAL");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000
        );
        assert_eq!(state.get_account(&maker).unwrap().balance, 1_000);
        assert!(state.get_offer(&offer_key).is_some());
        assert!(
            state.get_trustline_for(&dest_id(), &issuer, &usd).is_none(),
            "failed quality-limited partial must not mutate destination funds"
        );
    }

    #[test]
    fn default_book_xrp_to_iou_payment_consumes_offer() {
        let maker = [0x77; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(maker, 1_000, 0));
        fund_iou_holder(&mut state, maker, issuer, usd.clone(), 10.0);
        allow_iou_holder(&mut state, dest_id(), issuer, usd.clone(), 20.0);
        state.insert_offer(book_offer(
            maker,
            1,
            Amount::Xrp(100),
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(4.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(50);
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &[],
            0,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000 - 40
        );
        assert_eq!(state.get_account(&maker).unwrap().balance, 1_040);
        let line = state
            .get_trustline_for(&dest_id(), &issuer, &usd)
            .expect("destination receives delivered IOU");
        assert_eq!(line.balance_for(&dest_id()), IouValue::from_f64(4.0));
    }

    #[test]
    fn default_book_partial_payment_delivers_best_available_when_full_book_is_dry() {
        const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

        let maker = [0x7C; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(maker, 1_000, 0));
        fund_iou_holder(&mut state, maker, issuer, usd.clone(), 4.0);
        allow_iou_holder(&mut state, dest_id(), issuer, usd.clone(), 20.0);
        state.insert_offer(book_offer(
            maker,
            1,
            Amount::Xrp(40),
            Amount::Iou {
                value: IouValue::from_f64(4.0),
                currency: usd.clone(),
                issuer,
            },
        ));

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let deliver_min = Amount::Iou {
            value: IouValue::from_f64(3.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(100);
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            Some(&deliver_min),
            &[],
            TF_PARTIAL_PAYMENT,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000 - 40
        );
        assert_eq!(state.get_account(&maker).unwrap().balance, 1_040);
        let line = state
            .get_trustline_for(&dest_id(), &issuer, &usd)
            .expect("destination receives best available partial");
        assert_eq!(line.balance_for(&dest_id()), IouValue::from_f64(4.0));
    }

    #[test]
    fn default_book_partial_payment_respects_limit_quality() {
        const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

        let maker = [0x7F; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(maker, 1_000, 0));
        fund_iou_holder(&mut state, maker, issuer, usd.clone(), 4.0);
        let offer = book_offer(
            maker,
            1,
            Amount::Xrp(80),
            Amount::Iou {
                value: IouValue::from_f64(4.0),
                currency: usd.clone(),
                issuer,
            },
        );
        let offer_key = offer.key();
        state.insert_offer(offer);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let deliver_min = Amount::Iou {
            value: IouValue::from_f64(3.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(100);
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            Some(&deliver_min),
            &[],
            TF_PARTIAL_PAYMENT | TF_LIMIT_QUALITY,
        );

        assert!(!result.success);
        assert_eq!(result.ter, "tecPATH_PARTIAL");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000
        );
        assert_eq!(state.get_account(&maker).unwrap().balance, 1_000);
        assert!(state.get_offer(&offer_key).is_some());
        assert!(
            state.get_trustline_for(&dest_id(), &issuer, &usd).is_none(),
            "failed quality-limited partial must not mutate destination funds"
        );
    }

    #[test]
    fn default_book_payment_respects_sendmax() {
        let maker = [0x77; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let mut state = state_with_accounts(0);
        state.insert_account(account(maker, 1_000, 0));
        fund_iou_holder(&mut state, maker, issuer, usd.clone(), 10.0);
        let offer = book_offer(
            maker,
            1,
            Amount::Xrp(100),
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            },
        );
        let key = offer.key();
        state.insert_offer(offer);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(4.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(30);
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &[],
            0,
        );

        assert!(!result.success);
        assert_eq!(result.ter, "tecPATH_PARTIAL");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            100_000_000
        );
        assert!(state.get_offer(&key).is_some());
    }

    #[test]
    fn default_amm_payment_executes_when_clob_book_is_empty() {
        let issuer = issuer_id();
        let usd = usd_currency();
        let pseudo = [0xBB; 20];
        let mut state = state_with_accounts(0);
        state.insert_account(account(genesis_id(), 1_000_000_000, 0));
        insert_amm_pool(
            &mut state,
            pseudo,
            issuer,
            usd.clone(),
            10_000_000_000,
            1_000.0,
        );
        allow_iou_holder(&mut state, dest_id(), issuer, usd.clone(), 20.0);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(200_000_000);
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &[],
            0,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            1_000_000_000 - 101_010_102
        );
        assert_eq!(
            state.get_account(&pseudo).unwrap().balance,
            10_000_000_000 + 101_010_102
        );
        let line = state
            .get_trustline_for(&dest_id(), &issuer, &usd)
            .expect("destination receives AMM-delivered IOU");
        assert_eq!(line.balance_for(&dest_id()), IouValue::from_f64(10.0));
    }

    #[test]
    fn default_domain_payment_does_not_fall_back_to_public_amm() {
        let issuer = issuer_id();
        let usd = usd_currency();
        let pseudo = [0xBD; 20];
        let mut state = state_with_accounts(0);
        state.insert_account(account(genesis_id(), 1_000_000_000, 0));
        insert_amm_pool(
            &mut state,
            pseudo,
            issuer,
            usd.clone(),
            10_000_000_000,
            1_000.0,
        );
        allow_iou_holder(&mut state, dest_id(), issuer, usd.clone(), 20.0);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(200_000_000);
        let result = ripple_calculate_with_domain(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &[],
            0,
            Some([0xDD; 32]),
            0,
        );

        assert!(!result.success);
        assert_eq!(result.ter, "tecPATH_DRY");
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            1_000_000_000
        );
        assert_eq!(state.get_account(&pseudo).unwrap().balance, 10_000_000_000);
        let line = state
            .get_trustline_for(&dest_id(), &issuer, &usd)
            .expect("destination line remains from preclaim setup");
        assert_eq!(line.balance_for(&dest_id()), IouValue::ZERO);
    }

    #[test]
    fn default_payment_prefers_better_amm_over_complete_clob_book() {
        let maker = [0x77; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let pseudo = [0xBC; 20];
        let mut state = state_with_accounts(0);
        state.insert_account(account(genesis_id(), 1_000_000_000, 0));
        state.insert_account(account(maker, 1_000_000_000, 0));
        fund_iou_holder(&mut state, maker, issuer, usd.clone(), 10.0);
        insert_amm_pool(
            &mut state,
            pseudo,
            issuer,
            usd.clone(),
            10_000_000_000,
            1_000.0,
        );
        allow_iou_holder(&mut state, dest_id(), issuer, usd.clone(), 20.0);
        let clob_offer = book_offer(
            maker,
            1,
            Amount::Xrp(150_000_000),
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            },
        );
        let clob_key = clob_offer.key();
        state.insert_offer(clob_offer);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(200_000_000);
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &[],
            0,
        );

        assert!(result.success);
        assert_eq!(result.ter, "tesSUCCESS");
        assert!(
            state.get_offer(&clob_key).is_some(),
            "better AMM route should leave the worse CLOB offer untouched"
        );
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            1_000_000_000 - 101_010_102
        );
        assert_eq!(
            state.get_account(&maker).unwrap().balance,
            1_000_000_000,
            "worse CLOB maker should not receive payment"
        );
    }

    #[test]
    fn default_payment_aggregates_cheaper_clob_partial_with_amm_remainder() {
        let maker = [0x78; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let pseudo = [0xBE; 20];
        let mut state = state_with_accounts(0);
        state.insert_account(account(genesis_id(), 1_000_000_000, 0));
        state.insert_account(account(maker, 1_000_000_000, 0));
        fund_iou_holder(&mut state, maker, issuer, usd.clone(), 6.0);
        allow_iou_holder(&mut state, dest_id(), issuer, usd.clone(), 20.0);
        insert_amm_pool(
            &mut state,
            pseudo,
            issuer,
            usd.clone(),
            10_000_000_000,
            1_000.0,
        );
        let clob_offer = book_offer(
            maker,
            1,
            Amount::Xrp(30_000_000),
            Amount::Iou {
                value: IouValue::from_f64(6.0),
                currency: usd.clone(),
                issuer,
            },
        );
        let clob_key = clob_offer.key();
        state.insert_offer(clob_offer);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(200_000_000);
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &[],
            0,
        );

        assert!(result.success, "unexpected TER: {}", result.ter);
        assert!(
            state.get_offer(&clob_key).is_none(),
            "cheaper CLOB liquidity should be consumed before AMM remainder; sender balance {}",
            state.get_account(&genesis_id()).unwrap().balance
        );
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            1_000_000_000 - 70_160_643
        );
        let line = state
            .get_trustline_for(&dest_id(), &issuer, &usd)
            .expect("destination receives full default delivery");
        assert_eq!(line.balance_for(&dest_id()), IouValue::from_f64(10.0));
    }

    #[test]
    fn default_payment_uses_amm_prefix_until_clob_quality_boundary() {
        let maker = [0x79; 20];
        let issuer = issuer_id();
        let usd = usd_currency();
        let pseudo = [0xBF; 20];
        let mut state = state_with_accounts(0);
        state.insert_account(account(genesis_id(), 1_000_000_000, 0));
        state.insert_account(account(maker, 1_000_000_000, 0));
        fund_iou_holder(&mut state, maker, issuer, usd.clone(), 10.0);
        allow_iou_holder(&mut state, dest_id(), issuer, usd.clone(), 20.0);
        insert_amm_pool(
            &mut state,
            pseudo,
            issuer,
            usd.clone(),
            10_000_000_000,
            1_000.0,
        );
        let clob_offer = book_offer(
            maker,
            1,
            Amount::Xrp(100_500_000),
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            },
        );
        let clob_key = clob_offer.key();
        state.insert_offer(clob_offer);

        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };
        let send_max = Amount::Xrp(120_000_000);
        let result = ripple_calculate(
            &mut state,
            &genesis_id(),
            &dest_id(),
            &deliver,
            Some(&send_max),
            None,
            &[],
            0,
        );

        assert!(result.success, "unexpected TER: {}", result.ter);
        assert!(
            state.get_account(&pseudo).unwrap().balance > 10_000_000_000,
            "AMM should provide the quality-bounded prefix before CLOB remainder"
        );
        assert!(
            state.get_offer(&clob_key).is_some(),
            "CLOB should only provide the remainder after AMM reaches book quality"
        );
        assert!(
            state.get_account(&genesis_id()).unwrap().balance >= 1_000_000_000 - 100_500_001,
            "AMM prefix should not materially worsen the spend at the CLOB quality boundary"
        );
        let line = state
            .get_trustline_for(&dest_id(), &issuer, &usd)
            .expect("destination receives full default delivery");
        assert_eq!(line.balance_for(&dest_id()), IouValue::from_f64(10.0));
    }

    #[test]
    fn run_tx_default_amm_payment_preserves_sender_xrp_debit() {
        let issuer = issuer_id();
        let usd = usd_currency();
        let pseudo = [0xBB; 20];
        let mut state = state_with_accounts(0);
        state.insert_account(account(genesis_id(), 1_000_000_000, 0));
        insert_amm_pool(
            &mut state,
            pseudo,
            issuer,
            usd.clone(),
            10_000_000_000,
            1_000.0,
        );
        allow_iou_holder(&mut state, dest_id(), issuer, usd.clone(), 20.0);

        let kp = genesis_kp();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd,
                issuer,
            })
            .send_max(Amount::Xrp(200_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();
        let tx = parse_blob(&signed.blob).unwrap();

        let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert!(result.applied);
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            1_000_000_000 - 12 - 101_010_102
        );
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
            None,
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
