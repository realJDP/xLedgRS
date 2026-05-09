//! Shared transaction flow skeleton.
//!
//! This module is intentionally dormant for now. It gives Payment,
//! OfferCreate, BookStep, and AMM liquidity a common rippled-shaped seam before
//! any behavior is moved onto it.

#![allow(dead_code, unused_imports)]

mod amm_step;
mod amount;
mod book;
mod book_offer_ops;
mod book_step;
mod direct_step;
mod offer_math;
mod path;
mod quality;
mod sandbox;
mod step;
mod strand;
mod xrp_endpoint_step;

pub(crate) use amm_step::AmmStep;
pub(crate) use amount::{AmountKind, FlowAmount, Rounding};
pub(crate) use book::FlowBook;
pub(crate) use book_offer_ops::{
    delete_offer_from_dirs, offer_fully_consumed_by_output, offer_has_zero_amount,
    quote_offer_create_crossing_fill, quote_offer_for_desired_output, quote_offer_for_input_limit,
    rewrite_partial_offer_after_output_fill, OfferFillQuote,
};
pub(crate) use book_step::{
    apply_book_fill_plan, apply_book_partial_fill_plan, plan_book_exact_in_all_qualities_for_taker,
    plan_book_exact_out, plan_book_exact_out_all_qualities,
    plan_book_exact_out_all_qualities_for_taker, plan_book_exact_out_all_qualities_with_recipient,
    plan_book_exact_out_with_recipient, plan_book_partial_in_all_qualities, read_book_tip,
    BookFill, BookFillPlan, BookReadResult, BookStep, BookStepCandidate, OfferReadStatus,
    RIPPLE_MAX_OFFERS_CONSIDERED,
};
pub(crate) use direct_step::DirectStep;
pub(crate) use offer_math::{
    amount_to_iou_value, ceil_in_strict_via_quality, ceil_out_strict_via_quality, compare_amounts,
    compare_iou_values, iou_value_to_amount, normalize_u128, quality_rate_from_book_dir,
    quality_rate_from_u64, zero_amount_like,
};
pub(crate) use path::{
    build_payment_strands, build_payment_strands_with_domain, validate_payment_paths, FlowStepSpec,
    FlowStrandSpec,
};
pub(crate) use quality::{FlowQuality, QualityFunction};
pub(crate) use sandbox::{FlowSandbox, FlowSandboxCommit};
pub(crate) use step::{FlowStep, StepBook, StepResult};
pub(crate) use strand::{flow_exact_out, flow_with_input, Strand, StrandFlowResult};
pub(crate) use xrp_endpoint_step::XrpEndpointStep;
