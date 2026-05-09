use super::{
    compare_amounts, compare_iou_values, delete_offer_from_dirs, offer_fully_consumed_by_output,
    quote_offer_for_desired_output, quote_offer_for_input_limit, FlowAmount, FlowBook, FlowQuality,
    FlowSandbox, FlowStep, QualityFunction, StepBook, StepResult,
};
use crate::ledger::tx::amm_step::{self, AmmPool, AmmQuote};
use crate::ledger::tx::asset_flow::{
    account_transfer_rate, apply_amount_delta, issuer_transfer_rate_gross_amount,
    issuer_transfer_rate_net_amount, spendable_xrp_balance, transfer_rate_gross_debit_amount,
    transfer_rate_net_deliverable_amount, AssetDelta,
};
use crate::ledger::tx::mptoken;
use crate::ledger::{AccountRoot, BookKey, Key, LedgerState, Offer, RippleState};
use crate::transaction::amount::{Amount, Currency, IouValue, Issue};

pub(crate) const RIPPLE_MAX_OFFERS_CONSIDERED: u32 = 1500;

/// Read-only classification for a CLOB offer candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OfferReadStatus {
    Usable,
    Expired,
    ZeroAmount,
    Unfunded,
    TinyReducedQuality,
    Unauthorized,
    DomainInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BookStepCandidate {
    pub(crate) key: Key,
    pub(crate) status: OfferReadStatus,
    pub(crate) taker_pays: Amount,
    pub(crate) taker_gets: Amount,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BookReadResult {
    pub(crate) candidates: Vec<BookStepCandidate>,
    pub(crate) removable: Vec<Key>,
    pub(crate) offers_used: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BookFill {
    pub(crate) key: Key,
    pub(crate) offer_input: Amount,
    pub(crate) input: Amount,
    pub(crate) output: Amount,
    pub(crate) owner_output_debit: Amount,
    pub(crate) fully_consumed: bool,
    pub(crate) amm: Option<AmmFill>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AmmFill {
    pub(crate) pool: AmmPool,
    pub(crate) quote: AmmQuote,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BookFillPlan {
    pub(crate) fills: Vec<BookFill>,
    pub(crate) removals: Vec<Key>,
    pub(crate) input: Option<FlowAmount>,
    pub(crate) output: Option<FlowAmount>,
    pub(crate) offers_used: u32,
    pub(crate) complete: bool,
}

/// FlowStep-backed CLOB liquidity.
///
/// This keeps the existing read/plan/apply split but exposes it through the
/// same reverse/forward seam as DirectStep. The caller supplies the taker and
/// output recipient because those accounts are transaction-context, not book
/// identity.
#[allow(dead_code)]
pub(crate) struct BookStep {
    book: FlowBook,
    taker: [u8; 20],
    output_recipient: [u8; 20],
    close_time: u64,
    max_offers: u32,
    all_qualities: bool,
    amm_multi_path: bool,
    amm_iteration: u16,
    amm_initial_pool: Option<crate::ledger::tx::amm_step::AmmPool>,
    offer_crossing: bool,
    cached_in: Option<FlowAmount>,
    cached_out: Option<FlowAmount>,
    inactive: bool,
}

#[allow(dead_code)]
impl BookStep {
    pub(crate) fn new(book: FlowBook, taker: [u8; 20], output_recipient: [u8; 20]) -> Self {
        Self {
            book,
            taker,
            output_recipient,
            close_time: 0,
            max_offers: RIPPLE_MAX_OFFERS_CONSIDERED,
            all_qualities: false,
            amm_multi_path: false,
            amm_iteration: 0,
            amm_initial_pool: None,
            offer_crossing: false,
            cached_in: None,
            cached_out: None,
            inactive: false,
        }
    }

    pub(crate) fn with_close_time(mut self, close_time: u64) -> Self {
        self.close_time = close_time;
        self
    }

    pub(crate) fn with_max_offers(mut self, max_offers: u32) -> Self {
        self.max_offers = max_offers;
        self
    }

    pub(crate) fn with_all_qualities(mut self, all_qualities: bool) -> Self {
        self.all_qualities = all_qualities;
        self
    }

    pub(crate) fn with_amm_context(mut self, multi_path: bool, iteration: u16) -> Self {
        self.amm_multi_path = multi_path;
        self.amm_iteration = iteration;
        self
    }

    pub(crate) fn with_amm_initial_pool(
        mut self,
        initial_pool: Option<crate::ledger::tx::amm_step::AmmPool>,
    ) -> Self {
        self.amm_initial_pool = initial_pool;
        self
    }

    pub(crate) fn with_offer_crossing(mut self, offer_crossing: bool) -> Self {
        self.offer_crossing = offer_crossing;
        self
    }

    fn plan(&self, state: &LedgerState, requested_out: &FlowAmount) -> BookFillPlan {
        plan_book_exact_out_internal(
            state,
            &self.book,
            requested_out,
            self.close_time,
            self.max_offers,
            !self.all_qualities,
            Some(self.output_recipient),
            Some(self.taker),
            self.amm_multi_path,
            self.amm_iteration,
            self.amm_initial_pool.as_ref(),
            self.offer_crossing,
        )
    }

    fn plan_input(&self, state: &LedgerState, offered_in: &FlowAmount) -> BookFillPlan {
        plan_book_exact_in_internal(
            state,
            &self.book,
            offered_in,
            self.close_time,
            self.max_offers,
            !self.all_qualities,
            self.output_recipient,
            Some(self.taker),
            self.amm_multi_path,
            self.amm_iteration,
            self.amm_initial_pool.as_ref(),
            self.offer_crossing,
        )
    }
}

impl FlowStep for BookStep {
    fn rev(
        &mut self,
        state: &mut LedgerState,
        requested_out: &FlowAmount,
    ) -> Result<StepResult, &'static str> {
        check_book_step_ready(state, &self.book)?;
        let plan = self.plan(state, requested_out);
        if !plan.complete {
            self.inactive = book_step_plan_inactive(&plan, self.max_offers);
            return Err("tecPATH_DRY");
        }

        let Some(input) = plan.input.clone() else {
            self.inactive = book_step_plan_inactive(&plan, self.max_offers);
            return Err("tecPATH_DRY");
        };
        let Some(output) = plan.output.clone() else {
            self.inactive = book_step_plan_inactive(&plan, self.max_offers);
            return Err("tecPATH_DRY");
        };
        let result = StepResult::new(input, output);
        self.cached_in = Some(result.input.clone());
        self.cached_out = Some(result.output.clone());
        self.inactive = plan.offers_used >= self.max_offers;
        Ok(result)
    }

    fn fwd(
        &mut self,
        state: &mut LedgerState,
        offered_in: &FlowAmount,
    ) -> Result<StepResult, &'static str> {
        check_book_step_ready(state, &self.book)?;
        let plan = self.plan_input(state, offered_in);
        if !plan.complete {
            if self.all_qualities && !plan.fills.is_empty() {
                let result =
                    apply_book_partial_fill_plan(state, &plan, self.taker, self.output_recipient)?;
                self.cached_in = Some(result.input.clone());
                self.cached_out = Some(result.output.clone());
                self.inactive = book_step_plan_inactive(&plan, self.max_offers);
                return Ok(result);
            } else {
                self.inactive = book_step_plan_inactive(&plan, self.max_offers);
                return Err("tecPATH_DRY");
            }
        }

        let result = apply_book_fill_plan(state, &plan, self.taker, self.output_recipient)?;
        self.cached_in = Some(result.input.clone());
        self.cached_out = Some(result.output.clone());
        self.inactive = plan.offers_used >= self.max_offers;
        Ok(result)
    }

    fn valid_fwd(
        &mut self,
        state: &mut LedgerState,
        offered_in: &FlowAmount,
    ) -> Result<StepResult, &'static str> {
        let Some(cached_out) = self.cached_out.clone() else {
            return self.fwd(state, offered_in);
        };
        check_book_step_ready(state, &self.book)?;
        let plan = self.plan(state, &cached_out);
        if !plan.complete {
            self.inactive = book_step_plan_inactive(&plan, self.max_offers);
            return Err("tecPATH_DRY");
        }
        let Some(input) = plan.input.as_ref() else {
            self.inactive = book_step_plan_inactive(&plan, self.max_offers);
            return Err("tecPATH_DRY");
        };
        if compare_amounts(input.as_amount(), offered_in.as_amount()) == std::cmp::Ordering::Greater
        {
            self.inactive = true;
            return Err("tecPATH_DRY");
        }
        let result = apply_book_fill_plan(state, &plan, self.taker, self.output_recipient)?;
        self.cached_in = Some(result.input.clone());
        self.cached_out = Some(result.output.clone());
        self.inactive = plan.offers_used >= self.max_offers;
        Ok(result)
    }

    fn cached_in(&self) -> Option<&FlowAmount> {
        self.cached_in.as_ref()
    }

    fn cached_out(&self) -> Option<&FlowAmount> {
        self.cached_out.as_ref()
    }

    fn inactive(&self) -> bool {
        self.inactive
    }

    fn book(&self) -> Option<StepBook> {
        Some(StepBook {
            book: self.book.clone(),
        })
    }

    fn quality_upper_bound(&self, state: &LedgerState) -> Option<FlowQuality> {
        self.quality_function(state).map(|qf| qf.quality())
    }

    fn quality_function(&self, state: &LedgerState) -> Option<QualityFunction> {
        let clob_quality = first_usable_book_quality(
            state,
            &self.book,
            self.close_time,
            self.output_recipient,
            Some(self.taker),
            self.offer_crossing,
        );
        let amm_quality = if self.book.domain_id.is_none() {
            let pool = amm_step::load_amm_pool_for_account(
                state,
                &self.book.in_issue,
                &self.book.out_issue,
                &self.taker,
                self.close_time,
            )
            .or_else(|| amm_step::load_amm_pool(state, &self.book.in_issue, &self.book.out_issue));
            pool.and_then(|pool| {
                super::amm_step::quality_function_from_pool(&pool).and_then(|quality| {
                    book_step_quality_adjustment(
                        state,
                        &self.book,
                        Some(self.taker),
                        self.output_recipient,
                    )
                    .and_then(|factor| quality.scaled_by(factor))
                })
            })
        } else {
            None
        };

        match (clob_quality, amm_quality) {
            (Some(clob), Some(amm)) => {
                if amm.quality().not_worse_than(clob) {
                    Some(amm)
                } else {
                    Some(QualityFunction::constant(clob))
                }
            }
            (Some(clob), None) => Some(QualityFunction::constant(clob)),
            (None, Some(amm)) => Some(amm),
            (None, None) => None,
        }
    }
}

fn book_step_plan_inactive(plan: &BookFillPlan, max_offers: u32) -> bool {
    plan.offers_used >= max_offers || (!plan.complete && plan.fills.is_empty())
}

fn check_book_step_ready(state: &LedgerState, book: &FlowBook) -> Result<(), &'static str> {
    if book.in_issue == book.out_issue {
        return Err("temBAD_PATH");
    }
    if !issuer_exists_for_issue(state, &book.in_issue)
        || !issuer_exists_for_issue(state, &book.out_issue)
    {
        return Err("tecNO_ISSUER");
    }
    Ok(())
}

fn issuer_exists_for_issue(state: &LedgerState, issue: &Issue) -> bool {
    match issue {
        Issue::Xrp => true,
        Issue::Iou { issuer, .. } => load_account_readonly(state, issuer).is_some(),
        Issue::Mpt(_) => false,
    }
}

/// Inspect a CLOB book in stored quality order without consuming liquidity.
pub(crate) fn read_book_tip(
    state: &LedgerState,
    book: &FlowBook,
    close_time: u64,
    max_offers: u32,
) -> BookReadResult {
    let Some(book_key) = flow_book_to_book_key(book) else {
        return BookReadResult::default();
    };
    let Some(order_book) = state.get_book(&book_key) else {
        return BookReadResult::default();
    };

    let mut result = BookReadResult::default();
    for key in order_book.iter_by_quality() {
        if result.offers_used >= max_offers {
            break;
        }
        result.offers_used += 1;

        let Some(offer) = state.get_offer(key) else {
            result.removable.push(*key);
            continue;
        };

        let status = classify_offer(state, book, offer, close_time);
        if offer_status_removable(status) {
            result.removable.push(*key);
        }
        result.candidates.push(BookStepCandidate {
            key: *key,
            status,
            taker_pays: offer.taker_pays.clone(),
            taker_gets: offer.taker_gets.clone(),
        });

        if status == OfferReadStatus::Usable {
            break;
        }
    }

    result
}

/// Build a reverse exact-output quote against one book without mutating state.
///
/// This intentionally starts as a planner only. The apply phase will consume the
/// plan through `FlowSandbox` after this quote path is covered.
pub(crate) fn plan_book_exact_out(
    state: &LedgerState,
    book: &FlowBook,
    requested_out: &FlowAmount,
    close_time: u64,
    max_offers: u32,
) -> BookFillPlan {
    plan_book_exact_out_internal(
        state,
        book,
        requested_out,
        close_time,
        max_offers,
        true,
        None,
        None,
        false,
        0,
        None,
        false,
    )
}

/// Build a reverse exact-output quote that may walk through worse quality
/// directories after the current book tip is exhausted.
///
/// rippled's strand loop consumes the best quality, re-evaluates the strand,
/// then continues when more output is still needed. This planner keeps the
/// existing one-shot shape but does not stop at the first quality boundary, so
/// default book payments do not falsely fail when they require multiple book
/// directories.
pub(crate) fn plan_book_exact_out_all_qualities(
    state: &LedgerState,
    book: &FlowBook,
    requested_out: &FlowAmount,
    close_time: u64,
    max_offers: u32,
) -> BookFillPlan {
    plan_book_exact_out_internal(
        state,
        book,
        requested_out,
        close_time,
        max_offers,
        false,
        None,
        None,
        false,
        0,
        None,
        false,
    )
}

pub(crate) fn plan_book_exact_out_with_recipient(
    state: &LedgerState,
    book: &FlowBook,
    requested_out: &FlowAmount,
    close_time: u64,
    max_offers: u32,
    output_recipient: [u8; 20],
) -> BookFillPlan {
    plan_book_exact_out_internal(
        state,
        book,
        requested_out,
        close_time,
        max_offers,
        true,
        Some(output_recipient),
        None,
        false,
        0,
        None,
        false,
    )
}

pub(crate) fn plan_book_exact_out_all_qualities_with_recipient(
    state: &LedgerState,
    book: &FlowBook,
    requested_out: &FlowAmount,
    close_time: u64,
    max_offers: u32,
    output_recipient: [u8; 20],
) -> BookFillPlan {
    plan_book_exact_out_internal(
        state,
        book,
        requested_out,
        close_time,
        max_offers,
        false,
        Some(output_recipient),
        None,
        false,
        0,
        None,
        false,
    )
}

pub(crate) fn plan_book_exact_out_all_qualities_for_taker(
    state: &LedgerState,
    book: &FlowBook,
    requested_out: &FlowAmount,
    close_time: u64,
    max_offers: u32,
    taker: [u8; 20],
    output_recipient: [u8; 20],
) -> BookFillPlan {
    plan_book_exact_out_internal(
        state,
        book,
        requested_out,
        close_time,
        max_offers,
        false,
        Some(output_recipient),
        Some(taker),
        false,
        0,
        None,
        true,
    )
}

/// Build a forward exact-input quote against one book without mutating state.
///
/// Forward execution is used by the strand replay half of Flow.  The planner is
/// intentionally exact-input: if the book cannot consume the offered input at
/// the currently allowed quality range, the caller gets `tecPATH_DRY` rather
/// than a partial mutation.
pub(crate) fn plan_book_exact_in(
    state: &LedgerState,
    book: &FlowBook,
    offered_in: &FlowAmount,
    close_time: u64,
    max_offers: u32,
    stop_at_quality_boundary: bool,
) -> BookFillPlan {
    plan_book_exact_in_internal(
        state,
        book,
        offered_in,
        close_time,
        max_offers,
        stop_at_quality_boundary,
        [0u8; 20],
        None,
        false,
        0,
        None,
        false,
    )
}

pub(crate) fn plan_book_exact_in_with_recipient(
    state: &LedgerState,
    book: &FlowBook,
    offered_in: &FlowAmount,
    close_time: u64,
    max_offers: u32,
    stop_at_quality_boundary: bool,
    output_recipient: [u8; 20],
) -> BookFillPlan {
    plan_book_exact_in_internal(
        state,
        book,
        offered_in,
        close_time,
        max_offers,
        stop_at_quality_boundary,
        output_recipient,
        None,
        false,
        0,
        None,
        false,
    )
}

pub(crate) fn plan_book_exact_in_all_qualities_for_taker(
    state: &LedgerState,
    book: &FlowBook,
    offered_in: &FlowAmount,
    close_time: u64,
    max_offers: u32,
    taker: [u8; 20],
    output_recipient: [u8; 20],
) -> BookFillPlan {
    plan_book_exact_in_internal(
        state,
        book,
        offered_in,
        close_time,
        max_offers,
        false,
        output_recipient,
        Some(taker),
        false,
        0,
        None,
        true,
    )
}

fn plan_book_exact_in_internal(
    state: &LedgerState,
    book: &FlowBook,
    offered_in: &FlowAmount,
    close_time: u64,
    max_offers: u32,
    stop_at_quality_boundary: bool,
    output_recipient: [u8; 20],
    taker: Option<[u8; 20]>,
    amm_multi_path: bool,
    amm_iteration: u16,
    amm_initial_pool: Option<&crate::ledger::tx::amm_step::AmmPool>,
    offer_crossing: bool,
) -> BookFillPlan {
    if offered_in.issue() != Some(book.in_issue.clone()) {
        return BookFillPlan::default();
    }
    let Some(book_key) = flow_book_to_book_key(book) else {
        return BookFillPlan::default();
    };
    let order_book = state.get_book(&book_key);

    let mut plan = BookFillPlan::default();
    let mut remaining_in = offered_in.as_amount().clone();
    let mut total_in: Option<Amount> = None;
    let mut total_out: Option<Amount> = None;
    let mut active_quality = None::<[u8; 32]>;
    let mut planned_owner_debits = Vec::<OwnerFundDebit>::new();

    if let Some(amm_fill) = plan_amm_exact_in_fill(
        state,
        book,
        &remaining_in,
        close_time,
        output_recipient,
        first_usable_clob_quote_exact_in(
            state,
            book,
            order_book,
            &remaining_in,
            close_time,
            output_recipient,
        )
        .as_ref(),
        taker,
        amm_multi_path,
        amm_iteration,
        amm_initial_pool,
    ) {
        total_in = Some(add_amount(total_in.as_ref(), &amm_fill.input));
        total_out = Some(add_amount(total_out.as_ref(), &amm_fill.output));
        remaining_in = crate::ledger::offer::subtract_amount(&remaining_in, &amm_fill.input);
        plan.fills.push(amm_fill);
    }

    let Some(order_book) = order_book else {
        plan.complete = crate::ledger::offer::amount_is_zero(&remaining_in);
        plan.input = total_in.map(FlowAmount::new);
        plan.output = total_out.map(FlowAmount::new);
        return plan;
    };

    for key in order_book.iter_by_quality() {
        if plan.offers_used >= max_offers || crate::ledger::offer::amount_is_zero(&remaining_in) {
            break;
        }
        plan.offers_used += 1;

        let Some(offer) = state.get_offer(key) else {
            plan.removals.push(*key);
            continue;
        };

        if let Some(quality) = active_quality {
            if stop_at_quality_boundary && offer.book_directory != quality {
                break;
            }
        }

        let status = classify_offer(state, book, offer, close_time);
        if status != OfferReadStatus::Usable {
            if offer_status_removable(status) {
                plan.removals.push(*key);
            }
            continue;
        }

        let raw_funded_output =
            funded_offer_output_after_planned_debits(state, offer, &planned_owner_debits);
        let funded_output = if output_recipient == [0u8; 20] {
            raw_funded_output
        } else {
            funded_offer_output_for_recipient_amount(
                state,
                offer,
                &output_recipient,
                &raw_funded_output,
                offer_crossing,
            )
        };
        if crate::ledger::offer::amount_is_zero(&funded_output) {
            plan.removals.push(*key);
            continue;
        }

        let effective_remaining_in =
            book_step_net_offer_input_budget(state, book, taker, output_recipient, &remaining_in);
        let input_limit = min_amount(&effective_remaining_in, &offer.taker_pays);
        let Some(mut quote) = quote_offer_for_input_limit(offer, &input_limit, false) else {
            continue;
        };
        if compare_amounts(&quote.output, &funded_output) == std::cmp::Ordering::Greater {
            let Some(capped) = quote_offer_for_desired_output(offer, &funded_output, true) else {
                continue;
            };
            quote = capped;
        }
        if crate::ledger::offer::amount_is_zero(&quote.input)
            || crate::ledger::offer::amount_is_zero(&quote.output)
        {
            continue;
        }

        if active_quality.is_none() {
            active_quality = Some(offer.book_directory);
        }

        let step_input =
            book_step_gross_step_input(state, book, taker, Some(output_recipient), &quote.input);
        let owner_output_debit = planned_owner_debit(
            state,
            offer,
            &quote.output,
            Some(output_recipient),
            offer_crossing,
        );
        let fully_consumed = offer_fully_consumed_by_output(offer, &quote.output, &funded_output);
        total_in = Some(add_amount(total_in.as_ref(), &step_input));
        total_out = Some(add_amount(total_out.as_ref(), &quote.output));
        remaining_in = crate::ledger::offer::subtract_amount(&remaining_in, &step_input);
        planned_owner_debits.push(OwnerFundDebit {
            account: offer.account,
            amount: owner_output_debit.clone(),
        });
        plan.fills.push(BookFill {
            key: *key,
            offer_input: quote.input,
            input: step_input,
            output: quote.output,
            owner_output_debit,
            fully_consumed,
            amm: None,
        });
    }

    plan.complete = crate::ledger::offer::amount_is_zero(&remaining_in);
    plan.input = total_in.map(FlowAmount::new);
    plan.output = total_out.map(FlowAmount::new);
    plan
}

/// Build a forward input quote that may stop after consuming all available
/// liquidity before exhausting the caller's input budget.
pub(crate) fn plan_book_partial_in_all_qualities(
    state: &LedgerState,
    book: &FlowBook,
    offered_in: &FlowAmount,
    close_time: u64,
    max_offers: u32,
) -> BookFillPlan {
    plan_book_exact_in(state, book, offered_in, close_time, max_offers, false)
}

fn plan_book_exact_out_internal(
    state: &LedgerState,
    book: &FlowBook,
    requested_out: &FlowAmount,
    close_time: u64,
    max_offers: u32,
    stop_at_quality_boundary: bool,
    output_recipient: Option<[u8; 20]>,
    taker: Option<[u8; 20]>,
    amm_multi_path: bool,
    amm_iteration: u16,
    amm_initial_pool: Option<&crate::ledger::tx::amm_step::AmmPool>,
    offer_crossing: bool,
) -> BookFillPlan {
    if requested_out.issue() != Some(book.out_issue.clone()) {
        return BookFillPlan::default();
    }
    let Some(book_key) = flow_book_to_book_key(book) else {
        return BookFillPlan::default();
    };
    let order_book = state.get_book(&book_key);

    let mut plan = BookFillPlan::default();
    let mut remaining_out = requested_out.as_amount().clone();
    let mut total_in: Option<Amount> = None;
    let mut total_out: Option<Amount> = None;
    let mut active_quality = None::<[u8; 32]>;
    let mut planned_owner_debits = Vec::<OwnerFundDebit>::new();

    if let Some(amm_fill) = plan_amm_exact_out_fill(
        state,
        book,
        &remaining_out,
        close_time,
        output_recipient,
        first_usable_clob_quote_exact_out(
            state,
            book,
            order_book,
            &remaining_out,
            close_time,
            output_recipient,
        )
        .as_ref(),
        taker,
        amm_multi_path,
        amm_iteration,
        amm_initial_pool,
    ) {
        total_in = Some(add_amount(total_in.as_ref(), &amm_fill.input));
        total_out = Some(add_amount(total_out.as_ref(), &amm_fill.output));
        remaining_out = crate::ledger::offer::subtract_amount(&remaining_out, &amm_fill.output);
        plan.fills.push(amm_fill);
    }

    let Some(order_book) = order_book else {
        plan.complete = crate::ledger::offer::amount_is_zero(&remaining_out);
        plan.input = total_in.map(FlowAmount::new);
        plan.output = total_out.map(FlowAmount::new);
        return plan;
    };

    for key in order_book.iter_by_quality() {
        if plan.offers_used >= max_offers || crate::ledger::offer::amount_is_zero(&remaining_out) {
            break;
        }
        plan.offers_used += 1;

        let Some(offer) = state.get_offer(key) else {
            plan.removals.push(*key);
            continue;
        };

        if let Some(quality) = active_quality {
            if stop_at_quality_boundary && offer.book_directory != quality {
                break;
            }
        }

        let status = classify_offer(state, book, offer, close_time);
        if status != OfferReadStatus::Usable {
            if offer_status_removable(status) {
                plan.removals.push(*key);
            }
            continue;
        }

        let raw_funded_output =
            funded_offer_output_after_planned_debits(state, offer, &planned_owner_debits);
        let funded_output = match output_recipient {
            Some(recipient) => funded_offer_output_for_recipient_amount(
                state,
                offer,
                &recipient,
                &raw_funded_output,
                offer_crossing,
            ),
            None => raw_funded_output,
        };
        if crate::ledger::offer::amount_is_zero(&funded_output) {
            plan.removals.push(*key);
            continue;
        }
        let available_output = min_amount(&offer.taker_gets, &funded_output);
        let desired_output = min_amount(&remaining_out, &available_output);
        let Some(quote) = quote_offer_for_desired_output(offer, &desired_output, true) else {
            continue;
        };

        if crate::ledger::offer::amount_is_zero(&quote.input)
            || crate::ledger::offer::amount_is_zero(&quote.output)
        {
            continue;
        }

        if active_quality.is_none() {
            active_quality = Some(offer.book_directory);
        }

        let step_input =
            book_step_gross_step_input(state, book, taker, output_recipient, &quote.input);
        let owner_output_debit = planned_owner_debit(
            state,
            offer,
            &quote.output,
            output_recipient,
            offer_crossing,
        );
        let fully_consumed = offer_fully_consumed_by_output(offer, &quote.output, &funded_output);
        total_in = Some(add_amount(total_in.as_ref(), &step_input));
        total_out = Some(add_amount(total_out.as_ref(), &quote.output));
        remaining_out = crate::ledger::offer::subtract_amount(&remaining_out, &quote.output);
        planned_owner_debits.push(OwnerFundDebit {
            account: offer.account,
            amount: owner_output_debit.clone(),
        });
        plan.fills.push(BookFill {
            key: *key,
            offer_input: quote.input,
            input: step_input,
            output: quote.output,
            owner_output_debit,
            fully_consumed,
            amm: None,
        });
    }

    plan.complete = crate::ledger::offer::amount_is_zero(&remaining_out);
    plan.input = total_in.map(FlowAmount::new);
    plan.output = total_out.map(FlowAmount::new);
    plan
}

#[derive(Debug, Clone)]
struct ClobQualityQuote {
    input: Amount,
    output: Amount,
}

fn first_usable_clob_quote_exact_out(
    state: &LedgerState,
    book: &FlowBook,
    order_book: Option<&crate::ledger::offer::OrderBook>,
    remaining_out: &Amount,
    close_time: u64,
    output_recipient: Option<[u8; 20]>,
) -> Option<ClobQualityQuote> {
    let order_book = order_book?;
    for key in order_book.iter_by_quality() {
        let offer = state.get_offer(key)?;
        if classify_offer(state, book, offer, close_time) != OfferReadStatus::Usable {
            continue;
        }
        let raw_funded_output = funded_offer_output(state, offer);
        let funded_output = match output_recipient {
            Some(recipient) => funded_offer_output_for_recipient_amount(
                state,
                offer,
                &recipient,
                &raw_funded_output,
                false,
            ),
            None => raw_funded_output,
        };
        if crate::ledger::offer::amount_is_zero(&funded_output) {
            continue;
        }
        let available_output = min_amount(&offer.taker_gets, &funded_output);
        let desired_output = min_amount(remaining_out, &available_output);
        let quote = quote_offer_for_desired_output(offer, &desired_output, true)?;
        if !crate::ledger::offer::amount_is_zero(&quote.input)
            && !crate::ledger::offer::amount_is_zero(&quote.output)
        {
            return Some(ClobQualityQuote {
                input: quote.input,
                output: quote.output,
            });
        }
    }
    None
}

fn first_usable_clob_quote_exact_in(
    state: &LedgerState,
    book: &FlowBook,
    order_book: Option<&crate::ledger::offer::OrderBook>,
    remaining_in: &Amount,
    close_time: u64,
    output_recipient: [u8; 20],
) -> Option<ClobQualityQuote> {
    let order_book = order_book?;
    for key in order_book.iter_by_quality() {
        let offer = state.get_offer(key)?;
        if classify_offer(state, book, offer, close_time) != OfferReadStatus::Usable {
            continue;
        }
        let raw_funded_output = funded_offer_output(state, offer);
        let funded_output = if output_recipient == [0u8; 20] {
            raw_funded_output
        } else {
            funded_offer_output_for_recipient_amount(
                state,
                offer,
                &output_recipient,
                &raw_funded_output,
                false,
            )
        };
        if crate::ledger::offer::amount_is_zero(&funded_output) {
            continue;
        }
        let input_limit = min_amount(remaining_in, &offer.taker_pays);
        let mut quote = quote_offer_for_input_limit(offer, &input_limit, false)?;
        if compare_amounts(&quote.output, &funded_output) == std::cmp::Ordering::Greater {
            quote = quote_offer_for_desired_output(offer, &funded_output, true)?;
        }
        if !crate::ledger::offer::amount_is_zero(&quote.input)
            && !crate::ledger::offer::amount_is_zero(&quote.output)
        {
            return Some(ClobQualityQuote {
                input: quote.input,
                output: quote.output,
            });
        }
    }
    None
}

fn first_usable_book_quality(
    state: &LedgerState,
    book: &FlowBook,
    close_time: u64,
    output_recipient: [u8; 20],
    taker: Option<[u8; 20]>,
    offer_crossing: bool,
) -> Option<FlowQuality> {
    let book_key = flow_book_to_book_key(book)?;
    let order_book = state.get_book(&book_key)?;
    for key in order_book.iter_by_quality() {
        let offer = state.get_offer(key)?;
        if classify_offer(state, book, offer, close_time) != OfferReadStatus::Usable {
            continue;
        }
        let raw_funded_output = funded_offer_output(state, offer);
        let funded_output = if output_recipient == [0u8; 20] {
            raw_funded_output
        } else {
            funded_offer_output_for_recipient_amount(
                state,
                offer,
                &output_recipient,
                &raw_funded_output,
                offer_crossing,
            )
        };
        if crate::ledger::offer::amount_is_zero(&funded_output) {
            continue;
        }
        let desired_output = min_amount(&offer.taker_gets, &funded_output);
        let quote = quote_offer_for_desired_output(offer, &desired_output, true)?;
        if crate::ledger::offer::amount_is_zero(&quote.input)
            || crate::ledger::offer::amount_is_zero(&quote.output)
        {
            continue;
        }
        let step_input =
            book_step_gross_step_input(state, book, taker, Some(output_recipient), &quote.input);
        return FlowQuality::from_amounts(&step_input, &quote.output, true);
    }
    None
}

fn book_step_quality_adjustment(
    state: &LedgerState,
    book: &FlowBook,
    taker: Option<[u8; 20]>,
    output_recipient: [u8; 20],
) -> Option<FlowQuality> {
    let probe = amount_probe_for_issue(&book.in_issue)?;
    let gross = book_step_gross_step_input(state, book, taker, Some(output_recipient), &probe);
    FlowQuality::from_amounts(&gross, &probe, true)
}

fn amount_probe_for_issue(issue: &Issue) -> Option<Amount> {
    match issue {
        Issue::Xrp => Some(Amount::Xrp(1_000_000)),
        Issue::Iou { currency, issuer } => Some(Amount::Iou {
            value: IouValue {
                mantissa: 1_000_000_000_000_000,
                exponent: -15,
            },
            currency: currency.clone(),
            issuer: *issuer,
        }),
        Issue::Mpt(_) => None,
    }
}

fn plan_amm_exact_out_fill(
    state: &LedgerState,
    book: &FlowBook,
    remaining_out: &Amount,
    close_time: u64,
    _output_recipient: Option<[u8; 20]>,
    clob_quote: Option<&ClobQualityQuote>,
    taker: Option<[u8; 20]>,
    amm_multi_path: bool,
    amm_iteration: u16,
    amm_initial_pool: Option<&crate::ledger::tx::amm_step::AmmPool>,
) -> Option<BookFill> {
    if book.domain_id.is_some() || crate::ledger::offer::amount_is_zero(remaining_out) {
        return None;
    }
    let pool = taker
        .and_then(|account| {
            amm_step::load_amm_pool_for_account(
                state,
                &book.in_issue,
                &book.out_issue,
                &account,
                close_time,
            )
        })
        .or_else(|| amm_step::load_amm_pool(state, &book.in_issue, &book.out_issue))?;
    let max_out = amm_step::max_swap_output(&pool)?;
    let target_out = min_amount(remaining_out, &max_out);
    if crate::ledger::offer::amount_is_zero(&target_out) {
        return None;
    }

    let quote = if amm_multi_path {
        let initial_pool = amm_initial_pool.unwrap_or(&pool);
        let fib = amm_step::quote_fibonacci_offer_with_initial(&pool, initial_pool, amm_iteration)?;
        let quote = limit_amm_offer_by_output(fib, &target_out)?;
        if let Some(reference) = clob_quote {
            if !quality_not_worse_than(
                &quote.spent_in,
                &quote.delivered_out,
                &reference.input,
                &reference.output,
            ) {
                return None;
            }
        }
        quote
    } else if let Some(reference) = clob_quote {
        let reference_quality = reference_flow_quality(reference)?;
        if amm_step::spot_quality_close_or_worse_than(&pool, reference_quality.rate())? {
            return None;
        }
        let full = amm_step::quote_exact_out(&pool, &target_out)?;
        if quality_not_worse_than(
            &full.spent_in,
            &full.delivered_out,
            &reference.input,
            &reference.output,
        ) {
            full
        } else {
            let boundary = amm_step::quote_to_clob_quality(&pool, reference_quality.rate())?;
            if compare_amounts(&boundary.delivered_out, &target_out) == std::cmp::Ordering::Greater
            {
                amm_step::quote_exact_out(&pool, &target_out)?
            } else {
                boundary
            }
        }
    } else {
        amm_step::quote_exact_out(&pool, &target_out)?
    };
    if let Some(reference) = clob_quote {
        if compare_amounts(&quote.delivered_out, &target_out) == std::cmp::Ordering::Greater
            || !quality_not_worse_than(
                &quote.spent_in,
                &quote.delivered_out,
                &reference.input,
                &reference.output,
            )
        {
            return None;
        }
    }
    amm_fill_from_quote(pool, quote)
}

fn plan_amm_exact_in_fill(
    state: &LedgerState,
    book: &FlowBook,
    remaining_in: &Amount,
    close_time: u64,
    _output_recipient: [u8; 20],
    clob_quote: Option<&ClobQualityQuote>,
    taker: Option<[u8; 20]>,
    amm_multi_path: bool,
    amm_iteration: u16,
    amm_initial_pool: Option<&crate::ledger::tx::amm_step::AmmPool>,
) -> Option<BookFill> {
    if book.domain_id.is_some() || crate::ledger::offer::amount_is_zero(remaining_in) {
        return None;
    }
    let pool = taker
        .and_then(|account| {
            amm_step::load_amm_pool_for_account(
                state,
                &book.in_issue,
                &book.out_issue,
                &account,
                close_time,
            )
        })
        .or_else(|| amm_step::load_amm_pool(state, &book.in_issue, &book.out_issue))?;
    let quote = if amm_multi_path {
        let initial_pool = amm_initial_pool.unwrap_or(&pool);
        let fib = amm_step::quote_fibonacci_offer_with_initial(&pool, initial_pool, amm_iteration)?;
        let quote = limit_amm_offer_by_input(fib, remaining_in)?;
        if let Some(reference) = clob_quote {
            if !quality_not_worse_than(
                &quote.spent_in,
                &quote.delivered_out,
                &reference.input,
                &reference.output,
            ) {
                return None;
            }
        }
        quote
    } else if let Some(reference) = clob_quote {
        let reference_quality = reference_flow_quality(reference)?;
        if amm_step::spot_quality_close_or_worse_than(&pool, reference_quality.rate())? {
            return None;
        }
        let full = amm_step::quote_exact_in(&pool, remaining_in)?;
        if quality_not_worse_than(
            &full.spent_in,
            &full.delivered_out,
            &reference.input,
            &reference.output,
        ) {
            full
        } else {
            let boundary = amm_step::quote_to_clob_quality(&pool, reference_quality.rate())?;
            if compare_amounts(&boundary.spent_in, remaining_in) == std::cmp::Ordering::Greater {
                return None;
            }
            boundary
        }
    } else {
        amm_step::quote_exact_in(&pool, remaining_in)?
    };
    if let Some(reference) = clob_quote {
        if compare_amounts(&quote.spent_in, remaining_in) == std::cmp::Ordering::Greater
            || !quality_not_worse_than(
                &quote.spent_in,
                &quote.delivered_out,
                &reference.input,
                &reference.output,
            )
        {
            return None;
        }
    }
    amm_fill_from_quote(pool, quote)
}

fn limit_amm_offer_by_output(quote: AmmQuote, limit_out: &Amount) -> Option<AmmQuote> {
    if compare_amounts(&quote.delivered_out, limit_out) != std::cmp::Ordering::Greater {
        return Some(quote);
    }
    let book_key = BookKey::from_amounts(&quote.spent_in, &quote.delivered_out);
    let quality = crate::ledger::directory::offer_quality(&quote.delivered_out, &quote.spent_in);
    let book_directory = crate::ledger::directory::book_dir_quality_key(&book_key, quality).0;
    let (spent_in, delivered_out) = super::offer_math::ceil_out_strict_via_quality(
        &quote.spent_in,
        &quote.delivered_out,
        limit_out,
        &book_directory,
        true,
    );
    Some(AmmQuote {
        spent_in,
        delivered_out,
    })
}

fn limit_amm_offer_by_input(quote: AmmQuote, limit_in: &Amount) -> Option<AmmQuote> {
    if compare_amounts(&quote.spent_in, limit_in) != std::cmp::Ordering::Greater {
        return Some(quote);
    }
    let book_key = BookKey::from_amounts(&quote.spent_in, &quote.delivered_out);
    let quality = crate::ledger::directory::offer_quality(&quote.delivered_out, &quote.spent_in);
    let book_directory = crate::ledger::directory::book_dir_quality_key(&book_key, quality).0;
    let (spent_in, delivered_out) = super::offer_math::ceil_in_strict_via_quality(
        &quote.spent_in,
        &quote.delivered_out,
        limit_in,
        &book_directory,
        false,
    );
    Some(AmmQuote {
        spent_in,
        delivered_out,
    })
}

fn amm_fill_from_quote(pool: AmmPool, quote: AmmQuote) -> Option<BookFill> {
    if crate::ledger::offer::amount_is_zero(&quote.spent_in)
        || crate::ledger::offer::amount_is_zero(&quote.delivered_out)
    {
        return None;
    }
    Some(BookFill {
        key: Key([0u8; 32]),
        offer_input: quote.spent_in.clone(),
        input: quote.spent_in.clone(),
        output: quote.delivered_out.clone(),
        owner_output_debit: quote.delivered_out.clone(),
        fully_consumed: true,
        amm: Some(AmmFill { pool, quote }),
    })
}

fn reference_flow_quality(reference: &ClobQualityQuote) -> Option<FlowQuality> {
    FlowQuality::from_amounts(&reference.input, &reference.output, true)
}

fn quality_not_worse_than(
    input: &Amount,
    output: &Amount,
    reference_in: &Amount,
    reference_out: &Amount,
) -> bool {
    let input_value = super::amount_to_iou_value(input);
    let output_value = super::amount_to_iou_value(output);
    let reference_in_value = super::amount_to_iou_value(reference_in);
    let reference_out_value = super::amount_to_iou_value(reference_out);
    if !input_value.is_positive()
        || !output_value.is_positive()
        || !reference_in_value.is_positive()
        || !reference_out_value.is_positive()
    {
        return false;
    }

    let actual_cross = input_value.mul_round(&reference_out_value, false);
    let reference_cross = reference_in_value.mul_round(&output_value, false);
    compare_iou_values(&actual_cross, &reference_cross) != std::cmp::Ordering::Greater
}

pub(crate) fn apply_book_fill_plan(
    state: &mut LedgerState,
    plan: &BookFillPlan,
    taker: [u8; 20],
    output_recipient: [u8; 20],
) -> Result<StepResult, &'static str> {
    if !plan.complete {
        return Err("tecPATH_DRY");
    }
    apply_book_fill_plan_inner(state, plan, taker, output_recipient)
}

pub(crate) fn apply_book_partial_fill_plan(
    state: &mut LedgerState,
    plan: &BookFillPlan,
    taker: [u8; 20],
    output_recipient: [u8; 20],
) -> Result<StepResult, &'static str> {
    if plan.fills.is_empty() {
        return Err("tecPATH_DRY");
    }
    apply_book_fill_plan_inner(state, plan, taker, output_recipient)
}

fn apply_book_fill_plan_inner(
    state: &mut LedgerState,
    plan: &BookFillPlan,
    taker: [u8; 20],
    output_recipient: [u8; 20],
) -> Result<StepResult, &'static str> {
    let Some(input) = plan.input.clone() else {
        return Err("tecPATH_DRY");
    };
    let Some(output) = plan.output.clone() else {
        return Err("tecPATH_DRY");
    };
    let used_amm = plan.fills.iter().any(|fill| fill.amm.is_some());

    let mut sandbox = FlowSandbox::begin(state);
    for key in &plan.removals {
        if let Some(deleted) = delete_offer_from_dirs(sandbox.state_mut(), key) {
            decrement_owner_count(sandbox.state_mut(), &deleted.offer.account);
        }
    }

    for fill in &plan.fills {
        if let Some(amm_fill) = &fill.amm {
            if !book_step_can_debit_input(sandbox.state(), &taker, &amm_fill.quote.spent_in)
                || !book_step_can_credit_amm_output(
                    sandbox.state(),
                    &output_recipient,
                    &amm_fill.quote.delivered_out,
                )
            {
                sandbox.discard();
                return Err("tecPATH_DRY");
            }
            if !amm_step::apply_swap_to_state(
                sandbox.state_mut(),
                &amm_fill.pool,
                &amm_fill.quote,
                &taker,
                &output_recipient,
            ) {
                sandbox.discard();
                return Err("tecPATH_DRY");
            }
            continue;
        }

        let Some(offer) = sandbox.state().get_offer(&fill.key).cloned() else {
            sandbox.discard();
            return Err("tecPATH_DRY");
        };

        let taker_input_debit = fill.input.clone();
        let owner_output_debit = fill.owner_output_debit.clone();

        if !book_step_can_debit_input(sandbox.state(), &taker, &taker_input_debit)
            || !book_step_can_debit_input(sandbox.state(), &offer.account, &owner_output_debit)
            || !book_step_can_credit_output(sandbox.state(), &output_recipient, &fill.output)
            || !book_step_can_credit_output(sandbox.state(), &offer.account, &fill.offer_input)
        {
            sandbox.discard();
            return Err("tecPATH_DRY");
        }

        if !apply_amount_delta(
            sandbox.state_mut(),
            &taker,
            AssetDelta::Debit,
            &taker_input_debit,
        ) || !apply_amount_delta(
            sandbox.state_mut(),
            &offer.account,
            AssetDelta::Debit,
            &owner_output_debit,
        ) || !apply_amount_delta(
            sandbox.state_mut(),
            &output_recipient,
            AssetDelta::Credit,
            &fill.output,
        ) || !apply_amount_delta(
            sandbox.state_mut(),
            &offer.account,
            AssetDelta::Credit,
            &fill.offer_input,
        ) {
            sandbox.discard();
            return Err("tecPATH_DRY");
        }

        if fill.fully_consumed {
            if let Some(deleted) = delete_offer_from_dirs(sandbox.state_mut(), &fill.key) {
                decrement_owner_count(sandbox.state_mut(), &deleted.offer.account);
            }
        } else if let Some(updated) =
            super::rewrite_partial_offer_after_output_fill(&offer, &fill.output)
        {
            sandbox.state_mut().remove_offer(&fill.key);
            sandbox.state_mut().insert_offer(updated);
        } else {
            if let Some(deleted) = delete_offer_from_dirs(sandbox.state_mut(), &fill.key) {
                decrement_owner_count(sandbox.state_mut(), &deleted.offer.account);
            }
        }
    }

    let _commit = sandbox.commit();
    Ok(if used_amm {
        StepResult::with_amm(input, output)
    } else {
        StepResult::new(input, output)
    })
}

fn book_step_can_debit_input(state: &LedgerState, account: &[u8; 20], amount: &Amount) -> bool {
    match amount {
        Amount::Xrp(drops) => spendable_xrp_balance(state, account) >= *drops,
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            if account == issuer {
                return true;
            }
            if issuer_global_frozen(state, issuer) {
                return false;
            }
            let Some(line) = load_trustline_readonly(state, account, issuer, currency) else {
                return false;
            };
            if trustline_frozen_by_issuer(&line, issuer) || trustline_has_deep_freeze(&line) {
                return false;
            }
            compare_iou_values(&line.balance_for(account), value) != std::cmp::Ordering::Less
        }
        Amount::Mpt(_) => mptoken::can_debit_mpt_amount(state, account, amount),
    }
}

fn book_step_can_credit_output(state: &LedgerState, account: &[u8; 20], amount: &Amount) -> bool {
    match amount {
        Amount::Xrp(_) => state.get_account(account).is_some(),
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            if account == issuer {
                return true;
            }
            if issuer_global_frozen(state, issuer) {
                return false;
            }
            let Some(line) = load_trustline_readonly(state, account, issuer, currency) else {
                return false;
            };
            if trustline_frozen_by_issuer(&line, issuer) || trustline_has_deep_freeze(&line) {
                return false;
            }
            if issuer_requires_auth_without_line_auth(state, issuer, account, &line) {
                return false;
            }

            let balance = line.balance_for(account);
            let limit = trustline_limit_for_holder(&line, account);
            compare_iou_values(&limit.sub(&balance), value) != std::cmp::Ordering::Less
        }
        Amount::Mpt(_) => state.get_account(account).is_some(),
    }
}

fn book_step_can_credit_amm_output(
    state: &LedgerState,
    account: &[u8; 20],
    amount: &Amount,
) -> bool {
    match amount {
        Amount::Iou {
            value,
            currency,
            issuer,
            ..
        } if account != issuer => {
            if issuer_global_frozen(state, issuer) {
                return false;
            }
            match load_trustline_readonly(state, account, issuer, currency) {
                Some(line) => {
                    if trustline_frozen_by_issuer(&line, issuer)
                        || trustline_has_deep_freeze(&line)
                        || issuer_requires_auth_without_line_auth(state, issuer, account, &line)
                    {
                        return false;
                    }
                    let balance = line.balance_for(account);
                    let limit = trustline_limit_for_holder(&line, account);
                    compare_iou_values(&limit.sub(&balance), value) != std::cmp::Ordering::Less
                }
                None => false,
            }
        }
        _ => book_step_can_credit_output(state, account, amount),
    }
}

fn trustline_limit_for_holder(line: &RippleState, account: &[u8; 20]) -> IouValue {
    if account == &line.low_account {
        line.low_limit
    } else {
        line.high_limit
    }
}

fn issuer_requires_auth(state: &LedgerState, issuer: &[u8; 20]) -> bool {
    load_account_readonly(state, issuer)
        .map(|account| (account.flags & crate::ledger::account::LSF_REQUIRE_AUTH) != 0)
        .unwrap_or(false)
}

fn issuer_requires_auth_without_line_auth(
    state: &LedgerState,
    issuer: &[u8; 20],
    holder: &[u8; 20],
    line: &RippleState,
) -> bool {
    let Some(issuer_account) = load_account_readonly(state, issuer) else {
        return false;
    };
    (issuer_account.flags & crate::ledger::account::LSF_REQUIRE_AUTH) != 0
        && (line.flags & trustline_auth_flag_for(issuer, holder)) == 0
        && line.balance.is_zero()
}

fn decrement_owner_count(state: &mut LedgerState, account: &[u8; 20]) {
    if let Some(acct) = crate::ledger::tx::load_existing_account(state, account) {
        let mut updated = acct.clone();
        updated.owner_count = updated.owner_count.saturating_sub(1);
        state.insert_account(updated);
    }
}

fn classify_offer(
    state: &LedgerState,
    book: &FlowBook,
    offer: &Offer,
    close_time: u64,
) -> OfferReadStatus {
    if offer
        .expiration
        .is_some_and(|expiration| expiration as u64 <= close_time)
    {
        return OfferReadStatus::Expired;
    }

    if crate::ledger::offer::amount_is_zero(&offer.taker_pays)
        || crate::ledger::offer::amount_is_zero(&offer.taker_gets)
    {
        return OfferReadStatus::ZeroAmount;
    }

    if offerer_deep_frozen_for_pays_iou(state, offer) {
        return OfferReadStatus::Unfunded;
    }

    if !offer_domain_valid(state, book, offer, close_time) {
        return OfferReadStatus::DomainInvalid;
    }

    if !offerer_authorized_for_pays_iou(state, offer) {
        return OfferReadStatus::Unauthorized;
    }

    if !offerer_can_fund_gets(state, offer) {
        return OfferReadStatus::Unfunded;
    }

    let owner_funds = funded_offer_output(state, offer);
    if super::book_offer_ops::offer_should_remove_tiny_reduced_quality(offer, &owner_funds) {
        return OfferReadStatus::TinyReducedQuality;
    }

    OfferReadStatus::Usable
}

fn offer_status_removable(status: OfferReadStatus) -> bool {
    matches!(
        status,
        OfferReadStatus::Expired
            | OfferReadStatus::ZeroAmount
            | OfferReadStatus::Unfunded
            | OfferReadStatus::TinyReducedQuality
            | OfferReadStatus::Unauthorized
            | OfferReadStatus::DomainInvalid
    )
}

fn offer_domain_valid(
    state: &LedgerState,
    book: &FlowBook,
    offer: &Offer,
    close_time: u64,
) -> bool {
    if offer.domain_id != book.domain_id {
        return false;
    }
    match book.domain_id {
        Some(domain_id) => crate::ledger::tx::permissioned_domain::account_in_domain(
            state,
            &offer.account,
            &domain_id,
            close_time,
        ),
        None => true,
    }
}

fn offerer_deep_frozen_for_pays_iou(state: &LedgerState, offer: &Offer) -> bool {
    let Amount::Iou {
        currency, issuer, ..
    } = &offer.taker_pays
    else {
        return false;
    };
    if offer.account == *issuer {
        return false;
    }
    load_trustline_readonly(state, &offer.account, issuer, currency)
        .map(|line| trustline_has_deep_freeze(&line))
        .unwrap_or(false)
}

fn offerer_authorized_for_pays_iou(state: &LedgerState, offer: &Offer) -> bool {
    let Amount::Iou {
        currency, issuer, ..
    } = &offer.taker_pays
    else {
        return true;
    };
    if offer.account == *issuer {
        return true;
    }

    let Some(issuer_account) = load_account_readonly(state, issuer) else {
        return true;
    };
    if (issuer_account.flags & crate::ledger::account::LSF_REQUIRE_AUTH) == 0 {
        return true;
    }

    let Some(line) = load_trustline_readonly(state, &offer.account, issuer, currency) else {
        return false;
    };
    (line.flags & trustline_auth_flag_for(issuer, &offer.account)) != 0
}

fn funded_offer_output(state: &LedgerState, offer: &Offer) -> Amount {
    min_amount(
        &offer.taker_gets,
        &owner_total_funds_for_offer_output(state, offer),
    )
}

fn owner_total_funds_for_offer_output(state: &LedgerState, offer: &Offer) -> Amount {
    match &offer.taker_gets {
        Amount::Xrp(_) => {
            let available = spendable_xrp_for_offer(state, &offer.account);
            Amount::Xrp(available)
        }
        Amount::Iou {
            currency, issuer, ..
        } => {
            let funds = iou_offer_funds(state, &offer.account, issuer, currency);
            if funds.is_zero() || funds.is_negative() {
                return Amount::Iou {
                    value: IouValue::ZERO,
                    currency: currency.clone(),
                    issuer: *issuer,
                };
            }
            Amount::Iou {
                value: funds,
                currency: currency.clone(),
                issuer: *issuer,
            }
        }
        Amount::Mpt(_) => Amount::Mpt(Vec::new()),
    }
}

fn funded_offer_output_for_recipient(
    state: &LedgerState,
    offer: &Offer,
    output_recipient: &[u8; 20],
) -> Amount {
    let raw_funded = funded_offer_output(state, offer);
    funded_offer_output_for_recipient_amount(state, offer, output_recipient, &raw_funded, false)
}

fn funded_offer_output_for_recipient_amount(
    state: &LedgerState,
    offer: &Offer,
    output_recipient: &[u8; 20],
    raw_funded: &Amount,
    waive_offer_crossing_owner_fee: bool,
) -> Amount {
    let deliverable = if waive_offer_crossing_owner_fee && offer.account == *output_recipient {
        raw_funded.clone()
    } else {
        transfer_rate_net_deliverable_amount(state, &offer.account, output_recipient, raw_funded)
    };
    let creditable = recipient_credit_limit_for_amount(state, output_recipient, &deliverable);
    min_amount(&offer.taker_gets, &creditable)
}

fn recipient_credit_limit_for_amount(
    state: &LedgerState,
    account: &[u8; 20],
    amount: &Amount,
) -> Amount {
    match amount {
        Amount::Xrp(_) => {
            if state.get_account(account).is_some() {
                amount.clone()
            } else {
                Amount::Xrp(0)
            }
        }
        Amount::Iou {
            currency, issuer, ..
        } => {
            if account == issuer {
                return amount.clone();
            }
            if issuer_global_frozen(state, issuer) {
                return zero_amount_like_local(amount);
            }
            let Some(line) = load_trustline_readonly(state, account, issuer, currency) else {
                return zero_amount_like_local(amount);
            };
            if trustline_frozen_by_issuer(&line, issuer) || trustline_has_deep_freeze(&line) {
                return zero_amount_like_local(amount);
            }
            if issuer_requires_auth_without_line_auth(state, issuer, account, &line) {
                return zero_amount_like_local(amount);
            }

            let balance = line.balance_for(account);
            let limit = trustline_limit_for_holder(&line, account);
            let room = limit.sub(&balance);
            if !room.is_positive() {
                return zero_amount_like_local(amount);
            }
            min_amount(
                amount,
                &Amount::Iou {
                    value: room,
                    currency: currency.clone(),
                    issuer: *issuer,
                },
            )
        }
        Amount::Mpt(_) => amount.clone(),
    }
}

#[derive(Debug, Clone)]
struct OwnerFundDebit {
    account: [u8; 20],
    amount: Amount,
}

fn funded_offer_output_after_planned_debits(
    state: &LedgerState,
    offer: &Offer,
    planned_debits: &[OwnerFundDebit],
) -> Amount {
    let mut available = owner_total_funds_for_offer_output(state, offer);
    for debit in planned_debits {
        if debit.account == offer.account && same_amount_issue(&available, &debit.amount) {
            available = saturating_subtract_amount(&available, &debit.amount);
            if crate::ledger::offer::amount_is_zero(&available) {
                break;
            }
        }
    }
    min_amount(&offer.taker_gets, &available)
}

fn planned_owner_debit(
    state: &LedgerState,
    offer: &Offer,
    delivered_output: &Amount,
    output_recipient: Option<[u8; 20]>,
    waive_offer_crossing_owner_fee: bool,
) -> Amount {
    match output_recipient {
        Some(recipient) if waive_offer_crossing_owner_fee && recipient == offer.account => {
            delivered_output.clone()
        }
        Some(recipient) => {
            transfer_rate_gross_debit_amount(state, &offer.account, &recipient, delivered_output)
        }
        None => delivered_output.clone(),
    }
}

fn book_step_gross_step_input(
    state: &LedgerState,
    book: &FlowBook,
    taker: Option<[u8; 20]>,
    output_recipient: Option<[u8; 20]>,
    offer_input: &Amount,
) -> Amount {
    let Amount::Iou { issuer, .. } = offer_input else {
        return offer_input.clone();
    };
    if !matches!(&book.in_issue, Issue::Iou { issuer: book_issuer, .. } if book_issuer == issuer) {
        return offer_input.clone();
    }
    if Some(*issuer) == taker || Some(*issuer) == output_recipient {
        return offer_input.clone();
    }
    issuer_transfer_rate_gross_amount(offer_input, account_transfer_rate(state, issuer))
}

fn book_step_net_offer_input_budget(
    state: &LedgerState,
    book: &FlowBook,
    taker: Option<[u8; 20]>,
    output_recipient: [u8; 20],
    step_input_budget: &Amount,
) -> Amount {
    let Amount::Iou { issuer, .. } = step_input_budget else {
        return step_input_budget.clone();
    };
    if !matches!(&book.in_issue, Issue::Iou { issuer: book_issuer, .. } if book_issuer == issuer) {
        return step_input_budget.clone();
    }
    if Some(*issuer) == taker || *issuer == output_recipient {
        return step_input_budget.clone();
    }
    issuer_transfer_rate_net_amount(step_input_budget, account_transfer_rate(state, issuer))
}

fn saturating_subtract_amount(amount: &Amount, debit: &Amount) -> Amount {
    if compare_amounts(amount, debit) != std::cmp::Ordering::Greater {
        return zero_amount_like_local(amount);
    }
    crate::ledger::offer::subtract_amount(amount, debit)
}

fn zero_amount_like_local(amount: &Amount) -> Amount {
    match amount {
        Amount::Xrp(_) => Amount::Xrp(0),
        Amount::Iou {
            currency, issuer, ..
        } => Amount::Iou {
            value: IouValue::ZERO,
            currency: currency.clone(),
            issuer: *issuer,
        },
        Amount::Mpt(_) => amount.clone(),
    }
}

fn same_amount_issue(lhs: &Amount, rhs: &Amount) -> bool {
    match (lhs, rhs) {
        (Amount::Xrp(_), Amount::Xrp(_)) => true,
        (
            Amount::Iou {
                currency, issuer, ..
            },
            Amount::Iou {
                currency: rhs_currency,
                issuer: rhs_issuer,
                ..
            },
        ) => currency == rhs_currency && issuer == rhs_issuer,
        (Amount::Mpt(lhs), Amount::Mpt(rhs)) => lhs == rhs,
        _ => false,
    }
}

fn min_amount(a: &Amount, b: &Amount) -> Amount {
    if compare_amounts(a, b) == std::cmp::Ordering::Greater {
        b.clone()
    } else {
        a.clone()
    }
}

fn add_amount(current: Option<&Amount>, delta: &Amount) -> Amount {
    let Some(current) = current else {
        return delta.clone();
    };
    match (current, delta) {
        (Amount::Xrp(a), Amount::Xrp(b)) => Amount::Xrp(a.saturating_add(*b)),
        (
            Amount::Iou {
                value,
                currency,
                issuer,
            },
            Amount::Iou { value: rhs, .. },
        ) => Amount::Iou {
            value: value.add(rhs),
            currency: currency.clone(),
            issuer: *issuer,
        },
        _ => current.clone(),
    }
}

fn offerer_can_fund_gets(state: &LedgerState, offer: &Offer) -> bool {
    match &offer.taker_gets {
        Amount::Xrp(drops) => *drops > 0 && spendable_xrp_for_offer(state, &offer.account) > 0,
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            if issuer_global_frozen(state, issuer) {
                return false;
            }
            if offer.account == *issuer {
                return true;
            }
            let Some(line) = load_trustline_readonly(state, &offer.account, issuer, currency)
            else {
                return false;
            };
            if trustline_frozen_by_issuer(&line, issuer) || trustline_has_deep_freeze(&line) {
                return false;
            }
            if !trustline_authorized_by_issuer(state, issuer, &offer.account, &line) {
                return false;
            }
            let funds = iou_offer_funds_from_line(&offer.account, &line);
            !value.is_zero() && funds.is_positive()
        }
        Amount::Mpt(_) => mptoken::can_debit_mpt_amount(state, &offer.account, &offer.taker_gets),
    }
}

fn spendable_xrp_for_offer(state: &LedgerState, account: &[u8; 20]) -> u64 {
    let Some(account) = state.get_account(account) else {
        return 0;
    };
    let fees = crate::ledger::read_fees(state);
    let reserve = fees
        .reserve
        .saturating_add((account.owner_count as u64).saturating_mul(fees.increment));
    account.balance.saturating_sub(reserve)
}

fn iou_offer_funds(
    state: &LedgerState,
    account: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
) -> IouValue {
    if account == issuer {
        return IouValue {
            mantissa: 9_999_999_999_999_999,
            exponent: 80,
        };
    }
    if issuer_global_frozen(state, issuer) {
        return IouValue::ZERO;
    }
    if lp_token_underlying_frozen(state, account, issuer) {
        return IouValue::ZERO;
    }
    let Some(line) = load_trustline_readonly(state, account, issuer, currency) else {
        return IouValue::ZERO;
    };
    if trustline_frozen_by_issuer(&line, issuer) || trustline_has_deep_freeze(&line) {
        return IouValue::ZERO;
    }
    if !trustline_authorized_by_issuer(state, issuer, account, &line) {
        return IouValue::ZERO;
    }
    iou_offer_funds_from_line(account, &line)
}

fn iou_offer_funds_from_line(account: &[u8; 20], line: &RippleState) -> IouValue {
    let balance = line.balance_for(account);
    let opposite_limit = if account == &line.low_account {
        line.high_limit
    } else {
        line.low_limit
    };
    balance.add(&opposite_limit)
}

fn trustline_has_deep_freeze(line: &RippleState) -> bool {
    (line.flags
        & (crate::ledger::trustline::LSF_LOW_DEEP_FREEZE
            | crate::ledger::trustline::LSF_HIGH_DEEP_FREEZE))
        != 0
}

fn trustline_frozen_by_issuer(line: &RippleState, issuer: &[u8; 20]) -> bool {
    if issuer == &line.low_account {
        (line.flags & crate::ledger::trustline::LSF_LOW_FREEZE) != 0
    } else if issuer == &line.high_account {
        (line.flags & crate::ledger::trustline::LSF_HIGH_FREEZE) != 0
    } else {
        false
    }
}

fn trustline_auth_flag_for(issuer: &[u8; 20], holder: &[u8; 20]) -> u32 {
    if issuer > holder {
        crate::ledger::trustline::LSF_HIGH_AUTH
    } else {
        crate::ledger::trustline::LSF_LOW_AUTH
    }
}

fn trustline_authorized_by_issuer(
    state: &LedgerState,
    issuer: &[u8; 20],
    holder: &[u8; 20],
    line: &RippleState,
) -> bool {
    let Some(issuer_account) = load_account_readonly(state, issuer) else {
        return true;
    };
    (issuer_account.flags & crate::ledger::account::LSF_REQUIRE_AUTH) == 0
        || (line.flags & trustline_auth_flag_for(issuer, holder)) != 0
}

fn issuer_global_frozen(state: &LedgerState, issuer: &[u8; 20]) -> bool {
    load_account_readonly(state, issuer)
        .map(|account| (account.flags & crate::ledger::account::LSF_GLOBAL_FREEZE) != 0)
        .unwrap_or(false)
}

fn lp_token_underlying_frozen(
    state: &LedgerState,
    account: &[u8; 20],
    lp_issuer: &[u8; 20],
) -> bool {
    let Some(lp_issuer_account) = load_account_readonly(state, lp_issuer) else {
        return false;
    };
    let Some(amm_id) = account_amm_id(&lp_issuer_account) else {
        return false;
    };
    let Some((asset1, asset2)) = load_amm_assets(state, &amm_id) else {
        return true;
    };
    issue_frozen_for_account(state, account, &asset1)
        || issue_frozen_for_account(state, account, &asset2)
}

fn account_amm_id(account: &AccountRoot) -> Option<[u8; 32]> {
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

fn issue_frozen_for_account(state: &LedgerState, account: &[u8; 20], issue: &Issue) -> bool {
    let Issue::Iou { currency, issuer } = issue else {
        return false;
    };

    if issuer_global_frozen(state, issuer) {
        return true;
    }

    let Some(line) = load_trustline_readonly(state, account, issuer, currency) else {
        return false;
    };
    trustline_frozen_by_issuer(&line, issuer)
}

fn load_account_readonly(state: &LedgerState, account: &[u8; 20]) -> Option<AccountRoot> {
    if let Some(account) = state.get_account(account) {
        return Some(account.clone());
    }
    let key = crate::ledger::account::shamap_key(account);
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    AccountRoot::decode(&raw).ok()
}

fn load_trustline_readonly(
    state: &LedgerState,
    account: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
) -> Option<RippleState> {
    let key = crate::ledger::trustline::shamap_key(account, issuer, currency);
    if let Some(line) = state.get_trustline(&key) {
        return Some(line.clone());
    }
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    RippleState::decode_from_sle(&raw)
}

fn flow_book_to_book_key(book: &FlowBook) -> Option<BookKey> {
    let (pays_currency, pays_issuer) = issue_parts(&book.in_issue)?;
    let (gets_currency, gets_issuer) = issue_parts(&book.out_issue)?;
    Some(BookKey {
        pays_currency,
        pays_issuer,
        gets_currency,
        gets_issuer,
        domain_id: book.domain_id,
    })
}

fn issue_parts(issue: &Issue) -> Option<([u8; 20], [u8; 20])> {
    match issue {
        Issue::Xrp => Some(([0u8; 20], [0u8; 20])),
        Issue::Iou { currency, issuer } => Some((currency.code, *issuer)),
        Issue::Mpt(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{directory, AccountRoot};
    use crate::transaction::amount::{Currency, IouValue};

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

    fn account_with_transfer_rate(
        account_id: [u8; 20],
        balance: u64,
        transfer_rate: u32,
    ) -> AccountRoot {
        let mut account = account(account_id, balance);
        account.transfer_rate = transfer_rate;
        account
    }

    fn usd(issuer: [u8; 20], value: f64) -> Amount {
        Amount::Iou {
            value: IouValue::from_f64(value),
            currency: Currency::from_code("USD").unwrap(),
            issuer,
        }
    }

    fn fund_usd(state: &mut LedgerState, holder: [u8; 20], issuer: [u8; 20], value: f64) {
        let usd = Currency::from_code("USD").unwrap();
        let mut line = RippleState::new(&holder, &issuer, usd);
        line.transfer(&issuer, &IouValue::from_f64(value));
        state.insert_trustline(line);
    }

    fn allow_usd(state: &mut LedgerState, holder: [u8; 20], issuer: [u8; 20], limit: f64) {
        let usd = Currency::from_code("USD").unwrap();
        let mut line = state
            .get_trustline(&crate::ledger::trustline::shamap_key(
                &holder, &issuer, &usd,
            ))
            .cloned()
            .unwrap_or_else(|| RippleState::new(&holder, &issuer, usd));
        line.set_limit_for(&holder, IouValue::from_f64(limit));
        state.insert_trustline(line);
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

    #[test]
    fn book_reader_returns_first_usable_offer_by_quality() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 2_000_000));
        state.insert_offer(offer(maker, 1, usd(issuer, 10.0), Amount::Xrp(100)));
        state.insert_offer(offer(maker, 2, usd(issuer, 10.0), Amount::Xrp(100)));

        let book = FlowBook::new(
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
            Issue::Xrp,
        );
        let result = read_book_tip(&state, &book, 0, 1000);

        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].status, OfferReadStatus::Usable);
        assert_eq!(result.offers_used, 1);
    }

    #[test]
    fn book_step_quality_function_grosses_iou_input_transfer_rate() {
        let taker = [9u8; 20];
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 2_000_000));
        state.insert_account(account(maker, 2_000_000));
        state.insert_account(account_with_transfer_rate(issuer, 0, 1_200_000_000));
        state.insert_offer(offer(maker, 1, usd(issuer, 10.0), Amount::Xrp(100)));

        let book = FlowBook::new(
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
            Issue::Xrp,
        );
        let step = BookStep::new(book, taker, taker);
        let quality = step
            .quality_function(&state)
            .expect("book quality")
            .quality()
            .rate();

        assert_eq!(quality, IouValue::from_f64(0.12));
    }

    #[test]
    fn amm_multipath_limits_generated_offer_at_fixed_quality() {
        let quote = AmmQuote {
            spent_in: Amount::Xrp(100),
            delivered_out: Amount::Xrp(40),
        };

        let out_limited = limit_amm_offer_by_output(quote.clone(), &Amount::Xrp(10)).unwrap();
        assert_eq!(out_limited.delivered_out, Amount::Xrp(10));
        assert_eq!(out_limited.spent_in, Amount::Xrp(25));

        let in_limited = limit_amm_offer_by_input(quote, &Amount::Xrp(25)).unwrap();
        assert_eq!(in_limited.spent_in, Amount::Xrp(25));
        assert_eq!(in_limited.delivered_out, Amount::Xrp(10));
    }

    #[test]
    fn book_reader_marks_expired_and_continues() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 2_000_000));
        let mut expired = offer(maker, 1, usd(issuer, 10.0), Amount::Xrp(100));
        expired.expiration = Some(5);
        state.insert_offer(expired);
        state.insert_offer(offer(maker, 2, usd(issuer, 10.0), Amount::Xrp(100)));

        let book = FlowBook::new(
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
            Issue::Xrp,
        );
        let result = read_book_tip(&state, &book, 5, 1000);

        assert_eq!(result.candidates.len(), 2);
        assert_eq!(result.candidates[0].status, OfferReadStatus::Expired);
        assert_eq!(result.candidates[1].status, OfferReadStatus::Usable);
        assert_eq!(result.removable.len(), 1);
    }

    #[test]
    fn book_reader_marks_unauthorized_require_auth_offer_and_continues() {
        let unauthorized_maker = [1u8; 20];
        let issuer = [2u8; 20];
        let authorized_maker = [3u8; 20];
        let usd_currency = Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(unauthorized_maker, 2_000_000));
        let mut issuer_account = account(issuer, 1_000);
        issuer_account.flags |= crate::ledger::account::LSF_REQUIRE_AUTH;
        state.insert_account(issuer_account);
        state.insert_account(account(authorized_maker, 2_000_000));

        let mut authorized_line =
            RippleState::new(&authorized_maker, &issuer, usd_currency.clone());
        authorized_line.flags |= trustline_auth_flag_for(&issuer, &authorized_maker);
        state.insert_trustline(authorized_line);

        let unauthorized = offer(unauthorized_maker, 1, usd(issuer, 10.0), Amount::Xrp(100));
        let unauthorized_key = unauthorized.key();
        state.insert_offer(unauthorized);
        state.insert_offer(offer(
            authorized_maker,
            2,
            usd(issuer, 10.0),
            Amount::Xrp(100),
        ));

        let book = FlowBook::new(
            Issue::Iou {
                currency: usd_currency,
                issuer,
            },
            Issue::Xrp,
        );
        let result = read_book_tip(&state, &book, 0, 1000);

        assert_eq!(result.candidates.len(), 2);
        assert_eq!(result.candidates[0].status, OfferReadStatus::Unauthorized);
        assert_eq!(result.candidates[1].status, OfferReadStatus::Usable);
        assert_eq!(result.removable, vec![unauthorized_key]);
    }

    #[test]
    fn book_reader_treats_unauthorized_taker_gets_funds_as_unfunded() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 2_000_000));
        let mut issuer_account = account(issuer, 2_000_000);
        issuer_account.flags |= crate::ledger::account::LSF_REQUIRE_AUTH;
        state.insert_account(issuer_account);
        fund_usd(&mut state, maker, issuer, 10.0);

        let unauthorized = offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0));
        let unauthorized_key = unauthorized.key();
        state.insert_offer(unauthorized);

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let result = read_book_tip(&state, &book, 0, 1000);

        assert_eq!(result.candidates[0].status, OfferReadStatus::Unfunded);
        assert_eq!(result.removable, vec![unauthorized_key]);
    }

    #[test]
    fn exact_out_planner_tracks_same_owner_funds_across_offers() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let taker = [3u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 2_000_000));
        state.insert_account(account(issuer, 2_000_000));
        state.insert_account(account(taker, 2_000_000));
        fund_usd(&mut state, maker, issuer, 10.0);
        allow_usd(&mut state, taker, issuer, 25.0);

        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));
        state.insert_offer(offer(maker, 2, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out_with_recipient(
            &state,
            &book,
            &FlowAmount::new(usd(issuer, 20.0)),
            0,
            1000,
            taker,
        );

        assert!(!plan.complete);
        assert_eq!(plan.fills.len(), 1);
        assert_eq!(plan.output.unwrap().as_amount(), &usd(issuer, 10.0));
    }

    #[test]
    fn exact_out_with_recipient_caps_by_receiver_iou_limit() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let taker = [3u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 2_000_000));
        state.insert_account(account(issuer, 2_000_000));
        state.insert_account(account(taker, 2_000_000));
        fund_usd(&mut state, maker, issuer, 10.0);
        allow_usd(&mut state, taker, issuer, 4.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out_with_recipient(
            &state,
            &book,
            &FlowAmount::new(usd(issuer, 6.0)),
            0,
            1000,
            taker,
        );

        assert!(!plan.complete);
        assert_eq!(plan.fills.len(), 1);
        assert_eq!(plan.input, Some(FlowAmount::new(Amount::Xrp(40))));
        assert_eq!(plan.output, Some(FlowAmount::new(usd(issuer, 4.0))));
    }

    #[test]
    fn exact_out_with_recipient_skips_unauthorized_iou_receiver() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let taker = [3u8; 20];
        let usd_currency = Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 2_000_000));
        let mut issuer_account = account(issuer, 2_000_000);
        issuer_account.flags |= crate::ledger::account::LSF_REQUIRE_AUTH;
        state.insert_account(issuer_account);
        state.insert_account(account(taker, 2_000_000));
        fund_usd(&mut state, maker, issuer, 10.0);
        allow_usd(&mut state, taker, issuer, 10.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: usd_currency,
                issuer,
            },
        );
        let plan = plan_book_exact_out_with_recipient(
            &state,
            &book,
            &FlowAmount::new(usd(issuer, 1.0)),
            0,
            1000,
            taker,
        );

        assert!(!plan.complete);
        assert!(plan.fills.is_empty());
        assert!(plan.input.is_none());
        assert!(plan.output.is_none());
    }

    #[test]
    fn book_reader_marks_xrp_offer_below_reserve_unfunded() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        let maker_offer = offer(maker, 1, usd(issuer, 10.0), Amount::Xrp(100));
        let maker_offer_key = maker_offer.key();
        state.insert_offer(maker_offer);

        let book = FlowBook::new(
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
            Issue::Xrp,
        );
        let result = read_book_tip(&state, &book, 0, 1000);

        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].status, OfferReadStatus::Unfunded);
        assert_eq!(result.removable, vec![maker_offer_key]);
    }

    #[test]
    fn book_reader_removes_tiny_reduced_quality_offer() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 2_000_000));
        fund_usd(&mut state, maker, issuer, 1.0);

        let tiny = offer(maker, 1, Amount::Xrp(1), usd(issuer, 100.0));
        let tiny_key = tiny.key();
        state.insert_offer(tiny);

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let result = read_book_tip(&state, &book, 0, 1000);

        assert_eq!(result.candidates.len(), 1);
        assert_eq!(
            result.candidates[0].status,
            OfferReadStatus::TinyReducedQuality
        );
        assert_eq!(result.removable, vec![tiny_key]);
    }

    #[test]
    fn book_step_marks_inactive_when_dead_entries_hit_max_offers() {
        let taker = [9u8; 20];
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let usd_currency = Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 2_000_000));
        state.insert_account(account(maker, 2_000_000));
        state.insert_account(account(issuer, 0));

        let mut expired = offer(maker, 1, usd(issuer, 10.0), Amount::Xrp(100));
        expired.expiration = Some(5);
        state.insert_offer(expired);

        let book = FlowBook::new(
            Issue::Iou {
                currency: usd_currency,
                issuer,
            },
            Issue::Xrp,
        );
        let mut step = BookStep::new(book, taker, taker)
            .with_close_time(5)
            .with_max_offers(1);

        assert_eq!(
            FlowStep::fwd(&mut step, &mut state, &FlowAmount::new(usd(issuer, 1.0))),
            Err("tecPATH_DRY")
        );
        assert!(FlowStep::inactive(&step));
    }

    #[test]
    fn planner_quotes_exact_output_across_multiple_offers() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        fund_usd(&mut state, maker, issuer, 20.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));
        state.insert_offer(offer(maker, 2, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 12.0)), 0, 1000);

        assert!(plan.complete);
        assert_eq!(plan.fills.len(), 2);
        assert!(plan.fills[0].fully_consumed);
        assert!(!plan.fills[1].fully_consumed);
        assert_eq!(plan.input, Some(FlowAmount::new(Amount::Xrp(120))));
        assert_eq!(plan.output, Some(FlowAmount::new(usd(issuer, 12.0))));
    }

    #[test]
    fn planner_stops_at_quality_boundary() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        fund_usd(&mut state, maker, issuer, 20.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));
        state.insert_offer(offer(maker, 2, Amount::Xrp(300), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 12.0)), 0, 1000);

        assert!(!plan.complete);
        assert_eq!(plan.fills.len(), 1);
        assert_eq!(plan.output, Some(FlowAmount::new(usd(issuer, 10.0))));
    }

    #[test]
    fn exact_out_planner_ignores_dead_tip_before_quality_boundary() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        fund_usd(&mut state, maker, issuer, 20.0);
        let mut expired = offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0));
        expired.expiration = Some(5);
        let expired_key = expired.key();
        state.insert_offer(expired);
        state.insert_offer(offer(maker, 2, Amount::Xrp(200), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 5.0)), 5, 1000);

        assert!(plan.complete);
        assert_eq!(plan.removals, vec![expired_key]);
        assert_eq!(plan.input, Some(FlowAmount::new(Amount::Xrp(100))));
        assert_eq!(plan.output, Some(FlowAmount::new(usd(issuer, 5.0))));
    }

    #[test]
    fn exact_in_planner_ignores_dead_tip_before_quality_boundary() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let usd_currency = Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 2_000_000));
        let mut expired = offer(maker, 1, usd(issuer, 10.0), Amount::Xrp(100));
        expired.expiration = Some(5);
        let expired_key = expired.key();
        state.insert_offer(expired);
        state.insert_offer(offer(maker, 2, usd(issuer, 10.0), Amount::Xrp(50)));

        let book = FlowBook::new(
            Issue::Iou {
                currency: usd_currency,
                issuer,
            },
            Issue::Xrp,
        );
        let plan = plan_book_exact_in(
            &state,
            &book,
            &FlowAmount::new(usd(issuer, 5.0)),
            5,
            1000,
            true,
        );

        assert!(plan.complete);
        assert_eq!(plan.removals, vec![expired_key]);
        assert_eq!(plan.input, Some(FlowAmount::new(usd(issuer, 5.0))));
        assert_eq!(plan.output, Some(FlowAmount::new(Amount::Xrp(25))));
    }

    #[test]
    fn all_quality_planner_continues_past_first_quality_boundary() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        fund_usd(&mut state, maker, issuer, 20.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));
        state.insert_offer(offer(maker, 2, Amount::Xrp(300), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out_all_qualities(
            &state,
            &book,
            &FlowAmount::new(usd(issuer, 12.0)),
            0,
            1000,
        );

        assert!(plan.complete);
        assert_eq!(plan.fills.len(), 2);
        assert_eq!(plan.input, Some(FlowAmount::new(Amount::Xrp(160))));
        assert_eq!(plan.output, Some(FlowAmount::new(usd(issuer, 12.0))));
    }

    #[test]
    fn forward_planner_quotes_exact_input() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        fund_usd(&mut state, maker, issuer, 10.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_in(
            &state,
            &book,
            &FlowAmount::new(Amount::Xrp(40)),
            0,
            1000,
            true,
        );

        assert!(plan.complete);
        assert_eq!(plan.fills.len(), 1);
        assert_eq!(plan.input, Some(FlowAmount::new(Amount::Xrp(40))));
        assert_eq!(plan.output, Some(FlowAmount::new(usd(issuer, 4.0))));
    }

    #[test]
    fn forward_planner_caps_output_to_offer_owner_funds() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        fund_usd(&mut state, maker, issuer, 5.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_in(
            &state,
            &book,
            &FlowAmount::new(Amount::Xrp(60)),
            0,
            1000,
            true,
        );

        assert!(!plan.complete);
        assert_eq!(plan.fills.len(), 1);
        assert_eq!(plan.input, Some(FlowAmount::new(Amount::Xrp(50))));
        assert_eq!(plan.output, Some(FlowAmount::new(usd(issuer, 5.0))));
    }

    #[test]
    fn planner_reports_removable_expired_offer() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        let mut expired = offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0));
        let expired_key = expired.key();
        expired.expiration = Some(5);
        state.insert_offer(expired);

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 1.0)), 5, 1000);

        assert!(!plan.complete);
        assert_eq!(plan.removals, vec![expired_key]);
        assert!(plan.fills.is_empty());
    }

    #[test]
    fn planner_caps_iou_output_to_offer_owner_funds() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        fund_usd(&mut state, maker, issuer, 5.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 6.0)), 0, 1000);

        assert!(!plan.complete);
        assert_eq!(plan.fills.len(), 1);
        assert_eq!(plan.input, Some(FlowAmount::new(Amount::Xrp(50))));
        assert_eq!(plan.output, Some(FlowAmount::new(usd(issuer, 5.0))));
    }

    #[test]
    fn planner_removes_deep_frozen_iou_offer() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let usd_currency = Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        let mut line = RippleState::new(&maker, &issuer, usd_currency.clone());
        line.transfer(&issuer, &IouValue::from_f64(10.0));
        line.flags |= crate::ledger::trustline::LSF_LOW_DEEP_FREEZE;
        state.insert_trustline(line);
        let frozen = offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0));
        let frozen_key = frozen.key();
        state.insert_offer(frozen);

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: usd_currency,
                issuer,
            },
        );
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 1.0)), 0, 1000);

        assert!(!plan.complete);
        assert_eq!(plan.removals, vec![frozen_key]);
        assert!(plan.fills.is_empty());
    }

    #[test]
    fn planner_removes_issuer_frozen_iou_offer() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let usd_currency = Currency::from_code("USD").unwrap();
        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        let mut line = RippleState::new(&maker, &issuer, usd_currency.clone());
        line.transfer(&issuer, &IouValue::from_f64(10.0));
        if issuer == line.low_account {
            line.flags |= crate::ledger::trustline::LSF_LOW_FREEZE;
        } else {
            line.flags |= crate::ledger::trustline::LSF_HIGH_FREEZE;
        }
        state.insert_trustline(line);
        let frozen = offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0));
        let frozen_key = frozen.key();
        state.insert_offer(frozen);

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: usd_currency,
                issuer,
            },
        );
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 1.0)), 0, 1000);

        assert!(!plan.complete);
        assert_eq!(plan.removals, vec![frozen_key]);
        assert!(plan.fills.is_empty());
    }

    #[test]
    fn planner_removes_lp_token_offer_when_underlying_asset_is_frozen() {
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let amm_account = [3u8; 20];
        let usd_currency = Currency::from_code("USD").unwrap();
        let usd_issue = Issue::Iou {
            currency: usd_currency.clone(),
            issuer,
        };
        let lp_currency = crate::ledger::tx::amm::amm_lp_currency(&Currency::xrp(), &usd_currency);
        let lp_issue = Issue::Iou {
            currency: lp_currency.clone(),
            issuer: amm_account,
        };
        let amm_id = crate::ledger::tx::amm::amm_key(&Issue::Xrp, &usd_issue);

        let mut state = LedgerState::new();
        state.insert_account(account(maker, 1_000));
        let mut frozen_issuer = account(issuer, 0);
        frozen_issuer.flags |= crate::ledger::account::LSF_GLOBAL_FREEZE;
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

        let mut lp_line = RippleState::new(&maker, &amm_account, lp_currency);
        lp_line.transfer(&amm_account, &IouValue::from_f64(10.0));
        state.insert_trustline(lp_line);

        let frozen = offer(
            maker,
            1,
            Amount::Xrp(100),
            Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: match &lp_issue {
                    Issue::Iou { currency, .. } => currency.clone(),
                    _ => unreachable!(),
                },
                issuer: amm_account,
            },
        );
        let frozen_key = frozen.key();
        state.insert_offer(frozen);

        let plan = plan_book_exact_out(
            &state,
            &FlowBook::new(Issue::Xrp, lp_issue),
            &FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(1.0),
                currency: crate::ledger::tx::amm::amm_lp_currency(&Currency::xrp(), &usd_currency),
                issuer: amm_account,
            }),
            0,
            1000,
        );

        assert!(!plan.complete);
        assert_eq!(plan.removals, vec![frozen_key]);
        assert!(plan.fills.is_empty());
    }

    #[test]
    fn apply_plan_partially_rewrites_offer_and_moves_balances() {
        let taker = [9u8; 20];
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 1_001_000));
        state.insert_account(account(maker, 1_001_000));
        state.insert_account(account(issuer, 0));
        fund_usd(&mut state, maker, issuer, 10.0);
        allow_usd(&mut state, taker, issuer, 20.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 4.0)), 0, 1000);
        let result = apply_book_fill_plan(&mut state, &plan, taker, taker).unwrap();

        assert_eq!(result.input, FlowAmount::new(Amount::Xrp(40)));
        assert_eq!(state.get_account(&taker).unwrap().balance, 1_000_960);
        assert_eq!(state.get_account(&maker).unwrap().balance, 1_001_040);
        let remaining = state.get_offer(&plan.fills[0].key).unwrap();
        assert_eq!(remaining.taker_pays, Amount::Xrp(60));
        assert_eq!(remaining.taker_gets, usd(issuer, 6.0));
        assert_eq!(
            remaining.book_directory,
            plan_book_directory_for(Amount::Xrp(100), usd(issuer, 10.0))
        );
    }

    #[test]
    fn apply_plan_removes_fully_consumed_offer() {
        let taker = [9u8; 20];
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 1_001_000));
        state.insert_account(account(maker, 1_001_000));
        state.insert_account(account(issuer, 0));
        fund_usd(&mut state, maker, issuer, 10.0);
        allow_usd(&mut state, taker, issuer, 20.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 10.0)), 0, 1000);
        let key = plan.fills[0].key;

        apply_book_fill_plan(&mut state, &plan, taker, taker).unwrap();

        assert!(state.get_offer(&key).is_none());
    }

    #[test]
    fn forward_planner_counts_iou_input_transfer_rate_against_budget() {
        let taker = [9u8; 20];
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 1_000));
        state.insert_account(account(maker, 200_000_000));
        state.insert_account(account_with_transfer_rate(issuer, 0, 1_200_000_000));
        fund_usd(&mut state, taker, issuer, 100.0);
        allow_usd(&mut state, maker, issuer, 200.0);
        state.insert_offer(offer(
            maker,
            1,
            usd(issuer, 100.0),
            Amount::Xrp(100_000_000),
        ));

        let book = FlowBook::new(
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
            Issue::Xrp,
        );
        let plan = plan_book_exact_in_all_qualities_for_taker(
            &state,
            &book,
            &FlowAmount::new(usd(issuer, 100.0)),
            0,
            1000,
            taker,
            taker,
        );

        assert!(!plan.complete);
        assert_eq!(
            plan.input,
            Some(FlowAmount::new(Amount::Iou {
                value: IouValue {
                    mantissa: 9_999_999_999_999_999,
                    exponent: -14,
                },
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            }))
        );
        assert_eq!(plan.output, Some(FlowAmount::new(Amount::Xrp(83_333_333))));
        assert_eq!(
            plan.fills[0].offer_input,
            Amount::Iou {
                value: IouValue {
                    mantissa: 8_333_333_333_333_333,
                    exponent: -14,
                },
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            }
        );
    }

    #[test]
    fn apply_plan_debits_gross_iou_input_but_credits_offer_owner_raw_input() {
        let taker = [9u8; 20];
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 1_000));
        state.insert_account(account(maker, 200_000_000));
        state.insert_account(account_with_transfer_rate(issuer, 0, 1_200_000_000));
        fund_usd(&mut state, taker, issuer, 200.0);
        allow_usd(&mut state, maker, issuer, 200.0);
        state.insert_offer(offer(
            maker,
            1,
            usd(issuer, 100.0),
            Amount::Xrp(100_000_000),
        ));

        let book = FlowBook::new(
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
            Issue::Xrp,
        );
        let plan = plan_book_exact_out_all_qualities_for_taker(
            &state,
            &book,
            &FlowAmount::new(Amount::Xrp(100_000_000)),
            0,
            1000,
            taker,
            taker,
        );

        assert!(plan.complete);
        assert_eq!(plan.input, Some(FlowAmount::new(usd(issuer, 120.0))));
        assert_eq!(plan.fills[0].offer_input, usd(issuer, 100.0));
        let result = apply_book_fill_plan(&mut state, &plan, taker, taker).unwrap();

        assert_eq!(result.input, FlowAmount::new(usd(issuer, 120.0)));
        assert_eq!(state.get_account(&taker).unwrap().balance, 100_001_000);
        assert_eq!(state.get_account(&maker).unwrap().balance, 100_000_000);
        let taker_line = state
            .get_trustline(&crate::ledger::trustline::shamap_key(
                &taker,
                &issuer,
                &Currency::from_code("USD").unwrap(),
            ))
            .unwrap();
        let maker_line = state
            .get_trustline(&crate::ledger::trustline::shamap_key(
                &maker,
                &issuer,
                &Currency::from_code("USD").unwrap(),
            ))
            .unwrap();
        assert_eq!(taker_line.balance_for(&taker), IouValue::from_f64(80.0));
        assert_eq!(maker_line.balance_for(&maker), IouValue::from_f64(100.0));
    }

    #[test]
    fn offer_crossing_waives_owner_output_transfer_fee_when_owner_is_taker() {
        let taker = [9u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 1_000));
        state.insert_account(account_with_transfer_rate(issuer, 0, 1_200_000_000));
        fund_usd(&mut state, taker, issuer, 10.0);
        allow_usd(&mut state, taker, issuer, 100.0);
        state.insert_offer(offer(taker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out_all_qualities_for_taker(
            &state,
            &book,
            &FlowAmount::new(usd(issuer, 10.0)),
            0,
            1000,
            taker,
            taker,
        );

        assert!(plan.complete);
        assert_eq!(plan.output, Some(FlowAmount::new(usd(issuer, 10.0))));
        assert_eq!(plan.fills[0].owner_output_debit, usd(issuer, 10.0));
    }

    #[test]
    fn apply_plan_rejects_missing_iou_output_recipient_line() {
        let taker = [9u8; 20];
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 1_001_000));
        state.insert_account(account(maker, 1_001_000));
        fund_usd(&mut state, maker, issuer, 10.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 4.0)), 0, 1000);
        let key = plan.fills[0].key;

        assert_eq!(
            apply_book_fill_plan(&mut state, &plan, taker, taker),
            Err("tecPATH_DRY")
        );
        assert_eq!(state.get_account(&taker).unwrap().balance, 1_001_000);
        assert_eq!(state.get_account(&maker).unwrap().balance, 1_001_000);
        assert!(state.get_offer(&key).is_some());
    }

    #[test]
    fn apply_plan_rejects_amm_iou_output_without_recipient_line() {
        let taker = [9u8; 20];
        let issuer = [2u8; 20];
        let amm_account = [3u8; 20];
        let usd_currency = Currency::from_code("USD").unwrap();
        let usd_issue = Issue::Iou {
            currency: usd_currency.clone(),
            issuer,
        };
        let amm_id = crate::ledger::tx::amm::amm_key(&Issue::Xrp, &usd_issue);
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 1_000_000));
        let mut issuer_account = account(issuer, 0);
        issuer_account.flags |= crate::ledger::account::LSF_REQUIRE_AUTH;
        state.insert_account(issuer_account);
        let mut pseudo = account(amm_account, 1_000_000);
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
        fund_usd(&mut state, amm_account, issuer, 100.0);

        let book = FlowBook::new(Issue::Xrp, usd_issue);
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 1.0)), 0, 1000);

        assert!(plan.complete);
        assert!(plan.fills.iter().any(|fill| fill.amm.is_some()));
        assert_eq!(
            apply_book_fill_plan(&mut state, &plan, taker, taker),
            Err("tecPATH_DRY")
        );
        assert_eq!(state.get_account(&taker).unwrap().balance, 1_000_000);
        assert_eq!(state.get_account(&amm_account).unwrap().balance, 1_000_000);
    }

    #[test]
    fn apply_plan_rolls_back_when_taker_cannot_pay() {
        let taker = [9u8; 20];
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 10));
        state.insert_account(account(maker, 1_000));
        fund_usd(&mut state, maker, issuer, 10.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let plan = plan_book_exact_out(&state, &book, &FlowAmount::new(usd(issuer, 4.0)), 0, 1000);
        let key = plan.fills[0].key;

        assert_eq!(
            apply_book_fill_plan(&mut state, &plan, taker, taker),
            Err("tecPATH_DRY")
        );
        assert_eq!(state.get_account(&taker).unwrap().balance, 10);
        assert_eq!(state.get_account(&maker).unwrap().balance, 1_000);
        assert!(state.get_offer(&key).is_some());
    }

    #[test]
    fn book_step_runs_through_strand_exact_out() {
        let taker = [9u8; 20];
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 1_001_000));
        state.insert_account(account(maker, 1_001_000));
        state.insert_account(account(issuer, 0));
        fund_usd(&mut state, maker, issuer, 10.0);
        allow_usd(&mut state, taker, issuer, 20.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let step = BookStep::new(book.clone(), taker, taker);
        let mut strand = super::super::Strand::single(Box::new(step));

        let result = super::super::flow_exact_out(
            &mut state,
            &mut strand,
            FlowAmount::new(usd(issuer, 4.0)),
        );

        assert!(result.success, "{result:?}");
        assert_eq!(result.input, Some(FlowAmount::new(Amount::Xrp(40))));
        assert_eq!(result.output, Some(FlowAmount::new(usd(issuer, 4.0))));
        assert_eq!(state.get_account(&taker).unwrap().balance, 1_000_960);
        assert_eq!(state.get_account(&maker).unwrap().balance, 1_001_040);
    }

    #[test]
    fn book_step_runs_through_strand_forward_input() {
        let taker = [9u8; 20];
        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(taker, 1_001_000));
        state.insert_account(account(maker, 1_001_000));
        state.insert_account(account(issuer, 0));
        fund_usd(&mut state, maker, issuer, 10.0);
        allow_usd(&mut state, taker, issuer, 20.0);
        state.insert_offer(offer(maker, 1, Amount::Xrp(100), usd(issuer, 10.0)));

        let book = FlowBook::new(
            Issue::Xrp,
            Issue::Iou {
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            },
        );
        let step = BookStep::new(book.clone(), taker, taker);
        let mut strand = super::super::Strand::single(Box::new(step));

        let result = super::super::flow_with_input(
            &mut state,
            &mut strand,
            FlowAmount::new(Amount::Xrp(40)),
        );

        assert!(result.success, "{result:?}");
        assert_eq!(result.input, Some(FlowAmount::new(Amount::Xrp(40))));
        assert_eq!(result.output, Some(FlowAmount::new(usd(issuer, 4.0))));
        assert_eq!(state.get_account(&taker).unwrap().balance, 1_000_960);
        assert_eq!(state.get_account(&maker).unwrap().balance, 1_001_040);
    }

    fn plan_book_directory_for(pays: Amount, gets: Amount) -> [u8; 32] {
        let book_key = BookKey::from_amounts(&pays, &gets);
        let quality = directory::offer_quality(&gets, &pays);
        directory::book_dir_quality_key(&book_key, quality).0
    }
}
