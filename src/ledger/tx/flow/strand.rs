use super::{
    compare_amounts, iou_value_to_amount, FlowAmount, FlowQuality, FlowSandbox, FlowStep,
    QualityFunction,
};
use crate::ledger::LedgerState;

/// A candidate liquidity path made of DirectStep, BookStep, or AMM-backed
/// steps. Batch 3 only routes DirectStep through this shape.
pub(crate) struct Strand {
    steps: Vec<Box<dyn FlowStep>>,
}

impl Strand {
    pub(crate) fn new(steps: Vec<Box<dyn FlowStep>>) -> Self {
        Self { steps }
    }

    pub(crate) fn single(step: Box<dyn FlowStep>) -> Self {
        Self { steps: vec![step] }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.steps.len()
    }

    /// Rippled-style theoretical strand quality.
    ///
    /// Local `FlowQuality` is cost (`input / output`), so composing step
    /// qualities gives an upper-bound cost for filtering and ordering candidate
    /// strands before we spend work executing them.
    pub(crate) fn quality_upper_bound(&self, state: &LedgerState) -> Option<FlowQuality> {
        let mut quality = FlowQuality::ONE;
        for step in &self.steps {
            quality = quality.compose(step.quality_upper_bound(state)?);
        }
        Some(quality)
    }

    /// Reduce a one-strand request to the output amount that can meet a
    /// `tfLimitQuality` threshold.
    ///
    /// This mirrors rippled's `limitOut()` shape for AMM paths: every step
    /// exposes an average-quality function, then the composed path is solved
    /// for the largest final output that does not exceed the limit quality.
    pub(crate) fn limit_output_for_quality(
        &self,
        state: &LedgerState,
        remaining_out: &FlowAmount,
        limit_quality: FlowQuality,
    ) -> FlowAmount {
        let mut functions = Vec::<QualityFunction>::new();
        let mut has_variable = false;

        for step in &self.steps {
            let Some(qf) = step.quality_function(state) else {
                return remaining_out.clone();
            };
            if qf.is_variable() {
                has_variable = true;
            }
            functions.push(qf);
        }

        if !has_variable {
            return remaining_out.clone();
        }
        let max_out = super::amount_to_iou_value(remaining_out.as_amount());
        let Some(out_value) =
            QualityFunction::out_from_composed_average_quality(&functions, limit_quality, max_out)
        else {
            return remaining_out.clone();
        };

        let limited = FlowAmount::new(iou_value_to_amount(&out_value, remaining_out.as_amount()));
        if limited.is_zero()
            || compare_amounts(limited.as_amount(), remaining_out.as_amount())
                != std::cmp::Ordering::Less
        {
            return remaining_out.clone();
        }
        limited
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StrandFlowResult {
    pub(crate) success: bool,
    pub(crate) ter: &'static str,
    pub(crate) input: Option<FlowAmount>,
    pub(crate) output: Option<FlowAmount>,
    pub(crate) inactive: bool,
    pub(crate) used_amm: bool,
}

impl StrandFlowResult {
    fn dry(ter: &'static str, inactive: bool) -> Self {
        Self {
            success: false,
            ter,
            input: None,
            output: None,
            inactive,
            used_amm: false,
        }
    }

    fn success(input: FlowAmount, output: FlowAmount, inactive: bool, used_amm: bool) -> Self {
        Self {
            success: true,
            ter: "tesSUCCESS",
            input: Some(input),
            output: Some(output),
            inactive,
            used_amm,
        }
    }
}

/// Execute a strand for an exact output.
///
/// Rippled's strand engine first walks backward to quote the input required,
/// then replays the strand forward to perform the actual ledger mutations. The
/// backward pass here runs in a throwaway sandbox, so intermediate accounts do
/// not need to be pre-funded before earlier steps have credited them. Only the
/// forward replay is committed.
pub(crate) fn flow_exact_out(
    state: &mut LedgerState,
    strand: &mut Strand,
    requested_out: FlowAmount,
) -> StrandFlowResult {
    if strand.steps.is_empty() {
        return StrandFlowResult::dry("tecPATH_DRY", false);
    }

    let mut step_out = requested_out;
    let mut quote_sandbox = FlowSandbox::begin(state);
    for step in strand.steps.iter_mut().rev() {
        let result = match step.rev(quote_sandbox.state_mut(), &step_out) {
            Ok(result) => result,
            Err(ter) => {
                quote_sandbox.discard();
                return StrandFlowResult::dry(ter, step.inactive());
            }
        };
        step_out = result.input;
    }
    quote_sandbox.discard();

    let inactive = strand.steps.iter().any(|step| step.inactive());
    let quoted_in = step_out;
    let mut applied_out = quoted_in.clone();
    let mut used_amm = false;
    let mut apply_sandbox = FlowSandbox::begin(state);
    for step in strand.steps.iter_mut() {
        let result = match step.valid_fwd(apply_sandbox.state_mut(), &applied_out) {
            Ok(result) => result,
            Err(ter) => {
                apply_sandbox.discard();
                return StrandFlowResult::dry(ter, step.inactive());
            }
        };
        used_amm |= result.used_amm;
        applied_out = result.output;
    }

    let _commit = apply_sandbox.commit();
    let actual_in = strand
        .steps
        .first()
        .and_then(|step| step.cached_in())
        .cloned()
        .unwrap_or(quoted_in);
    let actual_out = strand
        .steps
        .last()
        .and_then(|step| step.cached_out())
        .cloned()
        .unwrap_or(applied_out);
    StrandFlowResult::success(actual_in, actual_out, inactive, used_amm)
}

/// Execute a strand forward from a known input amount.
///
/// This mirrors the forward replay half of rippled's strand engine. Like
/// `flow_exact_out`, it runs inside a ledger sandbox so any dry/failing step
/// leaves the caller's state unchanged.
pub(crate) fn flow_with_input(
    state: &mut LedgerState,
    strand: &mut Strand,
    offered_in: FlowAmount,
) -> StrandFlowResult {
    if strand.steps.is_empty() {
        return StrandFlowResult::dry("tecPATH_DRY", false);
    }

    let target_in = offered_in.clone();
    let mut step_in = offered_in;
    let mut actual_in: Option<FlowAmount> = None;
    let mut used_amm = false;
    let mut sandbox = FlowSandbox::begin(state);
    for step in strand.steps.iter_mut() {
        let result = match step.fwd(sandbox.state_mut(), &step_in) {
            Ok(result) => result,
            Err(ter) => {
                sandbox.discard();
                return StrandFlowResult::dry(ter, step.inactive());
            }
        };
        if actual_in.is_none() {
            actual_in = Some(result.input.clone());
        }
        used_amm |= result.used_amm;
        step_in = result.output;
    }

    let inactive = strand.steps.iter().any(|step| step.inactive());
    let _commit = sandbox.commit();
    StrandFlowResult::success(actual_in.unwrap_or(target_in), step_in, inactive, used_amm)
}

#[cfg(test)]
mod tests {
    use super::super::StepResult;
    use super::*;
    use crate::ledger::{AccountRoot, LedgerState, RippleState};
    use crate::transaction::amount::{Amount, Currency, IouValue};

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

    #[test]
    fn direct_step_strand_executes_exact_out() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let destination = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100));
        state.insert_account(account(issuer, 100));
        state.insert_account(account(destination, 100));

        let mut direct_line = RippleState::new(&sender, &destination, usd.clone());
        direct_line.transfer(&destination, &IouValue::from_f64(10.0));
        direct_line.set_limit_for(&destination, IouValue::from_f64(20.0));
        state.insert_trustline(direct_line);

        let step = super::super::DirectStep::new(sender, destination, issuer, usd.clone())
            .with_path_context(None, false, true, true);
        let mut strand = Strand::single(Box::new(step));
        let result = flow_exact_out(
            &mut state,
            &mut strand,
            FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd,
                issuer,
            }),
        );

        assert!(result.success);
        assert!(!result.inactive);
    }

    #[test]
    fn direct_step_strand_reports_clamped_exact_out() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let destination = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100));
        state.insert_account(account(issuer, 100));
        state.insert_account(account(destination, 100));

        let mut direct_line = RippleState::new(&sender, &destination, usd.clone());
        direct_line.transfer(&destination, &IouValue::from_f64(5.0));
        direct_line.set_limit_for(&destination, IouValue::from_f64(20.0));
        state.insert_trustline(direct_line);

        let step = super::super::DirectStep::new(sender, destination, issuer, usd.clone())
            .with_path_context(None, false, true, true);
        let mut strand = Strand::single(Box::new(step));
        let result = flow_exact_out(
            &mut state,
            &mut strand,
            FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            }),
        );

        assert!(result.success);
        assert_eq!(
            result.input,
            Some(FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer,
            }))
        );
        assert_eq!(
            result.output,
            Some(FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer,
            }))
        );
        let sender_line = state
            .get_trustline_for(&sender, &destination, &usd)
            .unwrap();
        assert!(sender_line.balance_for(&sender).is_zero());
    }

    struct TestMutatingStep {
        account: [u8; 20],
        balance: u64,
        fail: bool,
    }

    impl FlowStep for TestMutatingStep {
        fn rev(
            &mut self,
            state: &mut LedgerState,
            requested_out: &FlowAmount,
        ) -> Result<StepResult, &'static str> {
            let mut account = state.get_account(&self.account).unwrap().clone();
            account.balance = self.balance;
            state.insert_account(account);
            if self.fail {
                return Err("tecPATH_DRY");
            }
            Ok(StepResult::new(
                requested_out.clone(),
                requested_out.clone(),
            ))
        }

        fn fwd(
            &mut self,
            _state: &mut LedgerState,
            _offered_in: &FlowAmount,
        ) -> Result<StepResult, &'static str> {
            Err("tecPATH_DRY")
        }

        fn cached_in(&self) -> Option<&FlowAmount> {
            None
        }

        fn cached_out(&self) -> Option<&FlowAmount> {
            None
        }
    }

    #[test]
    fn strand_rolls_back_prior_step_mutations_when_later_reverse_step_fails() {
        let id = [4u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(id, 10));

        let mut strand = Strand::new(vec![
            Box::new(TestMutatingStep {
                account: id,
                balance: 30,
                fail: true,
            }),
            Box::new(TestMutatingStep {
                account: id,
                balance: 20,
                fail: false,
            }),
        ]);
        let result = flow_exact_out(&mut state, &mut strand, FlowAmount::new(Amount::Xrp(1)));

        assert!(!result.success);
        assert_eq!(state.get_account(&id).unwrap().balance, 10);
    }

    struct PartialReplayStep {
        cached_in: Option<FlowAmount>,
        cached_out: Option<FlowAmount>,
    }

    impl FlowStep for PartialReplayStep {
        fn rev(
            &mut self,
            _state: &mut LedgerState,
            requested_out: &FlowAmount,
        ) -> Result<StepResult, &'static str> {
            self.cached_in = Some(requested_out.clone());
            self.cached_out = Some(requested_out.clone());
            Ok(StepResult::new(
                requested_out.clone(),
                requested_out.clone(),
            ))
        }

        fn fwd(
            &mut self,
            _state: &mut LedgerState,
            offered_in: &FlowAmount,
        ) -> Result<StepResult, &'static str> {
            let out = FlowAmount::new(Amount::Xrp(4));
            self.cached_in = Some(offered_in.clone());
            self.cached_out = Some(out.clone());
            Ok(StepResult::new(offered_in.clone(), out))
        }

        fn cached_in(&self) -> Option<&FlowAmount> {
            self.cached_in.as_ref()
        }

        fn cached_out(&self) -> Option<&FlowAmount> {
            self.cached_out.as_ref()
        }
    }

    #[test]
    fn exact_out_reports_cached_forward_replay_amounts() {
        let mut state = LedgerState::new();
        let mut strand = Strand::single(Box::new(PartialReplayStep {
            cached_in: None,
            cached_out: None,
        }));

        let result = flow_exact_out(&mut state, &mut strand, FlowAmount::new(Amount::Xrp(10)));

        assert!(result.success);
        assert_eq!(result.input, Some(FlowAmount::new(Amount::Xrp(10))));
        assert_eq!(result.output, Some(FlowAmount::new(Amount::Xrp(4))));
    }

    #[test]
    fn direct_step_strand_executes_forward_input() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let destination = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100));
        state.insert_account(account(issuer, 100));
        state.insert_account(account(destination, 100));

        let mut direct_line = RippleState::new(&sender, &destination, usd.clone());
        direct_line.transfer(&destination, &IouValue::from_f64(10.0));
        direct_line.set_limit_for(&destination, IouValue::from_f64(20.0));
        state.insert_trustline(direct_line);

        let step = super::super::DirectStep::new(sender, destination, issuer, usd.clone());
        let mut strand = Strand::single(Box::new(step));
        let result = flow_with_input(
            &mut state,
            &mut strand,
            FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer,
            }),
        );

        assert!(result.success);
        assert_eq!(
            result.output,
            Some(FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd,
                issuer,
            }))
        );
    }
}
