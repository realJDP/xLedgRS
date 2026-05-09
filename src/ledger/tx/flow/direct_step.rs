use super::{FlowAmount, FlowQuality, FlowStep, QualityFunction, StepResult};
use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, Currency, IouValue, Issue};

const QUALITY_ONE: u32 = 1_000_000_000;

#[derive(Debug, Clone, Copy)]
struct DirectQuote {
    input: IouValue,
    src_to_dst: IouValue,
    output: IouValue,
}

/// Direct IOU step: account-to-account transfer through one issuer.
///
/// This mirrors the first useful seam in rippled's DirectStep. For Batch 2 it
/// executes the existing exact-output direct IOU behavior behind a Step-shaped
/// object; later batches can split this into pure reverse/forward passes.
pub(crate) struct DirectStep {
    sender: [u8; 20],
    destination: [u8; 20],
    issuer: [u8; 20],
    currency: Currency,
    send_max: Option<IouValue>,
    prev_direct_source: Option<[u8; 20]>,
    prev_is_book: bool,
    is_first: bool,
    is_last: bool,
    cached_in: Option<FlowAmount>,
    cached_out: Option<FlowAmount>,
}

impl DirectStep {
    pub(crate) fn new(
        sender: [u8; 20],
        destination: [u8; 20],
        issuer: [u8; 20],
        currency: Currency,
    ) -> Self {
        Self {
            sender,
            destination,
            issuer,
            currency,
            send_max: None,
            prev_direct_source: None,
            prev_is_book: false,
            is_first: false,
            is_last: false,
            cached_in: None,
            cached_out: None,
        }
    }

    pub(crate) fn with_send_max(mut self, send_max: Option<IouValue>) -> Self {
        self.send_max = send_max;
        self
    }

    pub(crate) fn with_path_context(
        mut self,
        prev_direct_source: Option<[u8; 20]>,
        prev_is_book: bool,
        is_first: bool,
        is_last: bool,
    ) -> Self {
        self.prev_direct_source = prev_direct_source;
        self.prev_is_book = prev_is_book;
        self.is_first = is_first;
        self.is_last = is_last;
        self
    }

    pub(crate) fn execute_exact_out(
        &mut self,
        state: &mut LedgerState,
        amount: &IouValue,
        send_max: Option<&IouValue>,
    ) -> Result<StepResult, &'static str> {
        if crate::ledger::tx::load_existing_account(state, &self.destination).is_none() {
            return Err("tecNO_DST");
        }
        self.check_path_constraints(state)?;

        let quote = self.quote_for_exact_output(state, amount)?;

        if send_max.is_some_and(|limit| quote.input.sub(limit).is_positive()) {
            return Err("tecPATH_PARTIAL");
        }

        self.validate_direct_line(state, &quote)?;
        ripple_credit_direct(
            state,
            &self.sender,
            &self.destination,
            &self.currency,
            &quote.src_to_dst,
        )?;

        let input = FlowAmount::new(Amount::Iou {
            value: quote.input,
            currency: self.currency.clone(),
            issuer: self.issuer,
        });
        let output = FlowAmount::new(Amount::Iou {
            value: quote.output,
            currency: self.currency.clone(),
            issuer: self.issuer,
        });
        self.cached_in = Some(input.clone());
        self.cached_out = Some(output.clone());

        Ok(StepResult::new(input, output))
    }

    fn quote_exact_out(
        &mut self,
        state: &mut LedgerState,
        amount: &IouValue,
        send_max: Option<&IouValue>,
    ) -> Result<StepResult, &'static str> {
        if crate::ledger::tx::load_existing_account(state, &self.destination).is_none() {
            return Err("tecNO_DST");
        }
        self.check_path_constraints(state)?;

        let quote = self.quote_for_exact_output(state, amount)?;

        if send_max.is_some_and(|limit| quote.input.sub(limit).is_positive()) {
            return Err("tecPATH_PARTIAL");
        }

        // Reverse pass quotes required input only. Source funds are verified
        // during forward replay, after previous steps have had a chance to
        // credit intermediate path accounts.
        if self.sender != self.issuer {
            let sender_key = crate::ledger::trustline::shamap_key(
                &self.sender,
                &self.destination,
                &self.currency,
            );
            let Some(sender_tl) = load_existing_trustline(state, &sender_key) else {
                return Err("tecPATH_DRY");
            };
            if self.prev_is_book && trustline_no_ripple_for(&sender_tl, &self.sender) {
                return Err("terNO_RIPPLE");
            }
        }

        if self.destination != self.issuer {
            let dest_key = crate::ledger::trustline::shamap_key(
                &self.sender,
                &self.destination,
                &self.currency,
            );
            let Some(dest_tl) = load_existing_trustline(state, &dest_key) else {
                return Err("tecPATH_DRY");
            };
            if issuer_requires_auth_without_line_auth(
                state,
                &self.sender,
                &self.destination,
                &dest_tl,
            ) {
                return Err("terNO_AUTH");
            }

            let dest_balance = dest_tl.balance_for(&self.destination);
            let dest_limit = trustline_limit_for(&dest_tl, &self.destination);
            if dest_limit
                .sub(&dest_balance)
                .sub(&quote.src_to_dst)
                .is_negative()
            {
                return Err("tecPATH_DRY");
            }
        }

        let input = FlowAmount::new(Amount::Iou {
            value: quote.input,
            currency: self.currency.clone(),
            issuer: self.issuer,
        });
        let output = FlowAmount::new(Amount::Iou {
            value: quote.output,
            currency: self.currency.clone(),
            issuer: self.issuer,
        });
        self.cached_in = Some(input.clone());
        self.cached_out = Some(output.clone());

        Ok(StepResult::new(input, output))
    }
}

impl FlowStep for DirectStep {
    fn rev(
        &mut self,
        state: &mut LedgerState,
        requested_out: &FlowAmount,
    ) -> Result<StepResult, &'static str> {
        let Amount::Iou {
            value,
            currency,
            issuer,
        } = requested_out.as_amount()
        else {
            return Err("tecPATH_DRY");
        };
        if *issuer != self.issuer || currency != &self.currency {
            return Err("tecPATH_DRY");
        }
        let send_max = self.send_max;
        self.quote_exact_out(state, value, send_max.as_ref())
    }

    fn fwd(
        &mut self,
        state: &mut LedgerState,
        offered_in: &FlowAmount,
    ) -> Result<StepResult, &'static str> {
        let Amount::Iou {
            value,
            currency,
            issuer,
        } = offered_in.as_amount()
        else {
            return Err("tecPATH_DRY");
        };
        if *issuer != self.issuer || currency != &self.currency || value.is_zero() {
            return Err("tecPATH_DRY");
        }

        if self
            .cached_in
            .as_ref()
            .is_some_and(|cached| cached.as_amount() == offered_in.as_amount())
        {
            if let Some(Amount::Iou { value: out, .. }) = self
                .cached_out
                .as_ref()
                .map(|cached| cached.as_amount().clone())
            {
                return self.execute_exact_out(state, &out, Some(value));
            }
        }

        let quote = self.quote_for_input(state, value)?;
        if quote.output.is_zero() || quote.output.is_negative() {
            return Err("tecPATH_DRY");
        }

        self.apply_quote(state, quote)
    }

    fn cached_in(&self) -> Option<&FlowAmount> {
        self.cached_in.as_ref()
    }

    fn cached_out(&self) -> Option<&FlowAmount> {
        self.cached_out.as_ref()
    }

    fn quality_upper_bound(&self, state: &LedgerState) -> Option<FlowQuality> {
        self.direct_quality(state)
    }

    fn quality_function(&self, state: &LedgerState) -> Option<QualityFunction> {
        self.direct_quality(state).map(QualityFunction::constant)
    }
}

impl DirectStep {
    fn quote_for_exact_output(
        &self,
        state: &mut LedgerState,
        output: &IouValue,
    ) -> Result<DirectQuote, &'static str> {
        if output.is_zero() || output.is_negative() {
            return Err("tecPATH_DRY");
        }

        let (_, dst_quality_in) = self.qualities(state);
        let requested_src_to_dst = output.div_round(&quality_to_iou_value(dst_quality_in), true);
        if requested_src_to_dst.is_zero() || requested_src_to_dst.is_negative() {
            return Err("tecPATH_DRY");
        }

        let max_src_to_dst = self.max_src_to_dst(state, self.is_first)?;
        let src_to_dst = max_src_to_dst
            .map(|max| min_iou_value(&requested_src_to_dst, &max))
            .unwrap_or(requested_src_to_dst);
        if src_to_dst.is_zero() || src_to_dst.is_negative() {
            return Err("tecPATH_DRY");
        }

        let (src_quality_out, _) = self.qualities(state);
        let input = src_to_dst.mul_round(&quality_to_iou_value(src_quality_out), true);
        if input.is_zero() || input.is_negative() {
            return Err("tecPATH_DRY");
        }

        let actual_output = if super::compare_iou_values(&src_to_dst, &requested_src_to_dst)
            == std::cmp::Ordering::Less
        {
            src_to_dst.mul_round(&quality_to_iou_value(dst_quality_in), false)
        } else {
            *output
        };
        if actual_output.is_zero() || actual_output.is_negative() {
            return Err("tecPATH_DRY");
        }

        Ok(DirectQuote {
            input,
            src_to_dst,
            output: actual_output,
        })
    }

    fn quote_for_input(
        &self,
        state: &mut LedgerState,
        input: &IouValue,
    ) -> Result<DirectQuote, &'static str> {
        if input.is_zero() || input.is_negative() {
            return Err("tecPATH_DRY");
        }

        let (src_quality_out, dst_quality_in) = self.qualities(state);
        let requested_src_to_dst = input.div_round(&quality_to_iou_value(src_quality_out), false);
        if requested_src_to_dst.is_zero() || requested_src_to_dst.is_negative() {
            return Err("tecPATH_DRY");
        }

        let max_src_to_dst = self.max_src_to_dst(state, true)?.ok_or("tecPATH_DRY")?;
        let src_to_dst = min_iou_value(&requested_src_to_dst, &max_src_to_dst);
        if src_to_dst.is_zero() || src_to_dst.is_negative() {
            return Err("tecPATH_DRY");
        }

        let actual_input = if super::compare_iou_values(&src_to_dst, &requested_src_to_dst)
            == std::cmp::Ordering::Less
        {
            src_to_dst.mul_round(&quality_to_iou_value(src_quality_out), true)
        } else {
            *input
        };
        let output = src_to_dst.mul_round(&quality_to_iou_value(dst_quality_in), false);
        if output.is_zero() || output.is_negative() {
            return Err("tecPATH_DRY");
        }

        Ok(DirectQuote {
            input: actual_input,
            src_to_dst,
            output,
        })
    }

    fn max_src_to_dst(
        &self,
        state: &mut LedgerState,
        include_sender_funds: bool,
    ) -> Result<Option<IouValue>, &'static str> {
        let mut max = None::<IouValue>;
        let (src_quality_out, _) = self.qualities(state);

        let direct_key =
            crate::ledger::trustline::shamap_key(&self.sender, &self.destination, &self.currency);
        let direct_tl = load_existing_trustline(state, &direct_key).ok_or("tecPATH_DRY")?;
        let sender_holds = direct_tl.balance_for(&self.sender);
        let max_direct = if sender_holds.is_positive() {
            sender_holds
        } else {
            trustline_limit_for(&direct_tl, &self.destination).add(&sender_holds)
        };
        if !max_direct.is_positive() {
            return Err("tecPATH_DRY");
        }
        let _ = (include_sender_funds, src_quality_out);
        max = Some(match max {
            Some(current) => min_iou_value(&current, &max_direct),
            None => max_direct,
        });

        Ok(max)
    }

    fn apply_quote(
        &mut self,
        state: &mut LedgerState,
        quote: DirectQuote,
    ) -> Result<StepResult, &'static str> {
        if crate::ledger::tx::load_existing_account(state, &self.destination).is_none() {
            return Err("tecNO_DST");
        }
        self.check_path_constraints(state)?;

        self.validate_direct_line(state, &quote)?;
        ripple_credit_direct(
            state,
            &self.sender,
            &self.destination,
            &self.currency,
            &quote.src_to_dst,
        )?;

        let input = FlowAmount::new(Amount::Iou {
            value: quote.input,
            currency: self.currency.clone(),
            issuer: self.issuer,
        });
        let output = FlowAmount::new(Amount::Iou {
            value: quote.output,
            currency: self.currency.clone(),
            issuer: self.issuer,
        });
        self.cached_in = Some(input.clone());
        self.cached_out = Some(output.clone());

        Ok(StepResult::new(input, output))
    }

    fn validate_direct_line(
        &self,
        state: &mut LedgerState,
        quote: &DirectQuote,
    ) -> Result<(), &'static str> {
        let direct_key =
            crate::ledger::trustline::shamap_key(&self.sender, &self.destination, &self.currency);
        let Some(direct_tl) = load_existing_trustline(state, &direct_key) else {
            return Err("tecPATH_DRY");
        };
        if self.prev_is_book && trustline_no_ripple_for(&direct_tl, &self.sender) {
            return Err("terNO_RIPPLE");
        }
        if issuer_requires_auth_without_line_auth(
            state,
            &self.sender,
            &self.destination,
            &direct_tl,
        ) {
            return Err("terNO_AUTH");
        }
        let sender_holds = direct_tl.balance_for(&self.sender);
        let max_direct = if sender_holds.is_positive() {
            sender_holds
        } else {
            trustline_limit_for(&direct_tl, &self.destination).add(&sender_holds)
        };
        if max_direct.sub(&quote.src_to_dst).is_negative() {
            return Err("tecPATH_DRY");
        }
        Ok(())
    }

    fn direct_quality(&self, state: &LedgerState) -> Option<FlowQuality> {
        let (src_quality_out, dst_quality_in) = self.qualities(state);
        let dst_quality_in = quality_to_iou_value(dst_quality_in);
        if dst_quality_in.mantissa <= 0 {
            return None;
        }
        Some(FlowQuality::new(
            quality_to_iou_value(src_quality_out).div_round(&dst_quality_in, true),
        ))
    }

    fn qualities(&self, state: &LedgerState) -> (u32, u32) {
        let src_quality_out = self.source_quality_out(state);
        let mut dst_quality_in = self.destination_quality_in(state);
        if self.is_last && dst_quality_in > QUALITY_ONE {
            dst_quality_in = QUALITY_ONE;
        }
        (src_quality_out, dst_quality_in)
    }

    fn source_quality_out(&self, state: &LedgerState) -> u32 {
        if self.sender == self.issuer {
            if self
                .prev_direct_source
                .is_some_and(|prev| prev != self.issuer)
            {
                return get_transfer_rate(state, &self.issuer);
            }
            return QUALITY_ONE;
        }

        let mut quality = if self.sender != self.issuer && self.destination != self.issuer {
            get_transfer_rate(state, &self.issuer)
        } else {
            QUALITY_ONE
        };

        if self.prev_direct_source.is_some() {
            if let Some(line_quality) =
                self.trustline_quality_out_for(state, &self.sender, &self.destination)
            {
                quality = quality.max(line_quality);
            }
        }

        if let Some(prev_source) = self.prev_direct_source {
            if prev_source != self.issuer {
                if let Some(prev_quality_in) =
                    self.trustline_quality_in_for(state, &self.sender, &prev_source)
                {
                    quality = quality.max(prev_quality_in);
                }
            }
        }

        normalize_quality(quality)
    }

    fn destination_quality_in(&self, state: &LedgerState) -> u32 {
        if self.destination == self.issuer {
            return QUALITY_ONE;
        }

        self.trustline_quality_in_for(state, &self.destination, &self.sender)
            .map(normalize_quality)
            .unwrap_or(QUALITY_ONE)
    }

    fn trustline_quality_in_for(
        &self,
        state: &LedgerState,
        account: &[u8; 20],
        peer: &[u8; 20],
    ) -> Option<u32> {
        let key = crate::ledger::trustline::shamap_key(account, peer, &self.currency);
        let line = load_trustline_readonly(state, &key)?;
        if account == &line.low_account {
            Some(line.low_quality_in)
        } else {
            Some(line.high_quality_in)
        }
    }

    fn trustline_quality_out_for(
        &self,
        state: &LedgerState,
        account: &[u8; 20],
        peer: &[u8; 20],
    ) -> Option<u32> {
        let key = crate::ledger::trustline::shamap_key(account, peer, &self.currency);
        let line = load_trustline_readonly(state, &key)?;
        if account == &line.low_account {
            Some(line.low_quality_out)
        } else {
            Some(line.high_quality_out)
        }
    }

    fn check_path_constraints(&self, state: &mut LedgerState) -> Result<(), &'static str> {
        if !(self.is_first && self.is_last) {
            check_freeze(state, &self.sender, &self.destination, &self.currency)?;
        }

        if let Some(prev_source) = self.prev_direct_source {
            if self.sender == self.issuer {
                return Ok(());
            }
            // NoRipple only applies when an account is actually rippling value
            // between two non-issuer neighbors. Issuer endpoint hops do not
            // have a second holder-to-holder trust line to inspect.
            if prev_source == self.issuer {
                return Ok(());
            }
            check_no_ripple(
                state,
                &prev_source,
                &self.sender,
                &self.destination,
                &self.currency,
            )?;
        }

        Ok(())
    }
}

fn min_iou_value(a: &IouValue, b: &IouValue) -> IouValue {
    if super::compare_iou_values(a, b) == std::cmp::Ordering::Greater {
        *b
    } else {
        *a
    }
}

fn normalize_quality(quality: u32) -> u32 {
    if quality == 0 {
        QUALITY_ONE
    } else {
        quality
    }
}

fn quality_to_iou_value(quality: u32) -> IouValue {
    let mut value = IouValue {
        mantissa: normalize_quality(quality) as i64,
        exponent: -9,
    };
    value.normalize();
    value
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

fn trustline_no_ripple_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> bool {
    let flag = if account == &tl.low_account {
        crate::ledger::trustline::LSF_LOW_NO_RIPPLE
    } else {
        crate::ledger::trustline::LSF_HIGH_NO_RIPPLE
    };
    (tl.flags & flag) != 0
}

fn trustline_reserve_flag_for(account: &[u8; 20], tl: &crate::ledger::RippleState) -> u32 {
    if account == &tl.low_account {
        crate::ledger::trustline::LSF_LOW_RESERVE
    } else {
        crate::ledger::trustline::LSF_HIGH_RESERVE
    }
}

fn trustline_freeze_flag_for(account: &[u8; 20], tl: &crate::ledger::RippleState) -> u32 {
    if account == &tl.low_account {
        crate::ledger::trustline::LSF_LOW_FREEZE
    } else {
        crate::ledger::trustline::LSF_HIGH_FREEZE
    }
}

fn trustline_qualities_clear_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> bool {
    if account == &tl.low_account {
        tl.low_quality_in == 0 && tl.low_quality_out == 0
    } else {
        tl.high_quality_in == 0 && tl.high_quality_out == 0
    }
}

fn decrement_owner_count(state: &mut LedgerState, account: &[u8; 20]) {
    if let Some(mut root) = load_account_readonly(state, account) {
        root.owner_count = root.owner_count.saturating_sub(1);
        state.insert_account(root);
    }
}

fn remove_from_owner_dir_with_hint(
    state: &mut LedgerState,
    owner: &[u8; 20],
    entry_key: &crate::ledger::Key,
    page: u64,
) {
    let root = crate::ledger::directory::owner_dir_key(owner);
    crate::ledger::directory::dir_remove_root_page(state, &root, page, &entry_key.0);
}

fn delete_direct_trustline(state: &mut LedgerState, tl: &crate::ledger::RippleState) {
    let key = tl.key();
    remove_from_owner_dir_with_hint(state, &tl.low_account, &key, tl.low_node);
    remove_from_owner_dir_with_hint(state, &tl.high_account, &key, tl.high_node);
    if !state.remove_trustline(&key) {
        state.remove_raw(&key);
    }
}

fn ripple_credit_direct(
    state: &mut LedgerState,
    sender: &[u8; 20],
    receiver: &[u8; 20],
    currency: &Currency,
    amount: &IouValue,
) -> Result<(), &'static str> {
    let key = crate::ledger::trustline::shamap_key(sender, receiver, currency);
    let Some(mut tl) = load_existing_trustline(state, &key) else {
        return Err("tecPATH_DRY");
    };

    let sender_balance_before = tl.balance_for(sender);
    tl.transfer(sender, amount);
    let sender_balance_after = tl.balance_for(sender);
    let sender_reserve_flag = trustline_reserve_flag_for(sender, &tl);
    let receiver_reserve_flag = trustline_reserve_flag_for(receiver, &tl);
    let sender_no_ripple = trustline_no_ripple_for(&tl, sender);
    let sender_default_ripple = load_account_readonly(state, sender)
        .map(|account| (account.flags & crate::ledger::account::LSF_DEFAULT_RIPPLE) != 0)
        .unwrap_or(false);

    let should_clear_sender_reserve = sender_balance_before.is_positive()
        && !sender_balance_after.is_positive()
        && (tl.flags & sender_reserve_flag) != 0
        && sender_no_ripple != sender_default_ripple
        && (tl.flags & trustline_freeze_flag_for(sender, &tl)) == 0
        && trustline_limit_for(&tl, sender).is_zero()
        && trustline_qualities_clear_for(&tl, sender);

    let mut delete_line = false;
    if should_clear_sender_reserve {
        decrement_owner_count(state, sender);
        tl.flags &= !sender_reserve_flag;
        delete_line = sender_balance_after.is_zero() && (tl.flags & receiver_reserve_flag) == 0;
    }

    if delete_line {
        delete_direct_trustline(state, &tl);
    } else {
        state.insert_trustline(tl);
    }

    Ok(())
}

fn check_no_ripple(
    state: &mut LedgerState,
    prev: &[u8; 20],
    cur: &[u8; 20],
    next: &[u8; 20],
    currency: &Currency,
) -> Result<(), &'static str> {
    let line_in_key = crate::ledger::trustline::shamap_key(prev, cur, currency);
    let line_out_key = crate::ledger::trustline::shamap_key(cur, next, currency);
    let line_in = load_existing_trustline(state, &line_in_key).ok_or("terNO_LINE")?;
    let line_out = load_existing_trustline(state, &line_out_key).ok_or("terNO_LINE")?;

    if trustline_no_ripple_for(&line_in, cur) && trustline_no_ripple_for(&line_out, cur) {
        return Err("terNO_RIPPLE");
    }

    Ok(())
}

fn check_freeze(
    state: &mut LedgerState,
    src: &[u8; 20],
    dst: &[u8; 20],
    currency: &Currency,
) -> Result<(), &'static str> {
    let dst_account = load_account_readonly(state, dst);
    if dst_account
        .as_ref()
        .map(|account| (account.flags & crate::ledger::account::LSF_GLOBAL_FREEZE) != 0)
        .unwrap_or(false)
    {
        return Err("terNO_LINE");
    }

    let line_key = crate::ledger::trustline::shamap_key(src, dst, currency);
    if let Some(line) = load_existing_trustline(state, &line_key) {
        if trustline_frozen_for(&line, dst) || trustline_has_deep_freeze(&line) {
            return Err("terNO_LINE");
        }
    }

    if let Some(account) = dst_account.as_ref() {
        if let Some(amm_id) = account_amm_id(account) {
            let Some((asset1, asset2)) = load_amm_assets(state, &amm_id) else {
                return Err("tecINTERNAL");
            };
            if issue_frozen_for_account(state, src, &asset1)
                || issue_frozen_for_account(state, src, &asset2)
            {
                return Err("terNO_LINE");
            }
        }
    }

    Ok(())
}

fn account_amm_id(account: &crate::ledger::AccountRoot) -> Option<[u8; 32]> {
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

fn issue_frozen_for_account(state: &mut LedgerState, account: &[u8; 20], issue: &Issue) -> bool {
    let Issue::Iou { currency, issuer } = issue else {
        return false;
    };

    if load_account_readonly(state, issuer)
        .map(|account| (account.flags & crate::ledger::account::LSF_GLOBAL_FREEZE) != 0)
        .unwrap_or(false)
    {
        return true;
    }

    let line_key = crate::ledger::trustline::shamap_key(account, issuer, currency);
    load_existing_trustline(state, &line_key)
        .map(|line| trustline_frozen_for(&line, issuer))
        .unwrap_or(false)
}

fn trustline_frozen_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> bool {
    let flag = if account == &tl.low_account {
        crate::ledger::trustline::LSF_LOW_FREEZE
    } else {
        crate::ledger::trustline::LSF_HIGH_FREEZE
    };
    (tl.flags & flag) != 0
}

fn trustline_has_deep_freeze(tl: &crate::ledger::RippleState) -> bool {
    (tl.flags
        & (crate::ledger::trustline::LSF_LOW_DEEP_FREEZE
            | crate::ledger::trustline::LSF_HIGH_DEEP_FREEZE))
        != 0
}

fn issuer_requires_auth_without_line_auth(
    state: &mut LedgerState,
    issuer: &[u8; 20],
    destination: &[u8; 20],
    tl: &crate::ledger::RippleState,
) -> bool {
    let Some(issuer_account) = crate::ledger::tx::load_existing_account(state, issuer) else {
        return false;
    };
    (issuer_account.flags & crate::ledger::account::LSF_REQUIRE_AUTH) != 0
        && (tl.flags & trustline_auth_flag_for(issuer, destination)) == 0
        && tl.balance.is_zero()
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

fn load_trustline_readonly(
    state: &LedgerState,
    key: &crate::ledger::Key,
) -> Option<crate::ledger::RippleState> {
    if let Some(tl) = state.get_trustline(key) {
        return Some(tl.clone());
    }
    let raw = state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))?;
    crate::ledger::RippleState::decode_from_sle(&raw)
}

fn load_account_readonly(
    state: &mut LedgerState,
    account: &[u8; 20],
) -> Option<crate::ledger::AccountRoot> {
    if let Some(account) = state.get_account(account) {
        return Some(account.clone());
    }
    let key = crate::ledger::account::shamap_key(account);
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    crate::ledger::AccountRoot::decode(&raw).ok()
}

fn get_transfer_rate(state: &LedgerState, issuer: &[u8; 20]) -> u32 {
    if let Some(acct) = state.get_account(issuer) {
        if acct.transfer_rate > 0 {
            return acct.transfer_rate;
        }
        return QUALITY_ONE;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{AccountRoot, RippleState};

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
    fn direct_step_forward_executes_offered_input() {
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

        let mut step = DirectStep::new(sender, destination, issuer, usd.clone())
            .with_path_context(None, false, true, true);
        let result = step
            .fwd(
                &mut state,
                &FlowAmount::new(Amount::Iou {
                    value: IouValue::from_f64(5.0),
                    currency: usd.clone(),
                    issuer,
                }),
            )
            .expect("forward direct step");

        assert_eq!(
            result.input,
            FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer,
            })
        );
        assert_eq!(
            result.output,
            FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd,
                issuer,
            })
        );
    }

    #[test]
    fn direct_step_destination_quality_in_moves_actual_trustline_amount() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let destination = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100));
        state.insert_account(account(issuer, 100));
        state.insert_account(account(destination, 100));

        let mut direct_line = RippleState::new(&sender, &destination, usd.clone());
        direct_line.transfer(&destination, &IouValue::from_f64(20.0));
        direct_line.set_limit_for(&destination, IouValue::from_f64(20.0));
        direct_line.high_quality_in = 500_000_000;
        state.insert_trustline(direct_line);

        let mut step = DirectStep::new(sender, destination, issuer, usd.clone())
            .with_path_context(None, false, true, true);
        let result = step
            .execute_exact_out(&mut state, &IouValue::from_f64(5.0), None)
            .expect("quality-in direct step");

        assert_eq!(
            result.input,
            FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            })
        );
        assert_eq!(
            result.output,
            FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer,
            })
        );
        let dest_line = state
            .get_trustline_for(&sender, &destination, &usd)
            .unwrap();
        assert_eq!(dest_line.balance_for(&sender), IouValue::from_f64(10.0));
    }

    #[test]
    fn direct_step_quality_function_uses_transfer_and_line_qualities() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let destination = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100));
        let mut issuer_account = account(issuer, 100);
        issuer_account.transfer_rate = 1_200_000_000;
        state.insert_account(issuer_account);
        state.insert_account(account(destination, 100));

        let mut direct_line = RippleState::new(&sender, &destination, usd.clone());
        direct_line.high_quality_in = 500_000_000;
        state.insert_trustline(direct_line);

        let step = DirectStep::new(sender, destination, issuer, usd)
            .with_path_context(None, false, true, false);
        let quality = step
            .quality_function(&state)
            .expect("direct quality")
            .quality()
            .rate();

        assert_eq!(quality, IouValue::from_f64(2.4));
    }

    #[test]
    fn direct_step_destination_limit_checks_quality_adjusted_delta() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let destination = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100));
        state.insert_account(account(issuer, 100));
        state.insert_account(account(destination, 100));

        let mut direct_line = RippleState::new(&sender, &destination, usd.clone());
        direct_line.set_limit_for(&destination, IouValue::from_f64(8.0));
        direct_line.high_quality_in = 500_000_000;
        state.insert_trustline(direct_line);

        let mut step = DirectStep::new(sender, destination, issuer, usd);
        let result = step
            .execute_exact_out(&mut state, &IouValue::from_f64(5.0), None)
            .expect("exact-output direct step clamps to available destination room");

        assert_eq!(
            result.input,
            FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(8.0),
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            })
        );
        assert_eq!(
            result.output,
            FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(4.0),
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            })
        );
    }

    #[test]
    fn direct_step_exact_out_clamps_to_sender_funds() {
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
        direct_line.set_limit_for(&destination, IouValue::from_f64(100.0));
        state.insert_trustline(direct_line);

        let mut step = DirectStep::new(sender, destination, issuer, usd.clone())
            .with_path_context(None, false, true, true);
        let result = step
            .execute_exact_out(&mut state, &IouValue::from_f64(10.0), None)
            .expect("exact-output direct step clamps to sender funds");

        assert_eq!(
            result.input,
            FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer,
            })
        );
        assert_eq!(
            result.output,
            FlowAmount::new(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd.clone(),
                issuer,
            })
        );
        let sender_line = state
            .get_trustline_for(&sender, &destination, &usd)
            .unwrap();
        assert!(sender_line.balance_for(&sender).is_zero());
    }

    #[test]
    fn direct_step_last_hop_caps_destination_quality_in_above_par() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let destination = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100));
        state.insert_account(account(issuer, 100));
        state.insert_account(account(destination, 100));

        let mut direct_line = RippleState::new(&sender, &destination, usd.clone());
        direct_line.transfer(&destination, &IouValue::from_f64(20.0));
        direct_line.set_limit_for(&destination, IouValue::from_f64(20.0));
        direct_line.high_quality_in = 2_000_000_000;
        state.insert_trustline(direct_line);

        let mut step = DirectStep::new(sender, destination, issuer, usd.clone())
            .with_path_context(None, false, true, true);
        step.execute_exact_out(&mut state, &IouValue::from_f64(5.0), None)
            .expect("last hop quality-in cap");

        let sender_line = state
            .get_trustline_for(&sender, &destination, &usd)
            .unwrap();
        assert_eq!(sender_line.balance_for(&sender), IouValue::from_f64(15.0));
    }

    #[test]
    fn direct_step_clears_sender_reserve_and_deletes_empty_line() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let destination = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        let mut sender_root = account(sender, 100);
        sender_root.owner_count = 1;
        state.insert_account(sender_root);
        state.insert_account(account(issuer, 100));
        state.insert_account(account(destination, 100));

        let mut direct_line = RippleState::new(&sender, &destination, usd.clone());
        direct_line.transfer(&destination, &IouValue::from_f64(5.0));
        direct_line.flags |=
            crate::ledger::trustline::LSF_LOW_RESERVE | crate::ledger::trustline::LSF_LOW_NO_RIPPLE;
        let line_key = direct_line.key();
        direct_line.low_node = crate::ledger::directory::dir_add(&mut state, &sender, line_key.0);
        direct_line.high_node =
            crate::ledger::directory::dir_add(&mut state, &destination, line_key.0);
        state.insert_trustline(direct_line);

        let mut step = DirectStep::new(sender, destination, issuer, usd.clone())
            .with_path_context(None, false, true, true);
        step.execute_exact_out(&mut state, &IouValue::from_f64(5.0), None)
            .expect("crossing zero clears sender reserve");

        assert_eq!(state.get_account(&sender).unwrap().owner_count, 0);
        assert!(state.get_trustline(&line_key).is_none());
        assert!(crate::ledger::directory::load_directory_fresh(
            &state,
            &crate::ledger::directory::owner_dir_key(&sender)
        )
        .is_none());
        assert!(crate::ledger::directory::load_directory_fresh(
            &state,
            &crate::ledger::directory::owner_dir_key(&destination)
        )
        .is_none());
    }

    #[test]
    fn direct_step_keeps_empty_line_when_receiver_reserve_remains() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let destination = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        let mut sender_root = account(sender, 100);
        sender_root.owner_count = 1;
        state.insert_account(sender_root);
        let mut destination_root = account(destination, 100);
        destination_root.owner_count = 1;
        state.insert_account(destination_root);
        state.insert_account(account(issuer, 100));

        let mut direct_line = RippleState::new(&sender, &destination, usd.clone());
        direct_line.transfer(&destination, &IouValue::from_f64(5.0));
        direct_line.flags |= crate::ledger::trustline::LSF_LOW_RESERVE
            | crate::ledger::trustline::LSF_LOW_NO_RIPPLE
            | crate::ledger::trustline::LSF_HIGH_RESERVE;
        state.insert_trustline(direct_line);

        let mut step = DirectStep::new(sender, destination, issuer, usd.clone())
            .with_path_context(None, false, true, true);
        step.execute_exact_out(&mut state, &IouValue::from_f64(5.0), None)
            .expect("receiver reserve keeps empty line");

        assert_eq!(state.get_account(&sender).unwrap().owner_count, 0);
        assert_eq!(state.get_account(&destination).unwrap().owner_count, 1);
        let line = state
            .get_trustline_for(&sender, &destination, &usd)
            .expect("receiver reserve keeps the zero-balance line");
        assert!(line.balance_for(&sender).is_zero());
        assert_eq!(line.flags & crate::ledger::trustline::LSF_LOW_RESERVE, 0);
        assert_ne!(line.flags & crate::ledger::trustline::LSF_HIGH_RESERVE, 0);
    }

    #[test]
    fn direct_step_keeps_sender_reserve_when_no_ripple_matches_default() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let destination = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        let mut sender_root = account(sender, 100);
        sender_root.owner_count = 1;
        state.insert_account(sender_root);
        state.insert_account(account(issuer, 100));
        state.insert_account(account(destination, 100));

        let mut direct_line = RippleState::new(&sender, &destination, usd.clone());
        direct_line.transfer(&destination, &IouValue::from_f64(5.0));
        direct_line.flags |= crate::ledger::trustline::LSF_LOW_RESERVE;
        state.insert_trustline(direct_line);

        let mut step = DirectStep::new(sender, destination, issuer, usd.clone())
            .with_path_context(None, false, true, true);
        step.execute_exact_out(&mut state, &IouValue::from_f64(5.0), None)
            .expect("matching no-ripple/default-ripple keeps sender reserve");

        assert_eq!(state.get_account(&sender).unwrap().owner_count, 1);
        let line = state
            .get_trustline_for(&sender, &destination, &usd)
            .expect("sender reserve keeps the zero-balance line");
        assert!(line.balance_for(&sender).is_zero());
        assert_ne!(line.flags & crate::ledger::trustline::LSF_LOW_RESERVE, 0);
    }

    #[test]
    fn direct_step_require_auth_returns_ter_no_auth() {
        let issuer = [1u8; 20];
        let destination = [2u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        let mut issuer_root = account(issuer, 100);
        issuer_root.flags |= crate::ledger::account::LSF_REQUIRE_AUTH;
        state.insert_account(issuer_root);
        state.insert_account(account(destination, 100));

        let mut line = RippleState::new(&issuer, &destination, usd.clone());
        line.high_limit = IouValue::from_f64(10.0);
        state.insert_trustline(line);

        let mut step = DirectStep::new(issuer, destination, issuer, usd);
        assert_eq!(
            step.execute_exact_out(&mut state, &IouValue::from_f64(1.0), None)
                .unwrap_err(),
            "terNO_AUTH"
        );
    }

    #[test]
    fn no_ripple_on_endpoint_redeem_does_not_block_direct_step() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100));
        state.insert_account(account(issuer, 100));

        let mut line = RippleState::new(&sender, &issuer, usd.clone());
        line.transfer(&issuer, &IouValue::from_f64(10.0));
        line.flags |= crate::ledger::trustline::LSF_LOW_NO_RIPPLE;
        state.insert_trustline(line);

        let mut step = DirectStep::new(sender, issuer, issuer, usd);
        step.execute_exact_out(&mut state, &IouValue::from_f64(5.0), None)
            .expect("endpoint no-ripple does not block redeeming to issuer");
    }

    #[test]
    fn no_ripple_on_both_sides_of_middle_account_blocks_direct_path() {
        let prev = [1u8; 20];
        let cur = [2u8; 20];
        let next = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(prev, 100));
        state.insert_account(account(cur, 100));
        state.insert_account(account(next, 100));

        let mut line_in = RippleState::new(&prev, &cur, usd.clone());
        line_in.flags |= crate::ledger::trustline::LSF_HIGH_NO_RIPPLE;
        state.insert_trustline(line_in);

        let mut line_out = RippleState::new(&cur, &next, usd.clone());
        line_out.transfer(&next, &IouValue::from_f64(10.0));
        line_out.flags |= crate::ledger::trustline::LSF_LOW_NO_RIPPLE;
        state.insert_trustline(line_out);

        let mut step = DirectStep::new(cur, next, next, usd).with_path_context(
            Some(prev),
            false,
            false,
            false,
        );
        assert_eq!(
            step.execute_exact_out(&mut state, &IouValue::from_f64(5.0), None)
                .unwrap_err(),
            "terNO_RIPPLE"
        );
    }

    #[test]
    fn frozen_destination_side_blocks_non_pure_direct_step() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100));
        state.insert_account(account(issuer, 100));

        let mut line = RippleState::new(&sender, &issuer, usd.clone());
        line.transfer(&issuer, &IouValue::from_f64(10.0));
        line.flags |= crate::ledger::trustline::LSF_HIGH_FREEZE;
        state.insert_trustline(line);

        let mut step = DirectStep::new(sender, issuer, issuer, usd);
        assert_eq!(
            step.execute_exact_out(&mut state, &IouValue::from_f64(5.0), None)
                .unwrap_err(),
            "terNO_LINE"
        );
    }

    #[test]
    fn frozen_underlying_asset_blocks_lp_token_direct_step_to_amm() {
        let holder = [1u8; 20];
        let issuer = [2u8; 20];
        let amm_account = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let usd_issue = Issue::Iou {
            currency: usd.clone(),
            issuer,
        };
        let lp_currency = crate::ledger::tx::amm::amm_lp_currency(&Currency::xrp(), &usd);
        let amm_id = crate::ledger::tx::amm::amm_key(&Issue::Xrp, &usd_issue);

        let mut state = LedgerState::new();
        state.insert_account(account(holder, 100));
        let mut frozen_issuer = account(issuer, 100);
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

        let amm_sle = crate::ledger::meta::build_sle(
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
        );
        state.insert_raw(amm_id, amm_sle);

        let mut lp_line = RippleState::new(&holder, &amm_account, lp_currency.clone());
        lp_line.transfer(&amm_account, &IouValue::from_f64(10.0));
        state.insert_trustline(lp_line);

        let mut step = DirectStep::new(holder, amm_account, amm_account, lp_currency);
        assert_eq!(
            step.execute_exact_out(&mut state, &IouValue::from_f64(5.0), None)
                .unwrap_err(),
            "terNO_LINE"
        );
    }
}
