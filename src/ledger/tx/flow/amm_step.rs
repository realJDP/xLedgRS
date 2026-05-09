use super::{
    compare_amounts, compare_iou_values, FlowAmount, FlowBook, FlowQuality, FlowStep,
    QualityFunction, StepResult,
};
use crate::ledger::tx::asset_flow::spendable_xrp_balance;
use crate::ledger::LedgerState;
use crate::transaction::amount::Amount;

/// FlowStep-backed AMM liquidity for a single issue hop.
pub(crate) struct AmmStep {
    book: FlowBook,
    taker: [u8; 20],
    output_recipient: [u8; 20],
    close_time: u64,
    cached_in: Option<FlowAmount>,
    cached_out: Option<FlowAmount>,
    inactive: bool,
}

impl AmmStep {
    pub(crate) fn new(book: FlowBook, taker: [u8; 20], output_recipient: [u8; 20]) -> Self {
        Self {
            book,
            taker,
            output_recipient,
            close_time: 0,
            cached_in: None,
            cached_out: None,
            inactive: false,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn with_close_time(mut self, close_time: u64) -> Self {
        self.close_time = close_time;
        self
    }

    fn pool(
        &mut self,
        state: &mut LedgerState,
    ) -> Result<crate::ledger::tx::amm_step::AmmPool, &'static str> {
        let pool = if self.close_time == 0 {
            crate::ledger::tx::amm_step::load_amm_pool(
                state,
                &self.book.in_issue,
                &self.book.out_issue,
            )
        } else {
            crate::ledger::tx::amm_step::load_amm_pool_for_account(
                state,
                &self.book.in_issue,
                &self.book.out_issue,
                &self.taker,
                self.close_time,
            )
        };
        pool.ok_or_else(|| {
            self.mark_inactive();
            "tecPATH_DRY"
        })
    }

    fn mark_inactive(&mut self) {
        self.cached_in = None;
        self.cached_out = None;
        self.inactive = true;
    }

    fn remember_quote(&mut self, quote: &crate::ledger::tx::amm_step::AmmQuote) -> StepResult {
        let input = FlowAmount::new(quote.spent_in.clone());
        let output = FlowAmount::new(quote.delivered_out.clone());
        self.cached_in = Some(input.clone());
        self.cached_out = Some(output.clone());
        self.inactive = false;
        StepResult::with_amm(input, output)
    }

    fn apply_quote(
        &mut self,
        state: &mut LedgerState,
        pool: &crate::ledger::tx::amm_step::AmmPool,
        quote: &crate::ledger::tx::amm_step::AmmQuote,
    ) -> Result<StepResult, &'static str> {
        if !can_debit_amm_input(state, &self.taker, &quote.spent_in)
            || !can_credit_amm_output(state, &self.output_recipient, &quote.delivered_out)
        {
            self.mark_inactive();
            return Err("tecPATH_DRY");
        }

        if !crate::ledger::tx::amm_step::apply_swap_to_state(
            state,
            pool,
            quote,
            &self.taker,
            &self.output_recipient,
        ) {
            self.mark_inactive();
            return Err("tecPATH_DRY");
        }
        Ok(self.remember_quote(quote))
    }
}

impl FlowStep for AmmStep {
    fn rev(
        &mut self,
        state: &mut LedgerState,
        requested_out: &FlowAmount,
    ) -> Result<StepResult, &'static str> {
        if requested_out.issue() != Some(self.book.out_issue.clone()) || requested_out.is_zero() {
            self.mark_inactive();
            return Err("tecPATH_DRY");
        }

        let pool = self.pool(state)?;
        let quote = quote_exact_out_bounded(&pool, requested_out.as_amount()).ok_or_else(|| {
            self.mark_inactive();
            "tecPATH_DRY"
        })?;

        Ok(self.remember_quote(&quote))
    }

    fn fwd(
        &mut self,
        state: &mut LedgerState,
        offered_in: &FlowAmount,
    ) -> Result<StepResult, &'static str> {
        if offered_in.issue() != Some(self.book.in_issue.clone()) || offered_in.is_zero() {
            self.mark_inactive();
            return Err("tecPATH_DRY");
        }

        let pool = self.pool(state)?;
        let quote = quote_exact_in_bounded(&pool, offered_in.as_amount()).ok_or_else(|| {
            self.mark_inactive();
            "tecPATH_DRY"
        })?;

        self.apply_quote(state, &pool, &quote)
    }

    fn valid_fwd(
        &mut self,
        state: &mut LedgerState,
        offered_in: &FlowAmount,
    ) -> Result<StepResult, &'static str> {
        if offered_in.issue() != Some(self.book.in_issue.clone()) || offered_in.is_zero() {
            self.mark_inactive();
            return Err("tecPATH_DRY");
        }

        let Some(cached_out) = self.cached_out.clone() else {
            return self.fwd(state, offered_in);
        };
        let pool = self.pool(state)?;
        let quote = quote_exact_out_bounded(&pool, cached_out.as_amount()).ok_or_else(|| {
            self.mark_inactive();
            "tecPATH_DRY"
        })?;
        if compare_amounts(&quote.spent_in, offered_in.as_amount()) == std::cmp::Ordering::Greater {
            self.mark_inactive();
            return Err("tecPATH_DRY");
        }

        self.apply_quote(state, &pool, &quote)
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

    fn quality_upper_bound(&self, state: &LedgerState) -> Option<FlowQuality> {
        let pool = if self.close_time == 0 {
            crate::ledger::tx::amm_step::load_amm_pool(
                state,
                &self.book.in_issue,
                &self.book.out_issue,
            )
        } else {
            crate::ledger::tx::amm_step::load_amm_pool_for_account(
                state,
                &self.book.in_issue,
                &self.book.out_issue,
                &self.taker,
                self.close_time,
            )
        }?;
        quality_upper_bound_from_pool(&pool)
    }

    fn quality_function(&self, state: &LedgerState) -> Option<QualityFunction> {
        let pool = if self.close_time == 0 {
            crate::ledger::tx::amm_step::load_amm_pool(
                state,
                &self.book.in_issue,
                &self.book.out_issue,
            )
        } else {
            crate::ledger::tx::amm_step::load_amm_pool_for_account(
                state,
                &self.book.in_issue,
                &self.book.out_issue,
                &self.taker,
                self.close_time,
            )
        }?;
        quality_function_from_pool(&pool)
    }
}

fn quote_exact_in_bounded(
    pool: &crate::ledger::tx::amm_step::AmmPool,
    offered_in: &Amount,
) -> Option<crate::ledger::tx::amm_step::AmmQuote> {
    let quote = crate::ledger::tx::amm_step::quote_exact_in(pool, offered_in)?;
    let max_out = crate::ledger::tx::amm_step::max_swap_output(pool)?;
    if compare_amounts(&quote.delivered_out, &max_out) != std::cmp::Ordering::Greater {
        return Some(quote);
    }

    let capped = crate::ledger::tx::amm_step::quote_exact_out(pool, &max_out)?;
    if compare_amounts(&capped.spent_in, offered_in) == std::cmp::Ordering::Greater {
        return None;
    }
    Some(capped)
}

fn quote_exact_out_bounded(
    pool: &crate::ledger::tx::amm_step::AmmPool,
    requested_out: &Amount,
) -> Option<crate::ledger::tx::amm_step::AmmQuote> {
    let max_out = crate::ledger::tx::amm_step::max_swap_output(pool)?;
    let target_out = if compare_amounts(requested_out, &max_out) == std::cmp::Ordering::Greater {
        max_out
    } else {
        requested_out.clone()
    };
    crate::ledger::tx::amm_step::quote_exact_out(pool, &target_out)
}

#[allow(dead_code)]
pub(crate) fn quality_upper_bound_from_pool(
    pool: &crate::ledger::tx::amm_step::AmmPool,
) -> Option<FlowQuality> {
    quality_function_from_pool(pool).map(|qf| qf.quality())
}

#[allow(dead_code)]
pub(crate) fn quality_function_from_pool(
    pool: &crate::ledger::tx::amm_step::AmmPool,
) -> Option<QualityFunction> {
    QualityFunction::amm(&pool.reserve_in, &pool.reserve_out, pool.trading_fee)
}

fn can_debit_amm_input(state: &mut LedgerState, account: &[u8; 20], amount: &Amount) -> bool {
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
            let key = crate::ledger::trustline::shamap_key(account, issuer, currency);
            let line = if let Some(existing) = state.get_trustline(&key) {
                existing.clone()
            } else if let Some(raw) = state
                .get_raw_owned(&key)
                .or_else(|| state.get_committed_raw_owned(&key))
            {
                let Some(decoded) = crate::ledger::RippleState::decode_from_sle(&raw) else {
                    return false;
                };
                state.hydrate_trustline(decoded.clone());
                decoded
            } else {
                return false;
            };
            compare_iou_values(&line.balance_for(account), value) != std::cmp::Ordering::Less
        }
        Amount::Mpt(_) => false,
    }
}

fn can_credit_amm_output(state: &mut LedgerState, account: &[u8; 20], amount: &Amount) -> bool {
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
            let key = crate::ledger::trustline::shamap_key(account, issuer, currency);
            let line = if let Some(existing) = state.get_trustline(&key) {
                existing.clone()
            } else if let Some(raw) = state
                .get_raw_owned(&key)
                .or_else(|| state.get_committed_raw_owned(&key))
            {
                let Some(decoded) = crate::ledger::RippleState::decode_from_sle(&raw) else {
                    return false;
                };
                state.hydrate_trustline(decoded.clone());
                decoded
            } else {
                return false;
            };
            if trustline_frozen_by_issuer(&line, issuer) || trustline_has_deep_freeze(&line) {
                return false;
            }
            if issuer_requires_auth_without_line_auth(state, issuer, account, &line) {
                return false;
            }
            let limit = if account == &line.low_account {
                line.low_limit
            } else {
                line.high_limit
            };
            let room = limit.sub(&line.balance_for(account));
            compare_iou_values(&room, value) != std::cmp::Ordering::Less
        }
        Amount::Mpt(_) => false,
    }
}

fn issuer_requires_auth(state: &LedgerState, issuer: &[u8; 20]) -> bool {
    state
        .get_account(issuer)
        .map(|account| (account.flags & crate::ledger::account::LSF_REQUIRE_AUTH) != 0)
        .unwrap_or(false)
}

fn issuer_requires_auth_without_line_auth(
    state: &LedgerState,
    issuer: &[u8; 20],
    holder: &[u8; 20],
    line: &crate::ledger::RippleState,
) -> bool {
    let Some(issuer_account) = state.get_account(issuer) else {
        return false;
    };
    (issuer_account.flags & crate::ledger::account::LSF_REQUIRE_AUTH) != 0
        && (line.flags & trustline_auth_flag_for(issuer, holder)) == 0
        && line.balance.is_zero()
}

fn issuer_global_frozen(state: &LedgerState, issuer: &[u8; 20]) -> bool {
    state
        .get_account(issuer)
        .map(|account| (account.flags & crate::ledger::account::LSF_GLOBAL_FREEZE) != 0)
        .unwrap_or(false)
}

fn trustline_auth_flag_for(issuer: &[u8; 20], holder: &[u8; 20]) -> u32 {
    if issuer > holder {
        crate::ledger::trustline::LSF_HIGH_AUTH
    } else {
        crate::ledger::trustline::LSF_LOW_AUTH
    }
}

fn trustline_has_deep_freeze(line: &crate::ledger::RippleState) -> bool {
    (line.flags
        & (crate::ledger::trustline::LSF_LOW_DEEP_FREEZE
            | crate::ledger::trustline::LSF_HIGH_DEEP_FREEZE))
        != 0
}

fn trustline_frozen_by_issuer(line: &crate::ledger::RippleState, issuer: &[u8; 20]) -> bool {
    if issuer == &line.low_account {
        (line.flags & crate::ledger::trustline::LSF_LOW_FREEZE) != 0
    } else if issuer == &line.high_account {
        (line.flags & crate::ledger::trustline::LSF_HIGH_FREEZE) != 0
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{AccountRoot, LedgerState, RippleState};
    use crate::transaction::amount::{Currency, IouValue, Issue};

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

    fn usd_issue() -> Issue {
        Issue::Iou {
            currency: Currency::from_code("USD").unwrap(),
            issuer: [0xAA; 20],
        }
    }

    fn usd_amount(value: f64) -> Amount {
        Amount::Iou {
            value: IouValue::from_f64(value),
            currency: Currency::from_code("USD").unwrap(),
            issuer: [0xAA; 20],
        }
    }

    fn amm_pool(
        asset_in: Issue,
        reserve_in: Amount,
        asset_out: Issue,
        reserve_out: Amount,
    ) -> crate::ledger::tx::amm_step::AmmPool {
        crate::ledger::tx::amm_step::AmmPool {
            pseudo_account: [0xBB; 20],
            asset_in,
            asset_out,
            reserve_in,
            reserve_out,
            trading_fee: 0,
        }
    }

    fn amm_sle(pseudo_account: [u8; 20], asset1: &Issue, asset2: &Issue) -> Vec<u8> {
        use crate::ledger::meta::ParsedField;

        crate::ledger::meta::build_sle(
            0x0079,
            &[
                ParsedField {
                    type_code: 8,
                    field_code: 1,
                    data: pseudo_account.to_vec(),
                },
                ParsedField {
                    type_code: 1,
                    field_code: 5,
                    data: 0u16.to_be_bytes().to_vec(),
                },
                ParsedField {
                    type_code: 24,
                    field_code: 3,
                    data: asset1.to_bytes(),
                },
                ParsedField {
                    type_code: 24,
                    field_code: 4,
                    data: asset2.to_bytes(),
                },
            ],
            None,
            None,
        )
    }

    fn state_with_xrp_usd_pool() -> (LedgerState, FlowBook, [u8; 20], [u8; 20]) {
        let mut state = LedgerState::new();
        let taker = [0x11; 20];
        let recipient = [0x22; 20];
        let pseudo = [0xBB; 20];
        let issuer = [0xAA; 20];
        let usd = Currency::from_code("USD").unwrap();
        let usd_issue = Issue::Iou {
            currency: usd.clone(),
            issuer,
        };

        state.insert_account(account(taker, 1_000_000_000));
        state.insert_account(account(recipient, 0));
        state.insert_account(account(issuer, 0));
        state.insert_account(account(pseudo, 10_000_000_000));

        let mut pool_line = RippleState::new(&pseudo, &issuer, usd.clone());
        pool_line.transfer(&issuer, &IouValue::from_f64(1_000.0));
        state.insert_trustline(pool_line);

        let mut recipient_line = RippleState::new(&recipient, &issuer, usd);
        recipient_line.set_limit_for(&recipient, IouValue::from_f64(2_000.0));
        state.insert_trustline(recipient_line);

        let key = crate::ledger::tx::amm::amm_key(&Issue::Xrp, &usd_issue);
        state.insert_raw(key, amm_sle(pseudo, &Issue::Xrp, &usd_issue));

        (
            state,
            FlowBook::new(Issue::Xrp, usd_issue),
            taker,
            recipient,
        )
    }

    fn issuer_freeze_flag_for(line: &RippleState, issuer: &[u8; 20]) -> u32 {
        if issuer == &line.low_account {
            crate::ledger::trustline::LSF_LOW_FREEZE
        } else {
            crate::ledger::trustline::LSF_HIGH_FREEZE
        }
    }

    #[test]
    fn amm_output_credit_rejects_global_frozen_issuer() {
        let (mut state, _, _, recipient) = state_with_xrp_usd_pool();
        let issuer = [0xAA; 20];
        let mut issuer_account = state.get_account(&issuer).unwrap().clone();
        issuer_account.flags |= crate::ledger::account::LSF_GLOBAL_FREEZE;
        state.insert_account(issuer_account);

        assert!(!can_credit_amm_output(
            &mut state,
            &recipient,
            &usd_amount(1.0)
        ));
    }

    #[test]
    fn amm_output_credit_rejects_issuer_side_frozen_line() {
        let (mut state, _, _, recipient) = state_with_xrp_usd_pool();
        let issuer = [0xAA; 20];
        let currency = Currency::from_code("USD").unwrap();
        let key = crate::ledger::trustline::shamap_key(&recipient, &issuer, &currency);
        let mut line = state.get_trustline(&key).unwrap().clone();
        line.flags |= issuer_freeze_flag_for(&line, &issuer);
        state.insert_trustline(line);

        assert!(!can_credit_amm_output(
            &mut state,
            &recipient,
            &usd_amount(1.0)
        ));
    }

    #[test]
    fn amm_output_credit_rejects_deep_frozen_line() {
        let (mut state, _, _, recipient) = state_with_xrp_usd_pool();
        let issuer = [0xAA; 20];
        let currency = Currency::from_code("USD").unwrap();
        let key = crate::ledger::trustline::shamap_key(&recipient, &issuer, &currency);
        let mut line = state.get_trustline(&key).unwrap().clone();
        line.flags |= crate::ledger::trustline::LSF_LOW_DEEP_FREEZE;
        state.insert_trustline(line);

        assert!(!can_credit_amm_output(
            &mut state,
            &recipient,
            &usd_amount(1.0)
        ));
    }

    #[test]
    fn amm_output_credit_rejects_unauthorized_zero_balance_line() {
        let (mut state, _, _, recipient) = state_with_xrp_usd_pool();
        let issuer = [0xAA; 20];
        let mut issuer_account = state.get_account(&issuer).unwrap().clone();
        issuer_account.flags |= crate::ledger::account::LSF_REQUIRE_AUTH;
        state.insert_account(issuer_account);
        let currency = Currency::from_code("USD").unwrap();
        let key = crate::ledger::trustline::shamap_key(&recipient, &issuer, &currency);
        let mut line = state.get_trustline(&key).unwrap().clone();
        line.balance = IouValue::ZERO;
        state.insert_trustline(line);

        assert!(!can_credit_amm_output(
            &mut state,
            &recipient,
            &usd_amount(1.0)
        ));
    }

    #[test]
    fn amm_output_credit_requires_existing_trustline() {
        let (mut state, _, _, recipient) = state_with_xrp_usd_pool();
        let issuer = [0xAA; 20];
        let currency = Currency::from_code("USD").unwrap();
        let key = crate::ledger::trustline::shamap_key(&recipient, &issuer, &currency);
        state.remove_trustline(&key);

        assert!(!can_credit_amm_output(
            &mut state,
            &recipient,
            &usd_amount(1.0)
        ));
    }

    #[test]
    fn amm_output_credit_respects_destination_limit_room() {
        let (mut state, _, _, recipient) = state_with_xrp_usd_pool();
        let issuer = [0xAA; 20];
        let currency = Currency::from_code("USD").unwrap();
        let key = crate::ledger::trustline::shamap_key(&recipient, &issuer, &currency);
        let mut line = state.get_trustline(&key).unwrap().clone();
        line.set_limit_for(&recipient, IouValue::from_f64(0.5));
        state.insert_trustline(line);

        assert!(!can_credit_amm_output(
            &mut state,
            &recipient,
            &usd_amount(1.0)
        ));
    }

    #[test]
    fn amm_xrp_input_debit_preserves_owner_reserve() {
        let (mut state, _, taker, _) = state_with_xrp_usd_pool();
        let fees = crate::ledger::read_fees(&state);
        let mut account = state.get_account(&taker).unwrap().clone();
        account.balance = fees.reserve + fees.increment + 50;
        account.owner_count = 1;
        state.insert_account(account);

        assert!(can_debit_amm_input(&mut state, &taker, &Amount::Xrp(50)));
        assert!(!can_debit_amm_input(&mut state, &taker, &Amount::Xrp(51)));
    }

    #[test]
    fn fwd_after_rev_uses_exact_in_not_stale_exact_out_cache() {
        let (mut state, book, taker, recipient) = state_with_xrp_usd_pool();
        let mut step = AmmStep::new(book, taker, recipient);

        let reverse = step
            .rev(&mut state, &FlowAmount::new(usd_amount(10.0)))
            .unwrap();
        assert_eq!(reverse.output, FlowAmount::new(usd_amount(10.0)));

        let forward = step
            .fwd(&mut state, &FlowAmount::new(Amount::Xrp(200_000_000)))
            .unwrap();

        assert_eq!(forward.input, FlowAmount::new(Amount::Xrp(200_000_000)));
        assert_eq!(
            compare_amounts(forward.output.as_amount(), &usd_amount(10.0)),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn valid_fwd_after_rev_preserves_exact_out_replay() {
        let (mut state, book, taker, recipient) = state_with_xrp_usd_pool();
        let mut step = AmmStep::new(book, taker, recipient);

        let reverse = step
            .rev(&mut state, &FlowAmount::new(usd_amount(10.0)))
            .unwrap();
        let replay = step
            .valid_fwd(&mut state, &FlowAmount::new(Amount::Xrp(200_000_000)))
            .unwrap();

        assert_eq!(replay.input, reverse.input);
        assert_eq!(replay.output, FlowAmount::new(usd_amount(10.0)));
    }

    #[test]
    fn exact_in_quote_is_capped_to_rippled_max_offer_shape() {
        let pool = amm_pool(
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
            usd_issue(),
            usd_amount(1_000.0),
        );

        let quote = quote_exact_in_bounded(&pool, &Amount::Xrp(2_000_000_000_000)).unwrap();

        assert_eq!(quote.delivered_out, usd_amount(990.0));
        assert_eq!(
            compare_amounts(&quote.spent_in, &Amount::Xrp(2_000_000_000_000)),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn exact_out_quote_over_pool_cap_returns_partial_max_offer() {
        let pool = amm_pool(
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
            usd_issue(),
            usd_amount(1_000.0),
        );

        let quote = quote_exact_out_bounded(&pool, &usd_amount(999.0)).unwrap();

        assert_eq!(quote.delivered_out, usd_amount(990.0));
    }

    #[test]
    fn pool_quality_helpers_expose_spot_and_variable_function() {
        let pool = amm_pool(
            Issue::Xrp,
            Amount::Xrp(10_000_000_000),
            usd_issue(),
            usd_amount(1_000.0),
        );

        assert!(quality_upper_bound_from_pool(&pool).is_some());
        let qf = quality_function_from_pool(&pool).unwrap();
        assert!(!qf.is_constant());
        assert_eq!(qf.quality(), quality_upper_bound_from_pool(&pool).unwrap());
    }
}
