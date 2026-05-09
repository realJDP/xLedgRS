use super::{compare_amounts, FlowAmount, FlowQuality, FlowStep, QualityFunction, StepResult};
use crate::ledger::tx::asset_flow::{apply_amount_delta, spendable_xrp_balance, AssetDelta};
use crate::ledger::LedgerState;
use crate::transaction::amount::Amount;

/// XRP endpoint step used when PaySteps normalizes an explicit path through an
/// XRP account boundary. IOU direct steps cannot represent this hop.
pub(crate) struct XrpEndpointStep {
    sender: [u8; 20],
    destination: [u8; 20],
    cached_in: Option<FlowAmount>,
    cached_out: Option<FlowAmount>,
}

impl XrpEndpointStep {
    pub(crate) fn new(sender: [u8; 20], destination: [u8; 20]) -> Self {
        Self {
            sender,
            destination,
            cached_in: None,
            cached_out: None,
        }
    }
}

impl FlowStep for XrpEndpointStep {
    fn rev(
        &mut self,
        state: &mut LedgerState,
        requested_out: &FlowAmount,
    ) -> Result<StepResult, &'static str> {
        let Amount::Xrp(drops) = requested_out.as_amount() else {
            return Err("tecPATH_DRY");
        };
        if *drops == 0 || state.get_account(&self.destination).is_none() {
            return Err("tecPATH_DRY");
        }
        let amount = FlowAmount::new(Amount::Xrp(*drops));
        self.cached_in = Some(amount.clone());
        self.cached_out = Some(amount.clone());
        Ok(StepResult::new(amount.clone(), amount))
    }

    fn fwd(
        &mut self,
        state: &mut LedgerState,
        offered_in: &FlowAmount,
    ) -> Result<StepResult, &'static str> {
        let amount = if let Some(cached_out) = self.cached_out.as_ref() {
            if compare_amounts(offered_in.as_amount(), cached_out.as_amount())
                == std::cmp::Ordering::Less
            {
                return Err("tecPATH_DRY");
            }
            cached_out.as_amount().clone()
        } else {
            offered_in.as_amount().clone()
        };

        let Amount::Xrp(drops) = amount else {
            return Err("tecPATH_DRY");
        };
        if drops == 0 {
            return Err("tecPATH_DRY");
        }
        let amount = Amount::Xrp(drops);
        if spendable_xrp_balance(state, &self.sender) < drops {
            return Err("tecPATH_DRY");
        }
        if !apply_amount_delta(state, &self.sender, AssetDelta::Debit, &amount)
            || !apply_amount_delta(state, &self.destination, AssetDelta::Credit, &amount)
        {
            return Err("tecPATH_DRY");
        }
        let flow_amount = FlowAmount::new(amount);
        self.cached_in = Some(flow_amount.clone());
        self.cached_out = Some(flow_amount.clone());
        Ok(StepResult::new(flow_amount.clone(), flow_amount))
    }

    fn cached_in(&self) -> Option<&FlowAmount> {
        self.cached_in.as_ref()
    }

    fn cached_out(&self) -> Option<&FlowAmount> {
        self.cached_out.as_ref()
    }

    fn quality_upper_bound(&self, _state: &LedgerState) -> Option<FlowQuality> {
        Some(FlowQuality::ONE)
    }

    fn quality_function(&self, _state: &LedgerState) -> Option<QualityFunction> {
        Some(QualityFunction::constant(FlowQuality::ONE))
    }
}
