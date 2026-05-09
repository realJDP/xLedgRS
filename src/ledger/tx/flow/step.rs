use super::{FlowAmount, FlowBook, FlowQuality, QualityFunction};
use crate::ledger::LedgerState;

/// Optional book metadata exposed by liquidity steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StepBook {
    pub(crate) book: FlowBook,
}

/// Reverse/forward step result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StepResult {
    pub(crate) input: FlowAmount,
    pub(crate) output: FlowAmount,
    pub(crate) used_amm: bool,
}

impl StepResult {
    pub(crate) fn new(input: FlowAmount, output: FlowAmount) -> Self {
        Self {
            input,
            output,
            used_amm: false,
        }
    }

    pub(crate) fn with_amm(input: FlowAmount, output: FlowAmount) -> Self {
        Self {
            input,
            output,
            used_amm: true,
        }
    }
}

/// Common interface for DirectStep, BookStep, and AMM-backed liquidity.
pub(crate) trait FlowStep {
    fn rev(
        &mut self,
        state: &mut LedgerState,
        requested_out: &FlowAmount,
    ) -> Result<StepResult, &'static str>;

    fn fwd(
        &mut self,
        state: &mut LedgerState,
        offered_in: &FlowAmount,
    ) -> Result<StepResult, &'static str>;

    fn valid_fwd(
        &mut self,
        state: &mut LedgerState,
        offered_in: &FlowAmount,
    ) -> Result<StepResult, &'static str> {
        self.fwd(state, offered_in)
    }

    fn cached_in(&self) -> Option<&FlowAmount>;

    fn cached_out(&self) -> Option<&FlowAmount>;

    fn inactive(&self) -> bool {
        false
    }

    fn book(&self) -> Option<StepBook> {
        None
    }

    fn quality_upper_bound(&self, _state: &LedgerState) -> Option<FlowQuality> {
        None
    }

    fn quality_function(&self, _state: &LedgerState) -> Option<QualityFunction> {
        None
    }
}
