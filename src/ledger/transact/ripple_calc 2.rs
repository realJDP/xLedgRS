//! RippleCalc — IOU/cross-currency payment flow engine.
//!
//! Matches rippled's RippleCalc (RippleCalc.cpp, StrandFlow.h).
//!
//! For follower/replay mode: returns Success without modifying state.
//! The metadata patches from the validated ledger contain the exact correct
//! FinalFields for all affected objects.
//!
//! For independent validation: needs full strand-based flow computation.
//! This is the single largest missing feature (~2000+ lines in rippled).
//!
//! Implementation plan:
//! 1. Direct XRP→IOU and IOU→XRP via single offer book crossing
//! 2. IOU→IOU via single offer book
//! 3. Multi-hop paths via strand decomposition
//! 4. Transfer fees per hop
//! 5. Partial payments (tfPartialPayment flag)

use crate::ledger::views::ApplyView;
use crate::transaction::amount::Amount;
use crate::transaction::parse::PathStep;

/// Result of a ripple calculation.
pub struct RippleCalcResult {
    pub success: bool,
    pub ter: &'static str,
    /// Amount actually delivered (may be less than requested for partial payments).
    pub delivered_amount: Option<Amount>,
}

/// Execute a ripple (IOU/cross-currency) payment through the flow engine.
///
/// In replay mode, returns Success and lets metadata patches apply state.
/// For independent validation, this needs full implementation.
pub fn ripple_calculate(
    _view: &mut dyn ApplyView,
    _sender: &[u8; 20],
    _destination: &[u8; 20],
    _deliver_amount: &Amount,
    _send_max: Option<&Amount>,
    _paths: &[Vec<PathStep>],
    _flags: u32,
) -> RippleCalcResult {
    // Metadata patches handle all state changes for ripple payments.
    // Returning Success ensures the tx gets the correct result code
    // (fee consumed, sequence bumped) while the patches apply the
    // exact state the network agreed on.
    //
    // TODO: Implement full flow engine for independent validation:
    // 1. Build strands from paths
    // 2. For each strand: compute available liquidity
    // 3. Flow through strands, consuming offers and adjusting balances
    // 4. Apply transfer fees
    // 5. Handle partial payments
    RippleCalcResult {
        success: true,
        ter: "tesSUCCESS",
        delivered_amount: None,
    }
}
