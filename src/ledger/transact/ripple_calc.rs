//! RippleCalc — IOU/cross-currency payment flow engine.
//!
//! Matches rippled's RippleCalc (RippleCalc.cpp, StrandFlow.h).
//!
//! This legacy helper was never completed. The maintained replay and close
//! path lives under `ledger::tx`, so callers in this module should reject
//! IOU payments instead of routing through a fake-success flow engine.
//!
//! If the legacy view-stack close is ever revived for independent validation,
//! this module still needs the full strand-based flow computation from rippled.
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
#[allow(dead_code)]
pub struct RippleCalcResult {
    pub success: bool,
    pub ter: &'static str,
    /// Amount actually delivered (may be less than requested for partial payments).
    pub delivered_amount: Option<Amount>,
}

/// Execute a ripple (IOU/cross-currency) payment through the flow engine.
///
/// Placeholder for the old view-stack transactor. It is intentionally unused by
/// current runtime code, which fails unsupported IOU payments earlier.
///
/// If an old path reaches this helper anyway, fail explicitly instead of
/// pretending the flow engine succeeded without touching state.
#[allow(dead_code)]
pub fn ripple_calculate(
    _view: &mut dyn ApplyView,
    _sender: &[u8; 20],
    _destination: &[u8; 20],
    _deliver_amount: &Amount,
    _send_max: Option<&Amount>,
    _paths: &[Vec<PathStep>],
    _flags: u32,
) -> RippleCalcResult {
    // A revived legacy transactor would still need the full flow engine:
    // 1. Build strands from paths
    // 2. For each strand: compute available liquidity
    // 3. Flow through strands, consuming offers and adjusting balances
    // 4. Apply transfer fees
    // 5. Handle partial payments
    RippleCalcResult {
        success: false,
        ter: "tecPATH_DRY",
        delivered_amount: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyView;

    impl crate::ledger::views::ReadView for DummyView {
        fn read(
            &self,
            _keylet: &crate::ledger::keylet::Keylet,
        ) -> Option<std::sync::Arc<crate::ledger::sle::SLE>> {
            None
        }

        fn succ(
            &self,
            _key: &crate::ledger::Key,
            _last: Option<&crate::ledger::Key>,
        ) -> Option<crate::ledger::Key> {
            None
        }

        fn info(&self) -> &crate::ledger::views::LedgerInfo {
            static INFO: std::sync::OnceLock<crate::ledger::views::LedgerInfo> =
                std::sync::OnceLock::new();
            INFO.get_or_init(crate::ledger::views::LedgerInfo::default)
        }

        fn fees(&self) -> &crate::ledger::fees::Fees {
            static FEES: std::sync::OnceLock<crate::ledger::fees::Fees> =
                std::sync::OnceLock::new();
            FEES.get_or_init(crate::ledger::fees::Fees::default)
        }

        fn rules(&self) -> &crate::ledger::rules::Rules {
            static RULES: std::sync::OnceLock<crate::ledger::rules::Rules> =
                std::sync::OnceLock::new();
            RULES.get_or_init(crate::ledger::rules::Rules::new)
        }
    }

    impl crate::ledger::views::ApplyView for DummyView {
        fn peek(
            &mut self,
            _keylet: &crate::ledger::keylet::Keylet,
        ) -> Option<std::sync::Arc<crate::ledger::sle::SLE>> {
            None
        }
        fn insert(&mut self, _sle: std::sync::Arc<crate::ledger::sle::SLE>) {}
        fn update(&mut self, _sle: std::sync::Arc<crate::ledger::sle::SLE>) {}
        fn erase(&mut self, _key: &crate::ledger::Key) {}
        fn apply_flags(&self) -> crate::ledger::views::ApplyFlags {
            crate::ledger::views::ApplyFlags::NONE
        }
    }

    #[test]
    fn ripple_calc_legacy_helper_fails_explicitly() {
        let mut view = DummyView;
        let result = ripple_calculate(
            &mut view,
            &[0x01; 20],
            &[0x02; 20],
            &Amount::Xrp(1),
            None,
            &[],
            0,
        );
        assert!(!result.success);
        assert_eq!(result.ter, "tecPATH_DRY");
        assert!(result.delivered_amount.is_none());
    }
}
