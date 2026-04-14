//! Fee settings for a ledger — parsed from the FeeSettings SLE.

/// Fee configuration for the current ledger.
#[derive(Debug, Clone, Copy)]
pub struct Fees {
    /// Base transaction fee in drops.
    pub base_fee: u64,
    /// Account reserve (minimum balance) in drops.
    pub reserve_base: u64,
    /// Per-object reserve increment in drops.
    pub reserve_inc: u64,
}

impl Default for Fees {
    fn default() -> Self {
        Self {
            base_fee: 10,
            reserve_base: 1_000_000,   // 1 XRP (current mainnet)
            reserve_inc: 200_000,      // 0.2 XRP (current mainnet)
        }
    }
}
