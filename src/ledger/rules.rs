//! xLedgRS purpose: Rules support for XRPL ledger state and SHAMap logic.
//! Active amendment set for a ledger.

use std::collections::HashSet;

/// Active amendment rules for a ledger.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    /// Active amendment hashes, stored as SHA-512-half values of amendment names.
    pub amendments: HashSet<[u8; 32]>,
}

impl Rules {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a specific amendment is enabled.
    pub fn enabled(&self, amendment_hash: &[u8; 32]) -> bool {
        self.amendments.contains(amendment_hash)
    }

    /// Create from a list of amendment hashes.
    pub fn from_amendments(hashes: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            amendments: hashes.into_iter().collect(),
        }
    }
}
