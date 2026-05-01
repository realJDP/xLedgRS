//! xLedgRS purpose: Check support for XRPL ledger state and SHAMap logic.
//! Check — a deferred payment instrument on the XRP Ledger.
//!
//! A check authorizes a destination to claim up to a specified amount of XRP.
//! Unlike escrow, the creator's balance is NOT locked at creation — it's
//! debited only when the check is cashed.
//!
//! SHAMap key: `SHA-512-half(0x0043 || account || sequence)`

use serde::{Deserialize, Serialize};

use crate::crypto::sha512_first_half;
use crate::ledger::Key;

const CHECK_SPACE: [u8; 2] = [0x00, 0x43];

pub fn shamap_key(account: &[u8; 20], sequence: u32) -> Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&CHECK_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(&sequence.to_be_bytes());
    Key(sha512_first_half(&data))
}

/// A deferred payment check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    /// Account that created the check.
    pub account: [u8; 20],
    /// Destination that can cash it.
    pub destination: [u8; 20],
    /// Maximum amount (XRP or IOU).
    pub send_max: crate::transaction::Amount,
    /// Sequence number of the CheckCreate tx.
    pub sequence: u32,
    /// 0 = no expiry, otherwise Ripple epoch timestamp.
    pub expiration: u32,
    /// Owner directory page index (default 0).
    pub owner_node: u64,
    /// Destination directory page index (default 0).
    pub destination_node: u64,
    /// Optional source tag.
    pub source_tag: Option<u32>,
    /// Optional destination tag.
    pub destination_tag: Option<u32>,
    /// Original binary SLE data — preserved for round-trip safety.
    #[serde(skip)]
    pub raw_sle: Option<Vec<u8>>,
}

impl Check {
    pub fn key(&self) -> Key {
        shamap_key(&self.account, self.sequence)
    }

    /// Produce binary SLE. Patches fields on preserved original if available, else encode().
    pub fn to_sle_binary(&self) -> Vec<u8> {
        let raw = match &self.raw_sle {
            Some(r) => r,
            None => return self.encode(),
        };

        let mut sle = crate::ledger::sle::SLE::new(
            self.key(),
            crate::ledger::sle::LedgerEntryType::Check,
            raw.clone(),
        );

        // Sequence (UInt32, 2, 4)
        sle.set_sequence(self.sequence);

        // Expiration (UInt32, 2, 10)
        if self.expiration != 0 {
            sle.set_field_u32(2, 10, self.expiration);
        } else {
            sle.remove_field(2, 10);
        }

        // SourceTag (UInt32, 2, 3)
        if let Some(tag) = self.source_tag {
            sle.set_field_u32(2, 3, tag);
        } else {
            sle.remove_field(2, 3);
        }

        // DestinationTag (UInt32, 2, 14)
        if let Some(tag) = self.destination_tag {
            sle.set_field_u32(2, 14, tag);
        } else {
            sle.remove_field(2, 14);
        }

        // OwnerNode (UInt64, 3, 4)
        sle.set_field_u64(3, 4, self.owner_node);
        // DestinationNode (UInt64, 3, 9)
        sle.set_field_u64(3, 9, self.destination_node);

        // SendMax (Amount, 6, 9)
        sle.set_field_raw_pub(6, 9, &self.send_max.to_bytes());

        // Account (AccountID, 8, 1)
        sle.set_field_account(8, 1, &self.account);
        // Destination (AccountID, 8, 3)
        sle.set_field_account(8, 3, &self.destination);

        sle.into_data()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut fields = vec![
            crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 1,
                data: self.account.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 3,
                data: self.destination.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 6,
                field_code: 9,
                data: self.send_max.to_bytes(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 4,
                data: self.sequence.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 4,
                data: self.owner_node.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 9,
                data: self.destination_node.to_be_bytes().to_vec(),
            },
        ];

        if self.expiration != 0 {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 10,
                data: self.expiration.to_be_bytes().to_vec(),
            });
        }
        if let Some(tag) = self.source_tag {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 3,
                data: tag.to_be_bytes().to_vec(),
            });
        }
        if let Some(tag) = self.destination_tag {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 14,
                data: tag.to_be_bytes().to_vec(),
            });
        }

        crate::ledger::meta::build_sle(0x0043, &fields, None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(n: u8) -> [u8; 20] {
        [n; 20]
    }

    #[test]
    fn test_check_key_deterministic() {
        assert_eq!(shamap_key(&acct(1), 5), shamap_key(&acct(1), 5));
    }

    #[test]
    fn test_different_checks_different_keys() {
        assert_ne!(shamap_key(&acct(1), 1), shamap_key(&acct(1), 2));
    }
}
