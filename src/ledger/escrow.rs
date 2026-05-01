//! xLedgRS purpose: Escrow support for XRPL ledger state and SHAMap logic.
//! Escrow — time-locked XRP held in a ledger object.
//!
//! An escrow locks XRP until a time condition is met:
//!   - `finish_after`: earliest time the escrow can be finished (recipient claims)
//!   - `cancel_after`: earliest time the escrow can be cancelled (sender reclaims)
//!
//! SHAMap key: `SHA-512-half(0x0075 || account || sequence)`

use serde::{Deserialize, Serialize};

use crate::crypto::sha512_first_half;
use crate::ledger::Key;
use crate::transaction::Amount;

const ESCROW_SPACE: [u8; 2] = [0x00, 0x75];

/// Compute the SHAMap key for an escrow.
pub fn shamap_key(account: &[u8; 20], sequence: u32) -> Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&ESCROW_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(&sequence.to_be_bytes());
    Key(sha512_first_half(&data))
}

/// A time-locked escrow holding XRP or a token amount.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Escrow {
    /// Account that created the escrow.
    pub account: [u8; 20],
    /// Destination that can finish (claim) the escrow.
    pub destination: [u8; 20],
    /// Amount in drops locked in the escrow.
    pub amount: u64,
    /// Full `Amount` field for IOU / MPT escrows. When absent, `amount`
    /// is encoded as XRP drops.
    #[serde(default)]
    pub held_amount: Option<Amount>,
    /// Sequence number of the EscrowCreate tx (also the escrow ID).
    pub sequence: u32,
    /// Earliest ledger close_time at which EscrowFinish is allowed (0 = no constraint).
    pub finish_after: u32,
    /// Earliest ledger close_time at which EscrowCancel is allowed (0 = no constraint).
    pub cancel_after: u32,
    /// Crypto-condition that must be fulfilled to finish the escrow (sfCondition).
    pub condition: Option<Vec<u8>>,
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

impl Escrow {
    pub fn key(&self) -> Key {
        shamap_key(&self.account, self.sequence)
    }

    pub fn amount_field(&self) -> Amount {
        self.held_amount.clone().unwrap_or(Amount::Xrp(self.amount))
    }

    pub fn to_sle_binary(&self) -> Vec<u8> {
        let raw = match &self.raw_sle {
            Some(r) => r,
            None => return self.encode(),
        };

        let mut sle = crate::ledger::sle::SLE::new(
            self.key(),
            crate::ledger::sle::LedgerEntryType::Escrow,
            raw.clone(),
        );

        // Sequence (UInt32, 2, 4)
        if self.sequence != 0 {
            sle.set_sequence(self.sequence);
        }

        // CancelAfter (UInt32, 2, 36)
        if self.cancel_after != 0 {
            sle.set_field_u32(2, 36, self.cancel_after);
        } else {
            sle.remove_field(2, 36);
        }

        // FinishAfter (UInt32, 2, 37)
        if self.finish_after != 0 {
            sle.set_field_u32(2, 37, self.finish_after);
        } else {
            sle.remove_field(2, 37);
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
        if self.destination_node != 0 {
            sle.set_field_u64(3, 9, self.destination_node);
        } else {
            sle.remove_field(3, 9);
        }

        // Amount (Amount, 6, 1) — XRP / IOU / MPT
        sle.set_field_raw_pub(6, 1, &self.amount_field().to_bytes());

        // Condition (VL, 7, 17)
        if let Some(ref condition) = self.condition {
            sle.set_field_raw_pub(7, 17, condition);
        } else {
            sle.remove_field(7, 17);
        }

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
                field_code: 1,
                data: self.amount_field().to_bytes(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 4,
                data: self.owner_node.to_be_bytes().to_vec(),
            },
        ];

        if self.sequence != 0 {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 4,
                data: self.sequence.to_be_bytes().to_vec(),
            });
        }
        if self.cancel_after != 0 {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 36,
                data: self.cancel_after.to_be_bytes().to_vec(),
            });
        }
        if self.finish_after != 0 {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 37,
                data: self.finish_after.to_be_bytes().to_vec(),
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
        if self.destination_node != 0 {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 9,
                data: self.destination_node.to_be_bytes().to_vec(),
            });
        }
        if let Some(condition) = &self.condition {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 7,
                field_code: 17,
                data: condition.clone(),
            });
        }

        crate::ledger::meta::build_sle(0x0075, &fields, None, None)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(n: u8) -> [u8; 20] {
        [n; 20]
    }

    #[test]
    fn test_escrow_key_deterministic() {
        assert_eq!(shamap_key(&acct(1), 5), shamap_key(&acct(1), 5));
    }

    #[test]
    fn test_different_escrows_different_keys() {
        assert_ne!(shamap_key(&acct(1), 1), shamap_key(&acct(1), 2));
        assert_ne!(shamap_key(&acct(1), 1), shamap_key(&acct(2), 1));
    }

    #[test]
    fn test_token_escrow_amount_roundtrips_to_sle() {
        let mptid = [0x33; 24];
        let escrow = Escrow {
            account: acct(1),
            destination: acct(2),
            amount: 0,
            held_amount: Some(Amount::from_mpt_value(55, mptid)),
            sequence: 7,
            finish_after: 0,
            cancel_after: 0,
            condition: None,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };
        let raw = escrow.to_sle_binary();
        let parsed = crate::ledger::meta::parse_sle(&raw).unwrap();
        let amount = parsed
            .fields
            .iter()
            .find(|field| field.type_code == 6 && field.field_code == 1)
            .map(|field| Amount::from_bytes(&field.data).unwrap().0)
            .unwrap();
        assert_eq!(amount, escrow.held_amount.unwrap());
    }
}
