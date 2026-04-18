//! PayChannel — an off-chain XRP payment channel between two accounts.
//!
//! A payment channel locks XRP that can be claimed incrementally by the
//! destination using pre-signed authorizations from the channel's public key.
//!
//! SHAMap key: `SHA-512-half(0x0078 || account || destination || sequence)`

use serde::{Deserialize, Serialize};

use crate::crypto::sha512_first_half;
use crate::ledger::Key;

const PAYCHAN_SPACE: [u8; 2] = [0x00, 0x78];

/// Hash prefix for payment channel claim signatures: `"CLM\0"`.
pub const PREFIX_CLAIM: [u8; 4] = [0x43, 0x4C, 0x4D, 0x00];

/// Compute the SHAMap key for a payment channel.
pub fn shamap_key(account: &[u8; 20], destination: &[u8; 20], sequence: u32) -> Key {
    let mut payload = Vec::with_capacity(2 + 20 + 20 + 4);
    payload.extend_from_slice(&PAYCHAN_SPACE);
    payload.extend_from_slice(account);
    payload.extend_from_slice(destination);
    payload.extend_from_slice(&sequence.to_be_bytes());
    Key(sha512_first_half(&payload))
}

/// An off-chain XRP payment channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayChannel {
    /// Account that created (and funded) the channel.
    pub account: [u8; 20],
    /// Destination that can claim from the channel.
    pub destination: [u8; 20],
    /// Total XRP deposited in the channel (drops).
    pub amount: u64,
    /// Amount already claimed by the destination (drops).
    pub balance: u64,
    /// Seconds after a close request before the channel can be deleted.
    pub settle_delay: u32,
    /// Public key used to verify claim authorizations (33-byte compressed).
    pub public_key: Vec<u8>,
    /// Sequence number of the PaymentChannelCreate tx.
    pub sequence: u32,
    /// Optional: earliest close_time at which the channel can be cancelled.
    pub cancel_after: u32,
    /// Set after a close is requested: close_time + settle_delay.
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

impl PayChannel {
    pub fn to_sle_binary(&self) -> Vec<u8> {
        let raw = match &self.raw_sle {
            Some(r) => r,
            None => return self.encode(),
        };

        let mut sle = crate::ledger::sle::SLE::new(
            self.key(),
            crate::ledger::sle::LedgerEntryType::PayChannel,
            raw.clone(),
        );

        // Sequence (UInt32, 2, 4)
        if self.sequence != 0 {
            sle.set_sequence(self.sequence);
        }

        // Expiration (UInt32, 2, 10)
        if self.expiration != 0 {
            sle.set_field_u32(2, 10, self.expiration);
        } else {
            sle.remove_field(2, 10);
        }

        // CancelAfter (UInt32, 2, 36)
        if self.cancel_after != 0 {
            sle.set_field_u32(2, 36, self.cancel_after);
        } else {
            sle.remove_field(2, 36);
        }

        // SettleDelay (UInt32, 2, 39)
        sle.set_field_u32(2, 39, self.settle_delay);

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

        // Amount (Amount, 6, 1) — XRP
        sle.set_field_raw_pub(
            6,
            1,
            &crate::transaction::Amount::Xrp(self.amount).to_bytes(),
        );
        // Balance (Amount, 6, 2) — XRP
        sle.set_field_raw_pub(
            6,
            2,
            &crate::transaction::Amount::Xrp(self.balance).to_bytes(),
        );

        // PublicKey (VL, 7, 1)
        sle.set_field_raw_pub(7, 1, &self.public_key);

        // Account (AccountID, 8, 1)
        sle.set_field_account(8, 1, &self.account);
        // Destination (AccountID, 8, 3)
        sle.set_field_account(8, 3, &self.destination);

        sle.into_data()
    }

    pub fn key(&self) -> Key {
        shamap_key(&self.account, &self.destination, self.sequence)
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
                data: crate::transaction::Amount::Xrp(self.amount).to_bytes(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 6,
                field_code: 2,
                data: crate::transaction::Amount::Xrp(self.balance).to_bytes(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 7,
                field_code: 1,
                data: self.public_key.clone(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 39,
                data: self.settle_delay.to_be_bytes().to_vec(),
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
        if self.expiration != 0 {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 10,
                data: self.expiration.to_be_bytes().to_vec(),
            });
        }
        if self.cancel_after != 0 {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 36,
                data: self.cancel_after.to_be_bytes().to_vec(),
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

        crate::ledger::meta::build_sle(0x0078, &fields, None, None)
    }

    /// Verify a claim authorization signature.
    ///
    /// The signer authorizes `(channel_key, claimed_amount)` using the
    /// channel's public key: `sign(CLM\0 || channel_key || amount_be)`.
    ///
    /// For secp256k1 keys, `verify_secp256k1` internally SHA-512-Halfs the
    /// payload before ECDSA verification, matching rippled.
    /// For Ed25519 keys (0xED prefix), ed25519 verify is used directly on
    /// the raw payload (no pre-hashing), matching rippled.
    pub fn verify_claim(&self, claimed_drops: u64, signature: &[u8]) -> bool {
        let mut payload = PREFIX_CLAIM.to_vec();
        payload.extend_from_slice(&self.key().0);
        payload.extend_from_slice(&claimed_drops.to_be_bytes());

        if self.public_key.first() == Some(&0xED) && self.public_key.len() == 33 {
            // Ed25519: strip the 0xED prefix byte to get the 32-byte verifying key
            use ed25519_dalek::Verifier;
            let Ok(key_bytes): Result<[u8; 32], _> = self.public_key[1..].try_into() else {
                return false;
            };
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
                return false;
            };
            let Ok(sig_bytes): Result<[u8; 64], _> = signature.try_into() else {
                return false;
            };
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            vk.verify(&payload, &sig).is_ok()
        } else {
            // secp256k1: verify_secp256k1 does SHA-512-Half(payload) internally
            crate::crypto::keys::verify_secp256k1(&self.public_key, &payload, signature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(n: u8) -> [u8; 20] {
        [n; 20]
    }

    #[test]
    fn test_paychan_key_deterministic() {
        assert_eq!(
            shamap_key(&acct(1), &acct(2), 5),
            shamap_key(&acct(1), &acct(2), 5)
        );
    }

    #[test]
    fn test_different_channels_different_keys() {
        assert_ne!(
            shamap_key(&acct(1), &acct(2), 1),
            shamap_key(&acct(1), &acct(2), 2)
        );
    }

    #[test]
    fn test_verify_claim_roundtrip() {
        use crate::crypto::keys::Secp256k1KeyPair;

        let kp = Secp256k1KeyPair::generate();
        let chan = PayChannel {
            account: acct(1),
            destination: acct(2),
            amount: 10_000_000,
            balance: 0,
            settle_delay: 3600,
            public_key: kp.public_key_bytes(),
            sequence: 1,
            cancel_after: 0,
            expiration: 0,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };

        let claimed = 5_000_000u64;
        // Build the raw payload (no pre-hashing — verify_secp256k1 will hash it)
        let mut payload = PREFIX_CLAIM.to_vec();
        payload.extend_from_slice(&chan.key().0);
        payload.extend_from_slice(&claimed.to_be_bytes());
        let sig = kp.sign(&payload);

        assert!(chan.verify_claim(claimed, &sig));
        assert!(!chan.verify_claim(claimed + 1, &sig)); // wrong amount
    }
}
