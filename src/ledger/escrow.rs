//! Escrow — time-locked XRP held in a ledger object.
//!
//! An escrow locks XRP until a time condition is met:
//!   - `finish_after`: earliest time the escrow can be finished (recipient claims)
//!   - `cancel_after`: earliest time the escrow can be cancelled (sender reclaims)
//!
//! SHAMap key: `SHA-512-half(0x0075 || account || sequence)`

use serde::{Deserialize, Serialize};

use crate::crypto::{sha256, sha512_first_half};
use crate::ledger::Key;
use crate::transaction::Amount;

const ESCROW_SPACE: [u8; 2] = [0x00, 0x75];
const MAX_PREIMAGE_SHA256_LENGTH: usize = 128;
const MAX_SERIALIZED_CONDITION_PAYLOAD: usize = 128;
const MAX_SERIALIZED_FULFILLMENT_PAYLOAD: usize = 256;

/// Compute the SHAMap key for an escrow.
pub fn shamap_key(account: &[u8; 20], sequence: u32) -> Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&ESCROW_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(&sequence.to_be_bytes());
    Key(sha512_first_half(&data))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreimageSha256Condition {
    pub fingerprint: [u8; 32],
    pub cost: u32,
}

fn read_der_len(data: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *data.get(*pos)?;
    *pos += 1;
    let is_long_form = (first & 0x80) != 0;
    if !is_long_form {
        return Some(first as usize);
    }

    let bytes = (first & 0x7f) as usize;
    if bytes == 0 || bytes > std::mem::size_of::<usize>() || *pos + bytes > data.len() {
        return None;
    }

    let mut len = 0usize;
    for byte in &data[*pos..*pos + bytes] {
        len = len.checked_mul(256)?.checked_add(*byte as usize)?;
    }
    *pos += bytes;
    if len == 0 {
        return None;
    }
    Some(len)
}

fn expect_tagged<'a>(data: &'a [u8], pos: &mut usize, tag: u8) -> Option<&'a [u8]> {
    if *data.get(*pos)? != tag {
        return None;
    }
    *pos += 1;
    let len = read_der_len(data, pos)?;
    let end = (*pos).checked_add(len)?;
    if end > data.len() {
        return None;
    }
    let out = &data[*pos..end];
    *pos = end;
    Some(out)
}

pub fn parse_preimage_sha256_condition(data: &[u8]) -> Option<PreimageSha256Condition> {
    let mut pos = 0usize;
    let content = expect_tagged(data, &mut pos, 0xa0)?;
    if pos != data.len() {
        return None;
    }
    if content.len() > MAX_SERIALIZED_CONDITION_PAYLOAD {
        return None;
    }

    let mut inner_pos = 0usize;
    let fingerprint_bytes = expect_tagged(content, &mut inner_pos, 0x80)?;
    if fingerprint_bytes.len() != 32 {
        return None;
    }
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(fingerprint_bytes);

    let cost_bytes = expect_tagged(content, &mut inner_pos, 0x81)?;
    if cost_bytes.is_empty() || cost_bytes.len() > 5 || (cost_bytes[0] & 0x80) != 0 {
        return None;
    }
    if cost_bytes.len() == 5 && cost_bytes[0] != 0 {
        return None;
    }
    let mut cost = 0u32;
    for byte in cost_bytes {
        cost = cost.checked_mul(256)?.checked_add(*byte as u32)?;
    }
    if cost as usize > MAX_PREIMAGE_SHA256_LENGTH {
        return None;
    }
    if inner_pos != content.len() {
        return None;
    }

    Some(PreimageSha256Condition { fingerprint, cost })
}

pub fn parse_preimage_sha256_fulfillment(data: &[u8]) -> Option<&[u8]> {
    let mut pos = 0usize;
    let content = expect_tagged(data, &mut pos, 0xa0)?;
    if pos != data.len() {
        return None;
    }
    if content.len() > MAX_SERIALIZED_FULFILLMENT_PAYLOAD {
        return None;
    }

    let mut inner_pos = 0usize;
    let preimage = expect_tagged(content, &mut inner_pos, 0x80)?;
    if preimage.len() > MAX_PREIMAGE_SHA256_LENGTH {
        return None;
    }
    if inner_pos != content.len() {
        return None;
    }
    Some(preimage)
}

pub fn validate_preimage_sha256_fulfillment(fulfillment: &[u8], condition: &[u8]) -> bool {
    let Some(condition) = parse_preimage_sha256_condition(condition) else {
        return false;
    };
    let Some(preimage) = parse_preimage_sha256_fulfillment(fulfillment) else {
        return false;
    };
    condition.cost == preimage.len() as u32 && condition.fingerprint == sha256(preimage)
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

    pub fn decode_from_sle(data: &[u8]) -> Option<Self> {
        let parsed = crate::ledger::meta::parse_sle(data)?;
        if parsed.entry_type != 0x0075 {
            return None;
        }

        let field = |type_code: u16, field_code: u16| {
            parsed
                .fields
                .iter()
                .find(|f| f.type_code == type_code && f.field_code == field_code)
                .map(|f| f.data.as_slice())
        };
        let account = field_account(field(8, 1)?)?;
        let destination = field_account(field(8, 3)?)?;
        let held_amount = field(6, 1)
            .and_then(|raw| Amount::from_bytes(raw).ok())
            .map(|(amount, _)| amount)?;
        let amount = match &held_amount {
            Amount::Xrp(drops) => *drops,
            _ => 0,
        };
        let sequence = field_u32(field(2, 4)?)?;

        Some(Self {
            account,
            destination,
            amount,
            held_amount: Some(held_amount),
            sequence,
            finish_after: field(2, 37).and_then(field_u32).unwrap_or(0),
            cancel_after: field(2, 36).and_then(field_u32).unwrap_or(0),
            condition: field(7, 17).map(|raw| raw.to_vec()),
            owner_node: field(3, 4).and_then(field_u64).unwrap_or(0),
            destination_node: field(3, 9).and_then(field_u64).unwrap_or(0),
            source_tag: field(2, 3).and_then(field_u32),
            destination_tag: field(2, 14).and_then(field_u32),
            raw_sle: Some(data.to_vec()),
        })
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

fn field_account(data: &[u8]) -> Option<[u8; 20]> {
    if data.len() < 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&data[..20]);
    Some(out)
}

fn field_u32(data: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(..4)?.try_into().ok()?))
}

fn field_u64(data: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(data.get(..8)?.try_into().ok()?))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(n: u8) -> [u8; 20] {
        [n; 20]
    }

    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            return vec![len as u8];
        }
        let bytes = len.to_be_bytes();
        let first_non_zero = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let encoded = &bytes[first_non_zero..];
        let mut out = vec![0x80 | encoded.len() as u8];
        out.extend_from_slice(encoded);
        out
    }

    fn der_uint32(value: u32) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let first_non_zero = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let mut encoded = bytes[first_non_zero..].to_vec();
        if encoded[0] & 0x80 != 0 {
            encoded.insert(0, 0);
        }
        encoded
    }

    fn preimage_condition_with_cost(preimage: &[u8], cost: u32) -> Vec<u8> {
        let fingerprint = crate::crypto::sha256(preimage);
        let cost_bytes = der_uint32(cost);
        let cost_len = der_len(cost_bytes.len());
        let content_len = 2 + fingerprint.len() + 1 + cost_len.len() + cost_bytes.len();
        let mut out = vec![0xa0];
        out.extend_from_slice(&der_len(content_len));
        out.extend_from_slice(&[0x80, 32]);
        out.extend_from_slice(&fingerprint);
        out.push(0x81);
        out.extend_from_slice(&cost_len);
        out.extend_from_slice(&cost_bytes);
        out
    }

    fn preimage_condition(preimage: &[u8]) -> Vec<u8> {
        preimage_condition_with_cost(preimage, preimage.len() as u32)
    }

    fn preimage_fulfillment(preimage: &[u8]) -> Vec<u8> {
        let preimage_len = der_len(preimage.len());
        let content_len = 1 + preimage_len.len() + preimage.len();
        let mut out = vec![0xa0];
        out.extend_from_slice(&der_len(content_len));
        out.push(0x80);
        out.extend_from_slice(&preimage_len);
        out.extend_from_slice(preimage);
        out
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

    #[test]
    fn test_preimage_sha256_crypto_condition_validation() {
        let condition = preimage_condition(b"open-ledger");
        let fulfillment = preimage_fulfillment(b"open-ledger");

        assert!(parse_preimage_sha256_condition(&condition).is_some());
        assert_eq!(
            parse_preimage_sha256_fulfillment(&fulfillment),
            Some(&b"open-ledger"[..])
        );
        assert!(validate_preimage_sha256_fulfillment(
            &fulfillment,
            &condition
        ));
        assert!(!validate_preimage_sha256_fulfillment(
            &preimage_fulfillment(b"wrong"),
            &condition
        ));
        assert!(!validate_preimage_sha256_fulfillment(
            &fulfillment,
            &preimage_condition_with_cost(b"open-ledger", b"open-ledger".len() as u32 + 1)
        ));
    }

    #[test]
    fn test_docs_empty_preimage_condition_validates() {
        let condition = hex::decode(
            "A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100",
        )
        .unwrap();
        let fulfillment = hex::decode("A0028000").unwrap();

        assert!(validate_preimage_sha256_fulfillment(
            &fulfillment,
            &condition
        ));
    }

    #[test]
    fn test_preimage_sha256_rejects_rippled_limits_and_unsupported_types() {
        let max_preimage = vec![0x55; 128];
        assert!(validate_preimage_sha256_fulfillment(
            &preimage_fulfillment(&max_preimage),
            &preimage_condition(&max_preimage)
        ));

        let too_long_preimage = vec![0x55; 129];
        assert!(!validate_preimage_sha256_fulfillment(
            &preimage_fulfillment(&too_long_preimage),
            &preimage_condition_with_cost(&too_long_preimage, 129)
        ));
        assert!(
            parse_preimage_sha256_condition(&preimage_condition_with_cost(b"a", 129)).is_none()
        );

        let mut unsupported_prefix_condition = preimage_condition(b"a");
        unsupported_prefix_condition[0] = 0xa1;
        assert!(parse_preimage_sha256_condition(&unsupported_prefix_condition).is_none());
    }
}
