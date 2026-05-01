//! xLedgRS purpose: Serialize support for transaction parsing and submission.
//! XRPL canonical binary serialization (STObject format).
//!
//! Used to produce the byte sequence that gets hashed for transaction signing.
//!
//! Signing hash prefixes (4 bytes prepended before hashing):
//!   Single-sign:  0x53545800  ("STX\0")
//!   Multi-sign:   0x534D5400  ("SMT\0")
//!
//! Variable-length field length encoding:
//!   0–192:        1 byte  = len
//!   193–12480:    2 bytes = 193 + ((len - 193) >> 8), (len - 193) & 0xFF
//!   12481–918744: 3 bytes = 241 + ((len - 12481) >> 16), ...

use crate::transaction::amount::Amount;
use crate::transaction::field::FieldDef;

/// Hash prefix for single-signed transactions.
pub const PREFIX_TX_SIGN: [u8; 4] = [0x53, 0x54, 0x58, 0x00];
/// Hash prefix for transaction identity (ID) hash.
pub const PREFIX_TX_ID: [u8; 4] = [0x54, 0x58, 0x4E, 0x00];
/// Hash prefix for multi-signed transactions.
pub const PREFIX_TX_MULTISIGN: [u8; 4] = [0x53, 0x4D, 0x54, 0x00];
/// Hash prefix for validations.
pub const PREFIX_VALIDATION: [u8; 4] = [0x56, 0x41, 0x4C, 0x00];
/// Hash prefix for proposals.
pub const PREFIX_PROPOSAL: [u8; 4] = [0x50, 0x52, 0x50, 0x00];

// ── Length encoding ───────────────────────────────────────────────────────────

/// Encode a variable-length field's byte count into XRPL length prefix format.
pub fn encode_length(len: usize, buf: &mut Vec<u8>) {
    if len <= 192 {
        buf.push(len as u8);
    } else if len <= 12480 {
        let adj = len - 193;
        buf.push(193 + (adj >> 8) as u8);
        buf.push((adj & 0xFF) as u8);
    } else if len <= 918744 {
        let adj = len - 12481;
        buf.push(241 + (adj >> 16) as u8);
        buf.push(((adj >> 8) & 0xFF) as u8);
        buf.push((adj & 0xFF) as u8);
    } else {
        panic!("field too large to encode: {} bytes", len);
    }
}

/// Decode a variable-length prefix, returning (length, bytes_consumed).
/// Returns (0, 0) on insufficient data to avoid panics on malformed input.
pub fn decode_length(data: &[u8]) -> (usize, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    let b0 = data[0] as usize;
    if b0 <= 192 {
        (b0, 1)
    } else if b0 <= 240 {
        if data.len() < 2 {
            return (0, 0);
        }
        let b1 = data[1] as usize;
        (193 + ((b0 - 193) << 8) + b1, 2)
    } else {
        if data.len() < 3 {
            return (0, 0);
        }
        let b1 = data[1] as usize;
        let b2 = data[2] as usize;
        (12481 + ((b0 - 241) << 16) + (b1 << 8) + b2, 3)
    }
}

// ── Serializer ────────────────────────────────────────────────────────────────

/// A single field value ready for serialization.
#[derive(Debug, Clone)]
pub enum FieldValue {
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    Hash128([u8; 16]),
    Hash160([u8; 20]),
    Hash256([u8; 32]),
    Amount(Amount),
    Blob(Vec<u8>),
    AccountID([u8; 20]),
}

impl FieldValue {
    /// Serialize the value into `buf` (without field ID prefix).
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        match self {
            FieldValue::UInt8(v) => buf.push(*v),
            FieldValue::UInt16(v) => buf.extend_from_slice(&v.to_be_bytes()),
            FieldValue::UInt32(v) => buf.extend_from_slice(&v.to_be_bytes()),
            FieldValue::UInt64(v) => buf.extend_from_slice(&v.to_be_bytes()),
            FieldValue::Hash128(v) => buf.extend_from_slice(v),
            FieldValue::Hash160(v) => buf.extend_from_slice(v),
            FieldValue::Hash256(v) => buf.extend_from_slice(v),
            FieldValue::Amount(a) => buf.extend_from_slice(&a.to_bytes()),
            FieldValue::Blob(v) => {
                encode_length(v.len(), buf);
                buf.extend_from_slice(v);
            }
            FieldValue::AccountID(v) => {
                encode_length(20, buf);
                buf.extend_from_slice(v);
            }
        }
    }
}

/// A (field, value) pair to be serialized.
#[derive(Debug, Clone)]
pub struct Field {
    pub def: FieldDef,
    pub value: FieldValue,
}

/// Serialize a list of fields in canonical (sorted) order into a byte buffer.
///
/// Pass `signing = true` to exclude non-signing fields (like TxnSignature).
pub fn serialize_fields(fields: &mut Vec<Field>, signing: bool) -> Vec<u8> {
    // Sort by (type_code, field_code) — required by the XRPL spec
    fields.sort_by_key(|f| f.def.sort_key());

    let mut buf = Vec::new();
    for field in fields.iter() {
        if signing && !field.def.is_signing {
            continue;
        }
        field.def.encode_id(&mut buf);
        field.value.write_to(&mut buf);
    }
    buf
}

/// Compute the signing hash for a single-signed transaction.
///
/// Hash = SHA-512-half(PREFIX_TX_SIGN || serialized_fields_for_signing)
pub fn signing_hash(fields: &mut Vec<Field>) -> [u8; 32] {
    let mut payload = PREFIX_TX_SIGN.to_vec();
    payload.extend_from_slice(&serialize_fields(fields, true));
    crate::crypto::sha512_first_half(&payload)
}

/// Compute the multi-sign hash for one signer.
///
/// Hash = SHA-512-half(PREFIX_TX_MULTISIGN || serialized_fields_for_signing || signer_account_id)
pub fn multisign_hash(fields: &mut Vec<Field>, signer_account: &[u8; 20]) -> [u8; 32] {
    let mut payload = PREFIX_TX_MULTISIGN.to_vec();
    payload.extend_from_slice(&serialize_fields(fields, true));
    payload.extend_from_slice(signer_account);
    crate::crypto::sha512_first_half(&payload)
}

/// Compute the transaction hash (ID) for a fully-signed transaction.
///
/// Hash = SHA-512-half(PREFIX_TX_ID || full_serialized_tx)
pub fn tx_hash(fields: &mut Vec<Field>) -> [u8; 32] {
    let mut payload = PREFIX_TX_ID.to_vec();
    payload.extend_from_slice(&serialize_fields(fields, false));
    crate::crypto::sha512_first_half(&payload)
}

/// Compute the transaction hash (ID) from an already serialized tx blob.
pub fn tx_blob_hash(blob: &[u8]) -> [u8; 32] {
    let mut payload = PREFIX_TX_ID.to_vec();
    payload.extend_from_slice(blob);
    crate::crypto::sha512_first_half(&payload)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::amount::Amount;
    use crate::transaction::field;

    #[test]
    fn test_length_encoding_roundtrip() {
        for len in [0, 1, 100, 192, 193, 1000, 12480, 12481, 50000] {
            let mut buf = Vec::new();
            encode_length(len, &mut buf);
            let (decoded, _) = decode_length(&buf);
            assert_eq!(decoded, len, "length round-trip failed for {len}");
        }
    }

    #[test]
    fn test_field_id_single_byte() {
        // type=1 (UInt16), field=2 → 0x12
        let f = field::TRANSACTION_TYPE; // type=1, field=2
        let mut buf = Vec::new();
        f.encode_id(&mut buf);
        assert_eq!(buf, vec![0x12]);
    }

    #[test]
    fn test_field_id_uint32_sequence() {
        // type=2 (UInt32), field=4 → 0x24
        let f = field::SEQUENCE;
        let mut buf = Vec::new();
        f.encode_id(&mut buf);
        assert_eq!(buf, vec![0x24]);
    }

    #[test]
    fn test_field_canonical_ordering() {
        // Fields should be sorted by (type_code, field_code)
        let mut fields = vec![
            Field {
                def: field::ACCOUNT,
                value: FieldValue::AccountID([0u8; 20]),
            },
            Field {
                def: field::SEQUENCE,
                value: FieldValue::UInt32(1),
            },
            Field {
                def: field::TRANSACTION_TYPE,
                value: FieldValue::UInt16(0),
            },
            Field {
                def: field::FEE,
                value: FieldValue::Amount(Amount::Xrp(12)),
            },
        ];
        serialize_fields(&mut fields, true);
        // After sort: TRANSACTION_TYPE(1,2), SEQUENCE(2,4), FEE(6,8), ACCOUNT(8,1)
        let sorted_names: Vec<_> = fields.iter().map(|f| f.def.name).collect();
        assert_eq!(
            sorted_names,
            ["TRANSACTION_TYPE", "SEQUENCE", "FEE", "ACCOUNT"]
        );
    }

    #[test]
    fn test_signing_hash_deterministic() {
        let mut fields1 = make_payment_fields();
        let mut fields2 = make_payment_fields();
        assert_eq!(signing_hash(&mut fields1), signing_hash(&mut fields2));
    }

    #[test]
    fn test_signing_excludes_txn_signature() {
        let mut fields_with_sig = make_payment_fields();
        fields_with_sig.push(Field {
            def: field::TXN_SIGNATURE,
            value: FieldValue::Blob(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        });
        let mut fields_without = make_payment_fields();

        // Signing hash should be the same whether TxnSignature is present or not
        assert_eq!(
            signing_hash(&mut fields_with_sig),
            signing_hash(&mut fields_without),
            "TxnSignature must be excluded from signing hash"
        );
    }

    fn make_payment_fields() -> Vec<Field> {
        vec![
            Field {
                def: field::TRANSACTION_TYPE,
                value: FieldValue::UInt16(0),
            }, // Payment
            Field {
                def: field::FLAGS,
                value: FieldValue::UInt32(0),
            },
            Field {
                def: field::SEQUENCE,
                value: FieldValue::UInt32(1),
            },
            Field {
                def: field::FEE,
                value: FieldValue::Amount(Amount::Xrp(12)),
            },
            Field {
                def: field::SIGNING_PUB_KEY,
                value: FieldValue::Blob(vec![0x02; 33]),
            },
            Field {
                def: field::ACCOUNT,
                value: FieldValue::AccountID([1u8; 20]),
            },
            Field {
                def: field::DESTINATION,
                value: FieldValue::AccountID([2u8; 20]),
            },
            Field {
                def: field::AMOUNT,
                value: FieldValue::Amount(Amount::Xrp(1_000_000)),
            },
        ]
    }
}
