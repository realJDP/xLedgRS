//! DID — Decentralized Identifier SLE.
//!
//! SHAMap key: `SHA-512-half(0x0049 || account)`
//! where 0x0049 is LedgerNameSpace::DID = 'I' = 0x49.

use serde::{Serialize, Deserialize};

use crate::crypto::sha512_first_half;
use crate::ledger::Key;

/// LedgerNameSpace::DID = 'I' = 0x49, stored as big-endian u16.
const DID_SPACE: [u8; 2] = [0x00, 0x49];

/// Compute the SHAMap key for a DID SLE (one per account).
pub fn shamap_key(account: &[u8; 20]) -> Key {
    let mut data = Vec::with_capacity(22);
    data.extend_from_slice(&DID_SPACE);
    data.extend_from_slice(account);
    Key(sha512_first_half(&data))
}

/// A Decentralized Identifier (DID) ledger object.
///
/// Fields from rippled: Account, DIDDocument (optional VL), URI (optional VL),
/// Data (optional VL), OwnerNode, PreviousTxnID, PreviousTxnLgrSeq.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Did {
    pub account:               [u8; 20],
    /// DIDDocument — optional variable-length blob.
    pub did_document:          Option<Vec<u8>>,
    /// URI — optional variable-length blob.
    pub uri:                   Option<Vec<u8>>,
    /// Data — optional variable-length blob.
    pub data:                  Option<Vec<u8>>,
    pub owner_node:            u64,
    pub previous_txn_id:       [u8; 32],
    pub previous_txn_lgrseq:   u32,
    /// Original binary SLE data — preserved for round-trip safety.
    #[serde(skip)]
    pub raw_sle:               Option<Vec<u8>>,
}

impl Did {
    pub fn to_sle_binary(&self) -> Vec<u8> {
        let raw = match &self.raw_sle {
            Some(r) => r,
            None => return self.encode(),
        };

        let mut sle = crate::ledger::sle::SLE::new(
            self.key(),
            crate::ledger::sle::LedgerEntryType::DID,
            raw.clone(),
        );

        // PreviousTxnID / PreviousTxnLgrSeq
        if self.previous_txn_id != [0u8; 32] {
            sle.set_previous_txn_id(&self.previous_txn_id);
        }
        if self.previous_txn_lgrseq > 0 {
            sle.set_previous_txn_lgr_seq(self.previous_txn_lgrseq);
        }

        // OwnerNode (UInt64, 3, 4)
        sle.set_field_u64(3, 4, self.owner_node);

        // URI (VL, 7, 5)
        if let Some(ref uri) = self.uri {
            sle.set_field_raw_pub(7, 5, uri);
        } else {
            sle.remove_field(7, 5);
        }

        // DIDDocument (VL, 7, 26)
        if let Some(ref doc) = self.did_document {
            sle.set_field_raw_pub(7, 26, doc);
        } else {
            sle.remove_field(7, 26);
        }

        // Data (VL, 7, 27)
        if let Some(ref data) = self.data {
            sle.set_field_raw_pub(7, 27, data);
        } else {
            sle.remove_field(7, 27);
        }

        // Account (AccountID, 8, 1)
        sle.set_field_account(8, 1, &self.account);

        sle.into_data()
    }

    pub fn key(&self) -> Key {
        shamap_key(&self.account)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut fields = vec![
            crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 1,
                data: self.account.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 4,
                data: self.owner_node.to_be_bytes().to_vec(),
            },
        ];

        if let Some(doc) = &self.did_document {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 7,
                field_code: 26,
                data: doc.clone(),
            });
        }
        if let Some(uri) = &self.uri {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 7,
                field_code: 5,
                data: uri.clone(),
            });
        }
        if let Some(data) = &self.data {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 7,
                field_code: 27,
                data: data.clone(),
            });
        }

        crate::ledger::meta::build_sle(
            0x0049,
            &fields,
            Some(self.previous_txn_id),
            Some(self.previous_txn_lgrseq),
        )
    }
}
