//! DepositPreauth — pre-authorization for deposits.
//!
//! Account A authorizes account B to send payments to A even when A has
//! the DepositAuth flag set.
//!
//! SHAMap key: `SHA-512-half(0x0070 || account || authorized)`

use serde::{Deserialize, Serialize};

use crate::crypto::sha512_first_half;
use crate::ledger::Key;

const DEPOSIT_PREAUTH_SPACE: [u8; 2] = [0x00, 0x70];

pub fn shamap_key(account: &[u8; 20], authorized: &[u8; 20]) -> Key {
    let mut data = Vec::with_capacity(42);
    data.extend_from_slice(&DEPOSIT_PREAUTH_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(authorized);
    Key(sha512_first_half(&data))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositPreauth {
    pub account: [u8; 20],
    pub authorized: [u8; 20],
    pub owner_node: u64,           // sfOwnerNode, default 0
    pub previous_txn_id: [u8; 32], // sfPreviousTxnID, default [0;32]
    pub previous_txn_lgrseq: u32,  // sfPreviousTxnLgrSeq, default 0
    /// Original binary SLE data — preserved for round-trip safety.
    #[serde(skip)]
    pub raw_sle: Option<Vec<u8>>,
}

impl DepositPreauth {
    pub fn to_sle_binary(&self) -> Vec<u8> {
        let raw = match &self.raw_sle {
            Some(r) => r,
            None => return self.encode(),
        };

        let mut sle = crate::ledger::sle::SLE::new(
            self.key(),
            crate::ledger::sle::LedgerEntryType::DepositPreauth,
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

        // Account (AccountID, 8, 1)
        sle.set_field_account(8, 1, &self.account);

        // Authorize (AccountID, 8, 5)
        sle.set_field_account(8, 5, &self.authorized);

        sle.into_data()
    }

    pub fn key(&self) -> Key {
        shamap_key(&self.account, &self.authorized)
    }

    pub fn encode(&self) -> Vec<u8> {
        crate::ledger::meta::build_sle(
            0x0070,
            &[
                crate::ledger::meta::ParsedField {
                    type_code: 8,
                    field_code: 1,
                    data: self.account.to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 8,
                    field_code: 5,
                    data: self.authorized.to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 3,
                    field_code: 4,
                    data: self.owner_node.to_be_bytes().to_vec(),
                },
            ],
            Some(self.previous_txn_id),
            Some(self.previous_txn_lgrseq),
        )
    }
}
