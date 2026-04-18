//! Ticket — a reserved sequence number for future use.
//!
//! TicketCreate reserves one or more sequence numbers that can be used
//! out of order in future transactions. Each ticket stores the owning account
//! and the reserved sequence number.
//!
//! SHAMap key: `SHA-512-half(0x0054 || account || sequence)`

use serde::{Deserialize, Serialize};

use crate::crypto::sha512_first_half;
use crate::ledger::Key;

const TICKET_SPACE: [u8; 2] = [0x00, 0x54];

pub fn shamap_key(account: &[u8; 20], sequence: u32) -> Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&TICKET_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(&sequence.to_be_bytes());
    Key(sha512_first_half(&data))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub account: [u8; 20],
    pub sequence: u32,
    pub owner_node: u64,           // sfOwnerNode, default 0
    pub previous_txn_id: [u8; 32], // sfPreviousTxnID, default [0;32]
    pub previous_txn_lgrseq: u32,  // sfPreviousTxnLgrSeq, default 0
    /// Original binary SLE data — preserved for round-trip safety.
    #[serde(skip)]
    pub raw_sle: Option<Vec<u8>>,
}

impl Ticket {
    pub fn to_sle_binary(&self) -> Vec<u8> {
        let raw = match &self.raw_sle {
            Some(r) => r,
            None => return self.encode(),
        };

        let mut sle = crate::ledger::sle::SLE::new(
            self.key(),
            crate::ledger::sle::LedgerEntryType::Ticket,
            raw.clone(),
        );

        // TicketSequence (UInt32, 2, 41)
        sle.set_field_u32(2, 41, self.sequence);

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

        sle.into_data()
    }

    pub fn key(&self) -> Key {
        shamap_key(&self.account, self.sequence)
    }

    pub fn encode(&self) -> Vec<u8> {
        crate::ledger::meta::build_sle(
            0x0054,
            &[
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
                crate::ledger::meta::ParsedField {
                    type_code: 2,
                    field_code: 41,
                    data: self.sequence.to_be_bytes().to_vec(),
                },
            ],
            Some(self.previous_txn_id),
            Some(self.previous_txn_lgrseq),
        )
    }
}
