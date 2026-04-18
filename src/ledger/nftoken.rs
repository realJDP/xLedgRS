//! NFToken — non-fungible tokens on the XRP Ledger.
//!
//! Simplified flat storage model (one entry per NFT) rather than the page
//! model used by rippled.

use crate::crypto::sha512_first_half;
use crate::ledger::Key;
use crate::transaction::amount::Amount;
use serde::{Deserialize, Serialize};

// ── NFTokenID construction ────────────────────────────────────────────────────

/// Construct a 32-byte NFTokenID.
///
/// Layout: flags(2) + transfer_fee(2) + issuer(20) + scrambled_taxon(4) + sequence(4)
pub fn make_nftoken_id(
    flags: u16,
    transfer_fee: u16,
    issuer: &[u8; 20],
    taxon: u32,
    sequence: u32,
) -> [u8; 32] {
    let scrambled = scramble_taxon(taxon, sequence);
    let mut id = [0u8; 32];
    id[0..2].copy_from_slice(&flags.to_be_bytes());
    id[2..4].copy_from_slice(&transfer_fee.to_be_bytes());
    id[4..24].copy_from_slice(issuer);
    id[24..28].copy_from_slice(&scrambled.to_be_bytes());
    id[28..32].copy_from_slice(&sequence.to_be_bytes());
    id
}

/// XRPL taxon scrambling: `(taxon ^ (384160001 * seq + 2459)) % 2^32`
fn scramble_taxon(taxon: u32, sequence: u32) -> u32 {
    let scramble = 384160001u64
        .wrapping_mul(sequence as u64)
        .wrapping_add(2459) as u32;
    taxon ^ scramble
}

// ── NFToken ───────────────────────────────────────────────────────────────────

/// Key space prefix for flat NFToken storage.
///
/// This is a simplified flat model that differs from rippled's page-based
/// NFTokenPage model. Because of this architectural difference, the SHAMap
/// will not match rippled for NFToken data specifically. This is a known
/// divergence — see the module-level docs.
const NFTOKEN_SPACE: [u8; 2] = [0x00, 0x50];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NFToken {
    /// The 32-byte NFTokenID (globally unique).
    pub nftoken_id: [u8; 32],
    /// Current owner (changes on transfer).
    pub owner: [u8; 20],
    /// Original minter (immutable).
    pub issuer: [u8; 20],
    /// Optional URI (set at mint, immutable).
    pub uri: Option<Vec<u8>>,
    /// Token flags (tfBurnable=0x0001, tfOnlyXRP=0x0002, tfTransferable=0x0008).
    pub flags: u16,
    /// Transfer fee in basis points (0-50000).
    pub transfer_fee: u16,
    /// Collection grouping.
    pub taxon: u32,
    // NOTE: The flat storage model does not store directory/provenance fields
    // (e.g. OwnerNode, PreviousTxnID, PreviousTxnLgrSeq) that rippled keeps
    // in the page-based NFTokenPage entries.
}

impl NFToken {
    pub fn shamap_key(&self) -> Key {
        Key(sha512_first_half(
            &[&NFTOKEN_SPACE[..], &self.nftoken_id].concat(),
        ))
    }
}

/// tfBurnable: issuer can burn even if not owner.
pub const TF_BURNABLE: u16 = 0x0001;
/// tfOnlyXRP: token can only be offered/sold for XRP.
pub const TF_ONLY_XRP: u16 = 0x0002;
/// tfCreateTrustLines: allow minting to create trust lines.
pub const TF_CREATE_TRUST_LINES: u16 = 0x0004;
/// tfTransferable: can be transferred to accounts other than issuer.
pub const TF_TRANSFERABLE: u16 = 0x0008;
/// tfMutable: token metadata can be mutated by the issuer.
pub const TF_MUTABLE: u16 = 0x0010;

// ── NFTokenOffer ──────────────────────────────────────────────────────────────

const NFT_OFFER_SPACE: [u8; 2] = [0x00, 0x71];

pub fn offer_shamap_key(account: &[u8; 20], sequence: u32) -> Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&NFT_OFFER_SPACE);
    data.extend_from_slice(account);
    data.extend_from_slice(&sequence.to_be_bytes());
    Key(sha512_first_half(&data))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NFTokenOffer {
    pub account: [u8; 20],
    pub sequence: u32,
    pub nftoken_id: [u8; 32],
    pub amount: Amount,
    pub destination: Option<[u8; 20]>,
    pub expiration: Option<u32>,
    /// 0x0001 = sell offer.
    pub flags: u32,
    pub owner_node: u64,           // sfOwnerNode, default 0
    pub nft_offer_node: u64,       // sfNFTokenOfferNode, default 0
    pub previous_txn_id: [u8; 32], // sfPreviousTxnID, default [0;32]
    pub previous_txn_lgrseq: u32,  // sfPreviousTxnLgrSeq, default 0
    /// Original binary SLE data — preserved for round-trip safety.
    #[serde(skip)]
    pub raw_sle: Option<Vec<u8>>,
}

impl NFTokenOffer {
    /// Decode an NFTokenOffer from raw SLE binary bytes.
    /// Preserves the original bytes in `raw_sle` for round-trip patching.
    pub fn decode_from_sle(data: &[u8]) -> Option<Self> {
        let parsed = crate::ledger::meta::parse_sle(data)?;
        let mut flags = 0u32;
        let mut sequence = 0u32;
        let mut owner_node = 0u64;
        let mut nft_offer_node = 0u64;
        let mut nftoken_id = [0u8; 32];
        let mut account = [0u8; 20];
        let mut destination: Option<[u8; 20]> = None;
        let mut expiration: Option<u32> = None;
        let mut amount = Amount::Xrp(0);

        for f in &parsed.fields {
            match (f.type_code, f.field_code) {
                (2, 2) if f.data.len() >= 4 => {
                    flags = u32::from_be_bytes(f.data[..4].try_into().ok()?)
                }
                (2, 4) if f.data.len() >= 4 => {
                    sequence = u32::from_be_bytes(f.data[..4].try_into().ok()?)
                }
                (2, 10) if f.data.len() >= 4 => {
                    expiration = Some(u32::from_be_bytes(f.data[..4].try_into().ok()?))
                }
                (3, 4) if f.data.len() >= 8 => {
                    owner_node = u64::from_be_bytes(f.data[..8].try_into().ok()?)
                }
                (3, 12) if f.data.len() >= 8 => {
                    nft_offer_node = u64::from_be_bytes(f.data[..8].try_into().ok()?)
                }
                (5, 10) if f.data.len() >= 32 => nftoken_id.copy_from_slice(&f.data[..32]),
                (6, 1) => {
                    let (p, _) = crate::transaction::amount::Amount::from_bytes(&f.data).ok()?;
                    amount = p;
                }
                (8, 2) if f.data.len() >= 20 => account.copy_from_slice(&f.data[..20]),
                (8, 3) if f.data.len() >= 20 => {
                    let mut d = [0u8; 20];
                    d.copy_from_slice(&f.data[..20]);
                    destination = Some(d);
                }
                _ => {}
            }
        }

        let mut previous_txn_id = [0u8; 32];
        if let Some(id) = parsed.prev_txn_id {
            previous_txn_id = id;
        }
        let previous_txn_lgrseq = parsed.prev_txn_lgrseq.unwrap_or(0);

        Some(NFTokenOffer {
            account,
            sequence,
            nftoken_id,
            amount,
            destination,
            expiration,
            flags,
            owner_node,
            nft_offer_node,
            previous_txn_id,
            previous_txn_lgrseq,
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
            crate::ledger::sle::LedgerEntryType::NFTokenOffer,
            raw.clone(),
        );

        // Flags (UInt32, 2, 2)
        sle.set_flags(self.flags);

        // NOTE: sfSequence is NOT serialized in NFTokenOffer SLE

        // PreviousTxnID / PreviousTxnLgrSeq
        if self.previous_txn_id != [0u8; 32] {
            sle.set_previous_txn_id(&self.previous_txn_id);
        }
        if self.previous_txn_lgrseq > 0 {
            sle.set_previous_txn_lgr_seq(self.previous_txn_lgrseq);
        }

        // Expiration (UInt32, 2, 10)
        if let Some(exp) = self.expiration {
            sle.set_field_u32(2, 10, exp);
        } else {
            sle.remove_field(2, 10);
        }

        // OwnerNode (UInt64, 3, 4)
        sle.set_field_u64(3, 4, self.owner_node);

        // NFTokenOfferNode (UInt64, 3, ?) — need to check field code
        // NFTokenID (Hash256, 5, 10)
        sle.set_field_h256(5, 10, &self.nftoken_id);

        // Amount (Amount, 6, 1)
        sle.set_field_raw_pub(6, 1, &self.amount.to_bytes());

        // Owner/Account (AccountID, 8, 2) — NFTokenOffer uses sfOwner not sfAccount
        sle.set_field_account(8, 2, &self.account);

        // Destination (AccountID, 8, 3) — optional
        if let Some(ref dest) = self.destination {
            sle.set_field_account(8, 3, dest);
        } else {
            sle.remove_field(8, 3);
        }

        sle.into_data()
    }

    pub fn key(&self) -> Key {
        offer_shamap_key(&self.account, self.sequence)
    }

    pub fn is_sell(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut fields = vec![
            crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 2,
                data: self.account.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 2,
                data: self.flags.to_be_bytes().to_vec(),
            },
            // sfSequence is NOT serialized in NFTokenOffer SLE — the sequence
            // is encoded in the key via offer_shamap_key(account, seq) but is
            // not a field in the on-ledger SLE. Including it produces 5 extra
            // bytes that diverge from rippled.
            crate::ledger::meta::ParsedField {
                type_code: 6,
                field_code: 1,
                data: self.amount.to_bytes(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 5,
                field_code: 10,
                data: self.nftoken_id.to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 4,
                data: self.owner_node.to_be_bytes().to_vec(),
            },
        ];

        if let Some(dest) = self.destination {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 3,
                data: dest.to_vec(),
            });
        }
        if let Some(exp) = self.expiration {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 10,
                data: exp.to_be_bytes().to_vec(),
            });
        }

        crate::ledger::meta::build_sle(
            0x0037,
            &fields,
            Some(self.previous_txn_id),
            Some(self.previous_txn_lgrseq),
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nftoken_id_deterministic() {
        let id1 = make_nftoken_id(0x0008, 0, &[1u8; 20], 42, 0);
        let id2 = make_nftoken_id(0x0008, 0, &[1u8; 20], 42, 0);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_sequence_different_id() {
        let id1 = make_nftoken_id(0, 0, &[1u8; 20], 0, 0);
        let id2 = make_nftoken_id(0, 0, &[1u8; 20], 0, 1);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_taxon_scrambling() {
        let s1 = scramble_taxon(0, 0);
        let s2 = scramble_taxon(0, 1);
        assert_ne!(
            s1, s2,
            "different sequences should produce different scrambled taxons"
        );
    }

    #[test]
    fn test_sle_round_trip_preserves_sf_sequence() {
        // Build a minimal NFTokenOffer SLE WITH sfSequence (type=2, field=4)
        use crate::ledger::meta::{build_sle, ParsedField};
        let seq: u32 = 1875; // 0x0753
        let fields = vec![
            ParsedField {
                type_code: 2,
                field_code: 2,
                data: 0x0001u32.to_be_bytes().to_vec(),
            }, // sfFlags
            ParsedField {
                type_code: 2,
                field_code: 4,
                data: seq.to_be_bytes().to_vec(),
            }, // sfSequence
            ParsedField {
                type_code: 6,
                field_code: 1,
                data: vec![0x40, 0, 0, 0, 0, 0, 0, 0],
            }, // sfAmount (0 XRP)
            ParsedField {
                type_code: 5,
                field_code: 10,
                data: vec![0xAA; 32],
            }, // sfNFTokenID
            ParsedField {
                type_code: 3,
                field_code: 4,
                data: 0u64.to_be_bytes().to_vec(),
            }, // sfOwnerNode
            ParsedField {
                type_code: 8,
                field_code: 2,
                data: vec![0xBB; 20],
            }, // sfOwner
        ];
        let raw = build_sle(0x0037, &fields, Some([0xCC; 32]), Some(100));

        // Verify sfSequence is in the raw blob
        let parsed = crate::ledger::meta::parse_sle(&raw).unwrap();
        let has_seq = parsed
            .fields
            .iter()
            .any(|f| f.type_code == 2 && f.field_code == 4);
        assert!(has_seq, "sfSequence must be present in initial SLE");

        // Round-trip through SLE::from_raw → set_previous_txn_id → into_data
        let key = crate::ledger::Key([0xDD; 32]);
        let mut sle = crate::ledger::sle::SLE::from_raw(key, raw.clone()).unwrap();
        sle.set_previous_txn_id(&[0xEE; 32]);
        sle.set_previous_txn_lgr_seq(200);
        let result = sle.into_data();

        // Verify sfSequence survived
        let parsed2 = crate::ledger::meta::parse_sle(&result).unwrap();
        let seq_field = parsed2
            .fields
            .iter()
            .find(|f| f.type_code == 2 && f.field_code == 4);
        assert!(
            seq_field.is_some(),
            "sfSequence must survive SLE round-trip"
        );
        let recovered_seq = u32::from_be_bytes(seq_field.unwrap().data[..4].try_into().unwrap());
        assert_eq!(recovered_seq, seq, "sfSequence value must be preserved");
    }

    #[test]
    fn test_to_sle_binary_preserves_sf_sequence_from_raw() {
        // Build a raw SLE with sfSequence, decode to NFTokenOffer, re-encode
        use crate::ledger::meta::{build_sle, ParsedField};
        let seq: u32 = 1875;
        let fields = vec![
            ParsedField {
                type_code: 2,
                field_code: 2,
                data: 0x0001u32.to_be_bytes().to_vec(),
            },
            ParsedField {
                type_code: 2,
                field_code: 4,
                data: seq.to_be_bytes().to_vec(),
            },
            ParsedField {
                type_code: 6,
                field_code: 1,
                data: vec![0x40, 0, 0, 0, 0, 0, 0, 0],
            },
            ParsedField {
                type_code: 5,
                field_code: 10,
                data: vec![0xAA; 32],
            },
            ParsedField {
                type_code: 3,
                field_code: 4,
                data: 0u64.to_be_bytes().to_vec(),
            },
            ParsedField {
                type_code: 8,
                field_code: 2,
                data: vec![0xBB; 20],
            },
        ];
        let raw = build_sle(0x0037, &fields, Some([0xCC; 32]), Some(100));

        // Decode into typed NFTokenOffer (should have raw_sle)
        let offer = NFTokenOffer::decode_from_sle(&raw).unwrap();
        assert_eq!(offer.sequence, seq);
        assert!(offer.raw_sle.is_some());

        // Re-encode via to_sle_binary (patching path)
        let result = offer.to_sle_binary();

        // sfSequence must still be present
        let parsed = crate::ledger::meta::parse_sle(&result).unwrap();
        let seq_field = parsed
            .fields
            .iter()
            .find(|f| f.type_code == 2 && f.field_code == 4);
        assert!(
            seq_field.is_some(),
            "sfSequence must survive to_sle_binary round-trip"
        );
        assert_eq!(
            u32::from_be_bytes(seq_field.unwrap().data[..4].try_into().unwrap()),
            seq,
        );
    }

    #[test]
    fn test_nftoken_id_layout() {
        let id = make_nftoken_id(0x0008, 100, &[0xAA; 20], 5, 10);
        // flags at bytes 0-1
        assert_eq!(u16::from_be_bytes([id[0], id[1]]), 0x0008);
        // transfer_fee at bytes 2-3
        assert_eq!(u16::from_be_bytes([id[2], id[3]]), 100);
        // issuer at bytes 4-23
        assert_eq!(&id[4..24], &[0xAA; 20]);
        // sequence at bytes 28-31
        assert_eq!(u32::from_be_bytes([id[28], id[29], id[30], id[31]]), 10);
    }
}
