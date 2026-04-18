//! Validator proposals — a node's current position on the next ledger.
//!
//! During the Establish phase each validator broadcasts a `Proposal`
//! containing the hash of the transaction set it wants to include.
//! Validators adjust their proposals to match the supermajority position.

use crate::crypto::sha512_first_half;

/// A validator's signed proposal for a specific ledger sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Ledger sequence this proposal is for.
    pub ledger_seq: u32,
    /// Hash of the proposed transaction set (32 bytes).
    pub tx_set_hash: [u8; 32],
    /// Hash of the previous (parent) ledger (32 bytes).
    pub previous_ledger: [u8; 32],
    /// Proposed ledger close time (seconds since Ripple epoch).
    pub close_time: u32,
    /// Which proposal iteration this is (0 = initial, increments on change).
    pub prop_seq: u32,
    /// Public key of the proposing validator (33 bytes compressed secp256k1).
    pub node_pubkey: Vec<u8>,
    /// Signature over the canonical proposal bytes.
    pub signature: Vec<u8>,
}

impl Proposal {
    /// The raw bytes that get signed, matching rippled's ConsensusProposal::signingHash() payload.
    ///
    /// Layout: PRP\0 (4 bytes) || proposeSeq (4 bytes BE) || closeTime (4 bytes BE)
    ///         || previousLedger (32 bytes) || position/txSetHash (32 bytes)
    ///
    /// Note: rippled computes SHA-512-Half of this payload in signingHash(), then passes
    /// that digest to signDigest(). In xLedgRS, sign() in keys.rs does SHA-512-Half
    /// internally, so this method returns the raw pre-hash payload.
    pub fn signing_bytes(&self) -> Vec<u8> {
        // Hash prefix for proposals: "PRP\0" = 0x50525000
        let mut v = Vec::with_capacity(4 + 4 + 4 + 32 + 32);
        v.extend_from_slice(&[0x50, 0x52, 0x50, 0x00]);
        v.extend_from_slice(&self.prop_seq.to_be_bytes());
        v.extend_from_slice(&self.close_time.to_be_bytes());
        v.extend_from_slice(&self.previous_ledger);
        v.extend_from_slice(&self.tx_set_hash);
        v
    }

    /// Produce the hash that identifies this proposal uniquely.
    /// Uses SHA-512-Half to match rippled's hashing convention.
    pub fn hash(&self) -> [u8; 32] {
        sha512_first_half(&self.signing_bytes())
    }

    /// Create an unsigned proposal (signature must be filled in before sending).
    pub fn new_unsigned(
        ledger_seq: u32,
        tx_set_hash: [u8; 32],
        previous_ledger: [u8; 32],
        close_time: u32,
        prop_seq: u32,
        node_pubkey: Vec<u8>,
    ) -> Self {
        Self {
            ledger_seq,
            tx_set_hash,
            previous_ledger,
            close_time,
            prop_seq,
            node_pubkey,
            signature: vec![],
        }
    }

    /// Create a signed proposal using the given secp256k1 keypair.
    pub fn new_signed(
        ledger_seq: u32,
        tx_set_hash: [u8; 32],
        previous_ledger: [u8; 32],
        close_time: u32,
        prop_seq: u32,
        kp: &crate::crypto::keys::Secp256k1KeyPair,
    ) -> Self {
        let mut p = Self::new_unsigned(
            ledger_seq,
            tx_set_hash,
            previous_ledger,
            close_time,
            prop_seq,
            kp.public_key_bytes(),
        );
        p.signature = kp.sign(&p.signing_bytes());
        p
    }

    /// Verify the proposal's signature against its own `node_pubkey`.
    /// Returns `false` if the signature is absent or invalid.
    pub fn verify_signature(&self) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        crate::crypto::keys::verify_secp256k1(
            &self.node_pubkey,
            &self.signing_bytes(),
            &self.signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prop(tx_hash: [u8; 32], seq: u32) -> Proposal {
        Proposal::new_unsigned(100, tx_hash, [0u8; 32], 0, seq, vec![0x02; 33])
    }

    #[test]
    fn test_signing_bytes_includes_prefix() {
        let p = prop([1u8; 32], 0);
        let bytes = p.signing_bytes();
        assert_eq!(
            &bytes[..4],
            &[0x50, 0x52, 0x50, 0x00],
            "must start with PRP prefix"
        );
    }

    #[test]
    fn test_signing_bytes_field_order() {
        // Verify the layout: PRP\0 || proposeSeq || closeTime || previousLedger || txSetHash
        let p = Proposal::new_unsigned(1, [0xAA; 32], [0xBB; 32], 42, 7, vec![0x02; 33]);
        let bytes = p.signing_bytes();
        assert_eq!(bytes.len(), 4 + 4 + 4 + 32 + 32);
        assert_eq!(&bytes[0..4], &[0x50, 0x52, 0x50, 0x00]); // PRP\0
        assert_eq!(&bytes[4..8], &7u32.to_be_bytes()); // proposeSeq
        assert_eq!(&bytes[8..12], &42u32.to_be_bytes()); // closeTime
        assert_eq!(&bytes[12..44], &[0xBB; 32]); // previousLedger
        assert_eq!(&bytes[44..76], &[0xAA; 32]); // txSetHash (position)
    }

    #[test]
    fn test_different_tx_sets_produce_different_hashes() {
        let p1 = prop([0u8; 32], 0);
        let p2 = prop([1u8; 32], 0);
        assert_ne!(p1.hash(), p2.hash());
    }

    #[test]
    fn test_different_prop_seq_produces_different_hash() {
        let p1 = prop([0u8; 32], 0);
        let p2 = prop([0u8; 32], 1);
        assert_ne!(p1.hash(), p2.hash());
    }

    #[test]
    fn test_hash_is_deterministic() {
        let p = prop([42u8; 32], 3);
        assert_eq!(p.hash(), p.hash());
    }
}
