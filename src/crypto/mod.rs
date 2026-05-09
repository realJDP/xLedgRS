//! Cryptography primitives for the XRP Ledger.
//!
//! Covers:
//! - SHA-256 / SHA-512 hashing
//! - RIPEMD-160 (for account ID derivation)
//! - XRPL base58check encoding/decoding
//! - Account address encoding (`r...`)
//! - Family-seed encoding/decoding (`s...`)
//! - secp256k1 key generation, signing, verification
//! - Ed25519 key generation, signing, verification

pub mod base58;
pub mod keys;

use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

// ── Hashing ──────────────────────────────────────────────────────────────────

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

pub fn sha512_first_half(data: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(data);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result[..32]);
    out
}

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut h = Ripemd160::new();
    h.update(data);
    h.finalize().into()
}

/// Derives an XRPL AccountID from a compressed public key.
/// AccountID = RIPEMD-160(SHA-256(pubkey))
pub fn account_id(pubkey: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(pubkey))
}
