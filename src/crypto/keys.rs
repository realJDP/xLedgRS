//! XRPL key generation, derivation, signing, and verification.
//!
//! The XRPL supports two key families:
//!
//! **secp256k1** (default) — uses a deterministic derivation from a 128-bit
//! family seed via HMAC-SHA512 (similar to BIP-32 but XRPL-specific).
//!
//! **Ed25519** — uses the seed bytes directly as the private key scalar
//! (after SHA-512 key expansion in ed25519-dalek).
//!
//! In both cases the *account address* is derived identically:
//!   AccountID = RIPEMD-160(SHA-256(compressed_public_key))

use crate::crypto::{account_id, sha512_first_half};
use crate::crypto::base58::{decode_seed, encode_account};
use anyhow::{bail, Result};

use thiserror::Error;


// ── Key types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Secp256k1,
    Ed25519,
}

/// A keypair that can sign XRPL transactions.
pub enum KeyPair {
    Secp256k1(Secp256k1KeyPair),
    Ed25519(Ed25519KeyPair),
}

impl KeyPair {
    /// The compressed public key bytes (33 bytes for secp256k1, 32 for Ed25519).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            KeyPair::Secp256k1(kp) => kp.public_key_bytes(),
            KeyPair::Ed25519(kp) => kp.public_key_bytes(),
        }
    }

    /// The XRPL account address (`r...`) for this keypair.
    pub fn account_address(&self) -> String {
        // Ed25519 pubkeys are prefixed with 0xED on-ledger
        let pubkey = match self {
            KeyPair::Ed25519(kp) => {
                let mut v = vec![0xED];
                v.extend_from_slice(&kp.public_key_bytes());
                v
            }
            KeyPair::Secp256k1(kp) => kp.public_key_bytes(),
        };
        let id = account_id(&pubkey);
        encode_account(&id)
    }

    /// Sign `message` and return the DER-encoded (secp256k1) or raw 64-byte (Ed25519) signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            KeyPair::Secp256k1(kp) => kp.sign(message),
            KeyPair::Ed25519(kp) => kp.sign(message),
        }
    }

    /// Verify a signature produced by `sign`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            KeyPair::Secp256k1(kp) => kp.verify(message, signature),
            KeyPair::Ed25519(kp) => kp.verify(message, signature),
        }
    }
}

// ── secp256k1 ────────────────────────────────────────────────────────────────

pub struct Secp256k1KeyPair {
    secret: secp256k1::SecretKey,
    public: secp256k1::PublicKey,
}

impl Secp256k1KeyPair {
    /// Generate a random keypair suitable for use as a node identity key.
    pub fn generate() -> Self {
        let secp = secp256k1::Secp256k1::new();
        let (secret, public) = secp.generate_keypair(&mut rand::thread_rng());
        Self { secret, public }
    }

    /// Derive a keypair from 16 bytes of family-seed entropy using XRPL's
    /// root-key derivation (sequence 0 of HMAC-SHA512 root derivation).
    pub fn from_seed_entropy(entropy: &[u8; 16]) -> Self {
        let secret = derive_secp256k1_account(entropy)
            .expect("secp256k1 account derivation should never fail");
        let secp = secp256k1::Secp256k1::new();
        let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        Self { secret, public }
    }

    /// Decode an `s...` family seed and derive the keypair.
    pub fn from_seed(seed_str: &str) -> Result<Self> {
        let entropy = decode_seed(seed_str)?;
        Ok(Self::from_seed_entropy(&entropy))
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public.serialize().to_vec() // 33-byte compressed
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let secp = secp256k1::Secp256k1::signing_only();
        // rippled (SecretKey.cpp:227) hashes with SHA-512-Half before ECDSA signing.
        let msg_hash = crate::crypto::sha512_first_half(message);
        let msg = secp256k1::Message::from_digest(msg_hash);
        // Note: secp256k1 crate v0.28+ normalizes ECDSA signatures to low-S form
        // by default (sign_ecdsa returns canonical signatures where S <= order/2),
        // satisfying rippled's "fully canonical" requirement.
        let sig = secp.sign_ecdsa(&msg, &self.secret);
        sig.serialize_der().to_vec()
    }

    /// Sign a 32-byte digest directly without hashing it first.
    /// Used for TLS session signatures where the value is already a hash.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Vec<u8> {
        let secp = secp256k1::Secp256k1::signing_only();
        let msg = secp256k1::Message::from_digest(*digest);
        let sig = secp.sign_ecdsa(&msg, &self.secret);
        sig.serialize_der().to_vec()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let secp = secp256k1::Secp256k1::verification_only();
        // Must match sign(): SHA-512-Half before ECDSA verification.
        let msg_hash = crate::crypto::sha512_first_half(message);
        let Ok(msg) = secp256k1::Message::from_digest_slice(&msg_hash) else { return false };
        let Ok(sig) = secp256k1::ecdsa::Signature::from_der(signature) else { return false };
        secp.verify_ecdsa(&msg, &sig, &self.public).is_ok()
    }
}

/// XRPL secp256k1 key derivation from 16-byte family seed entropy.
///
/// Two-step process:
/// 1. Root key: SHA-512(entropy || seq_u32_be)[0..32] until valid scalar
/// 2. Account key: (root_secret + SHA-512(root_pubkey || 0u32 || seq_u32_be)[0..32]) mod n
///
/// This matches rippled's `generateKeyPair` for the secp256k1 family.
fn derive_secp256k1_account(entropy: &[u8; 16]) -> Result<secp256k1::SecretKey> {
    let secp = secp256k1::Secp256k1::new();

    // Step 1: root private key
    let root_secret = derive_secp256k1_scalar(entropy, None)?;
    let root_public = secp256k1::PublicKey::from_secret_key(&secp, &root_secret);
    let root_pub_bytes = root_public.serialize(); // 33 bytes compressed

    // Step 2: account private key (account index 0)
    let account_index: u32 = 0;
    let account_key_material =
        derive_secp256k1_scalar_with_public(&root_pub_bytes, account_index)?;

    // account_secret = (root_secret + account_key_material) mod n
    let account_scalar = secp256k1::Scalar::from(account_key_material);
    let combined = root_secret.add_tweak(&account_scalar)?;
    Ok(combined)
}

/// SHA-512(data || seq_u32_be)[0..32] until it is a valid non-zero secp256k1 scalar.
fn derive_secp256k1_scalar(data: &[u8], extra: Option<&[u8]>) -> Result<secp256k1::SecretKey> {
    use sha2::{Digest, Sha512};
    for seq in 0u32.. {
        let mut h = Sha512::new();
        h.update(data);
        if let Some(e) = extra {
            h.update(e);
        }
        h.update(seq.to_be_bytes());
        let result = h.finalize();
        if let Ok(sk) = secp256k1::SecretKey::from_slice(&result[..32]) {
            return Ok(sk);
        }
    }
    bail!("scalar derivation exhausted")
}

/// SHA-512(root_pubkey || account_index_u32_be || seq_u32_be)[0..32]
fn derive_secp256k1_scalar_with_public(
    root_pub: &[u8],
    account_index: u32,
) -> Result<secp256k1::SecretKey> {
    use sha2::{Digest, Sha512};
    for seq in 0u32.. {
        let mut h = Sha512::new();
        h.update(root_pub);
        h.update(account_index.to_be_bytes());
        h.update(seq.to_be_bytes());
        let result = h.finalize();
        if let Ok(sk) = secp256k1::SecretKey::from_slice(&result[..32]) {
            return Ok(sk);
        }
    }
    bail!("account scalar derivation exhausted")
}

// ── Standalone verification ───────────────────────────────────────────────────

/// Verify a secp256k1 ECDSA DER signature over `message` using a compressed
/// public key (33 bytes).  The message is SHA-512-Half hashed before verification,
/// matching rippled's behavior (SecretKey.cpp) and `Secp256k1KeyPair::sign()`.
pub fn verify_secp256k1(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let secp = secp256k1::Secp256k1::verification_only();
    let Ok(pk) = secp256k1::PublicKey::from_slice(pubkey) else { return false };
    let msg_hash = crate::crypto::sha512_first_half(message);
    let Ok(msg) = secp256k1::Message::from_digest_slice(&msg_hash) else { return false };
    let Ok(sig) = secp256k1::ecdsa::Signature::from_der(signature) else { return false };
    secp.verify_ecdsa(&msg, &sig, &pk).is_ok()
}

/// Verify a signature over a 32-byte digest directly (no additional hashing).
/// Used for TLS session signature verification.
pub fn verify_secp256k1_digest(pubkey: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool {
    let secp = secp256k1::Secp256k1::verification_only();
    let Ok(pk) = secp256k1::PublicKey::from_slice(pubkey) else { return false };
    let Ok(msg) = secp256k1::Message::from_digest_slice(digest) else { return false };
    let Ok(sig) = secp256k1::ecdsa::Signature::from_der(signature) else { return false };
    secp.verify_ecdsa(&msg, &sig, &pk).is_ok()
}

// ── Ed25519 ──────────────────────────────────────────────────────────────────

pub struct Ed25519KeyPair {
    signing: ed25519_dalek::SigningKey,
}

impl Ed25519KeyPair {
    /// Derive an Ed25519 keypair from 16 bytes of family-seed entropy.
    ///
    /// XRPL Ed25519 derivation: expand the 16-byte entropy with SHA-512,
    /// use the first 32 bytes as the private scalar.
    pub fn from_seed_entropy(entropy: &[u8; 16]) -> Self {
        let expanded = sha512_first_half(entropy);
        let signing = ed25519_dalek::SigningKey::from_bytes(&expanded);
        Self { signing }
    }

    /// Decode an `s...` family seed and derive the keypair.
    pub fn from_seed(seed_str: &str) -> Result<Self> {
        let entropy = decode_seed(seed_str)?;
        Ok(Self::from_seed_entropy(&entropy))
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().to_vec() // 32 bytes
    }

    /// Sign raw message bytes.  Ed25519 internally hashes (SHA-512) the
    /// message, so callers must pass the *raw* signing payload — NOT a
    /// pre-computed hash.  The ed25519-dalek crate v2 enforces the S < L
    /// check on verification, satisfying rippled's canonicality requirement.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        self.signing.sign(message).to_bytes().to_vec()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        let Ok(sig_bytes): Result<[u8; 64], _> = signature.try_into() else { return false };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        // ed25519-dalek v2 checks S < L during verification, ensuring
        // signature canonicality as required by rippled.
        self.signing.verifying_key().verify(message, &sig).is_ok()
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid seed: {0}")]
    InvalidSeed(#[from] crate::crypto::base58::Base58Error),
    #[error("key derivation failed")]
    DerivationFailed,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// "masterpassphrase" is the well-known XRPL genesis seed.
    /// It should always derive rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh.
    #[test]
    fn test_genesis_keypair() {
        // Raw entropy for "masterpassphrase" (SHA256 of the passphrase, take first 16 bytes)
        // The actual XRPL genesis seed is: snoPBrXtMeMyMHUVTgbuqAfg1SUTb
        let kp = Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb")
            .expect("genesis seed should be valid");
        let addr = {
            let pubkey = kp.public_key_bytes();
            let id = account_id(&pubkey);
            encode_account(&id)
        };
        assert_eq!(addr, "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
            "genesis seed must derive genesis account");
    }

    /// Sign then verify round-trip for secp256k1.
    #[test]
    fn test_secp256k1_sign_verify() {
        let entropy = [42u8; 16];
        let kp = Secp256k1KeyPair::from_seed_entropy(&entropy);
        let message = b"hello xrpl";
        let sig = kp.sign(message);
        assert!(kp.verify(message, &sig), "signature should verify");
        assert!(!kp.verify(b"wrong message", &sig));
    }

    /// Sign then verify round-trip for Ed25519.
    #[test]
    fn test_ed25519_sign_verify() {
        let entropy = [7u8; 16];
        let kp = Ed25519KeyPair::from_seed_entropy(&entropy);
        let message = b"hello xrpl ed25519";
        let sig = kp.sign(message);
        assert!(kp.verify(message, &sig), "Ed25519 signature should verify");
        assert!(!kp.verify(b"different", &sig), "wrong message should not verify");
    }

    /// Both key types should produce valid r-addresses.
    #[test]
    fn test_address_format() {
        let entropy = [1u8; 16];
        let kp_sec = KeyPair::Secp256k1(Secp256k1KeyPair::from_seed_entropy(&entropy));
        let kp_ed  = KeyPair::Ed25519(Ed25519KeyPair::from_seed_entropy(&entropy));
        assert!(kp_sec.account_address().starts_with('r'));
        assert!(kp_ed.account_address().starts_with('r'));
    }
}
