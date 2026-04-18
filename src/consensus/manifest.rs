//! Validator manifests — master-key → ephemeral-signing-key delegation.
//!
//! A validator's long-lived master key is kept offline ("cold").  To sign
//! day-to-day proposals and validations the validator generates an ephemeral
//! **signing key** and publishes a *manifest*: a signed statement from the
//! master key authorizing the signing key for a specific sequence number.
//!
//! # Wire format (XRPL STObject binary, canonical field order)
//!
//! ```text
//! 0x24           sfSequence      (UInt32, type=2, field=4)
//! 0x71  VL data  sfPublicKey     (Blob,   type=7, field=1)  ← master pubkey
//! 0x73  VL data  sfSigningPubKey (Blob,   type=7, field=3)  ← signing pubkey
//! 0x70 0x12  VL  sfMasterSignature (Blob, type=7, field=18) ← not in signing bytes
//! 0x76  VL data  sfSignature     (Blob,   type=7, field=6)  ← not in signing bytes
//! ```
//!
//! # Signing bytes
//!
//! Both the master key and the signing key sign:
//! `"MAN\0" || sfSequence || sfPublicKey || sfSigningPubKey`
//!
//! # Revocation
//!
//! A manifest with `sequence == 0xFFFF_FFFF` and no `sfSigningPubKey`
//! permanently revokes the master key.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::crypto::keys::{verify_secp256k1, Secp256k1KeyPair};

/// Hash prefix for manifest signing: `"MAN\0"` = 0x4D414E00.
const PREFIX_MANIFEST: [u8; 4] = [0x4D, 0x41, 0x4E, 0x00];

/// Sequence number that permanently revokes a master key.
pub const REVOKE_SEQ: u32 = 0xFFFF_FFFF;

// ── Manifest ──────────────────────────────────────────────────────────────────

/// A signed delegation from a master key to an ephemeral signing key.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Master public key (33-byte compressed secp256k1).
    pub master_pubkey: Vec<u8>,
    /// Ephemeral signing public key (33-byte compressed secp256k1).
    /// Empty for a revocation manifest, which omits sfSigningPubKey on the wire.
    pub signing_pubkey: Vec<u8>,
    /// Sequence number — higher means newer; 0xFFFFFFFF = revocation.
    pub sequence: u32,
    /// Master key's signature over `signing_bytes()`.
    pub master_sig: Vec<u8>,
    /// Signing key's signature over `signing_bytes()` (proves key possession).
    /// Empty for revocation manifests (no signing key to prove possession of).
    pub signing_sig: Vec<u8>,
    /// Optional domain name (raw bytes).
    pub domain: Option<Vec<u8>>,
    /// Optional version number (UInt16).
    pub version: Option<u16>,
}

impl Manifest {
    // ── Canonical bytes ───────────────────────────────────────────────────────

    /// Canonical bytes that both master and signing keys must sign.
    ///
    /// Fields in canonical (type_code, field_code) order, excluding signatures.
    /// For revocations, sfSigningPubKey is omitted.
    pub fn signing_bytes(
        master_pubkey: &[u8],
        signing_pubkey: &[u8],
        sequence: u32,
        domain: Option<&[u8]>,
        version: Option<u16>,
    ) -> Vec<u8> {
        let is_revocation = sequence == REVOKE_SEQ;
        let mut v = PREFIX_MANIFEST.to_vec();

        // Canonical order: (type_code, field_code) ascending
        // UInt16 (type=1) fields first
        // sfVersion: (1, 16)
        if let Some(ver) = version {
            v.push(0x10); // type=1 high nibble, field=0 means extended
            v.push(16); // field_code = 16
            v.extend_from_slice(&ver.to_be_bytes());
        }

        // UInt32 (type=2) fields
        // sfSequence: field_id(2,4) = 0x24, then u32_be
        v.push(0x24);
        v.extend_from_slice(&sequence.to_be_bytes());

        // VL/Blob (type=7) fields in field_code order
        // sfPublicKey (master): field_id(7,1) = 0x71, VL(len), bytes
        v.push(0x71);
        v.push(master_pubkey.len() as u8);
        v.extend_from_slice(master_pubkey);

        // sfSigningPubKey: field_id(7,3) = 0x73, VL(len), bytes (omitted for revocations)
        if !is_revocation {
            v.push(0x73);
            v.push(signing_pubkey.len() as u8);
            v.extend_from_slice(signing_pubkey);
        }

        // sfDomain: field_id(7,7) = 0x77, VL(len), bytes
        if let Some(dom) = domain {
            v.push(0x77);
            v.push(dom.len() as u8);
            v.extend_from_slice(dom);
        }

        v
    }

    // ── Constructors ──────────────────────────────────────────────────────────

    /// Create and sign a normal manifest delegating `master_kp` → `signing_kp`.
    pub fn new_signed(
        sequence: u32,
        master_kp: &Secp256k1KeyPair,
        signing_kp: &Secp256k1KeyPair,
    ) -> Self {
        let master_pub = master_kp.public_key_bytes();
        let signing_pub = signing_kp.public_key_bytes();
        let bytes = Self::signing_bytes(&master_pub, &signing_pub, sequence, None, None);
        Self {
            master_sig: master_kp.sign(&bytes),
            signing_sig: signing_kp.sign(&bytes),
            master_pubkey: master_pub,
            signing_pubkey: signing_pub,
            sequence,
            domain: None,
            version: None,
        }
    }

    /// Create a revocation manifest — permanently invalidates `master_kp`.
    ///
    /// Revocation manifests have `sequence = 0xFFFFFFFF` and omit the
    /// signing pubkey. Only the master key signature is required.
    pub fn new_revocation(master_kp: &Secp256k1KeyPair) -> Self {
        let master_pub = master_kp.public_key_bytes();
        let bytes = Self::signing_bytes(&master_pub, &[], REVOKE_SEQ, None, None);
        Self {
            master_sig: master_kp.sign(&bytes),
            signing_sig: vec![],
            master_pubkey: master_pub,
            signing_pubkey: Vec::new(),
            sequence: REVOKE_SEQ,
            domain: None,
            version: None,
        }
    }

    // ── Verification ─────────────────────────────────────────────────────────

    /// Returns `true` if the manifest's signatures are valid.
    ///
    /// For normal manifests both signatures are checked.
    /// For revocation manifests only the master signature is checked.
    pub fn verify(&self) -> bool {
        let bytes = Self::signing_bytes(
            &self.master_pubkey,
            &self.signing_pubkey,
            self.sequence,
            self.domain.as_deref(),
            self.version,
        );
        let master_ok = verify_secp256k1(&self.master_pubkey, &bytes, &self.master_sig);
        if !master_ok {
            return false;
        }

        if self.is_revocation() {
            return true; // only master sig needed
        }

        verify_secp256k1(&self.signing_pubkey, &bytes, &self.signing_sig)
    }

    /// `true` if this manifest permanently revokes its master key.
    pub fn is_revocation(&self) -> bool {
        self.sequence == REVOKE_SEQ
    }

    // ── Wire serialization ────────────────────────────────────────────────────

    /// Serialize to the canonical wire format.
    ///
    /// Canonical field order: (type_code, field_code) ascending.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();

        // sfVersion (UInt16, type=1, field=16): extended encoding 0x10 0x10
        if let Some(ver) = self.version {
            v.push(0x10); // type=1 high nibble, field=0 → extended
            v.push(16); // field_code = 16
            v.extend_from_slice(&ver.to_be_bytes());
        }

        // sfSequence (UInt32, type=2, field=4): 0x24 + u32_be
        v.push(0x24);
        v.extend_from_slice(&self.sequence.to_be_bytes());

        // sfPublicKey (Blob, type=7, field=1): 0x71 + VL + bytes
        v.push(0x71);
        v.push(self.master_pubkey.len() as u8);
        v.extend_from_slice(&self.master_pubkey);

        // sfSigningPubKey (Blob, type=7, field=3): 0x73 + VL + bytes (omitted for revocations)
        if !self.is_revocation() {
            v.push(0x73);
            v.push(self.signing_pubkey.len() as u8);
            v.extend_from_slice(&self.signing_pubkey);
        }

        // sfSignature (Blob, type=7, field=6): 0x76 + VL + bytes
        if !self.signing_sig.is_empty() {
            v.push(0x76);
            v.push(self.signing_sig.len() as u8);
            v.extend_from_slice(&self.signing_sig);
        }

        // sfDomain (Blob, type=7, field=7): 0x77 + VL + bytes
        if let Some(ref dom) = self.domain {
            v.push(0x77);
            v.push(dom.len() as u8);
            v.extend_from_slice(dom);
        }

        // sfMasterSignature (Blob, type=7, field=18): 0x70 0x12 + VL + bytes
        v.push(0x70);
        v.push(0x12);
        v.push(self.master_sig.len() as u8);
        v.extend_from_slice(&self.master_sig);

        v
    }

    /// Deserialize from the canonical wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ManifestError> {
        let mut pos = 0;
        let mut sequence = None::<u32>;
        let mut master_pubkey = None::<Vec<u8>>;
        let mut signing_pubkey = None::<Vec<u8>>;
        let mut master_sig = None::<Vec<u8>>;
        let mut signing_sig = vec![];
        let mut domain = None::<Vec<u8>>;
        let mut version = None::<u16>;

        while pos < data.len() {
            let b = data[pos];
            pos += 1;

            let top = (b >> 4) as u16;
            let bot = (b & 0x0F) as u16;
            let (type_code, field_code) = if top == 0 && bot == 0 {
                if pos + 2 > data.len() {
                    return Err(ManifestError::Truncated);
                }
                let t = data[pos] as u16;
                let f = data[pos + 1] as u16;
                pos += 2;
                (t, f)
            } else if top == 0 {
                if pos >= data.len() {
                    return Err(ManifestError::Truncated);
                }
                let t = data[pos] as u16;
                pos += 1;
                (t, bot)
            } else if bot == 0 {
                if pos >= data.len() {
                    return Err(ManifestError::Truncated);
                }
                let f = data[pos] as u16;
                pos += 1;
                (top, f)
            } else {
                (top, bot)
            };

            match (type_code, field_code) {
                (1, 16) => {
                    // sfVersion (UInt16)
                    if pos + 2 > data.len() {
                        return Err(ManifestError::Truncated);
                    }
                    version = Some(u16::from_be_bytes(data[pos..pos + 2].try_into().unwrap()));
                    pos += 2;
                }
                (2, 4) => {
                    // sfSequence (UInt32)
                    if pos + 4 > data.len() {
                        return Err(ManifestError::Truncated);
                    }
                    sequence = Some(u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()));
                    pos += 4;
                }
                (7, _) => {
                    // Blob (VL-encoded)
                    if pos >= data.len() {
                        return Err(ManifestError::Truncated);
                    }
                    let vl = data[pos] as usize;
                    pos += 1;
                    if pos + vl > data.len() {
                        return Err(ManifestError::Truncated);
                    }
                    let blob = data[pos..pos + vl].to_vec();
                    match field_code {
                        1 => master_pubkey = Some(blob),  // sfPublicKey
                        3 => signing_pubkey = Some(blob), // sfSigningPubKey
                        6 => signing_sig = blob,          // sfSignature
                        7 => domain = Some(blob),         // sfDomain
                        18 => master_sig = Some(blob),    // sfMasterSignature
                        _ => {}
                    }
                    pos += vl;
                }
                _ => break, // unknown field, stop
            }
        }

        let seq = sequence.ok_or(ManifestError::MissingField("Sequence"))?;

        // Revocation manifests omit sfSigningPubKey entirely.
        let spk = if seq == REVOKE_SEQ {
            signing_pubkey.unwrap_or_default()
        } else {
            signing_pubkey.ok_or(ManifestError::MissingField("SigningPubKey"))?
        };

        Ok(Manifest {
            sequence: seq,
            master_pubkey: master_pubkey.ok_or(ManifestError::MissingField("PublicKey"))?,
            signing_pubkey: spk,
            master_sig: master_sig.ok_or(ManifestError::MissingField("MasterSignature"))?,
            signing_sig,
            domain,
            version,
        })
    }
}

// ── ManifestCache ─────────────────────────────────────────────────────────────

/// Maintains the current valid manifest for every known master key.
///
/// Used during consensus to map proposal/validation signing keys back to their
/// master keys for UNL trust checks.
#[derive(Default)]
pub struct ManifestCache {
    /// signing_pubkey → Manifest (the currently active one).
    by_signing_key: HashMap<Vec<u8>, Manifest>,
    /// master_pubkey → current active signing_pubkey (for O(1) rotation cleanup).
    master_to_signing: HashMap<Vec<u8>, Vec<u8>>,
    /// master_pubkey → current sequence (for replay protection + revocation).
    master_seq: HashMap<Vec<u8>, u32>,
    /// Exact raw manifest blobs seen recently, keyed by blob hash.
    seen_blob_hashes: HashSet<[u8; 32]>,
    seen_blob_order: VecDeque<[u8; 32]>,
}

const SEEN_MANIFEST_BLOB_CAP: usize = 32_768;

impl ManifestCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn add_impl(&mut self, manifest: Manifest, verify_signatures: bool) -> bool {
        let current_seq = self
            .master_seq
            .get(&manifest.master_pubkey)
            .copied()
            .unwrap_or(0);

        // Reject replays and stale/out-of-order manifests before doing any
        // expensive signature work. This matches the hot-path optimization in
        // rippled's manifest cache where stale gossip is dropped cheaply.
        if manifest.sequence <= current_seq {
            return false;
        }

        if verify_signatures && !manifest.verify() {
            return false;
        }

        // C14: Reject if signing_pubkey == master_pubkey
        if !manifest.is_revocation() && manifest.signing_pubkey == manifest.master_pubkey {
            return false;
        }

        // C14: Reject if ephemeral key is already a master key for a DIFFERENT validator
        if !manifest.is_revocation() {
            if self.master_seq.contains_key(&manifest.signing_pubkey)
                && manifest.signing_pubkey != manifest.master_pubkey
            {
                return false;
            }
        }

        // C14: Reject if ephemeral key is already an ephemeral key for a DIFFERENT validator
        if !manifest.is_revocation() {
            if let Some(existing) = self.by_signing_key.get(&manifest.signing_pubkey) {
                if existing.master_pubkey != manifest.master_pubkey {
                    return false;
                }
            }
        }

        // Remove the old signing-key entry for this master (key rotation).
        if let Some(old_signing) = self.master_to_signing.get(&manifest.master_pubkey) {
            self.by_signing_key.remove(&old_signing.clone());
        }

        // Record the new sequence.
        self.master_seq
            .insert(manifest.master_pubkey.clone(), manifest.sequence);

        if manifest.is_revocation() {
            // Revocation: remove master→signing mapping entirely; don't add a signing key.
            self.master_to_signing.remove(&manifest.master_pubkey);
        } else {
            self.master_to_signing.insert(
                manifest.master_pubkey.clone(),
                manifest.signing_pubkey.clone(),
            );
            self.by_signing_key
                .insert(manifest.signing_pubkey.clone(), manifest);
        }

        true
    }

    /// Add a manifest.  Returns `true` if accepted, `false` if rejected.
    ///
    /// Rejection reasons:
    /// - Signature(s) invalid
    /// - Sequence ≤ already-seen sequence for this master key (replay)
    /// - Master key was already revoked
    /// - Ephemeral key == master key (self-delegation)
    /// - Ephemeral key collision with another validator's master or ephemeral key
    pub fn add(&mut self, manifest: Manifest) -> bool {
        self.add_impl(manifest, true)
    }

    /// Add a manifest that has already been verified by another trusted cache.
    ///
    /// Used by consensus-round bookkeeping so signature
    /// verification twice for the same accepted manifest batch.
    pub fn add_prevalidated(&mut self, manifest: Manifest) -> bool {
        self.add_impl(manifest, false)
    }

    /// Current accepted sequence for a master key, or 0 if none is known.
    pub fn current_sequence_for_master(&self, master_pubkey: &[u8]) -> u32 {
        self.master_seq.get(master_pubkey).copied().unwrap_or(0)
    }

    /// Mark a raw manifest blob as recently seen. Returns `true` only the first
    /// verification is not repeated for an exact blob seen within the rolling window.
    pub fn mark_blob_seen(&mut self, blob: &[u8]) -> bool {
        let hash = crate::crypto::sha256(blob);
        if !self.seen_blob_hashes.insert(hash) {
            return false;
        }
        self.seen_blob_order.push_back(hash);
        while self.seen_blob_order.len() > SEEN_MANIFEST_BLOB_CAP {
            if let Some(oldest) = self.seen_blob_order.pop_front() {
                self.seen_blob_hashes.remove(&oldest);
            }
        }
        true
    }

    /// Resolve a signing key to the master key that authorized it.
    ///
    /// Returns `None` if the signing key has no manifest registered
    /// (caller should treat it as its own master key — single-key mode).
    pub fn signing_key_to_master(&self, signing_key: &[u8]) -> Option<&[u8]> {
        self.by_signing_key
            .get(signing_key)
            .map(|m| m.master_pubkey.as_slice())
    }

    /// Resolve a public key to its master key. If no manifest is known, the
    /// key is treated as its own master key.
    pub fn master_key(&self, public_key: &[u8]) -> Vec<u8> {
        self.signing_key_to_master(public_key)
            .map(|master| master.to_vec())
            .unwrap_or_else(|| public_key.to_vec())
    }

    pub fn signing_key_for_master(&self, master_pubkey: &[u8]) -> Option<Vec<u8>> {
        self.master_to_signing.get(master_pubkey).cloned()
    }

    pub fn manifest_for_master(&self, master_pubkey: &[u8]) -> Option<Vec<u8>> {
        let signing = self.master_to_signing.get(master_pubkey)?;
        self.by_signing_key.get(signing).map(|manifest| manifest.to_bytes())
    }

    pub fn sequence_for_master(&self, master_pubkey: &[u8]) -> Option<u32> {
        self.master_seq.get(master_pubkey).copied()
    }

    pub fn domain_for_master(&self, master_pubkey: &[u8]) -> Option<String> {
        let signing = self.master_to_signing.get(master_pubkey)?;
        let manifest = self.by_signing_key.get(signing)?;
        manifest
            .domain
            .as_ref()
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
    }

    pub fn signing_key_mappings(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.master_to_signing
            .iter()
            .map(|(master, signing)| (master.clone(), signing.clone()))
            .collect()
    }

    /// `true` if the master key has been revoked.
    pub fn is_revoked(&self, master_pubkey: &[u8]) -> bool {
        self.master_seq.get(master_pubkey).copied() == Some(REVOKE_SEQ)
    }

    /// Number of active (non-revoked) manifests.
    pub fn len(&self) -> usize {
        self.by_signing_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_signing_key.is_empty()
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("buffer truncated")]
    Truncated,
    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn kp() -> Secp256k1KeyPair {
        Secp256k1KeyPair::generate()
    }

    // ── Manifest creation and verification ────────────────────────────────────

    #[test]
    fn test_new_signed_verifies() {
        let master = kp();
        let signing = kp();
        let m = Manifest::new_signed(1, &master, &signing);
        assert!(m.verify(), "fresh manifest must verify");
        assert!(!m.is_revocation());
    }

    #[test]
    fn test_revocation_verifies() {
        let master = kp();
        let m = Manifest::new_revocation(&master);
        assert!(m.verify(), "revocation manifest must verify");
        assert!(m.is_revocation());
        assert_eq!(m.sequence, REVOKE_SEQ);
    }

    #[test]
    fn test_tampered_master_sig_fails() {
        let master = kp();
        let signing = kp();
        let mut m = Manifest::new_signed(1, &master, &signing);
        m.master_sig[0] ^= 0xFF;
        assert!(!m.verify());
    }

    #[test]
    fn test_tampered_signing_sig_fails() {
        let master = kp();
        let signing = kp();
        let mut m = Manifest::new_signed(1, &master, &signing);
        m.signing_sig[0] ^= 0xFF;
        assert!(!m.verify());
    }

    #[test]
    fn test_wrong_signing_key_fails() {
        // Signing sig from a different key must fail
        let master = kp();
        let signing = kp();
        let impostor = kp();
        let mut m = Manifest::new_signed(1, &master, &signing);
        // Replace signing pubkey with impostor — signing_sig no longer matches
        m.signing_pubkey = impostor.public_key_bytes();
        assert!(!m.verify());
    }

    // ── Wire serialization ────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_normal() {
        let master = kp();
        let signing = kp();
        let orig = Manifest::new_signed(42, &master, &signing);
        let bytes = orig.to_bytes();
        let decoded = Manifest::from_bytes(&bytes).expect("deserialize should succeed");
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.master_pubkey, orig.master_pubkey);
        assert_eq!(decoded.signing_pubkey, orig.signing_pubkey);
        assert_eq!(decoded.master_sig, orig.master_sig);
        assert_eq!(decoded.signing_sig, orig.signing_sig);
        assert!(decoded.verify(), "deserialized manifest must still verify");
    }

    #[test]
    fn test_roundtrip_revocation() {
        let master = kp();
        let orig = Manifest::new_revocation(&master);
        let bytes = orig.to_bytes();
        let decoded = Manifest::from_bytes(&bytes).expect("deserialize should succeed");
        assert!(decoded.is_revocation());
        assert!(decoded.verify());
    }

    #[test]
    fn test_signing_bytes_starts_with_prefix() {
        let bytes = Manifest::signing_bytes(&[0x02; 33], &[0x03; 33], 1, None, None);
        assert_eq!(&bytes[..4], &[0x4D, 0x41, 0x4E, 0x00]);
    }

    // ── ManifestCache ─────────────────────────────────────────────────────────

    #[test]
    fn test_cache_add_and_lookup() {
        let master = kp();
        let signing = kp();
        let m = Manifest::new_signed(1, &master, &signing);
        let master_pub = master.public_key_bytes();
        let signing_pub = signing.public_key_bytes();

        let mut cache = ManifestCache::new();
        assert!(cache.add(m), "valid manifest must be accepted");

        let resolved = cache.signing_key_to_master(&signing_pub);
        assert_eq!(resolved, Some(master_pub.as_slice()));
    }

    #[test]
    fn test_cache_rejects_invalid_signature() {
        let master = kp();
        let signing = kp();
        let mut m = Manifest::new_signed(1, &master, &signing);
        m.master_sig[0] ^= 0xFF; // corrupt
        let mut cache = ManifestCache::new();
        assert!(!cache.add(m));
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_rejects_replay() {
        let master = kp();
        let signing = kp();
        let m1 = Manifest::new_signed(1, &master, &signing);
        let m2 = Manifest::new_signed(1, &master, &signing); // same seq
        let mut cache = ManifestCache::new();
        assert!(cache.add(m1));
        assert!(!cache.add(m2), "replay (same sequence) must be rejected");
    }

    #[test]
    fn test_cache_key_rotation() {
        let master = kp();
        let signing1 = kp();
        let signing2 = kp();
        let m1 = Manifest::new_signed(1, &master, &signing1);
        let m2 = Manifest::new_signed(2, &master, &signing2);
        let pub1 = signing1.public_key_bytes();
        let pub2 = signing2.public_key_bytes();

        let mut cache = ManifestCache::new();
        assert!(cache.add(m1));
        assert!(
            cache.add(m2),
            "higher-sequence manifest must replace old one"
        );

        // Old signing key must be gone
        assert!(
            cache.signing_key_to_master(&pub1).is_none(),
            "old signing key must be evicted after rotation"
        );
        // New signing key must resolve to master
        assert_eq!(
            cache.signing_key_to_master(&pub2),
            Some(master.public_key_bytes().as_slice()),
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_revocation() {
        let master = kp();
        let signing = kp();
        let m1 = Manifest::new_signed(1, &master, &signing);
        let rev = Manifest::new_revocation(&master);
        let signing_pub = signing.public_key_bytes();
        let master_pub = master.public_key_bytes();

        let mut cache = ManifestCache::new();
        assert!(cache.add(m1));
        assert!(cache.add(rev), "revocation must be accepted");

        // After revocation: signing key gone, master marked as revoked
        assert!(cache.signing_key_to_master(&signing_pub).is_none());
        assert!(cache.is_revoked(&master_pub));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_no_manifest_returns_none() {
        let cache = ManifestCache::new();
        let random_key = kp().public_key_bytes();
        assert!(cache.signing_key_to_master(&random_key).is_none());
    }
}
