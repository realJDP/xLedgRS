//! Validator validations — signed attestations that a ledger hash is final.
//!
//! After consensus on a transaction set, each validator applies the transactions
//! and computes the resulting ledger hash. It then broadcasts a `Validation`
//! signing that hash. When 80%+ of the UNL sends matching validations the
//! ledger is considered fully validated and immutable.

use crate::crypto::sha512_first_half;

/// vfFullValidation — this is a full (not partial) validation.
pub const VF_FULL_VALIDATION: u32 = 0x0000_0001;
/// vfFullyCanonicalSig — always set for modern validations.
pub const VF_FULLY_CANONICAL_SIG: u32 = 0x8000_0000;

/// A validator's signed statement that a specific ledger hash is valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    /// Flags bitfield (sfFlags). Use VF_FULL_VALIDATION | VF_FULLY_CANONICAL_SIG for full.
    pub flags:           u32,
    /// Ledger sequence being validated (sfLedgerSequence).
    pub ledger_seq:      u32,
    /// When the validator signed this — Ripple epoch seconds (sfSigningTime).
    pub sign_time:       u32,
    /// sfCloseTime — close time of the validated ledger, if present.
    pub close_time:      Option<u32>,
    /// sfCookie — unique node cookie.
    pub cookie:          Option<u64>,
    /// sfServerVersion — server version identifier.
    pub server_version:  Option<u64>,
    /// Hash of the validated ledger — 32 bytes (sfLedgerHash).
    pub ledger_hash:     [u8; 32],
    /// sfConsensusHash — hash of the consensus transaction set.
    pub consensus_hash:  Option<[u8; 32]>,
    /// sfValidatedHash — previous validated ledger hash.
    pub validated_hash:  Option<[u8; 32]>,
    /// Public key of the validating node (sfSigningPubKey).
    pub node_pubkey:     Vec<u8>,
    /// Signature over the canonical validation bytes (sfSignature).
    pub signature:       Vec<u8>,
}

// ---------------------------------------------------------------------------
// SField header encoding helpers
// ---------------------------------------------------------------------------

/// Write a VL (variable-length) length prefix.
fn write_vl_length(out: &mut Vec<u8>, len: usize) {
    if len <= 192 {
        out.push(len as u8);
    } else if len <= 12480 {
        let adjusted = len - 193;
        out.push(((adjusted >> 8) + 193) as u8);
        out.push((adjusted & 0xFF) as u8);
    } else {
        let adjusted = len - 12481;
        out.push(241);
        out.push(((adjusted >> 16) & 0xFF) as u8);
        out.push(((adjusted >> 8) & 0xFF) as u8);
        out.push((adjusted & 0xFF) as u8);
    }
}

/// Parse a VL length prefix, returning (length, bytes_consumed).
fn read_vl_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() { return None; }
    let b0 = data[0] as usize;
    if b0 <= 192 {
        Some((b0, 1))
    } else if b0 <= 240 {
        if data.len() < 2 { return None; }
        let b1 = data[1] as usize;
        Some((193 + ((b0 - 193) << 8) + b1, 2))
    } else if b0 <= 254 {
        if data.len() < 3 { return None; }
        let b1 = data[1] as usize;
        let b2 = data[2] as usize;
        Some((12481 + ((b0 - 241) << 16) + (b1 << 8) + b2, 3))
    } else {
        None
    }
}

/// Parse a field header, returning ((type_code, field_code), bytes_consumed).
fn read_field_header(data: &[u8]) -> Option<((u8, u8), usize)> {
    if data.is_empty() { return None; }
    let b = data[0];
    let mut type_code = b >> 4;
    let mut field_code = b & 0x0F;
    let mut consumed = 1;
    if type_code == 0 {
        if data.len() < consumed + 1 { return None; }
        type_code = data[consumed];
        consumed += 1;
    }
    if field_code == 0 {
        if data.len() < consumed + 1 { return None; }
        field_code = data[consumed];
        consumed += 1;
    }
    Some(((type_code, field_code), consumed))
}

impl Validation {
    /// Produce the bytes that get signed (excludes sfSignature).
    /// Format: `VAL\0` prefix + STObject fields in canonical order.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut v = vec![0x56, 0x41, 0x4C, 0x00]; // "VAL\0"
        self.serialize_fields(&mut v, false);
        v
    }

    /// Serialize all STObject fields in canonical (type_code, field_code) order.
    /// If `include_signature` is true, sfSignature is included.
    fn serialize_fields(&self, out: &mut Vec<u8>, include_signature: bool) {
        // ---- UInt32 fields (type=2) in field_code order ----
        // sfFlags: field 2, header 0x22
        out.push(0x22);
        out.extend_from_slice(&self.flags.to_be_bytes());

        // sfLedgerSequence: field 6, header 0x26
        out.push(0x26);
        out.extend_from_slice(&self.ledger_seq.to_be_bytes());

        // sfCloseTime: field 7, header 0x27
        if let Some(ct) = self.close_time {
            out.push(0x27);
            out.extend_from_slice(&ct.to_be_bytes());
        }

        // sfSigningTime: field 9, header 0x29
        out.push(0x29);
        out.extend_from_slice(&self.sign_time.to_be_bytes());

        // ---- UInt64 fields (type=3) in field_code order ----
        // sfCookie: field 10, header 0x3A (type=3, field=10, both <16)
        if let Some(ck) = self.cookie {
            out.push(0x3A);
            out.extend_from_slice(&ck.to_be_bytes());
        }

        // sfServerVersion: field 11, header 0x3B
        if let Some(sv) = self.server_version {
            out.push(0x3B);
            out.extend_from_slice(&sv.to_be_bytes());
        }

        // ---- Hash256 fields (type=5) in field_code order ----
        // sfLedgerHash: field 1, header 0x51
        out.push(0x51);
        out.extend_from_slice(&self.ledger_hash);

        // sfConsensusHash: field 23 (>=16), header 0x50 0x17
        if let Some(ref ch) = self.consensus_hash {
            out.push(0x50);
            out.push(0x17);
            out.extend_from_slice(ch);
        }

        // sfValidatedHash: field 25 (>=16), header 0x50 0x19
        if let Some(ref vh) = self.validated_hash {
            out.push(0x50);
            out.push(0x19);
            out.extend_from_slice(vh);
        }

        // ---- VL/Blob fields (type=7) in field_code order ----
        // sfSigningPubKey: field 3, header 0x73
        out.push(0x73);
        write_vl_length(out, self.node_pubkey.len());
        out.extend_from_slice(&self.node_pubkey);

        // sfSignature: field 6, header 0x76 (excluded from signing)
        if include_signature && !self.signature.is_empty() {
            out.push(0x76);
            write_vl_length(out, self.signature.len());
            out.extend_from_slice(&self.signature);
        }
    }

    /// Hash this validation using SHA-512-Half (the XRP Ledger standard).
    pub fn hash(&self) -> [u8; 32] {
        sha512_first_half(&self.signing_bytes())
    }

    /// Create an unsigned validation. `full` controls the VF_FULL_VALIDATION flag;
    /// VF_FULLY_CANONICAL_SIG is always set.
    pub fn new_unsigned(
        ledger_seq:  u32,
        ledger_hash: [u8; 32],
        sign_time:   u32,
        full:        bool,
        node_pubkey: Vec<u8>,
    ) -> Self {
        let mut flags = VF_FULLY_CANONICAL_SIG;
        if full {
            flags |= VF_FULL_VALIDATION;
        }
        Self {
            flags,
            ledger_seq,
            sign_time,
            close_time: None,
            cookie: None,
            server_version: None,
            ledger_hash,
            consensus_hash: None,
            validated_hash: None,
            node_pubkey,
            signature: vec![],
        }
    }

    /// Create a signed validation using the given secp256k1 keypair.
    pub fn new_signed(
        ledger_seq:  u32,
        ledger_hash: [u8; 32],
        sign_time:   u32,
        full:        bool,
        kp: &crate::crypto::keys::Secp256k1KeyPair,
    ) -> Self {
        let mut v = Self::new_unsigned(
            ledger_seq, ledger_hash, sign_time, full,
            kp.public_key_bytes(),
        );
        v.signature = kp.sign(&v.signing_bytes());
        v
    }

    /// Whether this is a full validation (vs partial/ephemeral).
    pub fn is_full(&self) -> bool {
        self.flags & VF_FULL_VALIDATION != 0
    }

    /// Verify the validation's signature against its own `node_pubkey`.
    /// Returns `false` if the signature is absent or invalid.
    pub fn verify_signature(&self) -> bool {
        if self.signature.is_empty() { return false; }
        crate::crypto::keys::verify_secp256k1(
            &self.node_pubkey,
            &self.signing_bytes(),
            &self.signature,
        )
    }

    /// Serialize as a full STObject (all fields including signature) for the wire.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize_fields(&mut out, true);
        out
    }

    /// Parse a serialized STObject into a Validation.
    pub fn from_bytes(data: &[u8]) -> Option<Validation> {
        let mut pos = 0;
        let mut flags: Option<u32> = None;
        let mut ledger_seq: Option<u32> = None;
        let mut close_time: Option<u32> = None;
        let mut sign_time: Option<u32> = None;
        let mut cookie: Option<u64> = None;
        let mut server_version: Option<u64> = None;
        let mut ledger_hash: Option<[u8; 32]> = None;
        let mut consensus_hash: Option<[u8; 32]> = None;
        let mut validated_hash: Option<[u8; 32]> = None;
        let mut node_pubkey: Option<Vec<u8>> = None;
        let mut signature: Option<Vec<u8>> = None;

        while pos < data.len() {
            let ((type_code, field_code), hdr_len) = read_field_header(&data[pos..])?;
            pos += hdr_len;

            match type_code {
                // UInt16 (type=1) — skip unknown
                1 => {
                    if pos + 2 > data.len() { return None; }
                    // skip value
                    pos += 2;
                }
                // UInt32 (type=2)
                2 => {
                    if pos + 4 > data.len() { return None; }
                    let val = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?);
                    pos += 4;
                    match field_code {
                        2 => flags = Some(val),
                        6 => ledger_seq = Some(val),
                        7 => close_time = Some(val),
                        9 => sign_time = Some(val),
                        _ => {} // skip unknown UInt32 fields
                    }
                }
                // UInt64 (type=3)
                3 => {
                    if pos + 8 > data.len() { return None; }
                    let val = u64::from_be_bytes(data[pos..pos + 8].try_into().ok()?);
                    pos += 8;
                    match field_code {
                        10 => cookie = Some(val),
                        11 => server_version = Some(val),
                        _ => {}
                    }
                }
                // Hash128 (type=4)
                4 => {
                    if pos + 16 > data.len() { return None; }
                    pos += 16;
                }
                // Hash256 (type=5)
                5 => {
                    if pos + 32 > data.len() { return None; }
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&data[pos..pos + 32]);
                    pos += 32;
                    match field_code {
                        1 => ledger_hash = Some(h),
                        23 => consensus_hash = Some(h),
                        25 => validated_hash = Some(h),
                        _ => {}
                    }
                }
                // Amount (type=6) — 48 or 384 bits, complicated; skip for now
                6 => {
                    if pos >= data.len() { return None; }
                    // Native amount is 8 bytes, IOU is 48 bytes. Check top bit.
                    if pos + 8 > data.len() { return None; }
                    let first = data[pos];
                    if first & 0x80 != 0 && first & 0x40 == 0 {
                        // Native amount — 8 bytes
                        pos += 8;
                    } else {
                        // IOU amount — 48 bytes
                        if pos + 48 > data.len() { return None; }
                        pos += 48;
                    }
                }
                // VL/Blob (type=7)
                7 => {
                    let (vl_len, vl_consumed) = read_vl_length(&data[pos..])?;
                    pos += vl_consumed;
                    if pos + vl_len > data.len() { return None; }
                    let blob = data[pos..pos + vl_len].to_vec();
                    pos += vl_len;
                    match field_code {
                        3 => node_pubkey = Some(blob),
                        6 => signature = Some(blob),
                        _ => {}
                    }
                }
                // AccountID (type=8) — VL-prefixed
                8 => {
                    let (vl_len, vl_consumed) = read_vl_length(&data[pos..])?;
                    pos += vl_consumed;
                    if pos + vl_len > data.len() { return None; }
                    pos += vl_len;
                }
                // STObject end marker (type=14, field=1) or STArray end (type=15, field=1)
                14 | 15 => {
                    if field_code == 1 {
                        break; // end of object/array
                    }
                    // nested object/array — we can't easily skip without full parser
                    return None;
                }
                // Unknown type — we can't determine size, bail
                _ => return None,
            }
        }

        Some(Validation {
            flags: flags?,
            ledger_seq: ledger_seq?,
            sign_time: sign_time?,
            close_time,
            cookie,
            server_version,
            ledger_hash: ledger_hash?,
            consensus_hash,
            validated_hash,
            node_pubkey: node_pubkey?,
            signature: signature.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn val(hash: [u8; 32]) -> Validation {
        Validation::new_unsigned(100, hash, 0, true, vec![0x02; 33])
    }

    #[test]
    fn test_signing_bytes_prefix() {
        let v = val([0u8; 32]);
        assert_eq!(&v.signing_bytes()[..4], &[0x56, 0x41, 0x4C, 0x00]);
    }

    #[test]
    fn test_different_hashes_differ() {
        assert_ne!(val([0u8; 32]).hash(), val([1u8; 32]).hash());
    }

    #[test]
    fn test_full_vs_partial_differ() {
        let full    = Validation::new_unsigned(1, [0u8; 32], 0, true,  vec![0x02; 33]);
        let partial = Validation::new_unsigned(1, [0u8; 32], 0, false, vec![0x02; 33]);
        assert_ne!(full.hash(), partial.hash());
    }

    #[test]
    fn test_flags_full() {
        let v = Validation::new_unsigned(1, [0u8; 32], 0, true, vec![0x02; 33]);
        assert!(v.is_full());
        assert_eq!(v.flags, VF_FULLY_CANONICAL_SIG | VF_FULL_VALIDATION);
    }

    #[test]
    fn test_flags_partial() {
        let v = Validation::new_unsigned(1, [0u8; 32], 0, false, vec![0x02; 33]);
        assert!(!v.is_full());
        assert_eq!(v.flags, VF_FULLY_CANONICAL_SIG);
    }

    #[test]
    fn test_signing_bytes_stobject_format() {
        let v = val([0xAA; 32]);
        let sb = v.signing_bytes();
        // After the 4-byte prefix, first field should be sfFlags (0x22)
        assert_eq!(sb[4], 0x22);
        // Then sfLedgerSequence (0x26)
        assert_eq!(sb[4 + 1 + 4], 0x26);
        // Then sfSigningTime (0x29)
        assert_eq!(sb[4 + 1 + 4 + 1 + 4], 0x29);
    }

    #[test]
    fn test_to_bytes_from_bytes_roundtrip() {
        let mut v = Validation::new_unsigned(500, [0xBB; 32], 12345, true, vec![0x02; 33]);
        v.signature = vec![0xDE, 0xAD, 0xBE, 0xEF];
        v.close_time = Some(67890);
        v.cookie = Some(0x0102030405060708);
        v.server_version = Some(42);
        v.consensus_hash = Some([0xCC; 32]);
        v.validated_hash = Some([0xDD; 32]);

        let bytes = v.to_bytes();
        let parsed = Validation::from_bytes(&bytes).expect("parse failed");
        assert_eq!(parsed, v);
    }

    #[test]
    fn test_from_bytes_minimal() {
        let v = Validation::new_unsigned(1, [0u8; 32], 0, false, vec![0x02; 33]);
        let bytes = v.to_bytes();
        let parsed = Validation::from_bytes(&bytes).expect("parse failed");
        assert_eq!(parsed.flags, v.flags);
        assert_eq!(parsed.ledger_seq, v.ledger_seq);
        assert_eq!(parsed.ledger_hash, v.ledger_hash);
        assert_eq!(parsed.close_time, None);
        assert_eq!(parsed.cookie, None);
    }
}
