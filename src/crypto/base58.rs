//! XRPL base58check encoding/decoding.
//!
//! XRPL uses a custom base58 alphabet — different from Bitcoin's:
//!   rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz
//!
//! Prefixes:
//!   0x00  → account address  (r...)
//!   0x21  → family seed      (s...)
//!   0x1C  → node public key  (n...)

use crate::crypto::sha256d;
use thiserror::Error;

/// XRPL's custom base58 alphabet.
const ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// Version prefixes recognised by the XRPL.
pub const PREFIX_ACCOUNT_ID: u8 = 0x00;
pub const PREFIX_FAMILY_SEED: u8 = 0x21;
pub const PREFIX_NODE_PUBLIC: u8 = 0x1C;

#[derive(Debug, Error)]
pub enum Base58Error {
    #[error("invalid base58 character: {0:?}")]
    InvalidChar(char),
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("wrong payload length: expected {expected}, got {got}")]
    WrongLength { expected: usize, got: usize },
}

/// Encode `payload` with `prefix` byte and a 4-byte checksum.
pub fn encode(prefix: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(1 + payload.len() + 4);
    data.push(prefix);
    data.extend_from_slice(payload);
    let check = &sha256d(&data)[..4];
    data.extend_from_slice(check);

    // Count leading zero bytes (they become leading 'r' chars in this alphabet)
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert to base58
    let mut n = num_bigint::BigUint::from_bytes_be(&data);
    let base = num_bigint::BigUint::from(58u32);
    let mut digits: Vec<u8> = Vec::new();
    while n > num_bigint::BigUint::ZERO {
        let (q, r) = (&n / &base, &n % &base);
        digits.push(r.to_u32_digits().first().copied().unwrap_or(0) as u8);
        n = q;
    }
    digits.reverse();

    let mut result = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        result.push(ALPHABET[0] as char);
    }
    for d in digits {
        result.push(ALPHABET[d as usize] as char);
    }
    result
}

/// Decode a base58check string, returning `(prefix, payload)`.
pub fn decode(s: &str) -> Result<(u8, Vec<u8>), Base58Error> {
    // Build reverse lookup
    let mut lookup = [0xff_u8; 128];
    for (i, &c) in ALPHABET.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let mut n = num_bigint::BigUint::ZERO;
    let base = num_bigint::BigUint::from(58u32);
    let mut leading_zeros = 0usize;
    let mut past_leading = false;

    for ch in s.chars() {
        let idx = ch as usize;
        if idx >= 128 || lookup[idx] == 0xff {
            return Err(Base58Error::InvalidChar(ch));
        }
        let val = lookup[idx];
        if !past_leading {
            if val == 0 {
                leading_zeros += 1;
            } else {
                past_leading = true;
            }
        }
        n = n * &base + num_bigint::BigUint::from(val);
    }

    let mut decoded = n.to_bytes_be();
    // Prepend leading zero bytes
    let mut full = vec![0u8; leading_zeros];
    full.append(&mut decoded);

    // Must have at least prefix + 4-byte checksum
    if full.len() < 5 {
        return Err(Base58Error::BadChecksum);
    }

    let (body, check) = full.split_at(full.len() - 4);
    let expected = &sha256d(body)[..4];
    if check != expected {
        return Err(Base58Error::BadChecksum);
    }

    let prefix = body[0];
    Ok((prefix, body[1..].to_vec()))
}

/// Encode a 20-byte account ID as an `r...` address.
pub fn encode_account(id: &[u8; 20]) -> String {
    encode(PREFIX_ACCOUNT_ID, id)
}

/// Decode an `r...` address into a 20-byte account ID.
pub fn decode_account(address: &str) -> Result<[u8; 20], Base58Error> {
    let (prefix, payload) = decode(address)?;
    if prefix != PREFIX_ACCOUNT_ID {
        return Err(Base58Error::BadChecksum);
    }
    if payload.len() != 20 {
        return Err(Base58Error::WrongLength {
            expected: 20,
            got: payload.len(),
        });
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&payload);
    Ok(out)
}

/// Encode 16 bytes of entropy as an `s...` family seed.
pub fn encode_seed(entropy: &[u8; 16]) -> String {
    encode(PREFIX_FAMILY_SEED, entropy)
}

/// Decode an `s...` family seed into 16 bytes of entropy.
pub fn decode_seed(seed: &str) -> Result<[u8; 16], Base58Error> {
    let (prefix, payload) = decode(seed)?;
    if prefix != PREFIX_FAMILY_SEED {
        return Err(Base58Error::BadChecksum);
    }
    if payload.len() != 16 {
        return Err(Base58Error::WrongLength {
            expected: 16,
            got: payload.len(),
        });
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known XRPL genesis account address.
    #[test]
    fn test_genesis_account() {
        // The XRPL "black hole" account (all zeros pubkey hash)
        let id = [0u8; 20];
        let addr = encode_account(&id);
        // Known encoding of zero account ID
        assert!(
            addr.starts_with('r'),
            "address must start with r, got {addr}"
        );
    }

    /// Round-trip: encode then decode should give back the same bytes.
    #[test]
    fn test_account_roundtrip() {
        let id: [u8; 20] = [
            0x5E, 0x7B, 0x0F, 0xA1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        ];
        let addr = encode_account(&id);
        let decoded = decode_account(&addr).expect("round-trip failed");
        assert_eq!(id, decoded);
    }

    /// Known XRPL address from the docs.
    #[test]
    fn test_known_address() {
        // rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh is the genesis account
        // derived from the well-known family seed "masterpassphrase"
        let addr = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
        let result = decode_account(addr);
        assert!(
            result.is_ok(),
            "failed to decode known address: {:?}",
            result
        );
    }

    /// Seed round-trip.
    #[test]
    fn test_seed_roundtrip() {
        let entropy = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let encoded = encode_seed(&entropy);
        assert!(
            encoded.starts_with('s'),
            "seed must start with s, got {encoded}"
        );
        let decoded = decode_seed(&encoded).expect("seed round-trip failed");
        assert_eq!(entropy, decoded);
    }

    /// Bad checksum should be rejected.
    #[test]
    fn test_bad_checksum() {
        let mut addr = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".to_string();
        // Flip the last character
        let last = addr.pop().unwrap();
        addr.push(if last == 'h' { 'a' } else { 'h' });
        assert!(decode_account(&addr).is_err());
    }
}
