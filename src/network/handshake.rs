//! XRPL peer handshake — HTTP upgrade to RTXP binary protocol.
//!
//! After a TLS connection is established, peers negotiate the protocol
//! using an HTTP/1.1 upgrade exchange before switching to RTXP framing:
//!
//! **Initiator sends:**
//! ```text
//! GET / HTTP/1.1
//! User-Agent: xledgrs/0.1.0
//! Upgrade: XRPL/2.2
//! Connection: Upgrade
//! Connect-As: Peer
//! Public-Key: <node pubkey, base58 n... prefix>
//! Session-Signature: <base64(sign(tls_session_hash))>
//! Network-ID: 0
//! Network-Time: <ripple_epoch_seconds>
//! Instance-Cookie: <random_u64>
//! Closed-Ledger: <hex_hash>
//! Previous-Ledger: <hex_hash>
//! X-Protocol-Ctl: compr=lz4
//! ```
//!
//! **Responder replies (success):**
//! ```text
//! HTTP/1.1 101 Switching Protocols
//! Connection: Upgrade
//! Upgrade: XRPL/2.2
//! Connect-As: Peer
//! Public-Key: <node pubkey>
//! Session-Signature: <base64(sign(tls_session_hash))>
//! ```
//!
//! After the 101 response both sides switch to RTXP binary framing.
//! The session signature proves possession of the private key for the
//! advertised public key, preventing identity spoofing.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::HashMap;
use thiserror::Error;

use crate::crypto::base58::{decode, encode, PREFIX_NODE_PUBLIC};

// ── Protocol constants ────────────────────────────────────────────────────────

pub const XRPL_PROTOCOL: &str = "XRPL/2.2";
pub const XRPL_PROTOCOL_MIN: &str = "XRPL/2.0";
pub const USER_AGENT: &str = concat!("xledgrs/", env!("CARGO_PKG_VERSION"));

/// Ripple epoch: 2000-01-01T00:00:00Z in Unix epoch seconds.
const RIPPLE_EPOCH: u64 = 946684800;

// ── Outgoing request ──────────────────────────────────────────────────────────

/// Build the HTTP upgrade request sent by the initiating peer.
///
/// `node_pubkey` — 33-byte compressed secp256k1 public key (or 32-byte Ed25519).
/// `session_signature` — signature over the TLS session hash (see below).
/// `network_id` — network identifier (0 = mainnet, 1 = testnet).
/// `ledger_hash` — hex hash of the last closed ledger.
/// `parent_hash` — hex hash of the parent of the last closed ledger.
pub fn build_request(
    node_pubkey: &[u8],
    session_signature: &[u8],
    network_id: u32,
    ledger_hash: &str,
    parent_hash: &str,
) -> String {
    let pubkey_b58 = encode(PREFIX_NODE_PUBLIC, node_pubkey);
    let sig_b64 = B64.encode(session_signature);
    let network_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().saturating_sub(RIPPLE_EPOCH))
        .unwrap_or(0);
    let cookie: u64 = rand::random();
    format!(
        "GET / HTTP/1.1\r\n\
User-Agent: {USER_AGENT}\r\n\
Upgrade: {XRPL_PROTOCOL}\r\n\
Connection: Upgrade\r\n\
Connect-As: Peer\r\n\
Crawl: public\r\n\
Public-Key: {pubkey_b58}\r\n\
Session-Signature: {sig_b64}\r\n\
Network-ID: {network_id}\r\n\
Network-Time: {network_time}\r\n\
Instance-Cookie: {cookie}\r\n\
Closed-Ledger: {ledger_hash}\r\n\
Previous-Ledger: {parent_hash}\r\n\
X-Protocol-Ctl: compr=lz4\r\n\
\r\n"
    )
}

/// Build the HTTP upgrade request with minimal headers (backward compatible).
pub fn build_request_simple(node_pubkey: &[u8], session_signature: &[u8]) -> String {
    build_request(
        node_pubkey,
        session_signature,
        0,
        &"0".repeat(64),
        &"0".repeat(64),
    )
}

/// Build the 101 Switching Protocols response sent by the accepting peer.
pub fn build_response(node_pubkey: &[u8], session_signature: &[u8]) -> String {
    let pubkey_b58 = encode(PREFIX_NODE_PUBLIC, node_pubkey);
    let sig_b64 = B64.encode(session_signature);
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
Connection: Upgrade\r\n\
Upgrade: {XRPL_PROTOCOL}\r\n\
Connect-As: Peer\r\n\
Public-Key: {pubkey_b58}\r\n\
Session-Signature: {sig_b64}\r\n\
\r\n"
    )
}

/// Build a rejection response (e.g. too many peers).
pub fn build_rejection(reason: &str) -> String {
    format!(
        "HTTP/1.1 503 Service Unavailable\r\n\
         Server: {USER_AGENT}\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {reason}",
        reason.len()
    )
}

// ── Parsed handshake ──────────────────────────────────────────────────────────

/// The information extracted from a completed handshake.
#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    /// The remote peer's node public key (raw bytes, 33 for secp256k1).
    pub node_pubkey: Vec<u8>,
    /// The remote peer's session signature (raw bytes).
    pub session_signature: Vec<u8>,
    /// Negotiated protocol version string (e.g. "XRPL/2.2").
    pub protocol: String,
    /// Remote peer's user-agent string, if provided.
    pub user_agent: Option<String>,
    /// Network ID from the peer (0 = mainnet, 1 = testnet).
    pub network_id: Option<u32>,
    /// Network time (Ripple epoch seconds) from the peer.
    pub network_time: Option<u64>,
    /// Hex hash of the peer's last closed ledger.
    pub closed_ledger: Option<String>,
    /// Hex hash of the peer's previous ledger.
    pub previous_ledger: Option<String>,
    /// X-Protocol-Ctl value (e.g. "compr=lz4").
    pub features: Option<String>,
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse HTTP headers from a raw request or response, returning
/// (status_or_request_line, headers_map, bytes_consumed).
///
/// Returns `None` if the full header block hasn't arrived yet.
fn parse_http_headers(buf: &[u8]) -> Option<(String, HashMap<String, String>, usize)> {
    // Find the blank line that ends the headers (\r\n\r\n)
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_block = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = header_block.split("\r\n");

    let first_line = lines.next()?.to_string();
    let mut headers = HashMap::new();

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    Some((first_line, headers, end + 4))
}

/// Parse and validate an incoming upgrade **request** from a peer.
///
/// Returns `(HandshakeInfo, bytes_consumed)` on success.
pub fn parse_request(buf: &[u8]) -> Result<Option<(HandshakeInfo, usize)>, HandshakeError> {
    let Some((first_line, headers, consumed)) = parse_http_headers(buf) else {
        return Ok(None); // incomplete
    };

    // Must be GET /
    if !first_line.starts_with("GET") {
        return Err(HandshakeError::UnexpectedMethod(first_line));
    }

    validate_and_extract(headers, consumed)
}

/// Parse and validate an incoming upgrade **response** from a peer.
///
/// Returns `(HandshakeInfo, bytes_consumed)` on success,
/// or `Err(HandshakeError::Rejected)` if the peer sent a non-101.
pub fn parse_response(buf: &[u8]) -> Result<Option<(HandshakeInfo, usize)>, HandshakeError> {
    let Some((first_line, headers, consumed)) = parse_http_headers(buf) else {
        return Ok(None); // incomplete
    };

    if !first_line.contains("101") {
        let status = first_line.splitn(3, ' ').nth(1).unwrap_or("?").to_string();
        let raw = String::from_utf8_lossy(&buf[..consumed]).to_string();
        return Err(HandshakeError::Rejected { status, raw });
    }

    validate_and_extract(headers, consumed)
}

fn validate_and_extract(
    headers: HashMap<String, String>,
    consumed: usize,
) -> Result<Option<(HandshakeInfo, usize)>, HandshakeError> {
    // Validate Upgrade header
    let upgrade = headers
        .get("upgrade")
        .ok_or(HandshakeError::MissingHeader("Upgrade"))?;
    if !upgrade.starts_with("XRPL/") {
        return Err(HandshakeError::UnsupportedProtocol(upgrade.clone()));
    }
    let protocol = upgrade.clone();

    // Validate Connect-As
    let connect_as = headers
        .get("connect-as")
        .ok_or(HandshakeError::MissingHeader("Connect-As"))?;
    if connect_as.to_lowercase() != "peer" {
        return Err(HandshakeError::UnexpectedConnectAs(connect_as.clone()));
    }

    // Decode Public-Key (base58 node pubkey)
    let pubkey_b58 = headers
        .get("public-key")
        .ok_or(HandshakeError::MissingHeader("Public-Key"))?;
    let (prefix, node_pubkey) =
        decode(pubkey_b58).map_err(|_| HandshakeError::InvalidPublicKey(pubkey_b58.clone()))?;
    if prefix != PREFIX_NODE_PUBLIC {
        return Err(HandshakeError::InvalidPublicKey(pubkey_b58.clone()));
    }

    // Decode Session-Signature (base64)
    let sig_b64 = headers
        .get("session-signature")
        .ok_or(HandshakeError::MissingHeader("Session-Signature"))?;
    let session_signature = B64
        .decode(sig_b64)
        .map_err(|_| HandshakeError::InvalidSessionSignature)?;

    let user_agent = headers.get("user-agent").cloned();

    // Extract optional rippled-compatible headers
    let network_id = headers
        .get("network-id")
        .and_then(|v| v.parse::<u32>().ok());
    let network_time = headers
        .get("network-time")
        .and_then(|v| v.parse::<u64>().ok());
    let closed_ledger = headers.get("closed-ledger").cloned();
    let previous_ledger = headers.get("previous-ledger").cloned();
    let features = headers.get("x-protocol-ctl").cloned();

    Ok(Some((
        HandshakeInfo {
            node_pubkey,
            session_signature,
            protocol,
            user_agent,
            network_id,
            network_time,
            closed_ledger,
            previous_ledger,
            features,
        },
        consumed,
    )))
}

// ── Session hash ──────────────────────────────────────────────────────────────

/// Compute the value that peers sign to prove they hold their private key.
///
/// In production this is derived from the TLS Finished message (the session
/// hash from the TLS handshake). For testing, any shared 32-byte value works.
///
/// Both peers must sign the *same* session hash — the value is deterministic
/// given the TLS session so both sides can independently verify.
pub fn session_hash_to_sign(tls_finished_hash: &[u8]) -> [u8; 32] {
    crate::crypto::sha256(tls_finished_hash)
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("unexpected HTTP method: {0}")]
    UnexpectedMethod(String),
    #[error("peer rejected connection with status {status}")]
    Rejected { status: String, raw: String },
    #[error("missing required header: {0}")]
    MissingHeader(&'static str),
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("unexpected Connect-As value: {0}")]
    UnexpectedConnectAs(String),
    #[error("invalid node public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid session signature encoding")]
    InvalidSessionSignature,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Secp256k1KeyPair;

    fn test_keypair() -> Secp256k1KeyPair {
        Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap()
    }

    fn make_session_sig(kp: &Secp256k1KeyPair) -> Vec<u8> {
        let hash = session_hash_to_sign(b"fake-tls-finished");
        kp.sign(&hash)
    }

    #[test]
    fn test_request_roundtrip() {
        let kp = test_keypair();
        let pub_bytes = kp.public_key_bytes();
        let sig = make_session_sig(&kp);

        let req = build_request(&pub_bytes, &sig, 0, &"AA".repeat(32), &"BB".repeat(32));
        assert!(req.starts_with("GET / HTTP/1.1\r\n"));
        assert!(req.contains("Upgrade: XRPL/2.2"));
        assert!(req.contains("Connect-As: Peer"));
        assert!(req.contains("Network-ID: 0"));
        assert!(req.contains("X-Protocol-Ctl: compr=lz4"));
        assert!(req.ends_with("\r\n\r\n"));

        let (info, consumed) = parse_request(req.as_bytes())
            .unwrap()
            .expect("should parse successfully");

        assert_eq!(consumed, req.len());
        assert_eq!(info.node_pubkey, pub_bytes);
        assert_eq!(info.session_signature, sig);
        assert_eq!(info.protocol, XRPL_PROTOCOL);
        assert_eq!(info.user_agent.as_deref(), Some(USER_AGENT));
        assert_eq!(info.network_id, Some(0));
        assert!(info.closed_ledger.is_some());
        assert!(info.previous_ledger.is_some());
        assert_eq!(info.features.as_deref(), Some("compr=lz4"));
    }

    #[test]
    fn test_response_roundtrip() {
        let kp = test_keypair();
        let pub_bytes = kp.public_key_bytes();
        let sig = make_session_sig(&kp);

        let resp = build_response(&pub_bytes, &sig);
        assert!(resp.starts_with("HTTP/1.1 101"));

        let (info, consumed) = parse_response(resp.as_bytes())
            .unwrap()
            .expect("should parse successfully");

        assert_eq!(consumed, resp.len());
        assert_eq!(info.node_pubkey, pub_bytes);
        assert_eq!(info.session_signature, sig);
    }

    #[test]
    fn test_incomplete_returns_none() {
        let partial = b"GET / HTTP/1.1\r\nUpgrade: XRPL/2.2\r\n";
        let result = parse_request(partial).unwrap();
        assert!(result.is_none(), "incomplete headers should return None");
    }

    #[test]
    fn test_rejection_response_returns_error() {
        let rejection = build_rejection("Too many peers");
        let err = parse_response(rejection.as_bytes()).unwrap_err();
        assert!(matches!(err, HandshakeError::Rejected { .. }));
    }

    #[test]
    fn test_missing_public_key_header() {
        let bad = "HTTP/1.1 101 Switching Protocols\r\n\
                   Connection: Upgrade\r\n\
                   Upgrade: XRPL/2.2\r\n\
                   Connect-As: Peer\r\n\
                   Session-Signature: AAAA\r\n\
                   \r\n";
        let err = parse_response(bad.as_bytes()).unwrap_err();
        assert!(matches!(err, HandshakeError::MissingHeader("Public-Key")));
    }

    #[test]
    fn test_unsupported_protocol_rejected() {
        let bad = "HTTP/1.1 101 Switching Protocols\r\n\
                   Connection: Upgrade\r\n\
                   Upgrade: WebSocket/13\r\n\
                   Connect-As: Peer\r\n\
                   Public-Key: nHBt9fsb4849WmZiCds4r7TXzVtRyew4pu7U4bwxrfPBxAkbRkd6\r\n\
                   Session-Signature: AAAA\r\n\
                   \r\n";
        let err = parse_response(bad.as_bytes()).unwrap_err();
        assert!(matches!(err, HandshakeError::UnsupportedProtocol(_)));
    }

    #[test]
    fn test_session_hash_deterministic() {
        let h1 = session_hash_to_sign(b"tls-data");
        let h2 = session_hash_to_sign(b"tls-data");
        assert_eq!(h1, h2);
        let h3 = session_hash_to_sign(b"different");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_build_rejection_contains_reason() {
        let r = build_rejection("node is syncing");
        assert!(r.contains("503"));
        assert!(r.contains("node is syncing"));
    }

    #[test]
    fn test_simple_request_backward_compat() {
        let kp = test_keypair();
        let pub_bytes = kp.public_key_bytes();
        let sig = make_session_sig(&kp);
        let req = build_request_simple(&pub_bytes, &sig);
        assert!(req.contains("Network-ID: 0"));
        let (info, _) = parse_request(req.as_bytes()).unwrap().unwrap();
        assert_eq!(info.node_pubkey, pub_bytes);
    }
}
