//! XRPL peer handshake — HTTP upgrade to RTXP binary protocol.
//!
//! After a TLS connection is established, peers negotiate the protocol
//! using an HTTP/1.1 upgrade exchange before switching to RTXP framing:
//!
//! **Initiator sends:**
//! ```text
//! GET / HTTP/1.1
//! User-Agent: xLedgRSv2Beta/0.1.0
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
pub const USER_AGENT: &str = concat!("xLedgRSv2Beta/", env!("CARGO_PKG_VERSION"));

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
X-Protocol-Ctl: compr=lz4\r\n\
\r\n"
    )
}

/// Build a rejection response (e.g. too many peers).
pub fn build_rejection(reason: &str) -> String {
    let escaped_reason = reason.replace('\\', "\\\\").replace('"', "\\\"");
    let body = format!("{{\"error\":\"{escaped_reason}\"}}\n");
    format!(
        "HTTP/1.1 503 Service Unavailable\r\n\
Server: {USER_AGENT}\r\n\
Connection: close\r\n\
Content-Type: application/json\r\n\
Content-Length: {}\r\n\
\r\n\
{body}",
        body.len()
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
fn find_header_end(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((end, end + 4));
    }
    if let Some(end) = buf.windows(2).position(|w| w == b"\n\n") {
        return Some((end, end + 2));
    }
    None
}

fn parse_http_headers(buf: &[u8]) -> Option<(String, HashMap<String, String>, usize)> {
    let (end, consumed) = find_header_end(buf)?;
    let header_block = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = header_block.lines();

    let first_line = lines.next()?.to_string();
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut current_key: Option<String> = None;

    for line in lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(key) = current_key.as_ref() {
                if let Some(value) = headers.get_mut(key) {
                    value.push(' ');
                    value.push_str(line.trim());
                }
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim().to_string();
            headers
                .entry(key.clone())
                .and_modify(|existing| {
                    existing.push(',');
                    existing.push_str(&value);
                })
                .or_insert(value);
            current_key = Some(key);
        } else if let Some(key) = current_key.as_ref() {
            if let Some(value) = headers.get_mut(key) {
                if value.trim_end().ends_with(',') {
                    value.push(' ');
                    value.push_str(line.trim());
                }
            }
        }
    }

    Some((first_line, headers, consumed))
}

/// Parse and validate an incoming upgrade **request** from a peer.
///
/// Returns `(HandshakeInfo, bytes_consumed)` on success.
pub fn parse_request(buf: &[u8]) -> Result<Option<(HandshakeInfo, usize)>, HandshakeError> {
    let Some((first_line, headers, consumed)) = parse_http_headers(buf) else {
        return Ok(None); // incomplete
    };

    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method != "GET" || parts.next().is_some() {
        return Err(HandshakeError::UnexpectedMethod(first_line));
    }
    if target != "/" {
        return Err(HandshakeError::UnexpectedTarget(target.to_string()));
    }
    if !version.starts_with("HTTP/1.") {
        return Err(HandshakeError::InvalidHttpVersion(version.to_string()));
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

    let mut parts = first_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(HandshakeError::InvalidHttpVersion(version.to_string()));
    }
    if status != "101" {
        let raw = String::from_utf8_lossy(&buf[..consumed]).to_string();
        return Err(HandshakeError::Rejected {
            status: if status.is_empty() { "?" } else { status }.to_string(),
            raw,
        });
    }

    validate_and_extract(headers, consumed)
}

fn header_has_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .map(|part| part.trim())
        .any(|part| part.eq_ignore_ascii_case(token))
}

pub fn protocol_ctl_advertises_lz4(value: &str) -> bool {
    value
        .split([';', ','])
        .flat_map(|part| part.split_whitespace())
        .any(|part| part.eq_ignore_ascii_case("compr=lz4"))
}

fn parse_xrpl_protocol(value: &str) -> Option<(u32, u32)> {
    let version = value.strip_prefix("XRPL/")?;
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor))
}

fn supported_protocol(value: &str) -> bool {
    let Some(found) = parse_xrpl_protocol(value) else {
        return false;
    };
    let min = parse_xrpl_protocol(XRPL_PROTOCOL_MIN).expect("valid min protocol");
    let max = parse_xrpl_protocol(XRPL_PROTOCOL).expect("valid max protocol");
    found >= min && found <= max
}

fn parse_required_u32(
    headers: &HashMap<String, String>,
    name: &'static str,
) -> Result<Option<u32>, HandshakeError> {
    headers
        .get(name)
        .map(|v| {
            v.parse::<u32>()
                .map_err(|_| HandshakeError::InvalidHeader(name, v.clone()))
        })
        .transpose()
}

fn parse_required_u64(
    headers: &HashMap<String, String>,
    name: &'static str,
) -> Result<Option<u64>, HandshakeError> {
    headers
        .get(name)
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| HandshakeError::InvalidHeader(name, v.clone()))
        })
        .transpose()
}

fn parse_optional_hash(
    headers: &HashMap<String, String>,
    name: &'static str,
) -> Result<Option<String>, HandshakeError> {
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };
    if value.len() != 64 || !value.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(HandshakeError::InvalidHeader(name, value.clone()));
    }
    Ok(Some(value.to_ascii_uppercase()))
}

fn validate_and_extract(
    headers: HashMap<String, String>,
    consumed: usize,
) -> Result<Option<(HandshakeInfo, usize)>, HandshakeError> {
    // Validate Upgrade header
    let upgrade = headers
        .get("upgrade")
        .ok_or(HandshakeError::MissingHeader("Upgrade"))?;
    if !supported_protocol(upgrade) {
        return Err(HandshakeError::UnsupportedProtocol(upgrade.clone()));
    }
    let protocol = upgrade.clone();

    let connection = headers
        .get("connection")
        .ok_or(HandshakeError::MissingHeader("Connection"))?;
    if !header_has_token(connection, "upgrade") {
        return Err(HandshakeError::InvalidHeader(
            "Connection",
            connection.clone(),
        ));
    }

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
    if prefix != PREFIX_NODE_PUBLIC || !matches!(node_pubkey.len(), 33 | 32) {
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
    let network_id = parse_required_u32(&headers, "network-id")?;
    let network_time = parse_required_u64(&headers, "network-time")?;
    let closed_ledger = parse_optional_hash(&headers, "closed-ledger")?;
    let previous_ledger = parse_optional_hash(&headers, "previous-ledger")?;
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
    #[error("unexpected HTTP request target: {0}")]
    UnexpectedTarget(String),
    #[error("invalid HTTP version: {0}")]
    InvalidHttpVersion(String),
    #[error("peer rejected connection with status {status}")]
    Rejected { status: String, raw: String },
    #[error("missing required header: {0}")]
    MissingHeader(&'static str),
    #[error("invalid header {0}: {1}")]
    InvalidHeader(&'static str, String),
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
        assert!(req.contains("Connection: Upgrade"));
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
        assert!(resp.contains("X-Protocol-Ctl: compr=lz4"));

        let (info, consumed) = parse_response(resp.as_bytes())
            .unwrap()
            .expect("should parse successfully");

        assert_eq!(consumed, resp.len());
        assert_eq!(info.node_pubkey, pub_bytes);
        assert_eq!(info.session_signature, sig);
        assert_eq!(info.features.as_deref(), Some("compr=lz4"));
    }

    #[test]
    fn test_parser_accepts_lf_and_folded_headers() {
        let kp = test_keypair();
        let pub_bytes = kp.public_key_bytes();
        let sig = make_session_sig(&kp);
        let pubkey_b58 = encode(PREFIX_NODE_PUBLIC, &pub_bytes);
        let sig_b64 = B64.encode(&sig);
        let req = format!(
            "GET / HTTP/1.1\n\
Upgrade: XRPL/2.1\n\
Connection: keep-alive,\n\
 Upgrade\n\
Connect-As: Peer\n\
Public-Key: {pubkey_b58}\n\
Session-Signature: {sig_b64}\n\
Network-ID: 0\n\
Closed-Ledger: {}\n\
Previous-Ledger: {}\n\
\n",
            "aa".repeat(32),
            "bb".repeat(32)
        );
        let (info, consumed) = parse_request(req.as_bytes()).unwrap().unwrap();
        assert_eq!(consumed, req.len());
        assert_eq!(info.protocol, "XRPL/2.1");
        assert_eq!(info.closed_ledger, Some("AA".repeat(32)));
        assert_eq!(info.previous_ledger, Some("BB".repeat(32)));
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
    fn test_missing_connection_header_rejected() {
        let kp = test_keypair();
        let pub_bytes = kp.public_key_bytes();
        let sig = make_session_sig(&kp);
        let pubkey_b58 = encode(PREFIX_NODE_PUBLIC, &pub_bytes);
        let sig_b64 = B64.encode(&sig);
        let bad = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: XRPL/2.2\r\n\
Connect-As: Peer\r\n\
Public-Key: {pubkey_b58}\r\n\
Session-Signature: {sig_b64}\r\n\
\r\n"
        );
        let err = parse_response(bad.as_bytes()).unwrap_err();
        assert!(matches!(err, HandshakeError::MissingHeader("Connection")));
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
        assert!(r.contains("Connection: close\r\n"));
        assert!(r.ends_with("{\"error\":\"node is syncing\"}\n"));
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
