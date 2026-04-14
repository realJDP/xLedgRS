//! Validator list fetch — download and verify UNL from publisher sites.
//!
//! Implements rippled's ValidatorSite + ValidatorList pattern:
//! 1. HTTP(S) GET from configured publisher sites
//! 2. Parse response JSON (version 1: manifest + blob + signature)
//! 3. Verify blob signature with publisher key
//! 4. Parse blob to extract validator master public keys
//! 5. Update the shared UNL

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Fetched validator list — parsed and verified.
pub struct ValidatorList {
    pub sequence: u64,
    /// Validator master public keys (hex-encoded).
    pub validators: Vec<String>,
}

/// Fetch a validator list from a publisher URL (HTTP or HTTPS GET).
/// Returns the raw JSON response body.
async fn fetch_url(url: &str) -> anyhow::Result<String> {
    let (scheme, rest) = url.split_once("://")
        .ok_or_else(|| anyhow::anyhow!("invalid URL: {}", url))?;

    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(443)),
        None => match scheme {
            "https" => (host_port, 443),
            _ => (host_port, 80),
        },
    };

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\n\r\n",
        path, host,
    );

    let response = match scheme {
        "https" => fetch_https(host, port, &request).await?,
        "http" => fetch_http(host, port, &request).await?,
        _ => return Err(anyhow::anyhow!("unsupported scheme: {}", scheme)),
    };

    // Extract body after HTTP headers.
    let body_start = response.find("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("no HTTP body separator"))?;
    let body = &response[body_start + 4..];

    // Handle chunked transfer encoding.
    if response.contains("Transfer-Encoding: chunked") {
        Ok(decode_chunked(body))
    } else {
        Ok(body.to_string())
    }
}

async fn fetch_http(host: &str, port: u16, request: &str) -> anyhow::Result<String> {
    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    stream.write_all(request.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

async fn fetch_https(host: &str, port: u16, request: &str) -> anyhow::Result<String> {
    use rustls::ClientConfig;
    use rustls_pki_types::ServerName;
    use std::sync::Arc as StdArc;
    use tokio_rustls::TlsConnector;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(StdArc::new(config));

    let tcp = TcpStream::connect(format!("{}:{}", host, port)).await?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("invalid server name: {}", e))?;
    let mut tls = connector.connect(server_name, tcp).await?;

    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;
    // Signal end of writing so server knows we're done.
    tls.shutdown().await.ok();

    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn decode_chunked(data: &str) -> String {
    let mut result = String::new();
    let mut rest = data;
    loop {
        let line_end = match rest.find("\r\n") {
            Some(i) => i,
            None => break,
        };
        let size = usize::from_str_radix(&rest[..line_end], 16).unwrap_or(0);
        if size == 0 { break; }
        rest = &rest[line_end + 2..];
        if rest.len() < size { break; }
        result.push_str(&rest[..size]);
        rest = &rest[size..];
        if rest.starts_with("\r\n") { rest = &rest[2..]; }
    }
    result
}

/// Parse a version-1 validator list response and verify the blob signature.
///
/// `publisher_keys`: hex-encoded Ed25519 public keys trusted as publisher keys.
/// Returns the parsed validator list, or an error.
pub fn parse_and_verify(
    response_json: &str,
    publisher_keys: &[String],
) -> anyhow::Result<ValidatorList> {
    let json: serde_json::Value = serde_json::from_str(response_json)?;

    let version = json["version"].as_u64().unwrap_or(1);
    if version != 1 {
        return Err(anyhow::anyhow!("unsupported validator list version: {}", version));
    }

    let blob_b64 = json["blob"].as_str()
        .ok_or_else(|| anyhow::anyhow!("missing 'blob' field"))?;
    let signature_hex = json["signature"].as_str()
        .ok_or_else(|| anyhow::anyhow!("missing 'signature' field"))?;
    let manifest_b64 = json["manifest"].as_str()
        .ok_or_else(|| anyhow::anyhow!("missing 'manifest' field"))?;

    // Decode the blob (what's signed).
    let blob_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD, blob_b64,
    )?;

    // Decode the signature.
    let sig_bytes = hex::decode(signature_hex)?;

    // Decode the manifest to extract the publisher's master key.
    let manifest_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD, manifest_b64,
    )?;

    // Extract the master public key from the manifest.
    // Manifest is an STObject: look for sfPublicKey (type=7 VL, field=1).
    let master_key = extract_manifest_master_key(&manifest_bytes)
        .ok_or_else(|| anyhow::anyhow!("could not extract master key from manifest"))?;
    let master_key_hex = hex::encode_upper(&master_key);

    // Check that the master key is in our trusted publisher keys list.
    let trusted = publisher_keys.iter().any(|k| k.eq_ignore_ascii_case(&master_key_hex));
    if !trusted {
        return Err(anyhow::anyhow!(
            "publisher key {} not in trusted list", &master_key_hex[..16],
        ));
    }

    // Extract the signing key from the manifest (sfSigningPubKey, type=7 VL, field=3).
    let signing_key = extract_manifest_signing_key(&manifest_bytes)
        .ok_or_else(|| anyhow::anyhow!("could not extract signing key from manifest"))?;

    // Verify the blob signature using the signing key.
    verify_signature(&signing_key, &blob_bytes, &sig_bytes)?;

    // Parse the blob JSON to extract validators.
    let blob_json: serde_json::Value = serde_json::from_slice(&blob_bytes)?;
    let sequence = blob_json["sequence"].as_u64().unwrap_or(0);
    let validators_arr = blob_json["validators"].as_array()
        .ok_or_else(|| anyhow::anyhow!("missing 'validators' in blob"))?;

    let mut validators = Vec::new();
    for v in validators_arr {
        if let Some(key_hex) = v["validation_public_key"].as_str() {
            validators.push(key_hex.to_uppercase());
        }
    }

    Ok(ValidatorList { sequence, validators })
}

/// Extract sfPublicKey (type=7 VL, field=1) from a manifest STObject.
fn extract_manifest_master_key(manifest: &[u8]) -> Option<Vec<u8>> {
    extract_manifest_vl_field(manifest, 1)
}

/// Extract sfSigningPubKey (type=7 VL, field=3) from a manifest STObject.
fn extract_manifest_signing_key(manifest: &[u8]) -> Option<Vec<u8>> {
    extract_manifest_vl_field(manifest, 3)
}

/// Extract a VL (type=7) field by field_code from an STObject.
fn extract_manifest_vl_field(data: &[u8], target_field: u8) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos < data.len() {
        let byte = data[pos]; pos += 1;
        let hi = (byte >> 4) & 0x0F;
        let lo = byte & 0x0F;
        let (type_code, field_code) = if hi != 0 && lo != 0 {
            (hi, lo)
        } else if hi == 0 && lo != 0 {
            if pos >= data.len() { return None; }
            let t = data[pos]; pos += 1;
            (t, lo)
        } else if hi != 0 && lo == 0 {
            if pos >= data.len() { return None; }
            let f = data[pos]; pos += 1;
            (hi, f)
        } else {
            if pos + 1 >= data.len() { return None; }
            let t = data[pos]; pos += 1;
            let f = data[pos]; pos += 1;
            (t, f)
        };

        match type_code {
            1 => { // UInt16
                if pos + 2 > data.len() { return None; }
                pos += 2;
            }
            2 => { // UInt32
                if pos + 4 > data.len() { return None; }
                pos += 4;
            }
            7 => { // VL
                if pos >= data.len() { return None; }
                let (len, consumed) = decode_vl(data, pos);
                pos += consumed;
                if pos + len > data.len() { return None; }
                if field_code == target_field {
                    return Some(data[pos..pos + len].to_vec());
                }
                pos += len;
            }
            _ => {
                // Unknown type — can't determine length, stop.
                return None;
            }
        }
    }
    None
}

fn decode_vl(data: &[u8], pos: usize) -> (usize, usize) {
    if pos >= data.len() { return (0, 0); }
    let b0 = data[pos] as usize;
    if b0 <= 192 {
        (b0, 1)
    } else if b0 <= 240 {
        if pos + 1 >= data.len() { return (0, 1); }
        let b1 = data[pos + 1] as usize;
        (193 + ((b0 - 193) * 256) + b1, 2)
    } else {
        if pos + 2 >= data.len() { return (0, 1); }
        let b1 = data[pos + 1] as usize;
        let b2 = data[pos + 2] as usize;
        (12481 + ((b0 - 241) * 65536) + (b1 * 256) + b2, 3)
    }
}

/// Verify a signature. Supports Ed25519 (0xED prefix) and secp256k1.
fn verify_signature(pubkey: &[u8], message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
    if pubkey.len() == 33 && pubkey[0] == 0xED {
        // Ed25519
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let key_bytes: [u8; 32] = pubkey[1..33].try_into()
            .map_err(|_| anyhow::anyhow!("invalid Ed25519 key length"))?;
        let vk = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| anyhow::anyhow!("invalid Ed25519 key: {}", e))?;
        let sig = Signature::from_slice(signature)
            .map_err(|e| anyhow::anyhow!("invalid Ed25519 signature: {}", e))?;
        vk.verify(message, &sig)
            .map_err(|e| anyhow::anyhow!("Ed25519 signature verification failed: {}", e))
    } else if pubkey.len() == 33 {
        // secp256k1
        use secp256k1::{Message, Secp256k1};
        let secp = Secp256k1::verification_only();
        let pk = secp256k1::PublicKey::from_slice(pubkey)
            .map_err(|e| anyhow::anyhow!("invalid secp256k1 key: {}", e))?;
        // rippled signs with SHA-512-Half of the message.
        let hash = crate::crypto::sha512_first_half(message);
        let msg = Message::from_digest(hash);
        let sig = secp256k1::ecdsa::Signature::from_der(signature)
            .map_err(|e| anyhow::anyhow!("invalid secp256k1 signature: {}", e))?;
        secp.verify_ecdsa(&msg, &sig, &pk)
            .map_err(|e| anyhow::anyhow!("secp256k1 signature verification failed: {}", e))
    } else {
        Err(anyhow::anyhow!("unsupported public key format (len={})", pubkey.len()))
    }
}

/// Verify a validator list received via peer protocol (TMValidatorList message).
///
/// The protobuf fields contain: manifest (raw bytes), blob (base64), signature (hex).
/// This matches the HTTP response format — the protobuf just wraps the same data.
///
/// Returns the parsed list on success, or an error.
pub fn verify_peer_validator_list(
    manifest: &[u8],
    blob: &[u8],
    signature: &[u8],
    publisher_keys: &[String],
) -> anyhow::Result<ValidatorList> {
    // The blob and signature in the protobuf are the raw base64 and hex strings
    // from the publisher, passed through as bytes. Decode them.
    let blob_str = std::str::from_utf8(blob)
        .map_err(|_| anyhow::anyhow!("blob is not valid UTF-8"))?;
    let sig_str = std::str::from_utf8(signature)
        .map_err(|_| anyhow::anyhow!("signature is not valid UTF-8"))?;

    // Decode blob from base64
    let blob_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD, blob_str,
    ).map_err(|e| anyhow::anyhow!("blob base64 decode: {}", e))?;

    // Decode signature from hex
    let sig_bytes = hex::decode(sig_str)
        .map_err(|e| anyhow::anyhow!("signature hex decode: {}", e))?;

    // Extract master key from manifest and check trust
    let master_key = extract_manifest_master_key(manifest)
        .ok_or_else(|| anyhow::anyhow!("could not extract master key from manifest"))?;
    let master_key_hex = hex::encode_upper(&master_key);

    let trusted = publisher_keys.iter().any(|k| k.eq_ignore_ascii_case(&master_key_hex));
    if !trusted {
        return Err(anyhow::anyhow!(
            "publisher key {} not in trusted list", &master_key_hex[..16.min(master_key_hex.len())],
        ));
    }

    // Extract signing key and verify
    let signing_key = extract_manifest_signing_key(manifest)
        .ok_or_else(|| anyhow::anyhow!("could not extract signing key from manifest"))?;
    verify_signature(&signing_key, &blob_bytes, &sig_bytes)?;

    // Parse blob JSON
    let blob_json: serde_json::Value = serde_json::from_slice(&blob_bytes)?;
    let sequence = blob_json["sequence"].as_u64().unwrap_or(0);
    let validators_arr = blob_json["validators"].as_array()
        .ok_or_else(|| anyhow::anyhow!("missing 'validators' in blob"))?;

    let mut validators = Vec::new();
    for v in validators_arr {
        if let Some(key_hex) = v["validation_public_key"].as_str() {
            validators.push(key_hex.to_uppercase());
        }
    }

    Ok(ValidatorList { sequence, validators })
}

/// Convert hex-encoded validator public keys to raw bytes for the UNL.
pub fn hex_keys_to_unl(hex_keys: &[String]) -> Vec<Vec<u8>> {
    hex_keys.iter()
        .filter_map(|h| hex::decode(h).ok())
        .collect()
}

/// Run the validator list fetch loop.
/// Fetches from all configured sites, verifies, and updates the shared UNL.
pub async fn run_validator_list_fetch(
    sites: Vec<String>,
    publisher_keys: Vec<String>,
    unl: Arc<std::sync::RwLock<Vec<Vec<u8>>>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;

    if sites.is_empty() || publisher_keys.is_empty() {
        tracing::debug!("no validator list sites or publisher keys configured — skipping fetch");
        return;
    }

    // Wait 5s on startup before first fetch.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let mut best_sequence = 0u64;

    loop {
        if shutdown.load(Ordering::Relaxed) { break; }

        for site in &sites {
            tracing::info!("fetching validator list from {}", site);
            match fetch_url(site).await {
                Ok(body) => {
                    match parse_and_verify(&body, &publisher_keys) {
                        Ok(list) => {
                            if list.sequence > best_sequence {
                                best_sequence = list.sequence;
                                let new_unl = hex_keys_to_unl(&list.validators);
                                let count = new_unl.len();
                                *unl.write().unwrap_or_else(|e| e.into_inner()) = new_unl;
                                tracing::info!(
                                    "validator list updated: {} validators (seq={})",
                                    count, list.sequence,
                                );
                            } else {
                                tracing::debug!(
                                    "validator list seq={} not newer than current seq={}",
                                    list.sequence, best_sequence,
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!("validator list verification failed for {}: {}", site, e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("failed to fetch validator list from {}: {}", site, e);
                }
            }
        }

        // Refresh every 5 minutes.
        for _ in 0..60 {
            if shutdown.load(Ordering::Relaxed) { return; }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}
