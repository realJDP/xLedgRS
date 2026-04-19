//! Validator list fetch and verification for publisher-hosted UNL data.
//!
//! Implements the rippled ValidatorSite + ValidatorList pattern:
//! 1. HTTP(S) GET from configured publisher sites
//! 2. Parse response JSON (version 1: manifest + blob + signature)
//! 3. Verify blob signature with publisher key
//! 4. Parse blob to extract validator master public keys
//! 5. Update the shared UNL

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Fetched validator list — parsed and verified.
#[derive(Debug, Clone)]
pub struct ValidatorList {
    pub sequence: u64,
    /// Validator master public keys (hex-encoded).
    pub validators: Vec<String>,
    /// Publisher master public key (hex-encoded).
    pub publisher_key: String,
    /// Verified publisher manifest details used by admin inspection RPCs.
    pub manifest: Option<CachedManifestInfo>,
    /// Optional UNIX timestamp at which this list becomes active.
    pub effective: Option<u64>,
    /// Optional UNIX timestamp after which this list is no longer valid.
    pub expiration: Option<u64>,
    /// Optional publisher hint for the refresh interval, in seconds.
    pub refresh_interval: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CachedManifestInfo {
    pub master_key: String,
    pub signing_key: String,
    pub sequence: u32,
    pub domain: Option<String>,
    pub raw_manifest: String,
}

impl ValidatorList {
    fn is_active_at(&self, now: u64) -> bool {
        if self.effective.is_some_and(|effective| effective > now) {
            return false;
        }
        if self.expiration.is_some_and(|expiration| expiration <= now) {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorListApply {
    pub publisher_key: String,
    pub sequence: u64,
    pub effective_unl: Vec<Vec<u8>>,
    pub active_publishers: usize,
}

#[derive(Debug, Clone)]
pub enum ValidatorListApplyStatus {
    Accepted(ValidatorListApply),
    SameSequence,
    Stale,
    Expired,
}

#[derive(Debug, Clone)]
pub struct ValidatorSiteStatus {
    pub uri: String,
    pub last_refresh_status: Option<String>,
    pub last_refresh_time: Option<u64>,
    pub last_refresh_message: Option<String>,
    pub next_refresh_time: Option<u64>,
    pub refresh_interval_secs: u64,
}

#[derive(Debug, Clone)]
pub struct ValidatorPublisherSnapshot {
    pub publisher_key: String,
    pub current: Option<ValidatorPublisherListSnapshot>,
    pub remaining: Vec<ValidatorPublisherListSnapshot>,
    pub available: bool,
}

#[derive(Debug, Clone)]
pub struct ValidatorPublisherListSnapshot {
    pub sequence: u64,
    pub validators: Vec<String>,
    pub manifest: Option<CachedManifestInfo>,
    pub effective: Option<u64>,
    pub expiration: Option<u64>,
    pub refresh_interval: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ValidatorListSnapshot {
    pub static_validators: Vec<Vec<u8>>,
    pub publisher_lists: Vec<ValidatorPublisherSnapshot>,
    pub effective_unl: Vec<Vec<u8>>,
    pub threshold: u32,
    pub validation_quorum: u32,
}

#[derive(Debug)]
pub struct ValidatorListManager {
    threshold: u32,
    static_validators: Vec<Vec<u8>>,
    publisher_lists: HashMap<String, PublisherState>,
    effective_unl: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
struct PublisherState {
    current: Option<ValidatorList>,
    remaining: BTreeMap<u64, ValidatorList>,
}

impl PublisherState {
    fn has_sequence(&self, sequence: u64) -> bool {
        self.current
            .as_ref()
            .is_some_and(|list| list.sequence == sequence)
            || self.remaining.contains_key(&sequence)
    }

    fn max_sequence(&self) -> Option<u64> {
        self.current
            .as_ref()
            .map(|list| list.sequence)
            .into_iter()
            .chain(self.remaining.keys().copied())
            .max()
    }

    fn normalize(&mut self, now: u64) {
        self.remaining
            .retain(|_, list| !list.expiration.is_some_and(|expiration| expiration <= now));

        let current_sequence = self.current.as_ref().map(|list| list.sequence).unwrap_or(0);
        if let Some(next_sequence) = self
            .remaining
            .iter()
            .filter_map(|(sequence, list)| {
                (!list.effective.is_some_and(|effective| effective > now)).then_some(*sequence)
            })
            .max()
        {
            if next_sequence > current_sequence {
                if let Some(next) = self.remaining.remove(&next_sequence) {
                    self.current = Some(next);
                }
            }
        }

        if let Some(current_sequence) = self.current.as_ref().map(|list| list.sequence) {
            self.remaining
                .retain(|sequence, _| *sequence > current_sequence);
        }
    }
}

impl ValidatorListManager {
    pub fn new(static_validators: Vec<Vec<u8>>, threshold: u32) -> Self {
        let effective_unl = sort_dedup_unl(static_validators.clone());
        Self {
            threshold: threshold.max(1),
            static_validators,
            publisher_lists: HashMap::new(),
            effective_unl,
        }
    }

    pub fn apply(&mut self, list: ValidatorList, now: u64) -> Option<ValidatorListApply> {
        match self.apply_status(list, now) {
            ValidatorListApplyStatus::Accepted(update) => Some(update),
            ValidatorListApplyStatus::SameSequence
            | ValidatorListApplyStatus::Stale
            | ValidatorListApplyStatus::Expired => None,
        }
    }

    pub fn apply_status(&mut self, list: ValidatorList, now: u64) -> ValidatorListApplyStatus {
        if list.expiration.is_some_and(|expiration| expiration <= now) {
            return ValidatorListApplyStatus::Expired;
        }

        let publisher_key = list.publisher_key.clone();
        let sequence = list.sequence;
        let mut same_sequence = false;
        let mut stale = false;

        {
            let state = self
                .publisher_lists
                .entry(publisher_key.clone())
                .or_default();
            if state.has_sequence(sequence) {
                same_sequence = true;
            } else if state
                .max_sequence()
                .is_some_and(|current| current > sequence)
            {
                stale = true;
            } else if list.effective.is_some_and(|effective| effective > now) {
                state.remaining.insert(sequence, list);
            } else {
                state.current = Some(list);
                state
                    .remaining
                    .retain(|future_sequence, _| *future_sequence > sequence);
            }
        }

        let refreshed = self.refresh_effective_unl(now);
        if same_sequence {
            if refreshed {
                ValidatorListApplyStatus::Accepted(self.make_update(publisher_key, sequence, now))
            } else {
                ValidatorListApplyStatus::SameSequence
            }
        } else if stale {
            if refreshed {
                ValidatorListApplyStatus::Accepted(self.make_update(publisher_key, sequence, now))
            } else {
                ValidatorListApplyStatus::Stale
            }
        } else {
            ValidatorListApplyStatus::Accepted(self.make_update(publisher_key, sequence, now))
        }
    }

    pub fn current_unl(&self) -> Vec<Vec<u8>> {
        self.effective_unl_at(current_unix_time())
    }

    pub fn snapshot(&self, now: u64) -> ValidatorListSnapshot {
        let mut publisher_lists: Vec<_> = self
            .publisher_lists
            .iter()
            .map(|(publisher_key, state)| {
                let mut view = state.clone();
                view.normalize(now);
                ValidatorPublisherSnapshot {
                    publisher_key: publisher_key.clone(),
                    current: view.current.as_ref().map(snapshot_entry),
                    remaining: view.remaining.values().map(snapshot_entry).collect(),
                    available: view
                        .current
                        .as_ref()
                        .is_some_and(|list| list.is_active_at(now)),
                }
            })
            .collect();
        publisher_lists.sort_by(|a, b| a.publisher_key.cmp(&b.publisher_key));
        let effective_unl = self.effective_unl_at(now);
        ValidatorListSnapshot {
            static_validators: self.static_validators.clone(),
            publisher_lists,
            effective_unl: effective_unl.clone(),
            threshold: self.threshold,
            validation_quorum: ((effective_unl.len().max(1) as u32) * 80 / 100) + 1,
        }
    }

    fn rebuild_effective_unl(&self, now: u64) -> Vec<Vec<u8>> {
        let mut validator_counts: HashMap<String, u32> = HashMap::new();
        for list in self
            .publisher_lists
            .values()
            .filter_map(|state| {
                let mut state = state.clone();
                state.normalize(now);
                state.current
            })
            .filter(|list| list.is_active_at(now))
        {
            let unique_validators: HashSet<String> = list.validators.iter().cloned().collect();
            for validator in unique_validators {
                *validator_counts.entry(validator).or_insert(0) += 1;
            }
        }

        let mut effective = self.static_validators.clone();
        for (validator, count) in validator_counts {
            if count < self.threshold {
                continue;
            }
            if let Ok(key) = hex::decode(&validator) {
                effective.push(key);
            }
        }
        sort_dedup_unl(effective)
    }

    fn effective_unl_at(&self, now: u64) -> Vec<Vec<u8>> {
        self.rebuild_effective_unl(now)
    }

    fn refresh_effective_unl(&mut self, now: u64) -> bool {
        for state in self.publisher_lists.values_mut() {
            state.normalize(now);
        }
        let effective_unl = self.effective_unl_at(now);
        if effective_unl != self.effective_unl {
            self.effective_unl = effective_unl;
            true
        } else {
            false
        }
    }

    fn make_update(&self, publisher_key: String, sequence: u64, now: u64) -> ValidatorListApply {
        ValidatorListApply {
            publisher_key,
            sequence,
            effective_unl: self.effective_unl_at(now),
            active_publishers: self
                .publisher_lists
                .values()
                .filter(|state| {
                    let mut view = (*state).clone();
                    view.normalize(now);
                    view.current
                        .as_ref()
                        .is_some_and(|list| list.is_active_at(now))
                })
                .count(),
        }
    }

    pub fn manifest_for_public_key(&self, public_key: &str) -> Option<CachedManifestInfo> {
        let requested = public_key.to_ascii_uppercase();
        self.publisher_lists.values().find_map(|state| {
            state
                .current
                .iter()
                .chain(state.remaining.values())
                .find_map(|list| {
                    let manifest = list.manifest.as_ref()?;
                    if manifest.master_key.eq_ignore_ascii_case(&requested)
                        || manifest.signing_key.eq_ignore_ascii_case(&requested)
                        || crate::crypto::base58::encode(
                            crate::crypto::base58::PREFIX_NODE_PUBLIC,
                            &hex::decode(&manifest.master_key).ok()?,
                        ) == public_key
                        || crate::crypto::base58::encode(
                            crate::crypto::base58::PREFIX_NODE_PUBLIC,
                            &hex::decode(&manifest.signing_key).ok()?,
                        ) == public_key
                    {
                        Some(manifest.clone())
                    } else {
                        None
                    }
                })
        })
    }
}

fn snapshot_entry(list: &ValidatorList) -> ValidatorPublisherListSnapshot {
    ValidatorPublisherListSnapshot {
        sequence: list.sequence,
        validators: list.validators.clone(),
        manifest: list.manifest.clone(),
        effective: list.effective,
        expiration: list.expiration,
        refresh_interval: list.refresh_interval,
    }
}

fn sort_dedup_unl(mut unl: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    unl.sort();
    unl.dedup();
    unl
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const XRPL_EPOCH_OFFSET: u64 = 946_684_800;

fn parse_time_field(value: Option<&serde_json::Value>, field: &str) -> anyhow::Result<Option<u64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    if let Some(ts) = value.as_u64() {
        return Ok(Some(ts));
    }
    if let Some(ts) = value.as_str() {
        return ts
            .parse::<u64>()
            .map(Some)
            .map_err(|_| anyhow::anyhow!("invalid '{}' timestamp", field));
    }
    Err(anyhow::anyhow!("invalid '{}' timestamp", field))
}

fn parse_xrpl_time_field(
    value: Option<&serde_json::Value>,
    field: &str,
) -> anyhow::Result<Option<u64>> {
    Ok(parse_time_field(value, field)?.map(|ts| ts.saturating_add(XRPL_EPOCH_OFFSET)))
}

fn parse_refresh_interval_secs(value: Option<&serde_json::Value>) -> anyhow::Result<Option<u64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let minutes = if let Some(v) = value.as_u64() {
        v
    } else if let Some(v) = value.as_str() {
        v.parse::<u64>()
            .map_err(|_| anyhow::anyhow!("invalid 'refreshInterval' value"))?
    } else {
        return Err(anyhow::anyhow!("invalid 'refreshInterval' value"));
    };
    if minutes == 0 {
        return Ok(None);
    }
    Ok(Some(minutes.saturating_mul(60)))
}

fn parse_expiration_field(blob_json: &serde_json::Value) -> anyhow::Result<Option<u64>> {
    if let Some(expiration) = parse_xrpl_time_field(blob_json.get("expiration"), "expiration")? {
        return Ok(Some(expiration));
    }
    if let Some(valid_until) = parse_xrpl_time_field(blob_json.get("validUntil"), "validUntil")? {
        return Ok(Some(valid_until));
    }
    Ok(None)
}

/// Fetch a validator list from a publisher URL (HTTP or HTTPS GET).
/// Returns the raw JSON response body.
async fn fetch_url(url: &str) -> anyhow::Result<String> {
    let (scheme, rest) = url
        .split_once("://")
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

    extract_http_body(&response)
}

async fn fetch_http(host: &str, port: u16, request: &str) -> anyhow::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    stream.write_all(request.as_bytes()).await?;
    read_http_response(&mut stream).await
}

async fn fetch_https(host: &str, port: u16, request: &str) -> anyhow::Result<Vec<u8>> {
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

    read_http_response(&mut tls).await
}

async fn read_http_response<R>(reader: &mut R) -> anyhow::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => {
                if is_complete_http_response(&buf) {
                    return Ok(buf);
                }
                return Err(anyhow::anyhow!(
                    "unexpected EOF before complete HTTP response"
                ));
            }
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if is_complete_http_response(&buf) {
                    return Ok(buf);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                if is_complete_http_response(&buf) {
                    return Ok(buf);
                }
                return Err(err.into());
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn extract_http_body(response: &[u8]) -> anyhow::Result<String> {
    let header_end =
        header_end_offset(response).ok_or_else(|| anyhow::anyhow!("no HTTP body separator"))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| anyhow::anyhow!("HTTP headers are not valid UTF-8"))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP status line"))?;
    if !(200..300).contains(&status) {
        return Err(anyhow::anyhow!("HTTP status {}", status));
    }

    let body = &response[header_end..];
    if is_chunked_headers(headers) {
        Ok(decode_chunked(&String::from_utf8_lossy(body)))
    } else if let Some(content_length) = content_length(headers) {
        if body.len() < content_length {
            return Err(anyhow::anyhow!(
                "HTTP body shorter than Content-Length ({}/{})",
                body.len(),
                content_length
            ));
        }
        Ok(String::from_utf8_lossy(&body[..content_length]).to_string())
    } else {
        Ok(String::from_utf8_lossy(body).to_string())
    }
}

fn is_complete_http_response(response: &[u8]) -> bool {
    let Some(header_end) = header_end_offset(response) else {
        return false;
    };
    let Ok(headers) = std::str::from_utf8(&response[..header_end]) else {
        return false;
    };
    let body = &response[header_end..];
    if is_chunked_headers(headers) {
        return is_complete_chunked_body(body);
    }
    if let Some(content_length) = content_length(headers) {
        return body.len() >= content_length;
    }
    false
}

fn header_end_offset(response: &[u8]) -> Option<usize> {
    response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("content-length") {
            return None;
        }
        value.trim().parse::<usize>().ok()
    })
}

fn is_chunked_headers(headers: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
    })
}

fn is_complete_chunked_body(mut body: &[u8]) -> bool {
    loop {
        let Some(line_end) = body.windows(2).position(|window| window == b"\r\n") else {
            return false;
        };
        let Ok(size_line) = std::str::from_utf8(&body[..line_end]) else {
            return false;
        };
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(size_hex, 16) else {
            return false;
        };
        body = &body[line_end + 2..];
        if size == 0 {
            return body.starts_with(b"\r\n");
        }
        if body.len() < size + 2 {
            return false;
        }
        if &body[size..size + 2] != b"\r\n" {
            return false;
        }
        body = &body[size + 2..];
    }
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
        if size == 0 {
            break;
        }
        rest = &rest[line_end + 2..];
        if rest.len() < size {
            break;
        }
        result.push_str(&rest[..size]);
        rest = &rest[size..];
        if rest.starts_with("\r\n") {
            rest = &rest[2..];
        }
    }
    result
}

fn parse_trusted_manifest(
    manifest_bytes: &[u8],
    publisher_keys: &[String],
) -> anyhow::Result<crate::consensus::manifest::Manifest> {
    let manifest = crate::consensus::manifest::Manifest::from_bytes(manifest_bytes)
        .map_err(|e| anyhow::anyhow!("manifest decode failed: {}", e))?;
    if !manifest.verify() {
        return Err(anyhow::anyhow!("manifest signature verification failed"));
    }
    if manifest.is_revocation() {
        return Err(anyhow::anyhow!(
            "revocation manifest cannot authorize validator list blobs"
        ));
    }

    let master_key_hex = hex::encode_upper(&manifest.master_pubkey);
    let trusted = publisher_keys
        .iter()
        .any(|k| k.eq_ignore_ascii_case(&master_key_hex));
    if !trusted {
        return Err(anyhow::anyhow!(
            "publisher key {} not in trusted list",
            &master_key_hex[..16.min(master_key_hex.len())],
        ));
    }

    Ok(manifest)
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
        return Err(anyhow::anyhow!(
            "unsupported validator list version: {}",
            version
        ));
    }

    let blob_b64 = json["blob"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing 'blob' field"))?;
    let signature_hex = json["signature"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing 'signature' field"))?;
    let manifest_b64 = json["manifest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing 'manifest' field"))?;

    // Decode the blob payload.
    let blob_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, blob_b64)?;

    // Decode the signature.
    let sig_bytes = hex::decode(signature_hex)?;

    // Decode and verify the manifest before trusting any key material in it.
    let manifest_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, manifest_b64)?;
    let manifest = parse_trusted_manifest(&manifest_bytes, publisher_keys)?;
    let master_key_hex = hex::encode_upper(&manifest.master_pubkey);
    let manifest_info = CachedManifestInfo {
        master_key: master_key_hex.clone(),
        signing_key: hex::encode_upper(&manifest.signing_pubkey),
        sequence: manifest.sequence,
        domain: manifest
            .domain
            .as_ref()
            .map(|bytes| String::from_utf8_lossy(bytes).to_string()),
        raw_manifest: manifest_b64.to_string(),
    };

    // Verify the blob signature using the signing key.
    verify_signature(&manifest.signing_pubkey, &blob_bytes, &sig_bytes)?;

    // Parse the blob JSON to extract validators.
    let blob_json: serde_json::Value = serde_json::from_slice(&blob_bytes)?;
    let sequence = blob_json["sequence"].as_u64().unwrap_or(0);
    let effective = match parse_xrpl_time_field(blob_json.get("effective"), "effective")? {
        Some(ts) => Some(ts),
        None => parse_time_field(blob_json.get("effective_time"), "effective_time")?,
    };
    let expiration = parse_expiration_field(&blob_json)?;
    let refresh_interval = parse_refresh_interval_secs(json.get("refreshInterval"))?;
    let validators_arr = blob_json["validators"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing 'validators' in blob"))?;

    let mut validators = Vec::new();
    for v in validators_arr {
        if let Some(key_hex) = v["validation_public_key"].as_str() {
            validators.push(key_hex.to_uppercase());
        }
    }

    Ok(ValidatorList {
        sequence,
        validators,
        publisher_key: master_key_hex,
        manifest: Some(manifest_info),
        effective,
        expiration,
        refresh_interval,
    })
}

/// Verify a signature. Supports Ed25519 (0xED prefix) and secp256k1.
fn verify_signature(pubkey: &[u8], message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
    if pubkey.len() == 33 && pubkey[0] == 0xED {
        // Ed25519
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let key_bytes: [u8; 32] = pubkey[1..33]
            .try_into()
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
        Err(anyhow::anyhow!(
            "unsupported public key format (len={})",
            pubkey.len()
        ))
    }
}

/// Verify a validator list received via peer protocol (`TMValidatorList`).
///
/// The protobuf fields contain manifest (raw bytes), blob (base64), and
/// signature (hex). This matches the HTTP response format, with protobuf
/// wrapping the same data.
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
    let blob_str =
        std::str::from_utf8(blob).map_err(|_| anyhow::anyhow!("blob is not valid UTF-8"))?;
    let sig_str = std::str::from_utf8(signature)
        .map_err(|_| anyhow::anyhow!("signature is not valid UTF-8"))?;

    // Decode the blob from base64.
    let blob_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, blob_str)
        .map_err(|e| anyhow::anyhow!("blob base64 decode: {}", e))?;

    // Decode the signature from hex.
    let sig_bytes =
        hex::decode(sig_str).map_err(|e| anyhow::anyhow!("signature hex decode: {}", e))?;

    let manifest = parse_trusted_manifest(manifest, publisher_keys)?;
    let manifest_info = CachedManifestInfo {
        master_key: hex::encode_upper(&manifest.master_pubkey),
        signing_key: hex::encode_upper(&manifest.signing_pubkey),
        sequence: manifest.sequence,
        domain: manifest
            .domain
            .as_ref()
            .map(|bytes| String::from_utf8_lossy(bytes).to_string()),
        raw_manifest: base64::engine::general_purpose::STANDARD.encode(manifest.to_bytes()),
    };
    verify_signature(&manifest.signing_pubkey, &blob_bytes, &sig_bytes)?;

    // Parse the blob JSON.
    let blob_json: serde_json::Value = serde_json::from_slice(&blob_bytes)?;
    let sequence = blob_json["sequence"].as_u64().unwrap_or(0);
    let effective = match parse_xrpl_time_field(blob_json.get("effective"), "effective")? {
        Some(ts) => Some(ts),
        None => parse_time_field(blob_json.get("effective_time"), "effective_time")?,
    };
    let expiration = parse_expiration_field(&blob_json)?;
    let validators_arr = blob_json["validators"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing 'validators' in blob"))?;

    let mut validators = Vec::new();
    for v in validators_arr {
        if let Some(key_hex) = v["validation_public_key"].as_str() {
            validators.push(key_hex.to_uppercase());
        }
    }

    Ok(ValidatorList {
        sequence,
        validators,
        publisher_key: hex::encode_upper(&manifest.master_pubkey),
        manifest: Some(manifest_info),
        effective,
        expiration,
        refresh_interval: None,
    })
}

/// Convert hex-encoded validator public keys to raw bytes for the UNL.
pub fn hex_keys_to_unl(hex_keys: &[String]) -> Vec<Vec<u8>> {
    hex_keys
        .iter()
        .filter_map(|h| hex::decode(h).ok())
        .collect()
}

pub fn initial_site_statuses(
    sites: &[String],
) -> Arc<std::sync::Mutex<HashMap<String, ValidatorSiteStatus>>> {
    Arc::new(std::sync::Mutex::new(
        sites
            .iter()
            .map(|site| {
                (
                    site.clone(),
                    ValidatorSiteStatus {
                        uri: site.clone(),
                        last_refresh_status: None,
                        last_refresh_time: None,
                        last_refresh_message: None,
                        next_refresh_time: None,
                        refresh_interval_secs: 5 * 60,
                    },
                )
            })
            .collect(),
    ))
}

pub fn install_validator_list(
    manager: &Arc<std::sync::Mutex<ValidatorListManager>>,
    unl: &Arc<std::sync::RwLock<Vec<Vec<u8>>>>,
    list: ValidatorList,
) -> Option<ValidatorListApply> {
    match install_validator_list_status(manager, unl, list) {
        ValidatorListApplyStatus::Accepted(update) => Some(update),
        ValidatorListApplyStatus::SameSequence
        | ValidatorListApplyStatus::Stale
        | ValidatorListApplyStatus::Expired => None,
    }
}

pub fn install_validator_list_status(
    manager: &Arc<std::sync::Mutex<ValidatorListManager>>,
    unl: &Arc<std::sync::RwLock<Vec<Vec<u8>>>>,
    list: ValidatorList,
) -> ValidatorListApplyStatus {
    let now = current_unix_time();
    let status = {
        let mut manager = manager.lock().unwrap_or_else(|e| e.into_inner());
        manager.apply_status(list, now)
    };
    if let ValidatorListApplyStatus::Accepted(update) = &status {
        *unl.write().unwrap_or_else(|e| e.into_inner()) = update.effective_unl.clone();
    }
    status
}

/// Run the validator list fetch loop.
/// Fetches from all configured sites, verifies the lists, and updates the shared UNL.
pub async fn run_validator_list_fetch(
    sites: Vec<String>,
    publisher_keys: Vec<String>,
    manager: Arc<std::sync::Mutex<ValidatorListManager>>,
    unl: Arc<std::sync::RwLock<Vec<Vec<u8>>>>,
    site_statuses: Arc<std::sync::Mutex<HashMap<String, ValidatorSiteStatus>>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;

    if sites.is_empty() || publisher_keys.is_empty() {
        tracing::debug!("no validator list sites or publisher keys configured — skipping fetch");
        return;
    }

    // Wait 5s on startup before the first fetch.
    tokio::time::sleep(Duration::from_secs(5)).await;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let mut refresh_secs = 5 * 60;
        for site in &sites {
            tracing::info!("fetching validator list from {}", site);
            let queried_at = current_unix_time();
            let (status, message, site_refresh_secs) = match fetch_url(site).await {
                Ok(body) => match parse_and_verify(&body, &publisher_keys) {
                    Ok(list) => {
                        let site_refresh = list.refresh_interval.unwrap_or(5 * 60).max(60);
                        refresh_secs = refresh_secs.min(site_refresh);
                        match install_validator_list_status(&manager, &unl, list) {
                            ValidatorListApplyStatus::Accepted(update) => {
                                tracing::info!(
                                    "validator list updated: {} validators (seq={}, active_publishers={}, publisher={})",
                                    update.effective_unl.len(),
                                    update.sequence,
                                    update.active_publishers,
                                    &update.publisher_key[..16.min(update.publisher_key.len())],
                                );
                                ("accepted".to_string(), None, site_refresh)
                            }
                            ValidatorListApplyStatus::SameSequence => {
                                tracing::debug!("validator list update ignored (same sequence)");
                                ("same_sequence".to_string(), None, site_refresh)
                            }
                            ValidatorListApplyStatus::Stale => {
                                tracing::debug!("validator list update ignored (stale sequence)");
                                ("stale".to_string(), None, site_refresh)
                            }
                            ValidatorListApplyStatus::Expired => {
                                tracing::debug!("validator list update ignored (expired)");
                                (
                                    "invalid".to_string(),
                                    Some("publisher list expired".to_string()),
                                    site_refresh,
                                )
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("validator list verification failed for {}: {}", site, e);
                        let status = if e.to_string().contains("unsupported validator list version")
                        {
                            "unsupported_version"
                        } else if e.to_string().contains("not in trusted list") {
                            "untrusted"
                        } else {
                            "invalid"
                        };
                        (status.to_string(), Some(e.to_string()), 5 * 60)
                    }
                },
                Err(e) => {
                    tracing::warn!("failed to fetch validator list from {}: {}", site, e);
                    ("invalid".to_string(), Some(e.to_string()), 5 * 60)
                }
            };

            let mut statuses = site_statuses.lock().unwrap_or_else(|e| e.into_inner());
            let entry = statuses
                .entry(site.clone())
                .or_insert_with(|| ValidatorSiteStatus {
                    uri: site.clone(),
                    last_refresh_status: None,
                    last_refresh_time: None,
                    last_refresh_message: None,
                    next_refresh_time: None,
                    refresh_interval_secs: 5 * 60,
                });
            entry.last_refresh_status = Some(status);
            entry.last_refresh_time = Some(queried_at);
            entry.last_refresh_message = message;
            entry.refresh_interval_secs = site_refresh_secs;
            entry.next_refresh_time = Some(queried_at.saturating_add(site_refresh_secs));
        }

        let ticks = (refresh_secs / 5).max(1);
        for _ in 0..ticks {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;
    use crate::crypto::keys::Ed25519KeyPair;

    fn ed_pubkey_bytes(kp: &Ed25519KeyPair) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(0xED);
        out.extend_from_slice(&kp.public_key_bytes());
        out
    }

    fn signed_list_response(tamper_manifest: bool) -> (String, Vec<String>) {
        let master = crate::crypto::keys::Secp256k1KeyPair::generate();
        let signing = crate::crypto::keys::Secp256k1KeyPair::generate();
        let manifest = crate::consensus::manifest::Manifest::new_signed(1, &master, &signing);
        let mut manifest_bytes = manifest.to_bytes();
        if tamper_manifest {
            let last = manifest_bytes.len() - 1;
            manifest_bytes[last] ^= 0x01;
        }

        let blob_json = serde_json::json!({
            "sequence": 7,
            "validators": [
                { "validation_public_key": "ED0123456789ABCDEF" }
            ]
        });
        let blob_bytes = serde_json::to_vec(&blob_json).expect("blob json should serialize");
        let response = serde_json::json!({
            "version": 1,
            "manifest": base64::engine::general_purpose::STANDARD.encode(manifest_bytes),
            "blob": base64::engine::general_purpose::STANDARD.encode(&blob_bytes),
            "signature": hex::encode_upper(signing.sign(&blob_bytes)),
        })
        .to_string();

        (response, vec![hex::encode_upper(master.public_key_bytes())])
    }

    #[test]
    fn test_parse_and_verify_accepts_verified_manifest() {
        let (response, publisher_keys) = signed_list_response(false);
        let list =
            parse_and_verify(&response, &publisher_keys).expect("validator list should verify");
        assert_eq!(list.sequence, 7);
        assert_eq!(list.validators, vec!["ED0123456789ABCDEF".to_string()]);
        assert!(!list.publisher_key.is_empty());
        assert_eq!(list.refresh_interval, None);
    }

    #[test]
    fn test_parse_and_verify_rejects_tampered_manifest_even_if_master_key_matches() {
        let (response, publisher_keys) = signed_list_response(true);
        let err = parse_and_verify(&response, &publisher_keys).unwrap_err();
        assert!(
            err.to_string().contains("manifest"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_and_verify_accepts_valid_until_and_refresh_interval() {
        let master = crate::crypto::keys::Secp256k1KeyPair::generate();
        let signing = crate::crypto::keys::Secp256k1KeyPair::generate();
        let manifest = crate::consensus::manifest::Manifest::new_signed(1, &master, &signing);

        let blob_json = serde_json::json!({
            "sequence": 9,
            "validUntil": 12_345,
            "validators": [
                { "validation_public_key": "ED1122334455" }
            ]
        });
        let blob_bytes = serde_json::to_vec(&blob_json).unwrap();
        let response = serde_json::json!({
            "version": 1,
            "manifest": base64::engine::general_purpose::STANDARD.encode(manifest.to_bytes()),
            "blob": base64::engine::general_purpose::STANDARD.encode(&blob_bytes),
            "signature": hex::encode_upper(signing.sign(&blob_bytes)),
            "refreshInterval": 7
        })
        .to_string();
        let publisher_keys = vec![hex::encode_upper(master.public_key_bytes())];

        let parsed = parse_and_verify(&response, &publisher_keys).unwrap();
        assert_eq!(parsed.sequence, 9);
        assert_eq!(parsed.expiration, Some(12_345 + XRPL_EPOCH_OFFSET));
        assert_eq!(parsed.refresh_interval, Some(7 * 60));
    }

    #[test]
    fn test_parse_and_verify_converts_xrpl_epoch_effective_and_expiration() {
        let master = crate::crypto::keys::Secp256k1KeyPair::generate();
        let signing = crate::crypto::keys::Secp256k1KeyPair::generate();
        let manifest = crate::consensus::manifest::Manifest::new_signed(1, &master, &signing);

        let blob_json = serde_json::json!({
            "sequence": 10,
            "effective": 22_222,
            "expiration": 33_333,
            "validators": [
                { "validation_public_key": "ED5566778899" }
            ]
        });
        let blob_bytes = serde_json::to_vec(&blob_json).unwrap();
        let response = serde_json::json!({
            "version": 1,
            "manifest": base64::engine::general_purpose::STANDARD.encode(manifest.to_bytes()),
            "blob": base64::engine::general_purpose::STANDARD.encode(&blob_bytes),
            "signature": hex::encode_upper(signing.sign(&blob_bytes)),
        })
        .to_string();
        let publisher_keys = vec![hex::encode_upper(master.public_key_bytes())];

        let parsed = parse_and_verify(&response, &publisher_keys).unwrap();
        assert_eq!(parsed.sequence, 10);
        assert_eq!(parsed.effective, Some(22_222 + XRPL_EPOCH_OFFSET));
        assert_eq!(parsed.expiration, Some(33_333 + XRPL_EPOCH_OFFSET));
    }

    #[test]
    fn test_parse_and_verify_accepts_ed25519_publisher_manifest() {
        let master = Ed25519KeyPair::from_seed_entropy(&[3u8; 16]);
        let signing = Ed25519KeyPair::from_seed_entropy(&[4u8; 16]);
        let master_pub = ed_pubkey_bytes(&master);
        let signing_pub = ed_pubkey_bytes(&signing);
        let manifest_bytes = crate::consensus::manifest::Manifest {
            master_pubkey: master_pub.clone(),
            signing_pubkey: signing_pub.clone(),
            sequence: 1,
            master_sig: master.sign(&crate::consensus::manifest::Manifest::signing_bytes(
                &master_pub,
                &signing_pub,
                1,
                None,
                None,
            )),
            signing_sig: signing.sign(&crate::consensus::manifest::Manifest::signing_bytes(
                &master_pub,
                &signing_pub,
                1,
                None,
                None,
            )),
            domain: None,
            version: None,
        }
        .to_bytes();

        let blob_json = serde_json::json!({
            "sequence": 11,
            "validators": [
                { "validation_public_key": "ED998877665544332211" }
            ]
        });
        let blob_bytes = serde_json::to_vec(&blob_json).unwrap();
        let response = serde_json::json!({
            "version": 1,
            "manifest": base64::engine::general_purpose::STANDARD.encode(manifest_bytes),
            "blob": base64::engine::general_purpose::STANDARD.encode(&blob_bytes),
            "signature": hex::encode_upper(signing.sign(&blob_bytes)),
        })
        .to_string();
        let publisher_keys = vec![hex::encode_upper(master_pub)];

        let parsed = parse_and_verify(&response, &publisher_keys).unwrap();
        assert_eq!(parsed.sequence, 11);
        assert_eq!(
            parsed.publisher_key,
            hex::encode_upper(ed_pubkey_bytes(&master))
        );
    }

    #[test]
    fn test_validator_list_manager_applies_threshold_per_validator() {
        let static_validator = vec![vec![0xAA; 33]];
        let mut manager = ValidatorListManager::new(static_validator.clone(), 2);
        let now = 1_000u64;

        let first = ValidatorList {
            sequence: 1,
            validators: vec!["11".repeat(33), "22".repeat(33)],
            publisher_key: "AA".repeat(33),
            manifest: None,
            effective: None,
            expiration: Some(now + 100),
            refresh_interval: None,
        };
        let update = manager.apply(first, now).expect("first list should store");
        assert_eq!(update.effective_unl, static_validator);

        let second = ValidatorList {
            sequence: 1,
            validators: vec!["22".repeat(33), "33".repeat(33)],
            publisher_key: "BB".repeat(33),
            manifest: None,
            effective: None,
            expiration: Some(now + 100),
            refresh_interval: None,
        };
        let update = manager
            .apply(second, now)
            .expect("second list should store");
        assert_eq!(update.effective_unl.len(), 2);
        assert!(update.effective_unl.contains(&vec![0xAA; 33]));
        assert!(update.effective_unl.contains(&vec![0x22; 33]));
    }

    #[test]
    fn test_validator_list_manager_rejects_stale_or_expired_lists() {
        let mut manager = ValidatorListManager::new(Vec::new(), 1);
        let publisher = "AA".repeat(33);

        let current = ValidatorList {
            sequence: 5,
            validators: vec!["11".repeat(33)],
            publisher_key: publisher.clone(),
            manifest: None,
            effective: None,
            expiration: Some(200),
            refresh_interval: None,
        };
        assert!(manager.apply(current, 100).is_some());

        let stale = ValidatorList {
            sequence: 4,
            validators: vec!["22".repeat(33)],
            publisher_key: publisher.clone(),
            manifest: None,
            effective: None,
            expiration: Some(200),
            refresh_interval: None,
        };
        assert!(manager.apply(stale, 100).is_none());

        let expired = ValidatorList {
            sequence: 6,
            validators: vec!["33".repeat(33)],
            publisher_key: "BB".repeat(33),
            manifest: None,
            effective: None,
            expiration: Some(100),
            refresh_interval: None,
        };
        assert!(manager.apply(expired, 100).is_none());
    }

    #[test]
    fn test_future_effective_list_does_not_replace_current_until_effective() {
        let publisher = "AA".repeat(33);
        let mut manager = ValidatorListManager::new(Vec::new(), 1);

        let current = ValidatorList {
            sequence: 5,
            validators: vec!["11".repeat(33)],
            publisher_key: publisher.clone(),
            manifest: None,
            effective: None,
            expiration: Some(400),
            refresh_interval: None,
        };
        manager
            .apply(current, 100)
            .expect("current list should apply");

        let future = ValidatorList {
            sequence: 6,
            validators: vec!["22".repeat(33)],
            publisher_key: publisher.clone(),
            manifest: None,
            effective: Some(200),
            expiration: Some(500),
            refresh_interval: None,
        };
        manager
            .apply(future, 100)
            .expect("future list should stage");

        let before = manager.snapshot(150);
        assert_eq!(before.publisher_lists.len(), 1);
        assert_eq!(
            before.publisher_lists[0]
                .current
                .as_ref()
                .map(|list| list.sequence),
            Some(5)
        );
        assert_eq!(before.publisher_lists[0].remaining.len(), 1);
        assert_eq!(before.publisher_lists[0].remaining[0].sequence, 6);

        let after = manager.snapshot(250);
        assert_eq!(after.publisher_lists.len(), 1);
        assert_eq!(
            after.publisher_lists[0]
                .current
                .as_ref()
                .map(|list| list.sequence),
            Some(6)
        );
        assert!(after.publisher_lists[0].remaining.is_empty());
    }

    #[test]
    fn test_complete_http_response_with_content_length() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
        assert!(is_complete_http_response(response));
        assert_eq!(extract_http_body(response).unwrap(), "{\"status\":\"ok\"}");
    }

    #[test]
    fn test_incomplete_http_response_with_content_length() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n{\"status\":\"ok\"}";
        assert!(!is_complete_http_response(response));
        assert!(extract_http_body(response).is_err());
    }

    #[test]
    fn test_complete_chunked_http_response() {
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert!(is_complete_http_response(response));
        assert_eq!(extract_http_body(response).unwrap(), "hello");
    }

    #[test]
    fn test_extract_http_body_rejects_non_success_status() {
        let response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
        assert!(extract_http_body(response).is_err());
    }
}
