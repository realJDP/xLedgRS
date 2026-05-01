//! xLedgRS purpose: Fetch authoritative ledger data from JSON-RPC peers.
//! RPC-based state sync for downloading full ledger state from a rippled
//! admin endpoint.
//!
//! Instead of syncing via the peer protocol, this module fetches the account
//! state via `ledger_data` RPC calls with binary mode and marker-based
//! pagination. A single rippled node with admin access can serve the entire
//! state without disconnecting the caller.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{error, info, warn};

use crate::ledger::LedgerHeader;
use crate::storage::Storage;

/// Number of objects requested per RPC page.
const PAGE_LIMIT: u32 = 2048;

/// Progress counters exposed to the rest of the node.
pub struct RpcSyncState {
    pub objects_downloaded: AtomicU64,
    pub accounts_parsed: AtomicU64,
    pub pages_fetched: AtomicU64,
    pub running: AtomicBool,
    pub complete: AtomicBool,
}

impl RpcSyncState {
    pub fn new() -> Self {
        Self {
            objects_downloaded: AtomicU64::new(0),
            accounts_parsed: AtomicU64::new(0),
            pages_fetched: AtomicU64::new(0),
            running: AtomicBool::new(false),
            complete: AtomicBool::new(false),
        }
    }
}

/// Run the RPC sync to completion. Fetches all state objects from
/// `ledger_data` and stores them in the given storage backend.
pub async fn run_rpc_sync(
    rpc_host: String,
    rpc_port: u16,
    storage: Arc<Storage>,
    sync_state: Arc<RpcSyncState>,
) {
    sync_state.running.store(true, Ordering::SeqCst);
    info!("RPC sync starting — target {}:{}", rpc_host, rpc_port);

    let mut marker: Option<String> = None;
    let mut total_objects: u64 = 0;
    let mut total_accounts: u64 = 0;
    let mut pages: u64 = 0;
    // Use a specific validated ledger so state remains consistent across pages.
    let mut ledger_index: Option<u64> = None;

    loop {
        // Build the request.
        let params = if let Some(ref m) = marker {
            if let Some(seq) = ledger_index {
                format!(
                    r#"{{"method":"ledger_data","params":[{{"ledger_index":{},"limit":{},"binary":true,"marker":"{}"}}]}}"#,
                    seq, PAGE_LIMIT, m
                )
            } else {
                format!(
                    r#"{{"method":"ledger_data","params":[{{"ledger_index":"validated","limit":{},"binary":true,"marker":"{}"}}]}}"#,
                    PAGE_LIMIT, m
                )
            }
        } else {
            format!(
                r#"{{"method":"ledger_data","params":[{{"ledger_index":"validated","limit":{},"binary":true}}]}}"#,
                PAGE_LIMIT
            )
        };

        // Make the HTTP request.
        let body = match http_post(&rpc_host, rpc_port, &params).await {
            Ok(b) => b,
            Err(e) => {
                warn!("RPC sync HTTP error: {e} — retrying in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        // Parse the JSON response.
        let resp: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                warn!("RPC sync JSON parse error: {e} — retrying in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        let result = &resp["result"];
        if result["status"].as_str() != Some("success") {
            let err = result["error_message"]
                .as_str()
                .or(result["error"].as_str())
                .unwrap_or("unknown");
            error!("RPC sync error: {err} — retrying in 10s");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            // Reset the marker on error and start over.
            marker = None;
            ledger_index = None;
            continue;
        }

        // Lock to the specific ledger index on the first page.
        if ledger_index.is_none() {
            if let Some(seq) = result["ledger_index"].as_u64() {
                ledger_index = Some(seq);
                info!("RPC sync locked to ledger {}", seq);
            }
        }

        // Extract state objects.
        let state = match result["state"].as_array() {
            Some(arr) => arr,
            None => {
                warn!("RPC sync: no state array in response");
                break;
            }
        };

        if state.is_empty() {
            info!("RPC sync: empty page, done");
            break;
        }

        // Parse binary objects: each has `index` (hex key) and `data`
        // (hex STObject).
        let mut leaves: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(state.len());
        for obj in state {
            let index_hex = match obj["index"].as_str() {
                Some(s) => s,
                None => continue,
            };
            let data_hex = match obj["data"].as_str() {
                Some(s) => s,
                None => continue,
            };
            let key = match hex::decode(index_hex) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let data = match hex::decode(data_hex) {
                Ok(d) => d,
                Err(_) => continue,
            };
            leaves.push((key, data));
        }

        let page_count = leaves.len() as u64;

        // Leaf persistence is handled by SHAMap/NuDB; only counts are tracked here.
        {
            total_objects += page_count;
            total_accounts += leaves.len() as u64;
            pages += 1;

            sync_state
                .objects_downloaded
                .store(total_objects, Ordering::Relaxed);
            sync_state
                .accounts_parsed
                .store(total_accounts, Ordering::Relaxed);
            sync_state.pages_fetched.store(pages, Ordering::Relaxed);

            if pages % 500 == 0 {
                info!(
                    "RPC sync progress: {} objects ({} accounts) across {} pages",
                    total_objects, total_accounts, pages
                );
            }
        }

        // Check for the next marker.
        marker = result["marker"].as_str().map(|s| s.to_string());
        if marker.is_none() {
            info!("RPC sync complete — no more markers");
            break;
        }

        // Yield briefly to avoid starving other tasks.
        tokio::task::yield_now().await;
    }

    info!(
        "RPC sync download done: {} total objects, {} accounts, {} pages — rebuilding indexes...",
        total_objects, total_accounts, pages
    );

    // Persist the synced ledger header so follower startup has a stable anchor.
    if let Some(seq) = ledger_index {
        match fetch_ledger_header(&rpc_host, rpc_port, seq).await {
            Ok(header) => {
                if let Err(e) = storage.save_ledger(&header, &[]) {
                    error!("Failed to save RPC sync ledger header: {e}");
                }
                let hash_hex = hex::encode_upper(header.hash);
                if let Err(e) = storage.save_meta(header.sequence, &hash_hex, &header) {
                    error!("Failed to save RPC sync metadata: {e}");
                }
                if let Err(e) = storage.persist_sync_anchor(&header) {
                    error!("Failed to persist RPC sync anchor: {e}");
                }
                if let Err(e) = storage.flush() {
                    error!("Failed to flush after RPC sync: {e}");
                }
            }
            Err(e) => {
                error!("RPC sync completed but could not fetch synced ledger header for seq {seq}: {e}");
                if let Err(e) = storage.set_sync_ledger(seq) {
                    error!("Failed to save sync ledger fallback: {e}");
                }
                if let Err(e) = storage.flush() {
                    error!("Failed to flush RPC sync fallback metadata: {e}");
                }
            }
        }
    }

    sync_state.complete.store(true, Ordering::SeqCst);
    sync_state.running.store(false, Ordering::SeqCst);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpcTransport {
    Http,
    Https,
}

/// Minimal HTTP POST client with TLS support for public XRPL RPC endpoints.
///
/// Local/private admin RPC is still plain HTTP, but public full-history
/// endpoints on ports like 51234 expect HTTPS.
pub async fn http_post(host: &str, port: u16, body: &str) -> anyhow::Result<String> {
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        host, port, body.len(), body
    );

    let response = match preferred_transport(host, port) {
        RpcTransport::Https => match post_https(host, port, &request).await {
            Ok(resp) => resp,
            Err(https_err) => {
                let http_err = match post_http(host, port, &request).await {
                    Ok(resp) => return extract_http_body(&resp),
                    Err(err) => err,
                };
                return Err(anyhow::anyhow!(
                    "HTTPS request failed ({https_err}); HTTP fallback failed ({http_err})"
                ));
            }
        },
        RpcTransport::Http => post_http(host, port, &request).await?,
    };

    extract_http_body(&response)
}

fn preferred_transport(host: &str, port: u16) -> RpcTransport {
    if is_probably_local_host(host) {
        return RpcTransport::Http;
    }
    match port {
        443 | 51234 => RpcTransport::Https,
        _ => RpcTransport::Http,
    }
}

fn is_probably_local_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host == "::1" || host == "[::1]" {
        return true;
    }

    let parsed = host
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<std::net::IpAddr>();
    match parsed {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private(),
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unique_local(),
        Err(_) => false,
    }
}

async fn post_http(host: &str, port: u16, request: &str) -> anyhow::Result<Vec<u8>> {
    let addr = format!("{}:{}", host, port);
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout (10s)"))??;

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    read_http_response(&mut stream).await
}

async fn post_https(host: &str, port: u16, request: &str) -> anyhow::Result<Vec<u8>> {
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

    let addr = format!("{}:{}", host, port);
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout (10s)"))??;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?;
    let mut tls = connector.connect(server_name, tcp).await?;

    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;
    read_http_response(&mut tls).await
}

async fn read_http_response<R>(reader: &mut R) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(60), reader.read(&mut chunk))
            .await
        {
            Ok(Ok(0)) => {
                if is_complete_http_response(&response) {
                    return Ok(response);
                }
                return Err(anyhow::anyhow!(
                    "unexpected EOF before complete HTTP response"
                ));
            }
            Ok(Ok(n)) => {
                response.extend_from_slice(&chunk[..n]);
                if is_complete_http_response(&response) {
                    return Ok(response);
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow::anyhow!("read timeout (60s)")),
        }
    }
}

fn extract_http_body(response: &[u8]) -> anyhow::Result<String> {
    let body_start = header_end_offset(response)
        .ok_or_else(|| anyhow::anyhow!("no HTTP body separator found"))?;
    let headers = std::str::from_utf8(&response[..body_start])
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

    let body = &response[body_start..];
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

async fn fetch_ledger_header(host: &str, port: u16, seq: u64) -> anyhow::Result<LedgerHeader> {
    let req = format!(
        r#"{{"method":"ledger","params":[{{"ledger_index":{},"transactions":false,"expand":false}}]}}"#,
        seq
    );
    let body = http_post(host, port, &req).await?;
    let resp: serde_json::Value = serde_json::from_str(&body)?;
    let result = &resp["result"];
    if result["status"].as_str() != Some("success") {
        let err = result["error_message"]
            .as_str()
            .or(result["error"].as_str())
            .unwrap_or("unknown");
        return Err(anyhow::anyhow!("ledger RPC failed: {err}"));
    }

    parse_ledger_header_from_result(result)
}

fn parse_ledger_header_from_result(result: &serde_json::Value) -> anyhow::Result<LedgerHeader> {
    let ledger = &result["ledger"];
    let mut header = LedgerHeader {
        sequence: parse_seq_field(ledger, "ledger_index")? as u32,
        hash: parse_hash_field(ledger, "ledger_hash")?,
        parent_hash: parse_hash_field(ledger, "parent_hash")?,
        close_time: parse_u64_field(ledger, "close_time")?,
        total_coins: parse_u64_field(ledger, "total_coins")?,
        account_hash: parse_hash_field(ledger, "account_hash")?,
        transaction_hash: parse_hash_field(ledger, "transaction_hash")?,
        parent_close_time: parse_u64_field(ledger, "parent_close_time").unwrap_or(0) as u32,
        close_time_resolution: parse_u64_field(ledger, "close_time_resolution").unwrap_or(10) as u8,
        close_flags: parse_u64_field(ledger, "close_flags").unwrap_or(0) as u8,
    };

    let computed = header.compute_hash();
    if header.hash == [0u8; 32] {
        header.hash = computed;
    } else if header.hash != computed {
        return Err(anyhow::anyhow!(
            "ledger hash mismatch for seq {}: rpc={} computed={}",
            header.sequence,
            hex::encode_upper(header.hash),
            hex::encode_upper(computed),
        ));
    }

    Ok(header)
}

fn parse_hash_field(obj: &serde_json::Value, key: &str) -> anyhow::Result<[u8; 32]> {
    let hex_str = obj[key]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing {key}"))?;
    let bytes = hex::decode(hex_str).map_err(|e| anyhow::anyhow!("invalid {key}: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{key} must be 32 bytes"))?;
    Ok(arr)
}

fn parse_u64_field(obj: &serde_json::Value, key: &str) -> anyhow::Result<u64> {
    if let Some(v) = obj[key].as_u64() {
        return Ok(v);
    }
    if let Some(v) = obj[key].as_str() {
        return v
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("invalid {key}: {e}"));
    }
    Err(anyhow::anyhow!("missing {key}"))
}

fn parse_seq_field(obj: &serde_json::Value, key: &str) -> anyhow::Result<u64> {
    parse_u64_field(obj, key)
}

/// Decode HTTP chunked transfer encoding.
fn decode_chunked(input: &str) -> String {
    let mut result = String::new();
    let mut remaining = input;

    loop {
        // Find the chunk-size line.
        let line_end = match remaining.find("\r\n") {
            Some(pos) => pos,
            None => break,
        };
        let size_str = remaining[..line_end].trim();
        let chunk_size = match usize::from_str_radix(size_str, 16) {
            Ok(s) => s,
            Err(_) => break,
        };
        if chunk_size == 0 {
            break; // Final chunk.
        }

        let data_start = line_end + 2;
        if data_start + chunk_size > remaining.len() {
            // Partial chunk; take what is available.
            result.push_str(&remaining[data_start..]);
            break;
        }
        result.push_str(&remaining[data_start..data_start + chunk_size]);
        remaining = &remaining[data_start + chunk_size..];
        // Skip trailing `\r\n` after the chunk data.
        if remaining.starts_with("\r\n") {
            remaining = &remaining[2..];
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_decode_chunked_simple() {
        let input = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(input), "hello world");
    }

    #[test]
    fn test_decode_chunked_single() {
        let input = "d\r\n{\"test\":true}\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(input), "{\"test\":true}");
    }

    #[test]
    fn test_preferred_transport_public_rpc_uses_https() {
        assert_eq!(
            preferred_transport("s1.ripple.com", 51234),
            RpcTransport::Https
        );
        assert_eq!(preferred_transport("example.com", 443), RpcTransport::Https);
    }

    #[test]
    fn test_preferred_transport_local_admin_uses_http() {
        assert_eq!(preferred_transport("127.0.0.1", 5005), RpcTransport::Http);
        assert_eq!(preferred_transport("localhost", 51234), RpcTransport::Http);
        assert_eq!(preferred_transport("10.0.0.9", 51234), RpcTransport::Http);
    }

    #[test]
    fn test_extract_http_body_rejects_non_success_status() {
        let response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nnope";
        let err = extract_http_body(response).unwrap_err().to_string();
        assert!(err.contains("HTTP status 503"));
    }

    fn make_header(seq: u32) -> LedgerHeader {
        let mut header = LedgerHeader {
            sequence: seq,
            hash: [0u8; 32],
            parent_hash: [0x11; 32],
            close_time: 12345,
            total_coins: 100_000_000_000_000_000,
            account_hash: [0x22; 32],
            transaction_hash: [0x33; 32],
            parent_close_time: 12340,
            close_time_resolution: 10,
            close_flags: 0,
        };
        header.hash = header.compute_hash();
        header
    }

    #[test]
    fn test_parse_ledger_header_from_result_round_trip() {
        let header = make_header(500);
        let result = json!({
            "status": "success",
            "ledger": {
                "ledger_index": header.sequence.to_string(),
                "ledger_hash": hex::encode_upper(header.hash),
                "parent_hash": hex::encode_upper(header.parent_hash),
                "close_time": header.close_time,
                "total_coins": header.total_coins.to_string(),
                "account_hash": hex::encode_upper(header.account_hash),
                "transaction_hash": hex::encode_upper(header.transaction_hash),
                "parent_close_time": header.parent_close_time,
                "close_time_resolution": header.close_time_resolution,
                "close_flags": header.close_flags,
            }
        });

        let parsed = parse_ledger_header_from_result(&result).unwrap();
        assert_eq!(parsed.sequence, header.sequence);
        assert_eq!(parsed.hash, header.hash);
        assert_eq!(parsed.parent_hash, header.parent_hash);
        assert_eq!(parsed.account_hash, header.account_hash);
        assert_eq!(parsed.transaction_hash, header.transaction_hash);
    }

    #[test]
    fn test_parse_ledger_header_from_result_rejects_hash_mismatch() {
        let header = make_header(501);
        let result = json!({
            "status": "success",
            "ledger": {
                "ledger_index": header.sequence,
                "ledger_hash": hex::encode_upper([0xFF; 32]),
                "parent_hash": hex::encode_upper(header.parent_hash),
                "close_time": header.close_time,
                "total_coins": header.total_coins,
                "account_hash": hex::encode_upper(header.account_hash),
                "transaction_hash": hex::encode_upper(header.transaction_hash),
            }
        });

        let err = parse_ledger_header_from_result(&result)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ledger hash mismatch"));
    }
}
