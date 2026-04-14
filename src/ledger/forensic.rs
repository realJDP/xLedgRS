//! Forensic capture for engine-divergence debugging.
//!
//! When the follower detects a state-hash mismatch on the first ledger after
//! a sync anchor, this module writes a self-contained bundle to disk so the
//! investigation can continue offline against cached reference data even
//! after rippled's retention window rolls past the mismatch ledger.
//!
//! Bundle layout:
//!
//!   {data_dir}/debug-runs/{anchor_seq}-{mismatch_seq}-{iso8601}/
//!     artifact.json          — human-readable summary + hashes + counts
//!     anchor_header.bin      — bincode LedgerHeader (parent of mismatch)
//!     validated_header.bin   — bincode LedgerHeader (rippled's mismatch header)
//!     tx_blobs.bin           — bincode Vec<(tx_blob, meta_blob)>
//!     prestate.bin           — bincode HashMap<key, pre-replay SLE bytes>
//!     rippled_reference.bin  — bincode HashMap<key, rippled post-state bytes>
//!     per_tx_attribution.jsonl — one JSON line per tx touching keys
//!
//! The replay_fixture harness loads this bundle and calls replay_ledger()
//! offline, comparing its output byte-for-byte against rippled_reference.bin
//! to identify the first divergent key.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::ledger::close::TxAttribution;
use crate::ledger::LedgerHeader;

/// Inputs to a forensic capture run. All fields are owned so the capture can
/// run async after the caller drops its state lock.
pub struct CaptureInputs {
    pub bundle_root:          PathBuf,
    pub anchor_seq:           u32,
    pub anchor_hash:          Option<[u8; 32]>,
    pub anchor_account_hash:  Option<[u8; 32]>,
    pub mismatch_seq:         u32,
    pub local_account_hash:   [u8; 32],
    pub network_account_hash: [u8; 32],
    pub parent_header:        LedgerHeader,
    pub validated_header:     LedgerHeader,
    pub applied_count:        usize,
    pub failed_count:         usize,
    pub skipped_count:        usize,
    pub touched_keys:         Vec<[u8; 32]>,
    pub per_tx_attribution:   Vec<TxAttribution>,
    pub tx_blobs:             Vec<(Vec<u8>, Vec<u8>)>,
    pub prestate:             HashMap<[u8; 32], Vec<u8>>,
    pub rpc_host:             Option<String>,
    pub rpc_port:             u16,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Artifact {
    pub version:                    String,
    pub created_at:                 String,
    pub node_version:               String,
    pub anchor_seq:                 u32,
    pub anchor_hash:                Option<String>,
    pub anchor_account_hash:        Option<String>,
    pub mismatch_seq:               u32,
    pub local_account_hash:         String,
    pub network_account_hash:       String,
    pub applied_count:              usize,
    pub failed_count:               usize,
    pub skipped_count:              usize,
    pub tx_count:                   usize,
    pub touched_key_count:          usize,
    pub prestate_key_count:         usize,
    pub rippled_reference_key_count: usize,
    pub rippled_reference_fetched:  bool,
}

/// Capture a forensic bundle. Failures are logged but non-fatal — callers
/// must not rely on the bundle existing.
pub async fn capture_forensic_bundle(inputs: CaptureInputs) -> anyhow::Result<(PathBuf, HashMap<[u8; 32], Vec<u8>>)> {
    let ts = iso8601_now();
    let dir = inputs.bundle_root.join(format!(
        "{}-{}-{}",
        inputs.anchor_seq, inputs.mismatch_seq, ts,
    ));
    fs::create_dir_all(&dir)?;

    // 1. Headers
    fs::write(
        dir.join("anchor_header.bin"),
        bincode::serialize(&inputs.parent_header)?,
    )?;
    fs::write(
        dir.join("validated_header.bin"),
        bincode::serialize(&inputs.validated_header)?,
    )?;

    // 2. Transaction blobs (raw wire bytes for replay_ledger input)
    fs::write(
        dir.join("tx_blobs.bin"),
        bincode::serialize(&inputs.tx_blobs)?,
    )?;

    // 3. Per-tx attribution (JSON Lines for grep/jq inspection)
    {
        let mut jsonl = String::new();
        for attr in &inputs.per_tx_attribution {
            jsonl.push_str(&serde_json::to_string(attr)?);
            jsonl.push('\n');
        }
        fs::write(dir.join("per_tx_attribution.jsonl"), jsonl)?;
    }

    // 4. Pre-replay state snapshot for all metadata-affected keys
    fs::write(
        dir.join("prestate.bin"),
        bincode::serialize(&inputs.prestate)?,
    )?;

    // 5. Fetch rippled reference bytes for touched keys while the ledger is
    //    still in rippled's retention window. This is the step that captures
    //    "authoritative expected post-state" offline.
    let (rippled_reference, rippled_fetched) = if let Some(host) = inputs.rpc_host.as_deref() {
        match fetch_rippled_reference(
            host,
            inputs.rpc_port,
            inputs.mismatch_seq,
            &inputs.touched_keys,
        )
        .await
        {
            Ok(m) => (m, true),
            Err(e) => {
                warn!("forensic: rippled reference fetch failed: {}", e);
                (HashMap::new(), false)
            }
        }
    } else {
        warn!("forensic: no rpc_host configured; skipping rippled reference fetch");
        (HashMap::new(), false)
    };
    fs::write(
        dir.join("rippled_reference.bin"),
        bincode::serialize(&rippled_reference)?,
    )?;

    // 6. Summary artifact (written last so it reflects the final state)
    let artifact = Artifact {
        version:                    "1".into(),
        created_at:                 ts.clone(),
        node_version:               env!("CARGO_PKG_VERSION").into(),
        anchor_seq:                 inputs.anchor_seq,
        anchor_hash:                inputs.anchor_hash.map(hex32),
        anchor_account_hash:        inputs.anchor_account_hash.map(hex32),
        mismatch_seq:               inputs.mismatch_seq,
        local_account_hash:         hex32(inputs.local_account_hash),
        network_account_hash:       hex32(inputs.network_account_hash),
        applied_count:              inputs.applied_count,
        failed_count:               inputs.failed_count,
        skipped_count:              inputs.skipped_count,
        tx_count:                   inputs.tx_blobs.len(),
        touched_key_count:          inputs.touched_keys.len(),
        prestate_key_count:         inputs.prestate.len(),
        rippled_reference_key_count: rippled_reference.len(),
        rippled_reference_fetched:  rippled_fetched,
    };
    fs::write(
        dir.join("artifact.json"),
        serde_json::to_string_pretty(&artifact)?,
    )?;

    info!(
        "forensic: captured bundle at {:?} (touched={} prestate={} rippled_ref={} fetched={})",
        dir,
        inputs.touched_keys.len(),
        inputs.prestate.len(),
        rippled_reference.len(),
        rippled_fetched,
    );

    Ok((dir, rippled_reference))
}

/// Public mainnet endpoints used as fallback when the local rippled doesn't
/// have the target ledger in its `complete_ledgers` window. Mirrors the
/// constant in `src/ledger/follow.rs` used by `fetch_sle_binary`.
const PUBLIC_SERVERS: &[(&str, u16)] = &[
    ("s1.ripple.com", 51234),
    ("s2.ripple.com", 51234),
    ("44.225.136.208", 51234),
    ("54.208.98.161", 51234),
];

/// Try one endpoint once. Returns:
///   Ok(Some(bytes))  -> parsed a successful response with node_binary
///   Ok(None)         -> reached the server but no usable data (lgrNotFound,
///                       missing field, etc.)
///   Err(_)           -> transport/parse error
async fn try_fetch_one(
    host: &str,
    port: u16,
    req: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::rpc_sync::http_post(host, port, req),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timeout"))??;
    let resp: serde_json::Value = serde_json::from_str(&body)?;
    let result = &resp["result"];
    if result["status"].as_str() != Some("success") {
        return Ok(None);
    }
    if let Some(nb) = result["node_binary"].as_str() {
        if let Ok(bytes) = hex::decode(nb) {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

async fn fetch_one_with_fallback(
    has_local: bool,
    local_host: String,
    local_port: u16,
    req: String,
) -> Option<Vec<u8>> {
    if has_local {
        if let Ok(Some(b)) = try_fetch_one(&local_host, local_port, &req).await {
            return Some(b);
        }
    }
    for (pub_host, pub_port) in PUBLIC_SERVERS {
        if let Ok(Some(b)) = try_fetch_one(pub_host, *pub_port, &req).await {
            return Some(b);
        }
    }
    None
}

async fn fetch_rippled_reference(
    host: &str,
    port: u16,
    ledger_seq: u32,
    keys: &[[u8; 32]],
) -> anyhow::Result<HashMap<[u8; 32], Vec<u8>>> {
    // Fan out all ledger_entry calls concurrently. Each task tries the local
    // rippled first (if configured), then falls back to public mainnet servers
    // in round-robin order. This matches the pattern used by the override
    // fetchers in follow.rs and avoids serial worst-case wait of
    // O(keys * (timeout_local + timeout_pub1 + timeout_pub2)).
    let has_local = port > 0;
    let host_owned = host.to_string();
    let mut join_set = tokio::task::JoinSet::new();
    for key in keys {
        let key_copy = *key;
        let req = format!(
            r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
            hex::encode(key),
            ledger_seq,
        );
        let host_clone = host_owned.clone();
        join_set.spawn(async move {
            let bytes = fetch_one_with_fallback(has_local, host_clone, port, req).await;
            (key_copy, bytes)
        });
    }
    let mut out = HashMap::with_capacity(keys.len());
    while let Some(res) = join_set.join_next().await {
        if let Ok((key, Some(bytes))) = res {
            out.insert(key, bytes);
        }
    }
    Ok(out)
}

fn hex32(bytes: [u8; 32]) -> String {
    hex::encode_upper(bytes)
}

fn iso8601_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Minimal RFC3339-ish timestamp without pulling in chrono. Seconds since
    // epoch is sortable and unambiguous; good enough for directory naming.
    format!("epoch{}", now)
}

/// Build a prestate snapshot for the set of keys touched by a ledger's
/// transaction metadata. Used from inside follow.rs's spawn_blocking closure
/// to capture pre-replay bytes while the state lock is held.
pub fn collect_metadata_affected_keys(
    meta_with_hashes: &[([u8; 32], Vec<u8>)],
) -> Vec<[u8; 32]> {
    let mut keys = std::collections::HashSet::new();
    for (_tx_hash, meta_blob) in meta_with_hashes {
        let nodes = match std::panic::catch_unwind(|| {
            crate::ledger::meta::parse_metadata(meta_blob)
        }) {
            Ok(n) => n,
            Err(_) => continue,
        };
        for node in nodes {
            keys.insert(node.ledger_index);
        }
    }
    keys.into_iter().collect()
}

/// Deserialize helpers used by the replay_fixture harness.
pub mod loader {
    use super::*;

    pub fn load_artifact(dir: &Path) -> anyhow::Result<Artifact> {
        let bytes = fs::read(dir.join("artifact.json"))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn load_anchor_header(dir: &Path) -> anyhow::Result<LedgerHeader> {
        let bytes = fs::read(dir.join("anchor_header.bin"))?;
        Ok(bincode::deserialize(&bytes)?)
    }

    pub fn load_validated_header(dir: &Path) -> anyhow::Result<LedgerHeader> {
        let bytes = fs::read(dir.join("validated_header.bin"))?;
        Ok(bincode::deserialize(&bytes)?)
    }

    pub fn load_tx_blobs(dir: &Path) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let bytes = fs::read(dir.join("tx_blobs.bin"))?;
        Ok(bincode::deserialize(&bytes)?)
    }

    pub fn load_prestate(dir: &Path) -> anyhow::Result<HashMap<[u8; 32], Vec<u8>>> {
        let bytes = fs::read(dir.join("prestate.bin"))?;
        Ok(bincode::deserialize(&bytes)?)
    }

    pub fn load_rippled_reference(
        dir: &Path,
    ) -> anyhow::Result<HashMap<[u8; 32], Vec<u8>>> {
        let bytes = fs::read(dir.join("rippled_reference.bin"))?;
        Ok(bincode::deserialize(&bytes)?)
    }
}
