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
//!     created_overrides.bin  — bincode HashMap<key, created authoritative override status>
//!     modified_overrides.bin — bincode HashMap<key, modified authoritative SLE bytes>
//!     rippled_reference.bin  — bincode HashMap<key, rippled post-state bytes>
//!     per_tx_attribution.jsonl — one JSON line per tx touching keys
//!
//! The replay_fixture harness loads this bundle and calls replay_ledger()
//! offline, comparing its output byte-for-byte against rippled_reference.bin
//! to identify the first divergent key.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::ledger::close::TxAttribution;
use crate::ledger::LedgerHeader;

/// Inputs to a forensic capture run. All fields are owned so the capture can
/// run async after the caller drops its state lock.
pub struct CaptureInputs {
    pub bundle_root: PathBuf,
    pub anchor_seq: u32,
    pub anchor_hash: Option<[u8; 32]>,
    pub anchor_account_hash: Option<[u8; 32]>,
    pub mismatch_seq: u32,
    pub local_account_hash: [u8; 32],
    pub network_account_hash: [u8; 32],
    pub parent_header: LedgerHeader,
    pub validated_header: LedgerHeader,
    pub applied_count: usize,
    pub failed_count: usize,
    pub skipped_count: usize,
    pub touched_keys: Vec<[u8; 32]>,
    pub per_tx_attribution: Vec<TxAttribution>,
    pub tx_blobs: Vec<(Vec<u8>, Vec<u8>)>,
    pub prestate: HashMap<[u8; 32], Vec<u8>>,
    pub created_overrides: HashMap<crate::ledger::Key, crate::ledger::follow::RpcLedgerEntryFetch>,
    pub modified_overrides: HashMap<crate::ledger::Key, Vec<u8>>,
    pub rpc_host: Option<String>,
    pub rpc_port: u16,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Artifact {
    pub version: String,
    pub created_at: String,
    pub node_version: String,
    pub anchor_seq: u32,
    pub anchor_hash: Option<String>,
    pub anchor_account_hash: Option<String>,
    pub mismatch_seq: u32,
    pub local_account_hash: String,
    pub network_account_hash: String,
    pub applied_count: usize,
    pub failed_count: usize,
    pub skipped_count: usize,
    pub tx_count: usize,
    pub touched_key_count: usize,
    pub prestate_key_count: usize,
    pub rippled_reference_key_count: usize,
    pub rippled_reference_fetched: bool,
}

fn write_reference_checkpoint(
    dir: &Path,
    inputs: &CaptureInputs,
    created_at: &str,
    prestate_key_count: usize,
    rippled_reference: &HashMap<[u8; 32], Vec<u8>>,
    rippled_reference_fetched: bool,
) -> anyhow::Result<()> {
    fs::write(
        dir.join("rippled_reference.bin"),
        bincode::serialize(rippled_reference)?,
    )?;

    let artifact = Artifact {
        version: "1".into(),
        created_at: created_at.to_owned(),
        node_version: env!("CARGO_PKG_VERSION").into(),
        anchor_seq: inputs.anchor_seq,
        anchor_hash: inputs.anchor_hash.map(hex32),
        anchor_account_hash: inputs.anchor_account_hash.map(hex32),
        mismatch_seq: inputs.mismatch_seq,
        local_account_hash: hex32(inputs.local_account_hash),
        network_account_hash: hex32(inputs.network_account_hash),
        applied_count: inputs.applied_count,
        failed_count: inputs.failed_count,
        skipped_count: inputs.skipped_count,
        tx_count: inputs.tx_blobs.len(),
        touched_key_count: inputs.touched_keys.len(),
        prestate_key_count,
        rippled_reference_key_count: rippled_reference.len(),
        rippled_reference_fetched,
    };
    fs::write(
        dir.join("artifact.json"),
        serde_json::to_string_pretty(&artifact)?,
    )?;

    Ok(())
}

fn write_prestate_checkpoint(
    dir: &Path,
    prestate: &HashMap<[u8; 32], Vec<u8>>,
) -> anyhow::Result<()> {
    fs::write(dir.join("prestate.bin"), bincode::serialize(prestate)?)?;
    Ok(())
}

fn authoritative_touched_keys(inputs: &CaptureInputs) -> HashSet<[u8; 32]> {
    let mut keys = HashSet::new();
    // `touched_keys` is the caller's full capture scope, including helper-mutated
    // directory neighbors that may not appear as first-class metadata nodes.
    // Never seed those prestate slots from final rippled reference bytes.
    keys.extend(inputs.touched_keys.iter().copied());
    for attr in &inputs.per_tx_attribution {
        keys.extend(attr.created_keys.iter().copied());
        keys.extend(attr.modified_keys.iter().copied());
    }
    keys.extend(inputs.created_overrides.keys().map(|key| key.0));
    keys.extend(inputs.modified_overrides.keys().map(|key| key.0));
    keys
}

fn backfill_untouched_prestate_from_reference(
    prestate: &mut HashMap<[u8; 32], Vec<u8>>,
    reference: &HashMap<[u8; 32], Vec<u8>>,
    authoritative_touched: &HashSet<[u8; 32]>,
) -> usize {
    let mut added = 0usize;
    for (key, bytes) in reference {
        if authoritative_touched.contains(key) || prestate.contains_key(key) {
            continue;
        }
        prestate.insert(*key, bytes.clone());
        added += 1;
    }
    added
}

/// Capture a forensic bundle. Failures are logged but non-fatal — callers
/// must not rely on the bundle existing.
pub async fn capture_forensic_bundle(
    inputs: CaptureInputs,
) -> anyhow::Result<(
    PathBuf,
    HashMap<[u8; 32], Vec<u8>>,
    HashSet<[u8; 32]>,
    HashSet<[u8; 32]>,
)> {
    let ts = iso8601_now();
    let dir = inputs.bundle_root.join(format!(
        "{}-{}-{}",
        inputs.anchor_seq, inputs.mismatch_seq, ts,
    ));
    info!(
        "forensic: starting bundle capture at {:?} (touched={} prestate={} txs={})",
        dir,
        inputs.touched_keys.len(),
        inputs.prestate.len(),
        inputs.tx_blobs.len(),
    );
    fs::create_dir_all(&dir)?;
    info!("forensic: created bundle directory {:?}", dir);

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
    let mut captured_prestate = inputs.prestate.clone();
    write_prestate_checkpoint(&dir, &captured_prestate)?;
    fs::write(
        dir.join("created_overrides.bin"),
        bincode::serialize(&inputs.created_overrides)?,
    )?;
    fs::write(
        dir.join("modified_overrides.bin"),
        bincode::serialize(&inputs.modified_overrides)?,
    )?;

    let initial_reference_keys: Vec<[u8; 32]> = {
        let mut keys = std::collections::BTreeSet::new();
        keys.extend(inputs.touched_keys.iter().copied());
        keys.extend(captured_prestate.keys().copied());
        keys.into_iter().collect()
    };
    let authoritative_touched = authoritative_touched_keys(&inputs);

    // 5. Fetch rippled reference bytes for touched keys while the ledger is
    //    still in rippled's retention window. This is the step that captures
    //    "authoritative expected post-state" offline.
    let rpc_host = inputs.rpc_host.as_deref();
    let (mut rippled_reference, mut rippled_not_found, mut rippled_unavailable, rippled_fetched) =
        if let Some(host) = rpc_host {
            match fetch_rippled_reference(
                host,
                inputs.rpc_port,
                inputs.mismatch_seq,
                &initial_reference_keys,
            )
            .await
            {
                Ok((m, not_found, unavailable)) => (m, not_found, unavailable, true),
                Err(e) => {
                    warn!("forensic: rippled reference fetch failed: {}", e);
                    (HashMap::new(), HashSet::new(), HashSet::new(), false)
                }
            }
        } else {
            warn!("forensic: no rpc_host configured; skipping rippled reference fetch");
            (HashMap::new(), HashSet::new(), HashSet::new(), false)
        };
    let initial_backfilled = backfill_untouched_prestate_from_reference(
        &mut captured_prestate,
        &rippled_reference,
        &authoritative_touched,
    );
    if initial_backfilled > 0 {
        write_prestate_checkpoint(&dir, &captured_prestate)?;
        info!(
            "forensic: backfilled untouched prestate from base rippled reference seq={} added={} total_prestate={}",
            inputs.mismatch_seq,
            initial_backfilled,
            captured_prestate.len(),
        );
    }
    write_reference_checkpoint(
        &dir,
        &inputs,
        &ts,
        captured_prestate.len(),
        &rippled_reference,
        false,
    )?;
    if rippled_fetched {
        // Deep owner/book neighborhoods can outgrow the first enrichment cap.
        // Give the crawl enough headroom to prove that the frontier is exhausted
        // instead of stopping at an artificial ceiling.
        const REFERENCE_ENRICH_MAX_KEYS: usize = 1_000_000;
        let requested_keys: HashSet<[u8; 32]> = initial_reference_keys.iter().copied().collect();
        let mut remaining_budget = REFERENCE_ENRICH_MAX_KEYS;
        let host = rpc_host.expect("rpc_host must be present when rippled_fetched is true");
        while remaining_budget > 0 {
            let extra_reference_keys = collect_reference_enrichment_keys(
                &requested_keys,
                &rippled_reference,
                &rippled_not_found,
                &rippled_unavailable,
                remaining_budget,
            );
            if extra_reference_keys.is_empty() {
                break;
            }
            info!(
                "forensic: enriching rippled reference seq={} extra_keys={} remaining_budget={}",
                inputs.mismatch_seq,
                extra_reference_keys.len(),
                remaining_budget,
            );
            match fetch_rippled_reference(
                host,
                inputs.rpc_port,
                inputs.mismatch_seq,
                &extra_reference_keys,
            )
            .await
            {
                Ok((extra_map, extra_not_found, extra_unavailable)) => {
                    if extra_map.is_empty()
                        && extra_not_found.is_empty()
                        && extra_unavailable.is_empty()
                    {
                        break;
                    }
                    remaining_budget = remaining_budget.saturating_sub(
                        extra_map.len() + extra_not_found.len() + extra_unavailable.len(),
                    );
                    let backfilled = backfill_untouched_prestate_from_reference(
                        &mut captured_prestate,
                        &extra_map,
                        &authoritative_touched,
                    );
                    if backfilled > 0 {
                        write_prestate_checkpoint(&dir, &captured_prestate)?;
                        info!(
                            "forensic: backfilled untouched prestate from enriched rippled reference seq={} round=reference-enrich added={} total_prestate={}",
                            inputs.mismatch_seq,
                            backfilled,
                            captured_prestate.len(),
                        );
                    }
                    rippled_reference.extend(extra_map);
                    rippled_not_found.extend(extra_not_found);
                    rippled_unavailable.extend(extra_unavailable);
                    write_reference_checkpoint(
                        &dir,
                        &inputs,
                        &ts,
                        captured_prestate.len(),
                        &rippled_reference,
                        false,
                    )?;
                }
                Err(e) => {
                    warn!("forensic: rippled reference enrich failed: {}", e);
                    break;
                }
            }
        }
        const DIRECT_EDGE_TARGET_CAP: usize = 200_000;
        const DIRECT_EDGE_CLOSURE_MAX_FETCHES: usize = 1_000_000;
        let mut remaining_direct_edge_budget = DIRECT_EDGE_CLOSURE_MAX_FETCHES;
        let mut round = 0usize;
        while remaining_direct_edge_budget > 0 {
            round += 1;
            let direct_targets = collect_direct_missing_reference_targets(
                &rippled_reference,
                &inputs.per_tx_attribution,
                &rippled_not_found,
                &rippled_unavailable,
                DIRECT_EDGE_TARGET_CAP.min(remaining_direct_edge_budget),
            );
            if direct_targets.is_empty() {
                break;
            }
            info!(
                "forensic: closing direct reference edges seq={} round={} targets={}",
                inputs.mismatch_seq,
                round,
                direct_targets.len(),
            );
            match fetch_rippled_reference(
                host,
                inputs.rpc_port,
                inputs.mismatch_seq,
                &direct_targets,
            )
            .await
            {
                Ok((extra_map, extra_not_found, extra_unavailable)) => {
                    let newly_found = extra_map.len();
                    if !extra_not_found.is_empty() && extra_not_found.len() <= 32 {
                        let mut stubborn: Vec<String> =
                            extra_not_found.iter().copied().map(hex32).collect();
                        stubborn.sort();
                        info!(
                            "forensic: direct reference edges still not found seq={} round={} count={} keys={:?}",
                            inputs.mismatch_seq,
                            round,
                            stubborn.len(),
                            stubborn,
                        );
                    }
                    remaining_direct_edge_budget = remaining_direct_edge_budget.saturating_sub(
                        newly_found + extra_not_found.len() + extra_unavailable.len(),
                    );
                    let backfilled = backfill_untouched_prestate_from_reference(
                        &mut captured_prestate,
                        &extra_map,
                        &authoritative_touched,
                    );
                    if backfilled > 0 {
                        write_prestate_checkpoint(&dir, &captured_prestate)?;
                        info!(
                            "forensic: backfilled untouched prestate from direct-edge rippled reference seq={} round={} added={} total_prestate={}",
                            inputs.mismatch_seq,
                            round,
                            backfilled,
                            captured_prestate.len(),
                        );
                    }
                    rippled_reference.extend(extra_map);
                    rippled_not_found.extend(extra_not_found);
                    rippled_unavailable.extend(extra_unavailable);
                    write_reference_checkpoint(
                        &dir,
                        &inputs,
                        &ts,
                        captured_prestate.len(),
                        &rippled_reference,
                        false,
                    )?;
                    if newly_found == 0 {
                        break;
                    }
                }
                Err(e) => {
                    warn!("forensic: direct reference edge closure failed: {}", e);
                    break;
                }
            }
        }
        if remaining_direct_edge_budget == 0 {
            warn!(
                "forensic: direct reference edge closure hit max budget seq={} captured={} max_extra={}",
                inputs.mismatch_seq,
                rippled_reference.len(),
                DIRECT_EDGE_CLOSURE_MAX_FETCHES,
            );
        }
        if remaining_budget == 0 {
            warn!(
                "forensic: rippled reference enrichment hit max budget seq={} captured={} requested={} max_extra={}",
                inputs.mismatch_seq,
                rippled_reference.len(),
                requested_keys.len(),
                REFERENCE_ENRICH_MAX_KEYS,
            );
        }
    }
    write_reference_checkpoint(
        &dir,
        &inputs,
        &ts,
        captured_prestate.len(),
        &rippled_reference,
        rippled_fetched,
    )?;

    info!(
        "forensic: captured bundle at {:?} (touched={} prestate={} rippled_ref={} fetched={})",
        dir,
        inputs.touched_keys.len(),
        captured_prestate.len(),
        rippled_reference.len(),
        rippled_fetched,
    );

    Ok((
        dir,
        rippled_reference,
        rippled_not_found,
        rippled_unavailable,
    ))
}

fn collect_direct_missing_reference_targets(
    rippled_reference: &HashMap<[u8; 32], Vec<u8>>,
    per_tx_attribution: &[TxAttribution],
    not_found: &HashSet<[u8; 32]>,
    unavailable: &HashSet<[u8; 32]>,
    max_targets: usize,
) -> Vec<[u8; 32]> {
    let mut out = std::collections::BTreeSet::new();
    for edge in collect_missing_reference_edges(rippled_reference, per_tx_attribution) {
        if !direct_reference_edge_should_close(edge.edge_label) {
            continue;
        }
        if rippled_reference.contains_key(&edge.target_key)
            || not_found.contains(&edge.target_key)
            || unavailable.contains(&edge.target_key)
        {
            continue;
        }
        out.insert(edge.target_key);
        if out.len() >= max_targets {
            break;
        }
    }
    out.into_iter().collect()
}

fn direct_reference_edge_should_close(edge_label: &str) -> bool {
    !matches!(edge_label, "OwnerDirectory.next" | "OwnerDirectory.prev")
}

/// Stable public mainnet Clio endpoints used as fallback when the local
/// rippled doesn't have the target ledger in its `complete_ledgers` window.
///
/// These are treated as the authoritative public sources for "not found"
/// decisions. A key is only considered definitively absent when both public
/// Clio servers say so for the requested validated ledger.
const PUBLIC_SERVERS: &[(&str, u16)] = &[("s1.ripple.com", 51234), ("s2.ripple.com", 51234)];
const FINAL_NOT_FOUND_CONFIRM_ATTEMPTS: usize = 3;
const FINAL_NOT_FOUND_CONFIRM_DELAY_MS: u64 = 150;
const FINAL_NOT_FOUND_CONFIRM_CONCURRENCY: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReferenceFetch {
    Found(Vec<u8>),
    NotFound,
    Unavailable,
}

fn response_indicates_not_found(resp: &serde_json::Value) -> bool {
    fn matches_not_found(value: &serde_json::Value) -> bool {
        value.as_str().map_or(false, |s| {
            let lower = s.to_ascii_lowercase();
            lower.contains("entrynotfound")
                || lower.contains("objectnotfound")
                || lower.contains("notfound")
                || lower.contains("not found")
        })
    }

    [
        &resp["error"],
        &resp["error_message"],
        &resp["result"]["error"],
        &resp["result"]["error_message"],
        &resp["result"]["message"],
    ]
    .into_iter()
    .any(matches_not_found)
}

/// Try one endpoint once and preserve "not found" vs "unavailable".
async fn try_fetch_one(host: &str, port: u16, req: &str) -> anyhow::Result<ReferenceFetch> {
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::rpc_sync::http_post(host, port, req),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timeout"))??;
    let resp: serde_json::Value = serde_json::from_str(&body)?;
    if let Some(nb) = resp["result"]["node_binary"].as_str() {
        if let Ok(bytes) = hex::decode(nb) {
            return Ok(ReferenceFetch::Found(bytes));
        }
    }
    if response_indicates_not_found(&resp) {
        Ok(ReferenceFetch::NotFound)
    } else {
        Ok(ReferenceFetch::Unavailable)
    }
}

async fn fetch_one_with_fallback(
    has_local: bool,
    local_host: String,
    local_port: u16,
    req: String,
) -> ReferenceFetch {
    let mut public_not_found = 0usize;
    if has_local {
        if let Ok(status) = try_fetch_one(&local_host, local_port, &req).await {
            match status {
                ReferenceFetch::Found(bytes) => return ReferenceFetch::Found(bytes),
                // Local history gaps are not authoritative for absence.
                ReferenceFetch::NotFound | ReferenceFetch::Unavailable => {}
            }
        }
    }
    for (pub_host, pub_port) in PUBLIC_SERVERS {
        if let Ok(status) = try_fetch_one(pub_host, *pub_port, &req).await {
            match status {
                ReferenceFetch::Found(bytes) => return ReferenceFetch::Found(bytes),
                ReferenceFetch::NotFound => public_not_found += 1,
                ReferenceFetch::Unavailable => {}
            }
        }
    }
    if public_not_found == PUBLIC_SERVERS.len() {
        ReferenceFetch::NotFound
    } else {
        ReferenceFetch::Unavailable
    }
}

async fn fetch_rippled_reference_once(
    host: &str,
    port: u16,
    ledger_seq: u32,
    keys: &[[u8; 32]],
) -> anyhow::Result<(
    HashMap<[u8; 32], Vec<u8>>,
    HashSet<[u8; 32]>,
    HashSet<[u8; 32]>,
)> {
    const REF_FETCH_CONCURRENCY: usize = 64;
    // Fan out all ledger_entry calls concurrently. Each task tries the local
    // rippled first (if configured), then falls back to public mainnet servers
    // in round-robin order. This matches the pattern used by the override
    // fetchers in follow.rs and avoids serial worst-case wait of
    // O(keys * (timeout_local + timeout_pub1 + timeout_pub2)).
    let has_local = port > 0;
    let host_owned = host.to_string();
    let mut join_set = tokio::task::JoinSet::new();
    let mut out = HashMap::with_capacity(keys.len());
    let mut not_found = HashSet::new();
    let mut unavailable = HashSet::new();
    let mut next = 0usize;
    let mut completed = 0usize;

    while next < keys.len() || !join_set.is_empty() {
        while next < keys.len() && join_set.len() < REF_FETCH_CONCURRENCY {
            let key_copy = keys[next];
            next += 1;
            let req = format!(
                r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                hex::encode(key_copy),
                ledger_seq,
            );
            let host_clone = host_owned.clone();
            join_set.spawn(async move {
                let bytes = fetch_one_with_fallback(has_local, host_clone, port, req).await;
                (key_copy, bytes)
            });
        }

        let Some(res) = join_set.join_next().await else {
            break;
        };
        if let Ok((key, status)) = res {
            match status {
                ReferenceFetch::Found(bytes) => {
                    out.insert(key, bytes);
                }
                ReferenceFetch::NotFound => {
                    not_found.insert(key);
                }
                ReferenceFetch::Unavailable => {
                    unavailable.insert(key);
                }
            }
            completed += 1;
            if completed % 512 == 0 || completed == keys.len() {
                info!(
                    "forensic: rippled reference progress seq={} completed={}/{} found={} not_found={} unavailable={}",
                    ledger_seq,
                    completed,
                    keys.len(),
                    out.len(),
                    not_found.len(),
                    unavailable.len(),
                );
            }
        }
    }
    Ok((out, not_found, unavailable))
}

async fn confirm_persistent_not_found(
    ledger_seq: u32,
    keys: &[[u8; 32]],
) -> anyhow::Result<(
    HashMap<[u8; 32], Vec<u8>>,
    HashSet<[u8; 32]>,
    HashSet<[u8; 32]>,
)> {
    let mut join_set = tokio::task::JoinSet::new();
    let mut out = HashMap::with_capacity(keys.len());
    let mut not_found = HashSet::new();
    let mut unavailable = HashSet::new();
    let mut next = 0usize;
    let mut completed = 0usize;

    while next < keys.len() || !join_set.is_empty() {
        while next < keys.len() && join_set.len() < FINAL_NOT_FOUND_CONFIRM_CONCURRENCY {
            let key = keys[next];
            next += 1;
            join_set.spawn(async move {
                let req = format!(
                    r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                    hex::encode(key),
                    ledger_seq,
                );
                let mut public_not_found = 0usize;
                let mut saw_unavailable = false;
                let mut found_bytes = None;

                'servers: for (pub_host, pub_port) in PUBLIC_SERVERS {
                    for attempt in 0..FINAL_NOT_FOUND_CONFIRM_ATTEMPTS {
                        match try_fetch_one(pub_host, *pub_port, &req).await {
                            Ok(ReferenceFetch::Found(bytes)) => {
                                found_bytes = Some(bytes);
                                break 'servers;
                            }
                            Ok(ReferenceFetch::NotFound) => {
                                if attempt + 1 < FINAL_NOT_FOUND_CONFIRM_ATTEMPTS {
                                    tokio::time::sleep(std::time::Duration::from_millis(
                                        FINAL_NOT_FOUND_CONFIRM_DELAY_MS,
                                    ))
                                    .await;
                                } else {
                                    public_not_found += 1;
                                }
                            }
                            Ok(ReferenceFetch::Unavailable) | Err(_) => {
                                saw_unavailable = true;
                                break;
                            }
                        }
                    }
                }

                let status = if let Some(bytes) = found_bytes {
                    ReferenceFetch::Found(bytes)
                } else if public_not_found == PUBLIC_SERVERS.len() && !saw_unavailable {
                    ReferenceFetch::NotFound
                } else {
                    ReferenceFetch::Unavailable
                };
                (key, status)
            });
        }

        let Some(res) = join_set.join_next().await else {
            break;
        };
        if let Ok((key, status)) = res {
            match status {
                ReferenceFetch::Found(bytes) => {
                    out.insert(key, bytes);
                }
                ReferenceFetch::NotFound => {
                    not_found.insert(key);
                }
                ReferenceFetch::Unavailable => {
                    unavailable.insert(key);
                }
            }
            completed += 1;
            if completed % 16 == 0 || completed == keys.len() {
                info!(
                    "forensic: final confirmation progress seq={} completed={}/{} recovered={} still_not_found={} unavailable={}",
                    ledger_seq,
                    completed,
                    keys.len(),
                    out.len(),
                    not_found.len(),
                    unavailable.len(),
                );
            }
        }
    }

    Ok((out, not_found, unavailable))
}

pub async fn fetch_rippled_reference(
    host: &str,
    port: u16,
    ledger_seq: u32,
    keys: &[[u8; 32]],
) -> anyhow::Result<(
    HashMap<[u8; 32], Vec<u8>>,
    HashSet<[u8; 32]>,
    HashSet<[u8; 32]>,
)> {
    const RETRY_ROUNDS: usize = 2;

    let (mut out, mut not_found, mut unavailable) =
        fetch_rippled_reference_once(host, port, ledger_seq, keys).await?;

    for round in 0..RETRY_ROUNDS {
        if unavailable.is_empty() && not_found.is_empty() {
            break;
        }
        let prior_not_found = not_found.len();
        let prior_unavailable = unavailable.len();
        let mut retry_keys = Vec::with_capacity(prior_not_found + prior_unavailable);
        retry_keys.extend(not_found.drain());
        retry_keys.extend(unavailable.drain());
        info!(
            "forensic: retrying unresolved rippled references seq={} round={} keys={} prior_not_found={} prior_unavailable={}",
            ledger_seq,
            round + 1,
            retry_keys.len(),
            prior_not_found,
            prior_unavailable,
        );
        let (retry_out, retry_not_found, retry_unavailable) =
            fetch_rippled_reference_once(host, port, ledger_seq, &retry_keys).await?;
        out.extend(retry_out);
        not_found = retry_not_found;
        unavailable = retry_unavailable;
    }

    if !not_found.is_empty() {
        let confirm_keys: Vec<[u8; 32]> = not_found.iter().copied().collect();
        info!(
            "forensic: final public confirmation for persistent not_found seq={} keys={} attempts_per_server={}",
            ledger_seq,
            confirm_keys.len(),
            FINAL_NOT_FOUND_CONFIRM_ATTEMPTS,
        );
        let (confirm_out, confirm_not_found, confirm_unavailable) =
            confirm_persistent_not_found(ledger_seq, &confirm_keys).await?;
        let recovered = confirm_out.len();
        let still_missing = confirm_not_found.len();
        let became_unavailable = confirm_unavailable.len();
        out.extend(confirm_out);
        not_found = confirm_not_found;
        unavailable.extend(confirm_unavailable);
        info!(
            "forensic: final public confirmation complete seq={} recovered={} still_not_found={} became_unavailable={}",
            ledger_seq,
            recovered,
            still_missing,
            became_unavailable,
        );
    }

    Ok((out, not_found, unavailable))
}

pub fn collect_reference_enrichment_keys(
    requested_keys: &HashSet<[u8; 32]>,
    rippled_reference: &HashMap<[u8; 32], Vec<u8>>,
    not_found: &HashSet<[u8; 32]>,
    unavailable: &HashSet<[u8; 32]>,
    max_extra: usize,
) -> Vec<[u8; 32]> {
    let mut owner_member_discovered = std::collections::BTreeSet::new();
    for (key, raw) in rippled_reference {
        for related in owner_directory_member_keys_from_raw(*key, raw) {
            if requested_keys.contains(&related)
                || rippled_reference.contains_key(&related)
                || not_found.contains(&related)
                || unavailable.contains(&related)
            {
                continue;
            }
            owner_member_discovered.insert(related);
        }
    }

    let mut hop_discovered = std::collections::BTreeSet::new();
    for (key, raw) in rippled_reference {
        for related in transitive_reference_scope_keys_from_raw(*key, raw) {
            if requested_keys.contains(&related)
                || rippled_reference.contains_key(&related)
                || not_found.contains(&related)
                || unavailable.contains(&related)
                || owner_member_discovered.contains(&related)
            {
                continue;
            }
            hop_discovered.insert(related);
        }
    }

    let mut chain_discovered = std::collections::BTreeSet::new();
    for (key, raw) in rippled_reference {
        for related in collect_directory_chain_neighbors(*key, raw) {
            if requested_keys.contains(&related)
                || rippled_reference.contains_key(&related)
                || not_found.contains(&related)
                || unavailable.contains(&related)
                || owner_member_discovered.contains(&related)
                || hop_discovered.contains(&related)
            {
                continue;
            }
            chain_discovered.insert(related);
        }
    }

    owner_member_discovered
        .into_iter()
        .chain(hop_discovered.into_iter())
        .chain(chain_discovered.into_iter())
        .take(max_extra)
        .collect()
}

fn owner_directory_member_keys_from_raw(key: [u8; 32], raw: &[u8]) -> Vec<[u8; 32]> {
    let Some(sle) = crate::ledger::sle::SLE::from_raw(crate::ledger::Key(key), raw.to_vec()) else {
        return Vec::new();
    };
    if sle.entry_type() != crate::ledger::sle::LedgerEntryType::DirectoryNode {
        return Vec::new();
    }

    let Ok(dir) = crate::ledger::directory::DirectoryNode::decode(raw, key) else {
        return Vec::new();
    };
    if dir.exchange_rate.is_some() {
        return Vec::new();
    }

    dir.indexes
}

#[derive(Debug, Clone)]
pub struct MissingReferenceEdge {
    pub source_key: [u8; 32],
    pub source_class: &'static str,
    pub edge_label: &'static str,
    pub target_key: [u8; 32],
    pub target_class: &'static str,
    pub tx_index: Option<u32>,
    pub tx_type: Option<String>,
    pub ter_token: Option<String>,
}

pub fn collect_missing_reference_edges(
    rippled_reference: &HashMap<[u8; 32], Vec<u8>>,
    per_tx_attribution: &[TxAttribution],
) -> Vec<MissingReferenceEdge> {
    let mut first_touch = HashMap::<[u8; 32], &TxAttribution>::new();
    for attr in per_tx_attribution {
        for key in attr.created_keys.iter().chain(attr.modified_keys.iter()) {
            first_touch.entry(*key).or_insert(attr);
        }
    }

    let mut out = Vec::new();
    for (key_bytes, raw) in rippled_reference {
        let key = crate::ledger::Key(*key_bytes);
        let Some(sle) = crate::ledger::sle::SLE::from_raw(key, raw.clone()) else {
            continue;
        };
        let attr = first_touch.get(key_bytes).copied();
        let mut push_missing =
            |edge_label: &'static str, target_key: [u8; 32], target_class: &'static str| {
                if rippled_reference.contains_key(&target_key) {
                    return;
                }
                out.push(MissingReferenceEdge {
                    source_key: *key_bytes,
                    source_class: match sle.entry_type() {
                        crate::ledger::sle::LedgerEntryType::DirectoryNode => "DirectoryNode",
                        crate::ledger::sle::LedgerEntryType::Offer => "Offer",
                        crate::ledger::sle::LedgerEntryType::RippleState => "RippleState",
                        crate::ledger::sle::LedgerEntryType::AccountRoot => "AccountRoot",
                        _ => "Other",
                    },
                    edge_label,
                    target_key,
                    target_class,
                    tx_index: attr.map(|a| a.tx_index),
                    tx_type: attr.map(|a| a.tx_type.clone()),
                    ter_token: attr.map(|a| a.ter_token.clone()),
                });
            };

        match sle.entry_type() {
            crate::ledger::sle::LedgerEntryType::DirectoryNode => {
                let Ok(dir) = crate::ledger::directory::DirectoryNode::decode(raw, *key_bytes)
                else {
                    continue;
                };
                if dir.root_index != *key_bytes {
                    push_missing("DirectoryNode.root", dir.root_index, "DirectoryNode");
                }
                if dir.index_next != 0 {
                    push_missing(
                        if dir.exchange_rate.is_some() {
                            "BookDirectory.next"
                        } else {
                            "OwnerDirectory.next"
                        },
                        crate::ledger::directory::page_key(&dir.root_index, dir.index_next).0,
                        "DirectoryNode",
                    );
                }
                if dir.index_previous != 0 {
                    push_missing(
                        if dir.exchange_rate.is_some() {
                            "BookDirectory.prev"
                        } else {
                            "OwnerDirectory.prev"
                        },
                        crate::ledger::directory::page_key(&dir.root_index, dir.index_previous).0,
                        "DirectoryNode",
                    );
                }
            }
            crate::ledger::sle::LedgerEntryType::Offer => {
                let Some(offer) = crate::ledger::offer::Offer::decode_from_sle(raw) else {
                    continue;
                };
                push_missing(
                    "Offer.account",
                    crate::ledger::account::shamap_key(&offer.account).0,
                    "AccountRoot",
                );

                let owner_root = crate::ledger::directory::owner_dir_key(&offer.account).0;
                push_missing("Offer.owner_root", owner_root, "DirectoryNode");
                if offer.owner_node != 0 {
                    push_missing(
                        "Offer.owner_page",
                        crate::ledger::directory::page_key(&owner_root, offer.owner_node).0,
                        "DirectoryNode",
                    );
                }

                push_missing("Offer.book_root", offer.book_directory, "DirectoryNode");
                if offer.book_node != 0 {
                    push_missing(
                        "Offer.book_page",
                        crate::ledger::directory::page_key(&offer.book_directory, offer.book_node)
                            .0,
                        "DirectoryNode",
                    );
                }
            }
            crate::ledger::sle::LedgerEntryType::RippleState => {
                let Some(line) = crate::ledger::trustline::RippleState::decode_from_sle(raw) else {
                    continue;
                };
                push_missing(
                    "RippleState.low_account",
                    crate::ledger::account::shamap_key(&line.low_account).0,
                    "AccountRoot",
                );
                push_missing(
                    "RippleState.high_account",
                    crate::ledger::account::shamap_key(&line.high_account).0,
                    "AccountRoot",
                );

                let low_root = crate::ledger::directory::owner_dir_key(&line.low_account).0;
                let high_root = crate::ledger::directory::owner_dir_key(&line.high_account).0;
                push_missing("RippleState.low_root", low_root, "DirectoryNode");
                push_missing("RippleState.high_root", high_root, "DirectoryNode");
                if line.low_node != 0 {
                    push_missing(
                        "RippleState.low_page",
                        crate::ledger::directory::page_key(&low_root, line.low_node).0,
                        "DirectoryNode",
                    );
                }
                if line.high_node != 0 {
                    push_missing(
                        "RippleState.high_page",
                        crate::ledger::directory::page_key(&high_root, line.high_node).0,
                        "DirectoryNode",
                    );
                }
            }
            _ => {}
        }
    }

    out.sort_by(|a, b| {
        a.tx_index
            .unwrap_or(u32::MAX)
            .cmp(&b.tx_index.unwrap_or(u32::MAX))
            .then_with(|| a.edge_label.cmp(b.edge_label))
            .then_with(|| a.source_key.cmp(&b.source_key))
            .then_with(|| a.target_key.cmp(&b.target_key))
    });
    out
}

fn transitive_reference_scope_keys_from_raw(key: [u8; 32], raw: &[u8]) -> Vec<[u8; 32]> {
    let entry_type = crate::ledger::sle::SLE::from_raw(crate::ledger::Key(key), raw.to_vec())
        .map(|sle| sle.entry_type());

    match entry_type {
        Some(crate::ledger::sle::LedgerEntryType::DirectoryNode) => {
            let Ok(dir) = crate::ledger::directory::DirectoryNode::decode(raw, key) else {
                return Vec::new();
            };
            if dir.exchange_rate.is_none() {
                // Owner-directory chain crawling is handled separately via
                // collect_directory_chain_neighbors(), but the page members
                // themselves are the objects that expose the missing Offer /
                // RippleState adjacency we still need to pull into rippled
                // parity.
                return dir.indexes;
            }
            let mut out = dir.indexes;
            if dir.root_index != key {
                out.push(dir.root_index);
            }
            if dir.index_next != 0 {
                out.push(crate::ledger::directory::page_key(&dir.root_index, dir.index_next).0);
            }
            if dir.index_previous != 0 {
                out.push(crate::ledger::directory::page_key(&dir.root_index, dir.index_previous).0);
            }
            return out;
        }
        Some(crate::ledger::sle::LedgerEntryType::Offer)
        | Some(crate::ledger::sle::LedgerEntryType::RippleState) => {
            let (delta, _) = crate::ledger::follow::collect_authoritative_hop_scope_from_raw(
                crate::ledger::Key(key),
                raw,
            );
            return delta.into_iter().map(|related| related.0).collect();
        }
        _ => {}
    }

    let (delta, _) = crate::ledger::follow::collect_authoritative_hop_scope_from_raw(
        crate::ledger::Key(key),
        raw,
    );
    delta.into_iter().map(|related| related.0).collect()
}

fn collect_directory_chain_neighbors(key: [u8; 32], raw: &[u8]) -> Vec<[u8; 32]> {
    let Some(sle) = crate::ledger::sle::SLE::from_raw(crate::ledger::Key(key), raw.to_vec()) else {
        return Vec::new();
    };
    if sle.entry_type() != crate::ledger::sle::LedgerEntryType::DirectoryNode {
        return Vec::new();
    }

    let Ok(dir) = crate::ledger::directory::DirectoryNode::decode(raw, key) else {
        return Vec::new();
    };

    // Owner directories are useful as one-step seeds from the root page, but
    // recursively walking every discovered owner page burns budget on large
    // account inventories and produces a long tail of low-signal page fetches.
    // Keep book-directory chain traversal intact, but only expand owner
    // directory neighbors from the root page itself.
    if dir.exchange_rate.is_none() && dir.root_index != key {
        return Vec::new();
    }

    let mut related = Vec::with_capacity(3);
    if dir.root_index != key {
        related.push(dir.root_index);
    }
    if dir.index_next != 0 {
        related.push(crate::ledger::directory::page_key(&dir.root_index, dir.index_next).0);
    }
    if dir.index_previous != 0 {
        related.push(crate::ledger::directory::page_key(&dir.root_index, dir.index_previous).0);
    }
    related
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
pub fn collect_metadata_affected_keys(meta_with_hashes: &[([u8; 32], Vec<u8>)]) -> Vec<[u8; 32]> {
    let mut keys = std::collections::HashSet::new();
    for (_tx_hash, meta_blob) in meta_with_hashes {
        let nodes =
            match std::panic::catch_unwind(|| crate::ledger::meta::parse_metadata(meta_blob)) {
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

    pub fn load_created_overrides(
        dir: &Path,
    ) -> anyhow::Result<HashMap<crate::ledger::Key, crate::ledger::follow::RpcLedgerEntryFetch>>
    {
        match fs::read(dir.join("created_overrides.bin")) {
            Ok(bytes) => Ok(bincode::deserialize(&bytes)?),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
            Err(err) => Err(err.into()),
        }
    }

    pub fn load_modified_overrides(
        dir: &Path,
    ) -> anyhow::Result<HashMap<crate::ledger::Key, Vec<u8>>> {
        match fs::read(dir.join("modified_overrides.bin")) {
            Ok(bytes) => Ok(bincode::deserialize(&bytes)?),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
            Err(err) => Err(err.into()),
        }
    }

    pub fn load_rippled_reference(dir: &Path) -> anyhow::Result<HashMap<[u8; 32], Vec<u8>>> {
        let bytes = fs::read(dir.join("rippled_reference.bin"))?;
        Ok(bincode::deserialize(&bytes)?)
    }

    pub fn load_per_tx_attribution(dir: &Path) -> anyhow::Result<Vec<TxAttribution>> {
        let text = fs::read_to_string(dir.join("per_tx_attribution.jsonl"))?;
        let mut out = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            out.push(serde_json::from_str(line)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_reference_keys_include_prestate_only_entries() {
        let touched = [[0x11; 32], [0x22; 32]];
        let prestate_only = [0x33; 32];
        let mut prestate = HashMap::new();
        prestate.insert(touched[1], vec![1]);
        prestate.insert(prestate_only, vec![2]);

        let mut keys = std::collections::BTreeSet::new();
        keys.extend(touched);
        keys.extend(prestate.keys().copied());
        let keys: Vec<[u8; 32]> = keys.into_iter().collect();

        assert!(keys.contains(&touched[0]));
        assert!(keys.contains(&touched[1]));
        assert!(keys.contains(&prestate_only));
    }

    #[test]
    fn authoritative_touched_keys_include_capture_scope() {
        let scope_only = [0x44; 32];
        let metadata_key = [0x55; 32];
        let override_key = crate::ledger::Key([0x66; 32]);
        let inputs = CaptureInputs {
            bundle_root: PathBuf::new(),
            anchor_seq: 1,
            anchor_hash: None,
            anchor_account_hash: None,
            mismatch_seq: 2,
            local_account_hash: [0; 32],
            network_account_hash: [0; 32],
            parent_header: LedgerHeader::default(),
            validated_header: LedgerHeader::default(),
            applied_count: 0,
            failed_count: 0,
            skipped_count: 0,
            touched_keys: vec![scope_only],
            per_tx_attribution: vec![TxAttribution {
                tx_id: [0; 32],
                tx_index: 0,
                tx_type: "OfferCreate".to_string(),
                ter_token: "tesSUCCESS".to_string(),
                created_keys: Vec::new(),
                modified_keys: vec![metadata_key],
            }],
            tx_blobs: Vec::new(),
            prestate: HashMap::new(),
            created_overrides: HashMap::from([(
                override_key,
                crate::ledger::follow::RpcLedgerEntryFetch::NotFound,
            )]),
            modified_overrides: HashMap::new(),
            rpc_host: None,
            rpc_port: 0,
        };

        let protected = authoritative_touched_keys(&inputs);

        assert!(protected.contains(&scope_only));
        assert!(protected.contains(&metadata_key));
        assert!(protected.contains(&override_key.0));
    }

    #[test]
    fn mixed_public_not_found_and_unavailable_stays_ambiguous() {
        assert_eq!(PUBLIC_SERVERS.len(), 2);
        let public_not_found = 1usize;
        let status = if public_not_found == PUBLIC_SERVERS.len() {
            ReferenceFetch::NotFound
        } else {
            ReferenceFetch::Unavailable
        };
        assert_eq!(status, ReferenceFetch::Unavailable);
    }

    #[test]
    fn retry_round_rechecks_not_found_and_unavailable() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        let mut not_found = HashSet::from([a]);
        let mut unavailable = HashSet::from([b]);
        let mut retry_keys = Vec::new();
        retry_keys.extend(not_found.drain());
        retry_keys.extend(unavailable.drain());
        let retry_keys: HashSet<[u8; 32]> = retry_keys.into_iter().collect();

        assert!(retry_keys.contains(&a));
        assert!(retry_keys.contains(&b));
        assert!(not_found.is_empty());
        assert!(unavailable.is_empty());
    }

    #[test]
    fn found_result_should_override_public_not_found_majority() {
        let statuses = [
            ReferenceFetch::NotFound,
            ReferenceFetch::Found(vec![0xAB]),
            ReferenceFetch::NotFound,
        ];
        let mut found = None;
        for status in statuses {
            if let ReferenceFetch::Found(bytes) = status {
                found = Some(bytes);
                break;
            }
        }

        assert_eq!(found, Some(vec![0xAB]));
    }

    #[test]
    fn reference_enrichment_includes_transitive_offer_book_scope() {
        let owner = [0x11; 20];
        let owner_root = crate::ledger::directory::owner_dir_key(&owner);
        let owner_page = crate::ledger::directory::page_key(&owner_root.0, 7);
        let owner_member = [0x42; 32];
        let dir = crate::ledger::directory::DirectoryNode {
            key: owner_page.0,
            root_index: owner_root.0,
            indexes: vec![owner_member],
            index_next: 8,
            index_previous: 0,
            owner: Some(owner),
            exchange_rate: None,
            taker_pays_currency: None,
            taker_pays_issuer: None,
            taker_gets_currency: None,
            taker_gets_issuer: None,
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: true,
            has_index_previous: false,
            raw_sle: None,
        };

        let offer = crate::ledger::offer::Offer {
            account: owner,
            sequence: 22,
            taker_pays: crate::transaction::amount::Amount::Xrp(10),
            taker_gets: crate::transaction::amount::Amount::Xrp(20),
            flags: 0,
            book_directory: {
                let mut key = [0x7A; 32];
                key[24..32].copy_from_slice(&9u64.to_be_bytes());
                key
            },
            book_node: 9,
            owner_node: 7,
            expiration: None,
            domain_id: None,
            additional_books: vec![[0x55; 32]],
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let offer_key = offer.key();

        let mut rippled_reference = HashMap::new();
        rippled_reference.insert(owner_page.0, dir.to_sle_binary());
        rippled_reference.insert(offer_key.0, offer.to_sle_binary());

        let out = collect_reference_enrichment_keys(
            &HashSet::new(),
            &rippled_reference,
            &HashSet::new(),
            &HashSet::new(),
            16,
        );
        let out: HashSet<[u8; 32]> = out.into_iter().collect();
        assert!(out.contains(&owner_root.0));
        assert!(out.contains(&crate::ledger::account::shamap_key(&owner).0));
        assert!(out.contains(&crate::ledger::Key(offer.book_directory).0));
        assert!(out.contains(&crate::ledger::directory::page_key(&offer.book_directory, 9).0));
        assert!(out.contains(&[0x55; 32]));
        assert!(out.contains(&owner_member));
    }

    #[test]
    fn reference_enrichment_owner_root_can_seed_first_chain_page() {
        let owner = [0x12; 20];
        let owner_root = crate::ledger::directory::owner_dir_key(&owner);
        let next_page = crate::ledger::directory::page_key(&owner_root.0, 8);
        let root = crate::ledger::directory::DirectoryNode {
            key: owner_root.0,
            root_index: owner_root.0,
            indexes: vec![],
            index_next: 8,
            index_previous: 8,
            owner: Some(owner),
            exchange_rate: None,
            taker_pays_currency: None,
            taker_pays_issuer: None,
            taker_gets_currency: None,
            taker_gets_issuer: None,
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: true,
            has_index_previous: true,
            raw_sle: None,
        };

        let mut rippled_reference = HashMap::new();
        rippled_reference.insert(owner_root.0, root.to_sle_binary());

        let out = collect_reference_enrichment_keys(
            &HashSet::new(),
            &rippled_reference,
            &HashSet::new(),
            &HashSet::new(),
            4,
        );
        let out: HashSet<[u8; 32]> = out.into_iter().collect();

        assert!(out.contains(&next_page.0));
    }

    #[test]
    fn reference_enrichment_includes_transitive_ripplestate_owner_scope() {
        let low = [0x21; 20];
        let high = [0x22; 20];
        let low_root = crate::ledger::directory::owner_dir_key(&low);
        let high_root = crate::ledger::directory::owner_dir_key(&high);
        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let line = crate::ledger::trustline::RippleState {
            low_account: low,
            high_account: high,
            currency: usd,
            balance: crate::transaction::amount::IouValue::ZERO,
            low_limit: crate::transaction::amount::IouValue::from_f64(1.0),
            high_limit: crate::transaction::amount::IouValue::from_f64(1.0),
            flags: 0,
            low_quality_in: 0,
            low_quality_out: 0,
            high_quality_in: 0,
            high_quality_out: 0,
            low_node: 3,
            high_node: 5,
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };

        let mut rippled_reference = HashMap::new();
        rippled_reference.insert(line.key().0, line.to_sle_binary());

        let out = collect_reference_enrichment_keys(
            &HashSet::new(),
            &rippled_reference,
            &HashSet::new(),
            &HashSet::new(),
            16,
        );
        let out: HashSet<[u8; 32]> = out.into_iter().collect();

        assert!(out.contains(&crate::ledger::account::shamap_key(&low).0));
        assert!(out.contains(&crate::ledger::account::shamap_key(&high).0));
        assert!(out.contains(&low_root.0));
        assert!(out.contains(&high_root.0));
        assert!(out.contains(&crate::ledger::directory::page_key(&low_root.0, 3).0));
        assert!(out.contains(&crate::ledger::directory::page_key(&high_root.0, 5).0));
    }

    #[test]
    fn reference_enrichment_includes_owner_directory_members() {
        let owner = [0x31; 20];
        let owner_root = crate::ledger::directory::owner_dir_key(&owner);
        let owner_page = crate::ledger::directory::page_key(&owner_root.0, 9);
        let offer = crate::ledger::offer::Offer {
            account: owner,
            sequence: 55,
            taker_pays: crate::transaction::amount::Amount::Xrp(10),
            taker_gets: crate::transaction::amount::Amount::Xrp(20),
            flags: 0,
            book_directory: {
                let mut key = [0x6A; 32];
                key[24..32].copy_from_slice(&11u64.to_be_bytes());
                key
            },
            book_node: 11,
            owner_node: 9,
            expiration: None,
            domain_id: None,
            additional_books: vec![],
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let dir = crate::ledger::directory::DirectoryNode {
            key: owner_page.0,
            root_index: owner_root.0,
            indexes: vec![offer.key().0],
            index_next: 0,
            index_previous: 0,
            owner: Some(owner),
            exchange_rate: None,
            taker_pays_currency: None,
            taker_pays_issuer: None,
            taker_gets_currency: None,
            taker_gets_issuer: None,
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };

        let mut rippled_reference = HashMap::new();
        rippled_reference.insert(owner_page.0, dir.to_sle_binary());

        let out = collect_reference_enrichment_keys(
            &HashSet::new(),
            &rippled_reference,
            &HashSet::new(),
            &HashSet::new(),
            16,
        );
        let out: HashSet<[u8; 32]> = out.into_iter().collect();

        assert!(out.contains(&offer.key().0));
    }

    #[test]
    fn reference_enrichment_expands_initially_requested_sources() {
        let owner = [0x3A; 20];
        let owner_root = crate::ledger::directory::owner_dir_key(&owner);
        let owner_page = crate::ledger::directory::page_key(&owner_root.0, 12);
        let offer = crate::ledger::offer::Offer {
            account: owner,
            sequence: 88,
            taker_pays: crate::transaction::amount::Amount::Xrp(10),
            taker_gets: crate::transaction::amount::Amount::Xrp(20),
            flags: 0,
            book_directory: {
                let mut key = [0x7D; 32];
                key[24..32].copy_from_slice(&13u64.to_be_bytes());
                key
            },
            book_node: 13,
            owner_node: 12,
            expiration: None,
            domain_id: None,
            additional_books: vec![],
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let dir = crate::ledger::directory::DirectoryNode {
            key: owner_page.0,
            root_index: owner_root.0,
            indexes: vec![offer.key().0],
            index_next: 0,
            index_previous: 0,
            owner: Some(owner),
            exchange_rate: None,
            taker_pays_currency: None,
            taker_pays_issuer: None,
            taker_gets_currency: None,
            taker_gets_issuer: None,
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };

        let mut rippled_reference = HashMap::new();
        rippled_reference.insert(owner_page.0, dir.to_sle_binary());
        rippled_reference.insert(offer.key().0, offer.to_sle_binary());
        let requested = HashSet::from([owner_page.0, offer.key().0]);

        let out = collect_reference_enrichment_keys(
            &requested,
            &rippled_reference,
            &HashSet::new(),
            &HashSet::new(),
            16,
        );
        let out: HashSet<[u8; 32]> = out.into_iter().collect();

        assert!(out.contains(&crate::ledger::account::shamap_key(&owner).0));
        assert!(out.contains(&owner_root.0));
        assert!(out.contains(&offer.book_directory));
    }

    #[test]
    fn reference_enrichment_prioritizes_owner_directory_members_over_chain_neighbors() {
        let owner = [0x41; 20];
        let owner_root = crate::ledger::directory::owner_dir_key(&owner);
        let owner_page = crate::ledger::directory::page_key(&owner_root.0, 4);
        let next_page = crate::ledger::directory::page_key(&owner_root.0, 5);
        let offer = crate::ledger::offer::Offer {
            account: owner,
            sequence: 66,
            taker_pays: crate::transaction::amount::Amount::Xrp(10),
            taker_gets: crate::transaction::amount::Amount::Xrp(20),
            flags: 0,
            book_directory: {
                let mut key = [0x6C; 32];
                key[24..32].copy_from_slice(&17u64.to_be_bytes());
                key
            },
            book_node: 17,
            owner_node: 4,
            expiration: None,
            domain_id: None,
            additional_books: vec![],
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let dir = crate::ledger::directory::DirectoryNode {
            key: owner_page.0,
            root_index: owner_root.0,
            indexes: vec![offer.key().0],
            index_next: 5,
            index_previous: 0,
            owner: Some(owner),
            exchange_rate: None,
            taker_pays_currency: None,
            taker_pays_issuer: None,
            taker_gets_currency: None,
            taker_gets_issuer: None,
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: true,
            has_index_previous: false,
            raw_sle: None,
        };

        let mut rippled_reference = HashMap::new();
        rippled_reference.insert(owner_page.0, dir.to_sle_binary());

        let out = collect_reference_enrichment_keys(
            &HashSet::new(),
            &rippled_reference,
            &HashSet::new(),
            &HashSet::new(),
            1,
        );

        assert_eq!(out, vec![offer.key().0]);
        assert!(!out.contains(&next_page.0));
    }

    #[test]
    fn reference_enrichment_prioritizes_hop_scope_over_chain_neighbors() {
        let owner = [0x51; 20];
        let owner_root = crate::ledger::directory::owner_dir_key(&owner);
        let owner_page = crate::ledger::directory::page_key(&owner_root.0, 6);
        let next_page = crate::ledger::directory::page_key(&owner_root.0, 7);
        let offer = crate::ledger::offer::Offer {
            account: owner,
            sequence: 77,
            taker_pays: crate::transaction::amount::Amount::Xrp(10),
            taker_gets: crate::transaction::amount::Amount::Xrp(20),
            flags: 0,
            book_directory: {
                let mut key = [0x7C; 32];
                key[24..32].copy_from_slice(&3u64.to_be_bytes());
                key
            },
            book_node: 3,
            owner_node: 6,
            expiration: None,
            domain_id: None,
            additional_books: vec![],
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let dir = crate::ledger::directory::DirectoryNode {
            key: owner_page.0,
            root_index: owner_root.0,
            indexes: vec![offer.key().0],
            index_next: 7,
            index_previous: 0,
            owner: Some(owner),
            exchange_rate: None,
            taker_pays_currency: None,
            taker_pays_issuer: None,
            taker_gets_currency: None,
            taker_gets_issuer: None,
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: true,
            has_index_previous: false,
            raw_sle: None,
        };

        let mut rippled_reference = HashMap::new();
        rippled_reference.insert(owner_page.0, dir.to_sle_binary());
        rippled_reference.insert(offer.key().0, offer.to_sle_binary());

        let out = collect_reference_enrichment_keys(
            &HashSet::new(),
            &rippled_reference,
            &HashSet::new(),
            &HashSet::new(),
            2,
        );

        assert_eq!(out.len(), 2);
        assert!(!out.contains(&next_page.0));
    }

    #[test]
    fn direct_edge_closure_skips_owner_directory_chain_neighbors() {
        let owner = [0x61; 20];
        let owner_root = crate::ledger::directory::owner_dir_key(&owner);
        let mut owner_page =
            crate::ledger::directory::DirectoryNode::new_page(&owner_root.0, 1, Some(owner));
        owner_page.index_next = 2;

        let book = crate::ledger::offer::BookKey {
            pays_currency: [0x71; 20],
            pays_issuer: [0x72; 20],
            gets_currency: [0x73; 20],
            gets_issuer: [0x74; 20],
        };
        let mut book_root = crate::ledger::directory::DirectoryNode::new_book_root(&book, 9);
        book_root.index_next = 3;

        let owner_next = crate::ledger::directory::page_key(&owner_root.0, 2).0;
        let book_next = crate::ledger::directory::page_key(&book_root.root_index, 3).0;

        let mut rippled_reference = HashMap::new();
        rippled_reference.insert(
            owner_root.0,
            crate::ledger::DirectoryNode::new_owner_root(&owner).to_sle_binary(),
        );
        rippled_reference.insert(owner_page.key, owner_page.to_sle_binary());
        rippled_reference.insert(book_root.key, book_root.to_sle_binary());

        let out = collect_direct_missing_reference_targets(
            &rippled_reference,
            &[],
            &HashSet::new(),
            &HashSet::new(),
            8,
        );
        let out: HashSet<[u8; 32]> = out.into_iter().collect();

        assert!(!out.contains(&owner_next));
        assert!(out.contains(&book_next));
    }
}
