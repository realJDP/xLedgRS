//! Offline replay harness for engine-divergence debugging.
//!
//! Loads a forensic bundle produced by the follower's capture path and runs
//! `replay_ledger()` against the captured pre-state, tx blobs, and validated
//! header. Compares the computed `account_hash` against rippled's (from the
//! bundle) and, when they differ, walks the touched-key set in sorted order
//! against `rippled_reference.bin` to identify the first divergent key.
//!
//! Usage:
//!
//!   cargo run --bin replay_fixture -- --bundle <path-to-bundle-dir>

use std::path::PathBuf;
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
};

use clap::Parser;
use serde::Deserialize;
use tracing::{error, info, warn};

use xrpl::ledger::close::{
    apply_authoritative_validated_tx_metadata, replay_ledger_with_created_overrides,
};
use xrpl::ledger::follow::apply_metadata_patches_for_replay;
use xrpl::ledger::forensic::{collect_reference_enrichment_keys, fetch_rippled_reference, loader};
use xrpl::ledger::ter::ApplyFlags;
use xrpl::ledger::tx::{run_tx, TxContext};
use xrpl::ledger::{Key, LedgerState, ReplayResult};
use xrpl::transaction::parse::parse_blob;
use xrpl::transaction::{Amount, ParsedTx};

fn prestate_has_directory_previous_txn_fields(
    prestate: &std::collections::HashMap<[u8; 32], Vec<u8>>,
) -> bool {
    prestate.iter().any(|(key, bytes)| {
        bytes.len() >= 3
            && bytes[0] == 0x11
            && u16::from_be_bytes([bytes[1], bytes[2]]) == 0x0064
            && xrpl::ledger::DirectoryNode::decode(bytes, *key)
                .map(|dir| dir.previous_txn_id.is_some() || dir.previous_txn_lgr_seq.is_some())
                .unwrap_or(false)
    })
}

fn enable_replay_amendments(
    state: &mut LedgerState,
    prestate: &std::collections::HashMap<[u8; 32], Vec<u8>>,
) {
    for amendment in xrpl::ledger::read_amendments(state) {
        state.enable_amendment(amendment);
    }

    // Sparse forensic bundles may omit the Amendments singleton. If captured
    // DirectoryNodes already contain PreviousTxn fields, mirror the network
    // rule so raw-engine diagnostics do not manufacture false directory diffs.
    let fix_previous_txn_id = xrpl::crypto::sha512_first_half(b"fixPreviousTxnID");
    if !state.is_amendment_active(&fix_previous_txn_id)
        && prestate_has_directory_previous_txn_fields(prestate)
    {
        state.enable_amendment(fix_previous_txn_id);
        info!("inferred fixPreviousTxnID from captured DirectoryNode PreviousTxn fields");
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Path to a forensic bundle directory produced by the follower.
    #[arg(long)]
    bundle: PathBuf,

    /// Resolve the rippled reference live from public Clio/local rippled
    /// instead of relying only on rippled_reference.bin from the bundle.
    #[arg(long, default_value_t = false)]
    live_reference: bool,

    /// Local rippled host. Leave empty to use only public Clio fallback.
    #[arg(long, default_value = "")]
    rpc_host: String,

    /// Local rippled port. Set to 0 to skip the local host and use only public
    /// Clio fallback.
    #[arg(long, default_value_t = 0)]
    rpc_port: u16,

    /// Maximum number of enrichment keys to fetch beyond the initial
    /// metadata/prestate frontier when live rippled parity is enabled.
    #[arg(long, default_value_t = 256_000)]
    live_reference_budget: usize,

    /// Optional path to a JSONL dump of the full post-state after replay.
    /// Each line is one object with a stable key ordering.
    #[arg(long)]
    dump_post_state: Option<PathBuf>,

    /// Optional sorted JSONL full-state reference dump. When provided, replay
    /// comparisons use a streamed subset of this file for touched/metadata
    /// keys instead of relying only on the bundle reference.
    #[arg(long)]
    reference_jsonl: Option<PathBuf>,
}

struct ReplayStep {
    blob: Vec<u8>,
    tx_id: [u8; 32],
    tx_index: u32,
    nodes: Vec<xrpl::ledger::meta::AffectedNode>,
    meta_summary: xrpl::ledger::meta::MetadataSummary,
}

struct TxTouchRecord {
    tx_index: u32,
    tx_type: String,
    ter: String,
    touched_keys: Vec<Key>,
}

fn offer_create_metadata_looks_like_amm_crossing(
    nodes: &[xrpl::ledger::meta::AffectedNode],
) -> bool {
    !nodes
        .iter()
        .any(|node| matches!(node.entry_type, 0x0064 | 0x006f))
}

fn payment_metadata_looks_like_amm_self_swap(
    parsed: &ParsedTx,
    nodes: &[xrpl::ledger::meta::AffectedNode],
) -> bool {
    if parsed.tx_type != 0
        || parsed.destination != Some(parsed.account)
        || parsed.send_max.is_none()
        || nodes
            .iter()
            .any(|node| matches!(node.entry_type, 0x0064 | 0x006f))
    {
        return false;
    }

    let deliver = parsed
        .amount
        .as_ref()
        .cloned()
        .or_else(|| parsed.amount_drops.map(Amount::Xrp));
    match (deliver.as_ref(), parsed.send_max.as_ref()) {
        (Some(Amount::Xrp(_)), Some(Amount::Iou { .. }))
        | (Some(Amount::Iou { .. }), Some(Amount::Xrp(_))) => true,
        (
            Some(Amount::Iou {
                currency, issuer, ..
            }),
            Some(Amount::Iou {
                currency: send_max_currency,
                issuer: send_max_issuer,
                ..
            }),
        ) => currency != send_max_currency || issuer != send_max_issuer,
        _ => false,
    }
}

#[derive(Debug, Deserialize)]
struct ReferenceJsonLine {
    key: String,
    #[allow(dead_code)]
    entry_type: String,
    #[allow(dead_code)]
    len: usize,
    status: String,
    raw_hex: String,
}

fn seed_state_from_prestate(
    prestate: &std::collections::HashMap<[u8; 32], Vec<u8>>,
) -> LedgerState {
    let mut state = LedgerState::new();
    for (k, bytes) in prestate {
        state.insert_raw(Key(*k), bytes.clone());
    }
    enable_replay_amendments(&mut state, prestate);
    state
}

fn collect_post_state_keys(state: &LedgerState) -> std::collections::BTreeSet<Key> {
    let mut keys = std::collections::BTreeSet::new();
    keys.extend(state.iter_raw_entries().into_iter().map(|(key, _)| key));
    keys.extend(
        state
            .iter_accounts()
            .map(|(account_id, _)| xrpl::ledger::account::shamap_key(account_id)),
    );
    keys.extend(state.iter_trustlines().map(|(key, _)| *key));
    keys.extend(state.iter_checks().map(|(key, _)| *key));
    keys.extend(state.iter_deposit_preauths().map(|(key, _)| *key));
    keys.extend(state.iter_dids().map(|(key, _)| *key));
    keys.extend(state.iter_escrows().map(|(key, _)| *key));
    keys.extend(state.iter_paychans().map(|(key, _)| *key));
    keys.extend(state.iter_tickets().map(|(key, _)| *key));
    keys.extend(state.iter_nftokens().map(|(_, nft)| nft.shamap_key()));
    keys.extend(state.iter_nft_offers().map(|(key, _)| *key));
    keys.extend(state.iter_offers().map(|(key, _)| *key));
    keys.extend(state.iter_directories().map(|(key, _)| *key));
    keys
}

fn dump_full_post_state_jsonl(state: &LedgerState, path: &std::path::Path) -> anyhow::Result<()> {
    #[derive(serde::Serialize)]
    struct Entry<'a> {
        key: String,
        entry_type: String,
        len: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        raw_hex: Option<String>,
        status: &'a str,
    }

    let mut writer = BufWriter::new(File::create(path)?);
    let keys = collect_post_state_keys(state);
    for key in keys {
        let raw = state.get_raw_owned(&key);
        let entry_type = raw
            .as_deref()
            .and_then(|bytes| xrpl::ledger::sle::SLE::from_raw(key, bytes.to_vec()))
            .map(|sle| return_type_name(sle.entry_type()))
            .unwrap_or_else(|| "<missing>".to_string());
        let line = Entry {
            key: hex::encode_upper(key.0),
            entry_type,
            len: raw.as_ref().map(|bytes| bytes.len()).unwrap_or(0),
            raw_hex: raw.as_ref().map(hex::encode_upper),
            status: if raw.is_some() { "present" } else { "missing" },
        };
        writer.write_all(serde_json::to_string(&line)?.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

fn collect_reference_overlay_keys(
    result: &ReplayResult,
    metadata_affected_keys: &std::collections::HashSet<[u8; 32]>,
    prestate: &std::collections::HashMap<[u8; 32], Vec<u8>>,
) -> std::collections::BTreeSet<Key> {
    let mut keys = std::collections::BTreeSet::<Key>::new();
    keys.extend(result.touched_keys.iter().copied());
    keys.extend(metadata_affected_keys.iter().copied().map(Key));
    keys.extend(prestate.keys().copied().map(Key));
    for attr in &result.per_tx_attribution {
        keys.extend(attr.created_keys.iter().copied().map(Key));
        keys.extend(attr.modified_keys.iter().copied().map(Key));
    }
    keys
}

fn load_reference_subset_jsonl(
    path: &std::path::Path,
    keys: &std::collections::BTreeSet<Key>,
) -> anyhow::Result<std::collections::HashMap<[u8; 32], Vec<u8>>> {
    let wanted = keys
        .iter()
        .map(|key| (hex::encode_upper(key.0), key.0))
        .collect::<Vec<_>>();
    if wanted.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    let reader = BufReader::new(File::open(path)?);
    let mut lines = reader.lines();
    let mut cursor = 0usize;
    let mut found = std::collections::HashMap::<[u8; 32], Vec<u8>>::new();

    while cursor < wanted.len() {
        let Some(line) = lines.next() else {
            break;
        };
        let row: ReferenceJsonLine = serde_json::from_str(&line?)?;
        while cursor < wanted.len() && wanted[cursor].0 < row.key {
            cursor += 1;
        }
        if cursor >= wanted.len() {
            break;
        }
        if wanted[cursor].0 != row.key {
            continue;
        }
        if row.status == "present" {
            found.insert(wanted[cursor].1, hex::decode(&row.raw_hex)?);
        }
        cursor += 1;
    }

    Ok(found)
}

fn build_meta_with_hashes(tx_blobs: &[(Vec<u8>, Vec<u8>)]) -> Vec<([u8; 32], Vec<u8>)> {
    tx_blobs
        .iter()
        .map(|(tx, meta)| {
            let mut data = Vec::with_capacity(4 + tx.len());
            data.extend_from_slice(&xrpl::transaction::serialize::PREFIX_TX_ID);
            data.extend_from_slice(tx);
            let tx_hash = xrpl::crypto::sha512_first_half(&data);
            (tx_hash, meta.clone())
        })
        .collect()
}

fn build_replay_steps(tx_blobs: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<Vec<ReplayStep>> {
    let mut steps = Vec::with_capacity(tx_blobs.len());
    for (blob, meta) in tx_blobs {
        let tx_id = {
            let mut data = Vec::with_capacity(4 + blob.len());
            data.extend_from_slice(&xrpl::transaction::serialize::PREFIX_TX_ID);
            data.extend_from_slice(blob);
            xrpl::crypto::sha512_first_half(&data)
        };
        let (tx_index_opt, nodes) = xrpl::ledger::meta::parse_metadata_with_index(meta);
        let tx_index = tx_index_opt.ok_or_else(|| {
            anyhow::anyhow!(
                "tx {} missing sfTransactionIndex in metadata",
                hex::encode_upper(&tx_id[..4]),
            )
        })?;
        steps.push(ReplayStep {
            blob: blob.clone(),
            tx_id,
            tx_index,
            nodes,
            meta_summary: xrpl::ledger::meta::parse_metadata_summary(meta),
        });
    }
    steps.sort_by_key(|step| step.tx_index);
    Ok(steps)
}

async fn enrich_rippled_reference_from_live(
    rippled_reference: &mut std::collections::HashMap<[u8; 32], Vec<u8>>,
    prestate: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    metadata_affected_keys: &std::collections::HashSet<[u8; 32]>,
    ledger_seq: u32,
    rpc_host: &str,
    rpc_port: u16,
    max_budget: usize,
) -> anyhow::Result<()> {
    let mut initial_keys = std::collections::BTreeSet::new();
    initial_keys.extend(metadata_affected_keys.iter().copied());
    initial_keys.extend(prestate.keys().copied());
    let requested_keys: std::collections::HashSet<[u8; 32]> =
        initial_keys.iter().copied().collect();

    let mut missing_initial = Vec::new();
    for key in &initial_keys {
        if !rippled_reference.contains_key(key) {
            missing_initial.push(*key);
        }
    }

    let host = if rpc_host.is_empty() {
        "127.0.0.1"
    } else {
        rpc_host
    };
    let mut not_found = std::collections::HashSet::new();
    let mut unavailable = std::collections::HashSet::new();

    if !missing_initial.is_empty() {
        info!(
            "live rippled parity: fetching initial reference keys={} ledger_seq={} local_host={} local_port={}",
            missing_initial.len(),
            ledger_seq,
            host,
            rpc_port,
        );
        let (initial_map, initial_not_found, initial_unavailable) =
            fetch_rippled_reference(host, rpc_port, ledger_seq, &missing_initial).await?;
        rippled_reference.extend(initial_map);
        not_found.extend(initial_not_found);
        unavailable.extend(initial_unavailable);
    }

    let mut remaining_budget = max_budget;
    while remaining_budget > 0 {
        let extra_keys = collect_reference_enrichment_keys(
            &requested_keys,
            rippled_reference,
            &not_found,
            &unavailable,
            remaining_budget,
        );
        if extra_keys.is_empty() {
            break;
        }
        info!(
            "live rippled parity: enriching reference extra_keys={} remaining_budget={} ledger_seq={}",
            extra_keys.len(),
            remaining_budget,
            ledger_seq,
        );
        let (extra_map, extra_not_found, extra_unavailable) =
            fetch_rippled_reference(host, rpc_port, ledger_seq, &extra_keys).await?;
        if extra_map.is_empty() && extra_not_found.is_empty() && extra_unavailable.is_empty() {
            break;
        }
        remaining_budget = remaining_budget
            .saturating_sub(extra_map.len() + extra_not_found.len() + extra_unavailable.len());
        rippled_reference.extend(extra_map);
        not_found.extend(extra_not_found);
        unavailable.extend(extra_unavailable);
    }

    info!(
        "live rippled parity: final reference keys={} not_found={} unavailable={} ledger_seq={}",
        rippled_reference.len(),
        not_found.len(),
        unavailable.len(),
        ledger_seq,
    );

    Ok(())
}

fn log_prefix_divergence(
    step: &ReplayStep,
    parsed: &xrpl::transaction::parse::ParsedTx,
    phase: &str,
    local_touched: &[(Key, Option<Vec<u8>>)],
    authoritative_keys: &[Key],
    local_state: &LedgerState,
    authoritative_state: &LedgerState,
    ter_token: &str,
) {
    error!(
        "FIRST DIVERGENT TX: phase={} tx_index={} tx_id={} tx_type={} ter={}",
        phase,
        step.tx_index,
        hex::encode_upper(step.tx_id),
        parsed.tx_type,
        ter_token,
    );
    let mut keys = std::collections::BTreeSet::new();
    keys.extend(authoritative_keys.iter().copied());
    keys.extend(local_touched.iter().map(|(key, _)| *key));
    let mut detailed_logged = false;
    let mut summary_logged = 0usize;
    for key in keys {
        if summary_logged >= 40 && detailed_logged {
            break;
        }
        let local = local_state.get_raw_owned(&key);
        let authoritative = authoritative_state.get_raw_owned(&key);
        if local == authoritative {
            continue;
        }
        let type_name = object_class_name(key, local.as_deref().or(authoritative.as_deref()));
        if !detailed_logged {
            error!(
                "FIRST DIVERGENT OBJECT: key={} class={}",
                hex::encode_upper(key.0),
                type_name,
            );
            log_object_snapshot("local", key, local.as_deref());
            log_object_snapshot("authoritative", key, authoritative.as_deref());
            log_directory_index_delta(
                key,
                local.as_deref(),
                authoritative.as_deref(),
                local_state,
                authoritative_state,
            );
            detailed_logged = true;
        }
        if summary_logged >= 40 {
            continue;
        }
        error!(
            "  tx-key-diff key={} type={} local={} authoritative={}",
            hex::encode_upper(&key.0[..8]),
            type_name,
            local
                .as_ref()
                .map(|bytes| format!("len={}", bytes.len()))
                .unwrap_or_else(|| "deleted".into()),
            authoritative
                .as_ref()
                .map(|bytes| format!("len={}", bytes.len()))
                .unwrap_or_else(|| "deleted".into()),
        );
        summary_logged += 1;
    }
}

fn log_directory_index_delta(
    key: Key,
    local: Option<&[u8]>,
    authoritative: Option<&[u8]>,
    local_state: &LedgerState,
    authoritative_state: &LedgerState,
) {
    let (Some(local), Some(authoritative)) = (local, authoritative) else {
        return;
    };
    let Ok(local_dir) = xrpl::ledger::DirectoryNode::decode(local, key.0) else {
        return;
    };
    let Ok(authoritative_dir) = xrpl::ledger::DirectoryNode::decode(authoritative, key.0) else {
        return;
    };

    let local_set: std::collections::BTreeSet<[u8; 32]> =
        local_dir.indexes.iter().copied().collect();
    let authoritative_set: std::collections::BTreeSet<[u8; 32]> =
        authoritative_dir.indexes.iter().copied().collect();
    let extra: Vec<[u8; 32]> = local_set.difference(&authoritative_set).copied().collect();
    let missing: Vec<[u8; 32]> = authoritative_set.difference(&local_set).copied().collect();

    for extra_key in extra.iter().take(12) {
        let entry_key = Key(*extra_key);
        let local_raw = local_state.get_raw_owned(&entry_key);
        let authoritative_raw = authoritative_state.get_raw_owned(&entry_key);
        error!(
            "      directory local-extra index={} local_type={} authoritative_type={}",
            hex::encode_upper(extra_key),
            object_class_name(entry_key, local_raw.as_deref()),
            object_class_name(entry_key, authoritative_raw.as_deref()),
        );
        if let Some(raw) = local_raw.as_deref() {
            log_object_snapshot("local-extra-object", entry_key, Some(raw));
        }
    }
    for missing_key in missing.iter().take(12) {
        let entry_key = Key(*missing_key);
        let local_raw = local_state.get_raw_owned(&entry_key);
        let authoritative_raw = authoritative_state.get_raw_owned(&entry_key);
        error!(
            "      directory local-missing index={} local_type={} authoritative_type={}",
            hex::encode_upper(missing_key),
            object_class_name(entry_key, local_raw.as_deref()),
            object_class_name(entry_key, authoritative_raw.as_deref()),
        );
        if let Some(raw) = authoritative_raw.as_deref() {
            log_object_snapshot("authoritative-missing-object", entry_key, Some(raw));
        }
    }
}

fn tx_keys_differ(
    local_touched: &[(Key, Option<Vec<u8>>)],
    authoritative_keys: &[Key],
    local_state: &LedgerState,
    authoritative_state: &LedgerState,
) -> bool {
    let mut keys = std::collections::BTreeSet::new();
    keys.extend(authoritative_keys.iter().copied());
    keys.extend(local_touched.iter().map(|(key, _)| *key));
    keys.into_iter()
        .any(|key| local_state.get_raw_owned(&key) != authoritative_state.get_raw_owned(&key))
}

fn raw_preview(bytes: &[u8]) -> String {
    let preview_len = bytes.len().min(16);
    format!(
        "len={} head={}",
        bytes.len(),
        hex::encode_upper(&bytes[..preview_len])
    )
}

fn object_class_name(key: Key, raw: Option<&[u8]>) -> String {
    raw.and_then(|bytes| xrpl::ledger::sle::SLE::from_raw(key, bytes.to_vec()))
        .map(|sle| return_type_name(sle.entry_type()))
        .unwrap_or_else(|| "<deleted>".to_string())
}

fn log_object_snapshot(label: &str, key: Key, raw: Option<&[u8]>) {
    let Some(bytes) = raw else {
        error!("    {label}: deleted");
        return;
    };

    let class_name = object_class_name(key, Some(bytes));
    error!("    {label}: class={} {}", class_name, raw_preview(bytes));
    match class_name.as_str() {
        "AccountRoot" => {
            if let Ok(acct) = xrpl::ledger::account::AccountRoot::decode(bytes) {
                error!(
                    "      account={} balance={} sequence={} owner_count={} flags=0x{:08X} regular_key={} ticket_count={} prev_seq={}",
                    hex::encode_upper(acct.account_id),
                    acct.balance,
                    acct.sequence,
                    acct.owner_count,
                    acct.flags,
                    acct
                        .regular_key
                        .map(hex::encode_upper)
                        .unwrap_or_else(|| "<none>".into()),
                    acct.ticket_count,
                    acct.previous_txn_lgr_seq,
                );
            }
        }
        "RippleState" => {
            if let Some(tl) = xrpl::ledger::RippleState::decode(bytes) {
                error!(
                    "      low={} high={} currency={} balance={:?} low_limit={:?} high_limit={:?} flags=0x{:08X} low_node={} high_node={}",
                    hex::encode_upper(tl.low_account),
                    hex::encode_upper(tl.high_account),
                    hex::encode_upper(tl.currency.code),
                    tl.balance,
                    tl.low_limit,
                    tl.high_limit,
                    tl.flags,
                    tl.low_node,
                    tl.high_node,
                );
            }
        }
        "DirectoryNode" => {
            if let Ok(dir) = xrpl::ledger::DirectoryNode::decode(bytes, key.0) {
                error!(
                    "      root={} owner={} next={} prev={} indexes={}",
                    hex::encode_upper(dir.root_index),
                    dir.owner
                        .map(hex::encode_upper)
                        .unwrap_or_else(|| "<none>".into()),
                    dir.index_next,
                    dir.index_previous,
                    dir.indexes.len(),
                );
            }
        }
        "Offer" => {
            if let Some(offer) = xrpl::ledger::Offer::decode_from_sle(bytes) {
                error!(
                    "      account={} sequence={} flags=0x{:08X} book_directory={} book_node={} owner_node={}",
                    hex::encode_upper(offer.account),
                    offer.sequence,
                    offer.flags,
                    hex::encode_upper(offer.book_directory),
                    offer.book_node,
                    offer.owner_node,
                );
            }
        }
        "LedgerHashes" => {
            if let Some(sle) = xrpl::ledger::sle::SLE::from_raw(key, bytes.to_vec()) {
                let first_seq = sle
                    .get_field_u32(2, 26)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "<none>".into());
                let last_seq = sle
                    .get_field_u32(2, 27)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "<none>".into());
                let hashes_raw = sle
                    .get_field_vl(19, 2)
                    .or_else(|| sle.get_field_vl(19, 1))
                    .unwrap_or_default();
                let preview = hashes_raw
                    .chunks_exact(32)
                    .take(2)
                    .map(hex::encode_upper)
                    .collect::<Vec<_>>()
                    .join(",");
                let tail = hashes_raw
                    .chunks_exact(32)
                    .rev()
                    .take(2)
                    .map(hex::encode_upper)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(",");
                error!(
                    "      first_seq={} last_seq={} hashes={} preview=[{}] tail=[{}]",
                    first_seq,
                    last_seq,
                    hashes_raw.len() / 32,
                    preview,
                    tail,
                );
            }
        }
        _ => {}
    }
}

fn log_first_three_way_object_mismatch(
    records: &[TxTouchRecord],
    local_state: &LedgerState,
    authoritative_state: &LedgerState,
    rippled_reference: &std::collections::HashMap<[u8; 32], Vec<u8>>,
) {
    let report = |tx_index: Option<u32>, tx_type: Option<&str>, ter: Option<&str>, key: Key| {
        let local = local_state.get_raw_owned(&key);
        let authoritative = authoritative_state.get_raw_owned(&key);
        let reference = rippled_reference.get(&key.0).cloned();
        if local == authoritative && local.as_ref() == reference.as_ref() {
            return false;
        }

        let class_name = object_class_name(
            key,
            local
                .as_deref()
                .or(authoritative.as_deref())
                .or(reference.as_deref()),
        );
        let pair_tag = match (
            local.as_ref() == authoritative.as_ref(),
            local.as_ref() == reference.as_ref(),
            authoritative.as_ref() == reference.as_ref(),
        ) {
            (true, true, true) => "all_equal",
            (false, false, false) => "local!=auth!=ref",
            (false, true, false) => "local!=auth",
            (false, false, true) => "local!=ref",
            (true, false, false) => "auth!=ref",
            (true, true, false) => "auth!=ref",
            (true, false, true) => "local!=ref",
            (false, true, true) => "local!=auth",
        };

        error!(
            "FIRST OBJECT MISMATCH: tx_index={} tx_type={} ter={} key={} class={} pair={}",
            tx_index
                .map(|v| v.to_string())
                .unwrap_or_else(|| "<unknown>".into()),
            tx_type.unwrap_or("<unknown>"),
            ter.unwrap_or("<unknown>"),
            hex::encode_upper(key.0),
            class_name,
            pair_tag,
        );
        log_object_snapshot("local", key, local.as_deref());
        log_object_snapshot("authoritative", key, authoritative.as_deref());
        log_object_snapshot("rippled", key, reference.as_deref());
        true
    };

    for record in records {
        for key in &record.touched_keys {
            if report(
                Some(record.tx_index),
                Some(&record.tx_type),
                Some(&record.ter),
                *key,
            ) {
                return;
            }
        }
    }

    let mut all_keys = std::collections::BTreeSet::<Key>::new();
    all_keys.extend(
        local_state
            .iter_raw_entries()
            .into_iter()
            .map(|(key, _)| key),
    );
    all_keys.extend(
        authoritative_state
            .iter_raw_entries()
            .into_iter()
            .map(|(key, _)| key),
    );
    all_keys.extend(rippled_reference.keys().copied().map(Key));
    for key in all_keys {
        if report(None, None, None, key) {
            return;
        }
    }

    warn!("no 3-way object mismatch found after hash mismatch");
}

fn log_first_full_state_mismatch(
    result: &ReplayResult,
    local_state: &LedgerState,
    prestate: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    rippled_reference: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    include_reference_only: bool,
) -> bool {
    let mut all_keys = std::collections::BTreeSet::<Key>::new();
    if include_reference_only {
        all_keys.extend(rippled_reference.keys().copied().map(Key));
    } else {
        warn!(
            "sparse reference bundle: limiting full-state mismatch scan to captured prestate and touched keys"
        );
    }
    all_keys.extend(prestate.keys().copied().map(Key));
    all_keys.extend(result.touched_keys.iter().copied());

    for key in all_keys {
        let local = local_state.get_raw_owned(&key);
        let reference = rippled_reference.get(&key.0).cloned();
        if local.as_ref() == reference.as_ref() {
            continue;
        }

        let tx_attr = result.per_tx_attribution.iter().find(|attr| {
            attr.modified_keys
                .iter()
                .any(|candidate| candidate == &key.0)
                || attr
                    .created_keys
                    .iter()
                    .any(|candidate| candidate == &key.0)
        });
        let class_name = object_class_name(key, local.as_deref().or(reference.as_deref()));
        error!(
            "FULL STATE MISMATCH: tx_index={} tx_type={} ter={} key={} class={}",
            tx_attr
                .map(|attr| attr.tx_index.to_string())
                .unwrap_or_else(|| "<unknown>".into()),
            tx_attr
                .map(|attr| attr.tx_type.as_str())
                .unwrap_or("<unknown>"),
            tx_attr
                .map(|attr| attr.ter_token.as_str())
                .unwrap_or("<unknown>"),
            hex::encode_upper(key.0),
            class_name,
        );
        log_object_snapshot("local", key, local.as_deref());
        log_object_snapshot("rippled", key, reference.as_deref());
        return true;
    }

    warn!("no full-state object mismatch found after hash mismatch");
    false
}

fn log_missing_reference_provenance(
    rippled_reference: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    per_tx_attribution: &[xrpl::ledger::close::TxAttribution],
) {
    let edges = xrpl::ledger::forensic::collect_missing_reference_edges(
        rippled_reference,
        per_tx_attribution,
    );
    if edges.is_empty() {
        warn!("no unresolved direct reference edges found after hash mismatch");
        return;
    }

    let unique_targets = edges
        .iter()
        .map(|edge| edge.target_key)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    warn!(
        "unresolved direct reference edges after hash mismatch: edges={} unique_targets={}",
        edges.len(),
        unique_targets,
    );
    for edge in edges.iter().take(10) {
        error!(
            "MISSING REF EDGE: tx_index={} tx_type={} ter={} source={} source_class={} edge={} target={} target_class={}",
            edge.tx_index
                .map(|v| v.to_string())
                .unwrap_or_else(|| "<unknown>".into()),
            edge.tx_type.as_deref().unwrap_or("<unknown>"),
            edge.ter_token.as_deref().unwrap_or("<unknown>"),
            hex::encode_upper(edge.source_key),
            edge.source_class,
            edge.edge_label,
            hex::encode_upper(edge.target_key),
            edge.target_class,
        );
    }
}

fn scan_for_first_divergent_tx(
    anchor_header: &xrpl::ledger::LedgerHeader,
    validated_header: &xrpl::ledger::LedgerHeader,
    prestate: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    tx_blobs: &[(Vec<u8>, Vec<u8>)],
    _rippled_reference: &std::collections::HashMap<[u8; 32], Vec<u8>>,
) -> anyhow::Result<bool> {
    let steps = build_replay_steps(tx_blobs)?;
    let mut local_state = seed_state_from_prestate(prestate);
    let mut authoritative_state = seed_state_from_prestate(prestate);
    let mut masked_engine_divergences = 0usize;

    for (step_idx, step) in steps.iter().enumerate() {
        let parsed = parse_blob(&step.blob).map_err(|e| {
            anyhow::anyhow!(
                "parse_blob failed for tx {} at index {}: {:?}",
                hex::encode_upper(&step.tx_id[..4]),
                step.tx_index,
                e,
            )
        })?;
        if step_idx == 0 || (step_idx + 1) % 16 == 0 || step_idx + 1 == steps.len() {
            info!(
                "PREFIX SCAN PROGRESS: tx={} of {} tx_index={} tx_type={}",
                step_idx + 1,
                steps.len(),
                step.tx_index,
                parsed.tx_type,
            );
        }
        let replay_ctx = TxContext {
            validated_result: step.meta_summary.result,
            validated_delivered_amount: step.meta_summary.delivered_amount.clone(),
            validated_offer_create_amm_bridge: parsed.tx_type == 7
                && offer_create_metadata_looks_like_amm_crossing(&step.nodes),
            validated_payment_amm_self_swap_bridge: step.meta_summary.result
                == Some(xrpl::ledger::ter::TES_SUCCESS)
                && payment_metadata_looks_like_amm_self_swap(&parsed, &step.nodes),
            ..TxContext::from_parent(anchor_header, validated_header.close_time)
        };
        let local_result = run_tx(
            &mut local_state,
            &parsed,
            &replay_ctx,
            ApplyFlags::VALIDATED_REPLAY,
        );
        let local_touched = local_result.touched.clone();
        if local_result.applied {
            xrpl::ledger::close::stamp_touched_previous_fields(
                &mut local_state,
                &local_touched,
                &step.tx_id,
                validated_header.sequence,
            );
        }
        let authoritative_keys = apply_authoritative_validated_tx_metadata(
            &mut authoritative_state,
            &step.tx_id,
            validated_header.sequence,
            &step.nodes,
            &[],
        );
        let pure_engine_differs = tx_keys_differ(
            &local_touched,
            &authoritative_keys,
            &local_state,
            &authoritative_state,
        );
        let mut masked_by_reconcile = false;
        if pure_engine_differs {
            let logged_pre_reconcile = masked_engine_divergences < 4;
            if logged_pre_reconcile {
                error!(
                    "PREFIX ENGINE OBJECT MISMATCH: tx_index={} tx_id={} masked_by_reconcile=<pending>",
                    step.tx_index,
                    hex::encode_upper(step.tx_id),
                );
                log_prefix_divergence(
                    step,
                    &parsed,
                    "engine",
                    &local_touched,
                    &authoritative_keys,
                    &local_state,
                    &authoritative_state,
                    local_result.ter.token(),
                );
            }
            local_state.begin_tx();
            let _ = apply_authoritative_validated_tx_metadata(
                &mut local_state,
                &step.tx_id,
                validated_header.sequence,
                &step.nodes,
                &local_touched,
            );
            let probe_reconciled_differs = tx_keys_differ(
                &local_touched,
                &authoritative_keys,
                &local_state,
                &authoritative_state,
            );
            masked_by_reconcile = !probe_reconciled_differs;
            local_state.discard_tx();

            if !masked_by_reconcile && !logged_pre_reconcile {
                error!(
                    "PREFIX ENGINE OBJECT MISMATCH: tx_index={} tx_id={} masked_by_reconcile={}",
                    step.tx_index,
                    hex::encode_upper(step.tx_id),
                    masked_by_reconcile,
                );
                log_prefix_divergence(
                    step,
                    &parsed,
                    "engine",
                    &local_touched,
                    &authoritative_keys,
                    &local_state,
                    &authoritative_state,
                    local_result.ter.token(),
                );
            }
            if !masked_by_reconcile || logged_pre_reconcile {
                error!(
                    "POST-RECONCILE OBJECT DIFF: tx_index={} tx_id={} differs_after_reconcile={}",
                    step.tx_index,
                    hex::encode_upper(step.tx_id),
                    probe_reconciled_differs,
                );
            }
        }
        let _ = apply_authoritative_validated_tx_metadata(
            &mut local_state,
            &step.tx_id,
            validated_header.sequence,
            &step.nodes,
            &local_touched,
        );
        let reconciled_differs = tx_keys_differ(
            &local_touched,
            &authoritative_keys,
            &local_state,
            &authoritative_state,
        );
        if masked_by_reconcile && !reconciled_differs {
            masked_engine_divergences += 1;
            continue;
        }
        if reconciled_differs {
            error!(
                "PREFIX RECONCILED OBJECT MISMATCH: tx_index={} tx_id={}",
                step.tx_index,
                hex::encode_upper(step.tx_id),
            );
            log_prefix_divergence(
                step,
                &parsed,
                "reconciled",
                &local_touched,
                &authoritative_keys,
                &local_state,
                &authoritative_state,
                local_result.ter.token(),
            );
            return Ok(true);
        }
    }

    info!(
        "PREFIX SCAN: no per-tx divergence between local replay and metadata-only authoritative state across {} transactions",
        steps.len(),
    );
    let _ = anchor_header;
    Ok(false)
}

fn parse_skip_hashes(sle: &xrpl::ledger::sle::SLE) -> Vec<[u8; 32]> {
    let Some(raw) = sle.get_field_vl(19, 2).or_else(|| sle.get_field_vl(19, 1)) else {
        return Vec::new();
    };
    raw.chunks_exact(32)
        .filter_map(|chunk| chunk.try_into().ok())
        .collect()
}

fn parsed_u64(
    fields: &[xrpl::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<u64> {
    let field = fields
        .iter()
        .find(|field| field.type_code == type_code && field.field_code == field_code)?;
    if field.data.len() < 8 {
        return None;
    }
    Some(u64::from_be_bytes(field.data[..8].try_into().ok()?))
}

fn parsed_hash256(
    fields: &[xrpl::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<[u8; 32]> {
    let field = fields
        .iter()
        .find(|field| field.type_code == type_code && field.field_code == field_code)?;
    (field.data.len() >= 32)
        .then(|| field.data[..32].try_into().ok())
        .flatten()
}

fn parsed_account(
    fields: &[xrpl::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<[u8; 20]> {
    let field = fields
        .iter()
        .find(|field| field.type_code == type_code && field.field_code == field_code)?;
    (field.data.len() >= 20)
        .then(|| field.data[..20].try_into().ok())
        .flatten()
}

fn parsed_amount_issuer(
    fields: &[xrpl::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<[u8; 20]> {
    let field = fields
        .iter()
        .find(|field| field.type_code == type_code && field.field_code == field_code)?;
    (field.data.len() >= 48)
        .then(|| field.data[28..48].try_into().ok())
        .flatten()
}

fn build_skip_sle(
    key: Key,
    first_ledger_sequence: Option<u32>,
    last_seq: u32,
    hashes: &[[u8; 32]],
) -> Vec<u8> {
    let mut sle = xrpl::ledger::sle::SLE::new(
        key,
        xrpl::ledger::sle::LedgerEntryType::LedgerHashes,
        vec![0x11, 0x00, 0x68],
    );
    sle.set_flags(0);
    if let Some(first_seq) = first_ledger_sequence {
        sle.set_field_u32(2, 26, first_seq);
    }
    sle.set_field_u32(2, 27, last_seq);
    let mut hashes_raw = Vec::with_capacity(hashes.len() * 32);
    for hash in hashes {
        hashes_raw.extend_from_slice(hash);
    }
    sle.set_field_raw_pub(19, 2, &hashes_raw);
    sle.into_data()
}

fn backfill_skip_prestate(
    prestate: &mut std::collections::HashMap<[u8; 32], Vec<u8>>,
    rippled_reference: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    parent_seq: u32,
) {
    let mut maybe_backfill = |key: Key| {
        if prestate.contains_key(&key.0) {
            return;
        }
        let Some(post_raw) = rippled_reference.get(&key.0).cloned() else {
            return;
        };
        let Some(post_sle) = xrpl::ledger::sle::SLE::from_raw(key, post_raw) else {
            return;
        };
        let mut hashes = parse_skip_hashes(&post_sle);
        if hashes.pop().is_none() {
            return;
        }
        let last_seq = post_sle.get_field_u32(2, 27).unwrap_or(parent_seq);
        let prestate_raw = build_skip_sle(
            key,
            post_sle.get_field_u32(2, 26),
            last_seq.saturating_sub(1),
            &hashes,
        );
        prestate.insert(key.0, prestate_raw);
    };

    maybe_backfill(xrpl::ledger::keylet::skip().key);
    if (parent_seq & 0xFF) == 0 && parent_seq > 0 {
        maybe_backfill(xrpl::ledger::keylet::skip_for_ledger(parent_seq).key);
    }
}

fn backfill_unchanged_prestate_from_reference(
    prestate: &mut std::collections::HashMap<[u8; 32], Vec<u8>>,
    rippled_reference: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    mismatch_seq: u32,
    metadata_affected_keys: &std::collections::HashSet<[u8; 32]>,
) {
    fn entry_predates_mismatch(key: Key, raw: &[u8], mismatch_seq: u32) -> bool {
        let Some(post_sle) = xrpl::ledger::sle::SLE::from_raw(key, raw.to_vec()) else {
            return false;
        };
        if matches!(
            post_sle.entry_type(),
            xrpl::ledger::sle::LedgerEntryType::LedgerHashes
        ) {
            return false;
        }
        let Some(prev_seq) = post_sle.previous_txn_lgr_seq() else {
            return false;
        };
        prev_seq > 0 && prev_seq < mismatch_seq
    }

    for (key_bytes, post_raw) in rippled_reference {
        if prestate.contains_key(key_bytes) {
            continue;
        }
        let key = Key(*key_bytes);
        let Some(post_sle) = xrpl::ledger::sle::SLE::from_raw(key, post_raw.clone()) else {
            continue;
        };
        if matches!(
            post_sle.entry_type(),
            xrpl::ledger::sle::LedgerEntryType::LedgerHashes
        ) {
            continue;
        }
        if metadata_affected_keys.contains(key_bytes) {
            continue;
        }
        // For a single-ledger replay, any entry present in the authoritative
        // post-ledger state that was not touched by this ledger's metadata
        // must already have existed in the parent state. Seed it directly so
        // sparse forensic bundles don't misclassify untouched reference
        // neighborhoods as post-ledger diffs.
        if entry_predates_mismatch(key, post_raw, mismatch_seq)
            || !metadata_affected_keys.contains(key_bytes)
        {
            prestate.insert(*key_bytes, post_raw.clone());
        }
    }
}

fn collect_metadata_affected_keys(
    tx_blobs: &[(Vec<u8>, Vec<u8>)],
) -> std::collections::HashSet<[u8; 32]> {
    let mut keys = std::collections::HashSet::new();
    for (_, meta_blob) in tx_blobs {
        let nodes = match std::panic::catch_unwind(|| xrpl::ledger::meta::parse_metadata(meta_blob))
        {
            Ok(nodes) => nodes,
            Err(_) => continue,
        };
        for node in nodes {
            keys.insert(node.ledger_index);
        }
    }
    keys
}

fn return_type_name(entry_type: xrpl::ledger::sle::LedgerEntryType) -> String {
    match entry_type {
        xrpl::ledger::sle::LedgerEntryType::AccountRoot => "AccountRoot".to_string(),
        xrpl::ledger::sle::LedgerEntryType::DirectoryNode => "DirectoryNode".to_string(),
        xrpl::ledger::sle::LedgerEntryType::RippleState => "RippleState".to_string(),
        xrpl::ledger::sle::LedgerEntryType::Offer => "Offer".to_string(),
        xrpl::ledger::sle::LedgerEntryType::LedgerHashes => "LedgerHashes".to_string(),
        other => format!("{other:?}"),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt().init();

    let args = Args::parse();
    let dir = &args.bundle;
    info!("loading bundle from {:?}", dir);

    let anchor_header = loader::load_anchor_header(dir)?;
    let validated_header = loader::load_validated_header(dir)?;
    let tx_blobs = loader::load_tx_blobs(dir)?;
    let mut prestate = loader::load_prestate(dir)?;
    let captured_prestate_keys = prestate.len();
    let created_overrides = loader::load_created_overrides(dir).unwrap_or_default();
    let modified_overrides = loader::load_modified_overrides(dir).unwrap_or_default();
    let mut rippled_reference = loader::load_rippled_reference(dir).unwrap_or_default();
    let artifact = loader::load_artifact(dir).ok();
    let rippled_reference_fetched = artifact
        .as_ref()
        .map(|artifact| artifact.rippled_reference_fetched)
        .unwrap_or(!rippled_reference.is_empty());
    let metadata_affected_keys = collect_metadata_affected_keys(&tx_blobs);
    let has_authoritative_overrides =
        !created_overrides.is_empty() || !modified_overrides.is_empty();
    if args.live_reference {
        enrich_rippled_reference_from_live(
            &mut rippled_reference,
            &prestate,
            &metadata_affected_keys,
            validated_header.sequence,
            &args.rpc_host,
            args.rpc_port,
            args.live_reference_budget,
        )
        .await?;
    }
    if has_authoritative_overrides {
        info!(
            "bundle includes authoritative overrides; skipping legacy reference backfill to preserve captured prestate (captured_keys={})",
            captured_prestate_keys,
        );
    } else {
        backfill_skip_prestate(&mut prestate, &rippled_reference, anchor_header.sequence);
        backfill_unchanged_prestate_from_reference(
            &mut prestate,
            &rippled_reference,
            validated_header.sequence,
            &metadata_affected_keys,
        );
    }

    info!(
        "bundle anchor_seq={} mismatch_seq={} tx_count={} prestate_keys={} captured_prestate_keys={} rippled_ref_keys={} rippled_ref_fetched={}",
        artifact
            .as_ref()
            .map(|artifact| artifact.anchor_seq)
            .unwrap_or(anchor_header.sequence),
        artifact
            .as_ref()
            .map(|artifact| artifact.mismatch_seq)
            .unwrap_or(validated_header.sequence),
        tx_blobs.len(),
        prestate.len(),
        captured_prestate_keys,
        rippled_reference.len(),
        rippled_reference_fetched,
    );
    info!(
        "bundle authoritative overrides: created={} modified={}",
        created_overrides.len(),
        modified_overrides.len(),
    );

    let mut state = LedgerState::new();
    for (k, bytes) in &prestate {
        state.insert_raw(Key(*k), bytes.clone());
    }
    enable_replay_amendments(&mut state, &prestate);
    info!("seeded {} keys into fresh LedgerState", prestate.len());

    let meta_with_hashes = build_meta_with_hashes(&tx_blobs);
    let mut result = replay_ledger_with_created_overrides(
        &anchor_header,
        &mut state,
        tx_blobs.clone(),
        &validated_header,
        true,
        Some(&created_overrides),
    );
    let engine_actual = result.header.account_hash;
    if engine_actual != validated_header.account_hash {
        info!(
            "engine replay mismatch before metadata patches: local={} expected={} created_overrides={} modified_overrides={}",
            hex::encode_upper(&engine_actual[..16]),
            hex::encode_upper(&validated_header.account_hash[..16]),
            created_overrides.len(),
            modified_overrides.len(),
        );
        apply_metadata_patches_for_replay(
            &meta_with_hashes,
            validated_header.sequence,
            &created_overrides,
            &modified_overrides,
            &result.per_tx_local_touched,
            &mut state,
        );
        result.header.account_hash = state.state_hash();
    }

    info!(
        "replay: applied={} failed={} skipped={} touched_keys={} per_tx_attribution={}",
        result.applied_count,
        result.failed_count,
        result.skipped_count,
        result.touched_keys.len(),
        result.per_tx_attribution.len(),
    );

    if let Some(ref dump_path) = args.dump_post_state {
        dump_full_post_state_jsonl(&state, dump_path)?;
        info!("full post-state dump written: {}", dump_path.display());
    }

    let expected = validated_header.account_hash;
    let actual = result.header.account_hash;
    if expected == actual {
        info!(
            "HASH MATCH: local={} expected={}",
            hex::encode_upper(&actual[..16]),
            hex::encode_upper(&expected[..16]),
        );
        return Ok(());
    }

    error!(
        "HASH MISMATCH: local={} expected={}",
        hex::encode_upper(&actual[..16]),
        hex::encode_upper(&expected[..16]),
    );

    let mut comparison_reference = rippled_reference;
    if let Some(ref reference_jsonl) = args.reference_jsonl {
        let overlay_keys =
            collect_reference_overlay_keys(&result, &metadata_affected_keys, &prestate);
        let mut filtered = std::collections::HashMap::<[u8; 32], Vec<u8>>::new();
        for key in &overlay_keys {
            if let Some(bytes) = comparison_reference.get(&key.0) {
                filtered.insert(key.0, bytes.clone());
            }
        }
        let overlay = load_reference_subset_jsonl(reference_jsonl, &overlay_keys)?;
        let found = overlay.len();
        let requested = overlay_keys.len();
        filtered.extend(overlay);
        info!(
            "reference jsonl overlay: requested_keys={} found_keys={} missing_keys={} path={}",
            requested,
            found,
            requested.saturating_sub(found),
            reference_jsonl.display(),
        );
        comparison_reference = filtered;
    }

    if comparison_reference.is_empty() {
        warn!("rippled_reference.bin is empty — cannot locate first divergent key");
        warn!("re-capture the bundle with a live rippled endpoint configured");
        return Ok(());
    }

    // Walk all replay-touched and metadata-affected keys. The metadata union is
    // important for directory pages that are patched authoritatively rather
    // than visited by the local engine.
    let mut comparison_keys = std::collections::BTreeSet::<[u8; 32]>::new();
    comparison_keys.extend(result.touched_keys.iter().map(|k| k.0));
    comparison_keys.extend(metadata_affected_keys.iter().copied());
    comparison_keys.extend(created_overrides.keys().map(|key| key.0));
    comparison_keys.extend(modified_overrides.keys().map(|key| key.0));
    let sorted: Vec<[u8; 32]> = comparison_keys.into_iter().collect();

    let mut matched = 0usize;
    let mut matched_deleted = 0usize;
    let mut divergent = 0usize;
    let mut not_in_reference = 0usize;
    let mut local_missing = 0usize;
    let mut not_in_ref_present = 0usize;
    let mut not_in_ref_deleted = 0usize;
    let mut not_in_ref_type_counts = std::collections::BTreeMap::<String, usize>::new();
    let mut not_in_ref_logged = 0usize;

    for k in &sorted {
        let local_bytes = state.get_raw_owned(&Key(*k));
        let expected_bytes = comparison_reference.get(k).cloned();
        if expected_bytes.is_none() {
            if local_bytes.is_none() {
                matched += 1;
                matched_deleted += 1;
                continue;
            }
            not_in_reference += 1;
            let type_name = match local_bytes
                .as_ref()
                .and_then(|bytes| xrpl::ledger::sle::SLE::from_raw(Key(*k), bytes.clone()))
                .map(|sle| sle.entry_type())
            {
                Some(xrpl::ledger::sle::LedgerEntryType::AccountRoot) => "AccountRoot".to_string(),
                Some(xrpl::ledger::sle::LedgerEntryType::DirectoryNode) => {
                    "DirectoryNode".to_string()
                }
                Some(xrpl::ledger::sle::LedgerEntryType::RippleState) => "RippleState".to_string(),
                Some(xrpl::ledger::sle::LedgerEntryType::Offer) => "Offer".to_string(),
                Some(xrpl::ledger::sle::LedgerEntryType::LedgerHashes) => {
                    "LedgerHashes".to_string()
                }
                Some(other) => return_type_name(other),
                None => "<deleted>".to_string(),
            };
            *not_in_ref_type_counts.entry(type_name.clone()).or_insert(0) += 1;
            if local_bytes.is_some() {
                not_in_ref_present += 1;
            } else {
                not_in_ref_deleted += 1;
            }
            if not_in_ref_logged < 20 {
                error!(
                    "NOT IN REF #{}: key={} local_state={} type={}",
                    not_in_ref_logged + 1,
                    hex::encode_upper(&k[..8]),
                    if local_bytes.is_some() {
                        "present"
                    } else {
                        "deleted"
                    },
                    type_name,
                );
                for attr in result.per_tx_attribution.iter().filter(|attr| {
                    attr.modified_keys.iter().any(|key| key == k)
                        || attr.created_keys.iter().any(|key| key == k)
                }) {
                    error!(
                        "  touched by tx_index={} tx_type={} ter={}",
                        attr.tx_index, attr.tx_type, attr.ter_token
                    );
                }
                not_in_ref_logged += 1;
            }
            continue;
        }
        if local_bytes.is_none() {
            local_missing += 1;
            error!(
                "KEY MISSING LOCALLY: key={} expected_len={}",
                hex::encode_upper(&k[..8]),
                expected_bytes.as_ref().map(|b| b.len()).unwrap_or(0),
            );
            continue;
        }
        if local_bytes == expected_bytes {
            matched += 1;
            continue;
        }
        divergent += 1;
        let local = local_bytes.unwrap();
        let expected = expected_bytes.unwrap();
        // Determine SLE type from first 3 bytes
        let sle_type = if local.len() >= 3 && local[0] == 0x11 {
            u16::from_be_bytes([local[1], local[2]])
        } else {
            0
        };
        let type_name = match sle_type {
            0x0061 => "AccountRoot",
            0x0064 => "DirectoryNode",
            0x0072 => "RippleState",
            0x006F => "Offer",
            0x0075 => "Escrow",
            0x0078 => "PayChannel",
            0x0043 => "Check",
            0x0054 => "Ticket",
            0x0037 => "NFTokenOffer",
            0x0050 => "NFTokenPage",
            0x0049 => "DID",
            _ => "Unknown",
        };
        // Find first differing byte
        let first_diff_pos = local
            .iter()
            .zip(expected.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(local.len().min(expected.len()));
        error!(
            "DIVERGENT #{}: key={} type=0x{:04X}({}) len={}vs{} first_diff_byte={}",
            divergent,
            hex::encode_upper(&k[..8]),
            sle_type,
            type_name,
            local.len(),
            expected.len(),
            first_diff_pos,
        );
        // Show the differing region
        let start = first_diff_pos.saturating_sub(4);
        let end = (first_diff_pos + 12).min(local.len()).min(expected.len());
        error!(
            "  local   [{}..{}]: {}",
            start,
            end,
            hex::encode_upper(&local[start..end]),
        );
        error!(
            "  expected[{}..{}]: {}",
            start,
            end,
            hex::encode_upper(&expected[start..end]),
        );
        if sle_type == 0x0064 {
            let local_dir = xrpl::ledger::DirectoryNode::decode(&local, *k)
                .map_err(|e| anyhow::anyhow!("local directory decode failed: {:?}", e))?;
            let expected_dir = xrpl::ledger::DirectoryNode::decode(&expected, *k)
                .map_err(|e| anyhow::anyhow!("expected directory decode failed: {:?}", e))?;
            let local_set: std::collections::BTreeSet<[u8; 32]> =
                local_dir.indexes.iter().copied().collect();
            let expected_set: std::collections::BTreeSet<[u8; 32]> =
                expected_dir.indexes.iter().copied().collect();
            let extra: Vec<[u8; 32]> = local_set.difference(&expected_set).copied().collect();
            let missing: Vec<[u8; 32]> = expected_set.difference(&local_set).copied().collect();
            error!(
                "  directory root={} owner={} local_indexes={} expected_indexes={} local_next={} expected_next={} local_prev={} expected_prev={}",
                hex::encode_upper(local_dir.root_index),
                local_dir
                    .owner
                    .map(hex::encode_upper)
                    .unwrap_or_else(|| "<none>".into()),
                local_dir.indexes.len(),
                expected_dir.indexes.len(),
                local_dir.index_next,
                expected_dir.index_next,
                local_dir.index_previous,
                expected_dir.index_previous,
            );
            for key in extra.iter().take(8) {
                error!("  directory extra index: {}", hex::encode_upper(key));
            }
            for key in missing.iter().take(8) {
                error!("  directory missing index: {}", hex::encode_upper(key));
            }
            for attr in result.per_tx_attribution.iter().filter(|attr| {
                attr.modified_keys.iter().any(|key| key == k)
                    || attr.created_keys.iter().any(|key| key == k)
            }) {
                error!(
                    "  touched by tx_index={} tx_type={} ter={}",
                    attr.tx_index, attr.tx_type, attr.ter_token
                );
            }
            for (blob, meta) in &tx_blobs {
                let mut tx_id_payload = Vec::with_capacity(4 + blob.len());
                tx_id_payload.extend_from_slice(&xrpl::transaction::serialize::PREFIX_TX_ID);
                tx_id_payload.extend_from_slice(blob);
                let tx_id = xrpl::crypto::sha512_first_half(&tx_id_payload);
                let (tx_index, nodes) = xrpl::ledger::meta::parse_metadata_with_index(meta);
                if !nodes.iter().any(|node| {
                    &node.ledger_index == k
                        || extra
                            .iter()
                            .any(|extra_key| &node.ledger_index == extra_key)
                        || missing
                            .iter()
                            .any(|missing_key| &node.ledger_index == missing_key)
                }) {
                    continue;
                }
                error!(
                    "  metadata tx_index={} tx_id={}",
                    tx_index.unwrap_or(u32::MAX),
                    hex::encode_upper(tx_id),
                );
                for node in &nodes {
                    if &node.ledger_index != k
                        && !extra
                            .iter()
                            .any(|extra_key| &node.ledger_index == extra_key)
                        && !missing
                            .iter()
                            .any(|missing_key| &node.ledger_index == missing_key)
                    {
                        continue;
                    }
                    error!(
                        "    node action={:?} type=0x{:04X} key={} fields={} prev_fields={} has_indexes={}",
                        node.action,
                        node.entry_type,
                        hex::encode_upper(node.ledger_index),
                        node.fields.len(),
                        node.previous_fields.len(),
                        node.fields.iter().any(|field| field.type_code == 19 && field.field_code == 1),
                    );
                    if node.entry_type == 0x006f {
                        error!(
                            "      offer final owner_node={:?} book_node={:?} book_dir={} prev owner_node={:?} prev book_node={:?} prev book_dir={}",
                            parsed_u64(&node.fields, 3, 4),
                            parsed_u64(&node.fields, 3, 3),
                            parsed_hash256(&node.fields, 5, 16)
                                .map(hex::encode_upper)
                                .unwrap_or_else(|| "<none>".into()),
                            parsed_u64(&node.previous_fields, 3, 4),
                            parsed_u64(&node.previous_fields, 3, 3),
                            parsed_hash256(&node.previous_fields, 5, 16)
                                .map(hex::encode_upper)
                                .unwrap_or_else(|| "<none>".into()),
                        );
                    }
                    if node.entry_type == 0x0064 {
                        error!(
                            "      dir root={} owner={} index_next={:?} index_prev={:?}",
                            parsed_hash256(&node.fields, 5, 8)
                                .map(hex::encode_upper)
                                .unwrap_or_else(|| "<none>".into()),
                            parsed_account(&node.fields, 8, 2)
                                .map(hex::encode_upper)
                                .unwrap_or_else(|| "<none>".into()),
                            parsed_u64(&node.fields, 3, 1),
                            parsed_u64(&node.fields, 3, 2),
                        );
                    }
                }
            }
        }
    }

    // Also check rippled reference keys not in touched set
    let touched_set: std::collections::HashSet<[u8; 32]> = sorted.iter().copied().collect();
    let mut ref_only = 0usize;
    let mut ref_only_changed = 0usize;
    let mut ref_only_type_counts = std::collections::BTreeMap::<String, usize>::new();
    let mut ref_only_logged = 0usize;
    for k in comparison_reference.keys() {
        if !touched_set.contains(k) {
            ref_only += 1;
            let expected = comparison_reference.get(k).cloned();
            let pre = prestate.get(k).cloned();
            let changed = pre.as_ref() != expected.as_ref();
            if changed {
                ref_only_changed += 1;
                let type_name = expected
                    .as_ref()
                    .and_then(|bytes| xrpl::ledger::sle::SLE::from_raw(Key(*k), bytes.clone()))
                    .map(|sle| return_type_name(sle.entry_type()))
                    .unwrap_or_else(|| "<unknown>".to_string());
                *ref_only_type_counts.entry(type_name.clone()).or_insert(0) += 1;
                if ref_only_logged < 20 {
                    error!(
                        "REF-ONLY CHANGED #{}: key={} type={} prestate={} final_len={}",
                        ref_only_logged + 1,
                        hex::encode_upper(&k[..8]),
                        type_name,
                        if pre.is_some() { "present" } else { "missing" },
                        expected.as_ref().map(|b| b.len()).unwrap_or(0),
                    );
                    if let Some(raw) = expected.as_ref() {
                        if let Some(sle) = xrpl::ledger::sle::SLE::from_raw(Key(*k), raw.clone()) {
                            if sle.entry_type() == xrpl::ledger::sle::LedgerEntryType::DirectoryNode
                            {
                                if let Ok(dir) = xrpl::ledger::DirectoryNode::decode(raw, *k) {
                                    error!(
                                        "  directory root={} owner={} next={} prev={} indexes={}",
                                        hex::encode_upper(dir.root_index),
                                        dir.owner
                                            .map(hex::encode_upper)
                                            .unwrap_or_else(|| "<none>".into()),
                                        dir.index_next,
                                        dir.index_previous,
                                        dir.indexes.len(),
                                    );
                                    for (blob, meta) in &tx_blobs {
                                        let parsed =
                                            xrpl::transaction::parse::parse_blob(blob).ok();
                                        let mut tx_id_payload = Vec::with_capacity(4 + blob.len());
                                        tx_id_payload.extend_from_slice(
                                            &xrpl::transaction::serialize::PREFIX_TX_ID,
                                        );
                                        tx_id_payload.extend_from_slice(blob);
                                        let tx_id = xrpl::crypto::sha512_first_half(&tx_id_payload);
                                        let (tx_index, nodes) =
                                            xrpl::ledger::meta::parse_metadata_with_index(meta);
                                        let related = nodes.iter().any(|node| {
                                            (node.entry_type == 0x0064
                                                && (node.ledger_index == *k
                                                    || parsed_hash256(&node.fields, 5, 8)
                                                        == Some(dir.root_index)
                                                    || parsed_hash256(&node.previous_fields, 5, 8)
                                                        == Some(dir.root_index)
                                                    || parsed_account(&node.fields, 8, 2)
                                                        == dir.owner
                                                    || parsed_account(&node.previous_fields, 8, 2)
                                                        == dir.owner))
                                                || (node.entry_type == 0x006f
                                                    && parsed_account(&node.fields, 8, 1)
                                                        == dir.owner)
                                                || (node.entry_type == 0x0072
                                                    && (parsed_amount_issuer(&node.fields, 6, 6)
                                                        == dir.owner
                                                        || parsed_amount_issuer(
                                                            &node.fields,
                                                            6,
                                                            7,
                                                        ) == dir.owner
                                                        || parsed_amount_issuer(
                                                            &node.previous_fields,
                                                            6,
                                                            6,
                                                        ) == dir.owner
                                                        || parsed_amount_issuer(
                                                            &node.previous_fields,
                                                            6,
                                                            7,
                                                        ) == dir.owner))
                                        });
                                        if related {
                                            error!(
                                                "  related metadata tx_index={} tx_id={}",
                                                tx_index.unwrap_or(u32::MAX),
                                                hex::encode_upper(tx_id),
                                            );
                                            for node in nodes.iter().filter(|node| {
                                                (node.entry_type == 0x0064
                                                    && (node.ledger_index == *k
                                                        || parsed_hash256(&node.fields, 5, 8)
                                                            == Some(dir.root_index)
                                                        || parsed_hash256(
                                                            &node.previous_fields,
                                                            5,
                                                            8,
                                                        ) == Some(dir.root_index)
                                                        || parsed_account(&node.fields, 8, 2)
                                                            == dir.owner
                                                        || parsed_account(
                                                            &node.previous_fields,
                                                            8,
                                                            2,
                                                        ) == dir.owner))
                                                    || (node.entry_type == 0x006f
                                                        && parsed_account(&node.fields, 8, 1)
                                                            == dir.owner)
                                                    || (node.entry_type == 0x0072
                                                        && (parsed_amount_issuer(
                                                            &node.fields,
                                                            6,
                                                            6,
                                                        ) == dir.owner
                                                            || parsed_amount_issuer(
                                                                &node.fields,
                                                                6,
                                                                7,
                                                            ) == dir.owner
                                                            || parsed_amount_issuer(
                                                                &node.previous_fields,
                                                                6,
                                                                6,
                                                            ) == dir.owner
                                                            || parsed_amount_issuer(
                                                                &node.previous_fields,
                                                                6,
                                                                7,
                                                            ) == dir.owner))
                                            }) {
                                                error!(
                                                    "    node action={:?} type=0x{:04X} key={} root={} owner={} next={:?} prev={:?}",
                                                    node.action,
                                                    node.entry_type,
                                                    hex::encode_upper(node.ledger_index),
                                                    parsed_hash256(&node.fields, 5, 8)
                                                        .or_else(|| {
                                                            parsed_hash256(
                                                                &node.previous_fields,
                                                                5,
                                                                8,
                                                            )
                                                        })
                                                        .map(hex::encode_upper)
                                                        .unwrap_or_else(|| "<none>".into()),
                                                    parsed_account(&node.fields, 8, 2)
                                                        .or_else(|| {
                                                            parsed_account(
                                                                &node.previous_fields,
                                                                8,
                                                                2,
                                                            )
                                                        })
                                                        .map(hex::encode_upper)
                                                        .unwrap_or_else(|| "<none>".into()),
                                                    parsed_u64(&node.fields, 3, 1).or_else(|| {
                                                        parsed_u64(&node.previous_fields, 3, 1)
                                                    }),
                                                    parsed_u64(&node.fields, 3, 2).or_else(|| {
                                                        parsed_u64(&node.previous_fields, 3, 2)
                                                    }),
                                                );
                                            }
                                        }
                                        if parsed
                                            .as_ref()
                                            .map(|tx| tx.account == dir.owner.unwrap_or([0u8; 20]))
                                            .unwrap_or(false)
                                        {
                                            let tx = parsed.as_ref().unwrap();
                                            error!(
                                                "  owner account tx tx_index={} tx_id={} tx_type={} seq={}",
                                                tx_index.unwrap_or(u32::MAX),
                                                hex::encode_upper(tx_id),
                                                tx.tx_type,
                                                tx.sequence,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ref_only_logged += 1;
                }
            }
        }
    }

    info!(
        "SUMMARY: touched={} matched={} matched_deleted={} divergent={} not_in_ref={} local_missing={} ref_only={}",
        sorted.len(),
        matched,
        matched_deleted,
        divergent,
        not_in_reference,
        local_missing,
        ref_only,
    );
    if !not_in_ref_type_counts.is_empty() {
        info!(
            "NOT IN REF DETAIL: present={} deleted={} by_type={:?}",
            not_in_ref_present, not_in_ref_deleted, not_in_ref_type_counts,
        );
    }
    if ref_only_changed > 0 {
        info!(
            "REF-ONLY CHANGED DETAIL: count={} by_type={:?}",
            ref_only_changed, ref_only_type_counts,
        );
    }

    if scan_for_first_divergent_tx(
        &anchor_header,
        &validated_header,
        &prestate,
        &tx_blobs,
        &comparison_reference,
    )? {
        return Ok(());
    }

    let full_reference_available = args.reference_jsonl.is_some();
    if !full_reference_available && !rippled_reference_fetched {
        warn!(
            "rippled reference was captured as incomplete; ref-only gaps are capture/enrichment signals, not standalone TX-engine divergences"
        );
    }
    let found_full_state_mismatch = log_first_full_state_mismatch(
        &result,
        &state,
        &prestate,
        &comparison_reference,
        full_reference_available,
    );
    if !found_full_state_mismatch {
        log_missing_reference_provenance(&comparison_reference, &result.per_tx_attribution);
    }

    Ok(())
}
