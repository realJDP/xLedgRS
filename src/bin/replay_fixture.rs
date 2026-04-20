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

use clap::Parser;
use tracing::{error, info, warn};

use xrpl::ledger::close::replay_ledger;
use xrpl::ledger::forensic::loader;
use xrpl::ledger::{Key, LedgerState};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Path to a forensic bundle directory produced by the follower.
    #[arg(long)]
    bundle: PathBuf,
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
    (field.data.len() >= 32).then(|| field.data[..32].try_into().ok()).flatten()
}

fn parsed_account(
    fields: &[xrpl::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<[u8; 20]> {
    let field = fields
        .iter()
        .find(|field| field.type_code == type_code && field.field_code == field_code)?;
    (field.data.len() >= 20).then(|| field.data[..20].try_into().ok()).flatten()
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

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let args = Args::parse();
    let dir = &args.bundle;
    info!("loading bundle from {:?}", dir);

    let artifact = loader::load_artifact(dir)?;
    let anchor_header = loader::load_anchor_header(dir)?;
    let validated_header = loader::load_validated_header(dir)?;
    let tx_blobs = loader::load_tx_blobs(dir)?;
    let mut prestate = loader::load_prestate(dir)?;
    let rippled_reference = loader::load_rippled_reference(dir).unwrap_or_default();
    backfill_skip_prestate(&mut prestate, &rippled_reference, anchor_header.sequence);

    info!(
        "bundle anchor_seq={} mismatch_seq={} tx_count={} prestate_keys={} rippled_ref_keys={} rippled_ref_fetched={}",
        artifact.anchor_seq,
        artifact.mismatch_seq,
        tx_blobs.len(),
        prestate.len(),
        rippled_reference.len(),
        artifact.rippled_reference_fetched,
    );

    let mut state = LedgerState::new();
    for (k, bytes) in &prestate {
        state.insert_raw(Key(*k), bytes.clone());
    }
    info!("seeded {} keys into fresh LedgerState", prestate.len());

    let result = replay_ledger(
        &anchor_header,
        &mut state,
        tx_blobs.clone(),
        &validated_header,
        true,
    );

    info!(
        "replay: applied={} failed={} skipped={} touched_keys={} per_tx_attribution={}",
        result.applied_count,
        result.failed_count,
        result.skipped_count,
        result.touched_keys.len(),
        result.per_tx_attribution.len(),
    );

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

    if rippled_reference.is_empty() {
        warn!("rippled_reference.bin is empty — cannot locate first divergent key");
        warn!("re-capture the bundle with a live rippled endpoint configured");
        return Ok(());
    }

    // Walk all touched keys and compare them byte-for-byte against the
    // rippled reference bundle.
    let mut sorted: Vec<[u8; 32]> = result.touched_keys.iter().map(|k| k.0).collect();
    sorted.sort();

    let mut matched = 0usize;
    let mut divergent = 0usize;
    let mut not_in_reference = 0usize;
    let mut local_missing = 0usize;
    let mut not_in_ref_present = 0usize;
    let mut not_in_ref_deleted = 0usize;
    let mut not_in_ref_type_counts = std::collections::BTreeMap::<String, usize>::new();
    let mut not_in_ref_logged = 0usize;

    for k in &sorted {
        let local_bytes = state.get_raw_owned(&Key(*k));
        let expected_bytes = rippled_reference.get(k).cloned();
        if expected_bytes.is_none() {
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
                    if local_bytes.is_some() { "present" } else { "deleted" },
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
                attr.modified_keys.iter().any(|key| key == k) || attr.created_keys.iter().any(|key| key == k)
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
                        || extra.iter().any(|extra_key| &node.ledger_index == extra_key)
                        || missing.iter().any(|missing_key| &node.ledger_index == missing_key)
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
                        && !extra.iter().any(|extra_key| &node.ledger_index == extra_key)
                        && !missing.iter().any(|missing_key| &node.ledger_index == missing_key)
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
    for k in rippled_reference.keys() {
        if !touched_set.contains(k) {
            ref_only += 1;
            let expected = rippled_reference.get(k).cloned();
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
                            if sle.entry_type() == xrpl::ledger::sle::LedgerEntryType::DirectoryNode {
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
                                        let parsed = xrpl::transaction::parse::parse_blob(blob).ok();
                                        let mut tx_id_payload = Vec::with_capacity(4 + blob.len());
                                        tx_id_payload.extend_from_slice(
                                            &xrpl::transaction::serialize::PREFIX_TX_ID,
                                        );
                                        tx_id_payload.extend_from_slice(blob);
                                        let tx_id =
                                            xrpl::crypto::sha512_first_half(&tx_id_payload);
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
        "SUMMARY: touched={} matched={} divergent={} not_in_ref={} local_missing={} ref_only={}",
        sorted.len(),
        matched,
        divergent,
        not_in_reference,
        local_missing,
        ref_only,
    );
    if !not_in_ref_type_counts.is_empty() {
        info!(
            "NOT IN REF DETAIL: present={} deleted={} by_type={:?}",
            not_in_ref_present,
            not_in_ref_deleted,
            not_in_ref_type_counts,
        );
    }
    if ref_only_changed > 0 {
        info!(
            "REF-ONLY CHANGED DETAIL: count={} by_type={:?}",
            ref_only_changed,
            ref_only_type_counts,
        );
    }

    Ok(())
}
