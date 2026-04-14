//! Offline replay harness for engine-divergence debugging.
//!
//! Loads a forensic bundle produced by the follower's capture path and runs
//! `replay_ledger()` against the captured pre-state, tx blobs, and validated
//! header. Compares our computed `account_hash` against rippled's (from the
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

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let args = Args::parse();
    let dir = &args.bundle;
    info!("loading bundle from {:?}", dir);

    let artifact = loader::load_artifact(dir)?;
    let anchor_header = loader::load_anchor_header(dir)?;
    let validated_header = loader::load_validated_header(dir)?;
    let tx_blobs = loader::load_tx_blobs(dir)?;
    let prestate = loader::load_prestate(dir)?;
    let rippled_reference = loader::load_rippled_reference(dir).unwrap_or_default();

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

    // Walk ALL touched keys, byte-compare against rippled reference.
    let mut sorted: Vec<[u8; 32]> = result.touched_keys.iter().map(|k| k.0).collect();
    sorted.sort();

    let mut matched = 0usize;
    let mut divergent = 0usize;
    let mut not_in_reference = 0usize;
    let mut local_missing = 0usize;

    for k in &sorted {
        let local_bytes = state.get_raw_owned(&Key(*k));
        let expected_bytes = rippled_reference.get(k).cloned();
        if expected_bytes.is_none() {
            not_in_reference += 1;
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
        } else { 0 };
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
        let first_diff_pos = local.iter().zip(expected.iter())
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
            start, end,
            hex::encode_upper(&local[start..end]),
        );
        error!(
            "  expected[{}..{}]: {}",
            start, end,
            hex::encode_upper(&expected[start..end]),
        );
    }

    // Also check rippled reference keys not in touched set
    let touched_set: std::collections::HashSet<[u8; 32]> = sorted.iter().copied().collect();
    let mut ref_only = 0usize;
    for k in rippled_reference.keys() {
        if !touched_set.contains(k) {
            ref_only += 1;
        }
    }

    info!(
        "SUMMARY: touched={} matched={} divergent={} not_in_ref={} local_missing={} ref_only={}",
        sorted.len(), matched, divergent, not_in_reference, local_missing, ref_only,
    );

    Ok(())
}
