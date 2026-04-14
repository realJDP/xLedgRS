//! Deterministic reproducer for Bug B (tfSell + tfImmediateOrCancel crossing
//! math divergence).
//!
//! Loads the captured forensic bundle for mainnet ledger 103483090, seeds a
//! fresh `LedgerState` with the pre-replay metadata-affected keys, and replays
//! only tx_idx=0 — an `OfferCreate` from account
//! `3200D97F878B3DB3252290FB8F9C9710AA369182` with flags `tfSell | tfIOC` and
//! 3 crossing candidates in the opposite book.
//!
//! The assertion is byte-exact against the rippled reference post-state for
//! the divergent RLUSD trust line (RippleState SLE, shamap key
//! `02E619195FA6D4F298FCE0EE851282604CAAB64A3B008A65811D2F8CA402FC83`).
//!
//! This test is a fixture reproducer. It depends on the forensic bundle at
//! `debug-runs/103483089-103483090-epoch1775952772/` being present on disk;
//! if the bundle is missing the test silently skips so it doesn't block CI on
//! fresh checkouts that haven't re-captured.
//!
//! Current expected state: FAILS with a Balance amount mismatch (Bug B not
//! yet fixed). Used to iterate on the fix.

use std::path::PathBuf;

use xrpl::ledger::close::replay_ledger;
use xrpl::ledger::forensic::loader;
use xrpl::ledger::{Key, LedgerState};

const BUNDLE_DIR: &str = "debug-runs/103483089-103483090-epoch1775952772";
const DIVERGENT_KEY_HEX: &str =
    "02E619195FA6D4F298FCE0EE851282604CAAB64A3B008A65811D2F8CA402FC83";

fn decode_key(hex_str: &str) -> [u8; 32] {
    let v = hex::decode(hex_str).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

#[test]
fn bug_b_tfsell_tx0_trust_line_matches_rippled() {
    let bundle = PathBuf::from(BUNDLE_DIR);
    if !bundle.exists() {
        eprintln!(
            "bundle not found at {:?} — skipping (re-capture required)",
            bundle,
        );
        return;
    }

    // Load bundle pieces
    let anchor_header = loader::load_anchor_header(&bundle).unwrap();
    let validated_header = loader::load_validated_header(&bundle).unwrap();
    let mut tx_blobs = loader::load_tx_blobs(&bundle).unwrap();
    let prestate = loader::load_prestate(&bundle).unwrap();
    let rippled_reference = loader::load_rippled_reference(&bundle).unwrap();

    // Keep only tx 0 — the target OfferCreate.
    assert!(!tx_blobs.is_empty(), "bundle must contain at least one tx");
    tx_blobs.truncate(1);

    // Seed a fresh LedgerState from the captured pre-replay state.
    let mut state = LedgerState::new();
    for (k, bytes) in &prestate {
        state.insert_raw(Key(*k), bytes.clone());
    }

    // Run replay_ledger with just tx 0.
    let result = replay_ledger(
        &anchor_header,
        &mut state,
        tx_blobs,
        &validated_header,
        true,
    );

    eprintln!(
        "tx0 replay: applied={} failed={} skipped={} touched_keys={}",
        result.applied_count,
        result.failed_count,
        result.skipped_count,
        result.touched_keys.len(),
    );

    // Check the divergent trust line.
    let div_key = Key(decode_key(DIVERGENT_KEY_HEX));
    let local = state
        .get_raw_owned(&div_key)
        .expect("trust line must exist post-replay");
    let expected = rippled_reference
        .get(&div_key.0)
        .cloned()
        .expect("rippled_reference.bin must contain this key");

    if local == expected {
        return; // PASS — Bug B fixed.
    }

    // Dump a byte-level comparison so the diff is visible on failure.
    eprintln!("DIVERGENT KEY: {}", DIVERGENT_KEY_HEX);
    eprintln!("  local    ({:>4}b): {}", local.len(), hex::encode_upper(&local));
    eprintln!("  rippled  ({:>4}b): {}", expected.len(), hex::encode_upper(&expected));
    let mlen = local.len().min(expected.len());
    for i in 0..mlen {
        if local[i] != expected[i] {
            eprintln!(
                "  first byte diff at offset {}: local=0x{:02X} rippled=0x{:02X}",
                i, local[i], expected[i],
            );
            break;
        }
    }

    panic!("Bug B tfSell crossing math — trust line post-state does not match rippled");
}
