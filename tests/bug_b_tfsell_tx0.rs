//! Deterministic reproducer for Bug B (tfSell + tfImmediateOrCancel crossing
//! math divergence).
//!
//! Loads an opt-in captured forensic bundle, seeds a fresh `LedgerState` with
//! the pre-replay metadata-affected keys, and replays only tx_idx=0 — an
//! `OfferCreate` from account
//! `3200D97F878B3DB3252290FB8F9C9710AA369182` with flags `tfSell | tfIOC` and
//! 3 crossing candidates in the opposite book.
//!
//! The assertion is byte-exact against the rippled reference post-state for
//! the divergent RLUSD trust line (RippleState SLE, shamap key
//! `02E619195FA6D4F298FCE0EE851282604CAAB64A3B008A65811D2F8CA402FC83`).
//!
//! Set `XLEDGRSV2BETA_BUG_B_FIXTURE` to the forensic bundle directory to run this
//! test. Without the env var, the test skips so fresh checkouts do not depend
//! on private capture data.

use std::path::PathBuf;

use xrpl::ledger::close::replay_ledger;
use xrpl::ledger::forensic::loader;
use xrpl::ledger::{Key, LedgerState};

const DIVERGENT_KEY_HEX: &str = "02E619195FA6D4F298FCE0EE851282604CAAB64A3B008A65811D2F8CA402FC83";

fn decode_key(hex_str: &str) -> [u8; 32] {
    let v = hex::decode(hex_str).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

#[test]
fn bug_b_tfsell_tx0_trust_line_matches_rippled() {
    let Some(bundle) = std::env::var_os("XLEDGRSV2BETA_BUG_B_FIXTURE").map(PathBuf::from) else {
        eprintln!("XLEDGRSV2BETA_BUG_B_FIXTURE not set — skipping forensic fixture test");
        return;
    };
    if !bundle.exists() {
        eprintln!(
            "bundle not found at {:?} — skipping (re-capture required)",
            bundle,
        );
        return;
    }

    // Load the captured bundle inputs.
    let anchor_header = loader::load_anchor_header(&bundle).unwrap();
    let validated_header = loader::load_validated_header(&bundle).unwrap();
    let mut tx_blobs = loader::load_tx_blobs(&bundle).unwrap();
    let prestate = loader::load_prestate(&bundle).unwrap();
    let rippled_reference = loader::load_rippled_reference(&bundle).unwrap();

    // Keep only transaction 0, which is the target OfferCreate.
    assert!(!tx_blobs.is_empty(), "bundle must contain at least one tx");
    tx_blobs.truncate(1);

    // Seed a fresh LedgerState from the captured pre-replay state.
    let mut state = LedgerState::new();
    for (k, bytes) in &prestate {
        state.insert_raw(Key(*k), bytes.clone());
    }

    // Replay only transaction 0.
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

    // Compare the divergent trust line against the rippled reference state.
    let div_key = Key(decode_key(DIVERGENT_KEY_HEX));
    let local = state
        .get_raw_owned(&div_key)
        .expect("trust line must exist post-replay");
    let expected = rippled_reference
        .get(&div_key.0)
        .cloned()
        .expect("rippled_reference.bin must contain this key");

    if local == expected {
        return;
    }

    // Emit a byte-level diff to preserve the failing post-state.
    eprintln!("DIVERGENT KEY: {}", DIVERGENT_KEY_HEX);
    eprintln!(
        "  local    ({:>4}b): {}",
        local.len(),
        hex::encode_upper(&local)
    );
    eprintln!(
        "  rippled  ({:>4}b): {}",
        expected.len(),
        hex::encode_upper(&expected)
    );
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
