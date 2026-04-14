//! Reproducer for Bug C: book directory retains extra entry after self-cross
//! offer removal. Replays txs 0..=25 from the forensic bundle and asserts
//! the book directory `036D7E923EF22B65...` matches rippled byte-exact.

use std::path::PathBuf;
use xrpl::ledger::close::replay_ledger;
use xrpl::ledger::forensic::loader;
use xrpl::ledger::{Key, LedgerState};

const BUNDLE_DIR: &str = "debug-runs/103483089-103483090-epoch1775955380";
const DIVERGENT_KEY_HEX: &str =
    "036D7E923EF22B65E19D95A6365C3373E1E96586E27015074A06ADD99C2D8000";

#[test]
fn bug_c_book_dir_matches_rippled() {
    let bundle = PathBuf::from(BUNDLE_DIR);
    if !bundle.exists() {
        eprintln!("bundle not found — skipping");
        return;
    }

    let anchor_header = loader::load_anchor_header(&bundle).unwrap();
    let validated_header = loader::load_validated_header(&bundle).unwrap();
    let mut tx_blobs = loader::load_tx_blobs(&bundle).unwrap();
    let prestate = loader::load_prestate(&bundle).unwrap();
    let rippled_reference = loader::load_rippled_reference(&bundle).unwrap();

    // Replay txs 0..=25 (enough to cover the divergence).
    tx_blobs.truncate(26);

    let mut state = LedgerState::new();
    for (k, bytes) in &prestate {
        state.insert_raw(Key(*k), bytes.clone());
    }

    let result = replay_ledger(
        &anchor_header,
        &mut state,
        tx_blobs,
        &validated_header,
        false,
    );

    eprintln!(
        "replay: applied={} failed={} skipped={} touched={}",
        result.applied_count, result.failed_count, result.skipped_count,
        result.touched_keys.len(),
    );

    let div_key_bytes = hex::decode(DIVERGENT_KEY_HEX).unwrap();
    let mut div_key = [0u8; 32];
    div_key.copy_from_slice(&div_key_bytes);

    let local = state.get_raw_owned(&Key(div_key));
    let expected = rippled_reference.get(&div_key).cloned();

    match (&local, &expected) {
        (Some(l), Some(e)) if l == e => {
            return; // PASS
        }
        _ => {}
    }

    eprintln!("DIVERGENT BookDirectory: {}", DIVERGENT_KEY_HEX);
    eprintln!(
        "  local    ({:>4}b): {}",
        local.as_ref().map(|b| b.len()).unwrap_or(0),
        local.as_ref().map(|b| hex::encode_upper(b)).unwrap_or_else(|| "<missing>".into()),
    );
    eprintln!(
        "  rippled  ({:>4}b): {}",
        expected.as_ref().map(|b| b.len()).unwrap_or(0),
        expected.as_ref().map(|b| hex::encode_upper(b)).unwrap_or_else(|| "<missing>".into()),
    );
    panic!("Bug C: book directory post-state does not match rippled");
}
