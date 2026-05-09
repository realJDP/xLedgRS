use std::path::PathBuf;

use clap::Parser;

use xrpl::ledger::forensic::loader;
use xrpl::ledger::{Key, LedgerState};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    bundle: PathBuf,
}

fn seed_state(entries: &std::collections::HashMap<[u8; 32], Vec<u8>>) -> LedgerState {
    let mut state = LedgerState::new();
    for (key, bytes) in entries {
        state.insert_raw(Key(*key), bytes.clone());
    }
    state
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let validated_header = loader::load_validated_header(&args.bundle)?;
    let rippled_reference = loader::load_rippled_reference(&args.bundle)?;

    let mut state = seed_state(&rippled_reference);
    let computed = state.state_hash();

    println!(
        "bundle={} reference_keys={} computed_account_hash={} validated_account_hash={}",
        args.bundle.display(),
        rippled_reference.len(),
        hex::encode_upper(computed),
        hex::encode_upper(validated_header.account_hash),
    );

    Ok(())
}
