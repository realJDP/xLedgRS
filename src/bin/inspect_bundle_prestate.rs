//! xLedgRS purpose: Inspect Bundle Prestate diagnostic utility for parity investigation.
use std::path::PathBuf;

use clap::Parser;
use xrpl::ledger::forensic::loader;
use xrpl::ledger::sle::{LedgerEntryType, SLE};
use xrpl::ledger::Key;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    bundle: PathBuf,

    #[arg(long)]
    key: String,
}

fn parse_key(hex_key: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = hex_key.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(hex)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32-byte hex key"))?;
    Ok(arr)
}

fn entry_type_name(raw: &[u8], key: [u8; 32]) -> String {
    match SLE::from_raw(Key(key), raw.to_vec()).map(|sle| sle.entry_type()) {
        Some(LedgerEntryType::AccountRoot) => "AccountRoot".to_string(),
        Some(LedgerEntryType::DirectoryNode) => "DirectoryNode".to_string(),
        Some(LedgerEntryType::RippleState) => "RippleState".to_string(),
        Some(LedgerEntryType::Offer) => "Offer".to_string(),
        Some(other) => format!("{other:?}"),
        None => "Unknown".to_string(),
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let key = parse_key(&args.key)?;
    let prestate = loader::load_prestate(&args.bundle)?;
    if let Some(raw) = prestate.get(&key) {
        println!(
            "prestate: present key={} entry_type={} raw_len={}",
            hex::encode_upper(key),
            entry_type_name(raw, key),
            raw.len()
        );
    } else {
        println!("prestate: missing key={}", hex::encode_upper(key));
    }
    Ok(())
}
