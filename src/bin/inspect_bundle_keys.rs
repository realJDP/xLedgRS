use std::path::PathBuf;

use clap::Parser;

use xrpl::ledger::forensic::loader;
use xrpl::ledger::Key;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    bundle: PathBuf,

    #[arg(required = true)]
    keys: Vec<String>,
}

fn entry_type_name(raw: &[u8]) -> String {
    if raw.len() >= 3 && raw[0] == 0x11 {
        let entry_type = u16::from_be_bytes([raw[1], raw[2]]);
        return xrpl::ledger::sle::LedgerEntryType::from_u16(entry_type)
            .map(|entry| format!("{entry:?}"))
            .unwrap_or_else(|| format!("0x{entry_type:04X}"));
    }
    "<unknown>".to_string()
}

fn parse_key(hex_key: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_key)?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be exactly 32 bytes"))?;
    Ok(key)
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let prestate = loader::load_prestate(&args.bundle)?;
    let rippled_reference = loader::load_rippled_reference(&args.bundle)?;
    let tx_blobs = loader::load_tx_blobs(&args.bundle)?;

    for key_text in &args.keys {
        let key = parse_key(key_text)?;
        println!("KEY {}", hex::encode_upper(key));

        match prestate.get(&key) {
            Some(raw) => {
                println!(
                    "  prestate: present type={} len={}",
                    entry_type_name(raw),
                    raw.len()
                );
            }
            None => println!("  prestate: missing"),
        }

        match rippled_reference.get(&key) {
            Some(raw) => {
                println!(
                    "  rippled_reference: present type={} len={}",
                    entry_type_name(raw),
                    raw.len()
                );
            }
            None => println!("  rippled_reference: missing"),
        }

        let mut found = false;
        for (_blob, meta) in &tx_blobs {
            let (tx_index_opt, nodes) = xrpl::ledger::meta::parse_metadata_with_index(meta);
            for node in nodes {
                if node.ledger_index != key {
                    continue;
                }
                found = true;
                let tx_index = tx_index_opt
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "<unknown>".to_string());
                println!(
                    "  metadata: tx_index={} action={:?} entry_type=0x{:04X}",
                    tx_index, node.action, node.entry_type
                );
            }
        }
        if !found {
            println!("  metadata: not referenced");
        }

        let key = Key(key);
        let owner_page = prestate
            .get(&key.0)
            .and_then(|raw| xrpl::ledger::DirectoryNode::decode(raw, key.0).ok())
            .map(|dir| {
                (
                    dir.owner,
                    dir.root_index,
                    dir.index_next,
                    dir.index_previous,
                )
            });
        if let Some((owner, root_index, index_next, index_previous)) = owner_page {
            println!(
                "  directory: owner={} root={} next={} prev={}",
                owner
                    .map(hex::encode_upper)
                    .unwrap_or_else(|| "<none>".to_string()),
                hex::encode_upper(root_index),
                index_next,
                index_previous
            );
        }
    }

    Ok(())
}
