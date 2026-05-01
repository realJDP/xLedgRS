//! xLedgRS purpose: Analyze Missing Refs diagnostic utility for parity investigation.
use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::Parser;

use xrpl::ledger::forensic::collect_missing_reference_edges;
use xrpl::ledger::forensic::loader;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    bundle: PathBuf,
}

fn bump(map: &mut BTreeMap<String, usize>, key: impl Into<String>) {
    *map.entry(key.into()).or_insert(0) += 1;
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let reference = loader::load_rippled_reference(&args.bundle)?;
    let per_tx_attribution = loader::load_per_tx_attribution(&args.bundle).unwrap_or_default();
    let edges = collect_missing_reference_edges(&reference, &per_tx_attribution);

    let mut missing = BTreeMap::<String, usize>::new();
    let mut samples = BTreeMap::<String, Vec<String>>::new();

    for edge in &edges {
        bump(&mut missing, edge.edge_label.to_string());
        let bucket = samples.entry(edge.edge_label.to_string()).or_default();
        if bucket.len() < 5 {
            bucket.push(format!(
                "source={} source_class={} target={} target_class={} tx_index={} tx_type={}",
                hex::encode_upper(edge.source_key),
                edge.source_class,
                hex::encode_upper(edge.target_key),
                edge.target_class,
                edge.tx_index
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "<unknown>".into()),
                edge.tx_type.as_deref().unwrap_or("<unknown>"),
            ));
        }
    }

    println!(
        "bundle={} reference_keys={} missing_edges={}",
        args.bundle.display(),
        reference.len(),
        edges.len(),
    );
    for (kind, count) in &missing {
        println!("{kind}: {count}");
        if let Some(rows) = samples.get(kind) {
            for row in rows {
                println!("  {row}");
            }
        }
    }

    Ok(())
}
