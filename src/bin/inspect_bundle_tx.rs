//! xLedgRS purpose: Inspect Bundle Tx diagnostic utility for parity investigation.
use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::Parser;
use xrpl::ledger::close::TxAttribution;
use xrpl::ledger::forensic::loader;
use xrpl::ledger::meta::parse_metadata_summary;
use xrpl::transaction::amount::Amount;
use xrpl::transaction::parse::{parse_blob, PathStep};
use xrpl::transaction::serialize::tx_blob_hash;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    bundle: PathBuf,

    #[arg(long)]
    seq: Vec<u32>,

    #[arg(long)]
    tx_index: Vec<usize>,
}

fn format_amount(amount: &Option<Amount>) -> String {
    match amount {
        Some(Amount::Xrp(drops)) => format!("{drops} drops"),
        Some(Amount::Iou {
            value,
            currency,
            issuer,
        }) => format!(
            "IOU {}e{} {} issuer={}",
            value.mantissa,
            value.exponent,
            hex::encode_upper(currency.code),
            hex::encode_upper(issuer)
        ),
        Some(Amount::Mpt(value)) => format!("MPT {}", hex::encode_upper(value)),
        None => "-".to_string(),
    }
}

fn sle_type_name(raw: &[u8]) -> &'static str {
    if raw.len() >= 3 && raw[0] == 0x11 {
        match u16::from_be_bytes([raw[1], raw[2]]) {
            0x0061 => "AccountRoot",
            0x0064 => "DirectoryNode",
            0x006F => "Offer",
            0x0072 => "RippleState",
            0x0075 => "Escrow",
            0x0078 => "PayChannel",
            0x0043 => "Check",
            0x0054 => "Ticket",
            0x0037 => "NFTokenOffer",
            0x0050 => "NFTokenPage",
            _ => "Unknown",
        }
    } else {
        "NonSLE"
    }
}

fn format_path_step(step: &PathStep) -> String {
    let mut parts = Vec::new();
    if let Some(account) = step.account {
        parts.push(format!("acct={}", hex::encode_upper(account)));
    }
    if let Some(currency) = step.currency {
        parts.push(format!("cur={}", hex::encode_upper(currency)));
    }
    if let Some(issuer) = step.issuer {
        parts.push(format!("iss={}", hex::encode_upper(issuer)));
    }
    if parts.is_empty() {
        "empty".to_string()
    } else {
        parts.join(",")
    }
}

fn format_paths(paths: &[Vec<PathStep>]) -> String {
    if paths.is_empty() {
        return "-".to_string();
    }
    paths
        .iter()
        .enumerate()
        .map(|(idx, path)| {
            let steps = path
                .iter()
                .map(format_path_step)
                .collect::<Vec<_>>()
                .join(" -> ");
            format!("{idx}:[{steps}]")
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn describe_key_state(
    key: &[u8; 32],
    prestate: &std::collections::HashMap<[u8; 32], Vec<u8>>,
    rippled_reference: &std::collections::HashMap<[u8; 32], Vec<u8>>,
) -> String {
    let pre = prestate
        .get(key)
        .map(|raw| sle_type_name(raw).to_string())
        .unwrap_or_else(|| "-".to_string());
    let reference = rippled_reference
        .get(key)
        .map(|raw| sle_type_name(raw).to_string())
        .unwrap_or_else(|| "-".to_string());
    format!(
        "key={} pre={} ref={}",
        hex::encode_upper(&key[..8]),
        pre,
        reference
    )
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let tx_blobs = loader::load_tx_blobs(&args.bundle)?;
    let per_tx_attribution = loader::load_per_tx_attribution(&args.bundle).unwrap_or_default();
    let prestate = loader::load_prestate(&args.bundle).unwrap_or_default();
    let rippled_reference = loader::load_rippled_reference(&args.bundle).unwrap_or_default();
    let wanted_seqs: BTreeSet<u32> = args.seq.into_iter().collect();
    let wanted_indexes: BTreeSet<usize> = args.tx_index.into_iter().collect();
    let filter_by_seq = !wanted_seqs.is_empty();
    let filter_by_idx = !wanted_indexes.is_empty();

    let attr_by_tx_id: std::collections::HashMap<[u8; 32], &TxAttribution> = per_tx_attribution
        .iter()
        .map(|attr| (attr.tx_id, attr))
        .collect();

    let tx_sources: Vec<(usize, Vec<u8>, Vec<u8>, Option<&TxAttribution>)> = tx_blobs
        .iter()
        .enumerate()
        .map(|(fallback_idx, (blob, meta))| {
            let tx_id = tx_blob_hash(blob);
            let attr = attr_by_tx_id.get(&tx_id).copied();
            let idx = attr
                .map(|attr| attr.tx_index as usize)
                .unwrap_or(fallback_idx);
            (idx, blob.clone(), meta.clone(), attr)
        })
        .collect();

    for (idx, blob, meta, attr) in tx_sources {
        let parsed = parse_blob(&blob)?;
        let meta_summary = parse_metadata_summary(&meta);
        let matches_seq = wanted_seqs.contains(&parsed.sequence);
        let matches_idx = wanted_indexes.contains(&idx);
        let include = match (filter_by_seq, filter_by_idx) {
            (false, false) => true,
            (true, false) => matches_seq,
            (false, true) => matches_idx,
            (true, true) => matches_seq || matches_idx,
        };
        if !include {
            continue;
        }

        println!(
            "idx={} type={} seq={} acct={} dest={} flags=0x{:08X} pays={} gets={} amount={} send_max={} delivered={} paths={}{}",
            idx,
            parsed.tx_type,
            parsed.sequence,
            hex::encode_upper(parsed.account),
            parsed
                .destination
                .map(hex::encode_upper)
                .unwrap_or_else(|| "-".to_string()),
            parsed.flags,
            format_amount(&parsed.taker_pays),
            format_amount(&parsed.taker_gets),
            format_amount(&parsed.amount),
            format_amount(&parsed.send_max),
            format_amount(&meta_summary.delivered_amount),
            parsed.paths.len(),
            attr.map(|attr| format!(" ter={}", attr.ter_token))
                .unwrap_or_default(),
        );
        if !parsed.paths.is_empty() {
            println!("  paths {}", format_paths(&parsed.paths));
        }
        if let Some(attr) = attr {
            for key in &attr.created_keys {
                println!(
                    "  created {}",
                    describe_key_state(key, &prestate, &rippled_reference)
                );
            }
            for key in &attr.modified_keys {
                println!(
                    "  modified {}",
                    describe_key_state(key, &prestate, &rippled_reference)
                );
            }
        }
    }

    Ok(())
}
