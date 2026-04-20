use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::Parser;
use xrpl::ledger::forensic::loader;
use xrpl::transaction::amount::Amount;
use xrpl::transaction::parse::parse_blob;

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

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let tx_blobs = loader::load_tx_blobs(&args.bundle)?;
    let wanted_seqs: BTreeSet<u32> = args.seq.into_iter().collect();
    let wanted_indexes: BTreeSet<usize> = args.tx_index.into_iter().collect();
    let filter_by_seq = !wanted_seqs.is_empty();
    let filter_by_idx = !wanted_indexes.is_empty();

    for (idx, (blob, _meta)) in tx_blobs.iter().enumerate() {
        let parsed = parse_blob(blob)?;
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
            "idx={} type={} seq={} acct={} dest={} flags=0x{:08X} pays={} gets={} amount={} send_max={}",
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
        );
    }

    Ok(())
}
