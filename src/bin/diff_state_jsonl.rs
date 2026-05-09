use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use clap::Parser;
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    local: PathBuf,

    #[arg(long)]
    reference: PathBuf,

    #[arg(long, default_value_t = 50)]
    limit: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct JsonLine {
    key: String,
    entry_type: String,
    len: usize,
    #[allow(dead_code)]
    status: String,
    raw_hex: String,
}

fn read_next(
    lines: &mut impl Iterator<Item = std::io::Result<String>>,
) -> anyhow::Result<Option<JsonLine>> {
    match lines.next() {
        Some(line) => Ok(Some(serde_json::from_str(&line?)?)),
        None => Ok(None),
    }
}

fn first_diff_byte(local: &str, reference: &str) -> Option<usize> {
    let local_bytes = local.as_bytes();
    let reference_bytes = reference.as_bytes();
    let shared = local_bytes.len().min(reference_bytes.len());
    for idx in 0..shared {
        if local_bytes[idx] != reference_bytes[idx] {
            return Some(idx / 2);
        }
    }
    (local_bytes.len() != reference_bytes.len()).then_some(shared / 2)
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let local_reader = BufReader::new(File::open(&args.local)?);
    let reference_reader = BufReader::new(File::open(&args.reference)?);
    let mut local_lines = local_reader.lines();
    let mut reference_lines = reference_reader.lines();

    let mut local_current = read_next(&mut local_lines)?;
    let mut reference_current = read_next(&mut reference_lines)?;

    let mut matched = 0usize;
    let mut different = 0usize;
    let mut local_only = 0usize;
    let mut reference_only = 0usize;
    let mut different_by_type = std::collections::BTreeMap::<String, usize>::new();
    let mut logged = 0usize;

    while local_current.is_some() || reference_current.is_some() {
        match (local_current.as_ref(), reference_current.as_ref()) {
            (Some(local), Some(reference)) if local.key == reference.key => {
                if local.raw_hex == reference.raw_hex {
                    matched += 1;
                } else {
                    different += 1;
                    *different_by_type
                        .entry(reference.entry_type.clone())
                        .or_insert(0) += 1;
                    if logged < args.limit {
                        println!(
                            "DIFF key={} type={} local_len={} ref_len={} first_diff_byte={}",
                            local.key,
                            reference.entry_type,
                            local.len,
                            reference.len,
                            first_diff_byte(&local.raw_hex, &reference.raw_hex)
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "<unknown>".into()),
                        );
                        logged += 1;
                    }
                }
                local_current = read_next(&mut local_lines)?;
                reference_current = read_next(&mut reference_lines)?;
            }
            (Some(local), Some(reference)) if local.key < reference.key => {
                local_only += 1;
                if logged < args.limit {
                    println!(
                        "LOCAL ONLY key={} type={} len={}",
                        local.key, local.entry_type, local.len
                    );
                    logged += 1;
                }
                local_current = read_next(&mut local_lines)?;
            }
            (Some(_), Some(reference)) => {
                reference_only += 1;
                if logged < args.limit {
                    println!(
                        "REFERENCE ONLY key={} type={} len={}",
                        reference.key, reference.entry_type, reference.len
                    );
                    logged += 1;
                }
                reference_current = read_next(&mut reference_lines)?;
            }
            (Some(local), None) => {
                local_only += 1;
                if logged < args.limit {
                    println!(
                        "LOCAL ONLY key={} type={} len={}",
                        local.key, local.entry_type, local.len
                    );
                    logged += 1;
                }
                local_current = read_next(&mut local_lines)?;
            }
            (None, Some(reference)) => {
                reference_only += 1;
                if logged < args.limit {
                    println!(
                        "REFERENCE ONLY key={} type={} len={}",
                        reference.key, reference.entry_type, reference.len
                    );
                    logged += 1;
                }
                reference_current = read_next(&mut reference_lines)?;
            }
            (None, None) => break,
        }
    }

    println!(
        "SUMMARY matched={} different={} local_only={} reference_only={}",
        matched, different, local_only, reference_only
    );
    if !different_by_type.is_empty() {
        println!("DIFFERENT BY TYPE {:?}", different_by_type);
    }

    Ok(())
}
