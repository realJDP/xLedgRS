use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use serde::Serialize;
use xrpl::ledger::sle::{LedgerEntryType, SLE};
use xrpl::ledger::sparse_shamap::{self, SparseSHAMap};
use xrpl::ledger::Key;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    host: String,

    #[arg(long)]
    fallback_host: Vec<String>,

    #[arg(long)]
    port: u16,

    #[arg(long)]
    ledger: u32,

    #[arg(long)]
    output: PathBuf,

    #[arg(long, default_value_t = 256)]
    limit: usize,

    #[arg(long, default_value_t = 3)]
    request_rounds: usize,

    #[arg(long, default_value_t = 1_000)]
    retry_delay_ms: u64,
}

#[derive(Serialize)]
struct JsonLine {
    key: String,
    entry_type: String,
    len: usize,
    raw_hex: String,
    status: &'static str,
}

fn entry_type_name(entry_type: LedgerEntryType) -> String {
    match entry_type {
        LedgerEntryType::AccountRoot => "AccountRoot".to_string(),
        LedgerEntryType::Offer => "Offer".to_string(),
        LedgerEntryType::RippleState => "RippleState".to_string(),
        LedgerEntryType::DirectoryNode => "DirectoryNode".to_string(),
        LedgerEntryType::Check => "Check".to_string(),
        LedgerEntryType::Escrow => "Escrow".to_string(),
        LedgerEntryType::PayChannel => "PayChannel".to_string(),
        LedgerEntryType::DepositPreauth => "DepositPreauth".to_string(),
        LedgerEntryType::DID => "Did".to_string(),
        LedgerEntryType::Ticket => "Ticket".to_string(),
        LedgerEntryType::NFTokenOffer => "NFTokenOffer".to_string(),
        LedgerEntryType::NFTokenPage => "NFTokenPage".to_string(),
        LedgerEntryType::LedgerHashes => "LedgerHashes".to_string(),
        _ => format!("{entry_type:?}"),
    }
}

fn parse_ledger_index(value: &serde_json::Value) -> anyhow::Result<u32> {
    if let Some(seq) = value.as_u64() {
        return Ok(seq as u32);
    }
    if let Some(seq) = value.as_str().and_then(|s| s.parse::<u32>().ok()) {
        return Ok(seq);
    }
    anyhow::bail!("missing or invalid ledger_index in ledger response");
}

fn parse_ledger_hash(value: &serde_json::Value) -> Option<String> {
    value.as_str().map(|hash| hash.to_ascii_uppercase())
}

async fn http_post_with_retries(
    hosts: &[String],
    port: u16,
    req: &str,
    context: &str,
    request_rounds: usize,
    retry_delay_ms: u64,
) -> anyhow::Result<String> {
    let request_rounds = request_rounds.max(1);
    let mut failures = Vec::new();
    for round in 1..=request_rounds {
        for host in hosts {
            match xrpl::rpc_sync::http_post(host, port, req).await {
                Ok(body) => {
                    if round > 1 || host != &hosts[0] {
                        eprintln!(
                            "recovered {} via host={} round={}/{}",
                            context, host, round, request_rounds
                        );
                    }
                    return Ok(body);
                }
                Err(err) => {
                    failures.push(format!(
                        "host={} round={}/{} err={}",
                        host, round, request_rounds, err
                    ));
                }
            }
        }

        if round < request_rounds {
            tokio::time::sleep(Duration::from_millis(retry_delay_ms)).await;
        }
    }

    anyhow::bail!(
        "{} failed after {} round(s): {}",
        context,
        request_rounds,
        failures.join(" | ")
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let mut hosts = Vec::with_capacity(1 + args.fallback_host.len());
    hosts.push(args.host.clone());
    hosts.extend(args.fallback_host.iter().cloned());

    let header_req = format!(
        r#"{{"method":"ledger","params":[{{"ledger_index":{},"transactions":false,"expand":false}}]}}"#,
        args.ledger
    );
    let header_body = http_post_with_retries(
        &hosts,
        args.port,
        &header_req,
        &format!("ledger header fetch for {}", args.ledger),
        args.request_rounds,
        args.retry_delay_ms,
    )
    .await?;
    let header_resp: serde_json::Value = serde_json::from_str(&header_body)?;
    let header = &header_resp["result"]["ledger"];
    let expected_hash = header["account_hash"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing account_hash in ledger response"))?
        .to_uppercase();
    let ledger_index = parse_ledger_index(&header["ledger_index"])?;
    let expected_ledger_hash = parse_ledger_hash(&header["hash"])
        .or_else(|| parse_ledger_hash(&header["ledger_hash"]))
        .or_else(|| parse_ledger_hash(&header_resp["result"]["ledger_hash"]))
        .ok_or_else(|| anyhow::anyhow!("missing ledger hash in ledger response"))?;

    let mut writer = BufWriter::new(File::create(&args.output)?);
    let mut sparse = SparseSHAMap::new();
    let mut marker: Option<String> = None;
    let mut pages = 0usize;
    let mut objects = 0usize;
    let mut last_key_hex: Option<String> = None;

    loop {
        let req = if let Some(ref marker) = marker {
            format!(
                r#"{{"method":"ledger_data","params":[{{"ledger_index":{},"limit":{},"binary":true,"marker":"{}"}}]}}"#,
                ledger_index, args.limit, marker
            )
        } else {
            format!(
                r#"{{"method":"ledger_data","params":[{{"ledger_index":{},"limit":{},"binary":true}}]}}"#,
                ledger_index, args.limit
            )
        };

        let body = http_post_with_retries(
            &hosts,
            args.port,
            &req,
            &format!(
                "ledger_data fetch for ledger {} marker {}",
                ledger_index,
                marker.as_deref().unwrap_or("<start>")
            ),
            args.request_rounds,
            args.retry_delay_ms,
        )
        .await?;
        let resp: serde_json::Value = serde_json::from_str(&body)?;
        let result = &resp["result"];
        if result["status"].as_str() != Some("success") {
            anyhow::bail!("ledger_data failed: {}", body);
        }
        if result["validated"].as_bool() != Some(true) {
            anyhow::bail!("ledger_data returned non-validated page: {}", body);
        }

        let page_ledger_index = parse_ledger_index(&result["ledger_index"])?;
        if page_ledger_index != ledger_index {
            anyhow::bail!(
                "ledger_data page changed ledger_index: expected {} got {}",
                ledger_index,
                page_ledger_index
            );
        }

        let page_ledger_hash = parse_ledger_hash(&result["ledger_hash"])
            .ok_or_else(|| anyhow::anyhow!("ledger_data omitted ledger_hash"))?;
        if page_ledger_hash != expected_ledger_hash {
            anyhow::bail!(
                "ledger_data page changed ledger_hash: expected {} got {}",
                expected_ledger_hash,
                page_ledger_hash
            );
        }

        let state = result["state"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("ledger_data omitted state array"))?;
        for object in state {
            let key_hex = object["index"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("state entry omitted index"))?
                .to_ascii_uppercase();
            if let Some(previous_key) = last_key_hex.as_ref() {
                if key_hex <= *previous_key {
                    anyhow::bail!(
                        "ledger_data key order broke monotonicity at {} after {}",
                        key_hex,
                        previous_key
                    );
                }
            }
            let raw_hex = object["data"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("state entry omitted data"))?
                .to_ascii_uppercase();
            let key_bytes = hex::decode(&key_hex)?;
            if key_bytes.len() != 32 {
                anyhow::bail!("invalid state key length for {}", key_hex);
            }
            let raw = hex::decode(&raw_hex)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            sparse.insert(key, sparse_shamap::leaf_hash(&raw, &key));

            let entry_type = SLE::from_raw(Key(key), raw.clone())
                .map(|sle| entry_type_name(sle.entry_type()))
                .unwrap_or_else(|| "<decode_failed>".to_string());
            let line = JsonLine {
                key: key_hex.clone(),
                entry_type,
                len: raw.len(),
                raw_hex,
                status: "present",
            };
            writer.write_all(serde_json::to_string(&line)?.as_bytes())?;
            writer.write_all(b"\n")?;
            objects += 1;
            last_key_hex = Some(key_hex);
        }

        pages += 1;
        if pages == 1 {
            eprintln!(
                "first_page ledger={} ledger_hash={} validated=true page_objects={}",
                ledger_index,
                expected_ledger_hash,
                state.len()
            );
        }
        if pages % 100 == 0 {
            eprintln!(
                "progress ledger={} pages={} objects={} marker={}",
                ledger_index,
                pages,
                objects,
                result["marker"].as_str().unwrap_or("<done>")
            );
        }

        let next_marker = result["marker"].as_str().map(|value| value.to_string());
        if let (Some(current_marker), Some(next_marker)) = (marker.as_ref(), next_marker.as_ref()) {
            if current_marker == next_marker {
                anyhow::bail!("ledger_data marker did not advance: {}", current_marker);
            }
        }
        if next_marker.is_some() && state.is_empty() {
            anyhow::bail!("ledger_data returned empty page while marker was still present");
        }

        marker = next_marker;
        if marker.is_none() {
            break;
        }
    }

    writer.flush()?;

    let actual_hash = hex::encode_upper(sparse.root_hash());
    println!(
        "ledger={} objects={} pages={} expected_account_hash={} actual_account_hash={} output={}",
        ledger_index,
        objects,
        pages,
        expected_hash,
        actual_hash,
        args.output.display()
    );

    if actual_hash != expected_hash {
        anyhow::bail!(
            "full-state hash mismatch for ledger {}: expected {} got {}",
            ledger_index,
            expected_hash,
            actual_hash
        );
    }

    Ok(())
}
