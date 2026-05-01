//! xLedgRS purpose: Run storage and live hash diagnostics for mismatches.
//! Diagnostic tool for debugging hash mismatches.
//!
//! Verifies internal consistency of stored state:
//! 1. Object count vs leaf hash count
//! 2. Recomputes leaf hashes from stored objects, checks against stored hashes
//! 3. Builds SparseSHAMap from leaf hashes, prints root hash
//! 4. Samples objects against RPC if available
//! 5. Checks for common corruption patterns

use std::sync::Arc;

use crate::ledger::sparse_shamap::{self, SparseSHAMap};
use crate::storage::Storage;

pub async fn run_diagnose(
    storage: Arc<Storage>,
    rpc_endpoint: Option<String>,
) -> anyhow::Result<()> {
    println!("=== xLedgRSv2Beta state diagnostic ===\n");

    // Basic info from SQLite storage
    let sync_ledger = storage.get_sync_ledger();
    let stats = storage.stats();

    println!("Synced ledger:    {:?}", sync_ledger);
    println!("Stored ledgers:   {}", stats.ledgers);
    println!("Stored txs:       {}", stats.transactions);
    println!("Sync complete:    {}", storage.is_sync_complete());
    println!();

    // Object-level iteration is no longer available from SQLite; state objects
    // now live in NuDB. Use --verify-hash for hash verification.
    println!("Object-level diagnostics are unavailable from SQLite storage.");
    println!("Use --verify-hash to verify hash computation against a live RPC endpoint.");
    println!();

    // Check against network if endpoint provided
    if let Some(ref endpoint) = rpc_endpoint {
        let (host, port) = parse_endpoint(endpoint);
        println!("Checking against RPC {}:{}...", host, port);

        if let Some(seq) = sync_ledger {
            // Get current validated ledger for comparison
            let req2 = r#"{"method":"server_info","params":[{}]}"#;
            match crate::rpc_sync::http_post(&host, port, req2).await {
                Ok(body) => {
                    if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&body) {
                        let info = &resp["result"]["info"];
                        let validated = info["validated_ledger"]["seq"].as_u64();
                        let complete = info["complete_ledgers"].as_str();
                        println!("  rippled validated: {:?}", validated);
                        println!("  complete_ledgers:  {:?}", complete);
                        if let Some(v) = validated {
                            let diff = v as i64 - seq as i64;
                            println!("  sync is {} ledgers behind", diff);
                        }
                    }
                }
                Err(e) => println!("  server_info error: {e}"),
            }
        }
    } else {
        println!("No --rpc-sync endpoint specified; network verification is disabled.");
        println!("Re-run with --rpc-sync <host:port> to compare against rippled.");
    }

    println!("\n=== Summary ===");
    println!(
        "Storage stats: {} ledgers, {} transactions",
        stats.ledgers, stats.transactions
    );

    Ok(())
}

/// Definitive hash verification: stream `ledger_data` from RPC, compute the
/// root hash, and compare it against the ledger's `account_hash`. This checks
/// the `leaf_hash` and `SparseSHAMap` implementations without using storage.
pub async fn verify_hash_live(host: &str, port: u16) -> anyhow::Result<()> {
    println!("=== Live hash verification ===\n");

    // 1. Get current validated ledger and its account_hash
    let req = r#"{"method":"ledger","params":[{"ledger_index":"validated"}]}"#;
    let body = crate::rpc_sync::http_post(host, port, req).await?;
    let resp: serde_json::Value = serde_json::from_str(&body)?;
    let result = &resp["result"]["ledger"];
    let mut ledger_seq = result["ledger_index"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("no ledger_index"))?;
    let mut expected_hash = result["account_hash"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no account_hash"))?
        .to_uppercase();

    println!("Ledger:        {}", ledger_seq);
    println!("Expected hash: {}", expected_hash);
    println!();

    // 2. Stream all objects via ledger_data, build SparseSHAMap on the fly
    let mut sparse = SparseSHAMap::new();
    let mut marker: Option<String> = None;
    let mut total = 0u64;
    let mut pages = 0u64;
    let mut start = std::time::Instant::now();

    loop {
        let params = if let Some(ref m) = marker {
            format!(
                r#"{{"method":"ledger_data","params":[{{"ledger_index":{},"limit":2048,"binary":true,"marker":"{}"}}]}}"#,
                ledger_seq, m
            )
        } else {
            format!(
                r#"{{"method":"ledger_data","params":[{{"ledger_index":{},"limit":2048,"binary":true}}]}}"#,
                ledger_seq
            )
        };

        let body = match crate::rpc_sync::http_post(host, port, &params).await {
            Ok(b) => b,
            Err(e) => {
                println!("  HTTP error: {e} — retrying in 2s");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        let resp: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                println!("  JSON parse error: {e} — retrying in 2s");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        let result = &resp["result"];

        if result["status"].as_str() != Some("success") {
            let err = result["error"].as_str().unwrap_or("unknown");
            // If ledger was pruned, start over with a fresh one
            if err == "lgrNotFound" || err == "internal" {
                println!(
                    "  Ledger {} pruned — restarting with fresh validated ledger...",
                    ledger_seq
                );
                // Get new validated ledger
                let req = r#"{"method":"ledger","params":[{"ledger_index":"validated"}]}"#;
                let body = crate::rpc_sync::http_post(host, port, req).await?;
                let resp: serde_json::Value = serde_json::from_str(&body)?;
                let r = &resp["result"]["ledger"];
                ledger_seq = r["ledger_index"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or_else(|| anyhow::anyhow!("no ledger_index on retry"))?;
                expected_hash = r["account_hash"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("no account_hash on retry"))?
                    .to_uppercase();
                println!("  New target: ledger {} hash {}", ledger_seq, expected_hash);
                // Reset state
                sparse = SparseSHAMap::new();
                marker = None;
                total = 0;
                pages = 0;
                start = std::time::Instant::now();
                continue;
            }
            anyhow::bail!("RPC error: {err}");
        }

        let state = result["state"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("no state array"))?;

        if state.is_empty() {
            break;
        }

        for obj in state {
            let index_hex = match obj["index"].as_str() {
                Some(s) => s,
                None => continue,
            };
            let data_hex = match obj["data"].as_str() {
                Some(s) => s,
                None => continue,
            };
            let key_bytes = hex::decode(index_hex).unwrap_or_default();
            let data_bytes = hex::decode(data_hex).unwrap_or_default();
            if key_bytes.len() != 32 {
                continue;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            let lh = sparse_shamap::leaf_hash(&data_bytes, &key);
            sparse.insert(key, lh);
            total += 1;
        }

        pages += 1;
        if pages % 500 == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let rate = total as f64 / elapsed;
            println!("  {} objects, {} pages, {:.0} obj/s", total, pages, rate);
        }

        marker = result["marker"].as_str().map(|s| s.to_string());
        if marker.is_none() {
            break;
        }

        tokio::task::yield_now().await;
    }

    let our_hash = sparse.root_hash();
    let elapsed = start.elapsed();

    println!();
    println!("Objects:       {}", total);
    println!("Pages:         {}", pages);
    println!("Time:          {:.1}s", elapsed.as_secs_f64());
    println!("Our hash:      {}", hex::encode_upper(our_hash));
    println!("Expected hash: {}", expected_hash);

    if hex::encode_upper(our_hash) == expected_hash {
        println!("\n*** MATCH! Our leaf_hash + SparseSHAMap code is CORRECT. ***");
    } else {
        println!("\n*** MISMATCH — hash computation failed to match. ***");
    }

    Ok(())
}

fn parse_endpoint(s: &str) -> (String, u16) {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    let host = parts[0].to_string();
    let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(5005);
    (host, port)
}
