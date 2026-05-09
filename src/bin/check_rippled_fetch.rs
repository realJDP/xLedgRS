use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    host: String,

    #[arg(long)]
    port: u16,

    #[arg(long)]
    ledger: u32,

    #[arg(long)]
    key: String,

    #[arg(long, default_value_t = 1)]
    repeats: usize,
}

fn response_indicates_not_found(resp: &serde_json::Value) -> bool {
    fn matches_not_found(value: &serde_json::Value) -> bool {
        value.as_str().map_or(false, |s| {
            let lower = s.to_ascii_lowercase();
            lower.contains("entrynotfound")
                || lower.contains("objectnotfound")
                || lower.contains("notfound")
                || lower.contains("not found")
        })
    }

    [
        &resp["error"],
        &resp["error_message"],
        &resp["result"]["error"],
        &resp["result"]["error_message"],
        &resp["result"]["message"],
    ]
    .into_iter()
    .any(matches_not_found)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let key = args.key.trim().to_ascii_lowercase();

    for attempt in 1..=args.repeats {
        let req = format!(
            r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
            key, args.ledger,
        );
        match xrpl::rpc_sync::http_post(&args.host, args.port, &req).await {
            Ok(body) => {
                let resp: serde_json::Value = serde_json::from_str(&body)?;
                if let Some(nb) = resp["result"]["node_binary"].as_str() {
                    println!(
                        "attempt={} status=found node_len={} prefix={}",
                        attempt,
                        nb.len() / 2,
                        &nb[..nb.len().min(32)]
                    );
                } else if response_indicates_not_found(&resp) {
                    println!("attempt={} status=not_found body={}", attempt, body);
                } else {
                    println!("attempt={} status=other body={}", attempt, body);
                }
            }
            Err(err) => {
                println!("attempt={} status=error err={}", attempt, err);
            }
        }
    }

    Ok(())
}
