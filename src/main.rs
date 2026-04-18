use clap::Parser;
use std::sync::Arc;
use tracing::info;

mod grpc;
mod process_control;

use xrpl::config::{ConfigFile, HistoryRetention};
use xrpl::node::{Node, NodeConfig};

#[derive(Parser, Debug)]
#[command(
    name = "xledgrs",
    about = "XRP Ledger node implemented in Rust",
    version
)]
struct Args {
    /// Address to listen for peer connections
    #[arg(long, default_value = "0.0.0.0:51235")]
    peer_addr: String,

    /// Address to listen for JSON-RPC requests
    #[arg(long, default_value = "127.0.0.1:5005")]
    rpc_addr: String,

    /// Address to listen for gRPC requests (omit to disable gRPC)
    #[arg(long)]
    grpc_addr: Option<String>,

    /// Maximum number of peer connections
    #[arg(long, default_value_t = 21)]
    max_peers: usize,

    /// Bootstrap peer addresses (comma-separated)
    #[arg(long, default_value = "")]
    bootstrap: String,

    /// Fixed peer addresses (can be specified multiple times)
    #[arg(long)]
    fixed_peer: Vec<String>,

    /// Address to listen for WebSocket connections
    #[arg(long, default_value = "127.0.0.1:6006")]
    ws_addr: String,

    /// Directory for persistent state (omit for in-memory only)
    #[arg(long)]
    data_dir: Option<String>,

    /// Path to config file (supports xLedgRS TOML and xrpld-style cfg)
    #[arg(long)]
    config: Option<String>,

    /// Start the node in the background and return immediately
    #[arg(long)]
    start: bool,

    /// Stop a background node using its PID file
    #[arg(long)]
    stop: bool,

    /// Restart a background node using its PID file
    #[arg(long)]
    restart: bool,

    /// Show background node status from its PID file
    #[arg(long)]
    status: bool,

    /// Override the PID file used by --start/--stop/--restart/--status
    #[arg(long)]
    pid_file: Option<String>,

    /// Override the log file used by --start/--restart
    #[arg(long)]
    log_file: Option<String>,

    /// Network ID (0 = mainnet, 1 = testnet, 2 = devnet)
    #[arg(long, default_value_t = 0)]
    network_id: u32,

    /// Maximum objects to download during state sync (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    max_sync: u64,

    /// Rippled admin RPC endpoint for fast state sync (e.g. "127.0.0.1:5005")
    #[arg(long)]
    rpc_sync: Option<String>,

    /// Standalone mode: keep networking disabled and allow local ledger_accept.
    #[arg(long, default_value_t = false)]
    standalone: bool,

    /// Enable the local consensus/ledger-close loop.
    /// Leave off for a normal follower node.
    #[arg(long, default_value_t = false)]
    enable_consensus_close_loop: bool,

    /// Test mode: apply one ledger, check hash, exit.
    #[arg(long)]
    test_one_ledger: bool,

    /// Ledger sequence for test mode
    #[arg(long)]
    test_seq: Option<u32>,

    /// RPC source for test mode (e.g. "s2.ripple.com:51234")
    #[arg(long, default_value = "s2.ripple.com:51234")]
    test_source: String,

    /// Cache file for test ledger (skip s2 fetch on subsequent runs)
    #[arg(long)]
    test_cache: Option<String>,

    #[arg(long)]
    test_skip_creates: bool,
    #[arg(long)]
    test_skip_modifies: bool,
    #[arg(long)]
    test_skip_deletes: bool,

    /// Dump a single object's hex from storage and exit
    #[arg(long)]
    dump_object: Option<String>,

    /// Diagnose hash mismatch: verify leaf hashes, check object counts, sample against RPC
    #[arg(long)]
    diagnose: bool,

    /// Verify hash computation: stream ledger_data from RPC, compute root hash, compare
    #[arg(long)]
    verify_hash: bool,

    /// Compact NuDB: walk current state tree, copy live nodes to new DB, remove stale data
    #[arg(long)]
    compact: bool,

    #[arg(long, hide = true)]
    daemon_child: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    {
        use tracing_subscriber::prelude::*;
        let (filter_layer, reload_handle) =
            tracing_subscriber::reload::Layer::new(tracing_subscriber::filter::LevelFilter::INFO);
        xrpl::rpc::install_log_reload_handle(reload_handle);
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
    let args = Args::parse();
    let config_file_path = args.config.as_ref().map(std::path::PathBuf::from);
    let file_cfg = config_file_path
        .as_ref()
        .and_then(|path| match ConfigFile::load(path) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                tracing::warn!("failed to load config {}: {}", path.display(), e);
                None
            }
        });
    let configured_data_dir = args.data_dir.clone().map(std::path::PathBuf::from).or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|cfg| cfg.runtime.data_dir.clone())
    });
    let exe_name = std::env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "xledgrs".to_string());
    let control_request = process_control::ControlRequest {
        start: args.start,
        stop: args.stop,
        restart: args.restart,
        status: args.status,
        daemon_child: args.daemon_child,
    };
    let control_files = process_control::resolve_control_files(
        &exe_name,
        config_file_path.as_deref(),
        configured_data_dir.as_deref(),
        args.pid_file.as_deref(),
        args.log_file.as_deref(),
    );
    if process_control::handle_control_request(control_request, &control_files)? {
        return Ok(());
    }

    let mut bootstrap: Vec<std::net::SocketAddr> = args
        .bootstrap
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let s = s.trim();
            match s.parse() {
                Ok(addr) => Some(addr),
                Err(e) => {
                    tracing::warn!("ignoring bad bootstrap address '{}': {}", s, e);
                    None
                }
            }
        })
        .collect();
    if let Some(ref cfg) = file_cfg {
        for peer in &cfg.runtime.bootstrap_peers {
            let s = normalize_peer_endpoint(peer);
            if s.is_empty() {
                continue;
            }
            if let Ok(addr) = s.parse() {
                bootstrap.push(addr);
            } else {
                use std::net::ToSocketAddrs;
                match s.to_socket_addrs() {
                    Ok(addrs) => {
                        let resolved: Vec<_> = addrs.collect();
                        tracing::info!("resolved bootstrap {} → {} addresses", s, resolved.len());
                        bootstrap.extend(resolved);
                    }
                    Err(e) => {
                        tracing::warn!("failed to resolve bootstrap {}: {}", s, e);
                    }
                }
            }
        }
    }
    let mut fixed_peers = args.fixed_peer.clone();
    if let Some(ref cfg) = file_cfg {
        fixed_peers.extend(cfg.runtime.fixed_peers.iter().cloned());
    }
    // Fixed peers are treated as full-history peers and are priority-dialed for
    // catch-up over the peer protocol.
    let mut fixed_addrs: Vec<std::net::SocketAddr> = Vec::new();
    for fp in &fixed_peers {
        let s = normalize_peer_endpoint(fp);
        if let Ok(addr) = s.parse() {
            fixed_addrs.push(addr);
        } else {
            use std::net::ToSocketAddrs;
            match s.to_socket_addrs() {
                Ok(addrs) => {
                    let resolved: Vec<_> = addrs.collect();
                    tracing::info!("resolved fixed peer {} → {} addresses", s, resolved.len());
                    fixed_addrs.extend(resolved);
                }
                Err(e) => {
                    tracing::warn!("failed to resolve fixed peer {}: {}", s, e);
                }
            }
        }
    }
    if !fixed_addrs.is_empty() {
        tracing::info!(
            "ips_fixed: {} peers registered as full-history",
            fixed_addrs.len()
        );
    }
    // Add fixed peers to bootstrap discovery so they are included in the known peers set.
    bootstrap.extend(fixed_addrs.iter());

    // Fall back to built-in public seeds only when no peers are configured.
    if bootstrap.is_empty() {
        use std::net::ToSocketAddrs;
        let hubs = [
            "r.ripple.com:51235",         // Ripple Labs (16 IPs)
            "sahyadri.isrdc.in:51235",    // ISRDC
            "hubs.xrpkuwait.com:51235",   // XRP Kuwait (5 IPs)
            "hub.xrpl-commons.org:51235", // XRPL Commons
            "s1.ripple.com:51235",        // Ripple public server
            "s2.ripple.com:51235",        // Ripple public server
            "169.55.164.20:51235",        // Ripple full-history
            "50.22.123.215:51235",        // Ripple full-history
        ];
        for hub in &hubs {
            match hub.to_socket_addrs() {
                Ok(addrs) => {
                    let resolved: Vec<_> = addrs.collect();
                    tracing::info!("bootstrap: resolved {} → {} addresses", hub, resolved.len());
                    bootstrap.extend(resolved);
                }
                Err(e) => {
                    tracing::warn!("bootstrap: failed to resolve {}: {}", hub, e);
                }
            }
        }
    } else {
        tracing::info!(
            "using {} configured bootstrap peers; skipping built-in public seed fallback",
            bootstrap.len()
        );
    }

    // Crawl the XRPL network — separate full-history nodes from fast general peers.
    // Full-history nodes (complete_ledgers starting from 32570) go into their own list
    // for diff sync. Fast general peers go into bootstrap for live following.
    let mut full_history_peers: Vec<std::net::SocketAddr> = Vec::new();
    if bootstrap.is_empty() {
        use std::net::{SocketAddr, TcpStream};
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        tracing::info!("crawling XRPL network...");

        // Crawl all hubs — collect IPs and identify full-history nodes
        let mut all_ips = std::collections::HashSet::new();
        let mut full_history_ips = std::collections::HashSet::new();
        let crawl_urls = [
            "https://s1.ripple.com:51235/crawl",
            "https://s2.ripple.com:51235/crawl",
            "https://r.ripple.com:51235/crawl",
            "https://sahyadri.isrdc.in:51235/crawl",
            "https://hubs.xrpkuwait.com:51235/crawl",
            "https://hub.xrpl-commons.org:51235/crawl",
            "https://169.55.164.20:51235/crawl",
            "https://50.22.123.215:51235/crawl",
        ];
        for url in &crawl_urls {
            if let Some(peers) = (|| -> Option<Vec<(String, bool)>> {
                let body = std::process::Command::new("curl")
                    .args(["-s", "-m", "5", "--insecure", url])
                    .output()
                    .ok()?;
                let json: serde_json::Value = serde_json::from_slice(&body.stdout).ok()?;
                let active = json.get("overlay")?.get("active")?.as_array()?;
                let mut out = Vec::new();
                for peer in active {
                    if let Some(ip) = peer.get("ip").and_then(|v| v.as_str()) {
                        if !ip.contains(':')
                            && !ip.starts_with("10.")
                            && !ip.starts_with("192.168.")
                        {
                            // Deep history = 100K+ ledger span (~4 days).
            // These peers can serve ledgers needed for catch-up.
                            let is_deep = peer
                                .get("complete_ledgers")
                                .and_then(|v| v.as_str())
                                .map_or(false, |cl| {
                                    if let Some((s, e)) = cl.split_once('-') {
                                        if let (Ok(start), Ok(end)) =
                                            (s.parse::<u64>(), e.parse::<u64>())
                                        {
                                            return end.saturating_sub(start) > 100_000;
                                        }
                                    }
                                    false
                                });
                            out.push((ip.to_string(), is_deep));
                        }
                    }
                }
                Some(out)
            })() {
                let deep_count = peers.iter().filter(|(_, f)| *f).count();
                tracing::info!(
                    "crawl {}: {} peers ({} deep-history)",
                    url,
                    peers.len(),
                    deep_count
                );
                for (ip, is_deep) in peers {
                    all_ips.insert(ip.clone());
                    if is_deep {
                        full_history_ips.insert(ip);
                    }
                }
            }
        }

        // TCP probe ALL crawled IPs — measure latency
        let crawl_ips: Vec<String> = all_ips.into_iter().collect();
        if !crawl_ips.is_empty() {
            tracing::info!("TCP probing {} peers on port 51235...", crawl_ips.len());
            let results: Arc<Mutex<Vec<(Duration, SocketAddr, bool)>>> =
                Arc::new(Mutex::new(Vec::new()));
            let mut handles = Vec::new();

            for ip in &crawl_ips {
                let addr_str = format!("{}:51235", ip);
                let is_deep = full_history_ips.contains(ip);
                if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                    let results = results.clone();
                    handles.push(std::thread::spawn(move || {
                        let start = Instant::now();
                        if TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok() {
                            results.lock().unwrap_or_else(|e| e.into_inner()).push((
                                start.elapsed(),
                                addr,
                                is_deep,
                            ));
                        }
                    }));
                }
            }
            for h in handles {
                let _ = h.join();
            }

            let mut probed = results.lock().unwrap_or_else(|e| e.into_inner()).clone();
            probed.sort_by_key(|(d, _, _)| *d);

            // Split into two lists: deep-history (100K+ span, for sync) and fast general (for live)
            let mut fast_general: Vec<SocketAddr> = Vec::new();
            for (_latency, addr, is_deep) in &probed {
                if *is_deep {
                    full_history_peers.push(*addr);
                } else if fast_general.len() < 50 {
                    fast_general.push(*addr);
                }
            }

            if !full_history_peers.is_empty() {
                tracing::info!(
                    "deep-history peers (100K+ ledgers): {} alive (fastest={}ms, slowest={}ms)",
                    full_history_peers.len(),
                    probed
                        .iter()
                        .filter(|(_, _, f)| *f)
                        .next()
                        .map_or(0, |(d, _, _)| d.as_millis()),
                    probed
                        .iter()
                        .filter(|(_, _, f)| *f)
                        .last()
                        .map_or(0, |(d, _, _)| d.as_millis()),
                );
            } else {
                tracing::warn!("no deep-history peers responded to TCP probe");
            }

            if !fast_general.is_empty() {
                tracing::info!(
                    "fast peers: {} (fastest={}ms) — adding to bootstrap",
                    fast_general.len(),
                    probed
                        .iter()
                        .filter(|(_, _, f)| !f)
                        .next()
                        .map_or(0, |(d, _, _)| d.as_millis()),
                );
                bootstrap.extend(fast_general);
            }
        }
    } else {
        tracing::info!("configured peers present; skipping public crawl fallback");
    }

    let peer_addr = if args.peer_addr == "0.0.0.0:51235" {
        file_cfg
            .as_ref()
            .and_then(|cfg| cfg.runtime.peer_addr)
            .unwrap_or(args.peer_addr.parse()?)
    } else {
        args.peer_addr.parse()?
    };
    let rpc_addr = if args.rpc_addr == "127.0.0.1:5005" {
        file_cfg
            .as_ref()
            .and_then(|cfg| cfg.runtime.rpc_addr)
            .unwrap_or(args.rpc_addr.parse()?)
    } else {
        args.rpc_addr.parse()?
    };
    let ws_addr = if args.ws_addr == "127.0.0.1:6006" {
        file_cfg
            .as_ref()
            .and_then(|cfg| cfg.runtime.ws_addr)
            .unwrap_or(args.ws_addr.parse()?)
    } else {
        args.ws_addr.parse()?
    };
    let grpc_addr = if let Some(ref arg_addr) = args.grpc_addr {
        Some(arg_addr.parse()?)
    } else {
        file_cfg.as_ref().and_then(|cfg| cfg.runtime.grpc_addr)
    };
    let max_peers = if args.max_peers == 21 {
        file_cfg
            .as_ref()
            .and_then(|cfg| cfg.runtime.max_peers)
            .unwrap_or(args.max_peers)
    } else {
        args.max_peers
    };
    let data_dir = configured_data_dir.clone();
    let network_id = if args.network_id == 0 {
        file_cfg
            .as_ref()
            .and_then(|cfg| cfg.runtime.network_id)
            .unwrap_or(args.network_id)
    } else {
        args.network_id
    };
    let ledger_history = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.runtime.ledger_history)
        .unwrap_or(HistoryRetention::Count(256));
    let fetch_depth = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.runtime.fetch_depth)
        .unwrap_or(HistoryRetention::Full);
    let online_delete = file_cfg.as_ref().and_then(|cfg| cfg.runtime.online_delete);
    let standalone = if args.standalone {
        true
    } else {
        file_cfg
            .as_ref()
            .and_then(|cfg| cfg.runtime.standalone)
            .unwrap_or(false)
    };
    let enable_consensus_close_loop = if args.enable_consensus_close_loop || standalone {
        true
    } else {
        file_cfg
            .as_ref()
            .and_then(|cfg| cfg.runtime.enable_consensus_close_loop)
            .unwrap_or(false)
    };

    let config = NodeConfig {
        peer_addr,
        rpc_addr,
        ws_addr,
        max_peers,
        bootstrap,
        use_tls: true,
        data_dir,
        config_file: config_file_path,
        network_id,
        max_sync: args.max_sync,
        rpc_sync: args.rpc_sync.or_else(|| {
            file_cfg
                .as_ref()
                .and_then(|cfg| cfg.runtime.rpc_sync.clone())
        }),
        full_history_peers: {
            let mut fhp = full_history_peers;
            fhp.extend(fixed_addrs.iter());
            fhp.sort();
            fhp.dedup();
            fhp
        },
        ledger_history,
        fetch_depth,
        online_delete,
        standalone,
        enable_consensus_close_loop,
        post_sync_checkpoint_script: file_cfg
            .as_ref()
            .and_then(|cfg| cfg.runtime.post_sync_checkpoint_script.clone()),
        validation_seed: file_cfg
            .as_ref()
            .and_then(|cfg| cfg.validation_seed.clone()),
    };

    let test_one = args.test_one_ledger;
    let test_seq = args.test_seq;
    let test_source = args.test_source.clone();
    let test_cache = args.test_cache.clone();
    let test_skip = (
        args.test_skip_creates,
        args.test_skip_modifies,
        args.test_skip_deletes,
    );

    info!(
        peer_addr = %config.peer_addr,
        rpc_addr  = %config.rpc_addr,
        grpc_addr = ?grpc_addr,
        max_peers = config.max_peers,
        "xledgrs starting"
    );

    // Dump object mode
    if let Some(ref key_hex) = args.dump_object {
        let data_dir = config.data_dir.as_ref().expect("--data-dir required");
        let _storage = xrpl::storage::Storage::open(data_dir).unwrap();
        let _key_bytes = hex::decode(key_hex).expect("invalid hex key");
        // Object store removed (was RocksDB) — objects live in NuDB now
        println!("NOT FOUND (object store removed — use NuDB nodestore)");
        return Ok(());
    }

    // Verify hash mode: definitive test of leaf_hash + SparseSHAMap
    if args.verify_hash {
        let endpoint = config
            .rpc_sync
            .as_ref()
            .expect("--rpc-sync required for --verify-hash");
        let (host, port) = {
            let parts: Vec<&str> = endpoint.splitn(2, ':').collect();
            (
                parts[0].to_string(),
                parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(5005u16),
            )
        };
        return xrpl::diagnose::verify_hash_live(&host, port).await;
    }

    // Diagnose mode: verify stored state integrity
    if args.diagnose {
        let data_dir = config
            .data_dir
            .as_ref()
            .expect("--data-dir required for --diagnose");
        let storage = std::sync::Arc::new(xrpl::storage::Storage::open(data_dir).unwrap());
        return xrpl::diagnose::run_diagnose(storage, config.rpc_sync).await;
    }

    // Compact mode: prune NuDB to only live state tree nodes
    if args.compact {
        let data_dir = config
            .data_dir
            .as_ref()
            .expect("--data-dir required for --compact");
        let nodestore_dir = data_dir.join("nodestore");
        if !nodestore_dir.exists() {
            tracing::error!("NuDB nodestore not found at {:?}", nodestore_dir);
            return Ok(());
        }

        // Load the root hash from storage metadata.
        let storage = xrpl::storage::Storage::open(data_dir).expect("failed to open storage");
        let (ledger_seq, root_hash) = match storage.load_meta() {
            Ok((seq, _hash_hex, header)) => {
                tracing::info!(
                    "compacting state for ledger {} (account_hash={})",
                    seq,
                    hex::encode_upper(&header.account_hash[..8])
                );
                (seq, header.account_hash)
            }
            Err(e) => {
                tracing::error!("failed to load ledger header: {e}");
                return Ok(());
            }
        };

        let compact_dir = nodestore_dir.with_extension("compact");
        if compact_dir.exists() {
            tracing::warn!("removing stale compact directory at {:?}", compact_dir);
            std::fs::remove_dir_all(&compact_dir)?;
        }

        let source_count;
        let result = {
            let store = std::sync::Arc::new(
                xrpl::ledger::node_store::NuDBNodeStore::open(&nodestore_dir)
                    .expect("failed to open NuDB"),
            ) as std::sync::Arc<dyn xrpl::ledger::node_store::NodeStore>;
            source_count = store.count();

            tracing::info!(
                "compacting NuDB from root hash: source={:?} target={:?}",
                nodestore_dir,
                compact_dir
            );
            xrpl::ledger::prune::compact_nodestore(&store, root_hash, &compact_dir)?
        };

        let verified = {
            let compact_store = std::sync::Arc::new(
                xrpl::ledger::node_store::NuDBNodeStore::open(&compact_dir)
                    .expect("failed to open compacted NuDB"),
            )
                as std::sync::Arc<dyn xrpl::ledger::node_store::NodeStore>;
            xrpl::ledger::prune::verify_nodestore(&compact_store, root_hash)?
        };

        if verified.total != result.total
            || verified.inner_nodes != result.inner_nodes
            || verified.leaf_nodes != result.leaf_nodes
        {
            tracing::error!(
                "compaction verification mismatch: copied={} ({} inner, {} leaf) verified={} ({} inner, {} leaf)",
                result.total,
                result.inner_nodes,
                result.leaf_nodes,
                verified.total,
                verified.inner_nodes,
                verified.leaf_nodes
            );
            return Ok(());
        }

        match xrpl::ledger::prune::swap_compacted_nodestore(&nodestore_dir, &compact_dir) {
            Ok(backup_dir) => {
                tracing::info!(
                    "compact+swap complete for ledger {}: live={} ({} inner, {} leaf), source_count={} backup={:?}",
                    ledger_seq,
                    verified.total,
                    verified.inner_nodes,
                    verified.leaf_nodes,
                    source_count,
                    backup_dir
                );
                tracing::info!(
                    "restart the validator using {:?}; keep {:?} until startup succeeds, then remove it manually",
                    nodestore_dir,
                    backup_dir
                );
            }
            Err(e) => {
                tracing::error!("failed to swap compacted NuDB into place: {e}");
            }
        }
        return Ok(());
    }

    // Test mode: apply one ledger, check hash, exit
    if test_one {
        let data_dir = config
            .data_dir
            .as_ref()
            .expect("--data-dir required for test mode");
        let (host, port) = {
            let parts: Vec<&str> = test_source.splitn(2, ':').collect();
            (
                parts[0].to_string(),
                parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(51234),
            )
        };
        return xrpl::ledger::follow::test_one_ledger(
            data_dir, &host, port, test_seq, test_cache, test_skip,
        )
        .await;
    }

    let _pid_guard = process_control::install_pid_guard_if_needed(control_request, &control_files)?;
    let node = Arc::new(Node::new(config));
    let storage = node.storage().cloned();
    node.clone().start().await?;
    let grpc_runtime = if let Some(addr) = grpc_addr {
        Some(grpc::GrpcRuntime::spawn(node.clone(), addr).await?)
    } else {
        None
    };

    // Wait for SIGINT (ctrl-c) or SIGTERM (kill)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }

    // Graceful shutdown — signal all background tasks to exit
    info!("shutting down...");
    node.signal_shutdown();
    if let Some(grpc_runtime) = grpc_runtime {
        grpc_runtime.shutdown().await;
    }
    // Brief wait for background tasks to notice the flag and exit
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Save sync inner nodes so tree walk can resume on restart
    {
        let sync_guard = node.sync_lock();
        if let Some(ref guard) = sync_guard {
            if let Some(ref syncer) = **guard {
                // Inner nodes stored in NuDB — no export needed
                if let Some(ref store) = storage {
                    let _ = store.save_leaf_count(syncer.leaf_count() as u64);
                    info!("shutdown: saved leaf count");
                }
            }
        }
    }

    // Save current ledger header so follower can resume with prev_header
    {
        let state = node.state_ref().read().await;
        if let Some(ref store) = storage {
            let _ = store.save_meta(
                state.ctx.ledger_seq,
                &state.ctx.ledger_hash,
                &state.ctx.ledger_header,
            );
            info!("shutdown: saved ledger {} header", state.ctx.ledger_seq);
        }
    }

    // Flush storage — checkpoints SQLite
    if let Some(ref store) = storage {
        if let Err(e) = store.flush() {
            tracing::error!("flush error: {e}");
        }
    }
    info!("clean shutdown complete");
    Ok(())
}

fn normalize_peer_endpoint(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.contains(':') {
        return trimmed.to_string();
    }
    let mut parts = trimmed.split_whitespace();
    let Some(host) = parts.next() else {
        return String::new();
    };
    let Some(port) = parts.next() else {
        return trimmed.to_string();
    };
    if parts.next().is_some() {
        return trimmed.to_string();
    }
    format!("{host}:{port}")
}

#[cfg(test)]
mod tests {
    use super::normalize_peer_endpoint;

    #[test]
    fn normalize_peer_endpoint_accepts_rippled_style_host_port() {
        assert_eq!(
            normalize_peer_endpoint("r.ripple.com 51235"),
            "r.ripple.com:51235"
        );
        assert_eq!(
            normalize_peer_endpoint("169.55.164.20 51235"),
            "169.55.164.20:51235"
        );
        assert_eq!(
            normalize_peer_endpoint("s1.ripple.com:51235"),
            "s1.ripple.com:51235"
        );
    }
}
