//! xLedgRS purpose: Mod support for JSON-RPC and WebSocket APIs.
//! JSON-RPC and WebSocket APIs for supported rippled-compatible requests.
//!
//! Unsupported methods and transaction types return explicit errors rather than
//! silently claiming full rippled coverage.
//!
//! Each method lives in its own submodule. This file provides the dispatcher
//! that routes incoming requests to the appropriate handler.

pub mod handlers;
pub mod path_requests;
pub mod types;
pub mod ws;

pub use types::{RpcError, RpcRequest, RpcResponse};

#[derive(Debug, Clone, Default)]
pub struct LogLevels {
    pub base: String,
    pub partitions: std::collections::BTreeMap<String, String>,
}

static LOG_LEVELS: std::sync::OnceLock<std::sync::Mutex<LogLevels>> = std::sync::OnceLock::new();
static LOG_LEVEL_RELOAD: std::sync::OnceLock<
    std::sync::Mutex<
        Option<
            tracing_subscriber::reload::Handle<
                tracing_subscriber::filter::LevelFilter,
                tracing_subscriber::Registry,
            >,
        >,
    >,
> = std::sync::OnceLock::new();

fn log_levels_state() -> &'static std::sync::Mutex<LogLevels> {
    LOG_LEVELS.get_or_init(|| {
        std::sync::Mutex::new(LogLevels {
            base: "info".to_string(),
            partitions: std::collections::BTreeMap::new(),
        })
    })
}

fn log_reload_state() -> &'static std::sync::Mutex<
    Option<
        tracing_subscriber::reload::Handle<
            tracing_subscriber::filter::LevelFilter,
            tracing_subscriber::Registry,
        >,
    >,
> {
    LOG_LEVEL_RELOAD.get_or_init(|| std::sync::Mutex::new(None))
}

pub fn install_log_reload_handle(
    handle: tracing_subscriber::reload::Handle<
        tracing_subscriber::filter::LevelFilter,
        tracing_subscriber::Registry,
    >,
) {
    *log_reload_state().lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
}

pub fn current_log_levels() -> LogLevels {
    log_levels_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

pub fn set_log_level(partition: Option<&str>, severity: &str) -> Result<(), ()> {
    let normalized = severity.to_ascii_lowercase();
    let level = match normalized.as_str() {
        "trace" => tracing_subscriber::filter::LevelFilter::TRACE,
        "debug" => tracing_subscriber::filter::LevelFilter::DEBUG,
        "info" => tracing_subscriber::filter::LevelFilter::INFO,
        "warn" | "warning" => tracing_subscriber::filter::LevelFilter::WARN,
        "error" | "fatal" => tracing_subscriber::filter::LevelFilter::ERROR,
        _ => return Err(()),
    };

    let mut levels = log_levels_state().lock().unwrap_or_else(|e| e.into_inner());
    match partition.map(|p| p.to_ascii_lowercase()) {
        None => {
            levels.base = normalized.clone();
            if let Some(handle) = log_reload_state()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                let _ = handle.reload(level);
            }
        }
        Some(partition) if partition == "base" => {
            levels.base = normalized.clone();
            if let Some(handle) = log_reload_state()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                let _ = handle.reload(level);
            }
        }
        Some(partition) => {
            levels.partitions.insert(partition, normalized);
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PeerSummary {
    pub address: String,
    pub status: String,
    pub inbound: Option<bool>,
    pub latency: Option<u32>,
    pub ledger: Option<String>,
    pub protocol: Option<String>,
    pub public_key: Option<String>,
    pub version: Option<String>,
    pub cluster: Option<crate::network::cluster::ClusterPeerSummary>,
}

#[derive(Debug, Clone)]
pub struct FetchInfoSnapshot {
    pub key: String,
    pub hash: String,
    pub have_header: bool,
    pub have_state: bool,
    pub have_transactions: bool,
    pub needed_state_hashes: Vec<String>,
    pub backend_fetch_errors: usize,
    pub peers: usize,
    pub timeouts: u32,
    pub in_flight: usize,
    pub inner_nodes: usize,
    pub state_nodes: usize,
    pub pass: u32,
    pub new_objects: usize,
    pub tail_stuck_hash: Option<String>,
    pub tail_stuck_retries: u32,
}

#[derive(Debug, Clone)]
pub struct ConsensusInfoSnapshot {
    pub ledger_seq: u32,
    pub phase: String,
    pub mode: String,
    pub consensus: String,
    pub proposers: usize,
    pub validations: usize,
    pub disputes: usize,
    pub quorum: u32,
    pub converge_percent: u32,
    pub elapsed_ms: u64,
    pub previous_ledger: String,
    pub our_position: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BlacklistEntry {
    pub address: String,
    pub reason: String,
    pub expires_in_ms: u64,
}

#[derive(Debug, Clone)]
pub struct TxRelayMetricsSnapshot {
    pub queued_transactions: usize,
    pub peer_count: usize,
    pub max_queue_size: usize,
    pub escalation_multiplier: u64,
    pub txns_expected: u64,
    pub candidate_set_hash: String,
    pub tracked_transactions: usize,
    pub submitted_transactions: u64,
    pub inbound_tracked: usize,
    pub accepted_transactions: u64,
    pub duplicate_transactions: u64,
    pub relayed_transactions: u64,
    pub persisted_transactions: u64,
}

/// Returns true if this RPC method needs write access (mutates tx_pool/broadcast_queue).
pub fn needs_write(method: &str) -> bool {
    matches!(
        method,
        "ledger_accept"
            | "ledger_cleaner"
            | "peer_reservations_add"
            | "peer_reservations_del"
            | "can_delete"
            | "connect"
            | "fetch_info"
            | "log_level"
            | "stop"
            | "submit"
            | "submit_multisigned"
    )
}

/// Returns true if this RPC method is admin-only and should never be exposed on public RPC.
pub fn needs_admin(method: &str) -> bool {
    matches!(
        method,
        "blacklist"
            | "can_delete"
            | "channel_authorize"
            | "connect"
            | "consensus_info"
            | "fetch_info"
            | "get_counts"
            | "ledger_accept"
            | "ledger_cleaner"
            | "ledger_request"
            | "log_level"
            | "logrotate"
            | "peers"
            | "peer_reservations_add"
            | "peer_reservations_del"
            | "peer_reservations_list"
            | "print"
            | "sign"
            | "sign_for"
            | "stop"
            | "submit"
            | "submit_multisigned"
            | "unl_list"
            | "validation_create"
            | "validator_info"
            | "validator_list_sites"
            | "validators"
            | "wallet_propose"
    )
}

fn ensure_method_allowed(method: &str, ctx: &NodeContext) -> Result<(), RpcError> {
    if needs_admin(method) && !ctx.admin_rpc_enabled {
        return Err(RpcError::forbidden(
            "Admin RPC method is disabled unless all RPC endpoints are bound to loopback.",
        ));
    }
    Ok(())
}

/// Route a read-only request. All handlers except submit work with &NodeContext.
pub fn dispatch_read(req: RpcRequest, ctx: &NodeContext) -> RpcResponse {
    let method = req.method.clone();
    if let Err(e) = ensure_method_allowed(&method, ctx) {
        return RpcResponse::err(e, req.id);
    }
    let result = match req.method.as_str() {
        "server_info" => handlers::server_info(ctx),
        "server_state" => handlers::server_state(ctx),
        "ping" => handlers::ping(),
        "storage_info" => handlers::storage_info(ctx),
        "account_info" => handlers::account_info(&req.params, ctx),
        "account_lines" => handlers::account_lines(&req.params, ctx),
        "account_offers" => handlers::account_offers(&req.params, ctx),
        "account_tx" => handlers::account_tx(&req.params, ctx),
        "book_offers" => handlers::book_offers(&req.params, ctx),
        "book_changes" => handlers::book_changes(&req.params, ctx),
        "blacklist" => handlers::blacklist(&req.params, ctx),
        "consensus_info" => handlers::consensus_info(ctx),
        "channel_authorize" => handlers::channel_authorize(&req.params, ctx),
        "channel_verify" => handlers::channel_verify(&req.params),
        "fee" => handlers::fee(ctx),
        "fetch_info" => handlers::fetch_info(&req.params, ctx),
        "feature" => handlers::feature(&req.params, ctx),
        "gateway_balances" => handlers::gateway_balances(&req.params, ctx),
        "get_counts" => handlers::get_counts(ctx),
        "get_aggregate_price" => handlers::get_aggregate_price(&req.params, ctx),
        "ledger_data" => handlers::ledger_data(&req.params, ctx),
        "ledger_accept" => handlers::ledger_accept(ctx),
        "ledger_cleaner" => handlers::ledger_cleaner(&req.params, ctx),
        "ledger_header" => handlers::ledger_header(&req.params, ctx),
        "ledger_request" => handlers::ledger_request(&req.params, ctx),
        "log_level" => handlers::log_level(&req.params),
        "logrotate" => handlers::logrotate(ctx),
        "manifest" => handlers::manifest(&req.params, ctx),
        "peers" => handlers::peers(ctx),
        "peer_reservations_list" => handlers::peer_reservations_list(ctx),
        "print" => handlers::print(&req.params, ctx),
        "noripple_check" => handlers::noripple_check(&req.params, ctx),
        "path_find" => handlers::path_find(&req.params, &req.id, ctx),
        "sign" => handlers::sign(&req.params, ctx),
        "sign_for" => handlers::sign_for(&req.params, ctx),
        "ripple_path_find" => handlers::ripple_path_find(&req.params, ctx),
        "simulate" => handlers::simulate(&req.params, ctx),
        "server_definitions" => handlers::server_definitions(&req.params),
        "subscribe" => ws::subscription_change_snapshot(&req.params, ctx, true),
        "transaction_entry" => handlers::transaction_entry(&req.params, ctx),
        "tx" => handlers::tx(&req.params, ctx),
        "tx_history" => handlers::tx_history(&req.params, ctx),
        "tx_reduce_relay" => handlers::tx_reduce_relay(ctx),
        "unl_list" => handlers::unl_list(ctx),
        "unsubscribe" => ws::subscription_change_snapshot(&req.params, ctx, false),
        "validator_info" => handlers::validator_info(ctx),
        "validator_list_sites" => handlers::validator_list_sites(ctx),
        "validators" => handlers::validators(ctx),
        "vault_info" => handlers::vault_info(&req.params, ctx),
        "version" => handlers::version(),
        "ledger" => handlers::ledger(&req.params, ctx),
        "ledger_entry" => handlers::ledger_entry(&req.params, ctx),
        "account_objects" => handlers::account_objects(&req.params, ctx),
        "account_nfts" => handlers::account_nfts(&req.params, ctx),
        "account_channels" => handlers::account_channels(&req.params, ctx),
        "account_currencies" => handlers::account_currencies(&req.params, ctx),
        "amm_info" => handlers::amm_info(&req.params, ctx),
        "random" => handlers::random(),
        "ledger_closed" => handlers::ledger_closed(ctx),
        "ledger_current" => handlers::ledger_current(ctx),
        "nft_buy_offers" => handlers::nft_buy_offers(&req.params, ctx),
        "nft_sell_offers" => handlers::nft_sell_offers(&req.params, ctx),
        "owner_info" => handlers::owner_info(&req.params, ctx),
        "deposit_authorized" => handlers::deposit_authorized(&req.params, ctx),
        "validation_create" => handlers::validation_create(&req.params),
        "wallet_propose" => handlers::wallet_propose(&req.params),
        other => Err(RpcError::unknown_method(other)),
    };
    let id = req.id;
    match result {
        Ok(r) => RpcResponse::ok(r, id),
        Err(e) => RpcResponse::err(e, id),
    }
}

/// Lock-free snapshot of RPC-visible state.
/// Updated atomically via ArcSwap — readers never block.
#[derive(Debug, Clone)]
pub struct RpcSnapshot {
    pub ledger_seq: u32,
    pub ledger_hash: String,
    pub ledger_header: crate::ledger::LedgerHeader,
    pub fees: crate::ledger::Fees,
    pub peer_count: usize,
    pub object_count: usize,
    pub leaf_count: usize,
    pub build_version: &'static str,
    pub network_id: u32,
    pub standalone_mode: bool,
    pub start_time: std::time::Instant,
    pub memory_mb: usize,
    pub complete_ledgers: String,
    pub sync_done: bool,
    pub follower_healthy: bool,
    pub validation_quorum: u32,
    /// Lightweight load/stall snapshot used by status RPCs.
    pub load_snapshot: crate::network::load::LoadSnapshot,
    /// rippled-style state accounting for operating-mode transitions.
    pub state_accounting_snapshot: Option<crate::network::ops::StateAccountingSnapshot>,
    /// Node identity public key (base58 n... format).
    pub pubkey_node: String,
    /// Validator signing key (base58 n... format), empty if observer.
    pub validator_key: String,
}

impl Default for RpcSnapshot {
    fn default() -> Self {
        Self {
            ledger_seq: 0,
            ledger_hash: "0".repeat(64),
            ledger_header: Default::default(),
            fees: crate::ledger::Fees::default(),
            peer_count: 0,
            object_count: 0,
            leaf_count: 0,
            build_version: env!("CARGO_PKG_VERSION"),
            network_id: 0,
            standalone_mode: false,
            start_time: std::time::Instant::now(),
            memory_mb: 0,
            complete_ledgers: String::new(),
            sync_done: false,
            follower_healthy: true,
            validation_quorum: 0,
            load_snapshot: crate::network::load::LoadSnapshot::default(),
            state_accounting_snapshot: None,
            pubkey_node: String::new(),
            validator_key: String::new(),
        }
    }
}

/// Route a parsed request to the correct handler and return a response.
pub fn dispatch(req: RpcRequest, ctx: &mut NodeContext) -> RpcResponse {
    let method = req.method.clone();
    if let Err(e) = ensure_method_allowed(&method, ctx) {
        return RpcResponse::err(e, req.id);
    }
    let result = match req.method.as_str() {
        "server_info" => handlers::server_info(ctx),
        "ping" => handlers::ping(),
        "storage_info" => handlers::storage_info(ctx),
        "account_info" => handlers::account_info(&req.params, ctx),
        "account_lines" => handlers::account_lines(&req.params, ctx),
        "account_offers" => handlers::account_offers(&req.params, ctx),
        "account_tx" => handlers::account_tx(&req.params, ctx),
        "book_offers" => handlers::book_offers(&req.params, ctx),
        "book_changes" => handlers::book_changes(&req.params, ctx),
        "blacklist" => handlers::blacklist(&req.params, ctx),
        "can_delete" => handlers::can_delete(&req.params, ctx),
        "channel_authorize" => handlers::channel_authorize(&req.params, ctx),
        "channel_verify" => handlers::channel_verify(&req.params),
        "connect" => handlers::connect(&req.params, ctx),
        "consensus_info" => handlers::consensus_info(ctx),
        "fee" => handlers::fee(ctx),
        "fetch_info" => handlers::fetch_info(&req.params, ctx),
        "feature" => handlers::feature(&req.params, ctx),
        "gateway_balances" => handlers::gateway_balances(&req.params, ctx),
        "get_counts" => handlers::get_counts(ctx),
        "get_aggregate_price" => handlers::get_aggregate_price(&req.params, ctx),
        "ledger_data" => handlers::ledger_data(&req.params, ctx),
        "ledger_accept" => handlers::ledger_accept(ctx),
        "ledger_cleaner" => handlers::ledger_cleaner(&req.params, ctx),
        "ledger_header" => handlers::ledger_header(&req.params, ctx),
        "ledger_request" => handlers::ledger_request(&req.params, ctx),
        "log_level" => handlers::log_level(&req.params),
        "logrotate" => handlers::logrotate(ctx),
        "manifest" => handlers::manifest(&req.params, ctx),
        "peers" => handlers::peers(ctx),
        "peer_reservations_add" => handlers::peer_reservations_add(&req.params, ctx),
        "peer_reservations_del" => handlers::peer_reservations_del(&req.params, ctx),
        "peer_reservations_list" => handlers::peer_reservations_list(ctx),
        "print" => handlers::print(&req.params, ctx),
        "noripple_check" => handlers::noripple_check(&req.params, ctx),
        "path_find" => handlers::path_find(&req.params, &req.id, ctx),
        "sign" => handlers::sign(&req.params, ctx),
        "sign_for" => handlers::sign_for(&req.params, ctx),
        "ripple_path_find" => handlers::ripple_path_find(&req.params, ctx),
        "simulate" => handlers::simulate(&req.params, ctx),
        "server_definitions" => handlers::server_definitions(&req.params),
        "subscribe" => ws::subscription_change_snapshot(&req.params, ctx, true),
        "submit" | "submit_multisigned" => handlers::submit(&req.params, ctx),
        "transaction_entry" => handlers::transaction_entry(&req.params, ctx),
        "tx" => handlers::tx(&req.params, ctx),
        "tx_history" => handlers::tx_history(&req.params, ctx),
        "tx_reduce_relay" => handlers::tx_reduce_relay(ctx),
        "unl_list" => handlers::unl_list(ctx),
        "unsubscribe" => ws::subscription_change_snapshot(&req.params, ctx, false),
        "validator_info" => handlers::validator_info(ctx),
        "validator_list_sites" => handlers::validator_list_sites(ctx),
        "validators" => handlers::validators(ctx),
        "vault_info" => handlers::vault_info(&req.params, ctx),
        "version" => handlers::version(),
        "ledger" => handlers::ledger(&req.params, ctx),
        "ledger_entry" => handlers::ledger_entry(&req.params, ctx),
        "account_objects" => handlers::account_objects(&req.params, ctx),
        "account_nfts" => handlers::account_nfts(&req.params, ctx),
        "account_channels" => handlers::account_channels(&req.params, ctx),
        "account_currencies" => handlers::account_currencies(&req.params, ctx),
        "amm_info" => handlers::amm_info(&req.params, ctx),
        "random" => handlers::random(),
        "server_state" => handlers::server_state(ctx),
        "ledger_closed" => handlers::ledger_closed(ctx),
        "ledger_current" => handlers::ledger_current(ctx),
        "nft_buy_offers" => handlers::nft_buy_offers(&req.params, ctx),
        "nft_sell_offers" => handlers::nft_sell_offers(&req.params, ctx),
        "owner_info" => handlers::owner_info(&req.params, ctx),
        "stop" => handlers::stop(ctx),
        "deposit_authorized" => handlers::deposit_authorized(&req.params, ctx),
        "validation_create" => handlers::validation_create(&req.params),
        "wallet_propose" => handlers::wallet_propose(&req.params),
        other => Err(RpcError::unknown_method(other)),
    };

    match result {
        Ok(v) => RpcResponse::ok(v, req.id),
        Err(e) => RpcResponse::err(e, req.id),
    }
}

/// Shared node state passed to every handler.
#[derive(Clone)]
pub struct NodeContext {
    pub network: &'static str,
    pub network_id: u32,
    pub build_version: &'static str,
    pub start_time: std::time::Instant,
    /// Sequence number of the latest validated ledger.
    pub ledger_seq: u32,
    /// Hash of the latest validated ledger (hex).
    pub ledger_hash: String,
    /// Network fee parameters (from FeeSettings SLE).
    pub fees: crate::ledger::Fees,
    /// Live account state for the latest validated ledger.
    /// Behind its own Mutex so the follower can lock it independently from SharedState.
    pub ledger_state: std::sync::Arc<std::sync::Mutex<crate::ledger::LedgerState>>,
    /// Transaction pool — validated txs waiting for the next ledger close.
    /// Behind Arc<RwLock> so the RPC read path shares live data instead of cloning.
    pub tx_pool: std::sync::Arc<std::sync::RwLock<crate::ledger::TxPool>>,
    /// The current ledger header (updated after each close).
    pub ledger_header: crate::ledger::LedgerHeader,
    /// Closed ledger history and transaction index.
    /// Behind Arc<RwLock> so the RPC read path shares live data instead of cloning.
    pub history: std::sync::Arc<std::sync::RwLock<crate::ledger::LedgerStore>>,
    /// Messages queued for broadcast to peers (drained by the RPC handler).
    pub broadcast_queue: Vec<crate::network::message::RtxpMessage>,
    /// Enabled amendments (feature flags).
    pub amendments: std::collections::HashSet<String>,
    /// Number of currently connected peers (updated before RPC dispatch).
    pub peer_count: usize,
    /// Number of persisted content-addressed nodestore objects.
    pub object_count: usize,
    /// Node identity public key (base58 n... format).
    pub pubkey_node: String,
    /// Validator signing key (base58 n... format), empty if observer.
    pub validator_key: String,
    /// Lightweight peer summaries for admin inspection RPCs.
    pub peer_summaries: Vec<PeerSummary>,
    /// Snapshot of the current state-sync fetch, if any.
    pub fetch_info: Option<FetchInfoSnapshot>,
    /// Snapshot of the current consensus round, if one is active.
    pub consensus_info: Option<ConsensusInfoSnapshot>,
    /// Request flag for admin `fetch_info` clear=true calls.
    pub sync_clear_requested: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Pending peer connect requests submitted through admin RPC.
    pub connect_requests: Option<std::sync::Arc<std::sync::Mutex<Vec<std::net::SocketAddr>>>>,
    /// Shutdown request flag submitted through admin RPC.
    pub shutdown_requested: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Force the next open ledger round to close immediately.
    pub force_ledger_accept: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Standalone/local ledger accept request coordinator.
    pub ledger_accept_service: Option<std::sync::Arc<crate::ledger::control::LedgerAcceptService>>,
    /// Current online-delete keep window, if configured.
    pub online_delete: Option<u32>,
    /// Current `can_delete` advisory target.
    pub can_delete_target: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// Background ledger cleaner service used by admin RPC.
    pub ledger_cleaner: Option<std::sync::Arc<crate::ledger::control::LedgerCleanerService>>,
    /// Standalone mode matches rippled's local-only control plane behavior.
    pub standalone_mode: bool,
    /// Admin-only RPC methods (`sign`, `sign_for`, `submit`) are allowed only
    /// when all RPC endpoints are loopback-bound.
    pub admin_rpc_enabled: bool,
    /// Persistent storage reference for fallback lookups (mainnet state).
    pub storage: Option<std::sync::Arc<crate::storage::Storage>>,
    /// RPC sync progress (when --rpc-sync is active).
    pub rpc_sync_state: Option<std::sync::Arc<crate::rpc_sync::RpcSyncState>>,
    /// Ledger follower progress.
    pub follower_state: Option<std::sync::Arc<crate::ledger::follow::FollowerState>>,
    /// Live validator list manager for admin inspection methods.
    pub validator_list_manager:
        Option<std::sync::Arc<std::sync::Mutex<crate::validator_list::ValidatorListManager>>>,
    /// Shared manifest cache populated from peer manifests.
    pub manifest_cache: Option<std::sync::Arc<std::sync::Mutex<crate::consensus::ManifestCache>>>,
    /// Configured validator list sites.
    pub validator_list_sites: Vec<String>,
    /// Per-site validator list refresh status for admin inspection.
    pub validator_site_statuses: Option<
        std::sync::Arc<
            std::sync::Mutex<
                std::collections::HashMap<String, crate::validator_list::ValidatorSiteStatus>,
            >,
        >,
    >,
    /// Admin-maintained peer reservations keyed by node public key.
    pub peer_reservations:
        Option<std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>>,
    /// Lightweight peerfinder snapshot for admin inspection.
    pub peerfinder_snapshot: Option<crate::network::peerfinder::PeerfinderSnapshot>,
    /// Lightweight cluster snapshot for admin inspection.
    pub cluster_snapshot: Option<crate::network::cluster::ClusterSnapshot>,
    /// Lightweight resource-manager snapshot for admin inspection.
    pub resource_snapshot: Option<crate::network::resource::ResourceSnapshot>,
    /// Shared path request registry used by WebSocket path_find.
    pub path_requests:
        Option<std::sync::Arc<std::sync::Mutex<crate::rpc::path_requests::PathRequestManager>>>,
    /// Snapshot of active path requests.
    pub path_request_snapshot: Option<crate::rpc::path_requests::PathRequestSnapshot>,
    /// Live sync debug log handle used by `logrotate`.
    pub debug_log: Option<std::sync::Arc<std::sync::Mutex<Option<std::fs::File>>>>,
    /// Path of the currently active sync debug log file.
    pub debug_log_path: Option<std::sync::Arc<std::sync::Mutex<Option<std::path::PathBuf>>>>,
    /// Snapshot of currently cooled-down / benched peers used by blacklist.
    pub blacklist_entries: Vec<BlacklistEntry>,
    /// Snapshot of relay / queue metrics used by tx_reduce_relay.
    pub tx_relay_metrics: Option<TxRelayMetricsSnapshot>,
    /// Lightweight load/stall snapshot for server status surfaces.
    pub load_snapshot: crate::network::load::LoadSnapshot,
    /// rippled-style state accounting for operating-mode transitions.
    pub state_accounting_snapshot: Option<crate::network::ops::StateAccountingSnapshot>,
    /// Snapshot of recently ingressed network transactions.
    pub inbound_transactions_snapshot:
        Option<crate::ledger::inbound_transactions::InboundTransactionsSnapshot>,
    /// Snapshot of active per-hash inbound ledger acquisitions.
    pub inbound_ledgers_snapshot: Option<crate::ledger::inbound::InboundLedgersSnapshot>,
    /// Snapshot of transaction lifecycle state across network + consensus.
    pub tx_master_snapshot: Option<crate::transaction::master::TxMasterSnapshot>,
    /// Snapshot of validated/open ledger lifecycle.
    pub ledger_master_snapshot: Option<crate::ledger::master::LedgerMasterSnapshot>,
    /// Snapshot of the current open ledger runtime state.
    pub open_ledger_snapshot: Option<crate::ledger::open_ledger::OpenLedgerSnapshot>,
    /// Snapshot of the background ledger cleaner state.
    pub ledger_cleaner_snapshot: Option<crate::ledger::control::LedgerCleanerSnapshot>,
    /// Snapshot of backend NodeStore activity and fault counters.
    pub node_store_snapshot: Option<crate::ledger::node_store::NodeStoreSnapshot>,
    /// Snapshot of the transient fetch-pack overlay used for stale sync reuse.
    pub fetch_pack_snapshot: Option<crate::ledger::fetch_pack::FetchPackSnapshot>,
    /// Lightweight NetworkOPs-style aggregate status snapshot.
    pub network_ops_snapshot: Option<crate::network::ops::NetworkOpsSnapshot>,
    /// The current closed ledger (view-stack based, replaces ledger_state).
    /// RPC handlers should read from this via ReadView methods.
    pub closed_ledger: Option<std::sync::Arc<crate::ledger::ledger_core::ClosedLedger>>,
}

impl Default for NodeContext {
    fn default() -> Self {
        Self {
            network: "mainnet",
            network_id: 0,
            build_version: env!("CARGO_PKG_VERSION"),
            start_time: std::time::Instant::now(),
            ledger_seq: 0,
            ledger_hash: "0".repeat(64),
            fees: crate::ledger::Fees::default(),
            ledger_state: std::sync::Arc::new(std::sync::Mutex::new(
                crate::ledger::LedgerState::new(),
            )),
            tx_pool: std::sync::Arc::new(std::sync::RwLock::new(crate::ledger::TxPool::new())),
            history: std::sync::Arc::new(std::sync::RwLock::new(crate::ledger::LedgerStore::new())),
            broadcast_queue: Vec::new(),
            ledger_header: crate::ledger::LedgerHeader {
                sequence: 0,
                hash: [0u8; 32],
                parent_hash: [0u8; 32],
                close_time: 0,
                total_coins: 100_000_000_000_000_000,
                account_hash: [0u8; 32],
                transaction_hash: [0u8; 32],
                parent_close_time: 0,
                close_time_resolution: 10,
                close_flags: 0,
            },
            amendments: std::collections::HashSet::new(),
            peer_count: 0,
            object_count: 0,
            pubkey_node: String::new(),
            validator_key: String::new(),
            peer_summaries: Vec::new(),
            fetch_info: None,
            consensus_info: None,
            sync_clear_requested: None,
            connect_requests: None,
            shutdown_requested: None,
            force_ledger_accept: None,
            ledger_accept_service: None,
            online_delete: None,
            can_delete_target: None,
            ledger_cleaner: None,
            standalone_mode: false,
            admin_rpc_enabled: false,
            storage: None,
            rpc_sync_state: None,
            follower_state: None,
            validator_list_manager: None,
            manifest_cache: None,
            validator_list_sites: Vec::new(),
            validator_site_statuses: None,
            peer_reservations: None,
            peerfinder_snapshot: None,
            cluster_snapshot: None,
            resource_snapshot: None,
            path_requests: Some(std::sync::Arc::new(std::sync::Mutex::new(
                crate::rpc::path_requests::PathRequestManager::default(),
            ))),
            path_request_snapshot: None,
            debug_log: None,
            debug_log_path: None,
            blacklist_entries: Vec::new(),
            tx_relay_metrics: None,
            load_snapshot: crate::network::load::LoadSnapshot::default(),
            state_accounting_snapshot: None,
            inbound_transactions_snapshot: None,
            inbound_ledgers_snapshot: None,
            tx_master_snapshot: None,
            ledger_master_snapshot: None,
            open_ledger_snapshot: None,
            ledger_cleaner_snapshot: None,
            node_store_snapshot: None,
            fetch_pack_snapshot: None,
            network_ops_snapshot: None,
            closed_ledger: None,
        }
    }
}
