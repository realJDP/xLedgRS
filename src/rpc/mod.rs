//! JSON-RPC API — rippled-compatible request/response handling.
//!
//! Implements the standard rippled RPC surface so existing tools
//! (xrpl.js, xrpl-py, Xumm, etc.) work without modification.
//!
//! Each method lives in its own submodule. This file provides the
//! dispatcher that routes incoming requests to the right handler.

pub mod handlers;
pub mod types;
pub mod ws;

pub use types::{RpcError, RpcRequest, RpcResponse};


/// Returns true if this RPC method needs write access (mutates tx_pool/broadcast_queue).
pub fn needs_write(method: &str) -> bool {
    matches!(method, "submit" | "submit_multisigned")
}

/// Route a read-only request. All handlers except submit work with &NodeContext.
pub fn dispatch_read(req: RpcRequest, ctx: &NodeContext) -> RpcResponse {
    let result = match req.method.as_str() {
        "server_info" | "server_state" => handlers::server_info(ctx),
        "ping"           => handlers::ping(),
        "storage_info"   => handlers::storage_info(ctx),
        "account_info"   => handlers::account_info(&req.params, ctx),
        "account_lines"  => handlers::account_lines(&req.params, ctx),
        "account_offers" => handlers::account_offers(&req.params, ctx),
        "account_tx"     => handlers::account_tx(&req.params, ctx),
        "book_offers"    => handlers::book_offers(&req.params, ctx),
        "fee"            => handlers::fee(ctx),
        "feature"        => handlers::feature(&req.params, ctx),
        "ledger_data"    => handlers::ledger_data(&req.params, ctx),
        "sign"           => handlers::sign(&req.params, ctx),
        "sign_for"       => handlers::sign_for(&req.params, ctx),
        "ripple_path_find" => handlers::ripple_path_find(&req.params, ctx),
        "tx"             => handlers::tx(&req.params, ctx),
        "ledger"         => handlers::ledger(&req.params, ctx),
        "ledger_entry"   => handlers::ledger_entry(&req.params, ctx),
        "account_objects" => handlers::account_objects(&req.params, ctx),
        "account_nfts"   => handlers::account_nfts(&req.params, ctx),
        "account_channels" => handlers::account_channels(&req.params, ctx),
        "account_currencies" => handlers::account_currencies(&req.params, ctx),
        "random"         => handlers::random(),
        "ledger_closed"  => handlers::ledger_closed(ctx),
        "ledger_current" => handlers::ledger_current(ctx),
        "deposit_authorized" => handlers::deposit_authorized(&req.params, ctx),
        other            => Err(RpcError::unknown_method(other)),
    };
    let id = req.id;
    match result {
        Ok(r)  => RpcResponse::ok(r, id),
        Err(e) => RpcResponse::err(e, id),
    }
}

/// Lock-free snapshot of RPC-visible state.
/// Updated atomically via ArcSwap — readers never block.
#[derive(Debug, Clone)]
pub struct RpcSnapshot {
    pub ledger_seq:    u32,
    pub ledger_hash:   String,
    pub ledger_header: crate::ledger::LedgerHeader,
    pub fees:          crate::ledger::Fees,
    pub peer_count:    usize,
    pub object_count:  usize,
    pub build_version: &'static str,
    pub network_id:    u32,
    pub start_time:    std::time::Instant,
    pub memory_mb:     usize,
    pub complete_ledgers: String,
    pub sync_done:     bool,
    pub validation_quorum: u32,
    /// Node identity public key (base58 n... format).
    pub pubkey_node: String,
    /// Validator signing key (base58 n... format), empty if observer.
    pub validator_key: String,
}

impl Default for RpcSnapshot {
    fn default() -> Self {
        Self {
            ledger_seq: 0, ledger_hash: "0".repeat(64),
            ledger_header: Default::default(), fees: crate::ledger::Fees::default(),
            peer_count: 0, object_count: 0,
            build_version: env!("CARGO_PKG_VERSION"),
            network_id: 0, start_time: std::time::Instant::now(),
            memory_mb: 0, complete_ledgers: String::new(),
            sync_done: false, validation_quorum: 0,
            pubkey_node: String::new(), validator_key: String::new(),
        }
    }
}

/// Route a parsed request to the correct handler and return a response.
pub fn dispatch(req: RpcRequest, ctx: &mut NodeContext) -> RpcResponse {
    let result = match req.method.as_str() {
        "server_info"  => handlers::server_info(ctx),
        "ping"         => handlers::ping(),
        "storage_info" => handlers::storage_info(ctx),
        "account_info"  => handlers::account_info(&req.params, ctx),
        "account_lines"   => handlers::account_lines(&req.params, ctx),
        "account_offers"  => handlers::account_offers(&req.params, ctx),
        "account_tx"      => handlers::account_tx(&req.params, ctx),
        "book_offers"     => handlers::book_offers(&req.params, ctx),
        "fee"            => handlers::fee(ctx),
        "feature"        => handlers::feature(&req.params, ctx),
        "ledger_data"    => handlers::ledger_data(&req.params, ctx),
        "sign"               => handlers::sign(&req.params, ctx),
        "sign_for"           => handlers::sign_for(&req.params, ctx),
        "ripple_path_find"   => handlers::ripple_path_find(&req.params, ctx),
        "submit" | "submit_multisigned" => handlers::submit(&req.params, ctx),
        "tx"           => handlers::tx(&req.params, ctx),
        "ledger"       => handlers::ledger(&req.params, ctx),
        "ledger_entry"       => handlers::ledger_entry(&req.params, ctx),
        "account_objects"    => handlers::account_objects(&req.params, ctx),
        "account_nfts"       => handlers::account_nfts(&req.params, ctx),
        "account_channels"   => handlers::account_channels(&req.params, ctx),
        "account_currencies" => handlers::account_currencies(&req.params, ctx),
        "random"             => handlers::random(),
        "server_state"       => handlers::server_info(ctx),
        "ledger_closed"      => handlers::ledger_closed(ctx),
        "ledger_current"     => handlers::ledger_current(ctx),
        "deposit_authorized" => handlers::deposit_authorized(&req.params, ctx),
        other          => Err(RpcError::unknown_method(other)),
    };

    match result {
        Ok(v)  => RpcResponse::ok(v, req.id),
        Err(e) => RpcResponse::err(e, req.id),
    }
}

/// Shared node state passed to every handler.
#[derive(Clone)]
pub struct NodeContext {
    pub network:       &'static str,
    pub network_id:    u32,
    pub build_version: &'static str,
    pub start_time:    std::time::Instant,
    /// Sequence number of the latest validated ledger.
    pub ledger_seq:    u32,
    /// Hash of the latest validated ledger (hex).
    pub ledger_hash:   String,
    /// Network fee parameters (from FeeSettings SLE).
    pub fees:          crate::ledger::Fees,
    /// Live account state for the latest validated ledger.
    /// Behind its own Mutex so the follower can lock it independently from SharedState.
    pub ledger_state:  std::sync::Arc<std::sync::Mutex<crate::ledger::LedgerState>>,
    /// Transaction pool — validated txs waiting for the next ledger close.
    /// Behind Arc<RwLock> so the RPC read path shares live data instead of cloning.
    pub tx_pool:       std::sync::Arc<std::sync::RwLock<crate::ledger::TxPool>>,
    /// The current ledger header (updated after each close).
    pub ledger_header: crate::ledger::LedgerHeader,
    /// Closed ledger history and transaction index.
    /// Behind Arc<RwLock> so the RPC read path shares live data instead of cloning.
    pub history:         std::sync::Arc<std::sync::RwLock<crate::ledger::LedgerStore>>,
    /// Messages queued for broadcast to peers (drained by the RPC handler).
    pub broadcast_queue: Vec<crate::network::message::RtxpMessage>,
    /// Enabled amendments (feature flags).
    pub amendments: std::collections::HashSet<String>,
    /// Number of currently connected peers (updated before RPC dispatch).
    pub peer_count: usize,
    /// Number of objects in persistent storage (redb).
    pub object_count: usize,
    /// Persistent storage reference for fallback lookups (mainnet state).
    pub storage: Option<std::sync::Arc<crate::storage::Storage>>,
    /// RPC sync progress (when --rpc-sync is active).
    pub rpc_sync_state: Option<std::sync::Arc<crate::rpc_sync::RpcSyncState>>,
    /// Ledger follower progress.
    pub follower_state: Option<std::sync::Arc<crate::ledger::follow::FollowerState>>,
    /// The current closed ledger (view-stack based, replaces ledger_state).
    /// RPC handlers should read from this via ReadView methods.
    pub closed_ledger: Option<std::sync::Arc<crate::ledger::ledger_core::ClosedLedger>>,
}

impl Default for NodeContext {
    fn default() -> Self {
        Self {
            network:       "mainnet",
            network_id:    0,
            build_version: env!("CARGO_PKG_VERSION"),
            start_time:    std::time::Instant::now(),
            ledger_seq:    0,
            ledger_hash:   "0".repeat(64),
            fees:          crate::ledger::Fees::default(),
            ledger_state:  std::sync::Arc::new(std::sync::Mutex::new(crate::ledger::LedgerState::new())),
            tx_pool:       std::sync::Arc::new(std::sync::RwLock::new(crate::ledger::TxPool::new())),
            history:       std::sync::Arc::new(std::sync::RwLock::new(crate::ledger::LedgerStore::new())),
            broadcast_queue: Vec::new(),
            ledger_header: crate::ledger::LedgerHeader {
                sequence: 0, hash: [0u8; 32], parent_hash: [0u8; 32],
                close_time: 0, total_coins: 100_000_000_000_000_000,
                account_hash: [0u8; 32], transaction_hash: [0u8; 32],
                parent_close_time: 0, close_time_resolution: 10, close_flags: 0,
            },
            amendments: std::collections::HashSet::new(),
            peer_count: 0,
            object_count: 0,
            storage: None,
            rpc_sync_state: None,
            follower_state: None,
            closed_ledger: None,
        }
    }
}
