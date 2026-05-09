//! The Node — ties all subsystems together and runs the main event loop.
//!
//! Responsibilities:
//! - Accept inbound TCP peer connections (optionally wrapped in TLS)
//! - Dial outbound peers from a bootstrap list
//! - Dispatch incoming RTXP messages to the right handler
//! - Serve JSON-RPC requests over HTTP
//! - Drive consensus rounds

use prost::Message as ProstMessage;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, trace, warn};

use crate::crypto::keys::Secp256k1KeyPair;
use crate::network::message::{FrameDecoder, MessageType, RtxpMessage, HEADER_SIZE};
use crate::network::peer::{Direction, Peer, PeerAction, PeerEvent, PeerId, PeerState};
use crate::rpc::{NodeContext, RpcRequest};
use crate::tls::OpenSslConfig;

#[path = "node/close_loop.rs"]
mod close_loop;
#[path = "node/consensus_control.rs"]
mod consensus_control;
#[path = "node/http_io.rs"]
mod http_io;
#[path = "node/init.rs"]
mod init;
#[path = "node/legacy_sync.rs"]
mod legacy_sync;
#[path = "node/load_manager.rs"]
mod load_manager;
#[path = "node/message_router.rs"]
mod message_router;
#[path = "node/peer_connect.rs"]
mod peer_connect;
#[path = "node/peer_control.rs"]
mod peer_control;
#[path = "node/peer_disconnect.rs"]
mod peer_disconnect;
#[path = "node/peer_discovery.rs"]
mod peer_discovery;
#[path = "node/peer_handshake.rs"]
mod peer_handshake;
#[path = "node/peer_io.rs"]
mod peer_io;
#[path = "node/peer_policy.rs"]
mod peer_policy;
#[path = "node/peer_read.rs"]
mod peer_read;
#[path = "node/peer_session.rs"]
mod peer_session;
#[path = "node/protocol_helpers.rs"]
mod protocol_helpers;
#[path = "node/resource_manager.rs"]
mod resource_manager;
#[path = "node/rpc_server.rs"]
mod rpc_server;
#[path = "node/runtime_helpers.rs"]
mod runtime_helpers;
#[path = "node/runtime_snapshots.rs"]
mod runtime_snapshots;
#[path = "node/shared_state.rs"]
mod shared_state;
#[path = "node/startup.rs"]
mod startup;
#[path = "node/sync_data.rs"]
mod sync_data;
#[path = "node/sync_helpers.rs"]
mod sync_helpers;
#[path = "node/sync_ingress.rs"]
mod sync_ingress;
#[path = "node/sync_lifecycle.rs"]
mod sync_lifecycle;
#[path = "node/sync_mesh.rs"]
mod sync_mesh;
#[path = "node/sync_timer.rs"]
mod sync_timer;
#[path = "node/sync_transport.rs"]
mod sync_transport;
#[path = "node/tx_ingress.rs"]
mod tx_ingress;

#[cfg(test)]
use peer_policy::peer_reservation_headroom;
use peer_policy::{peer_is_reserved, peer_reservation_description, peer_reservations_map};
use protocol_helpers::{
    collect_shamap_ledger_nodes, encode_ledger_base_header_bytes, node_event_label,
    node_status_label, parse_host_port, requested_get_ledger_hash, should_close_ledger,
    transaction_accounts_from_blob,
};
use sync_helpers::{
    build_li_base_nodes, is_pending_sync_anchor, plan_sync_completion_outcome,
    resolve_get_ledger_header, should_issue_reply_followup, should_refuse_get_ledger_for_load,
    tune_sync_request_for_peer_latency,
};
#[cfg(test)]
use sync_helpers::{should_use_timeout_object_fallback, sync_gate_accepts_response};

// No outbound sync rate limiting — matches rippled's InboundLedger which
// sends as fast as responses arrive. Remote peers enforce their own resource
// budgets and will disconnect if overloaded.

const MAX_RPC_HEADER_BYTES: usize = 16_384;
const MAX_RPC_BODY_BYTES: usize = 1_048_576;
const MAX_RPC_REQUEST_BYTES: usize = MAX_RPC_HEADER_BYTES + MAX_RPC_BODY_BYTES;
static SYNC_STALL_CHECKER_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static SYNC_BATCH_PROCESSOR_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static LOAD_MANAGER_LOOP_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static RESOURCE_MANAGER_LOOP_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SyncTuningConfig {
    pub sync_parse_workers: usize,
    pub sync_data_pipeline_capacity: usize,
    pub sync_request_generation_capacity: usize,
    pub sync_persistence_capacity: usize,
    pub sync_data_queue_max: usize,
    pub sync_data_queue_per_ledger: usize,
    pub sync_data_queue_per_peer: usize,
    pub sync_data_queue_bytes: usize,
    pub sync_data_batch_size: usize,
    pub peer_route_queue: usize,
    pub sync_reply_followup_peers: usize,
    pub sync_timeout_followup_peers: usize,
    pub sync_timeout_retries: u32,
    pub sync_idle_pump_after_ms: u64,
    pub sync_completion_check_interval_ms: u64,
    pub peer_idle_timeout_ms: u64,
    pub slow_route_ms: u64,
    pub slow_manifest_route_ms: u64,
    pub severe_route_ms: u64,
    pub object_fallback_after_timeouts: u32,
    pub object_fallback_batch_size: usize,
    pub object_fallback_empty_peer_cooldown_ms: u64,
    pub shutdown_grace_ms: u64,
    pub peer_route_drain_timeout_ms: u64,
}

impl Default for SyncTuningConfig {
    fn default() -> Self {
        Self {
            sync_parse_workers: 4,
            sync_data_pipeline_capacity: 1,
            sync_request_generation_capacity: 1,
            sync_persistence_capacity: 4,
            sync_data_queue_max: 128,
            sync_data_queue_per_ledger: 64,
            sync_data_queue_per_peer: 32,
            sync_data_queue_bytes: 64 * 1024 * 1024,
            sync_data_batch_size: 16,
            peer_route_queue: 256,
            sync_reply_followup_peers: crate::ledger::inbound::REPLY_FOLLOWUP_PEERS,
            sync_timeout_followup_peers: crate::ledger::inbound::TIMEOUT_FOLLOWUP_PEERS,
            sync_timeout_retries: crate::ledger::inbound::LEDGER_TIMEOUT_RETRIES_MAX as u32,
            sync_idle_pump_after_ms: 12_000,
            sync_completion_check_interval_ms: 15_000,
            peer_idle_timeout_ms: 90_000,
            slow_route_ms: 100,
            slow_manifest_route_ms: 300,
            severe_route_ms: 500,
            object_fallback_after_timeouts: 3,
            object_fallback_batch_size: crate::ledger::inbound::REQ_OBJECTS_TIMEOUT,
            object_fallback_empty_peer_cooldown_ms: 60_000,
            shutdown_grace_ms: 500,
            peer_route_drain_timeout_ms: 2_000,
        }
    }
}

impl SyncTuningConfig {
    pub fn from_runtime(value: &crate::config::RuntimeSyncTuning) -> Self {
        let mut cfg = Self::default();
        if let Some(v) = value.sync_parse_workers {
            cfg.sync_parse_workers = v;
        }
        if let Some(v) = value.sync_data_pipeline_capacity {
            cfg.sync_data_pipeline_capacity = v;
        }
        if let Some(v) = value.sync_request_generation_capacity {
            cfg.sync_request_generation_capacity = v;
        }
        if let Some(v) = value.sync_persistence_capacity {
            cfg.sync_persistence_capacity = v;
        }
        if let Some(v) = value.sync_data_queue_max {
            cfg.sync_data_queue_max = v;
        }
        if let Some(v) = value.sync_data_queue_per_ledger {
            cfg.sync_data_queue_per_ledger = v;
        }
        if let Some(v) = value.sync_data_queue_per_peer {
            cfg.sync_data_queue_per_peer = v;
        }
        if let Some(v) = value.sync_data_queue_bytes {
            cfg.sync_data_queue_bytes = v;
        }
        if let Some(v) = value.sync_data_batch_size {
            cfg.sync_data_batch_size = v;
        }
        if let Some(v) = value.peer_route_queue {
            cfg.peer_route_queue = v;
        }
        if let Some(v) = value.sync_reply_followup_peers {
            cfg.sync_reply_followup_peers = v;
        }
        if let Some(v) = value.sync_timeout_followup_peers {
            cfg.sync_timeout_followup_peers = v;
        }
        if let Some(v) = value.sync_timeout_retries {
            cfg.sync_timeout_retries = v;
        }
        if let Some(v) = value.sync_idle_pump_after_ms {
            cfg.sync_idle_pump_after_ms = v;
        }
        if let Some(v) = value.sync_completion_check_interval_ms {
            cfg.sync_completion_check_interval_ms = v;
        }
        if let Some(v) = value.peer_idle_timeout_ms {
            cfg.peer_idle_timeout_ms = v;
        }
        if let Some(v) = value.slow_route_ms {
            cfg.slow_route_ms = v;
        }
        if let Some(v) = value.slow_manifest_route_ms {
            cfg.slow_manifest_route_ms = v;
        }
        if let Some(v) = value.severe_route_ms {
            cfg.severe_route_ms = v;
        }
        if let Some(v) = value.object_fallback_after_timeouts {
            cfg.object_fallback_after_timeouts = v;
        }
        if let Some(v) = value.object_fallback_batch_size {
            cfg.object_fallback_batch_size = v;
        }
        if let Some(v) = value.object_fallback_empty_peer_cooldown_ms {
            cfg.object_fallback_empty_peer_cooldown_ms = v;
        }
        if let Some(v) = value.shutdown_grace_ms {
            cfg.shutdown_grace_ms = v;
        }
        if let Some(v) = value.peer_route_drain_timeout_ms {
            cfg.peer_route_drain_timeout_ms = v;
        }
        cfg.clamped()
    }

    pub fn clamped(mut self) -> Self {
        self.sync_parse_workers = self.sync_parse_workers.clamp(1, 32);
        self.sync_data_pipeline_capacity = self.sync_data_pipeline_capacity.clamp(1, 1024);
        self.sync_request_generation_capacity =
            self.sync_request_generation_capacity.clamp(1, 1024);
        self.sync_persistence_capacity = self.sync_persistence_capacity.clamp(1, 1024);
        self.sync_data_queue_max = self.sync_data_queue_max.clamp(1, 1_000_000);
        self.sync_data_queue_per_ledger = self.sync_data_queue_per_ledger.clamp(1, 1_000_000);
        self.sync_data_queue_per_peer = self.sync_data_queue_per_peer.clamp(1, 1_000_000);
        self.sync_data_queue_bytes = self
            .sync_data_queue_bytes
            .clamp(1024, 16 * 1024 * 1024 * 1024);
        self.sync_data_batch_size = self.sync_data_batch_size.clamp(1, 4096);
        self.peer_route_queue = self.peer_route_queue.clamp(1, 1_000_000);
        self.sync_reply_followup_peers = self.sync_reply_followup_peers.clamp(1, 128);
        self.sync_timeout_followup_peers = self.sync_timeout_followup_peers.clamp(1, 128);
        self.sync_timeout_retries = self.sync_timeout_retries.clamp(1, 10_000);
        self.sync_idle_pump_after_ms = self.sync_idle_pump_after_ms.clamp(1, 3_600_000);
        self.sync_completion_check_interval_ms =
            self.sync_completion_check_interval_ms.clamp(1, 3_600_000);
        self.peer_idle_timeout_ms = self.peer_idle_timeout_ms.clamp(1_000, 3_600_000);
        self.slow_route_ms = self.slow_route_ms.clamp(1, 60_000);
        self.slow_manifest_route_ms = self.slow_manifest_route_ms.clamp(1, 60_000);
        self.severe_route_ms = self.severe_route_ms.clamp(1, 60_000);
        self.object_fallback_after_timeouts = self.object_fallback_after_timeouts.clamp(1, 10_000);
        self.object_fallback_batch_size = self.object_fallback_batch_size.clamp(1, 4096);
        self.object_fallback_empty_peer_cooldown_ms = self
            .object_fallback_empty_peer_cooldown_ms
            .clamp(1, 3_600_000);
        self.shutdown_grace_ms = self.shutdown_grace_ms.clamp(0, 3_600_000);
        self.peer_route_drain_timeout_ms = self.peer_route_drain_timeout_ms.clamp(1, 3_600_000);
        self
    }

    pub fn idle_pump_after(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.sync_idle_pump_after_ms)
    }

    pub fn completion_check_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.sync_completion_check_interval_ms)
    }

    pub fn peer_idle_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.peer_idle_timeout_ms)
    }

    pub fn peer_route_drain_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.peer_route_drain_timeout_ms)
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Address to listen on for peer connections.
    pub peer_addr: SocketAddr,
    /// Address to listen on for JSON-RPC requests.
    pub rpc_addr: SocketAddr,
    /// Address to listen on for WebSocket connections.
    pub ws_addr: SocketAddr,
    /// Maximum number of connected peers.
    pub max_peers: usize,
    /// Maximum expensive peer-route work items processed concurrently.
    pub route_worker_count: usize,
    /// Bootstrap peers to dial on startup.
    pub bootstrap: Vec<SocketAddr>,
    /// Whether to wrap peer connections in TLS.
    pub use_tls: bool,
    /// Directory for persistent storage (None = in-memory only).
    pub data_dir: Option<std::path::PathBuf>,
    /// Path to TOML config file (validators, amendments).
    pub config_file: Option<std::path::PathBuf>,
    /// Network ID (0 = mainnet, 1 = testnet, 2 = devnet).
    pub network_id: u32,
    /// Maximum objects to download during state sync (0 = unlimited).
    pub max_sync: u64,
    /// Optional rippled admin RPC endpoint for fast state sync (e.g. "127.0.0.1:5005").
    pub rpc_sync: Option<String>,
    /// Full-history peer addresses (identified from /crawl complete_ledgers).
    pub full_history_peers: Vec<SocketAddr>,
    /// Historical ledger retention policy for in-memory/rpc history.
    pub ledger_history: crate::config::HistoryRetention,
    /// Historical fetch depth advertised and served by this node.
    pub fetch_depth: crate::config::HistoryRetention,
    /// Online delete / pruning threshold. `None` keeps all persisted history.
    pub online_delete: Option<u32>,
    /// Standalone mode: disable peer networking and allow local ledger_accept.
    pub standalone: bool,
    /// Whether to run the local consensus/ledger close loop.
    /// Normal follower nodes should leave this off.
    pub enable_consensus_close_loop: bool,
    /// Explicit test/safe-mode escape hatch allowing standalone consensus to
    /// sign proposals with the node key when no validator key is configured.
    pub allow_node_key_consensus: bool,
    /// Optional script run at sync completion before follower starts.
    /// Used to snapshot the freshly-synced data dir for quick restore.
    pub post_sync_checkpoint_script: Option<std::path::PathBuf>,
    /// Operator-tunable live sync and peer routing limits.
    pub sync_tuning: SyncTuningConfig,
    /// Base58-encoded validation seed. When set, the node becomes a validator
    /// and signs proposals/validations with the derived key instead of node_key.
    pub validation_seed: Option<String>,
    /// Hex-encoded secp256k1 validator signing secret key.
    pub validation_secret_key: Option<String>,
    /// Base64-encoded rippled validator token. When present, the validator
    /// signing key is derived from the token payload.
    pub validator_token: Option<String>,
}

impl NodeConfig {
    /// Maximum outbound peer slots. Matches rippled: ~60% of max_peers, minimum 10.
    pub fn max_outbound(&self) -> usize {
        ((self.max_peers * 60 + 50) / 100)
            .max(10)
            .min(self.max_peers)
    }
    /// Target peer mesh while bootstrapping state sync.
    ///
    /// Keep this below the full outbound slot count so bootstrap does not churn
    /// through public peers faster than they can serve useful SHAMap data.
    pub fn sync_peer_target(&self) -> usize {
        self.max_outbound()
            .min(12)
            .max(crate::ledger::inbound::REPLY_FOLLOWUP_PEERS)
    }
    /// Maximum inbound peer slots. Remainder after outbound.
    pub fn max_inbound(&self) -> usize {
        self.max_peers.saturating_sub(self.max_outbound())
    }
    /// Expensive peer-route worker concurrency, clamped to a safe range.
    pub fn route_worker_count(&self) -> usize {
        self.route_worker_count.clamp(1, 16)
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            peer_addr: "0.0.0.0:51235".parse().unwrap(),
            rpc_addr: "127.0.0.1:5005".parse().unwrap(),
            ws_addr: "127.0.0.1:6006".parse().unwrap(),
            max_peers: 21,
            route_worker_count: 1,
            bootstrap: vec![],
            use_tls: true,
            data_dir: None,
            config_file: None,
            network_id: 0,
            max_sync: 0,
            rpc_sync: None,
            full_history_peers: vec![],
            ledger_history: crate::config::HistoryRetention::Count(256),
            fetch_depth: crate::config::HistoryRetention::Full,
            online_delete: None,
            standalone: false,
            enable_consensus_close_loop: false,
            allow_node_key_consensus: false,
            post_sync_checkpoint_script: None,
            sync_tuning: SyncTuningConfig::default(),
            validation_seed: None,
            validation_secret_key: None,
            validator_token: None,
        }
    }
}

// ── Shared state ──────────────────────────────────────────────────────────────

/// State shared across all peer tasks and the RPC server.
pub struct SharedState {
    pub ctx: NodeContext,
    pub peers: HashMap<PeerId, PeerState>,
    /// One sender per connected peer — write an RtxpMessage here and the
    /// peer task will send it on the wire.
    pub peer_txs: HashMap<PeerId, mpsc::Sender<RtxpMessage>>,
    /// Known peer addresses (for peer discovery exchange).
    /// Known peer addresses — VecDeque for round-robin cycling.
    /// Pop from front to dial, push to back after use. Ensures even rotation.
    pub known_peers: std::collections::VecDeque<SocketAddr>,
    /// Shared runtime service bundle.
    pub services: crate::services::RuntimeServices,
    /// True while a snapshot or history sync is in progress.
    pub sync_in_progress: bool,
    /// True after the first state sync has completed — prevents re-syncing.
    pub sync_done: bool,
    /// Addresses of currently connected peers (to avoid double-dialing).
    pub connected_addrs: std::collections::HashSet<SocketAddr>,
    /// Per-peer measured latency in milliseconds (from ping/pong round-trip).
    pub peer_latency: HashMap<PeerId, u32>,
    /// Per-peer ping send time — to measure round-trip when pong arrives.
    pub peer_ping_sent: HashMap<PeerId, (u32, std::time::Instant)>, // (seq, sent_at)
    /// PeerId → SocketAddr mapping for identifying localhost/cluster peers.
    pub peer_addrs: HashMap<PeerId, SocketAddr>,
    /// Handshake metadata for active peers.
    pub peer_handshakes: HashMap<PeerId, crate::network::handshake::HandshakeInfo>,
    /// Manager-owned peerfinder slot handles for live peers.
    pub peerfinder_slots: HashMap<PeerId, crate::network::peerfinder::PeerfinderSlot>,
    /// Cooldown for failed/rejected peer addresses — don't re-dial for 130s.
    pub peer_cooldowns: HashMap<SocketAddr, std::time::Instant>,
    /// Peers that failed to respond to sync requests — benched for 20 minutes.
    pub sync_peer_cooldown: HashMap<PeerId, std::time::Instant>,
    /// Recent sync usefulness by peer — higher means recent liAS_NODE batches
    /// from this peer contained more useful nodes.
    pub peer_sync_useful: HashMap<PeerId, u32>,
    /// Cumulative useful sync nodes by peer for operator diagnostics.
    pub peer_sync_useful_total: HashMap<PeerId, u64>,
    /// Recent duplicate/zero-useful sync responses by peer.
    pub peer_sync_duplicates: HashMap<PeerId, u32>,
    /// Cumulative duplicate/zero-useful sync responses by peer.
    pub peer_sync_duplicates_total: HashMap<PeerId, u64>,
    /// Last time a peer returned useful sync data for the current sync run.
    pub peer_sync_last_useful: HashMap<PeerId, std::time::Instant>,
    /// Track repeated implausible validations so bad peers don't spam logs forever.
    pub implausible_validation_state: HashMap<PeerId, (std::time::Instant, u32)>, // (last_seen, count)
    /// RPC sync progress counters (when --rpc-sync is used).
    pub rpc_sync_state: Option<Arc<crate::rpc_sync::RpcSyncState>>,
    /// Ledger follower progress (when --rpc-sync is used).
    pub follower_state: Option<Arc<crate::ledger::follow::FollowerState>>,
    /// Exact ledger hash/seq whose tx tree must be acquired before the
    /// initial sync handoff can be considered complete.
    pub pending_sync_anchor: Option<(u32, [u8; 32])>,
    /// Deep-history peer addresses (100K+ ledger span, from /crawl). Used as bootstrap hints.
    pub full_history_peers: Vec<SocketAddr>,
    /// Per-peer ledger range — populated from TMStatusChange firstSeq/lastSeq.
    /// This is the authoritative source for which peers have which ledgers.
    pub peer_ledger_range: HashMap<PeerId, (u32, u32)>, // (min_seq, max_seq)
    /// Active consensus round — tracks proposals and validations.
    pub current_round: Option<crate::consensus::ConsensusRound>,
    /// Proposals received for the next ledger before the round opens.
    staged_proposals: HashMap<String, crate::consensus::Proposal>,
    peer_counter: u64,
    /// Per-peer connection direction (inbound vs outbound).
    pub peer_direction: HashMap<PeerId, Direction>,
    /// Per-peer squelch state: the peer requested that validator `X` messages
    /// not be relayed to it.
    /// Keyed by (peer_id → validator_pubkey → expiry). Lazy expiry on read.
    pub peer_squelch: HashMap<PeerId, HashMap<Vec<u8>, std::time::Instant>>,
    /// Ring buffer of recently validated ledger hashes, keyed by seq.
    /// Populated by the validation handler. The follower looks up N+1 here
    /// to replay consecutive ledgers. Capacity 256.
    pub validated_hashes: std::collections::HashMap<u32, [u8; 32]>,
    /// Ordered list of validated seqs for ring buffer eviction.
    validated_hash_order: std::collections::VecDeque<u32>,
    /// Trusted full validations observed when no active round is available.
    outside_round_validations: crate::consensus::PreferredLedgerTracker,
}

impl SharedState {}

// ── Node ──────────────────────────────────────────────────────────────────────

pub struct Node {
    config: NodeConfig,
    state: Arc<RwLock<SharedState>>,
    /// Broadcast channel for WebSocket event streaming.
    ws_events: tokio::sync::broadcast::Sender<crate::rpc::ws::WsEvent>,
    /// Persistent storage (None = in-memory only).
    storage: Option<Arc<crate::storage::Storage>>,
    /// The node's secp256k1 identity key (used for peer handshakes).
    node_key: Secp256k1KeyPair,
    /// Validator signing key derived from [validation_seed] config.
    /// When Some, the node signs validations & proposals with this key.
    validator_key: Option<Secp256k1KeyPair>,
    /// Validator manifests loaded from local validator token config and safe to
    /// advertise proactively to peers.
    local_validator_manifests: Vec<crate::consensus::Manifest>,
    /// OpenSSL TLS configuration for peer connections (computes rippled-compatible session hash).
    openssl_tls: Option<OpenSslConfig>,
    /// Direct reference to NuDB backend for lock-free sync writes.
    /// Bypasses LedgerState + SHAMap mutexes — like rippled's gotNode() callback.
    nudb_backend: Option<Arc<dyn crate::ledger::node_store::NodeStore>>,
    /// Trusted validator public keys for ConsensusRound.
    /// Behind Arc<RwLock> so the validator list fetch loop can update it.
    unl: Arc<std::sync::RwLock<Vec<Vec<u8>>>>,
    /// Tracks per-publisher validator lists and applies threshold semantics.
    validator_list_state: Arc<std::sync::Mutex<crate::validator_list::ValidatorListManager>>,
    /// Validator list publisher config (sites + publisher keys).
    validator_list_config: crate::config::ValidatorListConfig,
    /// Shutdown signal — all background tasks check this and exit when true.
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    /// Shared runtime bundle for active sync state, gating, and response queues.
    sync_runtime: Arc<crate::sync_runtime::SyncRuntime>,
    /// Global concurrency gate for expensive peer-route work.
    route_work_permits: Arc<tokio::sync::Semaphore>,
    /// Message dedup — separate from SharedState to avoid lock contention.
    /// SHA-256 of payload → true if seen. Cleared periodically.
    msg_dedup: Arc<std::sync::Mutex<(std::collections::HashSet<[u8; 32]>, std::time::Instant)>>,
    /// Debug log file for sync diagnostics (separate from main xLedgRSv2Beta.log).
    debug_log: Arc<std::sync::Mutex<Option<std::fs::File>>>,
    /// Lock-free RPC snapshot — updated atomically, read instantly by server_info.
    rpc_snapshot: arc_swap::ArcSwap<crate::rpc::RpcSnapshot>,
    /// Lock-free read-only RPC context — avoids SharedState lock contention for normal reads.
    rpc_read_ctx: arc_swap::ArcSwap<crate::rpc::NodeContext>,
    /// Advisory `can_delete` target for online-delete style pruning.
    can_delete_target: Arc<std::sync::atomic::AtomicU32>,
    /// Per-hash ledger acquisitions — routes responses by hash, no shared channels.
    inbound_ledgers: Arc<std::sync::Mutex<crate::ledger::inbound::InboundLedgers>>,
    /// Long-lived background tasks started by `Node::start`.
    background_tasks: Arc<std::sync::Mutex<Vec<BackgroundTask>>>,
}

struct BackgroundTask {
    name: &'static str,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackgroundTaskJoinSummary {
    pub completed: usize,
    pub aborted: usize,
    pub failed: usize,
}

/// Why sync_trigger was called — matches rippled's InboundLedger::Trigger enum.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TriggerReason {
    /// Called from the 3-second timer — recovery + stall detection.
    Timeout,
}

impl Node {}

// ── Free helpers ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        http_io, is_pending_sync_anchor, peer_is_reserved, peer_reservation_headroom,
        plan_sync_completion_outcome, should_close_ledger, should_issue_reply_followup,
        should_use_timeout_object_fallback, sync_gate_accepts_response, sync_mesh,
        tune_sync_request_for_peer_latency, Node, NodeConfig, SharedState, TriggerReason,
    };
    use crate::network::message::{MessageType, RtxpMessage};
    use crate::network::peer::{Direction, Peer, PeerId, PeerState};
    use base64::Engine as _;
    use prost::Message as ProstMessage;
    use std::collections::HashMap;
    use std::time::Duration;

    fn test_header(seq: u32, byte: u8) -> crate::ledger::LedgerHeader {
        crate::ledger::LedgerHeader {
            sequence: seq,
            hash: [byte; 32],
            parent_hash: [byte.wrapping_sub(1); 32],
            close_time: seq as u64,
            total_coins: 100_000_000_000,
            account_hash: [byte.wrapping_add(1); 32],
            transaction_hash: [byte.wrapping_add(2); 32],
            parent_close_time: seq.saturating_sub(1),
            close_time_resolution: 30,
            close_flags: 0,
        }
    }

    #[test]
    fn test_should_close_idle_ledger_after_interval() {
        assert!(should_close_ledger(
            false,
            0,
            0,
            0,
            Duration::from_secs(4),
            Duration::from_secs(15),
            Duration::from_secs(15),
            Duration::from_secs(15),
        ));
    }

    #[test]
    fn test_should_not_close_busy_ledger_before_minimum_time() {
        assert!(!should_close_ledger(
            true,
            10,
            0,
            0,
            Duration::from_secs(4),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(15),
        ));
    }

    #[test]
    fn test_should_close_when_majority_already_closed() {
        assert!(should_close_ledger(
            false,
            10,
            4,
            2,
            Duration::from_secs(4),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(15),
        ));
    }

    #[test]
    fn test_peer_reservation_helpers_match_base58_keys() {
        let reservations =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::from([(
                crate::crypto::base58::encode(
                    crate::crypto::base58::PREFIX_NODE_PUBLIC,
                    &[9u8; 33],
                ),
                "vip".to_string(),
            )])));
        assert!(peer_is_reserved(Some(&reservations), &[9u8; 33]));
        assert!(!peer_is_reserved(Some(&reservations), &[8u8; 33]));
        assert_eq!(peer_reservation_headroom(Some(&reservations)), 1);
    }

    #[test]
    fn test_send_to_peers_with_ledger_counts_only_successful_sends() {
        let mut state = SharedState::new(crate::rpc::NodeContext::default());
        let peer = PeerId(1);
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(RtxpMessage::new(MessageType::Ping, vec![1]))
            .unwrap();
        state.peer_txs.insert(peer, tx);
        state.peer_ledger_range.insert(peer, (1, 10));

        let msg = RtxpMessage::new(MessageType::Ping, vec![2]);
        assert_eq!(state.send_to_peers_with_ledger(&msg, 5, 1), 0);

        let _ = rx.try_recv().unwrap();
        assert_eq!(state.send_to_peers_with_ledger(&msg, 5, 1), 1);
    }

    #[tokio::test]
    async fn test_handle_manifests_only_publishes_and_relays_accepted_entries() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let source_addr: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let source_consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(source_addr, false, None);
        let source_peer = Peer::new(PeerId(1), source_addr, Direction::Inbound, source_consumer);

        let relay_peer = PeerId(2);
        let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel(4);
        {
            let mut state = node.state.write().await;
            state.peer_txs.insert(relay_peer, relay_tx);
        }

        let mut ws_rx = node.ws_events.subscribe();
        let master = crate::crypto::keys::Secp256k1KeyPair::generate();
        let signing = crate::crypto::keys::Secp256k1KeyPair::generate();
        let manifest = crate::consensus::Manifest::new_signed(1, &master, &signing);
        let msg = crate::network::relay::encode_manifests(&[manifest.clone(), manifest.clone()]);

        let _ = node.handle_manifests_message(&source_peer, &msg).await;

        match ws_rx.recv().await.unwrap() {
            crate::rpc::ws::WsEvent::ManifestReceived { manifest: received } => {
                assert_eq!(received.sequence, manifest.sequence);
                assert_eq!(received.master_pubkey, manifest.master_pubkey);
            }
            other => panic!("expected manifest event, got {other:?}"),
        }
        match ws_rx.recv().await.unwrap() {
            crate::rpc::ws::WsEvent::PeerMessage { msg_type, detail } => {
                assert_eq!(msg_type, "manifest");
                assert!(detail.contains("accepted=1"));
            }
            other => panic!("expected peer message event, got {other:?}"),
        }
        assert!(matches!(
            ws_rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));

        let relayed = relay_rx.try_recv().expect("accepted manifest should relay");
        let decoded = crate::network::relay::decode_manifests(&relayed.payload);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].sequence, manifest.sequence);
        assert_eq!(decoded[0].master_pubkey, manifest.master_pubkey);
        assert!(relay_rx.try_recv().is_err());

        let cache_len = node
            .state
            .read()
            .await
            .ctx
            .manifest_cache
            .as_ref()
            .expect("manifest cache")
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        assert_eq!(cache_len, 1);
    }

    #[tokio::test]
    async fn test_peer_read_enqueues_expensive_route_work_without_awaiting_route() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let addr: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let resource_consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(addr, false, None);
        let mut peer = Peer::new(PeerId(1), addr, Direction::Inbound, resource_consumer);
        peer.state = PeerState::Active;
        let mut dec = crate::network::message::FrameDecoder::new();
        let (mut stream, _other) = tokio::io::duplex(1024);
        let (route_tx, mut route_rx, _result_tx, _result_rx) = node.peer_route_channel();
        let session_hash = [0x55; 32];
        let mut route_seq = 0u64;
        for msg_type in [MessageType::LedgerData, MessageType::GetObjects] {
            let wire = RtxpMessage::new(msg_type, Vec::new()).encode();
            let disconnect = node
                .process_peer_frames(
                    &mut stream,
                    &mut peer,
                    &mut dec,
                    &wire,
                    &session_hash,
                    &route_tx,
                    &mut route_seq,
                    0,
                )
                .await;

            assert!(!disconnect);
            let job = route_rx.try_recv().expect("expensive route job");
            assert_eq!(job.seq, route_seq - 1);
        }
        assert_eq!(peer.rx_count, 0);
        let metrics = node.sync_runtime.metrics_snapshot();
        assert_eq!(metrics.route_messages_total, 0);
        assert_eq!(metrics.route_queue_enqueued_total, 2);
        assert_eq!(metrics.route_queue_max_len, 1);
        assert_eq!(metrics.route_queue_capacity, 256);
    }

    #[tokio::test]
    async fn test_peer_read_returns_while_route_worker_is_backpressured() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let _route_permit = node
            .route_work_permits
            .acquire()
            .await
            .expect("route work permit");
        let addr: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let resource_consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(addr, false, None);
        let mut peer = Peer::new(PeerId(1), addr, Direction::Inbound, resource_consumer);
        peer.state = PeerState::Active;
        let mut dec = crate::network::message::FrameDecoder::new();
        let (mut stream, _other) = tokio::io::duplex(1024);
        let (route_tx, route_rx, result_tx, mut result_rx) = node.peer_route_channel();
        let route_worker = tokio::spawn(
            node.clone()
                .run_peer_route_worker(peer.id, route_rx, result_tx),
        );
        let session_hash = [0x55; 32];
        let mut route_seq = 0u64;
        let wire = [
            RtxpMessage::new(MessageType::LedgerData, Vec::new()).encode(),
            RtxpMessage::new(MessageType::GetObjects, Vec::new()).encode(),
        ]
        .concat();

        let disconnect = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            node.process_peer_frames(
                &mut stream,
                &mut peer,
                &mut dec,
                &wire,
                &session_hash,
                &route_tx,
                &mut route_seq,
                0,
            ),
        )
        .await
        .expect("read loop should not await route worker");

        assert!(!disconnect);
        assert_eq!(route_seq, 2);
        assert!(result_rx.try_recv().is_err());
        let metrics = node.sync_runtime.metrics_snapshot();
        assert_eq!(metrics.route_queue_enqueued_total, 2);
        assert_eq!(metrics.route_messages_total, 0);
        route_worker.abort();
    }

    #[tokio::test]
    async fn test_peer_read_queues_messages_behind_pending_route_work() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let addr: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let resource_consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(addr, false, None);
        let mut peer = Peer::new(PeerId(1), addr, Direction::Inbound, resource_consumer);
        peer.state = PeerState::Active;
        let mut dec = crate::network::message::FrameDecoder::new();
        let (mut stream, _other) = tokio::io::duplex(1024);
        let (route_tx, mut route_rx, _result_tx, _result_rx) = node.peer_route_channel();
        let session_hash = [0x55; 32];
        let mut route_seq = 1u64;
        let wire = RtxpMessage::new(MessageType::Ping, Vec::new()).encode();

        let disconnect = node
            .process_peer_frames(
                &mut stream,
                &mut peer,
                &mut dec,
                &wire,
                &session_hash,
                &route_tx,
                &mut route_seq,
                0,
            )
            .await;

        assert!(!disconnect);
        let job = route_rx.try_recv().expect("message behind route work");
        assert_eq!(job.seq, 1);
        assert_eq!(route_seq, 2);
        assert_eq!(peer.rx_count, 0);
        assert_eq!(node.sync_runtime.metrics_snapshot().route_messages_total, 0);
    }

    #[tokio::test]
    async fn test_peer_read_disconnects_instead_of_silently_dropping_ordered_route_work() {
        let node = std::sync::Arc::new(Node::new(NodeConfig {
            sync_tuning: super::SyncTuningConfig {
                peer_route_queue: 1,
                peer_route_drain_timeout_ms: 1,
                ..super::SyncTuningConfig::default()
            },
            ..NodeConfig::default()
        }));
        let addr: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let resource_consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(addr, false, None);
        let mut peer = Peer::new(PeerId(1), addr, Direction::Inbound, resource_consumer);
        peer.state = PeerState::Active;
        let mut dec = crate::network::message::FrameDecoder::new();
        let (mut stream, _other) = tokio::io::duplex(1024);
        let (route_tx, mut route_rx, _result_tx, _result_rx) = node.peer_route_channel();
        let session_hash = [0x55; 32];
        let mut route_seq = 0u64;
        let wire = [
            RtxpMessage::new(MessageType::LedgerData, Vec::new()).encode(),
            RtxpMessage::new(MessageType::GetObjects, Vec::new()).encode(),
        ]
        .concat();

        let disconnect = node
            .process_peer_frames(
                &mut stream,
                &mut peer,
                &mut dec,
                &wire,
                &session_hash,
                &route_tx,
                &mut route_seq,
                0,
            )
            .await;

        assert!(disconnect);
        assert_eq!(route_seq, 1);
        let _first = route_rx.try_recv().expect("first route job remains queued");
        let metrics = node.sync_runtime.metrics_snapshot();
        assert_eq!(metrics.route_queue_full_total, 1);
        assert_eq!(metrics.route_queue_dropped_total, 1);
    }

    #[test]
    fn test_route_worker_count_is_clamped_for_operator_config() {
        let mut config = NodeConfig {
            route_worker_count: 0,
            ..NodeConfig::default()
        };
        assert_eq!(config.route_worker_count(), 1);

        config.route_worker_count = 4;
        assert_eq!(config.route_worker_count(), 4);

        config.route_worker_count = 99;
        assert_eq!(config.route_worker_count(), 16);
    }

    #[test]
    fn test_sync_tuning_is_clamped_for_operator_config() {
        let tuning = super::SyncTuningConfig {
            sync_parse_workers: 0,
            sync_data_queue_bytes: 1,
            peer_route_queue: 0,
            sync_timeout_retries: 0,
            peer_idle_timeout_ms: 0,
            object_fallback_batch_size: 0,
            peer_route_drain_timeout_ms: 0,
            ..super::SyncTuningConfig::default()
        }
        .clamped();

        assert_eq!(tuning.sync_parse_workers, 1);
        assert_eq!(tuning.sync_data_queue_bytes, 1024);
        assert_eq!(tuning.peer_route_queue, 1);
        assert_eq!(tuning.sync_timeout_retries, 1);
        assert_eq!(
            tuning.peer_idle_timeout(),
            std::time::Duration::from_secs(1)
        );
        assert_eq!(tuning.object_fallback_batch_size, 1);
        assert_eq!(
            tuning.peer_route_drain_timeout(),
            std::time::Duration::from_millis(1)
        );
    }

    #[tokio::test]
    async fn test_rpc_shutdown_flag_is_node_shutdown_flag() {
        let node = Node::new(NodeConfig::default());
        let ctx_flag = {
            let state = node.state.read().await;
            state.ctx.shutdown_requested.clone().expect("shutdown flag")
        };

        assert!(std::sync::Arc::ptr_eq(&ctx_flag, &node.shutdown_flag()));
        ctx_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(node.is_shutting_down());
    }

    #[tokio::test]
    async fn test_background_tasks_join_with_bounded_abort() {
        let node = Node::new(NodeConfig::default());
        node.track_background_task("quick", tokio::spawn(async {}));
        node.track_background_task(
            "stuck",
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }),
        );

        let joined = node
            .join_background_tasks(std::time::Duration::from_millis(10))
            .await;

        assert_eq!(joined.completed, 1);
        assert_eq!(joined.aborted, 1);
        assert_eq!(joined.failed, 0);
    }

    #[tokio::test]
    async fn test_handle_manifests_prefers_highest_sequence_per_master_in_batch() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let source_addr: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let source_consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(source_addr, false, None);
        let source_peer = Peer::new(PeerId(1), source_addr, Direction::Inbound, source_consumer);

        let relay_peer = PeerId(2);
        let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel(4);
        {
            let mut state = node.state.write().await;
            state.peer_txs.insert(relay_peer, relay_tx);
        }

        let mut ws_rx = node.ws_events.subscribe();
        let master = crate::crypto::keys::Secp256k1KeyPair::generate();
        let signing1 = crate::crypto::keys::Secp256k1KeyPair::generate();
        let signing2 = crate::crypto::keys::Secp256k1KeyPair::generate();
        let manifest1 = crate::consensus::Manifest::new_signed(1, &master, &signing1);
        let manifest2 = crate::consensus::Manifest::new_signed(2, &master, &signing2);
        let msg = crate::network::relay::encode_manifests(&[manifest1.clone(), manifest2.clone()]);

        let _ = node.handle_manifests_message(&source_peer, &msg).await;

        match ws_rx.recv().await.unwrap() {
            crate::rpc::ws::WsEvent::ManifestReceived { manifest: received } => {
                assert_eq!(received.sequence, manifest2.sequence);
                assert_eq!(received.master_pubkey, manifest2.master_pubkey);
                assert_eq!(received.signing_pubkey, manifest2.signing_pubkey);
            }
            other => panic!("expected manifest event, got {other:?}"),
        }
        match ws_rx.recv().await.unwrap() {
            crate::rpc::ws::WsEvent::PeerMessage { msg_type, detail } => {
                assert_eq!(msg_type, "manifest");
                assert!(detail.contains("accepted=1"));
            }
            other => panic!("expected peer message event, got {other:?}"),
        }
        assert!(matches!(
            ws_rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));

        let relayed = relay_rx.try_recv().expect("accepted manifest should relay");
        let decoded = crate::network::relay::decode_manifests(&relayed.payload);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].sequence, manifest2.sequence);
        assert_eq!(decoded[0].master_pubkey, manifest2.master_pubkey);
        assert_eq!(decoded[0].signing_pubkey, manifest2.signing_pubkey);
        assert!(relay_rx.try_recv().is_err());

        let cache_len = node
            .state
            .read()
            .await
            .ctx
            .manifest_cache
            .as_ref()
            .expect("manifest cache")
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        assert_eq!(cache_len, 1);
    }

    #[tokio::test]
    async fn test_handle_manifests_skips_repeated_raw_batch_from_another_peer() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let addr_a: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let addr_b: std::net::SocketAddr = "127.0.0.1:51236".parse().unwrap();
        let peer_a = Peer::new(
            PeerId(1),
            addr_a,
            Direction::Inbound,
            crate::network::resource::ResourceManager::default()
                .new_inbound_endpoint(addr_a, false, None),
        );
        let peer_b = Peer::new(
            PeerId(2),
            addr_b,
            Direction::Inbound,
            crate::network::resource::ResourceManager::default()
                .new_inbound_endpoint(addr_b, false, None),
        );

        let relay_peer = PeerId(3);
        let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel(4);
        {
            let mut state = node.state.write().await;
            state.peer_txs.insert(relay_peer, relay_tx);
        }

        let mut ws_rx = node.ws_events.subscribe();
        let master = crate::crypto::keys::Secp256k1KeyPair::generate();
        let signing = crate::crypto::keys::Secp256k1KeyPair::generate();
        let manifest = crate::consensus::Manifest::new_signed(1, &master, &signing);
        let msg = crate::network::relay::encode_manifests(std::slice::from_ref(&manifest));

        let _ = node.handle_manifests_message(&peer_a, &msg).await;
        let _ = node.handle_manifests_message(&peer_b, &msg).await;

        match ws_rx.recv().await.unwrap() {
            crate::rpc::ws::WsEvent::ManifestReceived { manifest: received } => {
                assert_eq!(received.sequence, manifest.sequence);
                assert_eq!(received.master_pubkey, manifest.master_pubkey);
            }
            other => panic!("expected manifest event, got {other:?}"),
        }
        match ws_rx.recv().await.unwrap() {
            crate::rpc::ws::WsEvent::PeerMessage { msg_type, detail } => {
                assert_eq!(msg_type, "manifest");
                assert!(detail.contains("accepted=1"));
            }
            other => panic!("expected peer message event, got {other:?}"),
        }
        assert!(matches!(
            ws_rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));

        let relayed = relay_rx
            .try_recv()
            .expect("first manifest batch should relay");
        let decoded = crate::network::relay::decode_manifests(&relayed.payload);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].sequence, manifest.sequence);
        assert!(relay_rx.try_recv().is_err());
    }

    #[test]
    fn validator_token_rejects_manifest_secret_identity_mismatch() {
        let master = crate::crypto::keys::Secp256k1KeyPair::from_secret_bytes(&[1u8; 32]).unwrap();
        let signing = crate::crypto::keys::Secp256k1KeyPair::from_secret_bytes(&[2u8; 32]).unwrap();
        let manifest = crate::consensus::Manifest::new_signed(1, &master, &signing);
        let payload = serde_json::json!({
            "manifest": base64::engine::general_purpose::STANDARD.encode(manifest.to_bytes()),
            "validation_secret_key": hex::encode([3u8; 32]),
        });
        let token = base64::engine::general_purpose::STANDARD.encode(payload.to_string());

        let node = Node::new(NodeConfig {
            validator_token: Some(token),
            validation_secret_key: Some(hex::encode([3u8; 32])),
            ..NodeConfig::default()
        });

        assert!(node.validator_key.is_none());
        assert!(node.local_validator_manifests.is_empty());
    }

    #[test]
    fn validator_token_accepts_matching_manifest_secret_identity() {
        let master = crate::crypto::keys::Secp256k1KeyPair::from_secret_bytes(&[1u8; 32]).unwrap();
        let signing = crate::crypto::keys::Secp256k1KeyPair::from_secret_bytes(&[2u8; 32]).unwrap();
        let manifest = crate::consensus::Manifest::new_signed(1, &master, &signing);
        let payload = serde_json::json!({
            "manifest": base64::engine::general_purpose::STANDARD.encode(manifest.to_bytes()),
            "validation_secret_key": hex::encode([2u8; 32]),
        });
        let token = base64::engine::general_purpose::STANDARD.encode(payload.to_string());

        let node = Node::new(NodeConfig {
            validator_token: Some(token),
            validation_secret_key: Some(hex::encode([2u8; 32])),
            ..NodeConfig::default()
        });

        assert_eq!(
            node.validator_key
                .as_ref()
                .map(|key| key.public_key_bytes()),
            Some(signing.public_key_bytes())
        );
        assert_eq!(node.local_validator_manifests.len(), 1);
    }

    #[test]
    fn consensus_signing_key_requires_validator_key_or_explicit_safe_mode() {
        let node = Node::new(NodeConfig::default());
        assert!(node.consensus_signing_key().is_none());

        let safe_node = Node::new(NodeConfig {
            allow_node_key_consensus: true,
            ..NodeConfig::default()
        });
        assert!(safe_node.consensus_signing_key().is_some());
    }

    fn test_validation_message(ledger_seq: u32, ledger_hash: [u8; 32]) -> RtxpMessage {
        use prost::Message as _;

        let pubkey = vec![0xED; 33];
        let sig = vec![0xAA; 72];
        let sign_time: u32 = 1_712_000_000;

        let mut blob = Vec::new();
        blob.push(0x22);
        blob.extend_from_slice(&1u32.to_be_bytes());
        blob.push(0x26);
        blob.extend_from_slice(&ledger_seq.to_be_bytes());
        blob.push(0x29);
        blob.extend_from_slice(&sign_time.to_be_bytes());
        blob.push(0x51);
        blob.extend_from_slice(&ledger_hash);
        blob.push(0x73);
        blob.push(pubkey.len() as u8);
        blob.extend_from_slice(&pubkey);
        blob.push(0x76);
        blob.push(sig.len() as u8);
        blob.extend_from_slice(&sig);

        let pb = crate::proto::TmValidation {
            validation: blob,
            ..Default::default()
        };
        RtxpMessage::new(MessageType::Validation, pb.encode_to_vec())
    }

    fn test_signed_validation_message(
        kp: &crate::crypto::keys::Secp256k1KeyPair,
        ledger_seq: u32,
        ledger_hash: [u8; 32],
    ) -> RtxpMessage {
        use prost::Message as _;

        let sign_time: u32 = 1_712_000_000;
        let validation =
            crate::consensus::Validation::new_signed(ledger_seq, ledger_hash, sign_time, true, kp);
        let pb = crate::proto::TmValidation {
            validation: validation.to_bytes(),
            ..Default::default()
        };
        RtxpMessage::new(MessageType::Validation, pb.encode_to_vec())
    }

    #[tokio::test]
    async fn test_round_accepts_ephemeral_validation_resolved_by_shared_manifest_cache() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let master = crate::crypto::keys::Secp256k1KeyPair::generate();
        let signing = crate::crypto::keys::Secp256k1KeyPair::generate();
        let manifest = crate::consensus::Manifest::new_signed(1, &master, &signing);
        let addr: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(addr, false, None);
        let peer = Peer::new(PeerId(1), addr, Direction::Inbound, consumer);
        let ledger_hash = [0xAC; 32];
        let msg = test_signed_validation_message(&signing, 300_000, ledger_hash);

        node.unl
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(master.public_key_bytes());
        {
            let mut state = node.state.write().await;
            state.sync_done = true;
            state.ctx.ledger_seq = 299_999;
            state
                .ctx
                .manifest_cache
                .as_ref()
                .expect("manifest cache")
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .add(manifest);
            state.current_round = Some(crate::consensus::ConsensusRound::new(
                300_000,
                vec![master.public_key_bytes()],
                [0xAB; 32],
                false,
                Duration::from_secs(4),
                1,
            ));
        }

        let _ = node.handle_validation_message(&peer, &msg).await;

        let state = node.state.read().await;
        let round = state.current_round.as_ref().expect("round remains active");
        assert_eq!(round.validation_count_for(&ledger_hash), 1);
    }

    #[tokio::test]
    async fn test_implausible_untrusted_validation_does_not_bench_peer_while_syncing() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let addr: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(addr, false, None);
        let peer = Peer::new(PeerId(1), addr, Direction::Inbound, consumer);
        let msg = test_validation_message(100_000, [0xAB; 32]);

        {
            let mut state = node.state.write().await;
            state.sync_done = false;
            state.peer_addrs.insert(peer.id, addr);
            state.peer_ledger_range.insert(peer.id, (99_500, 100_500));
            state
                .peer_ledger_range
                .insert(PeerId(99), (300_000, 300_500));
        }

        let _ = node.handle_validation_message(&peer, &msg).await;

        let state = node.state.read().await;
        assert!(
            !state.sync_peer_cooldown.contains_key(&peer.id),
            "syncing node should not bench a peer for untrusted implausible validations"
        );
        assert!(
            !state.peer_cooldowns.contains_key(&addr),
            "syncing node should not dial-cooldown the peer address for untrusted implausible validations"
        );
        assert!(
            !state.implausible_validation_state.contains_key(&peer.id),
            "syncing node should not accumulate implausible-validation repeat state for untrusted traffic"
        );
    }

    #[tokio::test]
    async fn test_implausible_validation_does_not_bench_peer_after_sync() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let addr: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(addr, false, None);
        let peer = Peer::new(PeerId(1), addr, Direction::Inbound, consumer);
        let msg = test_validation_message(100_000, [0xAB; 32]);

        {
            let mut state = node.state.write().await;
            state.sync_done = true;
            state.peer_addrs.insert(peer.id, addr);
            state.peer_ledger_range.insert(peer.id, (99_500, 100_500));
            state
                .peer_ledger_range
                .insert(PeerId(99), (300_000, 300_500));
        }

        for _ in 0..10 {
            let _ = node.handle_validation_message(&peer, &msg).await;
        }

        let state = node.state.read().await;
        assert!(
            !state.sync_peer_cooldown.contains_key(&peer.id),
            "relayed validations should not bench the transport peer after sync"
        );
        assert!(
            !state.peer_cooldowns.contains_key(&addr),
            "relayed validations should not dial-cooldown the peer address after sync"
        );
        assert!(
            !state.implausible_validation_state.contains_key(&peer.id),
            "relay-level implausibility tracking should not poison a peer after sync"
        );
    }

    #[tokio::test]
    async fn test_trusted_validation_without_current_round_does_not_mark_validated() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let validators = (0..5)
            .map(|_| crate::crypto::keys::Secp256k1KeyPair::generate())
            .collect::<Vec<_>>();
        let addr: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(addr, false, None);
        let peer = Peer::new(PeerId(1), addr, Direction::Inbound, consumer);
        let ledger_hash = [0xCD; 32];
        let msg = test_signed_validation_message(&validators[0], 300_000, ledger_hash);

        {
            let mut unl = node.unl.write().unwrap_or_else(|e| e.into_inner());
            unl.clear();
            unl.extend(
                validators
                    .iter()
                    .map(|validator| validator.public_key_bytes()),
            );
        }

        {
            let mut state = node.state.write().await;
            state.sync_done = true;
            state.peer_addrs.insert(peer.id, addr);
            state.peer_ledger_range.insert(peer.id, (99_500, 100_500));
            state
                .peer_ledger_range
                .insert(PeerId(99), (300_000, 300_500));
            state.ctx.ledger_seq = 100_000;
            state.ctx.ledger_hash = hex::encode_upper([0xAB; 32]);
            state.ctx.validator_list_manager = None;
            state.current_round = None;
        }

        let _ = node.handle_validation_message(&peer, &msg).await;

        let state = node.state.read().await;
        assert_eq!(state.ctx.ledger_seq, 100_000);
        assert_eq!(state.ctx.ledger_hash, hex::encode_upper([0xAB; 32]));
        assert_eq!(state.validated_hashes.get(&300_000), None);
        assert_eq!(state.services.ledger_master.hash_for_seq(300_000), None);
        assert!(
            !state.sync_peer_cooldown.contains_key(&peer.id),
            "trusted relayed validations should not bench the peer even when they do not reach quorum"
        );
    }

    #[tokio::test]
    async fn test_trusted_validation_quorum_without_current_round_records_validated_hash() {
        let node = std::sync::Arc::new(Node::new(NodeConfig::default()));
        let validators = (0..5)
            .map(|_| crate::crypto::keys::Secp256k1KeyPair::generate())
            .collect::<Vec<_>>();
        let addr: std::net::SocketAddr = "127.0.0.1:51236".parse().unwrap();
        let consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(addr, false, None);
        let peer = Peer::new(PeerId(1), addr, Direction::Inbound, consumer);
        let ledger_hash = [0xCE; 32];

        {
            let mut unl = node.unl.write().unwrap_or_else(|e| e.into_inner());
            unl.clear();
            unl.extend(
                validators
                    .iter()
                    .map(|validator| validator.public_key_bytes()),
            );
        }

        {
            let mut state = node.state.write().await;
            state.sync_done = true;
            state.peer_addrs.insert(peer.id, addr);
            state.peer_ledger_range.insert(peer.id, (99_500, 100_500));
            state
                .peer_ledger_range
                .insert(PeerId(99), (300_000, 300_500));
            state.ctx.ledger_seq = 100_000;
            state.ctx.validator_list_manager = None;
            state.current_round = None;
        }

        for validator in &validators[..4] {
            let msg = test_signed_validation_message(validator, 300_000, ledger_hash);
            let _ = node.handle_validation_message(&peer, &msg).await;
        }

        let state = node.state.read().await;
        assert_eq!(state.validated_hashes.get(&300_000), Some(&ledger_hash));
        assert_eq!(
            state.services.ledger_master.hash_for_seq(300_000),
            Some(ledger_hash)
        );
    }

    #[test]
    fn test_send_to_peers_with_ledger_uses_configured_full_history_peer_without_range() {
        let mut state = SharedState::new(crate::rpc::NodeContext::default());
        let peer = PeerId(7);
        let addr: std::net::SocketAddr = "127.0.0.1:51235".parse().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        state.peer_txs.insert(peer, tx);
        state.peer_addrs.insert(peer, addr);
        state.full_history_peers.push(addr);

        let msg = RtxpMessage::new(MessageType::Ping, vec![9]);
        assert_eq!(state.send_to_peers_with_ledger(&msg, 103290083, 1), 1);
        let sent = rx.try_recv().unwrap();
        assert_eq!(sent.payload, vec![9]);
    }

    #[test]
    fn test_send_to_peers_with_ledger_prefers_more_useful_peer() {
        let mut state = SharedState::new(crate::rpc::NodeContext::default());
        let peer_a = PeerId(1);
        let peer_b = PeerId(2);
        let (tx_a, mut rx_a) = tokio::sync::mpsc::channel(1);
        let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(1);
        state.peer_txs.insert(peer_a, tx_a);
        state.peer_txs.insert(peer_b, tx_b);
        state.peer_ledger_range.insert(peer_a, (1, 10));
        state.peer_ledger_range.insert(peer_b, (1, 10));
        state.peer_sync_useful.insert(peer_a, 5);
        state.peer_sync_useful.insert(peer_b, 50);

        let msg = RtxpMessage::new(MessageType::Ping, vec![7]);
        assert_eq!(state.send_to_peers_with_ledger(&msg, 5, 1), 1);
        assert!(rx_a.try_recv().is_err());
        let sent = rx_b.try_recv().unwrap();
        assert_eq!(sent.payload, vec![7]);
    }

    #[test]
    fn test_send_to_peers_with_ledger_keeps_breadth_when_multiple_peers_cover_seq() {
        let mut state = SharedState::new(crate::rpc::NodeContext::default());
        let strong = PeerId(1);
        let weak = PeerId(2);
        let (tx_strong, mut rx_strong) = tokio::sync::mpsc::channel(1);
        let (tx_weak, mut rx_weak) = tokio::sync::mpsc::channel(1);
        state.peer_txs.insert(strong, tx_strong);
        state.peer_txs.insert(weak, tx_weak);
        state.peer_ledger_range.insert(strong, (1, 10));
        state.peer_ledger_range.insert(weak, (1, 10));
        state.peer_sync_useful.insert(strong, 100);
        state.peer_sync_useful.insert(weak, 10);

        let msg = RtxpMessage::new(MessageType::Ping, vec![8]);
        assert_eq!(state.send_to_peers_with_ledger(&msg, 5, 2), 2);
        let sent = rx_strong.try_recv().unwrap();
        assert_eq!(sent.payload, vec![8]);
        let sent = rx_weak.try_recv().unwrap();
        assert_eq!(sent.payload, vec![8]);
    }

    #[test]
    fn test_sync_candidate_peers_falls_back_to_open_mesh_when_ranges_missing() {
        let mut state = SharedState::new(crate::rpc::NodeContext::default());
        for id in 1..=8 {
            let peer = PeerId(id);
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            state.peer_txs.insert(peer, tx);
        }

        let selected = state.sync_candidate_peers(999, 6);
        assert_eq!(selected.len(), 6);
        assert_eq!(selected[0], PeerId(1));
        assert_eq!(selected[5], PeerId(6));
    }

    #[test]
    fn test_sync_candidate_peers_prefers_useful_peers_without_collapsing_mesh() {
        let mut state = SharedState::new(crate::rpc::NodeContext::default());
        for id in 1..=5 {
            let peer = PeerId(id);
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            state.peer_txs.insert(peer, tx);
            state.peer_ledger_range.insert(peer, (1, 10));
        }
        state.peer_sync_useful.insert(PeerId(1), 100);
        state.peer_sync_useful.insert(PeerId(2), 40);
        state.peer_sync_useful.insert(PeerId(3), 20);
        state.peer_sync_useful.insert(PeerId(4), 10);
        state.peer_sync_useful.insert(PeerId(5), 1);

        let selected = state.sync_candidate_peers(5, 4);
        assert_eq!(selected, vec![PeerId(1), PeerId(2), PeerId(3), PeerId(4)]);
    }

    #[test]
    fn test_sync_candidate_peers_skips_benched_peers() {
        let mut state = SharedState::new(crate::rpc::NodeContext::default());
        for id in 1..=4 {
            let peer = PeerId(id);
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            state.peer_txs.insert(peer, tx);
            state.peer_ledger_range.insert(peer, (1, 10));
            state.peer_sync_useful.insert(peer, (100 - id) as u32);
        }
        state.sync_peer_cooldown.insert(
            PeerId(1),
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        );

        let selected = state.sync_candidate_peers(5, 3);
        assert_eq!(selected, vec![PeerId(2), PeerId(3), PeerId(4)]);
    }

    #[test]
    fn test_select_reply_sync_peers_prefers_useful_and_fills_mesh() {
        let node = Node::new(NodeConfig::default());
        let mut state = SharedState::new(crate::rpc::NodeContext::default());
        let mut peer_useful_counts = HashMap::new();

        for id in 1..=4 {
            let peer = PeerId(id);
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            state.peer_txs.insert(peer, tx);
            state.peer_ledger_range.insert(peer, (1, 10));
            state.peers.insert(peer, PeerState::Active);
        }

        peer_useful_counts.insert(PeerId(1), 100);
        peer_useful_counts.insert(PeerId(2), 60);
        peer_useful_counts.insert(PeerId(3), 49);
        peer_useful_counts.insert(PeerId(4), 10);

        let mut selected = node.select_reply_sync_peers(&state, 5, &peer_useful_counts, 6);
        selected.sort_by_key(|pid| pid.0);

        assert_eq!(selected, vec![PeerId(1), PeerId(2), PeerId(3), PeerId(4)]);
    }

    #[test]
    fn test_select_timeout_sync_peers_prefers_recently_useful_peers() {
        let node = Node::new(NodeConfig::default());
        let mut state = SharedState::new(crate::rpc::NodeContext::default());

        for id in 1..=4 {
            let peer = PeerId(id);
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            state.peer_txs.insert(peer, tx);
            state.peer_ledger_range.insert(peer, (1, 10));
            state.peers.insert(peer, PeerState::Active);
            state.peer_sync_useful.insert(peer, (100 - id) as u32);
        }

        let now = std::time::Instant::now();
        state
            .peer_sync_last_useful
            .insert(PeerId(3), now - std::time::Duration::from_secs(2));
        state
            .peer_sync_last_useful
            .insert(PeerId(2), now - std::time::Duration::from_secs(4));
        state
            .peer_sync_last_useful
            .insert(PeerId(1), now - std::time::Duration::from_secs(40));

        let selected = node.select_timeout_sync_peers(&state, 5, 2);
        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&PeerId(2)));
        assert!(selected.contains(&PeerId(3)));
        assert!(!selected.contains(&PeerId(1)));
    }

    #[test]
    fn test_select_timeout_sync_peers_backfills_from_broader_mesh() {
        let node = Node::new(NodeConfig::default());
        let mut state = SharedState::new(crate::rpc::NodeContext::default());

        for id in 1..=4 {
            let peer = PeerId(id);
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            state.peer_txs.insert(peer, tx);
            state.peer_ledger_range.insert(peer, (1, 10));
            state.peers.insert(peer, PeerState::Active);
            state.peer_sync_useful.insert(peer, (100 - id) as u32);
        }

        let now = std::time::Instant::now();
        state
            .peer_sync_last_useful
            .insert(PeerId(2), now - std::time::Duration::from_secs(5));

        let selected = node.select_timeout_sync_peers(&state, 5, 3);
        assert_eq!(selected.len(), 3);
        assert!(selected.contains(&PeerId(2)));
        assert!(selected.contains(&PeerId(1)));
        assert!(selected.contains(&PeerId(3)));
    }

    #[test]
    fn test_rotate_sync_peer_window_advances_across_ranked_mesh() {
        let eligible = vec![
            (PeerId(1), 100, 10),
            (PeerId(2), 80, 20),
            (PeerId(3), 60, 30),
            (PeerId(4), 40, 40),
            (PeerId(5), 20, 50),
        ];

        assert_eq!(
            sync_mesh::rotate_sync_peer_window(eligible.clone(), 3, 0),
            vec![PeerId(1), PeerId(2), PeerId(3)]
        );
        assert_eq!(
            sync_mesh::rotate_sync_peer_window(eligible.clone(), 3, 1),
            vec![PeerId(2), PeerId(3), PeerId(4)]
        );
        assert_eq!(
            sync_mesh::rotate_sync_peer_window(eligible, 3, 4),
            vec![PeerId(5), PeerId(1), PeerId(2)]
        );
    }

    #[test]
    fn test_root_bootstrap_requests_split_root_children_without_tree_walk() {
        let header = crate::ledger::LedgerHeader::default();
        let mut syncer =
            crate::sync_coordinator::SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header);
        let mut root_wire = vec![0u8; 513];
        root_wire[..32].fill(0xAA);
        root_wire[32..64].fill(0xBB);
        root_wire[512] = 0x02;

        let reqs = crate::sync_bootstrap::build_root_bootstrap_requests(&mut syncer, &root_wire, 2);
        assert_eq!(reqs.len(), 2);
        assert_eq!(syncer.peer.in_flight, 2);
        assert_eq!(syncer.peer.recent_nodes.len(), 2);

        for req in reqs {
            let pb = <crate::proto::TmGetLedger as ProstMessage>::decode(req.payload.as_slice())
                .unwrap();
            assert_eq!(pb.node_i_ds.len(), 1);
        }
    }

    #[test]
    fn test_parse_http_content_length_case_insensitive() {
        let header = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(http_io::parse_http_content_length(header), Some(42));

        let header = b"POST / HTTP/1.1\r\ncontent-length: 7\r\n\r\n";
        assert_eq!(http_io::parse_http_content_length(header), Some(7));
    }

    #[test]
    fn test_build_li_base_nodes_includes_optional_roots_after_header() {
        let header = test_header(321, 0x5A);
        let state_root_wire = vec![0x11; 513];
        let tx_root_wire = vec![0x22; 513];

        let nodes = super::build_li_base_nodes(
            &header,
            Some(state_root_wire.clone()),
            Some(tx_root_wire.clone()),
        );
        assert_eq!(nodes.len(), 3);
        assert!(nodes[0].nodeid.is_none());
        let decoded = crate::sync::parse_ledger_header_from_base(&nodes[0].nodedata)
            .expect("header should decode");
        assert_eq!(decoded.sequence, header.sequence);
        assert_eq!(decoded.account_hash, header.account_hash);
        assert_eq!(decoded.transaction_hash, header.transaction_hash);
        assert_eq!(nodes[1].nodedata, state_root_wire);
        assert_eq!(
            nodes[1].nodeid.as_deref(),
            Some(&crate::ledger::shamap_id::SHAMapNodeID::root().to_wire()[..])
        );
        assert_eq!(nodes[2].nodedata, tx_root_wire);
        assert_eq!(
            nodes[2].nodeid.as_deref(),
            Some(&crate::ledger::shamap_id::SHAMapNodeID::root().to_wire()[..])
        );

        let header_only = super::build_li_base_nodes(&header, None, None);
        assert_eq!(header_only.len(), 1);
    }

    #[test]
    fn test_should_refuse_get_ledger_for_local_load_and_full_peer_queue() {
        let mut load = crate::network::load::LoadSnapshot::default();
        assert!(!super::should_refuse_get_ledger_for_load(
            &load,
            Some(8),
            crate::proto::TmLedgerInfoType::LiBase as i32,
        ));

        assert!(super::should_refuse_get_ledger_for_load(
            &load,
            Some(0),
            crate::proto::TmLedgerInfoType::LiBase as i32,
        ));

        load.local_fee = load.load_base * 3;
        assert!(super::should_refuse_get_ledger_for_load(
            &load,
            Some(8),
            crate::proto::TmLedgerInfoType::LiAsNode as i32,
        ));
        assert!(!super::should_refuse_get_ledger_for_load(
            &load,
            Some(0),
            crate::proto::TmLedgerInfoType::LiTsCandidate as i32,
        ));
    }

    #[test]
    fn test_sync_gate_accepts_ltclosed_ledgerdata_response() {
        let header = crate::ledger::LedgerHeader::default();
        let sync = std::sync::Mutex::new(Some(crate::sync_coordinator::SyncCoordinator::new(
            10, [0u8; 32], [0x22; 32], None, header,
        )));

        assert!(sync_gate_accepts_response(
            &sync,
            0,
            Some(&[0xAB; 32]),
            None,
            false,
        ));
    }

    #[test]
    fn test_sync_gate_accepts_ltclosed_object_response_without_seq() {
        let header = crate::ledger::LedgerHeader::default();
        let sync = std::sync::Mutex::new(Some(crate::sync_coordinator::SyncCoordinator::new(
            10, [0u8; 32], [0x22; 32], None, header,
        )));

        assert!(sync_gate_accepts_response(
            &sync,
            0,
            Some(&[0xEF; 32]),
            None,
            true,
        ));
        assert!(sync_gate_accepts_response(
            &sync,
            0,
            Some(&[0xEF; 32]),
            Some(78),
            true,
        ));
    }

    #[test]
    fn test_sync_gate_accepts_non_ltclosed_object_response_by_target_hash() {
        let header = crate::ledger::LedgerHeader::default();
        let ledger_hash = [0xAB; 32];
        let sync = std::sync::Mutex::new(Some(crate::sync_coordinator::SyncCoordinator::new(
            10,
            ledger_hash,
            [0x22; 32],
            None,
            header,
        )));
        let target_h8 = u64::from_be_bytes(ledger_hash[..8].try_into().unwrap());

        assert!(sync_gate_accepts_response(
            &sync,
            target_h8,
            Some(&ledger_hash),
            None,
            true,
        ));
        assert!(!sync_gate_accepts_response(
            &sync,
            target_h8,
            Some(&[0xCD; 32]),
            None,
            true,
        ));
    }

    #[test]
    fn test_timeout_object_fallback_disabled_in_ltclosed_mode() {
        assert!(!should_use_timeout_object_fallback(true, 5, &[0u8; 32]));
        assert!(!should_use_timeout_object_fallback(true, 10, &[0u8; 32]));
        assert!(should_use_timeout_object_fallback(true, 5, &[0xAB; 32]));
        assert!(!should_use_timeout_object_fallback(false, 5, &[0xAB; 32]));
    }

    #[test]
    fn test_timeout_object_fallback_matches_rippled_aggressive_threshold() {
        assert!(!should_use_timeout_object_fallback(true, 4, &[0xAB; 32]));
        assert!(should_use_timeout_object_fallback(true, 5, &[0xAB; 32]));
    }

    #[test]
    fn test_fixed_target_sync_reacquires_immediately_after_failure() {
        let inactive = Some((777, [0xAB; 32]));
        let (seq, hash, reason) = crate::sync_bootstrap::choose_sync_kickstart_target(
            inactive,
            900,
            Some([0xCD; 32]),
            None,
        );
        assert_eq!(seq, 777);
        assert_eq!(hash, Some([0xAB; 32]));
        assert_eq!(reason, "fixed-target reacquire");
    }

    #[test]
    fn test_stale_fixed_target_sync_retargets_to_latest_trusted_ledger() {
        let inactive = Some((123, [0xAB; 32]));
        let latest_hash = [0xCD; 32];
        let (seq, hash, reason) = crate::sync_bootstrap::choose_sync_kickstart_target(
            inactive,
            456,
            Some(latest_hash),
            None,
        );
        assert_eq!(seq, 456);
        assert_eq!(hash, Some(latest_hash));
        assert_eq!(reason, "stale fixed-target retarget");
    }

    #[test]
    fn test_sync_timeout_counter_matches_rippled_progress_cycle() {
        let mut peer = crate::sync::PeerSyncManager::new(10, [0x11; 32], [0x22; 32]);

        assert_eq!(
            peer.on_timer_tick(),
            Some(crate::ledger::inbound::TimeoutTick::Timeout(1))
        );

        peer.note_progress();

        assert_eq!(
            peer.on_timer_tick(),
            Some(crate::ledger::inbound::TimeoutTick::Progress)
        );
        assert_eq!(
            peer.on_timer_tick(),
            Some(crate::ledger::inbound::TimeoutTick::Timeout(2))
        );
    }

    #[test]
    fn test_sync_timeout_does_not_build_bulk_reply_requests() {
        let header = crate::ledger::LedgerHeader::default();
        let sync = std::sync::Arc::new(std::sync::Mutex::new(Some(
            crate::sync_coordinator::SyncCoordinator::new(10, [0x11; 32], [0x22; 32], None, header),
        )));

        let (reqs, seq, abandon) =
            Node::sync_trigger_blocking(&sync, &None, TriggerReason::Timeout);

        assert!(reqs.is_empty());
        assert_eq!(seq, 10);
        assert!(!abandon);
    }

    #[test]
    fn test_choose_sync_kickstart_target_prefers_nearby_inactive_fixed_target() {
        let latest_hash = [0x11; 32];
        let fixed_hash = [0xAB; 32];
        assert_eq!(
            crate::sync_bootstrap::choose_sync_kickstart_target(
                Some((350, fixed_hash)),
                456,
                Some(latest_hash),
                None,
            ),
            (350, Some(fixed_hash), "fixed-target reacquire"),
        );
        assert_eq!(
            crate::sync_bootstrap::choose_sync_kickstart_target(
                Some((123, fixed_hash)),
                456,
                Some(latest_hash),
                None,
            ),
            (456, Some(latest_hash), "stale fixed-target retarget"),
        );
        assert_eq!(
            crate::sync_bootstrap::choose_sync_kickstart_target(None, 456, Some(latest_hash), None,),
            (456, Some(latest_hash), "no syncer yet"),
        );
        assert_eq!(
            crate::sync_bootstrap::choose_sync_kickstart_target(None, 456, None, Some(789)),
            (
                789,
                None,
                "no syncer yet (seq-only; using reachable peer latest)"
            ),
        );
        assert_eq!(
            crate::sync_bootstrap::choose_sync_kickstart_target(None, 456, None, None),
            (
                456,
                None,
                "no syncer yet (seq-only; trusted hash unavailable)"
            ),
        );
    }

    #[test]
    fn test_choose_reachable_seq_only_target_uses_peer_latest_when_local_is_stale() {
        assert_eq!(
            crate::sync_bootstrap::choose_reachable_seq_only_target(100, &[(150, 200), (180, 250)],),
            Some(250),
        );
        assert_eq!(
            crate::sync_bootstrap::choose_reachable_seq_only_target(190, &[(150, 200), (180, 250)],),
            None,
        );
        assert_eq!(
            crate::sync_bootstrap::choose_reachable_seq_only_target(100, &[]),
            None,
        );
    }

    #[test]
    fn test_should_start_sync_from_header_allows_inactive_fixed_target_match() {
        let target_hash = [0xAB; 32];
        assert!(crate::sync_bootstrap::should_start_sync_from_header(
            false,
            123,
            target_hash,
            Some((123, target_hash)),
        ));
        assert!(!crate::sync_bootstrap::should_start_sync_from_header(
            false,
            123,
            [0xCD; 32],
            Some((123, target_hash)),
        ));
        assert!(!crate::sync_bootstrap::should_start_sync_from_header(
            false,
            124,
            target_hash,
            Some((123, target_hash)),
        ));
        assert!(crate::sync_bootstrap::should_start_sync_from_header(
            true, 999, [0x11; 32], None,
        ));
    }

    #[test]
    fn test_should_resume_from_sync_anchor_requires_usable_root_and_anchor() {
        assert!(crate::sync_bootstrap::should_resume_from_sync_anchor(
            true, true, true, false, true
        ));
        assert!(crate::sync_bootstrap::should_resume_from_sync_anchor(
            true, true, false, true, true
        ));
        assert!(!crate::sync_bootstrap::should_resume_from_sync_anchor(
            true, true, false, false, true
        ));
        assert!(!crate::sync_bootstrap::should_resume_from_sync_anchor(
            true, false, true, true, true
        ));
        assert!(!crate::sync_bootstrap::should_resume_from_sync_anchor(
            true, true, true, true, false
        ));
        assert!(!crate::sync_bootstrap::should_resume_from_sync_anchor(
            false, true, true, true, true
        ));
    }

    #[test]
    fn test_should_prefer_history_latest_only_after_completed_sync_without_resume_header() {
        assert!(crate::sync_bootstrap::should_prefer_history_latest(
            true, false
        ));
        assert!(!crate::sync_bootstrap::should_prefer_history_latest(
            true, true
        ));
        assert!(!crate::sync_bootstrap::should_prefer_history_latest(
            false, false
        ));
    }

    #[test]
    fn test_should_issue_reply_followup_refills_zero_useful_epochs() {
        assert!(should_issue_reply_followup("Continue", true));
        assert!(should_issue_reply_followup("PassComplete", true));
        assert!(should_issue_reply_followup("Continue", false));
        assert!(!should_issue_reply_followup("Inactive", true));
    }

    #[test]
    fn test_is_pending_sync_anchor_allows_exact_hash_match_when_seq_missing() {
        let pending = Some((555, [0xAB; 32]));
        assert!(is_pending_sync_anchor(pending, 0, &[0xAB; 32]));
        assert!(is_pending_sync_anchor(pending, 555, &[0xAB; 32]));
        assert!(!is_pending_sync_anchor(pending, 556, &[0xAB; 32]));
        assert!(!is_pending_sync_anchor(pending, 0, &[0xCD; 32]));
    }

    #[test]
    fn test_plan_sync_completion_outcome_requires_target_hash_match() {
        let outcome = plan_sync_completion_outcome([0xAA; 32], [0xBB; 32]);

        assert!(!outcome.verified);
        assert!(outcome.clear_sync_in_progress);
        assert!(!outcome.persist_anchor);
        assert!(!outcome.mark_sync_done);
        assert!(!outcome.broadcast_connected);
        assert!(!outcome.start_follower);
    }

    #[test]
    fn test_plan_sync_completion_outcome_commits_verified_handoff() {
        let outcome = plan_sync_completion_outcome([0xCC; 32], [0xCC; 32]);

        assert!(outcome.verified);
        assert!(outcome.clear_sync_in_progress);
        assert!(outcome.persist_anchor);
        assert!(outcome.mark_sync_done);
        assert!(outcome.broadcast_connected);
        assert!(outcome.start_follower);
    }

    #[test]
    fn test_resolve_get_ledger_header_ltclosed_ignores_sequence() {
        let current = test_header(100, 0xAA);
        let historical = test_header(80, 0x55);
        let mut history = crate::ledger::history::LedgerStore::with_limit(None);
        history.insert_ledger(historical, vec![]);

        let req = crate::proto::TmGetLedger {
            ltype: Some(crate::proto::TmLedgerType::LtClosed as i32),
            ledger_seq: Some(80),
            ..Default::default()
        };

        let resolved = super::resolve_get_ledger_header(&req, &current, &history).unwrap();
        assert_eq!(resolved.hash, current.hash);
        assert_eq!(resolved.sequence, current.sequence);
    }

    #[test]
    fn test_resolve_get_ledger_header_rejects_ltcurrent() {
        let current = test_header(100, 0xAA);
        let history = crate::ledger::history::LedgerStore::with_limit(None);
        let req = crate::proto::TmGetLedger {
            ltype: Some(crate::proto::TmLedgerType::LtCurrent as i32),
            ..Default::default()
        };

        assert!(matches!(
            super::resolve_get_ledger_header(&req, &current, &history),
            Err(crate::proto::TmReplyError::ReBadRequest)
        ));
    }

    #[test]
    fn test_resolve_get_ledger_header_rejects_malformed_hash() {
        let current = test_header(100, 0xAA);
        let history = crate::ledger::history::LedgerStore::with_limit(None);
        let req = crate::proto::TmGetLedger {
            ledger_hash: Some(vec![0xAB; 31]),
            ..Default::default()
        };

        assert!(matches!(
            super::resolve_get_ledger_header(&req, &current, &history),
            Err(crate::proto::TmReplyError::ReBadRequest)
        ));
    }

    #[test]
    fn test_resolve_get_ledger_header_hash_lookup_uses_history() {
        let current = test_header(100, 0xAA);
        let historical = test_header(80, 0x55);
        let mut history = crate::ledger::history::LedgerStore::with_limit(None);
        history.insert_ledger(historical.clone(), vec![]);

        let req = crate::proto::TmGetLedger {
            ledger_hash: Some(historical.hash.to_vec()),
            ..Default::default()
        };

        let resolved = super::resolve_get_ledger_header(&req, &current, &history).unwrap();
        assert_eq!(resolved.hash, historical.hash);
        assert_eq!(resolved.sequence, historical.sequence);
    }

    #[test]
    fn test_tune_sync_request_for_peer_latency_deepens_high_latency_li_as_node_reply() {
        let req = crate::network::relay::encode_get_ledger_state(
            &[0xAB; 32],
            &[vec![0u8; 33]],
            0,
            1,
            None,
            444,
        );

        let tuned =
            tune_sync_request_for_peer_latency(&req, Some(300)).expect("should deepen request");
        let pb = <crate::proto::TmGetLedger as ProstMessage>::decode(tuned.payload.as_slice())
            .expect("tuned request should decode");
        assert_eq!(pb.query_depth, Some(2));
    }

    #[test]
    fn test_tune_sync_request_for_peer_latency_leaves_timeout_requests_alone() {
        let req = crate::network::relay::encode_get_ledger_state(
            &[0xAB; 32],
            &[vec![0u8; 33]],
            0,
            0,
            Some(crate::proto::TmQueryType::QtIndirect as i32),
            444,
        );

        assert!(tune_sync_request_for_peer_latency(&req, Some(600)).is_none());
    }

    #[test]
    fn test_collect_shamap_ledger_nodes_dedupes_fat_queries() {
        let mut map = crate::ledger::shamap::SHAMap::new_state();
        let key_a = crate::ledger::Key::from_hex(
            "1000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let key_b = crate::ledger::Key::from_hex(
            "1100000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let key_c = crate::ledger::Key::from_hex(
            "2000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        map.insert(key_a, b"alpha".to_vec());
        map.insert(key_b, b"beta".to_vec());
        map.insert(key_c, b"gamma".to_vec());

        let root_id = crate::ledger::shamap_id::SHAMapNodeID::root();
        let branch_one = root_id.child_id(1);
        let (nodes, invalid) = super::collect_shamap_ledger_nodes(
            &mut map,
            &[root_id.to_wire().to_vec(), branch_one.to_wire().to_vec()],
            1,
        );

        assert_eq!(invalid, 0);
        assert_eq!(nodes.len(), 5);

        let mut unique_ids: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
        for node in &nodes {
            unique_ids.insert(node.nodeid.clone().expect("query responses carry node ids"));
        }
        assert_eq!(unique_ids.len(), nodes.len());
    }
}
