//! The Node — ties all subsystems together and runs the main event loop.
//!
//! Responsibilities:
//! - Accept inbound TCP peer connections (optionally wrapped in TLS)
//! - Dial outbound peers from a bootstrap list
//! - Dispatch incoming RTXP messages to the right handler
//! - Serve JSON-RPC requests over HTTP
//! - Drive consensus rounds

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use prost::Message as ProstMessage;
use tracing::{debug, error, info, trace, warn};

use crate::crypto::keys::Secp256k1KeyPair;
use crate::network::message::{FrameDecoder, MessageType, RtxpMessage, HEADER_SIZE};
use crate::network::peer::{Direction, Peer, PeerAction, PeerEvent, PeerId, PeerState};
use crate::rpc::{dispatch, NodeContext, RpcRequest};
use crate::tls::OpenSslConfig;

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

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Address to listen on for peer connections.
    pub peer_addr: SocketAddr,
    /// Address to listen on for JSON-RPC requests.
    pub rpc_addr:  SocketAddr,
    /// Address to listen on for WebSocket connections.
    pub ws_addr:   SocketAddr,
    /// Maximum number of connected peers.
    pub max_peers: usize,
    /// Bootstrap peers to dial on startup.
    pub bootstrap: Vec<SocketAddr>,
    /// Whether to wrap peer connections in TLS.
    pub use_tls:   bool,
    /// Directory for persistent storage (None = in-memory only).
    pub data_dir:    Option<std::path::PathBuf>,
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
    /// Historical fetch depth we advertise/serve.
    pub fetch_depth: crate::config::HistoryRetention,
    /// Online delete / pruning threshold. `None` keeps all persisted history.
    pub online_delete: Option<u32>,
    /// Whether to run the local consensus/ledger close loop.
    /// Normal follower nodes should leave this off.
    pub enable_consensus_close_loop: bool,
    /// Optional script run at sync completion before follower starts.
    /// Used to snapshot the freshly-synced data dir for quick restore.
    pub post_sync_checkpoint_script: Option<std::path::PathBuf>,
    /// Base58-encoded validation seed. When set, the node becomes a validator
    /// and signs proposals/validations with the derived key instead of node_key.
    pub validation_seed: Option<String>,
}

impl NodeConfig {
    /// Maximum outbound peer slots. Matches rippled: ~60% of max_peers, minimum 10.
    pub fn max_outbound(&self) -> usize {
        ((self.max_peers * 15 + 50) / 100).max(10).min(self.max_peers)
    }
    /// Maximum inbound peer slots. Remainder after outbound.
    pub fn max_inbound(&self) -> usize {
        self.max_peers.saturating_sub(self.max_outbound())
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            peer_addr:   "0.0.0.0:51235".parse().unwrap(),
            rpc_addr:    "127.0.0.1:5005".parse().unwrap(),
            ws_addr:     "127.0.0.1:6006".parse().unwrap(),
            max_peers:   21,
            bootstrap:   vec![],
            use_tls:     true,
            data_dir:    None,
            config_file: None,
            network_id:  0,
            max_sync:    0,
            rpc_sync:    None,
            full_history_peers: vec![],
            ledger_history: crate::config::HistoryRetention::Count(256),
            fetch_depth: crate::config::HistoryRetention::Full,
            online_delete: None,
            enable_consensus_close_loop: false,
            post_sync_checkpoint_script: None,
            validation_seed: None,
        }
    }
}

// ── Shared state ──────────────────────────────────────────────────────────────

/// State shared across all peer tasks and the RPC server.
pub struct SharedState {
    pub ctx:      NodeContext,
    pub peers:    HashMap<PeerId, PeerState>,
    /// One sender per connected peer — write an RtxpMessage here and the
    /// peer task will send it on the wire.
    pub peer_txs: HashMap<PeerId, mpsc::Sender<RtxpMessage>>,
    /// Known peer addresses (for peer discovery exchange).
    /// Known peer addresses — VecDeque for round-robin cycling.
    /// Pop from front to dial, push to back after use. Ensures even rotation.
    pub known_peers: std::collections::VecDeque<SocketAddr>,
    /// True while a snapshot or history sync is in progress.
    pub sync_in_progress: bool,
    /// True after the first state sync has completed — prevents re-syncing.
    pub sync_done: bool,
    /// Addresses of currently connected peers (to avoid double-dialing).
    pub connected_addrs: std::collections::HashSet<SocketAddr>,
    /// Per-peer measured latency in milliseconds (from ping/pong round-trip).
    pub peer_latency: HashMap<PeerId, u32>,
    /// Per-peer ping send time — to measure round-trip when pong arrives.
    pub peer_ping_sent: HashMap<PeerId, (u32, std::time::Instant)>,  // (seq, sent_at)
    /// PeerId → SocketAddr mapping for identifying localhost/cluster peers.
    pub peer_addrs: HashMap<PeerId, SocketAddr>,
    /// Cooldown for failed/rejected peer addresses — don't re-dial for 130s.
    pub peer_cooldowns: HashMap<SocketAddr, std::time::Instant>,
    /// Peers that failed to respond to sync requests — benched for 20 minutes.
    pub sync_peer_cooldown: HashMap<PeerId, std::time::Instant>,
    /// Recent sync usefulness by peer — higher means recent liAS_NODE batches
    /// from this peer contained more useful nodes.
    pub peer_sync_useful: HashMap<PeerId, u32>,
    /// Track repeated implausible validations so bad peers don't spam logs forever.
    pub implausible_validation_state: HashMap<PeerId, (std::time::Instant, u32)>, // (last_seen, count)
    /// RPC sync progress counters (when --rpc-sync is used).
    pub rpc_sync_state: Option<Arc<crate::rpc_sync::RpcSyncState>>,
    /// Ledger follower progress (when --rpc-sync is used).
    pub follower_state: Option<Arc<crate::ledger::follow::FollowerState>>,
    /// Deep-history peer addresses (100K+ ledger span, from /crawl). Used as bootstrap hints.
    pub full_history_peers: Vec<SocketAddr>,
    /// Per-peer ledger range — populated from TMStatusChange firstSeq/lastSeq.
    /// This is the authoritative source for which peers have which ledgers.
    pub peer_ledger_range: HashMap<PeerId, (u32, u32)>,  // (min_seq, max_seq)
    /// Active consensus round — tracks proposals and validations.
    pub current_round: Option<crate::consensus::ConsensusRound>,
    /// Proposals received for the next ledger before our round opens.
    staged_proposals: HashMap<String, crate::consensus::Proposal>,
    peer_counter: u64,
    /// Per-peer connection direction (inbound vs outbound).
    pub peer_direction: HashMap<PeerId, Direction>,
    /// Per-peer squelch state: peer told us "don't relay validator X's messages to me."
    /// Keyed by (peer_id → validator_pubkey → expiry). Lazy expiry on read.
    pub peer_squelch: HashMap<PeerId, HashMap<Vec<u8>, std::time::Instant>>,
    /// Ring buffer of recently validated ledger hashes, keyed by seq.
    /// Populated by the validation handler. The follower looks up N+1 here
    /// to replay consecutive ledgers. Capacity 256.
    pub validated_hashes: std::collections::HashMap<u32, [u8; 32]>,
    /// Ordered list of validated seqs for ring buffer eviction.
    validated_hash_order: std::collections::VecDeque<u32>,
}

impl SharedState {
    fn new(ctx: NodeContext) -> Self {
        Self {
            ctx, peers: HashMap::new(), peer_txs: HashMap::new(),
            known_peers: std::collections::VecDeque::new(),
            connected_addrs: std::collections::HashSet::new(),
            peer_latency: HashMap::new(),
            peer_ping_sent: HashMap::new(),
            peer_addrs: HashMap::new(),
            peer_cooldowns: HashMap::new(),
            sync_peer_cooldown: HashMap::new(),
            peer_sync_useful: HashMap::new(),
            implausible_validation_state: HashMap::new(),
            rpc_sync_state: None,
            follower_state: None,
            full_history_peers: vec![],
            peer_ledger_range: HashMap::new(),
            current_round: None,
            staged_proposals: HashMap::new(),
            sync_in_progress: false,
            sync_done: false,
            peer_counter: 0,
            peer_direction: HashMap::new(),
            peer_squelch: HashMap::new(),
            validated_hashes: std::collections::HashMap::new(),
            validated_hash_order: std::collections::VecDeque::new(),
        }
    }

    /// Record a validated ledger hash. Replaces any previous hash for the same
    /// seq (handles multiple validators reporting different hashes — last wins,
    /// which is fine since trusted validations converge). Evicts oldest when
    /// capacity exceeds 256.
    pub fn record_validated_hash(&mut self, seq: u32, hash: [u8; 32]) {
        if !self.validated_hashes.contains_key(&seq) {
            self.validated_hash_order.push_back(seq);
            // Evict oldest if over capacity
            while self.validated_hash_order.len() > 256 {
                if let Some(old_seq) = self.validated_hash_order.pop_front() {
                    self.validated_hashes.remove(&old_seq);
                }
            }
        }
        // Always overwrite — later validations for the same seq are fine
        self.validated_hashes.insert(seq, hash);
    }

    fn next_peer_id(&mut self) -> PeerId {
        self.peer_counter += 1;
        PeerId(self.peer_counter)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.values().filter(|s| s.is_open()).count()
    }

    /// Count active inbound peers.
    pub fn inbound_count(&self) -> usize {
        self.peer_direction.iter()
            .filter(|(id, dir)| **dir == Direction::Inbound && self.peers.get(id).map_or(false, |s| s.is_open()))
            .count()
    }

    /// Count active outbound peers.
    pub fn outbound_count(&self) -> usize {
        self.peer_direction.iter()
            .filter(|(id, dir)| **dir == Direction::Outbound && self.peers.get(id).map_or(false, |s| s.is_open()))
            .count()
    }

    /// Add a peer address to known_peers if not already present.
    /// Capped at 1000 entries to prevent unbounded growth.
    pub fn add_known_peer(&mut self, addr: SocketAddr) {
        if !self.known_peers.contains(&addr) {
            if self.known_peers.len() >= 1000 {
                self.known_peers.pop_front();
            }
            self.known_peers.push_back(addr);
        }
    }

    /// Send a message to every connected peer (except `exclude`).
    pub fn broadcast(&self, msg: &RtxpMessage, exclude: Option<PeerId>) {
        for (&id, tx) in &self.peer_txs {
            if exclude == Some(id) { continue; }
            let _ = tx.try_send(msg.clone());
        }
    }

    /// Broadcast a validation/proposal to all peers, but skip peers that have
    /// squelched the given validator pubkey. Lazy expiry: stale entries are
    /// removed on check. Returns the number of relays skipped due to squelch.
    pub fn broadcast_with_squelch(
        &mut self,
        msg: &RtxpMessage,
        exclude: Option<PeerId>,
        validator_pubkey: &[u8],
    ) -> usize {
        let now = std::time::Instant::now();
        let mut skipped = 0usize;
        for (&id, tx) in &self.peer_txs {
            if exclude == Some(id) { continue; }
            // Check squelch state for this peer + validator.
            if let Some(map) = self.peer_squelch.get_mut(&id) {
                if let Some(&expiry) = map.get(validator_pubkey) {
                    if now < expiry {
                        skipped += 1;
                        continue; // squelched — skip
                    } else {
                        // Expired — remove lazily.
                        map.remove(validator_pubkey);
                    }
                }
            }
            let _ = tx.try_send(msg.clone());
        }
        skipped
    }

    /// Send a message to N deep-history peers, round-robin style.
    /// Send to N peers that have a specific ledger, round-robin.
    /// Uses peer_ledger_range from TMStatusChange — the authoritative source.
    pub fn send_to_peers_with_ledger(&mut self, msg: &RtxpMessage, seq: u32, count: usize) -> usize {
        use rand::seq::SliceRandom;

        let is_configured_full_history = |pid: &PeerId| {
            self.peer_addrs.get(pid)
                .map(|addr| self.full_history_peers.contains(addr))
                .unwrap_or(false)
        };
        let mut eligible: Vec<(PeerId, u32, u32)> = self.peer_txs.keys()
            .filter(|pid| {
                self.peer_ledger_range.get(pid)
                    .map_or_else(
                        || is_configured_full_history(pid),
                        |&(min, max)| (seq >= min && seq <= max) || is_configured_full_history(pid),
                    )
            })
            .map(|pid| {
                let useful = self.peer_sync_useful.get(pid).copied().unwrap_or(0);
                let latency = self.peer_latency.get(pid).copied().unwrap_or(u32::MAX / 4);
                (*pid, useful, latency)
            })
            .collect();

        if eligible.is_empty() {
            // Debug: how many ranges do we have vs connected peers?
            let ranges = self.peer_ledger_range.len();
            let connected = self.peer_txs.len();
            let covering = self.peer_ledger_range.values()
                .filter(|&&(min, max)| seq >= min && seq <= max).count();
            if ranges > 0 {
                tracing::debug!(
                    "send_to_peers: seq={} connected={} ranges={} covering={} (no eligible — range/peer mismatch?)",
                    seq, connected, ranges, covering,
                );
            }
            return 0;
        }

        eligible.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| a.2.cmp(&b.2))
                .then_with(|| a.0.0.cmp(&b.0.0))
        });

        let best_useful = eligible.first().map(|(_, useful, _)| *useful).unwrap_or(0);
        if best_useful > 0 {
            let threshold = best_useful / 2;
            eligible.retain(|(_, useful, _)| *useful >= threshold);
        }

        let mut rng = rand::thread_rng();
        eligible.shuffle(&mut rng);

        let mut sent = 0;
        for (peer_id, _, _) in eligible.into_iter().take(count) {
            if let Some(tx) = self.peer_txs.get(&peer_id) {
                if tx.try_send(msg.clone()).is_ok() {
                    sent += 1;
                }
            }
        }
        sent
    }
}

fn should_close_ledger(
    any_transactions: bool,
    prev_proposers: usize,
    proposers_closed: usize,
    proposers_validated: usize,
    prev_round_time: std::time::Duration,
    time_since_prev_close: std::time::Duration,
    open_time: std::time::Duration,
    idle_interval: std::time::Duration,
) -> bool {
    use std::time::Duration;

    if prev_round_time > Duration::from_secs(600)
        || time_since_prev_close > Duration::from_secs(600)
    {
        return true;
    }

    if (proposers_closed + proposers_validated) > (prev_proposers / 2) {
        return true;
    }

    if !any_transactions {
        return time_since_prev_close >= idle_interval;
    }

    if open_time < Duration::from_secs(2) {
        return false;
    }

    if open_time < prev_round_time / 2 {
        return false;
    }

    true
}

/// Parse "host:port" string, defaulting to port 6008.
fn parse_host_port(s: &str) -> (String, u16) {
    if let Some(colon) = s.rfind(':') {
        let host = s[..colon].to_string();
        let port = s[colon + 1..].parse().unwrap_or(6008);
        (host, port)
    } else {
        (s.to_string(), 6008)
    }
}

// ── Node ──────────────────────────────────────────────────────────────────────

pub struct Node {
    config:    NodeConfig,
    state:     Arc<RwLock<SharedState>>,
    /// Broadcast channel for WebSocket event streaming.
    ws_events: tokio::sync::broadcast::Sender<crate::rpc::ws::WsEvent>,
    /// Persistent storage (None = in-memory only).
    storage:   Option<Arc<crate::storage::Storage>>,
    /// The node's secp256k1 identity key (used for peer handshakes).
    node_key:  Secp256k1KeyPair,
    /// Validator signing key derived from [validation_seed] config.
    /// When Some, the node signs validations & proposals with this key.
    validator_key: Option<Secp256k1KeyPair>,
    /// OpenSSL TLS configuration for peer connections (computes rippled-compatible session hash).
    openssl_tls: Option<OpenSslConfig>,
    /// Direct reference to NuDB backend for lock-free sync writes.
    /// Bypasses LedgerState + SHAMap mutexes — like rippled's gotNode() callback.
    nudb_backend: Option<Arc<dyn crate::ledger::node_store::NodeStore>>,
    /// Trusted validator public keys for ConsensusRound.
    /// Behind Arc<RwLock> so the validator list fetch loop can update it.
    unl:       Arc<std::sync::RwLock<Vec<Vec<u8>>>>,
    /// Validator list publisher config (sites + publisher keys).
    validator_list_config: crate::config::ValidatorListConfig,
    /// Shutdown signal — all background tasks check this and exit when true.
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    /// Active state syncer — downloads the account state SHAMap tree.
    sync: Arc<std::sync::Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
    /// Lock-free gate for liAS_NODE intake: first 8 bytes of the current sync target hash.
    /// Updated when syncer is created/restarted. Allows response routing without acquiring sync lock.
    sync_target_hash8: Arc<std::sync::atomic::AtomicU64>,
    /// Round-robin index for distributing sync requests across peers.
    sync_rr: Arc<std::sync::atomic::AtomicUsize>,
    /// Queue for liAS_NODE responses — matches rippled's mReceivedData.
    /// Push under lock (fast), then notify runData to process.
    sync_data_queue: Arc<std::sync::Mutex<Vec<(PeerId, crate::proto::TmLedgerData)>>>,
    /// Notify signal for runData — wakes the data processor when new responses arrive.
    sync_data_notify: Arc<tokio::sync::Notify>,
    /// Channel for diff sync responses (liAS_NODE during follow mode).
    diff_sync_tx: mpsc::Sender<crate::proto::TmLedgerData>,
    diff_sync_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<crate::proto::TmLedgerData>>>,
    /// Message dedup — separate from SharedState to avoid lock contention.
    /// SHA-256 of payload → true if seen. Cleared periodically.
    msg_dedup: Arc<std::sync::Mutex<(std::collections::HashSet<[u8; 32]>, std::time::Instant)>>,
    /// Debug log file for sync diagnostics (separate from main xledgrs.log).
    debug_log: Arc<std::sync::Mutex<Option<std::fs::File>>>,
    /// Lock-free RPC snapshot — updated atomically, read instantly by server_info.
    rpc_snapshot: arc_swap::ArcSwap<crate::rpc::RpcSnapshot>,
    /// Lock-free read-only RPC context — avoids SharedState lock contention for normal reads.
    rpc_read_ctx: arc_swap::ArcSwap<crate::rpc::NodeContext>,
    /// Per-hash ledger acquisitions — routes responses by hash, no shared channels.
    inbound_ledgers: Arc<std::sync::Mutex<crate::ledger::inbound::InboundLedgers>>,
}

/// Why sync_trigger was called — matches rippled's InboundLedger::Trigger enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TriggerReason {
    /// Called from the 3-second timer — recovery + stall detection.
    Timeout,
}

fn sync_gate_accepts_response(
    sync: &std::sync::Mutex<Option<crate::sync_coordinator::SyncCoordinator>>,
    target_h8: u64,
    resp_hash: Option<&[u8]>,
    object_seq: Option<u32>,
    is_object_response: bool,
) -> bool {
    let hash_matches_target = resp_hash
        .filter(|hash| hash.len() >= 8)
        .map(|hash| u64::from_be_bytes(hash[..8].try_into().unwrap_or([0; 8])))
        .is_some_and(|resp_h8| target_h8 != 0 && resp_h8 == target_h8);
    if hash_matches_target {
        return true;
    }

    let Ok(guard) = sync.try_lock() else {
        return false;
    };
    let Some(syncer) = guard.as_ref() else {
        return false;
    };
    if !syncer.peer.accepts_ltclosed_responses() {
        return false;
    }
    if is_object_response {
        return object_seq.is_some_and(|seq| syncer.peer.knows_object_query(seq));
    }
    resp_hash.is_some_and(|hash| hash.len() == 32)
}

fn collect_shamap_ledger_nodes(
    map: &mut crate::ledger::shamap::SHAMap,
    raw_node_ids: &[Vec<u8>],
    query_depth: u32,
) -> (Vec<crate::proto::TmLedgerNode>, usize) {
    let mut nodes_by_id = std::collections::BTreeMap::<Vec<u8>, Vec<u8>>::new();
    let mut invalid_node_ids = 0usize;

    for raw_nid in raw_node_ids {
        let Some(node_id) = crate::ledger::shamap_id::SHAMapNodeID::from_wire(raw_nid) else {
            invalid_node_ids += 1;
            continue;
        };
        for (wire_id, nodedata) in map.get_wire_nodes_for_query(&node_id, query_depth) {
            nodes_by_id.entry(wire_id.to_vec()).or_insert(nodedata);
        }
    }

    let nodes = nodes_by_id
        .into_iter()
        .map(|(nodeid, nodedata)| crate::proto::TmLedgerNode {
            nodedata,
            nodeid: Some(nodeid),
        })
        .collect();
    (nodes, invalid_node_ids)
}

fn requested_get_ledger_hash(
    req: &crate::proto::TmGetLedger,
) -> Result<Option<[u8; 32]>, crate::proto::TmReplyError> {
    match req.ledger_hash.as_deref() {
        None => Ok(None),
        Some(hash) if hash.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(hash);
            Ok(Some(out))
        }
        Some(_) => Err(crate::proto::TmReplyError::ReBadRequest),
    }
}

fn resolve_get_ledger_header(
    req: &crate::proto::TmGetLedger,
    current: &crate::ledger::LedgerHeader,
    history: &crate::ledger::history::LedgerStore,
) -> Result<crate::ledger::LedgerHeader, crate::proto::TmReplyError> {
    let requested_hash = requested_get_ledger_hash(req)?;
    match req.ltype {
        Some(x) if x == crate::proto::TmLedgerType::LtCurrent as i32 => {
            // rippled no longer serves ltCURRENT TMGetLedger requests.
            return Err(crate::proto::TmReplyError::ReBadRequest);
        }
        Some(x)
            if x != crate::proto::TmLedgerType::LtAccepted as i32
                && x != crate::proto::TmLedgerType::LtClosed as i32 =>
        {
            return Err(crate::proto::TmReplyError::ReBadRequest);
        }
        _ => {}
    }

    if let Some(hash) = requested_hash {
        if current.hash == hash {
            return Ok(current.clone());
        }
        return history
            .get_ledger_by_hash(&hash)
            .map(|rec| rec.header.clone())
            .ok_or(crate::proto::TmReplyError::ReNoLedger);
    }

    if req.ltype == Some(crate::proto::TmLedgerType::LtClosed as i32) {
        return history
            .latest_ledger()
            .map(|rec| {
                if rec.header.sequence > current.sequence {
                    rec.header.clone()
                } else {
                    current.clone()
                }
            })
            .or_else(|| (current.sequence > 0).then_some(current.clone()))
            .ok_or(crate::proto::TmReplyError::ReNoLedger);
    }

    if let Some(seq) = req.ledger_seq {
        if seq == current.sequence {
            Ok(current.clone())
        } else {
            history
                .get_ledger(seq)
                .map(|rec| rec.header.clone())
                .ok_or(crate::proto::TmReplyError::ReNoLedger)
        }
    } else {
        Ok(current.clone())
    }
}

impl Node {
    fn lock_sync(&self) -> std::sync::MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>> {
        self.sync.lock().unwrap_or_else(|e| {
            warn!("sync mutex poisoned; recovering inner state");
            e.into_inner()
        })
    }

    /// Get a reference to the storage (for graceful shutdown flush).
    pub fn storage(&self) -> Option<&Arc<crate::storage::Storage>> {
        self.storage.as_ref()
    }

    /// Access the sync mutex for shutdown persistence.
    pub fn sync_lock(&self) -> Option<std::sync::MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>>> {
        Some(self.lock_sync())
    }

    /// Access the shared state RwLock.
    pub fn state_ref(&self) -> &Arc<tokio::sync::RwLock<SharedState>> {
        &self.state
    }

    /// Signal all background tasks to exit. Called from main.rs on SIGTERM/SIGINT.
    pub fn signal_shutdown(&self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Check if shutdown has been signaled.
    fn is_shutting_down(&self) -> bool {
        self.shutdown.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn build_rpc_read_context(
        state: &SharedState,
        _storage: Option<&Arc<crate::storage::Storage>>,
    ) -> NodeContext {
        NodeContext {
            network: state.ctx.network,
            network_id: state.ctx.network_id,
            build_version: state.ctx.build_version,
            start_time: state.ctx.start_time,
            ledger_seq: state.ctx.ledger_seq,
            ledger_hash: state.ctx.ledger_hash.clone(),
            fees: state.ctx.fees,
            ledger_state: state.ctx.ledger_state.clone(),
            tx_pool: state.ctx.tx_pool.clone(),
            ledger_header: state.ctx.ledger_header.clone(),
            history: state.ctx.history.clone(),
            broadcast_queue: Vec::new(),
            amendments: state.ctx.amendments.clone(),
            peer_count: state.peer_count(),
            object_count: 0,
            storage: state.ctx.storage.clone(),
            rpc_sync_state: state.rpc_sync_state.clone(),
            follower_state: state.follower_state.clone(),
            closed_ledger: state.ctx.closed_ledger.clone(),
        }
    }

    fn build_rpc_snapshot(
        state: &SharedState,
        _storage: Option<&Arc<crate::storage::Storage>>,
        node_key: &Secp256k1KeyPair,
        validator_key: Option<&Secp256k1KeyPair>,
        nudb_backend: Option<&Arc<dyn crate::ledger::node_store::NodeStore>>,
    ) -> crate::rpc::RpcSnapshot {
        let pubkey_node = crate::crypto::base58::encode(
            crate::crypto::base58::PREFIX_NODE_PUBLIC,
            &node_key.public_key_bytes(),
        );
        let validator_key_b58 = validator_key.map(|vk| {
            crate::crypto::base58::encode(
                crate::crypto::base58::PREFIX_NODE_PUBLIC,
                &vk.public_key_bytes(),
            )
        }).unwrap_or_default();

        crate::rpc::RpcSnapshot {
            ledger_seq:    state.ctx.ledger_seq,
            ledger_hash:   state.ctx.ledger_hash.clone(),
            ledger_header: state.ctx.ledger_header.clone(),
            fees:          state.ctx.fees,
            peer_count:    state.peer_txs.len(),
            object_count: {
                // Prefer direct NuDB backend count, then LedgerState NuDB
                let direct_nudb = nudb_backend.map(|b| b.count() as usize).unwrap_or(0);
                if direct_nudb > 0 {
                    direct_nudb
                } else {
                    let ls = state.ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                    let nudb_count = ls.nudb_object_count();
                    if nudb_count > 0 { nudb_count } else { 0 }
                }
            },
            build_version: state.ctx.build_version,
            network_id:    state.ctx.network_id,
            start_time:    state.ctx.start_time,
            memory_mb:     crate::rpc::handlers::get_memory_mb() as usize,
            complete_ledgers: state.ctx.history.read().unwrap_or_else(|e| e.into_inner()).complete_ledgers(),
            sync_done: state.sync_done,
            validation_quorum: state.current_round.as_ref().map(|r| r.quorum()).unwrap_or(0),
            pubkey_node: pubkey_node,
            validator_key: validator_key_b58,
        }
    }

    /// Update the lock-free RPC snapshot from current shared state.
    /// Called after any significant state change (ledger close, validation, sync).
    pub async fn update_rpc_snapshot(&self) {
        let state = self.state.read().await;
        let snap = Self::build_rpc_snapshot(&state, self.storage.as_ref(), &self.node_key, self.validator_key.as_ref(), self.nudb_backend.as_ref());
        let ctx = Self::build_rpc_read_context(&state, self.storage.as_ref());
        self.rpc_snapshot.store(Arc::new(snap));
        self.rpc_read_ctx.store(Arc::new(ctx));
    }

    /// Get the lock-free RPC snapshot for server_info.
    pub fn rpc_snapshot(&self) -> arc_swap::Guard<Arc<crate::rpc::RpcSnapshot>> {
        self.rpc_snapshot.load()
    }

    /// Check if a message has been seen before (dedup). Returns true if NEW (first time).
    /// Uses message-type-specific content keys matching rippled's HashRouter:
    /// - Validations: SHA-512-Half of the `validation` field (not the full protobuf)
    /// - Transactions: SHA-512-Half of the `raw_transaction` field (= txID)
    /// - Proposals: SHA-256 of concatenated content fields
    /// - Other: SHA-256 of full payload
    fn message_is_new(&self, msg_type: MessageType, payload: &[u8]) -> bool {
        use prost::Message as ProstMessage;
        let hash: [u8; 32] = match msg_type {
            MessageType::Validation => {
                if let Ok(val) = crate::proto::TmValidation::decode(payload) {
                    crate::crypto::sha512_first_half(&val.validation)
                } else {
                    crate::crypto::sha256(payload)
                }
            }
            MessageType::Transaction => {
                if let Ok(tx) = crate::proto::TmTransaction::decode(payload) {
                    // txID = SHA-512-Half(TXN\0 + raw_transaction)
                    let mut data = vec![0x54, 0x58, 0x4E, 0x00];
                    data.extend_from_slice(&tx.raw_transaction);
                    crate::crypto::sha512_first_half(&data)
                } else {
                    crate::crypto::sha256(payload)
                }
            }
            MessageType::ProposeLedger => {
                if let Ok(prop) = crate::proto::TmProposeSet::decode(payload) {
                    // Unique ID from content fields
                    let mut data = Vec::new();
                    data.extend_from_slice(&prop.current_tx_hash);
                    data.extend_from_slice(&prop.previousledger);
                    data.extend_from_slice(&prop.propose_seq.to_be_bytes());
                    data.extend_from_slice(&prop.close_time.to_be_bytes());
                    data.extend_from_slice(&prop.node_pub_key);
                    crate::crypto::sha256(&data)
                } else {
                    crate::crypto::sha256(payload)
                }
            }
            _ => crate::crypto::sha256(payload),
        };
        let mut guard = self.msg_dedup.lock().unwrap_or_else(|e| e.into_inner());
        if guard.1.elapsed().as_secs() >= 300 {
            guard.0.clear();
            guard.1 = std::time::Instant::now();
        }
        guard.0.insert(hash)
    }

    fn debug_log(&self, msg: &str) {
        if let Ok(mut guard) = self.debug_log.lock() {
            if let Some(ref mut file) = *guard {
                use std::io::Write;
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let _ = writeln!(file, "[{}] {}", ts, msg);
            }
        }
    }

    pub fn new(config: NodeConfig) -> Self {
        // Load config file (validators + amendments)
        let cfg = config.config_file.as_ref().and_then(|path| {
            match crate::config::ConfigFile::load(path) {
                Ok(c)  => { info!("loaded config from {}", path.display()); Some(c) }
                Err(e) => { warn!("failed to load config {}: {e}", path.display()); None }
            }
        });
        let unl = cfg.as_ref().map(|c| c.unl()).unwrap_or_default();
        let validator_lists = cfg.as_ref().map(|c| c.validator_lists.clone()).unwrap_or_default();
        let amendments = cfg.as_ref().map(|c| c.enabled_amendments()).unwrap_or_default();

        if !unl.is_empty() {
            info!("UNL loaded with {} validators", unl.len());
        }
        if !validator_lists.sites.is_empty() || !validator_lists.publisher_keys.is_empty() {
            info!(
                "validator list config loaded: {} site(s), {} publisher key(s), threshold={}",
                validator_lists.sites.len(),
                validator_lists.publisher_keys.len(),
                validator_lists.effective_threshold()
            );
            warn!(
                "validator list publisher fetch/verification is unavailable in this build; using only locally configured [validators] entries for trust decisions"
            );
        }
        if !amendments.is_empty() {
            info!("amendments enabled: {:?}", amendments);
        }

        // Try to load from persistent storage
        let storage = config.data_dir.as_ref().and_then(|dir| {
            match crate::storage::Storage::open(dir) {
                Ok(s) => Some(Arc::new(s)),
                Err(e) => { error!("failed to open storage at {}: {e}", dir.display()); None }
            }
        });

        let mut ctx = if let Some(ref store) = storage {
            if store.has_state() {
                info!("loading state from disk...");
                let ledger_state_inner = crate::ledger::LedgerState::new();
                let history_inner = store.load_history_with_limit(config.ledger_history.max_history_limit())
                    .unwrap_or_else(|_| crate::ledger::LedgerStore::with_limit(config.ledger_history.max_history_limit()));
                let (mut seq, mut hash, mut header) = store.load_meta()
                    .unwrap_or((0, "0".repeat(64), Default::default()));
                if let Some(latest) = history_inner.latest_ledger() {
                    let hist_seq = latest.header.sequence;
                    let hist_hash = hex::encode_upper(latest.header.hash);
                    if seq != hist_seq || header.sequence != hist_seq || hash != hist_hash {
                        warn!(
                            "storage meta disagrees with ledger history (meta_seq={}, hist_seq={}) — preferring historical latest ledger",
                            seq, hist_seq,
                        );
                        seq = hist_seq;
                        hash = hist_hash;
                        header = latest.header.clone();
                    }
                }
                info!("loaded ledger {seq} with {} accounts", ledger_state_inner.account_count());
                NodeContext {
                    network:       "mainnet",
                    network_id:    config.network_id,
                    build_version: env!("CARGO_PKG_VERSION"),
                    start_time:    std::time::Instant::now(),
                    ledger_seq:    seq,
                    ledger_hash:   hash,
                    ledger_header: header,
                    ledger_state:  Arc::new(std::sync::Mutex::new(ledger_state_inner)),
                    history:       Arc::new(std::sync::RwLock::new(history_inner)),
                    ..Default::default()
                }
            } else {
                Self::fresh_genesis_ctx(config.network_id, config.ledger_history.max_history_limit())
            }
        } else {
            Self::fresh_genesis_ctx(config.network_id, config.ledger_history.max_history_limit())
        };
        // Wire storage into LedgerState for get_raw_owned() disk fallback in sparse mode
        if let Some(ref store) = storage {
            ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner()).set_storage(store.clone());
        }

        // Create content-addressed NodeStore (NuDB) for SHAMap nodes.
        // This is the rippled architecture: tree nodes stored by content hash,
        // SHAMap walks fetch from disk on demand via the CachedNodeStore layer.
        let mut nudb_direct: Option<Arc<dyn crate::ledger::node_store::NodeStore>> = None;
        if let Some(ref dir) = config.data_dir {
            let nudb_dir = dir.join("nodestore");
            match crate::ledger::node_store::NuDBNodeStore::open(&nudb_dir) {
                Ok(nudb) => {
                    let backend: std::sync::Arc<dyn crate::ledger::node_store::NodeStore> =
                        std::sync::Arc::new(nudb);
                    // Keep direct backend ref for lock-free sync writes
                    nudb_direct = Some(backend.clone());
                    // Wrap with 256MB LRU cache for SHAMap reads
                    let cached: std::sync::Arc<dyn crate::ledger::node_store::NodeStore> =
                        std::sync::Arc::new(crate::ledger::tree_cache::CachedNodeStore::with_max_bytes(
                            backend, 500_000, 256 * 1024 * 1024,
                        ));
                    let nudb_shamap = crate::ledger::shamap::SHAMap::with_backend(
                        crate::ledger::shamap::MapType::AccountState, cached,
                    );
                    ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner())
                        .set_nudb_shamap(nudb_shamap);
                    info!("NuDB NodeStore ready at {} (content-addressed, 256MB cache)", nudb_dir.display());
                }
                Err(e) => {
                    warn!("failed to open NuDB NodeStore at {}: {e} — running without", nudb_dir.display());
                }
            }
        }

        // Load or generate persistent node identity key (matches rippled's wallet.db NodeIdentity)
        let node_key = if let Some(ref store) = storage {
            if let Some(seed_bytes) = store.get_meta("node_seed") {
                if seed_bytes.len() >= 16 {
                    let mut entropy = [0u8; 16];
                    entropy.copy_from_slice(&seed_bytes[..16]);
                    Secp256k1KeyPair::from_seed_entropy(&entropy)
                } else {
                    let kp = Secp256k1KeyPair::generate();
                    let _ = store.save_meta_kv("node_seed", &kp.public_key_bytes()[..16]);
                    kp
                }
            } else {
                // First run — generate and persist
                let entropy: [u8; 16] = rand::random();
                let kp = Secp256k1KeyPair::from_seed_entropy(&entropy);
                let _ = store.save_meta_kv("node_seed", &entropy);
                kp
            }
        } else {
            Secp256k1KeyPair::generate()
        };
        // Log the node public key in base58 (n... format) for cluster config
        let pubkey_bytes = node_key.public_key_bytes();
        let node_pubkey_b58 = crate::crypto::base58::encode(
            crate::crypto::base58::PREFIX_NODE_PUBLIC, &pubkey_bytes,
        );
        info!("node public key: {}", node_pubkey_b58);

        // Derive validator signing key from [validation_seed] if configured
        let validator_key = config.validation_seed.as_deref().and_then(|seed| {
            match Secp256k1KeyPair::from_seed(seed) {
                Ok(kp) => {
                    let vk_bytes = kp.public_key_bytes();
                    let vk_b58 = crate::crypto::base58::encode(
                        crate::crypto::base58::PREFIX_NODE_PUBLIC, &vk_bytes,
                    );
                    info!("validator signing key: {}", vk_b58);
                    Some(kp)
                }
                Err(e) => {
                    error!("failed to derive validator key from validation_seed: {e}");
                    None
                }
            }
        });
        let openssl_tls = if config.use_tls {
            match OpenSslConfig::new_self_signed() {
                Ok(cfg) => Some(cfg),
                Err(e)  => { error!("OpenSSL TLS setup failed: {e}"); None }
            }
        } else {
            None
        };
        // Set amendments on context
        ctx.amendments = amendments;
        // Set storage reference for live RPC lookups (Phase 4)
        ctx.storage = storage.clone();

        let (ws_events, _) = tokio::sync::broadcast::channel(4096);
        let mut shared = SharedState::new(ctx);

        // Detect existing database and decide: sync from scratch or follower-only.
        // rippled approach: if we have state, replay missed ledgers via follower.
        // Only run the tree syncer when starting from zero.
        if let Some(ref store) = storage {
            let has_completed_sync = store.is_sync_complete();
            if has_completed_sync {
                // Previously completed sync — skip tree syncer, use follower only.
                // The follower will replay missed ledgers by applying transactions,
                // catching up in seconds instead of hours of tree walking.
                info!("existing database detected — follower-only mode (no tree sync)");
                {
                    let mut ls = shared.ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                    ls.enable_sparse();
                    if let Some(root_hash) = store.get_sync_account_hash() {
                        match ls.load_nudb_root(root_hash) {
                            Ok(true) => info!(
                                "rehydrated NuDB SHAMap root from sync anchor {}",
                                hex::encode_upper(&root_hash[..8]),
                            ),
                            Ok(false) => warn!(
                                "could not rehydrate NuDB SHAMap root from sync anchor {}",
                                hex::encode_upper(&root_hash[..8]),
                            ),
                            Err(e) => warn!(
                                "failed to rehydrate NuDB SHAMap root from sync anchor {}: {}",
                                hex::encode_upper(&root_hash[..8]),
                                e,
                            ),
                        }
                    } else {
                        warn!("sync_complete set but no sync_account_hash found for NuDB root rehydrate");
                    }
                }
                shared.sync_done = true;
            } else {
                // Fresh sync — clear any stale handoff metadata from a previous generation
                info!("no sync_complete flag — clearing stale handoff metadata for fresh sync");
                let _ = store.clear_sync_handoff();
            }
        }

        // Populate fees and amendments from ledger state SLEs.
        {
            let mut ls = shared.ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            shared.ctx.fees = crate::ledger::read_fees(&ls);
            let enabled = crate::ledger::read_amendments(&ls);
            if !enabled.is_empty() {
                info!("loaded {} enabled amendments from Amendments SLE", enabled.len());
                for hash in enabled {
                    ls.enable_amendment(hash);
                }
            }
        }

        let initial_rpc_snapshot = Self::build_rpc_snapshot(&shared, storage.as_ref(), &node_key, validator_key.as_ref(), nudb_direct.as_ref());
        let initial_rpc_read_ctx = Self::build_rpc_read_context(&shared, storage.as_ref());
        let state = Arc::new(RwLock::new(shared));
        let sync_data_queue = Arc::new(std::sync::Mutex::new(Vec::<(PeerId, crate::proto::TmLedgerData)>::new()));
        let sync_data_notify = Arc::new(tokio::sync::Notify::new());
        let (diff_sync_tx, diff_sync_rx) = mpsc::channel::<crate::proto::TmLedgerData>(4096);

        let debug_log = if let Some(ref dir) = config.data_dir {
            let debug_dir = std::path::Path::new(dir).join("debug_logs");
            let _ = std::fs::create_dir_all(&debug_dir);
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            let path = debug_dir.join(format!("sync_{}.log", ts));
            std::fs::File::create(&path).ok()
        } else {
            None
        };

        Self {
            config,
            state,
            node_key,
            validator_key,
            storage,
            openssl_tls,
            ws_events,
            nudb_backend: nudb_direct,
            unl: Arc::new(std::sync::RwLock::new(unl)),
            validator_list_config: validator_lists,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            sync: Arc::new(std::sync::Mutex::new(None)),
            sync_target_hash8: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            sync_rr: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            sync_data_queue,
            sync_data_notify,
            diff_sync_tx,
            diff_sync_rx: Arc::new(tokio::sync::Mutex::new(diff_sync_rx)),
            msg_dedup: Arc::new(std::sync::Mutex::new((std::collections::HashSet::new(), std::time::Instant::now()))),
            debug_log: Arc::new(std::sync::Mutex::new(debug_log)),
            rpc_snapshot: arc_swap::ArcSwap::from_pointee(initial_rpc_snapshot),
            rpc_read_ctx: arc_swap::ArcSwap::from_pointee(initial_rpc_read_ctx),
            inbound_ledgers: Arc::new(std::sync::Mutex::new(crate::ledger::inbound::InboundLedgers::new())),
        }
    }

    /// Returns the validator signing key if configured, otherwise the node identity key.
    /// Used for signing proposals and validations.
    fn signing_key(&self) -> &Secp256k1KeyPair {
        self.validator_key.as_ref().unwrap_or(&self.node_key)
    }

    fn fresh_genesis_ctx(network_id: u32, history_limit: Option<u32>) -> NodeContext {
        use crate::crypto::keys::Secp256k1KeyPair;
        use crate::ledger::AccountRoot;

        let mut ctx = NodeContext {
            network:       "mainnet",
            network_id,
            build_version: env!("CARGO_PKG_VERSION"),
            start_time:    std::time::Instant::now(),
            ledger_seq:    1,
            ledger_hash:   "0".repeat(64),
            history:       Arc::new(std::sync::RwLock::new(crate::ledger::LedgerStore::with_limit(history_limit))),
            ..Default::default()
        };
        // Seed genesis account
        {
            let mut ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            if let Ok(kp) = Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb") {
                let account_id = crate::crypto::account_id(&kp.public_key_bytes());
                ls.insert_account(AccountRoot {
                    account_id,
                    balance:     100_000_000_000_000_000,
                    sequence:    1,
                    owner_count: 0,
                    flags:       0,
                    regular_key: None, minted_nftokens: 0, burned_nftokens: 0,
                    transfer_rate: 0, domain: Vec::new(), tick_size: 0, ticket_count: 0,
                    previous_txn_id: [0u8; 32], previous_txn_lgr_seq: 0, raw_sle: None,
                });
            }
            // Genesis ledger header
            let account_hash = ls.state_hash();
            ctx.ledger_header = crate::ledger::LedgerHeader {
                sequence: 1, hash: [0u8; 32], parent_hash: [0u8; 32],
                close_time: 0, total_coins: 100_000_000_000_000_000,
                account_hash, transaction_hash: [0u8; 32],
                parent_close_time: 0, close_time_resolution: 10, close_flags: 0,
            };
            ls.mark_all_dirty();
        }
        let hash = ctx.ledger_header.compute_hash();
        ctx.ledger_header.hash = hash;
        ctx.ledger_hash = hex::encode_upper(hash);
        ctx.history.write().unwrap_or_else(|e| e.into_inner()).insert_ledger(ctx.ledger_header.clone(), vec![]);
        ctx
    }

    /// Start the node: peer listener, RPC server, and bootstrap dialing.
    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        info!(
            "xledgrs node starting — peer={} rpc={} tls={}",
            self.config.peer_addr, self.config.rpc_addr, self.config.use_tls
        );

        // Store full-history peers in shared state for the follower
        if !self.config.full_history_peers.is_empty() {
            let mut ss = self.state.write().await;
            ss.full_history_peers = self.config.full_history_peers.clone();
            info!("registered {} full-history peers for diff sync", ss.full_history_peers.len());
        }

        // Spawn peer listener
        let node1 = self.clone();
        tokio::spawn(async move {
            if let Err(e) = node1.run_peer_listener().await {
                error!("peer listener error: {e}");
            }
        });

        // Spawn RPC server
        let node2 = self.clone();
        tokio::spawn(async move {
            if let Err(e) = node2.run_rpc_server().await {
                error!("RPC server error: {e}");
            }
        });

        // Seed bootstrap addresses into known_peers
        {
            let mut state = self.state.write().await;
            for addr in &self.config.bootstrap {
                state.add_known_peer(*addr);
            }
        }

        // Dial only localhost + first 2 bootstrap peers — discovery loop ramps the rest
        {
            let mut initial_count = 0;
            for addr in &self.config.bootstrap.clone() {
                let is_local = addr.ip().is_loopback();
                if !is_local && initial_count >= 2 { continue; }
                if !is_local { initial_count += 1; }
                let node3 = self.clone();
                let addr = *addr;
                tokio::spawn(async move {
                    if let Err(e) = node3.dial(addr).await {
                        warn!("failed to dial bootstrap peer {addr}: {e}");
                    }
                });
            }
            info!("initial dial: localhost + {} bootstrap peers (rest via discovery ramp)", initial_count);
        }

        // Priority-dial deep-history peers — these are critical for diff sync catch-up.
        // Dial ALL of them upfront (they're already TCP-probed and alive).
        if !self.config.full_history_peers.is_empty() {
            let count = self.config.full_history_peers.len();
            for addr in &self.config.full_history_peers {
                let node_dh = self.clone();
                let addr = *addr;
                tokio::spawn(async move {
                    if let Err(e) = node_dh.dial(addr).await {
                        warn!("failed to dial deep-history peer {addr}: {e}");
                    }
                });
            }
            info!("dialing {} deep-history peers for sync", count);
        }

        if self.config.enable_consensus_close_loop {
            info!("consensus close loop enabled");
            let node4 = self.clone();
            tokio::spawn(async move {
                node4.run_ledger_close_loop().await;
            });
        } else {
            info!("consensus close loop disabled; running in follower mode");
        }

        // Spawn validator list fetch loop (updates UNL from publisher sites).
        if !self.validator_list_config.sites.is_empty() {
            let sites = self.validator_list_config.sites.clone();
            let pub_keys = self.validator_list_config.publisher_keys.clone();
            let unl = self.unl.clone();
            let shutdown = self.shutdown.clone();
            tokio::spawn(async move {
                crate::validator_list::run_validator_list_fetch(sites, pub_keys, unl, shutdown).await;
            });
        }

        // Spawn WebSocket server
        let ws_addr = self.config.ws_addr;
        let ws_tls = self.config.use_tls;
        let ws_state = self.state.clone();
        let ws_tx = self.ws_events.clone();
        tokio::spawn(async move {
            crate::rpc::ws::run_ws_server_with_sender(ws_addr, ws_tls, ws_state, ws_tx).await;
        });

        // Spawn peer discovery loop — periodically dial new known peers
        let node5 = self.clone();
        tokio::spawn(async move {
            node5.run_discovery_loop().await;
        });

        // RPC bootstrap: if --rpc-sync is set and sync not yet complete,
        // download full state from rippled admin RPC before starting peer sync.
        {
            let sync_done = {
                let state = self.state.read().await;
                state.sync_done
            };
            if !sync_done {
                if let Some(ref ep) = self.config.rpc_sync {
                    let (host, port) = parse_host_port(ep);
                    if port > 0 {
                        info!("RPC bootstrap: downloading state from {}:{}", host, port);
                        let store = self.storage.as_ref().expect("storage required for RPC bootstrap");
                        let rpc_state = Arc::new(crate::rpc_sync::RpcSyncState::new());
                        crate::rpc_sync::run_rpc_sync(
                            host, port, store.clone(), rpc_state.clone(),
                        ).await;

                        if rpc_state.complete.load(std::sync::atomic::Ordering::SeqCst) {
                            info!("RPC bootstrap complete — loading SparseSHAMap");
                            {
                                let state = self.state.read().await;
                                let mut ls = state.ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                                ls.enable_sparse();
                                // Leaf hashes are in NuDB now — no bulk load from storage
                                let warm_t0 = std::time::Instant::now();
                                let h = ls.state_hash();
                                info!(
                                    "SparseSHAMap hash warmup: {}ms root={}",
                                    warm_t0.elapsed().as_millis(),
                                    hex::encode_upper(&h[..8]),
                                );
                            }
                            let mut state = self.state.write().await;
                            state.sync_done = true;
                            info!("RPC bootstrap: sync_done=true — follower will report hash matches");
                        } else {
                            warn!("RPC bootstrap failed — falling through to peer sync");
                        }
                    }
                }
            } else {
                info!("sync already complete — skipping RPC bootstrap");
            }
        }

        // Spawn peer-based SHAMap sync — matches rippled's InboundLedger architecture:
        // 1. gotData (intake) pushes to sync_data_queue (done inline at message router)
        // 2. runData (data processor) wakes on notify, drains queue, processes, triggers
        // 3. onTimer (timer) fires every 3s, clears recent, triggers for recovery
        {
            if !SYNC_STALL_CHECKER_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let node6 = self.clone();
                tokio::spawn(async move {
                    node6.run_sync_timer().await;
                });
            } else {
                warn!("sync timer already started; skipping duplicate spawn");
            }

            if !SYNC_BATCH_PROCESSOR_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let node_batch = self.clone();
                tokio::spawn(async move {
                    node_batch.run_sync_data_processor().await;
                });
            } else {
                warn!("sync data processor already started; skipping duplicate spawn");
            }
        }

        // Do NOT set sync_done here — the StateSyncer needs liAS_NODE responses
        // routed to it (sync_data_queue) until the full state tree is downloaded.
        // sync_done is set by run_sync_data_processor() when the sync completes.
        // Spawn ledger follower only when sync is already complete (restart case).
        // During initial sync, the follower wastes CPU replaying ledgers against
        // incomplete state. After sync completes, start_follower() is called from
        // run_sync_data_processor.
        let sync_done = { self.state.read().await.sync_done };
        if sync_done {
            self.start_follower().await;
        }

        Ok(())
    }

    /// Start the ledger follower task. Called after sync completes or on restart
    /// when sync was previously completed.
    async fn start_follower(&self) {
        if let Some(ref storage) = self.storage {
            let storage = storage.clone();
            let state_ref = self.state.clone();
            let follower = Arc::new(crate::ledger::follow::FollowerState::new());
            let follower2 = follower.clone();
            let diff_rx = self.diff_sync_rx.clone();
            let (rpc_host, rpc_port) = if let Some(ref ep) = self.config.rpc_sync {
                parse_host_port(ep)
            } else {
                ("127.0.0.1".to_string(), 0u16)
            };
            let il = self.inbound_ledgers.clone();
            tokio::spawn(async move {
                crate::ledger::follow::run_follower(rpc_host, rpc_port, storage, follower2, state_ref, diff_rx, il).await;
            });
            {
                let mut ss = self.state.write().await;
                ss.follower_state = Some(follower);
            }
            info!("follower started");
        }
    }

    /// Trigger a state re-sync to the current validated ledger.
    /// Called when the follower detects a hash mismatch — instead of replaying
    /// with divergent state, we re-sync the state tree (delta only, fast).
    pub async fn trigger_resync(&self) {
        info!("trigger_resync: clearing sync state and re-entering sync mode");

        // 1. Stop the follower
        {
            let state = self.state.read().await;
            if let Some(ref fs) = state.follower_state {
                fs.running.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }

        // 2. Clear the syncer so a new one gets created for the current tip
        {
            let mut guard = self.sync.lock().unwrap_or_else(|e| e.into_inner());
            *guard = None;
        }

        // 3. Clear sync flags in storage
        if let Some(ref store) = self.storage {
            let _ = store.clear_sync_handoff();
        }

        // 4. Reset state flags so the sync path re-activates
        {
            let mut state = self.state.write().await;
            state.sync_done = false;
            state.sync_in_progress = false;
            state.follower_state = None;
        }

        info!("trigger_resync: sync state cleared — will re-sync to current validated ledger");
    }

    async fn run_post_sync_checkpoint(&self, sync_header: &crate::ledger::LedgerHeader) {
        let Some(script) = self.config.post_sync_checkpoint_script.clone() else {
            return;
        };
        let Some(data_dir) = self.config.data_dir.clone() else {
            warn!("post-sync checkpoint skipped: no data_dir configured");
            return;
        };

        let seq = sync_header.sequence.to_string();
        let ledger_hash = hex::encode_upper(sync_header.hash);
        let account_hash = hex::encode_upper(sync_header.account_hash);
        info!(
            "post-sync checkpoint: running {} for seq={} hash={}",
            script.display(),
            sync_header.sequence,
            hex::encode_upper(&sync_header.hash[..8]),
        );

        let script_for_cmd = script.clone();
        let data_dir_for_cmd = data_dir.clone();
        let run = tokio::task::spawn_blocking(move || {
            std::process::Command::new(&script_for_cmd)
                .env("XLEDGRS_SYNC_LEDGER_SEQ", &seq)
                .env("XLEDGRS_SYNC_LEDGER_HASH", &ledger_hash)
                .env("XLEDGRS_SYNC_ACCOUNT_HASH", &account_hash)
                .env("XLEDGRS_SYNC_DATA_DIR", &data_dir_for_cmd)
                .output()
        }).await;

        match run {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if output.status.success() {
                    if stdout.is_empty() {
                        info!("post-sync checkpoint complete");
                    } else {
                        info!("post-sync checkpoint complete: {}", stdout);
                    }
                } else {
                    error!(
                        "post-sync checkpoint failed: status={} stdout='{}' stderr='{}'",
                        output.status,
                        stdout,
                        stderr,
                    );
                }
            }
            Ok(Err(e)) => {
                error!(
                    "post-sync checkpoint failed to launch {}: {}",
                    script.display(),
                    e,
                );
            }
            Err(e) => {
                error!("post-sync checkpoint task join failed: {}", e);
            }
        }
    }

    // ── Peer discovery ────────────────────────────────────────────────────

    /// Periodically check for known-but-unconnected peers and try dialing them.
    /// Ramps up gradually: start with 3 peers, add 3 more every 30s until target.
    /// Prevents mass-burn events from connecting to 50 peers simultaneously.
    async fn run_discovery_loop(self: Arc<Self>) {
        let start_time = std::time::Instant::now();
        loop {
            let delay = {
                let state = self.state.read().await;
                if state.peer_txs.is_empty() { 1 } else { 5 }
            };
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            if self.is_shutting_down() { info!("discovery loop: shutdown"); return; }
            let to_dial: Vec<SocketAddr> = {
                let mut state = self.state.write().await;
                // Prune expired cooldowns
                let now = std::time::Instant::now();
                state.peer_cooldowns.retain(|_, expires| *expires > now);

                // Ramp: start with 3, add 3 every 30s, cap at outbound limit.
                let elapsed_secs = start_time.elapsed().as_secs();
                let max_out = self.config.max_outbound();
                let target_outbound = (3 + (elapsed_secs / 30) * 3).min(max_out as u64) as usize;

                // Always redial localhost if not connected (cluster peer, unlimited)
                let mut addrs: Vec<SocketAddr> = Vec::new();
                for addr in state.known_peers.iter() {
                    if addr.ip().is_loopback() && !state.connected_addrs.contains(addr) {
                        addrs.push(*addr);
                    }
                }

                // Pop up to 3 from front of queue, try to dial, push to back.
                // Respect outbound slot limit.
                if state.outbound_count() < target_outbound {
                    let mut tried = 0;
                    let mut scanned = 0;
                    let queue_len = state.known_peers.len();
                    while tried < 3 && scanned < queue_len {
                        if let Some(addr) = state.known_peers.pop_front() {
                            scanned += 1;
                            if !addr.ip().is_loopback()
                                && !state.connected_addrs.contains(&addr)
                                && !state.peer_cooldowns.contains_key(&addr)
                            {
                                addrs.push(addr);
                                tried += 1;
                            }
                            // Push to back regardless — maintains the rotation
                            state.known_peers.push_back(addr);
                        } else {
                            break;
                        }
                    }
                }
                addrs
            };

            for addr in to_dial {
                let node = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = node.dial(addr).await {
                        warn!("discovery dial to {addr} failed: {e}");
                    }
                });
            }
        }
    }

    // ── Sync stall detection ──────────────────────────────────────────────

    /// Pick the next peer for sync requests using rippled-style latency scoring.
    /// Score = 10000 (base) - latency_ms * 30 - 8000 (if unknown latency) + random(0-9999)
    /// Sorted by score, round-robin among top peers.
    fn next_sync_peer(&self, state: &SharedState) -> Option<PeerId> {
        let mut open_peers: Vec<(PeerId, i32)> = state.peers.iter()
            .filter(|(_, ps)| ps.is_open())
            // Skip peers benched for unresponsiveness
            .filter(|(id, _)| {
                state.sync_peer_cooldown.get(id)
                    .map(|expires| std::time::Instant::now() >= *expires)
                    .unwrap_or(true)
            })
            .map(|(id, _)| {
                let mut score: i32 = rand::random::<u16>() as i32 % 10000; // random 0-9999
                score += 10000; // base score
                if let Some(&latency_ms) = state.peer_latency.get(id) {
                    score -= (latency_ms as i32) * 30; // penalize high latency
                } else {
                    score -= 8000; // penalize unknown latency
                }
                (*id, score)
            })
            .collect();
        if open_peers.is_empty() { return None; }
        open_peers.sort_by(|a, b| b.1.cmp(&a.1));
        // Pick from top peers — low latency peers naturally dominate
        let top = open_peers.len().min(6);
        let idx = self.sync_rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % top;

        // Periodic debug logging (~every 100 calls)
        if idx == 0 {
            static PEER_SELECT_LOG_CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let ctr = PEER_SELECT_LOG_CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if ctr % 100 == 0 {
                let total_open = state.peers.values().filter(|ps| ps.is_open()).count();
                let benched = state.sync_peer_cooldown.len();
                let top_scores: Vec<_> = open_peers.iter().take(5).map(|(pid, s)| format!("{:?}={}", pid, s)).collect();
                self.debug_log(&format!(
                    "PEER_SELECT: {} open, {} benched, top scores: [{}]",
                    total_open, benched, top_scores.join(", "),
                ));
            }
        }

        Some(open_peers[idx].0)
    }

    /// Core trigger function — matches rippled's InboundLedger::trigger().
    ///
    /// Acquires the sync lock, finds missing nodes, builds requests, sends to peers.
    /// Called by both run_sync_data_processor (Reply) and run_sync_timer (Timeout).
    ///
    /// Returns (requests_to_send, sync_seq, abandon_sync).
    fn sync_trigger_blocking(
        sync_arc: &Arc<std::sync::Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
        sync_target_hash8: &Arc<std::sync::atomic::AtomicU64>,
        storage: &Option<Arc<crate::storage::Storage>>,
        reason: TriggerReason,
    ) -> (Vec<RtxpMessage>, u32, bool) {
        const MAX_SYNC_STALLED_RETRIES: u32 = 6; // rippled's value; walks are fast now (~40ms)

        let lock_wait = std::time::Instant::now();
        let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
        let lock_wait_ms = lock_wait.elapsed().as_millis();
        let hold_start = std::time::Instant::now();
        let _store_ref = storage.as_ref().map(|s| s.as_ref());

        let syncer = match guard.as_mut() {
            Some(s) if s.active() => s,
            _ => {
                drop(guard);
                return (vec![], 0, false);
            }
        };

        let sync_seq = syncer.ledger_seq();

        // Completion is detected by the data processor, not the timer.
        // Timer only handles retries and timeouts (matching rippled).

        // For Timeout: three-phase local check (gather, lookup outside lock, apply)
        // We do the lookup inline since we already hold the lock; the storage reads
        // are fast. For truly expensive lookups we could drop/reacquire.
        if reason == TriggerReason::Timeout {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            let elapsed_secs = syncer.peer.last_response.elapsed().as_secs();

            let missing = syncer.get_missing(256); // rippled uses 256+ for aggressive sync
            let pending = syncer.pending_count();
            let cookies_out = syncer.peer.outstanding_cookie_count();
            let recent_count = syncer.peer.recent_node_count();

            info!(
                "sync tick: active={} in_flight={} pending={} missing={} inner={} leaf={} pass={} cookies={} recent={}",
                syncer.active(), syncer.in_flight(), pending, missing.len(),
                syncer.inner_count(), syncer.leaf_count(), syncer.pass_number(),
                cookies_out, recent_count,
            );

            // Detailed stuck node logging removed — SyncCoordinator manages tree internally

            // When stuck on 1 missing node, track and potentially force GetObjects
            if missing.len() == 1 {
                let stuck_hash = missing[0].1;
                let stuck_depth = missing[0].0.depth();
                {
                    if stuck_hash == syncer.tail_stuck_hash() {
                        syncer.set_tail_stuck_retries(syncer.tail_stuck_retries().saturating_add(1));
                    } else {
                        syncer.set_tail_stuck_hash(stuck_hash);
                        syncer.set_tail_stuck_retries(1);
                    }
                    info!(
                        "STUCK NODE: depth={} hash={} in_known={} tail_retries={} target_seq={}",
                        stuck_depth,
                        hex::encode_upper(&stuck_hash[..8]),
                        false, // in_known not tracked
                        syncer.tail_stuck_retries(),
                        sync_seq,
                    );
                    // Track the repeatedly-missing tail node here so the timeout
                    // path can escalate to GetObjects after several stalled retries.
                    // Node IDs are recovered later from pending_object_* maps.
                }
            } else {
                syncer.set_tail_stuck_hash([0u8; 32]);
                syncer.set_tail_stuck_retries(0);
            }

            // Progress-based stall detection (no in-flight counting)
            static LAST_SYNC_RETRY: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let last_retry_secs = LAST_SYNC_RETRY.load(std::sync::atomic::Ordering::Relaxed);
            let secs_since_retry = now_secs.saturating_sub(last_retry_secs);

            // Stall decision
            let is_stalled = elapsed_secs >= 3;
            if is_stalled {
                if syncer.is_pass_complete() {
                    let progress_this_pass = syncer.new_objects_this_pass();
                    info!(
                        "sync timer: restarting stalled pass {} ({} new this pass, pending={}, retries={})",
                        syncer.pass_number(), progress_this_pass, pending, syncer.stalled_retries(),
                    );
                    syncer.peer.start_new_pass();
                    syncer.peer.clear_recent();
                    if progress_this_pass > 0 {
                        syncer.set_stalled_retries(0);
                    }
                } else if syncer.stalled_retries() >= MAX_SYNC_STALLED_RETRIES {
                    // If we're close to done (< 50 missing), don't abandon —
                    // push harder with broadcast instead of retargeting.
                    // Retargeting near the tail wastes the 99% we already have.
                    if missing.len() < 50 {
                        warn!(
                            "sync timer: near completion ({} missing) — broadcasting instead of abandoning",
                            missing.len(),
                        );
                        syncer.set_stalled_retries(0);
                        syncer.peer.clear_recent();
                        // Fall through to build requests below (will broadcast)
                    } else {
                        warn!(
                            "sync timer: abandoning stuck sync target after {} retries ({} missing); re-acquiring latest ledger",
                            syncer.stalled_retries(), missing.len(),
                        );
                        syncer.set_active(false);
                        sync_target_hash8.store(0, std::sync::atomic::Ordering::Relaxed);
                        syncer.peer.reset_in_flight();
                        syncer.peer.clear_recent();
                        syncer.set_stalled_retries(0);
                        syncer.peer.pass_number = 0;
                        syncer.peer.last_response = std::time::Instant::now();
                        syncer.peer.last_new_nodes = std::time::Instant::now();
                        let hold_ms = hold_start.elapsed().as_millis();
                        if lock_wait_ms > 5 || hold_ms > 20 {
                            info!("sync trigger(timeout): lock_wait={}ms hold={}ms", lock_wait_ms, hold_ms);
                        }
                        drop(guard);
                        return (vec![], sync_seq, true); // abandon
                    }
                } else {
                    let retry_allowed = now_secs >= last_retry_secs + 3;
                    if retry_allowed {
                        syncer.set_stalled_retries(syncer.stalled_retries().saturating_add(1));
                        LAST_SYNC_RETRY.store(now_secs, std::sync::atomic::Ordering::Relaxed);

                        // Track tail-stall: if the same set of missing nodes
                        // persists across retries, escalate to GetObjects.
                        let first_missing_hash = missing.first().map(|m| m.1).unwrap_or([0u8; 32]);
                        if first_missing_hash == syncer.tail_stuck_hash() {
                            syncer.set_tail_stuck_retries(syncer.tail_stuck_retries().saturating_add(1));
                        } else {
                            syncer.set_tail_stuck_hash(first_missing_hash);
                            syncer.set_tail_stuck_retries(1);
                        }

                        // After 3 retries with same missing set, switch to
                        // GetObjects (by-hash fetch from peer node stores).
                        let use_object_fallback = syncer.stalled_retries() >= 3;
                        let req = if use_object_fallback {
                            syncer.build_timeout_object_request()
                        } else {
                            syncer.build_timeout_request().first().cloned()
                        };
                        if let Some(req) = req {
                            info!(
                                "sync stall ({}s) — timeout-retrying (attempt #{}, mode={})",
                                elapsed_secs, syncer.stalled_retries(),
                                if use_object_fallback { "getobjects" } else { "getledger" },
                            );
                            // Like rippled: timeout sends to all peers (peer=nullptr → broadcast)
                            let hold_ms = hold_start.elapsed().as_millis();
                            if lock_wait_ms > 5 || hold_ms > 20 {
                                info!("sync trigger(timeout): lock_wait={}ms hold={}ms", lock_wait_ms, hold_ms);
                            }
                            drop(guard);
                            return (vec![req], sync_seq, false);
                        }
                    } else {
                        info!(
                            "sync timer: retry suppressed by cooldown ({}s since last retry)",
                            secs_since_retry,
                        );
                    }
                }
            }
        }

        // warm_walk_cache not needed — SHAMap lazy-loads from NuDB

        // Build requests from missing nodes and fan out across peers.
        // rippled sends ~256 missing nodes per peer, to up to 6 peers.
        let reqs = syncer.build_multi_requests(6, crate::sync::SyncRequestReason::Reply);
        let has_req = !reqs.is_empty();
        let req_count = reqs.len();
        let hold_ms = hold_start.elapsed().as_millis();
        if lock_wait_ms > 5 || hold_ms > 20 {
            info!("sync trigger({:?}): lock_wait={}ms hold={}ms has_req={} n_reqs={}", reason, lock_wait_ms, hold_ms, has_req, req_count);
        }
        drop(guard);
        // Return all requests — caller will fan out across peers
        (reqs, sync_seq, false)
    }

    /// Send a single trigger request to a specific peer (or broadcast if no peer given).
    /// Matches rippled: sendRequest(tmGL, peer) sends to one peer, or all if peer==nullptr.
    async fn sync_send_request(&self, req: &RtxpMessage, _sync_seq: u32, target_peer: Option<PeerId>) {
        let state = self.state.write().await;
        match target_peer {
            Some(peer_id) => {
                // Send to specific peer (like rippled's trigger(peer, reply))
                if let Some(tx) = state.peer_txs.get(&peer_id) {
                    let _ = tx.try_send(req.clone());
                }
            }
            None => {
                // Broadcast to ALL peers (like rippled's sendRequest(tmGL, nullptr))
                state.broadcast(req, None);
            }
        }
    }

    /// onTimer — fires every 3 seconds like rippled's InboundLedger timer.
    /// Clears recent_nodes, calls trigger(timeout) for recovery.
    /// Also handles housekeeping: RPC snapshot, peer dialing, pings, cooldowns, kickstart.
    async fn run_sync_timer(self: Arc<Self>) {
        use std::time::Duration;
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if self.is_shutting_down() { info!("sync timer: shutdown"); return; }

            // Refresh RPC snapshot every tick — cheap (Arc clones + cached memory)
            self.update_rpc_snapshot().await;

            // Check if follower requested a state re-sync
            {
                let state = self.state.read().await;
                if let Some(ref fs) = state.follower_state {
                    if fs.resync_requested.swap(false, std::sync::atomic::Ordering::SeqCst) {
                        drop(state);
                        info!("sync timer: follower requested re-sync — triggering state re-sync");
                        self.trigger_resync().await;
                        continue;
                    }
                }
            }

            // Proactive peer dialing when sync is active and peer count is low.
            {
                let (peers_low, sync_active) = {
                    let state = self.state.read().await;
                    let sync_active = state.sync_in_progress || {
                        self.sync.try_lock().ok()
                            .and_then(|g| g.as_ref().map(|s| s.active()))
                            .unwrap_or(false)
                    };
                    (state.peer_count() < 3, sync_active)
                };
                if peers_low && sync_active {
                    let mut state = self.state.write().await;
                    let mut dialed = 0;
                    let queue_len = state.known_peers.len();
                    let mut scanned = 0;
                    while dialed < 3 && scanned < queue_len {
                        if let Some(addr) = state.known_peers.pop_front() {
                            scanned += 1;
                            let cooled = state.peer_cooldowns.get(&addr)
                                .map_or(false, |exp| std::time::Instant::now() < *exp);
                            if !cooled && !state.connected_addrs.contains(&addr) {
                                state.known_peers.push_back(addr);
                                drop(state);
                                info!("sync timer: low peers during sync, dialing {}", addr);
                                let node = self.clone();
                                tokio::spawn(async move { let _ = node.dial(addr).await; });
                                dialed += 1;
                                state = self.state.write().await;
                            } else {
                                state.known_peers.push_back(addr);
                            }
                        }
                    }
                }
            }

            // Periodic ping for latency measurement (every 30s)
            {
                static LAST_PING_ROUND: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let prev = LAST_PING_ROUND.load(std::sync::atomic::Ordering::Relaxed);
                if now_secs >= prev + 30 {
                    LAST_PING_ROUND.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                    let mut state = self.state.write().await;
                    let open_pids: Vec<PeerId> = state.peers.iter()
                        .filter(|(_, ps)| ps.is_open())
                        .map(|(id, _)| *id)
                        .collect();
                    for pid in open_pids {
                        let seq = rand::random::<u32>();
                        state.peer_ping_sent.insert(pid, (seq, std::time::Instant::now()));
                        if let Some(tx) = state.peer_txs.get(&pid) {
                            let ping_msg = crate::network::relay::encode_ping(seq);
                            let _ = tx.try_send(ping_msg);
                        }
                    }
                }
            }

            // Periodic status broadcast (every 15s) — keeps peers from
            // closing our connection due to protocol inactivity.
            // rippled peers expect periodic TMStatusChange to confirm we're alive.
            {
                static LAST_STATUS_BROADCAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let prev = LAST_STATUS_BROADCAST.load(std::sync::atomic::Ordering::Relaxed);
                if now_secs >= prev + 15 {
                    LAST_STATUS_BROADCAST.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                    let state = self.state.read().await;
                    let status_msg = crate::network::relay::encode_status_change(
                        crate::proto::NodeStatus::NsConnected,
                        crate::proto::NodeEvent::NeAcceptedLedger,
                        state.ctx.ledger_seq,
                        &state.ctx.ledger_header.hash,
                    );
                    state.broadcast(&status_msg, None);
                }
            }

            // Periodic cooldown pruning (~every 60s)
            {
                static LAST_COOLDOWN_PRUNE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let prev = LAST_COOLDOWN_PRUNE.load(std::sync::atomic::Ordering::Relaxed);
                if now_secs >= prev + 60 {
                    LAST_COOLDOWN_PRUNE.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                    let mut state = self.state.write().await;
                    let before = state.sync_peer_cooldown.len();
                    state.sync_peer_cooldown.retain(|pid, expires| {
                        let still_active = std::time::Instant::now() < *expires;
                        if !still_active {
                            self.debug_log(&format!("UNBENCHED: peer {:?}", pid));
                        }
                        still_active
                    });
                    let removed = before - state.sync_peer_cooldown.len();
                    if removed > 0 {
                        self.debug_log(&format!("cooldown prune: removed {} expired entries", removed));
                    }
                }
            }

            // If sync hasn't started yet (no syncer) OR the syncer was
            // abandoned (exists but inactive), send liBASE to kick-start.
            // After an abandon, the single re-acquire sent to one peer may
            // never get a response — this ensures periodic retries to all peers
            // so the liBASE handler can retarget the inactive syncer.
            {
                let needs_kickstart = self.sync.try_lock().ok().map_or(false, |g| {
                    match g.as_ref() {
                        None => true,                // no syncer yet
                        Some(s) => !s.active(),      // abandoned syncer waiting for retarget
                    }
                });
                if needs_kickstart {
                    let state = self.state.read().await;
                    let have_validated_target =
                        state.ctx.ledger_seq > 1 && state.ctx.ledger_header.hash != [0u8; 32];
                    if !state.sync_done
                        && state.peer_count() >= 1
                        && self.storage.is_some()
                        && have_validated_target
                    {
                        static LAST_KICKSTART: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                        let prev = LAST_KICKSTART.load(std::sync::atomic::Ordering::Relaxed);
                        if now_secs >= prev + 15 {
                            LAST_KICKSTART.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                            let cookie = crate::sync::next_cookie();
                            // Use the latest validated hash from peers (current network state).
                            // On restart, the local ledger_header.hash may be stale — peers
                            // won't have that old ledger's state tree anymore.
                            let hash = state.validated_hashes.get(&state.ctx.ledger_seq)
                                .copied()
                                .unwrap_or(state.ctx.ledger_header.hash);
                            let get_msg = crate::network::relay::encode_get_ledger_base(&hash, cookie);
                            let mut sent = 0;
                            for (pid, ps) in &state.peers {
                                if !ps.is_open() { continue; }
                                if let Some(tx) = state.peer_txs.get(pid) {
                                    let _ = tx.try_send(get_msg.clone());
                                    sent += 1;
                                    if sent >= 3 { break; }
                                }
                            }
                            if sent > 0 {
                                let reason = if self.sync.try_lock().ok().map_or(false, |g| g.is_some()) {
                                    "abandoned syncer awaiting retarget"
                                } else {
                                    "no syncer yet"
                                };
                                info!("sync timer: {reason}, sent liBASE kickstart to {sent} peers");
                            }
                        }
                    }
                }
            }

            // Clear recent_nodes unconditionally — matches rippled's 3-second timer
            // that clears mRecentNodes. Does NOT need the data queue lock.
            {
                if let Ok(mut guard) = self.sync.try_lock() {
                    if let Some(ref mut syncer) = *guard {
                        syncer.peer.clear_recent();
                    }
                }
            }

            // Check if sync is active and stalled before calling trigger
            let sync_active = self.sync.try_lock().ok()
                .and_then(|g| g.as_ref().map(|s| s.active()))
                .unwrap_or(false);
            if !sync_active { continue; }

            // trigger(timeout) — acquire sync lock, find missing, build requests, send
            let sync_arc = self.sync.clone();
            let sync_target_hash8 = self.sync_target_hash8.clone();
            let storage_clone = self.storage.clone();
            let trigger_result = tokio::task::spawn_blocking(move || {
                Self::sync_trigger_blocking(&sync_arc, &sync_target_hash8, &storage_clone, TriggerReason::Timeout)
            }).await;
            let (reqs, sync_seq, abandon) = match trigger_result {
                Ok(r) => r,
                Err(e) => { error!("sync timer spawn_blocking panicked: {}", e); continue; }
            };

            if abandon {
                // Real abandon — re-acquire a fresh ledger
                let mut state = self.state.write().await;
                state.sync_in_progress = false;
                let best_peer = state.peer_ledger_range.iter()
                    .max_by_key(|(_, (_, last))| *last)
                    .map(|(pid, (_, last))| (*pid, *last));
                if let Some((pid, latest_seq)) = best_peer {
                    let cookie = crate::sync::next_cookie();
                    let req = crate::network::relay::encode_get_ledger_base_by_seq(latest_seq, cookie);
                    if let Some(tx) = state.peer_txs.get(&pid) {
                        let _ = tx.try_send(req);
                        info!("sync timer: sent liBASE re-acquire for ledger {} to peer {:?}", latest_seq, pid);
                    }
                }
                continue;
            }

            // Timer trigger: round-robin during bulk sync, broadcast when stalled.
            // Broadcast wastes bandwidth (15x dup) during bulk but is needed at
            // the tail where most peers have evicted the target's deep nodes.
            if !reqs.is_empty() {
                let is_stalled = {
                    self.sync.try_lock().ok()
                        .and_then(|g| g.as_ref().map(|s| s.peer.stalled_retries > 0))
                        .unwrap_or(false)
                };
                if is_stalled {
                    // Broadcast to all peers — tail stall recovery
                    for req in &reqs {
                        self.sync_send_request(req, sync_seq, None).await;
                    }
                } else {
                    // Round-robin across peers — bulk sync
                    let state = self.state.read().await;
                    let peer_ids: Vec<_> = state.peer_txs.keys().copied().collect();
                    drop(state);
                    for (i, req) in reqs.iter().enumerate() {
                        if peer_ids.is_empty() {
                            self.sync_send_request(req, sync_seq, None).await;
                        } else {
                            let pid = peer_ids[i % peer_ids.len()];
                            self.sync_send_request(req, sync_seq, Some(pid)).await;
                        }
                    }
                }
            }
        }
    }

    // ── Sync data processor (runData) ──────────────────────────────────

    /// runData — matches rippled's InboundLedger::runData().
    /// Wakes on notify, swaps queue out (fast), processes each response
    /// under the sync lock, then calls trigger(Reply) for follow-up requests.
    async fn run_sync_data_processor(self: Arc<Self>) {
        let shutdown = self.shutdown.clone();
        const NUDB_FLUSH_THRESHOLD: usize = 4000;
        let mut pending_leaves: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        loop {
            // Wait for data arrival or shutdown
            tokio::select! {
                _ = self.sync_data_notify.notified() => {},
                _ = async {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        if shutdown.load(std::sync::atomic::Ordering::Relaxed) { return; }
                    }
                } => {
                    info!("data processor: shutdown");
                    return;
                }
            }

            // Swap queue out under the queue lock (fast — like rippled's mReceivedData swap)
            let batch: Vec<(PeerId, crate::proto::TmLedgerData)> = {
                let mut q = self.sync_data_queue.lock().unwrap_or_else(|e| e.into_inner());
                std::mem::take(&mut *q)
            };
            if batch.is_empty() { continue; }
            let batch_len = batch.len();

            self.debug_log(&format!("BATCH: {} responses, collecting leaves", batch_len));

            // Process all on a blocking thread — CPU-heavy work.
            // Sync lock is held for processing, then RELEASED before trigger.
            let sync_arc = self.sync.clone();
            let storage_clone = self.storage.clone();
            let max_sync = self.config.max_sync;
            let walk_start = std::time::Instant::now();
            let blocking_result = tokio::task::spawn_blocking(move || {
                let lock_wait = std::time::Instant::now();
                let mut guard = sync_arc.lock().unwrap_or_else(|e| e.into_inner());
                let lock_wait_ms = lock_wait.elapsed().as_millis();
                let _store_ref = storage_clone.as_ref().map(|s| s.as_ref());
                if let Some(ref mut syncer) = *guard {
                    let proc_start = std::time::Instant::now();
                    let mut peer_useful_counts: HashMap<PeerId, u32> = HashMap::new();
                    let mut all_leaves: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                    let missing_before = 999usize; // skip expensive walk, only used for logging

                    // processData: process each response under the sync lock
                    for (peer_id, ld) in &batch {
                        let is_object_response = ld.error == Some(1);
                        let accepted = if is_object_response {
                            let accepted = syncer.peer.accept_object_response(
                                &ld.ledger_hash,
                                ld.request_cookie.map(|c| c as u32),
                            );
                            if accepted {
                                if let Some(seq) = ld.request_cookie {
                                    syncer.pending_object_cookies.remove(&seq);
                                }
                            }
                            accepted
                        } else {
                            syncer.peer.accept_response(&ld.ledger_hash, ld.request_cookie)
                        };
                        if !accepted {
                            if missing_before <= 5 {
                                let hash_match = ld.ledger_hash.len() >= 8
                                    && ld.ledger_hash[..8] == syncer.ledger_hash()[..8];
                                info!(
                                    "RESPONSE DROPPED: peer={:?} is_obj={} cookie={:?} hash_match={} nodes={} our_hash={}",
                                    peer_id, is_object_response,
                                    ld.request_cookie, hash_match, ld.nodes.len(),
                                    hex::encode_upper(&syncer.ledger_hash()[..8]),
                                );
                            }
                            continue;
                        }
                        let progress = syncer.process_response(ld);
                        let useful = (progress.inner_received + progress.leaf_received) as u32;
                        if !progress.leaves.is_empty() {
                            all_leaves.extend(progress.leaves);
                        }
                        if missing_before <= 5 {
                            info!(
                                "RESPONSE ACCEPTED: peer={:?} is_obj={} inner={} leaf={} nodes_in_msg={}",
                                peer_id, is_object_response,
                                progress.inner_received, progress.leaf_received,
                                ld.nodes.len(),
                            );
                        }
                        if useful > 0 {
                            *peer_useful_counts.entry(*peer_id).or_insert(0) += useful;
                        }
                    }
                    // Skip second get_missing walk — it's expensive and only diagnostic
                    // Cache eviction handled by SHAMap + FullBelowCache internally

                    let info = (syncer.inner_count(), syncer.leaf_count(), syncer.ledger_seq(),
                                syncer.pass_number(), syncer.new_objects_this_pass());

                    let hit_cap = max_sync > 0
                        && syncer.leaf_count() as u64 >= max_sync;

                    let outcome = if !syncer.active() {
                        "Inactive" // Already completed — don't re-check or re-take
                    } else if hit_cap {
                        syncer.set_active(false);
                        "HitCap"
                    } else if syncer.is_complete() {
                        let root = syncer.root_hash();
                        let target = syncer.peer.account_hash;
                        info!(
                            "sync is_complete=true root={} target={} match={}",
                            hex::encode_upper(&root[..8]),
                            hex::encode_upper(&target[..8]),
                            root == target,
                        );
                        syncer.set_active(false);
                        "TrulyComplete"
                    } else if syncer.is_pass_complete() {
                        syncer.peer.start_new_pass();
                        "PassComplete"
                    } else {
                        "Continue"
                    };

                    // If complete, extract SHAMap and sync header while we still hold the lock
                    let completed_shamap = if outcome == "TrulyComplete" {
                        let sync_header = syncer.sync_header.clone();
                        Some((syncer.take_shamap(), sync_header))
                    } else {
                        None
                    };

                    let hold_ms = proc_start.elapsed().as_millis();
                    // RELEASE sync lock — matching rippled's runData pattern
                    drop(guard);
                    if lock_wait_ms > 5 || hold_ms > 20 {
                        tracing::info!(
                            "sync processData: lock_wait={}ms hold={}ms outcome={}",
                            lock_wait_ms, hold_ms, outcome,
                        );
                    }
                    Some((outcome, info, peer_useful_counts, completed_shamap, all_leaves))
                } else {
                    drop(guard);
                    None
                }
            }).await;
            let result = match blocking_result {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(e) => { error!("sync data processor spawn_blocking panicked: {}", e); continue; }
            };
            let (outcome, sync_info, peer_useful_counts, completed_shamap, synced_leaves) = result;
            let walk_ms = walk_start.elapsed().as_millis();

            // Accumulate leaves in RAM, batch-flush to NuDB every 4000 for speed.
            if !synced_leaves.is_empty() {
                pending_leaves.extend(synced_leaves);
                if pending_leaves.len() >= NUDB_FLUSH_THRESHOLD {
                    let state = self.state.read().await;
                    let ls = state.ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                    ls.store_leaves_to_nudb(&pending_leaves);
                    info!(
                        "sync data processor: flushed {} leaves to NuDB",
                        pending_leaves.len(),
                    );
                    pending_leaves.clear();
                }
            }

            // Handle completion BEFORE triggering — no sync lock held
            // This is the rippled done() equivalent: hand off SHAMap + persist handoff metadata
            if let Some((shamap, sync_header)) = completed_shamap {
                // Flush remaining accumulated leaves before final NuDB flush
                if !pending_leaves.is_empty() {
                    let state = self.state.read().await;
                    let ls = state.ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                    ls.store_leaves_to_nudb(&pending_leaves);
                    info!("sync data processor: flushed final {} leaves to NuDB", pending_leaves.len());
                    pending_leaves.clear();
                }
                info!("sync data processor: tree complete — flushing NuDB to disk");
                if let Some(ref backend) = self.nudb_backend {
                    match backend.flush_to_disk() {
                        Ok(()) => info!("NuDB flush complete"),
                        Err(e) => error!("NuDB flush FAILED: {}", e),
                    }
                }
                info!("sync data processor: handing off SHAMap to LedgerState");
                {
                    let state = self.state.read().await;
                    let mut ls = state.ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                    ls.set_nudb_shamap(shamap);
                }
                // Persist sync-specific handoff metadata BEFORE flipping sync_done.
                // The follower reads these to determine its exact starting point.
                // All keys are written as one logical set.
                if let Some(ref store) = self.storage {
                    let _ = store.persist_sync_anchor(&sync_header);
                    let _ = store.flush();
                }
                self.run_post_sync_checkpoint(&sync_header).await;
                // Flip sync_done AFTER handoff is fully installed
                {
                    let mut state = self.state.write().await;
                    state.sync_done = true;
                    state.sync_in_progress = false;
                }
                info!(
                    "sync complete — synced_ledger={} hash={} — handoff persisted, starting follower",
                    sync_header.sequence, hex::encode_upper(&sync_header.hash[..8]),
                );
                // Start the follower now that we have full state
                self.start_follower().await;
            }

            // Matching rippled's runData: sample up to 6 most useful peers,
            // build one request per peer, distribute across peers.
            let trigger_start = std::time::Instant::now();

            let mut useful_peers: Vec<(PeerId, u32)> = peer_useful_counts.iter()
                .map(|(pid, count)| (*pid, *count))
                .collect();
            // Prune peers below 50% of best (matching rippled's PeerDataCounts::prune)
            if let Some(max_count) = useful_peers.iter().map(|(_, c)| *c).max() {
                let thresh = max_count / 2;
                useful_peers.retain(|(_, c)| *c >= thresh);
            }
            useful_peers.sort_by(|a, b| b.1.cmp(&a.1));
            useful_peers.truncate(6);
            let num_peers = useful_peers.len().max(1); // at least 1 (broadcast)

            // Build up to num_peers requests under one sync lock hold.
            // Each request gets different missing nodes via recent_nodes filter.
            let sync_arc_trigger = self.sync.clone();
            let trigger_result = tokio::task::spawn_blocking(move || {
                let mut guard = sync_arc_trigger.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ref mut syncer) = *guard {
                    if !syncer.active() { return (vec![], 0u32); }
                    let reqs = syncer.build_multi_requests(num_peers, crate::sync::SyncRequestReason::Reply);
                    let seq = syncer.ledger_seq();
                    (reqs, seq)
                } else {
                    (vec![], 0u32)
                }
            }).await;
            let (reqs, sync_seq) = match trigger_result {
                Ok(r) => r,
                Err(e) => { error!("sync trigger(Reply) panicked: {}", e); (vec![], 0) }
            };

            // Distribute requests across useful peers round-robin
            let mut total_reqs = 0usize;
            if !reqs.is_empty() {
                if useful_peers.is_empty() {
                    // No useful peers — broadcast first request to all
                    self.sync_send_request(&reqs[0], sync_seq, None).await;
                    total_reqs = 1;
                } else {
                    for (i, req) in reqs.iter().enumerate() {
                        let peer_idx = i % useful_peers.len();
                        let (pid, _) = useful_peers[peer_idx];
                        self.sync_send_request(req, sync_seq, Some(pid)).await;
                        total_reqs += 1;
                    }
                }
            }
            let trigger_ms = trigger_start.elapsed().as_millis();

            self.debug_log(&format!(
                "PROCESSED: {} inner + {} leaf, processData={}ms, trigger={}ms, {} reqs to {} peers",
                sync_info.0, sync_info.1, walk_ms, trigger_ms, total_reqs, useful_peers.len(),
            ));

            if !peer_useful_counts.is_empty() {
                let mut state = self.state.write().await;
                for (peer_id, useful) in peer_useful_counts {
                    let entry = state.peer_sync_useful.entry(peer_id).or_insert(0);
                    *entry = entry.saturating_mul(3) / 4 + useful;
                }
            }

            // Yield to let the follower and other tasks run between batches.
            tokio::task::yield_now().await;

            // Handle outcomes
            match outcome {
                "TrulyComplete" => {
                    self.debug_log(&format!(
                        "SYNC COMPLETE: {} inner + {} leaf",
                        sync_info.0, sync_info.1,
                    ));
                    info!(
                        "state sync TRULY COMPLETE: {} total objects across {} passes",
                        sync_info.1, sync_info.3,
                    );
                    if let Some(ref store) = self.storage {
                        let leaf_count = match self.sync.try_lock() {
                            Ok(guard) => {
                                if let Some(ref syncer) = *guard {
                                    syncer.leaf_count() as u64
                                } else {
                                    0
                                }
                            }
                            Err(_) => {
                                debug!("leaf count save deferred: sync lock busy");
                                0
                            }
                        };
                        let _ = store.save_meta_kv("leaf_count", &leaf_count.to_le_bytes());
                    }
                    // All leaves already written to NuDB by add_known_node.
                    if let Some(ref store) = self.storage {
                        let _ = store.set_sync_complete();
                        let _ = store.flush();
                    }

                    // Tell all peers we're synced
                    {
                        let state = self.state.read().await;
                        let status_msg = crate::network::relay::encode_status_change(
                            crate::proto::NodeStatus::NsConnected,
                            crate::proto::NodeEvent::NeAcceptedLedger,
                            state.ctx.ledger_seq,
                            &state.ctx.ledger_header.hash,
                        );
                        state.broadcast(&status_msg, None);
                        info!("broadcast nsConnected status to {} peers", state.peer_count());
                    }

                    // Load leaf hashes into SparseSHAMap
                    {
                        let ls_arc = {
                            let state = self.state.read().await;
                            state.ctx.ledger_state.clone()
                        };
                        let our_hash = {
                            let mut ls = ls_arc.lock().unwrap_or_else(|e| e.into_inner());
                            ls.enable_sparse();
                            {
                                // Leaf hashes are in NuDB now — no bulk load from storage
                            }
                            ls.state_hash()
                        };
                        let mut state = self.state.write().await;
                        let network_hash = state.ctx.ledger_header.account_hash;
                        state.sync_in_progress = false;
                        if our_hash == network_hash {
                            info!(
                                "sync verification PASSED: hash={} matches network",
                                hex::encode_upper(&our_hash[..8]),
                            );
                            state.sync_done = true;
                        } else {
                            warn!(
                                "sync verification FAILED: ours={} network={} — staying in syncing state",
                                hex::encode_upper(&our_hash[..8]),
                                hex::encode_upper(&network_hash[..8]),
                            );
                            // Do NOT set sync_done — hash mismatch means state is wrong
                        }
                    }
                }
                "HitCap" => {
                    info!(
                        "state sync hit max_sync cap: {} leaf + {} inner nodes",
                        sync_info.1, sync_info.0,
                    );
                }
                _ => {}
            }

            // Periodic logging
            {
                static LAST_LOG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let prev = LAST_LOG.load(std::sync::atomic::Ordering::Relaxed);
                if now >= prev + 10 {
                    LAST_LOG.store(now, std::sync::atomic::Ordering::Relaxed);
                    let nudb_objects = self.nudb_backend.as_ref().map_or(0, |b| b.count() as usize);
                    info!(
                        "sync: {} unique nodes in NuDB | received {} from peers ({}i {}l, {:.0}% dup) | batch: {}",
                        nudb_objects,
                        sync_info.0 + sync_info.1,
                        sync_info.0, sync_info.1,
                        if nudb_objects > 0 { ((sync_info.0 + sync_info.1) as f64 / nudb_objects as f64 - 1.0) * 100.0 } else { 0.0 },
                        batch_len,
                    );
                }
            }

            // Debug summary every 30s
            {
                static LAST_SUMMARY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                static PREV_LEAF_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let prev = LAST_SUMMARY.load(std::sync::atomic::Ordering::Relaxed);
                if now >= prev + 30 {
                    LAST_SUMMARY.store(now, std::sync::atomic::Ordering::Relaxed);
                    let prev_leaves = PREV_LEAF_COUNT.swap(sync_info.1 as u64, std::sync::atomic::Ordering::Relaxed);
                    let delta = (sync_info.1 as u64).saturating_sub(prev_leaves);
                    let rate_k_per_min = (delta * 2) / 1000;
                    let state = self.state.read().await;
                    let active_peers = state.peer_count();
                    let benched_peers = state.sync_peer_cooldown.len();
                    let latencies: Vec<_> = state.peer_latency.iter()
                        .map(|(pid, lat)| format!("{:?}={}ms", pid, lat)).collect();
                    let redb_mb = 0u64;
                    self.debug_log(&format!(
                        "SUMMARY: rate={}K/min, peers={} active/{} benched, latencies=[{}], inner={}, leaf={}, redb=~{}K_objs",
                        rate_k_per_min, active_peers, benched_peers,
                        latencies.join(", "), sync_info.0, sync_info.1, redb_mb,
                    ));
                }
            }

            // Periodic inner node saving (~every 100K leaves)
            {
                static LAST_INNER_SAVE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let total = sync_info.1 as u64;
                let prev_inner = LAST_INNER_SAVE.load(std::sync::atomic::Ordering::Relaxed);
                if total >= prev_inner + 100_000 {
                    LAST_INNER_SAVE.store(total, std::sync::atomic::Ordering::Relaxed);
                    if let Some(ref store) = self.storage {
                        let leaf_count = match self.sync.try_lock() {
                            Ok(guard) => {
                                if let Some(ref syncer) = *guard {
                                    syncer.leaf_count() as u64
                                } else {
                                    0
                                }
                            }
                            Err(_) => {
                                debug!("leaf count save deferred: sync lock busy");
                                0
                            }
                        };
                        let _ = store.save_meta_kv("leaf_count", &leaf_count.to_le_bytes());
                        info!("periodic save: {total} leaves total");
                    }
                }
            }
        }
    }

    // ── Ledger close loop ──────────────────────────────────────────────────

    /// Consensus-driven ledger close loop.
    ///
    /// Phases per round:
    /// 1. **Open** (1s): collect transactions in the pool.
    /// 2. **Propose**: broadcast our tx-set hash to peers.
    /// 3. **Establish** (3s): collect peer proposals, converge.
    /// 4. **Accept**: apply the agreed tx set, close the ledger.
    /// 5. **Validate**: broadcast a validation of the new ledger hash.
    async fn run_ledger_close_loop(self: Arc<Self>) {
        use std::time::{Duration, SystemTime};
        use crate::consensus::{Proposal, Validation};
        use crate::network::relay;

        // Wait a beat before the first round.
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Track previous round metrics for shouldCloseLedger and checkConsensus.
        let mut prev_round_time = Duration::from_secs(4); // bootstrap default ~4s
        let mut prev_proposers: usize = 0; // bootstrap: no previous proposers
        // Persistent consensus mode across rounds (wrong-ledger survives round boundaries).
        let mut persistent_mode = crate::consensus::ConsensusMode::Proposing;

        loop {
            // ── Phase 1: Open — shouldCloseLedger ───────────────────────────
            let open_start = tokio::time::Instant::now();
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let open_time = open_start.elapsed();
                let (has_txs, prev_proposers, proposers_closed, proposers_validated) = {
                    let state = self.state.read().await;
                    let next_seq = state.ctx.ledger_seq + 1;
                    let prev_proposers = state.current_round.as_ref()
                        .map(|round| round.proposal_count())
                        .unwrap_or(0);
                    let proposers_validated = state.current_round.as_ref()
                        .map(|round| round.validation_count())
                        .unwrap_or(0);
                    let pool_guard = state.ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
                    let has_txs = !pool_guard.is_empty();
                    drop(pool_guard);
                    (
                        has_txs,
                        prev_proposers,
                        state.staged_proposals.values().filter(|p| p.ledger_seq == next_seq).count(),
                        proposers_validated,
                    )
                };
                if should_close_ledger(
                    has_txs,
                    prev_proposers,
                    proposers_closed,
                    proposers_validated,
                    prev_round_time,
                    open_time,
                    open_time,
                    Duration::from_secs(15),
                ) {
                    break;
                }
            }

            let next_seq = {
                let state = self.state.read().await;
                state.ctx.ledger_seq + 1
            };

            // ── Phase 2: Propose ─────────────────────────────────────────────
            // Compute the tx-set hash from the current pool contents.
            let tx_set_hash = {
                let state = self.state.read().await;
                let pool_guard = state.ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
                let hash = pool_guard.canonical_set_hash();
                drop(pool_guard);
                hash
            };

            // Broadcast our proposal
            // Ripple epoch = 2000-01-01T00:00:00Z = 946684800 UNIX seconds
            let close_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs().saturating_sub(946684800) as u32)
                .unwrap_or(0);

            let prev_hash = {
                let state = self.state.read().await;
                state.ctx.ledger_header.hash
            };
            let proposal = Proposal::new_signed(
                next_seq, tx_set_hash, prev_hash, close_time, 0, self.signing_key(),
            );
            let prop_msg = relay::encode_proposal(&proposal);

            // Initialize consensus round with persistent mode
            let should_propose = persistent_mode == crate::consensus::ConsensusMode::Proposing
                && !self.unl.read().unwrap_or_else(|e| e.into_inner()).is_empty();
            {
                let mut state = self.state.write().await;
                let unl_snapshot = self.unl.read().unwrap_or_else(|e| e.into_inner()).clone();
                let mut round = crate::consensus::ConsensusRound::new(
                    next_seq, unl_snapshot, prev_hash, should_propose,
                    prev_round_time, prev_proposers,
                );
                round.mode = persistent_mode;
                round.our_close_time = close_time as u64;
                round.close_ledger(tx_set_hash);
                let staged = std::mem::take(&mut state.staged_proposals);
                for (key, prop) in staged {
                    if prop.ledger_seq == next_seq && prop.prop_seq != crate::consensus::round::SEQ_LEAVE {
                        if round.add_proposal(prop.clone()) {
                            round.add_close_time_vote(prop.close_time as u64);
                        }
                    } else if prop.ledger_seq > next_seq {
                        state.staged_proposals.insert(key, prop);
                    }
                }
                state.current_round = Some(round);
                if should_propose {
                    state.broadcast(&prop_msg, None);
                }
            }
            if should_propose {
                info!("proposed ledger {next_seq} tx_set={}...", &hex::encode_upper(tx_set_hash)[..16]);
            } else {
                info!("observing ledger {next_seq} (mode={:?})", persistent_mode);
            }

            // ── Phase 3: Establish — convergence loop ────────────────────────
            // Poll every 250ms: update disputes, check consensus state machine.
            let round_start = tokio::time::Instant::now();
            let mut prop_seq = 0u32;
            let mut last_propose_time = tokio::time::Instant::now();
            let mut consensus_exit_state = crate::consensus::round::ConsensusState::No;
            let mut wrong_ledger_hash: Option<[u8; 32]> = None;
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;

                // Check for wrong ledger — majority building on different parent
                {
                    let mut state = self.state.write().await;
                    if let Some(ref mut round) = state.current_round {
                        if let Some(correct_parent) = round.check_wrong_ledger() {
                            warn!(
                                "consensus: wrong ledger! majority on {} but we're on {} — bowing out",
                                &hex::encode_upper(correct_parent)[..16],
                                &hex::encode_upper(prev_hash)[..16],
                            );
                            round.handle_wrong_ledger();
                            wrong_ledger_hash = Some(correct_parent);
                            break;
                        }
                    }
                }

                // Update disputes + convergence using relative timing
                let new_position = {
                    let mut state = self.state.write().await;
                    if let Some(ref mut round) = state.current_round {
                        let cp = round.converge_percent();
                        // Update avalanche votes on disputed transactions
                        let changed = round.update_disputes(cp);
                        if changed.is_empty() {
                            round.tick_unchanged();
                        } else {
                            round.reset_unchanged();
                        }
                        // Check close time consensus
                        round.check_close_time_consensus();
                        // Try to converge on tx set
                        round.try_converge()
                    } else {
                        None
                    }
                };

                if let Some(new_hash) = new_position {
                    prop_seq += 1;
                    let updated = Proposal::new_signed(
                        next_seq, new_hash, prev_hash, close_time, prop_seq, self.signing_key(),
                    );
                    let msg = relay::encode_proposal(&updated);
                    let state = self.state.read().await;
                    state.broadcast(&msg, None);
                    info!(
                        "consensus: updated position prop_seq={} tx_set={}...",
                        prop_seq, &hex::encode_upper(new_hash)[..16],
                    );
                }

                // Run the consensus state machine
                let cs = {
                    let mut state = self.state.write().await;
                    if let Some(ref mut round) = state.current_round {
                        if round.unl_size() == 0 {
                            // No UNL → accept immediately after MIN_CONSENSUS
                            if round.establish_elapsed() >= crate::consensus::round::MIN_CONSENSUS {
                                crate::consensus::round::ConsensusState::Yes
                            } else {
                                crate::consensus::round::ConsensusState::No
                            }
                        } else {
                            round.check_consensus()
                        }
                    } else {
                        crate::consensus::round::ConsensusState::Yes
                    }
                };

                match cs {
                    crate::consensus::round::ConsensusState::Yes => {
                        let elapsed = round_start.elapsed();
                        info!("consensus: reached after {:.1}s (TX + close time agreement)", elapsed.as_secs_f64());
                        consensus_exit_state = cs;
                        break;
                    }
                    crate::consensus::round::ConsensusState::MovedOn => {
                        let elapsed = round_start.elapsed();
                        warn!("consensus: network moved on without us after {:.1}s", elapsed.as_secs_f64());
                        consensus_exit_state = cs;
                        break;
                    }
                    crate::consensus::round::ConsensusState::Expired => {
                        let elapsed = round_start.elapsed();
                        warn!("consensus: expired after {:.1}s — force accepting", elapsed.as_secs_f64());
                        consensus_exit_state = cs;
                        break;
                    }
                    crate::consensus::round::ConsensusState::No => {
                        // Keep waiting
                    }
                }

                // Proposal regeneration — re-broadcast every 12s to keep fresh
                // (rippled's proposeINTERVAL = 12s, proposeFRESHNESS = 20s)
                if should_propose && last_propose_time.elapsed() > Duration::from_secs(12) {
                    last_propose_time = tokio::time::Instant::now();
                    if let Some(pos) = {
                        let state = self.state.read().await;
                        state.current_round.as_ref().and_then(|r| r.our_position)
                    } {
                        prop_seq += 1;
                        let refreshed = Proposal::new_signed(
                            next_seq, pos, prev_hash, close_time, prop_seq, self.signing_key(),
                        );
                        let msg = relay::encode_proposal(&refreshed);
                        let state = self.state.read().await;
                        state.broadcast(&msg, None);
                        info!("consensus: refreshed proposal prop_seq={}", prop_seq);
                    }
                }
            }
            let _ = consensus_exit_state; // used for future logging/metrics

            // ── Wrong-ledger recovery path ───────────────────────────────────
            // If wrong ledger was detected, skip close/validate entirely.
            // Request the correct parent so the follower can catch up.
            // DO NOT mutate ledger_header/state — that would create an
            // inconsistency between the header and the state tree. The
            // follower / sync path handles the actual branch switch.
            if let Some(correct_hash) = wrong_ledger_hash {
                info!(
                    "consensus: wrong-ledger recovery — requesting correct parent {}...",
                    &hex::encode_upper(correct_hash)[..16],
                );

                // Request the correct ledger from peers via InboundLedgers.
                // This primes the acquisition so the follower can pick it up.
                {
                    let mut guard = self.inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                    guard.create(correct_hash, 0);
                }

                // Broadcast liBASE request to all peers — kick off acquisition.
                let cookie = rand::random::<u64>();
                let base_req = relay::encode_get_ledger_base(&correct_hash, cookie);
                {
                    let state = self.state.read().await;
                    state.broadcast(&base_req, None);
                }

                // Stay in WrongLedger mode. The follower / sync path will
                // acquire the correct ledger and update the header+state
                // atomically. Once that happens and we produce a successful
                // validation, persistent_mode returns to Proposing.
                persistent_mode = crate::consensus::ConsensusMode::WrongLedger;
                warn!("consensus: staying in WrongLedger — follower will acquire correct branch");

                // Clean up round without closing.
                {
                    let mut state = self.state.write().await;
                    state.current_round = None;
                }
                continue; // Skip close/validate, go to next round.
            }

            // ── Normal path: accept and close ────────────────────────────────

            // Accept the round — extract consensus close time and metrics.
            let (consensus_close_time, have_ct_consensus) = {
                let state = self.state.read().await;
                if let Some(ref round) = state.current_round {
                    (round.our_close_time, round.have_close_time_consensus)
                } else {
                    (0u64, false)
                }
            };
            {
                let mut state = self.state.write().await;
                if let Some(ref mut round) = state.current_round {
                    if let Some(result) = round.accept() {
                        let state_label = match result.state {
                            crate::consensus::round::ConsensusState::Yes     => "Yes",
                            crate::consensus::round::ConsensusState::MovedOn => "MovedOn",
                            crate::consensus::round::ConsensusState::Expired => "Expired",
                            crate::consensus::round::ConsensusState::No      => "No",
                        };
                        info!(
                            "consensus: accepted ledger {} — {}/{} agree ({:.0}%) state={} round_time={:.1}s close_time_consensus={}",
                            result.ledger_seq, result.agree_count, result.unl_size,
                            result.agreement_pct() * 100.0, state_label,
                            result.round_time.as_secs_f64(), have_ct_consensus,
                        );
                        // Feed metrics to next round.
                        prev_round_time = result.round_time;
                        prev_proposers = result.proposers;
                    }
                }
            }

            // ── Phase 4: Accept — close the ledger ───────────────────────────
            // Use consensus-agreed close time when available, fall back to wall clock.
            let close_time_u64 = if have_ct_consensus && consensus_close_time > 0 {
                consensus_close_time
            } else {
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            };

            // Drain tx pool and clone what we need, release SharedState first.
            // Then lock ledger_state alone for the heavy close_ledger work.
            // This prevents blocking all SharedState access during replay.
            let (prev_header, ls_arc, mut tx_pool) = {
                let state = self.state.write().await;
                let prev_header = state.ctx.ledger_header.clone();
                let ls_arc = state.ctx.ledger_state.clone();
                let tx_pool = std::mem::take(&mut *state.ctx.tx_pool.write().unwrap_or_else(|e| e.into_inner()));
                (prev_header, ls_arc, tx_pool)
            }; // SharedState released

            // ── Close directly against LedgerState ─────────────────────────
            // Consensus close now uses the same `ledger::close` engine we
            // trust for independent replay, so the legacy transact/view stack
            // is no longer on the live runtime path.
            let result = {
                let mut ls = ls_arc.lock().unwrap_or_else(|e| e.into_inner());
                crate::ledger::close::close_ledger(
                    &prev_header,
                    &mut ls,
                    &mut tx_pool,
                    close_time_u64,
                    have_ct_consensus,
                )
            };

            let seq = result.header.sequence;
            let hash = result.header.hash;
            let applied = result.applied_count;
            let failed = result.failed_count;
            let skipped = result.skipped_count;
            let tx_records = result.tx_records.clone();
            let close_time_u64 = result.header.close_time;
            let ledger_hash_hex = hex::encode_upper(hash);

            // Read fees from the updated ledger state (FeeSettings SLE).
            let updated_fees = {
                let ls = ls_arc.lock().unwrap_or_else(|e| e.into_inner());
                crate::ledger::read_fees(&ls)
            };

            // Reacquire SharedState briefly for metadata updates
            {
                let mut state = self.state.write().await;
                state.ctx.ledger_header = result.header.clone();
                state.ctx.ledger_seq = seq;
                state.ctx.ledger_hash = ledger_hash_hex.clone();
                state.ctx.fees = updated_fees;
                // Put back any remaining transactions
                if !tx_pool.is_empty() {
                    *state.ctx.tx_pool.write().unwrap_or_else(|e| e.into_inner()) = tx_pool;
                }
                state.ctx.history.write().unwrap_or_else(|e| e.into_inner()).insert_ledger(result.header.clone(), result.tx_records.clone());
            }

            // Create ClosedLedger from current state for ReadView-based RPC
            let closed_ledger = {
                let mut ls = ls_arc.lock().unwrap_or_else(|e| e.into_inner());
                let state_map = ls.snapshot_state_map();
                let tx_map = crate::ledger::shamap::SHAMap::new_transaction();
                std::sync::Arc::new(crate::ledger::ledger_core::ClosedLedger::new(
                    crate::ledger::views::LedgerInfo {
                        seq, hash, close_time: close_time_u64,
                        account_hash: result.header.account_hash,
                        tx_hash: result.header.transaction_hash,
                        total_coins: result.header.total_coins,
                        ..Default::default()
                    },
                    state_map,
                    tx_map,
                    crate::ledger::fees::Fees {
                        base_fee: updated_fees.base,
                        reserve_base: updated_fees.reserve,
                        reserve_inc: updated_fees.increment,
                    },
                    crate::ledger::rules::Rules::new(),
                ))
            }; // ls dropped here, before await
            {
                let mut state = self.state.write().await;
                state.ctx.closed_ledger = Some(closed_ledger);
            }

            if let Some(ref store) = self.storage {
                let _ = store.save_ledger(&result.header, &result.tx_records);
                let _ = store.save_meta(seq, &ledger_hash_hex, &result.header);

                let _ = store.flush();
            }

            info!(
                "ledger {seq} closed — applied={applied} failed={failed} skipped={skipped} hash={}...",
                &hex::encode_upper(hash)[..16],
            );

            // Refresh RPC snapshot after ledger close
            self.update_rpc_snapshot().await;

            // ── Phase 5: Validate — broadcast validation ─────────────────────
            let validation = Validation::new_signed(
                seq, hash, close_time, true, self.signing_key(),
            );
            let val_msg = relay::encode_validation(&validation);
            {
                let state = self.state.read().await;
                state.broadcast(&val_msg, None);
            }
            info!("validated ledger {seq}");

            // prev_round_time and prev_proposers already set from result.round_time/proposers above.

            // Wait briefly for validation quorum, then clean up round
            tokio::time::sleep(Duration::from_secs(1)).await;
            {
                let mut state = self.state.write().await;
                if let Some(ref mut round) = state.current_round {
                    if let Some(validated_hash) = round.check_validated() {
                        info!(
                            "consensus: ledger {} fully validated (80%+ quorum) hash={}...",
                            seq, &hex::encode_upper(validated_hash)[..16],
                        );
                        // Successful validation → stay in proposing mode
                        persistent_mode = crate::consensus::ConsensusMode::Proposing;
                    }
                    // Persist mode for wrong-ledger recovery across rounds
                    if round.mode == crate::consensus::ConsensusMode::WrongLedger {
                        persistent_mode = crate::consensus::ConsensusMode::WrongLedger;
                    } else if round.mode == crate::consensus::ConsensusMode::SwitchedLedger {
                        persistent_mode = crate::consensus::ConsensusMode::Observing;
                    }
                }
                state.current_round = None;
            }

            // Emit WebSocket events
            let validated_ledgers = {
                let st = self.state.read().await;
                let h = st.ctx.history.read().unwrap_or_else(|e| e.into_inner()).complete_ledgers();
                h
            };
            let peer_count = self.state.read().await.peer_count();
            let ws_fees = {
                let st = self.state.read().await;
                st.ctx.fees
            };
            let _ = self.ws_events.send(crate::rpc::ws::WsEvent::LedgerClosed {
                ledger_seq: seq,
                ledger_hash: ledger_hash_hex.clone(),
                tx_count: applied,
                ledger_time: close_time as u64,
                network_id: self.config.network_id,
                validated_ledgers,
                fee_base: ws_fees.base,
                reserve_base: ws_fees.reserve,
                reserve_inc: ws_fees.increment,
            });
            let _ = self.ws_events.send(crate::rpc::ws::WsEvent::ServerStatus {
                ledger_seq: seq,
                ledger_hash: ledger_hash_hex.clone(),
                network_id: self.config.network_id,
                peer_count,
                validated_ledgers: self.state.read().await.ctx.history.read().unwrap_or_else(|e| e.into_inner()).complete_ledgers(),
            });
            for rec in tx_records {
                let accounts = match crate::transaction::parse_blob(&rec.blob) {
                    Ok(parsed) => {
                        let mut touched = Vec::with_capacity(2);
                        touched.push(crate::crypto::base58::encode_account(&parsed.account));
                        if let Some(dest) = parsed.destination {
                            let dest_b58 = crate::crypto::base58::encode_account(&dest);
                            if !touched.iter().any(|a| a == &dest_b58) {
                                touched.push(dest_b58);
                            }
                        }
                        touched
                    }
                    Err(_) => Vec::new(),
                };
                let _ = self.ws_events.send(crate::rpc::ws::WsEvent::Transaction {
                    tx_record: rec,
                    ledger_hash: ledger_hash_hex.clone(),
                    close_time: close_time_u64,
                    network_id: self.config.network_id,
                    accounts,
                });
            }
        }
    }

    // ── Peer listener ─────────────────────────────────────────────────────────

    async fn run_peer_listener(self: Arc<Self>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.config.peer_addr).await?;
        info!(
            "listening for peers on {} — slots: {} inbound, {} outbound (max_peers={})",
            self.config.peer_addr, self.config.max_inbound(), self.config.max_outbound(), self.config.max_peers,
        );

        // Rate limiting: track recent connections per IP
        let mut ip_last_connect: HashMap<std::net::IpAddr, tokio::time::Instant> =
            HashMap::new();
        let rate_limit = std::time::Duration::from_secs(2); // min 2s between connections per IP

        loop {
            let (tcp, addr) = listener.accept().await?;

            // Global throttle — small delay to prevent accept loop flooding
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            // Per-IP rate limit
            let now = tokio::time::Instant::now();
            if let Some(last) = ip_last_connect.get(&addr.ip()) {
                if now.duration_since(*last) < rate_limit {
                    warn!("rate limited {addr} — too frequent");
                    continue;
                }
            }
            ip_last_connect.insert(addr.ip(), now);

            // Evict stale entries periodically
            if ip_last_connect.len() > 1000 {
                ip_last_connect.retain(|_, v| now.duration_since(*v) < std::time::Duration::from_secs(60));
            }

            {
                let state = self.state.read().await;
                let inbound = state.inbound_count();
                let max_in = self.config.max_inbound();
                // Always allow localhost (cluster/rippled peer) regardless of limits.
                if !addr.ip().is_loopback() && inbound >= max_in {
                    warn!("inbound slots full ({}/{}) — rejecting {addr}", inbound, max_in);
                    continue;
                }
            }

            info!("inbound connection from {addr}");
            let node = self.clone();

            if self.openssl_tls.is_some() {
                // Create the Ssl object before the spawn to avoid lifetime issues with self
                let ssl = match openssl::ssl::Ssl::new(self.openssl_tls.as_ref().unwrap().acceptor.context()) {
                    Ok(ssl) => ssl,
                    Err(e) => {
                        warn!("SSL object creation error for {addr}: {e}");
                        continue;
                    }
                };
                tokio::spawn(async move {
                    match tokio_openssl::SslStream::new(ssl, tcp) {
                        Ok(mut stream) => {
                            if let Err(e) = std::pin::Pin::new(&mut stream).accept().await {
                                warn!("TLS accept error from {addr}: {e}");
                                return;
                            }
                            let session_hash = crate::tls::make_shared_value(stream.ssl())
                                .unwrap_or([0u8; 32]);
                            node.handle_peer(stream, session_hash, addr, Direction::Inbound).await;
                        }
                        Err(e) => warn!("TLS stream creation error from {addr}: {e}"),
                    }
                });
            } else {
                tokio::spawn(async move {
                    node.handle_peer(tcp, [0u8; 32], addr, Direction::Inbound).await;
                });
            }
        }
    }

    /// Dial an outbound peer.
    async fn dial(self: Arc<Self>, addr: SocketAddr) -> anyhow::Result<()> {
        info!("dialing {addr}");
        let tcp = TcpStream::connect(addr).await?;

        if let Some(ref ossl) = self.openssl_tls {
            let ssl = openssl::ssl::Ssl::new(&ossl.connector_ctx)?;
            let mut stream = tokio_openssl::SslStream::new(ssl, tcp)?;
            std::pin::Pin::new(&mut stream).connect().await?;
            let session_hash = crate::tls::make_shared_value(stream.ssl())
                .unwrap_or([0u8; 32]);
            self.handle_peer(stream, session_hash, addr, Direction::Outbound).await;
        } else {
            self.handle_peer(tcp, [0u8; 32], addr, Direction::Outbound).await;
        }
        Ok(())
    }

    // ── Per-peer I/O loop ─────────────────────────────────────────────────────

    async fn handle_peer<S>(
        self: Arc<Self>,
        mut stream: S,
        session_hash: [u8; 32],
        addr: SocketAddr,
        dir: Direction,
    ) where S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static {
        // Register peer and create outbound message channel
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<RtxpMessage>(64);
        let id = {
            let mut s = self.state.write().await;
            let id = s.next_peer_id();
            s.peers.insert(id, PeerState::Connecting);
            s.peer_txs.insert(id, outbound_tx);
            s.peer_direction.insert(id, dir);
            id
        };

        let mut peer = Peer::new(id, addr, dir);

        // Transition state machine to Handshaking (action ignored — IO handled below)
        peer.handle(PeerEvent::TlsEstablished);

        // ── Phase 1: raw HTTP upgrade handshake ───────────────────────────────
        //
        // The XRPL HTTP upgrade exchange happens over raw bytes before any RTXP
        // framing.  We read until \r\n\r\n, parse, then switch to frame mode.
        let (handshake_info, leftover) =
            match self.perform_handshake(&mut stream, &session_hash, dir).await {
                Ok(r)  => r,
                Err(e) => {
                    let err_str = format!("{e}");
                    let is_503 = err_str.contains("503");
                    // 503 = slots full (60s, peer isn't mad, just full)
                    // Other = possible resource exhaustion (130s, wait for full decay at 128s)
                    let cooldown = if is_503 { 60 } else { 130 };
                    warn!("peer {id:?} ({addr}) handshake failed (cooldown {cooldown}s)");
                    let mut s = self.state.write().await;
                    s.peers.remove(&id);
                    s.peer_txs.remove(&id);
                    s.peer_ledger_range.remove(&id);
                    s.peer_cooldowns.insert(addr, std::time::Instant::now() + std::time::Duration::from_secs(cooldown));
                    // Parse peer-ips from 503 redirect body for peer discovery
                    if is_503 {
                        if let Some(body_start) = err_str.find("body=") {
                            let body = &err_str[body_start + 5..];
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                                if let Some(ips) = json["peer-ips"].as_array() {
                                    for ip in ips {
                                        if let Some(ip_str) = ip.as_str() {
                                            if let Ok(addr) = ip_str.parse::<std::net::SocketAddr>() {
                                                s.add_known_peer(addr);
                                            } else if let Ok(ip_addr) = ip_str.parse::<std::net::IpAddr>() {
                                                s.add_known_peer(std::net::SocketAddr::new(ip_addr, 51235));
                                            }
                                        }
                                    }
                                    info!("503 redirect: discovered {} peer IPs", ips.len());
                                }
                            }
                        }
                    }
                    return;
                }
            };

        // Verify the peer's session signature against their claimed public key.
        // The signature must be present and valid — reject peers that omit it.
        if handshake_info.session_signature.is_empty() {
            warn!("peer {id:?} ({addr}) missing session signature — rejecting");
            let mut s = self.state.write().await;
            s.peers.remove(&id);
            s.peer_txs.remove(&id);
            return;
        }
        if !crate::crypto::keys::verify_secp256k1_digest(
            &handshake_info.node_pubkey,
            &session_hash,
            &handshake_info.session_signature,
        ) {
            warn!("peer {id:?} ({addr}) session signature verification failed — rejecting");
            let mut s = self.state.write().await;
            s.peers.remove(&id);
            s.peer_txs.remove(&id);
            return;
        }
        // Reject self-connections — don't waste a slot talking to ourselves
        if handshake_info.node_pubkey == self.node_key.public_key_bytes() {
            warn!("peer {id:?} ({addr}) is ourselves — rejecting self-connection");
            let mut s = self.state.write().await;
            s.peers.remove(&id);
            s.peer_txs.remove(&id);
            return;
        }

        // Reject peers on a different network. Matches rippled's behavior:
        // only reject if peer sends Network-ID AND it doesn't match ours.
        // Missing Network-ID is accepted (many legitimate peers don't send it).
        if let Some(peer_net_id) = handshake_info.network_id {
            if peer_net_id != self.config.network_id {
                warn!("peer {id:?} ({addr}) network-id mismatch: ours={} theirs={} — rejecting",
                    self.config.network_id, peer_net_id);
                let mut s = self.state.write().await;
                s.peers.remove(&id);
                s.peer_txs.remove(&id);
                return;
            }
        }

        let action = peer.handle(PeerEvent::HandshakeAccepted(handshake_info));
        if let Err(e) = self.execute_action(&mut stream, &mut peer, action, &session_hash).await {
            warn!("peer {id:?} ({addr}) post-handshake action error: {e}");
            let mut s = self.state.write().await;
            s.peers.remove(&id);
                    s.peer_txs.remove(&id);
            return;
        }

        info!("peer {id:?} ({addr}) handshake complete — entering RTXP loop");

        // ── Tell peer our status so they send us theirs ──────────
        let status_msg = {
            let state = self.state.read().await;
            // Send NsConnected so the peer treats us as a synced node
            // and sends TMStatusChange with their firstSeq/lastSeq.
            crate::network::relay::encode_status_change(
                crate::proto::NodeStatus::NsConnected,
                crate::proto::NodeEvent::NeAcceptedLedger,
                state.ctx.ledger_seq,
                &state.ctx.ledger_header.hash,
            )
        };
        let _ = stream.write_all(&status_msg.encode()).await;

        // ── Peer discovery: send our known endpoints + ourselves ─────────
        let endpoints_msg = {
            let state = self.state.read().await;
            let mut endpoints: Vec<SocketAddr> = state.known_peers.iter().copied().collect();
            // Include ourselves so peers can connect back to us
            endpoints.push(self.config.peer_addr);
            crate::network::relay::encode_endpoints(&endpoints)
        };
        let _ = stream.write_all(&endpoints_msg.encode()).await;
        // Track this connection + send initial ping for latency measurement
        let ping_msg = {
            let mut state = self.state.write().await;
            state.add_known_peer(addr);
            state.connected_addrs.insert(addr);
            state.peer_addrs.insert(id, addr);
            // Send ping to measure latency
            let seq = rand::random::<u32>();
            state.peer_ping_sent.insert(id, (seq, std::time::Instant::now()));
            crate::network::relay::encode_ping(seq)
        };
        let _ = stream.write_all(&ping_msg.encode()).await;

        // Check if peer negotiated LZ4 compression (X-Protocol-Ctl: compr=lz4)
        let use_compression = peer.info.as_ref()
            .and_then(|i| i.features.as_ref())
            .map(|f| f.contains("lz4"))
            .unwrap_or(false);

        // ── Phase 2: RTXP framing loop ────────────────────────────────────────
        let mut dec = FrameDecoder::new();
        // Any bytes that arrived alongside the last HTTP response go in first
        if !leftover.is_empty() {
            let _ = dec.feed(&leftover);
        }
        let mut buf = vec![0u8; 8192];

        // Main event loop — select between inbound reads and outbound sends
        loop {
            tokio::select! {
                // Inbound: read from the network
                result = stream.read(&mut buf) => {
                    let n = match result {
                        Ok(0) => {
                            info!("peer {id:?} closed connection");
                            peer.handle(PeerEvent::RemoteClosed);
                            break;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            warn!("peer {id:?} read error: {e}");
                            peer.handle(PeerEvent::Error(e.to_string()));
                            break;
                        }
                    };

                    if dec.feed(&buf[..n]).is_err() {
                        warn!("peer {id:?} buffer overflow — disconnecting");
                        break;
                    }

                    loop {
                        match dec.drain_messages() {
                            Err(e) => {
                                warn!("peer {id:?} frame error: {e}");
                                peer.handle(PeerEvent::Error(e.to_string()));
                                break;
                            }
                            Ok(msgs) => {
                                if msgs.is_empty() { break; }
                                for msg in msgs {
                                    let msg_type = msg.msg_type;
                                    let rm_t0 = std::time::Instant::now();
                                    let event = self.route_message(&peer, msg).await;
                                    let rm_ms = rm_t0.elapsed().as_millis();
                                    if rm_ms > 100 {
                                        warn!(
                                            "SLOW route_message: {:?} from {:?} took {}ms",
                                            msg_type, peer.id, rm_ms,
                                        );
                                    }
                                    let action = peer.handle(event);
                                    if let Err(e) = self.execute_action(&mut stream, &mut peer, action, &session_hash).await {
                                        warn!("peer {id:?} action error: {e}");
                                    }
                                }
                            }
                        }
                        if dec.buffered_bytes() < HEADER_SIZE { break; }
                    }
                }

                // Outbound: relay messages from the broadcast channel
                Some(msg) = outbound_rx.recv() => {
                    let wire = if use_compression { msg.encode_compressed() } else { msg.encode() };
                    if let Err(e) = stream.write_all(&wire).await {
                        warn!("peer {id:?} write error: {e}");
                        break;
                    }
                }
            }

            if peer.state.is_closed() { break; }
        }

        // Deregister peer
        {
            let mut s = self.state.write().await;
            s.peers.remove(&id);
            s.peer_txs.remove(&id);
            s.peer_addrs.remove(&id);
            s.peer_latency.remove(&id);
            s.peer_ping_sent.remove(&id);
            s.sync_peer_cooldown.remove(&id);
            s.peer_sync_useful.remove(&id);
            s.implausible_validation_state.remove(&id);
            s.peer_direction.remove(&id);
            s.peer_squelch.remove(&id);
            s.connected_addrs.remove(&addr);
            // Cooldown: don't re-dial for 130s — except localhost (cluster peer, always reconnect)
            if !addr.ip().is_loopback() {
                s.peer_cooldowns.insert(addr, std::time::Instant::now() + std::time::Duration::from_secs(130));
            }
        }
        info!("peer {id:?} ({addr}) disconnected{}", if addr.ip().is_loopback() { "" } else { " — cooldown 130s" });
    }

    // ── Handshake helpers ─────────────────────────────────────────────────────

    /// Perform the raw HTTP upgrade exchange.
    ///
    /// **Outbound**: sends the GET request, then reads until the 101 response.
    /// **Inbound**: reads until the GET request; the 101 is sent afterwards by
    ///   `execute_action(SendHandshakeResponse)` so the state machine fires it.
    ///
    /// Returns `(HandshakeInfo, leftover_bytes)`.  Leftover bytes are any data
    /// that arrived after the `\r\n\r\n` — pre-feed these into FrameDecoder.
    async fn perform_handshake<S>(
        &self,
        stream:       &mut S,
        session_hash: &[u8; 32],
        dir:          Direction,
    ) -> anyhow::Result<(crate::network::handshake::HandshakeInfo, Vec<u8>)>
    where S: AsyncReadExt + AsyncWriteExt + Unpin + Send {
        match dir {
            Direction::Outbound => {
                // Send HTTP GET upgrade request with rippled-compatible headers
                let pubkey = self.node_key.public_key_bytes();
                let sig    = self.node_key.sign_digest(session_hash);
                let (ledger_hash, parent_hash) = {
                    let state = self.state.read().await;
                    let lh = state.ctx.ledger_hash.clone();
                    let ph = hex::encode_upper(state.ctx.ledger_header.parent_hash);
                    (lh, ph)
                };
                let req = crate::network::handshake::build_request(
                    &pubkey, &sig, self.config.network_id, &ledger_hash, &parent_hash,
                );
                stream.write_all(req.as_bytes()).await?;

                // Read until the complete 101 response
                let (raw, leftover) = read_http_headers(stream).await?;
                match crate::network::handshake::parse_response(&raw) {
                    Ok(Some((info, _))) => Ok((info, leftover)),
                    Ok(None) => anyhow::bail!("incomplete handshake response"),
                    Err(e) => {
                        // On 503, leftover contains the JSON body with peer-ips
                        let body = String::from_utf8_lossy(&leftover);
                        anyhow::bail!("{e} body={body}")
                    }
                }
            }
            Direction::Inbound => {
                // Read until the complete GET request
                let (raw, leftover) = read_http_headers(stream).await?;
                let info = match crate::network::handshake::parse_request(&raw)? {
                    Some((info, _)) => info,
                    None            => anyhow::bail!("incomplete handshake request"),
                };
                // The 101 response is sent by execute_action(SendHandshakeResponse)
                Ok((info, leftover))
            }
        }
    }

    /// Map an incoming RTXP message to a `PeerEvent`.
    ///
    /// Side-effects: consensus messages are relayed to other peers and
    /// processed locally (proposals → consensus round, validations → quorum).
    async fn route_message(&self, peer: &Peer, msg: RtxpMessage) -> PeerEvent {
        use crate::network::relay;

        // Debug: log non-common message types
        match msg.msg_type {
            MessageType::Ping | MessageType::Validation | MessageType::Transaction
            | MessageType::GetLedger | MessageType::LedgerData
            | MessageType::ProposeLedger => {}
            _ => {
                trace!("msg type {:?} from {:?} ({} bytes)", msg.msg_type, peer.id, msg.payload.len());
            }
        }

        match msg.msg_type {
            MessageType::Ping => {
                if let Some((is_ping, seq)) = relay::decode_ping(&msg.payload) {
                    if is_ping {
                        // Reply with pong
                        let pong = relay::encode_pong(seq);
                        if let Some(tx) = self.state.read().await.peer_txs.get(&peer.id) {
                            let _ = tx.try_send(pong);
                        }
                    } else {
                        // Pong received — measure latency
                        let mut state = self.state.write().await;
                        if let Some((sent_seq, sent_at)) = state.peer_ping_sent.remove(&peer.id) {
                            if sent_seq == seq {
                                let latency = sent_at.elapsed().as_millis() as u32;
                                state.peer_latency.insert(peer.id, latency);
                                // Auto-bench slow peers immediately — frees connection slot
                                if latency > 10000 {
                                    // Very slow — 20 min bench
                                    let expires = std::time::Instant::now() + std::time::Duration::from_secs(1200);
                                    state.sync_peer_cooldown.insert(peer.id, expires);
                                    self.debug_log(&format!("LATENCY+BENCHED-SLOW: peer {:?} = {}ms (>10s, 20min)", peer.id, latency));
                                } else if latency > 5000 {
                                    // Moderately slow — 5 min bench
                                    let expires = std::time::Instant::now() + std::time::Duration::from_secs(300);
                                    state.sync_peer_cooldown.insert(peer.id, expires);
                                    self.debug_log(&format!("LATENCY+BENCHED-MODERATE: peer {:?} = {}ms (>5s, 5min)", peer.id, latency));
                                } else {
                                    self.debug_log(&format!("LATENCY: peer {:?} = {}ms", peer.id, latency));
                                }
                            }
                        }
                    }
                }
                PeerEvent::MessageReceived(MessageType::Ping, msg.payload)
            }
            MessageType::StatusChange => {
                // Parse TMStatusChange to extract peer's ledger range
                if let Ok(sc) = <crate::proto::TmStatusChange as ProstMessage>::decode(msg.payload.as_slice()) {
                    if let (Some(first), Some(last)) = (sc.first_seq, sc.last_seq) {
                        if first > 0 && last >= first {
                            let mut state = self.state.write().await;
                            let old = state.peer_ledger_range.insert(peer.id, (first, last));
                            if old.is_none() {
                                let span = last - first;
                                info!(
                                    "peer {:?} ledger range: {}-{} (span={})",
                                    peer.id, first, last, span,
                                );
                            }
                        }
                    }
                }
                PeerEvent::MessageReceived(MessageType::StatusChange, msg.payload)
            }
            MessageType::Transaction => {
                // Decode TMTransaction, snapshot data, persist off-runtime
                if let Ok(pb) = <crate::proto::TmTransaction as ProstMessage>::decode(msg.payload.as_slice()) {
                    let blob = pb.raw_transaction.clone();
                    let hash = crate::crypto::sha512_first_half(&blob);
                    let ledger_seq = {
                        self.state.read().await.ctx.ledger_seq
                    };

                    // Persist to storage off the async runtime
                    if let Some(ref store) = self.storage {
                        let store2 = store.clone();
                        let blob2 = blob.clone();
                        tokio::task::spawn_blocking(move || {
                            let rec = crate::ledger::history::TxRecord {
                                blob: blob2,
                                meta: vec![],
                                hash,
                                ledger_seq,
                                tx_index: 0,
                                result: "pending".into(),
                            };
                            let _ = store2.save_transaction(&rec);
                        });
                    }

                    // Add to in-memory history — brief write lock, no I/O
                    {
                        let state = self.state.read().await;
                        if let Ok(_parsed) = crate::transaction::parse_blob(&blob) {
                            state.ctx.history.write().unwrap_or_else(|e| e.into_inner()).insert_tx(crate::ledger::history::TxRecord {
                                blob,
                                meta: vec![],
                                hash,
                                ledger_seq,
                                tx_index: 0,
                                result: "pending".into(),
                            });
                        }
                    }
                }

                if !self.message_is_new(MessageType::Transaction, &msg.payload) {
                    return PeerEvent::MessageReceived(MessageType::Transaction, msg.payload);
                }
                let relay_msg = RtxpMessage::new(MessageType::Transaction, msg.payload.clone());
                self.state.read().await.broadcast(&relay_msg, Some(peer.id));
                let _ = self.ws_events.send(crate::rpc::ws::WsEvent::PeerMessage {
                    msg_type: "transaction".into(),
                    detail: format!("from {:?}", peer.id),
                });
                PeerEvent::MessageReceived(MessageType::Transaction, msg.payload)
            }
            MessageType::ProposeLedger => {
                if !self.message_is_new(MessageType::ProposeLedger, &msg.payload) {
                    return PeerEvent::MessageReceived(MessageType::ProposeLedger, msg.payload);
                }
                if let Some(prop) = relay::decode_proposal(&msg.payload) {
                    debug!(
                        "received proposal seq={} from peer {:?}",
                        prop.prop_seq, peer.id
                    );
                    // Feed into consensus round
                    {
                        let mut state = self.state.write().await;
                        let next_seq = state.ctx.ledger_seq + 1;
                        let staged_key = hex::encode(&prop.node_pubkey);
                        if prop.prop_seq == crate::consensus::round::SEQ_LEAVE {
                            if let Some(round) = state.current_round.as_mut() {
                                let node_id = hex::encode(&prop.node_pubkey);
                                round.peer_bowed_out(&node_id);
                                info!("consensus: peer {} bowed out", &node_id[..16]);
                            } else {
                                info!("consensus: ignoring bow-out outside an active round");
                            }
                        } else if state.current_round.as_ref().map(|round| round.ledger_seq) == Some(prop.ledger_seq) {
                            if let Some(round) = state.current_round.as_mut() {
                                let trusted = round.add_proposal(prop.clone());
                                if trusted {
                                    round.add_close_time_vote(prop.close_time as u64);
                                }
                            }
                        } else if prop.ledger_seq == next_seq {
                            match state.staged_proposals.get(&staged_key) {
                                Some(existing) if existing.prop_seq >= prop.prop_seq => {}
                                _ => {
                                    state.staged_proposals.insert(staged_key, prop.clone());
                                }
                            }
                        }
                    }
                    let relay_msg = relay::encode_proposal(&prop);
                    self.state.read().await.broadcast(&relay_msg, Some(peer.id));
                    let _ = self.ws_events.send(crate::rpc::ws::WsEvent::PeerMessage {
                        msg_type: "proposal".into(),
                        detail: format!("seq={} from {:?}", prop.prop_seq, peer.id),
                    });
                }
                PeerEvent::MessageReceived(MessageType::ProposeLedger, msg.payload)
            }
            MessageType::LedgerData => {
                // Handle TMGetLedger responses — parse the ledger header from
                // liBASE responses and update our displayed ledger info.
                if let Some(ld) = relay::decode_ledger_data(&msg.payload) {
                    debug!(
                        "LedgerData response: type={} seq={} nodes={} error={:?} from {:?}",
                        ld.r#type, ld.ledger_seq, ld.nodes.len(), ld.error, peer.id,
                    );
                    if ld.r#type == crate::proto::TmLedgerInfoType::LiBase as i32 {
                        // liBASE response — first node contains the raw header
                        if let Some(node) = ld.nodes.first() {
                            if let Some(header) = crate::sync::parse_ledger_header_from_base(&node.nodedata) {
                                info!(
                                    "received ledger header from peer {:?}: seq={} hash={}",
                                    peer.id,
                                    header.sequence,
                                    &hex::encode_upper(header.hash)[..16],
                                );
                                // Route to InboundLedger BEFORE acquiring state write lock
                                // to avoid ABBA deadlock with the follower (which holds
                                // inbound_ledgers then acquires state.write).
                                {
                                    let mut guard = self.inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                                    guard.got_header(&header.hash, header.clone());
                                }
                                // Brief write lock for state updates ONLY — no disk I/O inside.
                                let is_current = {
                                    let mut state = self.state.write().await;
                                    if header.sequence >= state.ctx.ledger_seq {
                                        state.ctx.ledger_header = header.clone();
                                        state.ctx.ledger_seq = header.sequence;
                                        state.ctx.ledger_hash = hex::encode_upper(header.hash);
                                        state.ctx.history.write().unwrap_or_else(|e| e.into_inner()).insert_ledger(header.clone(), vec![]);
                                        true
                                    } else {
                                        false
                                    }
                                }; // Write lock released — all disk I/O below is lock-free.

                                if is_current {
                                    // Persist to storage off the async runtime
                                    if let Some(ref store) = self.storage {
                                        let store2 = store.clone();
                                        let header2 = header.clone();
                                        let online_delete = self.config.online_delete;
                                        tokio::task::spawn_blocking(move || {
                                            let _ = store2.save_ledger(&header2, &[]);
                                            let _ = store2.save_meta(
                                                header2.sequence,
                                                &hex::encode_upper(header2.hash),
                                                &header2,
                                            );
                                            let _ = store2.flush();
                                            if header2.sequence % 256 == 0 {
                                                if let Some(keep) = online_delete.filter(|k| *k > 0) {
                                                    if header2.sequence % keep == 0 {
                                                        match store2.prune_history(header2.sequence, keep) {
                                                            Ok(n) if n > 0 => tracing::info!("pruned {n} old ledger headers (keeping last {keep})"),
                                                            _ => {}
                                                        }
                                                        let _before_seq = header2.sequence.saturating_sub(keep);
                                                    }
                                                }
                                            }
                                        });
                                    }

                                    // ── State sync trigger ──
                                    // try_lock to avoid blocking async runtime when batch processor holds lock
                                    let (already_syncing, has_syncer) = {
                                        match self.sync.try_lock() {
                                            Ok(guard) => (
                                                guard.as_ref().map_or(false, |s| s.active()),
                                                guard.is_some(),
                                            ),
                                            Err(_) => (true, true), // assume busy = syncing
                                        }
                                    };
                                    let (sync_done, open_peers, sync_in_progress) = {
                                        let state = self.state.read().await;
                                        (state.sync_done, state.peer_count(), state.sync_in_progress)
                                    };
                                    if !sync_done && self.storage.is_some() && open_peers >= 1 {
                                        // Retarget abandoned syncer: keep the in-memory SHAMap
                                        // (inner nodes are 99.99% shared across ledgers) but
                                        // update the target. The root-feed below (line ~3790)
                                        // will install the new root into the tree.
                                        //
                                        // Critical: do NOT set already_syncing — the retargeted
                                        // syncer needs the new state root from this liBASE.
                                        // Without it, get_missing walks stale branches.
                                        if has_syncer && !already_syncing {
                                            if let Ok(mut guard) = self.sync.try_lock() {
                                                if let Some(ref s) = *guard {
                                                    if !s.active() {
                                                        info!(
                                                            "retargeting abandoned syncer to ledger {} (keeping {} inner + {} leaf in memory)",
                                                            header.sequence, s.inner_count(), s.leaf_count(),
                                                        );
                                                        let syncer = guard.as_mut().unwrap();
                                                        // In ltCLOSED mode, try to rebind before retargeting.
                                                        // If this header's account_hash matches our tree root,
                                                        // we've completed the stale-target rollover.
                                                        if syncer.offer_validated_header(&header) {
                                                            info!(
                                                                "ltCLOSED rollover: syncer rebound to ledger {} — checking completion",
                                                                header.sequence,
                                                            );
                                                        } else {
                                                            syncer.retarget(
                                                                header.sequence,
                                                                header.hash,
                                                                header.account_hash,
                                                                header.clone(),
                                                            );
                                                        }
                                                        // Mirror the active sync mode in the queue-first gate.
                                                        // ltCLOSED rollover uses a zero target hash until the
                                                        // syncer rebinds to a validated header.
                                                        let h8 = u64::from_be_bytes(syncer.ledger_hash()[..8].try_into().unwrap());
                                                        self.sync_target_hash8.store(h8, std::sync::atomic::Ordering::Relaxed);
                                                    }
                                                }
                                            }
                                        }
                                        if has_syncer || already_syncing || sync_in_progress {
                                            // Frozen target: do NOT touch syncer during active sync.
                                            // rippled uses const hash_ — never changes mid-sync.
                                        } else {
                                            // Create new syncer — all sync work happens BEFORE
                                            // any state.write() to prevent deadlock.
                                            info!(
                                                "starting state sync for ledger {} account_hash={} ({} peers ready)",
                                                header.sequence,
                                                &hex::encode_upper(header.account_hash)[..16],
                                                open_peers,
                                            );
                                            let mut syncer = crate::sync_coordinator::SyncCoordinator::new(
                                                header.sequence,
                                                header.hash,
                                                header.account_hash,
                                                self.nudb_backend.clone(),
                                                header.clone(),
                                            );
                                            // Import persisted inner nodes from previous sync.
                                            // The tree structure is 99.99% stable across ledgers
                                            // (only changed branches differ). Loading inner nodes
                                            // lets the tree walk skip already-downloaded subtrees
                                            // instead of re-walking the entire tree from scratch.
                                            // The walk loads inner nodes on-demand via get_node_or_load().
                                            // No bulk import needed — matches rippled's approach
                                            // where nodes are fetched from NodeStore on demand.
                                            if let Some(ref store) = self.storage {
                                                if let Some(lc) = store.get_meta("leaf_count") {
                                                    if lc.len() >= 8 {
                                                        syncer.set_leaf_count(u64::from_le_bytes(lc[..8].try_into().unwrap()) as usize);
                                                    }
                                                }
                                            }
                                            // Skip blocking startup rebuild — the timer's
                                            // check_local will handle it incrementally.
                                            // Doing it here blocks the async runtime.
                                            let sync_completed_from_disk = false;
                                            if sync_completed_from_disk {
                                                info!(
                                                    "state sync fully satisfied from local storage for ledger {}",
                                                    header.sequence,
                                                );
                                                syncer.set_active(false);
                                            }
                                            // Install syncer with try_lock — NEVER block async
                                            // runtime with a blocking lock. If try_lock fails,
                                            // the batch processor holds the lock and the next
                                            // liBASE will retry.
                                            let installed = {
                                                let h8 = u64::from_be_bytes(header.hash[..8].try_into().unwrap());
                                                self.sync_target_hash8.store(h8, std::sync::atomic::Ordering::Relaxed);
                                                if let Ok(mut guard) = self.sync.try_lock() {
                                                    *guard = Some(syncer);
                                                    true
                                                } else {
                                                    warn!("sync lock busy during syncer install — will retry on next liBASE");
                                                    false
                                                }
                                            };
                                            // State writes AFTER sync lock is released — never nested.
                                            if installed {
                                                let mut state = self.state.write().await;
                                                state.sync_in_progress = true;
                                                if sync_completed_from_disk {
                                                    state.sync_done = true;
                                                    state.sync_in_progress = false;
                                                }
                                            }
                                        }

                                        // Feed state root from liBASE and build first request.
                                        // Skip when already syncing (frozen target — don't touch).
                                        let have_syncer_now = {
                                            self.sync.try_lock().ok().map_or(false, |g| g.is_some())
                                        };
                                        if !already_syncing && have_syncer_now {
                                        let (progress, first_req) = {
                                            let Ok(mut guard) = self.sync.try_lock() else {
                                                // Lock busy — skip bootstrap, next liBASE will catch it
                                                return PeerEvent::MessageReceived(MessageType::LedgerData, msg.payload);
                                            };
                                            let Some(syncer) = guard.as_mut() else {
                                                warn!(
                                                    "state sync bootstrap skipped: syncer missing after startup path for ledger {}",
                                                    header.sequence,
                                                );
                                                return PeerEvent::MessageReceived(MessageType::LedgerData, msg.payload);
                                            };

                                            // Feed ONLY the state root (nodes[1]), NOT the tx root (nodes[2])
                                            let fake_ld = crate::proto::TmLedgerData {
                                                ledger_hash: ld.ledger_hash.clone(),
                                                ledger_seq: ld.ledger_seq,
                                                r#type: crate::proto::TmLedgerInfoType::LiAsNode as i32,
                                                nodes: if ld.nodes.len() > 1 {
                                                    vec![crate::proto::TmLedgerNode {
                                                        nodedata: ld.nodes[1].nodedata.clone(),
                                                        nodeid: ld.nodes[1].nodeid.clone(),
                                                    }]
                                                } else {
                                                    vec![]
                                                },
                                                request_cookie: None,
                                                error: None,
                                            };
                                            let progress = syncer.process_response(&fake_ld);
                                            let first_req = syncer.build_next_request(crate::sync::SyncRequestReason::Reply).first().cloned();
                                            (progress, first_req)
                                        };

                                        // Leaves written to NuDB by add_known_node.

                                        info!(
                                            "state sync bootstrap: {} inner + {} leaf",
                                            progress.total_inner, progress.total_leaf,
                                        );

                                        if let Some(req) = first_req {
                                            let state = self.state.read().await;
                                            // Send to the responding peer first
                                            if let Some(tx) = state.peer_txs.get(&peer.id) {
                                                let _ = tx.try_send(req.clone());
                                            }
                                            // Send same request to 1-2 more peers for redundancy
                                            let mut extra_sent = 0;
                                            for _ in 0..2 {
                                                if let Some(pid) = self.next_sync_peer(&state) {
                                                    if pid != peer.id {
                                                        if let Some(tx) = state.peer_txs.get(&pid) {
                                                            let _ = tx.try_send(req.clone());
                                                            extra_sent += 1;
                                                        }
                                                    }
                                                }
                                            }
                                            if extra_sent > 0 {
                                                info!("sent redundant initial request to {extra_sent} additional peers");
                                            }
                                        }

                                        let _ = self.ws_events.send(crate::rpc::ws::WsEvent::PeerMessage {
                                            msg_type: "sync".into(),
                                            detail: format!("state sync started for ledger {}", header.sequence),
                                        });
                                        } // end if !already_syncing
                                        else if !already_syncing && sync_in_progress {
                                            warn!(
                                                "state sync flagged in progress but no syncer exists for ledger {}; clearing stale sync_in_progress",
                                                header.sequence,
                                            );
                                            let mut state = self.state.write().await;
                                            state.sync_in_progress = false;
                                        }
                                    } else {
                                        // Base snapshot sync is complete (or disabled), so it is
                                        // safe to request and apply the live TX tree for this ledger.
                                        let cookie = crate::sync::next_cookie();
                                        let tx_req = relay::encode_get_ledger_txs(cookie);
                                        let state = self.state.read().await;
                                        if let Some(tx) = state.peer_txs.get(&peer.id) {
                                            let _ = tx.try_send(tx_req);
                                        }

                                        // Sync already active: a fresh liBASE means a peer just
                                        // closed a ledger — their ltCLOSED state is fresh RIGHT
                                        // NOW.  Fire off a new batch immediately.
                                        //
                                        // If pending is empty and in_flight is 0, a pass just ended
                                        // and we need to feed the new root to start the next pass.
                                        let fresh_req = if let Ok(mut guard) = self.sync.try_lock() {
                                            if let Some(ref mut syncer) = *guard {
                                                if syncer.active() && syncer.pending_count() == 0 && syncer.peer.last_response.elapsed().as_secs() > 2 {
                                                    syncer.peer.start_new_pass();
                                                    // Extract root children directly, bypass bloom filter
                                                    if ld.nodes.len() > 1 {
                                                        let root_data = &ld.nodes[1].nodedata;
                                                        let hash_start = if root_data.len() == 513 { 1 } else if root_data.len() == 512 { 0 } else { 4 };
                                                        if root_data.len() >= hash_start + 512 {
                                                            let mut children = Vec::new();
                                                            for i in 0..16u8 {
                                                                let off = hash_start + (i as usize) * 32;
                                                                let child = &root_data[off..off+32];
                                                                if child.iter().any(|&b| b != 0) {
                                                                    // Build 33-byte SHAMapNodeID: path + depth
                                                                    let mut id = vec![0u8; 32];
                                                                    id[0] = i << 4; // nibble 0 = branch i
                                                                    id.push(1); // depth 1
                                                                    children.push(id);
                                                                }
                                                            }
                                                            let count = children.len();
                                                            // force_pending not needed — SHAMap tree walk handles discovery
                                                            let _ = children;
                                                            info!(
                                                                "starting pass {} with {} children from ledger {}",
                                                                syncer.pass_number(), count, header.sequence,
                                                            );
                                                        }
                                                    }
                                                    syncer.build_next_request(crate::sync::SyncRequestReason::Reply).first().cloned()
                                                } else if syncer.active() && syncer.pending_count() > 0 {
                                                    syncer.build_next_request(crate::sync::SyncRequestReason::Reply).first().cloned()
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        } else {
                                            None // Lock busy — skip
                                        };
                                        if let Some(req) = fresh_req {
                                            let (primary_tx, secondary_tx) = {
                                                let state = self.state.read().await;
                                                let primary = state.peer_txs.get(&peer.id).cloned();
                                                let secondary = self.next_sync_peer(&state)
                                                    .filter(|pid| *pid != peer.id)
                                                    .and_then(|pid| state.peer_txs.get(&pid).cloned());
                                                (primary, secondary)
                                            };
                                            let mut delivered = false;
                                            if let Some(tx) = primary_tx {
                                                if tx.send(req.clone()).await.is_ok() {
                                                    delivered = true;
                                                }
                                            }
                                            if !delivered {
                                                if let Some(tx) = secondary_tx {
                                                    let _ = tx.send(req).await;
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                warn!(
                                    "failed to parse ledger header from peer {:?} ({} bytes)",
                                    peer.id,
                                    node.nodedata.len(),
                                );
                            }
                        }
                    } else if ld.r#type == crate::proto::TmLedgerInfoType::LiAsNode as i32 {
                        // Route to diff sync channel if in follow mode,
                        // otherwise to initial sync batch processor.
                        let sync_done = {
                            let state = self.state.read().await;
                            state.sync_done
                        };
                        if sync_done {
                            if self.diff_sync_tx.send(ld.clone()).await.is_err() {
                                warn!("diff sync response channel closed");
                            }
                        } else {
                            // Queue-first intake: cheap lock-free gate, validate in batch processor.
                            // This prevents valid responses from being dropped when the sync lock is busy.
                            let target_h8 = self.sync_target_hash8.load(std::sync::atomic::Ordering::Relaxed);
                            let accepted_by_gate = sync_gate_accepts_response(
                                &self.sync,
                                target_h8,
                                Some(&ld.ledger_hash),
                                None,
                                false,
                            );
                            if accepted_by_gate {
                                {
                                    let mut q = self.sync_data_queue.lock().unwrap_or_else(|e| e.into_inner());
                                    q.push((peer.id, ld.clone()));
                                }
                                self.sync_data_notify.notify_one();
                            } else {
                                debug!(
                                    "dropping liAS_NODE at gate: accepted={} cookie={:?} hash={}",
                                    accepted_by_gate, ld.request_cookie,
                                    hex::encode_upper(&ld.ledger_hash[..std::cmp::min(8, ld.ledger_hash.len())]),
                                );
                            }
                        }
                        // Also route to follower's prefetch channel for lazy state fetch
                        {
                            let state = self.state.read().await;
                            if let Some(ref fs) = state.follower_state {
                                let _ = fs.prefetch_tx.try_send(ld.clone());
                            }
                        }
                    } else if ld.r#type == crate::proto::TmLedgerInfoType::LiTxNode as i32 {
                        // Route to InboundLedger by hash — drops if no acquisition exists
                        {
                            let hash: [u8; 32] = if ld.ledger_hash.len() == 32 {
                                let mut h = [0u8; 32];
                                h.copy_from_slice(&ld.ledger_hash);
                                h
                            } else {
                                [0u8; 32]
                            };
                            let mut guard = self.inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                            let routed = guard.got_tx_data(&hash, &ld.nodes);
                            if !routed && !ld.nodes.is_empty() {
                                warn!(
                                    "liTX_NODE dropped: no acquisition for hash={} seq={} nodes={} pending_acquisitions={}",
                                    hex::encode_upper(&hash[..8]), ld.ledger_seq, ld.nodes.len(), guard.len(),
                                );
                            }
                        }
                        // ── liTX_NODE response — apply transactions to state ──
                        // Collect leaf node data from the TX SHAMap tree.
                        // TX tree leaves do NOT have the MLN\0 prefix — they are
                        // raw serialized transaction+metadata pairs.
                        let mut tx_blobs: Vec<Vec<u8>> = Vec::new();
                        for node in &ld.nodes {
                            let data = &node.nodedata;
                            if data.len() < 10 { continue; }

                            // Detect inner vs leaf:
                            // - Inner: MIN\0 prefix (4 bytes) + 512 bytes, or 512/513 bytes (wire)
                            // - Leaf in TX tree: raw STObject (starts with field headers)
                            let is_inner = (data.len() == 512 || data.len() == 513)
                                || (data.len() >= 516
                                    && data[0] == 0x4D && data[1] == 0x49
                                    && data[2] == 0x4E && data[3] == 0x00);

                            if is_inner {
                                continue; // skip inner nodes
                            }

                            // TX SHAMap wire format: the LAST byte is the wire type:
                            //   0x00 = raw transaction (no metadata)
                            //   0x04 = transaction + metadata concatenated
                            // Strip the wire type byte, then try to parse.
                            if data.len() < 10 { continue; }

                            let wire_type = data[data.len() - 1];
                            let payload = &data[..data.len() - 1]; // strip wire type byte

                            // For type 0x04 (tx+metadata), both are STObjects concatenated.
                            // parse_blob will parse the transaction and stop when it hits
                            // metadata fields it doesn't recognize — that's fine, we just
                            // need the transaction portion parsed.
                            // For type 0x00 (raw tx), payload is the full transaction.
                            if wire_type == 0x04 && payload.len() > 32 {
                                // Transaction + metadata + 32-byte key
                                // Strip last 32 bytes (key)
                                let item_data = &payload[..payload.len() - 32];
                                // item_data = VL(tx_blob) + tx_blob + VL(meta_blob) + meta_blob
                                // Decode VL to extract just the transaction
                                {
                                    let (tx_len, vl_bytes) = crate::transaction::serialize::decode_length(item_data);
                                    let tx_start = vl_bytes;
                                    let tx_end = tx_start + tx_len;
                                    if tx_end <= item_data.len() {
                                        tx_blobs.push(item_data[tx_start..tx_end].to_vec());
                                    }
                                }
                            } else if wire_type == 0x00 {
                                // Raw transaction, no metadata, no key
                                tx_blobs.push(payload.to_vec());
                            }
                            // wire_type 0x01 = account state, 0x03 = inner node — skip
                        }

                        let (ledger_seq, sync_complete) = {
                            let state = self.state.read().await;
                            (state.ctx.ledger_seq, state.sync_done)
                        };

                        if sync_complete {
                            // ── Post-sync: parse/store/history only — NO ledger_state mutation ──
                            // The follower is the authoritative state writer after sync.
                            // Matching rippled: incoming liTX_NODE data is buffered/stored,
                            // never applied directly to state.
                            let mut failed_parse = 0usize;
                            let mut parsed_count = 0usize;
                            let mut tx_records: Vec<crate::ledger::history::TxRecord> = Vec::new();

                            for tx_blob in &tx_blobs {
                                match crate::transaction::parse_blob(tx_blob) {
                                    Ok(_parsed) => {
                                        parsed_count += 1;
                                        let hash = crate::crypto::sha512_first_half(tx_blob);
                                        tx_records.push(crate::ledger::history::TxRecord {
                                            blob: tx_blob.clone(),
                                            meta: vec![],
                                            hash,
                                            ledger_seq,
                                            tx_index: 0,
                                            result: "pending".to_string(),
                                        });
                                    }
                                    Err(e) => {
                                        failed_parse += 1;
                                        debug!("liTX_NODE parse fail seq={}: {}", ledger_seq, e);
                                    }
                                }
                            }

                            // Save raw tx blobs to storage
                            if !tx_records.is_empty() {
                                if let Some(ref store) = self.storage {
                                    for rec in &tx_records {
                                        let _ = store.save_transaction(rec);
                                    }
                                }
                            }

                            // Insert into history for RPC lookups
                            {
                                let state = self.state.read().await;
                                let mut history = state.ctx.history.write().unwrap_or_else(|e| e.into_inner());
                                for rec in tx_records {
                                    history.insert_tx(rec);
                                }
                            }

                            let total = tx_blobs.len();
                            info!(
                                "ledger {}: buffered {}/{} txs (follower mode, no state apply) parse_fail={}",
                                ledger_seq, parsed_count, total, failed_parse,
                            );
                        } else {
                            // ── Pre-sync: apply transactions directly to state ──
                            // During initial sync the follower isn't active yet,
                            // so liTX_NODE is the only writer.
                            let (close_time, ls_arc) = {
                                let state = self.state.read().await;
                                (state.ctx.ledger_header.close_time, state.ctx.ledger_state.clone())
                            };

                            let ls_arc2 = ls_arc.clone();
                            let tx_blobs_owned = tx_blobs.clone();
                            let litx_spawn_t0 = std::time::Instant::now();
                            let blocking_result = tokio::task::spawn_blocking(move || {
                                let mut applied_b = 0usize;
                                let mut failed_apply_b = 0usize;
                                let mut failed_parse_b = 0usize;
                                let mut records: Vec<crate::ledger::history::TxRecord> = Vec::new();

                                let mut ls = ls_arc2.lock().unwrap_or_else(|e| e.into_inner());
                                let pre_account_count = ls.account_count();

                                for tx_blob in &tx_blobs_owned {
                                    match crate::transaction::parse_blob(tx_blob) {
                                        Ok(parsed) => {
                                            let node_ctx = crate::ledger::apply::TxContext {
                                                parent_hash: [0u8; 32],
                                                ledger_seq: 0,
                                                close_time,
                                                validated_result: None,
                                                validated_delivered_amount: None,
                                            };
                                            let result = crate::ledger::apply::apply_tx(
                                                &mut ls,
                                                &parsed,
                                                &node_ctx,
                                            );

                                            let hash = crate::crypto::sha512_first_half(tx_blob);
                                            let result_str = match &result {
                                                crate::ledger::apply::ApplyResult::Success => {
                                                    applied_b += 1;
                                                    "tesSUCCESS".to_string()
                                                }
                                                crate::ledger::apply::ApplyResult::ClaimedCost(c) => {
                                                    failed_apply_b += 1;
                                                    c.to_string()
                                                }
                                            };

                                            records.push(crate::ledger::history::TxRecord {
                                                blob: tx_blob.clone(),
                                                meta: vec![],
                                                hash,
                                                ledger_seq,
                                                tx_index: 0,
                                                result: result_str,
                                            });
                                        }
                                        Err(_e) => {
                                            failed_parse_b += 1;
                                        }
                                    }
                                }

                                let new_accts = ls.account_count().saturating_sub(pre_account_count);

                                // Take dirty state while we hold the mutex
                                if applied_b > 0 || failed_apply_b > 0 {
                                    let _ = ls.take_dirty();
                                }

                                (applied_b, failed_apply_b, failed_parse_b, new_accts, records)
                            }).await.unwrap_or((0, 0, 0, 0, Vec::new()));
                            let litx_spawn_ms = litx_spawn_t0.elapsed().as_millis();
                            if litx_spawn_ms > 50 {
                                info!("liTX_NODE spawn_blocking total={}ms seq={}", litx_spawn_ms, ledger_seq);
                            }

                            let applied = blocking_result.0;
                            let failed_apply = blocking_result.1;
                            let failed_parse = blocking_result.2;
                            let new_accounts = blocking_result.3;
                            let tx_records_to_insert = blocking_result.4;

                            // Storage I/O — outside ALL locks
                            if !tx_records_to_insert.is_empty() {
                                if let Some(ref store) = self.storage {
                                    for rec in &tx_records_to_insert {
                                        let _ = store.save_transaction(rec);
                                    }
                                }
                            }

                            // Brief write lock for history insert only
                            {
                                let state = self.state.read().await;
                                let mut history = state.ctx.history.write().unwrap_or_else(|e| e.into_inner());
                                for rec in tx_records_to_insert {
                                    history.insert_tx(rec);
                                }
                            }

                            let total = tx_blobs.len();
                            info!(
                                "ledger {}: applied {}/{} txs ({} new accounts) parse_fail={} apply_fail={}",
                                ledger_seq, applied, total, new_accounts, failed_parse, failed_apply,
                            );
                        }
                    } else {
                        debug!(
                            "received LedgerData type={} seq={} nodes={} from peer {:?}",
                            ld.r#type, ld.ledger_seq, ld.nodes.len(), peer.id,
                        );
                    }
                }
                PeerEvent::MessageReceived(MessageType::LedgerData, msg.payload)
            }
            MessageType::Validation => {
                if let Some(val) = relay::decode_validation(&msg.payload) {
                    debug!(
                        "received validation ledger_seq={} from peer {:?}",
                        val.ledger_seq, peer.id
                    );

                    // Update state + consensus in ONE brief write lock.
                    // Only advance ledger_seq from TRUSTED validations (UNL members),
                    // matching rippled's NetworkOPs::checkLastValidatedLedger.
                    // Untrusted validations are still added to the round for counting
                    // but don't advance our notion of "current validated ledger."
                    let mut should_request_base = false;
                    let mut should_register_acquisition = false;
                    {
                        let mut state = self.state.write().await;

                        let peer_range_ok = state.peer_ledger_range.get(&peer.id)
                            .map(|(first, last)| {
                                let lower = first.saturating_sub(1024);
                                let upper = last.saturating_add(1024);
                                val.ledger_seq >= lower && val.ledger_seq <= upper
                            })
                            .unwrap_or(true);
                        let follower_anchor = state.follower_state.as_ref()
                            .map(|fs| fs.current_seq.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(0);
                        let history_anchor = state.ctx.history.read().unwrap_or_else(|e| e.into_inner()).latest_ledger()
                            .map(|l| l.header.sequence)
                            .unwrap_or(0);
                        let peer_anchor = state.peer_ledger_range.values()
                            .map(|(_, last)| *last)
                            .max()
                            .unwrap_or(0);
                        let anchor = peer_anchor.max(follower_anchor).max(history_anchor);
                        let anchor_ok = if anchor > 0 {
                            val.ledger_seq >= anchor.saturating_sub(100_000)
                                && val.ledger_seq <= anchor.saturating_add(100_000)
                        } else {
                            true
                        };
                        let plausible = peer_range_ok && anchor_ok;
                        if !plausible {
                            let now = std::time::Instant::now();
                            let entry = state.implausible_validation_state
                                .entry(peer.id)
                                .or_insert((now, 0));
                            if now.duration_since(entry.0) > std::time::Duration::from_secs(30) {
                                *entry = (now, 1);
                            } else {
                                entry.0 = now;
                                entry.1 = entry.1.saturating_add(1);
                            }
                            let repeats = entry.1;
                            debug!(
                                "ignoring implausible validation seq={} from peer {:?} (peer_range_ok={} anchor={} follower={} history={} repeats={})",
                                val.ledger_seq, peer.id, peer_range_ok, anchor, follower_anchor, history_anchor, repeats,
                            );
                            // Global rate-limited summary (one info line per 30s)
                            {
                                static IMPLAUSIBLE_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                                static LAST_SUMMARY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                                let count = IMPLAUSIBLE_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                                let now_secs = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                let prev = LAST_SUMMARY.load(std::sync::atomic::Ordering::Relaxed);
                                if now_secs >= prev + 30 {
                                    LAST_SUMMARY.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                                    info!("suppressed {} implausible validations in last 30s", count);
                                    IMPLAUSIBLE_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                            if repeats >= 10 {
                                let expires = now + std::time::Duration::from_secs(600);
                                state.sync_peer_cooldown.insert(peer.id, expires);
                            }
                        } else {
                            state.implausible_validation_state.remove(&peer.id);
                        }

                        // Check trust via consensus round (UNL membership)
                        let is_trusted = if let Some(ref mut round) = state.current_round {
                            let t = round.add_validation(val.clone());
                            if t { info!("consensus: accepted trusted validation for ledger {}", val.ledger_seq); }
                            t && plausible
                        } else {
                            // No round active — accept all validations during
                            // initial sync when we don't have consensus yet.
                            // But still reject obviously implausible sequence numbers.
                            plausible
                        };

                        // Record every trusted validation hash for follower lookup
                        if is_trusted {
                            state.record_validated_hash(val.ledger_seq, val.ledger_hash);
                        }

                        // Only advance ledger_seq from trusted validations
                        if is_trusted && val.ledger_seq > state.ctx.ledger_seq {
                            state.ctx.ledger_seq = val.ledger_seq;
                            state.ctx.ledger_hash = hex::encode_upper(val.ledger_hash);

                            // Register acquisition for follower (always, even pre-sync)
                            should_register_acquisition = true;

                            // Only send liBASE+liTX_NODE requests after sync is done.
                            // During initial sync, this traffic competes with state sync
                            // for peer send queue capacity. rippled's processLedgerRequest
                            // silently drops requests when send_queue >= dropSendQueue.
                            if state.sync_done {
                                static LAST_BASE_REQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                                let now_secs = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                let prev = LAST_BASE_REQ.load(std::sync::atomic::Ordering::Relaxed);
                                if now_secs >= prev + 3 {
                                    LAST_BASE_REQ.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                                    should_request_base = true;
                                }
                            }
                        }
                    } // Write lock released

                    // Always register the acquisition — even when request sending
                    // is rate-limited. liTX_NODE responses from other peers' requests
                    // may arrive before the follower creates its own acquisition.
                    if should_register_acquisition {
                        let mut guard = self.inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                        guard.create(val.ledger_hash, val.ledger_seq);
                    }

                    // Rate-limited: send liBASE+liTX_NODE requests
                    if should_request_base {
                        info!(
                            "peer {:?} validated ledger {} — requesting header",
                            peer.id, val.ledger_seq,
                        );
                        let cookie = crate::sync::next_cookie();
                        let get_msg = relay::encode_get_ledger_base(&val.ledger_hash, cookie);
                        let sent = {
                            let state = self.state.read().await;
                            let mut sent = 0;
                            if let Some(tx) = state.peer_txs.get(&peer.id) {
                                let _ = tx.try_send(get_msg.clone());
                                sent += 1;
                            }
                            for _ in 0..2 {
                                if let Some(pid) = self.next_sync_peer(&state) {
                                    if pid != peer.id {
                                        if let Some(tx) = state.peer_txs.get(&pid) {
                                            let _ = tx.try_send(get_msg.clone());
                                            sent += 1;
                                        }
                                    }
                                }
                            }
                            // Also request liTX_NODE immediately — peers have the
                            // tx tree hot right after validation. Requesting later
                            // (from the follower loop) means peers may have evicted it.
                            let tx_cookie = crate::sync::next_cookie();
                            let tx_msg = relay::encode_get_ledger_txs_for_hash(&val.ledger_hash, tx_cookie);
                            for (&pid, ptx) in &state.peer_txs {
                                if sent >= 3 { break; }
                                let _ = ptx.try_send(tx_msg.clone());
                                sent += 1;
                                let _ = pid; // suppress warning
                            }
                            sent
                        };
                        info!("sent liBASE+liTX_NODE to {sent} peers for ledger {}", val.ledger_seq);
                        // Update lock-free RPC snapshot
                        self.update_rpc_snapshot().await;
                    }

                    if !self.message_is_new(MessageType::Validation, &msg.payload) {
                        return PeerEvent::MessageReceived(MessageType::Validation, msg.payload);
                    }
                    let relay_msg = relay::encode_validation(&val);
                    let squelch_skipped = {
                        let mut state = self.state.write().await;
                        state.broadcast_with_squelch(&relay_msg, Some(peer.id), &val.node_pubkey)
                    };
                    if squelch_skipped > 0 {
                        tracing::debug!(
                            "validation relay: skipped {} squelched peer(s) for validator {}...",
                            squelch_skipped, &hex::encode_upper(&val.node_pubkey[..8.min(val.node_pubkey.len())]),
                        );
                    }
                    let _ = self.ws_events.send(crate::rpc::ws::WsEvent::PeerMessage {
                        msg_type: "validation".into(),
                        detail: format!("ledger_seq={} from {:?}", val.ledger_seq, peer.id),
                    });
                }
                PeerEvent::MessageReceived(MessageType::Validation, msg.payload)
            }
            MessageType::Manifests => {
                if !self.message_is_new(MessageType::Manifests, &msg.payload) {
                    return PeerEvent::MessageReceived(MessageType::Manifests, msg.payload);
                }
                // Process ALL manifests in the batch, not just the first
                let manifests = relay::decode_manifests(&msg.payload);
                for manifest in &manifests {
                    info!(
                        "received manifest seq={} from peer {:?}",
                        manifest.sequence, peer.id
                    );
                    {
                        let mut state = self.state.write().await;
                        if let Some(ref mut round) = state.current_round {
                            round.add_manifest(manifest.clone());
                        }
                    }
                }
                if let Some(manifest) = manifests.into_iter().next() {
                    let relay_msg = relay::encode_manifest(&manifest);
                    self.state.read().await.broadcast(&relay_msg, Some(peer.id));
                    let _ = self.ws_events.send(crate::rpc::ws::WsEvent::PeerMessage {
                        msg_type: "manifest".into(),
                        detail: format!("seq={} from {:?}", manifest.sequence, peer.id),
                    });
                }
                PeerEvent::MessageReceived(MessageType::Manifests, msg.payload)
            }
            MessageType::ValidatorList => {
                // TMValidatorList (type 54) — peer-propagated UNL update.
                if let Some(vl) = relay::decode_validator_list(&msg.payload) {
                    let publisher_keys: Vec<String> = self.validator_list_config.publisher_keys.clone();
                    match crate::validator_list::verify_peer_validator_list(
                        &vl.manifest, &vl.blob, &vl.signature, &publisher_keys,
                    ) {
                        Ok(list) => {
                            // Update UNL if this is a newer sequence
                            let new_unl = crate::validator_list::hex_keys_to_unl(&list.validators);
                            if !new_unl.is_empty() {
                                let mut unl = self.unl.write().unwrap_or_else(|e| e.into_inner());
                                *unl = new_unl;
                                info!(
                                    "updated UNL from peer validator list (seq={}, {} validators)",
                                    list.sequence, unl.len(),
                                );
                            }
                        }
                        Err(e) => {
                            debug!("peer validator list rejected: {e}");
                        }
                    }
                    // Relay to other peers
                    let relay_msg = RtxpMessage::new(MessageType::ValidatorList, msg.payload.clone());
                    self.state.read().await.broadcast(&relay_msg, Some(peer.id));
                }
                PeerEvent::MessageReceived(MessageType::ValidatorList, msg.payload)
            }
            MessageType::ValidatorListCollection => {
                // TMValidatorListCollection (type 56) — v2 UNL with multiple blobs.
                if let Some((shared_manifest, blobs)) = relay::decode_validator_list_collection(&msg.payload) {
                    let publisher_keys: Vec<String> = self.validator_list_config.publisher_keys.clone();
                    for vl_blob in &blobs {
                        // Use per-blob manifest if present, otherwise shared manifest
                        let manifest = vl_blob.manifest.as_deref().unwrap_or(&shared_manifest);
                        match crate::validator_list::verify_peer_validator_list(
                            manifest, &vl_blob.blob, &vl_blob.signature, &publisher_keys,
                        ) {
                            Ok(list) => {
                                let new_unl = crate::validator_list::hex_keys_to_unl(&list.validators);
                                if !new_unl.is_empty() {
                                    let mut unl = self.unl.write().unwrap_or_else(|e| e.into_inner());
                                    *unl = new_unl;
                                    info!(
                                        "updated UNL from peer validator list collection (seq={}, {} validators)",
                                        list.sequence, unl.len(),
                                    );
                                }
                            }
                            Err(e) => {
                                debug!("peer validator list collection blob rejected: {e}");
                            }
                        }
                    }
                    // Relay to other peers
                    let relay_msg = RtxpMessage::new(MessageType::ValidatorListCollection, msg.payload.clone());
                    self.state.read().await.broadcast(&relay_msg, Some(peer.id));
                }
                PeerEvent::MessageReceived(MessageType::ValidatorListCollection, msg.payload)
            }
            MessageType::Endpoints => {
                // Peer discovery: add new addresses to known_peers.
                // Actual dialing is done by handle_peer after route_message returns.
                let addrs = relay::decode_endpoints(&msg.payload);
                {
                    let mut state = self.state.write().await;
                    for a in addrs {
                        state.add_known_peer(a);
                    }
                }
                PeerEvent::MessageReceived(MessageType::Endpoints, msg.payload)
            }
            // xLedgRS custom sync messages (Unknown(200..206))
            // These are handled here for backward compatibility with xLedgRS peers.
            MessageType::Unknown(200) => {
                // GetSnapshot
                if let Some(seq) = relay::decode_get_snapshot(&msg.payload) {
                    info!("peer {:?} requested snapshot (seq={})", peer.id, seq);
                    let state = self.state.read().await;
                    let tx = state.peer_txs.get(&peer.id).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.try_send(relay::encode_snapshot_header(&state.ctx.ledger_header));
                        let ls = state.ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                        let accounts: Vec<_> = ls.iter_accounts().map(|(_, a)| a.clone()).collect();
                        drop(ls);
                        if !accounts.is_empty() {
                            let data = bincode::serialize(&accounts).unwrap_or_default();
                            let _ = tx.try_send(relay::encode_snapshot_chunk(0, data));
                        }
                        let _ = tx.try_send(relay::encode_snapshot_end(
                            state.ctx.ledger_seq,
                            &state.ctx.ledger_header.account_hash,
                        ));
                    }
                }
                PeerEvent::MessageReceived(msg.msg_type, msg.payload)
            }
            MessageType::Unknown(201) => {
                // SnapshotHeader
                if let Some(header) = relay::decode_snapshot_header(&msg.payload) {
                    info!("received snapshot header: ledger {}", header.sequence);
                    let mut state = self.state.write().await;
                    state.ctx.ledger_header = header.clone();
                    state.ctx.ledger_seq = header.sequence;
                    state.ctx.ledger_hash = hex::encode_upper(header.hash);
                    state.ctx.history.write().unwrap_or_else(|e| e.into_inner()).insert_ledger(header, vec![]);
                }
                PeerEvent::MessageReceived(msg.msg_type, msg.payload)
            }
            MessageType::Unknown(202) => {
                // SnapshotChunk
                if !msg.payload.is_empty() {
                    let obj_type = msg.payload[0];
                    let data = &msg.payload[1..];
                    let state = self.state.read().await;
                    match obj_type {
                        0 => {
                            if let Ok(accounts) = bincode::deserialize::<Vec<crate::ledger::AccountRoot>>(data) {
                                let mut ls = state.ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                                for a in accounts { ls.insert_account(a); }
                            }
                        }
                        _ => {}
                    }
                }
                PeerEvent::MessageReceived(msg.msg_type, msg.payload)
            }
            MessageType::Unknown(203) => {
                // SnapshotEnd
                if let Some((seq, hash)) = relay::decode_snapshot_end(&msg.payload) {
                    let mut state = self.state.write().await;
                    let local_hash = {
                        let mut ls = state.ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                        ls.state_hash()
                    };
                    if local_hash == hash {
                        info!("snapshot verified: ledger {seq} state hash matches");
                    } else {
                        warn!("snapshot hash MISMATCH for ledger {seq}");
                    }
                    state.sync_in_progress = false;
                }
                PeerEvent::MessageReceived(msg.msg_type, msg.payload)
            }
            MessageType::Unknown(204) => {
                // GetHistory
                if let Some((start, end)) = relay::decode_get_history(&msg.payload) {
                    info!("peer {:?} requested history {start}..{end}", peer.id);
                    let state = self.state.read().await;
                    let tx = state.peer_txs.get(&peer.id).cloned();
                    if let Some(tx) = tx {
                        let capped_end = end.min(start + 255);
                        let history = state.ctx.history.read().unwrap_or_else(|e| e.into_inner());
                        for seq in start..=capped_end {
                            if let Some(rec) = history.get_ledger(seq) {
                                let tx_records: Vec<_> = rec.tx_hashes.iter()
                                    .filter_map(|h| history.get_tx(h).cloned())
                                    .collect();
                                let _ = tx.try_send(relay::encode_history_ledger(&rec.header, &tx_records));
                            }
                        }
                        let _ = tx.try_send(relay::encode_history_end(start, capped_end));
                    }
                }
                PeerEvent::MessageReceived(msg.msg_type, msg.payload)
            }
            MessageType::Unknown(205) => {
                // HistoryLedger
                if let Some((header, tx_records)) = relay::decode_history_ledger(&msg.payload) {
                    if header.compute_hash() == header.hash {
                        info!("received history ledger {}", header.sequence);
                        let state = self.state.write().await;
                        state.ctx.history.write().unwrap_or_else(|e| e.into_inner()).insert_ledger(header, tx_records);
                    } else {
                        warn!("rejected history ledger: hash mismatch");
                    }
                }
                PeerEvent::MessageReceived(msg.msg_type, msg.payload)
            }
            MessageType::Unknown(206) => {
                // HistoryEnd
                info!("history download complete");
                let mut state = self.state.write().await;
                state.sync_in_progress = false;
                PeerEvent::MessageReceived(msg.msg_type, msg.payload)
            }
            MessageType::GetLedger => {
                // Incoming TMGetLedger request from a peer — serve the requested
                // ledger data directly from our header/history/state stores.
                if let Ok(req) = <crate::proto::TmGetLedger as ProstMessage>::decode(msg.payload.as_slice()) {
                    let state = self.state.read().await;
                    let current = state.ctx.ledger_header.clone();
                    let peer_tx = state.peer_txs.get(&peer.id).cloned();
                    let cookie = req.request_cookie.map(|c| c as u32);
                    let requested_hash = requested_get_ledger_hash(&req)
                        .ok()
                        .flatten()
                        .unwrap_or([0u8; 32]);
                    let requested_seq = req.ledger_seq.unwrap_or(0);

                    let history = state.ctx.history.read().unwrap_or_else(|e| e.into_inner());

                    if let Some(tx) = peer_tx {
                        let header = match resolve_get_ledger_header(&req, &current, &history) {
                            Ok(header) => header,
                            Err(err) => {
                                let reply = relay::encode_ledger_data_error(
                                    &requested_hash,
                                    requested_seq,
                                    req.itype,
                                    cookie,
                                    err,
                                );
                                let _ = tx.try_send(reply);
                                debug!(
                                    "GetLedger bad request from {:?}: type={} ltype={:?} seq={} hash_len={}",
                                    peer.id,
                                    req.itype,
                                    req.ltype,
                                    requested_seq,
                                    req.ledger_hash.as_ref().map(|hash| hash.len()).unwrap_or(0),
                                );
                                return PeerEvent::MessageReceived(MessageType::GetLedger, msg.payload);
                            }
                        };
                        if header.sequence <= 1 {
                            let reply = relay::encode_ledger_data_error(
                                &requested_hash,
                                requested_seq,
                                req.itype,
                                cookie,
                                crate::proto::TmReplyError::ReNoLedger,
                            );
                            let _ = tx.try_send(reply);
                            debug!(
                                "GetLedger miss from {:?}: type={} seq={} hash={}",
                                peer.id,
                                req.itype,
                                requested_seq,
                                hex::encode_upper(&requested_hash[..8]),
                            );
                            return PeerEvent::MessageReceived(MessageType::GetLedger, msg.payload);
                        }

                        match req.itype {
                            x if x == crate::proto::TmLedgerInfoType::LiBase as i32 => {
                                let mut header_bytes = Vec::with_capacity(118);
                                header_bytes.extend_from_slice(&header.sequence.to_be_bytes());
                                header_bytes.extend_from_slice(&header.total_coins.to_be_bytes());
                                header_bytes.extend_from_slice(&header.parent_hash);
                                header_bytes.extend_from_slice(&header.transaction_hash);
                                header_bytes.extend_from_slice(&header.account_hash);
                                header_bytes.extend_from_slice(&header.parent_close_time.to_be_bytes());
                                header_bytes.extend_from_slice(&(header.close_time as u32).to_be_bytes());
                                header_bytes.push(header.close_time_resolution);
                                header_bytes.push(header.close_flags);

                                let response = crate::proto::TmLedgerData {
                                    ledger_hash: header.hash.to_vec(),
                                    ledger_seq: header.sequence,
                                    r#type: crate::proto::TmLedgerInfoType::LiBase as i32,
                                    nodes: vec![crate::proto::TmLedgerNode {
                                        nodedata: header_bytes,
                                        nodeid: None,
                                    }],
                                    request_cookie: cookie,
                                    error: None,
                                };

                                let reply = RtxpMessage::new(MessageType::LedgerData, response.encode_to_vec());
                                let _ = tx.try_send(reply);
                                info!("served liBASE to {:?} (ledger {})", peer.id, header.sequence);
                            }
                            x if x == crate::proto::TmLedgerInfoType::LiTxNode as i32 => {
                                let tx_records = state.ctx.history.read().unwrap_or_else(|e| e.into_inner()).ledger_txs(header.sequence);
                                let node_ids: Vec<Vec<u8>> = if req.node_i_ds.is_empty() {
                                    vec![vec![0u8; 33]]
                                } else {
                                    req.node_i_ds.clone()
                                };
                                let query_depth = req.query_depth.unwrap_or(0);
                                let mut tx_map = crate::ledger::shamap::SHAMap::new_transaction();
                                for rec in tx_records {
                                    let mut data =
                                        Vec::with_capacity(rec.blob.len() + rec.meta.len() + 8);
                                    crate::transaction::serialize::encode_length(
                                        rec.blob.len(),
                                        &mut data,
                                    );
                                    data.extend_from_slice(&rec.blob);
                                    crate::transaction::serialize::encode_length(
                                        rec.meta.len(),
                                        &mut data,
                                    );
                                    data.extend_from_slice(&rec.meta);
                                    tx_map.insert(crate::ledger::Key(rec.hash), data);
                                }
                                let (nodes, invalid_node_ids) =
                                    collect_shamap_ledger_nodes(&mut tx_map, &node_ids, query_depth);

                                if !nodes.is_empty() {
                                    let response = crate::proto::TmLedgerData {
                                        ledger_hash: header.hash.to_vec(),
                                        ledger_seq: header.sequence,
                                        r#type: crate::proto::TmLedgerInfoType::LiTxNode as i32,
                                        nodes,
                                        request_cookie: cookie,
                                        error: None,
                                    };

                                    let reply = RtxpMessage::new(
                                        MessageType::LedgerData,
                                        response.encode_to_vec(),
                                    );
                                    let _ = tx.try_send(reply);
                                    info!("served liTX_NODE to {:?} (ledger {})", peer.id, header.sequence);
                                } else {
                                    let reply = relay::encode_ledger_data_error(
                                        &header.hash,
                                        header.sequence,
                                        crate::proto::TmLedgerInfoType::LiTxNode as i32,
                                        cookie,
                                        if invalid_node_ids == node_ids.len() {
                                            crate::proto::TmReplyError::ReBadRequest
                                        } else {
                                            crate::proto::TmReplyError::ReNoNode
                                        },
                                    );
                                    let _ = tx.try_send(reply);
                                }
                            }
                            x if x == crate::proto::TmLedgerInfoType::LiAsNode as i32 => {
                                // Serve liAS_NODE for any ledger we have a header for.
                                let is_current = header.hash == current.hash && header.sequence == current.sequence;
                                let node_ids: Vec<Vec<u8>> = if req.node_i_ds.is_empty() {
                                    vec![vec![0u8; 33]]
                                } else {
                                    req.node_i_ds.clone()
                                };
                                let query_depth = req.query_depth.unwrap_or(0);
                                let Some(mut requested_state_map) = ({
                                    let mut ls = state.ctx.ledger_state.lock()
                                        .unwrap_or_else(|e| e.into_inner());
                                    if is_current {
                                        Some(ls.peer_state_map_snapshot())
                                    } else {
                                        ls.historical_state_map_from_root(header.account_hash)
                                    }
                                }) else {
                                    let reply = relay::encode_ledger_data_error(
                                        &header.hash,
                                        header.sequence,
                                        crate::proto::TmLedgerInfoType::LiAsNode as i32,
                                        cookie,
                                        crate::proto::TmReplyError::ReNoNode,
                                    );
                                    let _ = tx.try_send(reply);
                                    debug!(
                                        "GetLedger liAS_NODE unavailable for ledger {} from {:?}",
                                        header.sequence, peer.id,
                                    );
                                    return PeerEvent::MessageReceived(MessageType::GetLedger, msg.payload);
                                };
                                let (nodes, invalid_node_ids) = collect_shamap_ledger_nodes(
                                    &mut requested_state_map,
                                    &node_ids,
                                    query_depth,
                                );

                                if !nodes.is_empty() {
                                    let response = crate::proto::TmLedgerData {
                                        ledger_hash: header.hash.to_vec(),
                                        ledger_seq: header.sequence,
                                        r#type: crate::proto::TmLedgerInfoType::LiAsNode as i32,
                                        nodes,
                                        request_cookie: cookie,
                                        error: None,
                                    };

                                    let reply = RtxpMessage::new(MessageType::LedgerData, response.encode_to_vec());
                                    let _ = tx.try_send(reply);
                                    info!(
                                        "served liAS_NODE to {:?} (ledger {}, {})",
                                        peer.id, header.sequence,
                                        if is_current { "current" } else { "historical" },
                                    );
                                } else {
                                    let reply = relay::encode_ledger_data_error(
                                        &header.hash,
                                        header.sequence,
                                        crate::proto::TmLedgerInfoType::LiAsNode as i32,
                                        cookie,
                                        if invalid_node_ids == node_ids.len() {
                                            crate::proto::TmReplyError::ReBadRequest
                                        } else {
                                            crate::proto::TmReplyError::ReNoNode
                                        },
                                    );
                                    let _ = tx.try_send(reply);
                                }
                            }
                            _ => {
                                let reply = relay::encode_ledger_data_error(
                                    &requested_hash,
                                    requested_seq,
                                    req.itype,
                                    cookie,
                                    crate::proto::TmReplyError::ReBadRequest,
                                );
                                let _ = tx.try_send(reply);
                            }
                        }
                    }
                }
                PeerEvent::MessageReceived(MessageType::GetLedger, msg.payload)
            }
            MessageType::GetObjects => {
                // TMGetObjectByHash — can be a request (query=true) or response.
                if let Ok(pb) = <crate::proto::TmGetObjectByHash as ProstMessage>::decode(msg.payload.as_slice()) {
                    if pb.query {
                        // INCOMING REQUEST — serve objects from our storage.
                        let mut reply_objects = Vec::new();

                        for obj in &pb.objects {
                            let Some(ref hash) = obj.hash else {
                                continue;
                            };
                            if hash.len() != 32 {
                                continue;
                            }
                            let mut key = [0u8; 32];
                            key.copy_from_slice(hash);

                            let data = if pb.r#type == crate::proto::tm_get_object_by_hash::ObjectType::OtStateNode as i32 {
                                self.nudb_backend
                                    .as_ref()
                                    .and_then(|backend| backend.fetch(&key).ok().flatten())
                            } else {
                                self.storage.as_ref().and_then(|store| store.lookup_raw_tx(hash))
                            };

                            if let Some(data) = data {
                                reply_objects.push(crate::proto::TmIndexedObject {
                                    hash: Some(hash.clone()),
                                    data: Some(data),
                                    node_id: obj.node_id.clone(),
                                    index: None,
                                    ledger_seq: None,
                                });
                            }
                        }

                        if !reply_objects.is_empty() {
                            let reply = crate::proto::TmGetObjectByHash {
                                r#type: pb.r#type,
                                query: false, // this is a response
                                seq: pb.seq,
                                ledger_hash: pb.ledger_hash.clone(),
                                fat: None,
                                objects: reply_objects.clone(),
                            };

                            let reply_msg = RtxpMessage::new(
                                MessageType::GetObjects,
                                reply.encode_to_vec(),
                            );
                            let state = self.state.read().await;
                            if let Some(tx) = state.peer_txs.get(&peer.id) {
                                let _ = tx.try_send(reply_msg);
                            }
                            info!(
                                "served {}/{} objects to {:?}",
                                reply_objects.len(), pb.objects.len(), peer.id,
                            );
                        }
                    } else {
                        let target_h8 = self.sync_target_hash8.load(std::sync::atomic::Ordering::Relaxed);
                        let accepted_by_gate = sync_gate_accepts_response(
                            &self.sync,
                            target_h8,
                            pb.ledger_hash.as_deref(),
                            pb.seq.map(|seq| seq as u32),
                            true,
                        );

                        if accepted_by_gate {
                            info!(
                                "queuing object response from {:?}: seq={:?} count={}",
                                peer.id, pb.seq, pb.objects.len(),
                            );
                            // Recover nodeids from sync-side pending maps.
                            // Prefer explicit fields in response; fall back to:
                            // 1) hash->nodeid map, 2) cookie+response-order map.
                            let (nodeid_map, cookie_nodeids): (
                                std::collections::HashMap<[u8; 32], [u8; 33]>,
                                Vec<[u8; 33]>,
                            ) = {
                                if let Ok(guard) = self.sync.try_lock() {
                                    if let Some(s) = guard.as_ref() {
                                        let by_hash = s.pending_object_nodeids.clone();
                                        let by_cookie = pb
                                            .seq
                                            .and_then(|seq| s.pending_object_cookies.get(&(seq as u32)).cloned())
                                            .unwrap_or_default();
                                        (by_hash, by_cookie)
                                    } else {
                                        (std::collections::HashMap::new(), Vec::new())
                                    }
                                } else {
                                    (std::collections::HashMap::new(), Vec::new())
                                }
                            };
                            let mut converted_count = 0u32;
                            let mut recovered_nodeids = 0u32;
                            let mut recovered_by_order = 0u32;
                            let nodes: Vec<crate::proto::TmLedgerNode> = pb.objects.iter()
                                .enumerate()
                                .filter_map(|obj| {
                                    // Try response fields first, fall back to pending map by content hash
                                    let node_path = obj.1.index.clone()
                                        .or(obj.1.node_id.clone())
                                        .or_else(|| {
                                            obj.1.hash.as_ref().and_then(|h| {
                                                if h.len() == 32 {
                                                    let mut key = [0u8; 32];
                                                    key.copy_from_slice(h);
                                                    nodeid_map.get(&key).map(|nid| {
                                                        recovered_nodeids += 1;
                                                        nid.to_vec()
                                                    })
                                                } else { None }
                                            })
                                        })
                                        .or_else(|| {
                                            // Some peers omit hash/index/node_id in GetObjects responses.
                                            // Fall back to request order within this cookie.
                                            cookie_nodeids.get(obj.0).map(|nid| {
                                                recovered_by_order += 1;
                                                nid.to_vec()
                                            })
                                        });
                                    obj.1.data.as_ref().and_then(|data| {
                                        // GetObjects returns NodeStore storage format
                                        // (prefix + payload). Convert to peer wire format
                                        // (payload + wireType suffix) for process_response().
                                        let wire_data = if let Some(w) = crate::sync::storage_to_wire(data) {
                                            converted_count += 1;
                                            w
                                        } else {
                                            // Unknown format — pass through as-is
                                            data.clone()
                                        };
                                        Some(crate::proto::TmLedgerNode {
                                            nodedata: wire_data,
                                            nodeid: node_path,
                                        })
                                    })
                                })
                                .collect();
                            if converted_count > 0 || !nodes.is_empty() {
                                let inner_count = nodes.iter().filter(|n| {
                                    let d = &n.nodedata;
                                    d.last() == Some(&2) || d.last() == Some(&3)
                                }).count();
                                let leaf_count = nodes.iter().filter(|n| {
                                    n.nodedata.last() == Some(&1)
                                }).count();
                                info!(
                                    "GetObjects response: {} nodes ({}inner {}leaf {}other) converted={} recovered_nodeids={} recovered_by_order={} from {:?}",
                                    nodes.len(), inner_count, leaf_count,
                                    nodes.len() - inner_count - leaf_count,
                                    converted_count, recovered_nodeids, recovered_by_order, peer.id,
                                );
                            }
                            if !nodes.is_empty() {
                                // Repackage as TmLedgerData for the shared batch channel.
                                // CONVENTION: error=Some(1) marks this as a GetObjects response
                                // so the batch processor calls accept_object_response(seq)
                                // instead of accept_response(cookie). The seq is stored in
                                // request_cookie. See batch processor loop (~line 1535).
                                let ld = crate::proto::TmLedgerData {
                                    ledger_hash: pb.ledger_hash.clone().unwrap_or_default(),
                                    ledger_seq: 0,
                                    r#type: crate::proto::TmLedgerInfoType::LiAsNode as i32,
                                    nodes,
                                    request_cookie: pb.seq.map(|s| s as u32),
                                    error: Some(1), // GetObjects marker — see convention above
                                };
                                {
                                    let mut q = self.sync_data_queue.lock().unwrap_or_else(|e| e.into_inner());
                                    q.push((peer.id, ld));
                                }
                                self.sync_data_notify.notify_one();
                            }
                        } else {
                            debug!(
                                "ignoring object response from {:?}: accepted={} seq={:?} count={}",
                                peer.id, accepted_by_gate, pb.seq, pb.objects.len(),
                            );
                        }
                    }
                }
                PeerEvent::MessageReceived(MessageType::GetObjects, msg.payload)
            }
            MessageType::Squelch => {
                if let Some(sq) = relay::decode_squelch(&msg.payload) {
                    let mut state = self.state.write().await;
                    if sq.squelch {
                        let duration = sq.duration_secs.unwrap_or(600); // default 10 min
                        let expiry = std::time::Instant::now() + std::time::Duration::from_secs(duration as u64);
                        state.peer_squelch
                            .entry(peer.id)
                            .or_default()
                            .insert(sq.validator_pubkey.clone(), expiry);
                        tracing::debug!(
                            "squelch received: peer={} validator={}... duration={}s",
                            peer.id.0, hex::encode_upper(&sq.validator_pubkey[..8.min(sq.validator_pubkey.len())]),
                            duration,
                        );
                    } else {
                        if let Some(map) = state.peer_squelch.get_mut(&peer.id) {
                            map.remove(&sq.validator_pubkey);
                            tracing::debug!(
                                "unsquelch received: peer={} validator={}...",
                                peer.id.0, hex::encode_upper(&sq.validator_pubkey[..8.min(sq.validator_pubkey.len())]),
                            );
                        }
                    }
                }
                PeerEvent::MessageReceived(MessageType::Squelch, msg.payload)
            }
            other => PeerEvent::MessageReceived(other, msg.payload),
        }
    }

    /// Execute an action produced by the peer state machine.
    async fn execute_action<S>(
        &self,
        stream:       &mut S,
        peer:         &mut Peer,
        action:       PeerAction,
        session_hash: &[u8; 32],
    ) -> anyhow::Result<()>
    where S: AsyncWriteExt + Unpin + Send {
        match action {
            PeerAction::SendHandshakeRequest => {
                let pubkey = self.node_key.public_key_bytes();
                let sig    = self.node_key.sign_digest(session_hash);
                let req    = crate::network::handshake::build_request_simple(&pubkey, &sig);
                stream.write_all(req.as_bytes()).await?;
            }
            PeerAction::SendHandshakeResponse => {
                let pubkey = self.node_key.public_key_bytes();
                let sig    = self.node_key.sign_digest(session_hash);
                let resp   = crate::network::handshake::build_response(&pubkey, &sig);
                stream.write_all(resp.as_bytes()).await?;
            }
            PeerAction::SendMessage(msg_type, payload) => {
                let msg  = RtxpMessage::new(msg_type, payload);
                stream.write_all(&msg.encode()).await?;
            }
            PeerAction::CloseSocket => {
                let _ = stream.shutdown().await;
            }
            PeerAction::Warn(msg) => {
                warn!("peer {:?}: {msg}", peer.id);
            }
            PeerAction::None => {}
        }
        Ok(())
    }

    // ── RPC server ────────────────────────────────────────────────────────────

    async fn run_rpc_server(self: Arc<Self>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.config.rpc_addr).await?;
        info!("JSON-RPC server on {}", self.config.rpc_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(e) = node.handle_rpc(stream).await {
                    warn!("RPC error from {addr}: {e}");
                }
            });
        }
    }

    // ── RPC helpers ───────────────────────────────────────────────────────────

    async fn handle_rpc(self: Arc<Self>, mut stream: TcpStream) -> anyhow::Result<()> {
        let raw = read_rpc_request(&mut stream).await?;
        if raw.is_empty() { return Ok(()); }

        // Strip HTTP wrapper if present (POST / HTTP/1.1 ... \r\n\r\n<body>)
        let body = if raw.starts_with(b"POST") || raw.starts_with(b"GET") {
            raw.windows(4)
               .position(|w| w == b"\r\n\r\n")
               .map(|i| &raw[i + 4..])
               .unwrap_or(raw.as_slice())
        } else {
            raw.as_slice()
        };

        if body.is_empty() {
            let reply = serde_json::json!({
                "result": {
                    "error": "invalidParams",
                    "error_code": 31,
                    "error_message": "Unable to parse request.",
                    "status": "error",
                }
            }).to_string();
            let http = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                reply.len(), reply
            );
            stream.write_all(http.as_bytes()).await?;
            return Ok(());
        }

        // Parse request first (no lock needed)
        let req = match RpcRequest::parse(body) {
            Ok(r) => r,
            Err(e) => {
                let reply = serde_json::json!({
                    "result": {
                        "error": "invalidParams",
                        "error_code": 31,
                        "error_message": format!("Unable to parse request: {e}"),
                        "status": "error",
                    }
                }).to_string();
                let http = format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                    reply.len(), reply
                );
                stream.write_all(http.as_bytes()).await?;
                return Ok(());
            }
        };

        // server_info uses the lock-free ArcSwap snapshot — NEVER blocks
        let reply = if req.method == "server_info" || req.method == "server_state" {
            let snap = self.rpc_snapshot.load();
            let follower = {
                let state = self.state.try_read();
                state.ok().and_then(|s| s.follower_state.clone())
            };
            let rpc_sync = {
                let state = self.state.try_read();
                state.ok().and_then(|s| s.rpc_sync_state.clone())
            };
            let result = crate::rpc::handlers::server_info_snapshot(
                &snap, follower.as_ref(), rpc_sync.as_ref(),
            );
            let id = req.id;
            match result {
                Ok(r) => crate::rpc::RpcResponse::ok(r, id).to_json(),
                Err(e) => crate::rpc::RpcResponse::err(e, id).to_json(),
            }
        } else if crate::rpc::needs_write(&req.method) {
            // Submit needs write lock (mutates tx_pool + broadcast_queue)
            let mut state = self.state.write().await;
            state.ctx.peer_count = state.peer_count();
            state.ctx.follower_state = state.follower_state.clone();
            let reply = dispatch(req, &mut state.ctx).to_json();
            let pending: Vec<_> = state.ctx.broadcast_queue.drain(..).collect();
            for msg in &pending {
                state.broadcast(msg, None);
            }
            reply
        } else {
            let ctx = self.rpc_read_ctx.load();
            crate::rpc::dispatch_read(req, ctx.as_ref()).to_json()
        };

        let http = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
            reply.len(),
            reply
        );
        stream.write_all(http.as_bytes()).await?;
        Ok(())
    }
}

// ── Free helpers ───────────────────────────────────────────────────────────────

fn parse_http_content_length(header: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(header).ok()?;
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

async fn read_rpc_request(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut chunk = vec![0u8; 8192];
    let mut raw = Vec::new();

    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > MAX_RPC_REQUEST_BYTES {
            anyhow::bail!("rpc request exceeded size limit");
        }

        let is_http = raw.starts_with(b"POST") || raw.starts_with(b"GET");
        if !is_http {
            break;
        }

        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let split = pos + 4;
            if split > MAX_RPC_HEADER_BYTES {
                anyhow::bail!("rpc headers exceeded size limit");
            }
            let content_length = parse_http_content_length(&raw[..split]).unwrap_or(0);
            if content_length > MAX_RPC_BODY_BYTES {
                anyhow::bail!("rpc body exceeded size limit");
            }
            if raw.len() >= split + content_length {
                break;
            }
        }
    }

    Ok(raw)
}

/// Read from `stream` until a complete HTTP header block ending with `\r\n\r\n`
/// has been received.
///
/// Returns `(header_bytes_including_blank_line, leftover_bytes)`.
/// Leftover bytes are any data that arrived after the blank line — in practice
/// a peer might start sending RTXP frames immediately after the 101 response,
/// so callers should pre-feed the leftover into `FrameDecoder`.
async fn read_http_headers<S>(stream: &mut S) -> anyhow::Result<(Vec<u8>, Vec<u8>)>
where S: AsyncReadExt + Unpin {
    let mut chunk = vec![0u8; 4096];
    let mut raw   = Vec::new();

    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 { anyhow::bail!("connection closed before handshake completed"); }
        raw.extend_from_slice(&chunk[..n]);

        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let split    = pos + 4;
            let leftover = raw[split..].to_vec();
            raw.truncate(split);
            return Ok((raw, leftover));
        }

        if raw.len() > 16_384 {
            anyhow::bail!("handshake headers exceeded 16 KiB limit");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_http_content_length, should_close_ledger, sync_gate_accepts_response, SharedState};
    use crate::network::message::{MessageType, RtxpMessage};
    use crate::network::peer::PeerId;
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
    fn test_send_to_peers_with_ledger_counts_only_successful_sends() {
        let mut state = SharedState::new(crate::rpc::NodeContext::default());
        let peer = PeerId(1);
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(RtxpMessage::new(MessageType::Ping, vec![1])).unwrap();
        state.peer_txs.insert(peer, tx);
        state.peer_ledger_range.insert(peer, (1, 10));

        let msg = RtxpMessage::new(MessageType::Ping, vec![2]);
        assert_eq!(state.send_to_peers_with_ledger(&msg, 5, 1), 0);

        let _ = rx.try_recv().unwrap();
        assert_eq!(state.send_to_peers_with_ledger(&msg, 5, 1), 1);
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
    fn test_send_to_peers_with_ledger_prunes_weak_peers_below_half_best() {
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
        assert_eq!(state.send_to_peers_with_ledger(&msg, 5, 2), 1);
        let sent = rx_strong.try_recv().unwrap();
        assert_eq!(sent.payload, vec![8]);
        assert!(rx_weak.try_recv().is_err());
    }

    #[test]
    fn test_parse_http_content_length_case_insensitive() {
        let header = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(parse_http_content_length(header), Some(42));

        let header = b"POST / HTTP/1.1\r\ncontent-length: 7\r\n\r\n";
        assert_eq!(parse_http_content_length(header), Some(7));
    }

    #[test]
    fn test_sync_gate_accepts_ltclosed_ledgerdata_response() {
        let header = crate::ledger::LedgerHeader::default();
        let sync = std::sync::Mutex::new(Some(crate::sync_coordinator::SyncCoordinator::new(
            10,
            [0u8; 32],
            [0x22; 32],
            None,
            header,
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
    fn test_sync_gate_accepts_ltclosed_object_response_by_seq() {
        let header = crate::ledger::LedgerHeader::default();
        let sync = std::sync::Mutex::new(Some(crate::sync_coordinator::SyncCoordinator::new(
            10,
            [0u8; 32],
            [0x22; 32],
            None,
            header,
        )));
        {
            let mut guard = sync.lock().unwrap();
            let syncer = guard.as_mut().expect("syncer should exist");
            syncer.peer.outstanding_object_queries.insert(77);
        }

        assert!(sync_gate_accepts_response(
            &sync,
            0,
            Some(&[0xEF; 32]),
            Some(77),
            true,
        ));
        assert!(!sync_gate_accepts_response(
            &sync,
            0,
            Some(&[0xEF; 32]),
            Some(78),
            true,
        ));
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
