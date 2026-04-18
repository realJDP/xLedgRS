//! WebSocket API server — real-time event streaming + request/response.
//!
//! Reuses the same `dispatch()` function as the HTTP JSON-RPC server for
//! request/response.  Additionally supports `subscribe`/`unsubscribe` for
//! real-time ledger and transaction events.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

const SUPPORTED_STREAMS: &[&str] = &[
    "ledger",
    "server",
    "transactions",
    "transactions_proposed",
    "validations",
    "peer_status",
    "consensus",
    "book_changes",
    "manifests",
    "peer_messages",
];
static NEXT_WS_CLIENT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Events that can be broadcast to WebSocket subscribers.
#[derive(Debug, Clone)]
pub enum WsEvent {
    /// A new ledger was validated.
    LedgerClosed {
        ledger_seq: u32,
        ledger_hash: String,
        tx_count: usize,
        ledger_time: u64,
        network_id: u32,
        validated_ledgers: String,
        fee_base: u64,
        reserve_base: u64,
        reserve_inc: u64,
    },
    /// Server status update.
    ServerStatus {
        ledger_seq: u32,
        ledger_hash: String,
        network_id: u32,
        peer_count: usize,
        validated_ledgers: String,
        server_status: String,
        load_snapshot: crate::network::load::LoadSnapshot,
        base_fee: u64,
    },
    /// A transaction was validated (included in a closed ledger).
    Transaction {
        tx_record: crate::ledger::history::TxRecord,
        ledger_hash: String,
        close_time: u64,
        network_id: u32,
        accounts: Vec<String>,
    },
    /// A proposed transaction seen on the network before validation.
    ProposedTransaction {
        tx_blob: Vec<u8>,
        network_id: u32,
        accounts: Vec<String>,
    },
    /// A validation received from a peer or produced locally.
    ValidationReceived {
        validation: crate::consensus::Validation,
        network_id: u32,
    },
    /// A consensus phase transition.
    ConsensusPhase { consensus: String },
    /// A peer status change emitted from TMStatusChange.
    PeerStatusChange { payload: Value },
    /// Per-ledger book change summary.
    BookChanges { payload: Value },
    /// A manifest received from the network.
    ManifestReceived {
        manifest: crate::consensus::Manifest,
    },
    /// A peer protocol message was received.
    PeerMessage { msg_type: String, detail: String },
}

impl WsEvent {
    pub fn to_json(&self, api_version: u32) -> Value {
        match self {
            WsEvent::LedgerClosed {
                ledger_seq,
                ledger_hash,
                tx_count,
                ledger_time,
                network_id,
                validated_ledgers,
                fee_base,
                reserve_base,
                reserve_inc,
            } => json!({
                "type":              "ledgerClosed",
                "ledger_index":      ledger_seq,
                "ledger_hash":       ledger_hash,
                "ledger_time":       ledger_time,
                "network_id":        network_id,
                "txn_count":         tx_count,
                "reserve_base":      reserve_base,
                "reserve_inc":       reserve_inc,
                "fee_base":          fee_base,
                "validated_ledgers": validated_ledgers,
            }),
            WsEvent::ServerStatus {
                ledger_seq,
                ledger_hash,
                network_id,
                peer_count,
                validated_ledgers,
                server_status,
                load_snapshot,
                base_fee,
            } => {
                let mut out = json!({
                    "type":              "serverStatus",
                    "server_status":     server_status,
                    "load_base":         load_snapshot.load_base,
                    "load_factor":       load_snapshot.load_factor(),
                    "load_factor_server": load_snapshot.load_factor_server(),
                    "base_fee":          base_fee,
                    "peers":             peer_count,
                    "ledger_index":      ledger_seq,
                    "ledger_hash":       ledger_hash,
                    "network_id":        network_id,
                    "validated_ledgers": validated_ledgers,
                });
                if let Some(local) = load_snapshot.load_factor_local() {
                    out["load_factor_local"] = json!(local);
                }
                if let Some(net) = load_snapshot.load_factor_net() {
                    out["load_factor_net"] = json!(net);
                }
                if let Some(cluster) = load_snapshot.load_factor_cluster() {
                    out["load_factor_cluster"] = json!(cluster);
                }
                out
            }
            WsEvent::Transaction {
                tx_record,
                ledger_hash,
                close_time,
                network_id,
                ..
            } => {
                let result_code = crate::ledger::ter::token_to_code(&tx_record.result)
                    .map(|r| r.code())
                    .unwrap_or(0);
                let mut out = json!({
                    "type":           "transaction",
                    "validated":      true,
                    "status":         "closed",
                    "ledger_index":   tx_record.ledger_seq,
                    "ledger_hash":    ledger_hash,
                    "engine_result":  tx_record.result,
                    "engine_result_code": result_code,
                    "engine_result_message": crate::ledger::ter::code_to_message(result_code),
                    "close_time_iso": crate::rpc::handlers::close_time_iso_string(*close_time),
                });
                if let Some(ctid) = crate::rpc::handlers::encode_ctid(
                    tx_record.ledger_seq,
                    tx_record.tx_index,
                    u32::from(*network_id),
                ) {
                    out["ctid"] = json!(ctid);
                }
                let hash_hex = hex::encode_upper(tx_record.hash);
                if api_version >= 2 {
                    if let Ok(parsed) = crate::transaction::parse_blob(&tx_record.blob) {
                        out["tx_json"] = crate::rpc::handlers::parsed_tx_json(&parsed);
                    } else {
                        out["tx_blob"] = json!(hex::encode_upper(&tx_record.blob));
                    }
                    out["hash"] = json!(hash_hex);
                    out["meta"] =
                        crate::rpc::handlers::metadata_json(&tx_record.meta, &tx_record.result);
                } else {
                    if let Ok(parsed) = crate::transaction::parse_blob(&tx_record.blob) {
                        let mut tx_obj = crate::rpc::handlers::parsed_tx_json(&parsed);
                        tx_obj["hash"] = json!(hash_hex);
                        out["transaction"] = tx_obj;
                    } else {
                        out["transaction"] = json!({ "hash": hash_hex });
                    }
                    out["meta"] =
                        crate::rpc::handlers::metadata_json(&tx_record.meta, &tx_record.result);
                }
                out
            }
            WsEvent::ProposedTransaction {
                tx_blob,
                network_id,
                ..
            } => {
                let hash_hex =
                    hex::encode_upper(crate::transaction::serialize::tx_blob_hash(tx_blob));
                let mut out = json!({
                    "type": "transaction",
                    "validated": false,
                    "status": "proposed",
                    "network_id": network_id,
                });
                if api_version >= 2 {
                    if let Ok(parsed) = crate::transaction::parse_blob(tx_blob) {
                        out["tx_json"] = crate::rpc::handlers::parsed_tx_json(&parsed);
                    } else {
                        out["tx_blob"] = json!(hex::encode_upper(tx_blob));
                    }
                    out["hash"] = json!(hash_hex);
                } else if let Ok(parsed) = crate::transaction::parse_blob(tx_blob) {
                    let mut tx_obj = crate::rpc::handlers::parsed_tx_json(&parsed);
                    tx_obj["hash"] = json!(hash_hex);
                    out["transaction"] = tx_obj;
                } else {
                    out["transaction"] = json!({ "hash": hash_hex });
                }
                out
            }
            WsEvent::ValidationReceived {
                validation,
                network_id,
            } => {
                let mut out = json!({
                    "type": "validationReceived",
                    "validation_public_key": crate::crypto::base58::encode(
                        crate::crypto::base58::PREFIX_NODE_PUBLIC,
                        &validation.node_pubkey,
                    ),
                    "ledger_hash": hex::encode_upper(validation.ledger_hash),
                    "signature": hex::encode_upper(&validation.signature),
                    "full": validation.is_full(),
                    "flags": validation.flags,
                    "signing_time": validation.sign_time,
                    "data": hex::encode_upper(validation.to_bytes()),
                    "network_id": network_id,
                    "ledger_index": validation.ledger_seq,
                });
                if let Some(server_version) = validation.server_version {
                    out["server_version"] = json!(server_version.to_string());
                }
                if let Some(cookie) = validation.cookie {
                    out["cookie"] = json!(cookie.to_string());
                }
                if let Some(validated_hash) = validation.validated_hash {
                    out["validated_hash"] = json!(hex::encode_upper(validated_hash));
                }
                if let Some(close_time) = validation.close_time {
                    out["close_time"] = json!(close_time);
                }
                if api_version < 2 {
                    out["ledger_index"] = json!(validation.ledger_seq.to_string());
                }
                out
            }
            WsEvent::ConsensusPhase { consensus } => json!({
                "type": "consensusPhase",
                "consensus": consensus,
            }),
            WsEvent::PeerStatusChange { payload } => payload.clone(),
            WsEvent::BookChanges { payload } => payload.clone(),
            WsEvent::ManifestReceived { manifest } => {
                let mut out = json!({
                    "type": "manifestReceived",
                    "master_key": crate::crypto::base58::encode(
                        crate::crypto::base58::PREFIX_NODE_PUBLIC,
                        &manifest.master_pubkey,
                    ),
                    "seq": manifest.sequence,
                    "master_signature": hex::encode_upper(&manifest.master_sig),
                    "manifest": hex::encode_upper(manifest.to_bytes()),
                });
                if !manifest.signing_pubkey.is_empty() {
                    out["signing_key"] = json!(crate::crypto::base58::encode(
                        crate::crypto::base58::PREFIX_NODE_PUBLIC,
                        &manifest.signing_pubkey,
                    ));
                }
                if !manifest.signing_sig.is_empty() {
                    out["signature"] = json!(hex::encode_upper(&manifest.signing_sig));
                }
                if let Some(domain) = manifest.domain.as_ref() {
                    out["domain"] = json!(String::from_utf8_lossy(domain).to_string());
                }
                out
            }
            WsEvent::PeerMessage { msg_type, detail } => json!({
                "type":     "peerMessage",
                "msg_type": msg_type,
                "detail":   detail,
            }),
        }
    }
}

struct ClientSubscriptions {
    client_id: u64,
    streams: HashSet<String>,
    accounts: HashSet<String>,
    accounts_proposed: HashSet<String>,
    books: Vec<BookSubscription>,
    path_find: bool,
    api_version: u32,
}

impl ClientSubscriptions {
    fn new(client_id: u64) -> Self {
        Self {
            client_id,
            streams: HashSet::new(),
            accounts: HashSet::new(),
            accounts_proposed: HashSet::new(),
            books: Vec::new(),
            path_find: false,
            api_version: 1,
        }
    }
}

impl Default for ClientSubscriptions {
    fn default() -> Self {
        Self::new(0)
    }
}

#[derive(Clone)]
struct BookSubscription {
    direct: crate::ledger::BookKey,
    inverse: Option<crate::ledger::BookKey>,
}

impl BookSubscription {
    fn matches(&self, key: &crate::ledger::BookKey) -> bool {
        self.direct == *key || self.inverse.as_ref().is_some_and(|inverse| inverse == key)
    }
}

fn parse_ws_currency_spec(v: &Value) -> Result<([u8; 20], [u8; 20]), crate::rpc::RpcError> {
    let currency_str = v.get("currency").and_then(Value::as_str).unwrap_or("XRP");
    if currency_str == "XRP" {
        return Ok(([0u8; 20], [0u8; 20]));
    }
    let currency = crate::transaction::amount::Currency::from_code(currency_str)
        .map_err(|_| crate::rpc::RpcError::invalid_params("invalid currency"))?;
    let issuer_str = v
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| crate::rpc::RpcError::invalid_params("issuer required for non-XRP"))?;
    let issuer = crate::crypto::base58::decode_account(issuer_str)
        .map_err(|_| crate::rpc::RpcError::invalid_params("invalid issuer"))?;
    Ok((currency.code, issuer))
}

fn parse_book_subscription(book: &Value) -> Result<BookSubscription, crate::rpc::RpcError> {
    if !book.is_object() {
        return Err(crate::rpc::RpcError::invalid_params("Invalid parameters."));
    }
    let taker_pays = parse_ws_currency_spec(
        book.get("taker_pays")
            .ok_or_else(|| crate::rpc::RpcError::invalid_params("missing currency spec"))?,
    )?;
    let taker_gets = parse_ws_currency_spec(
        book.get("taker_gets")
            .ok_or_else(|| crate::rpc::RpcError::invalid_params("missing currency spec"))?,
    )?;
    let direct = crate::ledger::BookKey {
        pays_currency: taker_pays.0,
        pays_issuer: taker_pays.1,
        gets_currency: taker_gets.0,
        gets_issuer: taker_gets.1,
    };
    let inverse = book
        .get("both")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        .then(|| direct.inverse());
    Ok(BookSubscription { direct, inverse })
}

fn parsed_fields_amount(
    fields: &[crate::ledger::meta::ParsedField],
    field_code: u16,
) -> Option<crate::transaction::amount::Amount> {
    let field = fields
        .iter()
        .find(|field| field.type_code == 6 && field.field_code == field_code)?;
    crate::transaction::amount::Amount::from_bytes(&field.data)
        .ok()
        .map(|(amount, _)| amount)
}

fn affected_book_keys_from_nodes(
    nodes: &[crate::ledger::meta::AffectedNode],
) -> HashSet<crate::ledger::BookKey> {
    let mut books = HashSet::new();
    for node in nodes {
        if node.entry_type != 0x006F {
            continue;
        }
        for fields in [&node.fields, &node.previous_fields] {
            let Some(taker_pays) = parsed_fields_amount(fields, 4) else {
                continue;
            };
            let Some(taker_gets) = parsed_fields_amount(fields, 5) else {
                continue;
            };
            books.insert(crate::ledger::BookKey::from_amounts(
                &taker_pays,
                &taker_gets,
            ));
        }
    }
    books
}

fn tx_matches_book_subscription(
    subscriptions: &[BookSubscription],
    tx_record: &crate::ledger::history::TxRecord,
) -> bool {
    if subscriptions.is_empty() {
        return false;
    }
    let (_, nodes) = crate::ledger::meta::parse_metadata_with_index(&tx_record.meta);
    let books = affected_book_keys_from_nodes(&nodes);
    subscriptions
        .iter()
        .any(|subscription| books.iter().any(|book| subscription.matches(book)))
}

fn event_matches_subscriptions(evt: &WsEvent, subscriptions: &ClientSubscriptions) -> bool {
    match evt {
        WsEvent::LedgerClosed { .. } => subscriptions.streams.contains("ledger"),
        WsEvent::ServerStatus { .. } => subscriptions.streams.contains("server"),
        WsEvent::Transaction {
            accounts,
            tx_record,
            ..
        } => {
            subscriptions.streams.contains("transactions")
                || accounts
                    .iter()
                    .any(|acct| subscriptions.accounts.contains(acct))
                || tx_matches_book_subscription(&subscriptions.books, tx_record)
        }
        WsEvent::ProposedTransaction { accounts, .. } => {
            subscriptions.streams.contains("transactions_proposed")
                || accounts
                    .iter()
                    .any(|acct| subscriptions.accounts_proposed.contains(acct))
        }
        WsEvent::ValidationReceived { .. } => subscriptions.streams.contains("validations"),
        WsEvent::ConsensusPhase { .. } => subscriptions.streams.contains("consensus"),
        WsEvent::PeerStatusChange { .. } => subscriptions.streams.contains("peer_status"),
        WsEvent::BookChanges { .. } => subscriptions.streams.contains("book_changes"),
        WsEvent::ManifestReceived { .. } => subscriptions.streams.contains("manifests"),
        WsEvent::PeerMessage { .. } => subscriptions.streams.contains("peer_messages"),
    }
}

/// Maximum concurrent WebSocket connections.
const MAX_WS_CONNECTIONS: usize = 1000;

/// Run the WebSocket server (takes the broadcast sender so each client gets a receiver).
pub async fn run_ws_server_with_sender(
    addr: SocketAddr,
    enable_tls: bool,
    state: Arc<tokio::sync::RwLock<crate::node::SharedState>>,
    event_tx: broadcast::Sender<WsEvent>,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("WebSocket bind failed on {addr}: {e}");
            return;
        }
    };
    let tls_acceptor = if enable_tls {
        match crate::tls::TlsConfig::new_self_signed() {
            Ok(cfg) => Some(TlsAcceptor::from(cfg.server)),
            Err(err) => {
                warn!("WebSocket TLS setup failed on {addr}: {err}; serving ws:// only");
                None
            }
        }
    } else {
        None
    };
    info!(
        "WebSocket server on {addr}{}",
        if tls_acceptor.is_some() {
            " (accepting ws:// and wss://)"
        } else {
            " (accepting ws://)"
        }
    );

    let conn_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("WS accept error: {e}");
                continue;
            }
        };

        let current = conn_count.load(std::sync::atomic::Ordering::Relaxed);
        if current >= MAX_WS_CONNECTIONS {
            warn!("WS connection limit reached ({MAX_WS_CONNECTIONS}) — rejecting {addr}");
            continue;
        }
        conn_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let state = state.clone();
        let event_rx = event_tx.subscribe();
        let count = conn_count.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_ws_client(stream, tls_acceptor, state, event_rx).await {
                warn!("WS client {addr} error: {e}");
            }
            count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}

fn stream_looks_like_tls(peek: &[u8]) -> bool {
    matches!(peek.first(), Some(0x16))
}

async fn handle_ws_client(
    stream: TcpStream,
    tls_acceptor: Option<TlsAcceptor>,
    state: Arc<tokio::sync::RwLock<crate::node::SharedState>>,
    event_rx: broadcast::Receiver<WsEvent>,
) -> anyhow::Result<()> {
    let mut peek = [0u8; 1];
    let peeked = stream.peek(&mut peek).await?;
    if stream_looks_like_tls(&peek[..peeked]) {
        let acceptor = tls_acceptor
            .ok_or_else(|| anyhow::anyhow!("TLS WebSocket requested but WSS is disabled"))?;
        let tls_stream = acceptor.accept(stream).await?;
        handle_ws_stream(tls_stream, state, event_rx).await
    } else {
        handle_ws_stream(stream, state, event_rx).await
    }
}

async fn handle_ws_stream<S>(
    stream: S,
    state: Arc<tokio::sync::RwLock<crate::node::SharedState>>,
    mut event_rx: broadcast::Receiver<WsEvent>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ws_stream = tokio_tungstenite::accept_async(stream).await?;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Track subscriptions for this client
    let mut subscriptions = ClientSubscriptions::new(
        NEXT_WS_CLIENT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    );

    loop {
        tokio::select! {
            // Client sends a message (request or subscribe)
            msg = ws_rx.next() => {
                let msg = match msg {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => { warn!("WS read error: {e}"); break; }
                    None => break, // client disconnected
                };

                if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
                    let req_json: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => {
                            let out = tokio_tungstenite::tungstenite::Message::Text(
                                response_err(
                                    crate::rpc::RpcError::invalid_params("Invalid parameters."),
                                    Value::Null,
                                ).to_string()
                            );
                            ws_tx.send(out).await?;
                            continue;
                        }
                    };
                    let command = req_json.get("command")
                        .or_else(|| req_json.get("method"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let is_subscription = matches!(command, "subscribe" | "unsubscribe");

                    let reply = if is_subscription {
                        let shared = state.read().await;
                        let mut ctx = shared.ctx.clone();
                        hydrate_ws_read_context(&shared, &mut ctx);
                        let peer_count = ctx.peer_count;
                        handle_ws_message(
                            &text,
                            &mut ctx,
                            peer_count,
                            &mut subscriptions,
                        )
                    } else {
                        match crate::rpc::RpcRequest::parse(text.as_bytes()) {
                            Ok(rpc_req) if crate::rpc::needs_write(&rpc_req.method) => {
                                let mut shared = state.write().await;
                                shared.ctx.peer_count = shared.peer_count();
                                serde_json::to_value(crate::rpc::dispatch(rpc_req, &mut shared.ctx))
                                    .unwrap_or_else(|_| json!({"result":{"status":"error","error":"internal","error_message":"serialization failed"}}))
                            }
                            Ok(rpc_req) => {
                                let shared = state.read().await;
                                let mut ctx = shared.ctx.clone();
                                hydrate_ws_read_context(&shared, &mut ctx);
                                serde_json::to_value(crate::rpc::dispatch_read(rpc_req, &ctx))
                                    .unwrap_or_else(|_| json!({"result":{"status":"error","error":"internal","error_message":"serialization failed"}}))
                            }
                            Err(_) => response_err(crate::rpc::RpcError::invalid_params("Invalid parameters."), Value::Null),
                        }
                    };
                    let out = tokio_tungstenite::tungstenite::Message::Text(reply.to_string());
                    ws_tx.send(out).await?;
                }
            }

            // Broadcast event from the node
            event = event_rx.recv() => {
                let evt = match event {
                    Ok(e) => e,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                };
                let should_send = event_matches_subscriptions(&evt, &subscriptions);
                if should_send {
                    let msg = tokio_tungstenite::tungstenite::Message::Text(
                        evt.to_json(subscriptions.api_version).to_string()
                    );
                    if ws_tx.send(msg).await.is_err() {
                        break;
                    }
                }

                if matches!(evt, WsEvent::LedgerClosed { .. }) {
                    if subscriptions.path_find {
                        let ctx = {
                            let shared = state.read().await;
                            let mut ctx = shared.ctx.clone();
                            hydrate_ws_read_context(&shared, &mut ctx);
                            ctx
                        };
                        let path_req = ctx.path_requests.as_ref().and_then(|manager| {
                            manager
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .request_for(subscriptions.client_id)
                        });
                        if let Some(path_req) = path_req {
                            if let Ok(update) = path_find_update(&path_req, &ctx) {
                                if let Some(manager) = ctx.path_requests.as_ref() {
                                    let mut guard =
                                        manager.lock().unwrap_or_else(|e| e.into_inner());
                                    guard.note_recompute();
                                    guard.upsert(subscriptions.client_id, path_req, &update);
                                }
                                let msg = tokio_tungstenite::tungstenite::Message::Text(
                                    update.to_string()
                                );
                                if ws_tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(manager) = {
        let shared = state.read().await;
        shared.ctx.path_requests.clone()
    } {
        manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .close(subscriptions.client_id);
    }

    Ok(())
}

fn hydrate_ws_read_context(shared: &crate::node::SharedState, ctx: &mut crate::rpc::NodeContext) {
    ctx.peer_count = shared.peer_count();
    ctx.object_count = 0;
    ctx.load_snapshot = shared.services.load_manager.snapshot();
    ctx.peerfinder_snapshot = Some(shared.services.peerfinder.snapshot(32));
    let mut cluster_snapshot = shared.services.cluster.snapshot(32);
    if let Some(reservations) = ctx.peer_reservations.as_ref() {
        let configured = reservations.lock().unwrap_or_else(|e| e.into_inner()).len();
        cluster_snapshot.configured = cluster_snapshot.configured.max(configured);
    }
    ctx.cluster_snapshot = Some(cluster_snapshot);
    ctx.resource_snapshot = Some(
        shared
            .services
            .resource_manager
            .snapshot(std::time::Instant::now(), 32),
    );
    ctx.path_request_snapshot = ctx.path_requests.as_ref().map(|manager| {
        manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot(32)
    });
    let inbound_snapshot = shared.services.inbound_transactions.snapshot(32);
    let tx_master_snapshot = shared.services.tx_master.snapshot(32);
    let pool = ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
    let complete_ledgers = ctx
        .history
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .complete_ledgers();
    let candidate_set_hash = pool.canonical_set_hash();
    ctx.tx_relay_metrics = Some(crate::rpc::TxRelayMetricsSnapshot {
        queued_transactions: pool.len(),
        peer_count: ctx.peer_count,
        max_queue_size: pool.metrics.max_queue_size(),
        escalation_multiplier: pool.metrics.escalation_multiplier,
        txns_expected: pool.metrics.txns_expected,
        candidate_set_hash: hex::encode_upper(candidate_set_hash),
        tracked_transactions: tx_master_snapshot.tracked,
        submitted_transactions: tx_master_snapshot.submitted_total,
        inbound_tracked: inbound_snapshot.tracked,
        accepted_transactions: inbound_snapshot.accepted_total,
        duplicate_transactions: inbound_snapshot.duplicate_total,
        relayed_transactions: inbound_snapshot.relayed_total,
        persisted_transactions: inbound_snapshot.persisted_total,
    });
    drop(pool);
    ctx.inbound_transactions_snapshot = Some(inbound_snapshot);
    ctx.tx_master_snapshot = Some(tx_master_snapshot);
    ctx.node_store_snapshot = shared.services.node_store_snapshot();
    ctx.fetch_pack_snapshot = shared.services.fetch_pack_snapshot();
    let mut ledger_master_snapshot = shared.services.ledger_master.snapshot();
    if ledger_master_snapshot.validated_seq == 0 {
        ledger_master_snapshot.validated_seq = ctx.ledger_header.sequence;
        ledger_master_snapshot.validated_hash = ctx.ledger_hash.clone();
        ledger_master_snapshot.open_ledger_seq = ctx.ledger_seq.saturating_add(1);
        ledger_master_snapshot.complete_ledgers = complete_ledgers;
        ledger_master_snapshot.last_close_time = ctx.ledger_header.close_time;
        ledger_master_snapshot.queued_transactions = ctx
            .tx_relay_metrics
            .as_ref()
            .map(|metrics| metrics.queued_transactions)
            .unwrap_or(0);
        ledger_master_snapshot.candidate_set_hash = hex::encode_upper(candidate_set_hash);
    }
    ctx.ledger_master_snapshot = Some(ledger_master_snapshot);
    ctx.network_ops_snapshot = Some(crate::network::ops::NetworkOpsSnapshot::from_context(ctx));
}

fn handle_ws_message(
    text: &str,
    ctx: &mut crate::rpc::NodeContext,
    peer_count: usize,
    subscriptions: &mut ClientSubscriptions,
) -> Value {
    let req: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            return response_err(
                crate::rpc::RpcError::invalid_params("Invalid parameters."),
                Value::Null,
            )
        }
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);

    let command = req
        .get("command")
        .or_else(|| req.get("method"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if let Some(api_version) = req.get("api_version") {
        let version = api_version
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| crate::rpc::RpcError::invalid_params("Invalid field 'api_version'."));
        match version {
            Ok(v) => subscriptions.api_version = v,
            Err(err) => return response_err(err, id),
        }
    }

    match command {
        "subscribe" => {
            match apply_subscription_change(&req, ctx, peer_count, subscriptions, true) {
                Ok(result) => response_ok(result, id),
                Err(err) => response_err(err, id),
            }
        }
        "unsubscribe" => {
            match apply_subscription_change(&req, ctx, peer_count, subscriptions, false) {
                Ok(result) => response_ok(result, id),
                Err(err) => response_err(err, id),
            }
        }
        "path_find" => handle_ws_path_find(&req, ctx, subscriptions, id),
        _ => {
            // Dispatch as a normal RPC request
            match crate::rpc::RpcRequest::parse(text.as_bytes()) {
                Ok(rpc_req) => serde_json::from_str(&crate::rpc::dispatch(rpc_req, ctx).to_json())
                    .unwrap_or(json!({"error": "internal"})),
                Err(_) => response_err(
                    crate::rpc::RpcError::invalid_params("Invalid parameters."),
                    id,
                ),
            }
        }
    }
}

fn path_find_update(
    req: &Value,
    ctx: &crate::rpc::NodeContext,
) -> Result<Value, crate::rpc::RpcError> {
    crate::rpc::handlers::path_find_update_result(req, ctx)
}

fn handle_ws_path_find(
    req: &Value,
    ctx: &crate::rpc::NodeContext,
    subscriptions: &mut ClientSubscriptions,
    id: Value,
) -> Value {
    let Some(manager) = ctx.path_requests.as_ref() else {
        return response_err(
            crate::rpc::RpcError::internal("path request manager unavailable"),
            id,
        );
    };
    let subcommand = req
        .get("subcommand")
        .and_then(Value::as_str)
        .unwrap_or("status");

    match subcommand {
        "create" => match path_find_update(req, ctx) {
            Ok(result) => {
                let mut guard = manager.lock().unwrap_or_else(|e| e.into_inner());
                guard.upsert(subscriptions.client_id, req.clone(), &result);
                subscriptions.path_find = true;
                response_ok(result, id)
            }
            Err(err) => response_err(err, id),
        },
        "status" => {
            let stored = manager
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .request_for(subscriptions.client_id);
            let Some(stored) = stored else {
                return response_err(
                    crate::rpc::RpcError::invalid_params("No active path_find request."),
                    id,
                );
            };
            match path_find_update(&stored, ctx) {
                Ok(result) => {
                    manager.lock().unwrap_or_else(|e| e.into_inner()).upsert(
                        subscriptions.client_id,
                        stored,
                        &result,
                    );
                    subscriptions.path_find = true;
                    response_ok(result, id)
                }
                Err(err) => response_err(err, id),
            }
        }
        "close" => {
            manager
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .close(subscriptions.client_id);
            subscriptions.path_find = false;
            response_ok(json!({"closed": true}), id)
        }
        _ => response_err(
            crate::rpc::RpcError::invalid_params("Unsupported path_find subcommand."),
            id,
        ),
    }
}

fn response_ok(result: Value, id: Value) -> Value {
    serde_json::to_value(crate::rpc::RpcResponse::ok(result, id))
        .unwrap_or_else(|_| json!({"result":{"status":"error","error":"internal","error_message":"serialization failed"}}))
}

fn response_err(error: crate::rpc::RpcError, id: Value) -> Value {
    serde_json::to_value(crate::rpc::RpcResponse::err(error, id))
        .unwrap_or_else(|_| json!({"result":{"status":"error","error":"internal","error_message":"serialization failed"}}))
}

fn act_malformed(detail: &str) -> crate::rpc::RpcError {
    crate::rpc::RpcError {
        code: "actMalformed",
        error_code: 35,
        message: detail.to_string(),
        extra: None,
    }
}

fn apply_subscription_change(
    req: &Value,
    ctx: &crate::rpc::NodeContext,
    peer_count: usize,
    subscriptions: &mut ClientSubscriptions,
    subscribe: bool,
) -> Result<Value, crate::rpc::RpcError> {
    let has_streams = req.get("streams").is_some();
    let has_accounts = req.get("accounts").is_some();
    let has_accounts_proposed = req.get("accounts_proposed").is_some();
    let has_books = req.get("books").is_some();
    if !has_streams && !has_accounts && !has_accounts_proposed && !has_books {
        return Err(crate::rpc::RpcError::invalid_params("Invalid parameters."));
    }

    let mut result = json!({
        "status": "success",
        "type": "response",
    });

    if let Some(streams_value) = req.get("streams") {
        let streams = streams_value
            .as_array()
            .ok_or_else(|| crate::rpc::RpcError::invalid_params("Invalid parameters."))?;
        for stream in streams {
            let Some(name) = stream.as_str() else {
                return Err(crate::rpc::RpcError::invalid_params("Invalid parameters."));
            };
            if !SUPPORTED_STREAMS.contains(&name) {
                return Err(crate::rpc::RpcError::invalid_params(
                    "Stream not supported.",
                ));
            }
            if name == "peer_status" && !ctx.admin_rpc_enabled {
                return Err(crate::rpc::RpcError::forbidden(
                    "peer_status stream requires admin RPC",
                ));
            }
            if subscribe {
                subscriptions.streams.insert(name.to_string());
            } else {
                subscriptions.streams.remove(name);
            }
        }
    }

    if let Some(accounts_value) = req.get("accounts") {
        let accounts = accounts_value
            .as_array()
            .ok_or_else(|| crate::rpc::RpcError::invalid_params("Invalid parameters."))?;
        if accounts.is_empty() {
            return Err(act_malformed("Account malformed."));
        }
        for acct in accounts {
            let Some(account) = acct.as_str() else {
                return Err(act_malformed("Account malformed."));
            };
            if crate::crypto::base58::decode_account(account).is_err() {
                return Err(act_malformed("Account malformed."));
            }
            if subscribe {
                subscriptions.accounts.insert(account.to_string());
            } else {
                subscriptions.accounts.remove(account);
            }
        }
    }

    if let Some(accounts_value) = req.get("accounts_proposed") {
        let accounts = accounts_value
            .as_array()
            .ok_or_else(|| crate::rpc::RpcError::invalid_params("Invalid parameters."))?;
        if accounts.is_empty() {
            return Err(act_malformed("Account malformed."));
        }
        for acct in accounts {
            let Some(account) = acct.as_str() else {
                return Err(act_malformed("Account malformed."));
            };
            if crate::crypto::base58::decode_account(account).is_err() {
                return Err(act_malformed("Account malformed."));
            }
            if subscribe {
                subscriptions.accounts_proposed.insert(account.to_string());
            } else {
                subscriptions.accounts_proposed.remove(account);
            }
        }
    }

    if let Some(books_value) = req.get("books") {
        let books = books_value
            .as_array()
            .ok_or_else(|| crate::rpc::RpcError::invalid_params("Invalid parameters."))?;
        let mut offers = Vec::new();
        for book in books {
            let parsed_book = parse_book_subscription(book)?;
            let snapshot = book
                .get("snapshot")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let mut params = book.clone();
            if let Some(map) = params.as_object_mut() {
                map.entry("ledger_index".to_string())
                    .or_insert_with(|| json!(ctx.ledger_seq));
            }
            if subscribe {
                if !subscriptions.books.iter().any(|existing| {
                    existing.direct == parsed_book.direct && existing.inverse == parsed_book.inverse
                }) {
                    subscriptions.books.push(parsed_book.clone());
                }
            } else {
                subscriptions.books.retain(|existing| {
                    !(existing.direct == parsed_book.direct
                        && existing.inverse == parsed_book.inverse)
                });
            }
            if snapshot {
                let snapshot_res = crate::rpc::handlers::book_offers(&params, ctx)?;
                if let Some(arr) = snapshot_res.get("offers").and_then(Value::as_array) {
                    offers.extend(arr.iter().cloned());
                }
            }
        }
        if !offers.is_empty() {
            result["offers"] = json!(offers);
        } else if subscribe
            && books
                .iter()
                .any(|b| b.get("snapshot").and_then(Value::as_bool).unwrap_or(false))
        {
            result["offers"] = json!([]);
        }
    }

    if subscriptions.streams.contains("ledger") {
        result["ledger_index"] = json!(ctx.ledger_seq);
        result["ledger_hash"] = json!(ctx.ledger_hash);
        result["network_id"] = json!(ctx.network_id);
    }

    if subscriptions.streams.contains("server") {
        result["server_status"] = json!("full");
        result["peers"] = json!(peer_count);
        result["network_id"] = json!(ctx.network_id);
    }

    Ok(result)
}

pub fn subscription_change_snapshot(
    params: &Value,
    ctx: &crate::rpc::NodeContext,
    subscribe: bool,
) -> Result<Value, crate::rpc::RpcError> {
    let mut subscriptions = ClientSubscriptions::new(0);
    apply_subscription_change(params, ctx, ctx.peer_count, &mut subscriptions, subscribe)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ws_ctx() -> crate::rpc::NodeContext {
        let mut ctx = crate::rpc::NodeContext::default();
        ctx.ledger_seq = 7;
        ctx.ledger_hash = "A".repeat(64);
        ctx.network_id = 21338;
        ctx
    }

    #[test]
    fn subscribe_ledger_returns_envelope_and_snapshot() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":5,"command":"subscribe","streams":["ledger"]}"#,
            &mut ctx,
            9,
            &mut subs,
        );
        assert_eq!(reply["id"], 5);
        assert_eq!(reply["result"]["status"], "success");
        assert_eq!(reply["result"]["type"], "response");
        assert_eq!(reply["result"]["ledger_index"], 7);
        assert_eq!(reply["result"]["network_id"], 21338);
    }

    #[test]
    fn subscribe_requires_valid_parameters() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(r#"{"id":1,"command":"subscribe"}"#, &mut ctx, 0, &mut subs);
        assert_eq!(reply["result"]["status"], "error");
        assert_eq!(reply["result"]["error"], "invalidParams");
    }

    #[test]
    fn subscribe_rejects_non_array_streams() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":2,"command":"subscribe","streams":"ledger"}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "error");
        assert_eq!(reply["result"]["error"], "invalidParams");
    }

    #[test]
    fn subscribe_rejects_empty_accounts() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":3,"command":"subscribe","accounts":[]}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "error");
        assert_eq!(reply["result"]["error"], "actMalformed");
    }

    #[test]
    fn subscribe_rejects_unsupported_streams() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":4,"command":"subscribe","streams":["not_real"]}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "error");
        assert_eq!(reply["result"]["error"], "invalidParams");
    }

    #[test]
    fn subscribe_accepts_new_streams() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":41,"command":"subscribe","streams":["validations","consensus","book_changes","manifests","transactions_proposed"]}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "success");
        assert!(subs.streams.contains("validations"));
        assert!(subs.streams.contains("consensus"));
        assert!(subs.streams.contains("book_changes"));
        assert!(subs.streams.contains("manifests"));
        assert!(subs.streams.contains("transactions_proposed"));
    }

    #[test]
    fn subscribe_rejects_peer_status_without_admin() {
        let mut ctx = ws_ctx();
        ctx.admin_rpc_enabled = false;
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":42,"command":"subscribe","streams":["peer_status"]}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "error");
        assert_eq!(reply["result"]["error"], "forbidden");
    }

    #[test]
    fn subscribe_accepts_peer_status_for_admin() {
        let mut ctx = ws_ctx();
        ctx.admin_rpc_enabled = true;
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":43,"command":"subscribe","streams":["peer_status"]}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "success");
        assert!(subs.streams.contains("peer_status"));
    }

    #[test]
    fn tls_detection_identifies_client_hello() {
        assert!(stream_looks_like_tls(&[0x16]));
        assert!(stream_looks_like_tls(&[0x16, 0x03, 0x01]));
    }

    #[test]
    fn tls_detection_leaves_plain_http_alone() {
        assert!(!stream_looks_like_tls(b"GET /"));
        assert!(!stream_looks_like_tls(&[]));
    }

    #[test]
    fn subscribe_accepts_accounts_proposed() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":6,"command":"subscribe","accounts_proposed":["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"]}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "success");
        assert!(subs
            .accounts_proposed
            .contains("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"));
    }

    #[test]
    fn subscribe_accepts_live_book_streams() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":7,"command":"subscribe","books":[{"taker_pays":{"currency":"XRP"},"taker_gets":{"currency":"USD","issuer":"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"}}]}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "success");
        assert_eq!(subs.books.len(), 1);
    }

    #[test]
    fn affected_books_extract_offer_book_keys() {
        let usd = crate::transaction::amount::Amount::Iou {
            currency: crate::transaction::amount::Currency::from_code("USD").unwrap(),
            issuer: crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")
                .unwrap(),
            value: crate::transaction::amount::IouValue::from_f64(10.0),
        };
        let xrp = crate::transaction::amount::Amount::Xrp(1_000_000);
        let node = crate::ledger::meta::AffectedNode {
            action: crate::ledger::meta::Action::Modified,
            entry_type: 0x006F,
            ledger_index: [0u8; 32],
            fields: vec![
                crate::ledger::meta::ParsedField {
                    type_code: 6,
                    field_code: 4,
                    data: xrp.to_bytes(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 6,
                    field_code: 5,
                    data: usd.to_bytes(),
                },
            ],
            previous_fields: Vec::new(),
            prev_txn_id: None,
            prev_txn_lgrseq: None,
        };
        let books = affected_book_keys_from_nodes(&[node]);
        assert!(books.contains(&crate::ledger::BookKey::from_amounts(&xrp, &usd)));
    }

    #[test]
    fn subscribe_rejects_invalid_api_version() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":8,"command":"subscribe","streams":["ledger"],"api_version":5000000000}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "error");
        assert_eq!(reply["result"]["error"], "invalidParams");
    }

    #[test]
    fn accounts_proposed_only_matches_proposed_transactions() {
        let mut subs = ClientSubscriptions::default();
        subs.accounts_proposed
            .insert("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".to_string());

        let proposed = WsEvent::ProposedTransaction {
            tx_blob: vec![0u8; 4],
            network_id: 21338,
            accounts: vec!["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".to_string()],
        };
        assert!(event_matches_subscriptions(&proposed, &subs));

        let validated = WsEvent::Transaction {
            tx_record: crate::ledger::history::TxRecord {
                blob: vec![],
                meta: vec![],
                hash: [0u8; 32],
                ledger_seq: 1,
                tx_index: 0,
                result: "tesSUCCESS".to_string(),
            },
            ledger_hash: "A".repeat(64),
            close_time: 0,
            network_id: 21338,
            accounts: vec!["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".to_string()],
        };
        assert!(!event_matches_subscriptions(&validated, &subs));
    }

    #[test]
    fn validation_event_uses_string_ledger_index_for_api_v1() {
        let mut validation =
            crate::consensus::Validation::new_unsigned(99, [1u8; 32], 123, true, vec![0x02; 33]);
        validation.signature = vec![0xAA; 64];
        let event = WsEvent::ValidationReceived {
            validation,
            network_id: 21338,
        };
        let out = event.to_json(1);
        assert_eq!(out["type"], "validationReceived");
        assert_eq!(out["ledger_index"], "99");
    }

    #[test]
    fn server_status_event_uses_live_load_fields() {
        let mut load = crate::network::load::LoadSnapshot::default();
        load.local_fee = crate::network::load::LOAD_BASE * 2;
        let event = WsEvent::ServerStatus {
            ledger_seq: 9,
            ledger_hash: "B".repeat(64),
            network_id: 21338,
            peer_count: 3,
            validated_ledgers: "1-9".to_string(),
            server_status: "syncing".to_string(),
            load_snapshot: load,
            base_fee: 10,
        };
        let out = event.to_json(2);
        assert_eq!(out["type"], "serverStatus");
        assert_eq!(out["server_status"], "syncing");
        assert_eq!(out["load_base"], json!(crate::network::load::LOAD_BASE));
        assert_eq!(
            out["load_factor"],
            json!(crate::network::load::LOAD_BASE * 2)
        );
        assert_eq!(
            out["load_factor_local"],
            json!(crate::network::load::LOAD_BASE * 2)
        );
    }

    #[test]
    fn path_find_create_status_and_close_round_trip() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let req = r#"{"id":9,"command":"path_find","subcommand":"create","source_account":"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","destination_account":"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","destination_amount":"1"}"#;
        let create = handle_ws_message(req, &mut ctx, 0, &mut subs);
        assert_eq!(create["result"]["status"], "success");
        assert!(create["result"]["alternatives"].is_array());
        assert!(subs.path_find);

        let status = handle_ws_message(
            r#"{"id":10,"command":"path_find","subcommand":"status"}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(status["result"]["status"], "success");
        assert_eq!(status["result"]["type"], "path_find");

        let close = handle_ws_message(
            r#"{"id":11,"command":"path_find","subcommand":"close"}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(close["result"]["status"], "success");
        assert!(!subs.path_find);
    }

    #[test]
    fn path_find_status_requires_active_request() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let status = handle_ws_message(
            r#"{"id":12,"command":"path_find","subcommand":"status"}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(status["result"]["status"], "error");
        assert_eq!(status["result"]["error"], "invalidParams");
    }
}
