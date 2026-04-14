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

const SUPPORTED_STREAMS: &[&str] = &["ledger", "server", "transactions", "peer_messages"];

/// Events that can be broadcast to WebSocket subscribers.
#[derive(Debug, Clone)]
pub enum WsEvent {
    /// A new ledger was validated.
    LedgerClosed {
        ledger_seq:          u32,
        ledger_hash:         String,
        tx_count:            usize,
        ledger_time:         u64,
        network_id:          u32,
        validated_ledgers:   String,
        fee_base:            u64,
        reserve_base:        u64,
        reserve_inc:         u64,
    },
    /// Server status update.
    ServerStatus {
        ledger_seq:        u32,
        ledger_hash:       String,
        network_id:        u32,
        peer_count:        usize,
        validated_ledgers: String,
    },
    /// A transaction was validated (included in a closed ledger).
    Transaction {
        tx_record:   crate::ledger::history::TxRecord,
        ledger_hash: String,
        close_time:  u64,
        network_id:  u32,
        accounts:    Vec<String>,
    },
    /// A peer protocol message was received.
    PeerMessage {
        msg_type: String,
        detail:   String,
    },
}

impl WsEvent {
    pub fn to_json(&self, api_version: u32) -> Value {
        match self {
            WsEvent::LedgerClosed { ledger_seq, ledger_hash, tx_count, ledger_time, network_id, validated_ledgers, fee_base, reserve_base, reserve_inc } => json!({
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
            WsEvent::ServerStatus { ledger_seq, ledger_hash, network_id, peer_count, validated_ledgers } => {
                // rippled's serverStatus event includes fee/load fields.
                // We include what we have — load_factor always 1 for now.
                let _ = (ledger_seq, ledger_hash, network_id, validated_ledgers); // suppress unused
                json!({
                    "type":              "serverStatus",
                    "server_status":     if *peer_count > 0 { "full" } else { "disconnected" },
                    "load_base":         256,
                    "load_factor":       256,
                    "load_factor_server": 256,
                    "base_fee":          10,
                })
            }
            WsEvent::Transaction { tx_record, ledger_hash, close_time, network_id, .. } => {
                let result_code = crate::ledger::ter::token_to_code(&tx_record.result)
                    .map(|r| r.code()).unwrap_or(0);
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
                    out["meta"] = crate::rpc::handlers::metadata_json(&tx_record.meta, &tx_record.result);
                } else {
                    if let Ok(parsed) = crate::transaction::parse_blob(&tx_record.blob) {
                        let mut tx_obj = crate::rpc::handlers::parsed_tx_json(&parsed);
                        tx_obj["hash"] = json!(hash_hex);
                        out["transaction"] = tx_obj;
                    } else {
                        out["transaction"] = json!({ "hash": hash_hex });
                    }
                    out["meta"] = crate::rpc::handlers::metadata_json(&tx_record.meta, &tx_record.result);
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

#[derive(Default)]
struct ClientSubscriptions {
    streams: HashSet<String>,
    accounts: HashSet<String>,
    accounts_proposed: HashSet<String>,
    books: Vec<Value>,
    api_version: u32,
}

/// Maximum concurrent WebSocket connections.
const MAX_WS_CONNECTIONS: usize = 1000;

/// Run the WebSocket server (takes the broadcast sender so each client gets a receiver).
pub async fn run_ws_server_with_sender(
    addr:     SocketAddr,
    enable_tls: bool,
    state:    Arc<tokio::sync::RwLock<crate::node::SharedState>>,
    event_tx: broadcast::Sender<WsEvent>,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => { warn!("WebSocket bind failed on {addr}: {e}"); return; }
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
            Err(e) => { warn!("WS accept error: {e}"); continue; }
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
    stream:   TcpStream,
    tls_acceptor: Option<TlsAcceptor>,
    state:    Arc<tokio::sync::RwLock<crate::node::SharedState>>,
    event_rx: broadcast::Receiver<WsEvent>,
) -> anyhow::Result<()> {
    let mut peek = [0u8; 1];
    let peeked = stream.peek(&mut peek).await?;
    if stream_looks_like_tls(&peek[..peeked]) {
        let acceptor = tls_acceptor.ok_or_else(|| anyhow::anyhow!(
            "TLS WebSocket requested but WSS is disabled"
        ))?;
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
    let mut subscriptions = ClientSubscriptions::default();

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
                        ctx.peer_count = shared.peer_count();
                        ctx.object_count = 0;
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
                                ctx.peer_count = shared.peer_count();
                                ctx.object_count = 0;
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
                let should_send = match &evt {
                    WsEvent::LedgerClosed { .. } => subscriptions.streams.contains("ledger"),
                    WsEvent::ServerStatus { .. } => subscriptions.streams.contains("server"),
                    WsEvent::Transaction { accounts, .. }  => {
                        subscriptions.streams.contains("transactions")
                            || accounts.iter().any(|acct| subscriptions.accounts.contains(acct))
                            || accounts.iter().any(|acct| subscriptions.accounts_proposed.contains(acct))
                    }
                    WsEvent::PeerMessage { .. }  => subscriptions.streams.contains("peer_messages"),
                };
                if should_send {
                    let msg = tokio_tungstenite::tungstenite::Message::Text(
                        evt.to_json(subscriptions.api_version).to_string()
                    );
                    if ws_tx.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

fn handle_ws_message(
    text: &str,
    ctx: &mut crate::rpc::NodeContext,
    peer_count: usize,
    subscriptions: &mut ClientSubscriptions,
) -> Value {
    let req: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return response_err(crate::rpc::RpcError::invalid_params("Invalid parameters."), Value::Null),
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);

    let command = req.get("command")
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
        _ => {
            // Dispatch as a normal RPC request
            match crate::rpc::RpcRequest::parse(text.as_bytes()) {
                Ok(rpc_req) => serde_json::from_str(&crate::rpc::dispatch(rpc_req, ctx).to_json())
                    .unwrap_or(json!({"error": "internal"})),
                Err(_) => response_err(crate::rpc::RpcError::invalid_params("Invalid parameters."), id),
            }
        }
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
        let streams = streams_value.as_array()
            .ok_or_else(|| crate::rpc::RpcError::invalid_params("Invalid parameters."))?;
        for stream in streams {
            let Some(name) = stream.as_str() else {
                return Err(crate::rpc::RpcError::invalid_params("Invalid parameters."));
            };
            if !SUPPORTED_STREAMS.contains(&name) {
                return Err(crate::rpc::RpcError::invalid_params("Stream not supported."));
            }
            if subscribe {
                subscriptions.streams.insert(name.to_string());
            } else {
                subscriptions.streams.remove(name);
            }
        }
    }

    if let Some(accounts_value) = req.get("accounts") {
        let accounts = accounts_value.as_array()
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
        let _ = accounts_value.as_array()
            .ok_or_else(|| crate::rpc::RpcError::invalid_params("Invalid parameters."))?;
        return Err(crate::rpc::RpcError::invalid_params("accounts_proposed is not supported."));
    }

    if let Some(books_value) = req.get("books") {
        let books = books_value.as_array()
            .ok_or_else(|| crate::rpc::RpcError::invalid_params("Invalid parameters."))?;
        let mut offers = Vec::new();
        for book in books {
            if !book.is_object() {
                return Err(crate::rpc::RpcError::invalid_params("Invalid parameters."));
            }
            let snapshot = book.get("snapshot").and_then(Value::as_bool).unwrap_or(false);
            if subscribe && !snapshot {
                return Err(crate::rpc::RpcError::invalid_params("Live book subscriptions are not supported."));
            }
            let mut params = book.clone();
            if let Some(map) = params.as_object_mut() {
                map.entry("ledger_index".to_string())
                    .or_insert_with(|| json!(ctx.ledger_seq));
            }
            if subscribe {
                subscriptions.books.push(book.clone());
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
        } else if subscribe && books.iter().any(|b| b.get("snapshot").and_then(Value::as_bool).unwrap_or(false)) {
            result["offers"] = json!([]);
        }
        if !subscribe {
            subscriptions.books.clear();
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
        let reply = handle_ws_message(
            r#"{"id":1,"command":"subscribe"}"#,
            &mut ctx,
            0,
            &mut subs,
        );
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
            r#"{"id":4,"command":"subscribe","streams":["validations"]}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "error");
        assert_eq!(reply["result"]["error"], "invalidParams");
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
    fn subscribe_rejects_accounts_proposed_until_supported() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":6,"command":"subscribe","accounts_proposed":["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"]}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "error");
        assert_eq!(reply["result"]["error"], "invalidParams");
    }

    #[test]
    fn subscribe_rejects_live_book_streams_until_supported() {
        let mut ctx = ws_ctx();
        let mut subs = ClientSubscriptions::default();
        let reply = handle_ws_message(
            r#"{"id":7,"command":"subscribe","books":[{"taker_pays":{"currency":"XRP"},"taker_gets":{"currency":"USD","issuer":"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"}}]}"#,
            &mut ctx,
            0,
            &mut subs,
        );
        assert_eq!(reply["result"]["status"], "error");
        assert_eq!(reply["result"]["error"], "invalidParams");
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
}
