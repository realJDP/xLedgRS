//! xLedgRS purpose: Integration test coverage for release and parity safety.
//! Integration tests — spin up real nodes and verify they talk to each other.
//!
//! Each test binds on a random port (port 0) so tests never conflict.

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use xrpl::network::message::MessageType;
use xrpl::node::{Node, NodeConfig};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Bind on port 0 and return the actual address assigned by the OS.
async fn free_addr() -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}

/// Start a node and return (node, peer_addr, rpc_addr).
async fn start_node() -> (Arc<Node>, std::net::SocketAddr, std::net::SocketAddr) {
    let peer_addr = free_addr().await;
    let rpc_addr = free_addr().await;
    let config = NodeConfig {
        peer_addr,
        rpc_addr,
        ws_addr: free_addr().await,
        max_peers: 5,
        bootstrap: vec![],
        use_tls: false,
        data_dir: None,
        config_file: None,
        network_id: 0,
        max_sync: 0,
        rpc_sync: None,
        full_history_peers: vec![],
        ledger_history: xrpl::config::HistoryRetention::Count(256),
        fetch_depth: xrpl::config::HistoryRetention::Full,
        online_delete: None,
        standalone: false,
        enable_consensus_close_loop: false,
        validator_token: None,
        validation_seed: None,
        post_sync_checkpoint_script: None,
    };
    let node = Arc::new(Node::new(config));
    node.clone().start().await.unwrap();
    // Give the listeners a moment to bind
    tokio::time::sleep(Duration::from_millis(50)).await;
    (node, peer_addr, rpc_addr)
}

/// Send an HTTP JSON-RPC request and return the response body.
async fn rpc(addr: std::net::SocketAddr, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("RPC read timed out")
        .unwrap();

    // Strip HTTP headers
    let raw = &buf[..n];
    let body_start = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
    String::from_utf8_lossy(&raw[body_start + 4..]).to_string()
}

// ── RPC tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_rpc_server_responds() {
    let (_, _, rpc_addr) = start_node().await;
    let resp = rpc(rpc_addr, r#"{"method":"ping","params":[],"id":1}"#).await;
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["result"]["status"], "success");
}

#[tokio::test]
async fn test_rpc_server_info() {
    let (_, _, rpc_addr) = start_node().await;
    let resp = rpc(rpc_addr, r#"{"method":"server_info","params":[],"id":2}"#).await;
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["result"]["status"], "success");
    assert!(json["result"]["info"]["build_version"].is_string());
    let state = json["result"]["info"]["server_state"].as_str().unwrap();
    assert!(
        ["full", "tracking", "syncing", "disconnected"].contains(&state),
        "unexpected server_state: {}",
        state,
    );
}

#[tokio::test]
async fn test_rpc_unknown_method() {
    let (_, _, rpc_addr) = start_node().await;
    let resp = rpc(rpc_addr, r#"{"method":"not_a_method","params":[],"id":3}"#).await;
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["result"]["status"], "error");
    assert_eq!(json["result"]["error"], "unknownCmd");
}

#[tokio::test]
async fn test_rpc_fee() {
    let (_, _, rpc_addr) = start_node().await;
    let resp = rpc(rpc_addr, r#"{"method":"fee","params":[],"id":4}"#).await;
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["result"]["status"], "success");
    assert_eq!(json["result"]["drops"]["base_fee"], "10");
}

#[tokio::test]
async fn test_rpc_submit_real_tx() {
    use xrpl::crypto::keys::{KeyPair, Secp256k1KeyPair};
    use xrpl::transaction::{builder::TxBuilder, Amount};

    let (_, _, rpc_addr) = start_node().await;

    let kp =
        KeyPair::Secp256k1(Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap());
    let signed = TxBuilder::payment()
        .account(&kp)
        .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
        .unwrap()
        .amount(Amount::Xrp(1_000_000))
        .fee(12)
        .sequence(1)
        .sign(&kp)
        .unwrap();

    let body = format!(
        r#"{{"method":"submit","params":[{{"tx_blob":"{}"}}],"id":5}}"#,
        signed.blob_hex()
    );
    let resp = rpc(rpc_addr, &body).await;
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();

    assert_eq!(json["result"]["status"], "success");
    assert_eq!(json["result"]["engine_result"], "tesSUCCESS");

    let returned_hash = json["result"]["tx_json"]["hash"].as_str().unwrap();
    assert_eq!(
        returned_hash,
        signed.hash_hex(),
        "hash returned by RPC must match the one computed locally"
    );
}

// ── Peer connection tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_peer_listener_accepts_connection() {
    let (_, peer_addr, _) = start_node().await;

    // Opening a TCP connection should succeed.
    let result = timeout(Duration::from_secs(2), TcpStream::connect(peer_addr)).await;

    assert!(result.is_ok(), "connect timed out");
    assert!(result.unwrap().is_ok(), "connection refused");
}

#[tokio::test]
async fn test_peer_receives_handshake_request_on_inbound() {
    // An inbound peer should wait for the caller's HTTP upgrade request.
    let (_, peer_addr, _) = start_node().await;
    let mut stream = TcpStream::connect(peer_addr).await.unwrap();

    // The node should remain silent until it receives the upgrade request.
    let mut buf = [0u8; 256];
    let result = timeout(Duration::from_millis(200), stream.read(&mut buf)).await;
    // A timeout is expected because no data should be sent yet.
    assert!(
        result.is_err(),
        "node should not send anything before receiving our request"
    );
}

#[tokio::test]
async fn test_outbound_node_sends_handshake() {
    // Start a plain TCP listener to capture the outbound handshake.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = listener.local_addr().unwrap();

    // Start a node that dials the test listener.
    let peer_addr = free_addr().await;
    let rpc_addr = free_addr().await;
    let config = NodeConfig {
        peer_addr,
        rpc_addr,
        ws_addr: free_addr().await,
        max_peers: 5,
        bootstrap: vec![target_addr],
        use_tls: false,
        data_dir: None,
        config_file: None,
        network_id: 0,
        max_sync: 0,
        rpc_sync: None,
        full_history_peers: vec![],
        ledger_history: xrpl::config::HistoryRetention::Count(256),
        fetch_depth: xrpl::config::HistoryRetention::Full,
        online_delete: None,
        standalone: false,
        enable_consensus_close_loop: false,
        validator_token: None,
        validation_seed: None,
        post_sync_checkpoint_script: None,
    };
    let node = Arc::new(Node::new(config));
    node.clone().start().await.unwrap();

    // Accept the connection initiated by the node.
    let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("node did not dial us within 2 seconds")
        .unwrap();

    // The first payload should be the HTTP upgrade request.
    let mut buf = vec![0u8; 2048];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("did not receive handshake within 2 seconds")
        .unwrap();

    let received = String::from_utf8_lossy(&buf[..n]);
    assert!(received.contains("GET / HTTP/1.1"), "must be HTTP GET");
    assert!(received.contains("Upgrade: XRPL/"), "must upgrade to XRPL");
    assert!(
        received.contains("Connect-As: Peer"),
        "must identify as peer"
    );
    assert!(received.contains("Public-Key:"), "must include public key");
    assert!(
        received.contains("Session-Signature:"),
        "must include session signature"
    );
}

#[tokio::test]
async fn test_two_nodes_connect() {
    // Node A listens; Node B dials Node A
    let (_, peer_addr_a, rpc_addr_a) = start_node().await;

    let config_b = NodeConfig {
        peer_addr: free_addr().await,
        rpc_addr: free_addr().await,
        ws_addr: free_addr().await,
        max_peers: 5,
        bootstrap: vec![peer_addr_a],
        use_tls: false,
        data_dir: None,
        config_file: None,
        network_id: 0,
        max_sync: 0,
        rpc_sync: None,
        full_history_peers: vec![],
        ledger_history: xrpl::config::HistoryRetention::Count(256),
        fetch_depth: xrpl::config::HistoryRetention::Full,
        online_delete: None,
        standalone: false,
        enable_consensus_close_loop: false,
        validator_token: None,
        validation_seed: None,
        post_sync_checkpoint_script: None,
    };
    let node_b = Arc::new(Node::new(config_b));
    node_b.clone().start().await.unwrap();

    // Give them time to exchange handshakes
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Both nodes should still be running — query Node A's RPC to verify
    let resp = rpc(rpc_addr_a, r#"{"method":"ping","params":[],"id":99}"#).await;
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["result"]["status"], "success");
}

// ── TLS peer connection test ──────────────────────────────────────────────────

#[tokio::test]
async fn test_two_tls_nodes_connect() {
    // Node A listens with TLS; Node B dials Node A with TLS.
    // After TLS handshake each side signs the keying-material session hash
    // with its secp256k1 identity key — the real Session-Signature flow.
    let peer_addr_a = free_addr().await;
    let rpc_addr_a = free_addr().await;

    let node_a = Arc::new(Node::new(NodeConfig {
        peer_addr: peer_addr_a,
        rpc_addr: rpc_addr_a,
        ws_addr: free_addr().await,
        max_peers: 5,
        bootstrap: vec![],
        use_tls: true,
        data_dir: None,
        config_file: None,
        network_id: 0,
        max_sync: 0,
        rpc_sync: None,
        full_history_peers: vec![],
        ledger_history: xrpl::config::HistoryRetention::Count(256),
        fetch_depth: xrpl::config::HistoryRetention::Full,
        online_delete: None,
        standalone: false,
        enable_consensus_close_loop: false,
        validator_token: None,
        validation_seed: None,
        post_sync_checkpoint_script: None,
    }));
    node_a.clone().start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let node_b = Arc::new(Node::new(NodeConfig {
        peer_addr: free_addr().await,
        rpc_addr: free_addr().await,
        ws_addr: free_addr().await,
        max_peers: 5,
        bootstrap: vec![peer_addr_a],
        use_tls: true,
        data_dir: None,
        config_file: None,
        network_id: 0,
        max_sync: 0,
        rpc_sync: None,
        full_history_peers: vec![],
        ledger_history: xrpl::config::HistoryRetention::Count(256),
        fetch_depth: xrpl::config::HistoryRetention::Full,
        online_delete: None,
        standalone: false,
        enable_consensus_close_loop: false,
        validator_token: None,
        validation_seed: None,
        post_sync_checkpoint_script: None,
    }));
    node_b.clone().start().await.unwrap();

    // Give TLS handshake time to complete
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Both nodes should still be running — Node A's RPC should respond
    let resp = rpc(rpc_addr_a, r#"{"method":"ping","params":[],"id":42}"#).await;
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["result"]["status"], "success");
}

// ── Frame codec tests (end-to-end through real TCP) ───────────────────────────

#[tokio::test]
async fn test_message_framing_over_tcp() {
    use xrpl::network::message::{FrameDecoder, RtxpMessage};

    // Start a server that echoes framed messages back
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap();
        // Echo back
        s.write_all(&buf[..n]).await.unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();

    // Send three messages
    let msgs = vec![
        RtxpMessage::new(MessageType::Ping, b"hello".to_vec()),
        RtxpMessage::new(MessageType::Ping, b"world".to_vec()),
        RtxpMessage::new(MessageType::Transaction, vec![0xDE, 0xAD, 0xBE, 0xEF]),
    ];
    for m in &msgs {
        client.write_all(&m.encode()).await.unwrap();
    }

    // Read back
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .unwrap()
        .unwrap();

    let mut dec = FrameDecoder::new();
    dec.feed(&buf[..n]).unwrap();
    let received = dec.drain_messages().unwrap();

    assert_eq!(received.len(), msgs.len());
    for (got, want) in received.iter().zip(msgs.iter()) {
        assert_eq!(got.msg_type, want.msg_type);
        assert_eq!(got.payload, want.payload);
    }
}
