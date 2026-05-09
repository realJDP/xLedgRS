use std::sync::atomic::Ordering;

use prost::Message as _;
use xrpl::ledger::LedgerHeader;
use xrpl::network::handshake;
use xrpl::network::message::MessageType;
use xrpl::network::peer::PeerId;
use xrpl::network::relay;
use xrpl::node::{Node, NodeConfig, SyncTuningConfig};
use xrpl::proto;
use xrpl::storage::Storage;
use xrpl::sync_coordinator::SyncCoordinator;
use xrpl::sync_runtime::SyncRuntime;

fn test_header(seq: u32, byte: u8) -> LedgerHeader {
    LedgerHeader {
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

fn ledger_data(hash_byte: u8, cookie: Option<u32>, bytes: usize) -> proto::TmLedgerData {
    proto::TmLedgerData {
        ledger_hash: vec![hash_byte; 32],
        ledger_seq: 100,
        r#type: proto::TmLedgerInfoType::LiAsNode as i32,
        nodes: vec![proto::TmLedgerNode {
            nodedata: vec![hash_byte; bytes],
            nodeid: Some(vec![0; 33]),
        }],
        request_cookie: cookie,
        error: None,
    }
}

#[test]
fn acceptance_gate_is_hash_exact_and_accounts_for_busy_vs_invalid() {
    let runtime = SyncRuntime::new();
    let header = test_header(100, 0x11);
    let ledger_hash = header.hash;
    let syncer = SyncCoordinator::new(
        header.sequence,
        ledger_hash,
        header.account_hash,
        None,
        header,
    );
    assert!(runtime.install_syncer(syncer));

    let _held = runtime.lock_sync();
    assert!(runtime.gate_accepts_response(Some(&ledger_hash), None, false));

    let mut prefix_collision = ledger_hash;
    prefix_collision[31] ^= 0xff;
    assert!(!runtime.gate_accepts_response(Some(&prefix_collision), None, false));
    assert!(!runtime.gate_accepts_response(Some(&ledger_hash[..31]), None, true));

    let snap = runtime.metrics_snapshot();
    assert_eq!(snap.gate_accept_total, 1);
    assert_eq!(snap.gate_lock_busy_total, 2);
    assert_eq!(
        snap.gate_invalid_total, 0,
        "busy lock outcomes must not be reported as malformed/invalid responses"
    );

    drop(_held);
    runtime.clear_syncer();
    assert!(!runtime.gate_accepts_response(Some(&ledger_hash), None, false));
    let snap = runtime.metrics_snapshot();
    assert_eq!(snap.gate_invalid_total, 1);
    assert_eq!(snap.gate_reject_total, 1);
}

#[test]
fn queue_backpressure_keeps_target_cookie_work_ahead_of_noisy_peers() {
    let runtime = SyncRuntime::with_tuning(SyncTuningConfig {
        sync_data_queue_max: 4,
        sync_data_queue_per_ledger: 3,
        sync_data_queue_per_peer: 2,
        sync_data_queue_bytes: 2048,
        sync_data_batch_size: 8,
        ..SyncTuningConfig::default()
    });
    let header = test_header(100, 0x11);
    let mut syncer = SyncCoordinator::new(
        header.sequence,
        header.hash,
        header.account_hash,
        None,
        header,
    );
    syncer.peer.outstanding_cookies.insert(777);
    assert!(runtime.install_syncer(syncer));

    runtime.queue_sync_data(PeerId(1), ledger_data(0x22, Some(1), 800));
    runtime.queue_sync_data(PeerId(1), ledger_data(0x11, Some(10), 800));
    runtime.queue_sync_data(PeerId(1), ledger_data(0x11, Some(11), 800));
    runtime.queue_sync_data(PeerId(2), ledger_data(0x11, None, 800));
    runtime.queue_sync_data(PeerId(3), ledger_data(0x11, Some(777), 800));

    let batch = runtime.take_sync_data_batch();
    assert!(
        batch
            .iter()
            .any(|(peer, msg)| *peer == PeerId(3) && msg.request_cookie == Some(777)),
        "outstanding target-cookie response should survive queue pressure"
    );
    assert!(
        batch
            .iter()
            .all(|(_, msg)| msg.ledger_hash == vec![0x11; 32]),
        "stale ledger responses should be the first candidates dropped"
    );
    assert!(runtime.metrics_snapshot().dropped_responses_total > 0);
}

#[test]
fn malformed_sync_response_shapes_are_rejected_before_queue_acceptance() {
    let runtime = SyncRuntime::new();
    let header = test_header(200, 0x33);
    let syncer = SyncCoordinator::new(
        header.sequence,
        header.hash,
        header.account_hash,
        None,
        header,
    );
    assert!(runtime.install_syncer(syncer));

    assert!(!runtime.gate_accepts_response(None, None, false));
    assert!(!runtime.gate_accepts_response(Some(&[0x33; 31]), None, false));
    assert!(!runtime.gate_accepts_response(Some(&[0x44; 32]), None, true));

    let snap = runtime.metrics_snapshot();
    assert_eq!(snap.gate_accept_total, 0);
    assert_eq!(snap.gate_invalid_total, 3);
    assert_eq!(snap.gate_reject_total, 3);
}

#[test]
fn peer_wire_requests_preserve_production_protocol_shape() {
    let ledger_hash = [0x44; 32];
    let state = relay::encode_get_ledger_state(&ledger_hash, &[vec![0; 33]], 7, 1, None, 55);
    assert_eq!(state.msg_type, MessageType::GetLedger);
    let state_pb = proto::TmGetLedger::decode(state.payload.as_slice()).unwrap();
    assert_eq!(state_pb.itype, proto::TmLedgerInfoType::LiAsNode as i32);
    assert_eq!(state_pb.ltype, None);
    assert_eq!(state_pb.ledger_hash.as_deref(), Some(&ledger_hash[..]));
    assert_eq!(state_pb.ledger_seq, Some(55));
    assert_eq!(state_pb.request_cookie, Some(7));
    assert_eq!(state_pb.query_depth, Some(1));

    let closed = relay::encode_get_ledger_state(&[0; 32], &[], 9, 2, None, 0);
    let closed_pb = proto::TmGetLedger::decode(closed.payload.as_slice()).unwrap();
    assert_eq!(closed_pb.ltype, Some(proto::TmLedgerType::LtClosed as i32));
    assert_eq!(closed_pb.ledger_hash, None);
    assert_eq!(closed_pb.ledger_seq, None);

    let tx_set = relay::encode_get_tx_set_nodes(&ledger_hash, &[vec![0; 33]], 10, 3);
    let tx_set_pb = proto::TmGetLedger::decode(tx_set.payload.as_slice()).unwrap();
    assert_eq!(
        tx_set_pb.itype,
        proto::TmLedgerInfoType::LiTsCandidate as i32
    );
    assert_eq!(
        tx_set_pb.query_type,
        Some(proto::TmQueryType::QtIndirect as i32)
    );

    let miss = relay::encode_ledger_data_error(
        &ledger_hash,
        55,
        proto::TmLedgerInfoType::LiAsNode as i32,
        Some(7),
        proto::TmReplyError::ReNoNode,
    );
    let miss_pb = proto::TmLedgerData::decode(miss.payload.as_slice()).unwrap();
    assert_eq!(miss.msg_type, MessageType::LedgerData);
    assert_eq!(miss_pb.error, Some(proto::TmReplyError::ReNoNode as i32));
    assert_eq!(miss_pb.nodes.len(), 0);
}

#[test]
fn handshake_request_advertises_live_peer_metadata_and_compression() {
    let request =
        handshake::build_request(&[2; 33], &[3; 64], 0, &"AA".repeat(32), &"BB".repeat(32));
    assert!(request.contains("User-Agent: xLedgRSv2Beta/"));
    assert!(request.contains("Upgrade: XRPL/2.2"));
    assert!(request.contains("Connect-As: Peer"));
    assert!(request.contains("Crawl: public"));
    assert!(request.contains("Network-ID: 0"));
    assert!(request.contains("Network-Time:"));
    assert!(request.contains("Closed-Ledger:"));
    assert!(request.contains("Previous-Ledger:"));
    assert!(request.contains("X-Protocol-Ctl: compr=lz4"));

    let (info, consumed) = handshake::parse_request(request.as_bytes())
        .unwrap()
        .expect("complete request");
    assert_eq!(consumed, request.len());
    assert_eq!(info.network_id, Some(0));
    assert!(info.network_time.is_some());
    let closed = "AA".repeat(32);
    let previous = "BB".repeat(32);
    assert_eq!(info.closed_ledger.as_deref(), Some(closed.as_str()));
    assert_eq!(info.previous_ledger.as_deref(), Some(previous.as_str()));
    assert_eq!(info.features.as_deref(), Some("compr=lz4"));
}

#[test]
fn storage_restart_anchor_requires_consistent_header_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let header = test_header(500, 0x55);
    {
        let storage = Storage::open(dir.path()).unwrap();
        storage.persist_sync_anchor(&header).unwrap();
        storage.save_leaf_count(12_345).unwrap();
        storage.flush().unwrap();
    }

    let reopened = Storage::open(dir.path()).unwrap();
    assert!(reopened.is_sync_complete());
    assert_eq!(reopened.get_sync_ledger(), Some(header.sequence as u64));
    assert_eq!(reopened.get_sync_ledger_hash(), Some(header.hash));
    assert_eq!(reopened.get_sync_account_hash(), Some(header.account_hash));
    let reopened_header = reopened
        .get_sync_ledger_header()
        .expect("sync ledger header should survive restart");
    assert_eq!(reopened_header.sequence, header.sequence);
    assert_eq!(reopened_header.hash, header.hash);
    assert_eq!(reopened_header.account_hash, header.account_hash);
    assert_eq!(reopened.get_leaf_count(), Some(12_345));

    reopened.clear_sync_handoff().unwrap();
    reopened.flush().unwrap();
    drop(reopened);

    let cleared = Storage::open(dir.path()).unwrap();
    assert!(!cleared.is_sync_complete());
    assert!(cleared.get_sync_ledger_header().is_none());
    assert_eq!(
        cleared.get_leaf_count(),
        Some(12_345),
        "partial NuDB progress counters are retained after clearing handoff metadata"
    );
}

#[tokio::test]
async fn shutdown_signal_is_shared_with_runtime_context() {
    let node = Node::new(NodeConfig::default());
    let ctx_flag = {
        let state = node.state_ref().read().await;
        state
            .ctx
            .shutdown_requested
            .clone()
            .expect("node context should expose shutdown flag")
    };

    assert!(std::sync::Arc::ptr_eq(&ctx_flag, &node.shutdown_flag()));
    assert!(!ctx_flag.load(Ordering::SeqCst));
    node.signal_shutdown();
    assert!(ctx_flag.load(Ordering::SeqCst));

    let summary = node
        .join_background_tasks(std::time::Duration::from_millis(1))
        .await;
    assert_eq!(summary.completed, 0);
    assert_eq!(summary.aborted, 0);
    assert_eq!(summary.failed, 0);
}
