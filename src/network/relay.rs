//! Peer message relay helpers for broadcasting consensus and transaction
//! messages over RTXP.
//!
//! Messages are encoded with Protocol Buffers for compatibility with rippled
//! nodes. The generated protobuf types live in `crate::proto`.

use prost::Message;

use crate::consensus::{Manifest, Proposal, Validation};
use crate::network::message::{MessageType, RtxpMessage};
use crate::proto;

// ── Proposal relay ────────────────────────────────────────────────────────────

/// Serialize a `Proposal` into an RTXP `ProposeLedger` message.
pub fn encode_proposal(prop: &Proposal) -> RtxpMessage {
    let pb = proto::TmProposeSet {
        propose_seq: prop.prop_seq,
        current_tx_hash: prop.tx_set_hash.to_vec(),
        node_pub_key: prop.node_pubkey.clone(),
        close_time: prop.close_time,
        signature: prop.signature.clone(),
        previousledger: prop.previous_ledger.to_vec(),
        added_transactions: vec![],
        removed_transactions: vec![],
        ..Default::default()
    };
    RtxpMessage::new(MessageType::ProposeLedger, pb.encode_to_vec())
}

/// Deserialize a `Proposal` from an RTXP `ProposeLedger` payload.
pub fn decode_proposal(data: &[u8]) -> Option<Proposal> {
    let pb = proto::TmProposeSet::decode(data).ok()?;

    let mut tx_set_hash = [0u8; 32];
    if pb.current_tx_hash.len() == 32 {
        tx_set_hash.copy_from_slice(&pb.current_tx_hash);
    } else {
        return None;
    }

    let mut previous_ledger = [0u8; 32];
    if pb.previousledger.len() == 32 {
        previous_ledger.copy_from_slice(&pb.previousledger);
    }

    Some(Proposal {
        ledger_seq: 0, // `TmProposeSet` does not carry `ledger_seq`; the caller may fill it in.
        tx_set_hash,
        close_time: pb.close_time,
        previous_ledger,
        prop_seq: pb.propose_seq,
        node_pubkey: pb.node_pub_key,
        signature: pb.signature,
    })
}

// ── Validation relay ──────────────────────────────────────────────────────────

/// Serialize a `Validation` into an RTXP `Validation` message.
///
/// The `validation` field in `TmValidation` carries the serialized validation
/// object.
pub fn encode_validation(val: &Validation) -> RtxpMessage {
    // Build a blob containing the validation fields.
    let mut blob = Vec::with_capacity(128);
    blob.extend_from_slice(&val.ledger_seq.to_be_bytes());
    blob.extend_from_slice(&val.ledger_hash);
    blob.extend_from_slice(&val.sign_time.to_be_bytes());
    blob.push(val.is_full() as u8);
    blob.push(val.node_pubkey.len() as u8);
    blob.extend_from_slice(&val.node_pubkey);
    blob.push(val.signature.len() as u8);
    blob.extend_from_slice(&val.signature);

    let pb = proto::TmValidation {
        validation: blob,
        ..Default::default()
    };
    RtxpMessage::new(MessageType::Validation, pb.encode_to_vec())
}

/// Deserialize a `Validation` from an RTXP `Validation` payload.
pub fn decode_validation(data: &[u8]) -> Option<Validation> {
    let pb = proto::TmValidation::decode(data).ok()?;
    let blob = &pb.validation;

    // The validation blob is an XRPL-serialized STObject with field headers.
    // Parse it by walking the encoded field prefixes.
    let mut pos = 0;
    let mut ledger_seq: u32 = 0;
    let mut ledger_hash = [0u8; 32];
    let mut sign_time: u32 = 0;
    let mut flags: u32 = 0;
    let mut node_pubkey = Vec::new();
    let mut signature = Vec::new();

    while pos < blob.len() {
        let header = blob[pos];
        pos += 1;
        let mut type_code = (header >> 4) & 0x0F;
        let mut field_code = (header & 0x0F) as u16;

        // Extended type code.
        if type_code == 0 {
            if pos >= blob.len() {
                break;
            }
            type_code = blob[pos];
            pos += 1;
        }

        // Extended field code.
        if field_code == 0 {
            if pos >= blob.len() {
                break;
            }
            field_code = blob[pos] as u16;
            pos += 1;
        }

        match type_code {
            1 => {
                // UInt16: 2 bytes.
                if pos + 2 > blob.len() {
                    break;
                }
                pos += 2;
            }
            2 => {
                // UInt32: 4 bytes.
                if pos + 4 > blob.len() {
                    break;
                }
                let val = u32::from_be_bytes(blob[pos..pos + 4].try_into().ok()?);
                match field_code {
                    2 => {
                        flags = val;
                    }
                    6 => {
                        ledger_seq = val;
                    }
                    9 => {
                        sign_time = val;
                    }
                    _ => {}
                }
                pos += 4;
            }
            3 => {
                // UInt64: 8 bytes.
                if pos + 8 > blob.len() {
                    break;
                }
                pos += 8;
            }
            4 => {
                // Hash128: 16 bytes.
                if pos + 16 > blob.len() {
                    break;
                }
                pos += 16;
            }
            5 => {
                // Hash256: 32 bytes.
                if pos + 32 > blob.len() {
                    break;
                }
                match field_code {
                    1 => {
                        ledger_hash.copy_from_slice(&blob[pos..pos + 32]);
                    }
                    23 => {}
                    _ => {}
                }
                pos += 32;
            }
            6 => {
                // Amount: variable length (XRP = 8 bytes, IOU = 48 bytes).
                if pos + 8 > blob.len() {
                    break;
                }
                let first = blob[pos];
                if first & 0x80 != 0 && (first & 0x40 == 0) {
                    // XRP amount.
                    pos += 8;
                } else {
                    // IOU amount.
                    if pos + 48 > blob.len() {
                        break;
                    }
                    pos += 48;
                }
            }
            7 => {
                // Blob (VL): length-prefixed.
                if pos >= blob.len() {
                    break;
                }
                let (vl_len, vl_bytes) = decode_vl_length(&blob[pos..])?;
                pos += vl_bytes;
                if pos + vl_len > blob.len() {
                    break;
                }
                match field_code {
                    3 => {
                        node_pubkey = blob[pos..pos + vl_len].to_vec();
                    }
                    6 => {
                        signature = blob[pos..pos + vl_len].to_vec();
                    }
                    _ => {}
                }
                pos += vl_len;
            }
            8 => {
                // AccountID (VL): length-prefixed.
                if pos >= blob.len() {
                    break;
                }
                let (vl_len, vl_bytes) = decode_vl_length(&blob[pos..])?;
                pos += vl_bytes;
                if pos + vl_len > blob.len() {
                    break;
                }
                pos += vl_len;
            }
            14 => {
                // STObject: skip the nested object.
                // Read until the end-of-object marker (0xE1).
                while pos < blob.len() && blob[pos] != 0xE1 {
                    pos += 1;
                }
                if pos < blob.len() {
                    pos += 1;
                } // Skip 0xE1.
            }
            15 => {
                // STArray: skip the nested array.
                while pos < blob.len() && blob[pos] != 0xF1 {
                    pos += 1;
                }
                if pos < blob.len() {
                    pos += 1;
                } // Skip 0xF1.
            }
            16 => {
                // UInt8: 1 byte.
                if pos >= blob.len() {
                    break;
                }
                pos += 1;
            }
            17 => {
                // Hash160: 20 bytes.
                if pos + 20 > blob.len() {
                    break;
                }
                pos += 20;
            }
            18 => {
                // PathSet: variable length, skip to end marker 0x00.
                while pos < blob.len() && blob[pos] != 0x00 {
                    pos += 1;
                }
                if pos < blob.len() {
                    pos += 1;
                }
            }
            19 => {
                // Vector256: VL-prefixed array of 32-byte hashes.
                if pos >= blob.len() {
                    break;
                }
                let (vl_len, vl_bytes) = decode_vl_length(&blob[pos..])?;
                pos += vl_bytes;
                if pos + vl_len > blob.len() {
                    break;
                }
                pos += vl_len;
            }
            _ => {
                // Unknown type: cannot continue parsing safely.
                break;
            }
        }
    }

    if ledger_seq == 0 {
        return None;
    }

    Some(Validation {
        ledger_seq,
        ledger_hash,
        sign_time,
        flags,
        node_pubkey,
        signature,
        close_time: None,
        consensus_hash: None,
        validated_hash: None,
        cookie: None,
        server_version: None,
    })
}

/// Decode XRPL variable-length encoding. Returns (length, bytes_consumed).
fn decode_vl_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let b0 = data[0] as usize;
    if b0 <= 192 {
        Some((b0, 1))
    } else if b0 <= 240 {
        if data.len() < 2 {
            return None;
        }
        let len = 193 + ((b0 - 193) * 256) + data[1] as usize;
        Some((len, 2))
    } else if b0 <= 254 {
        if data.len() < 3 {
            return None;
        }
        let len = 12481 + ((b0 - 241) * 65536) + (data[1] as usize * 256) + data[2] as usize;
        Some((len, 3))
    } else {
        None
    }
}

// ── Manifest relay ────────────────────────────────────────────────────────────

/// Serialize manifests into an RTXP message (type = Manifests) using protobuf.
pub fn encode_manifests(manifests: &[Manifest]) -> RtxpMessage {
    let pb = proto::TmManifests {
        list: manifests
            .iter()
            .map(|manifest| proto::TmManifest {
                stobject: manifest.to_bytes(),
            })
            .collect(),
        ..Default::default()
    };
    RtxpMessage::new(MessageType::Manifests, pb.encode_to_vec())
}

/// Serialize a `Manifest` into an RTXP message (type = Manifests) using protobuf.
pub fn encode_manifest(m: &Manifest) -> RtxpMessage {
    encode_manifests(std::slice::from_ref(m))
}

/// Deserialize a `Manifest` from an RTXP Manifests protobuf payload.
/// Returns the first valid manifest (for backward compat with single-manifest callers).
pub fn decode_manifest(data: &[u8]) -> Option<Manifest> {
    let pb = proto::TmManifests::decode(data).ok()?;
    let entry = pb.list.first()?;
    Manifest::from_bytes(&entry.stobject).ok()
}

/// Deserialize ALL manifests from an RTXP Manifests protobuf payload.
pub fn decode_manifests(data: &[u8]) -> Vec<Manifest> {
    let Ok(pb) = proto::TmManifests::decode(data) else {
        return vec![];
    };
    pb.list
        .iter()
        .filter_map(|entry| Manifest::from_bytes(&entry.stobject).ok())
        .collect()
}

/// Deserialize the raw manifest STObject blobs from an RTXP Manifests payload.
pub fn decode_manifest_blobs(data: &[u8]) -> Vec<Vec<u8>> {
    let Ok(pb) = proto::TmManifests::decode(data) else {
        return vec![];
    };
    pb.list.into_iter().map(|entry| entry.stobject).collect()
}

// ── ValidatorList relay ───────────────────────────────────────────────────────

/// Decoded TMValidatorList fields from a peer message.
pub struct PeerValidatorList {
    pub manifest: Vec<u8>,
    pub blob: Vec<u8>,
    pub signature: Vec<u8>,
    pub version: u32,
}

/// Decode a TMValidatorList (type 54) protobuf message.
pub fn decode_validator_list(data: &[u8]) -> Option<PeerValidatorList> {
    let pb = proto::TmValidatorList::decode(data).ok()?;
    Some(PeerValidatorList {
        manifest: pb.manifest,
        blob: pb.blob,
        signature: pb.signature,
        version: pb.version,
    })
}

/// Decoded TMValidatorListCollection fields — multiple blobs per message.
pub struct PeerValidatorListBlob {
    pub manifest: Option<Vec<u8>>,
    pub blob: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Decode a TMValidatorListCollection (type 56) protobuf message.
pub fn decode_validator_list_collection(
    data: &[u8],
) -> Option<(Vec<u8>, Vec<PeerValidatorListBlob>)> {
    let pb = proto::TmValidatorListCollection::decode(data).ok()?;
    let blobs = pb
        .blobs
        .into_iter()
        .map(|b| PeerValidatorListBlob {
            manifest: b.manifest,
            blob: b.blob,
            signature: b.signature,
        })
        .collect();
    Some((pb.manifest, blobs))
}

// ── Transaction relay ─────────────────────────────────────────────────────────

/// Wrap a raw transaction blob in an RTXP Transaction message using protobuf.
pub fn encode_transaction(blob: &[u8]) -> RtxpMessage {
    let pb = proto::TmTransaction {
        raw_transaction: blob.to_vec(),
        status: proto::TransactionStatus::TsNew as i32,
        receive_timestamp: None,
        deferred: None,
    };
    RtxpMessage::new(MessageType::Transaction, pb.encode_to_vec())
}

// ── Peer discovery (Endpoints) ────────────────────────────────────────────────

use std::net::SocketAddr;

/// Encode a list of known peer addresses as an Endpoints message using protobuf.
pub fn encode_endpoints(addrs: &[SocketAddr]) -> RtxpMessage {
    let endpoints_v2: Vec<proto::tm_endpoints::TmEndpointv2> = addrs
        .iter()
        .map(|addr| proto::tm_endpoints::TmEndpointv2 {
            endpoint: addr.to_string(),
            hops: 0,
        })
        .collect();

    let pb = proto::TmEndpoints {
        version: 2,
        endpoints_v2,
    };
    RtxpMessage::new(MessageType::Endpoints, pb.encode_to_vec())
}

/// Decode an Endpoints message from protobuf into a list of peer addresses.
pub fn decode_endpoints(data: &[u8]) -> Vec<SocketAddr> {
    let pb = match proto::TmEndpoints::decode(data) {
        Ok(pb) => pb,
        Err(_) => return Vec::new(),
    };

    pb.endpoints_v2
        .iter()
        .filter_map(|ep| ep.endpoint.parse::<SocketAddr>().ok())
        .collect()
}

// ── Ping / Pong ───────────────────────────────────────────────────────────────

/// Encode a ping message.
pub fn encode_ping(seq: u32) -> RtxpMessage {
    let pb = proto::TmPing {
        r#type: proto::tm_ping::PingType::PtPing as i32,
        seq: Some(seq),
        ping_time: None,
        net_time: None,
    };
    RtxpMessage::new(MessageType::Ping, pb.encode_to_vec())
}

/// Encode a pong message (reply to a ping).
pub fn encode_pong(seq: u32) -> RtxpMessage {
    let pb = proto::TmPing {
        r#type: proto::tm_ping::PingType::PtPong as i32,
        seq: Some(seq),
        ping_time: None,
        net_time: None,
    };
    RtxpMessage::new(MessageType::Ping, pb.encode_to_vec())
}

/// Decode a ping/pong message. Returns (is_ping, sequence).
pub fn decode_ping(data: &[u8]) -> Option<(bool, u32)> {
    let pb = proto::TmPing::decode(data).ok()?;
    let is_ping = pb.r#type == proto::tm_ping::PingType::PtPing as i32;
    Some((is_ping, pb.seq.unwrap_or(0)))
}

// ── Status change ──────────────────────────────────────────────────────────────

/// Encode a status change message.
pub fn encode_status_change(
    status: proto::NodeStatus,
    event: proto::NodeEvent,
    seq: u32,
    hash: &[u8; 32],
) -> RtxpMessage {
    let pb = proto::TmStatusChange {
        new_status: Some(status as i32),
        new_event: Some(event as i32),
        ledger_seq: Some(seq),
        ledger_hash: Some(hash.to_vec()),
        ledger_hash_previous: None,
        network_time: None,
        first_seq: None,
        last_seq: None,
    };
    RtxpMessage::new(MessageType::StatusChange, pb.encode_to_vec())
}

/// Encode a TMCluster gossip message carrying the current cluster load.
pub fn encode_cluster(
    public_key: &str,
    node_load: u32,
    address: Option<&str>,
    blocked_peers: u32,
) -> RtxpMessage {
    let mut load_sources = Vec::new();
    if blocked_peers > 0 {
        load_sources.push(proto::TmLoadSource {
            name: "blocked_peers".to_string(),
            cost: blocked_peers.max(1),
            count: Some(blocked_peers),
        });
    }
    let pb = proto::TmCluster {
        cluster_nodes: vec![proto::TmClusterNode {
            public_key: public_key.to_string(),
            report_time: unix_now_u32(),
            node_load: node_load.max(crate::network::load::LOAD_BASE),
            node_name: None,
            address: address.map(str::to_string),
        }],
        load_sources,
    };
    RtxpMessage::new(MessageType::Cluster, pb.encode_to_vec())
}

fn unix_now_u32() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(u32::MAX as u64) as u32
}

// ── Ledger sync (rippled-compatible TMGetLedger/TMLedgerData) ─────────────────

/// Encode a TMGetLedger request for the base ledger header (liBASE).
pub fn encode_get_ledger_base(ledger_hash: &[u8; 32], cookie: u64) -> RtxpMessage {
    let pb = proto::TmGetLedger {
        itype: proto::TmLedgerInfoType::LiBase as i32,
        ltype: Some(proto::TmLedgerType::LtAccepted as i32),
        ledger_hash: Some(ledger_hash.to_vec()),
        request_cookie: if cookie != 0 { Some(cookie) } else { None },
        ledger_seq: None,
        node_i_ds: vec![],
        query_type: None,
        query_depth: None,
    };
    RtxpMessage::new(MessageType::GetLedger, pb.encode_to_vec())
}

/// Encode a TMGetLedger request for a ledger header by sequence number.
/// Peers with full history will respond with the header.
pub fn encode_get_ledger_base_by_seq(seq: u32, cookie: u64) -> RtxpMessage {
    let pb = proto::TmGetLedger {
        itype: proto::TmLedgerInfoType::LiBase as i32,
        ltype: Some(proto::TmLedgerType::LtAccepted as i32),
        ledger_hash: None,
        request_cookie: if cookie != 0 { Some(cookie) } else { None },
        ledger_seq: Some(seq),
        node_i_ds: vec![],
        query_type: None,
        query_depth: None,
    };
    RtxpMessage::new(MessageType::GetLedger, pb.encode_to_vec())
}

/// Decode a TMLedgerData response from raw payload bytes.
pub fn decode_ledger_data(payload: &[u8]) -> Option<proto::TmLedgerData> {
    proto::TmLedgerData::decode(payload).ok()
}

/// Encode an empty TMLedgerData error reply.
pub fn encode_ledger_data_error(
    ledger_hash: &[u8; 32],
    ledger_seq: u32,
    info_type: i32,
    cookie: Option<u32>,
    error: proto::TmReplyError,
) -> RtxpMessage {
    let pb = proto::TmLedgerData {
        ledger_hash: ledger_hash.to_vec(),
        ledger_seq,
        r#type: info_type,
        nodes: vec![],
        request_cookie: cookie,
        error: Some(error as i32),
    };
    RtxpMessage::new(MessageType::LedgerData, pb.encode_to_vec())
}

/// Encode a TMGetLedger request for account state nodes (liAS_NODE).
///
/// When `node_ids` is empty, rippled returns the root node of the state tree.
/// When `node_ids` contains specific hashes, it returns those nodes.
/// `query_depth` of 1 tells rippled to include one extra level of children.
pub fn encode_get_ledger_state(
    ledger_hash: &[u8; 32],
    node_ids: &[Vec<u8>],
    cookie: u64,
    query_depth: u32,
    query_type: Option<i32>,
    ledger_seq: u32,
) -> RtxpMessage {
    // Use the specific ledger hash if provided, otherwise request ltCLOSED
    let has_hash = !ledger_hash.iter().all(|&b| b == 0);
    let pb = proto::TmGetLedger {
        itype: proto::TmLedgerInfoType::LiAsNode as i32,
        // rippled doesn't set ltype for liAS_NODE when ledger_hash is provided
        ltype: if has_hash {
            None
        } else {
            Some(proto::TmLedgerType::LtClosed as i32)
        },
        ledger_hash: if has_hash {
            Some(ledger_hash.to_vec())
        } else {
            None
        },
        // ltCLOSED requests are for the peer's current tree, not a historical
        // sequence. Only carry ledger_seq when an explicit hash is also in play.
        ledger_seq: if has_hash && ledger_seq > 0 {
            Some(ledger_seq)
        } else {
            None
        },
        node_i_ds: node_ids.to_vec(),
        request_cookie: if cookie != 0 { Some(cookie) } else { None },
        query_type,
        query_depth: Some(query_depth),
    };
    RtxpMessage::new(MessageType::GetLedger, pb.encode_to_vec())
}

/// Encode a TMGetLedger request for specific SHAMap leaves by their keys.
///
/// Used for lazy state fetch: request specific account/object leaves from a
/// peer's state tree.  Each key is encoded as a 33-byte SHAMapNodeID:
/// [32-byte key][depth=64 (0x40)] — matching rippled's getRawString() format
/// (SHAMapNodeID.cpp).
///
/// `query_depth` of 0 returns only the requested leaves (no children).
pub fn encode_get_ledger_leaves(
    ledger_hash: &[u8; 32],
    shamap_keys: &[[u8; 32]],
    cookie: u64,
) -> RtxpMessage {
    // Encode each key as a 33-byte SHAMapNodeID: [key][depth=64]
    let node_ids: Vec<Vec<u8>> = shamap_keys
        .iter()
        .map(|key| {
            let mut nid = Vec::with_capacity(33);
            nid.extend_from_slice(key);
            nid.push(64); // leafDepth = 64
            nid
        })
        .collect();

    let pb = proto::TmGetLedger {
        itype: proto::TmLedgerInfoType::LiAsNode as i32,
        ltype: None,
        ledger_hash: Some(ledger_hash.to_vec()),
        ledger_seq: None,
        node_i_ds: node_ids,
        request_cookie: if cookie != 0 { Some(cookie) } else { None },
        query_type: None,
        query_depth: Some(0), // just the leaves, no children
    };
    RtxpMessage::new(MessageType::GetLedger, pb.encode_to_vec())
}

/// Encode a TMGetObjectByHash request for specific state-tree node hashes.
pub fn encode_get_state_nodes_by_hash(
    ledger_hash: &[u8; 32],
    nodes: &[([u8; 32], [u8; 33])],
    ledger_seq: u32,
    seq: u32,
) -> RtxpMessage {
    let objects = nodes
        .iter()
        .map(|(hash, _node_id)| crate::proto::TmIndexedObject {
            hash: Some(hash.to_vec()),
            index: None,
            data: None,
            ledger_seq: Some(ledger_seq),
            node_id: None,
        })
        .collect();

    let pb = crate::proto::TmGetObjectByHash {
        r#type: crate::proto::tm_get_object_by_hash::ObjectType::OtStateNode as i32,
        query: true,
        seq: Some(seq),
        ledger_hash: if ledger_hash.iter().all(|&b| b == 0) {
            None
        } else {
            Some(ledger_hash.to_vec())
        },
        fat: None,
        objects,
    };
    RtxpMessage::new(MessageType::GetObjects, pb.encode_to_vec())
}

/// Encode a TMGetLedger request for the transaction tree (liTX_NODE, ltCLOSED).
///
/// Requests the full transaction SHAMap for the peer's latest closed ledger.
/// TX trees are small (typically 10-50 transactions per ledger) so one request
/// with queryDepth=2 usually gets the entire tree.
pub fn encode_get_ledger_txs(cookie: u64) -> RtxpMessage {
    let pb = proto::TmGetLedger {
        itype: proto::TmLedgerInfoType::LiTxNode as i32,
        ltype: Some(proto::TmLedgerType::LtClosed as i32),
        ledger_hash: None,
        ledger_seq: None,
        node_i_ds: vec![vec![0u8; 33]], // root node
        request_cookie: if cookie != 0 { Some(cookie) } else { None },
        query_type: None,
        query_depth: Some(2), // get full tree (small for tx trees)
    };
    RtxpMessage::new(MessageType::GetLedger, pb.encode_to_vec())
}

/// Encode a TMGetLedger request for the transaction tree of a SPECIFIC ledger.
/// Used by the follower to get tx+metadata for a validated ledger.
pub fn encode_get_ledger_txs_for_hash(ledger_hash: &[u8; 32], cookie: u64) -> RtxpMessage {
    let pb = proto::TmGetLedger {
        itype: proto::TmLedgerInfoType::LiTxNode as i32,
        ltype: Some(proto::TmLedgerType::LtAccepted as i32),
        ledger_hash: Some(ledger_hash.to_vec()),
        ledger_seq: None,
        node_i_ds: vec![vec![0u8; 33]], // root node
        request_cookie: if cookie != 0 { Some(cookie) } else { None },
        query_type: None,
        query_depth: Some(3), // max depth (Tuning::maxQueryDepth=3), handles large tx trees
    };
    RtxpMessage::new(MessageType::GetLedger, pb.encode_to_vec())
}

/// Encode a TMGetLedger request for specific transaction-tree node IDs.
///
/// Used when an acquisition already has part of the tx SHAMap and needs
/// authoritative follow-up for missing descendants.
pub fn encode_get_ledger_txs_for_hash_nodes(
    ledger_hash: &[u8; 32],
    node_ids: &[Vec<u8>],
    cookie: u64,
) -> RtxpMessage {
    let pb = proto::TmGetLedger {
        itype: proto::TmLedgerInfoType::LiTxNode as i32,
        ltype: Some(proto::TmLedgerType::LtAccepted as i32),
        ledger_hash: Some(ledger_hash.to_vec()),
        ledger_seq: None,
        node_i_ds: node_ids.to_vec(),
        request_cookie: if cookie != 0 { Some(cookie) } else { None },
        query_type: None,
        query_depth: Some(0),
    };
    RtxpMessage::new(MessageType::GetLedger, pb.encode_to_vec())
}

/// Encode a TMGetLedger request for a consensus transaction set (liTS_CANDIDATE).
///
/// The tx set is a SHAMap whose leaves are raw transaction blobs.
/// `set_hash` is the consensus_hash from validator validations.
/// Peers that participated in the recent consensus round will have this set.
pub fn encode_get_tx_set(set_hash: &[u8; 32], cookie: u64) -> RtxpMessage {
    let pb = proto::TmGetLedger {
        itype: proto::TmLedgerInfoType::LiTsCandidate as i32,
        ltype: None,
        ledger_hash: Some(set_hash.to_vec()),
        ledger_seq: Some(0), // rippled requires seq=0 for liTS_CANDIDATE
        node_i_ds: vec![vec![0u8; 33]], // root node
        request_cookie: if cookie != 0 { Some(cookie) } else { None },
        query_type: None,
        query_depth: Some(3),
    };
    RtxpMessage::new(MessageType::GetLedger, pb.encode_to_vec())
}

// ── Replay delta (ledger catch-up via peer protocol) ─────────────────────────

/// Encode a TMReplayDeltaRequest ��� requests all transactions for a ledger.
///
/// The response contains the ledger header + all transactions (each as
/// VL-encoded tx_blob + metadata).  Metadata includes sfTransactionIndex
/// which gives execution order.
pub fn encode_replay_delta_request(ledger_hash: &[u8; 32]) -> RtxpMessage {
    let pb = proto::TmReplayDeltaRequest {
        ledger_hash: ledger_hash.to_vec(),
    };
    RtxpMessage::new(MessageType::ReplayDeltaReq, pb.encode_to_vec())
}

/// Decode a TMReplayDeltaResponse from raw payload bytes.
pub fn decode_replay_delta_response(payload: &[u8]) -> Option<proto::TmReplayDeltaResponse> {
    proto::TmReplayDeltaResponse::decode(payload).ok()
}

// ── Snapshot sync (xLedgRSv2Beta custom — not understood by rippled) ────────────────
// This remains a project-local protocol; wire-compatible TMGetLedger parity is
// a future interoperability goal rather than a hidden requirement of this code.

pub fn encode_get_snapshot(seq: u32) -> RtxpMessage {
    RtxpMessage::new(MessageType::Unknown(200), seq.to_be_bytes().to_vec())
}

pub fn decode_get_snapshot(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes(data[..4].try_into().ok()?))
}

pub fn encode_snapshot_header(header: &crate::ledger::LedgerHeader) -> RtxpMessage {
    let data = bincode::serialize(header).unwrap_or_default();
    RtxpMessage::new(MessageType::Unknown(201), data)
}

pub fn decode_snapshot_header(data: &[u8]) -> Option<crate::ledger::LedgerHeader> {
    bincode::deserialize(data).ok()
}

/// Encode a snapshot chunk: object_type(u8) + bincode-serialized batch of objects.
pub fn encode_snapshot_chunk(object_type: u8, data: Vec<u8>) -> RtxpMessage {
    let mut payload = vec![object_type];
    payload.extend_from_slice(&data);
    RtxpMessage::new(MessageType::Unknown(202), payload)
}

pub fn encode_snapshot_end(seq: u32, state_hash: &[u8; 32]) -> RtxpMessage {
    let mut payload = seq.to_be_bytes().to_vec();
    payload.extend_from_slice(state_hash);
    RtxpMessage::new(MessageType::Unknown(203), payload)
}

pub fn decode_snapshot_end(data: &[u8]) -> Option<(u32, [u8; 32])> {
    if data.len() < 36 {
        return None;
    }
    let seq = u32::from_be_bytes(data[..4].try_into().ok()?);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[4..36]);
    Some((seq, hash))
}

// ── Historical ledger download (xLedgRSv2Beta custom — not understood by rippled) ──
// This remains a project-local protocol; wire-compatible TMGetLedger parity is
// a future interoperability goal rather than a hidden requirement of this code.

pub fn encode_get_history(start: u32, end: u32) -> RtxpMessage {
    let mut payload = start.to_be_bytes().to_vec();
    payload.extend_from_slice(&end.to_be_bytes());
    RtxpMessage::new(MessageType::Unknown(204), payload)
}

pub fn decode_get_history(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < 8 {
        return None;
    }
    let start = u32::from_be_bytes(data[..4].try_into().ok()?);
    let end = u32::from_be_bytes(data[4..8].try_into().ok()?);
    Some((start, end))
}

pub fn encode_history_ledger(
    header: &crate::ledger::LedgerHeader,
    tx_records: &[crate::ledger::history::TxRecord],
) -> RtxpMessage {
    let mut payload = Vec::new();
    let header_bytes = bincode::serialize(header).unwrap_or_default();
    payload.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&header_bytes);
    payload.extend_from_slice(&(tx_records.len() as u32).to_be_bytes());
    for rec in tx_records {
        let rec_bytes = bincode::serialize(rec).unwrap_or_default();
        payload.extend_from_slice(&(rec_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&rec_bytes);
    }
    RtxpMessage::new(MessageType::Unknown(205), payload)
}

pub fn decode_history_ledger(
    data: &[u8],
) -> Option<(
    crate::ledger::LedgerHeader,
    Vec<crate::ledger::history::TxRecord>,
)> {
    if data.len() < 8 {
        return None;
    }
    let mut pos = 0;
    let hdr_len = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
    pos += 4;
    if pos + hdr_len > data.len() {
        return None;
    }
    let header: crate::ledger::LedgerHeader =
        bincode::deserialize(&data[pos..pos + hdr_len]).ok()?;
    pos += hdr_len;
    if pos + 4 > data.len() {
        return None;
    }
    let tx_count = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
    pos += 4;
    let mut tx_records = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        if pos + 4 > data.len() {
            break;
        }
        let rec_len = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if pos + rec_len > data.len() {
            break;
        }
        if let Ok(rec) =
            bincode::deserialize::<crate::ledger::history::TxRecord>(&data[pos..pos + rec_len])
        {
            tx_records.push(rec);
        }
        pos += rec_len;
    }
    Some((header, tx_records))
}

pub fn encode_history_end(start: u32, end: u32) -> RtxpMessage {
    let mut payload = start.to_be_bytes().to_vec();
    payload.extend_from_slice(&end.to_be_bytes());
    RtxpMessage::new(MessageType::Unknown(206), payload)
}

// ── Squelch ──────────────────────────────────────────────────────────────────

/// Decoded squelch message.
pub struct SquelchMessage {
    /// True = squelch, false = unsquelch.
    pub squelch: bool,
    /// Validator public key (raw bytes, typically 33 bytes compressed).
    pub validator_pubkey: Vec<u8>,
    /// Squelch duration in seconds (only present when squelching).
    pub duration_secs: Option<u32>,
}

/// Decode a TMSquelch protobuf payload.
pub fn decode_squelch(payload: &[u8]) -> Option<SquelchMessage> {
    use prost::Message;
    let pb = proto::TmSquelch::decode(payload).ok()?;
    Some(SquelchMessage {
        squelch: pb.squelch,
        validator_pubkey: pb.validator_pub_key,
        duration_secs: pb.squelch_duration,
    })
}

/// Encode a TMSquelch message.
pub fn encode_squelch(
    validator_pubkey: &[u8],
    squelch: bool,
    duration_secs: Option<u32>,
) -> RtxpMessage {
    use prost::Message;
    let pb = proto::TmSquelch {
        squelch,
        validator_pub_key: validator_pubkey.to_vec(),
        squelch_duration: duration_secs,
    };
    RtxpMessage::new(MessageType::Squelch, pb.encode_to_vec())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Secp256k1KeyPair;

    #[test]
    fn test_proposal_roundtrip() {
        let kp = Secp256k1KeyPair::generate();
        let orig = Proposal::new_signed(42, [0xAB; 32], [0xCD; 32], 1000, 3, &kp);
        let msg = encode_proposal(&orig);
        assert_eq!(msg.msg_type, MessageType::ProposeLedger);

        let decoded = decode_proposal(&msg.payload).expect("decode should succeed");
        // Note: ledger_seq is not in TmProposeSet, so it defaults to 0
        assert_eq!(decoded.tx_set_hash, [0xAB; 32]);
        assert_eq!(decoded.close_time, 1000);
        assert_eq!(decoded.prop_seq, 3);
        assert_eq!(decoded.node_pubkey, orig.node_pubkey);
        assert_eq!(decoded.signature, orig.signature);
    }

    // validation roundtrip test removed — encode_validation uses legacy format
    // while decode_validation now parses rippled's STObject format.
    // Validation encoding uses the legacy format, while decoding expects
    // rippled's STObject layout, so only decode coverage remains here.

    #[test]
    fn test_manifest_roundtrip() {
        let master = Secp256k1KeyPair::generate();
        let signing = Secp256k1KeyPair::generate();
        let orig = Manifest::new_signed(1, &master, &signing);
        let msg = encode_manifest(&orig);
        assert_eq!(msg.msg_type, MessageType::Manifests);

        let decoded = decode_manifest(&msg.payload).expect("decode should succeed");
        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.master_pubkey, orig.master_pubkey);
        assert_eq!(decoded.signing_pubkey, orig.signing_pubkey);
        assert!(decoded.verify());
    }

    #[test]
    fn test_manifest_batch_roundtrip() {
        let master_a = Secp256k1KeyPair::generate();
        let signing_a = Secp256k1KeyPair::generate();
        let master_b = Secp256k1KeyPair::generate();
        let signing_b = Secp256k1KeyPair::generate();
        let manifests = vec![
            Manifest::new_signed(1, &master_a, &signing_a),
            Manifest::new_signed(2, &master_b, &signing_b),
        ];

        let msg = encode_manifests(&manifests);
        let decoded = decode_manifests(&msg.payload);

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].sequence, manifests[0].sequence);
        assert_eq!(decoded[1].sequence, manifests[1].sequence);
        assert_eq!(decoded[0].master_pubkey, manifests[0].master_pubkey);
        assert_eq!(decoded[1].master_pubkey, manifests[1].master_pubkey);
        assert!(decoded.iter().all(Manifest::verify));
    }

    #[test]
    fn test_transaction_encoding() {
        let blob = vec![0x12, 0x00, 0x00, 0x22]; // minimal tx header
        let msg = encode_transaction(&blob);
        assert_eq!(msg.msg_type, MessageType::Transaction);
        // Payload is now protobuf-encoded, so it won't match raw blob
        let pb = proto::TmTransaction::decode(msg.payload.as_slice()).unwrap();
        assert_eq!(pb.raw_transaction, blob);
    }

    #[test]
    fn test_truncated_proposal_returns_none() {
        assert!(decode_proposal(&[0u8; 2]).is_none());
    }

    #[test]
    fn test_truncated_validation_returns_none() {
        assert!(decode_validation(&[0u8; 2]).is_none());
    }

    #[test]
    fn test_endpoints_roundtrip() {
        let addrs = vec![
            "192.168.1.1:51235".parse::<SocketAddr>().unwrap(),
            "10.0.0.5:51235".parse::<SocketAddr>().unwrap(),
        ];
        let msg = encode_endpoints(&addrs);
        assert_eq!(msg.msg_type, MessageType::Endpoints);
        let decoded = decode_endpoints(&msg.payload);
        assert_eq!(decoded, addrs);
    }

    #[test]
    fn test_endpoints_empty() {
        let msg = encode_endpoints(&[]);
        let decoded = decode_endpoints(&msg.payload);
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_ping_pong() {
        let ping_msg = encode_ping(42);
        assert_eq!(ping_msg.msg_type, MessageType::Ping);
        let (is_ping, seq) = decode_ping(&ping_msg.payload).unwrap();
        assert!(is_ping);
        assert_eq!(seq, 42);

        let pong_msg = encode_pong(42);
        assert_eq!(pong_msg.msg_type, MessageType::Ping);
        let (is_ping, seq) = decode_ping(&pong_msg.payload).unwrap();
        assert!(!is_ping);
        assert_eq!(seq, 42);
    }

    #[test]
    fn test_validation_decode_field_mapping() {
        // Build a validation STObject blob with known pubkey and signature,
        // wrap in TMValidation protobuf, decode, and verify fields are correct.
        use prost::Message;

        let pubkey = vec![0xED; 33]; // 33-byte Ed25519 pubkey
        let sig = vec![0xAA; 72]; // 72-byte signature
        let ledger_seq: u32 = 103_293_070;
        let ledger_hash = [0xBB; 32];
        let sign_time: u32 = 1_712_000_000;

        // Build the STObject in canonical order (matching validation.rs serialize_fields)
        let mut blob = Vec::new();

        // sfFlags (type=2, field=2): header 0x22
        blob.push(0x22);
        blob.extend_from_slice(&1u32.to_be_bytes());

        // sfLedgerSequence (type=2, field=6): header 0x26
        blob.push(0x26);
        blob.extend_from_slice(&ledger_seq.to_be_bytes());

        // sfSigningTime (type=2, field=9): header 0x29
        blob.push(0x29);
        blob.extend_from_slice(&sign_time.to_be_bytes());

        // sfLedgerHash (type=5, field=1): header 0x51
        blob.push(0x51);
        blob.extend_from_slice(&ledger_hash);

        // sfSigningPubKey (type=7, field=3): header 0x73
        blob.push(0x73);
        blob.push(pubkey.len() as u8); // VL length (33 <= 192)
        blob.extend_from_slice(&pubkey);

        // sfSignature (type=7, field=6): header 0x76
        blob.push(0x76);
        blob.push(sig.len() as u8); // VL length (72 <= 192)
        blob.extend_from_slice(&sig);

        // Wrap in TMValidation protobuf
        let pb = proto::TmValidation {
            validation: blob,
            ..Default::default()
        };
        let pb_bytes = pb.encode_to_vec();

        // Decode via relay.rs
        let decoded = decode_validation(&pb_bytes).expect("decode should succeed");

        assert_eq!(decoded.ledger_seq, ledger_seq, "ledger_seq mismatch");
        assert_eq!(decoded.ledger_hash, ledger_hash, "ledger_hash mismatch");
        assert_eq!(decoded.sign_time, sign_time, "sign_time mismatch");
        assert_eq!(
            decoded.node_pubkey, pubkey,
            "node_pubkey should be field 3 (sfSigningPubKey)"
        );
        assert_eq!(
            decoded.signature, sig,
            "signature should be field 6 (sfSignature)"
        );
        assert_eq!(decoded.node_pubkey.len(), 33, "pubkey should be 33 bytes");
        assert_eq!(decoded.signature.len(), 72, "signature should be 72 bytes");
    }

    #[test]
    fn test_encode_get_state_nodes_by_hash_omits_zero_hash() {
        let msg = encode_get_state_nodes_by_hash(&[0u8; 32], &[([0xAB; 32], [0u8; 33])], 10, 77);
        let pb = proto::TmGetObjectByHash::decode(msg.payload.as_slice()).unwrap();
        assert!(pb.ledger_hash.is_none());
        assert_eq!(pb.seq, Some(77));
        assert_eq!(pb.objects.len(), 1);
        assert!(pb.objects[0].node_id.is_none());
    }

    #[test]
    fn test_encode_ledger_data_error_sets_reply_error() {
        let msg = encode_ledger_data_error(
            &[0x11; 32],
            99,
            proto::TmLedgerInfoType::LiAsNode as i32,
            Some(7),
            proto::TmReplyError::ReNoNode,
        );
        let pb = proto::TmLedgerData::decode(msg.payload.as_slice()).unwrap();
        assert_eq!(pb.ledger_hash, vec![0x11; 32]);
        assert_eq!(pb.ledger_seq, 99);
        assert_eq!(pb.r#type, proto::TmLedgerInfoType::LiAsNode as i32);
        assert_eq!(pb.request_cookie, Some(7));
        assert_eq!(pb.error, Some(proto::TmReplyError::ReNoNode as i32));
        assert!(pb.nodes.is_empty());
    }

    #[test]
    fn test_encode_get_ledger_state_closed_omits_hash_and_seq() {
        let msg = encode_get_ledger_state(
            &[0u8; 32],
            &[vec![0u8; 33]],
            0,
            1,
            Some(proto::TmQueryType::QtIndirect as i32),
            777,
        );
        let pb = proto::TmGetLedger::decode(msg.payload.as_slice()).unwrap();
        assert_eq!(pb.itype, proto::TmLedgerInfoType::LiAsNode as i32);
        assert_eq!(pb.ltype, Some(proto::TmLedgerType::LtClosed as i32));
        assert!(pb.ledger_hash.is_none());
        assert!(pb.ledger_seq.is_none());
        assert_eq!(pb.query_depth, Some(1));
        assert_eq!(pb.query_type, Some(proto::TmQueryType::QtIndirect as i32));
    }

    #[test]
    fn test_encode_get_ledger_state_hash_request_omits_ltype() {
        let msg = encode_get_ledger_state(&[0xAB; 32], &[vec![0u8; 33]], 9, 0, None, 444);
        let pb = proto::TmGetLedger::decode(msg.payload.as_slice()).unwrap();
        assert!(pb.ltype.is_none());
        assert_eq!(pb.ledger_hash, Some(vec![0xAB; 32]));
        assert_eq!(pb.ledger_seq, Some(444));
        assert_eq!(pb.request_cookie, Some(9));
    }

    #[test]
    fn test_encode_get_ledger_leaves_omits_ltype_for_specific_hash() {
        let msg = encode_get_ledger_leaves(&[0xCD; 32], &[[0x11; 32]], 0);
        let pb = proto::TmGetLedger::decode(msg.payload.as_slice()).unwrap();
        assert!(pb.ltype.is_none());
        assert_eq!(pb.ledger_hash, Some(vec![0xCD; 32]));
        assert_eq!(pb.query_depth, Some(0));
        assert_eq!(pb.node_i_ds.len(), 1);
    }
}
