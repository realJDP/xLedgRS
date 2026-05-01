//! xLedgRS purpose: Sync Helpers piece of the live node runtime.
use super::*;

pub(super) fn build_li_base_nodes(
    header: &crate::ledger::LedgerHeader,
    state_root_wire: Option<Vec<u8>>,
) -> Vec<crate::proto::TmLedgerNode> {
    let mut nodes = vec![crate::proto::TmLedgerNode {
        nodedata: encode_ledger_base_header_bytes(header),
        nodeid: None,
    }];
    if let Some(root_wire) = state_root_wire {
        nodes.push(crate::proto::TmLedgerNode {
            nodedata: root_wire,
            nodeid: Some(
                crate::ledger::shamap_id::SHAMapNodeID::root()
                    .to_wire()
                    .to_vec(),
            ),
        });
    }
    nodes
}

const HIGH_LATENCY_SYNC_QUERY_DEPTH_MS: u32 = 300;

pub(super) fn tune_sync_request_for_peer_latency(
    req: &RtxpMessage,
    peer_latency_ms: Option<u32>,
) -> Option<RtxpMessage> {
    if peer_latency_ms.unwrap_or(0) < HIGH_LATENCY_SYNC_QUERY_DEPTH_MS {
        return None;
    }
    if req.msg_type != MessageType::GetLedger {
        return None;
    }

    let mut pb =
        <crate::proto::TmGetLedger as ProstMessage>::decode(req.payload.as_slice()).ok()?;
    if pb.itype != crate::proto::TmLedgerInfoType::LiAsNode as i32 {
        return None;
    }
    if pb.query_depth != Some(1) {
        return None;
    }

    pb.query_depth = Some(2);
    Some(RtxpMessage::new(MessageType::GetLedger, pb.encode_to_vec()))
}

pub(super) fn resolve_get_ledger_header(
    req: &crate::proto::TmGetLedger,
    current: &crate::ledger::LedgerHeader,
    history: &crate::ledger::history::LedgerStore,
) -> Result<crate::ledger::LedgerHeader, crate::proto::TmReplyError> {
    let requested_hash = requested_get_ledger_hash(req)?;
    match req.ltype {
        Some(x) if x == crate::proto::TmLedgerType::LtCurrent as i32 => {
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

#[cfg(test)]
pub(super) fn should_use_timeout_object_fallback(
    by_hash_armed: bool,
    stalled_retries: u32,
    ledger_hash: &[u8; 32],
) -> bool {
    by_hash_armed && stalled_retries > 4 && *ledger_hash != [0u8; 32]
}

#[cfg(test)]
pub(super) fn sync_gate_accepts_response(
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

    let Ok(guard) = sync.try_lock() else {
        return false;
    };
    let Some(syncer) = guard.as_ref() else {
        return false;
    };
    if is_object_response {
        let seq_known = object_seq.is_some_and(|seq| syncer.peer.knows_object_query(seq));
        if !seq_known {
            return false;
        }
        if syncer.peer.accepts_ltclosed_responses() {
            return resp_hash.is_some_and(|hash| hash.len() == 32);
        }
        return hash_matches_target;
    }
    if hash_matches_target {
        return true;
    }
    if !syncer.peer.accepts_ltclosed_responses() {
        return false;
    }
    resp_hash.is_some_and(|hash| hash.len() == 32)
}

pub(super) fn should_issue_reply_followup(outcome: &str, had_useful_epoch: bool) -> bool {
    had_useful_epoch && matches!(outcome, "Continue" | "PassComplete")
}

pub(super) fn is_pending_sync_anchor(
    pending_sync_anchor: Option<(u32, [u8; 32])>,
    ledger_seq: u32,
    ledger_hash: &[u8; 32],
) -> bool {
    pending_sync_anchor.is_some_and(|(pending_seq, pending_hash)| {
        pending_hash == *ledger_hash && (ledger_seq == 0 || pending_seq == ledger_seq)
    })
}

pub(super) fn compute_acquired_tx_root(tx_blobs: &[(Vec<u8>, Vec<u8>)]) -> [u8; 32] {
    let mut tx_map = crate::ledger::sparse_shamap::SparseSHAMap::new();
    for (tx_blob, meta_blob) in tx_blobs {
        let mut leaf_data = Vec::with_capacity(tx_blob.len() + meta_blob.len() + 8);
        crate::transaction::serialize::encode_length(tx_blob.len(), &mut leaf_data);
        leaf_data.extend_from_slice(tx_blob);
        crate::transaction::serialize::encode_length(meta_blob.len(), &mut leaf_data);
        leaf_data.extend_from_slice(meta_blob);
        let tx_id = crate::transaction::serialize::tx_blob_hash(tx_blob);
        let leaf_hash = crate::ledger::close::tx_leaf_hash(&leaf_data, &tx_id);
        tx_map.insert(tx_id, leaf_hash);
    }
    if tx_map.len() == 0 {
        [0u8; 32]
    } else {
        tx_map.root_hash()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SyncCompletionOutcome {
    pub verified: bool,
    pub clear_sync_in_progress: bool,
    pub persist_anchor: bool,
    pub mark_sync_done: bool,
    pub broadcast_connected: bool,
    pub start_follower: bool,
}

pub(super) fn plan_sync_completion_outcome(
    verified_root_hash: [u8; 32],
    target_account_hash: [u8; 32],
) -> SyncCompletionOutcome {
    let verified = verified_root_hash == target_account_hash;
    SyncCompletionOutcome {
        verified,
        clear_sync_in_progress: true,
        persist_anchor: verified,
        mark_sync_done: verified,
        broadcast_connected: verified,
        start_follower: verified,
    }
}
