//! xLedgRS purpose: Protocol Helpers piece of the live node runtime.
pub(super) fn should_close_ledger(
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
pub(super) fn parse_host_port(s: &str) -> (String, u16) {
    if let Some(colon) = s.rfind(':') {
        let host = s[..colon].to_string();
        let port = s[colon + 1..].parse().unwrap_or(6008);
        (host, port)
    } else {
        (s.to_string(), 6008)
    }
}

pub(super) fn collect_shamap_ledger_nodes(
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

pub(super) fn requested_get_ledger_hash(
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

pub(super) fn encode_ledger_base_header_bytes(header: &crate::ledger::LedgerHeader) -> Vec<u8> {
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
    header_bytes
}

pub(super) fn transaction_accounts_from_blob(blob: &[u8]) -> Vec<String> {
    match crate::transaction::parse_blob(blob) {
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
    }
}

pub(super) fn node_status_label(status: i32) -> Option<&'static str> {
    match crate::proto::NodeStatus::try_from(status).ok()? {
        crate::proto::NodeStatus::NsConnecting => Some("CONNECTING"),
        crate::proto::NodeStatus::NsConnected => Some("CONNECTED"),
        crate::proto::NodeStatus::NsMonitoring => Some("MONITORING"),
        crate::proto::NodeStatus::NsValidating => Some("VALIDATING"),
        crate::proto::NodeStatus::NsShutting => Some("SHUTTING"),
    }
}

pub(super) fn node_event_label(event: i32) -> Option<&'static str> {
    match crate::proto::NodeEvent::try_from(event).ok()? {
        crate::proto::NodeEvent::NeClosingLedger => Some("CLOSING_LEDGER"),
        crate::proto::NodeEvent::NeAcceptedLedger => Some("ACCEPTED_LEDGER"),
        crate::proto::NodeEvent::NeSwitchedLedger => Some("SWITCHED_LEDGER"),
        crate::proto::NodeEvent::NeLostSync => Some("LOST_SYNC"),
    }
}
