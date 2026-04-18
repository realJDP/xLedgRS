pub fn choose_sync_kickstart_target(
    inactive_target: Option<(u32, [u8; 32])>,
    latest_seq: u32,
    latest_hash: [u8; 32],
) -> (u32, [u8; 32], &'static str) {
    if let Some((seq, hash)) = inactive_target {
        (seq, hash, "fixed-target reacquire")
    } else {
        (latest_seq, latest_hash, "no syncer yet")
    }
}

pub fn should_start_sync_from_header(
    is_current: bool,
    header_seq: u32,
    header_hash: [u8; 32],
    inactive_target: Option<(u32, [u8; 32])>,
) -> bool {
    is_current
        || inactive_target.is_some_and(|(target_seq, target_hash)| {
            header_seq == target_seq && header_hash == target_hash
        })
}

pub fn should_resume_from_sync_anchor(
    has_completed_sync: bool,
    has_sync_account_hash: bool,
    has_sync_ledger_hash: bool,
    has_sync_ledger_header: bool,
    rehydrated_root: bool,
) -> bool {
    has_completed_sync
        && has_sync_account_hash
        && (has_sync_ledger_hash || has_sync_ledger_header)
        && rehydrated_root
}

fn root_missing_from_wire(
    root_wire: &[u8],
) -> Vec<(crate::ledger::shamap_id::SHAMapNodeID, [u8; 32])> {
    let hashes = if root_wire.len() >= 516
        && root_wire[0] == 0x4D
        && root_wire[1] == 0x49
        && root_wire[2] == 0x4E
        && root_wire[3] == 0x00
    {
        &root_wire[4..516]
    } else if root_wire.len() >= 513 {
        &root_wire[..512]
    } else if root_wire.len() >= 512 {
        &root_wire[..512]
    } else {
        return vec![];
    };

    let root = crate::ledger::shamap_id::SHAMapNodeID::root();
    let mut missing = Vec::new();
    for branch in 0..16u8 {
        let off = (branch as usize) * 32;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hashes[off..off + 32]);
        if hash.iter().any(|&b| b != 0) {
            missing.push((root.child_id(branch), hash));
        }
    }
    missing
}

pub fn build_root_bootstrap_requests(
    syncer: &mut crate::sync_coordinator::SyncCoordinator,
    root_wire: &[u8],
    max_requests: usize,
) -> Vec<crate::network::message::RtxpMessage> {
    let missing = root_missing_from_wire(root_wire);
    if missing.is_empty() {
        return vec![];
    }

    let fanout = max_requests.max(1).min(missing.len());
    let per_request = (missing.len() + fanout - 1) / fanout;
    let mut reqs = Vec::with_capacity(fanout);

    for chunk in missing.chunks(per_request.max(1)) {
        for (_, hash) in chunk {
            syncer.peer.recent_nodes.insert(*hash);
        }
        let node_ids: Vec<Vec<u8>> = chunk.iter().map(|(nid, _)| nid.to_wire().to_vec()).collect();
        reqs.push(crate::network::relay::encode_get_ledger_state(
            syncer.ledger_hash(),
            &node_ids,
            0,
            1,
            None,
            syncer.ledger_seq(),
        ));
    }

    syncer.peer.in_flight = syncer.peer.in_flight.saturating_add(reqs.len());
    reqs
}
