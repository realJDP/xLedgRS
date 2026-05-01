//! xLedgRS purpose: Shared State piece of the live node runtime.
use super::*;

impl SharedState {
    pub(super) fn new(ctx: NodeContext) -> Self {
        let start_time = ctx.start_time;
        Self {
            ctx,
            peers: HashMap::new(),
            peer_txs: HashMap::new(),
            known_peers: std::collections::VecDeque::new(),
            services: crate::services::RuntimeServices::new(start_time),
            connected_addrs: std::collections::HashSet::new(),
            peer_latency: HashMap::new(),
            peer_ping_sent: HashMap::new(),
            peer_addrs: HashMap::new(),
            peer_handshakes: HashMap::new(),
            peerfinder_slots: HashMap::new(),
            peer_cooldowns: HashMap::new(),
            sync_peer_cooldown: HashMap::new(),
            peer_sync_useful: HashMap::new(),
            peer_sync_last_useful: HashMap::new(),
            implausible_validation_state: HashMap::new(),
            rpc_sync_state: None,
            follower_state: None,
            pending_sync_anchor: None,
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

    pub fn record_validated_hash(&mut self, seq: u32, hash: [u8; 32]) {
        self.services.ledger_master.record_validated_hash(seq, hash);
        if !self.validated_hashes.contains_key(&seq) {
            self.validated_hash_order.push_back(seq);
            while self.validated_hash_order.len() > 256 {
                if let Some(old_seq) = self.validated_hash_order.pop_front() {
                    self.validated_hashes.remove(&old_seq);
                }
            }
        }
        self.validated_hashes.insert(seq, hash);
    }

    pub fn peer_count(&self) -> usize {
        self.peers.values().filter(|s| s.is_open()).count()
    }

    pub fn inbound_count(&self) -> usize {
        self.peer_direction
            .iter()
            .filter(|(id, dir)| {
                **dir == Direction::Inbound && self.peers.get(id).is_some_and(|s| s.is_open())
            })
            .count()
    }

    pub fn outbound_count(&self) -> usize {
        self.peer_direction
            .iter()
            .filter(|(id, dir)| {
                **dir == Direction::Outbound && self.peers.get(id).is_some_and(|s| s.is_open())
            })
            .count()
    }

    pub fn broadcast(&self, msg: &RtxpMessage, exclude: Option<PeerId>) {
        for (&id, tx) in &self.peer_txs {
            if exclude == Some(id) {
                continue;
            }
            let _ = tx.try_send(msg.clone());
        }
    }

    pub fn broadcast_with_squelch(
        &mut self,
        msg: &RtxpMessage,
        exclude: Option<PeerId>,
        validator_pubkey: &[u8],
    ) -> usize {
        let now = std::time::Instant::now();
        let mut skipped = 0usize;
        for (&id, tx) in &self.peer_txs {
            if exclude == Some(id) {
                continue;
            }
            if let Some(map) = self.peer_squelch.get_mut(&id) {
                if let Some(&expiry) = map.get(validator_pubkey) {
                    if now < expiry {
                        skipped += 1;
                        continue;
                    }
                    map.remove(validator_pubkey);
                }
            }
            let _ = tx.try_send(msg.clone());
        }
        skipped
    }
}
