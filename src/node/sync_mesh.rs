//! xLedgRS purpose: Sync Mesh piece of the live node runtime.
use super::*;

pub(crate) fn rotate_sync_peer_window(
    mut eligible: Vec<(PeerId, u32, u32)>,
    count: usize,
    start: usize,
) -> Vec<PeerId> {
    if eligible.is_empty() || count == 0 {
        return vec![];
    }

    eligible.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| a.0 .0.cmp(&b.0 .0))
    });

    let len = eligible.len();
    let take = count.min(len);
    let start = start % len;

    (0..take)
        .map(|offset| eligible[(start + offset) % len].0)
        .collect()
}

impl SharedState {
    /// Return up to `count` open peers that are best suited to serve `seq`.
    ///
    /// This keeps sync fan-out pinned to peers that actually advertise the
    /// target ledger while still falling back to open peers if ranges have not
    /// arrived yet.
    pub(super) fn sync_candidate_peers(&self, seq: u32, count: usize) -> Vec<PeerId> {
        let not_benched = |pid: &PeerId| {
            self.sync_peer_cooldown
                .get(pid)
                .map(|expires| std::time::Instant::now() >= *expires)
                .unwrap_or(true)
        };
        let is_configured_full_history = |pid: &PeerId| {
            self.peer_addrs
                .get(pid)
                .map(|addr| self.full_history_peers.contains(addr))
                .unwrap_or(false)
        };

        let mut eligible: Vec<(PeerId, u32, u32)> = self
            .peer_txs
            .keys()
            .filter(|pid| self.peers.get(pid).map(|ps| ps.is_open()).unwrap_or(true))
            .filter(|pid| not_benched(pid))
            .filter(|pid| {
                self.peer_ledger_range.get(pid).map_or_else(
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
            eligible = self
                .peer_txs
                .keys()
                .filter(|pid| self.peers.get(pid).map(|ps| ps.is_open()).unwrap_or(true))
                .filter(|pid| not_benched(pid))
                .map(|pid| {
                    let useful = self.peer_sync_useful.get(pid).copied().unwrap_or(0);
                    let latency = self.peer_latency.get(pid).copied().unwrap_or(u32::MAX / 4);
                    (*pid, useful, latency)
                })
                .collect();
        }

        if eligible.is_empty() {
            return vec![];
        }

        rotate_sync_peer_window(eligible, count, 0)
    }

    /// Send to N peers that have a specific ledger, round-robin.
    /// Uses peer_ledger_range from TMStatusChange — the authoritative source.
    pub(crate) fn send_to_peers_with_ledger(
        &mut self,
        msg: &RtxpMessage,
        seq: u32,
        count: usize,
    ) -> usize {
        let eligible = self.sync_candidate_peers(seq, count);

        if eligible.is_empty() {
            let ranges = self.peer_ledger_range.len();
            let connected = self.peer_txs.len();
            let covering = self
                .peer_ledger_range
                .values()
                .filter(|&&(min, max)| seq >= min && seq <= max)
                .count();
            if ranges > 0 {
                tracing::debug!(
                    "send_to_peers: seq={} connected={} ranges={} covering={} (no eligible — range/peer mismatch?)",
                    seq, connected, ranges, covering,
                );
            }
            return 0;
        }

        let mut sent = 0;
        for peer_id in eligible {
            if let Some(tx) = self.peer_txs.get(&peer_id) {
                if tx.try_send(msg.clone()).is_ok() {
                    sent += 1;
                }
            }
        }
        sent
    }
}

impl Node {
    pub(super) fn next_sync_peer(&self, state: &SharedState) -> Option<PeerId> {
        let mut open_peers: Vec<(PeerId, i32)> = state
            .peers
            .iter()
            .filter(|(_, ps)| ps.is_open())
            .filter(|(id, _)| {
                state
                    .sync_peer_cooldown
                    .get(id)
                    .map(|expires| std::time::Instant::now() >= *expires)
                    .unwrap_or(true)
            })
            .map(|(id, _)| {
                let mut score: i32 = rand::random::<u16>() as i32 % 10000;
                score += 10000;
                if let Some(&latency_ms) = state.peer_latency.get(id) {
                    score -= (latency_ms as i32) * 30;
                } else {
                    score -= 8000;
                }
                (*id, score)
            })
            .collect();
        if open_peers.is_empty() {
            return None;
        }
        open_peers.sort_by(|a, b| b.1.cmp(&a.1));
        let top = open_peers.len().min(6);
        let idx = self
            .sync_runtime
            .round_robin()
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % top;

        if idx == 0 {
            static PEER_SELECT_LOG_CTR: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let ctr = PEER_SELECT_LOG_CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if ctr % 100 == 0 {
                let total_open = state.peers.values().filter(|ps| ps.is_open()).count();
                let benched = state.sync_peer_cooldown.len();
                let top_scores: Vec<_> = open_peers
                    .iter()
                    .take(5)
                    .map(|(pid, s)| format!("{:?}={}", pid, s))
                    .collect();
                self.debug_log(&format!(
                    "PEER_SELECT: {} open, {} benched, top scores: [{}]",
                    total_open,
                    benched,
                    top_scores.join(", "),
                ));
            }
        }

        Some(open_peers[idx].0)
    }

    pub(super) fn select_sync_peers(
        &self,
        state: &SharedState,
        seq: u32,
        count: usize,
    ) -> Vec<PeerId> {
        let not_benched = |pid: &PeerId| {
            state
                .sync_peer_cooldown
                .get(pid)
                .map(|expires| std::time::Instant::now() >= *expires)
                .unwrap_or(true)
        };
        let is_configured_full_history = |pid: &PeerId| {
            state
                .peer_addrs
                .get(pid)
                .map(|addr| state.full_history_peers.contains(addr))
                .unwrap_or(false)
        };

        let mut eligible: Vec<(PeerId, u32, u32)> = state
            .peer_txs
            .keys()
            .filter(|pid| state.peers.get(pid).map(|ps| ps.is_open()).unwrap_or(true))
            .filter(|pid| not_benched(pid))
            .filter(|pid| {
                state.peer_ledger_range.get(pid).map_or_else(
                    || is_configured_full_history(pid),
                    |&(min, max)| (seq >= min && seq <= max) || is_configured_full_history(pid),
                )
            })
            .map(|pid| {
                let useful = state.peer_sync_useful.get(pid).copied().unwrap_or(0);
                let latency = state.peer_latency.get(pid).copied().unwrap_or(u32::MAX / 4);
                (*pid, useful, latency)
            })
            .collect();

        if eligible.is_empty() {
            eligible = state
                .peer_txs
                .keys()
                .filter(|pid| state.peers.get(pid).map(|ps| ps.is_open()).unwrap_or(true))
                .filter(|pid| not_benched(pid))
                .map(|pid| {
                    let useful = state.peer_sync_useful.get(pid).copied().unwrap_or(0);
                    let latency = state.peer_latency.get(pid).copied().unwrap_or(u32::MAX / 4);
                    (*pid, useful, latency)
                })
                .collect();
        }

        let start = self
            .sync_runtime
            .round_robin()
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        rotate_sync_peer_window(eligible, count, start)
    }

    pub(super) fn select_reply_sync_peers(
        &self,
        state: &SharedState,
        seq: u32,
        peer_useful_counts: &HashMap<PeerId, u32>,
        count: usize,
    ) -> Vec<PeerId> {
        if peer_useful_counts.is_empty() {
            return self.select_sync_peers(state, seq, count);
        }

        let not_benched = |pid: &PeerId| {
            state
                .sync_peer_cooldown
                .get(pid)
                .map(|expires| std::time::Instant::now() >= *expires)
                .unwrap_or(true)
        };
        let is_configured_full_history = |pid: &PeerId| {
            state
                .peer_addrs
                .get(pid)
                .map(|addr| state.full_history_peers.contains(addr))
                .unwrap_or(false)
        };

        let max_useful = peer_useful_counts.values().copied().max().unwrap_or(0);
        let threshold = max_useful / 2;
        let mut eligible: Vec<PeerId> = peer_useful_counts
            .iter()
            .filter(|(_, useful)| **useful >= threshold)
            .map(|(pid, _)| *pid)
            .filter(|pid| state.peers.get(pid).map(|ps| ps.is_open()).unwrap_or(true))
            .filter(not_benched)
            .filter(|pid| {
                state.peer_ledger_range.get(pid).map_or_else(
                    || is_configured_full_history(pid),
                    |&(min, max)| (seq >= min && seq <= max) || is_configured_full_history(pid),
                )
            })
            .collect();

        if eligible.is_empty() {
            return self.select_sync_peers(state, seq, count);
        }

        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        eligible.shuffle(&mut rng);
        eligible.truncate(count.min(eligible.len()));
        eligible
    }

    pub(super) fn select_timeout_sync_peers(
        &self,
        state: &SharedState,
        seq: u32,
        count: usize,
    ) -> Vec<PeerId> {
        let not_benched = |pid: &PeerId| {
            state
                .sync_peer_cooldown
                .get(pid)
                .map(|expires| std::time::Instant::now() >= *expires)
                .unwrap_or(true)
        };
        let is_configured_full_history = |pid: &PeerId| {
            state
                .peer_addrs
                .get(pid)
                .map(|addr| state.full_history_peers.contains(addr))
                .unwrap_or(false)
        };

        let now = std::time::Instant::now();
        let mut recent: Vec<(PeerId, std::time::Duration, u32, u32)> = state
            .peer_sync_last_useful
            .iter()
            .filter_map(|(pid, at)| {
                if !state.peers.get(pid).map(|ps| ps.is_open()).unwrap_or(false) {
                    return None;
                }
                if !not_benched(pid) {
                    return None;
                }
                let in_range = state.peer_ledger_range.get(pid).map_or_else(
                    || is_configured_full_history(pid),
                    |&(min, max)| (seq >= min && seq <= max) || is_configured_full_history(pid),
                );
                if !in_range {
                    return None;
                }
                let age = now.saturating_duration_since(*at);
                if age > std::time::Duration::from_secs(30) {
                    return None;
                }
                let useful = state.peer_sync_useful.get(pid).copied().unwrap_or(0);
                let latency = state.peer_latency.get(pid).copied().unwrap_or(u32::MAX / 4);
                Some((*pid, age, useful, latency))
            })
            .collect();

        recent.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| b.2.cmp(&a.2))
                .then_with(|| a.3.cmp(&b.3))
        });
        let mut selected: Vec<PeerId> = recent
            .into_iter()
            .take(count)
            .map(|(pid, _, _, _)| pid)
            .collect();

        if selected.len() < count {
            for pid in self.select_sync_peers(state, seq, count) {
                if selected.contains(&pid) {
                    continue;
                }
                selected.push(pid);
                if selected.len() >= count {
                    break;
                }
            }
        }

        selected
    }
}
