//! xLedgRS purpose: Ops support for XRPL peer networking.
#[derive(Debug, Clone, Default)]
pub struct NetworkOpsSnapshot {
    pub server_state: String,
    pub peer_count: usize,
    pub object_count: usize,
    pub known_peers: usize,
    pub dialable_peers: usize,
    pub backed_off_peers: usize,
    pub peerfinder_retry_ready: usize,
    pub peerfinder_ready: usize,
    pub peerfinder_cooling: usize,
    pub peerfinder_cold: usize,
    pub peerfinder_sources: usize,
    pub cluster_configured: usize,
    pub cluster_observed: usize,
    pub cluster_connected: usize,
    pub blocked_peers: usize,
    pub warned_peers: usize,
    pub resource_tracked: usize,
    pub resource_ip_balance: i64,
    pub resource_peer_balance: i64,
    pub resource_balance: i64,
    pub resource_warning_events: u64,
    pub resource_disconnect_events: u64,
    pub node_store_fetch_errors: u64,
    pub node_store_flush_ops: u64,
    pub node_store_last_flush_unix: Option<u64>,
    pub node_store_last_flush_duration_ms: Option<u64>,
    pub fetch_pack_entries: usize,
    pub fetch_pack_backend_fill_total: u64,
    pub fetch_pack_reused_total: u64,
    pub fetch_pack_persisted_total: u64,
    pub fetch_pack_persist_errors_total: u64,
    pub fetch_pack_flush_ops: u64,
    pub fetch_pack_last_flush_unix: Option<u64>,
    pub fetch_pack_last_flush_duration_ms: Option<u64>,
    pub tracked_inbound_ledgers: usize,
    pub failed_inbound_ledgers: usize,
    pub queued_transactions: usize,
    pub tracked_transactions: usize,
    pub submitted_transactions: u64,
    pub active_path_requests: usize,
    pub tracked_inbound_transactions: usize,
    pub load_queue_depth: usize,
    pub load_queue_capacity: usize,
    pub load_queue_overloaded: bool,
    pub load_factor: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StateCounterSnapshot {
    pub transitions: u64,
    pub duration_us: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateAccountingSnapshot {
    pub disconnected: StateCounterSnapshot,
    pub connected: StateCounterSnapshot,
    pub syncing: StateCounterSnapshot,
    pub tracking: StateCounterSnapshot,
    pub full: StateCounterSnapshot,
    pub server_state_duration_us: u64,
    pub initial_sync_duration_us: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperatingMode {
    Disconnected = 0,
    Connected = 1,
    Syncing = 2,
    Tracking = 3,
    Full = 4,
}

impl OperatingMode {
    fn from_server_state(state: &str) -> Self {
        match state {
            "connected" => Self::Connected,
            "syncing" => Self::Syncing,
            "tracking" => Self::Tracking,
            "full" | "proposing" | "validating" => Self::Full,
            _ => Self::Disconnected,
        }
    }

    fn idx(self) -> usize {
        self as usize
    }
}

#[derive(Debug)]
struct StateAccountingInner {
    process_start: std::time::Instant,
    current_mode: OperatingMode,
    current_start: std::time::Instant,
    counters: [StateCounterSnapshot; 5],
    initial_sync_duration_us: Option<u64>,
}

#[derive(Debug)]
pub struct StateAccounting {
    inner: std::sync::Mutex<StateAccountingInner>,
}

impl Default for StateAccounting {
    fn default() -> Self {
        Self::new(std::time::Instant::now())
    }
}

impl StateAccounting {
    pub fn new(process_start: std::time::Instant) -> Self {
        Self {
            inner: std::sync::Mutex::new(StateAccountingInner {
                process_start,
                current_mode: OperatingMode::Disconnected,
                current_start: process_start,
                counters: [StateCounterSnapshot::default(); 5],
                initial_sync_duration_us: None,
            }),
        }
    }

    pub fn snapshot(
        &self,
        current_server_state: &str,
        now: std::time::Instant,
    ) -> StateAccountingSnapshot {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mode = OperatingMode::from_server_state(current_server_state);
        if mode != inner.current_mode {
            let elapsed = now
                .saturating_duration_since(inner.current_start)
                .as_micros() as u64;
            let current_idx = inner.current_mode.idx();
            inner.counters[current_idx].duration_us = inner.counters[current_idx]
                .duration_us
                .saturating_add(elapsed);
            inner.current_mode = mode;
            inner.current_start = now;
            let next_idx = mode.idx();
            inner.counters[next_idx].transitions =
                inner.counters[next_idx].transitions.saturating_add(1);
            if mode == OperatingMode::Full && inner.initial_sync_duration_us.is_none() {
                inner.initial_sync_duration_us = Some(
                    now.saturating_duration_since(inner.process_start)
                        .as_micros() as u64,
                );
            }
        }

        let mut counters = inner.counters;
        let current_elapsed = now
            .saturating_duration_since(inner.current_start)
            .as_micros() as u64;
        counters[inner.current_mode.idx()].duration_us = counters[inner.current_mode.idx()]
            .duration_us
            .saturating_add(current_elapsed);

        StateAccountingSnapshot {
            disconnected: counters[OperatingMode::Disconnected.idx()],
            connected: counters[OperatingMode::Connected.idx()],
            syncing: counters[OperatingMode::Syncing.idx()],
            tracking: counters[OperatingMode::Tracking.idx()],
            full: counters[OperatingMode::Full.idx()],
            server_state_duration_us: current_elapsed,
            initial_sync_duration_us: inner.initial_sync_duration_us,
        }
    }
}

pub fn snapshot_server_state_label(
    sync_done: bool,
    follower_healthy: bool,
    age: u64,
    peer_count: usize,
) -> &'static str {
    if sync_done && follower_healthy && age < 60 {
        "full"
    } else if sync_done {
        "tracking"
    } else if peer_count > 0 {
        "syncing"
    } else {
        "disconnected"
    }
}

pub fn synthetic_state_accounting_snapshot(
    start_time: std::time::Instant,
    current_server_state: &str,
    now: std::time::Instant,
) -> StateAccountingSnapshot {
    let mode = OperatingMode::from_server_state(current_server_state);
    let elapsed = now.saturating_duration_since(start_time).as_micros() as u64;
    let current = StateCounterSnapshot {
        transitions: 1,
        duration_us: elapsed,
    };
    let mut snapshot = StateAccountingSnapshot {
        server_state_duration_us: elapsed,
        initial_sync_duration_us: None,
        ..Default::default()
    };
    match mode {
        OperatingMode::Disconnected => snapshot.disconnected = current,
        OperatingMode::Connected => snapshot.connected = current,
        OperatingMode::Syncing => snapshot.syncing = current,
        OperatingMode::Tracking => snapshot.tracking = current,
        OperatingMode::Full => {
            snapshot.full = current;
            snapshot.initial_sync_duration_us = Some(elapsed);
        }
    }
    snapshot
}

impl NetworkOpsSnapshot {
    pub fn from_context(ctx: &crate::rpc::NodeContext) -> Self {
        let now = std::time::Instant::now();
        let active_path_requests = ctx
            .path_request_snapshot
            .as_ref()
            .map(|snapshot| snapshot.active_requests)
            .unwrap_or(0);
        let tracked_inbound_transactions = ctx
            .inbound_transactions_snapshot
            .as_ref()
            .map(|snapshot| snapshot.tracked)
            .unwrap_or(0);
        let (tracked_inbound_ledgers, failed_inbound_ledgers) = ctx
            .inbound_ledgers_snapshot
            .as_ref()
            .map(|snapshot| (snapshot.active, snapshot.failed))
            .unwrap_or((0, 0));
        let (tracked_transactions, submitted_transactions) = ctx
            .tx_master_snapshot
            .as_ref()
            .map(|snapshot| (snapshot.tracked, snapshot.submitted_total))
            .unwrap_or((0, 0));
        let queued_transactions = ctx
            .tx_relay_metrics
            .as_ref()
            .map(|snapshot| snapshot.queued_transactions)
            .unwrap_or(0);
        let known_peers = ctx
            .peerfinder_snapshot
            .as_ref()
            .map(|snapshot| snapshot.total_known)
            .unwrap_or(0);
        let dialable_peers = ctx
            .peerfinder_snapshot
            .as_ref()
            .map(|snapshot| snapshot.dialable)
            .unwrap_or(0);
        let backed_off_peers = ctx
            .peerfinder_snapshot
            .as_ref()
            .map(|snapshot| snapshot.backed_off)
            .unwrap_or(0);
        let peerfinder_retry_ready = ctx
            .peerfinder_snapshot
            .as_ref()
            .map(|snapshot| snapshot.retry_ready)
            .unwrap_or(0);
        let (peerfinder_ready, peerfinder_cooling, peerfinder_cold, peerfinder_sources) = ctx
            .peerfinder_snapshot
            .as_ref()
            .map(|snapshot| {
                (
                    snapshot.ready,
                    snapshot.cooling,
                    snapshot.cold,
                    snapshot.distinct_sources,
                )
            })
            .unwrap_or((0, 0, 0, 0));
        let (cluster_configured, cluster_connected, cluster_observed) = ctx
            .cluster_snapshot
            .as_ref()
            .map(|snapshot| (snapshot.configured, snapshot.connected, snapshot.observed))
            .unwrap_or((0, 0, 0));
        let blocked_peers = ctx
            .resource_snapshot
            .as_ref()
            .map(|snapshot| snapshot.blocked)
            .unwrap_or(0);
        let warned_peers = ctx
            .resource_snapshot
            .as_ref()
            .map(|snapshot| snapshot.warned)
            .unwrap_or(0);
        let resource_tracked = ctx
            .resource_snapshot
            .as_ref()
            .map(|snapshot| snapshot.tracked)
            .unwrap_or(0);
        let resource_ip_balance = ctx
            .resource_snapshot
            .as_ref()
            .map(|snapshot| snapshot.ip_balance)
            .unwrap_or(0);
        let resource_peer_balance = ctx
            .resource_snapshot
            .as_ref()
            .map(|snapshot| snapshot.peer_balance)
            .unwrap_or(0);
        let resource_balance = ctx
            .resource_snapshot
            .as_ref()
            .map(|snapshot| snapshot.total_balance)
            .unwrap_or(0);
        let resource_warning_events = ctx
            .resource_snapshot
            .as_ref()
            .map(|snapshot| snapshot.total_warnings)
            .unwrap_or(0);
        let resource_disconnect_events = ctx
            .resource_snapshot
            .as_ref()
            .map(|snapshot| snapshot.total_disconnects)
            .unwrap_or(0);
        let node_store_fetch_errors = ctx
            .node_store_snapshot
            .as_ref()
            .map(|snapshot| snapshot.fetch_errors)
            .unwrap_or(0);
        let node_store_flush_ops = ctx
            .node_store_snapshot
            .as_ref()
            .map(|snapshot| snapshot.flush_ops)
            .unwrap_or(0);
        let node_store_last_flush_unix = ctx
            .node_store_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.last_flush_unix);
        let node_store_last_flush_duration_ms = ctx
            .node_store_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.last_flush_duration_ms);
        let (
            fetch_pack_entries,
            fetch_pack_backend_fill_total,
            fetch_pack_reused_total,
            fetch_pack_persisted_total,
            fetch_pack_persist_errors_total,
            fetch_pack_flush_ops,
            fetch_pack_last_flush_unix,
            fetch_pack_last_flush_duration_ms,
        ) = ctx
            .fetch_pack_snapshot
            .as_ref()
            .map(|snapshot| {
                (
                    snapshot.tracked,
                    snapshot.backend_fill_total,
                    snapshot.reused_total,
                    snapshot.persisted_total,
                    snapshot.persist_errors_total,
                    snapshot.flush_ops,
                    snapshot.last_flush_unix,
                    snapshot.last_flush_duration_ms,
                )
            })
            .unwrap_or((0, 0, 0, 0, 0, 0, None, None));
        let rpc_sync_complete = ctx
            .rpc_sync_state
            .as_ref()
            .map(|state| state.complete.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(true);
        let follower_synced = ctx
            .follower_state
            .as_ref()
            .map(|state| {
                !state
                    .resync_requested
                    .load(std::sync::atomic::Ordering::Relaxed)
            })
            .unwrap_or(true);
        let load_stalled = ctx.load_snapshot.is_stalled(now);
        let load_troubled = load_stalled || ctx.load_snapshot.is_loaded_cluster();
        let server_state = if ctx.ledger_seq == 0 {
            "disconnected"
        } else if !rpc_sync_complete {
            "syncing"
        } else if !follower_synced {
            "tracking"
        } else if load_troubled {
            "tracking"
        } else if ctx.peer_count == 0 && known_peers == 0 {
            "disconnected"
        } else if ctx.peer_count == 0 {
            "connected"
        } else {
            "full"
        };
        Self {
            server_state: server_state.to_string(),
            peer_count: ctx.peer_count,
            object_count: ctx.object_count,
            known_peers,
            dialable_peers,
            backed_off_peers,
            peerfinder_retry_ready,
            peerfinder_ready,
            peerfinder_cooling,
            peerfinder_cold,
            peerfinder_sources,
            cluster_configured,
            cluster_observed,
            cluster_connected,
            blocked_peers,
            warned_peers,
            resource_tracked,
            resource_ip_balance,
            resource_peer_balance,
            resource_balance,
            resource_warning_events,
            resource_disconnect_events,
            node_store_fetch_errors,
            node_store_flush_ops,
            node_store_last_flush_unix,
            node_store_last_flush_duration_ms,
            fetch_pack_entries,
            fetch_pack_backend_fill_total,
            fetch_pack_reused_total,
            fetch_pack_persisted_total,
            fetch_pack_persist_errors_total,
            fetch_pack_flush_ops,
            fetch_pack_last_flush_unix,
            fetch_pack_last_flush_duration_ms,
            tracked_inbound_ledgers,
            failed_inbound_ledgers,
            queued_transactions,
            tracked_transactions,
            submitted_transactions,
            active_path_requests,
            tracked_inbound_transactions,
            load_queue_depth: ctx.load_snapshot.queue_depth,
            load_queue_capacity: ctx.load_snapshot.queue_capacity,
            load_queue_overloaded: ctx.load_snapshot.queue_overloaded,
            load_factor: ctx.load_snapshot.load_factor_server(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_accounting_tracks_syncing_and_full_durations() {
        let start = std::time::Instant::now();
        let accounting = StateAccounting::new(start);

        let syncing = accounting.snapshot("syncing", start + std::time::Duration::from_secs(2));
        assert_eq!(syncing.syncing.transitions, 1);
        assert_eq!(syncing.server_state_duration_us, 0);
        assert_eq!(syncing.disconnected.duration_us, 2_000_000);

        let full = accounting.snapshot("full", start + std::time::Duration::from_secs(5));
        assert_eq!(full.full.transitions, 1);
        assert_eq!(full.syncing.duration_us, 3_000_000);
        assert_eq!(full.initial_sync_duration_us, Some(5_000_000));
    }

    #[test]
    fn loaded_cluster_state_reports_tracking() {
        let mut ctx = crate::rpc::NodeContext::default();
        ctx.ledger_seq = 1;
        ctx.peer_count = 1;
        ctx.load_snapshot.cluster_fee = crate::network::load::LOAD_BASE * 2;

        let snapshot = NetworkOpsSnapshot::from_context(&ctx);
        assert_eq!(snapshot.server_state, "tracking");
    }
}
