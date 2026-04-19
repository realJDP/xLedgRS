//! Load/stall tracking for server status surfaces.
//!
//! xledgrs keeps a dedicated load-manager cycle backed by a runtime job-queue
//! view so `server_info`, `server_state`, and WebSocket `serverStatus` expose
//! live stall and fee-pressure state instead of fixed values.

use std::time::{Duration, Instant};

pub const LOAD_BASE: u32 = 256;
const FEE_INC_FRACTION: u32 = 4;
const FEE_DEC_FRACTION: u32 = 4;
const FEE_MAX: u32 = LOAD_BASE * 1_000_000;
const STALL_THRESHOLD: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobTypeSnapshot {
    pub job_type: String,
    pub waiting: usize,
    pub in_progress: usize,
    pub over_target: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobQueueSnapshot {
    pub threads: usize,
    pub queued_transactions: usize,
    pub tracked_transactions: usize,
    pub tracked_inbound_transactions: usize,
    pub active_path_requests: usize,
    pub active_inbound_ledgers: usize,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub overloaded: bool,
    pub job_types: Vec<JobTypeSnapshot>,
}

impl JobQueueSnapshot {
    pub fn pressure_fee(&self, load_base: u32) -> u32 {
        let mut fee = load_base;
        let soft_capacity = self.queue_capacity.max(1);
        if self.queued_transactions >= soft_capacity {
            let overflow = self
                .queued_transactions
                .saturating_sub(soft_capacity)
                .min(16) as u32;
            fee = fee
                .saturating_add(load_base)
                .saturating_add(overflow * (load_base / 4));
        } else if self.queued_transactions > 0 {
            let queue_pressure = ((self.queued_transactions as u32).min(soft_capacity as u32)
                * load_base)
                / (soft_capacity as u32).max(1);
            fee = fee.saturating_add(queue_pressure / 2);
        }
        fee = fee.saturating_add((self.tracked_transactions.min(32) as u32) * (load_base / 32));
        fee = fee
            .saturating_add((self.tracked_inbound_transactions.min(32) as u32) * (load_base / 64));
        fee = fee.saturating_add((self.active_path_requests.min(8) as u32) * (load_base / 8));
        fee = fee.saturating_add((self.active_inbound_ledgers.min(8) as u32) * (load_base / 4));
        fee.max(load_base)
    }

    pub fn is_overloaded(&self, load_base: u32) -> bool {
        self.overloaded || self.pressure_fee(load_base) > load_base
    }

    pub fn overload_reason(&self) -> Option<&str> {
        self.job_types
            .iter()
            .find(|job| job.over_target)
            .map(|job| job.job_type.as_str())
    }
}

#[derive(Debug, Clone, Default)]
pub struct JobQueue {
    snapshot: JobQueueSnapshot,
}

impl JobQueue {
    pub fn refresh(
        &mut self,
        queued_transactions: usize,
        queue_capacity: usize,
        tracked_transactions: usize,
        tracked_inbound_transactions: usize,
        active_path_requests: usize,
        active_inbound_ledgers: usize,
    ) {
        let queue_depth = queued_transactions
            .saturating_add(tracked_transactions)
            .saturating_add(tracked_inbound_transactions)
            .saturating_add(active_path_requests.saturating_mul(2))
            .saturating_add(active_inbound_ledgers.saturating_mul(4));
        let soft_capacity = queue_capacity.max(1);
        let threads = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        let tracked_target = soft_capacity.saturating_mul(2).max(4);
        let inbound_target = soft_capacity.max(4);
        let path_target = threads.max(2);
        let ledger_target = threads.max(1);
        let job_types = vec![
            JobTypeSnapshot {
                job_type: "transaction_queue".to_string(),
                waiting: queued_transactions,
                in_progress: 0,
                over_target: queued_transactions >= soft_capacity,
            },
            JobTypeSnapshot {
                job_type: "transaction_tracking".to_string(),
                waiting: tracked_transactions,
                in_progress: 0,
                over_target: tracked_transactions >= tracked_target,
            },
            JobTypeSnapshot {
                job_type: "inbound_transactions".to_string(),
                waiting: tracked_inbound_transactions,
                in_progress: 0,
                over_target: tracked_inbound_transactions >= inbound_target,
            },
            JobTypeSnapshot {
                job_type: "path_requests".to_string(),
                waiting: 0,
                in_progress: active_path_requests,
                over_target: active_path_requests >= path_target,
            },
            JobTypeSnapshot {
                job_type: "inbound_ledgers".to_string(),
                waiting: 0,
                in_progress: active_inbound_ledgers,
                over_target: active_inbound_ledgers >= ledger_target,
            },
        ];
        self.snapshot = JobQueueSnapshot {
            threads,
            queued_transactions,
            tracked_transactions,
            tracked_inbound_transactions,
            active_path_requests,
            active_inbound_ledgers,
            queue_depth,
            queue_capacity,
            overloaded: queued_transactions >= soft_capacity
                || queue_depth > soft_capacity
                || job_types.iter().any(|job| job.over_target),
            job_types,
        };
    }

    pub fn snapshot(&self) -> JobQueueSnapshot {
        self.snapshot.clone()
    }
}

#[derive(Debug, Clone)]
pub struct LoadSnapshot {
    pub load_base: u32,
    pub local_fee: u32,
    pub queue_fee: u32,
    pub remote_fee: u32,
    pub cluster_fee: u32,
    pub job_queue_threads: usize,
    pub queued_transactions: usize,
    pub tracked_transactions: usize,
    pub tracked_inbound_transactions: usize,
    pub active_path_requests: usize,
    pub active_inbound_ledgers: usize,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub queue_overloaded: bool,
    pub queue_job_types: Vec<JobTypeSnapshot>,
    pub last_heartbeat: Instant,
    pub armed: bool,
    pub warning_count: u64,
    pub slow_operation_count: u64,
    pub sync_stall_count: u64,
    pub service_cycles: u64,
    pub overload_cycles: u64,
    pub idle_cycles: u64,
    pub last_warning_reason: Option<String>,
    pub last_cycle_reason: Option<String>,
}

impl Default for LoadSnapshot {
    fn default() -> Self {
        Self {
            load_base: LOAD_BASE,
            local_fee: LOAD_BASE,
            queue_fee: LOAD_BASE,
            remote_fee: LOAD_BASE,
            cluster_fee: LOAD_BASE,
            job_queue_threads: 1,
            queued_transactions: 0,
            tracked_transactions: 0,
            tracked_inbound_transactions: 0,
            active_path_requests: 0,
            active_inbound_ledgers: 0,
            queue_depth: 0,
            queue_capacity: 0,
            queue_overloaded: false,
            queue_job_types: Vec::new(),
            last_heartbeat: Instant::now(),
            armed: false,
            warning_count: 0,
            slow_operation_count: 0,
            sync_stall_count: 0,
            service_cycles: 0,
            overload_cycles: 0,
            idle_cycles: 0,
            last_warning_reason: None,
            last_cycle_reason: None,
        }
    }
}

impl LoadSnapshot {
    pub fn fee_reference(&self) -> u32 {
        self.load_base
    }

    pub fn fee_queue(&self) -> u32 {
        self.local_fee
    }

    pub fn fee_escalation(&self) -> u32 {
        self.load_factor_server()
    }

    pub fn pressure_floor(&self) -> u32 {
        self.load_base
            .max(self.queue_fee)
            .max(self.remote_fee)
            .max(self.cluster_fee)
    }

    pub fn load_factor_server(&self) -> u32 {
        self.local_fee
            .max(self.remote_fee)
            .max(self.cluster_fee)
            .max(self.load_base)
    }

    pub fn load_factor(&self) -> u32 {
        self.load_factor_server()
    }

    pub fn scaling_factors(&self) -> (u32, u32) {
        (
            self.local_fee.max(self.remote_fee),
            self.remote_fee.max(self.cluster_fee),
        )
    }

    pub fn heartbeat_age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_heartbeat)
    }

    pub fn heartbeat_age_secs(&self, now: Instant) -> u64 {
        self.heartbeat_age(now).as_secs()
    }

    pub fn is_stalled(&self, now: Instant) -> bool {
        self.armed && self.heartbeat_age(now) >= STALL_THRESHOLD
    }

    pub fn load_factor_local(&self) -> Option<u32> {
        (self.local_fee != self.load_base).then_some(self.local_fee)
    }

    pub fn load_factor_net(&self) -> Option<u32> {
        (self.remote_fee != self.load_base).then_some(self.remote_fee)
    }

    pub fn load_factor_cluster(&self) -> Option<u32> {
        (self.cluster_fee != self.load_base).then_some(self.cluster_fee)
    }

    pub fn is_loaded_local(&self) -> bool {
        self.local_fee != self.load_base
    }

    pub fn is_queue_overloaded(&self) -> bool {
        self.queue_overloaded
    }

    pub fn is_loaded_cluster(&self) -> bool {
        self.local_fee != self.load_base || self.cluster_fee != self.load_base
    }

    pub fn service_cycles(&self) -> u64 {
        self.service_cycles
    }

    pub fn overload_cycles(&self) -> u64 {
        self.overload_cycles
    }

    pub fn idle_cycles(&self) -> u64 {
        self.idle_cycles
    }
}

#[derive(Debug, Clone, Default)]
pub struct LoadManager {
    snapshot: LoadSnapshot,
    raise_count: u32,
}

impl LoadManager {
    pub fn activate_stall_detector(&mut self, now: Instant) {
        self.snapshot.armed = true;
        self.snapshot.last_heartbeat = now;
    }

    pub fn heartbeat(&mut self, now: Instant) {
        self.snapshot.last_heartbeat = now;
        self.raise_count = 0;
    }

    pub fn note_slow_operation(
        &mut self,
        elapsed: Duration,
        reason: impl Into<String>,
        _now: Instant,
    ) -> bool {
        self.snapshot.slow_operation_count = self.snapshot.slow_operation_count.saturating_add(1);
        let reason = reason.into();
        if elapsed >= Duration::from_secs(1) {
            self.snapshot.warning_count = self.snapshot.warning_count.saturating_add(1);
            self.snapshot.last_warning_reason = Some(reason);
            self.raise_count = self.raise_count.saturating_add(2);
            return self.try_raise_local_fee();
        }
        self.note_warning(reason)
    }

    pub fn note_sync_stall(&mut self, reason: impl Into<String>, _now: Instant) -> bool {
        self.snapshot.sync_stall_count = self.snapshot.sync_stall_count.saturating_add(1);
        self.note_warning(reason)
    }

    pub fn set_remote_fee(&mut self, fee: u32) {
        self.snapshot.remote_fee = fee.max(self.snapshot.load_base);
    }

    pub fn set_cluster_fee(&mut self, fee: u32) {
        self.snapshot.cluster_fee = fee.max(self.snapshot.load_base);
    }

    pub fn refresh_local_queue_health(&mut self, queue: &JobQueueSnapshot, _now: Instant) {
        self.snapshot.job_queue_threads = queue.threads;
        self.snapshot.queued_transactions = queue.queued_transactions;
        self.snapshot.tracked_transactions = queue.tracked_transactions;
        self.snapshot.tracked_inbound_transactions = queue.tracked_inbound_transactions;
        self.snapshot.active_path_requests = queue.active_path_requests;
        self.snapshot.active_inbound_ledgers = queue.active_inbound_ledgers;
        self.snapshot.queue_depth = queue.queue_depth;
        self.snapshot.queue_capacity = queue.queue_capacity;
        self.snapshot.queue_fee = queue.pressure_fee(self.snapshot.load_base);
        self.snapshot.queue_overloaded = queue.is_overloaded(self.snapshot.load_base);
        self.snapshot.queue_job_types = queue.job_types.clone();
        self.snapshot.local_fee = self.snapshot.local_fee.max(self.snapshot.pressure_floor());
    }

    pub fn refresh_network_health(
        &mut self,
        peer_count: usize,
        known_peers: usize,
        dialable_peers: usize,
        backed_off_peers: usize,
        retry_ready_peers: usize,
        ready_peers: usize,
        cooling_peers: usize,
        cold_peers: usize,
        redirects: usize,
        distinct_sources: usize,
        blocked_peers: usize,
        warned_peers: usize,
        resource_ip_balance: i64,
        resource_peer_balance: i64,
        resource_balance: i64,
        resource_disconnects: u64,
        resource_warnings: u64,
    ) {
        let overloaded = peer_count == 0 && known_peers == 0
            || blocked_peers > 0
            || warned_peers > 0
            || resource_disconnects > 0
            || resource_warnings > 0
            || resource_balance > 0
            || resource_ip_balance > 0
            || resource_peer_balance > 0;
        let redirect_pressure = redirects > 0;
        let _overloaded = overloaded || redirect_pressure;
        let mut fee = self.snapshot.load_base;
        if peer_count == 0 && dialable_peers > 0 {
            fee = fee.saturating_mul(2);
        } else if peer_count == 0 && known_peers > 0 {
            fee = fee.saturating_add(self.snapshot.load_base);
        } else if peer_count <= 1 && known_peers > peer_count {
            fee = fee.saturating_add(self.snapshot.load_base / 2);
        }
        if known_peers > 0 && dialable_peers == 0 {
            fee = fee.saturating_add(self.snapshot.load_base);
        }
        if ready_peers == 0 && known_peers > 0 {
            fee = fee.saturating_add(self.snapshot.load_base / 2);
        }
        fee = fee.saturating_add((cooling_peers.min(8) as u32) * (self.snapshot.load_base / 16));
        fee = fee.saturating_add((cold_peers.min(8) as u32) * (self.snapshot.load_base / 8));
        fee = fee.saturating_add((backed_off_peers.min(8) as u32) * (self.snapshot.load_base / 8));
        if backed_off_peers > 0 && retry_ready_peers == 0 {
            fee = fee.saturating_add(self.snapshot.load_base / 8);
        }
        if redirects > 0 {
            fee = fee.saturating_add((redirects.min(8) as u32) * (self.snapshot.load_base / 16));
        }
        if known_peers > 0 && distinct_sources > 0 {
            let concentration = known_peers.saturating_sub(distinct_sources).min(8) as u32;
            fee = fee.saturating_add(concentration * (self.snapshot.load_base / 16));
        }
        fee = fee.saturating_add((warned_peers.min(8) as u32) * (self.snapshot.load_base / 16));
        fee = fee.saturating_add((blocked_peers.min(8) as u32) * (self.snapshot.load_base / 4));
        if resource_ip_balance > 0 {
            let balance_pressure = ((resource_ip_balance / 1_000).clamp(0, 8)) as u32;
            fee = fee.saturating_add(balance_pressure * (self.snapshot.load_base / 16));
        }
        if resource_peer_balance > 0 {
            let balance_pressure = ((resource_peer_balance / 1_000).clamp(0, 8)) as u32;
            fee = fee.saturating_add(balance_pressure * (self.snapshot.load_base / 8));
        }
        if resource_balance > 0 {
            let balance_pressure = ((resource_balance / 1_000).clamp(0, 8)) as u32;
            fee = fee.saturating_add(balance_pressure * (self.snapshot.load_base / 8));
        }
        fee = fee
            .saturating_add((resource_disconnects.min(8) as u32) * (self.snapshot.load_base / 8));
        fee =
            fee.saturating_add((resource_warnings.min(16) as u32) * (self.snapshot.load_base / 32));
        self.set_remote_fee(fee);
    }

    pub fn refresh_cluster_health(
        &mut self,
        configured: usize,
        connected: usize,
        reported_fee: Option<u32>,
    ) {
        let mut fee = self.snapshot.load_base;
        if configured > 0 && connected < configured {
            let missing = configured.saturating_sub(connected).min(4) as u32;
            fee = fee.saturating_add(missing * (self.snapshot.load_base / 2));
            if connected == 0 {
                fee = fee.saturating_add(self.snapshot.load_base);
            }
        }
        if let Some(reported_fee) = reported_fee {
            fee = fee.max(reported_fee.max(self.snapshot.load_base));
        }
        self.set_cluster_fee(fee);
    }

    pub fn snapshot(&self) -> LoadSnapshot {
        self.snapshot.clone()
    }

    pub fn run_cycle(&mut self, now: Instant) -> bool {
        self.snapshot.service_cycles = self.snapshot.service_cycles.saturating_add(1);
        let overloaded = self.snapshot.queue_overloaded;
        self.snapshot.last_cycle_reason = Some(if overloaded {
            self.snapshot
                .queue_job_types
                .iter()
                .find(|job| job.over_target)
                .map(|job| format!("queue_overloaded:{}", job.job_type))
                .unwrap_or_else(|| "queue_overloaded".to_string())
        } else {
            "queue_idle".to_string()
        });
        if overloaded {
            self.snapshot.overload_cycles = self.snapshot.overload_cycles.saturating_add(1);
            self.raise_local_fee()
        } else {
            self.snapshot.idle_cycles = self.snapshot.idle_cycles.saturating_add(1);
            self.lower_local_fee(now)
        }
    }

    pub fn note_service_cycle(
        &mut self,
        overloaded: bool,
        reason: impl Into<String>,
        now: Instant,
    ) -> bool {
        self.snapshot.service_cycles = self.snapshot.service_cycles.saturating_add(1);
        self.snapshot.last_cycle_reason = Some(reason.into());
        if overloaded {
            self.snapshot.overload_cycles = self.snapshot.overload_cycles.saturating_add(1);
            self.snapshot.warning_count = self.snapshot.warning_count.saturating_add(1);
            self.raise_count = self.raise_count.saturating_add(1);
            self.try_raise_local_fee()
        } else {
            self.snapshot.idle_cycles = self.snapshot.idle_cycles.saturating_add(1);
            self.heartbeat(now);
            false
        }
    }

    fn note_warning(&mut self, reason: impl Into<String>) -> bool {
        self.snapshot.warning_count = self.snapshot.warning_count.saturating_add(1);
        self.snapshot.last_warning_reason = Some(reason.into());
        self.raise_count = self.raise_count.saturating_add(1);
        self.try_raise_local_fee()
    }

    fn try_raise_local_fee(&mut self) -> bool {
        if self.raise_count < 2 {
            return false;
        }
        self.raise_count = 0;
        self.raise_local_fee()
    }

    fn raise_local_fee(&mut self) -> bool {
        let original = self.snapshot.local_fee;
        self.snapshot.local_fee = self.snapshot.local_fee.max(self.snapshot.pressure_floor());
        let inc = (self.snapshot.local_fee / FEE_INC_FRACTION).max(1);
        self.snapshot.local_fee = self.snapshot.local_fee.saturating_add(inc).min(FEE_MAX);
        self.snapshot.local_fee != original
    }

    fn lower_local_fee(&mut self, now: Instant) -> bool {
        let original = self.snapshot.local_fee;
        self.heartbeat(now);
        if self.snapshot.local_fee > self.snapshot.load_base {
            let dec = (self.snapshot.local_fee / FEE_DEC_FRACTION).max(1);
            self.snapshot.local_fee = self
                .snapshot
                .local_fee
                .saturating_sub(dec)
                .max(self.snapshot.pressure_floor());
        } else {
            self.snapshot.local_fee = self.snapshot.local_fee.max(self.snapshot.pressure_floor());
        }
        self.snapshot.local_fee != original
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue_snapshot(
        queued_transactions: usize,
        queue_capacity: usize,
        tracked_transactions: usize,
        tracked_inbound_transactions: usize,
        active_path_requests: usize,
        active_inbound_ledgers: usize,
    ) -> JobQueueSnapshot {
        let mut queue = JobQueue::default();
        queue.refresh(
            queued_transactions,
            queue_capacity,
            tracked_transactions,
            tracked_inbound_transactions,
            active_path_requests,
            active_inbound_ledgers,
        );
        queue.snapshot()
    }

    #[test]
    fn repeated_warnings_raise_local_fee() {
        let now = Instant::now();
        let mut manager = LoadManager::default();
        manager.activate_stall_detector(now);
        assert!(!manager.note_sync_stall("first", now));
        assert!(manager.note_sync_stall("second", now));
        assert!(manager.snapshot().local_fee > LOAD_BASE);
    }

    #[test]
    fn heartbeat_clears_stall_and_run_cycle_lowers_local_fee() {
        let now = Instant::now();
        let mut manager = LoadManager::default();
        manager.activate_stall_detector(now);
        let later = now + STALL_THRESHOLD + Duration::from_secs(1);
        assert!(!manager.note_sync_stall("one", now));
        assert!(manager.note_sync_stall("two", now));
        let stalled = manager.snapshot();
        assert!(stalled.is_stalled(later));
        let raised_fee = stalled.local_fee;
        manager.heartbeat(later);
        assert!(!manager.snapshot().is_stalled(later));
        manager.run_cycle(later);
        let recovered = manager.snapshot();
        assert!(recovered.local_fee < raised_fee);
    }

    #[test]
    fn network_and_cluster_health_raise_remote_components() {
        let mut manager = LoadManager::default();
        manager.refresh_network_health(0, 5, 4, 1, 1, 1, 1, 2, 2, 2, 3, 2, 2500, 3500, 6000, 2, 4);
        manager.refresh_cluster_health(3, 1, None);
        let snapshot = manager.snapshot();
        assert!(snapshot.remote_fee > LOAD_BASE);
        assert!(snapshot.cluster_fee > LOAD_BASE);
    }

    #[test]
    fn reported_cluster_load_raises_cluster_fee() {
        let mut manager = LoadManager::default();
        manager.refresh_cluster_health(1, 1, Some(LOAD_BASE * 3));
        assert_eq!(manager.snapshot().cluster_fee, LOAD_BASE * 3);
    }

    #[test]
    fn snapshot_exposes_rippled_style_scaling_factors() {
        let mut manager = LoadManager::default();
        manager.set_remote_fee(LOAD_BASE * 2);
        manager.set_cluster_fee(LOAD_BASE * 3);
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.scaling_factors(), (LOAD_BASE * 2, LOAD_BASE * 3));
        assert_eq!(snapshot.fee_reference(), LOAD_BASE);
        assert_eq!(snapshot.fee_queue(), LOAD_BASE);
        assert_eq!(snapshot.fee_escalation(), LOAD_BASE * 3);
        assert!(!snapshot.is_loaded_local());
        assert!(snapshot.is_loaded_cluster());
    }

    #[test]
    fn idle_decay_keeps_the_pressure_floor() {
        let mut manager = LoadManager::default();
        manager.set_remote_fee(LOAD_BASE * 2);
        manager.set_cluster_fee(LOAD_BASE * 3);
        manager.snapshot.local_fee = LOAD_BASE * 6;
        let now = Instant::now();
        manager.run_cycle(now);
        let snapshot = manager.snapshot();
        assert!(snapshot.local_fee >= LOAD_BASE * 3);
        assert_eq!(snapshot.pressure_floor(), LOAD_BASE * 3);
    }

    #[test]
    fn overload_raises_local_fee_above_the_pressure_floor() {
        let mut manager = LoadManager::default();
        manager.set_remote_fee(LOAD_BASE * 2);
        manager.set_cluster_fee(LOAD_BASE * 3);
        let now = Instant::now();
        manager.activate_stall_detector(now);
        let queue = queue_snapshot(12, 4, 6, 4, 2, 3);
        manager.refresh_local_queue_health(&queue, now);
        assert!(manager.run_cycle(now));
        let snapshot = manager.snapshot();
        assert!(snapshot.local_fee > LOAD_BASE * 3);
        assert!(snapshot.local_fee >= snapshot.fee_queue());
        assert_eq!(snapshot.fee_escalation(), snapshot.load_factor_server());
    }

    #[test]
    fn local_queue_pressure_raises_the_queue_floor() {
        let now = Instant::now();
        let mut manager = LoadManager::default();
        manager.activate_stall_detector(now);

        let queue = queue_snapshot(12, 4, 6, 4, 2, 3);
        manager.refresh_local_queue_health(&queue, now);
        manager.run_cycle(now);
        let snapshot = manager.snapshot();

        assert!(snapshot.queue_fee > LOAD_BASE);
        assert!(snapshot.local_fee >= snapshot.queue_fee);
        assert!(snapshot.queue_overloaded);
        assert_eq!(
            snapshot.last_cycle_reason.as_deref(),
            Some("queue_overloaded:transaction_queue")
        );
        assert!(snapshot.queue_depth >= 12);
        assert_eq!(snapshot.queued_transactions, 12);
        assert_eq!(snapshot.tracked_transactions, 6);
        assert_eq!(snapshot.tracked_inbound_transactions, 4);
        assert_eq!(snapshot.active_path_requests, 2);
        assert_eq!(snapshot.active_inbound_ledgers, 3);
    }

    #[test]
    fn resource_pressure_raises_remote_fee() {
        let mut manager = LoadManager::default();
        manager.refresh_network_health(
            2, 4, 2, 0, 1, 1, 1, 1, 1, 1, 0, 0, 6_000, 1_500, 12_000, 3, 5,
        );
        let snapshot = manager.snapshot();
        assert!(snapshot.remote_fee > LOAD_BASE);
    }

    #[test]
    fn redirect_churn_raises_remote_fee() {
        let mut manager = LoadManager::default();
        manager.refresh_network_health(2, 4, 2, 0, 1, 1, 1, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0);
        let snapshot = manager.snapshot();
        assert!(snapshot.remote_fee > LOAD_BASE);
    }

    #[test]
    fn concentrated_sources_raise_remote_fee_more_than_diverse_sources() {
        let mut concentrated = LoadManager::default();
        concentrated
            .refresh_network_health(2, 6, 4, 0, 2, 1, 0, 1, 0, 1, 0, 0, 1_000, 0, 1_000, 0, 0);
        let concentrated_fee = concentrated.snapshot().remote_fee;

        let mut diverse = LoadManager::default();
        diverse.refresh_network_health(2, 6, 4, 0, 2, 1, 0, 1, 0, 6, 0, 0, 1_000, 0, 1_000, 0, 0);
        let diverse_fee = diverse.snapshot().remote_fee;

        assert!(concentrated_fee > diverse_fee);
    }

    #[test]
    fn service_cycles_track_overload_and_idle_pressure() {
        let now = Instant::now();
        let mut manager = LoadManager::default();
        manager.activate_stall_detector(now);
        let overloaded_queue = queue_snapshot(12, 4, 6, 4, 2, 3);
        manager.refresh_local_queue_health(&overloaded_queue, now);
        assert!(manager.run_cycle(now));
        let overloaded = manager.snapshot();
        assert_eq!(overloaded.service_cycles, 1);
        assert_eq!(overloaded.overload_cycles, 1);
        assert!(overloaded.local_fee > LOAD_BASE);

        let later = now + Duration::from_secs(1);
        let idle_queue = queue_snapshot(0, 4, 0, 0, 0, 0);
        manager.refresh_local_queue_health(&idle_queue, later);
        assert!(manager.run_cycle(later));
        let recovered = manager.snapshot();
        assert_eq!(recovered.service_cycles, 2);
        assert_eq!(recovered.idle_cycles, 1);
        assert_eq!(recovered.last_cycle_reason.as_deref(), Some("queue_idle"));
        assert!(recovered.local_fee >= LOAD_BASE);
    }

    #[test]
    fn job_queue_snapshot_tracks_overload_inputs() {
        let mut queue = JobQueue::default();
        queue.refresh(12, 4, 6, 4, 2, 3);
        let snapshot = queue.snapshot();
        assert!(snapshot.overloaded);
        assert_eq!(snapshot.queue_depth, 38);
        assert!(snapshot.is_overloaded(LOAD_BASE));
        assert!(snapshot.pressure_fee(LOAD_BASE) > LOAD_BASE);
        assert!(snapshot.threads >= 1);
        assert_eq!(snapshot.job_types[0].job_type, "transaction_queue");
        assert!(snapshot.job_types.iter().any(|job| job.over_target));
        assert_eq!(snapshot.overload_reason(), Some("transaction_queue"));
    }
}
