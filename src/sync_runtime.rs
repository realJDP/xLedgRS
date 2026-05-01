//! Live sync runtime coordination.
//!
//! Connects the sync coordinator, peer transport, timers, progress snapshots,
//! and node state transitions while a fixed ledger is being acquired.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use tokio::sync::{mpsc, Notify};

use crate::network::message::RtxpMessage;
use crate::network::peer::PeerId;

pub struct HeaderBootstrapPlan {
    pub progress: crate::sync_coordinator::SyncProgress,
    pub reqs: Vec<RtxpMessage>,
    pub seed_count: usize,
    pub restarted: bool,
}

pub struct HeaderTriggerPlan {
    pub ignore_mismatched_fixed_target: Option<(u32, [u8; 32])>,
    pub restart_fixed_target: bool,
    pub installed_syncer: bool,
    pub sync_lock_busy: bool,
    pub sync_completed_from_disk: bool,
    pub bootstrap: Option<HeaderBootstrapPlan>,
}

pub struct SyncRuntime {
    sync: Arc<Mutex<Option<crate::sync_coordinator::SyncCoordinator>>>,
    target_hash8: Arc<AtomicU64>,
    round_robin: Arc<AtomicUsize>,
    data_queue: Arc<Mutex<Vec<(PeerId, crate::proto::TmLedgerData)>>>,
    data_notify: Arc<Notify>,
    diff_sync_tx: mpsc::Sender<crate::proto::TmLedgerData>,
    diff_sync_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<crate::proto::TmLedgerData>>>,
}

impl SyncRuntime {
    pub fn new() -> Self {
        let (diff_sync_tx, diff_sync_rx) = mpsc::channel::<crate::proto::TmLedgerData>(4096);
        Self {
            sync: Arc::new(Mutex::new(None)),
            target_hash8: Arc::new(AtomicU64::new(0)),
            round_robin: Arc::new(AtomicUsize::new(0)),
            data_queue: Arc::new(Mutex::new(Vec::new())),
            data_notify: Arc::new(Notify::new()),
            diff_sync_tx,
            diff_sync_rx: Arc::new(tokio::sync::Mutex::new(diff_sync_rx)),
        }
    }

    pub fn lock_sync(&self) -> MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>> {
        self.sync.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn try_lock_sync(
        &self,
    ) -> Result<
        MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>>,
        TryLockError<MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>>>,
    > {
        self.sync.try_lock()
    }

    pub fn sync_arc(&self) -> Arc<Mutex<Option<crate::sync_coordinator::SyncCoordinator>>> {
        self.sync.clone()
    }

    pub fn clear_syncer(&self) {
        let mut guard = self.lock_sync();
        if let Some(syncer) = guard.as_mut() {
            syncer.stop();
        }
        *guard = None;
        self.set_target_hash8(0);
    }

    pub fn has_syncer(&self) -> bool {
        self.try_lock_sync()
            .ok()
            .is_some_and(|guard| guard.is_some())
    }

    pub fn sync_active(&self) -> bool {
        self.try_lock_sync()
            .ok()
            .and_then(|guard| guard.as_ref().map(|syncer| syncer.active()))
            .unwrap_or(false)
    }

    pub fn inactive_target(&self) -> Option<(u32, [u8; 32])> {
        self.try_lock_sync().ok().and_then(|guard| {
            guard.as_ref().and_then(|syncer| {
                (!syncer.active()).then_some((syncer.ledger_seq(), *syncer.ledger_hash()))
            })
        })
    }

    fn bootstrap_plan_from_wire(
        syncer: &mut crate::sync_coordinator::SyncCoordinator,
        ld: &crate::proto::TmLedgerData,
        seed_count: usize,
        restarted: bool,
    ) -> Option<HeaderBootstrapPlan> {
        let root = ld.nodes.get(1)?;
        let fake_ld = crate::proto::TmLedgerData {
            ledger_hash: ld.ledger_hash.clone(),
            ledger_seq: ld.ledger_seq,
            r#type: crate::proto::TmLedgerInfoType::LiAsNode as i32,
            nodes: vec![crate::proto::TmLedgerNode {
                nodedata: root.nodedata.clone(),
                nodeid: root.nodeid.clone(),
            }],
            request_cookie: None,
            error: None,
        };
        let progress = syncer.process_response(&fake_ld);
        let reqs = {
            let reqs = crate::sync_bootstrap::build_root_bootstrap_requests(
                syncer,
                &root.nodedata,
                seed_count,
            );
            if reqs.is_empty() {
                syncer.build_multi_requests(seed_count, crate::sync::SyncRequestReason::Reply)
            } else {
                reqs
            }
        };
        Some(HeaderBootstrapPlan {
            progress,
            reqs,
            seed_count,
            restarted,
        })
    }

    pub fn plan_header_trigger(
        &self,
        header: crate::ledger::LedgerHeader,
        ld: &crate::proto::TmLedgerData,
        backend: Option<Arc<dyn crate::ledger::node_store::NodeStore>>,
        leaf_count: Option<usize>,
        open_peers: usize,
        already_syncing: bool,
        sync_in_progress: bool,
    ) -> HeaderTriggerPlan {
        let mut plan = HeaderTriggerPlan {
            ignore_mismatched_fixed_target: None,
            restart_fixed_target: false,
            installed_syncer: false,
            sync_lock_busy: false,
            sync_completed_from_disk: false,
            bootstrap: None,
        };

        let mut guard = match self.try_lock_sync_for_header_trigger() {
            Some(guard) => guard,
            None => {
                plan.sync_lock_busy = true;
                return plan;
            }
        };

        if !already_syncing {
            if let Some(syncer) = guard.as_ref() {
                if !syncer.active() {
                    let target_hash = *syncer.ledger_hash();
                    let target_seq = syncer.ledger_seq();
                    let target_header = syncer.sync_header.clone();
                    if header.hash != target_hash {
                        plan.ignore_mismatched_fixed_target = Some((target_seq, target_hash));
                        return plan;
                    }
                    let mut restarted = crate::sync_coordinator::SyncCoordinator::new(
                        target_header.sequence,
                        target_header.hash,
                        target_header.account_hash,
                        backend.clone(),
                        target_header,
                    );
                    if let Some(lc) = leaf_count {
                        restarted.set_leaf_count(lc);
                    }
                    let seed_count = open_peers.max(1);
                    plan.bootstrap =
                        Self::bootstrap_plan_from_wire(&mut restarted, ld, seed_count, true);
                    let h8 = u64::from_be_bytes(target_hash[..8].try_into().unwrap());
                    self.set_target_hash8(h8);
                    *guard = Some(restarted);
                    plan.restart_fixed_target = true;
                }
            }
        }

        if guard.is_none() && !(already_syncing || sync_in_progress) {
            let mut syncer = crate::sync_coordinator::SyncCoordinator::new(
                header.sequence,
                header.hash,
                header.account_hash,
                backend,
                header,
            );
            if let Some(lc) = leaf_count {
                syncer.set_leaf_count(lc);
            }
            if plan.bootstrap.is_none() {
                plan.bootstrap = Self::bootstrap_plan_from_wire(&mut syncer, ld, 6, false);
            }
            let sync_completed_from_disk = false;
            if sync_completed_from_disk {
                syncer.set_active(false);
            }
            let target_hash8 = u64::from_be_bytes(syncer.ledger_hash()[..8].try_into().unwrap());
            self.set_target_hash8(target_hash8);
            *guard = Some(syncer);
            plan.installed_syncer = true;
            plan.sync_completed_from_disk = sync_completed_from_disk;
        }

        if plan.bootstrap.is_none() {
            if !already_syncing {
                let seed_count = if plan.restart_fixed_target {
                    open_peers.max(1)
                } else {
                    6
                };
                if let Some(syncer) = guard.as_mut() {
                    plan.bootstrap = Self::bootstrap_plan_from_wire(
                        syncer,
                        ld,
                        seed_count,
                        plan.restart_fixed_target,
                    );
                }
            }
        }

        plan
    }

    pub fn install_syncer(&self, syncer: crate::sync_coordinator::SyncCoordinator) -> bool {
        let target_hash8 = u64::from_be_bytes(syncer.ledger_hash()[..8].try_into().unwrap());
        if let Ok(mut guard) = self.try_lock_sync() {
            *guard = Some(syncer);
            self.set_target_hash8(target_hash8);
            true
        } else {
            false
        }
    }

    fn try_lock_sync_for_header_trigger(
        &self,
    ) -> Option<MutexGuard<'_, Option<crate::sync_coordinator::SyncCoordinator>>> {
        const HEADER_TRIGGER_LOCK_RETRIES: usize = 4;

        for attempt in 0..HEADER_TRIGGER_LOCK_RETRIES {
            match self.try_lock_sync() {
                Ok(guard) => return Some(guard),
                Err(TryLockError::Poisoned(err)) => return Some(err.into_inner()),
                Err(TryLockError::WouldBlock) if attempt + 1 < HEADER_TRIGGER_LOCK_RETRIES => {
                    std::thread::yield_now();
                }
                Err(TryLockError::WouldBlock) => return None,
            }
        }

        None
    }

    pub fn trigger_timeout_blocking(
        &self,
        storage: &Option<Arc<crate::storage::Storage>>,
    ) -> (Vec<RtxpMessage>, u32, bool) {
        const MAX_SYNC_STALLED_RETRIES: u32 =
            crate::ledger::inbound::LEDGER_TIMEOUT_RETRIES_MAX as u32;

        let lock_wait = std::time::Instant::now();
        let mut guard = self.sync.lock().unwrap_or_else(|e| e.into_inner());
        let lock_wait_ms = lock_wait.elapsed().as_millis();
        let hold_start = std::time::Instant::now();
        let _store_ref = storage.as_ref().map(|s| s.as_ref());

        let syncer = match guard.as_mut() {
            Some(s) if s.active() => s,
            _ => {
                drop(guard);
                return (vec![], 0, false);
            }
        };

        let sync_seq = syncer.ledger_seq();
        let response_idle_secs = syncer.peer.last_response.elapsed().as_secs();
        let useful_idle_secs = syncer.peer.last_new_nodes.elapsed().as_secs();
        let cookies_out = syncer.peer.outstanding_cookie_count();
        let recent_count = syncer.peer.recent_node_count();

        tracing::info!(
            "sync tick: active={} in_flight={} inner={} leaf={} pass={} cookies={} recent={} useful-idle={}s response-idle={}s",
            syncer.active(), syncer.in_flight(),
            syncer.inner_count(), syncer.leaf_count(), syncer.pass_number(),
            cookies_out, recent_count, useful_idle_secs, response_idle_secs,
        );

        match syncer.handle_timeout_tick(MAX_SYNC_STALLED_RETRIES) {
            crate::sync_coordinator::TimeoutHandling::Progress => {
                if useful_idle_secs >= 3 || response_idle_secs >= 3 {
                    tracing::info!(
                        "sync timer: progress tick (in_flight={} inner={} leaf={} useful-idle={}s response-idle={}s)",
                        syncer.in_flight(),
                        syncer.inner_count(),
                        syncer.leaf_count(),
                        useful_idle_secs,
                        response_idle_secs,
                    );
                }
                let hold_ms = hold_start.elapsed().as_millis();
                if lock_wait_ms > 5 || hold_ms > 20 {
                    tracing::info!(
                        "sync trigger(timeout): lock_wait={}ms hold={}ms",
                        lock_wait_ms,
                        hold_ms
                    );
                }
                drop(guard);
                (vec![], sync_seq, false)
            }
            crate::sync_coordinator::TimeoutHandling::RestartPass {
                progress_this_pass,
                timeout_count,
            } => {
                tracing::info!(
                    "sync timer: restarting stalled pass {} ({} new this pass, in_flight={}, retries={})",
                    syncer.pass_number(),
                    progress_this_pass,
                    syncer.in_flight(),
                    timeout_count,
                );
                let hold_ms = hold_start.elapsed().as_millis();
                if lock_wait_ms > 5 || hold_ms > 20 {
                    tracing::info!(
                        "sync trigger(timeout): lock_wait={}ms hold={}ms",
                        lock_wait_ms,
                        hold_ms
                    );
                }
                drop(guard);
                (vec![], sync_seq, false)
            }
            crate::sync_coordinator::TimeoutHandling::Deactivate { timeout_count } => {
                tracing::warn!(
                    "sync timer: marking fixed target inactive after {} timeouts (in_flight={}); awaiting same-ledger reacquire",
                    timeout_count,
                    syncer.in_flight(),
                );
                let hold_ms = hold_start.elapsed().as_millis();
                if lock_wait_ms > 5 || hold_ms > 20 {
                    tracing::info!(
                        "sync trigger(timeout): lock_wait={}ms hold={}ms",
                        lock_wait_ms,
                        hold_ms
                    );
                }
                drop(guard);
                (vec![], sync_seq, false)
            }
            crate::sync_coordinator::TimeoutHandling::Request {
                timeout_count,
                use_object_fallback,
                reqs,
            } => {
                tracing::info!(
                    "sync stall ({}s useful-idle, {}s response-idle) — timeout-retrying (attempt #{}, mode={})",
                    useful_idle_secs,
                    response_idle_secs,
                    timeout_count,
                    if use_object_fallback { "getobjects" } else { "getledger" },
                );
                let hold_ms = hold_start.elapsed().as_millis();
                if lock_wait_ms > 5 || hold_ms > 20 {
                    tracing::info!(
                        "sync trigger(timeout): lock_wait={}ms hold={}ms",
                        lock_wait_ms,
                        hold_ms
                    );
                }
                drop(guard);
                (reqs, sync_seq, false)
            }
            crate::sync_coordinator::TimeoutHandling::NoRequest {
                timeout_count,
                use_object_fallback,
            } => {
                tracing::warn!(
                    "sync timeout produced no request (attempt #{} in_flight={} cookies={} recent={} mode={})",
                    timeout_count,
                    syncer.in_flight(),
                    cookies_out,
                    recent_count,
                    if use_object_fallback { "getobjects" } else { "getledger" },
                );
                let hold_ms = hold_start.elapsed().as_millis();
                if lock_wait_ms > 5 || hold_ms > 20 {
                    tracing::info!(
                        "sync trigger(timeout): lock_wait={}ms hold={}ms",
                        lock_wait_ms,
                        hold_ms
                    );
                }
                drop(guard);
                (vec![], sync_seq, false)
            }
        }
    }

    pub fn round_robin(&self) -> &AtomicUsize {
        &self.round_robin
    }

    pub fn set_target_hash8(&self, hash8: u64) {
        self.target_hash8.store(hash8, Ordering::Relaxed);
    }

    pub fn target_hash8(&self) -> u64 {
        self.target_hash8.load(Ordering::Relaxed)
    }

    pub fn queue_sync_data(&self, peer_id: PeerId, msg: crate::proto::TmLedgerData) {
        let mut q = self.data_queue.lock().unwrap_or_else(|e| e.into_inner());
        q.push((peer_id, msg));
        drop(q);
        self.data_notify.notify_one();
    }

    pub fn take_sync_data_batch(&self) -> Vec<(PeerId, crate::proto::TmLedgerData)> {
        let mut q = self.data_queue.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *q)
    }

    pub fn data_notify(&self) -> Arc<Notify> {
        self.data_notify.clone()
    }

    pub fn diff_sync_sender(&self) -> mpsc::Sender<crate::proto::TmLedgerData> {
        self.diff_sync_tx.clone()
    }

    pub fn diff_sync_receiver(
        &self,
    ) -> Arc<tokio::sync::Mutex<mpsc::Receiver<crate::proto::TmLedgerData>>> {
        self.diff_sync_rx.clone()
    }

    pub fn gate_accepts_response(
        &self,
        resp_hash: Option<&[u8]>,
        object_seq: Option<u32>,
        is_object_response: bool,
    ) -> bool {
        let target_h8 = self.target_hash8();
        let hash_matches_target = resp_hash
            .filter(|hash| hash.len() >= 8)
            .map(|hash| u64::from_be_bytes(hash[..8].try_into().unwrap_or([0; 8])))
            .is_some_and(|resp_h8| target_h8 != 0 && resp_h8 == target_h8);

        let Ok(guard) = self.sync.try_lock() else {
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
}

#[cfg(test)]
mod tests {
    use super::SyncRuntime;

    fn test_header(seq: u32, byte: u8) -> crate::ledger::LedgerHeader {
        crate::ledger::LedgerHeader {
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

    fn test_state_wire() -> crate::proto::TmLedgerData {
        crate::proto::TmLedgerData {
            ledger_hash: vec![0x11; 32],
            ledger_seq: 100,
            r#type: crate::proto::TmLedgerInfoType::LiBase as i32,
            nodes: vec![
                crate::proto::TmLedgerNode {
                    nodedata: vec![0u8; 32],
                    nodeid: None,
                },
                crate::proto::TmLedgerNode {
                    nodedata: {
                        let mut root = vec![0u8; 516];
                        root[0..4].copy_from_slice(b"MIN\0");
                        for branch in 0..16usize {
                            let off = 4 + branch * 32;
                            root[off..off + 32].fill((branch as u8) + 1);
                        }
                        root
                    },
                    nodeid: None,
                },
            ],
            request_cookie: None,
            error: None,
        }
    }

    #[test]
    fn plan_header_trigger_ignores_wrong_fixed_target_hash() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let mut syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            header.hash,
            header.account_hash,
            None,
            header.clone(),
        );
        syncer.set_active(false);
        assert!(runtime.install_syncer(syncer));

        let wrong = test_header(100, 0x22);
        let plan =
            runtime.plan_header_trigger(wrong, &test_state_wire(), None, None, 4, false, false);
        assert_eq!(plan.ignore_mismatched_fixed_target, Some((100, [0x11; 32])));
        assert!(!plan.restart_fixed_target);
        assert!(plan.bootstrap.is_none());
    }

    #[test]
    fn plan_header_trigger_installs_new_syncer_and_bootstraps() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let plan = runtime.plan_header_trigger(
            header.clone(),
            &test_state_wire(),
            None,
            None,
            6,
            false,
            false,
        );
        assert!(plan.installed_syncer);
        assert!(plan.bootstrap.is_some());
        assert!(runtime.has_syncer());
        assert_eq!(
            runtime.target_hash8(),
            u64::from_be_bytes(header.hash[..8].try_into().unwrap())
        );
    }

    #[test]
    fn clear_syncer_removes_installed_syncer_and_resets_target_hash() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            header.hash,
            header.account_hash,
            None,
            header.clone(),
        );
        assert!(runtime.install_syncer(syncer));
        assert!(runtime.has_syncer());
        assert_ne!(runtime.target_hash8(), 0);

        runtime.clear_syncer();

        assert!(!runtime.has_syncer());
        assert_eq!(runtime.target_hash8(), 0);
    }

    #[test]
    fn plan_header_trigger_restarts_matching_inactive_fixed_target() {
        let runtime = SyncRuntime::new();
        let header = test_header(100, 0x11);
        let mut syncer = crate::sync_coordinator::SyncCoordinator::new(
            header.sequence,
            header.hash,
            header.account_hash,
            None,
            header.clone(),
        );
        syncer.set_active(false);
        assert!(runtime.install_syncer(syncer));

        let plan = runtime.plan_header_trigger(
            header.clone(),
            &test_state_wire(),
            None,
            Some(123),
            4,
            false,
            false,
        );

        assert!(plan.restart_fixed_target);
        assert!(plan.bootstrap.is_some());
        assert!(!plan.installed_syncer);

        let guard = runtime.lock_sync();
        let syncer = guard.as_ref().expect("syncer should remain installed");
        assert!(syncer.active());
        assert_eq!(syncer.ledger_seq(), header.sequence);
    }

    #[test]
    fn plan_header_trigger_reports_busy_sync_lock_without_partial_install() {
        let runtime = SyncRuntime::new();
        let _guard = runtime.lock_sync();
        let header = test_header(100, 0x11);

        let plan =
            runtime.plan_header_trigger(header, &test_state_wire(), None, None, 4, false, false);

        assert!(plan.sync_lock_busy);
        assert!(!plan.installed_syncer);
        assert!(!plan.restart_fixed_target);
        assert!(plan.bootstrap.is_none());
    }
}
