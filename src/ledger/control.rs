use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

#[derive(Debug, Default)]
pub struct LedgerAcceptService {
    requested: AtomicBool,
    waiters: Mutex<Vec<mpsc::SyncSender<u32>>>,
}

impl LedgerAcceptService {
    pub fn request(&self) -> mpsc::Receiver<u32> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(tx);
        self.requested.store(true, Ordering::SeqCst);
        rx
    }

    pub fn take_requested(&self) -> bool {
        self.requested.swap(false, Ordering::SeqCst)
            || !self
                .waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
    }

    pub fn complete(&self, ledger_current_index: u32) {
        let waiters = std::mem::take(
            &mut *self.waiters.lock().unwrap_or_else(|e| e.into_inner()),
        );
        for waiter in waiters {
            let _ = waiter.send(ledger_current_index);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LedgerCleanerRequest {
    pub current_seq: u32,
    pub ledger: Option<u32>,
    pub min_ledger: Option<u32>,
    pub max_ledger: Option<u32>,
    pub full: bool,
    pub fix_txns: bool,
    pub check_nodes: bool,
    pub stop: bool,
}

#[derive(Debug, Clone)]
pub struct LedgerCleanerSnapshot {
    pub state: String,
    pub online_delete: Option<u32>,
    pub pending: bool,
    pub min_ledger: Option<u32>,
    pub max_ledger: Option<u32>,
    pub full: bool,
    pub fix_txns: bool,
    pub check_nodes: bool,
    pub stop_requested: bool,
    pub last_message: Option<String>,
    pub last_run_started_unix: Option<u64>,
    pub last_run_finished_unix: Option<u64>,
    pub history_pruned: usize,
    pub failures: u32,
}

impl Default for LedgerCleanerSnapshot {
    fn default() -> Self {
        Self {
            state: "idle".to_string(),
            online_delete: None,
            pending: false,
            min_ledger: None,
            max_ledger: None,
            full: false,
            fix_txns: false,
            check_nodes: false,
            stop_requested: false,
            last_message: None,
            last_run_started_unix: None,
            last_run_finished_unix: None,
            history_pruned: 0,
            failures: 0,
        }
    }
}

pub struct LedgerCleanerService {
    tx: mpsc::Sender<LedgerCleanerRequest>,
    snapshot: Arc<Mutex<LedgerCleanerSnapshot>>,
    online_delete: Option<u32>,
    available: bool,
}

impl LedgerCleanerService {
    pub fn new(
        storage: Option<Arc<crate::storage::Storage>>,
        online_delete: Option<u32>,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel();
        let snapshot = Arc::new(Mutex::new(LedgerCleanerSnapshot {
            state: if storage.is_some() {
                "idle".to_string()
            } else {
                "unavailable".to_string()
            },
            online_delete,
            ..Default::default()
        }));
        let service = Arc::new(Self {
            tx,
            snapshot: snapshot.clone(),
            online_delete,
            available: storage.is_some(),
        });

        if let Some(storage) = storage {
            std::thread::spawn(move || run_cleaner_loop(storage, online_delete, rx, snapshot));
        }

        service
    }

    pub fn clean(&self, request: LedgerCleanerRequest) -> Result<(), String> {
        if !self.available {
            return Err("ledger cleaner unavailable".to_string());
        }

        {
            let mut snapshot = self.snapshot.lock().unwrap_or_else(|e| e.into_inner());
            snapshot.pending = !request.stop;
            snapshot.state = if request.stop {
                "stopping".to_string()
            } else {
                "queued".to_string()
            };
            snapshot.min_ledger = request.ledger.or(request.min_ledger);
            snapshot.max_ledger = request.ledger.or(request.max_ledger);
            snapshot.full = request.full;
            snapshot.fix_txns = request.fix_txns;
            snapshot.check_nodes = request.check_nodes;
            snapshot.stop_requested = request.stop;
            snapshot.last_message = Some(if request.stop {
                "Cleaner stop requested".to_string()
            } else {
                "Cleaner queued".to_string()
            });
        }

        self.tx
            .send(request)
            .map_err(|_| "ledger cleaner stopped".to_string())
    }

    pub fn snapshot(&self) -> LedgerCleanerSnapshot {
        self.snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn online_delete(&self) -> Option<u32> {
        self.online_delete
    }
}

fn run_cleaner_loop(
    storage: Arc<crate::storage::Storage>,
    online_delete: Option<u32>,
    rx: mpsc::Receiver<LedgerCleanerRequest>,
    snapshot: Arc<Mutex<LedgerCleanerSnapshot>>,
) {
    while let Ok(request) = rx.recv() {
        let request = coalesce_pending_request(request, &rx);
        if request.stop {
            while rx.try_recv().is_ok() {}
            let mut state = snapshot.lock().unwrap_or_else(|e| e.into_inner());
            state.state = "idle".to_string();
            state.pending = false;
            state.stop_requested = false;
            state.last_run_finished_unix = Some(unix_now());
            state.last_message = Some("Cleaner stopped".to_string());
            continue;
        }

        {
            let mut state = snapshot.lock().unwrap_or_else(|e| e.into_inner());
            state.state = "cleaning".to_string();
            state.pending = false;
            state.stop_requested = false;
            state.last_run_started_unix = Some(unix_now());
            state.min_ledger = request.ledger.or(request.min_ledger);
            state.max_ledger = request.ledger.or(request.max_ledger);
            state.full = request.full;
            state.fix_txns = request.fix_txns;
            state.check_nodes = request.check_nodes;
            state.last_message = Some("Cleaner running".to_string());
        }

        let result = execute_clean_request(&storage, online_delete, &request);
        let mut state = snapshot.lock().unwrap_or_else(|e| e.into_inner());
        state.state = "idle".to_string();
        state.last_run_finished_unix = Some(unix_now());
        match result {
            Ok((history_pruned, message)) => {
                state.history_pruned = history_pruned;
                state.last_message = Some(message);
            }
            Err(message) => {
                state.failures = state.failures.saturating_add(1);
                state.last_message = Some(message);
            }
        }
    }
}

fn coalesce_pending_request(
    mut request: LedgerCleanerRequest,
    rx: &mpsc::Receiver<LedgerCleanerRequest>,
) -> LedgerCleanerRequest {
    while let Ok(next) = rx.try_recv() {
        request = next;
    }
    request
}

fn execute_clean_request(
    storage: &crate::storage::Storage,
    online_delete: Option<u32>,
    request: &LedgerCleanerRequest,
) -> Result<(usize, String), String> {
    if let Some(ledger) = request.ledger {
        let ledger = ledger.min(request.current_seq.saturating_sub(1));
        if ledger == 0 {
            return Ok((0, "Cleaner found nothing to prune".to_string()));
        }
        let deleted = storage
            .prune_history_window(Some(ledger), ledger)
            .map_err(|e| format!("ledger cleaner failed: {e}"))?;
        return Ok((deleted, format!("Cleaner pruned {deleted} ledger(s)")));
    }

    if request.full || request.min_ledger.is_some() || request.max_ledger.is_some() {
        let max_ledger = request
            .max_ledger
            .unwrap_or_else(|| request.current_seq.saturating_sub(1))
            .min(request.current_seq.saturating_sub(1));
        let min_ledger = request.min_ledger.filter(|min| *min > 0);
        if max_ledger == 0 || min_ledger.is_some_and(|min| min > max_ledger) {
            return Ok((0, "Cleaner found nothing to prune".to_string()));
        }
        let deleted = storage
            .prune_history_window(min_ledger, max_ledger)
            .map_err(|e| format!("ledger cleaner failed: {e}"))?;
        return Ok((deleted, format!("Cleaner pruned {deleted} ledger(s)")));
    }

    if let Some(keep) = online_delete.filter(|keep| *keep > 0) {
        let deleted = storage
            .prune_history_to(request.current_seq, keep, request.max_ledger)
            .map_err(|e| format!("ledger cleaner failed: {e}"))?;
        return Ok((deleted, format!("Cleaner pruned {deleted} ledger(s)")));
    }

    Ok((0, "Cleaner found nothing to prune".to_string()))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_accept_service_completes_waiters() {
        let service = Arc::new(LedgerAcceptService::default());
        let rx = service.request();
        assert!(service.take_requested());
        service.complete(42);
        assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap(), 42);
    }

    #[test]
    fn ledger_cleaner_service_prunes_requested_range() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(crate::storage::Storage::open(dir.path()).unwrap());
        for seq in 1..=4 {
            storage
                .save_ledger(
                    &crate::ledger::LedgerHeader {
                        sequence: seq,
                        hash: [seq as u8; 32],
                        parent_hash: [0; 32],
                        close_time: seq as u64,
                        total_coins: 0,
                        account_hash: [0; 32],
                        transaction_hash: [0; 32],
                        parent_close_time: 0,
                        close_time_resolution: 10,
                        close_flags: 0,
                    },
                    &[],
                )
                .unwrap();
        }

        let service = LedgerCleanerService::new(Some(storage.clone()), Some(2));
        service
            .clean(LedgerCleanerRequest {
                current_seq: 5,
                min_ledger: Some(1),
                max_ledger: Some(2),
                ..Default::default()
            })
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if !storage.has_full_ledger_range(1, 2) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(!storage.has_full_ledger_range(1, 2));
        assert!(storage.has_full_ledger_range(3, 4));
        assert!(service.snapshot().history_pruned >= 2);
    }

    #[test]
    fn ledger_cleaner_coalesces_to_latest_request() {
        let (tx, rx) = mpsc::channel();
        tx.send(LedgerCleanerRequest {
            current_seq: 10,
            max_ledger: Some(1),
            ..Default::default()
        })
        .unwrap();
        tx.send(LedgerCleanerRequest {
            current_seq: 10,
            max_ledger: Some(2),
            ..Default::default()
        })
        .unwrap();
        tx.send(LedgerCleanerRequest {
            current_seq: 10,
            stop: true,
            ..Default::default()
        })
        .unwrap();

        let first = rx.recv().unwrap();
        let latest = coalesce_pending_request(first, &rx);
        assert!(latest.stop);
        assert_eq!(latest.max_ledger, None);
    }
}
