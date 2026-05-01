//! xLedgRS purpose: Fetch Pack support for XRPL ledger state and SHAMap logic.
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ledger::node_store::NodeStore;

const MAX_FETCH_PACK_NODES: usize = 16_384;
const FETCH_PACK_RETENTION_SECS: u64 = 15 * 60;
const MAX_QUARANTINED_HASHES: usize = 262_144;

#[derive(Debug, Clone)]
pub struct FetchPackEntrySummary {
    pub hash: String,
    pub size: usize,
    pub first_stashed_unix: u64,
    pub last_stashed_unix: u64,
    pub reuse_hits: u32,
}

#[derive(Debug, Clone, Default)]
pub struct FetchPackSnapshot {
    pub tracked: usize,
    pub stashed_total: u64,
    pub backend_fill_total: u64,
    pub imported_total: u64,
    pub reply_objects_total: u64,
    pub verified_objects_total: u64,
    pub missing_hash_total: u64,
    pub bad_hash_len_total: u64,
    pub missing_data_total: u64,
    pub normalize_reject_total: u64,
    pub hash_mismatch_total: u64,
    pub persisted_total: u64,
    pub persist_errors_total: u64,
    pub unchecked_fallbacks_total: u64,
    pub reused_total: u64,
    pub evicted_total: u64,
    pub last_import_error: Option<String>,
    pub flush_ops: u64,
    pub last_flush_unix: Option<u64>,
    pub last_flush_duration_ms: Option<u64>,
    pub last_flush_error: Option<String>,
    pub entries: Vec<FetchPackEntrySummary>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchPackImportResult {
    pub imported: usize,
    pub persisted: usize,
    pub persist_errors: usize,
    pub unchecked_fallbacks: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchPackObjectReplyImportResult {
    pub raw_objects: usize,
    pub verified_objects: usize,
    pub missing_hash: usize,
    pub bad_hash_len: usize,
    pub missing_data: usize,
    pub normalize_reject: usize,
    pub hash_mismatch: usize,
    pub persisted: usize,
    pub persist_errors: usize,
    pub unchecked_fallbacks: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct FetchPackEntry {
    data: Vec<u8>,
    first_stashed_unix: u64,
    last_stashed_unix: u64,
    reuse_hits: u32,
}

#[derive(Debug, Default)]
struct FetchPackState {
    entries: HashMap<[u8; 32], FetchPackEntry>,
    order: VecDeque<[u8; 32]>,
    stashed_total: u64,
    backend_fill_total: u64,
    imported_total: u64,
    reply_objects_total: u64,
    verified_objects_total: u64,
    missing_hash_total: u64,
    bad_hash_len_total: u64,
    missing_data_total: u64,
    normalize_reject_total: u64,
    hash_mismatch_total: u64,
    persisted_total: u64,
    persist_errors_total: u64,
    unchecked_fallbacks_total: u64,
    reused_total: u64,
    evicted_total: u64,
    last_import_error: Option<String>,
    flush_ops: u64,
    last_flush_unix: Option<u64>,
    last_flush_duration_ms: Option<u64>,
    last_flush_error: Option<String>,
}

pub struct FetchPackStore {
    inner: Arc<dyn NodeStore>,
    state: Mutex<FetchPackState>,
    quarantined: Mutex<QuarantineState>,
}

#[derive(Debug, Default)]
struct QuarantineState {
    hashes: std::collections::HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl FetchPackStore {
    pub fn wrap(inner: Arc<dyn NodeStore>) -> (Arc<dyn NodeStore>, Arc<Self>) {
        let service = Arc::new(Self {
            inner,
            state: Mutex::new(FetchPackState::default()),
            quarantined: Mutex::new(QuarantineState::default()),
        });
        let backend: Arc<dyn NodeStore> = service.clone();
        (backend, service)
    }

    pub fn stash_wire_node(
        &self,
        raw_node: &[u8],
        map_type: crate::ledger::MapType,
    ) -> std::io::Result<bool> {
        let Some((hash, data)) =
            crate::ledger::shamap_sync::prepare_wire_node_for_reuse(raw_node, map_type)?
        else {
            return Ok(false);
        };
        self.stash(hash, data);
        Ok(true)
    }

    pub fn snapshot(&self, limit: usize) -> FetchPackSnapshot {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut state = state;
        Self::trim_locked(&mut state, unix_now());
        let mut entries: Vec<_> = state
            .entries
            .iter()
            .map(|(hash, entry)| FetchPackEntrySummary {
                hash: hex::encode_upper(hash),
                size: entry.data.len(),
                first_stashed_unix: entry.first_stashed_unix,
                last_stashed_unix: entry.last_stashed_unix,
                reuse_hits: entry.reuse_hits,
            })
            .collect();
        entries.sort_by(|a, b| {
            b.last_stashed_unix
                .cmp(&a.last_stashed_unix)
                .then_with(|| a.hash.cmp(&b.hash))
        });
        entries.truncate(limit);
        FetchPackSnapshot {
            tracked: state.entries.len(),
            stashed_total: state.stashed_total,
            backend_fill_total: state.backend_fill_total,
            imported_total: state.imported_total,
            reply_objects_total: state.reply_objects_total,
            verified_objects_total: state.verified_objects_total,
            missing_hash_total: state.missing_hash_total,
            bad_hash_len_total: state.bad_hash_len_total,
            missing_data_total: state.missing_data_total,
            normalize_reject_total: state.normalize_reject_total,
            hash_mismatch_total: state.hash_mismatch_total,
            persisted_total: state.persisted_total,
            persist_errors_total: state.persist_errors_total,
            unchecked_fallbacks_total: state.unchecked_fallbacks_total,
            reused_total: state.reused_total,
            evicted_total: state.evicted_total,
            last_import_error: state.last_import_error.clone(),
            flush_ops: state.flush_ops,
            last_flush_unix: state.last_flush_unix,
            last_flush_duration_ms: state.last_flush_duration_ms,
            last_flush_error: state.last_flush_error.clone(),
            entries,
        }
    }

    pub fn import_verified_objects(&self, nodes: &[([u8; 32], Vec<u8>)]) -> FetchPackImportResult {
        let mut result = FetchPackImportResult {
            imported: nodes.len(),
            ..FetchPackImportResult::default()
        };

        if nodes.is_empty() {
            return result;
        }

        let batch_error = self
            .inner
            .store_batch(nodes)
            .err()
            .map(|err| err.to_string());
        if batch_error.is_none() {
            for (hash, data) in nodes {
                self.stash(*hash, data.clone());
            }
            result.persisted = nodes.len();
            self.note_import_result(&result);
            return result;
        }

        for (hash, data) in nodes {
            match self.inner.store(hash, data) {
                Ok(()) => {
                    self.stash(*hash, data.clone());
                    result.persisted += 1;
                }
                Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
                    result.persist_errors += 1;
                    result.last_error = Some(err.to_string());
                }
                Err(err) => {
                    result.persist_errors += 1;
                    result.last_error = Some(err.to_string());
                }
            }
        }

        if result.persist_errors == 0 {
            result.last_error = None;
        } else if result.last_error.is_none() {
            result.last_error = batch_error;
        }

        self.note_import_result(&result);
        result
    }

    pub fn import_object_reply_objects(
        &self,
        objects: &[crate::proto::TmIndexedObject],
    ) -> FetchPackObjectReplyImportResult {
        let mut result = FetchPackObjectReplyImportResult {
            raw_objects: objects.len(),
            ..FetchPackObjectReplyImportResult::default()
        };
        let mut verified = Vec::new();

        for obj in objects {
            let Some(hash) = obj.hash.as_ref() else {
                result.missing_hash += 1;
                continue;
            };
            let Some(data) = obj.data.as_ref() else {
                result.missing_data += 1;
                continue;
            };
            if hash.len() != 32 {
                result.bad_hash_len += 1;
                continue;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(hash);
            let Some(store_data) = crate::sync::object_reply_to_verified_store(&key, data) else {
                result.normalize_reject += 1;
                if crate::sync::object_reply_to_store(data).is_some() {
                    result.hash_mismatch += 1;
                }
                continue;
            };
            verified.push((key, store_data));
        }

        result.verified_objects = verified.len();
        let import = self.import_verified_objects(&verified);
        result.persisted = import.persisted;
        result.persist_errors = import.persist_errors;
        result.unchecked_fallbacks = import.unchecked_fallbacks;
        result.last_error = import.last_error;
        self.note_object_reply_result(&result);
        result
    }

    pub fn prune(&self, now_unix: u64) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::trim_locked(&mut state, now_unix);
    }

    fn stash(&self, hash: [u8; 32], data: Vec<u8>) {
        let now_unix = unix_now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.entries.get_mut(&hash) {
            Some(entry) => {
                entry.data = data;
                entry.last_stashed_unix = now_unix;
                state.order.retain(|queued| queued != &hash);
            }
            None => {
                state.entries.insert(
                    hash,
                    FetchPackEntry {
                        data,
                        first_stashed_unix: now_unix,
                        last_stashed_unix: now_unix,
                        reuse_hits: 0,
                    },
                );
            }
        }
        state.order.push_back(hash);
        state.stashed_total = state.stashed_total.saturating_add(1);
        Self::trim_locked(&mut state, now_unix);
    }

    fn is_quarantined(&self, hash: &[u8; 32]) -> bool {
        self.quarantined
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .hashes
            .contains(hash)
    }

    fn quarantine_hash(&self, hash: [u8; 32]) {
        let mut state = self.quarantined.lock().unwrap_or_else(|e| e.into_inner());
        if state.hashes.insert(hash) {
            state.order.push_back(hash);
            while state.order.len() > MAX_QUARANTINED_HASHES {
                if let Some(evicted) = state.order.pop_front() {
                    state.hashes.remove(&evicted);
                }
            }
        }
    }

    fn clear_overlay(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.entries.clear();
        state.order.clear();
    }

    fn note_import_result(&self, result: &FetchPackImportResult) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.imported_total = state.imported_total.saturating_add(result.imported as u64);
        state.persisted_total = state
            .persisted_total
            .saturating_add(result.persisted as u64);
        state.persist_errors_total = state
            .persist_errors_total
            .saturating_add(result.persist_errors as u64);
        state.unchecked_fallbacks_total = state
            .unchecked_fallbacks_total
            .saturating_add(result.unchecked_fallbacks as u64);
        state.last_import_error = result.last_error.clone();
    }

    fn note_object_reply_result(&self, result: &FetchPackObjectReplyImportResult) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.reply_objects_total = state
            .reply_objects_total
            .saturating_add(result.raw_objects as u64);
        state.verified_objects_total = state
            .verified_objects_total
            .saturating_add(result.verified_objects as u64);
        state.missing_hash_total = state
            .missing_hash_total
            .saturating_add(result.missing_hash as u64);
        state.bad_hash_len_total = state
            .bad_hash_len_total
            .saturating_add(result.bad_hash_len as u64);
        state.missing_data_total = state
            .missing_data_total
            .saturating_add(result.missing_data as u64);
        state.normalize_reject_total = state
            .normalize_reject_total
            .saturating_add(result.normalize_reject as u64);
        state.hash_mismatch_total = state
            .hash_mismatch_total
            .saturating_add(result.hash_mismatch as u64);
        state.last_import_error = result.last_error.clone();
    }

    fn fetch_overlay(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        let now_unix = unix_now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::trim_locked(&mut state, now_unix);
        let data = {
            let entry = state.entries.get_mut(hash)?;
            entry.reuse_hits = entry.reuse_hits.saturating_add(1);
            entry.last_stashed_unix = now_unix;
            entry.data.clone()
        };
        state.order.retain(|queued| queued != hash);
        state.order.push_back(*hash);
        state.reused_total = state.reused_total.saturating_add(1);
        Some(data)
    }

    fn note_flush_result(&self, started_at: Instant, result: &std::io::Result<()>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::trim_locked(&mut state, unix_now());
        state.flush_ops = state.flush_ops.saturating_add(1);
        state.last_flush_unix = Some(unix_now());
        state.last_flush_duration_ms = Some(started_at.elapsed().as_millis() as u64);
        match result {
            Ok(()) => {
                state.last_flush_error = None;
            }
            Err(err) => {
                state.last_flush_error = Some(err.to_string());
            }
        }
    }

    fn note_backend_fill(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::trim_locked(&mut state, unix_now());
        state.backend_fill_total = state.backend_fill_total.saturating_add(1);
    }

    fn trim_locked(state: &mut FetchPackState, now_unix: u64) {
        while state.entries.len() > MAX_FETCH_PACK_NODES {
            if let Some(hash) = state.order.pop_front() {
                if state.entries.remove(&hash).is_some() {
                    state.evicted_total = state.evicted_total.saturating_add(1);
                }
            }
        }
        while let Some(hash) = state.order.front().copied() {
            let remove = state
                .entries
                .get(&hash)
                .map(|entry| {
                    now_unix.saturating_sub(entry.last_stashed_unix) > FETCH_PACK_RETENTION_SECS
                })
                .unwrap_or(true);
            if !remove {
                break;
            }
            state.order.pop_front();
            if state.entries.remove(&hash).is_some() {
                state.evicted_total = state.evicted_total.saturating_add(1);
            }
        }
    }
}

impl NodeStore for FetchPackStore {
    fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        self.inner.store(hash, data)?;
        self.stash(*hash, data.to_vec());
        Ok(())
    }

    fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
        if let Some(data) = self.fetch_overlay(hash) {
            return Ok(Some(data));
        }
        if self.is_quarantined(hash) {
            return Ok(None);
        }
        let fetched = self.inner.fetch(hash)?;
        if let Some(data) = fetched.as_ref() {
            self.stash(*hash, data.clone());
            self.note_backend_fill();
        }
        Ok(fetched)
    }

    fn count(&self) -> u64 {
        self.inner.count()
    }

    fn store_unchecked(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        self.inner.store_unchecked(hash, data)?;
        self.stash(*hash, data.to_vec());
        Ok(())
    }

    fn store_batch(&self, nodes: &[([u8; 32], Vec<u8>)]) -> std::io::Result<()> {
        match self.inner.store_batch(nodes) {
            Ok(()) => {
                for (hash, data) in nodes {
                    self.stash(*hash, data.clone());
                }
                Ok(())
            }
            Err(batch_err) => {
                let mut fallback_error = None;
                for (hash, data) in nodes {
                    match self.inner.store(hash, data) {
                        Ok(()) => {
                            self.stash(*hash, data.clone());
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
                            fallback_error = Some(err.to_string());
                        }
                        Err(err) => {
                            fallback_error = Some(err.to_string());
                        }
                    }
                }
                if let Some(err) = fallback_error {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, err))
                } else {
                    tracing::debug!("fetch-pack batch store recovered after: {}", batch_err);
                    Ok(())
                }
            }
        }
    }

    fn flush_to_disk(&self) -> std::io::Result<()> {
        let started_at = Instant::now();
        let result = self.inner.flush_to_disk();
        self.note_flush_result(started_at, &result);
        result
    }

    fn mark_corrupt(&self, hash: &[u8; 32]) {
        self.quarantine_hash(*hash);
        self.inner.mark_corrupt(hash);
    }

    fn clear_in_memory(&self) {
        self.clear_overlay();
        self.inner.clear_in_memory();
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn stashed_node_fetches_before_backend() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (backend, fetch_pack) = FetchPackStore::wrap(inner.clone());
        let hash = [0x44; 32];
        inner.store(&hash, b"backend").unwrap();
        fetch_pack.stash(hash, b"overlay".to_vec());

        let fetched = backend.fetch(&hash).unwrap().unwrap();
        assert_eq!(fetched, b"overlay");
        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.tracked, 1);
        assert_eq!(snapshot.reused_total, 1);
        assert_eq!(snapshot.entries[0].reuse_hits, 1);
    }

    #[test]
    fn fetch_from_backend_populates_overlay_cache() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (backend, fetch_pack) = FetchPackStore::wrap(inner.clone());
        let hash = [0x45; 32];
        inner.store(&hash, b"backend").unwrap();

        let fetched = backend.fetch(&hash).unwrap().unwrap();
        assert_eq!(fetched, b"backend");
        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.tracked, 1);
        assert_eq!(snapshot.stashed_total, 1);
        assert_eq!(snapshot.backend_fill_total, 1);
        assert_eq!(snapshot.reused_total, 0);

        let fetched_again = backend.fetch(&hash).unwrap().unwrap();
        assert_eq!(fetched_again, b"backend");
        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.backend_fill_total, 1);
        assert_eq!(snapshot.reused_total, 1);
    }

    #[test]
    fn stash_wire_node_populates_fetch_pack_overlay() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (backend, fetch_pack) = FetchPackStore::wrap(inner);
        let key = [0xAA; 32];
        let mut wire = b"leaf".to_vec();
        wire.extend_from_slice(&key);
        wire.push(0x01);

        assert!(fetch_pack
            .stash_wire_node(&wire, crate::ledger::MapType::AccountState)
            .unwrap());

        let expected_hash = {
            let mut payload = Vec::with_capacity(4 + 4 + 32);
            payload.extend_from_slice(&crate::ledger::shamap::PREFIX_LEAF_STATE);
            payload.extend_from_slice(b"leaf");
            payload.extend_from_slice(&key);
            crate::crypto::sha512_first_half(&payload)
        };
        let fetched = backend.fetch(&expected_hash).unwrap().unwrap();
        assert_eq!(&fetched[..4], b"leaf");
    }

    #[derive(Default)]
    struct ImportFallbackStore {
        nodes: Mutex<HashMap<[u8; 32], Vec<u8>>>,
        store_calls: AtomicUsize,
        batch_calls: AtomicUsize,
        unchecked_calls: AtomicUsize,
    }

    impl NodeStore for ImportFallbackStore {
        fn store(&self, _hash: &[u8; 32], _data: &[u8]) -> io::Result<()> {
            self.store_calls.fetch_add(1, Ordering::Relaxed);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate-check read failed",
            ))
        }

        fn fetch(&self, hash: &[u8; 32]) -> io::Result<Option<Vec<u8>>> {
            Ok(self
                .nodes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(hash)
                .cloned())
        }

        fn store_unchecked(&self, hash: &[u8; 32], data: &[u8]) -> io::Result<()> {
            self.unchecked_calls.fetch_add(1, Ordering::Relaxed);
            self.nodes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(*hash, data.to_vec());
            Ok(())
        }

        fn store_batch(&self, _nodes: &[([u8; 32], Vec<u8>)]) -> io::Result<()> {
            self.batch_calls.fetch_add(1, Ordering::Relaxed);
            Err(io::Error::other("batch path unavailable"))
        }
    }

    struct ImportFailureStore;

    impl NodeStore for ImportFailureStore {
        fn store(&self, _hash: &[u8; 32], _data: &[u8]) -> io::Result<()> {
            Err(io::Error::other("store failed"))
        }

        fn fetch(&self, _hash: &[u8; 32]) -> io::Result<Option<Vec<u8>>> {
            Ok(None)
        }

        fn store_unchecked(&self, _hash: &[u8; 32], _data: &[u8]) -> io::Result<()> {
            Err(io::Error::other("unchecked failed"))
        }

        fn store_batch(&self, _nodes: &[([u8; 32], Vec<u8>)]) -> io::Result<()> {
            Err(io::Error::other("batch failed"))
        }
    }

    #[derive(Default)]
    struct BatchFallbackStore {
        nodes: Mutex<HashMap<[u8; 32], Vec<u8>>>,
        batch_calls: AtomicUsize,
        store_calls: AtomicUsize,
        unchecked_calls: AtomicUsize,
    }

    impl BatchFallbackStore {
        fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Vec<u8>>> {
            self.nodes.lock().unwrap_or_else(|e| e.into_inner())
        }
    }

    impl NodeStore for BatchFallbackStore {
        fn store(&self, hash: &[u8; 32], data: &[u8]) -> io::Result<()> {
            self.store_calls.fetch_add(1, Ordering::Relaxed);
            self.guard().insert(*hash, data.to_vec());
            Ok(())
        }

        fn fetch(&self, hash: &[u8; 32]) -> io::Result<Option<Vec<u8>>> {
            Ok(self.guard().get(hash).cloned())
        }

        fn store_unchecked(&self, hash: &[u8; 32], data: &[u8]) -> io::Result<()> {
            self.unchecked_calls.fetch_add(1, Ordering::Relaxed);
            self.guard().insert(*hash, data.to_vec());
            Ok(())
        }

        fn store_batch(&self, _nodes: &[([u8; 32], Vec<u8>)]) -> io::Result<()> {
            self.batch_calls.fetch_add(1, Ordering::Relaxed);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "batch unsupported",
            ))
        }
    }

    #[test]
    fn import_verified_objects_stashes_and_persists() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (backend, fetch_pack) = FetchPackStore::wrap(inner.clone());
        let hash = [0x55; 32];
        let result = fetch_pack.import_verified_objects(&[(hash, b"persisted".to_vec())]);
        assert_eq!(
            result,
            FetchPackImportResult {
                imported: 1,
                persisted: 1,
                persist_errors: 0,
                unchecked_fallbacks: 0,
                last_error: None,
            }
        );
        let fetched = backend.fetch(&hash).unwrap().unwrap();
        assert_eq!(fetched, b"persisted");
        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.imported_total, 1);
        assert_eq!(snapshot.persisted_total, 1);
        assert_eq!(snapshot.persist_errors_total, 0);
    }

    #[test]
    fn import_verified_objects_rejects_invaliddata_without_unchecked_store() {
        let inner = Arc::new(ImportFallbackStore::default());
        let typed_inner: Arc<dyn NodeStore> = inner.clone();
        let (backend, fetch_pack) = FetchPackStore::wrap(typed_inner);
        let hash = [0x66; 32];
        let result = fetch_pack.import_verified_objects(&[(hash, b"overlay".to_vec())]);
        assert_eq!(result.imported, 1);
        assert_eq!(result.persisted, 0);
        assert_eq!(result.persist_errors, 1);
        assert_eq!(result.unchecked_fallbacks, 0);
        assert!(result.last_error.is_some());
        assert_eq!(inner.batch_calls.load(Ordering::Relaxed), 1);
        assert_eq!(inner.store_calls.load(Ordering::Relaxed), 1);
        assert_eq!(inner.unchecked_calls.load(Ordering::Relaxed), 0);
        assert!(backend.fetch(&hash).unwrap().is_none());
        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.imported_total, 1);
        assert_eq!(snapshot.persisted_total, 0);
        assert_eq!(snapshot.unchecked_fallbacks_total, 0);
        assert!(snapshot.last_import_error.is_some());
    }

    #[test]
    fn import_verified_objects_does_not_expose_overlay_without_persistence() {
        let inner: Arc<dyn NodeStore> = Arc::new(ImportFailureStore);
        let (backend, fetch_pack) = FetchPackStore::wrap(inner);
        let hash = [0x67; 32];

        let result = fetch_pack.import_verified_objects(&[(hash, b"ghost".to_vec())]);
        assert_eq!(result.imported, 1);
        assert_eq!(result.persisted, 0);
        assert_eq!(result.persist_errors, 1);
        assert!(result.last_error.is_some());
        assert!(backend.fetch(&hash).unwrap().is_none());

        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.tracked, 0);
        assert_eq!(snapshot.persisted_total, 0);
        assert_eq!(snapshot.persist_errors_total, 1);
    }

    #[test]
    fn batch_store_falls_back_to_individual_writes_after_batch_failure() {
        let inner = Arc::new(BatchFallbackStore::default());
        let typed_inner: Arc<dyn NodeStore> = inner.clone();
        let (backend, fetch_pack) = FetchPackStore::wrap(typed_inner);
        let nodes = vec![([0x78; 32], b"a".to_vec()), ([0x79; 32], b"b".to_vec())];

        assert!(backend.store_batch(&nodes).is_ok());
        assert_eq!(inner.batch_calls.load(Ordering::Relaxed), 1);
        assert_eq!(inner.store_calls.load(Ordering::Relaxed), 2);
        assert_eq!(inner.unchecked_calls.load(Ordering::Relaxed), 0);
        assert_eq!(backend.fetch(&[0x78; 32]).unwrap().unwrap(), b"a");
        assert_eq!(backend.fetch(&[0x79; 32]).unwrap().unwrap(), b"b");

        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.tracked, 2);
        assert_eq!(snapshot.stashed_total, 2);
        assert_eq!(snapshot.persisted_total, 0);
    }

    #[test]
    fn quarantined_hashes_skip_backend_until_overlay_has_replacement() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (backend, fetch_pack) = FetchPackStore::wrap(inner.clone());
        let hash = [0xD1; 32];

        inner.store(&hash, b"backend").unwrap();
        backend.mark_corrupt(&hash);
        assert!(backend.fetch(&hash).unwrap().is_none());

        backend.store(&hash, b"overlay").unwrap();
        assert_eq!(backend.fetch(&hash).unwrap().unwrap(), b"overlay");
        fetch_pack.clear_overlay();
        assert!(backend.fetch(&hash).unwrap().is_none());
    }

    #[test]
    fn direct_store_populates_overlay_after_persist() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (backend, fetch_pack) = FetchPackStore::wrap(inner);
        let hash = [0x77; 32];

        backend.store(&hash, b"persisted").unwrap();

        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.tracked, 1);
        assert_eq!(snapshot.stashed_total, 1);
        assert_eq!(backend.fetch(&hash).unwrap().unwrap(), b"persisted");
        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.reused_total, 1);
    }

    #[test]
    fn batch_store_populates_overlay_after_persist() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (backend, fetch_pack) = FetchPackStore::wrap(inner);
        let nodes = vec![([0x88; 32], b"a".to_vec()), ([0x99; 32], b"b".to_vec())];

        backend.store_batch(&nodes).unwrap();

        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.tracked, 2);
        assert_eq!(snapshot.stashed_total, 2);
        assert_eq!(backend.fetch(&[0x88; 32]).unwrap().unwrap(), b"a");
        assert_eq!(backend.fetch(&[0x99; 32]).unwrap().unwrap(), b"b");
        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.reused_total, 2);
    }

    #[test]
    fn flush_to_disk_updates_snapshot() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (backend, fetch_pack) = FetchPackStore::wrap(inner);

        backend.flush_to_disk().unwrap();

        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.flush_ops, 1);
        assert!(snapshot.last_flush_unix.is_some());
        assert!(snapshot.last_flush_duration_ms.is_some());
        assert_eq!(snapshot.last_flush_error, None);
    }

    #[test]
    fn snapshot_prunes_expired_entries_before_reporting() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (_backend, fetch_pack) = FetchPackStore::wrap(inner);

        let hash = [0xAA; 32];
        fetch_pack.stash(hash, b"expired".to_vec());
        {
            let mut state = fetch_pack.state.lock().unwrap_or_else(|e| e.into_inner());
            let entry = state.entries.get_mut(&hash).expect("overlay entry");
            entry.first_stashed_unix = 1;
            entry.last_stashed_unix = 1;
        }

        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.tracked, 0);
        assert!(snapshot.entries.is_empty());
    }

    #[test]
    fn fetch_skips_expired_overlay_entries() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (backend, fetch_pack) = FetchPackStore::wrap(inner.clone());
        let hash = [0xAB; 32];

        inner.store(&hash, b"backend").unwrap();
        fetch_pack.stash(hash, b"stale-overlay".to_vec());
        {
            let mut state = fetch_pack.state.lock().unwrap_or_else(|e| e.into_inner());
            let entry = state.entries.get_mut(&hash).expect("overlay entry");
            entry.first_stashed_unix = 1;
            entry.last_stashed_unix = 1;
        }

        let fetched = backend.fetch(&hash).unwrap().unwrap();
        assert_eq!(fetched, b"backend");

        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.reused_total, 0);
        assert_eq!(snapshot.backend_fill_total, 1);
    }

    #[test]
    fn fetch_refreshes_overlay_retention_and_lru_order() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (backend, fetch_pack) = FetchPackStore::wrap(inner);
        let fresh_hash = [0xAC; 32];
        let stale_hash = [0xAD; 32];

        fetch_pack.stash(fresh_hash, b"fresh".to_vec());
        fetch_pack.stash(stale_hash, b"stale".to_vec());

        assert_eq!(backend.fetch(&fresh_hash).unwrap().unwrap(), b"fresh");

        let state = fetch_pack.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.order.front().copied(), Some(stale_hash));
        assert_eq!(state.order.back().copied(), Some(fresh_hash));
        assert_eq!(state.entries.get(&fresh_hash).unwrap().reuse_hits, 1);
    }

    #[test]
    fn refreshed_entry_does_not_block_pruning_older_expired_entries() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (_backend, fetch_pack) = FetchPackStore::wrap(inner);
        let fresh_hash = [0xAC; 32];
        let stale_hash = [0xAD; 32];

        fetch_pack.stash(fresh_hash, b"fresh".to_vec());
        fetch_pack.stash(stale_hash, b"stale".to_vec());
        fetch_pack.stash(fresh_hash, b"fresh-again".to_vec());
        {
            let mut state = fetch_pack.state.lock().unwrap_or_else(|e| e.into_inner());
            let stale_entry = state.entries.get_mut(&stale_hash).expect("stale entry");
            stale_entry.first_stashed_unix = 1;
            stale_entry.last_stashed_unix = 1;
        }

        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.tracked, 1);
        assert_eq!(snapshot.entries[0].hash, hex::encode_upper(fresh_hash));
        assert_eq!(snapshot.entries[0].size, b"fresh-again".len());
    }

    #[test]
    fn import_object_reply_objects_tracks_normalization_breakdown() {
        let inner: Arc<dyn NodeStore> = Arc::new(crate::ledger::node_store::MemNodeStore::new());
        let (_backend, fetch_pack) = FetchPackStore::wrap(inner);
        let key = [0xAB; 32];
        let mut good_leaf = b"leaf".to_vec();
        good_leaf.extend_from_slice(&key);
        let good_hash = {
            let mut payload = Vec::with_capacity(4 + 4 + 32);
            payload.extend_from_slice(&crate::ledger::shamap::PREFIX_LEAF_STATE);
            payload.extend_from_slice(b"leaf");
            payload.extend_from_slice(&key);
            crate::crypto::sha512_first_half(&payload)
        };
        let bad_hash = [0x11; 32];
        let objects = vec![
            crate::proto::TmIndexedObject {
                hash: None,
                data: Some(vec![1, 2, 3]),
                index: None,
                ledger_seq: Some(1),
                node_id: None,
            },
            crate::proto::TmIndexedObject {
                hash: Some(vec![1, 2]),
                data: Some(vec![1, 2, 3]),
                index: None,
                ledger_seq: Some(1),
                node_id: None,
            },
            crate::proto::TmIndexedObject {
                hash: Some(good_hash.to_vec()),
                data: None,
                index: None,
                ledger_seq: Some(1),
                node_id: None,
            },
            crate::proto::TmIndexedObject {
                hash: Some(bad_hash.to_vec()),
                data: Some(good_leaf.clone()),
                index: None,
                ledger_seq: Some(1),
                node_id: None,
            },
            crate::proto::TmIndexedObject {
                hash: Some(good_hash.to_vec()),
                data: Some(good_leaf),
                index: None,
                ledger_seq: Some(1),
                node_id: None,
            },
        ];

        let result = fetch_pack.import_object_reply_objects(&objects);
        assert_eq!(result.raw_objects, 5);
        assert_eq!(result.verified_objects, 1);
        assert_eq!(result.missing_hash, 1);
        assert_eq!(result.bad_hash_len, 1);
        assert_eq!(result.missing_data, 1);
        assert_eq!(result.normalize_reject, 1);
        assert_eq!(result.hash_mismatch, 1);
        assert_eq!(result.persisted, 1);

        let snapshot = fetch_pack.snapshot(4);
        assert_eq!(snapshot.reply_objects_total, 5);
        assert_eq!(snapshot.verified_objects_total, 1);
        assert_eq!(snapshot.normalize_reject_total, 1);
        assert_eq!(snapshot.hash_mismatch_total, 1);
    }
}
