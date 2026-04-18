//! Content-addressed storage for SHAMap nodes.
//!
//! Nodes are keyed by their content hash, which is the SHA-512-half of the
//! serialized node bytes. Both inner nodes and leaf nodes are stored here, and
//! the SHAMap structure itself provides the lookup path.
//!
//! The crate ships with a NuDB-backed store for persistent operation and an
//! in-memory store for tests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// Content-addressed storage for SHAMap nodes.
///
/// Keys are 32-byte content hashes, and values are the serialized node bytes.
/// Inner nodes store child hashes, while leaf nodes store SLE bytes plus the
/// entry key.
pub trait NodeStore: Send + Sync {
    /// Store a node under its content hash.
    fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()>;

    /// Fetch a node by its content hash.
    fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>>;

    /// Number of nodes stored.
    fn count(&self) -> u64 {
        0
    }

    /// Store without duplicate checks. The default falls back to `store()`.
    fn store_unchecked(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        self.store(hash, data)
    }

    /// Store multiple nodes in a batch.
    fn store_batch(&self, nodes: &[([u8; 32], Vec<u8>)]) -> std::io::Result<()> {
        for (hash, data) in nodes {
            self.store(hash, data)?;
        }
        Ok(())
    }

    /// Flush buffered writes to disk. The default implementation is a no-op.
    fn flush_to_disk(&self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeStoreSnapshot {
    pub fetch_hits: u64,
    pub fetch_missing: u64,
    pub fetch_errors: u64,
    pub store_ops: u64,
    pub store_unchecked_ops: u64,
    pub batch_store_ops: u64,
    pub batch_store_nodes: u64,
    pub flush_ops: u64,
    pub last_flush_unix: Option<u64>,
    pub last_flush_duration_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Default)]
pub struct NodeStoreStats {
    fetch_hits: AtomicU64,
    fetch_missing: AtomicU64,
    fetch_errors: AtomicU64,
    store_ops: AtomicU64,
    store_unchecked_ops: AtomicU64,
    batch_store_ops: AtomicU64,
    batch_store_nodes: AtomicU64,
    flush_ops: AtomicU64,
    last_flush_unix: AtomicU64,
    last_flush_duration_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl NodeStoreStats {
    fn remember_error(&self, err: &std::io::Error) {
        let mut slot = self.last_error.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(err.to_string());
    }

    fn note_fetch_result(&self, result: &std::io::Result<Option<Vec<u8>>>) {
        match result {
            Ok(Some(_)) => {
                self.fetch_hits.fetch_add(1, Ordering::Relaxed);
                self.last_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
            }
            Ok(None) => {
                self.fetch_missing.fetch_add(1, Ordering::Relaxed);
                self.last_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
            }
            Err(err) => {
                self.fetch_errors.fetch_add(1, Ordering::Relaxed);
                self.remember_error(err);
            }
        }
    }

    fn note_store_result(&self, unchecked: bool, result: &std::io::Result<()>) {
        if unchecked {
            self.store_unchecked_ops.fetch_add(1, Ordering::Relaxed);
        } else {
            self.store_ops.fetch_add(1, Ordering::Relaxed);
        }
        if let Err(err) = result {
            self.remember_error(err);
        } else {
            self.last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        }
    }

    fn note_batch_result(&self, node_count: usize, result: &std::io::Result<()>) {
        self.batch_store_ops.fetch_add(1, Ordering::Relaxed);
        self.batch_store_nodes
            .fetch_add(node_count as u64, Ordering::Relaxed);
        if let Err(err) = result {
            self.remember_error(err);
        } else {
            self.last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        }
    }

    fn note_flush_result(&self, started_at: std::time::Instant, result: &std::io::Result<()>) {
        self.flush_ops.fetch_add(1, Ordering::Relaxed);
        self.last_flush_unix.store(unix_now(), Ordering::Relaxed);
        self.last_flush_duration_ms
            .store(started_at.elapsed().as_millis() as u64, Ordering::Relaxed);
        if let Err(err) = result {
            self.remember_error(err);
        } else {
            self.last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        }
    }

    pub fn snapshot(&self) -> NodeStoreSnapshot {
        NodeStoreSnapshot {
            fetch_hits: self.fetch_hits.load(Ordering::Relaxed),
            fetch_missing: self.fetch_missing.load(Ordering::Relaxed),
            fetch_errors: self.fetch_errors.load(Ordering::Relaxed),
            store_ops: self.store_ops.load(Ordering::Relaxed),
            store_unchecked_ops: self.store_unchecked_ops.load(Ordering::Relaxed),
            batch_store_ops: self.batch_store_ops.load(Ordering::Relaxed),
            batch_store_nodes: self.batch_store_nodes.load(Ordering::Relaxed),
            flush_ops: self.flush_ops.load(Ordering::Relaxed),
            last_flush_unix: atomic_option(self.last_flush_unix.load(Ordering::Relaxed)),
            last_flush_duration_ms: atomic_option(
                self.last_flush_duration_ms.load(Ordering::Relaxed),
            ),
            last_error: self
                .last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        }
    }
}

pub struct ObservedNodeStore {
    inner: Arc<dyn NodeStore>,
    stats: Arc<NodeStoreStats>,
}

impl ObservedNodeStore {
    pub fn wrap(inner: Arc<dyn NodeStore>) -> (Arc<dyn NodeStore>, Arc<NodeStoreStats>) {
        let stats = Arc::new(NodeStoreStats::default());
        let observed: Arc<dyn NodeStore> = Arc::new(Self {
            inner,
            stats: stats.clone(),
        });
        (observed, stats)
    }
}

impl NodeStore for ObservedNodeStore {
    fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        let result = self.inner.store(hash, data);
        self.stats.note_store_result(false, &result);
        result
    }

    fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
        let result = self.inner.fetch(hash);
        self.stats.note_fetch_result(&result);
        result
    }

    fn count(&self) -> u64 {
        self.inner.count()
    }

    fn store_unchecked(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        let result = self.inner.store_unchecked(hash, data);
        self.stats.note_store_result(true, &result);
        result
    }

    fn store_batch(&self, nodes: &[([u8; 32], Vec<u8>)]) -> std::io::Result<()> {
        let result = self.inner.store_batch(nodes);
        self.stats.note_batch_result(nodes.len(), &result);
        result
    }

    fn flush_to_disk(&self) -> std::io::Result<()> {
        let started_at = std::time::Instant::now();
        let result = self.inner.flush_to_disk();
        self.stats.note_flush_result(started_at, &result);
        result
    }
}

fn atomic_option(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// NuDB-backed NodeStore — disk-primary, constant memory.
pub struct NuDBNodeStore {
    store: Mutex<nudb::Store>,
}

impl NuDBNodeStore {
    pub fn new(store: nudb::Store) -> Self {
        Self {
            store: Mutex::new(store),
        }
    }

    fn guard(&self) -> MutexGuard<'_, nudb::Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Flush all buffered writes to disk.
    pub fn flush(&self) -> std::io::Result<()> {
        let mut s = self.guard();
        s.flush()
    }

    pub fn open(dir: &std::path::Path) -> std::io::Result<Self> {
        // Check for the actual data file, not just the directory.
        // After a wipe the directory may exist but be empty.
        let dat_exists = dir.join("nudb.dat").exists();
        let store = if dat_exists {
            nudb::Store::open(dir)?
        } else {
            std::fs::create_dir_all(dir)?;
            nudb::Store::create(
                dir,
                nudb::StoreOptions {
                    key_size: 32,
                    block_size: 4096,
                    appnum: 0x4C44_5253, // "LDRS"
                    load_factor: 32768,
                },
            )?
        };
        Ok(Self::new(store))
    }
}

impl NodeStore for NuDBNodeStore {
    fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        let mut s = self.guard();
        let _ = s.insert(hash, data)?;
        Ok(())
    }

    fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
        let mut s = self.guard();
        s.fetch(hash)
    }

    fn count(&self) -> u64 {
        self.guard().key_count()
    }

    fn store_unchecked(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        let mut s = self.guard();
        s.insert_unchecked(hash, data)
    }

    fn store_batch(&self, nodes: &[([u8; 32], Vec<u8>)]) -> std::io::Result<()> {
        let mut s = self.guard();
        for (hash, data) in nodes {
            let _ = s.insert(hash, data)?;
        }
        Ok(())
    }

    fn flush_to_disk(&self) -> std::io::Result<()> {
        self.flush()
    }
}

/// In-memory NodeStore for testing.
pub struct MemNodeStore {
    nodes: Mutex<std::collections::HashMap<[u8; 32], Vec<u8>>>,
}

impl MemNodeStore {
    pub fn new() -> Self {
        Self {
            nodes: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn guard(&self) -> MutexGuard<'_, std::collections::HashMap<[u8; 32], Vec<u8>>> {
        self.nodes.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl NodeStore for MemNodeStore {
    fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        self.guard().insert(*hash, data.to_vec());
        Ok(())
    }

    fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.guard().get(hash).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn mem_store_roundtrip() {
        let store = MemNodeStore::new();
        let hash = [0xAB; 32];
        let data = b"test node data";
        store.store(&hash, data).unwrap();
        let fetched = store.fetch(&hash).unwrap().unwrap();
        assert_eq!(fetched, data);
    }

    #[test]
    fn mem_store_missing() {
        let store = MemNodeStore::new();
        assert!(store.fetch(&[0x01; 32]).unwrap().is_none());
    }

    #[test]
    fn nudb_store_roundtrip() {
        let dir = std::env::temp_dir().join("nudb_nodestore_test");
        let _ = std::fs::remove_dir_all(&dir);
        let store = NuDBNodeStore::open(&dir).unwrap();
        let hash = [0xCD; 32];
        let data = b"shamap node bytes";
        store.store(&hash, data).unwrap();
        let fetched = store.fetch(&hash).unwrap().unwrap();
        assert_eq!(fetched, data);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn observed_store_tracks_fetches_and_writes() {
        let inner: Arc<dyn NodeStore> = Arc::new(MemNodeStore::new());
        let (observed, stats) = ObservedNodeStore::wrap(inner);
        let hash = [0x11; 32];
        let missing = [0x22; 32];
        observed.store(&hash, b"abc").unwrap();
        assert_eq!(observed.fetch(&hash).unwrap(), Some(b"abc".to_vec()));
        assert_eq!(observed.fetch(&missing).unwrap(), None);
        observed.flush_to_disk().unwrap();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.store_ops, 1);
        assert_eq!(snapshot.fetch_hits, 1);
        assert_eq!(snapshot.fetch_missing, 1);
        assert_eq!(snapshot.fetch_errors, 0);
        assert_eq!(snapshot.flush_ops, 1);
        assert!(snapshot.last_flush_unix.is_some());
        assert!(snapshot.last_flush_duration_ms.is_some());
    }

    struct FlakyStore {
        fail_once: std::sync::atomic::AtomicBool,
        nodes: Mutex<std::collections::HashMap<[u8; 32], Vec<u8>>>,
    }

    impl FlakyStore {
        fn new() -> Self {
            Self {
                fail_once: std::sync::atomic::AtomicBool::new(true),
                nodes: Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn guard(&self) -> MutexGuard<'_, std::collections::HashMap<[u8; 32], Vec<u8>>> {
            self.nodes.lock().unwrap_or_else(|e| e.into_inner())
        }
    }

    impl NodeStore for FlakyStore {
        fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
            if self.fail_once.swap(false, Ordering::Relaxed) {
                return Err(std::io::Error::other("transient store failure"));
            }
            self.guard().insert(*hash, data.to_vec());
            Ok(())
        }

        fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
            Ok(self.guard().get(hash).cloned())
        }

        fn flush_to_disk(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn observed_store_clears_last_error_after_recovery() {
        let inner: Arc<dyn NodeStore> = Arc::new(FlakyStore::new());
        let (observed, stats) = ObservedNodeStore::wrap(inner);
        let hash = [0x33; 32];

        assert!(observed.store(&hash, b"first").is_err());
        assert!(stats.snapshot().last_error.is_some());

        observed.store(&hash, b"second").unwrap();
        let snapshot = stats.snapshot();
        assert!(snapshot.last_error.is_none());
        assert_eq!(snapshot.store_ops, 2);
    }
}
