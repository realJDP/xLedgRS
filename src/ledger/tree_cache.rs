//! TreeNodeCache — bounded LRU cache for SHAMap nodes.
//!
//! Sits between the SHAMap tree walk and the NodeStore disk backend.
//! Hot inner nodes stay cached; cold nodes get evicted.
//! Matches rippled's TreeNodeCache (~256MB, configurable).

use std::collections::HashMap;
use std::sync::{Arc, MutexGuard};

use crate::ledger::node_store::NodeStore;

/// A caching wrapper around a NodeStore.
/// Implements NodeStore itself — drop-in replacement with LRU eviction.
pub struct CachedNodeStore {
    backend: Arc<dyn NodeStore>,
    /// LRU cache: hash → data.
    cache: std::sync::Mutex<LruCache>,
}

struct LruCache {
    entries: HashMap<[u8; 32], Vec<u8>>,
    order: std::collections::VecDeque<[u8; 32]>,
    capacity: usize,
    /// Total bytes in cache (for memory-based limits).
    total_bytes: usize,
    /// Maximum bytes (0 = use entry count only).
    max_bytes: usize,
    hits: u64,
    misses: u64,
}

impl LruCache {
    fn new(capacity: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            order: std::collections::VecDeque::with_capacity(capacity),
            capacity,
            total_bytes: 0,
            max_bytes,
            hits: 0,
            misses: 0,
        }
    }

    fn get(&mut self, key: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(data) = self.entries.get(key) {
            self.hits += 1;
            // Move to back (most recently used)
            self.order.retain(|k| k != key);
            self.order.push_back(*key);
            Some(data.clone())
        } else {
            self.misses += 1;
            None
        }
    }

    fn insert(&mut self, key: [u8; 32], data: Vec<u8>) {
        let data_len = data.len();

        // If key already exists, update
        if let Some(old) = self.entries.insert(key, data) {
            self.total_bytes = self.total_bytes.saturating_sub(old.len()) + data_len;
            self.order.retain(|k| *k != key);
            self.order.push_back(key);
            return;
        }

        self.total_bytes += data_len;
        self.order.push_back(key);

        // Evict oldest entries until within limits
        while self.should_evict() {
            if let Some(old_key) = self.order.pop_front() {
                if let Some(old_data) = self.entries.remove(&old_key) {
                    self.total_bytes = self.total_bytes.saturating_sub(old_data.len());
                }
            } else {
                break;
            }
        }
    }

    fn should_evict(&self) -> bool {
        if self.entries.len() > self.capacity {
            return true;
        }
        if self.max_bytes > 0 && self.total_bytes > self.max_bytes {
            return true;
        }
        false
    }
}

impl CachedNodeStore {
    /// Create a cached wrapper with entry count limit.
    pub fn new(backend: Arc<dyn NodeStore>, capacity: usize) -> Self {
        Self {
            backend,
            cache: std::sync::Mutex::new(LruCache::new(capacity, 0)),
        }
    }

    /// Create a cached wrapper with byte-based memory limit.
    /// Capacity is a rough entry count hint; max_bytes is the hard limit.
    pub fn with_max_bytes(backend: Arc<dyn NodeStore>, capacity: usize, max_bytes: usize) -> Self {
        Self {
            backend,
            cache: std::sync::Mutex::new(LruCache::new(capacity, max_bytes)),
        }
    }

    fn cache_guard(&self) -> MutexGuard<'_, LruCache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Cache hit/miss stats.
    pub fn stats(&self) -> (u64, u64) {
        let c = self.cache_guard();
        (c.hits, c.misses)
    }

    /// Number of entries currently cached.
    pub fn len(&self) -> usize {
        self.cache_guard().entries.len()
    }

    /// Total bytes cached.
    pub fn bytes(&self) -> usize {
        self.cache_guard().total_bytes
    }
}

impl NodeStore for CachedNodeStore {
    fn count(&self) -> u64 {
        self.backend.count()
    }

    fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        // Write through to backend
        self.backend.store(hash, data)?;
        // Populate cache
        self.cache_guard().insert(*hash, data.to_vec());
        Ok(())
    }

    fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
        // Check cache first
        {
            let mut c = self.cache_guard();
            if let Some(data) = c.get(hash) {
                return Ok(Some(data));
            }
        }
        // Cache miss — fetch from backend
        let result = self.backend.fetch(hash)?;
        if let Some(ref data) = result {
            self.cache_guard().insert(*hash, data.clone());
        }
        Ok(result)
    }

    fn store_batch(&self, nodes: &[([u8; 32], Vec<u8>)]) -> std::io::Result<()> {
        self.backend.store_batch(nodes)?;
        let mut c = self.cache_guard();
        for (hash, data) in nodes {
            c.insert(*hash, data.clone());
        }
        Ok(())
    }

    fn mark_corrupt(&self, hash: &[u8; 32]) {
        {
            let mut cache = self.cache_guard();
            if let Some(old) = cache.entries.remove(hash) {
                cache.total_bytes = cache.total_bytes.saturating_sub(old.len());
            }
            cache.order.retain(|key| key != hash);
        }
        self.backend.mark_corrupt(hash);
    }

    fn clear_in_memory(&self) {
        {
            let mut cache = self.cache_guard();
            cache.entries.clear();
            cache.order.clear();
            cache.total_bytes = 0;
        }
        self.backend.clear_in_memory();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::node_store::MemNodeStore;

    #[test]
    fn cache_hit() {
        let backend = Arc::new(MemNodeStore::new());
        let cached = CachedNodeStore::new(backend, 100);

        let hash = [0x11; 32];
        cached.store(&hash, b"data").unwrap();

        // Should be a cache hit
        let result = cached.fetch(&hash).unwrap().unwrap();
        assert_eq!(result, b"data");

        let (hits, misses) = cached.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 0);
    }

    #[test]
    fn cache_miss_populates() {
        let backend = Arc::new(MemNodeStore::new());
        // Store directly in backend (bypassing cache)
        backend.store(&[0x22; 32], b"backend data").unwrap();

        let cached = CachedNodeStore::new(backend, 100);

        // First fetch: miss, populates cache
        let r1 = cached.fetch(&[0x22; 32]).unwrap().unwrap();
        assert_eq!(r1, b"backend data");

        // Second fetch: hit
        let r2 = cached.fetch(&[0x22; 32]).unwrap().unwrap();
        assert_eq!(r2, b"backend data");

        let (hits, misses) = cached.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
    }

    #[test]
    fn lru_eviction() {
        let backend = Arc::new(MemNodeStore::new());
        let cached = CachedNodeStore::new(backend, 3); // capacity = 3

        for i in 0u8..5 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            cached.store(&hash, &[i; 10]).unwrap();
        }

        // Only 3 most recent should be cached
        assert_eq!(cached.len(), 3);

        // Oldest (0, 1) should be evicted, (2, 3, 4) should be cached
        let (hits, _) = cached.stats();
        assert_eq!(hits, 0);
    }

    #[test]
    fn byte_limit_eviction() {
        let backend = Arc::new(MemNodeStore::new());
        // 100 bytes max
        let cached = CachedNodeStore::with_max_bytes(backend, 1000, 100);

        for i in 0u8..10 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            cached.store(&hash, &[i; 20]).unwrap(); // 20 bytes each
        }

        // Should have evicted to stay under 100 bytes
        assert!(
            cached.bytes() <= 100,
            "bytes={} should be <= 100",
            cached.bytes()
        );
    }
}
