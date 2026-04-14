//! FullBelowCache — tracks which SHAMap subtrees are fully synced.
//!
//! When getMissingNodes confirms all children of a subtree are present,
//! the subtree's content hash is marked "full below" for the current
//! generation. Subsequent walks skip these subtrees entirely.
//!
//! Generations prevent stale marks: a new sync cycle increments the
//! generation, invalidating old marks without clearing the cache.
//! Matches rippled's FullBelowCache (524K entries, 10-min expiry).

use std::collections::HashMap;

/// Cache tracking completed subtrees during sync.
pub struct FullBelowCache {
    /// hash → generation when marked complete
    entries: HashMap<[u8; 32], u32>,
    /// Current generation number
    generation: u32,
    /// Max entries before eviction
    capacity: usize,
}

impl FullBelowCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity.min(8192)),
            generation: 1,
            capacity,
        }
    }

    /// Current generation.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Advance to next generation. Old marks become stale.
    pub fn next_generation(&mut self) -> u32 {
        self.generation += 1;
        self.generation
    }

    /// Mark a hash as fully synced for the current generation.
    pub fn insert(&mut self, hash: [u8; 32]) {
        while self.entries.len() >= self.capacity {
            // Evict entries from old generations first
            let current = self.generation;
            let before = self.entries.len();
            self.entries.retain(|_, gen| *gen >= current.saturating_sub(2));
            if self.entries.len() == before {
                // All same generation — remove oldest half
                let to_remove: Vec<_> = self.entries.keys().take(self.entries.len() / 2).copied().collect();
                for k in to_remove { self.entries.remove(&k); }
            }
            if self.entries.len() >= self.capacity { break; } // safety
        }
        self.entries.insert(hash, self.generation);
    }

    /// Check if a hash is marked full for the current generation.
    /// Also refreshes the entry (touch) if found.
    pub fn touch_if_exists(&mut self, hash: &[u8; 32]) -> bool {
        if let Some(gen) = self.entries.get_mut(hash) {
            if *gen == self.generation {
                return true;
            }
        }
        false
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_insert_and_check() {
        let mut cache = FullBelowCache::new(1000);
        let hash = [0xAA; 32];

        assert!(!cache.touch_if_exists(&hash));
        cache.insert(hash);
        assert!(cache.touch_if_exists(&hash));
    }

    #[test]
    fn generation_invalidates() {
        let mut cache = FullBelowCache::new(1000);
        let hash = [0xBB; 32];

        cache.insert(hash);
        assert!(cache.touch_if_exists(&hash));

        cache.next_generation();
        assert!(!cache.touch_if_exists(&hash)); // stale
    }

    #[test]
    fn eviction_at_capacity() {
        let mut cache = FullBelowCache::new(10);
        for i in 0u8..20 {
            cache.insert([i; 32]);
        }
        assert!(cache.len() <= 10);
    }
}
