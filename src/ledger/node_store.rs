//! NodeStore — abstract content-addressed storage for SHAMap nodes.
//!
//! Matches rippled's NodeStore concept: nodes are stored by their content hash
//! (SHA-512-Half of the serialized data). Inner nodes and leaf nodes both go
//! here. The SHAMap tree structure itself IS the index.
//!
//! Two implementations:
//! - NuDB (disk, constant memory, production)
//! - In-memory HashMap (testing)

use std::sync::{Mutex, MutexGuard};

/// A content-addressed node store for SHAMap nodes.
///
/// Keys are 32-byte content hashes (SHA-512-Half of the node data).
/// Values are serialized node bytes (inner: 512 bytes of children hashes,
/// leaf: SLE data + 32-byte entry key).
pub trait NodeStore: Send + Sync {
    /// Store a node by its content hash.
    fn store(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()>;

    /// Fetch a node by its content hash. Returns None if not found.
    fn fetch(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>>;

    /// Number of nodes stored.
    fn count(&self) -> u64 { 0 }

    /// Store without duplicate check. Caller guarantees uniqueness.
    /// Default falls back to store().
    fn store_unchecked(&self, hash: &[u8; 32], data: &[u8]) -> std::io::Result<()> {
        self.store(hash, data)
    }

    /// Store multiple nodes in a batch (default: sequential stores).
    fn store_batch(&self, nodes: &[([u8; 32], Vec<u8>)]) -> std::io::Result<()> {
        for (hash, data) in nodes {
            self.store(hash, data)?;
        }
        Ok(())
    }

    /// Flush buffered writes to disk. Default no-op.
    fn flush_to_disk(&self) -> std::io::Result<()> { Ok(()) }
}

/// NuDB-backed NodeStore — disk-primary, constant memory.
pub struct NuDBNodeStore {
    store: Mutex<nudb::Store>,
}

impl NuDBNodeStore {
    pub fn new(store: nudb::Store) -> Self {
        Self { store: Mutex::new(store) }
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
            nudb::Store::create(dir, nudb::StoreOptions {
                key_size: 32,
                block_size: 4096,
                appnum: 0x4C44_5253, // "LDRS"
                load_factor: 32768,
            })?
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
        Self { nodes: Mutex::new(std::collections::HashMap::new()) }
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
}
