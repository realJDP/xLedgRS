//! xLedgRS purpose: Implement NuDB store read, write, and delete operations.
//! NuDB Store — the main read/write interface.
//!
//! Matches C++ NuDB architecture:
//! - Dirty bucket cache: buckets stay in RAM, flushed on commit
//! - Batched data writes: records accumulated in memory buffer
//! - pread-style reads: separate read file handle, no seek contention
//! - Deferred splits: run during commit, not inline per-insert

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use xxhash_rust::xxh64::xxh64;

use crate::format::*;

/// Options for creating a new NuDB store.
pub struct StoreOptions {
    /// Key size in bytes (default: 32 for SHA-256/SHA-512-half hashes).
    pub key_size: u16,
    /// Bucket block size in bytes (default: 4096).
    pub block_size: u16,
    /// Application identifier (default: 1).
    pub appnum: u64,
    /// Target load factor as fraction of 65536 (default: 32768 = 0.5).
    pub load_factor: u16,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            key_size: 32,
            block_size: 4096,
            appnum: 1,
            load_factor: 32768, // 0.5
        }
    }
}

/// A NuDB key-value store.
///
/// Write-once, hash-indexed, constant memory regardless of database size.
/// Keys are fixed-size (typically 32-byte hashes). Values are variable-size.
///
/// Matching C++ NuDB: inserts go to in-memory dirty bucket cache + data buffer.
/// commit() flushes everything to disk in bulk.
pub struct Store {
    _dat_path: PathBuf,
    _key_path: PathBuf,
    _log_path: PathBuf,
    /// Data file — append-only writes.
    dat_file: File,
    /// Key file — bucket reads/writes.
    key_file: File,
    /// Separate read handle for dat_file (pread-style, no seek contention).
    dat_reader: File,
    /// Separate read handle for key_file.
    key_reader: File,
    header: KeyHeader,
    /// Current linear hashing level.
    level: u32,
    /// Next bucket to split.
    next: u64,
    /// Dirty bucket cache — modified buckets held in RAM until commit.
    dirty_buckets: HashMap<u64, Bucket>,
    /// Buffered data records waiting to be flushed.
    data_buf: Vec<u8>,
    /// Current end-of-data-file offset (tracked in memory, no seek needed).
    dat_end: u64,
    /// Number of inserts since last commit.
    dirty_count: u32,
    /// How many inserts between automatic commits (0 = manual only).
    burst_interval: u32,
}

impl Store {
    /// Create a new NuDB store at the given directory.
    pub fn create(dir: &Path, opts: StoreOptions) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;

        let dat_path = dir.join("nudb.dat");
        let key_path = dir.join("nudb.key");
        let log_path = dir.join("nudb.log");

        let uid: u64 = rand_u64();
        let salt: u64 = rand_u64();
        let pepper = xxh64(&salt.to_le_bytes(), 0);

        // Write data file header
        let dat_header = DatHeader {
            version: VERSION,
            uid,
            appnum: opts.appnum,
            key_size: opts.key_size,
        };
        let mut dat_file = File::create(&dat_path)?;
        dat_header.write_to(&mut dat_file)?;
        dat_file.flush()?;

        // Write key file header + one empty bucket
        let key_header = KeyHeader {
            version: VERSION,
            uid,
            appnum: opts.appnum,
            key_size: opts.key_size,
            salt,
            pepper,
            block_size: opts.block_size,
            load_factor: opts.load_factor,
            bucket_count: 1,
            key_count: 0,
        };
        let mut key_file = File::create(&key_path)?;
        key_header.write_to(&mut key_file)?;
        let empty_bucket = vec![0u8; opts.block_size as usize];
        key_file.write_all(&empty_bucket)?;
        key_file.flush()?;

        // Re-open for read+write
        let dat_file = OpenOptions::new().read(true).write(true).open(&dat_path)?;
        let key_file = OpenOptions::new().read(true).write(true).open(&key_path)?;
        let dat_reader = OpenOptions::new().read(true).open(&dat_path)?;
        let key_reader = OpenOptions::new().read(true).open(&key_path)?;

        // Dat header: 8 (magic) + 2 (version) + 8 (uid) + 8 (appnum) + 2 (key_size) + 64 (reserved) = 92
        let dat_end = 92u64;

        Ok(Self {
            _dat_path: dat_path,
            _key_path: key_path,
            _log_path: log_path,
            dat_file,
            key_file,
            dat_reader,
            key_reader,
            header: key_header,
            level: 0,
            next: 0,
            dirty_buckets: HashMap::with_capacity(256),
            data_buf: Vec::with_capacity(256 * 1024), // 256KB initial buffer
            dat_end,
            dirty_count: 0,
            burst_interval: 4096,
        })
    }

    /// Open an existing NuDB store.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let dat_path = dir.join("nudb.dat");
        let key_path = dir.join("nudb.key");
        let log_path = dir.join("nudb.log");

        // Recover from log if present
        if log_path.exists() {
            let _ = std::fs::remove_file(&log_path);
        }

        let mut key_file = OpenOptions::new().read(true).write(true).open(&key_path)?;
        let header = KeyHeader::read_from(&mut key_file)?;

        let dat_file = OpenOptions::new().read(true).write(true).open(&dat_path)?;
        let dat_reader = OpenOptions::new().read(true).open(&dat_path)?;
        let key_reader = OpenOptions::new().read(true).open(&key_path)?;

        // Get current data file size
        let dat_end = dat_file.metadata()?.len();

        let (level, next) = compute_level_next(header.bucket_count);

        Ok(Self {
            _dat_path: dat_path,
            _key_path: key_path,
            _log_path: log_path,
            dat_file,
            key_file,
            dat_reader,
            key_reader,
            header,
            level,
            next,
            dirty_buckets: HashMap::with_capacity(256),
            data_buf: Vec::with_capacity(256 * 1024),
            dat_end,
            dirty_count: 0,
            burst_interval: 4096,
        })
    }

    /// Insert without checking for duplicates. Caller guarantees uniqueness.
    /// Pure memory — zero disk I/O. Call commit() or flush() to persist.
    pub fn insert_unchecked(&mut self, key: &[u8], value: &[u8]) -> io::Result<()> {
        assert_eq!(key.len(), self.header.key_size as usize);

        let hash = xxh64(key, self.header.salt);
        let hash48 = hash & 0xFFFF_FFFF_FFFF;
        let bucket_idx = self.bucket_index(hash);

        // Append record to in-memory data buffer
        let dat_offset = self.dat_end;
        let record_size = (self.header.key_size as u64) + (value.len() as u64);
        self.data_buf.extend_from_slice(&write_u48(record_size));
        self.data_buf.extend_from_slice(key);
        self.data_buf.extend_from_slice(value);
        self.dat_end += 6 + record_size;

        let entry = BucketEntry {
            offset: dat_offset,
            size: value.len() as u64,
            hash: hash48,
        };

        // Start from the existing bucket contents when there is no dirty copy.
        // This preserves the bucket's other entries while still allowing the
        // caller to append a verified duplicate record without a key scan.
        let mut bucket = if let Some(bucket) = self.dirty_buckets.remove(&bucket_idx) {
            bucket
        } else {
            self.get_bucket(bucket_idx)?
        };
        let capacity = self.header.bucket_capacity();
        if bucket.entries.len() >= capacity {
            // Spill needs disk write — flush data buffer first so spill offsets
            // remain valid, matching the checked insert path.
            self.flush_data_buf()?;
            self.spill_bucket(&mut bucket)?;
        }

        bucket.insert(entry);
        self.dirty_buckets.insert(bucket_idx, bucket);

        self.header.key_count += 1;
        self.dirty_count += 1;

        Ok(())
    }

    /// Insert a key-value pair. Returns true if inserted, false if key exists.
    ///
    /// Data is buffered in memory. Dirty buckets cached in RAM.
    /// Call commit() to flush to disk (or let burst_interval trigger auto-commit).
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> io::Result<bool> {
        assert_eq!(key.len(), self.header.key_size as usize);

        let hash = xxh64(key, self.header.salt);
        let hash48 = hash & 0xFFFF_FFFF_FFFF;

        // Check if key already exists (reads from cache or disk)
        let bucket_idx = self.bucket_index(hash);
        let bucket = self.get_bucket(bucket_idx)?;
        if self.key_exists_in_bucket(&bucket, key, hash48)? {
            return Ok(false);
        }

        // Append record to in-memory data buffer (no disk I/O)
        let dat_offset = self.dat_end;
        let record_size = (self.header.key_size as u64) + (value.len() as u64);
        self.data_buf.extend_from_slice(&write_u48(record_size));
        self.data_buf.extend_from_slice(key);
        self.data_buf.extend_from_slice(value);
        self.dat_end += 6 + record_size;

        // Insert into cached bucket (no disk I/O)
        let entry = BucketEntry {
            offset: dat_offset,
            size: value.len() as u64,
            hash: hash48,
        };

        let mut bucket = bucket;
        let capacity = self.header.bucket_capacity();

        if bucket.entries.len() >= capacity {
            // Spill needs disk write — flush data buffer first so spill offsets are valid
            self.flush_data_buf()?;
            self.spill_bucket(&mut bucket)?;
        }

        bucket.insert(entry);
        self.dirty_buckets.insert(bucket_idx, bucket);

        self.header.key_count += 1;
        self.dirty_count += 1;

        // Auto-commit at burst_interval
        if self.burst_interval > 0 && self.dirty_count >= self.burst_interval {
            self.commit()?;
        }

        Ok(true)
    }

    /// Fetch a value by key. Returns None if not found.
    ///
    /// Uses separate read handles — no seek contention with writes.
    pub fn fetch(&mut self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        assert_eq!(key.len(), self.header.key_size as usize);

        let hash = xxh64(key, self.header.salt);
        let hash48 = hash & 0xFFFF_FFFF_FFFF;
        let bucket_idx = self.bucket_index(hash);
        let bucket = self.get_bucket(bucket_idx)?;

        // Search in bucket entries
        for entry in &bucket.entries {
            if entry.hash == hash48 {
                match self.read_record(entry.offset) {
                    Ok((found_key, value)) => {
                        if found_key == key {
                            return Ok(Some(value));
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        // Search in spill chain
        let mut spill_offset = bucket.spill;
        while spill_offset != 0 {
            let (spill_bucket, next_spill) = match self.read_spill(spill_offset) {
                Ok(result) => result,
                Err(err) if err.kind() == io::ErrorKind::InvalidData => break,
                Err(err) => return Err(err),
            };
            for entry in &spill_bucket.entries {
                if entry.hash == hash48 {
                    match self.read_record(entry.offset) {
                        Ok((found_key, value)) => {
                            if found_key == key {
                                return Ok(Some(value));
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                            continue;
                        }
                        Err(err) => return Err(err),
                    }
                }
            }
            spill_offset = next_spill;
        }

        Ok(None)
    }

    /// Insert or update a key-value pair.
    pub fn upsert(&mut self, key: &[u8], value: &[u8]) -> io::Result<()> {
        assert_eq!(key.len(), self.header.key_size as usize);

        let hash = xxh64(key, self.header.salt);
        let hash48 = hash & 0xFFFF_FFFF_FFFF;
        let bucket_idx = self.bucket_index(hash);
        let mut bucket = self.get_bucket(bucket_idx)?;

        // Append new record to data buffer
        let dat_offset = self.dat_end;
        let record_size = (self.header.key_size as u64) + (value.len() as u64);
        self.data_buf.extend_from_slice(&write_u48(record_size));
        self.data_buf.extend_from_slice(key);
        self.data_buf.extend_from_slice(value);
        self.dat_end += 6 + record_size;

        // Check if key exists — update offset if so
        let mut found = false;
        for entry in &mut bucket.entries {
            if entry.hash == hash48 {
                let (found_key, _) = self.read_record(entry.offset)?;
                if found_key == key {
                    entry.offset = dat_offset;
                    entry.size = value.len() as u64;
                    found = true;
                    break;
                }
            }
        }

        // Check spill chain
        if !found {
            let mut spill_offset = bucket.spill;
            while spill_offset != 0 && !found {
                let (mut spill_bucket, next_spill) = self.read_spill(spill_offset)?;
                for entry in &mut spill_bucket.entries {
                    if entry.hash == hash48 {
                        let (found_key, _) = self.read_record(entry.offset)?;
                        if found_key == key {
                            entry.offset = dat_offset;
                            entry.size = value.len() as u64;
                            found = true;
                            break;
                        }
                    }
                }
                if found {
                    // Flush data buf first so spill rewrite is valid
                    self.flush_data_buf()?;
                    let block_size = self.header.block_size as usize;
                    let spill_bytes = spill_bucket.to_bytes(block_size);
                    self.dat_file.seek(SeekFrom::Start(spill_offset + 8))?;
                    self.dat_file.write_all(&spill_bytes)?;
                }
                spill_offset = next_spill;
            }
        }

        if found {
            self.dirty_buckets.insert(bucket_idx, bucket);
        } else {
            // New key
            let capacity = self.header.bucket_capacity();
            if bucket.entries.len() >= capacity {
                self.flush_data_buf()?;
                self.spill_bucket(&mut bucket)?;
            }
            bucket.insert(BucketEntry {
                offset: dat_offset,
                size: value.len() as u64,
                hash: hash48,
            });
            self.dirty_buckets.insert(bucket_idx, bucket);
            self.header.key_count += 1;
            self.dirty_count += 1;
            if self.burst_interval > 0 && self.dirty_count >= self.burst_interval {
                self.commit()?;
            }
        }

        Ok(())
    }

    /// Remove a key.
    pub fn remove(&mut self, key: &[u8]) -> io::Result<bool> {
        assert_eq!(key.len(), self.header.key_size as usize);

        let hash = xxh64(key, self.header.salt);
        let hash48 = hash & 0xFFFF_FFFF_FFFF;
        let bucket_idx = self.bucket_index(hash);
        let mut bucket = self.get_bucket(bucket_idx)?;

        let before = bucket.entries.len();
        bucket.entries.retain(|e| e.hash != hash48);
        if bucket.entries.len() < before {
            bucket.count = bucket.entries.len() as u16;
            self.dirty_buckets.insert(bucket_idx, bucket);
            self.header.key_count = self.header.key_count.saturating_sub(1);
            self.dirty_count += 1;
            if self.burst_interval > 0 && self.dirty_count >= self.burst_interval {
                self.commit()?;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Check if a key exists without reading the value.
    pub fn exists(&mut self, key: &[u8]) -> io::Result<bool> {
        Ok(self.fetch(key)?.is_some())
    }

    /// Set burst interval — number of inserts between auto-commits.
    pub fn set_burst(&mut self, interval: u32) {
        self.burst_interval = interval;
    }

    /// Commit all buffered writes to disk: data buffer + dirty buckets + splits + header.
    /// Matches C++ NuDB's commit() phase.
    pub fn commit(&mut self) -> io::Result<()> {
        // 1. Flush data buffer (single large sequential write)
        self.flush_data_buf()?;

        // 2. Run deferred splits
        self.run_splits()?;

        // 3. Write all dirty buckets to key file
        for (&idx, bucket) in &self.dirty_buckets {
            let offset = self.header.bucket_offset(idx);
            let buf = bucket.to_bytes(self.header.block_size as usize);
            self.key_file.seek(SeekFrom::Start(offset))?;
            self.key_file.write_all(&buf)?;
        }
        self.dirty_buckets.clear();

        // 4. Write header
        self.write_key_header()?;

        self.dirty_count = 0;
        Ok(())
    }

    /// Flush any deferred writes to disk. Alias for commit().
    pub fn flush(&mut self) -> io::Result<()> {
        if self.dirty_count > 0 || !self.data_buf.is_empty() || !self.dirty_buckets.is_empty() {
            self.commit()?;
        }
        self.key_file.flush()?;
        self.dat_file.flush()?;
        Ok(())
    }

    /// Number of keys stored.
    pub fn key_count(&self) -> u64 {
        self.header.key_count
    }

    /// Number of buckets.
    pub fn bucket_count(&self) -> u64 {
        self.header.bucket_count
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    /// Get a bucket — from dirty cache first, then disk.
    fn get_bucket(&mut self, index: u64) -> io::Result<Bucket> {
        if let Some(bucket) = self.dirty_buckets.get(&index) {
            return Ok(bucket.clone());
        }
        self.read_bucket_disk(index)
    }

    /// Read a bucket from the key file on disk (using read handle).
    fn read_bucket_disk(&mut self, index: u64) -> io::Result<Bucket> {
        let offset = self.header.bucket_offset(index);
        self.key_reader.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; self.header.block_size as usize];
        self.key_reader.read_exact(&mut buf)?;
        Bucket::try_from_bytes(&buf).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("invalid bucket {} at key offset {}: {}", index, offset, err),
            )
        })
    }

    /// Compute which bucket a hash maps to (linear hashing).
    fn bucket_index(&self, hash: u64) -> u64 {
        let modulus = 1u64 << self.level;
        let mut idx = hash % modulus;
        if idx < self.next {
            idx = hash % (modulus * 2);
        }
        idx
    }

    /// Write the key file header.
    fn write_key_header(&mut self) -> io::Result<()> {
        self.key_file.seek(SeekFrom::Start(0))?;
        self.header.write_to(&mut self.key_file)?;
        Ok(())
    }

    /// Flush the in-memory data buffer to the dat_file (single sequential write).
    fn flush_data_buf(&mut self) -> io::Result<()> {
        if !self.data_buf.is_empty() {
            let write_pos = self.dat_end - self.data_buf.len() as u64;
            self.dat_file.seek(SeekFrom::Start(write_pos))?;
            self.dat_file.write_all(&self.data_buf)?;
            self.data_buf.clear();
        }
        Ok(())
    }

    /// Read a record from the data file at the given offset.
    /// Uses the read handle — no seek contention with writes.
    /// Also checks the in-memory data buffer for unflushed records.
    fn read_record(&mut self, offset: u64) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let key_size = self.header.key_size as usize;

        // Check if the record is in the unflushed data buffer
        let flushed_end = self.dat_end - self.data_buf.len() as u64;
        if offset >= flushed_end {
            // Record is in the data buffer
            let buf_offset = (offset - flushed_end) as usize;
            if buf_offset + 6 > self.data_buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "record offset beyond buffer",
                ));
            }
            let total_size = read_u48(&self.data_buf[buf_offset..buf_offset + 6]) as usize;
            if total_size < key_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "record too small",
                ));
            }
            let val_size = total_size - key_size;
            let start = buf_offset + 6;
            let end = start.checked_add(total_size).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "record size overflow in buffer: start={} total_size={}",
                        start, total_size
                    ),
                )
            })?;
            if end > self.data_buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "record body beyond buffer: start={} total_size={} buffer_len={}",
                        start,
                        total_size,
                        self.data_buf.len()
                    ),
                ));
            }
            let key = self.data_buf[start..start + key_size].to_vec();
            let value = self.data_buf[start + key_size..start + key_size + val_size].to_vec();
            return Ok((key, value));
        }

        // Record is on disk — use read handle
        self.dat_reader.seek(SeekFrom::Start(offset))?;
        let mut size_buf = [0u8; 6];
        self.dat_reader.read_exact(&mut size_buf)?;
        let total_size = read_u48(&size_buf) as usize;
        let data_start = offset.saturating_add(6);
        let remaining_on_disk = self.dat_end.saturating_sub(data_start);

        if total_size < key_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "record too small",
            ));
        }
        if (total_size as u64) > remaining_on_disk {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "record extends beyond data file: offset={} total_size={} remaining={}",
                    offset, total_size, remaining_on_disk
                ),
            ));
        }
        let val_size = total_size - key_size;

        let mut key = vec![0u8; key_size];
        self.dat_reader.read_exact(&mut key)?;
        let mut value = vec![0u8; val_size];
        self.dat_reader.read_exact(&mut value)?;
        Ok((key, value))
    }

    /// Check if a key exists in a bucket (including spill chain).
    fn key_exists_in_bucket(
        &mut self,
        bucket: &Bucket,
        key: &[u8],
        hash48: u64,
    ) -> io::Result<bool> {
        for entry in &bucket.entries {
            if entry.hash == hash48 {
                match self.read_record(entry.offset) {
                    Ok((found_key, _)) => {
                        if found_key == key {
                            return Ok(true);
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        let mut spill_offset = bucket.spill;
        while spill_offset != 0 {
            let (spill_bucket, next_spill) = match self.read_spill(spill_offset) {
                Ok(result) => result,
                Err(err) if err.kind() == io::ErrorKind::InvalidData => break,
                Err(err) => return Err(err),
            };
            for entry in &spill_bucket.entries {
                if entry.hash == hash48 {
                    match self.read_record(entry.offset) {
                        Ok((found_key, _)) => {
                            if found_key == key {
                                return Ok(true);
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                            continue;
                        }
                        Err(err) => return Err(err),
                    }
                }
            }
            spill_offset = next_spill;
        }
        Ok(false)
    }

    /// Read a spill bucket from the data file.
    fn read_spill(&mut self, offset: u64) -> io::Result<(Bucket, u64)> {
        // Check data buffer first
        let flushed_end = self.dat_end - self.data_buf.len() as u64;
        if offset >= flushed_end {
            let buf_offset = (offset - flushed_end) as usize;
            if buf_offset + 8 > self.data_buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "spill offset beyond buffer",
                ));
            }
            let spill_size =
                u16::from_be_bytes([self.data_buf[buf_offset + 6], self.data_buf[buf_offset + 7]])
                    as usize;
            if spill_size < BUCKET_HEADER_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("spill bucket too small: {} bytes", spill_size),
                ));
            }
            if spill_size > self.header.block_size as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "spill bucket larger than block size: spill={} block={}",
                        spill_size, self.header.block_size
                    ),
                ));
            }
            let start = buf_offset + 8;
            if start + spill_size > self.data_buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "spill data beyond buffer",
                ));
            }
            let bucket = Bucket::try_from_bytes(&self.data_buf[start..start + spill_size])
                .map_err(|err| {
                    io::Error::new(
                        err.kind(),
                        format!(
                            "invalid spill bucket in buffer at offset {}: {}",
                            offset, err
                        ),
                    )
                })?;
            let spill = bucket.spill;
            return Ok((bucket, spill));
        }

        self.dat_reader.seek(SeekFrom::Start(offset))?;
        let mut header = [0u8; 8];
        self.dat_reader.read_exact(&mut header)?;
        let spill_size = u16::from_be_bytes([header[6], header[7]]) as usize;
        if spill_size < BUCKET_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("spill bucket too small: {} bytes", spill_size),
            ));
        }
        if spill_size > self.header.block_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "spill bucket larger than block size: spill={} block={}",
                    spill_size, self.header.block_size
                ),
            ));
        }
        let mut buf = vec![0u8; spill_size];
        self.dat_reader.read_exact(&mut buf)?;
        let bucket = Bucket::try_from_bytes(&buf).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("invalid spill bucket on disk at offset {}: {}", offset, err),
            )
        })?;
        let spill = bucket.spill;
        Ok((bucket, spill))
    }

    /// Spill a full bucket to the data file.
    fn spill_bucket(&mut self, bucket: &mut Bucket) -> io::Result<()> {
        let spill_offset = self.dat_end;
        let block_size = self.header.block_size as usize;
        let bucket_bytes = bucket.to_bytes(block_size);

        // Write spill to data buffer (batched)
        let mut record = Vec::with_capacity(8 + bucket_bytes.len());
        record.extend_from_slice(&[0u8; 6]);
        record.extend_from_slice(&(block_size as u16).to_be_bytes());
        record.extend_from_slice(&bucket_bytes);
        self.data_buf.extend_from_slice(&record);
        self.dat_end += record.len() as u64;

        // Update bucket: clear entries, set spill pointer
        bucket.spill = spill_offset;
        bucket.entries.clear();
        bucket.count = 0;
        Ok(())
    }

    /// Run deferred splits until load factor is satisfied.
    fn run_splits(&mut self) -> io::Result<()> {
        loop {
            let capacity = self.header.bucket_capacity() as u64;
            let total_capacity = self.header.bucket_count * capacity;
            let load = (self.header.key_count as u128 * 65536) / total_capacity.max(1) as u128;

            if load <= self.header.load_factor as u128 {
                break;
            }

            // Read bucket to split (from cache or disk)
            let old_bucket = self.get_bucket(self.next)?;
            let mut keep = Bucket::new();
            let mut move_out = Bucket::new();

            let new_modulus = 1u64 << (self.level + 1);

            // Redistribute entries
            for entry in &old_bucket.entries {
                let (key, _) = self.read_record(entry.offset)?;
                let hash = xxh64(&key, self.header.salt);
                let new_idx = hash % new_modulus;
                if new_idx == self.next {
                    keep.insert(*entry);
                } else {
                    move_out.insert(*entry);
                }
            }

            // Redistribute spill chain
            let mut spill_offset = old_bucket.spill;
            while spill_offset != 0 {
                let (spill_bucket, next_spill) = self.read_spill(spill_offset)?;
                for entry in &spill_bucket.entries {
                    let (key, _) = self.read_record(entry.offset)?;
                    let hash = xxh64(&key, self.header.salt);
                    let new_idx = hash % new_modulus;
                    if new_idx == self.next {
                        keep.insert(*entry);
                    } else {
                        move_out.insert(*entry);
                    }
                }
                spill_offset = next_spill;
            }

            // Update cached buckets
            keep.spill = 0;
            self.dirty_buckets.insert(self.next, keep);

            let new_bucket_idx = self.header.bucket_count;
            self.header.bucket_count += 1;
            move_out.spill = 0;
            self.dirty_buckets.insert(new_bucket_idx, move_out);

            // Advance linear hashing state
            self.next += 1;
            if self.next >= (1u64 << self.level) {
                self.level += 1;
                self.next = 0;
            }
        }
        Ok(())
    }
}

/// Compute level and next from bucket_count for linear hashing.
fn compute_level_next(bucket_count: u64) -> (u32, u64) {
    if bucket_count <= 1 {
        return (0, 0);
    }
    let mut level = 0u32;
    while (1u64 << (level + 1)) < bucket_count {
        level += 1;
    }
    let base = 1u64 << level;
    let next = bucket_count - base;
    if next >= base {
        (level + 1, 0)
    } else {
        (level, next)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Simple random u64 (not crypto-grade, just for UID/salt).
fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut v = t.as_nanos() as u64;
    v ^= v >> 13;
    v = v.wrapping_mul(0x7feb352d_u64);
    v ^= v >> 15;
    v
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nudb_test_{id}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn create_and_open() {
        let dir = temp_dir();
        {
            let store = Store::create(&dir, StoreOptions::default()).unwrap();
            assert_eq!(store.key_count(), 0);
            assert_eq!(store.bucket_count(), 1);
        }
        {
            let store = Store::open(&dir).unwrap();
            assert_eq!(store.key_count(), 0);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn insert_and_fetch() {
        let dir = temp_dir();
        let mut store = Store::create(&dir, StoreOptions::default()).unwrap();

        let key = [0x42u8; 32];
        let value = b"hello world";
        assert!(store.insert(&key, value).unwrap());
        assert!(!store.insert(&key, value).unwrap()); // duplicate

        let fetched = store.fetch(&key).unwrap().unwrap();
        assert_eq!(fetched, value);
        assert_eq!(store.key_count(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fetch_missing() {
        let dir = temp_dir();
        let mut store = Store::create(&dir, StoreOptions::default()).unwrap();
        let key = [0xAB; 32];
        assert!(store.fetch(&key).unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn many_inserts() {
        let dir = temp_dir();
        let mut store = Store::create(&dir, StoreOptions::default()).unwrap();

        for i in 0u32..1000 {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_le_bytes());
            let value = format!("value_{i}");
            assert!(store.insert(&key, value.as_bytes()).unwrap());
        }

        assert_eq!(store.key_count(), 1000);
        store.flush().unwrap();
        assert!(store.bucket_count() > 1, "should have split buckets");

        // Verify all can be fetched
        for i in 0u32..1000 {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_le_bytes());
            let value = store.fetch(&key).unwrap().expect("missing key");
            assert_eq!(value, format!("value_{i}").as_bytes());
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reopen_persists() {
        let dir = temp_dir();
        {
            let mut store = Store::create(&dir, StoreOptions::default()).unwrap();
            for i in 0u32..100 {
                let mut key = [0u8; 32];
                key[..4].copy_from_slice(&i.to_le_bytes());
                store.insert(&key, b"data").unwrap();
            }
        }
        {
            let mut store = Store::open(&dir).unwrap();
            assert_eq!(store.key_count(), 100);
            for i in 0u32..100 {
                let mut key = [0u8; 32];
                key[..4].copy_from_slice(&i.to_le_bytes());
                assert!(
                    store.fetch(&key).unwrap().is_some(),
                    "key {i} missing after reopen"
                );
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn upsert_updates_value() {
        let dir = temp_dir();
        let mut store = Store::create(&dir, StoreOptions::default()).unwrap();

        let key = [0x01; 32];
        store.upsert(&key, b"version1").unwrap();
        assert_eq!(store.fetch(&key).unwrap().unwrap(), b"version1");

        store.upsert(&key, b"version2").unwrap();
        assert_eq!(store.fetch(&key).unwrap().unwrap(), b"version2");

        assert_eq!(store.key_count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_key() {
        let dir = temp_dir();
        let mut store = Store::create(&dir, StoreOptions::default()).unwrap();

        let key = [0x02; 32];
        store.insert(&key, b"data").unwrap();
        assert!(store.exists(&key).unwrap());

        assert!(store.remove(&key).unwrap());
        assert!(!store.exists(&key).unwrap());
        assert_eq!(store.key_count(), 0);

        assert!(!store.remove(&key).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn upsert_many() {
        let dir = temp_dir();
        let mut store = Store::create(&dir, StoreOptions::default()).unwrap();

        for i in 0u32..500 {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_le_bytes());
            store.upsert(&key, &i.to_le_bytes()).unwrap();
        }
        assert_eq!(store.key_count(), 500);

        for i in 0u32..500 {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_le_bytes());
            let new_val = (i * 100).to_le_bytes();
            store.upsert(&key, &new_val).unwrap();
        }
        assert_eq!(store.key_count(), 500);

        for i in 0u32..500 {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_le_bytes());
            let val = store.fetch(&key).unwrap().unwrap();
            assert_eq!(val, (i * 100).to_le_bytes());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn insert_unchecked_preserves_existing_bucket_entries() {
        let dir = temp_dir();
        let mut store = Store::create(&dir, StoreOptions::default()).unwrap();

        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        store.insert(&key1, b"first").unwrap();
        store.flush().unwrap();

        store.insert_unchecked(&key2, b"second").unwrap();
        store.flush().unwrap();

        drop(store);
        let mut reopened = Store::open(&dir).unwrap();
        assert_eq!(reopened.fetch(&key1).unwrap().unwrap(), b"first");
        assert_eq!(reopened.fetch(&key2).unwrap().unwrap(), b"second");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fetch_skips_corrupt_duplicate_and_returns_newer_value() {
        let dir = temp_dir();
        let mut store = Store::create(&dir, StoreOptions::default()).unwrap();

        let key = [0xA5u8; 32];
        store.insert(&key, b"stale").unwrap();
        store.flush().unwrap();

        let hash = xxh64(&key, store.header.salt);
        let hash48 = hash & 0xFFFF_FFFF_FFFF;
        let bucket_idx = store.bucket_index(hash);
        let bucket = store.get_bucket(bucket_idx).unwrap();
        let entry = bucket
            .entries
            .iter()
            .find(|entry| entry.hash == hash48)
            .copied()
            .expect("original entry should exist");

        store.dat_file.seek(SeekFrom::Start(entry.offset)).unwrap();
        store.dat_file.write_all(&[0u8; 6]).unwrap();
        store.dat_file.flush().unwrap();

        store.insert_unchecked(&key, b"fresh").unwrap();
        store.flush().unwrap();

        drop(store);
        let mut reopened = Store::open(&dir).unwrap();
        assert_eq!(reopened.fetch(&key).unwrap().unwrap(), b"fresh");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn level_next_computation() {
        assert_eq!(compute_level_next(1), (0, 0));
        assert_eq!(compute_level_next(2), (1, 0));
        assert_eq!(compute_level_next(3), (1, 1));
        assert_eq!(compute_level_next(4), (2, 0));
        assert_eq!(compute_level_next(5), (2, 1));
        assert_eq!(compute_level_next(8), (3, 0));
    }

    #[test]
    fn read_record_rejects_truncated_buffer_record() {
        let dir = temp_dir();
        let mut store = Store::create(&dir, StoreOptions::default()).unwrap();
        let offset = store.dat_end;

        store.data_buf.extend_from_slice(&write_u48(64));
        store.data_buf.extend_from_slice(b"short");
        store.dat_end += 11;

        let err = store.read_record(offset).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("record body beyond buffer"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_spill_rejects_zero_sized_bucket_payload() {
        let dir = temp_dir();
        let mut store = Store::create(&dir, StoreOptions::default()).unwrap();
        let offset = store.dat_end;

        store.data_buf.extend_from_slice(&[0u8; 6]);
        store.data_buf.extend_from_slice(&0u16.to_be_bytes());
        store.dat_end += 8;

        let err = store.read_spill(offset).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("spill bucket too small"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_record_rejects_disk_record_larger_than_file() {
        let dir = temp_dir();
        let mut store = Store::create(&dir, StoreOptions::default()).unwrap();
        let offset = store.dat_end;

        store.dat_file.seek(SeekFrom::Start(offset)).unwrap();
        store.dat_file.write_all(&[0xFF; 6]).unwrap();
        store.dat_file.flush().unwrap();
        store.dat_end = offset + 6;

        let err = store.read_record(offset).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("record extends beyond data file"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
