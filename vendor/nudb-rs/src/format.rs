//! NuDB on-disk format constants and structures.

use std::io::{self, Read, Write};

// ── Magic identifiers ────────────────────────────────────────────────────────

pub const DAT_MAGIC: &[u8; 8] = b"nudb.dat";
pub const KEY_MAGIC: &[u8; 8] = b"nudb.key";
#[allow(dead_code)]
pub const LOG_MAGIC: &[u8; 8] = b"nudb.log";
pub const VERSION: u16 = 2;

// ── Header sizes ─────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub const DAT_HEADER_SIZE: u64 = 92;
pub const KEY_HEADER_SIZE: u64 = 104;
#[allow(dead_code)]
pub const LOG_HEADER_SIZE: u64 = 64;

// ── Bucket entry ─────────────────────────────────────────────────────────────

/// Size of one bucket entry: offset(6) + size(6) + hash(6) = 18 bytes.
pub const ENTRY_SIZE: usize = 18;

/// Bucket header: count(2) + spill(6) = 8 bytes.
pub const BUCKET_HEADER_SIZE: usize = 8;

// ── Integer encoding helpers ─────────────────────────────────────────────────

/// Read a 6-byte little-endian u48.
pub fn read_u48(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf[..6].copy_from_slice(&data[..6]);
    u64::from_le_bytes(buf)
}

/// Write a 6-byte little-endian u48.
pub fn write_u48(val: u64) -> [u8; 6] {
    let bytes = val.to_le_bytes();
    let mut out = [0u8; 6];
    out.copy_from_slice(&bytes[..6]);
    out
}

/// Read a 2-byte little-endian u16.
pub fn read_u16_le(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[0], data[1]])
}

/// Read an 8-byte little-endian u64.
#[allow(dead_code)]
pub fn read_u64_le(data: &[u8]) -> u64 {
    u64::from_le_bytes(data[..8].try_into().unwrap())
}

// ── Data file header ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DatHeader {
    pub version: u16,
    pub uid: u64,
    pub appnum: u64,
    pub key_size: u16,
}

impl DatHeader {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(DAT_MAGIC)?;
        w.write_all(&self.version.to_le_bytes())?;
        w.write_all(&self.uid.to_le_bytes())?;
        w.write_all(&self.appnum.to_le_bytes())?;
        w.write_all(&self.key_size.to_le_bytes())?;
        w.write_all(&[0u8; 64])?; // reserved
        Ok(())
    }

    #[allow(dead_code)]
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if &magic != DAT_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a nudb data file",
            ));
        }
        let mut buf2 = [0u8; 2];
        let mut buf8 = [0u8; 8];
        r.read_exact(&mut buf2)?;
        let version = u16::from_le_bytes(buf2);
        r.read_exact(&mut buf8)?;
        let uid = u64::from_le_bytes(buf8);
        r.read_exact(&mut buf8)?;
        let appnum = u64::from_le_bytes(buf8);
        r.read_exact(&mut buf2)?;
        let key_size = u16::from_le_bytes(buf2);
        let mut reserved = [0u8; 64];
        r.read_exact(&mut reserved)?;
        Ok(Self {
            version,
            uid,
            appnum,
            key_size,
        })
    }
}

// ── Key file header ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct KeyHeader {
    pub version: u16,
    pub uid: u64,
    pub appnum: u64,
    pub key_size: u16,
    pub salt: u64,
    pub pepper: u64,
    pub block_size: u16,
    pub load_factor: u16,
    pub bucket_count: u64,
    pub key_count: u64,
}

impl KeyHeader {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(KEY_MAGIC)?;
        w.write_all(&self.version.to_le_bytes())?;
        w.write_all(&self.uid.to_le_bytes())?;
        w.write_all(&self.appnum.to_le_bytes())?;
        w.write_all(&self.key_size.to_le_bytes())?;
        w.write_all(&self.salt.to_le_bytes())?;
        w.write_all(&self.pepper.to_le_bytes())?;
        w.write_all(&self.block_size.to_le_bytes())?;
        w.write_all(&self.load_factor.to_le_bytes())?;
        w.write_all(&self.bucket_count.to_le_bytes())?;
        w.write_all(&self.key_count.to_le_bytes())?;
        // Pad to KEY_HEADER_SIZE
        let written = 8 + 2 + 8 + 8 + 2 + 8 + 8 + 2 + 2 + 8 + 8; // 64
        let pad = KEY_HEADER_SIZE as usize - written;
        w.write_all(&vec![0u8; pad])?;
        Ok(())
    }

    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if &magic != KEY_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a nudb key file",
            ));
        }
        let mut b2 = [0u8; 2];
        let mut b8 = [0u8; 8];
        r.read_exact(&mut b2)?;
        let version = u16::from_le_bytes(b2);
        r.read_exact(&mut b8)?;
        let uid = u64::from_le_bytes(b8);
        r.read_exact(&mut b8)?;
        let appnum = u64::from_le_bytes(b8);
        r.read_exact(&mut b2)?;
        let key_size = u16::from_le_bytes(b2);
        r.read_exact(&mut b8)?;
        let salt = u64::from_le_bytes(b8);
        r.read_exact(&mut b8)?;
        let pepper = u64::from_le_bytes(b8);
        r.read_exact(&mut b2)?;
        let block_size = u16::from_le_bytes(b2);
        r.read_exact(&mut b2)?;
        let load_factor = u16::from_le_bytes(b2);
        r.read_exact(&mut b8)?;
        let bucket_count = u64::from_le_bytes(b8);
        r.read_exact(&mut b8)?;
        let key_count = u64::from_le_bytes(b8);
        // Skip remaining padding
        let read_so_far = 8 + 2 + 8 + 8 + 2 + 8 + 8 + 2 + 2 + 8 + 8;
        let remaining = KEY_HEADER_SIZE as usize - read_so_far;
        let mut pad = vec![0u8; remaining];
        r.read_exact(&mut pad)?;
        Ok(Self {
            version,
            uid,
            appnum,
            key_size,
            salt,
            pepper,
            block_size,
            load_factor,
            bucket_count,
            key_count,
        })
    }

    /// Maximum entries per bucket.
    pub fn bucket_capacity(&self) -> usize {
        (self.block_size as usize - BUCKET_HEADER_SIZE) / ENTRY_SIZE
    }

    /// File offset of a bucket by index.
    pub fn bucket_offset(&self, index: u64) -> u64 {
        KEY_HEADER_SIZE + index * self.block_size as u64
    }
}

// ── Bucket ───────────────────────────────────────────────────────────────────

/// A single bucket entry in the key file.
#[derive(Debug, Clone, Copy)]
pub struct BucketEntry {
    /// Offset into data file where the record starts.
    pub offset: u64,
    /// Size of the value data (not including key).
    pub size: u64,
    /// First 48 bits of the key hash (for fast rejection).
    pub hash: u64,
}

/// An in-memory bucket.
#[derive(Debug, Clone)]
pub struct Bucket {
    /// Number of entries.
    pub count: u16,
    /// Offset to spill record in data file (0 = no spill).
    pub spill: u64,
    /// Entries sorted by hash.
    pub entries: Vec<BucketEntry>,
}

impl Bucket {
    pub fn new() -> Self {
        Self {
            count: 0,
            spill: 0,
            entries: Vec::new(),
        }
    }

    /// Deserialize a bucket from raw bytes, validating the block is large enough
    /// and that the encoded entry count can actually fit in the provided data.
    pub fn try_from_bytes(data: &[u8]) -> io::Result<Self> {
        if data.len() < BUCKET_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "bucket block too small: got {} bytes, need at least {}",
                    data.len(),
                    BUCKET_HEADER_SIZE
                ),
            ));
        }

        let count = read_u16_le(&data[0..2]);
        let spill = read_u48(&data[2..8]);
        let max_entries = (data.len() - BUCKET_HEADER_SIZE) / ENTRY_SIZE;
        if count as usize > max_entries {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "bucket entry count {} exceeds capacity {} for {}-byte block",
                    count,
                    max_entries,
                    data.len()
                ),
            ));
        }

        let mut entries = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let base = BUCKET_HEADER_SIZE + i * ENTRY_SIZE;
            entries.push(BucketEntry {
                offset: read_u48(&data[base..base + 6]),
                size: read_u48(&data[base + 6..base + 12]),
                hash: read_u48(&data[base + 12..base + 18]),
            });
        }

        Ok(Self {
            count,
            spill,
            entries,
        })
    }

    /// Deserialize a bucket from a block_size buffer.
    #[allow(dead_code)]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self::try_from_bytes(data).unwrap_or_else(|_| Self::new())
    }

    /// Serialize a bucket into a block_size buffer.
    pub fn to_bytes(&self, block_size: usize) -> Vec<u8> {
        let mut buf = vec![0u8; block_size];
        buf[0..2].copy_from_slice(&self.count.to_le_bytes());
        buf[2..8].copy_from_slice(&write_u48(self.spill));
        for (i, e) in self.entries.iter().enumerate() {
            let base = BUCKET_HEADER_SIZE + i * ENTRY_SIZE;
            if base + ENTRY_SIZE > block_size {
                break;
            }
            buf[base..base + 6].copy_from_slice(&write_u48(e.offset));
            buf[base + 6..base + 12].copy_from_slice(&write_u48(e.size));
            buf[base + 12..base + 18].copy_from_slice(&write_u48(e.hash));
        }
        buf
    }

    /// Find an entry by hash prefix. Returns index if found.
    #[allow(dead_code)]
    pub fn find_hash(&self, hash48: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.hash == hash48)
    }

    /// Insert an entry, maintaining sort order by hash.
    pub fn insert(&mut self, entry: BucketEntry) {
        let pos = self
            .entries
            .iter()
            .position(|e| e.hash >= entry.hash)
            .unwrap_or(self.entries.len());
        self.entries.insert(pos, entry);
        self.count += 1;
    }
}
