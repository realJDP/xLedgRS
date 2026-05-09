use crate::error::{Error, Result};
use crate::field::{read_u16, read_u48, write_u16, write_u48};
use crate::format::{bucket_capacity, bucket_size};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub offset: u64,
    pub size: u64,
    pub hash: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    pub block_size: usize,
    pub count: usize,
    pub spill: u64,
    buf: Vec<u8>,
}

impl Bucket {
    pub fn empty(block_size: usize) -> Self {
        Self {
            block_size,
            count: 0,
            spill: 0,
            buf: vec![0; block_size],
        }
    }

    pub fn decode(block_size: usize, bytes: &[u8]) -> Result<Self> {
        let cap = bucket_capacity(block_size);
        let need = bucket_size(cap);
        if bytes.len() < need {
            return Err(Error::Corrupt("short bucket"));
        }
        let count = read_u16(&bytes[..2])? as usize;
        if count > cap {
            return Err(Error::InvalidBucketSize);
        }
        let spill = read_u48(&bytes[2..8])?;
        let mut buf = vec![0u8; block_size];
        buf[..need].copy_from_slice(&bytes[..need]);
        Ok(Self {
            block_size,
            count,
            spill,
            buf,
        })
    }

    pub fn decode_compact(block_size: usize, bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 8 {
            return Err(Error::Corrupt("short compact bucket"));
        }
        let count = read_u16(&bytes[..2])? as usize;
        if count > bucket_capacity(block_size) {
            return Err(Error::InvalidBucketSize);
        }
        let actual = bucket_size(count);
        if bytes.len() < actual {
            return Err(Error::Corrupt("short compact bucket entries"));
        }
        let mut bucket = Bucket::empty(block_size);
        bucket.buf[..actual].copy_from_slice(&bytes[..actual]);
        bucket.count = count;
        bucket.spill = read_u48(&bytes[2..8])?;
        Ok((bucket, actual))
    }

    pub fn actual_size(&self) -> usize {
        bucket_size(self.count)
    }

    pub fn capacity(&self) -> usize {
        bucket_capacity(self.block_size)
    }

    pub fn is_full(&self) -> bool {
        self.count >= self.capacity()
    }

    pub fn entries(&self) -> Result<Vec<Entry>> {
        (0..self.count).map(|i| self.entry(i)).collect()
    }

    pub fn entry(&self, index: usize) -> Result<Entry> {
        if index >= self.count {
            return Err(Error::Corrupt("bucket entry index out of bounds"));
        }
        let p = 8 + index * 18;
        Ok(Entry {
            offset: read_u48(&self.buf[p..p + 6])?,
            size: read_u48(&self.buf[p + 6..p + 12])?,
            hash: read_u48(&self.buf[p + 12..p + 18])?,
        })
    }

    pub fn lower_bound(&self, hash: u64) -> Result<usize> {
        let mut first = 0usize;
        let mut count = self.count;
        while count > 0 {
            let step = count / 2;
            let i = first + step;
            if self.entry(i)?.hash < hash {
                first = i + 1;
                count -= step + 1;
            } else {
                count = step;
            }
        }
        Ok(first)
    }

    pub fn insert(&mut self, entry: Entry) -> Result<()> {
        if self.is_full() {
            return Err(Error::InvalidBucketSize);
        }
        let i = self.lower_bound(entry.hash)?;
        let w = 18;
        let start = 8 + i * w;
        let end = 8 + self.count * w;
        self.buf.copy_within(start..end, start + w);
        self.count += 1;
        self.write_header()?;
        self.write_entry(i, entry)
    }

    pub fn clear(&mut self) -> Result<()> {
        self.buf.fill(0);
        self.count = 0;
        self.spill = 0;
        self.write_header()
    }

    pub fn set_spill(&mut self, spill: u64) -> Result<()> {
        self.spill = spill;
        self.write_header()
    }

    #[allow(dead_code)]
    pub fn erase(&mut self, index: usize) -> Result<()> {
        if index >= self.count {
            return Err(Error::Corrupt("erase index out of bounds"));
        }
        let w = 18;
        let start = 8 + index * w;
        let next = start + w;
        let end = 8 + self.count * w;
        self.buf.copy_within(next..end, start);
        self.count -= 1;
        self.buf[8 + self.count * w..8 + (self.count + 1) * w].fill(0);
        self.write_header()
    }

    pub fn as_block(&mut self) -> Result<&[u8]> {
        let actual = self.actual_size();
        self.buf[actual..].fill(0);
        self.write_header()?;
        Ok(&self.buf)
    }

    pub fn compact_bytes(&mut self) -> Result<&[u8]> {
        self.write_header()?;
        Ok(&self.buf[..self.actual_size()])
    }

    fn write_header(&mut self) -> Result<()> {
        write_u16(&mut self.buf[..2], self.count as u16)?;
        write_u48(&mut self.buf[2..8], self.spill)
    }

    fn write_entry(&mut self, index: usize, entry: Entry) -> Result<()> {
        let p = 8 + index * 18;
        write_u48(&mut self.buf[p..p + 6], entry.offset)?;
        write_u48(&mut self.buf[p + 6..p + 12], entry.size)?;
        write_u48(&mut self.buf[p + 12..p + 18], entry.hash)
    }
}
