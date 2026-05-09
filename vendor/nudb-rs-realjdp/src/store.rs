use crate::bucket::{Bucket, Entry};
use crate::error::{Error, Result};
use crate::field::{U48_MAX, read_u16, read_u64, write_u16, write_u48};
use crate::format::{
    DAT_HEADER_SIZE, DatHeader, KEY_HEADER_SIZE, KeyHeader, LOG_HEADER_SIZE, LogHeader,
    bucket_index, bucket_size, decode_dat_header, decode_key_header, decode_log_header,
    encode_dat_header, encode_key_header, encode_log_header, verify_log, verify_pair,
};
use crate::hasher::{hash_key, pepper};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions, remove_file};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub appnum: u64,
    pub uid: u64,
    pub salt: u64,
    pub key_size: usize,
    pub block_size: usize,
    pub load_factor: f32,
}

impl CreateOptions {
    pub fn new(appnum: u64, key_size: usize, block_size: usize) -> Self {
        let uid = entropy64();
        Self {
            appnum,
            uid,
            salt: uid.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15,
            key_size,
            block_size,
            load_factor: 0.5,
        }
    }
}

#[derive(Debug, Clone)]
struct Pending {
    hash: u64,
    value: Vec<u8>,
}

#[derive(Debug)]
pub struct Store {
    dat_path: PathBuf,
    key_path: PathBuf,
    log_path: PathBuf,
    dat: File,
    key: File,
    log: File,
    header: KeyHeader,
    buckets: u64,
    modulus: u64,
    threshold: usize,
    frac: usize,
    pending: BTreeMap<Vec<u8>, Pending>,
    record_count: u64,
}

impl Store {
    pub fn create<P: AsRef<Path>>(
        dat_path: P,
        key_path: P,
        log_path: P,
        options: CreateOptions,
    ) -> Result<()> {
        validate_create_options(&options)?;
        let load_factor = ((65_536.0 * options.load_factor).floor() as usize).min(65_535);
        let key_header = KeyHeader {
            uid: options.uid,
            appnum: options.appnum,
            key_size: options.key_size,
            salt: options.salt,
            pepper: pepper(options.salt),
            block_size: options.block_size,
            load_factor,
            capacity: crate::format::bucket_capacity(options.block_size),
            buckets: 1,
            modulus: 1,
        };
        let dat_header = DatHeader {
            uid: options.uid,
            appnum: options.appnum,
            key_size: options.key_size,
        };

        let dat_path = dat_path.as_ref();
        let key_path = key_path.as_ref();
        let log_path = log_path.as_ref();
        let mut created = Vec::new();
        let result = (|| -> Result<()> {
            let mut dat = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(dat_path)?;
            created.push(dat_path.to_path_buf());
            let mut key = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(key_path)?;
            created.push(key_path.to_path_buf());
            let log = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(log_path)?;
            created.push(log_path.to_path_buf());

            dat.write_all(&encode_dat_header(&dat_header)?)?;
            key.write_all(&encode_key_header(&key_header)?)?;
            let mut bucket = Bucket::empty(options.block_size);
            key.write_all(bucket.as_block()?)?;
            dat.sync_all()?;
            key.sync_all()?;
            log.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            for path in created {
                let _ = remove_file(path);
            }
        }
        result
    }

    pub fn open<P: AsRef<Path>>(dat_path: P, key_path: P, log_path: P) -> Result<Self> {
        let dat_path = dat_path.as_ref().to_path_buf();
        let key_path = key_path.as_ref().to_path_buf();
        let log_path = log_path.as_ref().to_path_buf();
        recover(&dat_path, &key_path, &log_path)?;

        let mut dat = OpenOptions::new().read(true).write(true).open(&dat_path)?;
        let mut key = OpenOptions::new().read(true).write(true).open(&key_path)?;
        let log = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&log_path)?;

        let dat_header = read_dat_header(&mut dat)?;
        let key_header = read_key_header(&mut key)?;
        verify_pair(&dat_header, &key_header)?;
        let threshold = (key_header.load_factor * key_header.capacity).max(65_536);
        let buckets = key_header.buckets;
        let modulus = key_header.modulus;
        let mut record_count = 0u64;
        visit_dat_records(&mut dat, key_header.key_size, |_, _| {
            record_count = record_count.saturating_add(1);
            Ok(())
        })?;

        Ok(Self {
            dat_path,
            key_path,
            log_path,
            dat,
            key,
            log,
            header: key_header,
            buckets,
            modulus,
            threshold,
            frac: threshold / 2,
            pending: BTreeMap::new(),
            record_count,
        })
    }

    pub fn appnum(&self) -> u64 {
        self.header.appnum
    }

    pub fn dat_path(&self) -> &Path {
        &self.dat_path
    }

    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn key_size(&self) -> usize {
        self.header.key_size
    }

    pub fn block_size(&self) -> usize {
        self.header.block_size
    }

    pub fn key_count(&self) -> u64 {
        self.record_count
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.check_key(key)?;
        if value.is_empty() {
            return Err(Error::Corrupt("NuDB values must be non-empty"));
        }
        if value.len() as u64 > u32::MAX as u64 || value.len() as u64 > U48_MAX {
            return Err(Error::ValueTooLarge);
        }
        if self.pending.contains_key(key) || self.exists_on_disk(key)? {
            return Err(Error::KeyExists);
        }
        let hash = hash_key(key, self.header.salt);
        self.pending.insert(
            key.to_vec(),
            Pending {
                hash,
                value: value.to_vec(),
            },
        );
        self.record_count = self.record_count.saturating_add(1);
        Ok(())
    }

    pub fn fetch(&mut self, key: &[u8]) -> Result<Vec<u8>> {
        self.check_key(key)?;
        if let Some(pending) = self.pending.get(key) {
            return Ok(pending.value.clone());
        }
        let hash = hash_key(key, self.header.salt);
        let n = bucket_index(hash, self.buckets, self.modulus);
        let bucket = self.read_key_bucket(n)?;
        self.fetch_from_bucket_chain(hash, key, bucket)
    }

    pub fn contains(&mut self, key: &[u8]) -> Result<bool> {
        self.check_key(key)?;
        if self.pending.contains_key(key) {
            return Ok(true);
        }
        self.exists_on_disk(key)
    }

    pub fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending);
        if let Err(error) = self.commit(pending) {
            return Err(error);
        }
        Ok(())
    }

    pub fn visit<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<()>,
    {
        self.flush()?;
        visit_dat_records(&mut self.dat, self.header.key_size, |key, value| {
            f(key, value)
        })
    }

    pub fn verify(&mut self) -> Result<usize> {
        self.flush()?;
        let mut values = Vec::new();
        visit_dat_records(&mut self.dat, self.header.key_size, |key, value| {
            values.push((key.to_vec(), value.to_vec()));
            Ok(())
        })?;
        let count = values.len();
        for (key, expected) in values {
            let actual = self.fetch(&key)?;
            if actual != expected {
                return Err(Error::Corrupt("key index points at wrong value"));
            }
        }
        Ok(count)
    }

    pub fn close(mut self) -> Result<()> {
        self.flush()?;
        self.log.set_len(0)?;
        self.log.sync_all()?;
        match remove_file(&self.log_path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
        Ok(())
    }

    fn commit(&mut self, pending: BTreeMap<Vec<u8>, Pending>) -> Result<()> {
        let old_key_size = self.key.metadata()?.len();
        let old_dat_size = self.dat.metadata()?.len();
        let log_header = LogHeader {
            uid: self.header.uid,
            appnum: self.header.appnum,
            key_size: self.header.key_size,
            salt: self.header.salt,
            pepper: self.header.pepper,
            block_size: self.header.block_size,
            key_file_size: old_key_size,
            dat_file_size: old_dat_size,
        };

        self.log.set_len(0)?;
        self.log.seek(SeekFrom::Start(0))?;
        self.log.write_all(&encode_log_header(&log_header)?)?;
        self.log.sync_all()?;

        let mut changed_original = BTreeMap::<u64, Bucket>::new();
        let mut changed_new = BTreeMap::<u64, Bucket>::new();
        let mut touched_original = BTreeSet::<u64>::new();
        let mut offsets = BTreeMap::<Vec<u8>, u64>::new();

        self.dat.seek(SeekFrom::End(0))?;
        for (key, item) in &pending {
            let offset = self.dat.stream_position()?;
            offsets.insert(key.clone(), offset);
            write_value_record(&mut self.dat, key, &item.value)?;
        }

        for (key, item) in &pending {
            if (self.frac + 65_536) >= self.threshold {
                self.frac = self.frac + 65_536 - self.threshold;
                if self.buckets == self.modulus {
                    self.modulus *= 2;
                }
                let n1 = self.buckets - (self.modulus / 2);
                let n2 = self.buckets;
                self.buckets += 1;
                let b1 = self.load_work_bucket(
                    n1,
                    &mut changed_new,
                    &mut changed_original,
                    &mut touched_original,
                )?;
                let b2 = Bucket::empty(self.header.block_size);
                changed_new.insert(n2, b2);
                self.split_bucket(n1, n2, b1, &mut changed_new)?;
            } else {
                self.frac += 65_536;
            }

            let n = bucket_index(item.hash, self.buckets, self.modulus);
            let mut bucket = self.load_work_bucket(
                n,
                &mut changed_new,
                &mut changed_original,
                &mut touched_original,
            )?;
            self.maybe_spill(&mut bucket)?;
            bucket.insert(Entry {
                offset: *offsets
                    .get(key)
                    .ok_or(Error::Corrupt("missing pending offset"))?,
                size: item.value.len() as u64,
                hash: item.hash,
            })?;
            changed_new.insert(n, bucket);
        }

        for (index, bucket) in &mut changed_original {
            self.log.write_all(&index.to_be_bytes())?;
            self.log.write_all(bucket.compact_bytes()?)?;
        }
        self.log.sync_all()?;

        for (index, bucket) in &mut changed_new {
            self.write_key_bucket(*index, bucket)?;
        }
        self.dat.sync_all()?;
        self.key.sync_all()?;
        self.log.set_len(0)?;
        self.log.sync_all()?;

        self.header.buckets = self.buckets;
        self.header.modulus = self.modulus;
        Ok(())
    }

    fn split_bucket(
        &mut self,
        n1: u64,
        n2: u64,
        mut b1: Bucket,
        changed_new: &mut BTreeMap<u64, Bucket>,
    ) -> Result<()> {
        let mut b2 = changed_new
            .remove(&n2)
            .unwrap_or_else(|| Bucket::empty(self.header.block_size));
        let mut all = Vec::new();
        all.extend(b1.entries()?);
        let mut spill = b1.spill;
        while spill != 0 {
            let sb = self.read_spill_bucket(spill)?;
            all.extend(sb.entries()?);
            spill = sb.spill;
        }
        b1.clear()?;
        b2.clear()?;
        for entry in all {
            let n = bucket_index(entry.hash, self.buckets, self.modulus);
            if n == n2 {
                self.maybe_spill(&mut b2)?;
                b2.insert(entry)?;
            } else if n == n1 {
                self.maybe_spill(&mut b1)?;
                b1.insert(entry)?;
            } else {
                return Err(Error::Corrupt("split produced wrong bucket"));
            }
        }
        changed_new.insert(n1, b1);
        changed_new.insert(n2, b2);
        Ok(())
    }

    fn load_work_bucket(
        &mut self,
        index: u64,
        changed_new: &mut BTreeMap<u64, Bucket>,
        changed_original: &mut BTreeMap<u64, Bucket>,
        touched_original: &mut BTreeSet<u64>,
    ) -> Result<Bucket> {
        if let Some(bucket) = changed_new.get(&index) {
            return Ok(bucket.clone());
        }
        let bucket = self.read_key_bucket(index)?;
        if touched_original.insert(index) {
            changed_original.insert(index, bucket.clone());
        }
        Ok(bucket)
    }

    fn maybe_spill(&mut self, bucket: &mut Bucket) -> Result<()> {
        if !bucket.is_full() {
            return Ok(());
        }
        let offset = self.dat.seek(SeekFrom::End(0))?;
        let mut compact = bucket.compact_bytes()?.to_vec();
        write_u48_to_file(&mut self.dat, 0)?;
        write_u16_to_file(&mut self.dat, compact.len() as u16)?;
        self.dat.write_all(&compact)?;
        let spill_offset = offset + 8;
        bucket.clear()?;
        bucket.set_spill(spill_offset)?;
        compact.clear();
        Ok(())
    }

    fn fetch_from_bucket_chain(
        &mut self,
        hash: u64,
        key: &[u8],
        mut bucket: Bucket,
    ) -> Result<Vec<u8>> {
        loop {
            let mut i = bucket.lower_bound(hash)?;
            while i < bucket.count {
                let entry = bucket.entry(i)?;
                if entry.hash != hash {
                    break;
                }
                let mut record_key = vec![0u8; self.header.key_size];
                self.dat.seek(SeekFrom::Start(entry.offset + 6))?;
                self.dat.read_exact(&mut record_key)?;
                if record_key == key {
                    let mut value = vec![0u8; entry.size as usize];
                    self.dat.read_exact(&mut value)?;
                    return Ok(value);
                }
                i += 1;
            }
            if bucket.spill == 0 {
                return Err(Error::KeyNotFound);
            }
            bucket = self.read_spill_bucket(bucket.spill)?;
        }
    }

    fn exists_on_disk(&mut self, key: &[u8]) -> Result<bool> {
        let hash = hash_key(key, self.header.salt);
        let n = bucket_index(hash, self.buckets, self.modulus);
        let bucket = self.read_key_bucket(n)?;
        match self.fetch_from_bucket_chain(hash, key, bucket) {
            Ok(_) => Ok(true),
            Err(Error::KeyNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn read_key_bucket(&mut self, index: u64) -> Result<Bucket> {
        if index >= self.buckets {
            return Err(Error::InvalidLogIndex);
        }
        let offset = (index + 1) * self.header.block_size as u64;
        let mut buf = vec![0u8; bucket_size(self.header.capacity)];
        self.key.seek(SeekFrom::Start(offset))?;
        self.key.read_exact(&mut buf)?;
        Bucket::decode(self.header.block_size, &buf)
    }

    fn write_key_bucket(&mut self, index: u64, bucket: &mut Bucket) -> Result<()> {
        let offset = (index + 1) * self.header.block_size as u64;
        self.key.seek(SeekFrom::Start(offset))?;
        self.key.write_all(bucket.as_block()?)?;
        Ok(())
    }

    fn read_spill_bucket(&mut self, offset: u64) -> Result<Bucket> {
        if offset < 8 {
            return Err(Error::Corrupt("invalid spill offset"));
        }
        self.dat.seek(SeekFrom::Start(offset - 2))?;
        let size = read_u16_from_file(&mut self.dat)? as usize;
        let mut buf = vec![0u8; size];
        self.dat.read_exact(&mut buf)?;
        let (bucket, _) = Bucket::decode_compact(self.header.block_size, &buf)?;
        Ok(bucket)
    }

    fn check_key(&self, key: &[u8]) -> Result<()> {
        if key.len() != self.header.key_size {
            return Err(Error::KeyLengthMismatch {
                expected: self.header.key_size,
                actual: key.len(),
            });
        }
        Ok(())
    }
}

fn recover(dat_path: &Path, key_path: &Path, log_path: &Path) -> Result<()> {
    let mut dat = OpenOptions::new().read(true).write(true).open(dat_path)?;
    let dat_header = read_dat_header(&mut dat)?;
    let mut key = OpenOptions::new().read(true).write(true).open(key_path)?;
    let key_header = read_key_header(&mut key)?;
    verify_pair(&dat_header, &key_header)?;

    let mut log = match OpenOptions::new().read(true).write(true).open(log_path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(Error::Io(error)),
    };
    let log_size = log.metadata()?.len();
    if log_size < LOG_HEADER_SIZE as u64 {
        log.set_len(0)?;
        log.sync_all()?;
        let _ = remove_file(log_path);
        return Ok(());
    }
    log.seek(SeekFrom::Start(0))?;
    let mut header_buf = [0u8; LOG_HEADER_SIZE];
    log.read_exact(&mut header_buf)?;
    let log_header = decode_log_header(&header_buf)?;
    verify_log(&key_header, &log_header)?;

    let mut cursor = LOG_HEADER_SIZE as u64;
    while cursor < log_size {
        if log_size - cursor < 8 {
            break;
        }
        log.seek(SeekFrom::Start(cursor))?;
        let index = read_u64_from_file(&mut log)?;
        cursor += 8;
        if index > key_header.buckets {
            return Err(Error::InvalidLogIndex);
        }
        let mut head = [0u8; 8];
        if log.read_exact(&mut head).is_err() {
            break;
        }
        let count = read_u16(&head[..2])? as usize;
        let actual = bucket_size(count);
        let mut compact = vec![0u8; actual];
        compact[..8].copy_from_slice(&head);
        if actual > 8 && log.read_exact(&mut compact[8..]).is_err() {
            break;
        }
        cursor += actual as u64;
        let (mut bucket, _) = Bucket::decode_compact(key_header.block_size, &compact)?;
        if bucket.spill != 0
            && bucket.spill + bucket_size(key_header.capacity) as u64 > dat.metadata()?.len()
        {
            return Err(Error::InvalidLogSpill);
        }
        let offset = (index + 1) * key_header.block_size as u64;
        key.seek(SeekFrom::Start(offset))?;
        key.write_all(bucket.as_block()?)?;
    }

    dat.set_len(log_header.dat_file_size)?;
    dat.sync_all()?;
    if log_header.key_file_size != 0 {
        key.set_len(log_header.key_file_size)?;
        key.sync_all()?;
    } else {
        drop(key);
        remove_file(key_path)?;
    }
    log.set_len(0)?;
    log.sync_all()?;
    drop(log);
    let _ = remove_file(log_path);
    Ok(())
}

fn validate_create_options(options: &CreateOptions) -> Result<()> {
    if options.key_size == 0 || options.key_size > u16::MAX as usize {
        return Err(Error::InvalidKeySize);
    }
    if options.block_size > u16::MAX as usize
        || crate::format::bucket_capacity(options.block_size) == 0
    {
        return Err(Error::InvalidBlockSize);
    }
    if !(0.0..1.0).contains(&options.load_factor) || options.load_factor == 0.0 {
        return Err(Error::InvalidLoadFactor);
    }
    Ok(())
}

fn read_dat_header(file: &mut File) -> Result<DatHeader> {
    let mut buf = [0u8; DAT_HEADER_SIZE];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut buf)?;
    decode_dat_header(&buf)
}

pub fn visit_dat_file<P, F>(dat_path: P, mut f: F) -> Result<()>
where
    P: AsRef<Path>,
    F: FnMut(&[u8], &[u8]) -> Result<()>,
{
    let mut dat = OpenOptions::new().read(true).open(dat_path)?;
    let header = read_dat_header(&mut dat)?;
    visit_dat_records(&mut dat, header.key_size, |key, value| f(key, value))
}

fn visit_dat_records<F>(file: &mut File, key_size: usize, mut f: F) -> Result<()>
where
    F: FnMut(&[u8], &[u8]) -> Result<()>,
{
    let end = file.metadata()?.len();
    let mut offset = DAT_HEADER_SIZE as u64;
    while offset < end {
        file.seek(SeekFrom::Start(offset))?;
        let size = read_u48_from_file(file)?;
        offset += 6;
        if size == 0 {
            let spill_size = read_u16_from_file(file)? as u64;
            offset += 2 + spill_size;
            continue;
        }
        let mut key = vec![0u8; key_size];
        file.read_exact(&mut key)?;
        let mut value = vec![0u8; size as usize];
        file.read_exact(&mut value)?;
        f(&key, &value)?;
        offset += key_size as u64 + size;
    }
    if offset != end {
        return Err(Error::Corrupt("data record ended past file end"));
    }
    Ok(())
}

fn read_key_header(file: &mut File) -> Result<KeyHeader> {
    let size = file.metadata()?.len();
    if size < KEY_HEADER_SIZE as u64 {
        return Err(Error::NotKeyFile);
    }
    let mut buf = vec![0u8; KEY_HEADER_SIZE];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut buf)?;
    decode_key_header(&buf, size)
}

fn write_value_record(file: &mut File, key: &[u8], value: &[u8]) -> Result<()> {
    write_u48_to_file(file, value.len() as u64)?;
    file.write_all(key)?;
    file.write_all(value)?;
    Ok(())
}

fn write_u16_to_file(file: &mut File, value: u16) -> Result<()> {
    let mut buf = [0u8; 2];
    write_u16(&mut buf, value)?;
    file.write_all(&buf)?;
    Ok(())
}

fn write_u48_to_file(file: &mut File, value: u64) -> Result<()> {
    let mut buf = [0u8; 6];
    write_u48(&mut buf, value)?;
    file.write_all(&buf)?;
    Ok(())
}

fn read_u16_from_file(file: &mut File) -> Result<u16> {
    let mut buf = [0u8; 2];
    file.read_exact(&mut buf)?;
    read_u16(&buf)
}

fn read_u48_from_file(file: &mut File) -> Result<u64> {
    let mut buf = [0u8; 6];
    file.read_exact(&mut buf)?;
    crate::field::read_u48(&buf)
}

fn read_u64_from_file(file: &mut File) -> Result<u64> {
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)?;
    read_u64(&buf)
}

fn entropy64() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1234_5678_9abc_def0);
    nanos ^ (&nanos as *const u64 as usize as u64).rotate_left(32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn paths(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        (dir.join("db.dat"), dir.join("db.key"), dir.join("db.log"))
    }

    fn key(i: u64) -> [u8; 8] {
        i.to_be_bytes()
    }

    fn value(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed ^ 0xa5a5_5a5a_d3c3_b4b4;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            out.push((x >> 56) as u8);
        }
        out
    }

    #[test]
    fn create_insert_fetch_reopen() {
        let dir = tempdir().unwrap();
        let (dat, keyp, log) = paths(dir.path());
        Store::create(
            &dat,
            &keyp,
            &log,
            CreateOptions {
                appnum: 7,
                uid: 11,
                salt: 13,
                key_size: 8,
                block_size: 512,
                load_factor: 0.5,
            },
        )
        .unwrap();
        let mut store = Store::open(&dat, &keyp, &log).unwrap();
        for i in 0..250u64 {
            store
                .insert(&key(i), format!("value-{i}").as_bytes())
                .unwrap();
        }
        for i in 0..250u64 {
            assert_eq!(
                store.fetch(&key(i)).unwrap(),
                format!("value-{i}").into_bytes()
            );
        }
        store.flush().unwrap();
        drop(store);

        let mut reopened = Store::open(&dat, &keyp, &log).unwrap();
        for i in 0..250u64 {
            assert_eq!(
                reopened.fetch(&key(i)).unwrap(),
                format!("value-{i}").into_bytes()
            );
        }
        assert_eq!(reopened.verify().unwrap(), 250);
        let mut visited = 0;
        reopened
            .visit(|_, _| {
                visited += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(visited, 250);
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let dir = tempdir().unwrap();
        let (dat, keyp, log) = paths(dir.path());
        Store::create(
            &dat,
            &keyp,
            &log,
            CreateOptions {
                appnum: 1,
                uid: 2,
                salt: 3,
                key_size: 8,
                block_size: 512,
                load_factor: 0.5,
            },
        )
        .unwrap();
        let mut store = Store::open(&dat, &keyp, &log).unwrap();
        store.insert(&key(1), b"a").unwrap();
        assert!(matches!(store.insert(&key(1), b"b"), Err(Error::KeyExists)));
        store.flush().unwrap();
        assert!(matches!(store.insert(&key(1), b"b"), Err(Error::KeyExists)));
    }

    #[test]
    fn deterministic_stress_multiple_flushes_and_visits() {
        let dir = tempdir().unwrap();
        let (dat, keyp, log) = paths(dir.path());
        Store::create(
            &dat,
            &keyp,
            &log,
            CreateOptions {
                appnum: 99,
                uid: 123,
                salt: 456,
                key_size: 8,
                block_size: 512,
                load_factor: 0.5,
            },
        )
        .unwrap();
        let mut expected = BTreeMap::new();
        let mut store = Store::open(&dat, &keyp, &log).unwrap();
        for i in 0..2_500u64 {
            let k = key(i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let v = value(i, 1 + (i as usize % 257));
            store.insert(&k, &v).unwrap();
            expected.insert(k.to_vec(), v);
            if i % 97 == 0 {
                store.flush().unwrap();
                assert_eq!(store.verify().unwrap(), expected.len());
            }
        }
        store.flush().unwrap();
        assert_eq!(store.verify().unwrap(), expected.len());
        drop(store);

        let mut reopened = Store::open(&dat, &keyp, &log).unwrap();
        for (k, v) in &expected {
            assert_eq!(reopened.fetch(k).unwrap(), *v);
        }
        assert_eq!(reopened.verify().unwrap(), expected.len());
    }

    #[test]
    fn recovery_rolls_back_when_log_is_present() {
        let dir = tempdir().unwrap();
        let (dat, keyp, log) = paths(dir.path());
        Store::create(
            &dat,
            &keyp,
            &log,
            CreateOptions {
                appnum: 1,
                uid: 2,
                salt: 3,
                key_size: 8,
                block_size: 512,
                load_factor: 0.5,
            },
        )
        .unwrap();
        let mut store = Store::open(&dat, &keyp, &log).unwrap();
        store.insert(&key(1), b"committed").unwrap();
        store.flush().unwrap();
        drop(store);

        let dat_size = std::fs::metadata(&dat).unwrap().len();
        let key_size = std::fs::metadata(&keyp).unwrap().len();
        let mut key_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&keyp)
            .unwrap();
        let kh = read_key_header(&mut key_file).unwrap();
        let lh = LogHeader {
            uid: kh.uid,
            appnum: kh.appnum,
            key_size: kh.key_size,
            salt: kh.salt,
            pepper: kh.pepper,
            block_size: kh.block_size,
            key_file_size: key_size,
            dat_file_size: dat_size,
        };
        let mut log_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&log)
            .unwrap();
        log_file
            .write_all(&encode_log_header(&lh).unwrap())
            .unwrap();
        log_file.sync_all().unwrap();

        let mut dat_file = OpenOptions::new().append(true).open(&dat).unwrap();
        dat_file.write_all(b"partial junk").unwrap();
        dat_file.sync_all().unwrap();
        drop(dat_file);

        let mut reopened = Store::open(&dat, &keyp, &log).unwrap();
        assert_eq!(std::fs::metadata(&dat).unwrap().len(), dat_size);
        assert_eq!(reopened.fetch(&key(1)).unwrap(), b"committed");
    }

    #[test]
    fn recovery_restores_logged_key_bucket_and_truncates_data() {
        let dir = tempdir().unwrap();
        let (dat, keyp, log) = paths(dir.path());
        Store::create(
            &dat,
            &keyp,
            &log,
            CreateOptions {
                appnum: 1,
                uid: 2,
                salt: 3,
                key_size: 8,
                block_size: 512,
                load_factor: 0.5,
            },
        )
        .unwrap();
        let mut store = Store::open(&dat, &keyp, &log).unwrap();
        for i in 0..80u64 {
            store
                .insert(&key(i), format!("stable-{i}").as_bytes())
                .unwrap();
        }
        store.flush().unwrap();
        drop(store);

        let dat_size = std::fs::metadata(&dat).unwrap().len();
        let key_size = std::fs::metadata(&keyp).unwrap().len();
        let mut key_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&keyp)
            .unwrap();
        let kh = read_key_header(&mut key_file).unwrap();
        let mut original_bucket = vec![0u8; bucket_size(kh.capacity)];
        key_file
            .seek(SeekFrom::Start(kh.block_size as u64))
            .unwrap();
        key_file.read_exact(&mut original_bucket).unwrap();

        let lh = LogHeader {
            uid: kh.uid,
            appnum: kh.appnum,
            key_size: kh.key_size,
            salt: kh.salt,
            pepper: kh.pepper,
            block_size: kh.block_size,
            key_file_size: key_size,
            dat_file_size: dat_size,
        };
        let mut log_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&log)
            .unwrap();
        log_file
            .write_all(&encode_log_header(&lh).unwrap())
            .unwrap();
        log_file.write_all(&0u64.to_be_bytes()).unwrap();
        let (mut bucket, _) = Bucket::decode_compact(kh.block_size, &original_bucket).unwrap();
        log_file.write_all(bucket.compact_bytes().unwrap()).unwrap();
        log_file.sync_all().unwrap();

        key_file
            .seek(SeekFrom::Start(kh.block_size as u64))
            .unwrap();
        key_file.write_all(&vec![0xff; kh.block_size]).unwrap();
        key_file.sync_all().unwrap();
        let mut dat_file = OpenOptions::new().append(true).open(&dat).unwrap();
        dat_file.write_all(b"partial commit bytes").unwrap();
        dat_file.sync_all().unwrap();
        drop(dat_file);
        drop(key_file);

        let mut reopened = Store::open(&dat, &keyp, &log).unwrap();
        assert_eq!(std::fs::metadata(&dat).unwrap().len(), dat_size);
        assert_eq!(std::fs::metadata(&keyp).unwrap().len(), key_size);
        for i in 0..80u64 {
            assert_eq!(
                reopened.fetch(&key(i)).unwrap(),
                format!("stable-{i}").into_bytes()
            );
        }
        assert_eq!(reopened.verify().unwrap(), 80);
    }
}
