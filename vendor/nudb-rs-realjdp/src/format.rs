use crate::error::{Error, Result};
use crate::field::{read_u16, read_u64, write_u16, write_u64};
use crate::hasher::pepper;

pub const CURRENT_VERSION: u16 = 2;
pub const DAT_HEADER_SIZE: usize = 92;
pub const KEY_HEADER_SIZE: usize = 104;
pub const LOG_HEADER_SIZE: usize = 62;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatHeader {
    pub uid: u64,
    pub appnum: u64,
    pub key_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHeader {
    pub uid: u64,
    pub appnum: u64,
    pub key_size: usize,
    pub salt: u64,
    pub pepper: u64,
    pub block_size: usize,
    pub load_factor: usize,
    pub capacity: usize,
    pub buckets: u64,
    pub modulus: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogHeader {
    pub uid: u64,
    pub appnum: u64,
    pub key_size: usize,
    pub salt: u64,
    pub pepper: u64,
    pub block_size: usize,
    pub key_file_size: u64,
    pub dat_file_size: u64,
}

pub fn bucket_size(capacity: usize) -> usize {
    2 + 6 + capacity * (6 + 6 + 6)
}

pub fn bucket_capacity(block_size: usize) -> usize {
    if block_size < KEY_HEADER_SIZE || block_size < 8 {
        return 0;
    }
    ((block_size - 8) / 18).min(u16::MAX as usize)
}

pub fn value_record_size(value_size: usize, key_size: usize) -> usize {
    6 + key_size + value_size
}

pub fn ceil_pow2(x: u64) -> u64 {
    if x <= 1 {
        return 1;
    }
    x.next_power_of_two()
}

pub fn bucket_index(hash: u64, buckets: u64, modulus: u64) -> u64 {
    let mut n = hash % modulus;
    if n >= buckets {
        n -= modulus / 2;
    }
    n
}

pub fn encode_dat_header(header: &DatHeader) -> Result<[u8; DAT_HEADER_SIZE]> {
    let mut out = [0u8; DAT_HEADER_SIZE];
    out[..8].copy_from_slice(b"nudb.dat");
    write_u16(&mut out[8..], CURRENT_VERSION)?;
    write_u64(&mut out[10..], header.uid)?;
    write_u64(&mut out[18..], header.appnum)?;
    write_u16(&mut out[26..], checked_u16(header.key_size)?)?;
    Ok(out)
}

pub fn decode_dat_header(buf: &[u8]) -> Result<DatHeader> {
    if buf.get(..8) != Some(b"nudb.dat") {
        return Err(Error::NotDataFile);
    }
    let version = read_u16(&buf[8..])?;
    if version != CURRENT_VERSION {
        return Err(Error::DifferentVersion { found: version });
    }
    let key_size = read_u16(&buf[26..])? as usize;
    if key_size == 0 {
        return Err(Error::InvalidKeySize);
    }
    Ok(DatHeader {
        uid: read_u64(&buf[10..])?,
        appnum: read_u64(&buf[18..])?,
        key_size,
    })
}

pub fn encode_key_header(header: &KeyHeader) -> Result<Vec<u8>> {
    if header.block_size < KEY_HEADER_SIZE {
        return Err(Error::InvalidBlockSize);
    }
    let mut out = vec![0u8; header.block_size];
    out[..8].copy_from_slice(b"nudb.key");
    write_u16(&mut out[8..], CURRENT_VERSION)?;
    write_u64(&mut out[10..], header.uid)?;
    write_u64(&mut out[18..], header.appnum)?;
    write_u16(&mut out[26..], checked_u16(header.key_size)?)?;
    write_u64(&mut out[28..], header.salt)?;
    write_u64(&mut out[36..], header.pepper)?;
    write_u16(&mut out[44..], checked_u16(header.block_size)?)?;
    write_u16(&mut out[46..], checked_u16(header.load_factor)?)?;
    Ok(out)
}

pub fn decode_key_header(buf: &[u8], file_size: u64) -> Result<KeyHeader> {
    if buf.get(..8) != Some(b"nudb.key") {
        return Err(Error::NotKeyFile);
    }
    let version = read_u16(&buf[8..])?;
    if version != CURRENT_VERSION {
        return Err(Error::DifferentVersion { found: version });
    }
    let key_size = read_u16(&buf[26..])? as usize;
    if key_size == 0 {
        return Err(Error::InvalidKeySize);
    }
    let salt = read_u64(&buf[28..])?;
    let stored_pepper = read_u64(&buf[36..])?;
    if stored_pepper != pepper(salt) {
        return Err(Error::HashMismatch);
    }
    let block_size = read_u16(&buf[44..])? as usize;
    let load_factor = read_u16(&buf[46..])? as usize;
    if load_factor == 0 {
        return Err(Error::InvalidLoadFactor);
    }
    let capacity = bucket_capacity(block_size);
    if capacity == 0 {
        return Err(Error::InvalidCapacity);
    }
    let buckets = if file_size > block_size as u64 {
        (file_size - block_size as u64) / block_size as u64
    } else {
        0
    };
    if buckets == 0 {
        return Err(Error::InvalidBucketCount);
    }
    Ok(KeyHeader {
        uid: read_u64(&buf[10..])?,
        appnum: read_u64(&buf[18..])?,
        key_size,
        salt,
        pepper: stored_pepper,
        block_size,
        load_factor,
        capacity,
        buckets,
        modulus: ceil_pow2(buckets),
    })
}

pub fn encode_log_header(header: &LogHeader) -> Result<[u8; LOG_HEADER_SIZE]> {
    let mut out = [0u8; LOG_HEADER_SIZE];
    out[..8].copy_from_slice(b"nudb.log");
    write_u16(&mut out[8..], CURRENT_VERSION)?;
    write_u64(&mut out[10..], header.uid)?;
    write_u64(&mut out[18..], header.appnum)?;
    write_u16(&mut out[26..], checked_u16(header.key_size)?)?;
    write_u64(&mut out[28..], header.salt)?;
    write_u64(&mut out[36..], header.pepper)?;
    write_u16(&mut out[44..], checked_u16(header.block_size)?)?;
    write_u64(&mut out[46..], header.key_file_size)?;
    write_u64(&mut out[54..], header.dat_file_size)?;
    Ok(out)
}

pub fn decode_log_header(buf: &[u8]) -> Result<LogHeader> {
    if buf.get(..8) != Some(b"nudb.log") {
        return Err(Error::NotLogFile);
    }
    let version = read_u16(&buf[8..])?;
    if version != CURRENT_VERSION {
        return Err(Error::DifferentVersion { found: version });
    }
    let key_size = read_u16(&buf[26..])? as usize;
    if key_size == 0 {
        return Err(Error::InvalidKeySize);
    }
    let salt = read_u64(&buf[28..])?;
    let stored_pepper = read_u64(&buf[36..])?;
    if stored_pepper != pepper(salt) {
        return Err(Error::HashMismatch);
    }
    Ok(LogHeader {
        uid: read_u64(&buf[10..])?,
        appnum: read_u64(&buf[18..])?,
        key_size,
        salt,
        pepper: stored_pepper,
        block_size: read_u16(&buf[44..])? as usize,
        key_file_size: read_u64(&buf[46..])?,
        dat_file_size: read_u64(&buf[54..])?,
    })
}

pub fn verify_pair(dat: &DatHeader, key: &KeyHeader) -> Result<()> {
    if dat.uid != key.uid {
        return Err(Error::UidMismatch);
    }
    if dat.appnum != key.appnum {
        return Err(Error::AppnumMismatch);
    }
    if dat.key_size != key.key_size {
        return Err(Error::KeySizeMismatch);
    }
    Ok(())
}

pub fn verify_log(key: &KeyHeader, log: &LogHeader) -> Result<()> {
    if key.uid != log.uid {
        return Err(Error::UidMismatch);
    }
    if key.appnum != log.appnum {
        return Err(Error::AppnumMismatch);
    }
    if key.key_size != log.key_size {
        return Err(Error::KeySizeMismatch);
    }
    if key.salt != log.salt {
        return Err(Error::SaltMismatch);
    }
    if key.pepper != log.pepper {
        return Err(Error::PepperMismatch);
    }
    if key.block_size != log.block_size {
        return Err(Error::BlockSizeMismatch);
    }
    Ok(())
}

fn checked_u16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::InvalidBlockSize)
}
