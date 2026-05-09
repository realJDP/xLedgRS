use crate::error::{Error, Result};

pub const U48_MAX: u64 = 0x0000_ffff_ffff_ffff;

#[inline]
pub fn read_u16(buf: &[u8]) -> Result<u16> {
    let bytes: [u8; 2] = buf
        .get(..2)
        .ok_or(Error::Corrupt("short u16"))?
        .try_into()
        .unwrap();
    Ok(u16::from_be_bytes(bytes))
}

#[inline]
pub fn read_u48(buf: &[u8]) -> Result<u64> {
    let b = buf.get(..6).ok_or(Error::Corrupt("short u48"))?;
    Ok(((b[0] as u64) << 40)
        | ((b[1] as u64) << 32)
        | ((b[2] as u64) << 24)
        | ((b[3] as u64) << 16)
        | ((b[4] as u64) << 8)
        | b[5] as u64)
}

#[inline]
pub fn read_u64(buf: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = buf
        .get(..8)
        .ok_or(Error::Corrupt("short u64"))?
        .try_into()
        .unwrap();
    Ok(u64::from_be_bytes(bytes))
}

#[inline]
pub fn write_u16(out: &mut [u8], value: u16) -> Result<()> {
    out.get_mut(..2)
        .ok_or(Error::Corrupt("short u16 write"))?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

#[inline]
pub fn write_u48(out: &mut [u8], value: u64) -> Result<()> {
    if value > U48_MAX {
        return Err(Error::Corrupt("u48 overflow"));
    }
    let out = out.get_mut(..6).ok_or(Error::Corrupt("short u48 write"))?;
    out[0] = (value >> 40) as u8;
    out[1] = (value >> 32) as u8;
    out[2] = (value >> 24) as u8;
    out[3] = (value >> 16) as u8;
    out[4] = (value >> 8) as u8;
    out[5] = value as u8;
    Ok(())
}

#[inline]
pub fn write_u64(out: &mut [u8], value: u64) -> Result<()> {
    out.get_mut(..8)
        .ok_or(Error::Corrupt("short u64 write"))?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u48_is_big_endian() {
        let mut buf = [0u8; 6];
        write_u48(&mut buf, 0x1234_5678_9abc).unwrap();
        assert_eq!(buf, [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
        assert_eq!(read_u48(&buf).unwrap(), 0x1234_5678_9abc);
    }
}
