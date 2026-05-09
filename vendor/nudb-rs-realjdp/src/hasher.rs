const PRIME64_1: u64 = 11_400_714_785_074_694_791;
const PRIME64_2: u64 = 14_029_467_366_897_019_727;
const PRIME64_3: u64 = 1_609_587_929_392_839_161;
const PRIME64_4: u64 = 9_650_029_242_287_828_579;
const PRIME64_5: u64 = 2_870_177_450_012_600_261;

#[inline]
fn round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(PRIME64_2))
        .rotate_left(31)
        .wrapping_mul(PRIME64_1)
}

#[inline]
fn merge_round(acc: u64, val: u64) -> u64 {
    let val = round(0, val);
    (acc ^ val).wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4)
}

#[inline]
fn read_le_u32(data: &[u8]) -> u32 {
    u32::from_le_bytes(data[..4].try_into().unwrap())
}

#[inline]
fn read_le_u64(data: &[u8]) -> u64 {
    u64::from_le_bytes(data[..8].try_into().unwrap())
}

pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let mut p = 0usize;
    let len = data.len();
    let mut h64;

    if len >= 32 {
        let limit = len - 32;
        let mut v1 = seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        let mut v2 = seed.wrapping_add(PRIME64_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME64_1);

        while p <= limit {
            v1 = round(v1, read_le_u64(&data[p..]));
            p += 8;
            v2 = round(v2, read_le_u64(&data[p..]));
            p += 8;
            v3 = round(v3, read_le_u64(&data[p..]));
            p += 8;
            v4 = round(v4, read_le_u64(&data[p..]));
            p += 8;
        }

        h64 = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h64 = merge_round(h64, v1);
        h64 = merge_round(h64, v2);
        h64 = merge_round(h64, v3);
        h64 = merge_round(h64, v4);
    } else {
        h64 = seed.wrapping_add(PRIME64_5);
    }

    h64 = h64.wrapping_add(len as u64);
    while p + 8 <= len {
        let k1 = round(0, read_le_u64(&data[p..]));
        h64 ^= k1;
        h64 = h64
            .rotate_left(27)
            .wrapping_mul(PRIME64_1)
            .wrapping_add(PRIME64_4);
        p += 8;
    }
    if p + 4 <= len {
        h64 ^= (read_le_u32(&data[p..]) as u64).wrapping_mul(PRIME64_1);
        h64 = h64
            .rotate_left(23)
            .wrapping_mul(PRIME64_2)
            .wrapping_add(PRIME64_3);
        p += 4;
    }
    while p < len {
        h64 ^= (data[p] as u64).wrapping_mul(PRIME64_5);
        h64 = h64.rotate_left(11).wrapping_mul(PRIME64_1);
        p += 1;
    }
    h64 ^= h64 >> 33;
    h64 = h64.wrapping_mul(PRIME64_2);
    h64 ^= h64 >> 29;
    h64 = h64.wrapping_mul(PRIME64_3);
    h64 ^= h64 >> 32;
    h64
}

pub fn hash_key(key: &[u8], salt: u64) -> u64 {
    (xxh64(key, salt) >> 16) & 0x0000_ffff_ffff_ffff
}

pub fn pepper(salt: u64) -> u64 {
    xxh64(&salt.to_le_bytes(), salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_xxhash64_values() {
        assert_eq!(xxh64(b"", 0), 0xef46_db37_51d8_e999);
        assert_eq!(xxh64(b"hello", 0), 0x26c7_827d_889f_6da3);
    }

    #[test]
    fn nudb_hash_is_upper_48_bits() {
        let full = xxh64(b"abc", 42);
        assert_eq!(hash_key(b"abc", 42), (full >> 16) & 0x0000_ffff_ffff_ffff);
    }
}
