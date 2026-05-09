//! A Rust port of NuDB's on-disk format and core store algorithm.
//!
//! This crate intentionally follows upstream NuDB's C++ file format:
//! big-endian integers, 48-bit offsets/sizes/hashes, a `.dat` append-only
//! value file, a `.key` linear-hash bucket file, and a `.log` rollback file.

mod bucket;
mod error;
mod field;
mod format;
mod hasher;
mod store;

pub use crate::error::{Error, Result};
pub use crate::format::{
    CURRENT_VERSION, DAT_HEADER_SIZE, KEY_HEADER_SIZE, LOG_HEADER_SIZE, bucket_capacity,
    bucket_index, bucket_size, value_record_size,
};
pub use crate::hasher::{hash_key, pepper, xxh64};
pub use crate::store::{CreateOptions, Store, visit_dat_file};
