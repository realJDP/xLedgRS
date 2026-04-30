//! NuDB — a pure Rust write-once, hash-indexed key-value store.
//!
//! Designed for content-addressable storage where keys are cryptographic hashes.
//! Constant memory usage regardless of database size. Append-only data file
//! with linear-hashed key index.
//!
//! File format compatible with C++ NuDB used by rippled.

mod format;
mod store;

pub use store::{Store, StoreOptions};
