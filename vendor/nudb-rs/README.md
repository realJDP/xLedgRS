# nudb-rs

A compatibility-first Rust port of NuDB.

This project treats upstream C++ NuDB as the format oracle. The goal is not a
NuDB-inspired store; it is byte-compatible `.dat`, `.key`, and `.log` handling
with deterministic Rust tests for the on-disk layout and recovery behavior.

The implementation follows the upstream C++ NuDB layout:

- `.dat`: append-only value and spill records
- `.key`: fixed-size linear-hash buckets
- `.log`: rollback records for crash recovery
- big-endian integer fields, including NuDB's 48-bit fields
- salted xxHash64 with NuDB's upper-48-bit hash reduction

Current API:

- create/open a store
- insert fixed-size keys and non-empty values
- fetch by key
- flush/close
- visit the data file
- count keys
- verify that all data-file values are reachable through the key file
- recover from a present NuDB log file on open

## Compatibility Status

Covered by the Rust test suite:

- Rust creates, inserts, fetches, flushes, reopens, visits, and verifies stores
- deterministic 2,500-record stress with many flushes
- duplicate-key rejection
- rollback recovery from a present log header
- rollback recovery restoring a logged key bucket after deliberate key-file corruption
- NuDB field encoding and upper-48-bit hash reduction

Still intentionally future work:

- async/background commit thread matching upstream's runtime behavior
- API-level concurrent fetch ergonomics
- offline key-file rebuild/rekey tooling
- very large multi-million-record soak runs
- real rippled node-store fixtures

## Testing

Run the Rust tests:

```sh
cargo test
```

## Example

```rust
use nudb_rs::{CreateOptions, Store};

let dat = "db.dat";
let key = "db.key";
let log = "db.log";

Store::create(dat, key, log, CreateOptions::new(1, 32, 4096))?;

let mut store = Store::open(dat, key, log)?;
let key_bytes = [7u8; 32];
store.insert(&key_bytes, b"value")?;
store.flush()?;

assert_eq!(store.fetch(&key_bytes)?, b"value");
# Ok::<(), nudb_rs::Error>(())
```
