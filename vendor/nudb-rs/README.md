# Vendored NuDB

This folder contains the vendored Rust NuDB implementation used by xLedgRSv2Beta
for XRPL node-object storage compatibility.

- `src/format.rs` - On-disk key/value format helpers.
- `src/store.rs` - NuDB store open/read/write/delete behavior.
- `src/lib.rs` - Public crate exports.

The vendored copy keeps xLedgRSv2Beta builds reproducible while NuDB compatibility
work is still moving quickly.
