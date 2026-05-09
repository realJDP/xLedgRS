# xLedgRSv2Beta Public Release Bundle

This folder is the clean public-release source bundle for `xLedgRSv2Beta`.

Contents:

- `Cargo.toml` - release-ready Rust package manifest.
- `vendor/nudb-rs/` - vendored NuDB dependency required by `Cargo.toml`.

Excluded from this copy:

- Git metadata.
- Rust build output (`target/`).
- Local agent/cache folders.
- macOS `.DS_Store` files.

Recommended validation commands before export:

```sh
cargo fmt --check
cargo build --release --bin xledgrs
cargo test --lib
cargo test --tests
cargo test --test release_safety
```

Release note:

This is a beta release intended for development, testing, protocol research,
and operator evaluation. Review configuration, validator identity, storage, and
network exposure before running it on public infrastructure.
