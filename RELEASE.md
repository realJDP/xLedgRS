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

Validation command used on the working source before export:

```sh
cargo test --target-dir /private/tmp/xLedgRSv2Beta-codex-target --lib
```

Result:

```text
1018 passed; 0 failed
```

Release note:

This is a beta release intended for development, testing, protocol research,
and operator evaluation. Review configuration, validator identity, storage, and
network exposure before running it on public infrastructure.
