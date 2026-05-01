# Tests

This folder contains integration, release-safety, and XRPL parity checks.

- `integration.rs` - Runtime and configuration integration coverage.
- `parity.rs` - Transaction/ledger parity fixtures and regression checks.
- `release_safety.rs` - Guards against shipping private or unsafe release artifacts.
- `bug_b_tfsell_tx0.rs` - Regression fixture for a TakerPays/TakerGets transaction edge case.
- `bug_c_book_dir.rs` - Regression fixture for book-directory and offer-quality parity.

The tests are intentionally close to observed ledger behavior so parity fixes can
be locked down before release.
