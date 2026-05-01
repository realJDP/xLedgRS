# Transaction Engine

Transaction modules parse, authenticate, serialize, and coordinate XRPL
transaction application. Ledger-specific effects are applied through ledger
views and transaction helpers.

- `amount.rs` - XRP/IOU amount math, canonicalization, and quality/rate helpers.
- `builder.rs` - Transaction construction helpers for tests and tools.
- `field.rs` - XRPL transaction field identifiers and typed field access.
- `master.rs` - Transaction master queue and submission coordination.
- `mod.rs` - Transaction module exports.
- `parse.rs` - Binary/JSON transaction parsing.
- `serialize.rs` - XRPL canonical transaction serialization.
