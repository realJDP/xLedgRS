# Diagnostic Binaries

These binaries are developer tools, not separate production daemons. They are
kept in-tree because they exercise the same serialization, SHAMap, ledger, and
transaction code used by the validator.

- `analyze_missing_refs.rs` - Investigates missing SHAMap references from replay or sync artifacts.
- `check_rippled_fetch.rs` - Smoke-tests ledger/state fetch behavior against a rippled-compatible RPC endpoint.
- `diff_state_jsonl.rs` - Compares exported ledger-state JSONL streams.
- `dump_rippled_ledger_state.rs` - Dumps authoritative rippled ledger state for local parity analysis.
- `hash_bundle_reference.rs` - Computes reference hashes for captured ledger bundles.
- `inspect_bundle_keys.rs` - Lists and inspects keys present in a captured replay bundle.
- `inspect_bundle_prestate.rs` - Examines pre-transaction state from a replay fixture.
- `inspect_bundle_state.rs` - Prints post-state objects from a replay fixture.
- `inspect_bundle_tx.rs` - Inspects transaction and metadata contents inside a bundle.
- `replay_fixture.rs` - Replays captured ledger fixtures through the transaction engine.
