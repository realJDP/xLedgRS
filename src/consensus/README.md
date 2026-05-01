# Consensus

Consensus modules model the XRPL consensus surface used by the node when it is
tracking the network, validating ledgers, and comparing proposals.

- `dispute.rs` - Tracks disputed transactions between proposal sets.
- `manifest.rs` - Handles validator manifests and signing key identity updates.
- `mod.rs` - Consensus module exports.
- `proposal.rs` - Consensus proposal structures and signing/serialization support.
- `round.rs` - Consensus round state and phase transitions.
- `validation.rs` - Ledger validation messages, quorum inputs, and validator signatures.
