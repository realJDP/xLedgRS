# Source Layout

This directory contains the Rust implementation of xLedgRSv2Beta. The code is
split by runtime responsibility so parity work can be traced from network input,
through sync and transaction replay, into ledger state and RPC output.

## Folders

- `bin/` - Developer and parity utilities for inspecting ledger bundles, replaying fixtures, and comparing state against rippled.
- `consensus/` - XRPL consensus data structures and validation/proposal handling.
- `crypto/` - XRPL key, address, and Base58 helpers.
- `ledger/` - Ledger objects, SHAMap state trees, transaction application views, sync/follower logic, and XRPL ledger-entry helpers.
- `network/` - Peer protocol framing, handshakes, peer discovery, load tracking, resource limits, and RTXP relay helpers.
- `node/` - Runtime orchestration for the live daemon: startup, peer sessions, sync lifecycle, message routing, and RPC serving.
- `rpc/` - JSON-RPC/WebSocket request types, handlers, path request tracking, and response shaping.
- `transaction/` - XRPL transaction parsing, serialization, amount math, signature/auth checks, and submission coordination.

## Top-Level Modules

- `config.rs` - Parses xLedgRSv2Beta TOML and rippled-style config files.
- `diagnose.rs` - Local and live diagnostics for state/hash mismatch investigation.
- `grpc.rs` - Optional gRPC service implementation around ledger/RPC APIs.
- `lib.rs` - Public crate module map used by tests, tools, and the daemon.
- `main.rs` - CLI entrypoint for the `xledgrs` binary.
- `node.rs` - Primary node type that wires peer networking, sync, consensus, RPC, and runtime state.
- `process_control.rs` - Daemon start/stop/status helpers and pid/log file management.
- `proto.rs` - Generated XRPL protocol buffer bindings.
- `rpc_sync.rs` - HTTP JSON-RPC helper path for pulling ledger data from a rippled-compatible endpoint.
- `services.rs` - Runtime service bundle shared by node subsystems.
- `storage.rs` - Persistent relational metadata and NuDB-backed object storage integration points.
- `sync*.rs` - State-tree sync coordinator, runtime, epochs, bootstrap, and processor components.
- `tls.rs` - TLS/OpenSSL configuration for XRPL peer connections.
- `validator_list.rs` - UNL publisher list fetching, verification, and validator key handling.
