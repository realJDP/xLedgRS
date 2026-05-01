# Node Runtime

The node runtime modules break the live daemon into focused pieces. `src/node.rs`
declares the primary `Node` type and imports these files with explicit paths.

- `close_loop.rs` - Consensus close-loop scheduling and ledger-close triggers.
- `consensus_control.rs` - Starts/stops consensus participation and validator activity.
- `http_io.rs` - JSON-RPC HTTP listener plumbing.
- `init.rs` - Node construction and service initialization.
- `legacy_sync.rs` - Compatibility sync path retained for older workflows.
- `load_manager.rs` - Runtime load and overload transitions.
- `message_router.rs` - Routes inbound RTXP messages to sync, transaction, consensus, or peer-control handlers.
- `peer_connect.rs` - Outbound peer dialing.
- `peer_control.rs` - Peer range/status updates and control-plane messages.
- `peer_disconnect.rs` - Peer cleanup and cooldown handling.
- `peer_discovery.rs` - Peerfinder seeding and peer advertisement handling.
- `peer_handshake.rs` - Peer handshake orchestration.
- `peer_io.rs` - Socket/TLS IO setup and inbound accept loop.
- `peer_policy.rs` - Peer admission and rate-limit policy.
- `peer_read.rs` - Frame read loop for established peers.
- `peer_session.rs` - Full peer session lifecycle.
- `protocol_helpers.rs` - Shared XRPL protocol helper functions.
- `resource_manager.rs` - Runtime resource accounting integration.
- `rpc_server.rs` - JSON-RPC/WebSocket server startup.
- `runtime_helpers.rs` - Shared async/runtime helper functions.
- `runtime_snapshots.rs` - Server info snapshots for RPC and diagnostics.
- `shared_state.rs` - Shared mutable state container for node services.
- `startup.rs` - High-level daemon startup sequencing.
- `sync_data.rs` - Sync data processor and NuDB flush/handoff behavior.
- `sync_helpers.rs` - Common sync helper routines.
- `sync_ingress.rs` - Inbound sync message handling.
- `sync_lifecycle.rs` - Sync state transitions and completion handoff.
- `sync_mesh.rs` - Peer mesh selection for state sync.
- `sync_timer.rs` - Sync timeout, kickstart, and reacquire logic.
- `sync_transport.rs` - Network transport for sync requests/responses.
- `tx_ingress.rs` - Inbound transaction submission and relay handling.
