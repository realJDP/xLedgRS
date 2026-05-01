# Network

Network modules implement the XRPL peer-facing layer: RTXP framing,
handshakes, peer management, load/resource accounting, and relay behavior.

- `cluster.rs` - Cluster peer metadata and trusted-peer tracking.
- `handshake.rs` - XRPL peer handshake construction and validation.
- `load.rs` - Job queue and load-factor accounting.
- `message.rs` - RTXP frame encoding/decoding and message type definitions.
- `mod.rs` - Network module exports.
- `ops.rs` - Server-state accounting and operational counters.
- `peer.rs` - Peer identity, state, direction, and control events.
- `peerfinder.rs` - Peer discovery table and address selection.
- `relay.rs` - Peer-to-peer relay helpers.
- `resource.rs` - Resource limits and abuse/rate tracking.
