# RPC

RPC modules expose a rippled-compatible control and query surface for local
clients, tools, and operational monitoring.

- `handlers.rs` - JSON-RPC method handlers and server-info responses.
- `mod.rs` - RPC context, request dispatch, and module exports.
- `path_requests.rs` - Pathfinding request state and lifecycle.
- `types.rs` - Shared RPC request/response structures.
- `ws.rs` - WebSocket listener and subscription plumbing.
