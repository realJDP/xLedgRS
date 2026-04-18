# xLedgRS

Version: `1.0beta`

`xLedgRS` is an XRP Ledger node implementation in Rust. The repository ships the core peer protocol runtime, ledger and SHAMap handling, JSON-RPC, WebSocket, optional gRPC services, persistent storage, and release-safe configuration templates for follower and validator deployments.

## What This Repository Includes

- XRPL peer networking over the native protobuf peer protocol
- Persistent ledger and state storage
- JSON-RPC and WebSocket server surfaces
- Optional gRPC service layer
- Mainnet and testnet configuration templates
- Validator templates that do not ship private seeds

## Repository Layout

- `src/` runtime, ledger, networking, transaction, RPC, and consensus code
- `cfg/` release-safe configuration templates
- `proto/` protobuf definitions for peer and gRPC services
- `tests/` integration, parity, and release-safety coverage

## Prerequisites

### macOS

```bash
brew install openssl pkg-config protobuf
```

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y build-essential clang pkg-config libssl-dev protobuf-compiler
```

### Rust

Install the stable Rust toolchain from [rustup.rs](https://rustup.rs), then confirm:

```bash
rustc --version
cargo --version
```

## Build

Build the release binary:

```bash
cargo build --release
```

The binary will be written to:

```bash
./target/release/xledgrs
```

## Command-Line Lifecycle

`xledgrs` now includes native process lifecycle commands, so the binary can manage its own background process without a separate shell wrapper.

Common usage:

```bash
./target/release/xledgrs --start --config ./xledgrs.cfg
./target/release/xledgrs --status --config ./xledgrs.cfg
./target/release/xledgrs --restart --config ./xledgrs.cfg
./target/release/xledgrs --stop --config ./xledgrs.cfg
```

By default:

- the node reads its listeners and storage path from `--config`
- the PID file is written under the configured data directory as `xledgrs.pid`
- the log file is written under the configured data directory as `xledgrs.log`

These can be overridden explicitly:

```bash
./target/release/xledgrs \
  --start \
  --config ./xledgrs.cfg \
  --pid-file /var/run/xledgrs.pid \
  --log-file /var/log/xledgrs.log
```

## Default Ports

The shipped source tree now uses rippled-style default ports:

- peer: `51235`
- JSON-RPC: `5005`
- WebSocket: `6006`

The binary CLI defaults match those ports, and the release config templates now do too.

## Quick Start

### Mainnet follower

1. Copy the mainnet template:

```bash
cp cfg/xledgrs.cfg ./xledgrs.cfg
```

2. Review:

- listener bind addresses
- `node_db.path`
- `validators_file`
- optional `rpc_sync`

3. Start the node:

```bash
./target/release/xledgrs --start --config ./xledgrs.cfg
```

4. Check status:

```bash
./target/release/xledgrs --status --config ./xledgrs.cfg
```

5. Query local JSON-RPC:

```bash
curl -s http://127.0.0.1:5005 \
  -d '{"method":"server_info","params":[{}]}'
```

### Testnet follower

```bash
cp cfg/testnet.cfg ./xledgrs-testnet.cfg
./target/release/xledgrs --start --config ./xledgrs-testnet.cfg
```

### Foreground run

For debugging or direct terminal use, run without `--start`:

```bash
./target/release/xledgrs --config ./xledgrs.cfg
```

The process will stay attached to the terminal and shut down on `Ctrl-C` or `SIGTERM`.

## Configuration

### Supported config formats

`xledgrs --config` accepts:

- the repository’s xLedgRS TOML format
- rippled/xrpld-style sectioned config files

### Shipped templates

- `cfg/xledgrs.cfg` mainnet follower template
- `cfg/testnet.cfg` testnet follower template
- `cfg/validator-mainnet.cfg` mainnet validator template
- `cfg/validator-testnet.cfg` testnet validator template
- `cfg/xledgrs-example.cfg` generic example template

### Important settings

The most important settings to review before running are:

- `[port_peer]`, `[port_rpc]`, `[port_ws]`
- `[node_db] path`
- `[validators_file]`
- `[ips]` and `[ips_fixed]`
- `[xledgrs]`
  - `enable_consensus_close_loop`
  - `rpc_sync`
  - `post_sync_checkpoint_script`
  - `standalone`

### Validator configuration

Validator mode requires operator-supplied identity material. Before using a validator template:

- provide a real validation seed or validator token
- set the correct public bind addresses for your infrastructure
- review peer exposure and firewall rules
- confirm your UNL and validator list policy
- use a dedicated storage path

The public repository does not ship private validator seeds.

## Runtime Surfaces

### JSON-RPC

The node exposes operational methods including:

- `server_info`
- `server_state`
- `ping`
- `ledger`
- `ledger_data`
- `ledger_entry`
- `account_info`
- `account_lines`
- `account_offers`
- `tx`
- `submit`
- `fee`

### WebSocket

The node exposes a local WebSocket server for event-driven consumers and operator tooling when `[port_ws]` is enabled.

### gRPC

The binary can also expose gRPC when `--grpc-addr` is supplied or a gRPC listener is configured. The repository includes:

- `XRPLedgerAPIService`
- `Xledgrs` extension service

The protobuf definitions live in `proto/`.

## Operational Notes

- The default mainnet follower template stores data under `./xledgrs-data`
- The default validator template stores data under `./xledgrs-validator-data`
- `post-sync-checkpoint.sh` is an optional post-sync helper referenced by the shipped configs
- The built-in peer bootstrap list uses public XRPL hubs when no custom peer list is configured

## Development

Fast validation:

```bash
cargo check --bin xledgrs
```

Full test run:

```bash
cargo test
```

Focused release-safety checks:

```bash
cargo test --test release_safety
```

## License

MIT
