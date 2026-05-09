# xLedgRSv2Beta

Version: `2.0.0-beta`

`xLedgRSv2Beta` is a beta XRP Ledger node implementation in Rust. The repository ships the core peer protocol runtime, ledger and SHAMap handling, JSON-RPC, WebSocket, optional gRPC services, persistent storage, and release-safe configuration templates for follower and validator deployments.

## Release Status

This is a public beta release. It is intended for development, testing, protocol research, and operator evaluation. Do not treat it as a drop-in replacement for `rippled` in production validator infrastructure until your own validation and risk review are complete.

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

`xLedgRSv2Beta` includes native process lifecycle commands, so the binary can manage its own background process without a separate shell wrapper.

Common usage:

```bash
./target/release/xledgrs --start --config ./xLedgRSv2Beta.cfg
./target/release/xledgrs --status --config ./xLedgRSv2Beta.cfg
./target/release/xledgrs --restart --config ./xLedgRSv2Beta.cfg
./target/release/xledgrs --stop --config ./xLedgRSv2Beta.cfg
```

By default:

- the node reads its listeners and storage path from `--config`
- the PID file is written under the configured data directory as `xLedgRSv2Beta.pid`
- the log file is written under the configured data directory as `xLedgRSv2Beta.log`

These can be overridden explicitly:

```bash
./target/release/xledgrs \
  --start \
  --config ./xLedgRSv2Beta.cfg \
  --pid-file /var/run/xLedgRSv2Beta.pid \
  --log-file /var/log/xLedgRSv2Beta.log
```

## Default Ports

The shipped source tree uses rippled-style default ports:

- peer: `51235`
- JSON-RPC: `5005`
- WebSocket: `6006`

The binary CLI defaults match those ports, and the release config templates do too.

## Quick Start

### Mainnet follower

1. Copy the mainnet template:

```bash
cp cfg/xLedgRSv2Beta.cfg ./xLedgRSv2Beta.cfg
```

2. Review:

- listener bind addresses
- `node_db.path`
- `validators_file`
- optional `rpc_sync`

3. Start the node:

```bash
./target/release/xledgrs --start --config ./xLedgRSv2Beta.cfg
```

4. Check status:

```bash
./target/release/xledgrs --status --config ./xLedgRSv2Beta.cfg
```

5. Query local JSON-RPC:

```bash
curl -s http://127.0.0.1:5005 \
  -d '{"method":"server_info","params":[{}]}'
```

### Testnet follower

```bash
cp cfg/testnet.cfg ./xLedgRSv2Beta-testnet.cfg
./target/release/xledgrs --start --config ./xLedgRSv2Beta-testnet.cfg
```

### Foreground run

For debugging or direct terminal use, run without `--start`:

```bash
./target/release/xledgrs --config ./xLedgRSv2Beta.cfg
```

The process will stay attached to the terminal and shut down on `Ctrl-C` or `SIGTERM`.

## Configuration

### Supported config formats

`xledgrs --config` accepts:

- the repository’s xLedgRSv2Beta TOML format
- rippled/xrpld-style sectioned config files

### Shipped templates

- `cfg/xLedgRSv2Beta.cfg` mainnet follower template
- `cfg/testnet.cfg` testnet follower template
- `cfg/validator-mainnet.cfg` mainnet validator template
- `cfg/validator-testnet.cfg` testnet validator template
- `cfg/xLedgRSv2Beta-example.cfg` generic example template

### Important settings

The most important settings to review before running are:

- `[port_peer]`, `[port_rpc]`, `[port_ws]`
- `[node_db] path`
- `[validators_file]`
- `[ips]` and `[ips_fixed]`
- `[xLedgRSv2Beta]`
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
- `XLedgRSv2Beta` extension service

The protobuf definitions live in `proto/`.

## Operational Notes

- The default mainnet follower template stores data under `./xLedgRSv2Beta-data`
- The default validator template stores data under `./xLedgRSv2Beta-validator-data`
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

Library-only validation, useful for fast release checks:

```bash
cargo test --lib
```

Focused release-safety checks:

```bash
cargo test --test release_safety
```

## License

MIT
