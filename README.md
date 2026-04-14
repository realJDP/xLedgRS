# xLedgRS

`xLedgRS` is a Rust implementation of an XRP Ledger node. It includes peer-to-peer networking, ledger replay, SHAMap-based account-state handling, JSON-RPC and WebSocket APIs, persistent storage, and operator-focused tooling for running follower or validator deployments.

## Highlights

- Connects to XRPL peer networks over the native protobuf peer protocol
- Replays and validates ledger state with persistent on-disk storage
- Serves JSON-RPC and WebSocket APIs for node operations and integrations
- Supports mainnet and testnet follower deployments
- Includes validator-mode configuration templates without shipping private seeds

## Repository Layout

- `src/` core runtime, networking, ledger, transaction, RPC, and consensus code
- `cfg/` release-safe configuration templates
- `scripts/` local startup and release-export helpers
- `proto/` peer protocol definitions derived from XRPL wire formats
- `tests/` parity, integration, and release-safety coverage

## Prerequisites

### macOS

```bash
brew install openssl pkg-config
```

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev clang
```

### Rust

Install the stable toolchain from [rustup.rs](https://rustup.rs), then confirm:

```bash
rustc --version
cargo --version
```

## Build

```bash
cargo build --release
```

The main binary is:

```bash
./target/release/xledgrs
```

## Quick Start

### Mainnet follower

1. Copy the mainnet template:

```bash
cp cfg/xrplnode.cfg ./xledgrs-mainnet.cfg
```

2. Review listener addresses and storage path.

3. Start the node:

```bash
./target/release/xledgrs --config ./xledgrs-mainnet.cfg
```

4. Query local RPC:

```bash
curl -s http://127.0.0.1:5057 -d '{"method":"server_info","params":[{}]}'
```

### Testnet follower

```bash
cp cfg/testnet.cfg ./xledgrs-testnet.cfg
./target/release/xledgrs --config ./xledgrs-testnet.cfg
```

## Configuration Templates

- `cfg/xrplnode.cfg` mainnet follower template
- `cfg/testnet.cfg` testnet follower template
- `cfg/validator-mainnet.cfg` mainnet validator template
- `cfg/validator-testnet.cfg` testnet validator template
- `cfg/xledgrs-example.cfg` generic example configuration

The public repository does not include validator seeds, validator tokens, or machine-specific peer and deployment settings.

## Validator Notes

Validator mode requires your own validator identity material and operational setup. Before using `cfg/validator-mainnet.cfg` or `cfg/validator-testnet.cfg`, you must:

- provide your own validation seed or validator token
- choose your own public bind addresses and ports
- review your UNL / validator list strategy
- secure RPC and WebSocket exposure appropriately

## Development Checks

```bash
cargo check --all-targets
cargo test
```

## RPC

The node exposes standard operational methods such as:

- `server_info`
- `ping`
- `ledger`
- `ledger_data`
- `account_info`
- `account_lines`
- `account_offers`
- `tx`
- `submit`
- `fee`

## Notes

- This repository ships safe templates for public use.
- Private deployment hosts, validator seeds, and operator-specific scripts should stay outside the shared repo.
- `rippled` remains the behavior reference for protocol parity and interoperability work.

## License

MIT
