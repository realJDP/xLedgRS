# Config Parity Roadmap

This document tracks how closely `xLedgRS` matches `rippled` / `xrpld`
configuration behavior.

Goal:
- keep the file layout and section names familiar to XRPL operators
- wire supported settings to real runtime behavior
- make unsupported settings explicit, with the missing feature/process noted

Reference files:
- `rippled/cfg/xrpld-example.cfg`
- `rippled/cfg/validators-example.txt`

## Status Key

- `Supported`: parsed and used by runtime behavior
- `Partial`: parsed, but only some fields are honored
- `Planned`: not yet supported; missing feature/process listed

## Main Config Sections

| Section | Status | Current xLedgRS behavior | Missing feature / process |
|---|---|---|---|
| `[server]` | Supported | Selects named listener sections | None |
| `[port_*]` | Partial | Peer / HTTP RPC / WS addresses are used | Admin ACLs, public/private split, gRPC, TLS cert files, queue limits |
| `[ips]` | Supported | Bootstrap peers loaded from config | None |
| `[ips_fixed]` | Supported | Fixed peers loaded from config | Long-lived fixed-peer policy tuning |
| `[peers_max]` | Supported | Sets max peer count | None |
| `[peer_private]` | Planned | Not parsed or enforced | Outbound privacy mode, peer advertisement suppression, only-connect-to-configured-peers mode |
| `[network_id]` | Supported | Sets network ID for handshake and validation logic | None |
| `[ledger_history]` | Supported | Controls retained local history window | None |
| `[fetch_depth]` | Supported | Controls advertised historical serving depth | Deeper serving policy enforcement could still improve |
| `[node_db]` | Partial | Uses `path` and `online_delete` | Backend type selection policy, `fast_load`, `earliest_seq`, delete tuning, backend-specific tuning |
| `[database_path]` | Partial | Used as alternate data dir source | Separate bookkeeping DB path is not distinct from main storage layout |
| `[sqlite]` | Planned | Ignored | SQLite tuning hooks and operational controls |
| `[debug_logfile]` | Planned | Ignored | Config-driven logging destination / rotation |
| `[rpc_startup]` | Planned | Ignored | Startup admin command runner |
| `[path_search]` | Planned | Ignored | Pathfinding resource knobs and feature completion |
| `[path_search_fast]` | Planned | Ignored | Same as above |
| `[path_search_max]` | Planned | Ignored | Same as above |
| `[validation_seed]` | Planned | Ignored | Real validator identity / key management |
| `[validator_token]` | Planned | Ignored | Offline validator token flow |
| `[validator_key_revocation]` | Planned | Ignored | Validator revocation handling |
| `[validators_file]` | Partial | File is loaded, local `[validators]` keys are accepted | Publisher list support and threshold rules |
| `[xledgrs]` | Supported | Custom node-specific settings like `enable_consensus_close_loop` | Expand only when rippled has no equivalent |

## validators.txt Sections

| Section | Status | Current xLedgRS behavior | Missing feature / process |
|---|---|---|---|
| `[validators]` | Supported | Local validator public keys are loaded | None |
| `[validator_list_sites]` | Planned | Ignored | Fetch signed publisher lists, cache them, refresh them, and merge into trusted UNL |
| `[validator_list_keys]` | Planned | Ignored | Verify publisher signatures and trust roots |
| `[validator_list_threshold]` | Planned | Ignored | Threshold logic over fetched validator lists |

## Important Gaps That Imply Real Features

These are not just parser gaps. They imply missing runtime systems:

1. Validator identity:
   `validation_seed`, `validator_token`, and `validator_key_revocation` require
   a real validator process model, secure key handling, and revocation-aware
   trust behavior.

2. Publisher-backed UNL:
   `validator_list_sites`, `validator_list_keys`, and
   `validator_list_threshold` require:
   - signed list fetch/update logic
   - persistent cache of fetched lists
   - publisher signature verification
   - dynamic trusted validator set updates

3. Peer privacy / topology control:
   `peer_private` needs:
   - peer advertisement suppression
   - outbound-only/private-topology behavior
   - config-driven network-isolation semantics

4. Storage / deletion tuning:
   richer `[node_db]` and `[sqlite]` support needs:
   - delete batch pacing
   - age-gated pruning
   - advisory delete workflow
   - backend-specific startup/load policies

5. Admin startup actions:
   `rpc_startup` requires:
   - startup command executor
   - ordering / failure semantics
   - safe allowlist for supported commands

6. Logging parity:
   `debug_logfile` needs:
   - configurable sink path
   - rotation policy
   - interaction with existing tracing setup

7. Pathfinding config:
   `path_search*` requires:
   - fuller pathfinding implementation
   - resource controls around pathfinding search breadth

## Recommended Implementation Order

1. `validators.txt` publisher-list support
2. `peer_private`
3. richer `[node_db]` delete / startup tuning
4. `[debug_logfile]`
5. `[rpc_startup]`
6. validator identity sections
7. pathfinding config

## Notes

- `xLedgRS` is already using a real config-driven startup path in operator
  environments via an explicit config file.
- For now, unsupported sections should be considered no-ops unless and until
  they are wired into runtime behavior.
