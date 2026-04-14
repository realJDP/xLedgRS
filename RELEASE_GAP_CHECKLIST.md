# XLedgRS V1 Beta Release Checklist

Baseline captured on 2026-04-13 in the active `xLedgRS-1.7` tree:

- `cargo check --all-targets --quiet`: passing
- `cargo test --quiet`: passing (`590` unit tests plus integration/doc test targets)
- warning cleanup: complete

Definition of done for this beta:

- mainnet-active transaction paths behave correctly in the shipping node paths
- unsupported or inactive amendment features do not silently succeed
- follower / sync / RPC paths do not rely on known placeholders for normal operation
- the tree stays green under `cargo check` and `cargo test`
- the shareable beta export contains no private seeds, hardcoded deploy hosts, or machine-specific configs

## Mainnet-critical

- [x] Replace active consensus close handling with the newer `ledger::close` / `ledger::tx` engine so `close_v2` and `ledger/transact/*` are no longer on the live runtime path
- [x] Remove silent success stubs from reachable transaction handlers
- [x] Implement `sfSigners` parsing in [`src/transaction/parse.rs`](src/transaction/parse.rs)
- [x] Finish `closed_ledger` snapshot construction in [`src/node.rs`](src/node.rs)
- [x] Fix `GetObjects` nodeid handling for stall recovery in [`src/node.rs`](src/node.rs)
- [x] Accept `ltCLOSED` recovery responses in the queue-first sync gate and serve state-node `GetObjects` from NuDB in [`src/node.rs`](src/node.rs)
- [x] Serve current `liAS_NODE` root / inner / leaf requests from the live state tree and return explicit TMReplyError replies when state nodes are unavailable in [`src/node.rs`](src/node.rs)
- [x] Implement historical root-based lookup for object serving in [`src/node.rs`](src/node.rs) and basic historical RPC reads in [`src/rpc/handlers.rs`](src/rpc/handlers.rs)
- [x] Page historical `ledger_data` directly from persisted account-state roots instead of returning an empty placeholder
- [x] Remove artificial historical RPC dead ends for `account_objects`, `account_nfts`, and `account_channels` when the persisted account-state root is available
- [x] Serve `TMGetLedger` subtree ("fat") responses for `liAS_NODE` and `liTX_NODE` using `nodeIDs + queryDepth` instead of flat exact-node replies
- [x] Tighten `TMGetLedger/TMLedgerData` parity in [`src/network/relay.rs`](src/network/relay.rs) and [`src/node.rs`](src/node.rs) so `ltCLOSED`, explicit-hash, `queryDepth`, and malformed-request handling follow the compatibility target more closely
- [x] Finish the offer expiration close-time check in [`src/ledger/tx/offer.rs`](src/ledger/tx/offer.rs)
- [x] Implement direct mainnet-active MPT flows in the active engine: issuance flags, allow-list enforcement, direct payments, clawback, and issuance / holder lock semantics in [`src/ledger/tx/mptoken.rs`](src/ledger/tx/mptoken.rs), [`src/ledger/tx/payment.rs`](src/ledger/tx/payment.rs), and [`src/ledger/tx/clawback.rs`](src/ledger/tx/clawback.rs)
- [x] Export a scrubbed beta tree without private validator seeds, hardcoded deploy hosts, or machine-specific config files

## Legacy stubs to clean up or explicitly fence off

These are no longer on the live consensus-close path after the runtime swap,
but they still need an intentional cleanup story before we call the repo done.

- [x] [`src/ledger/transact/payment.rs`](src/ledger/transact/payment.rs): IOU payment path fenced off with explicit unsupported failure
- [x] [`src/ledger/transact/offer_create.rs`](src/ledger/transact/offer_create.rs): offer crossing stub fenced off with explicit unsupported failure
- [x] [`src/ledger/transact/ripple_calc.rs`](src/ledger/transact/ripple_calc.rs): legacy helper now fails explicitly instead of returning fake `tesSUCCESS`, and the live legacy payment path rejects before reaching it
- [x] [`src/ledger/transact/nftoken.rs`](src/ledger/transact/nftoken.rs): metadata-driven mint/burn stubs fenced off explicitly
- [x] [`src/ledger/transact/nftoken_accept.rs`](src/ledger/transact/nftoken_accept.rs): accept/cancel legacy stubs fenced off explicitly
- [x] [`src/ledger/transact/amm.rs`](src/ledger/transact/amm.rs): AMM legacy stubs fenced off explicitly
- [x] [`src/ledger/transact/oracle.rs`](src/ledger/transact/oracle.rs): oracle legacy stubs fenced off explicitly
- [x] [`src/ledger/transact/mptoken.rs`](src/ledger/transact/mptoken.rs): MPToken legacy stubs fenced off explicitly
- [x] [`src/ledger/transact/credential.rs`](src/ledger/transact/credential.rs): credential legacy stubs fenced off explicitly
- [x] [`src/ledger/transact/permissioned_domain.rs`](src/ledger/transact/permissioned_domain.rs): permissioned-domain legacy stubs fenced off explicitly
- [x] [`src/ledger/transact/delegate.rs`](src/ledger/transact/delegate.rs): delegate legacy stub fenced off explicitly
- [x] [`src/ledger/transact/vault.rs`](src/ledger/transact/vault.rs): vault legacy stubs fenced off explicitly
- [x] [`src/ledger/transact/clawback.rs`](src/ledger/transact/clawback.rs): clawback legacy stub fenced off explicitly
- [x] [`src/ledger/transact/nftoken_modify.rs`](src/ledger/transact/nftoken_modify.rs): NFT modify legacy stub fenced off explicitly
- [x] [`src/ledger/transact/xchain.rs`](src/ledger/transact/xchain.rs): stub handler fenced off explicitly
- [x] [`src/ledger/transact/loan.rs`](src/ledger/transact/loan.rs): stub handlers fenced off explicitly
- [x] [`src/ledger/transact/mod.rs`](src/ledger/transact/mod.rs): generic fallback handler now rejects unknown tx types instead of returning success
- [x] [`src/ledger/transact/ledger_state_fix.rs`](src/ledger/transact/ledger_state_fix.rs): legacy handler fenced off explicitly
- [x] [`src/ledger/transact/pseudo.rs`](src/ledger/transact/pseudo.rs): pseudo-transaction handlers fenced off explicitly in the legacy transactor

## Inactive-amendment items

These do not need full same-day implementation if they are amendment-gated and explicitly disabled safely.

- [x] [`src/ledger/tx/batch.rs`](src/ledger/tx/batch.rs): replay-only bridge now fails explicitly outside validated replay
- [x] [`src/ledger/tx/xchain.rs`](src/ledger/tx/xchain.rs): replay-only bridge now fails explicitly outside validated replay
- [x] [`src/ledger/tx/loan.rs`](src/ledger/tx/loan.rs): cover/manage replay bridge now fails explicitly outside validated replay
- [x] [`src/ledger/tx/escrow.rs`](src/ledger/tx/escrow.rs): MPT escrow create / finish / cancel now move holder and issuance locked balances directly instead of relying on metadata patching

## RPC / tooling / polish

- [x] Audit the reachable RPC handlers in [`src/rpc/handlers.rs`](src/rpc/handlers.rs): no live method-level stub section remains, and unsupported surfaces are omitted from dispatch instead of pretending support
- [x] Clean [`src/rpc/types.rs`](src/rpc/types.rs) so the stale unused `notImpl` response path does not linger as a fake readiness signal
- [x] Accept both `ws://` and `wss://` clients on the WebSocket listener in [`src/rpc/ws.rs`](src/rpc/ws.rs) by sniffing TLS handshakes and wrapping only secure sessions

## Placeholder-only / low-risk cleanup

- [x] [`src/consensus/manifest.rs`](src/consensus/manifest.rs): revocation manifests now omit `sfSigningPubKey` instead of using an all-zero placeholder
- [x] [`src/ledger/sle.rs`](src/ledger/sle.rs): test fixture account is now named/commented explicitly instead of as a generic placeholder
- [x] [`src/ledger/transact/ticket_create.rs`](src/ledger/transact/ticket_create.rs): owner-directory page indices now stored in `OwnerNode`
- [x] [`src/ledger/transact/deposit_preauth.rs`](src/ledger/transact/deposit_preauth.rs): owner-directory page indices now stored in `OwnerNode`
- [x] [`src/ledger/transact/escrow.rs`](src/ledger/transact/escrow.rs): owner and destination directory page indices now populated and cleaned up
- [x] [`src/ledger/transact/check.rs`](src/ledger/transact/check.rs): owner and destination directory page indices now populated and cleaned up
- [x] [`src/ledger/transact/paychan.rs`](src/ledger/transact/paychan.rs): owner and destination directory page indices now populated and cleaned up
- [x] [`src/ledger/transact/did.rs`](src/ledger/transact/did.rs): owner-directory page indices now populated and cleaned up
- [x] [`src/ledger/transact/signer_list.rs`](src/ledger/transact/signer_list.rs): owner-directory page index preserved on replace and removed on delete
- [x] [`src/ledger/transact/nftoken.rs`](src/ledger/transact/nftoken.rs): legacy NFT offer creation now stores a real `OwnerNode`

## Notes

- `Node::Stub` references in `src/ledger/shamap.rs` are intentional lazy-load SHAMap nodes, not release gaps.
- Duplicate files with ` 2.rs` suffixes are not the compiled sources and should not be used for release work unless promoted intentionally.
- Validated replay bridges now cover batch / xchain / loan-modify / vault-set / vault-clawback / nftoken-modify / MPT-clawback and unknown future tx types; outside validated replay they fail explicitly instead of silently succeeding.
