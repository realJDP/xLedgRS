# Ledger

Ledger code owns XRPL state representation, transaction application views,
SHAMap hashing, sync/follower state, and ledger-entry helpers.

- `account.rs` - AccountRoot helpers and account-level ledger operations.
- `apply_view_impl.rs` - Concrete apply-view implementation used by transaction replay.
- `check.rs` - Check ledger-entry support.
- `close.rs` / `close_v2.rs` - Ledger close helpers and close-loop state transitions.
- `control.rs` - Ledger cleaner and retention control services.
- `deposit_preauth.rs` - DepositPreauth ledger-entry support.
- `did.rs` - DID ledger-entry support.
- `diff_sync.rs` - Difference-based state sync helpers.
- `directory.rs` - Owner/book directory encoding, ordering, and index math.
- `escrow.rs` - Escrow ledger-entry support.
- `fees.rs` - Fee voting and fee-setting support.
- `fetch_pack.rs` - Bundled ledger data used by replay/sync diagnostics.
- `follow.rs` - Follower replay loop after a validated sync handoff.
- `forensic.rs` - Hash-diff and metadata repair diagnostics.
- `full_below_cache.rs` - SHAMap full-below tracking cache.
- `history.rs` - Ledger history retention helpers.
- `inbound.rs` - Inbound ledger acquisition tracking.
- `inbound_transactions.rs` - Inbound transaction queueing and dedupe.
- `invariants.rs` - Ledger invariant checks run during transaction application.
- `keylet.rs` - XRPL keylet/index construction for ledger objects.
- `ledger_core.rs` - Core ledger header and hash structures.
- `master.rs` - Ledger master state shared by node services.
- `meta.rs` - Transaction metadata encoding and node effects.
- `mod.rs` - Ledger module exports.
- `nft_page.rs` / `nftoken.rs` - NFT page and NFToken ledger support.
- `node_store.rs` - NuDB/node-store object access and statistics integration.
- `offer.rs` - Offer ledger-entry support.
- `open_ledger.rs` / `open_view.rs` - Open-ledger state and view handling.
- `paychan.rs` - PaymentChannel ledger-entry support.
- `pool.rs` - Ledger object pool helpers.
- `prune.rs` - Online-delete/pruning support.
- `rules.rs` - Amendment/ruleset helpers.
- `sfield_meta.rs` - Serialized field metadata used by ledger/transaction codecs.
- `shamap*.rs` / `sparse_shamap.rs` - SHAMap node IDs, hashing, sparse construction, and sync support.
- `sle.rs` - Serialized ledger entry representation.
- `state_table.rs` - Batched state mutations for apply/replay.
- `ter.rs` - Transaction engine result codes.
- `ticket.rs` - Ticket ledger-entry support.
- `transactor.rs` - Shared transaction application scaffolding.
- `tree_cache.rs` - State-tree cache helpers.
- `trustline.rs` - RippleState/trustline ledger-entry support.
- `views.rs` - Read/write ledger view traits.
