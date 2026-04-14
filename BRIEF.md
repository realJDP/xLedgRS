# Security Audit Fix Brief — Remaining Issues

## 1. CRY-01/TXN-02: f64 in OrderBook sorting

**File:** `src/ledger/offer.rs`

**Problem (lines 230-258):** `OrderBook` uses `BTreeMap<(u64, u32), Key>` where the `u64` is `f64::to_bits()` from `quality()` (line 245). The `quality()` method (lines 53-57) computes `pays / gets` as f64 — lossy for IOU mantissa values exceeding 2^53. Two offers with different integer rates can map to the same f64 bit pattern, corrupting sort order or silently replacing entries.

**Existing helper:** `rate_gte()` at line 81 already provides the exact i128 cross-multiplication logic: `a_pays * b_gets >= b_pays * a_gets` with exponent normalization. This is the comparison primitive to reuse.

**Fix — replace the BTreeMap key with a newtype that implements `Ord` via cross-multiplication:**

```rust
/// Integer-exact quality key for BTreeMap ordering.
#[derive(Debug, Clone, Eq, PartialEq)]
struct QualityKey {
    taker_pays: Amount,
    taker_gets: Amount,
    sequence:   u32,
}

impl Ord for QualityKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Lower quality (cheaper for taker) sorts first.
        // rate_gte(self, other) means self >= other.
        if rate_gte(&self.taker_pays, &self.taker_gets,
                    &other.taker_pays, &other.taker_gets) {
            if rate_gte(&other.taker_pays, &other.taker_gets,
                        &self.taker_pays, &self.taker_gets) {
                // Equal quality — break tie by sequence (lower = older = higher priority)
                self.sequence.cmp(&other.sequence)
            } else {
                std::cmp::Ordering::Greater
            }
        } else {
            std::cmp::Ordering::Less
        }
    }
}
impl PartialOrd for QualityKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
```

Then change `OrderBook.offers` to `BTreeMap<QualityKey, Key>`, update `insert()` (line 241) and `remove()` (line 250) to construct `QualityKey` from the offer's `taker_pays`, `taker_gets`, and `sequence`. Remove the `quality()` f64 method or mark it `#[cfg(test)]` only.

**Touch points:**
- `src/ledger/offer.rs` lines 53-57 (`quality()`)
- `src/ledger/offer.rs` lines 230-262 (`OrderBook` struct, `insert`, `remove`, `iter_by_quality`)
- `src/ledger/offer.rs` lines 79-108 (`rate_gte` — reuse as-is)

---

## 2. TXN-03: IOU trust line limits not checked

**File:** `src/ledger/apply.rs`

**Problem (lines 144-164):** `apply_iou_payment` calls `tl.transfer(&tx.account, value)` and immediately writes the trust line back. It never checks whether the resulting balance exceeds the recipient's trust limit.

**File:** `src/ledger/trustline.rs`

**Relevant fields (lines 49-51):** `low_limit: IouValue` and `high_limit: IouValue` represent each side's maximum acceptable balance. `balance_for()` (lines 103-112) gives the signed balance from a given account's perspective.

**rippled behavior:** If `recipient_balance_after > recipient_limit`, reject with `tecPATH_PARTIAL` (or `tecUNFUNDED_PAYMENT` if the sender lacks funds — separate issue).

**Fix — insert a limit check between `transfer` and `insert_trustline` in `apply_iou_payment`:**

```rust
fn apply_iou_payment(
    state: &mut LedgerState, tx: &ParsedTx, dest_id: &[u8; 20],
    value: &IouValue, currency: &Currency, _issuer: &[u8; 20],
) -> ApplyResult {
    let key = trustline::shamap_key(&tx.account, dest_id, currency);
    let mut tl = match state.get_trustline(&key) {
        Some(t) => t.clone(),
        None    => return ApplyResult::ClaimedCost("tecPATH_DRY"),
    };

    tl.transfer(&tx.account, value);

    // ── NEW: Check recipient's trust limit ──
    let recipient_balance = tl.balance_for(dest_id);
    let recipient_limit = if dest_id == &tl.low_account {
        &tl.low_limit
    } else {
        &tl.high_limit
    };
    // Positive balance means recipient holds IOUs — must not exceed their limit.
    if recipient_balance.mantissa > 0 && iou_gt(&recipient_balance, recipient_limit) {
        return ApplyResult::ClaimedCost("tecPATH_PARTIAL");
    }

    state.insert_trustline(tl);
    ApplyResult::Success
}
```

Note: An `iou_gt(a, b) -> bool` helper is needed — align exponents and compare mantissas, or use the same cross-multiply pattern from `rate_gte`. Alternatively, add `impl PartialOrd for IouValue`.

**Touch points:**
- `src/ledger/apply.rs` lines 144-164 (`apply_iou_payment`)
- `src/ledger/trustline.rs` lines 49-51 (`low_limit`, `high_limit`)
- `src/ledger/trustline.rs` lines 98-112 (`balance_for`)
- `src/transaction/amount.rs` — add `IouValue` comparison helper (`iou_gt` or `PartialOrd` impl)

---

## 3. CON-04: Integrate ConsensusRound into close loop

**File:** `src/node.rs`

**Problem (lines 340-453):** `run_ledger_close_loop` broadcasts a proposal (phase 2) then sleeps 3 seconds (line 392) and unconditionally closes the ledger (phase 4). It never creates a `ConsensusRound`, never feeds peer proposals into it, and never calls `try_converge()`. The node closes on its own timer regardless of what peers think.

**File:** `src/consensus/round.rs`

**ConsensusRound API (all ready, no changes needed):**
- `ConsensusRound::new(seq, unl)` — line 94
- `close_ledger(tx_set_hash)` — line 120, transitions Open -> Establish
- `add_proposal(prop)` — line 131, records a UNL peer's proposal
- `try_converge()` — line 155, adopts most popular position if >= threshold
- `accept()` — line 180, declares consensus reached, returns `RoundResult`
- `add_validation(val)` / `check_validated()` — lines 199, 219

**Fix — restructure the loop to use ConsensusRound:**

```rust
// Before phase 2: create round
let unl = self.config.unl.clone(); // Vec<Vec<u8>> of trusted pubkeys
let mut round = ConsensusRound::new(next_seq, unl);
round.close_ledger(tx_set_hash);

// Phase 2: broadcast proposal (already done, keep as-is)

// Phase 3: Establish — poll for convergence instead of blind sleep
let establish_deadline = Instant::now() + Duration::from_secs(10);
loop {
    tokio::time::sleep(Duration::from_millis(250)).await;
    // Drain proposals received from peers (via channel from handle_peer)
    while let Ok(prop) = proposal_rx.try_recv() {
        round.add_proposal(prop);
    }
    if round.try_converge().is_some() || Instant::now() >= establish_deadline {
        break;
    }
}

// Phase 4: Accept — only close if consensus was reached
let result = round.accept();
if let Some(result) = result {
    // Use result.tx_set_hash to pick which tx set to apply
    // ... existing close_ledger logic ...
} else {
    warn!("consensus failed for ledger {next_seq}, skipping round");
    continue;
}

// Phase 5: Validate — after closing, feed validations and check quorum
// ... existing broadcast validation logic ...
while let Ok(val) = validation_rx.try_recv() {
    round.add_validation(val);
}
if let Some(validated_hash) = round.check_validated() {
    info!("ledger {next_seq} fully validated: {}", hex::encode_upper(validated_hash));
}
```

**Additional wiring needed:**
- A `tokio::sync::mpsc` channel to route proposals from `handle_peer` into the close loop.
- A second channel (or the same) for validations.
- The UNL list must be available on `self.config` (or loaded from state).

**Touch points:**
- `src/node.rs` lines 340-453 (`run_ledger_close_loop` — major rework)
- `src/node.rs` peer message handling (wherever proposals/validations arrive — route to channel)
- `src/consensus/round.rs` — API is ready, no changes needed

---

## 4. STO-01/LED-03: Non-atomic storage

**File:** `src/storage.rs`

**Problem (lines 63-107):** `save_state` calls `self.accounts.clear()` (line 65) followed by individual `insert()` calls across 8 trees. If the process crashes between `clear()` and the last `insert()`, state is partially or fully lost. Each tree is cleared and rewritten independently — no atomicity.

**sled API:** `sled::Batch` provides atomic multi-key writes within a single tree. `tree.apply_batch(batch)` is atomic per-tree. There is no cross-tree transaction in sled, but per-tree atomicity eliminates the destructive clear+rewrite window.

**Fix — use `Batch` per tree instead of clear+rewrite:**

```rust
pub fn save_state(&self, state: &crate::ledger::LedgerState) -> Result<()> {
    // For each tree: build a Batch that removes old keys and inserts new ones atomically.
    fn build_batch<K, V, F>(
        tree: &sled::Tree,
        entries: impl Iterator<Item = (K, V)>,
        serialize: F,
    ) -> Result<sled::Batch>
    where
        K: AsRef<[u8]>,
        F: Fn(&V) -> Result<Vec<u8>>,
    {
        let mut batch = sled::Batch::default();
        let mut new_keys: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();

        for (key, val) in entries {
            let k = key.as_ref().to_vec();
            batch.insert(k.as_slice(), serialize(&val)?);
            new_keys.insert(k);
        }
        // Remove keys that exist in the tree but not in the new state
        for entry in tree.iter() {
            let (k, _) = entry?;
            if !new_keys.contains(k.as_ref()) {
                batch.remove(k);
            }
        }
        Ok(batch)
    }

    // Apply one atomic batch per tree
    // accounts tree:
    let batch = build_batch(&self.accounts,
        state.iter_accounts().map(|(id, a)| (id.to_vec(), a)),
        |a| Ok(bincode::serialize(a)?))?;
    self.accounts.apply_batch(batch)?;

    // ... repeat for trustlines, checks, deposit_preauths, escrows,
    //     paychans, tickets, offers (8 trees total) ...

    Ok(())
}
```

**Key difference:** If a crash occurs mid-way, each tree that has already had its `apply_batch` is consistent. Trees not yet batched still have their previous-ledger data (stale but not empty). This is recoverable; the old clear+rewrite approach leaves trees empty on crash.

**Touch points:**
- `src/storage.rs` lines 63-107 (`save_state` — all 8 tree clear+rewrite blocks)

---

## 5. NET-05: Connection rate limiting

**File:** `src/node.rs`

**Problem (lines 458-490):** `run_peer_listener` checks `max_peers` (line 465) but has no per-IP rate limit or global accept throttle. A single IP can spam TCP connections — even if rejected at max_peers, the accept+TLS handshake costs CPU.

**Fix — add a `RateLimiter` struct and check it before TLS handshake:**

```rust
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

struct RateLimiter {
    per_ip: HashMap<IpAddr, (Instant, u32)>,
    global_count: u32,
    global_window_start: Instant,
}

impl RateLimiter {
    const MAX_PER_IP_PER_MIN: u32 = 5;
    const MAX_GLOBAL_PER_SEC: u32 = 20;
    const IP_WINDOW: Duration = Duration::from_secs(60);

    fn new() -> Self {
        Self {
            per_ip: HashMap::new(),
            global_count: 0,
            global_window_start: Instant::now(),
        }
    }

    fn check(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        // Global throttle
        if now.duration_since(self.global_window_start) > Duration::from_secs(1) {
            self.global_count = 0;
            self.global_window_start = now;
        }
        if self.global_count >= Self::MAX_GLOBAL_PER_SEC { return false; }

        // Per-IP throttle
        let entry = self.per_ip.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) > Self::IP_WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= Self::MAX_PER_IP_PER_MIN { return false; }

        self.global_count += 1;
        entry.1 += 1;
        true
    }
}
```

Insert into `run_peer_listener` right after `listener.accept()` (line 463), before the `peer_count` check:

```rust
let mut rate_limiter = RateLimiter::new();

loop {
    let (tcp, addr) = listener.accept().await?;

    if !rate_limiter.check(addr.ip()) {
        warn!("rate-limited connection from {}", addr.ip());
        drop(tcp);
        continue;
    }
    // ... existing max_peers check and TLS handshake ...
}
```

Periodically prune stale entries from `per_ip` to prevent unbounded growth (e.g., every 1000 accepts, retain only entries newer than IP_WINDOW).

**Touch points:**
- `src/node.rs` lines 458-490 (`run_peer_listener`)
- New `RateLimiter` struct — can live at top of `src/node.rs` or in `src/network/rate_limit.rs`

---

## 6. RPC-02: WebSocket connection limit

**File:** `src/rpc/ws.rs`

**Problem (lines 79-105):** `run_ws_server_with_sender` accepts connections in an unbounded loop with no limit on concurrent WebSocket clients. An attacker can open thousands of connections, exhausting memory and file descriptors.

**Fix — add an `AtomicU64` counter, reject when >= 1000:**

```rust
use std::sync::atomic::{AtomicU64, Ordering};

pub async fn run_ws_server_with_sender(
    addr:     SocketAddr,
    state:    Arc<tokio::sync::RwLock<crate::node::SharedState>>,
    event_tx: broadcast::Sender<WsEvent>,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => { warn!("WebSocket bind failed on {addr}: {e}"); return; }
    };
    info!("WebSocket server on {addr}");

    let conn_count = Arc::new(AtomicU64::new(0));
    const MAX_WS_CLIENTS: u64 = 1000;

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => { warn!("WS accept error: {e}"); continue; }
        };

        if conn_count.load(Ordering::Relaxed) >= MAX_WS_CLIENTS {
            warn!("WS connection limit reached ({MAX_WS_CLIENTS}), rejecting {addr}");
            drop(stream);
            continue;
        }

        conn_count.fetch_add(1, Ordering::Relaxed);
        let state = state.clone();
        let event_rx = event_tx.subscribe();
        let counter = conn_count.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_ws_client(stream, state, event_rx).await {
                warn!("WS client {addr} error: {e}");
            }
            counter.fetch_sub(1, Ordering::Relaxed);  // decrement on disconnect
        });
    }
}
```

**Touch points:**
- `src/rpc/ws.rs` lines 79-105 (`run_ws_server_with_sender` — add counter + guard)
- `src/rpc/ws.rs` line 99-103 (the `tokio::spawn` block — add decrement on task exit)

---

## 7. NET-04: Unsafe transmute in MessageType::to_u16

**File:** `src/network/message.rs`

**Problem (lines 85-91):** `to_u16` uses `unsafe { *(&other as *const _ as *const u16) }` to read the enum discriminant as a raw u16. This is undefined behavior — Rust does not guarantee that a pointer cast to `*const u16` on an enum with a `Unknown(u16)` variant reads the discriminant. The `Unknown(u16)` variant contains data that changes the memory layout.

**Current code (line 88):**
```rust
other => unsafe { *(&other as *const _ as *const u16) },
```

**Fix — safe match statement mirroring `from_u16` (lines 53-83):**

```rust
pub fn to_u16(self) -> u16 {
    match self {
        Self::Hello            => 1,
        Self::Ping             => 3,
        Self::Pong             => 4,
        Self::GetPeers         => 5,
        Self::Peers            => 6,
        Self::Transaction      => 30,
        Self::GetLedger        => 31,
        Self::LedgerData       => 32,
        Self::ProposeLedger    => 33,
        Self::StatusChange     => 34,
        Self::HaveSet          => 35,
        Self::Validation       => 41,
        Self::GetObjects       => 42,
        Self::GetShardInfo     => 50,
        Self::ShardInfo        => 51,
        Self::GetPeerShardInfo => 52,
        Self::PeerShardInfo    => 53,
        Self::Manifests        => 54,
        Self::Endpoints        => 15,
        Self::GetSnapshot      => 60,
        Self::SnapshotHeader   => 61,
        Self::SnapshotChunk    => 62,
        Self::SnapshotEnd      => 63,
        Self::GetHistory       => 64,
        Self::HistoryLedger    => 65,
        Self::HistoryEnd       => 66,
        Self::Unknown(n)       => n,
    }
}
```

This is a direct mirror of `from_u16`. LLVM optimizes both to equivalent machine code — zero performance cost. Removes the only `unsafe` block in the network module.

**Touch points:**
- `src/network/message.rs` lines 85-91 (`to_u16` method — replace 7 lines)

---

## Implementation Priority

1. **NET-04 (unsafe transmute)** — 5 min, zero risk, removes UB.
2. **RPC-02 (WS limit)** — 10 min, self-contained, prevents resource exhaustion.
3. **NET-05 (rate limiting)** — 20 min, self-contained, prevents connection spam.
4. **TXN-03 (trust line limits)** — 30 min, needs IouValue comparison helper.
5. **STO-01 (atomic storage)** — 30 min, mechanical Batch conversion.
6. **CRY-01/TXN-02 (OrderBook f64)** — 45 min, needs new QualityKey type + test updates.
7. **CON-04 (consensus integration)** — 2+ hours, requires channel wiring across modules.
