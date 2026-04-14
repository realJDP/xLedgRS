# Sync Acquisition State Machine Redesign Plan

**Date:** 2026-04-10  
**Status:** Frozen at 4.1M/26M leaves, sync dead after 5 target rollovers  
**Frozen artifacts:** `xledgrs-frozen-20260410`, `xledgrs-frozen-20260410.log`, `xledgrs-data-snapshot-20260410.tar.gz`

## Problem Summary

The peer-based state sync downloads ~700K leaves in a 30-60 second burst, then stalls permanently on 16 missing inner nodes. Timer retries broadcast requests but peers stop responding. After 10 retries (30s), it abandons and rolls over to a new target ledger — which stalls the same way. After 4-5 rollovers, the re-acquire itself fails and sync dies entirely.

**Frozen log evidence:**
- 5 sync targets attempted across 21 minutes
- Every target: burst → stall at `missing=16` → 10 retries → abandon
- `missing=16` in 100% of sync ticks (366/366) — always the bounded walk cap
- 40 stall events, 187 NuDB flushes (4000-leaf batches working)
- Final state: 4,134,844 leaves in 2.2GB NuDB, sync permanently dead

## Root Causes (Ordered by Impact)

### 1. No in-flight tracking → can't detect "requests sent, no response"

`sync_coordinator.rs:233`: `in_flight()` returns 0 always. No cookie tracking. No way to distinguish "nothing was sent" from "sent 6 requests, peers ignoring them." rippled tracks outstanding requests and knows when peers are unresponsive.

### 2. Reply trigger only fires on response arrival

`run_sync_data_processor` calls `trigger(Reply)` only after processing a batch. If responses stop coming, Reply stops firing. The only fallback is the 3-second timer, which broadcasts to ALL peers instead of targeting responsive ones. This creates a gap where the node has zero outstanding requests.

### 3. Timer sends to ALL peers instead of routing around bad ones

Timer trigger broadcasts to every peer. If 20 peers are connected but only 3 have the subtree we need, we're wasting 17 requests and the 3 useful peers may rate-limit us because we're also hitting them via Reply trigger.

### 4. `is_pass_complete()` 10s → 3s helped but isn't enough

Reduced from 10s to 3s, but the fundamental problem remains: pass restart re-walks the same tree, finds the same 16 missing nodes, sends them to the same peers that already refused.

### 5. Single-target architecture has no fallback for partially-available trees

When peers prune old state, specific subtrees become unavailable. The only recovery is abandon + re-acquire, which throws away ALL progress and starts a new target that will also become partially unavailable in ~60 seconds.

## Design: rippled-Style Acquisition State Machine

### Core Principle

rippled maintains **continuous outstanding requests** across multiple peers and never allows `in_flight` to drop to 0 during active sync. It tracks per-peer responsiveness and routes around unresponsive peers.

### State Machine

```
IDLE ──(validation arrives)──> ACQUIRING
ACQUIRING ──(liBASE response)──> SYNCING  
SYNCING ──(progress)──> SYNCING (continuous loop)
SYNCING ──(stall 3s)──> RECOVERING
RECOVERING ──(response arrives)──> SYNCING
RECOVERING ──(30s no progress)──> RE_ACQUIRING
RE_ACQUIRING ──(new liBASE)──> SYNCING (fresh target, KEEP existing tree)
SYNCING ──(tree complete + hash match)──> COMPLETE
```

### Key Changes

#### A. Implement real in-flight tracking

```rust
struct InFlightTracker {
    requests: HashMap<u64, InFlightRequest>,  // cookie → request
    next_cookie: u64,
}

struct InFlightRequest {
    peer_id: PeerId,
    node_ids: Vec<SHAMapNodeID>,
    sent_at: Instant,
    timeout: Duration,  // 5 seconds per request
}
```

- Every request gets a unique cookie (not 0)
- Track which peer each request went to
- On response: clear matching cookie, update peer latency stats
- On timeout (5s per request): mark peer as slow, re-send to different peer
- **Key invariant: if `in_flight < MIN_OUTSTANDING` (e.g., 3), immediately inject more requests**

#### B. Per-peer responsiveness scoring

```rust
struct PeerSyncScore {
    useful_nodes: u32,       // total useful nodes received
    total_requests: u32,     // total requests sent
    avg_latency_ms: u32,     // moving average response time
    consecutive_timeouts: u8, // timeouts without useful response
    last_useful: Instant,    // last time this peer sent useful data
}
```

- Peers with `consecutive_timeouts >= 3` are benched (skip for 60s)
- Reply trigger targets top-N responsive peers by latency
- Timeout trigger skips benched peers and tries others
- **Never send same missing nodes to same peer twice in a row** — rotate peers for stuck nodes

#### C. Continuous request injection (never drop to 0)

Current architecture:
```
response arrives → process → trigger(Reply) → send requests → wait for response
                                                                    ↑ gap here
```

New architecture:
```
response arrives → process → trigger(Reply) → send requests
                                                  ↓
timer (3s) ──────────────────────────────> check in_flight
                                               ↓
                                          if < MIN_OUTSTANDING → inject more
                                          if any request > 5s old → timeout + resend to different peer
```

**MIN_OUTSTANDING = 3**: Always maintain at least 3 requests in flight. When a response clears one, immediately send a replacement. Timer is backup, not primary driver.

#### D. Target rollover preserves tree progress

Current: abandon throws away SyncCoordinator and starts fresh.

New: Keep the in-memory SHAMap across target rollovers. The account state tree is 99%+ identical between consecutive ledgers. When rolling to a new target:

1. Keep existing SHAMap (inner nodes + leaves already downloaded)
2. Update `ledger_hash` and `account_hash` to new target
3. Update `sync_target_hash8` gate atomically
4. Re-walk tree to find new missing nodes (most will be the same)
5. Resume from where we left off — not from scratch

This is the single biggest win. Currently each rollover wastes 30-60 seconds of progress.

#### E. Smarter stall recovery

Instead of "retry same nodes to all peers," use escalating strategies:

1. **3s stall**: Re-send stuck nodes to 3 different peers (round-robin, not broadcast)
2. **6s stall**: Use `qtINDIRECT` flag (relay through peers)
3. **9s stall**: Use `GetObjects` fallback (request by hash, not tree position)
4. **15s stall**: Try different subtree walk order (skip stuck branch, come back later)
5. **30s stall**: Roll over target (keep tree)

### Implementation Order

**Phase 1: Stop the bleeding (1-2 hours)**
- [ ] Implement target rollover that preserves SHAMap tree
- [ ] Reduce re-acquire cooldown to match timer interval
- [ ] This alone should let sync complete (slow but steady)

**Phase 2: Per-request tracking (2-3 hours)**
- [ ] Add real cookie tracking to `build_requests_from_missing`
- [ ] Track per-request timeouts (5s)
- [ ] Re-send timed-out requests to different peers
- [ ] Implement `MIN_OUTSTANDING` invariant

**Phase 3: Per-peer scoring (1-2 hours)**
- [ ] Track per-peer latency and usefulness
- [ ] Bench unresponsive peers
- [ ] Route Reply requests to best peers
- [ ] Route stuck-node retries to peers that haven't been tried yet

**Phase 4: Continuous injection (1 hour)**
- [ ] On every response, check if `in_flight < MIN_OUTSTANDING`
- [ ] If yes, immediately build and send more requests (don't wait for timer)
- [ ] Timer becomes backup, not primary driver

## Files to Modify

| File | Changes |
|------|---------|
| `src/sync.rs` | Cookie tracking, per-request timeout, peer scoring in PeerSyncManager |
| `src/sync_coordinator.rs` | Real `in_flight()`, tree preservation across rollover |
| `src/node.rs` | Continuous injection in data processor, smarter timer, target rollover with tree reuse |
| `src/network/relay.rs` | Send real cookies in `encode_get_ledger_state` |

## Success Criteria

1. Sync completes 26M objects without manual intervention
2. No stall lasts longer than 15 seconds
3. Target rollover preserves >95% of downloaded tree
4. `in_flight` never stays at 0 for more than 1 timer tick during active sync
5. Total sync time under 2 hours on current hardware/network
