//! Peerfinder-style bootcache/livecache and slot-manager support.
//!
//! xledgrs keeps durable peer discovery state together with manager-owned
//! slot lifecycle, redirect handling, endpoint exchange, and autoconnect
//! ordering instead of a blind FIFO of remembered endpoints.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerfinderSlotDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerfinderSlot {
    id: u64,
    remote: SocketAddr,
    local: Option<SocketAddr>,
    direction: PeerfinderSlotDirection,
}

impl PeerfinderSlot {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn remote(&self) -> SocketAddr {
        self.remote
    }

    pub fn local(&self) -> Option<SocketAddr> {
        self.local
    }

    pub fn direction(&self) -> PeerfinderSlotDirection {
        self.direction
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerfinderEntry {
    pub address: SocketAddr,
    pub source: String,
    pub fixed: bool,
    pub last_seen_unix: u64,
    pub last_connected_unix: Option<u64>,
    pub success_count: u32,
    pub failure_count: u32,
    #[serde(default)]
    pub next_attempt_unix: u64,
}

impl PeerfinderEntry {
    fn last_active_unix(&self) -> u64 {
        self.last_connected_unix.unwrap_or(self.last_seen_unix)
    }
}

#[derive(Debug, Clone, Default)]
struct RuntimeEntry {
    discovery_count: u32,
    consecutive_failures: u32,
    last_attempt_unix: Option<u64>,
    slot_open: bool,
    connected: bool,
    redirect_count: u32,
    endpoint_reports: u32,
}

#[derive(Debug, Clone)]
struct SlotState {
    remote: SocketAddr,
    local: Option<SocketAddr>,
    direction: PeerfinderSlotDirection,
    connected: bool,
    activated: bool,
    reserved: bool,
    public_key: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Peerfinder {
    entries: BTreeMap<SocketAddr, PeerfinderEntry>,
    runtime: BTreeMap<SocketAddr, RuntimeEntry>,
    slots: BTreeMap<u64, SlotState>,
    next_slot_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerfinderSnapshot {
    pub total_known: usize,
    pub fixed: usize,
    pub with_successes: usize,
    pub dialable: usize,
    pub backed_off: usize,
    pub retry_ready: usize,
    pub ready: usize,
    pub cooling: usize,
    pub cold: usize,
    pub redirects: usize,
    pub distinct_sources: usize,
    pub inbound_slots: usize,
    pub outbound_slots: usize,
    pub active_slots: usize,
    pub reserved_slots: usize,
    pub top: Vec<PeerfinderEntry>,
}

impl Peerfinder {
    const REDIRECT_BACKOFF_SECS: u64 = 60;

    fn runtime_entry_mut(&mut self, address: SocketAddr) -> &mut RuntimeEntry {
        self.runtime.entry(address).or_default()
    }

    fn next_slot(&mut self) -> u64 {
        self.next_slot_id = self.next_slot_id.saturating_add(1);
        self.next_slot_id
    }

    fn has_slot_for(&self, address: SocketAddr) -> bool {
        self.slots.values().any(|slot| slot.remote == address)
    }

    fn has_live_runtime(&self, address: SocketAddr) -> bool {
        self.runtime
            .get(&address)
            .map(|runtime| runtime.slot_open || runtime.connected)
            .unwrap_or(false)
    }

    fn remove_slots_for_address(&mut self, address: SocketAddr) {
        self.slots.retain(|_, slot| slot.remote != address);
    }

    fn entry_score(&self, entry: &PeerfinderEntry, now_unix: u64, source_count: usize) -> i64 {
        let runtime = self.runtime.get(&entry.address);
        let discovery_count = runtime.map(|entry| entry.discovery_count).unwrap_or(0);
        let consecutive_failures = runtime
            .map(|entry| entry.consecutive_failures)
            .unwrap_or(entry.failure_count);
        const FIVE_MINUTES: u64 = 5 * 60;
        const ONE_HOUR: u64 = 60 * 60;
        const ONE_DAY: u64 = 24 * 60 * 60;
        let recent_success_bonus = match now_unix.saturating_sub(entry.last_active_unix()) {
            age if age <= FIVE_MINUTES => 10_000,
            age if age <= ONE_HOUR => 4_000,
            age if age <= ONE_DAY => 1_000,
            _ => 0,
        };
        let recently_seen_bonus = match now_unix.saturating_sub(entry.last_seen_unix) {
            age if age <= FIVE_MINUTES => 2_000,
            age if age <= ONE_HOUR => 800,
            age if age <= ONE_DAY => 200,
            _ => 0,
        };
        let fixed_bonus = if entry.fixed { 50_000 } else { 0 };
        let success_score = i64::from(entry.success_count.min(32)) * 250;
        let discovery_score = i64::from(discovery_count.min(16)) * 50;
        let source_count = source_count.max(1).min(8) as i64;
        let source_diversity_bonus = (9 - source_count) * 120;
        let failure_penalty =
            i64::from(entry.failure_count.min(64)) * 75 + i64::from(consecutive_failures.min(16)) * 400;
        let redirect_penalty = i64::from(runtime.map(|entry| entry.redirect_count).unwrap_or(0).min(8)) * 200;
        let backoff_penalty = if !entry.fixed && entry.next_attempt_unix > now_unix {
            100_000
        } else {
            0
        };
        fixed_bonus
            + recent_success_bonus
            + recently_seen_bonus
            + success_score
            + discovery_score
            + source_diversity_bonus
            - failure_penalty
            - redirect_penalty
            - backoff_penalty
    }

    fn ranked_entries(
        &self,
        now_unix: u64,
        include_backed_off: bool,
        include_connected: bool,
    ) -> Vec<PeerfinderEntry> {
        let mut entries: Vec<_> = self.entries.values().cloned().collect();
        let mut source_counts = BTreeMap::<String, usize>::new();
        for entry in self.entries.values() {
            *source_counts.entry(entry.source.clone()).or_insert(0) += 1;
        }
        if !include_backed_off {
            entries.retain(|entry| entry.fixed || entry.next_attempt_unix <= now_unix);
        }
        if !include_connected {
            entries.retain(|entry| !self.has_live_slot(entry.address));
        }
        entries.sort_by(|a, b| {
            let a_source_count = source_counts.get(&a.source).copied().unwrap_or(1);
            let b_source_count = source_counts.get(&b.source).copied().unwrap_or(1);
            self.entry_score(b, now_unix, b_source_count)
                .cmp(&self.entry_score(a, now_unix, a_source_count))
                .then_with(|| b.fixed.cmp(&a.fixed))
                .then_with(|| b.success_count.cmp(&a.success_count))
                .then_with(|| a.failure_count.cmp(&b.failure_count))
                .then_with(|| b.last_active_unix().cmp(&a.last_active_unix()))
                .then_with(|| a.address.cmp(&b.address))
        });
        entries
    }

    fn candidate_class(entry: &PeerfinderEntry, now_unix: u64) -> usize {
        if entry.fixed || entry.next_attempt_unix <= now_unix {
            return 0;
        }
        if entry.next_attempt_unix.saturating_sub(now_unix) <= 10 * 60 {
            return 1;
        }
        2
    }

    fn diversify_by_ip(entries: Vec<PeerfinderEntry>) -> Vec<SocketAddr> {
        let mut primary = Vec::with_capacity(entries.len());
        let mut secondary = Vec::new();
        let mut seen_ips = BTreeSet::<IpAddr>::new();
        for entry in entries {
            if seen_ips.insert(entry.address.ip()) {
                primary.push(entry.address);
            } else {
                secondary.push(entry.address);
            }
        }
        primary.extend(secondary);
        primary
    }

    fn autoconnect_entries_at(&self, now_unix: u64) -> Vec<PeerfinderEntry> {
        let mut entries = self.ranked_entries(now_unix, false, true);
        entries.retain(|entry| !self.has_live_slot(entry.address));
        entries
    }

    pub fn note_slot_opened(
        &mut self,
        address: SocketAddr,
        inbound: bool,
        now_unix: u64,
    ) -> PeerfinderSlot {
        let entry = self.entries.entry(address).or_insert(PeerfinderEntry {
            address,
            source: if inbound {
                "inbound_slot".to_string()
            } else {
                "outbound_slot".to_string()
            },
            fixed: false,
            last_seen_unix: now_unix,
            last_connected_unix: None,
            success_count: 0,
            failure_count: 0,
            next_attempt_unix: 0,
        });
        entry.last_seen_unix = entry.last_seen_unix.max(now_unix);
        let slot_id = self.next_slot();
        self.slots.insert(
            slot_id,
            SlotState {
                remote: address,
                local: None,
                direction: if inbound {
                    PeerfinderSlotDirection::Inbound
                } else {
                    PeerfinderSlotDirection::Outbound
                },
                connected: false,
                activated: false,
                reserved: false,
                public_key: None,
            },
        );
        let runtime = self.runtime_entry_mut(address);
        runtime.last_attempt_unix = Some(now_unix);
        runtime.slot_open = true;
        runtime.connected = false;
        PeerfinderSlot {
            id: slot_id,
            remote: address,
            local: None,
            direction: if inbound {
                PeerfinderSlotDirection::Inbound
            } else {
                PeerfinderSlotDirection::Outbound
            },
        }
    }

    pub fn new_inbound_slot(&mut self, remote: SocketAddr, now_unix: u64) -> PeerfinderSlot {
        self.note_slot_opened(remote, true, now_unix)
    }

    pub fn new_outbound_slot(&mut self, remote: SocketAddr, now_unix: u64) -> PeerfinderSlot {
        self.note_slot_opened(remote, false, now_unix)
    }

    pub fn activate(
        &mut self,
        slot: &PeerfinderSlot,
        public_key: Option<String>,
        reserved: bool,
        now_unix: u64,
    ) {
        if let Some(entry) = self.entries.get_mut(&slot.remote) {
            entry.last_seen_unix = entry.last_seen_unix.max(now_unix);
        }
        if let Some(state) = self.slots.get_mut(&slot.id) {
            state.connected = true;
            state.activated = true;
            state.reserved = reserved;
            state.public_key = public_key;
        }
    }

    pub fn on_connected(
        &mut self,
        slot: &mut PeerfinderSlot,
        local: Option<SocketAddr>,
        now_unix: u64,
    ) -> bool {
        slot.local = local;
        if let Some(state) = self.slots.get_mut(&slot.id) {
            state.local = local;
            state.connected = true;
        }
        self.note_connected(slot.remote, now_unix);
        true
    }

    pub fn has_live_slot(&self, address: SocketAddr) -> bool {
        self.has_slot_for(address) || self.has_live_runtime(address)
    }

    pub fn note_endpoints(
        &mut self,
        from: SocketAddr,
        addrs: &[SocketAddr],
        now_unix: u64,
    ) {
        let runtime = self.runtime_entry_mut(from);
        runtime.endpoint_reports = runtime.endpoint_reports.saturating_add(1);
        let source = format!("peer_endpoints:{from}");
        for addr in addrs {
            if *addr == from {
                continue;
            }
            self.note_discovered(*addr, source.clone(), now_unix);
        }
    }

    pub fn on_endpoints(&mut self, slot: &PeerfinderSlot, addrs: &[SocketAddr], now_unix: u64) {
        self.note_endpoints(slot.remote, addrs, now_unix);
    }

    pub fn build_endpoints_for_peer(
        &self,
        peer_addr: SocketAddr,
        now_unix: u64,
        limit: usize,
    ) -> Vec<SocketAddr> {
        let mut addrs =
            Self::diversify_by_ip(self.ranked_entries(now_unix, true, true))
                .into_iter()
                .filter(|addr| *addr != peer_addr)
                .collect::<Vec<_>>();
        if addrs.len() > limit {
            addrs.truncate(limit);
        }
        addrs
    }

    pub fn build_endpoints_for_peers(
        &self,
        now_unix: u64,
        limit: usize,
    ) -> Vec<(PeerfinderSlot, Vec<SocketAddr>)> {
        self.slots
            .iter()
            .filter(|(_, slot)| slot.connected && slot.activated)
            .map(|(id, slot)| {
                (
                    PeerfinderSlot {
                        id: *id,
                        remote: slot.remote,
                        local: slot.local,
                        direction: slot.direction,
                    },
                    self.build_endpoints_for_peer(slot.remote, now_unix, limit),
                )
            })
            .collect()
    }

    pub fn insert_static(&mut self, address: SocketAddr, now_unix: u64) {
        let entry = self.entries.entry(address).or_insert(PeerfinderEntry {
            address,
            source: "static".to_string(),
            fixed: true,
            last_seen_unix: now_unix,
            last_connected_unix: None,
            success_count: 0,
            failure_count: 0,
            next_attempt_unix: 0,
        });
        entry.fixed = true;
        entry.source = "static".to_string();
        entry.last_seen_unix = entry.last_seen_unix.max(now_unix);
        entry.next_attempt_unix = 0;
        let runtime = self.runtime_entry_mut(address);
        runtime.last_attempt_unix = Some(now_unix);
        runtime.consecutive_failures = 0;
        runtime.slot_open = false;
        runtime.connected = false;
    }

    pub fn note_discovered(
        &mut self,
        address: SocketAddr,
        source: impl Into<String>,
        now_unix: u64,
    ) {
        let source = source.into();
        let entry = self.entries.entry(address).or_insert(PeerfinderEntry {
            address,
            source: source.clone(),
            fixed: false,
            last_seen_unix: now_unix,
            last_connected_unix: None,
            success_count: 0,
            failure_count: 0,
            next_attempt_unix: 0,
        });
        if !entry.fixed {
            entry.source = source;
        }
        entry.last_seen_unix = entry.last_seen_unix.max(now_unix);
        let runtime = self.runtime_entry_mut(address);
        runtime.discovery_count = runtime.discovery_count.saturating_add(1);
        runtime.last_attempt_unix = Some(now_unix);
    }

    pub fn note_connected(&mut self, address: SocketAddr, now_unix: u64) {
        let entry = self.entries.entry(address).or_insert(PeerfinderEntry {
            address,
            source: "connected".to_string(),
            fixed: false,
            last_seen_unix: now_unix,
            last_connected_unix: Some(now_unix),
            success_count: 0,
            failure_count: 0,
            next_attempt_unix: 0,
        });
        entry.last_seen_unix = entry.last_seen_unix.max(now_unix);
        entry.last_connected_unix = Some(now_unix);
        entry.success_count = entry.success_count.saturating_add(1);
        entry.next_attempt_unix = 0;
        let runtime = self.runtime_entry_mut(address);
        runtime.last_attempt_unix = Some(now_unix);
        runtime.consecutive_failures = 0;
        runtime.slot_open = true;
        runtime.connected = true;
    }

    pub fn note_disconnected(
        &mut self,
        address: SocketAddr,
        reason: impl Into<String>,
        now_unix: u64,
    ) {
        self.note_failure(address, reason, now_unix);
        if let Some(entry) = self.entries.get_mut(&address) {
            entry.next_attempt_unix = now_unix;
        }
        if let Some(runtime) = self.runtime.get_mut(&address) {
            runtime.slot_open = false;
            runtime.connected = false;
        }
        self.remove_slots_for_address(address);
    }

    pub fn note_closed(&mut self, address: SocketAddr, now_unix: u64) {
        if let Some(entry) = self.entries.get_mut(&address) {
            entry.last_seen_unix = entry.last_seen_unix.max(now_unix);
        }
        self.remove_slots_for_address(address);
        if let Some(runtime) = self.runtime.get_mut(&address) {
            runtime.slot_open = false;
            runtime.connected = false;
            runtime.last_attempt_unix = Some(now_unix);
        }
    }

    pub fn on_closed(&mut self, slot: &PeerfinderSlot, now_unix: u64) {
        self.slots.remove(&slot.id);
        self.note_closed(slot.remote, now_unix);
    }

    pub fn note_redirect(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
        now_unix: u64,
    ) {
        let redirect_source = format!("redirect:{from}");
        if let Some(runtime) = self.runtime.get_mut(&from) {
            runtime.redirect_count = runtime.redirect_count.saturating_add(1);
        }
        self.note_disconnected(from, "redirected", now_unix);
        if let Some(entry) = self.entries.get_mut(&from) {
            if !entry.fixed {
                entry.next_attempt_unix = now_unix.saturating_add(Self::REDIRECT_BACKOFF_SECS);
            }
        }
        self.note_discovered(to, redirect_source, now_unix);
    }

    pub fn note_failure(&mut self, address: SocketAddr, reason: impl Into<String>, now_unix: u64) {
        let reason = reason.into();
        {
            let entry = self.entries.entry(address).or_insert(PeerfinderEntry {
                address,
                source: reason.clone(),
                fixed: false,
                last_seen_unix: now_unix,
                last_connected_unix: None,
                success_count: 0,
                failure_count: 0,
                next_attempt_unix: 0,
            });
            if !entry.fixed {
                entry.source = reason;
            }
            entry.last_seen_unix = entry.last_seen_unix.max(now_unix);
            entry.failure_count = entry.failure_count.saturating_add(1);
        }
        let runtime = self.runtime_entry_mut(address);
        runtime.last_attempt_unix = Some(now_unix);
        runtime.consecutive_failures = runtime.consecutive_failures.saturating_add(1);
        runtime.slot_open = false;
        runtime.connected = false;
        let exponent = runtime.consecutive_failures.saturating_sub(1).min(6);
        let backoff_secs = 20u64.saturating_mul(1u64 << exponent).min(1_800);
        if let Some(entry) = self.entries.get_mut(&address) {
            entry.next_attempt_unix = now_unix.saturating_add(backoff_secs);
        }
        self.remove_slots_for_address(address);
    }

    pub fn on_failure(
        &mut self,
        slot: &PeerfinderSlot,
        reason: impl Into<String>,
        now_unix: u64,
    ) {
        self.slots.remove(&slot.id);
        self.note_failure(slot.remote, reason, now_unix);
    }

    pub fn redirect(
        &self,
        slot: &PeerfinderSlot,
        now_unix: u64,
        limit: usize,
    ) -> Vec<SocketAddr> {
        self.build_endpoints_for_peer(slot.remote, now_unix, limit)
    }

    pub fn ordered_addrs(&self) -> Vec<SocketAddr> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::diversify_by_ip(self.autoconnect_entries_at(now_unix))
    }

    pub fn ordered_addrs_at(&self, now_unix: u64) -> Vec<SocketAddr> {
        Self::diversify_by_ip(self.ranked_entries(now_unix, false, false))
    }

    pub fn autoconnect(&self, now_unix: u64) -> Vec<SocketAddr> {
        Self::diversify_by_ip(self.autoconnect_entries_at(now_unix))
    }

    pub fn prune(&mut self, now_unix: u64) {
        const STALE_ENTRY_SECS: u64 = 7 * 24 * 60 * 60;
        const DEAD_ENTRY_SECS: u64 = 24 * 60 * 60;
        self.entries.retain(|_, entry| {
            if entry.fixed {
                return true;
            }
            let last_activity = entry.last_connected_unix.unwrap_or(entry.last_seen_unix);
            if now_unix.saturating_sub(last_activity) > STALE_ENTRY_SECS {
                return false;
            }
            if entry.failure_count >= 8
                && entry.success_count == 0
                && entry.last_connected_unix.is_none()
                && now_unix.saturating_sub(entry.last_seen_unix) > DEAD_ENTRY_SECS
            {
                return false;
            }
            true
        });
        self.runtime.retain(|address, _| self.entries.contains_key(address));
    }

    pub fn once_per_second(&mut self, now_unix: u64) {
        self.prune(now_unix);
    }

    pub fn persisted_entries(&self) -> Vec<PeerfinderEntry> {
        self.entries.values().cloned().collect()
    }

    pub fn load_persisted(&mut self, entries: Vec<PeerfinderEntry>) {
        self.entries = entries
            .into_iter()
            .map(|entry| (entry.address, entry))
            .collect();
        self.runtime.clear();
    }

    pub fn snapshot(&self, limit: usize) -> PeerfinderSnapshot {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut entries = self.ranked_entries(now_unix, true, true);
        let fixed = entries.iter().filter(|entry| entry.fixed).count();
        let with_successes = entries
            .iter()
            .filter(|entry| entry.success_count > 0 || entry.last_connected_unix.is_some())
            .count();
        let dialable = entries
            .iter()
            .filter(|entry| entry.fixed || entry.next_attempt_unix <= now_unix)
            .count();
        let backed_off = entries.len().saturating_sub(dialable);
        let retry_ready = entries
            .iter()
            .filter(|entry| entry.failure_count > 0 && entry.next_attempt_unix <= now_unix)
            .count();
        let ready = entries
            .iter()
            .filter(|entry| Self::candidate_class(entry, now_unix) == 0)
            .count();
        let cooling = entries
            .iter()
            .filter(|entry| Self::candidate_class(entry, now_unix) == 1)
            .count();
        let cold = entries
            .iter()
            .filter(|entry| Self::candidate_class(entry, now_unix) == 2)
            .count();
        let distinct_sources = entries
            .iter()
            .map(|entry| entry.source.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        let redirects = self
            .runtime
            .values()
            .map(|entry| entry.redirect_count as usize)
            .sum();
        let inbound_slots = self
            .slots
            .values()
            .filter(|slot| slot.direction == PeerfinderSlotDirection::Inbound)
            .count();
        let outbound_slots = self
            .slots
            .values()
            .filter(|slot| slot.direction == PeerfinderSlotDirection::Outbound)
            .count();
        let active_slots = self
            .slots
            .values()
            .filter(|slot| slot.connected && slot.activated)
            .count();
        let reserved_slots = self
            .slots
            .values()
            .filter(|slot| slot.reserved)
            .count();
        entries.truncate(limit);
        PeerfinderSnapshot {
            total_known: self.entries.len(),
            fixed,
            with_successes,
            dialable,
            backed_off,
            retry_ready,
            ready,
            cooling,
            cold,
            redirects,
            distinct_sources,
            inbound_slots,
            outbound_slots,
            active_slots,
            reserved_slots,
            top: entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_and_successful_peers_sort_first() {
        let now = 100;
        let fixed: SocketAddr = "192.0.2.1:51235".parse().unwrap();
        let learned: SocketAddr = "192.0.2.2:51235".parse().unwrap();
        let flaky: SocketAddr = "192.0.2.3:51235".parse().unwrap();

        let mut peerfinder = Peerfinder::default();
        peerfinder.note_discovered(learned, "peer", now);
        peerfinder.note_connected(learned, now + 5);
        peerfinder.insert_static(fixed, now + 10);
        peerfinder.note_failure(flaky, "dial_failed", now + 20);

        let ordered = peerfinder.ordered_addrs();
        assert_eq!(ordered[0], fixed);
        assert_eq!(ordered[1], flaky);
        assert!(!ordered.contains(&learned));
    }

    #[test]
    fn persisted_entries_round_trip() {
        let addr: SocketAddr = "198.51.100.10:51235".parse().unwrap();
        let mut peerfinder = Peerfinder::default();
        peerfinder.note_connected(addr, 42);

        let persisted = peerfinder.persisted_entries();
        let mut loaded = Peerfinder::default();
        loaded.load_persisted(persisted.clone());

        assert_eq!(loaded.persisted_entries(), persisted);
        assert_eq!(loaded.ordered_addrs_at(42), vec![addr]);
        assert_eq!(loaded.ordered_addrs(), vec![addr]);
    }

    #[test]
    fn autoconnect_queue_skips_connected_peers_and_prefers_fixed_candidates() {
        let now = 200;
        let fixed: SocketAddr = "203.0.113.40:51235".parse().unwrap();
        let cooling: SocketAddr = "203.0.113.41:51235".parse().unwrap();
        let connected: SocketAddr = "203.0.113.42:51235".parse().unwrap();

        let mut peerfinder = Peerfinder::default();
        peerfinder.insert_static(fixed, now);
        peerfinder.note_failure(cooling, "dial_failed", now);
        peerfinder.note_connected(connected, now);

        let ordered = peerfinder.ordered_addrs();
        assert_eq!(ordered[0], fixed);
        assert_eq!(ordered[1], cooling);
        assert!(!ordered.contains(&connected));
    }

    #[test]
    fn snapshot_reports_counts_and_top_entries() {
        let mut peerfinder = Peerfinder::default();
        peerfinder.insert_static("192.0.2.10:51235".parse().unwrap(), 10);
        peerfinder.note_connected("192.0.2.11:51235".parse().unwrap(), 20);
        let snapshot = peerfinder.snapshot(8);
        assert_eq!(snapshot.total_known, 2);
        assert_eq!(snapshot.fixed, 1);
        assert_eq!(snapshot.with_successes, 1);
        assert_eq!(snapshot.dialable, 2);
        assert_eq!(snapshot.top.len(), 2);
    }

    #[test]
    fn failures_back_off_until_next_attempt() {
        let addr: SocketAddr = "203.0.113.1:51235".parse().unwrap();
        let mut peerfinder = Peerfinder::default();
        peerfinder.note_failure(addr, "dial_failed", 100);
        assert!(peerfinder.ordered_addrs_at(100).is_empty());
        assert_eq!(peerfinder.ordered_addrs_at(130), vec![addr]);
    }

    #[test]
    fn repeated_failures_extend_the_backoff_window() {
        let addr: SocketAddr = "203.0.113.20:51235".parse().unwrap();
        let mut peerfinder = Peerfinder::default();
        peerfinder.note_failure(addr, "dial_failed", 100);
        let first_retry = peerfinder.persisted_entries()[0].next_attempt_unix;
        peerfinder.note_failure(addr, "dial_failed", 101);
        let second_retry = peerfinder.persisted_entries()[0].next_attempt_unix;
        assert!(second_retry > first_retry);
    }

    #[test]
    fn disconnected_peers_can_reenter_the_dial_queue() {
        let addr: SocketAddr = "203.0.113.21:51235".parse().unwrap();
        let other: SocketAddr = "203.0.113.24:51235".parse().unwrap();
        let mut peerfinder = Peerfinder::default();
        peerfinder.note_connected(addr, 100);
        peerfinder.note_discovered(other, "peer", 100);
        let initial = peerfinder.ordered_addrs_at(100);
        assert_eq!(initial[0], other);
        assert!(!initial.contains(&addr));
        peerfinder.note_disconnected(addr, "socket_closed", 160);
        let ordered = peerfinder.ordered_addrs_at(160);
        assert!(ordered.contains(&addr));
    }

    #[test]
    fn redirects_shift_dial_pressure_to_the_new_peer() {
        let from: SocketAddr = "203.0.113.22:51235".parse().unwrap();
        let to: SocketAddr = "203.0.113.23:51235".parse().unwrap();
        let mut peerfinder = Peerfinder::default();
        peerfinder.note_connected(from, 100);
        peerfinder.note_redirect(from, to, 120);
        let ordered = peerfinder.ordered_addrs_at(120);
        assert_eq!(ordered[0], to);
        assert!(!ordered.contains(&from));
        assert!(peerfinder.ordered_addrs_at(180).contains(&from));
        assert_eq!(peerfinder.snapshot(8).redirects, 1);
    }

    #[test]
    fn snapshot_reports_candidate_depth_by_backoff_window() {
        let mut peerfinder = Peerfinder::default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ready: SocketAddr = "203.0.113.10:51235".parse().unwrap();
        let cooling: SocketAddr = "203.0.113.11:51235".parse().unwrap();
        let cold: SocketAddr = "203.0.113.12:51235".parse().unwrap();

        peerfinder.note_connected(ready, now);
        peerfinder.note_failure(cooling, "dial_failed", now);
        peerfinder.note_failure(cold, "dial_failed", now);
        peerfinder.note_failure(cold, "dial_failed", now + 1);
        peerfinder.note_failure(cold, "dial_failed", now + 2);
        peerfinder.note_failure(cold, "dial_failed", now + 3);
        peerfinder.note_failure(cold, "dial_failed", now + 4);
        peerfinder.note_failure(cold, "dial_failed", now + 5);

        let snapshot = peerfinder.snapshot(8);
        assert_eq!(snapshot.ready, 1);
        assert_eq!(snapshot.cooling, 1);
        assert_eq!(snapshot.cold, 1);
        assert_eq!(snapshot.redirects, 0);
        assert_eq!(snapshot.distinct_sources, 2);
        assert_eq!(snapshot.dialable, 1);
        assert_eq!(snapshot.backed_off, 2);
        assert_eq!(snapshot.retry_ready, 0);
    }

    #[test]
    fn snapshot_reports_retry_ready_after_backoff_elapses() {
        let mut peerfinder = Peerfinder::default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let retry_ready: SocketAddr = "203.0.113.13:51235".parse().unwrap();

        peerfinder.note_failure(retry_ready, "dial_failed", now.saturating_sub(600));

        let snapshot = peerfinder.snapshot(8);
        assert_eq!(snapshot.retry_ready, 1);
        assert_eq!(snapshot.backed_off, 0);
        assert_eq!(snapshot.dialable, 1);
        assert_eq!(snapshot.ready, 1);
    }

    #[test]
    fn ordering_spreads_first_wave_across_unique_ips() {
        let mut peerfinder = Peerfinder::default();
        let a1: SocketAddr = "203.0.113.1:51235".parse().unwrap();
        let a2: SocketAddr = "203.0.113.1:51236".parse().unwrap();
        let b1: SocketAddr = "203.0.113.2:51235".parse().unwrap();

        peerfinder.note_connected(a1, 100);
        peerfinder.note_connected(a2, 99);
        peerfinder.note_connected(b1, 98);
        peerfinder.note_closed(a1, 100);
        peerfinder.note_closed(a2, 100);
        peerfinder.note_closed(b1, 100);

        let ordered = peerfinder.ordered_addrs_at(100);
        assert_eq!(ordered[0], a1);
        assert_eq!(ordered[1], b1);
        assert_eq!(ordered[2], a2);
    }

    #[test]
    fn lower_frequency_sources_rank_ahead_when_other_signals_match() {
        let mut peerfinder = Peerfinder::default();
        let now = 100;
        let common_a: SocketAddr = "203.0.113.30:51235".parse().unwrap();
        let common_b: SocketAddr = "203.0.113.31:51235".parse().unwrap();
        let rare: SocketAddr = "203.0.113.32:51235".parse().unwrap();

        peerfinder.note_connected(common_a, now);
        peerfinder.note_connected(common_b, now);
        peerfinder.note_discovered(rare, "rare-source", now);
        peerfinder.note_connected(rare, now);
        peerfinder.note_discovered(common_a, "common-source", now);
        peerfinder.note_discovered(common_b, "common-source", now);
        peerfinder.note_closed(common_a, now);
        peerfinder.note_closed(common_b, now);
        peerfinder.note_closed(rare, now);

        let ordered = peerfinder.ordered_addrs_at(now);
        assert_eq!(ordered[0], rare);
        assert!(ordered.contains(&common_a));
        assert!(ordered.contains(&common_b));
    }

    #[test]
    fn open_slots_stay_out_of_the_autoconnect_queue_until_closed() {
        let now = 100;
        let addr: SocketAddr = "203.0.113.60:51235".parse().unwrap();
        let mut peerfinder = Peerfinder::default();
        peerfinder.note_discovered(addr, "peer", now);
        peerfinder.note_slot_opened(addr, false, now + 1);

        assert!(!peerfinder.ordered_addrs_at(now + 1).contains(&addr));

        peerfinder.note_closed(addr, now + 2);
        assert!(peerfinder.ordered_addrs_at(now + 2).contains(&addr));
    }

    #[test]
    fn snapshot_reports_slot_counts_after_activation() {
        let now = 100;
        let inbound: SocketAddr = "203.0.113.61:51235".parse().unwrap();
        let outbound: SocketAddr = "203.0.113.62:51235".parse().unwrap();
        let mut peerfinder = Peerfinder::default();

        let mut inbound_slot = peerfinder.note_slot_opened(inbound, true, now);
        peerfinder.activate(&inbound_slot, Some("n9Inbound".to_string()), true, now + 1);
        let _ = peerfinder.on_connected(&mut inbound_slot, None, now + 1);
        let mut outbound_slot = peerfinder.note_slot_opened(outbound, false, now);
        peerfinder.activate(&outbound_slot, Some("n9Outbound".to_string()), false, now + 1);
        let _ = peerfinder.on_connected(&mut outbound_slot, None, now + 1);

        let snapshot = peerfinder.snapshot(8);
        assert_eq!(snapshot.inbound_slots, 1);
        assert_eq!(snapshot.outbound_slots, 1);
        assert_eq!(snapshot.active_slots, 2);
        assert_eq!(snapshot.reserved_slots, 1);
    }

    #[test]
    fn endpoint_reports_discover_peers_with_sender_context() {
        let now = 100;
        let from: SocketAddr = "203.0.113.63:51235".parse().unwrap();
        let to: SocketAddr = "203.0.113.64:51235".parse().unwrap();
        let mut peerfinder = Peerfinder::default();

        let slot = peerfinder.note_slot_opened(from, true, now);
        peerfinder.on_endpoints(&slot, &[from, to], now);

        let persisted = peerfinder.persisted_entries();
        let discovered = persisted.iter().find(|entry| entry.address == to).unwrap();
        assert_eq!(discovered.source, format!("peer_endpoints:{from}"));
        assert!(peerfinder.ordered_addrs_at(now).contains(&to));
    }

    #[test]
    fn build_endpoints_for_peers_returns_slot_bundles() {
        let now = 100;
        let inbound: SocketAddr = "203.0.113.70:51235".parse().unwrap();
        let learned: SocketAddr = "203.0.113.71:51235".parse().unwrap();
        let mut peerfinder = Peerfinder::default();

        peerfinder.note_discovered(learned, "peer", now);
        let mut slot = peerfinder.new_inbound_slot(inbound, now);
        peerfinder.activate(&slot, Some("n9Inbound".to_string()), false, now + 1);
        let _ = peerfinder.on_connected(&mut slot, Some("192.0.2.1:51235".parse().unwrap()), now + 1);

        let bundles = peerfinder.build_endpoints_for_peers(now + 1, 8);
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].0.remote(), inbound);
        assert_eq!(
            bundles[0].0.local(),
            Some("192.0.2.1:51235".parse().unwrap())
        );
        assert!(bundles[0].1.contains(&learned));
    }
}
