//! Resource/load tracking for peer addresses and long-lived consumers.
//!
//! xledgrs keeps a rippled-shaped manager that owns decaying penalties,
//! temporary blocks, consumer gossip, and runtime consumer identities instead
//! of rebuilding peer identity ad hoc at each call site.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const WARNING_THRESHOLD: i64 = 5_000;
const DISCONNECT_THRESHOLD: i64 = 25_000;
const MINIMUM_GOSSIP_BALANCE: i64 = 1_000;
const ENTRY_EXPIRATION: Duration = Duration::from_secs(300);
const DECAY_WINDOW_SECS: f64 = 32.0;
const DISCONNECT_BLOCK_MIN: Duration = Duration::from_secs(30);
const DISCONNECT_BLOCK_MAX: Duration = Duration::from_secs(600);
const BLOCK_LOG_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceDisposition {
    Ok,
    Warn,
    Disconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceConsumerKind {
    Inbound,
    Outbound,
    Unlimited,
    PeerIdentified,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ResourceKey {
    Ip(IpAddr),
    Peer(String),
}

impl ResourceKey {
    fn display(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Peer(public_key) => format!("node:{public_key}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResourceConsumer {
    endpoint_ip: IpAddr,
    peer_public_key: Option<String>,
    kind: ResourceConsumerKind,
}

impl ResourceConsumer {
    fn key(&self) -> ResourceKey {
        self.peer_public_key
            .as_ref()
            .map(|public_key| ResourceKey::Peer(public_key.clone()))
            .unwrap_or(ResourceKey::Ip(self.endpoint_ip))
    }

    pub fn kind(&self) -> ResourceConsumerKind {
        self.kind
    }

    pub fn is_unlimited(&self) -> bool {
        matches!(self.kind, ResourceConsumerKind::Unlimited)
    }

    pub fn address(&self) -> String {
        self.key().display()
    }
}

#[derive(Debug, Clone)]
struct ResourceEntry {
    local_balance: i64,
    remote_balance: i64,
    warnings: u32,
    disconnects: u32,
    last_reason: String,
    last_update: Instant,
    last_warning: Option<Instant>,
    last_block_log: Option<Instant>,
    blocked_until: Option<Instant>,
}

impl ResourceEntry {
    fn new(now: Instant) -> Self {
        Self {
            local_balance: 0,
            remote_balance: 0,
            warnings: 0,
            disconnects: 0,
            last_reason: String::new(),
            last_update: now,
            last_warning: None,
            last_block_log: None,
            blocked_until: None,
        }
    }

    fn decay_value(value: i64, elapsed: Duration) -> i64 {
        if value <= 0 {
            return 0;
        }
        let factor = 0.5f64.powf(elapsed.as_secs_f64() / DECAY_WINDOW_SECS);
        ((value as f64) * factor).round() as i64
    }

    fn decay_to(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_update);
        if !elapsed.is_zero() {
            self.local_balance = Self::decay_value(self.local_balance, elapsed);
        }
        self.last_update = now;
        if self.blocked_until.is_some_and(|until| until <= now) {
            self.blocked_until = None;
        }
    }

    fn balance_at(&self, now: Instant) -> i64 {
        let elapsed = now.saturating_duration_since(self.last_update);
        Self::decay_value(self.local_balance, elapsed).saturating_add(self.remote_balance)
    }

    fn is_blocked_at(&self, now: Instant) -> bool {
        self.blocked_until.is_some_and(|until| until > now)
    }
}

pub struct ResourceManager {
    entries: HashMap<ResourceKey, ResourceEntry>,
    imports: HashMap<String, HashMap<ResourceKey, i64>>,
    activity_cycles: u64,
    last_activity_unix: Option<u64>,
}

impl Default for ResourceManager {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            imports: HashMap::new(),
            activity_cycles: 0,
            last_activity_unix: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResourceEntrySummary {
    pub address: String,
    pub balance: i64,
    pub warnings: u32,
    pub disconnects: u32,
    pub last_reason: String,
    pub blocked_until_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceConsumerState {
    pub ip: Option<IpAddr>,
    pub peer: Option<String>,
    pub balance: i64,
    pub warnings: u32,
    pub disconnects: u32,
    pub last_reason: String,
    pub blocked_until_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceBlockStatus {
    pub remaining_ms: u64,
    pub last_reason: String,
    pub should_log: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceSnapshot {
    pub tracked: usize,
    pub tracked_ips: usize,
    pub tracked_peers: usize,
    pub blocked: usize,
    pub warned: usize,
    pub ip_balance: i64,
    pub peer_balance: i64,
    pub total_warnings: u64,
    pub total_disconnects: u64,
    pub total_balance: i64,
    pub activity_cycles: u64,
    pub last_activity_unix: Option<u64>,
    pub entries: Vec<ResourceEntrySummary>,
}

impl ResourceManager {
    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn import_key(consumer: &ResourceConsumerState) -> Option<ResourceKey> {
        consumer
            .peer
            .as_ref()
            .map(|peer| ResourceKey::Peer(peer.clone()))
            .or_else(|| consumer.ip.map(ResourceKey::Ip))
    }

    fn forwarded_ip(forwarded_for: Option<&str>) -> Option<IpAddr> {
        forwarded_for.and_then(|forwarded_for| forwarded_for.parse().ok())
    }

    fn refresh_import_state(entry: &mut ResourceEntry, now: Instant) {
        let balance = entry.local_balance.saturating_add(entry.remote_balance);
        if balance >= DISCONNECT_THRESHOLD {
            let overage = balance.saturating_sub(DISCONNECT_THRESHOLD) as u64;
            let extra_secs = (overage / 1_000).saturating_mul(10);
            let block_for =
                (DISCONNECT_BLOCK_MIN + Duration::from_secs(extra_secs)).min(DISCONNECT_BLOCK_MAX);
            entry.blocked_until = Some(entry.blocked_until.unwrap_or(now).max(now + block_for));
        }
    }

    pub fn new_inbound_endpoint(
        &self,
        addr: SocketAddr,
        proxy: bool,
        forwarded_for: Option<&str>,
    ) -> ResourceConsumer {
        let endpoint_ip = if proxy {
            Self::forwarded_ip(forwarded_for).unwrap_or(addr.ip())
        } else {
            addr.ip()
        };
        ResourceConsumer {
            endpoint_ip,
            peer_public_key: None,
            kind: ResourceConsumerKind::Inbound,
        }
    }

    pub fn new_outbound_endpoint(&self, addr: SocketAddr) -> ResourceConsumer {
        ResourceConsumer {
            endpoint_ip: addr.ip(),
            peer_public_key: None,
            kind: ResourceConsumerKind::Outbound,
        }
    }

    pub fn new_unlimited_endpoint(&self, addr: SocketAddr) -> ResourceConsumer {
        ResourceConsumer {
            endpoint_ip: addr.ip(),
            peer_public_key: None,
            kind: ResourceConsumerKind::Unlimited,
        }
    }

    pub fn new_peer_consumer(
        &self,
        addr: SocketAddr,
        public_key: Option<&str>,
    ) -> ResourceConsumer {
        ResourceConsumer {
            endpoint_ip: addr.ip(),
            peer_public_key: public_key.map(str::to_string),
            kind: if public_key.is_some() {
                ResourceConsumerKind::PeerIdentified
            } else {
                ResourceConsumerKind::Inbound
            },
        }
    }

    fn max_instant(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
        match (a, b) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    fn merge_local_pressure(target: &mut ResourceEntry, source: &ResourceEntry) {
        target.local_balance = target.local_balance.saturating_add(source.local_balance);
        target.warnings = target.warnings.saturating_add(source.warnings);
        target.disconnects = target.disconnects.saturating_add(source.disconnects);
        if !source.last_reason.is_empty() {
            target.last_reason = source.last_reason.clone();
        }
        target.last_warning = Self::max_instant(target.last_warning, source.last_warning);
        target.last_block_log = Self::max_instant(target.last_block_log, source.last_block_log);
        target.blocked_until = Self::max_instant(target.blocked_until, source.blocked_until);
    }

    fn migrate_local_pressure(&mut self, old_key: ResourceKey, new_key: ResourceKey, now: Instant) {
        if old_key == new_key {
            return;
        }
        let Some(mut old_entry) = self.entries.remove(&old_key) else {
            return;
        };
        old_entry.decay_to(now);
        let migrated = ResourceEntry {
            local_balance: old_entry.local_balance,
            remote_balance: 0,
            warnings: old_entry.warnings,
            disconnects: old_entry.disconnects,
            last_reason: old_entry.last_reason.clone(),
            last_update: now,
            last_warning: old_entry.last_warning,
            last_block_log: old_entry.last_block_log,
            blocked_until: old_entry.blocked_until,
        };

        old_entry.local_balance = 0;
        old_entry.warnings = 0;
        old_entry.disconnects = 0;
        old_entry.last_reason.clear();
        old_entry.last_warning = None;
        old_entry.last_block_log = None;
        old_entry.blocked_until = None;

        if old_entry.remote_balance >= MINIMUM_GOSSIP_BALANCE {
            self.entries.insert(old_key, old_entry);
        }

        let target = self
            .entries
            .entry(new_key)
            .or_insert_with(|| ResourceEntry::new(now));
        target.decay_to(now);
        Self::merge_local_pressure(target, &migrated);
    }

    pub fn set_consumer_public_key(
        &mut self,
        consumer: &mut ResourceConsumer,
        public_key: impl Into<String>,
        now: Instant,
    ) {
        if consumer.is_unlimited() {
            return;
        }
        let public_key = public_key.into();
        if consumer.peer_public_key.as_deref() == Some(public_key.as_str()) {
            consumer.kind = ResourceConsumerKind::PeerIdentified;
            return;
        }
        let old_key = consumer.key();
        consumer.peer_public_key = Some(public_key);
        consumer.kind = ResourceConsumerKind::PeerIdentified;
        let new_key = consumer.key();
        self.migrate_local_pressure(old_key, new_key, now);
    }

    pub fn charge_consumer(
        &mut self,
        consumer: &ResourceConsumer,
        units: i64,
        reason: impl Into<String>,
        now: Instant,
    ) -> ResourceDisposition {
        if consumer.is_unlimited() {
            return ResourceDisposition::Ok;
        }
        self.charge_key(consumer.key(), units, reason, now)
    }

    pub fn periodic_activity(&mut self, now: Instant) {
        self.activity_cycles = self.activity_cycles.saturating_add(1);
        self.last_activity_unix = Some(Self::unix_now());
        self.prune_expired(now);
    }

    pub fn charge_addr(
        &mut self,
        addr: SocketAddr,
        units: i64,
        reason: impl Into<String>,
        now: Instant,
    ) -> ResourceDisposition {
        let consumer = self.new_inbound_endpoint(addr, false, None);
        self.charge_consumer(&consumer, units, reason, now)
    }

    pub fn charge_peer(
        &mut self,
        addr: SocketAddr,
        public_key: Option<&str>,
        units: i64,
        reason: impl Into<String>,
        now: Instant,
    ) -> ResourceDisposition {
        let consumer = self.new_peer_consumer(addr, public_key);
        self.charge_consumer(&consumer, units, reason, now)
    }

    pub fn charge_inbound_endpoint(
        &mut self,
        addr: SocketAddr,
        proxy: bool,
        forwarded_for: Option<&str>,
        units: i64,
        reason: impl Into<String>,
        now: Instant,
    ) -> ResourceDisposition {
        let consumer = self.new_inbound_endpoint(addr, proxy, forwarded_for);
        self.charge_consumer(&consumer, units, reason, now)
    }

    pub fn charge_ip(
        &mut self,
        ip: IpAddr,
        units: i64,
        reason: impl Into<String>,
        now: Instant,
    ) -> ResourceDisposition {
        let consumer = ResourceConsumer {
            endpoint_ip: ip,
            peer_public_key: None,
            kind: ResourceConsumerKind::Inbound,
        };
        self.charge_consumer(&consumer, units, reason, now)
    }

    fn charge_key(
        &mut self,
        key: ResourceKey,
        units: i64,
        reason: impl Into<String>,
        now: Instant,
    ) -> ResourceDisposition {
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| ResourceEntry::new(now));
        entry.decay_to(now);
        entry.local_balance = entry.local_balance.saturating_add(units.max(0));
        entry.last_reason = reason.into();
        let balance = entry.local_balance.saturating_add(entry.remote_balance);

        if balance >= DISCONNECT_THRESHOLD {
            entry.disconnects = entry.disconnects.saturating_add(1);
            let overage = balance.saturating_sub(DISCONNECT_THRESHOLD) as u64;
            let extra_secs = (overage / 1_000).saturating_mul(10);
            let block_for =
                (DISCONNECT_BLOCK_MIN + Duration::from_secs(extra_secs)).min(DISCONNECT_BLOCK_MAX);
            entry.blocked_until = Some(entry.blocked_until.unwrap_or(now).max(now + block_for));
            ResourceDisposition::Disconnect
        } else if balance >= WARNING_THRESHOLD {
            let should_count = entry
                .last_warning
                .map(|last| now.saturating_duration_since(last) >= Duration::from_secs(1))
                .unwrap_or(true);
            if should_count {
                entry.warnings = entry.warnings.saturating_add(1);
                entry.last_warning = Some(now);
            }
            ResourceDisposition::Warn
        } else {
            ResourceDisposition::Ok
        }
    }

    pub fn is_blocked(&mut self, addr: SocketAddr, now: Instant) -> bool {
        if let Some(entry) = self.entries.get_mut(&ResourceKey::Ip(addr.ip())) {
            entry.decay_to(now);
            entry.blocked_until.is_some_and(|until| until > now)
        } else {
            false
        }
    }

    pub fn is_blocked_peer(
        &mut self,
        addr: SocketAddr,
        public_key: Option<&str>,
        now: Instant,
    ) -> bool {
        if let Some(public_key) = public_key {
            if let Some(entry) = self
                .entries
                .get_mut(&ResourceKey::Peer(public_key.to_string()))
            {
                entry.decay_to(now);
                return entry.blocked_until.is_some_and(|until| until > now);
            }
        }
        self.is_blocked(addr, now)
    }

    fn blocked_status(
        entry: &mut ResourceEntry,
        now: Instant,
        mark_log: bool,
    ) -> Option<ResourceBlockStatus> {
        entry.decay_to(now);
        let until = entry.blocked_until?;
        if until <= now {
            return None;
        }
        let should_log = entry
            .last_block_log
            .map(|last| now.saturating_duration_since(last) >= BLOCK_LOG_INTERVAL)
            .unwrap_or(true);
        if mark_log && should_log {
            entry.last_block_log = Some(now);
        }
        Some(ResourceBlockStatus {
            remaining_ms: until.saturating_duration_since(now).as_millis() as u64,
            last_reason: entry.last_reason.clone(),
            should_log,
        })
    }

    pub fn blocked_status_for_logging(
        &mut self,
        addr: SocketAddr,
        now: Instant,
    ) -> Option<ResourceBlockStatus> {
        let entry = self.entries.get_mut(&ResourceKey::Ip(addr.ip()))?;
        Self::blocked_status(entry, now, true)
    }

    pub fn blocked_peer_status_for_logging(
        &mut self,
        addr: SocketAddr,
        public_key: Option<&str>,
        now: Instant,
    ) -> Option<ResourceBlockStatus> {
        if let Some(public_key) = public_key {
            if let Some(entry) = self
                .entries
                .get_mut(&ResourceKey::Peer(public_key.to_string()))
            {
                return Self::blocked_status(entry, now, true);
            }
        }
        self.blocked_status_for_logging(addr, now)
    }

    pub fn prune_expired(&mut self, now: Instant) {
        self.entries.retain(|_, entry| {
            let idle = now.saturating_duration_since(entry.last_update);
            entry.decay_to(now);
            entry.local_balance.saturating_add(entry.remote_balance) >= MINIMUM_GOSSIP_BALANCE
                || entry.is_blocked_at(now)
                || idle < ENTRY_EXPIRATION
        });
    }

    pub fn blacklist_entries(&self, now: Instant) -> Vec<crate::rpc::BlacklistEntry> {
        let mut out = Vec::new();
        for (key, entry) in &self.entries {
            if let Some(until) = entry.blocked_until {
                if until > now {
                    let reason = format!("resource_drop:{}", entry.last_reason);
                    out.push(crate::rpc::BlacklistEntry {
                        address: key.display(),
                        reason,
                        expires_in_ms: until.saturating_duration_since(now).as_millis() as u64,
                    });
                }
            }
        }
        out.sort_by(|a, b| a.address.cmp(&b.address).then(a.reason.cmp(&b.reason)));
        out
    }

    pub fn snapshot(&self, now: Instant, limit: usize) -> ResourceSnapshot {
        let tracked_ips = self
            .entries
            .keys()
            .filter(|key| matches!(key, ResourceKey::Ip(_)))
            .count();
        let tracked_peers = self
            .entries
            .keys()
            .filter(|key| matches!(key, ResourceKey::Peer(_)))
            .count();
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .map(|(key, entry)| ResourceEntrySummary {
                address: key.display(),
                balance: entry.balance_at(now),
                warnings: entry.warnings,
                disconnects: entry.disconnects,
                last_reason: entry.last_reason.clone(),
                blocked_until_ms: entry
                    .blocked_until
                    .filter(|until| *until > now)
                    .map(|until| until.saturating_duration_since(now).as_millis() as u64),
            })
            .collect();
        entries.sort_by(|a, b| {
            b.blocked_until_ms
                .cmp(&a.blocked_until_ms)
                .then_with(|| b.balance.cmp(&a.balance))
                .then_with(|| a.address.cmp(&b.address))
        });
        let blocked = entries
            .iter()
            .filter(|entry| entry.blocked_until_ms.is_some())
            .count();
        let warned = entries
            .iter()
            .filter(|entry| entry.balance >= WARNING_THRESHOLD && entry.blocked_until_ms.is_none())
            .count();
        let ip_balance = self
            .entries
            .iter()
            .filter(|(key, _)| matches!(key, ResourceKey::Ip(_)))
            .map(|(_, entry)| entry.balance_at(now))
            .sum();
        let peer_balance = self
            .entries
            .iter()
            .filter(|(key, _)| matches!(key, ResourceKey::Peer(_)))
            .map(|(_, entry)| entry.balance_at(now))
            .sum();
        let total_warnings = self
            .entries
            .values()
            .map(|entry| u64::from(entry.warnings))
            .sum();
        let total_disconnects = self
            .entries
            .values()
            .map(|entry| u64::from(entry.disconnects))
            .sum();
        let total_balance = entries.iter().map(|entry| entry.balance).sum();
        entries.truncate(limit);
        ResourceSnapshot {
            tracked: self.entries.len(),
            tracked_ips,
            tracked_peers,
            blocked,
            warned,
            ip_balance,
            peer_balance,
            total_warnings,
            total_disconnects,
            total_balance,
            activity_cycles: self.activity_cycles,
            last_activity_unix: self.last_activity_unix,
            entries,
        }
    }

    pub fn export_consumers(&self, now: Instant, limit: usize) -> Vec<ResourceConsumerState> {
        let mut consumers: Vec<_> =
            self.entries
                .iter()
                .filter(|(key, _)| matches!(key, ResourceKey::Ip(_)))
                .filter_map(|(key, entry)| {
                    let balance = entry.balance_at(now);
                    if balance < MINIMUM_GOSSIP_BALANCE {
                        return None;
                    }
                    Some(match key {
                        ResourceKey::Ip(ip) => ResourceConsumerState {
                            ip: Some(*ip),
                            peer: None,
                            balance,
                            warnings: entry.warnings,
                            disconnects: entry.disconnects,
                            last_reason: entry.last_reason.clone(),
                            blocked_until_ms: entry.blocked_until.filter(|until| *until > now).map(
                                |until| until.saturating_duration_since(now).as_millis() as u64,
                            ),
                        },
                        ResourceKey::Peer(peer) => ResourceConsumerState {
                            ip: None,
                            peer: Some(peer.clone()),
                            balance,
                            warnings: entry.warnings,
                            disconnects: entry.disconnects,
                            last_reason: entry.last_reason.clone(),
                            blocked_until_ms: entry.blocked_until.filter(|until| *until > now).map(
                                |until| until.saturating_duration_since(now).as_millis() as u64,
                            ),
                        },
                    })
                })
                .collect();
        consumers.sort_by(|a, b| {
            b.blocked_until_ms
                .cmp(&a.blocked_until_ms)
                .then_with(|| b.balance.cmp(&a.balance))
                .then_with(|| a.peer.cmp(&b.peer))
                .then_with(|| a.ip.cmp(&b.ip))
        });
        consumers.truncate(limit);
        consumers
    }

    pub fn import_consumers(
        &mut self,
        origin: impl Into<String>,
        consumers: Vec<ResourceConsumerState>,
        now: Instant,
    ) {
        let origin = origin.into();
        let consumers: Vec<_> = consumers.into_iter().collect();
        let mut affected = HashSet::new();
        if let Some(previous) = self.imports.remove(&origin) {
            affected.extend(previous.into_keys());
        }

        let mut next = HashMap::new();
        for consumer in &consumers {
            let Some(key) = Self::import_key(consumer) else {
                continue;
            };
            affected.insert(key.clone());
            next.insert(key, consumer.balance.max(0));
        }

        self.imports.insert(origin, next);

        for key in affected {
            let remote_balance = self
                .imports
                .values()
                .filter_map(|import| import.get(&key))
                .copied()
                .sum::<i64>();
            let entry = self
                .entries
                .entry(key)
                .or_insert_with(|| ResourceEntry::new(now));
            entry.decay_to(now);
            entry.remote_balance = remote_balance;
            Self::refresh_import_state(entry, now);
        }

        for consumer in &consumers {
            let Some(key) = Self::import_key(consumer) else {
                continue;
            };
            let entry = self
                .entries
                .entry(key)
                .or_insert_with(|| ResourceEntry::new(now));
            entry.decay_to(now);
            entry.warnings = consumer.warnings;
            entry.disconnects = consumer.disconnects;
            entry.last_reason = consumer.last_reason.clone();
            entry.last_warning = None;
            entry.last_block_log = None;
            entry.blocked_until = consumer
                .blocked_until_ms
                .map(|ms| now + Duration::from_millis(ms))
                .filter(|until| *until > now);
            Self::refresh_import_state(entry, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_charge_blocks_temporarily() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let addr: SocketAddr = "192.0.2.10:51235".parse().unwrap();
        let disposition = manager.charge_addr(addr, WARNING_THRESHOLD, "warning", now);
        assert_eq!(disposition, ResourceDisposition::Warn);
        assert!(!manager.is_blocked(addr, now));
        assert!(manager.blacklist_entries(now).is_empty());
    }

    #[test]
    fn disconnect_charge_lasts_longer_and_decays() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let later = now + DISCONNECT_BLOCK_MAX + Duration::from_secs(1);
        let addr: SocketAddr = "198.51.100.7:51235".parse().unwrap();
        let disposition = manager.charge_addr(addr, DISCONNECT_THRESHOLD, "drop", now);
        assert_eq!(disposition, ResourceDisposition::Disconnect);
        assert!(manager.is_blocked(addr, now));
        manager.prune_expired(later);
        assert!(!manager.is_blocked(addr, later));
    }

    #[test]
    fn snapshot_reports_blocked_entries() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let addr: SocketAddr = "203.0.113.5:51235".parse().unwrap();
        let _ = manager.charge_addr(addr, DISCONNECT_THRESHOLD, "drop", now);
        let snapshot = manager.snapshot(now, 8);
        assert_eq!(snapshot.tracked, 1);
        assert_eq!(snapshot.tracked_ips, 1);
        assert_eq!(snapshot.tracked_peers, 0);
        assert_eq!(snapshot.blocked, 1);
        assert_eq!(snapshot.total_disconnects, 1);
        assert!(snapshot.ip_balance > 0);
        assert_eq!(snapshot.peer_balance, 0);
        assert_eq!(snapshot.entries[0].address, "203.0.113.5");
        assert!(snapshot.entries[0].blocked_until_ms.is_some());
    }

    #[test]
    fn peer_key_charges_do_not_poison_shared_ip_bucket() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let addr: SocketAddr = "198.51.100.7:51235".parse().unwrap();
        let disposition = manager.charge_peer(
            addr,
            Some("n9ExamplePeer"),
            DISCONNECT_THRESHOLD,
            "drop",
            now,
        );
        assert_eq!(disposition, ResourceDisposition::Disconnect);
        assert!(manager.is_blocked_peer(addr, Some("n9ExamplePeer"), now));
        assert!(!manager.is_blocked_peer(addr, Some("n9OtherPeer"), now));
        assert!(!manager.is_blocked(addr, now));
        let snapshot = manager.snapshot(now, 8);
        assert_eq!(snapshot.tracked_peers, 1);
        assert!(snapshot.peer_balance >= DISCONNECT_THRESHOLD);
    }

    #[test]
    fn setting_consumer_public_key_moves_local_pressure_to_peer_identity() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let addr: SocketAddr = "198.51.100.17:51235".parse().unwrap();
        let mut consumer = manager.new_inbound_endpoint(addr, false, None);

        let disposition = manager.charge_consumer(&consumer, DISCONNECT_THRESHOLD, "drop", now);
        assert_eq!(disposition, ResourceDisposition::Disconnect);
        assert!(manager.is_blocked(addr, now));

        manager.set_consumer_public_key(&mut consumer, "n9ExamplePeer", later);

        assert_eq!(consumer.kind(), ResourceConsumerKind::PeerIdentified);
        assert_eq!(consumer.address(), "node:n9ExamplePeer");
        assert!(!manager.is_blocked(addr, later));
        assert!(manager.is_blocked_peer(addr, Some("n9ExamplePeer"), later));
        let snapshot = manager.snapshot(later, 8);
        assert_eq!(snapshot.tracked_ips, 0);
        assert_eq!(snapshot.tracked_peers, 1);
        assert!(snapshot.peer_balance > 0);
        assert!(snapshot.entries[0].blocked_until_ms.is_some());
    }

    #[test]
    fn balance_decays_even_when_entry_is_kept_for_snapshotting() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let later = now + Duration::from_secs(64);
        let addr: SocketAddr = "192.0.2.44:51235".parse().unwrap();
        let _ = manager.charge_addr(addr, WARNING_THRESHOLD, "warning", now);
        let snapshot = manager.snapshot(later, 8);
        assert_eq!(snapshot.tracked, 1);
        assert_eq!(snapshot.total_warnings, 1);
        assert!(snapshot.entries[0].balance < WARNING_THRESHOLD);
        assert_eq!(snapshot.total_balance, snapshot.entries[0].balance);
    }

    #[test]
    fn consumer_state_export_round_trips_ip_gossip_and_keeps_peer_state_local() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let ip: SocketAddr = "192.0.2.60:51235".parse().unwrap();
        let peer: SocketAddr = "192.0.2.61:51235".parse().unwrap();
        let _ = manager.charge_addr(ip, WARNING_THRESHOLD, "warn-ip", now);
        let _ = manager.charge_peer(peer, Some("n9Peer"), DISCONNECT_THRESHOLD, "drop-peer", now);

        let exported = manager.export_consumers(now, 8);
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].ip, Some(ip.ip()));
        assert_eq!(exported[0].peer, None);

        let mut imported = ResourceManager::default();
        imported.import_consumers("origin-a", exported.clone(), now);

        assert_eq!(imported.export_consumers(now, 8), exported);
        assert!(!imported.is_blocked_peer(peer, Some("n9Peer"), now));
        assert!(!imported.is_blocked(peer, now));
        assert_eq!(imported.snapshot(now, 8).tracked_peers, 0);
    }

    #[test]
    fn same_origin_import_replaces_previous_remote_balance() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let addr: SocketAddr = "192.0.2.70:51235".parse().unwrap();
        let imported = ResourceConsumerState {
            ip: Some(addr.ip()),
            peer: None,
            balance: 2_000,
            warnings: 1,
            disconnects: 0,
            last_reason: "gossip-a".to_string(),
            blocked_until_ms: None,
        };
        manager.import_consumers("origin-a", vec![imported], now);
        assert_eq!(manager.export_consumers(now, 8)[0].balance, 2_000);

        let imported = ResourceConsumerState {
            ip: Some(addr.ip()),
            peer: None,
            balance: 1_600,
            warnings: 2,
            disconnects: 1,
            last_reason: "gossip-b".to_string(),
            blocked_until_ms: None,
        };
        manager.import_consumers("origin-a", vec![imported], now);

        let exported = manager.export_consumers(now, 8);
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].balance, 1_600);
        assert_eq!(exported[0].warnings, 2);
        assert_eq!(exported[0].disconnects, 1);
        assert_eq!(exported[0].last_reason, "gossip-b");
    }

    #[test]
    fn proxy_forwarded_inbound_endpoint_charges_the_forwarded_ip() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let proxy: SocketAddr = "203.0.113.80:51235".parse().unwrap();
        let forwarded = "198.51.100.80";

        let disposition = manager.charge_inbound_endpoint(
            proxy,
            true,
            Some(forwarded),
            DISCONNECT_THRESHOLD,
            "proxy-drop",
            now,
        );

        assert_eq!(disposition, ResourceDisposition::Disconnect);
        assert!(manager.is_blocked("198.51.100.80:51235".parse().unwrap(), now));
        assert!(!manager.is_blocked(proxy, now));
    }

    #[test]
    fn unlimited_consumers_do_not_accumulate_pressure() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let addr: SocketAddr = "203.0.113.81:51235".parse().unwrap();
        let consumer = manager.new_unlimited_endpoint(addr);

        let disposition = manager.charge_consumer(&consumer, DISCONNECT_THRESHOLD, "admin", now);

        assert_eq!(consumer.kind(), ResourceConsumerKind::Unlimited);
        assert_eq!(disposition, ResourceDisposition::Ok);
        assert_eq!(manager.snapshot(now, 8).tracked, 0);
    }

    #[test]
    fn periodic_activity_updates_snapshot_metadata() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let addr: SocketAddr = "192.0.2.72:51235".parse().unwrap();
        let _ = manager.charge_addr(addr, WARNING_THRESHOLD, "warn", now);

        manager.periodic_activity(now + Duration::from_secs(1));

        let snapshot = manager.snapshot(now + Duration::from_secs(1), 8);
        assert_eq!(snapshot.activity_cycles, 1);
        assert!(snapshot.last_activity_unix.is_some());
    }

    #[test]
    fn blocked_log_status_is_throttled_between_rejections() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let addr: SocketAddr = "192.0.2.73:51235".parse().unwrap();
        let _ = manager.charge_addr(addr, DISCONNECT_THRESHOLD + 1_000, "drop", now);

        let first = manager.blocked_status_for_logging(addr, now).unwrap();
        assert!(first.should_log);
        assert_eq!(first.last_reason, "drop");

        let second = manager
            .blocked_status_for_logging(addr, now + Duration::from_secs(1))
            .unwrap();
        assert!(!second.should_log);

        let third = manager
            .blocked_status_for_logging(addr, now + BLOCK_LOG_INTERVAL)
            .unwrap();
        assert!(third.should_log);
    }

    #[test]
    fn export_consumers_skips_entries_below_gossip_floor() {
        let mut manager = ResourceManager::default();
        let now = Instant::now();
        let addr: SocketAddr = "192.0.2.71:51235".parse().unwrap();
        let _ = manager.charge_addr(addr, 500, "tiny", now);
        assert!(manager.export_consumers(now, 8).is_empty());
    }
}
