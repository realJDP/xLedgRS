use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ClusterPeerSummary {
    pub address: String,
    pub public_key: Option<String>,
    pub tag: Option<String>,
    pub reserved: bool,
    pub loopback: bool,
    pub connected: bool,
    pub status: Option<String>,
    pub action: Option<String>,
    pub ledger_seq: Option<u32>,
    pub ledger_range: Option<(u32, u32)>,
    pub load_factor: Option<u32>,
    pub connected_since_unix: Option<u64>,
    pub last_status_unix: Option<u64>,
    pub last_report_unix: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct ClusterSnapshot {
    pub configured: usize,
    pub observed: usize,
    pub connected: usize,
    pub max_reported_load_factor: Option<u32>,
    pub entries: Vec<ClusterPeerSummary>,
}

#[derive(Debug, Clone)]
struct ClusterPeer {
    address: String,
    public_key: Option<String>,
    tag: Option<String>,
    reserved: bool,
    loopback: bool,
    connected: bool,
    status: Option<String>,
    action: Option<String>,
    ledger_seq: Option<u32>,
    ledger_range: Option<(u32, u32)>,
    load_factor: Option<u32>,
    connected_since_unix: Option<u64>,
    last_status_unix: Option<u64>,
    last_report_unix: Option<u64>,
}

#[derive(Debug, Default)]
pub struct ClusterManager {
    entries: BTreeMap<String, ClusterPeer>,
}

impl ClusterManager {
    pub fn note_connected(
        &mut self,
        addr: SocketAddr,
        public_key: Option<String>,
        reserved: bool,
        loopback: bool,
        tag: Option<String>,
    ) {
        let now = unix_now();
        let address = addr.to_string();
        let key = cluster_key(&address, public_key.as_deref());
        let entry = self.entries.entry(key).or_insert(ClusterPeer {
            address: address.clone(),
            public_key: public_key.clone(),
            tag: tag.clone(),
            reserved,
            loopback,
            connected: false,
            status: None,
            action: None,
            ledger_seq: None,
            ledger_range: None,
            load_factor: None,
            connected_since_unix: None,
            last_status_unix: None,
            last_report_unix: None,
        });
        entry.address = address;
        entry.public_key = public_key;
        entry.tag = tag;
        entry.reserved = reserved;
        entry.loopback = loopback;
        entry.connected = true;
        entry.connected_since_unix.get_or_insert(now);
    }

    pub fn note_status(
        &mut self,
        addr: SocketAddr,
        public_key: Option<String>,
        status: Option<String>,
        action: Option<String>,
        ledger_seq: Option<u32>,
        ledger_range: Option<(u32, u32)>,
    ) {
        let address = addr.to_string();
        let key = cluster_key(&address, public_key.as_deref());
        let Some(entry) = self.entries.get_mut(&key) else {
            return;
        };
        entry.status = status;
        entry.action = action;
        entry.ledger_seq = ledger_seq;
        if ledger_range.is_some() {
            entry.ledger_range = ledger_range;
        }
        entry.last_status_unix = Some(unix_now());
    }

    pub fn note_gossip(
        &mut self,
        public_key: String,
        report_time: u64,
        node_load: u32,
        node_name: Option<String>,
        address: Option<String>,
    ) {
        let key = cluster_key(address.as_deref().unwrap_or(""), Some(&public_key));
        let entry = self.entries.entry(key).or_insert(ClusterPeer {
            address: address.clone().unwrap_or_default(),
            public_key: Some(public_key.clone()),
            tag: node_name.clone(),
            reserved: false,
            loopback: false,
            connected: false,
            status: None,
            action: None,
            ledger_seq: None,
            ledger_range: None,
            load_factor: None,
            connected_since_unix: None,
            last_status_unix: None,
            last_report_unix: None,
        });
        if let Some(address) = address {
            entry.address = address;
        }
        entry.public_key = Some(public_key);
        if entry.tag.is_none() {
            entry.tag = node_name;
        }
        entry.load_factor = Some(node_load);
        entry.last_report_unix = Some(report_time);
    }

    pub fn note_disconnected(&mut self, addr: SocketAddr, public_key: Option<&str>) {
        let address = addr.to_string();
        let key = cluster_key(&address, public_key);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.connected = false;
            entry.action = Some("disconnected".to_string());
            entry.last_status_unix = Some(unix_now());
        }
    }

    pub fn summary_for(
        &self,
        addr: SocketAddr,
        public_key: Option<&str>,
    ) -> Option<ClusterPeerSummary> {
        let address = addr.to_string();
        let key = cluster_key(&address, public_key);
        self.entries.get(&key).map(|entry| ClusterPeerSummary {
            address: entry.address.clone(),
            public_key: entry.public_key.clone(),
            tag: entry.tag.clone(),
            reserved: entry.reserved,
            loopback: entry.loopback,
            connected: entry.connected,
            status: entry.status.clone(),
            action: entry.action.clone(),
            ledger_seq: entry.ledger_seq,
            ledger_range: entry.ledger_range,
            load_factor: entry.load_factor,
            connected_since_unix: entry.connected_since_unix,
            last_status_unix: entry.last_status_unix,
            last_report_unix: entry.last_report_unix,
        })
    }

    pub fn snapshot(&self, limit: usize) -> ClusterSnapshot {
        let mut entries: Vec<_> = self
            .entries
            .values()
            .map(|entry| ClusterPeerSummary {
                address: entry.address.clone(),
                public_key: entry.public_key.clone(),
                tag: entry.tag.clone(),
                reserved: entry.reserved,
                loopback: entry.loopback,
                connected: entry.connected,
                status: entry.status.clone(),
                action: entry.action.clone(),
                ledger_seq: entry.ledger_seq,
                ledger_range: entry.ledger_range,
                load_factor: entry.load_factor,
                connected_since_unix: entry.connected_since_unix,
                last_status_unix: entry.last_status_unix,
                last_report_unix: entry.last_report_unix,
            })
            .collect();
        entries.sort_by(|a, b| {
            b.connected
                .cmp(&a.connected)
                .then_with(|| a.address.cmp(&b.address))
        });
        entries.truncate(limit);
        ClusterSnapshot {
            configured: self
                .entries
                .iter()
                .filter(|(_, entry)| entry.reserved || entry.loopback)
                .count(),
            observed: self.entries.len(),
            connected: self
                .entries
                .iter()
                .filter(|(_, entry)| entry.connected)
                .count(),
            max_reported_load_factor: self
                .entries
                .values()
                .filter_map(|entry| entry.load_factor)
                .max(),
            entries,
        }
    }
}

fn cluster_key(address: &str, public_key: Option<&str>) -> String {
    public_key
        .map(str::to_string)
        .unwrap_or_else(|| format!("addr:{}", address))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_tracks_connect_status_and_disconnect() {
        let mut cluster = ClusterManager::default();
        let addr: SocketAddr = "127.0.0.1:51235".parse().unwrap();
        cluster.note_connected(
            addr,
            Some("n9Cluster".into()),
            true,
            true,
            Some("vip".into()),
        );
        cluster.note_status(
            addr,
            Some("n9Cluster".into()),
            Some("connected".into()),
            Some("accepted".into()),
            Some(100),
            Some((1, 100)),
        );
        let snapshot = cluster.snapshot(8);
        assert_eq!(snapshot.configured, 1);
        assert_eq!(snapshot.observed, 1);
        assert_eq!(snapshot.connected, 1);
        assert_eq!(snapshot.entries[0].ledger_range, Some((1, 100)));

        cluster.note_disconnected(addr, Some("n9Cluster"));
        let snapshot = cluster.snapshot(8);
        assert!(!snapshot.entries[0].connected);
    }

    #[test]
    fn cluster_tracks_reported_load_from_gossip() {
        let mut cluster = ClusterManager::default();
        cluster.note_gossip(
            "n9Cluster".into(),
            123,
            640,
            Some("vip".into()),
            Some("192.0.2.20:51235".into()),
        );
        let snapshot = cluster.snapshot(8);
        assert_eq!(snapshot.configured, 0);
        assert_eq!(snapshot.observed, 1);
        assert_eq!(snapshot.max_reported_load_factor, Some(640));
        assert_eq!(snapshot.entries[0].load_factor, Some(640));
        assert_eq!(snapshot.entries[0].last_report_unix, Some(123));
    }
}
