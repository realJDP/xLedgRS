//! Shared runtime services for the node's live service graph.
//!
//! This groups runtime services into one bundle so they can be wired,
//! snapshotted, and evolved together instead of living as a long list of
//! unrelated fields on `SharedState`.

pub struct RuntimeServices {
    pub peerfinder: crate::network::peerfinder::Peerfinder,
    pub resource_manager: crate::network::resource::ResourceManager,
    pub state_accounting: crate::network::ops::StateAccounting,
    pub job_queue: crate::network::load::JobQueue,
    pub load_manager: crate::network::load::LoadManager,
    pub cluster: crate::network::cluster::ClusterManager,
    pub path_requests:
        Option<std::sync::Arc<std::sync::Mutex<crate::rpc::path_requests::PathRequestManager>>>,
    pub fetch_pack: Option<std::sync::Arc<crate::ledger::fetch_pack::FetchPackStore>>,
    pub inbound_ledgers:
        Option<std::sync::Arc<std::sync::Mutex<crate::ledger::inbound::InboundLedgers>>>,
    pub inbound_transactions: crate::ledger::inbound_transactions::InboundTransactions,
    pub tx_master: crate::transaction::master::TransactionMaster,
    pub ledger_master: crate::ledger::master::LedgerMaster,
    pub open_ledger: crate::ledger::open_ledger::OpenLedger,
    pub ledger_cleaner: Option<std::sync::Arc<crate::ledger::control::LedgerCleanerService>>,
    pub node_store_stats: Option<std::sync::Arc<crate::ledger::node_store::NodeStoreStats>>,
}

impl RuntimeServices {
    pub fn new(now: std::time::Instant) -> Self {
        let mut load_manager = crate::network::load::LoadManager::default();
        load_manager.activate_stall_detector(now);
        Self {
            peerfinder: crate::network::peerfinder::Peerfinder::default(),
            resource_manager: crate::network::resource::ResourceManager::default(),
            state_accounting: crate::network::ops::StateAccounting::new(now),
            job_queue: crate::network::load::JobQueue::default(),
            load_manager,
            cluster: crate::network::cluster::ClusterManager::default(),
            path_requests: None,
            fetch_pack: None,
            inbound_ledgers: None,
            inbound_transactions: crate::ledger::inbound_transactions::InboundTransactions::default(
            ),
            tx_master: crate::transaction::master::TransactionMaster::default(),
            ledger_master: crate::ledger::master::LedgerMaster::default(),
            open_ledger: crate::ledger::open_ledger::OpenLedger::default(),
            ledger_cleaner: None,
            node_store_stats: None,
        }
    }

    pub fn attach_node_store_stats(
        &mut self,
        stats: std::sync::Arc<crate::ledger::node_store::NodeStoreStats>,
    ) {
        self.node_store_stats = Some(stats);
    }

    pub fn attach_fetch_pack(
        &mut self,
        fetch_pack: std::sync::Arc<crate::ledger::fetch_pack::FetchPackStore>,
    ) {
        self.fetch_pack = Some(fetch_pack);
    }

    pub fn attach_path_requests(
        &mut self,
        path_requests: std::sync::Arc<std::sync::Mutex<crate::rpc::path_requests::PathRequestManager>>,
    ) {
        self.path_requests = Some(path_requests);
    }

    pub fn attach_inbound_ledgers(
        &mut self,
        inbound_ledgers: std::sync::Arc<std::sync::Mutex<crate::ledger::inbound::InboundLedgers>>,
    ) {
        self.inbound_ledgers = Some(inbound_ledgers);
    }

    pub fn attach_ledger_cleaner(
        &mut self,
        ledger_cleaner: std::sync::Arc<crate::ledger::control::LedgerCleanerService>,
    ) {
        self.ledger_cleaner = Some(ledger_cleaner);
    }

    pub fn node_store_snapshot(&self) -> Option<crate::ledger::node_store::NodeStoreSnapshot> {
        self.node_store_stats.as_ref().map(|stats| stats.snapshot())
    }

    pub fn fetch_pack_snapshot(&self) -> Option<crate::ledger::fetch_pack::FetchPackSnapshot> {
        self.fetch_pack.as_ref().map(|fetch_pack| fetch_pack.snapshot(32))
    }

    pub fn inbound_ledgers_snapshot(
        &self,
    ) -> Option<crate::ledger::inbound::InboundLedgersSnapshot> {
        self.inbound_ledgers.as_ref().map(|inbound_ledgers| {
            inbound_ledgers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot(32)
        })
    }

    pub fn path_request_snapshot(
        &self,
    ) -> Option<crate::rpc::path_requests::PathRequestSnapshot> {
        self.path_requests.as_ref().map(|path_requests| {
            path_requests
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot(32)
        })
    }

    pub fn ledger_cleaner_snapshot(
        &self,
    ) -> Option<crate::ledger::control::LedgerCleanerSnapshot> {
        self.ledger_cleaner
            .as_ref()
            .map(|ledger_cleaner| ledger_cleaner.snapshot())
    }

    pub fn note_local_broadcasts(
        &mut self,
        pending: &[crate::network::message::RtxpMessage],
    ) {
        let now_unix = crate::transaction::master::unix_now();
        for msg in pending {
            if msg.msg_type != crate::network::message::MessageType::Transaction {
                continue;
            }
            let Ok(pb) =
                <crate::proto::TmTransaction as prost::Message>::decode(msg.payload.as_slice())
            else {
                continue;
            };
            let hash = crate::transaction::serialize::tx_blob_hash(&pb.raw_transaction);
            self.tx_master
                .observe_submitted(hash, pb.raw_transaction.len(), "rpc_submit", now_unix);
            self.tx_master.note_relayed(&hash, now_unix);
        }
    }

    pub fn refresh_health(
        &mut self,
        peer_count: usize,
        reservation_count: usize,
        now: std::time::Instant,
    ) {
        let now_unix = unix_now();
        self.peerfinder.once_per_second(now_unix);
        if let Some(fetch_pack) = self.fetch_pack.as_ref() {
            fetch_pack.prune(now_unix);
        }
        let open_ledger_snapshot = self.open_ledger.snapshot();
        let active_path_requests = self
            .path_requests
            .as_ref()
            .map(|path_requests| {
                path_requests
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .snapshot(0)
                    .active_requests
            })
            .unwrap_or(0);
        let active_inbound_ledgers = self
            .inbound_ledgers
            .as_ref()
            .map(|inbound_ledgers| {
                inbound_ledgers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .snapshot(0)
                    .active
            })
            .unwrap_or(0);
        self.job_queue.refresh(
            open_ledger_snapshot.queued_transactions,
            open_ledger_snapshot.max_queue_size,
            self.tx_master.snapshot(0).tracked,
            self.inbound_transactions.snapshot(0).tracked,
            active_path_requests,
            active_inbound_ledgers,
        );
        let job_queue_snapshot = self.job_queue.snapshot();
        self.load_manager.refresh_local_queue_health(
            &job_queue_snapshot,
            now,
        );
        let resource_snapshot = self.resource_manager.snapshot(now, 0);
        let peerfinder_snapshot = self.peerfinder.snapshot(0);
        self.load_manager.refresh_network_health(
            peer_count,
            peerfinder_snapshot.total_known,
            peerfinder_snapshot.dialable,
            peerfinder_snapshot.backed_off,
            peerfinder_snapshot.retry_ready,
            peerfinder_snapshot.ready,
            peerfinder_snapshot.cooling,
            peerfinder_snapshot.cold,
            peerfinder_snapshot.redirects,
            peerfinder_snapshot.distinct_sources,
            resource_snapshot.blocked,
            resource_snapshot.warned,
            resource_snapshot.ip_balance,
            resource_snapshot.peer_balance,
            resource_snapshot.total_balance,
            resource_snapshot.total_disconnects,
            resource_snapshot.total_warnings,
        );
        let mut cluster_snapshot = self.cluster.snapshot(0);
        cluster_snapshot.configured = cluster_snapshot.configured.max(reservation_count);
        self.load_manager.refresh_cluster_health(
            cluster_snapshot.configured,
            cluster_snapshot.connected,
            cluster_snapshot.max_reported_load_factor,
        );
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    #[test]
    fn local_broadcasts_feed_tx_master() {
        let mut services = crate::services::RuntimeServices::new(std::time::Instant::now());
        let tx = crate::network::relay::encode_transaction(&[1u8, 2, 3, 4]);

        services.note_local_broadcasts(&[tx]);

        let snapshot = services.tx_master.snapshot(4);
        assert_eq!(snapshot.tracked, 1);
        assert_eq!(snapshot.submitted_total, 1);
        assert_eq!(snapshot.relayed_total, 1);
        assert_eq!(snapshot.entries[0].status, "submitted");
        assert_eq!(snapshot.entries[0].source, "rpc_submit");
    }

    #[test]
    fn redirect_churn_raises_network_pressure() {
        let mut services = crate::services::RuntimeServices::new(std::time::Instant::now());
        let from: std::net::SocketAddr = "203.0.113.90:51235".parse().unwrap();
        let to: std::net::SocketAddr = "203.0.113.91:51235".parse().unwrap();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        services.peerfinder.note_connected(from, now_unix);
        services.peerfinder.note_redirect(from, to, now_unix.saturating_add(20));
        services.refresh_health(1, 0, std::time::Instant::now());

        let snapshot = services.load_manager.snapshot();
        assert!(snapshot.remote_fee > crate::network::load::LOAD_BASE);
    }

    #[test]
    fn refresh_health_populates_the_job_queue_service() {
        let mut services = crate::services::RuntimeServices::new(std::time::Instant::now());
        let metrics = crate::ledger::pool::FeeMetrics::default();
        services.job_queue.refresh(0, 4, 0, 0, 0, 0);
        services.open_ledger.note_queue_state(
            7,
            [0xAB; 32],
            &metrics,
        );

        services.refresh_health(1, 0, std::time::Instant::now());

        let snapshot = services.job_queue.snapshot();
        assert_eq!(snapshot.queued_transactions, 7);
        assert_eq!(snapshot.queue_capacity, metrics.max_queue_size());
        assert!(!snapshot.overloaded);
        assert_eq!(snapshot.job_types[0].job_type, "transaction_queue");
        assert_eq!(snapshot.job_types[0].waiting, 7);
    }
}
