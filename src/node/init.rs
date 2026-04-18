use super::*;

impl Node {
    pub fn new(config: NodeConfig) -> Self {
        let cfg = config.config_file.as_ref().and_then(|path| {
            match crate::config::ConfigFile::load(path) {
                Ok(c) => {
                    info!("loaded config from {}", path.display());
                    Some(c)
                }
                Err(e) => {
                    warn!("failed to load config {}: {e}", path.display());
                    None
                }
            }
        });
        let static_unl = cfg.as_ref().map(|c| c.unl()).unwrap_or_default();
        let validator_lists = cfg
            .as_ref()
            .map(|c| c.validator_lists.clone())
            .unwrap_or_default();
        let amendments = cfg
            .as_ref()
            .map(|c| c.enabled_amendments())
            .unwrap_or_default();
        let validator_list_state = Arc::new(std::sync::Mutex::new(
            crate::validator_list::ValidatorListManager::new(
                static_unl.clone(),
                validator_lists.effective_threshold(),
            ),
        ));
        let validator_site_statuses =
            crate::validator_list::initial_site_statuses(&validator_lists.sites);
        let manifest_cache = Arc::new(std::sync::Mutex::new(
            crate::consensus::ManifestCache::new(),
        ));
        let path_requests = Arc::new(std::sync::Mutex::new(
            crate::rpc::path_requests::PathRequestManager::default(),
        ));
        let unl = validator_list_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .current_unl();
        let admin_rpc_enabled =
            config.rpc_addr.ip().is_loopback() && config.ws_addr.ip().is_loopback();

        if !unl.is_empty() {
            info!("UNL loaded with {} validators", unl.len());
        }
        if !validator_lists.sites.is_empty() || !validator_lists.publisher_keys.is_empty() {
            info!(
                "validator list config loaded: {} site(s), {} publisher key(s), threshold={}",
                validator_lists.sites.len(),
                validator_lists.publisher_keys.len(),
                validator_lists.effective_threshold()
            );
        }
        if !admin_rpc_enabled {
            warn!(
                "admin RPC methods (sign, sign_for, submit) disabled because RPC/WS are not loopback-only (rpc_addr={}, ws_addr={})",
                config.rpc_addr,
                config.ws_addr
            );
        }
        if !amendments.is_empty() {
            info!("amendments enabled: {:?}", amendments);
        }

        let storage = config
            .data_dir
            .as_ref()
            .and_then(|dir| match crate::storage::Storage::open(dir) {
                Ok(s) => Some(Arc::new(s)),
                Err(e) => {
                    error!("failed to open storage at {}: {e}", dir.display());
                    None
                }
            });

        let mut ctx = if let Some(ref store) = storage {
            if store.has_state() {
                info!("loading state from disk...");
                let ledger_state_inner = crate::ledger::LedgerState::new();
                let history_inner = store
                    .load_history_with_limit(config.ledger_history.max_history_limit())
                    .unwrap_or_else(|_| {
                        crate::ledger::LedgerStore::with_limit(
                            config.ledger_history.max_history_limit(),
                        )
                    });
                let (mut seq, mut hash, mut header) =
                    store
                        .load_meta()
                        .unwrap_or((0, "0".repeat(64), Default::default()));
                if let Some(latest) = history_inner.latest_ledger() {
                    let hist_seq = latest.header.sequence;
                    let hist_hash = hex::encode_upper(latest.header.hash);
                    if seq != hist_seq || header.sequence != hist_seq || hash != hist_hash {
                        warn!(
                            "storage meta disagrees with ledger history (meta_seq={}, hist_seq={}) — preferring historical latest ledger",
                            seq, hist_seq,
                        );
                        seq = hist_seq;
                        hash = hist_hash;
                        header = latest.header.clone();
                    }
                }
                info!(
                    "loaded ledger {seq} with {} accounts",
                    ledger_state_inner.account_count()
                );
                NodeContext {
                    network: "mainnet",
                    network_id: config.network_id,
                    build_version: env!("CARGO_PKG_VERSION"),
                    start_time: std::time::Instant::now(),
                    ledger_seq: seq,
                    ledger_hash: hash,
                    ledger_header: header,
                    ledger_state: Arc::new(std::sync::Mutex::new(ledger_state_inner)),
                    history: Arc::new(std::sync::RwLock::new(history_inner)),
                    ..Default::default()
                }
            } else {
                Self::fresh_genesis_ctx(
                    config.network_id,
                    config.ledger_history.max_history_limit(),
                )
            }
        } else {
            Self::fresh_genesis_ctx(config.network_id, config.ledger_history.max_history_limit())
        };
        ctx.admin_rpc_enabled = admin_rpc_enabled;

        if let Some(ref store) = storage {
            ctx.ledger_state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .set_storage(store.clone());
        }

        let mut nudb_direct: Option<Arc<dyn crate::ledger::node_store::NodeStore>> = None;
        let mut node_store_stats: Option<Arc<crate::ledger::node_store::NodeStoreStats>> = None;
        let mut fetch_pack_service: Option<Arc<crate::ledger::fetch_pack::FetchPackStore>> = None;
        if let Some(ref dir) = config.data_dir {
            let nudb_dir = dir.join("nodestore");
            match crate::ledger::node_store::NuDBNodeStore::open(&nudb_dir) {
                Ok(nudb) => {
                    let raw_backend: std::sync::Arc<dyn crate::ledger::node_store::NodeStore> =
                        std::sync::Arc::new(nudb);
                    let (observed_backend, stats) =
                        crate::ledger::node_store::ObservedNodeStore::wrap(raw_backend);
                    let (backend, fetch_pack) =
                        crate::ledger::fetch_pack::FetchPackStore::wrap(observed_backend);
                    node_store_stats = Some(stats);
                    fetch_pack_service = Some(fetch_pack);
                    nudb_direct = Some(backend.clone());
                    let cached: std::sync::Arc<dyn crate::ledger::node_store::NodeStore> =
                        std::sync::Arc::new(
                            crate::ledger::tree_cache::CachedNodeStore::with_max_bytes(
                                backend,
                                500_000,
                                256 * 1024 * 1024,
                            ),
                        );
                    let nudb_shamap = crate::ledger::shamap::SHAMap::with_backend(
                        crate::ledger::shamap::MapType::AccountState,
                        cached,
                    );
                    ctx.ledger_state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .set_nudb_shamap(nudb_shamap);
                    info!(
                        "NuDB NodeStore ready at {} (content-addressed, 256MB cache)",
                        nudb_dir.display()
                    );
                }
                Err(e) => {
                    warn!(
                        "failed to open NuDB NodeStore at {}: {e} — running without",
                        nudb_dir.display()
                    );
                }
            }
        }

        let node_key = if let Some(ref store) = storage {
            if let Some(seed_bytes) = store.get_meta("node_seed") {
                if seed_bytes.len() >= 16 {
                    let mut entropy = [0u8; 16];
                    entropy.copy_from_slice(&seed_bytes[..16]);
                    Secp256k1KeyPair::from_seed_entropy(&entropy)
                } else {
                    let kp = Secp256k1KeyPair::generate();
                    let _ = store.save_meta_kv("node_seed", &kp.public_key_bytes()[..16]);
                    kp
                }
            } else {
                let entropy: [u8; 16] = rand::random();
                let kp = Secp256k1KeyPair::from_seed_entropy(&entropy);
                let _ = store.save_meta_kv("node_seed", &entropy);
                kp
            }
        } else {
            Secp256k1KeyPair::generate()
        };
        let pubkey_bytes = node_key.public_key_bytes();
        let node_pubkey_b58 =
            crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, &pubkey_bytes);
        info!("node public key: {}", node_pubkey_b58);

        let validator_key = config.validation_seed.as_deref().and_then(|seed| {
            match Secp256k1KeyPair::from_seed(seed) {
                Ok(kp) => {
                    let vk_bytes = kp.public_key_bytes();
                    let vk_b58 = crate::crypto::base58::encode(
                        crate::crypto::base58::PREFIX_NODE_PUBLIC,
                        &vk_bytes,
                    );
                    info!("validator signing key: {}", vk_b58);
                    Some(kp)
                }
                Err(e) => {
                    error!("failed to derive validator key from validation_seed: {e}");
                    None
                }
            }
        });
        let validator_key_b58 = validator_key
            .as_ref()
            .map(|kp| {
                crate::crypto::base58::encode(
                    crate::crypto::base58::PREFIX_NODE_PUBLIC,
                    &kp.public_key_bytes(),
                )
            })
            .unwrap_or_default();
        let openssl_tls = if config.use_tls {
            match OpenSslConfig::new_self_signed() {
                Ok(cfg) => Some(cfg),
                Err(e) => {
                    error!("OpenSSL TLS setup failed: {e}");
                    None
                }
            }
        } else {
            None
        };

        ctx.amendments = amendments;
        ctx.pubkey_node = node_pubkey_b58.clone();
        ctx.validator_key = validator_key_b58.clone();
        ctx.validator_list_manager = Some(validator_list_state.clone());
        ctx.manifest_cache = Some(manifest_cache.clone());
        ctx.validator_list_sites = validator_lists.sites.clone();
        ctx.validator_site_statuses = Some(validator_site_statuses.clone());
        ctx.path_requests = Some(path_requests.clone());
        let persisted_peer_reservations = storage
            .as_ref()
            .map(|store| store.load_peer_reservations())
            .unwrap_or_default();
        if !persisted_peer_reservations.is_empty() {
            info!(
                "loaded {} persisted peer reservation(s)",
                persisted_peer_reservations.len()
            );
        }
        ctx.peer_reservations = Some(Arc::new(std::sync::Mutex::new(persisted_peer_reservations)));
        ctx.sync_clear_requested = Some(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        ctx.connect_requests = Some(Arc::new(std::sync::Mutex::new(Vec::new())));
        ctx.shutdown_requested = Some(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        ctx.force_ledger_accept = Some(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        ctx.standalone_mode = config.standalone;
        let ledger_accept_service = (config.standalone && config.enable_consensus_close_loop)
            .then(|| Arc::new(crate::ledger::control::LedgerAcceptService::default()));
        ctx.ledger_accept_service = ledger_accept_service.clone();
        ctx.online_delete = config.online_delete;
        ctx.storage = storage.clone();
        let ledger_cleaner =
            crate::ledger::control::LedgerCleanerService::new(storage.clone(), config.online_delete);
        ctx.ledger_cleaner = Some(ledger_cleaner.clone());
        let can_delete_target = Arc::new(std::sync::atomic::AtomicU32::new(
            if config.online_delete.is_some() {
                u32::MAX
            } else {
                0
            },
        ));
        ctx.can_delete_target = Some(can_delete_target.clone());

        let (ws_events, _) = tokio::sync::broadcast::channel(4096);
        let mut shared = SharedState::new(ctx);
        if let Some(ref store) = storage {
            let persisted_peerfinder = store.load_peerfinder_bootcache();
            if !persisted_peerfinder.is_empty() {
                info!(
                    "loaded {} persisted peerfinder bootcache entrie(s)",
                    persisted_peerfinder.len()
                );
                shared
                    .services
                    .peerfinder
                    .load_persisted(persisted_peerfinder);
                shared.rebuild_known_peers();
                shared.refresh_runtime_health(std::time::Instant::now());
            }
        }

        if let Some(ref store) = storage {
            let has_completed_sync = store.is_sync_complete();
            let sync_account_hash = if has_completed_sync {
                store.get_sync_account_hash()
            } else {
                None
            };
            let has_sync_ledger_hash = has_completed_sync && store.get_sync_ledger_hash().is_some();
            let has_sync_ledger_header =
                has_completed_sync && store.get_sync_ledger_header().is_some();
            let rehydrated_root = if has_completed_sync {
                let mut loaded = false;
                {
                    let mut ls = shared
                        .ctx
                        .ledger_state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    ls.enable_sparse();
                    if let Some(root_hash) = sync_account_hash {
                        match ls.load_nudb_root(root_hash) {
                            Ok(true) => {
                                info!(
                                    "rehydrated NuDB SHAMap root from sync anchor {}",
                                    hex::encode_upper(&root_hash[..8]),
                                );
                                loaded = true;
                            }
                            Ok(false) => warn!(
                                "sync_complete set but NuDB root {} could not be rehydrated",
                                hex::encode_upper(&root_hash[..8]),
                            ),
                            Err(e) => warn!(
                                "sync_complete set but NuDB root {} failed to rehydrate: {}",
                                hex::encode_upper(&root_hash[..8]),
                                e,
                            ),
                        }
                    } else {
                        warn!(
                            "sync_complete set but no sync_account_hash found for NuDB root rehydrate"
                        );
                    }
                }
                loaded
            } else {
                false
            };

            if crate::sync_bootstrap::should_resume_from_sync_anchor(
                has_completed_sync,
                sync_account_hash.is_some(),
                has_sync_ledger_hash,
                has_sync_ledger_header,
                rehydrated_root,
            ) {
                info!("existing database detected — follower-only mode (no tree sync)");
                shared.sync_done = true;
            } else {
                if has_completed_sync {
                    warn!(
                        "sync_complete metadata present but no usable sync anchor could be restored — clearing handoff and re-entering state sync"
                    );
                }
                info!("no sync_complete flag — clearing stale handoff metadata for fresh sync");
                let _ = store.clear_sync_handoff();
            }
        }

        {
            let mut ls = shared
                .ctx
                .ledger_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            shared.ctx.fees = crate::ledger::read_fees(&ls);
            let enabled = crate::ledger::read_amendments(&ls);
            if !enabled.is_empty() {
                info!(
                    "loaded {} enabled amendments from Amendments SLE",
                    enabled.len()
                );
                for hash in enabled {
                    ls.enable_amendment(hash);
                }
            }
        }

        let (debug_log_file, debug_log_path_value) = if let Some(ref dir) = config.data_dir {
            let debug_dir = std::path::Path::new(dir).join("debug_logs");
            let _ = std::fs::create_dir_all(&debug_dir);
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let path = debug_dir.join(format!("sync_{}.log", ts));
            (std::fs::File::create(&path).ok(), Some(path))
        } else {
            (None, None)
        };
        let debug_log = Arc::new(std::sync::Mutex::new(debug_log_file));
        let debug_log_path = Arc::new(std::sync::Mutex::new(debug_log_path_value));
        shared.ctx.debug_log = Some(debug_log.clone());
        shared.ctx.debug_log_path = Some(debug_log_path.clone());
        if let Some(stats) = node_store_stats {
            shared.services.attach_node_store_stats(stats);
        }
        if let Some(fetch_pack) = fetch_pack_service {
            shared.services.attach_fetch_pack(fetch_pack);
        }
        shared.services.attach_ledger_cleaner(ledger_cleaner);
        shared.services.attach_path_requests(path_requests);
        let inbound_ledgers = Arc::new(std::sync::Mutex::new(
            crate::ledger::inbound::InboundLedgers::new(),
        ));
        shared
            .services
            .attach_inbound_ledgers(inbound_ledgers.clone());

        let initial_object_count = nudb_direct
            .as_ref()
            .map(|backend| backend.count() as usize)
            .filter(|count| *count > 0)
            .unwrap_or_else(|| Self::persisted_leaf_count(storage.as_ref()));
        let initial_rpc_snapshot = Self::build_rpc_snapshot(
            &shared,
            initial_object_count,
            &node_key,
            validator_key.as_ref(),
        );
        let initial_rpc_read_ctx = Self::build_rpc_read_context(
            &shared,
            initial_object_count,
            None,
        );
        let state = Arc::new(RwLock::new(shared));
        let sync_runtime = Arc::new(crate::sync_runtime::SyncRuntime::new());

        Self {
            config,
            state,
            node_key,
            validator_key,
            storage,
            openssl_tls,
            ws_events,
            nudb_backend: nudb_direct,
            unl: Arc::new(std::sync::RwLock::new(unl)),
            validator_list_state,
            validator_list_config: validator_lists,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            sync_runtime,
            msg_dedup: Arc::new(std::sync::Mutex::new((
                std::collections::HashSet::new(),
                std::time::Instant::now(),
            ))),
            debug_log,
            rpc_snapshot: arc_swap::ArcSwap::from_pointee(initial_rpc_snapshot),
            rpc_read_ctx: arc_swap::ArcSwap::from_pointee(initial_rpc_read_ctx),
            can_delete_target,
            inbound_ledgers,
        }
    }

    fn fresh_genesis_ctx(network_id: u32, history_limit: Option<u32>) -> NodeContext {
        use crate::crypto::keys::Secp256k1KeyPair;
        use crate::ledger::AccountRoot;

        let mut ctx = NodeContext {
            network: "mainnet",
            network_id,
            build_version: env!("CARGO_PKG_VERSION"),
            start_time: std::time::Instant::now(),
            ledger_seq: 1,
            ledger_hash: "0".repeat(64),
            history: Arc::new(std::sync::RwLock::new(
                crate::ledger::LedgerStore::with_limit(history_limit),
            )),
            ..Default::default()
        };
        {
            let mut ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            if let Ok(kp) = Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb") {
                let account_id = crate::crypto::account_id(&kp.public_key_bytes());
                ls.insert_account(AccountRoot {
                    account_id,
                    balance: 100_000_000_000_000_000,
                    sequence: 1,
                    owner_count: 0,
                    flags: 0,
                    regular_key: None,
                    minted_nftokens: 0,
                    burned_nftokens: 0,
                    transfer_rate: 0,
                    domain: Vec::new(),
                    tick_size: 0,
                    ticket_count: 0,
                    previous_txn_id: [0u8; 32],
                    previous_txn_lgr_seq: 0,
                    raw_sle: None,
                });
            }
            let account_hash = ls.state_hash();
            ctx.ledger_header = crate::ledger::LedgerHeader {
                sequence: 1,
                hash: [0u8; 32],
                parent_hash: [0u8; 32],
                close_time: 0,
                total_coins: 100_000_000_000_000_000,
                account_hash,
                transaction_hash: [0u8; 32],
                parent_close_time: 0,
                close_time_resolution: 10,
                close_flags: 0,
            };
            ls.mark_all_dirty();
        }
        let hash = ctx.ledger_header.compute_hash();
        ctx.ledger_header.hash = hash;
        ctx.ledger_hash = hex::encode_upper(hash);
        ctx.history
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert_ledger(ctx.ledger_header.clone(), vec![]);
        ctx
    }
}
