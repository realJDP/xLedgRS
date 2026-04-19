use super::*;

impl Node {
    fn log_tls_accept_error(addr: SocketAddr, err: &openssl::ssl::Error) {
        static TLS_EOF_SUPPRESSED: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        static LAST_TLS_EOF_SUMMARY: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);

        let text = err.to_string().to_ascii_lowercase();
        let transient_eof = text.contains("unexpected eof")
            || text.contains("close_notify")
            || text.contains("eof occurred in violation of protocol");
        if !transient_eof {
            warn!("TLS accept error from {addr}: {err}");
            return;
        }

        let count = TLS_EOF_SUPPRESSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let prev = LAST_TLS_EOF_SUMMARY.load(std::sync::atomic::Ordering::Relaxed);
        if now_secs >= prev + 60 {
            LAST_TLS_EOF_SUMMARY.store(now_secs, std::sync::atomic::Ordering::Relaxed);
            info!("suppressed {} transient TLS accept EOFs in last 60s", count);
            TLS_EOF_SUPPRESSED.store(0, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub(super) async fn run_peer_listener(self: Arc<Self>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.config.peer_addr).await?;
        info!(
            "listening for peers on {} — slots: {} inbound, {} outbound (max_peers={})",
            self.config.peer_addr,
            self.config.max_inbound(),
            self.config.max_outbound(),
            self.config.max_peers,
        );

        let mut ip_last_connect: HashMap<std::net::IpAddr, tokio::time::Instant> = HashMap::new();
        let rate_limit = std::time::Duration::from_secs(2);

        loop {
            let (tcp, addr) = listener.accept().await?;

            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            let now = tokio::time::Instant::now();
            if let Some(last) = ip_last_connect.get(&addr.ip()) {
                if now.duration_since(*last) < rate_limit {
                    warn!("rate limited {addr} — too frequent");
                    continue;
                }
            }
            ip_last_connect.insert(addr.ip(), now);

            if ip_last_connect.len() > 1000 {
                ip_last_connect
                    .retain(|_, v| now.duration_since(*v) < std::time::Duration::from_secs(60));
            }

            {
                let mut state = self.state.write().await;
                if let Err(reason) = state.can_accept_inbound_peer(addr, self.config.max_inbound())
                {
                    if reason == "resource_blocked" {
                        debug!("rejecting inbound {addr}: {reason}");
                    } else {
                        warn!("rejecting inbound {addr}: {reason}");
                    }
                    continue;
                }
            }

            info!("inbound connection from {addr}");
            let node = self.clone();

            if self.openssl_tls.is_some() {
                let ssl = match openssl::ssl::Ssl::new(
                    self.openssl_tls.as_ref().unwrap().acceptor.context(),
                ) {
                    Ok(ssl) => ssl,
                    Err(e) => {
                        warn!("SSL object creation error for {addr}: {e}");
                        continue;
                    }
                };
                tokio::spawn(async move {
                    match tokio_openssl::SslStream::new(ssl, tcp) {
                        Ok(mut stream) => {
                            if let Err(e) = std::pin::Pin::new(&mut stream).accept().await {
                                Self::log_tls_accept_error(addr, &e);
                                return;
                            }
                            let session_hash =
                                crate::tls::make_shared_value(stream.ssl()).unwrap_or([0u8; 32]);
                            node.handle_peer(stream, session_hash, addr, Direction::Inbound)
                                .await;
                        }
                        Err(e) => warn!("TLS stream creation error from {addr}: {e}"),
                    }
                });
            } else {
                tokio::spawn(async move {
                    node.handle_peer(tcp, [0u8; 32], addr, Direction::Inbound)
                        .await;
                });
            }
        }
    }

    pub(super) async fn dial(self: Arc<Self>, addr: SocketAddr) -> anyhow::Result<()> {
        info!("dialing {addr}");
        let tcp = match TcpStream::connect(addr).await {
            Ok(tcp) => tcp,
            Err(e) => {
                let mut state = self.state.write().await;
                state.note_peer_connect_failure(addr, "tcp_connect_failed");
                return Err(e.into());
            }
        };

        if let Some(ref ossl) = self.openssl_tls {
            let ssl = openssl::ssl::Ssl::new(&ossl.connector_ctx)?;
            let mut stream = tokio_openssl::SslStream::new(ssl, tcp)?;
            std::pin::Pin::new(&mut stream).connect().await?;
            let session_hash = crate::tls::make_shared_value(stream.ssl()).unwrap_or([0u8; 32]);
            self.handle_peer(stream, session_hash, addr, Direction::Outbound)
                .await;
        } else {
            self.handle_peer(tcp, [0u8; 32], addr, Direction::Outbound)
                .await;
        }
        Ok(())
    }
}
