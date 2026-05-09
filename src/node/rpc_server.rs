use super::http_io::{parse_forwarded_for, parse_http_request_line, read_rpc_request};
use super::*;

impl Node {
    pub(super) async fn run_rpc_server(self: Arc<Self>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.config.rpc_addr).await?;
        info!("JSON-RPC server on {}", self.config.rpc_addr);
        let mut shutdown_check = tokio::time::interval(std::time::Duration::from_millis(200));
        shutdown_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            let (stream, addr) = tokio::select! {
                accepted = listener.accept() => accepted?,
                _ = shutdown_check.tick() => {
                    if self.is_shutting_down() {
                        info!("JSON-RPC server: shutdown");
                        return Ok(());
                    }
                    continue;
                }
            };
            let node = self.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = node.handle_rpc(stream, addr).await {
                    warn!("RPC error from {addr}: {e}");
                }
            });
            self.track_background_task("rpc_connection", handle);
        }
    }

    pub(super) async fn handle_rpc(
        self: Arc<Self>,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let raw = read_rpc_request(&mut stream).await?;
        if raw.is_empty() {
            return Ok(());
        }

        let (header, body) = if raw.starts_with(b"POST") || raw.starts_with(b"GET") {
            raw.windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|i| (&raw[..i + 4], &raw[i + 4..]))
                .unwrap_or((&raw[..0], raw.as_slice()))
        } else {
            (&raw[..0], raw.as_slice())
        };

        let forwarded_for = addr
            .ip()
            .is_loopback()
            .then(|| parse_forwarded_for(header))
            .flatten();
        {
            let mut state = self.state.write().await;
            let consumer = state.services.resource_manager.new_inbound_endpoint(
                addr,
                addr.ip().is_loopback(),
                forwarded_for.as_deref(),
            );
            let _ = state.services.resource_manager.charge_consumer(
                &consumer,
                250,
                "rpc_request",
                std::time::Instant::now(),
            );
        }

        if let Some(("GET", target)) = parse_http_request_line(header) {
            if target == "/metrics" {
                let ctx = self.rpc_read_ctx.load();
                if !ctx.admin_rpc_enabled {
                    let body = "metrics endpoint requires admin RPC\n";
                    let http = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(http.as_bytes()).await?;
                    return Ok(());
                }
                let body = crate::rpc::handlers::metrics_text(ctx.as_ref());
                let http = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(http.as_bytes()).await?;
                return Ok(());
            }
        }

        if body.is_empty() {
            let reply = serde_json::json!({
                "result": {
                    "error": "invalidParams",
                    "error_code": 31,
                    "error_message": "Unable to parse request.",
                    "status": "error",
                }
            })
            .to_string();
            let http = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                reply.len(), reply
            );
            stream.write_all(http.as_bytes()).await?;
            return Ok(());
        }

        let req = match RpcRequest::parse(body) {
            Ok(r) => r,
            Err(e) => {
                let reply = serde_json::json!({
                    "result": {
                        "error": "invalidParams",
                        "error_code": 31,
                        "error_message": format!("Unable to parse request: {e}"),
                        "status": "error",
                    }
                })
                .to_string();
                let http = format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                    reply.len(), reply
                );
                stream.write_all(http.as_bytes()).await?;
                return Ok(());
            }
        };

        let reply = if req.method == "server_info" || req.method == "server_state" {
            let snap = self.rpc_snapshot.load();
            let follower = {
                let state = self.state.try_read();
                state.ok().and_then(|s| s.follower_state.clone())
            };
            let rpc_sync = {
                let state = self.state.try_read();
                state.ok().and_then(|s| s.rpc_sync_state.clone())
            };
            let result = if req.method == "server_state" {
                crate::rpc::handlers::server_state_snapshot(&snap)
            } else {
                crate::rpc::handlers::server_info_snapshot(
                    &snap,
                    follower.as_ref(),
                    rpc_sync.as_ref(),
                )
            };
            let id = req.id;
            let request = serde_json::json!({
                "method": req.method,
                "params": req.params,
            });
            match result {
                Ok(r) => crate::rpc::RpcResponse::ok(r, id).to_json(),
                Err(e) => crate::rpc::RpcResponse::err_with_request(e, id, request).to_json(),
            }
        } else if crate::rpc::needs_write(&req.method) {
            self.dispatch_write_rpc(req).await.to_json()
        } else {
            let ctx = self.rpc_read_ctx.load();
            crate::rpc::dispatch_read(req, ctx.as_ref()).to_json()
        };

        let http = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
            reply.len(),
            reply
        );
        stream.write_all(http.as_bytes()).await?;
        Ok(())
    }
}
