//! xLedgRS purpose: Rpc Server piece of the live node runtime.
use super::http_io::{parse_forwarded_for, read_rpc_request};
use super::*;

impl Node {
    pub(super) async fn run_rpc_server(self: Arc<Self>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.config.rpc_addr).await?;
        info!("JSON-RPC server on {}", self.config.rpc_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(e) = node.handle_rpc(stream, addr).await {
                    warn!("RPC error from {addr}: {e}");
                }
            });
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
            match result {
                Ok(r) => crate::rpc::RpcResponse::ok(r, id).to_json(),
                Err(e) => crate::rpc::RpcResponse::err(e, id).to_json(),
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
