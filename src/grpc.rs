//! xLedgRS purpose: Serve optional gRPC APIs backed by the node runtime.
//! gRPC service layer for xLedgRSv2Beta.
//!
//! This exposes the binary ledger RPC surface plus a local extension service
//! for server information and transaction submission convenience.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::json;
use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("org.xrpl.rpc.v1");
}

use pb::x_ledg_r_sv2_beta_server::{XLedgRSv2Beta, XLedgRSv2BetaServer};
use pb::xrp_ledger_api_service_server::{XrpLedgerApiService, XrpLedgerApiServiceServer};

pub struct GrpcRuntime {
    join: tokio::task::JoinHandle<()>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl GrpcRuntime {
    pub async fn spawn(node: Arc<xrpl::node::Node>, addr: SocketAddr) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let grpc_service = GrpcService { node, local_addr };
        let service = XLedgRSv2BetaServer::new(grpc_service.clone());
        let api_service = XrpLedgerApiServiceServer::new(grpc_service);
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let join = tokio::spawn(async move {
            let shutdown = async move {
                let _ = shutdown_rx.await;
            };
            if let Err(err) = tonic::transport::Server::builder()
                .add_service(service)
                .add_service(api_service)
                .serve_with_incoming_shutdown(incoming, shutdown)
                .await
            {
                tracing::error!("gRPC server stopped with error: {err}");
            }
        });

        Ok(Self {
            join,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.join.await;
    }
}

#[derive(Clone)]
struct GrpcService {
    node: Arc<xrpl::node::Node>,
    local_addr: SocketAddr,
}

struct LedgerPage {
    ledger_index: u32,
    ledger_hash: Vec<u8>,
    objects: BTreeMap<[u8; 32], Vec<u8>>,
    marker: Option<Vec<u8>>,
}

impl GrpcService {
    fn apply_request_identity(
        params: &mut serde_json::Map<String, serde_json::Value>,
        client_ip: &str,
        user: &str,
    ) {
        if !client_ip.is_empty() {
            params.insert("client_ip".to_string(), json!(client_ip));
        }
        if !user.is_empty() {
            params.insert("user".to_string(), json!(user));
        }
    }

    fn request_is_unlimited(client_ip: &str, user: &str) -> bool {
        !user.is_empty() && client_ip.is_empty()
    }

    async fn get_ledger_response_impl(
        &self,
        req: pb::GetLedgerRequest,
    ) -> Result<pb::GetLedgerResponse, Status> {
        let spec_ref = req.ledger.as_ref().and_then(|spec| spec.ledger.as_ref());
        let mut params = Self::ledger_specifier_to_params(spec_ref, "ledger")?;
        Self::apply_request_identity(&mut params, &req.client_ip, &req.user);
        if req.transactions {
            params.insert("transactions".to_string(), json!(true));
        }

        let ctx = self.node.rpc_read_context();
        let ctx = Arc::clone(&*ctx);
        let result = xrpl::rpc::handlers::ledger_header(&serde_json::Value::Object(params), &ctx)
            .map_err(map_rpc_error_to_status)?;
        let ledger_seq = result
            .get("ledger_index")
            .and_then(|value| value.as_u64())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| Status::internal("ledger_header omitted ledger_index"))?;
        let ledger_header = hex::decode(
            result
                .get("ledger_data")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Status::internal("ledger_header omitted ledger_data"))?,
        )
        .map_err(|_| Status::internal("ledger_header returned invalid ledger_data"))?;

        let (ledger_header_clone, tx_records) = {
            let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());
            let ledger_header_clone = if let Some(rec) = history.get_ledger(ledger_seq) {
                rec.header.clone()
            } else if ledger_seq == ctx.ledger_seq {
                ctx.ledger_header.clone()
            } else {
                return Err(Status::not_found("ledger not found"));
            };
            let tx_records = history.ledger_txs(ledger_seq);
            (ledger_header_clone, tx_records)
        };
        let transactions = if req.transactions {
            if req.expand {
                Some(pb::get_ledger_response::Transactions::TransactionsList(
                    pb::TransactionAndMetadataList {
                        transactions: tx_records
                            .iter()
                            .cloned()
                            .map(|record| pb::TransactionAndMetadata {
                                transaction_blob: record.blob,
                                metadata_blob: record.meta,
                            })
                            .collect(),
                    },
                ))
            } else {
                Some(pb::get_ledger_response::Transactions::HashesList(
                    pb::TransactionHashList {
                        hashes: tx_records
                            .iter()
                            .map(|record| record.hash.to_vec())
                            .collect(),
                    },
                ))
            }
        } else {
            None
        };

        let response_ledger_header = if ledger_header.is_empty() {
            bincode::serialize(&ledger_header_clone).unwrap_or_default()
        } else {
            ledger_header.clone()
        };

        let mut response = pb::GetLedgerResponse {
            ledger_header: response_ledger_header,
            transactions,
            validated: result
                .get("validated")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            ledger_objects: None,
            skiplist_included: false,
            is_unlimited: Self::request_is_unlimited(&req.client_ip, &req.user),
            objects_included: false,
            object_neighbors_included: false,
            book_successors: Vec::new(),
        };

        if req.get_objects {
            let desired = self
                .collect_ledger_page(spec_ref, "ledger", None, None, &req.client_ip, &req.user)
                .await?;
            let base = if ledger_seq > 0 {
                let base_spec = pb::ledger_specifier::Ledger::Sequence(ledger_seq - 1);
                self.collect_ledger_page(
                    Some(&base_spec),
                    "base_ledger",
                    None,
                    None,
                    &req.client_ip,
                    &req.user,
                )
                .await?
            } else {
                LedgerPage {
                    ledger_index: ledger_seq,
                    ledger_hash: ledger_header.clone(),
                    objects: BTreeMap::new(),
                    marker: None,
                }
            };
            response.objects_included = true;
            response.object_neighbors_included = req.get_object_neighbors;
            response.ledger_objects = Some(pb::RawLedgerObjects {
                objects: build_ledger_diff_objects(&base, &desired, true, req.get_object_neighbors),
            });
        }

        Ok(response)
    }

    async fn get_ledger_entry_response_impl(
        &self,
        req: pb::GetLedgerEntryRequest,
    ) -> Result<pb::GetLedgerEntryResponse, Status> {
        if req.key.len() != 32 {
            return Err(Status::invalid_argument("key must be 32 bytes"));
        }

        let mut params = Self::ledger_specifier_to_params(
            req.ledger.as_ref().and_then(|spec| spec.ledger.as_ref()),
            "ledger",
        )?;
        Self::apply_request_identity(&mut params, &req.client_ip, "");
        params.insert("binary".to_string(), json!(true));
        params.insert("index".to_string(), json!(hex::encode_upper(&req.key)));

        let ctx = self.node.rpc_read_context();
        let ctx = Arc::clone(&*ctx);
        let result = xrpl::rpc::handlers::ledger_entry(&serde_json::Value::Object(params), &ctx)
            .map_err(map_rpc_error_to_status)?;
        let node_binary = hex::decode(
            result
                .get("node_binary")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Status::internal("ledger_entry omitted node_binary"))?,
        )
        .map_err(|_| Status::internal("ledger_entry returned invalid node_binary"))?;

        Ok(pb::GetLedgerEntryResponse {
            ledger_object: Some(ledger_object_from_key_data(req.key, node_binary)),
            ledger: Some(clone_or_current_ledger_specifier(req.ledger.as_ref())),
        })
    }

    async fn get_ledger_data_response_impl(
        &self,
        req: pb::GetLedgerDataRequest,
    ) -> Result<pb::GetLedgerDataResponse, Status> {
        if !req.marker.is_empty() && req.marker.len() != 32 {
            return Err(Status::invalid_argument("marker must be 32 bytes"));
        }
        if !req.end_marker.is_empty() && req.end_marker.len() != 32 {
            return Err(Status::invalid_argument("end_marker must be 32 bytes"));
        }
        let page = self
            .collect_ledger_page(
                req.ledger.as_ref().and_then(|spec| spec.ledger.as_ref()),
                "ledger",
                (!req.marker.is_empty()).then_some(req.marker.as_slice()),
                (!req.end_marker.is_empty()).then_some(req.end_marker.as_slice()),
                &req.client_ip,
                &req.user,
            )
            .await?;

        Ok(pb::GetLedgerDataResponse {
            ledger_index: page.ledger_index,
            ledger_hash: page.ledger_hash.clone(),
            ledger_objects: Some(pb::RawLedgerObjects {
                objects: raw_objects_from_page(&page, false),
            }),
            marker: page.marker.unwrap_or_default(),
            is_unlimited: Self::request_is_unlimited(&req.client_ip, &req.user),
        })
    }

    async fn get_ledger_diff_response_impl(
        &self,
        req: pb::GetLedgerDiffRequest,
    ) -> Result<pb::GetLedgerDiffResponse, Status> {
        let base = self
            .collect_ledger_page(
                req.base_ledger
                    .as_ref()
                    .and_then(|spec| spec.ledger.as_ref()),
                "base_ledger",
                None,
                None,
                &req.client_ip,
                "",
            )
            .await?;
        let desired = self
            .collect_ledger_page(
                req.desired_ledger
                    .as_ref()
                    .and_then(|spec| spec.ledger.as_ref()),
                "desired_ledger",
                None,
                None,
                &req.client_ip,
                "",
            )
            .await?;
        let objects = build_ledger_diff_objects(&base, &desired, req.include_blobs, true);
        Ok(pb::GetLedgerDiffResponse {
            ledger_objects: Some(pb::RawLedgerObjects { objects }),
        })
    }

    fn ledger_specifier_to_params(
        spec: Option<&pb::ledger_specifier::Ledger>,
        field: &str,
    ) -> Result<serde_json::Map<String, serde_json::Value>, Status> {
        let mut params = serde_json::Map::new();
        let Some(spec) = spec else {
            params.insert("ledger_index".to_string(), json!("current"));
            return Ok(params);
        };

        match spec {
            pb::ledger_specifier::Ledger::Shortcut(shortcut) => {
                let shortcut = pb::ledger_specifier::Shortcut::try_from(*shortcut)
                    .map_err(|_| Status::invalid_argument(format!("invalid {field}")))?;
                let value = match shortcut {
                    pb::ledger_specifier::Shortcut::Validated => "validated",
                    pb::ledger_specifier::Shortcut::Closed => "closed",
                    pb::ledger_specifier::Shortcut::Unspecified
                    | pb::ledger_specifier::Shortcut::Current => "current",
                };
                params.insert("ledger_index".to_string(), json!(value));
            }
            pb::ledger_specifier::Ledger::Sequence(sequence) => {
                params.insert("ledger_index".to_string(), json!(sequence.to_string()));
            }
            pb::ledger_specifier::Ledger::Hash(hash) => {
                if hash.len() != 32 {
                    return Err(Status::invalid_argument(format!("invalid {field}")));
                }
                params.insert("ledger_hash".to_string(), json!(hex::encode_upper(hash)));
            }
        }
        Ok(params)
    }

    async fn collect_ledger_page(
        &self,
        spec: Option<&pb::ledger_specifier::Ledger>,
        field: &str,
        marker: Option<&[u8]>,
        end_marker: Option<&[u8]>,
        client_ip: &str,
        user: &str,
    ) -> Result<LedgerPage, Status> {
        let mut params = Self::ledger_specifier_to_params(spec, field)?;
        Self::apply_request_identity(&mut params, client_ip, user);
        let ctx = self.node.rpc_read_context();
        let ctx = Arc::clone(&*ctx);
        let mut objects = BTreeMap::new();
        let mut next_marker = marker.map(|marker| marker.to_vec());
        let mut ledger_index: Option<u32> = None;
        let mut ledger_hash: Option<Vec<u8>> = None;
        let mut continuation_marker: Option<Vec<u8>>;

        loop {
            params.insert("limit".to_string(), json!(256u32));
            if let Some(ref current_marker) = next_marker {
                params.insert(
                    "marker".to_string(),
                    json!(hex::encode_upper(current_marker)),
                );
            } else {
                params.remove("marker");
            }

            let result =
                xrpl::rpc::handlers::ledger_data(&serde_json::Value::Object(params.clone()), &ctx)
                    .map_err(map_rpc_error_to_status)?;
            if ledger_index.is_none() {
                ledger_index = result
                    .get("ledger_index")
                    .and_then(|value| value.as_u64())
                    .and_then(|value| u32::try_from(value).ok());
                ledger_hash = result
                    .get("ledger_hash")
                    .and_then(|value| value.as_str())
                    .map(hex::decode)
                    .transpose()
                    .map_err(|_| Status::internal("ledger_data returned invalid ledger_hash"))?;
            }
            let state = result
                .get("state")
                .and_then(|value| value.as_array())
                .ok_or_else(|| Status::internal("ledger_data omitted state"))?;
            let mut hit_end_marker = false;
            for entry in state {
                let key = entry
                    .get("index")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Status::internal("ledger_data state entry omitted index"))?;
                let data = entry
                    .get("data")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Status::internal("ledger_data state entry omitted data"))?;
                let key = hex::decode(key)
                    .map_err(|_| Status::internal("ledger_data returned invalid index"))?;
                if key.len() != 32 {
                    return Err(Status::internal("ledger_data returned invalid index size"));
                }
                if let Some(end_marker) = end_marker {
                    if key.as_slice() >= end_marker {
                        hit_end_marker = true;
                        break;
                    }
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&key);
                let data = hex::decode(data)
                    .map_err(|_| Status::internal("ledger_data returned invalid data"))?;
                objects.insert(key_bytes, data);
            }

            if hit_end_marker {
                continuation_marker = None;
                break;
            }

            continuation_marker = result
                .get("marker")
                .and_then(|value| value.as_str())
                .map(hex::decode)
                .transpose()
                .map_err(|_| Status::internal("ledger_data returned invalid marker"))?;

            if continuation_marker.as_ref().is_none_or(|m| m.is_empty()) {
                continuation_marker = None;
                break;
            }

            next_marker = continuation_marker.clone();
        }

        Ok(LedgerPage {
            ledger_index: ledger_index
                .ok_or_else(|| Status::internal("ledger_data omitted ledger_index"))?,
            ledger_hash: ledger_hash
                .ok_or_else(|| Status::internal("ledger_data omitted ledger_hash"))?,
            objects,
            marker: continuation_marker,
        })
    }
}

fn build_ledger_diff_objects(
    base: &LedgerPage,
    desired: &LedgerPage,
    include_blobs: bool,
    include_neighbors: bool,
) -> Vec<pb::RawLedgerObject> {
    let desired_keys: Vec<[u8; 32]> = desired.objects.keys().copied().collect();
    let mut keys: BTreeSet<[u8; 32]> = base.objects.keys().copied().collect();
    keys.extend(desired_keys.iter().copied());

    let mut objects = Vec::with_capacity(keys.len());
    for key in keys {
        let base_data = base.objects.get(&key);
        let desired_data = desired.objects.get(&key);
        let mod_type = match (base_data, desired_data) {
            (None, Some(_)) => pb::raw_ledger_object::ModificationType::Created,
            (Some(_), None) => pb::raw_ledger_object::ModificationType::Deleted,
            (Some(base_data), Some(desired_data)) if base_data != desired_data => {
                pb::raw_ledger_object::ModificationType::Modified
            }
            _ => continue,
        };
        let (predecessor, successor) = if include_neighbors {
            ledger_neighbors(&desired_keys, key)
        } else {
            (Vec::new(), Vec::new())
        };
        objects.push(pb::RawLedgerObject {
            data: if include_blobs {
                desired_data.cloned().unwrap_or_default()
            } else {
                Vec::new()
            },
            key: key.to_vec(),
            mod_type: mod_type as i32,
            predecessor,
            successor,
        });
    }

    objects
}

fn ledger_neighbors(keys: &[[u8; 32]], key: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    match keys.binary_search(&key) {
        Ok(index) => {
            let predecessor = index
                .checked_sub(1)
                .and_then(|idx| keys.get(idx))
                .map(|value| value.to_vec())
                .unwrap_or_default();
            let successor = keys
                .get(index + 1)
                .map(|value| value.to_vec())
                .unwrap_or_default();
            (predecessor, successor)
        }
        Err(index) => {
            let predecessor = index
                .checked_sub(1)
                .and_then(|idx| keys.get(idx))
                .map(|value| value.to_vec())
                .unwrap_or_default();
            let successor = keys
                .get(index)
                .map(|value| value.to_vec())
                .unwrap_or_default();
            (predecessor, successor)
        }
    }
}

fn current_ledger_specifier() -> pb::LedgerSpecifier {
    pb::LedgerSpecifier {
        ledger: Some(pb::ledger_specifier::Ledger::Shortcut(
            pb::ledger_specifier::Shortcut::Current as i32,
        )),
    }
}

fn clone_or_current_ledger_specifier(spec: Option<&pb::LedgerSpecifier>) -> pb::LedgerSpecifier {
    spec.cloned().unwrap_or_else(current_ledger_specifier)
}

fn ledger_object_from_key_data(key: Vec<u8>, data: Vec<u8>) -> pb::RawLedgerObject {
    pb::RawLedgerObject {
        data,
        key,
        mod_type: pb::raw_ledger_object::ModificationType::Unspecified as i32,
        predecessor: Vec::new(),
        successor: Vec::new(),
    }
}

fn raw_objects_from_page(page: &LedgerPage, include_neighbors: bool) -> Vec<pb::RawLedgerObject> {
    let desired_keys: Vec<[u8; 32]> = page.objects.keys().copied().collect();
    page.objects
        .iter()
        .map(|(key, data)| {
            let (predecessor, successor) = if include_neighbors {
                ledger_neighbors(&desired_keys, *key)
            } else {
                (Vec::new(), Vec::new())
            };
            pb::RawLedgerObject {
                data: data.clone(),
                key: key.to_vec(),
                mod_type: pb::raw_ledger_object::ModificationType::Unspecified as i32,
                predecessor,
                successor,
            }
        })
        .collect()
}

impl GrpcService {
    async fn submit_response_impl(
        &self,
        req: pb::SubmitRequest,
    ) -> Result<pb::SubmitResponse, Status> {
        if req.tx_blob.is_empty() {
            return Err(Status::invalid_argument("missing tx_blob"));
        }

        let rpc_req = xrpl::rpc::RpcRequest {
            method: "submit".to_string(),
            params: json!({
                "tx_blob": hex::encode_upper(req.tx_blob),
            }),
            id: serde_json::Value::Null,
        };
        let reply = self.node.dispatch_write_rpc(rpc_req).await;
        let result = reply.result;

        if result.get("status").and_then(|value| value.as_str()) == Some("error") {
            let code = result
                .get("error")
                .and_then(|value| value.as_str())
                .unwrap_or("internal");
            let message = result
                .get("error_message")
                .and_then(|value| value.as_str())
                .unwrap_or("submit failed");
            return Err(match code {
                "invalidParams" | "invalid_params" => Status::invalid_argument(message),
                "forbidden" => Status::permission_denied(message),
                _ => Status::internal(message),
            });
        }

        Ok(pb::SubmitResponse {
            status: result
                .get("status")
                .and_then(|value| value.as_str())
                .unwrap_or("success")
                .to_string(),
            accepted: result
                .get("accepted")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            applied: result
                .get("applied")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            broadcast: result
                .get("broadcast")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            engine_result: result
                .get("engine_result")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            engine_result_code: result
                .get("engine_result_code")
                .and_then(|value| value.as_i64())
                .and_then(|value| i32::try_from(value).ok())
                .unwrap_or_default(),
            engine_result_message: result
                .get("engine_result_message")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            tx_hash: result
                .get("tx_json")
                .and_then(|value| value.get("hash"))
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            message: result
                .get("engine_result_message")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
        })
    }
}

#[tonic::async_trait]
impl XrpLedgerApiService for GrpcService {
    async fn get_ledger(
        &self,
        request: Request<pb::GetLedgerRequest>,
    ) -> Result<Response<pb::GetLedgerResponse>, Status> {
        Ok(Response::new(
            self.get_ledger_response_impl(request.into_inner()).await?,
        ))
    }

    async fn get_ledger_entry(
        &self,
        request: Request<pb::GetLedgerEntryRequest>,
    ) -> Result<Response<pb::GetLedgerEntryResponse>, Status> {
        Ok(Response::new(
            self.get_ledger_entry_response_impl(request.into_inner())
                .await?,
        ))
    }

    async fn get_ledger_data(
        &self,
        request: Request<pb::GetLedgerDataRequest>,
    ) -> Result<Response<pb::GetLedgerDataResponse>, Status> {
        Ok(Response::new(
            self.get_ledger_data_response_impl(request.into_inner())
                .await?,
        ))
    }

    async fn get_ledger_diff(
        &self,
        request: Request<pb::GetLedgerDiffRequest>,
    ) -> Result<Response<pb::GetLedgerDiffResponse>, Status> {
        Ok(Response::new(
            self.get_ledger_diff_response_impl(request.into_inner())
                .await?,
        ))
    }
}

#[tonic::async_trait]
impl XLedgRSv2Beta for GrpcService {
    async fn get_server_info(
        &self,
        _request: Request<pb::GetServerInfoRequest>,
    ) -> Result<Response<pb::GetServerInfoResponse>, Status> {
        let snapshot = self.node.rpc_snapshot();
        let snapshot = Arc::clone(&*snapshot);
        let ledger_hash = hex::decode(&snapshot.ledger_hash).unwrap_or_default();
        let response = pb::GetServerInfoResponse {
            build_version: snapshot.build_version.to_string(),
            ledger_seq: snapshot.ledger_seq,
            ledger_hash,
            peer_count: snapshot.peer_count as u32,
            object_count: snapshot.object_count as u64,
            network_id: snapshot.network_id,
            sync_done: snapshot.sync_done,
            load_factor: snapshot.load_snapshot.load_factor_server(),
            grpc_addr: self.local_addr.to_string(),
        };
        Ok(Response::new(response))
    }

    async fn submit(
        &self,
        request: Request<pb::SubmitRequest>,
    ) -> Result<Response<pb::SubmitResponse>, Status> {
        Ok(Response::new(
            self.submit_response_impl(request.into_inner()).await?,
        ))
    }
}

fn map_rpc_error_to_status(err: xrpl::rpc::RpcError) -> Status {
    let code = err.code;
    match code {
        "lgrNotFound" => Status::not_found(err.message),
        "invalidParams" | "invalid_params" => Status::invalid_argument(err.message),
        "forbidden" => Status::permission_denied(err.message),
        _ => Status::internal(err.message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_server_info_response_uses_snapshot_values() {
        let node = Arc::new(xrpl::node::Node::new(xrpl::node::NodeConfig::default()));
        let service = GrpcService {
            node,
            local_addr: "127.0.0.1:50051".parse().unwrap(),
        };
        let snapshot = service.node.rpc_snapshot();
        let snapshot = Arc::clone(&*snapshot);
        let response = pb::GetServerInfoResponse {
            build_version: snapshot.build_version.to_string(),
            ledger_seq: snapshot.ledger_seq,
            ledger_hash: hex::decode(&snapshot.ledger_hash).unwrap_or_default(),
            peer_count: snapshot.peer_count as u32,
            object_count: snapshot.object_count as u64,
            network_id: snapshot.network_id,
            sync_done: snapshot.sync_done,
            load_factor: snapshot.load_snapshot.load_factor_server(),
            grpc_addr: service.local_addr.to_string(),
        };

        assert_eq!(response.build_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(response.grpc_addr, "127.0.0.1:50051");
        assert_eq!(response.ledger_hash.len(), 32);
    }

    #[tokio::test]
    async fn get_ledger_returns_current_snapshot_when_unqualified() {
        let node = Arc::new(xrpl::node::Node::new(xrpl::node::NodeConfig::default()));
        node.update_rpc_snapshot().await;
        let service = GrpcService {
            node: node.clone(),
            local_addr: "127.0.0.1:50051".parse().unwrap(),
        };

        let response = service
            .get_ledger_response_impl(pb::GetLedgerRequest {
                ledger: Some(pb::LedgerSpecifier {
                    ledger: Some(pb::ledger_specifier::Ledger::Shortcut(
                        pb::ledger_specifier::Shortcut::Current as i32,
                    )),
                }),
                transactions: false,
                expand: false,
                get_objects: false,
                client_ip: String::new(),
                user: String::new(),
                get_object_neighbors: false,
            })
            .await
            .expect("current ledger should be available");

        assert!(!response.ledger_header.is_empty());
        assert!(response.validated);
    }

    #[tokio::test]
    async fn get_ledger_marks_forwarded_user_as_unlimited() {
        let node = Arc::new(xrpl::node::Node::new(xrpl::node::NodeConfig::default()));
        node.update_rpc_snapshot().await;
        let service = GrpcService {
            node,
            local_addr: "127.0.0.1:50051".parse().unwrap(),
        };

        let response = service
            .get_ledger_response_impl(pb::GetLedgerRequest {
                ledger: Some(pb::LedgerSpecifier {
                    ledger: Some(pb::ledger_specifier::Ledger::Shortcut(
                        pb::ledger_specifier::Shortcut::Current as i32,
                    )),
                }),
                transactions: false,
                expand: false,
                get_objects: false,
                client_ip: String::new(),
                user: "secure-gateway".to_string(),
                get_object_neighbors: false,
            })
            .await
            .expect("current ledger should be available");

        assert!(response.is_unlimited);
    }

    #[tokio::test]
    async fn submit_rejects_empty_blob() {
        let node = Arc::new(xrpl::node::Node::new(xrpl::node::NodeConfig::default()));
        let service = GrpcService {
            node,
            local_addr: "127.0.0.1:50051".parse().unwrap(),
        };

        let err = service
            .submit(Request::new(pb::SubmitRequest {
                tx_blob: Vec::new(),
            }))
            .await
            .expect_err("empty blob should be rejected");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn get_ledger_data_returns_current_state_page() {
        let node = Arc::new(xrpl::node::Node::new(xrpl::node::NodeConfig::default()));
        node.update_rpc_snapshot().await;
        let service = GrpcService {
            node,
            local_addr: "127.0.0.1:50051".parse().unwrap(),
        };

        let response = service
            .get_ledger_data_response_impl(pb::GetLedgerDataRequest {
                ledger: Some(pb::LedgerSpecifier {
                    ledger: Some(pb::ledger_specifier::Ledger::Shortcut(
                        pb::ledger_specifier::Shortcut::Current as i32,
                    )),
                }),
                marker: Vec::new(),
                end_marker: Vec::new(),
                client_ip: String::new(),
                user: String::new(),
            })
            .await
            .expect("ledger data should be available");

        assert!(response.ledger_index > 0);
        assert_eq!(response.ledger_hash.len(), 32);
    }

    #[tokio::test]
    async fn get_ledger_data_marks_forwarded_user_as_unlimited() {
        let node = Arc::new(xrpl::node::Node::new(xrpl::node::NodeConfig::default()));
        node.update_rpc_snapshot().await;
        let service = GrpcService {
            node,
            local_addr: "127.0.0.1:50051".parse().unwrap(),
        };

        let response = service
            .get_ledger_data_response_impl(pb::GetLedgerDataRequest {
                ledger: Some(pb::LedgerSpecifier {
                    ledger: Some(pb::ledger_specifier::Ledger::Shortcut(
                        pb::ledger_specifier::Shortcut::Current as i32,
                    )),
                }),
                marker: Vec::new(),
                end_marker: Vec::new(),
                client_ip: String::new(),
                user: "secure-gateway".to_string(),
            })
            .await
            .expect("ledger data should be available");

        assert!(response.is_unlimited);
    }

    #[tokio::test]
    async fn get_ledger_entry_rejects_bad_index_size() {
        let node = Arc::new(xrpl::node::Node::new(xrpl::node::NodeConfig::default()));
        let service = GrpcService {
            node,
            local_addr: "127.0.0.1:50051".parse().unwrap(),
        };

        let err = service
            .get_ledger_entry_response_impl(pb::GetLedgerEntryRequest {
                ledger: Some(pb::LedgerSpecifier {
                    ledger: Some(pb::ledger_specifier::Ledger::Shortcut(
                        pb::ledger_specifier::Shortcut::Current as i32,
                    )),
                }),
                key: vec![1, 2, 3],
                client_ip: String::new(),
            })
            .await
            .expect_err("bad index should be rejected");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn build_ledger_diff_marks_created_modified_deleted_and_neighbors() {
        let mut base_objects = BTreeMap::new();
        base_objects.insert([1u8; 32], vec![1]);
        base_objects.insert([3u8; 32], vec![3]);
        base_objects.insert([5u8; 32], vec![5]);

        let mut desired_objects = BTreeMap::new();
        desired_objects.insert([1u8; 32], vec![1]);
        desired_objects.insert([2u8; 32], vec![22]);
        desired_objects.insert([3u8; 32], vec![33]);
        desired_objects.insert([6u8; 32], vec![6]);

        let base = LedgerPage {
            ledger_index: 1,
            ledger_hash: vec![1],
            objects: base_objects,
            marker: None,
        };
        let desired = LedgerPage {
            ledger_index: 2,
            ledger_hash: vec![2],
            objects: desired_objects,
            marker: None,
        };

        let diff = build_ledger_diff_objects(&base, &desired, true, true);
        assert_eq!(diff.len(), 4);

        let created = diff
            .iter()
            .find(|entry| entry.key == vec![2u8; 32])
            .expect("created entry missing");
        assert_eq!(
            created.mod_type,
            pb::raw_ledger_object::ModificationType::Created as i32
        );
        assert_eq!(created.data, vec![22]);
        assert_eq!(created.predecessor, vec![1u8; 32]);
        assert_eq!(created.successor, vec![3u8; 32]);

        let modified = diff
            .iter()
            .find(|entry| entry.key == vec![3u8; 32])
            .expect("modified entry missing");
        assert_eq!(
            modified.mod_type,
            pb::raw_ledger_object::ModificationType::Modified as i32
        );
        assert_eq!(modified.data, vec![33]);
        assert_eq!(modified.predecessor, vec![2u8; 32]);
        assert_eq!(modified.successor, vec![6u8; 32]);

        let deleted = diff
            .iter()
            .find(|entry| entry.key == vec![5u8; 32])
            .expect("deleted entry missing");
        assert_eq!(
            deleted.mod_type,
            pb::raw_ledger_object::ModificationType::Deleted as i32
        );
        assert!(deleted.data.is_empty());
        assert_eq!(deleted.predecessor, vec![3u8; 32]);
        assert_eq!(deleted.successor, vec![6u8; 32]);

        let created_tail = diff
            .iter()
            .find(|entry| entry.key == vec![6u8; 32])
            .expect("tail created entry missing");
        assert_eq!(
            created_tail.mod_type,
            pb::raw_ledger_object::ModificationType::Created as i32
        );
        assert_eq!(created_tail.data, vec![6]);
        assert_eq!(created_tail.predecessor, vec![3u8; 32]);
        assert!(created_tail.successor.is_empty());
    }

    #[test]
    fn ledger_specifier_to_params_maps_shortcuts() {
        let params = GrpcService::ledger_specifier_to_params(
            Some(&pb::ledger_specifier::Ledger::Shortcut(
                pb::ledger_specifier::Shortcut::Validated as i32,
            )),
            "base_ledger",
        )
        .expect("validated shortcut should map");

        assert_eq!(
            params.get("ledger_index").and_then(|v| v.as_str()),
            Some("validated")
        );
    }
}
