use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    xledgrs_host: String,

    #[arg(long, default_value_t = 5005)]
    xledgrs_port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    rippled_host: String,

    #[arg(long, default_value_t = 51234)]
    rippled_port: u16,

    #[arg(long, default_value_t = 300)]
    duration_secs: u64,

    #[arg(long, default_value_t = 5)]
    interval_secs: u64,

    #[arg(long)]
    output: PathBuf,

    #[arg(long, default_value_t = true)]
    include_metrics: bool,

    #[arg(long, default_value_t = 0)]
    getledger_pressure_concurrency: usize,

    #[arg(long, default_value_t = 0)]
    getledger_pressure_requests: usize,

    #[arg(long)]
    getledger_pressure_seq: Option<u32>,

    #[arg(long, default_value_t = false)]
    enforce_gates: bool,

    #[arg(long, default_value_t = 2)]
    max_ledger_lag: u64,

    #[arg(long, default_value_t = 20)]
    max_validated_age_secs: u64,

    #[arg(long, default_value_t = true)]
    require_validated_hash_match: bool,

    #[arg(long, default_value = "full,proposing,connected,syncing,tracking")]
    allowed_server_states: String,

    #[arg(long)]
    xledgrs_config: Option<PathBuf>,

    #[arg(long)]
    rippled_config: Option<PathBuf>,

    #[arg(long)]
    xledgrs_data_dir: Option<PathBuf>,

    #[arg(long)]
    rippled_data_dir: Option<PathBuf>,

    #[arg(long)]
    validator_list: Option<PathBuf>,

    #[arg(long, default_value = "unknown")]
    build_profile: String,
}

#[derive(Debug, Clone, Serialize)]
struct EndpointSample {
    ok: bool,
    error: Option<String>,
    server_state: Option<String>,
    network_ledger: Option<String>,
    validated_seq: Option<u64>,
    validated_hash: Option<String>,
    validated_age: Option<u64>,
    peers: Option<u64>,
    load_factor: Option<f64>,
    load_factor_server: Option<f64>,
    complete_ledgers: Option<String>,
    objects_stored: Option<u64>,
    leaf_count: Option<u64>,
    raw: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkSample {
    unix_ms: u128,
    elapsed_ms: u128,
    xledgrs: EndpointSample,
    rippled: EndpointSample,
    xledgrs_sync_metrics: Option<Value>,
    xledgrs_prometheus_metrics: Option<BTreeMap<String, f64>>,
    getledger_pressure: Option<GetLedgerPressureSample>,
}

#[derive(Debug, Serialize)]
struct BenchmarkHeader {
    kind: &'static str,
    started_unix_ms: u128,
    duration_secs: u64,
    interval_secs: u64,
    xledgrs: String,
    rippled: String,
    include_metrics: bool,
    getledger_pressure_concurrency: usize,
    getledger_pressure_requests: usize,
    getledger_pressure_seq: Option<u32>,
    gates: GateConfig,
    manifest: RunManifest,
}

#[derive(Debug, Clone, Serialize, Default)]
struct GetLedgerPressureSample {
    attempted: usize,
    ok: usize,
    errors: usize,
    elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
struct GateConfig {
    enforce: bool,
    max_ledger_lag: u64,
    max_validated_age_secs: u64,
    require_validated_hash_match: bool,
    allowed_server_states: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct GateViolation {
    elapsed_ms: u128,
    rule: &'static str,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct FileManifest {
    path: String,
    exists: bool,
    bytes: Option<u64>,
    sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RunManifest {
    git_commit: Option<String>,
    git_dirty: Option<bool>,
    executable: FileManifest,
    build_profile: String,
    os: String,
    kernel: Option<String>,
    xledgrs_config: Option<FileManifest>,
    rippled_config: Option<FileManifest>,
    xledgrs_data_dir: Option<String>,
    rippled_data_dir: Option<String>,
    validator_list: Option<FileManifest>,
    xledgrs_endpoint: String,
    rippled_endpoint: String,
    xledgrs_version_probe: Option<Value>,
    rippled_version_probe: Option<Value>,
}

#[derive(Debug, Default)]
struct Rollup {
    samples: u64,
    first_elapsed_ms: Option<u128>,
    last_elapsed_ms: Option<u128>,
    first_leaf_count: Option<u64>,
    last_leaf_count: Option<u64>,
    first_object_count: Option<u64>,
    last_object_count: Option<u64>,
    first_useful_nodes_total: Option<u64>,
    last_useful_nodes_total: Option<u64>,
    first_processed_responses_total: Option<u64>,
    last_processed_responses_total: Option<u64>,
    first_dropped_responses_total: Option<u64>,
    last_dropped_responses_total: Option<u64>,
    first_gate_lock_busy_total: Option<u64>,
    last_gate_lock_busy_total: Option<u64>,
    first_slow_route_messages_total: Option<u64>,
    last_slow_route_messages_total: Option<u64>,
    max_lock_wait_ms: u64,
    max_hold_ms: u64,
    max_batch_ms: u64,
    max_route_ms: u64,
    rippled_errors: std::collections::BTreeSet<String>,
    violations: Vec<GateViolation>,
    last_xledgrs: Option<EndpointSample>,
    last_rippled: Option<EndpointSample>,
}

#[derive(Debug, Serialize)]
struct BenchmarkSummary {
    kind: &'static str,
    samples: u64,
    elapsed_ms: Option<u128>,
    leaf_delta: Option<i128>,
    object_delta: Option<i128>,
    useful_nodes_delta: Option<i128>,
    processed_responses_delta: Option<i128>,
    dropped_responses_delta: Option<i128>,
    gate_lock_busy_delta: Option<i128>,
    slow_route_messages_delta: Option<i128>,
    max_lock_wait_ms: u64,
    max_hold_ms: u64,
    max_batch_ms: u64,
    max_route_ms: u64,
    rippled_errors: Vec<String>,
    verdict: &'static str,
    violations: Vec<GateViolation>,
    last_xledgrs: Option<EndpointSample>,
    last_rippled: Option<EndpointSample>,
}

impl Rollup {
    fn update(&mut self, sample: &BenchmarkSample, gates: &GateConfig) {
        self.samples = self.samples.saturating_add(1);
        if self.first_elapsed_ms.is_none() {
            self.first_elapsed_ms = Some(sample.elapsed_ms);
        }
        self.last_elapsed_ms = Some(sample.elapsed_ms);
        set_first_last(
            &mut self.first_leaf_count,
            &mut self.last_leaf_count,
            sample.xledgrs.leaf_count,
        );
        set_first_last(
            &mut self.first_object_count,
            &mut self.last_object_count,
            sample.xledgrs.objects_stored,
        );
        if let Some(error) = sample.rippled.error.as_ref() {
            self.rippled_errors.insert(error.clone());
        }
        self.violations.extend(evaluate_gates(sample, gates));
        if let Some(counters) = sample.xledgrs_sync_metrics.as_ref().and_then(|value| {
            value
                .get("counters")
                .and_then(|counters| counters.as_object())
        }) {
            set_first_last(
                &mut self.first_useful_nodes_total,
                &mut self.last_useful_nodes_total,
                counters.get("useful_nodes_total").and_then(Value::as_u64),
            );
            set_first_last(
                &mut self.first_processed_responses_total,
                &mut self.last_processed_responses_total,
                counters
                    .get("processed_responses_total")
                    .and_then(Value::as_u64),
            );
            set_first_last(
                &mut self.first_dropped_responses_total,
                &mut self.last_dropped_responses_total,
                counters
                    .get("dropped_responses_total")
                    .and_then(Value::as_u64),
            );
            set_first_last(
                &mut self.first_gate_lock_busy_total,
                &mut self.last_gate_lock_busy_total,
                counters.get("gate_lock_busy_total").and_then(Value::as_u64),
            );
            set_first_last(
                &mut self.first_slow_route_messages_total,
                &mut self.last_slow_route_messages_total,
                counters
                    .get("slow_route_messages_total")
                    .and_then(Value::as_u64),
            );
            self.max_lock_wait_ms = self.max_lock_wait_ms.max(
                counters
                    .get("max_lock_wait_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            );
            self.max_hold_ms = self.max_hold_ms.max(
                counters
                    .get("max_hold_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            );
            self.max_batch_ms = self.max_batch_ms.max(
                counters
                    .get("max_batch_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            );
            self.max_route_ms = self.max_route_ms.max(
                counters
                    .get("max_route_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            );
        }
        self.last_xledgrs = Some(sample.xledgrs.clone());
        self.last_rippled = Some(sample.rippled.clone());
    }

    fn finish(self) -> BenchmarkSummary {
        let verdict = if self.violations.is_empty() {
            "pass"
        } else {
            "fail"
        };
        BenchmarkSummary {
            kind: "live_sync_benchmark_summary",
            samples: self.samples,
            elapsed_ms: diff_u128(self.first_elapsed_ms, self.last_elapsed_ms),
            leaf_delta: diff_u64(self.first_leaf_count, self.last_leaf_count),
            object_delta: diff_u64(self.first_object_count, self.last_object_count),
            useful_nodes_delta: diff_u64(
                self.first_useful_nodes_total,
                self.last_useful_nodes_total,
            ),
            processed_responses_delta: diff_u64(
                self.first_processed_responses_total,
                self.last_processed_responses_total,
            ),
            dropped_responses_delta: diff_u64(
                self.first_dropped_responses_total,
                self.last_dropped_responses_total,
            ),
            gate_lock_busy_delta: diff_u64(
                self.first_gate_lock_busy_total,
                self.last_gate_lock_busy_total,
            ),
            slow_route_messages_delta: diff_u64(
                self.first_slow_route_messages_total,
                self.last_slow_route_messages_total,
            ),
            max_lock_wait_ms: self.max_lock_wait_ms,
            max_hold_ms: self.max_hold_ms,
            max_batch_ms: self.max_batch_ms,
            max_route_ms: self.max_route_ms,
            rippled_errors: self.rippled_errors.into_iter().collect(),
            verdict,
            violations: self.violations,
            last_xledgrs: self.last_xledgrs,
            last_rippled: self.last_rippled,
        }
    }
}

impl GateConfig {
    fn from_args(args: &Args) -> Self {
        let allowed_server_states = args
            .allowed_server_states
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        Self {
            enforce: args.enforce_gates,
            max_ledger_lag: args.max_ledger_lag,
            max_validated_age_secs: args.max_validated_age_secs,
            require_validated_hash_match: args.require_validated_hash_match,
            allowed_server_states,
        }
    }
}

fn set_first_last(first: &mut Option<u64>, last: &mut Option<u64>, value: Option<u64>) {
    if let Some(value) = value {
        if first.is_none() {
            *first = Some(value);
        }
        *last = Some(value);
    }
}

fn diff_u64(first: Option<u64>, last: Option<u64>) -> Option<i128> {
    Some(last? as i128 - first? as i128)
}

fn diff_u128(first: Option<u128>, last: Option<u128>) -> Option<u128> {
    Some(last?.saturating_sub(first?))
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn command_stdout(args: &[&str]) -> Option<String> {
    let (program, rest) = args.split_first()?;
    let output = Command::new(program).args(rest).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn file_manifest(path: &Path) -> FileManifest {
    let mut manifest = FileManifest {
        path: path.display().to_string(),
        exists: path.exists(),
        bytes: None,
        sha256: None,
    };
    let Ok(file) = File::open(path) else {
        return manifest;
    };
    let Ok(metadata) = file.metadata() else {
        return manifest;
    };
    if !metadata.is_file() {
        manifest.bytes = Some(metadata.len());
        return manifest;
    }
    manifest.bytes = Some(metadata.len());
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return manifest,
        }
    }
    manifest.sha256 = Some(hex::encode(hasher.finalize()));
    manifest
}

async fn build_manifest(args: &Args) -> RunManifest {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("<unknown>"));
    let xledgrs_version_probe =
        rpc_value(&args.xledgrs_host, args.xledgrs_port, "server_info").await;
    let rippled_version_probe =
        rpc_value(&args.rippled_host, args.rippled_port, "server_info").await;
    RunManifest {
        git_commit: command_stdout(&["git", "rev-parse", "HEAD"]),
        git_dirty: command_stdout(&["git", "status", "--porcelain"]).map(|s| !s.is_empty()),
        executable: file_manifest(&exe),
        build_profile: args.build_profile.clone(),
        os: std::env::consts::OS.to_string(),
        kernel: command_stdout(&["uname", "-a"]),
        xledgrs_config: args.xledgrs_config.as_deref().map(file_manifest),
        rippled_config: args.rippled_config.as_deref().map(file_manifest),
        xledgrs_data_dir: args
            .xledgrs_data_dir
            .as_ref()
            .map(|path| path.display().to_string()),
        rippled_data_dir: args
            .rippled_data_dir
            .as_ref()
            .map(|path| path.display().to_string()),
        validator_list: args.validator_list.as_deref().map(file_manifest),
        xledgrs_endpoint: format!("{}:{}", args.xledgrs_host, args.xledgrs_port),
        rippled_endpoint: format!("{}:{}", args.rippled_host, args.rippled_port),
        xledgrs_version_probe,
        rippled_version_probe,
    }
}

fn rpc_request_with_params(method: &str, params: Value) -> String {
    json!({
        "method": method,
        "params": [params],
        "id": 1,
    })
    .to_string()
}

fn rpc_request(method: &str) -> String {
    rpc_request_with_params(method, json!({}))
}

fn getledger_pressure_request(seq: Option<u32>) -> String {
    let mut params = serde_json::Map::new();
    if let Some(seq) = seq {
        params.insert("ledger_index".to_string(), json!(seq));
    } else {
        params.insert("ledger_index".to_string(), json!("validated"));
    }
    params.insert("transactions".to_string(), json!(false));
    params.insert("expand".to_string(), json!(false));
    rpc_request_with_params("ledger", Value::Object(params))
}

fn value_as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse::<u64>().ok()))
}

fn value_as_f64(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|s| s.parse::<f64>().ok()))
}

fn parse_endpoint_sample(body: &str) -> EndpointSample {
    let parsed: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(err) => {
            return EndpointSample {
                ok: false,
                error: Some(format!("invalid JSON: {err}")),
                server_state: None,
                network_ledger: None,
                validated_seq: None,
                validated_hash: None,
                validated_age: None,
                peers: None,
                load_factor: None,
                load_factor_server: None,
                complete_ledgers: None,
                objects_stored: None,
                leaf_count: None,
                raw: None,
            }
        }
    };
    let result = &parsed["result"];
    if result["status"].as_str() == Some("error") || result.get("error").is_some() {
        return EndpointSample {
            ok: false,
            error: result["error"]
                .as_str()
                .or_else(|| result["error_message"].as_str())
                .map(ToOwned::to_owned)
                .or_else(|| Some(result.to_string())),
            server_state: None,
            network_ledger: None,
            validated_seq: None,
            validated_hash: None,
            validated_age: None,
            peers: None,
            load_factor: None,
            load_factor_server: None,
            complete_ledgers: None,
            objects_stored: None,
            leaf_count: None,
            raw: Some(parsed),
        };
    }

    let info = result
        .get("info")
        .or_else(|| result.get("state"))
        .unwrap_or(result);
    let validated = &info["validated_ledger"];
    EndpointSample {
        ok: true,
        error: None,
        server_state: info["server_state"].as_str().map(ToOwned::to_owned),
        network_ledger: info["network_ledger"].as_str().map(ToOwned::to_owned),
        validated_seq: value_as_u64(&validated["seq"]),
        validated_hash: validated["hash"].as_str().map(ToOwned::to_owned),
        validated_age: value_as_u64(&validated["age"])
            .or_else(|| value_as_u64(&info["validated_ledger_age"])),
        peers: value_as_u64(&info["peers"]),
        load_factor: value_as_f64(&info["load_factor"]),
        load_factor_server: value_as_f64(&info["load_factor_server"]),
        complete_ledgers: info["complete_ledgers"].as_str().map(ToOwned::to_owned),
        objects_stored: value_as_u64(&info["objects_stored"]),
        leaf_count: value_as_u64(&info["leaf_count"]),
        raw: Some(parsed),
    }
}

fn push_violation(
    violations: &mut Vec<GateViolation>,
    sample: &BenchmarkSample,
    rule: &'static str,
    detail: impl Into<String>,
) {
    violations.push(GateViolation {
        elapsed_ms: sample.elapsed_ms,
        rule,
        detail: detail.into(),
    });
}

fn evaluate_endpoint(
    violations: &mut Vec<GateViolation>,
    sample: &BenchmarkSample,
    label: &'static str,
    endpoint: &EndpointSample,
    gates: &GateConfig,
) {
    if !endpoint.ok {
        push_violation(
            violations,
            sample,
            "endpoint_ok",
            format!(
                "{label} RPC failed: {}",
                endpoint.error.as_deref().unwrap_or("unknown")
            ),
        );
        return;
    }
    if let Some(age) = endpoint.validated_age {
        if age > gates.max_validated_age_secs {
            push_violation(
                violations,
                sample,
                "validated_age",
                format!(
                    "{label} validated ledger age {age}s exceeds {}s",
                    gates.max_validated_age_secs
                ),
            );
        }
    }
    if let Some(state) = endpoint.server_state.as_deref() {
        if !gates
            .allowed_server_states
            .iter()
            .any(|allowed| allowed == state)
        {
            push_violation(
                violations,
                sample,
                "server_state",
                format!(
                    "{label} server_state {state} not in {:?}",
                    gates.allowed_server_states
                ),
            );
        }
    }
}

fn evaluate_gates(sample: &BenchmarkSample, gates: &GateConfig) -> Vec<GateViolation> {
    let mut violations = Vec::new();
    evaluate_endpoint(&mut violations, sample, "xledgrs", &sample.xledgrs, gates);
    evaluate_endpoint(&mut violations, sample, "rippled", &sample.rippled, gates);

    if let (Some(local), Some(reference)) =
        (sample.xledgrs.validated_seq, sample.rippled.validated_seq)
    {
        let lag = local.abs_diff(reference);
        if lag > gates.max_ledger_lag {
            push_violation(
                &mut violations,
                sample,
                "validated_sequence_lag",
                format!(
                    "validated sequence lag {lag} exceeds {} (xledgrs={local} rippled={reference})",
                    gates.max_ledger_lag
                ),
            );
        }
    }

    if gates.require_validated_hash_match {
        if let (Some(local_seq), Some(reference_seq), Some(local_hash), Some(reference_hash)) = (
            sample.xledgrs.validated_seq,
            sample.rippled.validated_seq,
            sample.xledgrs.validated_hash.as_deref(),
            sample.rippled.validated_hash.as_deref(),
        ) {
            if local_seq == reference_seq && !local_hash.eq_ignore_ascii_case(reference_hash) {
                push_violation(
                    &mut violations,
                    sample,
                    "validated_hash_match",
                    format!(
                        "same sequence {local_seq} has different hashes xledgrs={local_hash} rippled={reference_hash}"
                    ),
                );
            }
        }
    }

    violations
}

async fn rpc_sample(host: &str, port: u16, method: &str) -> EndpointSample {
    let req = rpc_request(method);
    match xrpl::rpc_sync::http_post(host, port, &req).await {
        Ok(body) => parse_endpoint_sample(&body),
        Err(err) => EndpointSample {
            ok: false,
            error: Some(err.to_string()),
            server_state: None,
            network_ledger: None,
            validated_seq: None,
            validated_hash: None,
            validated_age: None,
            peers: None,
            load_factor: None,
            load_factor_server: None,
            complete_ledgers: None,
            objects_stored: None,
            leaf_count: None,
            raw: None,
        },
    }
}

async fn rpc_value(host: &str, port: u16, method: &str) -> Option<Value> {
    let req = rpc_request(method);
    let body = xrpl::rpc_sync::http_post(host, port, &req).await.ok()?;
    serde_json::from_str::<Value>(&body)
        .ok()?
        .get("result")
        .cloned()
}

async fn run_getledger_pressure(
    host: &str,
    port: u16,
    concurrency: usize,
    requests: usize,
    ledger_seq: Option<u32>,
) -> Option<GetLedgerPressureSample> {
    if concurrency == 0 || requests == 0 {
        return None;
    }
    let started = std::time::Instant::now();
    let request_body = std::sync::Arc::new(getledger_pressure_request(ledger_seq));
    let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ok = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let errors = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let workers = concurrency.min(requests);
    let mut handles = Vec::with_capacity(workers);

    for _ in 0..workers {
        let request_body = request_body.clone();
        let next = next.clone();
        let ok = ok.clone();
        let errors = errors.clone();
        let host = host.to_string();
        handles.push(tokio::spawn(async move {
            loop {
                let idx = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if idx >= requests {
                    break;
                }
                match xrpl::rpc_sync::http_post(&host, port, &request_body).await {
                    Ok(body) if response_is_success(&body) => {
                        ok.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    _ => {
                        errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    for handle in handles {
        if handle.await.is_err() {
            errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    Some(GetLedgerPressureSample {
        attempted: requests,
        ok: ok.load(std::sync::atomic::Ordering::Relaxed),
        errors: errors.load(std::sync::atomic::Ordering::Relaxed),
        elapsed_ms: started.elapsed().as_millis(),
    })
}

fn response_is_success(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let result = &value["result"];
    result["status"].as_str() != Some("error") && result.get("error").is_none()
}

async fn http_get(host: &str, port: u16, target: &str) -> anyhow::Result<String> {
    let mut stream = TcpStream::connect((host, port)).await?;
    let req = format!("GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
        .unwrap_or(0);
    let header = String::from_utf8_lossy(&raw[..split]);
    if !header.starts_with("HTTP/1.1 200") && !header.starts_with("HTTP/1.0 200") {
        anyhow::bail!(
            "GET {target} failed: {}",
            header.lines().next().unwrap_or("")
        );
    }
    Ok(String::from_utf8_lossy(&raw[split..]).into_owned())
}

fn parse_prometheus_metrics(text: &str) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, value)) = trimmed.rsplit_once(' ') else {
            continue;
        };
        let Some(value) = value.parse::<f64>().ok() else {
            continue;
        };
        let metric_name = name
            .split_once('{')
            .map(|(base, _)| base)
            .unwrap_or(name)
            .to_string();
        out.insert(metric_name, value);
    }
    out
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let gates = GateConfig::from_args(&args);
    let started = std::time::Instant::now();
    let started_unix_ms = unix_ms();
    let manifest = build_manifest(&args).await;
    let mut writer = BufWriter::new(File::create(&args.output)?);
    serde_json::to_writer(
        &mut writer,
        &BenchmarkHeader {
            kind: "live_sync_benchmark_start",
            started_unix_ms,
            duration_secs: args.duration_secs,
            interval_secs: args.interval_secs,
            xledgrs: format!("{}:{}", args.xledgrs_host, args.xledgrs_port),
            rippled: format!("{}:{}", args.rippled_host, args.rippled_port),
            include_metrics: args.include_metrics,
            getledger_pressure_concurrency: args.getledger_pressure_concurrency,
            getledger_pressure_requests: args.getledger_pressure_requests,
            getledger_pressure_seq: args.getledger_pressure_seq,
            gates: gates.clone(),
            manifest,
        },
    )?;
    writer.write_all(b"\n")?;

    let interval = Duration::from_secs(args.interval_secs.max(1));
    let duration = Duration::from_secs(args.duration_secs);
    let mut rollup = Rollup::default();
    loop {
        let elapsed = started.elapsed();
        let (xledgrs, rippled) = tokio::join!(
            rpc_sample(&args.xledgrs_host, args.xledgrs_port, "server_info"),
            rpc_sample(&args.rippled_host, args.rippled_port, "server_info"),
        );
        let (sync_metrics, prometheus_metrics) = if args.include_metrics {
            let (sync, metrics) = tokio::join!(
                rpc_value(&args.xledgrs_host, args.xledgrs_port, "sync_metrics"),
                http_get(&args.xledgrs_host, args.xledgrs_port, "/metrics"),
            );
            (
                sync,
                metrics.ok().map(|text| parse_prometheus_metrics(&text)),
            )
        } else {
            (None, None)
        };
        let getledger_pressure = run_getledger_pressure(
            &args.xledgrs_host,
            args.xledgrs_port,
            args.getledger_pressure_concurrency,
            args.getledger_pressure_requests,
            args.getledger_pressure_seq,
        )
        .await;

        let sample = BenchmarkSample {
            unix_ms: unix_ms(),
            elapsed_ms: elapsed.as_millis(),
            xledgrs,
            rippled,
            xledgrs_sync_metrics: sync_metrics,
            xledgrs_prometheus_metrics: prometheus_metrics,
            getledger_pressure,
        };
        rollup.update(&sample, &gates);
        serde_json::to_writer(&mut writer, &sample)?;
        writer.write_all(b"\n")?;
        writer.flush()?;

        if elapsed >= duration {
            break;
        }
        tokio::time::sleep(interval).await;
    }

    let summary = rollup.finish();
    let gate_failed = gates.enforce && summary.verdict == "fail";
    serde_json::to_writer(&mut writer, &summary)?;
    writer.write_all(b"\n")?;
    writer.flush()?;

    if gate_failed {
        anyhow::bail!(
            "live sync benchmark gates failed with {} violation(s)",
            summary.violations.len()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_prometheus_metrics_without_label_cardinality() {
        let text = r#"
# TYPE xledgrs_sync_active gauge
xledgrs_sync_active 1
xledgrs_job_waiting{job_type="ledger_data"} 4
xledgrs_job_waiting{job_type="path_requests"} 2
"#;
        let metrics = super::parse_prometheus_metrics(text);
        assert_eq!(metrics.get("xledgrs_sync_active"), Some(&1.0));
        assert_eq!(metrics.get("xledgrs_job_waiting"), Some(&2.0));
    }

    #[test]
    fn rollup_reports_counter_deltas() {
        let mut rollup = super::Rollup::default();
        let gates = super::GateConfig {
            enforce: false,
            max_ledger_lag: 2,
            max_validated_age_secs: 20,
            require_validated_hash_match: true,
            allowed_server_states: vec!["syncing".to_string()],
        };
        let first = super::BenchmarkSample {
            unix_ms: 1,
            elapsed_ms: 0,
            xledgrs: super::EndpointSample {
                ok: true,
                error: None,
                server_state: Some("syncing".to_string()),
                network_ledger: None,
                validated_seq: Some(0),
                validated_hash: None,
                validated_age: None,
                peers: Some(4),
                load_factor: None,
                load_factor_server: None,
                complete_ledgers: None,
                objects_stored: Some(10),
                leaf_count: Some(20),
                raw: None,
            },
            rippled: super::EndpointSample {
                ok: false,
                error: Some("refused".to_string()),
                server_state: None,
                network_ledger: None,
                validated_seq: None,
                validated_hash: None,
                validated_age: None,
                peers: None,
                load_factor: None,
                load_factor_server: None,
                complete_ledgers: None,
                objects_stored: None,
                leaf_count: None,
                raw: None,
            },
            xledgrs_sync_metrics: Some(serde_json::json!({
                "counters": {
                    "useful_nodes_total": 100,
                    "processed_responses_total": 5,
                    "dropped_responses_total": 0,
                    "gate_lock_busy_total": 0,
                    "slow_route_messages_total": 1,
                    "max_lock_wait_ms": 7,
                    "max_hold_ms": 8,
                    "max_batch_ms": 9,
                    "max_route_ms": 10
                }
            })),
            xledgrs_prometheus_metrics: None,
            getledger_pressure: None,
        };
        let mut last = first.clone();
        last.elapsed_ms = 30_000;
        last.xledgrs.leaf_count = Some(30);
        last.xledgrs.objects_stored = Some(15);
        last.xledgrs_sync_metrics = Some(serde_json::json!({
            "counters": {
                "useful_nodes_total": 180,
                "processed_responses_total": 9,
                "dropped_responses_total": 0,
                "gate_lock_busy_total": 2,
                "slow_route_messages_total": 3,
                "max_lock_wait_ms": 11,
                "max_hold_ms": 8,
                "max_batch_ms": 12,
                "max_route_ms": 10
            }
        }));
        rollup.update(&first, &gates);
        rollup.update(&last, &gates);
        let summary = rollup.finish();
        assert_eq!(summary.samples, 2);
        assert_eq!(summary.elapsed_ms, Some(30_000));
        assert_eq!(summary.leaf_delta, Some(10));
        assert_eq!(summary.object_delta, Some(5));
        assert_eq!(summary.useful_nodes_delta, Some(80));
        assert_eq!(summary.processed_responses_delta, Some(4));
        assert_eq!(summary.gate_lock_busy_delta, Some(2));
        assert_eq!(summary.slow_route_messages_delta, Some(2));
        assert_eq!(summary.max_lock_wait_ms, 11);
        assert_eq!(summary.max_batch_ms, 12);
        assert_eq!(summary.rippled_errors, vec!["refused".to_string()]);
    }

    #[test]
    fn builds_getledger_pressure_request_for_validated_or_sequence() {
        let validated = super::getledger_pressure_request(None);
        let parsed: serde_json::Value = serde_json::from_str(&validated).unwrap();
        assert_eq!(parsed["method"], "ledger");
        assert_eq!(parsed["params"][0]["ledger_index"], "validated");
        assert_eq!(parsed["params"][0]["transactions"], false);

        let sequenced = super::getledger_pressure_request(Some(123));
        let parsed: serde_json::Value = serde_json::from_str(&sequenced).unwrap();
        assert_eq!(parsed["params"][0]["ledger_index"], 123);
    }

    #[test]
    fn classifies_pressure_rpc_success_and_errors() {
        assert!(super::response_is_success(
            r#"{"result":{"status":"success"}}"#
        ));
        assert!(!super::response_is_success(
            r#"{"result":{"error":"tooBusy"}}"#
        ));
        assert!(!super::response_is_success("not json"));
    }
}
