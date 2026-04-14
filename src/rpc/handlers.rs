//! RPC method handlers — one function per rippled API method.
//!
//! Each handler takes `&RpcRequest` params and `&NodeContext`, returns
//! `Result<Value, RpcError>`. Response shapes match rippled exactly.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::crypto::base58::decode_account;

use crate::rpc::types::RpcError;
use crate::rpc::NodeContext;

fn lgr_not_found() -> RpcError {
    RpcError { code: "lgrNotFound", error_code: 21, message: "ledgerNotFound".into(), extra: None }
}

fn invalid_field(name: &str) -> RpcError {
    RpcError::invalid_params(&format!("Invalid field '{name}'."))
}

fn invalid_field_not_string(name: &str) -> RpcError {
    RpcError::invalid_params(&format!("Invalid field '{name}', not string."))
}

fn act_malformed() -> RpcError {
    RpcError { code: "actMalformed", error_code: 35, message: "Account malformed.".into(), extra: None }
}

fn txn_not_found() -> RpcError {
    RpcError { code: "txnNotFound", error_code: 29, message: "Transaction not found.".into(), extra: None }
}

fn txn_not_found_searched_all(searched_all: bool) -> RpcError {
    RpcError {
        code: "txnNotFound",
        error_code: 29,
        message: "Transaction not found.".into(),
        extra: Some(serde_json::Map::from_iter([
            ("searched_all".to_string(), json!(searched_all)),
        ])),
    }
}

fn invalid_lgr_range() -> RpcError {
    RpcError {
        code: "invalidLgrRange",
        error_code: 79,
        message: "Ledger range is invalid.".into(),
        extra: None,
    }
}

fn excessive_lgr_range() -> RpcError {
    RpcError {
        code: "excessiveLgrRange",
        error_code: 78,
        message: "Ledger range exceeds 1000.".into(),
        extra: None,
    }
}

fn wrong_network(network_id: u16) -> RpcError {
    RpcError {
        code: "wrongNetwork",
        error_code: 4,
        message: format!(
            "Wrong network. You should submit this request to a node running on NetworkID: {network_id}"
        ),
        extra: None,
    }
}

fn parse_account_field(params: &Value, field: &str) -> Result<[u8; 20], RpcError> {
    let raw = params
        .get(field)
        .ok_or_else(|| RpcError::invalid_params(&format!("missing '{field}' field")))?;
    let s = raw.as_str().ok_or_else(|| invalid_field(field))?;
    decode_account(s).map_err(|_| act_malformed())
}

fn parse_hex_key_marker(params: &Value) -> Result<Option<[u8; 32]>, RpcError> {
    match params.get("marker") {
        None => Ok(None),
        Some(Value::String(s)) => {
            let v = hex::decode(s).map_err(|_| invalid_field("marker"))?;
            if v.len() != 32 {
                return Err(invalid_field("marker"));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&v);
            Ok(Some(k))
        }
        Some(_) => Err(invalid_field_not_string("marker")),
    }
}

fn parse_ledger_data_marker(params: &Value) -> Result<Option<[u8; 32]>, RpcError> {
    match params.get("marker") {
        None => Ok(None),
        Some(Value::String(s)) => {
            let v = hex::decode(s)
                .map_err(|_| RpcError::invalid_params("Invalid field 'marker', not valid."))?;
            if v.len() != 32 {
                return Err(RpcError::invalid_params("Invalid field 'marker', not valid."));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&v);
            Ok(Some(k))
        }
        Some(_) => Err(RpcError::invalid_params("Invalid field 'marker', not valid.")),
    }
}

fn parse_ledger_data_limit(params: &Value, default: usize, max: usize) -> Result<usize, RpcError> {
    match params.get("limit") {
        None => Ok(default),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(|v| (v as usize).min(max))
            .ok_or_else(|| RpcError::invalid_params("Invalid field 'limit', not integer.")),
        Some(_) => Err(RpcError::invalid_params("Invalid field 'limit', not integer.")),
    }
}

fn parse_limit_field(params: &Value, default: usize, max: usize) -> Result<usize, RpcError> {
    match params.get("limit") {
        None => Ok(default),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(|v| (v as usize).min(max))
            .ok_or_else(|| RpcError::invalid_params("Invalid field 'limit', not unsigned integer.")),
        Some(_) => Err(RpcError::invalid_params("Invalid field 'limit', not unsigned integer.")),
    }
}

fn parse_bool_field(params: &Value, field: &str) -> Result<Option<bool>, RpcError> {
    match params.get(field) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(invalid_field(field)),
    }
}

fn parse_i32_field(params: &Value, field: &str) -> Result<Option<i32>, RpcError> {
    match params.get(field) {
        None => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .and_then(|v| i32::try_from(v).ok())
            .map(Some)
            .ok_or_else(|| RpcError::invalid_params(&format!("invalid {field}"))),
        Some(Value::String(s)) => s
            .parse::<i32>()
            .map(Some)
            .map_err(|_| RpcError::invalid_params(&format!("invalid {field}"))),
        Some(_) => Err(RpcError::invalid_params(&format!("invalid {field}"))),
    }
}

fn normalize_iou_pair(
    a: &crate::transaction::amount::IouValue,
    b: &crate::transaction::amount::IouValue,
) -> (i64, i64) {
    if a.exponent == b.exponent {
        return (a.mantissa, b.mantissa);
    }
    if a.exponent < b.exponent {
        let shift = (b.exponent - a.exponent).min(18) as u32;
        let scaled_b = b.mantissa.saturating_mul(10i64.pow(shift));
        (a.mantissa, scaled_b)
    } else {
        let shift = (a.exponent - b.exponent).min(18) as u32;
        let scaled_a = a.mantissa.saturating_mul(10i64.pow(shift));
        (scaled_a, b.mantissa)
    }
}

fn iou_gt(
    a: &crate::transaction::amount::IouValue,
    b: &crate::transaction::amount::IouValue,
) -> bool {
    let (am, bm) = normalize_iou_pair(a, b);
    am > bm
}

fn decode_ripple_state_any(raw: &[u8]) -> Option<crate::ledger::trustline::RippleState> {
    crate::ledger::trustline::RippleState::decode_from_sle(raw)
        .or_else(|| crate::ledger::trustline::RippleState::decode(raw))
}

fn parse_paychan_from_sle(raw: &[u8]) -> Option<crate::ledger::PayChannel> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    if parsed.entry_type != 0x0078 {
        return None;
    }

    let mut account = None;
    let mut destination = None;
    let mut amount = 0u64;
    let mut balance = 0u64;
    let mut public_key = Vec::new();
    let mut settle_delay = 0u32;
    let mut sequence = 0u32;
    let mut cancel_after = 0u32;
    let mut expiration = 0u32;
    let mut owner_node = 0u64;
    let mut destination_node = 0u64;
    let mut source_tag = None;
    let mut destination_tag = None;

    for field in parsed.fields {
        match (field.type_code, field.field_code) {
            (8, 1) if field.data.len() == 20 => {
                let mut v = [0u8; 20];
                v.copy_from_slice(&field.data);
                account = Some(v);
            }
            (8, 3) if field.data.len() == 20 => {
                let mut v = [0u8; 20];
                v.copy_from_slice(&field.data);
                destination = Some(v);
            }
            (6, 1) => {
                if let Ok((crate::transaction::amount::Amount::Xrp(v), _)) =
                    crate::transaction::amount::Amount::from_bytes(&field.data)
                {
                    amount = v;
                }
            }
            (6, 2) => {
                if let Ok((crate::transaction::amount::Amount::Xrp(v), _)) =
                    crate::transaction::amount::Amount::from_bytes(&field.data)
                {
                    balance = v;
                }
            }
            (7, 1) => public_key = field.data,
            (2, 39) if field.data.len() == 4 => {
                settle_delay = u32::from_be_bytes(field.data[..4].try_into().ok()?);
            }
            (2, 4) if field.data.len() == 4 => {
                sequence = u32::from_be_bytes(field.data[..4].try_into().ok()?);
            }
            (2, 10) if field.data.len() == 4 => {
                expiration = u32::from_be_bytes(field.data[..4].try_into().ok()?);
            }
            (2, 36) if field.data.len() == 4 => {
                cancel_after = u32::from_be_bytes(field.data[..4].try_into().ok()?);
            }
            (2, 3) if field.data.len() == 4 => {
                source_tag = Some(u32::from_be_bytes(field.data[..4].try_into().ok()?));
            }
            (2, 14) if field.data.len() == 4 => {
                destination_tag = Some(u32::from_be_bytes(field.data[..4].try_into().ok()?));
            }
            (3, 4) if field.data.len() == 8 => {
                owner_node = u64::from_be_bytes(field.data[..8].try_into().ok()?);
            }
            (3, 9) if field.data.len() == 8 => {
                destination_node = u64::from_be_bytes(field.data[..8].try_into().ok()?);
            }
            _ => {}
        }
    }

    Some(crate::ledger::PayChannel {
        account: account?,
        destination: destination?,
        amount,
        balance,
        settle_delay,
        public_key,
        sequence,
        cancel_after,
        expiration,
        owner_node,
        destination_node,
        source_tag,
        destination_tag,
        raw_sle: None,
    })
}

fn parse_ledger_index(params: &Value, current_seq: u32) -> Result<Option<u32>, RpcError> {
    let Some(raw) = params.get("ledger_index") else {
        return Ok(None);
    };

    match raw {
        Value::Number(n) => n
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .map(Some)
            .ok_or_else(|| RpcError::invalid_params("invalid ledger_index")),
        Value::String(s) if s == "validated" || s == "closed" || s == "current" => Ok(Some(current_seq)),
        Value::String(s) => s
            .parse::<u32>()
            .map(Some)
            .map_err(|_| RpcError::invalid_params("invalid ledger_index")),
        _ => Err(RpcError::invalid_params("invalid ledger_index")),
    }
}

fn parse_ledger_hash(
    params: &Value,
    ctx: &NodeContext,
) -> Result<Option<u32>, RpcError> {
    let Some(raw) = params.get("ledger_hash") else {
        return Ok(None);
    };
    let s = raw.as_str().ok_or_else(|| RpcError::invalid_params("invalid ledger_hash"))?;
    let bytes = hex::decode(s).map_err(|_| RpcError::invalid_params("invalid ledger_hash"))?;
    if bytes.len() != 32 {
        return Err(RpcError::invalid_params("invalid ledger_hash"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);

    if hash == ctx.ledger_header.hash {
        return Ok(Some(ctx.ledger_seq));
    }
    Ok(ctx.history.read().unwrap_or_else(|e| e.into_inner()).get_ledger_by_hash(&hash).map(|rec| rec.header.sequence))
}

fn resolve_ledger_selector(params: &Value, ctx: &NodeContext) -> Result<Option<u32>, RpcError> {
    if params.get("ledger_index").is_some() && params.get("ledger_hash").is_some() {
        return Err(RpcError::invalid_params(
            "Exactly one of 'ledger_hash' or 'ledger_index' can be specified.",
        ));
    }

    if params.get("ledger_hash").is_some() {
        return parse_ledger_hash(params, ctx).and_then(|opt| {
            if opt.is_none() {
                Err(lgr_not_found())
            } else {
                Ok(opt)
            }
        });
    }

    parse_ledger_index(params, ctx.ledger_seq)
}

fn historical_ledger_header(
    requested_seq: u32,
    ctx: &NodeContext,
) -> Result<crate::ledger::LedgerHeader, RpcError> {
    let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());
    match history.get_ledger(requested_seq) {
        Some(rec) => Ok(rec.header.clone()),
        None => Err(lgr_not_found()),
    }
}

fn historical_state_map(
    requested_seq: u32,
    ctx: &NodeContext,
    unavailable_message: &'static str,
) -> Result<(crate::ledger::LedgerHeader, crate::ledger::SHAMap), RpcError> {
    let header = historical_ledger_header(requested_seq, ctx)?;
    let map = {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        ls.historical_state_map_from_root(header.account_hash)
            .ok_or_else(|| RpcError::internal(unavailable_message))?
    };
    Ok((header, map))
}

fn collect_historical_state_entries(
    map: &mut crate::ledger::SHAMap,
) -> Result<Vec<(crate::ledger::Key, Vec<u8>)>, RpcError> {
    let mut entries = Vec::new();
    let mut next_key = map.first_key_lazy();
    while let Some(key) = next_key {
        let data = map
            .get(&key)
            .ok_or_else(|| RpcError::internal("historical ledger entry enumeration failed"))?;
        entries.push((key, data));
        next_key = map.upper_bound_lazy(&key);
    }
    Ok(entries)
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Get current process RSS in MB — in-process, no shell-out.
/// Uses mach task_info on macOS, /proc/self/statm on Linux.
/// Result is cached for 5 seconds to avoid overhead on hot paths.
pub fn get_memory_mb() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CACHED_MB: AtomicU64 = AtomicU64::new(0);
    static CACHED_AT: AtomicU64 = AtomicU64::new(0);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let prev = CACHED_AT.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 5 {
        return CACHED_MB.load(Ordering::Relaxed);
    }

    let mb = get_rss_mb_inner();
    CACHED_MB.store(mb, Ordering::Relaxed);
    CACHED_AT.store(now, Ordering::Relaxed);
    mb
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn get_rss_mb_inner() -> u64 {
    // mach task_info — zero syscall overhead vs shelling out to ps
    unsafe {
        let mut info: libc::mach_task_basic_info_data_t = std::mem::zeroed();
        let mut count = (std::mem::size_of::<libc::mach_task_basic_info_data_t>()
            / std::mem::size_of::<libc::natural_t>()) as libc::mach_msg_type_number_t;
        let kr = libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            &mut info as *mut _ as libc::task_info_t,
            &mut count,
        );
        if kr == libc::KERN_SUCCESS {
            info.resident_size as u64 / (1024 * 1024)
        } else {
            0
        }
    }
}

#[cfg(target_os = "linux")]
fn get_rss_mb_inner() -> u64 {
    // /proc/self/statm: fields are in pages; RSS is field 1
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4 / 1024) // 4 KiB pages → MB
        .unwrap_or(0)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn get_rss_mb_inner() -> u64 {
    0
}

// ── server_info ───────────────────────────────────────────────────────────────

/// Lock-free server_info using ArcSwap snapshot — never blocks during sync.
pub fn server_info_snapshot(
    snap: &crate::rpc::RpcSnapshot,
    follower: Option<&std::sync::Arc<crate::ledger::follow::FollowerState>>,
    rpc_sync: Option<&std::sync::Arc<crate::rpc_sync::RpcSyncState>>,
) -> Result<Value, RpcError> {
    const XRPL_EPOCH_OFFSET: u64 = 946_684_800;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let ledger_unix = snap.ledger_header.close_time as u64 + XRPL_EPOCH_OFFSET;
    let age = now_unix.saturating_sub(ledger_unix);

    // Format close_time as human-readable
    let close_time_human = {
        let unix_ts = snap.ledger_header.close_time as i64 + XRPL_EPOCH_OFFSET as i64;
        let secs = unix_ts % 60;
        let mins = (unix_ts / 60) % 60;
        let hours = (unix_ts / 3600) % 24;
        format!("{:02}:{:02}:{:02} UTC", hours, mins, secs)
    };

    let mut info = json!({
        "info": {
            "build_version":     snap.build_version,
            "network_id":        snap.network_id,
            "server_state":      if snap.sync_done && age < 60 { "full" }
                                 else if snap.sync_done { "tracking" }
                                 else if snap.peer_count > 0 { "syncing" }
                                 else { "disconnected" },
            "validation_quorum": snap.validation_quorum,
            "validated_ledger": {
                "seq":           snap.ledger_seq,
                "hash":          snap.ledger_hash,
                "base_fee_xrp":  snap.fees.base as f64 / 1_000_000.0,
                "reserve_base_xrp": snap.fees.reserve as f64 / 1_000_000.0,
                "reserve_inc_xrp":  snap.fees.increment as f64 / 1_000_000.0,
                "age":           age,
                "close_time":    snap.ledger_header.close_time,
                "close_time_human": close_time_human,
            },
            "validated_ledger_age": age,
            "load_factor":       1,
            "peers":             snap.peer_count,
            "pubkey_node":       snap.pubkey_node,
            "uptime":            snap.start_time.elapsed().as_secs(),
            "complete_ledgers":  snap.complete_ledgers,
            "memory_mb":         snap.memory_mb,
            "objects_stored":    snap.object_count,
        }
    });

    // Add validator key if configured
    if !snap.validator_key.is_empty() {
        info["info"]["validator_key"] = json!(snap.validator_key);
    }

    if let Some(ref fs) = follower {
        use std::sync::atomic::Ordering;
        info["info"]["follower"] = json!({
            "running":          fs.running.load(Ordering::Relaxed),
            "current_seq":      fs.current_seq.load(Ordering::Relaxed),
            "ledgers_applied":  fs.ledgers_applied.load(Ordering::Relaxed),
            "txs_applied":      fs.txs_applied.load(Ordering::Relaxed),
            "objects_created":  fs.objects_created.load(Ordering::Relaxed),
            "objects_modified": fs.objects_modified.load(Ordering::Relaxed),
            "objects_deleted":  fs.objects_deleted.load(Ordering::Relaxed),
            "hash_matches":     fs.hash_matches.load(Ordering::Relaxed),
            "hash_mismatches":  fs.hash_mismatches.load(Ordering::Relaxed),
        });
    }

    if let Some(ref rpc_state) = rpc_sync {
        use std::sync::atomic::Ordering;
        info["info"]["rpc_sync"] = json!({
            "running":  rpc_state.running.load(Ordering::Relaxed),
            "complete": rpc_state.complete.load(Ordering::Relaxed),
            "objects":  rpc_state.objects_downloaded.load(Ordering::Relaxed),
        });
    }

    Ok(info)
}

pub fn server_info(ctx: &NodeContext) -> Result<Value, RpcError> {
    // XRPL epoch starts at 2000-01-01 00:00:00 UTC = Unix timestamp 946684800
    const XRPL_EPOCH_OFFSET: u64 = 946_684_800;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ledger_unix = ctx.ledger_header.close_time as u64 + XRPL_EPOCH_OFFSET;
    let age = now_unix.saturating_sub(ledger_unix);

    // validation_quorum: 80% threshold of known validators + 1.
    // Use amendment count as a proxy for UNL size when ManifestCache isn't available.
    let unl_size = ctx.amendments.len().max(35) as u32; // floor at 35 (mainnet minimum)
    let validation_quorum: u32 = unl_size * 80 / 100 + 1;

    // Determine server_state from sync progress and ledger age
    let server_state = if ctx.ledger_seq == 0 {
        if ctx.peer_count > 0 { "syncing" } else { "disconnected" }
    } else if age < 60 {
        "full"
    } else if age < 300 {
        "tracking"
    } else {
        "syncing"
    };

    let mut info = json!({
        "info": {
            "build_version":         ctx.build_version,
            "network_id":            ctx.network_id,
            "server_state":          server_state,
            "validation_quorum":     validation_quorum,
            "validated_ledger": {
                "seq":               ctx.ledger_seq,
                "hash":              ctx.ledger_hash,
                "base_fee_xrp":      ctx.fees.base as f64 / 1_000_000.0,
                "reserve_base_xrp":  ctx.fees.reserve as f64 / 1_000_000.0,
                "reserve_inc_xrp":   ctx.fees.increment as f64 / 1_000_000.0,
                "age":               age,
                "close_time":        ctx.ledger_header.close_time,
            },
            "load_factor":           1,
            "peers":                 ctx.peer_count,
            "uptime":                ctx.start_time.elapsed().as_secs(),
            "complete_ledgers":      ctx.history.read().unwrap_or_else(|e| e.into_inner()).complete_ledgers(),
            "memory_mb":             get_memory_mb(),
            "objects_stored":        ctx.object_count,
        }
    });

    // Storage stats served via separate "storage_info" RPC to avoid
    // blocking server_info during heavy sync writes.

    // Add RPC sync progress if active
    if let Some(ref rpc_state) = ctx.rpc_sync_state {
        use std::sync::atomic::Ordering;
        info["info"]["rpc_sync"] = json!({
            "running":     rpc_state.running.load(Ordering::Relaxed),
            "complete":    rpc_state.complete.load(Ordering::Relaxed),
            "objects":     rpc_state.objects_downloaded.load(Ordering::Relaxed),
            "accounts":    rpc_state.accounts_parsed.load(Ordering::Relaxed),
            "pages":       rpc_state.pages_fetched.load(Ordering::Relaxed),
        });
    }

    // Add ledger follower progress if active
    if let Some(ref fs) = ctx.follower_state {
        use std::sync::atomic::Ordering;
        info["info"]["follower"] = json!({
            "running":          fs.running.load(Ordering::Relaxed),
            "current_seq":      fs.current_seq.load(Ordering::Relaxed),
            "ledgers_applied":  fs.ledgers_applied.load(Ordering::Relaxed),
            "txs_applied":      fs.txs_applied.load(Ordering::Relaxed),
            "objects_created":  fs.objects_created.load(Ordering::Relaxed),
            "objects_modified": fs.objects_modified.load(Ordering::Relaxed),
            "objects_deleted":  fs.objects_deleted.load(Ordering::Relaxed),
            "hash_matches":     fs.hash_matches.load(Ordering::Relaxed),
            "hash_mismatches":  fs.hash_mismatches.load(Ordering::Relaxed),
        });
    }

    Ok(info)
}

// ── ping ─────────────────────────────────────────────────────────────────────

pub fn storage_info(ctx: &NodeContext) -> Result<Value, RpcError> {
    if let Some(ref store) = ctx.storage {
        use std::sync::{Mutex, OnceLock};

        static CACHE: OnceLock<Mutex<Option<(u64, Value)>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(None));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Some((cached_at, value)) = cache.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if now.saturating_sub(*cached_at) < 5 {
                return Ok(value.clone());
            }
        }

        let s = store.stats();
        let value = json!({
            "engine": "SQLite + NuDB",
            "sqlite": {
                "transactions": s.transactions,
                "ledgers": s.ledgers,
            },
        });
        *cache.lock().unwrap_or_else(|e| e.into_inner()) = Some((now, value.clone()));
        Ok(value)
    } else {
        Err(RpcError { code: "noStorage", error_code: 73, message: "No storage configured.".into(), extra: None })
    }
}

pub fn ping() -> Result<Value, RpcError> {
    Ok(json!({}))
}

// ── fee ──────────────────────────────────────────────────────────────────────

pub fn fee(ctx: &NodeContext) -> Result<Value, RpcError> {
    use crate::ledger::pool::{FeeMetrics, BASE_LEVEL};

    let pool = ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
    let pool_size = pool.len();
    let metrics = &pool.metrics;
    let base = ctx.fees.base;

    // Compute escalated fee level for the next transaction
    let open_level = metrics.escalated_fee_level(pool_size as u64 + 1);
    let open_fee = FeeMetrics::fee_level_to_drops(open_level, base);
    let median_fee = FeeMetrics::fee_level_to_drops(metrics.escalation_multiplier, base);

    Ok(json!({
        "current_ledger_size": pool_size.to_string(),
        "current_queue_size":  "0",
        "drops": {
            "base_fee":         base.to_string(),
            "median_fee":       median_fee.to_string(),
            "minimum_fee":      base.to_string(),
            "open_ledger_fee":  open_fee.to_string(),
        },
        "expected_ledger_size": metrics.txns_expected.to_string(),
        "ledger_current_index": ctx.ledger_seq,
        "levels": {
            "median_level":     metrics.escalation_multiplier.to_string(),
            "minimum_level":    BASE_LEVEL.to_string(),
            "open_ledger_level": open_level.to_string(),
            "reference_level":  BASE_LEVEL.to_string(),
        },
        "max_queue_size": metrics.max_queue_size().to_string(),
    }))
}

// ── account_info ─────────────────────────────────────────────────────────────

pub fn account_info(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let address = params.get("account").and_then(Value::as_str).unwrap_or("");
    let account_id = parse_account_field(params, "account")?;
    let account_key = crate::ledger::keylet::account(&account_id).key;

    // Resolve ledger_index — rippled: lookupLedger validates the ledger exists
    let requested_seq = resolve_ledger_selector(params, ctx)?;

    let is_historical = requested_seq
        .map(|seq| seq != ctx.ledger_seq)
        .unwrap_or(false);

    let root = if is_historical {
        let target_seq = requested_seq.unwrap();
        let header = {
            let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());
            match history.get_ledger(target_seq) {
                Some(rec) => rec.header.clone(),
                None => return Err(lgr_not_found()),
            }
        };
        let raw = {
            let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            let mut map = ls
                .historical_state_map_from_root(header.account_hash)
                .ok_or_else(|| RpcError::internal("historical account lookup unavailable"))?;
            map.get(&account_key)
        };
        let raw = raw.ok_or_else(|| RpcError::not_found(address))?;
        crate::ledger::AccountRoot::decode(&raw)
            .map_err(|_| RpcError::not_found(address))?
    } else if let Some(ref cl) = ctx.closed_ledger {
        // New path: read from ClosedLedger via ReadView
        use crate::ledger::views::ReadView;
        let kl = crate::ledger::keylet::account(&account_id);
        let sle = cl.read(&kl).ok_or_else(|| RpcError::not_found(address))?;
        // Decode from SLE binary to typed struct for JSON response
        crate::ledger::AccountRoot::decode(sle.data())
            .map_err(|_| RpcError::not_found(address))?
    } else {
        // Legacy path: in-memory state with storage fallback
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        ls.get_account(&account_id)
            .cloned()
            .ok_or_else(|| RpcError::not_found(address))?
    };

    let key_hex = hex::encode_upper(
        crate::ledger::shamap_key(&account_id).0,
    );

    let mut account_data = json!({
        "Account":           crate::crypto::base58::encode_account(&account_id),
        "Balance":           root.balance.to_string(),
        "Flags":             root.flags,
        "LedgerEntryType":   "AccountRoot",
        "OwnerCount":        root.owner_count,
        "PreviousTxnID":     hex::encode_upper(&root.previous_txn_id),
        "PreviousTxnLgrSeq": root.previous_txn_lgr_seq,
        "Sequence":          root.sequence,
        "index":             key_hex,
    });

    // Optional AccountRoot fields — only include when set/non-zero
    if let Some(ref rk) = root.regular_key {
        account_data["RegularKey"] = json!(crate::crypto::base58::encode_account(rk));
    }
    if !root.domain.is_empty() {
        account_data["Domain"] = json!(hex::encode_upper(&root.domain));
    }
    if root.transfer_rate != 0 {
        account_data["TransferRate"] = json!(root.transfer_rate);
    }
    if root.tick_size != 0 {
        account_data["TickSize"] = json!(root.tick_size);
    }
    if root.ticket_count != 0 {
        account_data["TicketCount"] = json!(root.ticket_count);
    }
    if root.minted_nftokens != 0 {
        account_data["MintedNFTokens"] = json!(root.minted_nftokens);
    }
    if root.burned_nftokens != 0 {
        account_data["BurnedNFTokens"] = json!(root.burned_nftokens);
    }

    Ok(json!({
        "account_data":         account_data,
        "ledger_current_index": ctx.ledger_seq,
        "validated":            ctx.ledger_seq > 0,
    }))
}

// ── submit ────────────────────────────────────────────────────────────────────

// ── ripple_path_find ─────────────────────────────────────────────────────────

pub fn ripple_path_find(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    use crate::ledger::offer::{amount_to_f64, BookKey};
    use crate::transaction::amount::{Amount, Currency, IouValue};

    let src_addr = params.get("source_account").and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'source_account'"))?;
    let dst_addr = params.get("destination_account").and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'destination_account'"))?;
    let dst_amount_json = params.get("destination_amount")
        .ok_or_else(|| RpcError::invalid_params("missing 'destination_amount'"))?;

    let src_id = decode_account(src_addr)
        .map_err(|_| RpcError::invalid_params("invalid source_account"))?;
    let dst_id = decode_account(dst_addr)
        .map_err(|_| RpcError::invalid_params("invalid destination_account"))?;

    // Parse destination amount
    let (dst_currency, dst_issuer) = parse_currency_spec(Some(dst_amount_json))?;
    let dst_is_xrp = dst_currency == [0u8; 20];

    let dst_value = if dst_is_xrp {
        dst_amount_json.as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .or_else(|| dst_amount_json.as_u64().map(|v| v as f64))
            .unwrap_or(0.0)
    } else {
        dst_amount_json.get("value").and_then(Value::as_str)
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0)
    };

    let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
    let mut alternatives: Vec<Value> = Vec::new();

    // ── Direct XRP path (if destination wants XRP) ──────────────────────────
    if dst_is_xrp {
        // Source can send XRP directly if they have enough balance
        if let Some(src_acct) = ls.get_account(&src_id) {
            if src_acct.balance as f64 >= dst_value {
                alternatives.push(json!({
                    "paths_computed": [],
                    "source_amount": dst_value.to_string(),
                }));
            }
        }
    }

    // ── Direct trust line path (if source and dest share a trust line) ──────
    if !dst_is_xrp {
        let currency = Currency { code: dst_currency };
        if let Some(tl) = ls.get_trustline_for(&src_id, &dst_id, &currency) {
            let bal = tl.balance_for(&src_id);
            let bal_f = if bal.mantissa == 0 { 0.0 }
                else { bal.mantissa as f64 * 10f64.powi(bal.exponent) };
            if bal_f >= dst_value {
                alternatives.push(json!({
                    "paths_computed": [],
                    "source_amount": format_amount(&Amount::Iou {
                        value: IouValue::from_f64(dst_value),
                        currency: currency.clone(),
                        issuer: dst_issuer,
                    }),
                }));
            }
        }
    }

    // ── One-hop via XRP (IOU→XRP→IOU) ───────────────────────────────────────
    if !dst_is_xrp {
        // Check if there's an order book from XRP to destination currency
        let book_key = BookKey {
            pays_currency: dst_currency,
            pays_issuer:   dst_issuer,
            gets_currency: [0u8; 20], // XRP
            gets_issuer:   [0u8; 20],
        };
        if let Some(book) = ls.get_book(&book_key) {
            if !book.is_empty() {
                // Estimate cost: walk cheapest offers
                let mut xrp_needed = 0f64;
                let mut remaining = dst_value;
                for key in book.iter_by_quality() {
                    if remaining <= 0.0 { break; }
                    if let Some(off) = ls.get_offer(key) {
                        let gets_f = amount_to_f64(&off.taker_gets); // XRP
                        let pays_f = amount_to_f64(&off.taker_pays); // IOU
                        if pays_f <= 0.0 { continue; }
                        let fill = remaining.min(pays_f);
                        let cost = fill / pays_f * gets_f;
                        xrp_needed += cost;
                        remaining -= fill;
                    }
                }
                if remaining <= 0.0 {
                    alternatives.push(json!({
                        "paths_computed": [
                            [{"currency": "XRP"}]
                        ],
                        "source_amount": (xrp_needed.round().max(0.0) as u64).to_string(),
                    }));
                }
            }
        }
    }

    // ── One-hop via intermediary IOU ─────────────────────────────────────────
    // For each trust line the source holds, check if there's a book to the dest currency
    let src_lines = ls.trustlines_for_account(&src_id);
    for tl in &src_lines {
        let src_currency = &tl.currency;
        if src_currency.is_xrp() { continue; }
        if src_currency.code == dst_currency { continue; } // already handled above

        let peer = if src_id == tl.low_account { &tl.high_account } else { &tl.low_account };

        let book_key = BookKey {
            pays_currency: dst_currency,
            pays_issuer:   dst_issuer,
            gets_currency: src_currency.code,
            gets_issuer:   *peer,
        };
        if let Some(book) = ls.get_book(&book_key) {
            if !book.is_empty() {
                alternatives.push(json!({
                    "paths_computed": [
                        [{"currency": src_currency.to_ascii(), "issuer": crate::crypto::base58::encode_account(peer)}]
                    ],
                    "source_amount": format_amount(&Amount::Iou {
                        value: IouValue::from_f64(dst_value),
                        currency: src_currency.clone(),
                        issuer: *peer,
                    }),
                }));
            }
        }

        if alternatives.len() >= 6 { break; } // cap at 6
    }

    Ok(json!({
        "alternatives": alternatives,
        "destination_account": dst_addr,
        "destination_amount":  dst_amount_json,
    }))
}

// ── feature (amendments) ─────────────────────────────────────────────────────

pub fn feature(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    if let Some(name) = params.get("feature").and_then(Value::as_str) {
        let enabled = ctx.amendments.contains(name);
        let mut obj = serde_json::Map::new();
        obj.insert(name.to_string(), json!({ "enabled": enabled, "supported": enabled }));
        return Ok(json!({ "features": obj }));
    }

    let mut features = serde_json::Map::new();
    for name in &ctx.amendments {
        features.insert(name.clone(), json!({ "enabled": true, "supported": true }));
    }
    Ok(json!({ "features": features }))
}

/// XRPL engine result codes returned in the `submit` response.
// ── sign ─────────────────────────────────────────────────────────────────────

pub fn sign(params: &Value, _ctx: &NodeContext) -> Result<Value, RpcError> {
    use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
    use crate::transaction::{Amount, builder::TxBuilder};

    let secret = params.get("secret").and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'secret' field"))?;

    let tx_json = params.get("tx_json")
        .ok_or_else(|| RpcError::invalid_params("missing 'tx_json' field"))?;

    let kp = Secp256k1KeyPair::from_seed(secret)
        .map_err(|_| RpcError::invalid_params("invalid secret/seed"))?;
    let kp = KeyPair::Secp256k1(kp);

    // Extract fields from tx_json
    let tx_type = tx_json.get("TransactionType").and_then(Value::as_str).unwrap_or("Payment");
    let dest = tx_json.get("Destination").and_then(Value::as_str);
    let amount_val = tx_json.get("Amount");
    let fee = tx_json.get("Fee").and_then(Value::as_str)
        .and_then(|s| s.parse::<u64>().ok()).unwrap_or(12);
    let sequence = tx_json.get("Sequence").and_then(Value::as_u64).unwrap_or(0) as u32;

    let mut builder = match tx_type {
        "Payment"               => TxBuilder::payment(),
        "TrustSet"              => TxBuilder::trust_set(),
        "OfferCreate"           => TxBuilder::offer_create(),
        "OfferCancel"           => TxBuilder::offer_cancel(),
        "AccountSet"            => TxBuilder::account_set(),
        "EscrowCreate"          => TxBuilder::escrow_create(),
        "EscrowFinish"          => TxBuilder::escrow_finish(),
        "EscrowCancel"          => TxBuilder::escrow_cancel(),
        "CheckCreate"           => TxBuilder::check_create(),
        "CheckCash"             => TxBuilder::check_cash(),
        "CheckCancel"           => TxBuilder::check_cancel(),
        "PaymentChannelCreate"  => TxBuilder::paychan_create(),
        "PaymentChannelFund"    => TxBuilder::paychan_fund(),
        "PaymentChannelClaim"   => TxBuilder::paychan_claim(),
        _ => return Err(RpcError::invalid_params(&format!("unsupported tx type: {tx_type}"))),
    };

    builder = builder.account(&kp).fee(fee).sequence(sequence);

    if let Some(d) = dest {
        builder = builder.destination(d)
            .map_err(|_| RpcError::invalid_params("invalid Destination"))?;
    }

    if let Some(amt) = amount_val {
        if let Some(amount_obj) = amt.as_object() {
            // IOU: { "value": "100", "currency": "USD", "issuer": "r..." }
            let value_str = amount_obj.get("value").and_then(Value::as_str).unwrap_or("0");
            let currency_str = amount_obj.get("currency").and_then(Value::as_str).unwrap_or("USD");
            let issuer_str = amount_obj.get("issuer").and_then(Value::as_str)
                .ok_or_else(|| RpcError::invalid_params("IOU Amount missing 'issuer'"))?;
            let value_f64 = value_str.parse::<f64>()
                .map_err(|_| RpcError::invalid_params("invalid Amount value"))?;
            let currency = crate::transaction::amount::Currency::from_code(currency_str)
                .map_err(|_| RpcError::invalid_params("invalid Amount currency"))?;
            let issuer = decode_account(issuer_str)
                .map_err(|_| RpcError::invalid_params("invalid Amount issuer"))?;
            builder = builder.amount(Amount::Iou {
                value: crate::transaction::amount::IouValue::from_f64(value_f64),
                currency,
                issuer,
            });
        } else if let Some(drops_str) = amt.as_str() {
            if let Ok(drops) = drops_str.parse::<u64>() {
                builder = builder.amount(Amount::Xrp(drops));
            }
        } else if let Some(drops) = amt.as_u64() {
            builder = builder.amount(Amount::Xrp(drops));
        }
    }

    // Optional fields used by escrow, payment channel, and offer types
    if let Some(v) = tx_json.get("FinishAfter").and_then(Value::as_u64) {
        builder = builder.finish_after(v as u32);
    }
    if let Some(v) = tx_json.get("CancelAfter").and_then(Value::as_u64) {
        builder = builder.cancel_after(v as u32);
    }
    if let Some(v) = tx_json.get("OfferSequence").and_then(Value::as_u64) {
        builder = builder.offer_sequence(v as u32);
    }
    if let Some(v) = tx_json.get("SettleDelay").and_then(Value::as_u64) {
        builder = builder.settle_delay(v as u32);
    }
    if let Some(v) = tx_json.get("Expiration").and_then(Value::as_u64) {
        builder = builder.expiration(v as u32);
    }

    let signed = builder.sign(&kp)
        .map_err(|e| RpcError::internal(&format!("signing failed: {e}")))?;

    Ok(json!({
        "tx_blob": signed.blob_hex(),
        "tx_json": {
            "hash": signed.hash_hex(),
        },
    }))
}

// ── sign_for (multi-signing) ─────────────────────────────────────────────────

pub fn sign_for(params: &Value, _ctx: &NodeContext) -> Result<Value, RpcError> {
    use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
    use crate::transaction::{Amount, builder::TxBuilder, serialize};

    let secret = params.get("secret").and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'secret'"))?;
    let signer_addr = params.get("account").and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'account'"))?;
    let tx_json = params.get("tx_json")
        .ok_or_else(|| RpcError::invalid_params("missing 'tx_json'"))?;

    let signer_account_id = decode_account(signer_addr)
        .map_err(|_| RpcError::invalid_params("invalid signer account"))?;

    let kp = Secp256k1KeyPair::from_seed(secret)
        .map_err(|_| RpcError::invalid_params("invalid secret/seed"))?;
    let kp = KeyPair::Secp256k1(kp);

    // Build tx fields with EMPTY SigningPubKey (multi-sign requirement)
    let tx_type = tx_json.get("TransactionType").and_then(Value::as_str).unwrap_or("Payment");
    let dest = tx_json.get("Destination").and_then(Value::as_str);
    let fee = tx_json.get("Fee").and_then(Value::as_str)
        .and_then(|s| s.parse::<u64>().ok()).unwrap_or(12);
    let sequence = tx_json.get("Sequence").and_then(Value::as_u64).unwrap_or(0) as u32;
    let account_addr = tx_json.get("Account").and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'Account' in tx_json"))?;

    let mut builder = match tx_type {
        "Payment"     => TxBuilder::payment(),
        "TrustSet"    => TxBuilder::trust_set(),
        "OfferCreate" => TxBuilder::offer_create(),
        "AccountSet"  => TxBuilder::account_set(),
        _ => return Err(RpcError::invalid_params(&format!("unsupported tx type: {tx_type}"))),
    };

    builder = builder.account_address(account_addr)
        .map_err(|_| RpcError::invalid_params("invalid Account"))?
        .fee(fee).sequence(sequence);
    if let Some(d) = dest {
        builder = builder.destination(d)
            .map_err(|_| RpcError::invalid_params("invalid Destination"))?;
    }
    if let Some(amt) = tx_json.get("Amount").and_then(Value::as_str) {
        if let Ok(drops) = amt.parse::<u64>() {
            builder = builder.amount(Amount::Xrp(drops));
        }
    }

    // Build fields with empty signing pubkey for multi-sign
    let mut fields = builder.build_fields(vec![], None)
        .map_err(|e| RpcError::internal(&format!("field build failed: {e}")))?;

    // Compute multi-sign hash
    let hash = serialize::multisign_hash(&mut fields, &signer_account_id);

    // Sign with the signer's key
    let signature = kp.sign(&hash);
    let signing_pubkey = kp.public_key_bytes();

    Ok(json!({
        "tx_json": {
            "Signers": [{
                "Signer": {
                    "Account":       signer_addr,
                    "SigningPubKey":  hex::encode_upper(&signing_pubkey),
                    "TxnSignature":  hex::encode_upper(&signature),
                }
            }],
        },
    }))
}

// ── ledger_data ──────────────────────────────────────────────────────────────

pub fn ledger_data(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let limit = parse_ledger_data_limit(params, 256, 256)?;

    // Check if a specific historical ledger is requested
    let requested_seq = resolve_ledger_selector(params, ctx)?;

    let is_historical = requested_seq
        .map(|seq| seq != ctx.ledger_seq)
        .unwrap_or(false);

    // For historical ledgers, serve raw binary SLEs from versioned storage
    if is_historical {
        let target_seq = requested_seq.unwrap();
        let (header, mut map) = historical_state_map(
            target_seq,
            ctx,
            "historical ledger enumeration unavailable",
        )?;
        let marker = parse_ledger_data_marker(params)?;

        if let Some(mark) = marker {
            if map.get(&crate::ledger::Key(mark)).is_none() {
                return Err(RpcError::invalid_params("invalid marker"));
            }
        }

        let mut state_objects: Vec<Value> = Vec::with_capacity(limit);
        let mut last_key: Option<[u8; 32]> = None;
        let mut next_key = marker
            .map(crate::ledger::Key)
            .and_then(|mark| map.upper_bound_lazy(&mark))
            .or_else(|| {
                if marker.is_none() {
                    map.first_key_lazy()
                } else {
                    None
                }
            });

        while let Some(key) = next_key {
            let data = map
                .get(&key)
                .ok_or_else(|| RpcError::internal("historical ledger entry enumeration failed"))?;
            state_objects.push(json!({
                "index": hex::encode_upper(key.0),
                "data":  hex::encode_upper(data),
            }));
            last_key = Some(key.0);
            if state_objects.len() >= limit {
                break;
            }
            next_key = map.upper_bound_lazy(&key);
        }

        let truncated = state_objects.len() == limit;
        let mut result = json!({
            "ledger_index": target_seq,
            "ledger_hash":  hex::encode_upper(header.hash),
            "state":        state_objects,
            "historical":   true,
        });
        if truncated {
            result["truncated"] = json!(true);
            if let Some(lk) = last_key {
                result["marker"] = json!(hex::encode_upper(lk));
            }
        }
        return Ok(result);
    }

    // Current ledger — serve raw binary SLEs in key order with exact paging.
    let marker = parse_ledger_data_marker(params)?;
    let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mark) = marker {
        if ls.get_raw(&crate::ledger::Key(mark)).is_none() {
            return Err(RpcError::invalid_params("invalid marker"));
        }
    }
    let mut entries = ls.iter_raw_entries();
    entries.sort_by_key(|(key, _)| key.0);
    let mut state_objects: Vec<Value> = Vec::with_capacity(limit);
    let mut last_key: Option<[u8; 32]> = None;
    for (key, data) in entries {
        if let Some(after) = marker {
            if key.0 <= after {
                continue;
            }
        }
        state_objects.push(json!({
            "index": hex::encode_upper(key.0),
            "data":  hex::encode_upper(data),
        }));
        last_key = Some(key.0);
        if state_objects.len() >= limit {
            break;
        }
    }
    let truncated = state_objects.len() == limit;
    let mut result = json!({
        "ledger_index": ctx.ledger_seq,
        "ledger_hash":  ctx.ledger_hash,
        "state":        state_objects,
    });
    if truncated {
        result["truncated"] = json!(true);
        if let Some(lk) = last_key {
            result["marker"] = json!(hex::encode_upper(lk));
        }
    }
    Ok(result)
}

// ── account_lines ────────────────────────────────────────────────────────────

pub fn account_lines(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let address = params.get("account").and_then(Value::as_str).unwrap_or("");
    let account_id = parse_account_field(params, "account")?;
    let limit = parse_limit_field(params, 200, 400)?;
    let marker = parse_hex_key_marker(params)?;
    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let is_historical = requested_seq != ctx.ledger_seq;
    let peer = match params.get("peer") {
        None => None,
        Some(Value::String(s)) => Some(
            decode_account(s).map_err(|_| RpcError::invalid_params("malformed peer address"))?
        ),
        Some(_) => return Err(RpcError::invalid_params("malformed peer address")),
    };

    let line_json = |tl: &crate::ledger::trustline::RippleState| {
        let peer_id = if account_id == tl.low_account {
            tl.high_account
        } else {
            tl.low_account
        };
        let balance = tl.balance_for(&account_id);
        let limit = if account_id == tl.low_account {
            &tl.low_limit
        } else {
            &tl.high_limit
        };
        let limit_peer = if account_id == tl.low_account {
            &tl.high_limit
        } else {
            &tl.low_limit
        };
        json!({
            "account":    crate::crypto::base58::encode_account(&peer_id),
            "balance":    format_iou_value(&balance),
            "currency":   tl.currency.to_ascii(),
            "limit":      format_iou_value(limit),
            "limit_peer": format_iou_value(limit_peer),
            "no_ripple":  tl.flags & 0x00020000 != 0,
        })
    };

    let mut line_values: Vec<Value> = Vec::new();
    let mut next_marker: Option<[u8; 32]> = None;

    if is_historical {
        if ctx.history.read().unwrap_or_else(|e| e.into_inner()).get_ledger(requested_seq).is_none() {
            return Err(lgr_not_found());
        }
        // Historical trust-line enumeration not available (no object_history CF).
        return Err(RpcError::internal("historical account_lines not available"));
    } else if let Some(ref cl) = ctx.closed_ledger {
        // New path: read from ClosedLedger via ReadView + owner directory walk
        use crate::ledger::views::ReadView;
        let acct_kl = crate::ledger::keylet::account(&account_id);
        if cl.read(&acct_kl).is_none() {
            return Err(RpcError::not_found(address));
        }
        // Walk the owner directory to find RippleState entries
        let dir_kl = crate::ledger::keylet::owner_dir(&account_id);
        let mut dir_page = 0u64;
        let mut all_tl: Vec<(crate::ledger::Key, crate::ledger::trustline::RippleState)> = Vec::new();
        loop {
            let page_kl = crate::ledger::keylet::dir_page(&dir_kl.key.0, dir_page);
            let Some(dir_sle) = cl.read(&page_kl) else { break; };
            let Ok(dir_node) = crate::ledger::directory::DirectoryNode::decode(dir_sle.data(), page_kl.key.0) else { break; };
            for idx in &dir_node.indexes {
                let entry_key = crate::ledger::Key(*idx);
                // Try to read as RippleState
                if let Some(data) = cl.read(&crate::ledger::keylet::Keylet::new(entry_key, crate::ledger::sle::LedgerEntryType::RippleState)) {
                    if let Some(tl) = crate::ledger::trustline::RippleState::decode_from_sle(data.data()) {
                        if account_id == tl.low_account || account_id == tl.high_account {
                            all_tl.push((entry_key, tl));
                        }
                    }
                }
            }
            if dir_node.index_next != 0 {
                dir_page = dir_node.index_next;
            } else {
                break;
            }
        }
        all_tl.sort_by_key(|(key, _)| key.0);
        if let Some(mark) = marker {
            let marker_matches = all_tl.iter().any(|(key, tl)| {
                if key.0 != mark { return false; }
                let peer_id = if account_id == tl.low_account { tl.high_account } else { tl.low_account };
                peer.map(|p| p == peer_id).unwrap_or(true)
            });
            if !marker_matches {
                return Err(RpcError::invalid_params("invalid marker"));
            }
        }
        let mut last_returned: Option<[u8; 32]> = None;
        for (key, tl) in &all_tl {
            if let Some(after) = marker {
                if key.0 <= after { continue; }
            }
            let peer_id = if account_id == tl.low_account { tl.high_account } else { tl.low_account };
            if let Some(peer_filter) = peer {
                if peer_filter != peer_id { continue; }
            }
            if line_values.len() == limit {
                next_marker = last_returned;
                break;
            }
            line_values.push(line_json(tl));
            last_returned = Some(key.0);
        }
    } else {
        // Legacy path: in-memory state
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if ls.get_account(&account_id).is_none() {
            return Err(RpcError::not_found(address));
        }
        let mut lines: Vec<(crate::ledger::Key, &crate::ledger::trustline::RippleState)> = ls.trustlines_for_account(&account_id)
            .into_iter()
            .map(|tl| (tl.key(), tl))
            .collect();
        lines.sort_by_key(|(key, _)| key.0);
        if let Some(mark) = marker {
            let marker_matches = lines.iter().any(|(key, tl)| {
                if key.0 != mark {
                    return false;
                }
                let peer_id = if account_id == tl.low_account { tl.high_account } else { tl.low_account };
                peer.map(|p| p == peer_id).unwrap_or(true)
            });
            if !marker_matches {
                return Err(RpcError::invalid_params("invalid marker"));
            }
        }
        let mut last_returned: Option<[u8; 32]> = None;
        for (key, tl) in lines {
            if let Some(after) = marker {
                if key.0 <= after {
                    continue;
                }
            }
            let peer_id = if account_id == tl.low_account { tl.high_account } else { tl.low_account };
            if let Some(peer_filter) = peer {
                if peer_filter != peer_id {
                    continue;
                }
            }
            if line_values.len() == limit {
                next_marker = last_returned;
                break;
            }
            line_values.push(line_json(tl));
            last_returned = Some(key.0);
        }
    }

    let mut result = json!({
        "account": address,
        "lines":   line_values,
    });
    if let Some(m) = next_marker {
        result["marker"] = json!(hex::encode_upper(m));
    }
    Ok(result)
}

fn format_iou_value(v: &crate::transaction::amount::IouValue) -> String {
    if v.mantissa == 0 { return "0".to_string(); }
    // Simple decimal formatting
    let abs = v.mantissa.unsigned_abs();
    let sign = if v.mantissa < 0 { "-" } else { "" };
    if v.exponent >= 0 {
        let zeros = (v.exponent as usize).min(80); // cap to prevent huge alloc
        format!("{}{}{}", sign, abs, "0".repeat(zeros))
    } else {
        let exp = (-v.exponent) as usize;
        let s = format!("{:0>width$}", abs, width = exp + 1);
        let (int, frac) = s.split_at(s.len() - exp);
        let frac = frac.trim_end_matches('0');
        if frac.is_empty() {
            format!("{}{}", sign, int)
        } else {
            format!("{}{}.{}", sign, int, frac)
        }
    }
}

fn positive_iou_string(v: &crate::transaction::amount::IouValue) -> String {
    if v.mantissa <= 0 {
        "0".to_string()
    } else {
        format_iou_value(v)
    }
}

fn amount_as_f64(a: &crate::transaction::amount::Amount) -> Option<f64> {
    match a {
        crate::transaction::amount::Amount::Xrp(drops) => Some(*drops as f64),
        crate::transaction::amount::Amount::Iou { value, .. } => {
            Some((value.mantissa as f64) * 10f64.powi(value.exponent))
        }
        crate::transaction::amount::Amount::Mpt(_) => None,
    }
}

fn offer_quality_string(off: &crate::ledger::offer::Offer) -> String {
    let Some(pays) = amount_as_f64(&off.taker_pays) else { return "0".into(); };
    let Some(gets) = amount_as_f64(&off.taker_gets) else { return "0".into(); };
    if gets == 0.0 {
        return "0".into();
    }
    let q = pays / gets;
    let rounded = q.round();
    if (q - rounded).abs() < 1e-9 {
        format!("{rounded:.0}")
    } else {
        q.to_string()
    }
}

fn owner_funds_current(
    ls: &crate::ledger::LedgerState,
    off: &crate::ledger::offer::Offer,
) -> Option<String> {
    match &off.taker_gets {
        crate::transaction::amount::Amount::Xrp(_) => {
            Some(ls.get_account(&off.account)?.balance.to_string())
        }
        crate::transaction::amount::Amount::Iou { currency, issuer, .. } => {
            let tl = ls.get_trustline_for(&off.account, issuer, currency)?;
            Some(positive_iou_string(&tl.balance_for(&off.account)))
        }
        crate::transaction::amount::Amount::Mpt(_) => None,
    }
}

fn owner_funds_historical(
    _store: &crate::storage::Storage,
    _target_seq: u32,
    _off: &crate::ledger::offer::Offer,
) -> Option<String> {
    // Historical owner funds lookup not available (no object_history CF).
    None
}

// ── account_tx ───────────────────────────────────────────────────────────────

pub fn account_tx(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    if params.get("ledger_hash").is_some()
        && (params.get("ledger_index_min").is_some() || params.get("ledger_index_max").is_some())
    {
        return Err(RpcError::invalid_params(
            "Exactly one of 'ledger_hash' or a ledger range can be specified.",
        ));
    }

    let address = params.get("account").and_then(Value::as_str).unwrap_or("");
    let account_id = parse_account_field(params, "account")?;

    let limit = parse_limit_field(params, 200, 400)?;
    let marker = parse_hex_key_marker(params)?;
    let binary = parse_bool_field(params, "binary")?.unwrap_or(false);
    let count = parse_bool_field(params, "count")?.unwrap_or(false);
    let forward = parse_bool_field(params, "forward")?.unwrap_or(false);
    let offset = match params.get("offset") {
        None => 0usize,
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| RpcError::invalid_params("invalid offset"))?,
        Some(_) => return Err(RpcError::invalid_params("invalid offset")),
    };

    let exact_seq = resolve_ledger_selector(params, ctx)?;
    let ledger_min = parse_i32_field(params, "ledger_index_min")?;
    let ledger_max = parse_i32_field(params, "ledger_index_max")?;

    if exact_seq.is_some() && (ledger_min.is_some() || ledger_max.is_some()) {
        return Err(RpcError::invalid_params(
            "Exactly one of 'ledger_index'/'ledger_hash' or a ledger range can be specified.",
        ));
    }

    let (range_min, range_max) = if let Some(seq) = exact_seq {
        (Some(seq), Some(seq))
    } else {
        let min = match ledger_min {
            Some(v) if v >= 0 => Some(v as u32),
            Some(-1) | None => None,
            Some(_) => return Err(RpcError::invalid_params("invalid ledger_index_min")),
        };
        let max = match ledger_max {
            Some(v) if v >= 0 => Some(v as u32),
            Some(-1) | None => None,
            Some(_) => return Err(RpcError::invalid_params("invalid ledger_index_max")),
        };
        if let (Some(min), Some(max)) = (min, max) {
            if max < min {
                return Err(RpcError::invalid_params("ledger_index_max must be >= ledger_index_min"));
            }
        }
        (min, max)
    };

    let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());
    if let Some(seq) = exact_seq {
        if seq != ctx.ledger_seq && history.get_ledger(seq).is_none() {
            return Err(lgr_not_found());
        }
    }

    let tx_hashes = history.get_account_txs(&account_id);
    let mut seen = std::collections::HashSet::new();
    let mut txs: Vec<_> = tx_hashes
        .iter()
        .filter(|hash| seen.insert(**hash))
        .filter_map(|hash| history.get_tx(hash).cloned())
        .filter(|rec| {
            range_min.map(|min| rec.ledger_seq >= min).unwrap_or(true)
                && range_max.map(|max| rec.ledger_seq <= max).unwrap_or(true)
        })
        .collect();

    let total_count = txs.len();

    txs.sort_by_key(|rec| (rec.ledger_seq, rec.tx_index, rec.hash));
    if !forward {
        txs.reverse();
    }

    let start = if let Some(mark) = marker {
        txs.iter()
            .position(|rec| rec.hash == mark)
            .map(|idx| idx + 1)
            .ok_or_else(|| RpcError::invalid_params("invalid marker"))?
    } else {
        0
    };
    let start = start.saturating_add(offset);

    let mut transactions: Vec<Value> = Vec::new();
    let mut next_marker: Option<[u8; 32]> = None;
    let mut last_returned: Option<[u8; 32]> = None;
    for rec in txs.iter().skip(start) {
        if transactions.len() == limit {
            next_marker = last_returned;
            break;
        }
        transactions.push(tx_record_response(rec, ctx, binary));
        last_returned = Some(rec.hash);
    }

    let mut result = json!({
        "account":      address,
        "limit":        limit,
        "transactions": transactions,
    });
    if count {
        result["count"] = json!(total_count);
    }
    if let Some(mark) = next_marker {
        result["marker"] = json!(hex::encode_upper(mark));
    }
    Ok(result)
}

// ── book_offers ──────────────────────────────────────────────────────────────

pub fn book_offers(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    use crate::ledger::BookKey;
    let limit = parse_limit_field(params, 60, 100)?;
    if limit == 0 {
        return Err(invalid_field("limit"));
    }
    let marker = parse_hex_key_marker(params)?;
    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let is_historical = requested_seq != ctx.ledger_seq;

    let taker_pays = parse_currency_spec(params.get("taker_pays"))?;
    let taker_gets = parse_currency_spec(params.get("taker_gets"))?;

    let book_key = BookKey {
        pays_currency: taker_pays.0,
        pays_issuer:   taker_pays.1,
        gets_currency: taker_gets.0,
        gets_issuer:   taker_gets.1,
    };
    let mut next_marker: Option<[u8; 32]> = None;
    let mut offers_out: Vec<Value> = Vec::new();
    let offer_json = |off: &crate::ledger::offer::Offer, owner_funds: Option<String>| {
        let mut out = json!({
            "Account":    crate::crypto::base58::encode_account(&off.account),
            "BookDirectory": hex::encode_upper(off.book_directory),
            "BookNode":   off.book_node.to_string(),
            "Flags":      off.flags,
            "LedgerEntryType": "Offer",
            "OwnerNode":  off.owner_node.to_string(),
            "Sequence":   off.sequence,
            "TakerPays":  format_amount(&off.taker_pays),
            "TakerGets":  format_amount(&off.taker_gets),
            "quality":    offer_quality_string(off),
        });
        if let Some(funds) = owner_funds {
            out["owner_funds"] = json!(funds);
        }
        out
    };

    let _issue_of = |amt: &crate::transaction::amount::Amount| -> ([u8; 20], [u8; 20]) {
        match amt {
            crate::transaction::amount::Amount::Xrp(_) => ([0u8; 20], [0u8; 20]),
            crate::transaction::amount::Amount::Iou { currency, issuer, .. } => (currency.code, *issuer),
            crate::transaction::amount::Amount::Mpt(_) => ([0u8; 20], [0u8; 20]),
        }
    };

    let mut matching: Vec<(crate::ledger::Key, crate::ledger::offer::Offer)> = Vec::new();
    if is_historical {
        // Historical book_offers enumeration not available (no object_history CF).
        return Err(RpcError::internal("historical book_offers not available"));
    } else {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(book) = ls.get_book(&book_key) {
            matching = book.iter_by_quality()
                .filter_map(|key| ls.get_offer(key).cloned().map(|off| (*key, off)))
                .collect();
            if let Some(mark) = marker {
                if !matching.iter().any(|(key, _)| key.0 == mark) {
                    return Err(RpcError::invalid_params("invalid marker"));
                }
            }
            let mut last_returned: Option<[u8; 32]> = None;
            let mut past_marker = marker.is_none();
            for (key, off) in matching {
                if !past_marker {
                    if Some(key.0) == marker {
                        past_marker = true;
                    }
                    continue;
                }
                if offers_out.len() == limit {
                    next_marker = last_returned;
                    break;
                }
                offers_out.push(offer_json(&off, owner_funds_current(&ls, &off)));
                last_returned = Some(key.0);
            }
            let mut result = json!({ "offers": offers_out });
            if let Some(m) = next_marker {
                result["marker"] = json!(hex::encode_upper(m));
            }
            return Ok(result);
        }
    }

    matching.sort_by(|(ka, oa), (kb, ob)| {
        let qa = oa.quality().unwrap_or(f64::INFINITY);
        let qb = ob.quality().unwrap_or(f64::INFINITY);
        qa.partial_cmp(&qb)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| ka.0.cmp(&kb.0))
    });
    if let Some(mark) = marker {
        if !matching.iter().any(|(key, _)| key.0 == mark) {
            return Err(RpcError::invalid_params("invalid marker"));
        }
    }
    let mut last_returned: Option<[u8; 32]> = None;
    let mut past_marker = marker.is_none();
    for (key, off) in matching {
        if !past_marker {
            if Some(key.0) == marker {
                past_marker = true;
            }
            continue;
        }
        if offers_out.len() == limit {
            next_marker = last_returned;
            break;
        }
        let owner_funds = if is_historical {
            let store = ctx.storage.as_ref().and_then(|s| Some(owner_funds_historical(s, requested_seq, &off))).flatten();
            store
        } else {
            None
        };
        offers_out.push(offer_json(&off, owner_funds));
        last_returned = Some(key.0);
    }
    let mut result = json!({ "offers": offers_out });
    if let Some(m) = next_marker {
        result["marker"] = json!(hex::encode_upper(m));
    }
    Ok(result)
}

fn parse_currency_spec(v: Option<&Value>) -> Result<([u8; 20], [u8; 20]), RpcError> {
    let obj = v.ok_or_else(|| RpcError::invalid_params("missing currency spec"))?;
    let currency_str = obj.get("currency").and_then(Value::as_str).unwrap_or("XRP");
    if currency_str == "XRP" {
        return Ok(([0u8; 20], [0u8; 20]));
    }
    let currency = crate::transaction::amount::Currency::from_code(currency_str)
        .map_err(|_| RpcError::invalid_params("invalid currency"))?;
    let issuer_str = obj.get("issuer").and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("issuer required for non-XRP"))?;
    let issuer = decode_account(issuer_str)
        .map_err(|_| RpcError::invalid_params("invalid issuer"))?;
    Ok((currency.code, issuer))
}

pub(crate) fn format_amount(a: &crate::transaction::amount::Amount) -> Value {
    match a {
        crate::transaction::amount::Amount::Xrp(drops) => json!(drops.to_string()),
        crate::transaction::amount::Amount::Iou { value, currency, issuer } => {
            json!({
                "value":    format_iou_value(value),
                "currency": currency.to_ascii(),
                "issuer":   crate::crypto::base58::encode_account(issuer),
            })
        }
        crate::transaction::amount::Amount::Mpt(_) => {
            if let Some((value, mptid)) = a.mpt_parts() {
                json!({
                    "value": value.to_string(),
                    "mpt_issuance_id": hex::encode_upper(mptid),
                })
            } else {
                json!(hex::encode(a.to_bytes()))
            }
        }
    }
}

fn tx_type_name(tx_type: u16) -> &'static str {
    match tx_type {
        0 => "Payment",
        3 => "AccountSet",
        7 => "OfferCreate",
        8 => "OfferCancel",
        20 => "TrustSet",
        21 => "CheckCreate",
        22 => "CheckCash",
        23 => "CheckCancel",
        24 => "TicketCreate",
        25 => "SignerListSet",
        26 => "NFTokenMint",
        27 => "NFTokenBurn",
        28 => "NFTokenCreateOffer",
        29 => "NFTokenCancelOffer",
        30 => "NFTokenAcceptOffer",
        31 => "Clawback",
        33 => "SetRegularKey",
        40 => "EscrowCreate",
        41 => "EscrowFinish",
        42 => "EscrowCancel",
        43 => "PaymentChannelCreate",
        44 => "PaymentChannelFund",
        45 => "PaymentChannelClaim",
        58 => "DepositPreauth",
        59 => "AccountDelete",
        60 => "MPTokenIssuanceCreate",
        61 => "MPTokenIssuanceDestroy",
        62 => "MPTokenIssuanceSet",
        63 => "MPTokenAuthorize",
        64 => "VaultCreate",
        65 => "VaultDelete",
        66 => "VaultDeposit",
        67 => "VaultWithdraw",
        68 => "AMMCreate",
        69 => "AMMDeposit",
        70 => "AMMWithdraw",
        71 => "AMMDelete",
        72 => "LoanBrokerSet",
        73 => "LoanBrokerDelete",
        74 => "LoanSet",
        75 => "LoanDelete",
        _ => "Unknown",
    }
}

fn metadata_field_name(type_code: u16, field_code: u16) -> String {
    match (type_code, field_code) {
        (2, 2) => "Flags",
        (2, 4) => "Sequence",
        (2, 10) => "Expiration",
        (2, 11) => "TransferRate",
        (2, 13) => "OwnerCount",
        (2, 28) => "TransactionIndex",
        (2, 33) => "SetFlag",
        (2, 34) => "ClearFlag",
        (2, 41) => "TicketCount",
        (3, 3) => "BookNode",
        (3, 4) => "OwnerNode",
        (3, 7) => "LowNode",
        (3, 8) => "HighNode",
        (3, 9) => "DestinationNode",
        (5, 5) => "PreviousTxnID",
        (5, 6) => "LedgerIndex",
        (5, 10) => "NFTokenID",
        (5, 16) => "BookDirectory",
        (6, 2) => "Balance",
        (6, 4) => "TakerPays",
        (6, 5) => "TakerGets",
        (6, 6) => "LowLimit",
        (6, 7) => "HighLimit",
        (7, 5) => "URI",
        (7, 7) => "Domain",
        (8, 1) => "Account",
        (8, 2) => "Owner",
        (8, 3) => "Destination",
        (8, 4) => "Issuer",
        _ => return format!("field_{type_code}_{field_code}"),
    }
    .to_string()
}

fn metadata_fields_json(fields: &[crate::ledger::meta::ParsedField]) -> Value {
    let mut out = serde_json::Map::new();
    for field in fields {
        let name = metadata_field_name(field.type_code, field.field_code);
        let value = match field.type_code {
            2 if field.data.len() >= 4 => {
                json!(u32::from_be_bytes(field.data[..4].try_into().unwrap_or([0u8; 4])))
            }
            3 if field.data.len() >= 8 => {
                json!(u64::from_be_bytes(field.data[..8].try_into().unwrap_or([0u8; 8])).to_string())
            }
            5 => json!(hex::encode_upper(&field.data)),
            6 => {
                if let Ok((amt, _)) = crate::transaction::amount::Amount::from_bytes(&field.data) {
                    format_amount(&amt)
                } else {
                    json!(hex::encode_upper(&field.data))
                }
            }
            7 => json!(hex::encode_upper(&field.data)),
            8 if field.data.len() == 20 => {
                let mut account = [0u8; 20];
                account.copy_from_slice(&field.data);
                json!(crate::crypto::base58::encode_account(&account))
            }
            _ => json!(hex::encode_upper(&field.data)),
        };
        out.insert(name, value);
    }
    Value::Object(out)
}

pub(crate) fn metadata_json(meta_blob: &[u8], result: &str) -> Value {
    if meta_blob.is_empty() {
        return json!({
            "TransactionResult": result,
        });
    }

    let (tx_index, nodes) = crate::ledger::meta::parse_metadata_with_index(meta_blob);
    let mut out = serde_json::Map::new();
    out.insert("TransactionResult".to_string(), json!(result));
    if let Some(index) = tx_index {
        out.insert("TransactionIndex".to_string(), json!(index));
    }

    let affected: Vec<Value> = nodes.into_iter().map(|node| {
        let wrapper = match node.action {
            crate::ledger::meta::Action::Created => "CreatedNode",
            crate::ledger::meta::Action::Modified => "ModifiedNode",
            crate::ledger::meta::Action::Deleted => "DeletedNode",
        };
        let field_name = match node.action {
            crate::ledger::meta::Action::Created => "NewFields",
            crate::ledger::meta::Action::Modified | crate::ledger::meta::Action::Deleted => "FinalFields",
        };
        let mut inner = serde_json::Map::new();
        inner.insert("LedgerEntryType".to_string(), json!(sle_entry_type_name(node.entry_type)));
        inner.insert("LedgerIndex".to_string(), json!(hex::encode_upper(node.ledger_index)));
        inner.insert(field_name.to_string(), metadata_fields_json(&node.fields));
        if node.action == crate::ledger::meta::Action::Modified && !node.previous_fields.is_empty() {
            inner.insert("PreviousFields".to_string(), metadata_fields_json(&node.previous_fields));
        }
        json!({ wrapper: Value::Object(inner) })
    }).collect();
    if !affected.is_empty() {
        out.insert("AffectedNodes".to_string(), Value::Array(affected));
    }
    Value::Object(out)
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

pub(crate) fn close_time_iso_string(close_time: u64) -> String {
    const XRPL_EPOCH_OFFSET: i64 = 946_684_800;
    let unix = i64::try_from(close_time).unwrap_or(i64::MAX - XRPL_EPOCH_OFFSET) + XRPL_EPOCH_OFFSET;
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs / 3_600;
    let minute = (secs % 3_600) / 60;
    let second = secs % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

pub(crate) fn encode_ctid(ledger_seq: u32, tx_index: u32, network_id: u32) -> Option<String> {
    if ledger_seq >= 0x1000_0000 || tx_index > 0xFFFF || network_id > 0xFFFF {
        return None;
    }
    let value = ((0xC000_0000u64 + u64::from(ledger_seq)) << 32)
        | (u64::from(tx_index as u16) << 16)
        | u64::from(network_id as u16);
    Some(format!("{value:016X}"))
}

fn decode_ctid(ctid: &str) -> Option<(u32, u16, u16)> {
    if ctid.len() != 16 || !ctid.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let value = u64::from_str_radix(ctid, 16).ok()?;
    if (value & 0xF000_0000_0000_0000) != 0xC000_0000_0000_0000 {
        return None;
    }
    let ledger_seq = ((value >> 32) & 0x0FFF_FFFF) as u32;
    let tx_index = ((value >> 16) & 0xFFFF) as u16;
    let network_id = (value & 0xFFFF) as u16;
    Some((ledger_seq, tx_index, network_id))
}

pub(crate) fn parsed_tx_json(parsed: &crate::transaction::ParsedTx) -> Value {
    let mut out = json!({
        "TransactionType": tx_type_name(parsed.tx_type),
        "Account": crate::crypto::base58::encode_account(&parsed.account),
        "Fee": parsed.fee.to_string(),
        "Sequence": parsed.sequence,
        "Flags": parsed.flags,
        "SigningPubKey": hex::encode_upper(&parsed.signing_pubkey),
        "TxnSignature": hex::encode_upper(&parsed.signature),
    });

    if let Some(destination) = parsed.destination {
        out["Destination"] = json!(crate::crypto::base58::encode_account(&destination));
    }
    if let Some(amount) = parsed.amount.as_ref() {
        if parsed.tx_type == 0 {
            out["DeliverMax"] = format_amount(amount);
        } else {
            out["Amount"] = format_amount(amount);
        }
    } else if let Some(drops) = parsed.amount_drops {
        if parsed.tx_type == 0 {
            out["DeliverMax"] = json!(drops.to_string());
        } else {
            out["Amount"] = json!(drops.to_string());
        }
    }
    if let Some(amount) = parsed.limit_amount.as_ref() {
        out["LimitAmount"] = format_amount(amount);
    }
    if let Some(amount) = parsed.taker_pays.as_ref() {
        out["TakerPays"] = format_amount(amount);
    }
    if let Some(amount) = parsed.taker_gets.as_ref() {
        out["TakerGets"] = format_amount(amount);
    }
    if let Some(amount) = parsed.deliver_min.as_ref() {
        out["DeliverMin"] = format_amount(amount);
    }
    if let Some(offer_sequence) = parsed.offer_sequence {
        out["OfferSequence"] = json!(offer_sequence);
    }
    if let Some(set_flag) = parsed.set_flag {
        out["SetFlag"] = json!(set_flag);
    }
    if let Some(clear_flag) = parsed.clear_flag {
        out["ClearFlag"] = json!(clear_flag);
    }
    if let Some(transfer_rate) = parsed.transfer_rate {
        out["TransferRate"] = json!(transfer_rate);
    }
    if let Some(tick_size) = parsed.tick_size {
        out["TickSize"] = json!(tick_size);
    }
    if let Some(ticket_count) = parsed.ticket_count {
        out["TicketCount"] = json!(ticket_count);
    }
    if let Some(domain) = parsed.domain.as_ref() {
        out["Domain"] = json!(hex::encode_upper(domain));
    }
    out
}

fn tx_record_response(
    rec: &crate::ledger::history::TxRecord,
    ctx: &NodeContext,
    binary: bool,
) -> Value {
    let mut out = json!({
        "hash": hex::encode_upper(rec.hash),
        "ledger_index": rec.ledger_seq,
        "validated": true,
    });

    {
        let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());
        if let Some(header) = history.get_ledger(rec.ledger_seq).map(|r| &r.header)
            .or_else(|| (rec.ledger_seq == ctx.ledger_seq).then_some(&ctx.ledger_header))
        {
            out["ledger_hash"] = json!(hex::encode_upper(header.hash));
            out["close_time_iso"] = json!(close_time_iso_string(header.close_time));
        }
    }
    if let Some(ctid) = encode_ctid(rec.ledger_seq, rec.tx_index, ctx.network_id) {
        out["ctid"] = json!(ctid);
    }

    if binary {
        out["tx_blob"] = json!(hex::encode_upper(&rec.blob));
        if !rec.meta.is_empty() {
            out["meta_blob"] = json!(hex::encode_upper(&rec.meta));
        }
    } else if let Ok(parsed) = crate::transaction::parse_blob(&rec.blob) {
        out["tx_json"] = parsed_tx_json(&parsed);
        out["meta"] = metadata_json(&rec.meta, &rec.result);
    } else {
        out["tx_blob"] = json!(hex::encode_upper(&rec.blob));
        out["meta"] = metadata_json(&rec.meta, &rec.result);
    }

    out
}

// ── account_offers ───────────────────────────────────────────────────────────

pub fn account_offers(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let address = params.get("account").and_then(Value::as_str).unwrap_or("");
    let account_id = parse_account_field(params, "account")?;
    let limit = parse_limit_field(params, 200, 400)?;
    let marker = parse_hex_key_marker(params)?;
    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let is_historical = requested_seq != ctx.ledger_seq;

    let offer_json = |off: &crate::ledger::offer::Offer| {
        json!({
            "seq":        off.sequence,
            "taker_pays": format_amount(&off.taker_pays),
            "taker_gets": format_amount(&off.taker_gets),
            "flags":      off.flags,
            "quality":    off.quality().unwrap_or(0.0).to_string(),
        })
    };

    let mut next_marker: Option<[u8; 32]> = None;
    let mut offers_out: Vec<Value> = Vec::new();

    if is_historical {
        // Historical account_offers enumeration not available (no object_history CF).
        return Err(RpcError::internal("historical account_offers not available"));
    } else {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if ls.get_account(&account_id).is_none() {
            return Err(RpcError::not_found(address));
        }
        let mut offers: Vec<crate::ledger::offer::Offer> = ls.offers_by_account(&account_id)
            .into_iter()
            .cloned()
            .collect();
        offers.sort_by_key(|off| off.key().0);
        if let Some(mark) = marker {
            if !offers.iter().any(|off| off.key().0 == mark) {
                return Err(RpcError::invalid_params("invalid marker"));
            }
        }
        let mut last_returned: Option<[u8; 32]> = None;
        for off in offers {
            let key = off.key();
            if let Some(mark) = marker {
                if key.0 <= mark {
                    continue;
                }
            }
            if offers_out.len() == limit {
                next_marker = last_returned;
                break;
            }
            offers_out.push(offer_json(&off));
            last_returned = Some(key.0);
        }
    }

    let mut result = json!({
        "account": address,
        "offers":  offers_out,
    });
    if let Some(m) = next_marker {
        result["marker"] = json!(hex::encode_upper(m));
    }
    Ok(result)
}

// ── submit ────────────────────────────────────────────────────────────────────

/// Negative codes are `tem` (malformed) — transaction is rejected immediately.
/// Codes ≥ 100 are `tec` (claimed cost) — fee is claimed but tx not applied.
struct EngineResult {
    code:    &'static str,
    numeric: i32,
    message: &'static str,
}

impl EngineResult {
    const SUCCESS: Self = Self {
        code: "tesSUCCESS", numeric: 0,
        message: "The transaction was applied.",
    };
    const BAD_SIGNATURE: Self = Self {
        code: "temBAD_SIGNATURE", numeric: -281,
        message: "Transaction's signing key is not authorized.",
    };
    const BAD_AUTH: Self = Self {
        code: "temBAD_AUTH_MASTER", numeric: -272,
        message: "The transaction's signing key is not authorized by the account.",
    };
    const NO_ACCOUNT: Self = Self {
        code: "terNO_ACCOUNT", numeric: -96,
        message: "The account does not exist.",
    };
    const PAST_SEQ: Self = Self {
        code: "tefPAST_SEQ", numeric: -190,
        message: "This sequence number has already passed.",
    };
    const PRE_SEQ: Self = Self {
        code: "terPRE_SEQ", numeric: -95,
        message: "Missing/inapplicable prior transaction.",
    };
    const INSUF_FEE: Self = Self {
        code: "terINSUF_FEE_B", numeric: -97,
        message: "Account balance can't pay fee.",
    };
    const INSUFFICIENT_PAYMENT: Self = Self {
        code: "tecINSUFFICIENT_FUNDS", numeric: 148,
        message: "Insufficient balance to send.",
    };
    const INSUF_RESERVE: Self = Self {
        code: "tecINSUFFICIENT_RESERVE", numeric: 141,
        message: "Insufficient reserve to complete transaction.",
    };
}

pub fn submit(params: &Value, ctx: &mut NodeContext) -> Result<Value, RpcError> {
    const MAX_TX_BLOB_BYTES: usize = 1_048_576;

    let blob_hex = params
        .get("tx_blob")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'tx_blob' field"))?;

    if blob_hex.len() > MAX_TX_BLOB_BYTES.saturating_mul(2) {
        return Err(RpcError::invalid_params("tx_blob too large"));
    }

    let blob = hex::decode(blob_hex)
        .map_err(|_| RpcError::invalid_params("tx_blob is not valid hex"))?;

    if blob.len() < 10 {
        return Err(RpcError::invalid_params("tx_blob too short"));
    }
    if blob.len() > MAX_TX_BLOB_BYTES {
        return Err(RpcError::invalid_params("tx_blob too large"));
    }

    // Transaction hash = SHA-512-half(PREFIX || full_blob)
    let tx_hash = {
        use crate::transaction::serialize::PREFIX_TX_ID;
        let mut p = PREFIX_TX_ID.to_vec();
        p.extend_from_slice(&blob);
        crate::crypto::sha512_first_half(&p)
    };
    let tx_hash_hex = hex::encode_upper(tx_hash);

    // Parse the binary blob into its fields.
    let parsed = match crate::transaction::parse_blob(&blob) {
        Ok(p)  => p,
        Err(e) => return Err(RpcError::invalid_params(&format!("tx parse error: {e}"))),
    };

    // ── 1. Signature verification ─────────────────────────────────────────────
    let sig_ok = if parsed.signing_pubkey.first() == Some(&0xED) && parsed.signing_pubkey.len() == 33 {
        // Ed25519 key (0xED prefix + 32-byte key)
        let ed_key = &parsed.signing_pubkey[1..]; // strip 0xED prefix
        use ed25519_dalek::Verifier;
        (|| -> bool {
            let Ok(sig_bytes): Result<[u8; 64], _> = parsed.signature.as_slice().try_into() else { return false };
            let Ok(pk_bytes): Result<[u8; 32], _> = ed_key.try_into() else { return false };
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) else { return false };
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            // Ed25519 needs raw signing payload (it hashes internally), NOT the SHA512Half hash
            vk.verify(&parsed.signing_payload, &sig).is_ok()
        })()
    } else {
        // secp256k1: signing_hash is already SHA512Half — use verify_digest to avoid double-hashing
        crate::crypto::keys::verify_secp256k1_digest(
            &parsed.signing_pubkey,
            &parsed.signing_hash,
            &parsed.signature,
        )
    };
    if !sig_ok {
        return Ok(engine_result_response(
            &EngineResult::BAD_SIGNATURE, ctx, blob_hex, &tx_hash_hex,
            parsed.sequence, parsed.sequence,
        ));
    }

    // ── 2–3. Look up account (used for regular key check + existence) ────────
    let account_root = if let Some(ref cl) = ctx.closed_ledger {
        use crate::ledger::views::ReadView;
        let kl = crate::ledger::keylet::account(&parsed.account);
        cl.read(&kl).and_then(|sle| crate::ledger::AccountRoot::decode(sle.data()).ok())
    } else {
        ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner())
            .get_account(&parsed.account).cloned()
    };

    // ── 2. Confirm the signing key matches the account ────────────────────────
    // Accept the master key OR the regular key (if set).
    let derived_account = crate::crypto::account_id(&parsed.signing_pubkey);
    if derived_account != parsed.account {
        let is_regular = account_root.as_ref()
            .and_then(|a| a.regular_key)
            .map(|rk| rk == derived_account)
            .unwrap_or(false);
        if !is_regular {
            return Ok(engine_result_response(
                &EngineResult::BAD_AUTH, ctx, blob_hex, &tx_hash_hex,
                parsed.sequence, parsed.sequence,
            ));
        }
    }

    // ── 3. Account existence ──────────────────────────────────────────────────
    let account_root = match account_root {
        Some(r) => r,
        None    => return Ok(engine_result_response(
            &EngineResult::NO_ACCOUNT, ctx, blob_hex, &tx_hash_hex,
            0, 0,
        )),
    };

    // Account for pending transactions in the pool when checking sequence.
    let pending_from_account = ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner()).count_by_account(&parsed.account);
    let next_seq = account_root.sequence + pending_from_account as u32;
    let avail_seq = next_seq + 1;

    // ── 4. Sequence number check ──────────────────────────────────────────────
    if parsed.sequence < account_root.sequence {
        return Ok(engine_result_response(
            &EngineResult::PAST_SEQ, ctx, blob_hex, &tx_hash_hex,
            avail_seq, next_seq,
        ));
    }
    if parsed.sequence > next_seq {
        return Ok(engine_result_response(
            &EngineResult::PRE_SEQ, ctx, blob_hex, &tx_hash_hex,
            avail_seq, next_seq,
        ));
    }

    // ── 5. Minimum fee check ──────────────────────────────────────────────────
    if parsed.fee < ctx.fees.base {
        return Ok(engine_result_response(
            &EngineResult::INSUF_FEE, ctx, blob_hex, &tx_hash_hex,
            avail_seq, next_seq,
        ));
    }

    // ── 6. Balance checks ─────────────────────────────────────────────────────
    if account_root.balance < parsed.fee {
        return Ok(engine_result_response(
            &EngineResult::INSUF_FEE, ctx, blob_hex, &tx_hash_hex,
            avail_seq, next_seq,
        ));
    }
    if let Some(send) = parsed.amount_drops {
        let total = send.saturating_add(parsed.fee);
        if account_root.balance < total {
            return Ok(engine_result_response(
                &EngineResult::INSUFFICIENT_PAYMENT, ctx, blob_hex, &tx_hash_hex,
                avail_seq, next_seq,
            ));
        }
    }

    // ── 6. Reserve check ────────────────────────────────────────────────────
    // Account must maintain: base_reserve + owner_count * owner_reserve.
    // NOTE: These reserve values should ideally come from the FeeSettings ledger
    // object. We hardcode the current mainnet defaults since we don't parse
    // FeeSettings yet. This is acceptable as a documented limitation.
    {
        let reserve = ctx.fees.reserve + (account_root.owner_count as u64) * ctx.fees.increment;
        let spend = parsed.fee.saturating_add(parsed.amount_drops.unwrap_or(0));
        if account_root.balance.saturating_sub(spend) < reserve {
            // Allow the tx if it would *decrease* owner count (e.g., OfferCancel, TrustSet to 0)
            // For simplicity, only enforce on txs that increase obligations
            // Only block txs that strictly increase obligations.
            // TrustSet, NFTokenBurn, SignerListSet can decrease owner_count
            // and should NOT be blocked — they may free reserve.
            if matches!(parsed.tx_type,
                0  | // Payment (sends XRP)
                1  | // EscrowCreate (locks XRP + owner_count++)
                7  | // OfferCreate (owner_count++)
                10 | // TicketCreate (owner_count++)
                16 | // CheckCreate (owner_count++)
                19 | // DepositPreauth (owner_count++)
                25   // NFTokenMint (owner_count++)
            ) {
                return Ok(engine_result_response(
                    &EngineResult::INSUF_RESERVE, ctx, blob_hex, &tx_hash_hex,
                    avail_seq, next_seq,
                ));
            }
        }
    }

    // ── All checks passed — add to transaction pool and broadcast ───────────
    ctx.tx_pool.write().unwrap_or_else(|e| e.into_inner()).insert(tx_hash, blob.clone(), &parsed);
    ctx.broadcast_queue.push(
        crate::network::relay::encode_transaction(&blob),
    );

    Ok(engine_result_response(
        &EngineResult::SUCCESS, ctx, blob_hex, &tx_hash_hex,
        avail_seq, next_seq,
    ))
}

fn engine_result_response(
    res:      &EngineResult,
    ctx:      &NodeContext,
    blob_hex: &str,
    hash_hex: &str,
    seq_avail: u32,
    seq_next:  u32,
) -> Value {
    let applied  = res.numeric == 0;
    let accepted = res.numeric >= 0; // tec codes are "accepted" (fee claimed)
    let broadcast = applied; // broadcast when tesSUCCESS and tx was added to broadcast queue

    json!({
        "status":                   "success",
        "accepted":                 accepted,
        "account_sequence_available": seq_avail,
        "account_sequence_next":    seq_next,
        "applied":                  applied,
        "broadcast":                broadcast,
        "engine_result":            res.code,
        "engine_result_code":       res.numeric,
        "engine_result_message":    res.message,
        "kept":                     accepted,
        "queued":                   false,
        "open_ledger_cost":         ctx.fees.base.to_string(),
        "validated_ledger_index":   ctx.ledger_seq,
        "tx_blob":                  blob_hex,
        "tx_json": {
            "hash": hash_hex,
        },
    })
}

// ── tx ────────────────────────────────────────────────────────────────────────

pub fn tx(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let binary = parse_bool_field(params, "binary")?.unwrap_or(false);
    let min_ledger = parse_i32_field(params, "min_ledger")?;
    let max_ledger = parse_i32_field(params, "max_ledger")?;
    let hash = match (
        params.get("transaction").and_then(Value::as_str),
        params.get("ctid").and_then(Value::as_str),
    ) {
        (Some(_), Some(_)) => return Err(RpcError::invalid_params("Specify only one of 'transaction' or 'ctid'.")),
        (None, None) => return Err(RpcError::invalid_params("missing 'transaction' field")),
        (Some(hash_str), None) => {
            if hash_str.len() != 64 {
                return Err(RpcError::invalid_params("transaction hash must be 64 hex chars"));
            }
            let hash_bytes = hex::decode(hash_str)
                .map_err(|_| RpcError::invalid_params("transaction hash must be hex"))?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            Some(hash)
        }
        (None, Some(ctid)) => {
            let (ledger_seq, tx_index, network_id) =
                decode_ctid(ctid).ok_or_else(|| RpcError::invalid_params("invalid ctid"))?;
            if u32::from(network_id) != ctx.network_id {
                return Err(wrong_network(network_id));
            }
            ctx.history.read().unwrap_or_else(|e| e.into_inner())
                .ledger_txs(ledger_seq)
                .into_iter()
                .find(|rec| rec.tx_index == u32::from(tx_index))
                .map(|rec| rec.hash)
        }
    };

    let ledger_range = match (min_ledger, max_ledger) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => return Err(invalid_lgr_range()),
        (Some(min), Some(max)) if min < 0 || max < 0 => return Err(invalid_lgr_range()),
        (Some(min), Some(max)) => {
            let min = min as u32;
            let max = max as u32;
            if max < min {
                return Err(invalid_lgr_range());
            }
            if max - min > 1000 {
                return Err(excessive_lgr_range());
            }
            Some((min, max))
        }
    };

    let rec = hash.and_then(|hash| ctx.history.read().unwrap_or_else(|e| e.into_inner()).get_tx(&hash)
        .cloned()
        .or_else(|| {
            // Fall back to persistent storage for persisted transactions
            ctx.storage.as_ref().and_then(|s| s.lookup_tx(&hash))
        }));

    if let Some((min, max)) = ledger_range {
        match rec {
            Some(rec) if rec.ledger_seq >= min && rec.ledger_seq <= max => {
                return Ok(tx_record_response(&rec, ctx, binary));
            }
            Some(_) => {
                return Err(txn_not_found_searched_all(false));
            }
            None => {
                let searched_all = ctx.history.read().unwrap_or_else(|e| e.into_inner()).covers_ledger_range(min, max)
                    || ctx.storage.as_ref().map(|s| s.has_full_ledger_range(min, max)).unwrap_or(false);
                return Err(txn_not_found_searched_all(searched_all));
            }
        }
    }

    let rec = rec.ok_or_else(txn_not_found)?;

    Ok(tx_record_response(&rec, ctx, binary))
}

// ── ledger ────────────────────────────────────────────────────────────────────

pub fn ledger(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    // Accept "ledger_index": <number> or "ledger_index": "validated"
    let seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);

    // Look up in history first, fall back to current header
    let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());
    let rec = history.get_ledger(seq);
    let header = rec.map(|r| &r.header);
    let tx_hashes = rec.map(|r| r.tx_hashes.as_slice()).unwrap_or(&[]);

    // If not in history, check if it's the current ledger
    let hdr = match header {
        Some(h) => h,
        None if seq == ctx.ledger_seq => &ctx.ledger_header,
        None => return Err(lgr_not_found()),
    };

    let hash_hex        = hex::encode_upper(hdr.hash);
    let parent_hex      = hex::encode_upper(hdr.parent_hash);
    let tx_hash_hex     = hex::encode_upper(hdr.transaction_hash);
    let account_hex     = hex::encode_upper(hdr.account_hash);

    let mut response = json!({
        "ledger": {
            "ledger_index":     seq.to_string(),
            "ledger_hash":      hash_hex,
            "parent_hash":      parent_hex,
            "total_coins":      hdr.total_coins.to_string(),
            "close_time":       hdr.close_time,
            "closed":           true,
            "accepted":         true,
            "transaction_hash": tx_hash_hex,
            "account_hash":     account_hex,
        },
        "ledger_hash":  hash_hex,
        "ledger_index": seq,
        "validated":    true,
    });

    // Include transactions if requested
    if params.get("transactions").and_then(Value::as_bool).unwrap_or(false) {
        let tx_list: Vec<String> = tx_hashes.iter()
            .map(|h| hex::encode_upper(h))
            .collect();
        response["ledger"]["transactions"] = json!(tx_list);
    }

    Ok(response)
}

// ── Shared SLE/account-object decoding helpers ───────────────────────────────

fn parse_sle_field_header(data: &[u8], pos: usize) -> Option<(u16, u16, usize)> {
    if pos >= data.len() {
        return None;
    }
    let b = data[pos];
    let top = (b >> 4) as u16;
    let bot = (b & 0x0F) as u16;
    if top == 0 && bot == 0 {
        if pos + 3 > data.len() {
            return None;
        }
        Some((data[pos + 1] as u16, data[pos + 2] as u16, pos + 3))
    } else if top == 0 {
        if pos + 2 > data.len() {
            return None;
        }
        Some((data[pos + 1] as u16, bot, pos + 2))
    } else if bot == 0 {
        if pos + 2 > data.len() {
            return None;
        }
        Some((top, data[pos + 1] as u16, pos + 2))
    } else {
        Some((top, bot, pos + 1))
    }
}

fn sle_account_field(
    parsed: &crate::ledger::meta::ParsedSLE,
    field_code: u16,
) -> Option<[u8; 20]> {
    parsed.fields.iter().find_map(|field| {
        if field.type_code == 8 && field.field_code == field_code && field.data.len() == 20 {
            let mut out = [0u8; 20];
            out.copy_from_slice(&field.data);
            Some(out)
        } else {
            None
        }
    })
}

fn sle_u32_field(
    parsed: &crate::ledger::meta::ParsedSLE,
    field_code: u16,
) -> Option<u32> {
    parsed.fields.iter().find_map(|field| {
        if field.type_code == 2 && field.field_code == field_code && field.data.len() >= 4 {
            Some(u32::from_be_bytes(field.data[..4].try_into().ok()?))
        } else {
            None
        }
    })
}

fn sle_hash256_field(
    parsed: &crate::ledger::meta::ParsedSLE,
    field_code: u16,
) -> Option<[u8; 32]> {
    parsed.fields.iter().find_map(|field| {
        if field.type_code == 5 && field.field_code == field_code && field.data.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&field.data);
            Some(out)
        } else {
            None
        }
    })
}

fn sle_amount_field(
    parsed: &crate::ledger::meta::ParsedSLE,
    field_code: u16,
) -> Option<crate::transaction::amount::Amount> {
    parsed.fields.iter().find_map(|field| {
        if field.type_code == 6 && field.field_code == field_code {
            crate::transaction::amount::Amount::from_bytes(&field.data)
                .ok()
                .map(|(amt, _)| amt)
        } else {
            None
        }
    })
}

fn sle_blob_field(
    parsed: &crate::ledger::meta::ParsedSLE,
    field_code: u16,
) -> Option<Vec<u8>> {
    parsed.fields.iter().find_map(|field| {
        if field.type_code == 7 && field.field_code == field_code {
            Some(field.data.clone())
        } else {
            None
        }
    })
}

fn sle_entry_type_name(entry_type: u16) -> String {
    match entry_type {
        0x0037 => "NFTokenOffer",
        0x0043 => "Check",
        0x0049 => "DID",
        0x0050 => "NFTokenPage",
        0x0054 => "Ticket",
        0x0061 => "AccountRoot",
        0x0064 => "DirectoryNode",
        0x006f => "Offer",
        0x0070 => "DepositPreauth",
        0x0072 => "RippleState",
        0x0075 => "Escrow",
        0x0078 => "PayChannel",
        0x007e => "MPTokenIssuance",
        0x0081 => "Credential",
        other => return format!("Unknown({other:#06x})"),
    }
    .to_string()
}

fn parse_nft_page_tokens(raw: &[u8]) -> Option<Vec<crate::ledger::nft_page::PageToken>> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    if parsed.entry_type != 0x0050 {
        return None;
    }
    let array = parsed.fields.iter().find(|f| f.type_code == 15 && f.field_code == 10)?;
    let mut tokens = Vec::new();
    let mut pos = 0usize;
    while pos < array.data.len() {
        if array.data[pos] == 0xF1 {
            break;
        }
        let (tc, fc, new_pos) = parse_sle_field_header(&array.data, pos)?;
        if (tc, fc) != (14, 12) {
            return None;
        }
        pos = new_pos;
        let mut token_id = None;
        let mut uri = None;
        loop {
            if pos >= array.data.len() {
                return None;
            }
            match array.data[pos] {
                0xE1 => {
                    pos += 1;
                    break;
                }
                0xF1 => return None,
                _ => {}
            }
            let (tc, fc, new_pos) = parse_sle_field_header(&array.data, pos)?;
            pos = new_pos;
            match (tc, fc) {
                (5, 10) => {
                    if pos + 32 > array.data.len() {
                        return None;
                    }
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&array.data[pos..pos + 32]);
                    token_id = Some(id);
                    pos += 32;
                }
                (7, 5) => {
                    let (len, consumed) = crate::transaction::serialize::decode_length(&array.data[pos..]);
                    pos += consumed;
                    if pos + len > array.data.len() {
                        return None;
                    }
                    uri = Some(array.data[pos..pos + len].to_vec());
                    pos += len;
                }
                _ => return None,
            }
        }
        tokens.push(crate::ledger::nft_page::PageToken {
            nftoken_id: token_id?,
            uri,
        });
    }
    tokens.sort();
    Some(tokens)
}

fn nft_json(token: &crate::ledger::nft_page::PageToken) -> Value {
    let flags = u16::from_be_bytes([token.nftoken_id[0], token.nftoken_id[1]]);
    let transfer_fee = u16::from_be_bytes([token.nftoken_id[2], token.nftoken_id[3]]);
    let mut issuer = [0u8; 20];
    issuer.copy_from_slice(&token.nftoken_id[4..24]);
    let taxon = u32::from_be_bytes(token.nftoken_id[24..28].try_into().unwrap_or([0u8; 4]));
    let serial = u32::from_be_bytes(token.nftoken_id[28..32].try_into().unwrap_or([0u8; 4]));
    let mut obj = json!({
        "Flags": flags,
        "Issuer": crate::crypto::base58::encode_account(&issuer),
        "NFTokenID": hex::encode_upper(token.nftoken_id),
        "NFTokenTaxon": taxon,
        "TransferFee": transfer_fee,
        "nft_serial": serial,
    });
    if let Some(ref uri) = token.uri {
        obj["URI"] = json!(hex::encode_upper(uri));
    }
    obj
}

fn account_object_type_matches(entry_type: u16, type_filter: Option<&str>) -> bool {
    match type_filter {
        None => true,
        Some("state") => entry_type == 0x0072,
        Some("offer") => entry_type == 0x006f,
        Some("check") => entry_type == 0x0043,
        Some("escrow") => entry_type == 0x0075,
        Some("payment_channel") => entry_type == 0x0078,
        Some("ticket") => entry_type == 0x0054,
        Some("deposit_preauth") => entry_type == 0x0070,
        Some("did") => entry_type == 0x0049,
        Some("nft_page") => entry_type == 0x0050,
        Some("nft_offer") => entry_type == 0x0037,
        Some(_) => false,
    }
}

fn parse_account_objects_type(params: &Value) -> Result<Option<String>, RpcError> {
    match params.get("type") {
        None => Ok(None),
        Some(Value::String(s)) => match s.as_str() {
            "state" | "offer" | "check" | "escrow" | "payment_channel" |
            "ticket" | "deposit_preauth" | "did" | "nft_page" | "nft_offer" => Ok(Some(s.clone())),
            _ => Err(invalid_field("type")),
        },
        Some(_) => Err(invalid_field_not_string("type")),
    }
}

fn raw_object_owned_by_account(key: &[u8; 32], raw: &[u8], account_id: &[u8; 20]) -> Option<bool> {
    let Some(parsed) = crate::ledger::meta::parse_sle(raw) else {
        let tl = decode_ripple_state_any(raw)?;
        return Some(tl.low_account == *account_id || tl.high_account == *account_id);
    };
    match parsed.entry_type {
        0x0061 => Some(false),
        0x0072 => {
            let tl = decode_ripple_state_any(raw)?;
            Some(tl.low_account == *account_id || tl.high_account == *account_id)
        }
        0x0050 => Some(&key[..20] == account_id),
        _ => Some(
            sle_account_field(&parsed, 1) == Some(*account_id)
                || sle_account_field(&parsed, 2) == Some(*account_id),
        ),
    }
}

fn raw_object_summary(key: &[u8; 32], raw: &[u8]) -> Option<Value> {
    let Some(parsed) = crate::ledger::meta::parse_sle(raw) else {
        let tl = decode_ripple_state_any(raw)?;
        return Some(json!({
            "LedgerEntryType": "RippleState",
            "index": hex::encode_upper(key),
            "Balance": format_iou_value(&tl.balance),
            "LowLimit": format_iou_value(&tl.low_limit),
            "HighLimit": format_iou_value(&tl.high_limit),
            "currency": tl.currency.to_ascii(),
        }));
    };
    let mut out = json!({
        "LedgerEntryType": sle_entry_type_name(parsed.entry_type),
        "index": hex::encode_upper(key),
    });
    match parsed.entry_type {
        0x0072 => {
            let tl = decode_ripple_state_any(raw)?;
            out["Balance"] = json!(format_iou_value(&tl.balance));
            out["LowLimit"] = json!(format_iou_value(&tl.low_limit));
            out["HighLimit"] = json!(format_iou_value(&tl.high_limit));
            out["currency"] = json!(tl.currency.to_ascii());
        }
        0x006f => {
            let off = crate::ledger::offer::Offer::decode_from_sle(raw)?;
            out["Account"] = json!(crate::crypto::base58::encode_account(&off.account));
            out["Sequence"] = json!(off.sequence);
            out["TakerPays"] = format_amount(&off.taker_pays);
            out["TakerGets"] = format_amount(&off.taker_gets);
        }
        0x0078 => {
            let pc = parse_paychan_from_sle(raw)?;
            out["Account"] = json!(crate::crypto::base58::encode_account(&pc.account));
            out["Destination"] = json!(crate::crypto::base58::encode_account(&pc.destination));
            out["Amount"] = json!(pc.amount.to_string());
            out["Balance"] = json!(pc.balance.to_string());
        }
        0x0043 => {
            out["Account"] = json!(crate::crypto::base58::encode_account(&sle_account_field(&parsed, 1)?));
            out["Destination"] = json!(crate::crypto::base58::encode_account(&sle_account_field(&parsed, 3)?));
            out["SendMax"] = format_amount(&sle_amount_field(&parsed, 9)?);
        }
        0x0075 => {
            out["Account"] = json!(crate::crypto::base58::encode_account(&sle_account_field(&parsed, 1)?));
            out["Destination"] = json!(crate::crypto::base58::encode_account(&sle_account_field(&parsed, 3)?));
            out["Amount"] = format_amount(&sle_amount_field(&parsed, 1)?);
        }
        0x0054 => {
            out["Account"] = json!(crate::crypto::base58::encode_account(&sle_account_field(&parsed, 1)?));
            out["TicketSequence"] = json!(sle_u32_field(&parsed, 41)?);
        }
        0x0070 => {
            out["Account"] = json!(crate::crypto::base58::encode_account(&sle_account_field(&parsed, 1)?));
            out["Authorize"] = json!(crate::crypto::base58::encode_account(&sle_account_field(&parsed, 5)?));
        }
        0x0037 => {
            out["Owner"] = json!(crate::crypto::base58::encode_account(&sle_account_field(&parsed, 2)?));
            out["NFTokenID"] = json!(hex::encode_upper(sle_hash256_field(&parsed, 10)?));
            out["Amount"] = format_amount(&sle_amount_field(&parsed, 1)?);
            if let Some(dest) = sle_account_field(&parsed, 3) {
                out["Destination"] = json!(crate::crypto::base58::encode_account(&dest));
            }
            if let Some(exp) = sle_u32_field(&parsed, 10) {
                out["Expiration"] = json!(exp);
            }
            if let Some(flags) = sle_u32_field(&parsed, 2) {
                out["Flags"] = json!(flags);
            }
        }
        0x0049 => {
            out["Account"] = json!(crate::crypto::base58::encode_account(&sle_account_field(&parsed, 1)?));
            if let Some(uri) = sle_blob_field(&parsed, 5) {
                out["URI"] = json!(hex::encode_upper(uri));
            }
        }
        0x0050 => {
            let tokens = parse_nft_page_tokens(raw)?;
            out["NFTokens"] = json!(tokens.iter().map(|t| hex::encode_upper(t.nftoken_id)).collect::<Vec<_>>());
            if let Some(prev) = sle_hash256_field(&parsed, 26) {
                out["PreviousPageMin"] = json!(hex::encode_upper(prev));
            }
            if let Some(next) = sle_hash256_field(&parsed, 27) {
                out["NextPageMin"] = json!(hex::encode_upper(next));
            }
        }
        _ => {
            if let Some(account) = sle_account_field(&parsed, 1) {
                out["Account"] = json!(crate::crypto::base58::encode_account(&account));
            }
            if let Some(owner) = sle_account_field(&parsed, 2) {
                out["Owner"] = json!(crate::crypto::base58::encode_account(&owner));
            }
        }
    }
    Some(out)
}

fn nft_offer_summary(key: crate::ledger::Key, off: &crate::ledger::NFTokenOffer) -> Value {
    let mut out = json!({
        "LedgerEntryType": "NFTokenOffer",
        "index": hex::encode_upper(key.0),
        "Account": crate::crypto::base58::encode_account(&off.account),
        "NFTokenID": hex::encode_upper(off.nftoken_id),
        "Amount": format_amount(&off.amount),
        "Flags": off.flags,
    });
    if let Some(dest) = off.destination {
        out["Destination"] = json!(crate::crypto::base58::encode_account(&dest));
    }
    if let Some(exp) = off.expiration {
        out["Expiration"] = json!(exp);
    }
    out
}

fn parse_key_from_hex(raw: &Value, field: &str) -> Result<crate::ledger::Key, RpcError> {
    let s = raw.as_str().ok_or_else(|| invalid_field(field))?;
    let bytes = hex::decode(s).map_err(|_| invalid_field(field))?;
    if bytes.len() != 32 {
        return Err(invalid_field(field));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(crate::ledger::Key(out))
}

fn parse_account_value(raw: &Value, field: &str) -> Result<[u8; 20], RpcError> {
    let s = raw.as_str().ok_or_else(|| invalid_field(field))?;
    decode_account(s).map_err(|_| act_malformed())
}

fn parse_u32_value(raw: &Value, field: &str) -> Result<u32, RpcError> {
    match raw {
        Value::Number(n) => n
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| invalid_field(field)),
        Value::String(s) => s.parse::<u32>().map_err(|_| invalid_field(field)),
        _ => Err(invalid_field(field)),
    }
}

fn signer_list_key(account: &[u8; 20]) -> crate::ledger::Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&[0x00, 0x53]);
    data.extend_from_slice(account);
    data.extend_from_slice(&0u32.to_be_bytes());
    crate::ledger::Key(crate::crypto::sha512_first_half(&data))
}

fn resolve_ledger_entry_key(params: &Value) -> Result<crate::ledger::Key, RpcError> {
    if let Some(index) = params.get("index") {
        return parse_key_from_hex(index, "index");
    }
    if let Some(account) = params.get("account_root") {
        let account_id = parse_account_value(account, "account_root")?;
        return Ok(crate::ledger::account::shamap_key(&account_id));
    }
    if let Some(check) = params.get("check") {
        return parse_key_from_hex(check, "check");
    }
    if let Some(channel) = params.get("payment_channel") {
        return parse_key_from_hex(channel, "payment_channel");
    }
    if let Some(offer) = params.get("offer") {
        return match offer {
            Value::String(_) => parse_key_from_hex(offer, "offer"),
            Value::Object(map) => {
                let account = parse_account_value(
                    map.get("account").ok_or_else(|| invalid_field("offer"))?,
                    "account",
                )?;
                let seq = parse_u32_value(
                    map.get("seq").ok_or_else(|| invalid_field("offer"))?,
                    "seq",
                )?;
                Ok(crate::ledger::offer::shamap_key(&account, seq))
            }
            _ => Err(invalid_field("offer")),
        };
    }
    if let Some(escrow) = params.get("escrow") {
        return match escrow {
            Value::String(_) => parse_key_from_hex(escrow, "escrow"),
            Value::Object(map) => {
                let owner = parse_account_value(
                    map.get("owner").ok_or_else(|| invalid_field("escrow"))?,
                    "owner",
                )?;
                let seq = parse_u32_value(
                    map.get("seq").ok_or_else(|| invalid_field("escrow"))?,
                    "seq",
                )?;
                Ok(crate::ledger::escrow::shamap_key(&owner, seq))
            }
            _ => Err(invalid_field("escrow")),
        };
    }
    if let Some(ticket) = params.get("ticket") {
        return match ticket {
            Value::String(_) => parse_key_from_hex(ticket, "ticket"),
            Value::Object(map) => {
                let account = parse_account_value(
                    map.get("account").ok_or_else(|| invalid_field("ticket"))?,
                    "account",
                )?;
                let seq = parse_u32_value(
                    map.get("ticket_seq").ok_or_else(|| invalid_field("ticket"))?,
                    "ticket_seq",
                )?;
                Ok(crate::ledger::ticket::shamap_key(&account, seq))
            }
            _ => Err(invalid_field("ticket")),
        };
    }
    if let Some(dp) = params.get("deposit_preauth") {
        return match dp {
            Value::String(_) => parse_key_from_hex(dp, "deposit_preauth"),
            Value::Object(map) => {
                let owner = parse_account_value(
                    map.get("owner").ok_or_else(|| invalid_field("deposit_preauth"))?,
                    "owner",
                )?;
                let authorized = parse_account_value(
                    map.get("authorized").ok_or_else(|| invalid_field("deposit_preauth"))?,
                    "authorized",
                )?;
                Ok(crate::ledger::deposit_preauth::shamap_key(&owner, &authorized))
            }
            _ => Err(invalid_field("deposit_preauth")),
        };
    }
    if let Some(offer) = params.get("nft_offer") {
        return parse_key_from_hex(offer, "nft_offer");
    }
    if let Some(page) = params.get("nft_page") {
        return parse_key_from_hex(page, "nft_page");
    }
    if let Some(account) = params.get("did") {
        let account_id = parse_account_value(account, "did")?;
        return Ok(crate::ledger::did::shamap_key(&account_id));
    }
    if let Some(account) = params.get("signer_list") {
        let account_id = parse_account_value(account, "signer_list")?;
        return Ok(signer_list_key(&account_id));
    }
    for field in ["ripple_state", "state"] {
        if let Some(spec) = params.get(field) {
            return match spec {
                Value::Object(map) => {
                    let accounts = map
                        .get("accounts")
                        .and_then(Value::as_array)
                        .ok_or_else(|| invalid_field("accounts"))?;
                    if accounts.len() != 2 {
                        return Err(invalid_field("accounts"));
                    }
                    let account_a = parse_account_value(&accounts[0], "accounts")?;
                    let account_b = parse_account_value(&accounts[1], "accounts")?;
                    if account_a == account_b {
                        return Err(RpcError::invalid_params("Cannot have a trustline to self."));
                    }
                    let currency_code = map
                        .get("currency")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid_field("currency"))?;
                    let currency = crate::transaction::amount::Currency::from_code(currency_code)
                        .map_err(|_| invalid_field("currency"))?;
                    Ok(crate::ledger::trustline::shamap_key(&account_a, &account_b, &currency))
                }
                _ => Err(invalid_field(field)),
            };
        }
    }
    Err(RpcError::invalid_params(
        "missing ledger entry selector (supported: index, account_root, check, escrow, offer, payment_channel, ticket, deposit_preauth, nft_offer, nft_page, did, signer_list, ripple_state, state)",
    ))
}

pub fn ledger_entry(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let key = resolve_ledger_entry_key(params)?;
    let binary = parse_bool_field(params, "binary")?.unwrap_or(false);
    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let is_historical = requested_seq != ctx.ledger_seq;

    let raw = if is_historical {
        let header = {
            let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());
            match history.get_ledger(requested_seq) {
                Some(rec) => rec.header.clone(),
                None => return Err(lgr_not_found()),
            }
        };
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        let mut map = ls
            .historical_state_map_from_root(header.account_hash)
            .ok_or_else(|| RpcError::internal("historical ledger lookup unavailable"))?;
        map.get(&key)
    } else if let Some(ref cl) = ctx.closed_ledger {
        cl.get_raw(&key)
    } else {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        ls.get_raw_owned(&key)
    };

    let raw = raw.ok_or_else(|| RpcError::not_found("ledger entry"))?;
    if binary {
        return Ok(json!({
            "index": hex::encode_upper(key.0),
            "ledger_index": requested_seq,
            "node_binary": hex::encode_upper(raw),
            "validated": true,
        }));
    }

    let node = if raw.is_empty() {
        // Empty raw data — only occurs with legacy in-memory typed maps
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(off) = ls.get_nft_offer(&key) {
            nft_offer_summary(key, off)
        } else {
            json!({
                "LedgerEntryType": "Unknown",
                "index": hex::encode_upper(key.0),
            })
        }
    } else {
        raw_object_summary(&key.0, &raw).unwrap_or_else(|| {
            json!({
                "LedgerEntryType": "Unknown",
                "index": hex::encode_upper(key.0),
            })
        })
    };

    Ok(json!({
        "index": hex::encode_upper(key.0),
        "ledger_index": requested_seq,
        "node": node,
        "validated": true,
    }))
}

pub fn account_objects(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let address = params.get("account").and_then(Value::as_str).unwrap_or("");
    let account_id = parse_account_field(params, "account")?;
    let limit = parse_limit_field(params, 200, 400)?;
    let marker = match params.get("marker") {
        None => None,
        Some(Value::String(s)) => {
            let (_, entry) = s.split_once(',').ok_or_else(|| invalid_field("marker"))?;
            let bytes = hex::decode(entry).map_err(|_| invalid_field("marker"))?;
            if bytes.len() != 32 {
                return Err(invalid_field("marker"));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Some(key)
        }
        Some(_) => return Err(invalid_field_not_string("marker")),
    };
    let type_filter = parse_account_objects_type(params)?;
    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let is_historical = requested_seq != ctx.ledger_seq;

    let mut objects: Vec<(crate::ledger::Key, Value)> = Vec::new();
    if is_historical {
        let (_, mut map) = historical_state_map(
            requested_seq,
            ctx,
            "historical account_objects not available",
        )?;
        if map
            .get(&crate::ledger::account::shamap_key(&account_id))
            .is_none()
        {
            return Err(RpcError::not_found(address));
        }
        for (key, raw) in collect_historical_state_entries(&mut map)? {
            let Some(parsed) = crate::ledger::meta::parse_sle(&raw) else { continue; };
            if !account_object_type_matches(parsed.entry_type, type_filter.as_deref()) {
                continue;
            }
            if !raw_object_owned_by_account(&key.0, &raw, &account_id).unwrap_or(false) {
                continue;
            }
            if let Some(obj) = raw_object_summary(&key.0, &raw) {
                objects.push((key, obj));
            }
        }
    } else {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if ls.get_account(&account_id).is_none() {
            return Err(RpcError::not_found(address));
        }
        for (key, raw) in ls.iter_raw_entries() {
            let Some(parsed) = crate::ledger::meta::parse_sle(raw) else { continue; };
            if !account_object_type_matches(parsed.entry_type, type_filter.as_deref()) {
                continue;
            }
            if !raw_object_owned_by_account(&key.0, raw, &account_id).unwrap_or(false) {
                continue;
            }
            if let Some(obj) = raw_object_summary(&key.0, raw) {
                objects.push((key, obj));
            }
        }
    }

    objects.sort_by_key(|(key, _)| key.0);
    if let Some(mark) = marker {
        if !objects.iter().any(|(key, _)| key.0 == mark) {
            return Err(invalid_field("marker"));
        }
    }
    let mut out = Vec::new();
    let mut next_marker = None;
    let mut last_returned = None;
    for (key, obj) in objects {
        if let Some(mark) = marker {
            if key.0 <= mark {
                continue;
            }
        }
        if out.len() == limit {
            next_marker = last_returned;
            break;
        }
        out.push(obj);
        last_returned = Some(key.0);
    }

    let mut result = json!({
        "account": address,
        "account_objects": out,
    });
    if let Some(m) = next_marker {
        result["marker"] = json!(format!("0,{}", hex::encode_upper(m)));
    }
    Ok(result)
}

pub fn account_nfts(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let address = params.get("account").and_then(Value::as_str).unwrap_or("");
    let account_id = parse_account_field(params, "account")?;
    let limit = parse_limit_field(params, 200, 400)?;
    let marker = parse_hex_key_marker(params)?;
    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let is_historical = requested_seq != ctx.ledger_seq;

    let mut tokens: Vec<crate::ledger::nft_page::PageToken> = Vec::new();
    if is_historical {
        let (_, mut map) = historical_state_map(
            requested_seq,
            ctx,
            "historical account_nfts not available",
        )?;
        if map
            .get(&crate::ledger::account::shamap_key(&account_id))
            .is_none()
        {
            return Err(RpcError::not_found(address));
        }
        for (key, raw) in collect_historical_state_entries(&mut map)? {
            let Some(parsed) = crate::ledger::meta::parse_sle(&raw) else { continue; };
            if parsed.entry_type != 0x0050 || key.0[..20] != account_id[..] {
                continue;
            }
            if let Some(page_tokens) = parse_nft_page_tokens(&raw) {
                tokens.extend(page_tokens);
            }
        }
    } else {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if ls.get_account(&account_id).is_none() {
            return Err(RpcError::not_found(address));
        }
        for (_, page) in ls.iter_nft_pages_for(&account_id) {
            tokens.extend(page.tokens.clone());
        }
    }

    tokens.sort();
    if let Some(mark) = marker {
        if !tokens.iter().any(|t| t.nftoken_id == mark) {
            return Err(invalid_field("marker"));
        }
    }

    let mut out = Vec::new();
    let mut next_marker = None;
    let mut last_returned = None;
    for token in tokens {
        if let Some(mark) = marker {
            if token.nftoken_id <= mark {
                continue;
            }
        }
        if out.len() == limit {
            next_marker = last_returned;
            break;
        }
        out.push(nft_json(&token));
        last_returned = Some(token.nftoken_id);
    }

    let mut result = json!({
        "account": address,
        "account_nfts": out,
    });
    if let Some(m) = next_marker {
        result["marker"] = json!(hex::encode_upper(m));
    }
    Ok(result)
}

pub fn account_channels(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let address = params.get("account").and_then(Value::as_str).unwrap_or("");
    let account_id = parse_account_field(params, "account")?;
    let destination_filter = match params.get("destination_account") {
        None => None,
        Some(Value::String(s)) => Some(
            decode_account(s).map_err(|_| RpcError::invalid_params("malformed destination account"))?
        ),
        Some(_) => return Err(RpcError::invalid_params("malformed destination account")),
    };
    let limit = parse_limit_field(params, 200, 400)?;
    let marker = parse_hex_key_marker(params)?;
    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let is_historical = requested_seq != ctx.ledger_seq;

    let channel_json = |key: crate::ledger::Key, pc: &crate::ledger::PayChannel| {
        json!({
            "channel_id": hex::encode_upper(key.0),
            "account": crate::crypto::base58::encode_account(&pc.account),
            "destination_account": crate::crypto::base58::encode_account(&pc.destination),
            "amount": pc.amount.to_string(),
            "balance": pc.balance.to_string(),
            "public_key": hex::encode_upper(&pc.public_key),
            "public_key_hex": hex::encode_upper(&pc.public_key),
            "settle_delay": pc.settle_delay,
            "expiration": pc.expiration,
            "cancel_after": pc.cancel_after,
        })
    };

    let mut channels: Vec<(crate::ledger::Key, crate::ledger::PayChannel)>;
    if is_historical {
        let (_, mut map) = historical_state_map(
            requested_seq,
            ctx,
            "historical account_channels not available",
        )?;
        if map
            .get(&crate::ledger::account::shamap_key(&account_id))
            .is_none()
        {
            return Err(RpcError::not_found(address));
        }
        channels = collect_historical_state_entries(&mut map)?
            .into_iter()
            .filter_map(|(key, raw)| parse_paychan_from_sle(&raw).map(|pc| (key, pc)))
            .filter(|(_, pc)| pc.account == account_id)
            .filter(|(_, pc)| destination_filter.map(|d| pc.destination == d).unwrap_or(true))
            .collect();
    } else {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if ls.get_account(&account_id).is_none() {
            return Err(RpcError::not_found(address));
        }
        channels = ls.iter_paychans()
            .filter(|(_, pc)| pc.account == account_id)
            .filter(|(_, pc)| destination_filter.map(|d| pc.destination == d).unwrap_or(true))
            .map(|(k, pc)| (*k, pc.clone()))
            .collect();
    }

    channels.sort_by_key(|(key, _)| key.0);
    if let Some(mark) = marker {
        if !channels.iter().any(|(key, _)| key.0 == mark) {
            return Err(RpcError::invalid_params("invalid marker"));
        }
    }
    let mut out = Vec::new();
    let mut next_marker = None;
    let mut last_returned = None;
    for (key, pc) in channels {
        if let Some(mark) = marker {
            if key.0 <= mark {
                continue;
            }
        }
        if out.len() == limit {
            next_marker = last_returned;
            break;
        }
        out.push(channel_json(key, &pc));
        last_returned = Some(key.0);
    }

    let mut result = json!({
        "account": address,
        "channels": out,
    });
    if let Some(m) = next_marker {
        result["marker"] = json!(hex::encode_upper(m));
    }
    Ok(result)
}

pub fn account_currencies(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let address = params.get("account").and_then(Value::as_str).unwrap_or("");
    let account_id = parse_account_field(params, "account")?;
    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let is_historical = requested_seq != ctx.ledger_seq;

    let mut receive = std::collections::BTreeSet::new();
    let mut send = std::collections::BTreeSet::new();

    let process_line = |tl: &crate::ledger::trustline::RippleState,
                        receive: &mut std::collections::BTreeSet<String>,
                        send: &mut std::collections::BTreeSet<String>| {
        let bal = tl.balance_for(&account_id);
        let limit = if account_id == tl.low_account {
            &tl.low_limit
        } else {
            &tl.high_limit
        };
        let code = tl.currency.to_ascii();
        if iou_gt(limit, &bal) {
            receive.insert(code.clone());
        }
        if iou_gt(&bal, &crate::transaction::amount::IouValue::ZERO) {
            send.insert(code);
        }
    };

    if is_historical {
        // Historical account_currencies enumeration not available (no object_history CF).
        return Err(RpcError::internal("historical account_currencies not available"));
    } else {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if ls.get_account(&account_id).is_none() {
            return Err(RpcError::not_found(address));
        }
        for tl in ls.trustlines_for_account(&account_id) {
            process_line(tl, &mut receive, &mut send);
        }
    }

    Ok(json!({
        "receive_currencies": receive.into_iter().collect::<Vec<_>>(),
        "send_currencies": send.into_iter().collect::<Vec<_>>(),
    }))
}

pub fn random() -> Result<Value, RpcError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Generate 256 random bits (32 bytes) using a simple entropy source.
    // Hash timestamp + pid for uniqueness.
    let seed = format!(
        "{}-{}",
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
        std::process::id(),
    );
    let hash = crate::crypto::sha512_first_half(seed.as_bytes());
    Ok(json!({
        "random": hex::encode_upper(hash),
    }))
}

// ── ledger_closed ─────────────────────────────────────────────────────────────

pub fn ledger_closed(ctx: &NodeContext) -> Result<Value, RpcError> {
    Ok(json!({
        "ledger_hash": ctx.ledger_hash,
        "ledger_index": ctx.ledger_seq,
    }))
}

// ── ledger_current ────────────────────────────────────────────────────────────

pub fn ledger_current(ctx: &NodeContext) -> Result<Value, RpcError> {
    // Current (open) ledger is one ahead of the last validated
    Ok(json!({
        "ledger_current_index": ctx.ledger_seq + 1,
    }))
}

// ── deposit_authorized ────────────────────────────────────────────────────────

pub fn deposit_authorized(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let source_id = parse_account_field(params, "source_account")?;
    let dest_id = parse_account_field(params, "destination_account")?;

    let (has_deposit_auth, preauth_exists) = if let Some(ref cl) = ctx.closed_ledger {
        // New path: read from ClosedLedger via ReadView
        use crate::ledger::views::ReadView;
        let dest_kl = crate::ledger::keylet::account(&dest_id);
        let dest_sle = cl.read(&dest_kl)
            .ok_or_else(|| RpcError { code: "actNotFound", error_code: 19, message: "Destination account not found.".into(), extra: None })?;
        let dest_acct = crate::ledger::AccountRoot::decode(dest_sle.data())
            .map_err(|_| RpcError { code: "actNotFound", error_code: 19, message: "Destination account not found.".into(), extra: None })?;
        let deposit_auth_flag = crate::ledger::account::LSF_DEPOSIT_AUTH;
        let has_da = dest_acct.flags & deposit_auth_flag != 0;
        let preauth = if has_da && source_id != dest_id {
            let dp_kl = crate::ledger::keylet::deposit_preauth(&dest_id, &source_id);
            cl.exists(&dp_kl)
        } else {
            false
        };
        (has_da, preauth)
    } else {
        // Legacy path: in-memory state
        let state = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        let dest_acct = state.get_account(&dest_id)
            .ok_or_else(|| RpcError { code: "actNotFound", error_code: 19, message: "Destination account not found.".into(), extra: None })?;
        let deposit_auth_flag = crate::ledger::account::LSF_DEPOSIT_AUTH;
        let has_da = dest_acct.flags & deposit_auth_flag != 0;
        let preauth = if has_da && source_id != dest_id {
            let key = crate::ledger::deposit_preauth::shamap_key(&dest_id, &source_id);
            state.deposit_preauths.contains_key(&key)
        } else {
            false
        };
        (has_da, preauth)
    };

    let authorized = if !has_deposit_auth {
        true
    } else if source_id == dest_id {
        true
    } else {
        preauth_exists
    };

    Ok(json!({
        "deposit_authorized": authorized,
        "source_account": params.get("source_account").and_then(Value::as_str).unwrap_or(""),
        "destination_account": params.get("destination_account").and_then(Value::as_str).unwrap_or(""),
        "ledger_hash": ctx.ledger_hash,
        "ledger_current_index": ctx.ledger_seq,
    }))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{dispatch, NodeContext, RpcRequest};

    fn ctx() -> NodeContext {
        NodeContext {
            ledger_seq:  1000,
            ledger_hash: "A".repeat(64),
            ..Default::default()
        }
    }

    fn req(method: &str, params: Value) -> RpcRequest {
        RpcRequest { method: method.into(), params, id: json!(1) }
    }

    // ── server_info ───────────────────────────────────────────────────────────

    #[test]
    fn test_server_info_shape() {
        let resp = dispatch(req("server_info", json!({})), &mut ctx());
        let r = &resp.result;
        assert_eq!(r["status"], "success");
        assert!(r["info"]["build_version"].is_string());
        assert_eq!(r["info"]["validated_ledger"]["seq"], 1000);
        // server_state depends on ledger age — test ctx has close_time=0 so it's "syncing"
        let state = r["info"]["server_state"].as_str().unwrap();
        assert!(["full", "tracking", "syncing", "disconnected"].contains(&state));
    }

    #[test]
    fn test_server_info_complete_ledgers() {
        let mut c = ctx();
        // Populate history so complete_ledgers is non-empty
        let hdr = crate::ledger::LedgerHeader {
            sequence: 1000, hash: [0u8; 32], parent_hash: [0u8; 32],
            close_time: 0, total_coins: 0, account_hash: [0u8; 32],
            transaction_hash: [0u8; 32],
            parent_close_time: 0, close_time_resolution: 10, close_flags: 0,
        };
        c.history.write().unwrap().insert_ledger(hdr, vec![]);
        let resp = dispatch(req("server_info", json!({})), &mut c);
        assert_eq!(resp.result["info"]["complete_ledgers"], "1000-1000");
    }

    #[test]
    fn test_storage_info_exposed_when_storage_present() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = std::sync::Arc::new(crate::storage::Storage::open(tmp.path()).unwrap());
        let mut c = ctx();
        c.storage = Some(storage);

        let resp = dispatch(req("storage_info", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["engine"], "SQLite + NuDB");
        assert!(resp.result["sqlite"]["ledgers"].is_number());
    }

    // ── ping ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_ping_returns_success() {
        let resp = dispatch(req("ping", json!({})), &mut ctx());
        assert_eq!(resp.result["status"], "success");
    }

    // ── fee ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_fee_shape() {
        let resp = dispatch(req("fee", json!({})), &mut ctx());
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["drops"]["base_fee"], "10");
        assert!(resp.result["ledger_current_index"].is_number());
    }

    // ── account_info ──────────────────────────────────────────────────────────

    #[test]
    fn test_account_info_missing_param() {
        let resp = dispatch(req("account_info", json!({})), &mut ctx());
        assert_eq!(resp.result["status"], "error");
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_info_bad_address() {
        let resp = dispatch(req("account_info", json!({"account": "not_an_address"})), &mut ctx());
        assert_eq!(resp.result["status"], "error");
        assert_eq!(resp.result["error"], "actMalformed");
    }

    #[test]
    fn test_account_info_unfunded_not_found() {
        let resp = dispatch(
            req("account_info", json!({"account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"})),
            &mut ctx(), // ctx() has an empty ledger state
        );
        assert_eq!(resp.result["status"], "error");
        assert_eq!(resp.result["error"], "actNotFound");
    }

    fn ctx_with_genesis() -> NodeContext {
        use crate::crypto::keys::Secp256k1KeyPair;
        use crate::ledger::AccountRoot;

        let kp = Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap();
        let account_id = crate::crypto::account_id(&kp.public_key_bytes());

        let ctx = NodeContext {
            ledger_seq:  1,
            ledger_hash: "A".repeat(64),
            ..Default::default()
        };
        ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner()).insert_account(AccountRoot {
            account_id,
            balance:     100_000_000_000_000_000,
            sequence:    1,
            owner_count: 0,
            flags:       0,
            regular_key: None, minted_nftokens: 0, burned_nftokens: 0,
            transfer_rate: 0, domain: Vec::new(), tick_size: 0, ticket_count: 0,
            previous_txn_id: [0u8; 32], previous_txn_lgr_seq: 0, raw_sle: None,
        });
        ctx
    }

    fn ctx_with_trustlines_and_offers() -> (NodeContext, [u8; 20], [u8; 20], [u8; 20]) {
        use crate::crypto::keys::Secp256k1KeyPair;
        use crate::ledger::{AccountRoot, offer::Offer, trustline::RippleState};
        use crate::transaction::amount::{Amount, Currency, IouValue};

        let alice = Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap();
        let bob = Secp256k1KeyPair::generate();
        let carol = Secp256k1KeyPair::generate();
        let alice_id = crate::crypto::account_id(&alice.public_key_bytes());
        let bob_id = crate::crypto::account_id(&bob.public_key_bytes());
        let carol_id = crate::crypto::account_id(&carol.public_key_bytes());

        let ctx = NodeContext {
            ledger_seq:  1,
            ledger_hash: "A".repeat(64),
            ..Default::default()
        };
        {
            let ls = &mut *ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            for account_id in [alice_id, bob_id, carol_id] {
                ls.insert_account(AccountRoot {
                    account_id,
                    balance: 100_000_000_000,
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
                    previous_txn_lgr_seq: 0, raw_sle: None,
                });
            }

            let usd = Currency::from_code("USD").unwrap();
            let mut tl_bob = RippleState::new(&alice_id, &bob_id, usd.clone());
            tl_bob.low_limit = IouValue::from_f64(100.0);
            tl_bob.high_limit = IouValue::from_f64(100.0);
            ls.insert_trustline(tl_bob);

            let mut tl_carol = RippleState::new(&alice_id, &carol_id, usd);
            tl_carol.low_limit = IouValue::from_f64(50.0);
            tl_carol.high_limit = IouValue::from_f64(50.0);
            ls.insert_trustline(tl_carol);

            ls.insert_offer(Offer {
                account: alice_id,
                sequence: 1,
                taker_pays: Amount::Xrp(1_000_000),
                taker_gets: Amount::Iou {
                    value: IouValue::from_f64(1.0),
                    currency: Currency::from_code("USD").unwrap(),
                    issuer: bob_id,
                },
                flags: 0,
                book_directory: [0u8; 32],
                book_node: 0,
                owner_node: 0,
                expiration: None,
                domain_id: None,
                additional_books: Vec::new(),
                previous_txn_id: [0u8; 32],
                previous_txn_lgr_seq: 0,
                raw_sle: None,
            });
            ls.insert_offer(Offer {
                account: bob_id,
                sequence: 2,
                taker_pays: Amount::Xrp(2_000_000),
                taker_gets: Amount::Iou {
                    value: IouValue::from_f64(2.0),
                    currency: Currency::from_code("USD").unwrap(),
                    issuer: bob_id,
                },
                flags: 0,
                book_directory: [0u8; 32],
                book_node: 0,
                owner_node: 0,
                expiration: None,
                domain_id: None,
                additional_books: Vec::new(),
                previous_txn_id: [0u8; 32],
                previous_txn_lgr_seq: 0,
                raw_sle: None,
            });
        }

        (ctx, alice_id, bob_id, carol_id)
    }

    fn ctx_with_historical_state(
        state: crate::ledger::LedgerState,
        requested_seq: u32,
        ledger_hash: [u8; 32],
    ) -> NodeContext {
        let root_hash = state.nudb_root_hash().expect("historical test requires NuDB root");
        state.flush_nudb().unwrap();

        let ctx = NodeContext {
            ledger_seq: requested_seq + 100,
            ledger_hash: "C".repeat(64),
            ledger_state: std::sync::Arc::new(std::sync::Mutex::new(state)),
            ..Default::default()
        };
        let header = crate::ledger::LedgerHeader {
            sequence: requested_seq,
            hash: ledger_hash,
            parent_hash: [0u8; 32],
            close_time: 0,
            total_coins: 100_000_000_000_000_000,
            account_hash: root_hash,
            transaction_hash: [0u8; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };
        ctx.history.write().unwrap().insert_ledger(header, vec![]);
        ctx
    }

    #[test]
    fn test_account_info_genesis_account() {
        let resp = dispatch(
            req("account_info", json!({"account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"})),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["status"], "success");
        let data = &resp.result["account_data"];
        assert_eq!(data["Account"], "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh");
        assert_eq!(data["Balance"], "100000000000000000");
        assert_eq!(data["Sequence"], 1);
        assert_eq!(data["OwnerCount"], 0);
        assert_eq!(data["LedgerEntryType"], "AccountRoot");
        // index is a 64-char uppercase hex string
        let index = data["index"].as_str().unwrap();
        assert_eq!(index.len(), 64);
        assert!(index.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(resp.result["validated"], true);
    }

    #[test]
    fn test_account_info_historical_uses_nudb_root() {
        use crate::ledger::node_store::NuDBNodeStore;

        let tmp = tempfile::tempdir().unwrap();
        let backend = std::sync::Arc::new(NuDBNodeStore::open(tmp.path()).unwrap());
        let mut seeded = crate::ledger::LedgerState::new();
        seeded.set_nudb_shamap(crate::ledger::SHAMap::with_backend(
            crate::ledger::MapType::AccountState,
            backend,
        ));

        let account =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        seeded.insert_account(crate::ledger::AccountRoot {
            account_id: account,
            balance: 123_456_789,
            sequence: 7,
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
        let _ = seeded.take_dirty();
        let root = seeded.nudb_root_hash().unwrap();

        let header = crate::ledger::LedgerHeader {
            sequence: 500,
            hash: [0x77; 32],
            parent_hash: [0u8; 32],
            close_time: 0,
            total_coins: 100_000_000_000_000_000,
            account_hash: root,
            transaction_hash: [0u8; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };

        let mut c = ctx();
        c.ledger_state = std::sync::Arc::new(std::sync::Mutex::new(seeded));
        c.history.write().unwrap().insert_ledger(header, vec![]);

        let resp = dispatch(
            req("account_info", json!({
                "account": crate::crypto::base58::encode_account(&account),
                "ledger_index": 500
            })),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["account_data"]["Balance"], "123456789");
        assert_eq!(resp.result["account_data"]["Sequence"], 7);
    }

    #[test]
    fn test_account_info_different_account_not_found() {
        let resp = dispatch(
            req("account_info", json!({"account": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"})),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["error"], "actNotFound");
    }

    #[test]
    fn test_account_info_invalid_ledger_index() {
        let resp = dispatch(
            req("account_info", json!({
                "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                "ledger_index": "not_a_ledger"
            })),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_lines_peer_filter() {
        let (mut c, alice_id, bob_id, _) = ctx_with_trustlines_and_offers();
        let alice_addr = crate::crypto::base58::encode_account(&alice_id);
        let bob_addr = crate::crypto::base58::encode_account(&bob_id);
        let resp = dispatch(
            req("account_lines", json!({
                "account": alice_addr,
                "peer": bob_addr
            })),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["lines"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_account_lines_marker_rejected() {
        let resp = dispatch(
            req("account_lines", json!({
                "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                "marker": "deadbeef"
            })),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_lines_marker_paginates_without_skipping() {
        let (mut c, alice_id, _, _) = ctx_with_trustlines_and_offers();
        let first = dispatch(
            req("account_lines", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "limit": 1
            })),
            &mut c,
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();
        assert_eq!(first.result["lines"].as_array().unwrap().len(), 1);

        let second = dispatch(
            req("account_lines", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "limit": 1,
                "marker": marker
            })),
            &mut c,
        );
        assert_eq!(second.result["lines"].as_array().unwrap().len(), 1);
        assert_ne!(first.result["lines"][0], second.result["lines"][0]);
    }

    // ── submit ────────────────────────────────────────────────────────────────

    fn genesis_payment(seq: u32, amount: u64) -> String {
        use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
        use crate::transaction::{Amount, builder::TxBuilder};
        let kp = KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap(),
        );
        TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap()
            .amount(Amount::Xrp(amount))
            .fee(12)
            .sequence(seq)
            .sign(&kp).unwrap()
            .blob_hex()
    }

    fn ctx_with_account_tx_history() -> (NodeContext, String) {
        use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
        use crate::ledger::history::TxRecord;
        use crate::transaction::{Amount, builder::TxBuilder};

        let kp = KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap(),
        );
        let account = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".to_string();
        let destination = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
        let ctx = ctx_with_genesis();

        for (seq, amount) in [(10u32, 1_000_000u64), (11, 2_000_000), (12, 3_000_000)] {
            let signed = TxBuilder::payment()
                .account(&kp)
                .destination(destination).unwrap()
                .amount(Amount::Xrp(amount))
                .fee(12)
                .sequence(seq)
                .sign(&kp)
                .unwrap();
            let header = crate::ledger::LedgerHeader {
                sequence: seq,
                hash: [seq as u8; 32],
                parent_hash: [0u8; 32],
                close_time: seq as u64,
                total_coins: 100_000_000_000_000_000,
                account_hash: [0u8; 32],
                transaction_hash: [0u8; 32],
                parent_close_time: 0,
                close_time_resolution: 10,
                close_flags: 0,
            };
            ctx.history.write().unwrap_or_else(|e| e.into_inner()).insert_ledger(
                header,
                vec![TxRecord {
                    blob: signed.blob,
                    meta: Vec::new(),
                    hash: signed.hash,
                    ledger_seq: seq,
                    tx_index: 0,
                    result: "tesSUCCESS".into(),
                }],
            );
        }

        (ctx, account)
    }

    #[test]
    fn test_tx_response_meta_includes_affected_nodes_and_index() {
        use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
        use crate::ledger::close::close_ledger;
        use crate::ledger::TxPool;
        use crate::transaction::{Amount, builder::TxBuilder};

        let kp = KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap(),
        );
        let destination = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination(destination).unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();
        let parsed = crate::transaction::parse_blob(&signed.blob).unwrap();

        let mut ctx = ctx_with_genesis();
        ctx.ledger_header.sequence = 1;
        ctx.ledger_seq = 1;

        let mut pool = TxPool::new();
        assert!(pool.insert(signed.hash, signed.blob.clone(), &parsed));

        let result = {
            let mut ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            close_ledger(&ctx.ledger_header, &mut ls, &mut pool, 10, true)
        };
        ctx.history.write().unwrap_or_else(|e| e.into_inner()).insert_ledger(result.header.clone(), result.tx_records.clone());
        ctx.ledger_header = result.header.clone();
        ctx.ledger_seq = result.header.sequence;

        let tx_json = tx_record_response(&result.tx_records[0], &ctx, false);
        assert_eq!(tx_json["meta"]["TransactionResult"], "tesSUCCESS");
        assert_eq!(tx_json["meta"]["TransactionIndex"], 0);
        assert!(tx_json["meta"]["AffectedNodes"].is_array());
        assert!(!tx_json["meta"]["AffectedNodes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_submit_missing_blob() {
        let resp = dispatch(req("submit", json!({})), &mut ctx());
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_submit_invalid_hex() {
        let resp = dispatch(req("submit", json!({"tx_blob": "not-hex!"})), &mut ctx());
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_submit_rejects_oversized_blob() {
        let oversized = "AA".repeat(1_048_577);
        let resp = dispatch(req("submit", json!({"tx_blob": oversized})), &mut ctx());
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(resp.result["error_message"], "Invalid parameters: tx_blob too large");
    }

    #[test]
    fn test_submit_success_with_funded_account() {
        let blob = genesis_payment(1, 1_000_000);
        let resp = dispatch(
            req("submit", json!({"tx_blob": blob})),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["engine_result"], "tesSUCCESS");
        let hash = resp.result["tx_json"]["hash"].as_str().unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_submit_hash_matches_signed_tx() {
        use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
        use crate::transaction::{Amount, builder::TxBuilder};
        let kp = KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap(),
        );
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12).sequence(1).sign(&kp).unwrap();

        let resp = dispatch(
            req("submit", json!({"tx_blob": signed.blob_hex()})),
            &mut ctx_with_genesis(),
        );
        assert_eq!(
            resp.result["tx_json"]["hash"].as_str().unwrap(),
            signed.hash_hex(),
        );
    }

    #[test]
    fn test_submit_no_account_returns_ter() {
        // ctx() has empty ledger state — no accounts
        let blob = genesis_payment(1, 1_000_000);
        let resp = dispatch(req("submit", json!({"tx_blob": blob})), &mut ctx());
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["engine_result"], "terNO_ACCOUNT");
    }

    #[test]
    fn test_submit_wrong_sequence_past() {
        // Sequence 0, but account expects 1 → tefPAST_SEQ
        let blob = genesis_payment(0, 1_000_000);
        let resp = dispatch(
            req("submit", json!({"tx_blob": blob})),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["engine_result"], "tefPAST_SEQ");
    }

    #[test]
    fn test_submit_wrong_sequence_future() {
        // Sequence 99 but account is at 1 → terPRE_SEQ
        let blob = genesis_payment(99, 1_000_000);
        let resp = dispatch(
            req("submit", json!({"tx_blob": blob})),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["engine_result"], "terPRE_SEQ");
    }

    #[test]
    fn test_submit_insufficient_balance() {
        use crate::crypto::keys::Secp256k1KeyPair;
        use crate::ledger::AccountRoot;

        // Fund account with only 100 drops
        let kp = Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap();
        let account_id = crate::crypto::account_id(&kp.public_key_bytes());
        let mut ctx = NodeContext { ledger_seq: 1, ledger_hash: "A".repeat(64), ..Default::default() };
        ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner()).insert_account(AccountRoot {
            account_id, balance: 100, sequence: 1, owner_count: 0, flags: 0, regular_key: None, minted_nftokens: 0, burned_nftokens: 0,
            transfer_rate: 0, domain: Vec::new(), tick_size: 0, ticket_count: 0,
            previous_txn_id: [0u8; 32], previous_txn_lgr_seq: 0, raw_sle: None,
        });

        // Try to send 1 XRP = 1_000_000 drops (way more than 100)
        let blob = genesis_payment(1, 1_000_000);
        let resp = dispatch(req("submit", json!({"tx_blob": blob})), &mut ctx);
        assert_eq!(resp.result["engine_result"], "tecINSUFFICIENT_FUNDS");
    }

    #[test]
    fn test_submit_bad_signature() {
        // Tamper the last 10 bytes of the blob (signature area) to corrupt the sig
        let blob_hex = genesis_payment(1, 1_000_000);
        let mut blob = hex::decode(&blob_hex).unwrap();
        let len = blob.len();
        for b in &mut blob[len - 10..] { *b ^= 0xFF; }
        let tampered = hex::encode_upper(blob);
        let resp = dispatch(
            req("submit", json!({"tx_blob": tampered})),
            &mut ctx_with_genesis(),
        );
        // Either temBAD_SIGNATURE or a parse error (invalidParams) — both are rejections
        let r = &resp.result;
        let is_rejection =
            r["engine_result"] == "temBAD_SIGNATURE" ||
            r["error"] == "invalidParams";
        assert!(is_rejection, "tampered tx must be rejected: {r}");
    }

    // ── tx ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_tx_missing_param() {
        let resp = dispatch(req("tx", json!({})), &mut ctx());
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_tx_bad_hash() {
        let resp = dispatch(req("tx", json!({"transaction": "tooshort"})), &mut ctx());
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_tx_not_found() {
        let hash = "A".repeat(64);
        let resp = dispatch(req("tx", json!({"transaction": hash})), &mut ctx());
        assert_eq!(resp.result["error"], "txnNotFound");
    }

    #[test]
    fn test_tx_json_and_binary_modes() {
        let (mut c, _account) = ctx_with_account_tx_history();
        c.network_id = 0;
        let hash = hex::encode_upper(c.history.read().unwrap().ledger_txs(10)[0].hash);

        let json_resp = dispatch(
            req("tx", json!({"transaction": hash, "binary": false})),
            &mut c,
        );
        assert_eq!(json_resp.result["status"], "success");
        assert_eq!(json_resp.result["tx_json"]["TransactionType"], "Payment");
        assert_eq!(json_resp.result["tx_json"]["DeliverMax"], "1000000");
        assert!(json_resp.result["tx_json"].get("Amount").is_none());
        assert!(json_resp.result.get("tx_blob").is_none());
        assert_eq!(json_resp.result["ctid"], "C000000A00000000");
        assert_eq!(json_resp.result["close_time_iso"], "2000-01-01T00:00:10Z");

        let binary_resp = dispatch(
            req("tx", json!({"transaction": hash, "binary": true})),
            &mut c,
        );
        assert_eq!(binary_resp.result["status"], "success");
        assert!(binary_resp.result.get("tx_blob").is_some());
        assert!(binary_resp.result.get("tx_json").is_none());
        assert_eq!(binary_resp.result["ctid"], "C000000A00000000");
    }

    #[test]
    fn test_tx_range_found_and_not_found_shapes() {
        let (mut c, _account) = ctx_with_account_tx_history();
        let oldest = hex::encode_upper(c.history.read().unwrap().ledger_txs(10)[0].hash);

        let found = dispatch(
            req("tx", json!({
                "transaction": oldest,
                "binary": true,
                "min_ledger": 10,
                "max_ledger": 12
            })),
            &mut c,
        );
        assert_eq!(found.result["status"], "success");
        assert_eq!(found.result["ledger_index"], 10);

        let not_found_complete = dispatch(
            req("tx", json!({
                "transaction": "A".repeat(64),
                "binary": true,
                "min_ledger": 10,
                "max_ledger": 12
            })),
            &mut c,
        );
        assert_eq!(not_found_complete.result["error"], "txnNotFound");
        assert_eq!(not_found_complete.result["searched_all"], true);

        let not_found_incomplete = dispatch(
            req("tx", json!({
                "transaction": "B".repeat(64),
                "binary": true,
                "min_ledger": 10,
                "max_ledger": 99
            })),
            &mut c,
        );
        assert_eq!(not_found_incomplete.result["error"], "txnNotFound");
        assert_eq!(not_found_incomplete.result["searched_all"], false);
    }

    #[test]
    fn test_tx_invalid_and_excessive_ranges() {
        let resp = dispatch(
            req("tx", json!({
                "transaction": "A".repeat(64),
                "min_ledger": 12,
                "max_ledger": 10
            })),
            &mut ctx(),
        );
        assert_eq!(resp.result["error"], "invalidLgrRange");

        let resp = dispatch(
            req("tx", json!({
                "transaction": "A".repeat(64),
                "min_ledger": 1,
                "max_ledger": 1002
            })),
            &mut ctx(),
        );
        assert_eq!(resp.result["error"], "excessiveLgrRange");
    }

    #[test]
    fn test_tx_ctid_lookup_and_wrong_network() {
        let (mut c, _account) = ctx_with_account_tx_history();
        c.network_id = 0;
        let ctid = encode_ctid(12, 0, 0).unwrap();

        let resp = dispatch(
            req("tx", json!({
                "ctid": ctid.to_lowercase(),
                "binary": false
            })),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["ledger_index"], 12);
        assert_eq!(resp.result["ctid"], ctid);

        let wrong = dispatch(
            req("tx", json!({
                "ctid": encode_ctid(12, 0, 1).unwrap()
            })),
            &mut c,
        );
        assert_eq!(wrong.result["error"], "wrongNetwork");
        assert_eq!(wrong.result["error_code"], 4);
    }

    #[test]
    fn test_tx_transaction_and_ctid_rejected() {
        let mut c = ctx();
        let resp = dispatch(
            req("tx", json!({
                "transaction": "A".repeat(64),
                "ctid": encode_ctid(12, 0, 0).unwrap()
            })),
            &mut c,
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_tx_range_and_forward() {
        let (mut c, account) = ctx_with_account_tx_history();
        let resp = dispatch(
            req("account_tx", json!({
                "account": account,
                "ledger_index_min": 11,
                "ledger_index_max": 12,
                "forward": true,
                "binary": true
            })),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        let txs = resp.result["transactions"].as_array().unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0]["ledger_index"], 11);
        assert_eq!(txs[1]["ledger_index"], 12);
        assert!(txs[0].get("tx_blob").is_some());
        assert!(txs[0].get("tx_json").is_none());
    }

    #[test]
    fn test_account_tx_marker_paginates_without_skipping() {
        let (mut c, account) = ctx_with_account_tx_history();
        let first = dispatch(
            req("account_tx", json!({
                "account": account,
                "limit": 1
            })),
            &mut c,
        );
        assert_eq!(first.result["status"], "success");
        assert_eq!(first.result["transactions"].as_array().unwrap().len(), 1);
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let second = dispatch(
            req("account_tx", json!({
                "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                "limit": 1,
                "marker": marker
            })),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(second.result["transactions"].as_array().unwrap().len(), 1);
        assert_ne!(first.result["transactions"][0]["hash"], second.result["transactions"][0]["hash"]);
    }

    #[test]
    fn test_account_tx_invalid_limit_rejected() {
        let (mut c, account) = ctx_with_account_tx_history();
        let resp = dispatch(
            req("account_tx", json!({
                "account": account,
                "limit": "not_an_int"
            })),
            &mut c,
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_tx_exact_missing_ledger_not_found() {
        let (mut c, account) = ctx_with_account_tx_history();
        let resp = dispatch(
            req("account_tx", json!({
                "account": account,
                "ledger_index": 999
            })),
            &mut c,
        );
        assert_eq!(resp.result["error"], "lgrNotFound");
    }

    #[test]
    fn test_account_tx_count_and_offset() {
        let (mut c, account) = ctx_with_account_tx_history();
        let resp = dispatch(
            req("account_tx", json!({
                "account": account,
                "count": true,
                "offset": 1,
                "limit": 1
            })),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["count"], 3);
        let txs = resp.result["transactions"].as_array().unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0]["ledger_index"], 11);
    }

    #[test]
    fn test_account_tx_json_mode_returns_tx_json() {
        let (mut c, account) = ctx_with_account_tx_history();
        c.network_id = 0;
        let resp = dispatch(
            req("account_tx", json!({
                "account": account,
                "limit": 1,
                "binary": false
            })),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        let tx = &resp.result["transactions"][0];
        assert_eq!(tx["tx_json"]["TransactionType"], "Payment");
        assert_eq!(tx["tx_json"]["DeliverMax"], "3000000");
        assert!(tx["tx_json"].get("Amount").is_none());
        assert_eq!(tx["meta"]["TransactionResult"], "tesSUCCESS");
        assert!(tx.get("tx_blob").is_none());
        assert_eq!(tx["ctid"], "C000000C00000000");
        assert_eq!(tx["close_time_iso"], "2000-01-01T00:00:12Z");
    }

    #[test]
    fn test_tx_invalid_binary_rejected() {
        let resp = dispatch(
            req("tx", json!({
                "transaction": "A".repeat(64),
                "binary": "yes"
            })),
            &mut ctx(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(resp.result["error_message"], "Invalid parameters: Invalid field 'binary'.");
    }

    #[test]
    fn test_account_tx_invalid_binary_rejected() {
        let (mut c, account) = ctx_with_account_tx_history();
        let resp = dispatch(
            req("account_tx", json!({
                "account": account,
                "binary": "yes"
            })),
            &mut c,
        );
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(resp.result["error_message"], "Invalid parameters: Invalid field 'binary'.");
    }

    #[test]
    fn test_account_offers_marker_paginates_without_skipping() {
        let (mut c, alice_id, bob_id, _) = ctx_with_trustlines_and_offers();
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            ls.insert_offer(crate::ledger::Offer {
                account: alice_id,
                sequence: 3,
                taker_pays: crate::transaction::amount::Amount::Xrp(3_000_000),
                taker_gets: crate::transaction::amount::Amount::Iou {
                    value: crate::transaction::amount::IouValue::from_f64(3.0),
                    currency: crate::transaction::amount::Currency::from_code("USD").unwrap(),
                    issuer: bob_id,
                },
                flags: 0,
                book_directory: [0u8; 32],
                book_node: 0,
                owner_node: 0,
                expiration: None,
                domain_id: None,
                additional_books: Vec::new(),
                previous_txn_id: [0u8; 32],
                previous_txn_lgr_seq: 0,
                raw_sle: None,
            });
        }
        let first = dispatch(
            req("account_offers", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "limit": 1
            })),
            &mut c,
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();
        assert_eq!(first.result["offers"].as_array().unwrap().len(), 1);

        let second = dispatch(
            req("account_offers", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "limit": 1,
                "marker": marker
            })),
            &mut c,
        );
        assert_eq!(second.result["offers"].as_array().unwrap().len(), 1);
        assert_ne!(first.result["offers"][0], second.result["offers"][0]);
    }

    #[test]
    fn test_book_offers_marker_paginates_without_skipping() {
        let (mut c, _, bob_id, _) = ctx_with_trustlines_and_offers();
        let issuer = crate::crypto::base58::encode_account(&bob_id);
        let first = dispatch(
            req("book_offers", json!({
                "taker_pays": {"currency": "XRP"},
                "taker_gets": {"currency": "USD", "issuer": issuer},
                "limit": 1
            })),
            &mut c,
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();
        assert_eq!(first.result["offers"].as_array().unwrap().len(), 1);

        let second = dispatch(
            req("book_offers", json!({
                "taker_pays": {"currency": "XRP"},
                "taker_gets": {"currency": "USD", "issuer": crate::crypto::base58::encode_account(&bob_id)},
                "limit": 1,
                "marker": marker
            })),
            &mut c,
        );
        assert_eq!(second.result["offers"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_book_offers_enriched_fields_and_owner_funds() {
        use crate::ledger::{AccountRoot, offer::Offer, trustline::RippleState};
        use crate::transaction::amount::{Amount, Currency, IouValue};

        let mut c = ctx();
        let issuer = crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let owner = crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap();
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            for account_id in [issuer, owner] {
                ls.insert_account(AccountRoot {
                    account_id,
                    balance: 100_000_000_000,
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
                    previous_txn_lgr_seq: 0, raw_sle: None,
                });
            }

            let usd = Currency::from_code("USD").unwrap();
            let mut tl = RippleState::new(&owner, &issuer, usd.clone());
            tl.low_limit = IouValue::from_f64(1000.0);
            tl.high_limit = IouValue::from_f64(1000.0);
            tl.balance = if tl.low_account == owner {
                IouValue::from_f64(100.0)
            } else {
                IouValue::from_f64(-100.0)
            };
            ls.insert_trustline(tl);

            ls.insert_offer(Offer {
                account: owner,
                sequence: 5,
                taker_pays: Amount::Xrp(4_000_000_000),
                taker_gets: Amount::Iou {
                    value: IouValue::from_f64(10.0),
                    currency: usd,
                    issuer,
                },
                flags: 0,
                book_directory: [0xAB; 32],
                book_node: 0,
                owner_node: 0,
                expiration: None,
                domain_id: None,
                additional_books: Vec::new(),
                previous_txn_id: [0u8; 32],
                previous_txn_lgr_seq: 0,
                raw_sle: None,
            });
        }

        let resp = dispatch(
            req("book_offers", json!({
                "taker_pays": {"currency": "XRP"},
                "taker_gets": {"currency": "USD", "issuer": crate::crypto::base58::encode_account(&issuer)}
            })),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        let offer = &resp.result["offers"][0];
        assert_eq!(offer["Account"], crate::crypto::base58::encode_account(&owner));
        assert_eq!(offer["LedgerEntryType"], "Offer");
        assert_eq!(offer["BookDirectory"], hex::encode_upper([0xAB; 32]));
        assert_eq!(offer["BookNode"], "0");
        assert_eq!(offer["OwnerNode"], "0");
        assert_eq!(offer["owner_funds"], "100");
        assert_eq!(offer["quality"], "400000000");
    }

    #[test]
    fn test_account_currencies_current() {
        let (mut c, alice_id, bob_id, carol_id) = ctx_with_trustlines_and_offers();
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
            let key = crate::ledger::trustline::shamap_key(&alice_id, &bob_id, &usd);
            let mut tl = ls.get_trustline(&key).unwrap().clone();
            tl.balance = if alice_id == tl.low_account {
                crate::transaction::amount::IouValue::from_f64(10.0)
            } else {
                crate::transaction::amount::IouValue::from_f64(-10.0)
            };
            ls.insert_trustline(tl);

            let eur = crate::transaction::amount::Currency::from_code("EUR").unwrap();
            let mut tl2 = crate::ledger::trustline::RippleState::new(&alice_id, &carol_id, eur);
            tl2.low_limit = crate::transaction::amount::IouValue::from_f64(20.0);
            tl2.high_limit = crate::transaction::amount::IouValue::from_f64(20.0);
            ls.insert_trustline(tl2);
        }
        let resp = dispatch(
            req("account_currencies", json!({
                "account": crate::crypto::base58::encode_account(&alice_id)
            })),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        let recv = resp.result["receive_currencies"].as_array().unwrap();
        let send = resp.result["send_currencies"].as_array().unwrap();
        assert!(recv.iter().any(|v| v == "USD"));
        assert!(recv.iter().any(|v| v == "EUR"));
        assert!(send.iter().any(|v| v == "USD"));
        assert!(!send.iter().any(|v| v == "EUR"));
    }

    #[test]
    fn test_account_currencies_historical() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = std::sync::Arc::new(crate::storage::Storage::open(tmp.path()).unwrap());
        let (mut c, alice_id, bob_id, _) = ctx_with_trustlines_and_offers();
        c.storage = Some(storage.clone());

        let mut state = crate::ledger::LedgerState::new();
        state.insert_account(crate::ledger::account::AccountRoot {
            account_id: alice_id,
            balance: 100_000_000,
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
            previous_txn_lgr_seq: 0, raw_sle: None,
        });
        state.insert_account(crate::ledger::account::AccountRoot {
            account_id: bob_id,
            balance: 100_000_000,
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
            previous_txn_lgr_seq: 0, raw_sle: None,
        });
        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let mut tl = crate::ledger::trustline::RippleState::new(&alice_id, &bob_id, usd.clone());
        tl.low_limit = crate::transaction::amount::IouValue::from_f64(100.0);
        tl.high_limit = crate::transaction::amount::IouValue::from_f64(100.0);
        let tl_key = tl.key();
        state.update_trustline_typed(tl.clone());
        let raw_tl = crate::ledger::meta::build_sle(
            0x0072,
            &[
                crate::ledger::meta::ParsedField {
                    type_code: 6,
                    field_code: 2,
                    data: crate::transaction::amount::Amount::Iou {
                        value: crate::transaction::amount::IouValue::ZERO,
                        currency: usd.clone(),
                        issuer: tl.low_account,
                    }
                    .to_bytes(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 6,
                    field_code: 6,
                    data: crate::transaction::amount::Amount::Iou {
                        value: tl.low_limit.clone(),
                        currency: usd.clone(),
                        issuer: tl.low_account,
                    }
                    .to_bytes(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 6,
                    field_code: 7,
                    data: crate::transaction::amount::Amount::Iou {
                        value: tl.high_limit.clone(),
                        currency: usd,
                        issuer: tl.high_account,
                    }
                    .to_bytes(),
                },
            ],
            None,
            None,
        );
        state.insert_raw(tl_key, raw_tl);

        let hdr = crate::ledger::LedgerHeader {
            sequence: 500,
            hash: [0x55; 32],
            parent_hash: [0u8; 32],
            close_time: 0,
            total_coins: 100_000_000_000_000_000,
            account_hash: [0u8; 32],
            transaction_hash: [0u8; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };
        let mut _seeded = state;
        _seeded.mark_all_dirty();
        let _dirty = _seeded.take_dirty();
        storage.save_ledger(&hdr, &[]).unwrap();
        // State persistence now through NuDB/SHAMap — no save_state_delta_with_history.
        c.history.write().unwrap().insert_ledger(hdr, vec![]);

        let resp = dispatch(
            req("account_currencies", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "ledger_index": 500
            })),
            &mut c,
        );
        // Historical queries now return error (no object_history CF)
        assert_eq!(resp.result["status"], "error");
    }

    #[test]
    fn test_account_channels_basic_and_marker() {
        let mut c = ctx_with_genesis();
        let account = crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let dest = crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap();
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            ls.insert_account(crate::ledger::account::AccountRoot {
                account_id: dest,
                balance: 100_000_000,
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
                previous_txn_lgr_seq: 0, raw_sle: None,
            });
            ls.insert_paychan(crate::ledger::PayChannel {
                account,
                destination: dest,
                amount: 10_000_000,
                balance: 1_000_000,
                settle_delay: 3600,
                public_key: vec![0x02; 33],
                sequence: 1,
                cancel_after: 0,
                expiration: 0,
                owner_node: 0,
                destination_node: 0,
                source_tag: None,
                destination_tag: None,
                raw_sle: None,
            });
            ls.insert_paychan(crate::ledger::PayChannel {
                account,
                destination: dest,
                amount: 20_000_000,
                balance: 2_000_000,
                settle_delay: 7200,
                public_key: vec![0x03; 33],
                sequence: 2,
                cancel_after: 0,
                expiration: 0,
                owner_node: 0,
                destination_node: 0,
                source_tag: None,
                destination_tag: None,
                raw_sle: None,
            });
        }
        let first = dispatch(
            req("account_channels", json!({
                "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                "limit": 1
            })),
            &mut c,
        );
        assert_eq!(first.result["status"], "success");
        assert_eq!(first.result["channels"].as_array().unwrap().len(), 1);
        let marker = first.result["marker"].as_str().unwrap().to_string();
        let second = dispatch(
            req("account_channels", json!({
                "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                "limit": 1,
                "marker": marker
            })),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(second.result["channels"].as_array().unwrap().len(), 1);
        assert_ne!(first.result["channels"][0]["channel_id"], second.result["channels"][0]["channel_id"]);
    }

    #[test]
    fn test_historical_account_objects_and_channels_use_nudb_root() {
        use crate::ledger::node_store::NuDBNodeStore;

        let tmp = tempfile::tempdir().unwrap();
        let backend = std::sync::Arc::new(NuDBNodeStore::open(tmp.path()).unwrap());
        let mut state = crate::ledger::LedgerState::new();
        state.set_nudb_shamap(crate::ledger::SHAMap::with_backend(
            crate::ledger::MapType::AccountState,
            backend,
        ));

        let owner = [0x11u8; 20];
        let dest_a = [0x22u8; 20];
        let dest_b = [0x33u8; 20];
        for account_id in [owner, dest_a, dest_b] {
            state.insert_account(crate::ledger::AccountRoot {
                account_id,
                balance: 100_000_000,
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

        let chan_a = crate::ledger::PayChannel {
            account: owner,
            destination: dest_a,
            amount: 10_000_000,
            balance: 1_000_000,
            settle_delay: 3600,
            public_key: vec![0x02; 33],
            sequence: 1,
            cancel_after: 0,
            expiration: 0,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };
        let chan_b = crate::ledger::PayChannel {
            account: owner,
            destination: dest_b,
            amount: 20_000_000,
            balance: 2_000_000,
            settle_delay: 7200,
            public_key: vec![0x03; 33],
            sequence: 2,
            cancel_after: 0,
            expiration: 0,
            owner_node: 0,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };
        state.insert_raw(chan_a.key(), chan_a.to_sle_binary());
        state.insert_raw(chan_b.key(), chan_b.to_sle_binary());

        let mut c = ctx_with_historical_state(state, 500, [0x66; 32]);
        let owner_addr = crate::crypto::base58::encode_account(&owner);

        let first_objects = dispatch(
            req("account_objects", json!({
                "account": owner_addr,
                "ledger_index": 500,
                "type": "payment_channel",
                "limit": 1
            })),
            &mut c,
        );
        assert_eq!(first_objects.result["status"], "success");
        assert_eq!(first_objects.result["account_objects"].as_array().unwrap().len(), 1);
        assert_eq!(first_objects.result["account_objects"][0]["LedgerEntryType"], "PayChannel");
        let marker = first_objects.result["marker"].as_str().unwrap().to_string();

        let second_objects = dispatch(
            req("account_objects", json!({
                "account": crate::crypto::base58::encode_account(&owner),
                "ledger_index": 500,
                "type": "payment_channel",
                "limit": 1,
                "marker": marker
            })),
            &mut c,
        );
        assert_eq!(second_objects.result["status"], "success");
        assert_eq!(second_objects.result["account_objects"].as_array().unwrap().len(), 1);
        assert_ne!(
            first_objects.result["account_objects"][0]["index"],
            second_objects.result["account_objects"][0]["index"]
        );

        let first_channels = dispatch(
            req("account_channels", json!({
                "account": crate::crypto::base58::encode_account(&owner),
                "ledger_index": 500,
                "limit": 1
            })),
            &mut c,
        );
        assert_eq!(first_channels.result["status"], "success");
        assert_eq!(first_channels.result["channels"].as_array().unwrap().len(), 1);
        let channel_marker = first_channels.result["marker"].as_str().unwrap().to_string();

        let second_channels = dispatch(
            req("account_channels", json!({
                "account": crate::crypto::base58::encode_account(&owner),
                "ledger_index": 500,
                "limit": 1,
                "marker": channel_marker
            })),
            &mut c,
        );
        assert_eq!(second_channels.result["status"], "success");
        assert_eq!(second_channels.result["channels"].as_array().unwrap().len(), 1);
        assert_ne!(
            first_channels.result["channels"][0]["channel_id"],
            second_channels.result["channels"][0]["channel_id"]
        );
    }

    fn ctx_with_nft_pages() -> (NodeContext, [u8; 20]) {
        use crate::crypto::keys::Secp256k1KeyPair;
        use crate::ledger::AccountRoot;

        let alice = Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap();
        let alice_id = crate::crypto::account_id(&alice.public_key_bytes());
        let ctx = NodeContext {
            ledger_seq: 42,
            ledger_hash: "B".repeat(64),
            ..Default::default()
        };
        {
            let ls = &mut *ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            ls.insert_account(AccountRoot {
                account_id: alice_id,
                balance: 100_000_000,
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
                previous_txn_lgr_seq: 0, raw_sle: None,
            });
            for serial in 1..=3u32 {
                let token_id =
                    crate::ledger::nftoken::make_nftoken_id(0x0008, 100, &alice_id, 7, serial);
                ls.insert_nftoken_paged(&alice_id, token_id, Some(vec![serial as u8, serial as u8 + 1]));
            }
        }
        (ctx, alice_id)
    }

    #[test]
    fn test_account_nfts_marker_paginates() {
        let (mut c, alice_id) = ctx_with_nft_pages();
        let first = dispatch(
            req("account_nfts", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "limit": 1
            })),
            &mut c,
        );
        assert_eq!(first.result["status"], "success");
        assert_eq!(first.result["account_nfts"].as_array().unwrap().len(), 1);
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let second = dispatch(
            req("account_nfts", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "limit": 1,
                "marker": marker
            })),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(second.result["account_nfts"].as_array().unwrap().len(), 1);
        assert_ne!(first.result["account_nfts"][0], second.result["account_nfts"][0]);
    }

    #[test]
    fn test_account_nfts_historical_uses_nudb_root_and_marker() {
        use crate::ledger::node_store::NuDBNodeStore;

        let tmp = tempfile::tempdir().unwrap();
        let backend = std::sync::Arc::new(NuDBNodeStore::open(tmp.path()).unwrap());
        let mut state = crate::ledger::LedgerState::new();
        state.set_nudb_shamap(crate::ledger::SHAMap::with_backend(
            crate::ledger::MapType::AccountState,
            backend,
        ));

        let owner = [0x44u8; 20];
        state.insert_account(crate::ledger::AccountRoot {
            account_id: owner,
            balance: 100_000_000,
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
        for serial in 1..=2u32 {
            let token_id =
                crate::ledger::nftoken::make_nftoken_id(0x0008, 100, &owner, 7, serial);
            state.insert_nftoken_paged(&owner, token_id, Some(vec![serial as u8]));
        }

        let mut c = ctx_with_historical_state(state, 500, [0x67; 32]);
        let owner_addr = crate::crypto::base58::encode_account(&owner);
        let first = dispatch(
            req("account_nfts", json!({
                "account": owner_addr,
                "ledger_index": 500,
                "limit": 1
            })),
            &mut c,
        );
        assert_eq!(first.result["status"], "success");
        assert_eq!(first.result["account_nfts"].as_array().unwrap().len(), 1);
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let second = dispatch(
            req("account_nfts", json!({
                "account": crate::crypto::base58::encode_account(&owner),
                "ledger_index": 500,
                "limit": 1,
                "marker": marker
            })),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(second.result["account_nfts"].as_array().unwrap().len(), 1);
        assert_ne!(first.result["account_nfts"][0], second.result["account_nfts"][0]);
    }

    #[test]
    fn test_account_nfts_invalid_account_and_marker_shape() {
        let (mut c, alice_id) = ctx_with_nft_pages();

        let bad_account = dispatch(
            req("account_nfts", json!({
                "account": 17
            })),
            &mut c,
        );
        assert_eq!(bad_account.result["error"], "invalidParams");
        assert_eq!(bad_account.result["error_message"], "Invalid parameters: Invalid field 'account'.");

        let first = dispatch(
            req("account_nfts", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "limit": 1
            })),
            &mut c,
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();
        let bad_marker_type = dispatch(
            req("account_nfts", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "marker": 17
            })),
            &mut c,
        );
        assert_eq!(bad_marker_type.result["error"], "invalidParams");
        assert_eq!(bad_marker_type.result["error_message"], "Invalid parameters: Invalid field 'marker', not string.");

        let fake_marker = format!("{}0", &marker[..marker.len() - 1]);
        let bad_marker_value = dispatch(
            req("account_nfts", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "marker": fake_marker
            })),
            &mut c,
        );
        assert_eq!(bad_marker_value.result["error"], "invalidParams");
        assert_eq!(bad_marker_value.result["error_message"], "Invalid parameters: Invalid field 'marker'.");
    }

    #[test]
    fn test_ledger_entry_index_and_account_root() {
        let mut c = ctx_with_genesis();
        let account_id =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let key = crate::ledger::account::shamap_key(&account_id);

        let binary = dispatch(
            req("ledger_entry", json!({
                "index": hex::encode_upper(key.0),
                "binary": true
            })),
            &mut c,
        );
        assert_eq!(binary.result["status"], "success");
        assert!(binary.result["node_binary"].as_str().unwrap().len() > 10);

        let json_resp = dispatch(
            req("ledger_entry", json!({
                "account_root": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
            })),
            &mut c,
        );
        assert_eq!(json_resp.result["status"], "success");
        assert_eq!(json_resp.result["node"]["LedgerEntryType"], "AccountRoot");
    }

    #[test]
    fn test_ledger_entry_object_selectors() {
        let mut c = ctx_with_genesis();
        let owner =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let other =
            crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap();
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            ls.insert_check(crate::ledger::Check {
                account: owner,
                destination: other,
                send_max: crate::transaction::Amount::Xrp(1_000_000),
                sequence: 7,
                expiration: 0,
                owner_node: 0,
                destination_node: 0,
                source_tag: None,
                destination_tag: None,
                raw_sle: None,
            });
            ls.insert_escrow(crate::ledger::Escrow {
                account: owner,
                destination: other,
                amount: 2_000_000,
                held_amount: None,
                sequence: 8,
                finish_after: 0,
                cancel_after: 0,
                condition: None,
                owner_node: 0,
                destination_node: 0,
                source_tag: None,
                destination_tag: None,
                raw_sle: None,
            });
            ls.insert_offer(crate::ledger::Offer {
                account: owner,
                sequence: 9,
                taker_pays: crate::transaction::Amount::Xrp(3_000_000),
                taker_gets: crate::transaction::Amount::Xrp(4_000_000),
                flags: 0,
                book_directory: [0u8; 32],
                book_node: 0,
                owner_node: 0,
                expiration: None,
                domain_id: None,
                additional_books: Vec::new(),
                previous_txn_id: [0u8; 32],
                previous_txn_lgr_seq: 0,
                raw_sle: None,
            });
            ls.insert_paychan(crate::ledger::PayChannel {
                account: owner,
                destination: other,
                amount: 10_000_000,
                balance: 1_000_000,
                settle_delay: 3600,
                public_key: vec![0x02; 33],
                sequence: 10,
                cancel_after: 0,
                expiration: 0,
                owner_node: 0,
                destination_node: 0,
                source_tag: None,
                destination_tag: None,
                raw_sle: None,
            });
            ls.insert_ticket(crate::ledger::Ticket {
                account: owner,
                sequence: 11,
                owner_node: 0,
                previous_txn_id: [0u8; 32],
                previous_txn_lgrseq: 0,
                raw_sle: None,
            });
            ls.insert_deposit_preauth(crate::ledger::DepositPreauth {
                account: owner,
                authorized: other,
                owner_node: 0,
                previous_txn_id: [0u8; 32],
                previous_txn_lgrseq: 0,
                raw_sle: None,
            });
        }

        let cases = [
            (
                json!({"check": hex::encode_upper(crate::ledger::check::shamap_key(&owner, 7).0)}),
                "Check",
            ),
            (
                json!({"escrow": {"owner": crate::crypto::base58::encode_account(&owner), "seq": 8}}),
                "Escrow",
            ),
            (
                json!({"offer": {"account": crate::crypto::base58::encode_account(&owner), "seq": 9}}),
                "Offer",
            ),
            (
                json!({"payment_channel": hex::encode_upper(crate::ledger::paychan::shamap_key(&owner, &other, 10).0)}),
                "PayChannel",
            ),
            (
                json!({"ticket": {"account": crate::crypto::base58::encode_account(&owner), "ticket_seq": 11}}),
                "Ticket",
            ),
            (
                json!({"deposit_preauth": {"owner": crate::crypto::base58::encode_account(&owner), "authorized": crate::crypto::base58::encode_account(&other)}}),
                "DepositPreauth",
            ),
        ];

        for (params, entry_type) in cases {
            let resp = dispatch(req("ledger_entry", params), &mut c);
            assert_eq!(resp.result["status"], "success");
            assert_eq!(resp.result["node"]["LedgerEntryType"], entry_type);
        }
    }

    #[test]
    fn test_ledger_entry_ripple_state_and_nft_page_selectors() {
        let (mut trust_ctx, alice_id, bob_id, _) = ctx_with_trustlines_and_offers();
        let ripple = dispatch(
            req("ledger_entry", json!({
                "ripple_state": {
                    "accounts": [
                        crate::crypto::base58::encode_account(&alice_id),
                        crate::crypto::base58::encode_account(&bob_id)
                    ],
                    "currency": "USD"
                }
            })),
            &mut trust_ctx,
        );
        assert_eq!(ripple.result["status"], "success");
        assert_eq!(ripple.result["node"]["LedgerEntryType"], "RippleState");

        let (mut nft_ctx, alice_id) = ctx_with_nft_pages();
        let page_key = {
            let ls = nft_ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            let key = ls.iter_nft_pages_for(&alice_id).next().map(|(k, _)| k).unwrap();
            key
        };
        let page = dispatch(
            req("ledger_entry", json!({
                "nft_page": hex::encode_upper(page_key.0)
            })),
            &mut nft_ctx,
        );
        assert_eq!(page.result["status"], "success");
        assert_eq!(page.result["node"]["LedgerEntryType"], "NFTokenPage");
    }

    #[test]
    fn test_account_objects_offer_filter_and_marker() {
        use crate::ledger::offer::Offer;
        use crate::transaction::amount::{Amount, Currency, IouValue};

        let (mut c, alice_id, _, _) = ctx_with_trustlines_and_offers();
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            ls.insert_offer(Offer {
                account: alice_id,
                sequence: 9,
                taker_pays: Amount::Xrp(3_000_000),
                taker_gets: Amount::Iou {
                    value: IouValue::from_f64(3.0),
                    currency: Currency::from_code("USD").unwrap(),
                    issuer: alice_id,
                },
                flags: 0,
                book_directory: [0u8; 32],
                book_node: 0,
                owner_node: 0,
                expiration: None,
                domain_id: None,
                additional_books: Vec::new(),
                previous_txn_id: [0u8; 32],
                previous_txn_lgr_seq: 0,
                raw_sle: None,
            });
        }
        let first = dispatch(
            req("account_objects", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "type": "offer",
                "limit": 1
            })),
            &mut c,
        );
        assert_eq!(first.result["status"], "success");
        assert_eq!(first.result["account_objects"].as_array().unwrap().len(), 1);
        assert_eq!(first.result["account_objects"][0]["LedgerEntryType"], "Offer");
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let second = dispatch(
            req("account_objects", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "type": "offer",
                "limit": 1,
                "marker": marker
            })),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(second.result["account_objects"].as_array().unwrap().len(), 1);
        assert_ne!(
            first.result["account_objects"][0]["index"],
            second.result["account_objects"][0]["index"]
        );
    }

    #[test]
    fn test_account_objects_invalid_account_and_marker_shape() {
        use crate::ledger::offer::Offer;
        use crate::transaction::amount::{Amount, Currency, IouValue};

        let (mut c, alice_id, _, _) = ctx_with_trustlines_and_offers();
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            ls.insert_offer(Offer {
                account: alice_id,
                sequence: 10,
                taker_pays: Amount::Xrp(4_000_000),
                taker_gets: Amount::Iou {
                    value: IouValue::from_f64(4.0),
                    currency: Currency::from_code("USD").unwrap(),
                    issuer: alice_id,
                },
                flags: 0,
                book_directory: [0u8; 32],
                book_node: 0,
                owner_node: 0,
                expiration: None,
                domain_id: None,
                additional_books: Vec::new(),
                previous_txn_id: [0u8; 32],
                previous_txn_lgr_seq: 0,
                raw_sle: None,
            });
        }

        let bad_account = dispatch(
            req("account_objects", json!({
                "account": 17
            })),
            &mut c,
        );
        assert_eq!(bad_account.result["error"], "invalidParams");
        assert_eq!(bad_account.result["error_message"], "Invalid parameters: Invalid field 'account'.");

        let first = dispatch(
            req("account_objects", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "type": "offer",
                "limit": 1
            })),
            &mut c,
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let bad_marker_type = dispatch(
            req("account_objects", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "marker": 17
            })),
            &mut c,
        );
        assert_eq!(bad_marker_type.result["error"], "invalidParams");
        assert_eq!(bad_marker_type.result["error_message"], "Invalid parameters: Invalid field 'marker', not string.");

        let bad_marker_value = dispatch(
            req("account_objects", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "marker": marker.replace(',', "")
            })),
            &mut c,
        );
        assert_eq!(bad_marker_value.result["error"], "invalidParams");
        assert_eq!(bad_marker_value.result["error_message"], "Invalid parameters: Invalid field 'marker'.");
    }

    #[test]
    fn test_account_objects_invalid_type_and_limit_messages() {
        let (mut c, alice_id, _, _) = ctx_with_trustlines_and_offers();

        let bad_type_kind = dispatch(
            req("account_objects", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "type": 10
            })),
            &mut c,
        );
        assert_eq!(bad_type_kind.result["error"], "invalidParams");
        assert_eq!(bad_type_kind.result["error_message"], "Invalid parameters: Invalid field 'type', not string.");

        let bad_type_value = dispatch(
            req("account_objects", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "type": "expedited"
            })),
            &mut c,
        );
        assert_eq!(bad_type_value.result["error"], "invalidParams");
        assert_eq!(bad_type_value.result["error_message"], "Invalid parameters: Invalid field 'type'.");

        let bad_limit = dispatch(
            req("account_objects", json!({
                "account": crate::crypto::base58::encode_account(&alice_id),
                "limit": -1
            })),
            &mut c,
        );
        assert_eq!(bad_limit.result["error"], "invalidParams");
        assert_eq!(bad_limit.result["error_message"], "Invalid parameters: Invalid field 'limit', not unsigned integer.");
    }

    #[test]
    fn test_historical_nft_offer_survives_storage_for_rpc() {
        use crate::ledger::AccountRoot;
        use crate::ledger::NFTokenOffer;
        use crate::ledger::node_store::NuDBNodeStore;
        use crate::transaction::Amount;

        let tmp = tempfile::tempdir().unwrap();
        let storage = std::sync::Arc::new(crate::storage::Storage::open(tmp.path()).unwrap());
        let backend = std::sync::Arc::new(NuDBNodeStore::open(tmp.path()).unwrap());
        let owner =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let destination =
            crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap();
        let mut seeded = crate::ledger::LedgerState::new();
        seeded.set_nudb_shamap(crate::ledger::SHAMap::with_backend(
            crate::ledger::MapType::AccountState,
            backend,
        ));
        seeded.insert_account(AccountRoot {
            account_id: owner,
            balance: 100_000_000,
            sequence: 1,
            owner_count: 1,
            flags: 0,
            regular_key: None,
            minted_nftokens: 0,
            burned_nftokens: 0,
            transfer_rate: 0,
            domain: Vec::new(),
            tick_size: 0,
            ticket_count: 0,
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0, raw_sle: None,
        });
        let offer = NFTokenOffer {
            account: owner,
            sequence: 22,
            nftoken_id: [0xAB; 32],
            amount: Amount::Xrp(1_000_000),
            destination: Some(destination),
            expiration: Some(700),
            flags: 1,
            owner_node: 0,
            nft_offer_node: 0,
            previous_txn_id: [0u8; 32],
            previous_txn_lgrseq: 0,
            raw_sle: None,
        };
        let offer_key = offer.key();
        seeded.insert_nft_offer(offer.clone());
        let _dirty = seeded.take_dirty();
        let root = seeded.nudb_root_hash().unwrap();

        let header = crate::ledger::LedgerHeader {
            sequence: 500,
            hash: [0x55; 32],
            parent_hash: [0u8; 32],
            close_time: 0,
            total_coins: 100_000_000_000_000_000,
            account_hash: root,
            transaction_hash: [0u8; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };
        storage.save_ledger(&header, &[]).unwrap();

        let mut c = ctx();
        c.storage = Some(storage);
        c.ledger_state = std::sync::Arc::new(std::sync::Mutex::new(seeded));
        c.history.write().unwrap().insert_ledger(header, vec![]);

        let entry = dispatch(
            req("ledger_entry", json!({
                "nft_offer": hex::encode_upper(offer_key.0),
                "ledger_index": 500
            })),
            &mut c,
        );
        assert_eq!(entry.result["status"], "success");
        assert_eq!(entry.result["node"]["LedgerEntryType"], "NFTokenOffer");
        assert_eq!(entry.result["node"]["Amount"], "1000000");

        let objects = dispatch(
            req("account_objects", json!({
                "account": crate::crypto::base58::encode_account(&owner),
                "type": "nft_offer",
                "ledger_index": 500
            })),
            &mut c,
        );
        assert_eq!(objects.result["status"], "success");
        assert_eq!(objects.result["account_objects"].as_array().unwrap().len(), 1);
        assert_eq!(objects.result["account_objects"][0]["LedgerEntryType"], "NFTokenOffer");
    }

    // ── ledger ────────────────────────────────────────────────────────────────

    #[test]
    fn test_ledger_current() {
        let resp = dispatch(
            req("ledger", json!({"ledger_index": "validated"})),
            &mut ctx(),
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["ledger_index"], 1000);
    }

    #[test]
    fn test_ledger_by_seq() {
        let mut c = ctx();
        // Add ledger 500 to history
        let hdr = crate::ledger::LedgerHeader {
            sequence: 500, hash: [0x55; 32], parent_hash: [0u8; 32],
            close_time: 0, total_coins: 100_000_000_000_000_000,
            account_hash: [0u8; 32], transaction_hash: [0u8; 32],
            parent_close_time: 0, close_time_resolution: 10, close_flags: 0,
        };
        c.history.write().unwrap().insert_ledger(hdr, vec![]);
        let resp = dispatch(req("ledger", json!({"ledger_index": 500})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["ledger"]["ledger_index"], "500");
    }

    #[test]
    fn test_ledger_future_seq_not_found() {
        let resp = dispatch(req("ledger", json!({"ledger_index": 99999})), &mut ctx());
        assert_eq!(resp.result["error"], "lgrNotFound");
    }

    #[test]
    fn test_ledger_invalid_ledger_index() {
        let resp = dispatch(req("ledger", json!({"ledger_index": "not_a_ledger"})), &mut ctx());
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_lines_invalid_ledger_index() {
        let resp = dispatch(
            req("account_lines", json!({
                "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                "ledger_index": "not_a_ledger"
            })),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_offers_invalid_ledger_index() {
        let resp = dispatch(
            req("account_offers", json!({
                "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                "ledger_index": "not_a_ledger"
            })),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_book_offers_invalid_ledger_index() {
        let resp = dispatch(
            req("book_offers", json!({
                "taker_pays": { "currency": "XRP" },
                "taker_gets": { "currency": "USD", "issuer": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh" },
                "ledger_index": "not_a_ledger"
            })),
            &mut ctx(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_ledger_data_invalid_marker() {
        use crate::ledger::node_store::NuDBNodeStore;

        let tmp = tempfile::tempdir().unwrap();
        let backend = std::sync::Arc::new(NuDBNodeStore::open(tmp.path()).unwrap());
        let mut state = crate::ledger::LedgerState::new();
        state.set_nudb_shamap(crate::ledger::SHAMap::with_backend(
            crate::ledger::MapType::AccountState,
            backend,
        ));
        state.insert_account(crate::ledger::AccountRoot {
            account_id: [0x77; 20],
            balance: 1_000_000,
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
        let mut c = ctx_with_historical_state(state, 500, [0x55; 32]);

        let resp = dispatch(
            req("ledger_data", json!({"ledger_index": 500, "marker": "not_hex"})),
            &mut c,
        );
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(resp.result["error_message"], "Invalid parameters: Invalid field 'marker', not valid.");

        let resp = dispatch(
            req("ledger_data", json!({"ledger_index": 500, "marker": 17})),
            &mut c,
        );
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(resp.result["error_message"], "Invalid parameters: Invalid field 'marker', not valid.");
    }

    #[test]
    fn test_ledger_data_invalid_limit_message() {
        let resp = dispatch(req("ledger_data", json!({"limit": "0"})), &mut ctx());
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(resp.result["error_message"], "Invalid parameters: Invalid field 'limit', not integer.");
    }

    #[test]
    fn test_ledger_data_limit_is_capped() {
        use crate::crypto::keys::Secp256k1KeyPair;
        use crate::ledger::AccountRoot;

        let mut c = ctx();
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            for i in 0..300 {
                let kp = if i == 0 {
                    Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap()
                } else {
                    Secp256k1KeyPair::generate()
                };
                let account_id = crate::crypto::account_id(&kp.public_key_bytes());
                ls.insert_account(AccountRoot {
                    account_id,
                    balance: 1_000_000,
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
                    previous_txn_lgr_seq: 0, raw_sle: None,
                });
            }
        }

        let resp = dispatch(req("ledger_data", json!({"limit": 1000})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["state"].as_array().unwrap().len(), 256);
        assert_eq!(resp.result["truncated"], true);
    }

    #[test]
    fn test_ledger_data_current_marker_paginates() {
        let (mut c, _, _, _) = ctx_with_trustlines_and_offers();
        let first = dispatch(req("ledger_data", json!({"limit": 1})), &mut c);
        assert_eq!(first.result["state"].as_array().unwrap().len(), 1);
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let second = dispatch(
            req("ledger_data", json!({"limit": 1, "marker": marker})),
            &mut c,
        );
        assert_eq!(second.result["state"].as_array().unwrap().len(), 1);
        assert_ne!(first.result["state"][0]["index"], second.result["state"][0]["index"]);
    }

    #[test]
    fn test_ledger_data_historical_uses_nudb_root_and_marker() {
        use crate::ledger::account;
        use crate::ledger::node_store::NuDBNodeStore;
        use crate::ledger::AccountRoot;

        let tmp = tempfile::tempdir().unwrap();
        let backend = std::sync::Arc::new(NuDBNodeStore::open(tmp.path()).unwrap());

        let mut state = crate::ledger::LedgerState::new();
        state.set_nudb_shamap(crate::ledger::SHAMap::with_backend(
            crate::ledger::MapType::AccountState,
            backend,
        ));

        let accounts = [[1u8; 20], [2u8; 20], [3u8; 20]];
        for (i, account_id) in accounts.iter().enumerate() {
            state.insert_account(AccountRoot {
                account_id: *account_id,
                balance: 1_000_000 + i as u64,
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
        let expected_keys = {
            let mut keys: Vec<_> = accounts.iter().map(account::shamap_key).collect();
            keys.sort_by_key(|key| key.0);
            keys
        };
        let root_hash = state.nudb_root_hash().unwrap();
        state.flush_nudb().unwrap();

        let mut c = NodeContext {
            ledger_seq: 600,
            ledger_hash: "B".repeat(64),
            ledger_state: std::sync::Arc::new(std::sync::Mutex::new(state)),
            ..Default::default()
        };
        let hdr = crate::ledger::LedgerHeader {
            sequence: 500,
            hash: [0x55; 32],
            parent_hash: [0u8; 32],
            close_time: 0,
            total_coins: 100_000_000_000_000_000,
            account_hash: root_hash,
            transaction_hash: [0u8; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };
        c.history.write().unwrap().insert_ledger(hdr, vec![]);

        let first = dispatch(
            req("ledger_data", json!({"ledger_index": 500, "limit": 2})),
            &mut c,
        );
        assert_eq!(first.result["status"], "success");
        assert_eq!(first.result["historical"], true);
        let first_state = first.result["state"].as_array().unwrap();
        assert_eq!(first_state.len(), 2);
        assert_eq!(first_state[0]["index"], hex::encode_upper(expected_keys[0].0));
        assert_eq!(first_state[1]["index"], hex::encode_upper(expected_keys[1].0));
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let second = dispatch(
            req("ledger_data", json!({"ledger_index": 500, "limit": 2, "marker": marker})),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(second.result["historical"], true);
        let second_state = second.result["state"].as_array().unwrap();
        assert_eq!(second_state.len(), 1);
        assert_eq!(second_state[0]["index"], hex::encode_upper(expected_keys[2].0));
        assert!(second.result.get("marker").is_none());
    }

    #[test]
    fn test_book_offers_zero_limit_rejected() {
        let resp = dispatch(
            req("book_offers", json!({
                "ledger_index": "validated",
                "limit": 0,
                "taker_pays": { "currency": "XRP" },
                "taker_gets": { "currency": "USD", "issuer": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh" }
            })),
            &mut ctx(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(resp.result["error_message"], "Invalid parameters: Invalid field 'limit'.");
    }

    // ── unknown method ────────────────────────────────────────────────────────

    #[test]
    fn test_unknown_method() {
        let resp = dispatch(req("doesnt_exist", json!({})), &mut ctx());
        assert_eq!(resp.result["status"], "error");
        assert_eq!(resp.result["error"], "unknownCmd");
    }

    // ── request parsing ───────────────────────────────────────────────────────

    #[test]
    fn test_rippled_style_params_unwrapped() {
        // rippled wraps params in array: {"method":"ping","params":[{}]}
        let raw = br#"{"method":"ping","params":[{}],"id":42}"#;
        let req = RpcRequest::parse(raw).unwrap();
        assert_eq!(req.method, "ping");
        assert_eq!(req.id, json!(42));
    }

    #[test]
    fn test_response_serializes_correctly() {
        let resp = dispatch(req("ping", json!({})), &mut ctx());
        let json_str = resp.to_json();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["result"]["status"], "success");
    }
}
