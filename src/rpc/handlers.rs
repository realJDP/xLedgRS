//! RPC method handlers — one function per rippled API method.
//!
//! Each handler takes `&RpcRequest` params and `&NodeContext`, returns
//! `Result<Value, RpcError>`. Response shapes match rippled exactly.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use rand::RngCore;
use serde_json::{json, Value};

use crate::crypto::base58::decode_account;

use crate::rpc::types::RpcError;
use crate::rpc::NodeContext;

fn lgr_not_found() -> RpcError {
    RpcError {
        code: "lgrNotFound",
        error_code: 21,
        message: "ledgerNotFound".into(),
        extra: None,
    }
}

fn invalid_field(name: &str) -> RpcError {
    RpcError::invalid_params(&format!("Invalid field '{name}'."))
}

fn invalid_field_not_string(name: &str) -> RpcError {
    RpcError::invalid_params(&format!("Invalid field '{name}', not string."))
}

fn act_malformed() -> RpcError {
    RpcError {
        code: "actMalformed",
        error_code: 35,
        message: "Account malformed.".into(),
        extra: None,
    }
}

fn txn_not_found() -> RpcError {
    RpcError {
        code: "txnNotFound",
        error_code: 29,
        message: "Transaction not found.".into(),
        extra: None,
    }
}

fn txn_not_found_searched_all(searched_all: bool) -> RpcError {
    RpcError {
        code: "txnNotFound",
        error_code: 29,
        message: "Transaction not found.".into(),
        extra: Some(serde_json::Map::from_iter([(
            "searched_all".to_string(),
            json!(searched_all),
        )])),
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

fn parse_secret_string<'a>(
    params: &'a Value,
    field: &'static str,
) -> Result<Option<&'a str>, RpcError> {
    match params.get(field) {
        None => Ok(None),
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(s)),
        Some(Value::String(_)) => Err(RpcError::invalid_params(&format!(
            "Invalid field '{field}', not valid."
        ))),
        Some(_) => Err(RpcError::invalid_params(&format!(
            "Invalid field '{field}', not string."
        ))),
    }
}

fn parse_key_type(params: &Value) -> Result<Option<crate::crypto::keys::KeyType>, RpcError> {
    let Some(raw) = params.get("key_type") else {
        return Ok(None);
    };
    let value = raw
        .as_str()
        .ok_or_else(|| RpcError::invalid_params("Invalid field 'key_type', not string."))?;
    match value {
        "secp256k1" => Ok(Some(crate::crypto::keys::KeyType::Secp256k1)),
        "ed25519" => Ok(Some(crate::crypto::keys::KeyType::Ed25519)),
        _ => Err(RpcError {
            code: "badKeyType",
            error_code: 31,
            message: "Invalid field 'key_type'.".into(),
            extra: None,
        }),
    }
}

fn parse_generic_seed(secret: &str) -> Result<[u8; 16], RpcError> {
    if let Ok(seed) = crate::crypto::base58::decode_seed(secret) {
        return Ok(seed);
    }
    if let Ok(bytes) = hex::decode(secret) {
        if bytes.len() == 16 {
            let mut seed = [0u8; 16];
            seed.copy_from_slice(&bytes);
            return Ok(seed);
        }
    }
    let hash = crate::crypto::sha512_first_half(secret.as_bytes());
    let mut seed = [0u8; 16];
    seed.copy_from_slice(&hash[..16]);
    Ok(seed)
}

fn parse_rpc_seed(params: &Value) -> Result<(crate::crypto::keys::KeyType, [u8; 16]), RpcError> {
    let passphrase = parse_secret_string(params, "passphrase")?;
    let secret = parse_secret_string(params, "secret")?;
    let seed = parse_secret_string(params, "seed")?;
    let seed_hex = parse_secret_string(params, "seed_hex")?;
    let key_type = parse_key_type(params)?;

    let count = usize::from(passphrase.is_some())
        + usize::from(secret.is_some())
        + usize::from(seed.is_some())
        + usize::from(seed_hex.is_some());
    if count == 0 {
        return Err(RpcError::invalid_params("missing 'secret' field"));
    }
    if count > 1 {
        return Err(RpcError::invalid_params(
            "Exactly one of the following must be specified: passphrase, secret, seed or seed_hex.",
        ));
    }
    if secret.is_some() && key_type.is_some() {
        return Err(RpcError::invalid_params(
            "The secret field is not allowed if key_type is used.",
        ));
    }

    let derived_type = key_type.unwrap_or(crate::crypto::keys::KeyType::Secp256k1);
    let entropy = if let Some(value) = passphrase {
        parse_generic_seed(value)?
    } else if let Some(value) = secret {
        parse_generic_seed(value)?
    } else if let Some(value) = seed {
        crate::crypto::base58::decode_seed(value).map_err(|_| RpcError {
            code: "badSeed",
            error_code: 31,
            message: "Invalid field 'seed'.".into(),
            extra: None,
        })?
    } else if let Some(value) = seed_hex {
        let bytes = hex::decode(value).map_err(|_| RpcError {
            code: "badSeed",
            error_code: 31,
            message: "Invalid field 'seed_hex'.".into(),
            extra: None,
        })?;
        if bytes.len() != 16 {
            return Err(RpcError {
                code: "badSeed",
                error_code: 31,
                message: "Invalid field 'seed_hex'.".into(),
                extra: None,
            });
        }
        let mut seed = [0u8; 16];
        seed.copy_from_slice(&bytes);
        seed
    } else {
        return Err(RpcError::invalid_params("missing 'secret' field"));
    };

    Ok((derived_type, entropy))
}

fn parse_channel_id(params: &Value, field: &str) -> Result<[u8; 32], RpcError> {
    let raw = params
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params(&format!("missing '{field}' field")))?;
    if raw.len() != 64 {
        return Err(RpcError {
            code: "channelMalformed",
            error_code: 31,
            message: format!("Invalid field '{field}'."),
            extra: None,
        });
    }
    let bytes = hex::decode(raw).map_err(|_| RpcError {
        code: "channelMalformed",
        error_code: 31,
        message: format!("Invalid field '{field}'."),
        extra: None,
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_drops_string(params: &Value, field: &str) -> Result<u64, RpcError> {
    match params.get(field) {
        Some(Value::String(s)) if s.chars().all(|c| c.is_ascii_digit()) => {
            s.parse::<u64>().map_err(|_| RpcError {
                code: "channelAmtMalformed",
                error_code: 31,
                message: format!("Invalid field '{field}'."),
                extra: None,
            })
        }
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| RpcError {
            code: "channelAmtMalformed",
            error_code: 31,
            message: format!("Invalid field '{field}'."),
            extra: None,
        }),
        Some(_) => Err(RpcError {
            code: "channelAmtMalformed",
            error_code: 31,
            message: format!("Invalid field '{field}'."),
            extra: None,
        }),
        None => Err(RpcError::invalid_params(&format!(
            "missing '{field}' field"
        ))),
    }
}

fn parse_public_key_bytes(params: &Value, field: &str) -> Result<Vec<u8>, RpcError> {
    let raw = params
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params(&format!("missing '{field}' field")))?;
    if let Ok((_, payload)) = crate::crypto::base58::decode(raw) {
        if payload.len() == 33 {
            return Ok(payload);
        }
    }
    let bytes = hex::decode(raw).map_err(|_| RpcError {
        code: "publicMalformed",
        error_code: 31,
        message: format!("Invalid field '{field}'."),
        extra: None,
    })?;
    if bytes.len() != 33 {
        return Err(RpcError {
            code: "publicMalformed",
            error_code: 31,
            message: format!("Invalid field '{field}'."),
            extra: None,
        });
    }
    Ok(bytes)
}

fn parse_signature_hex(params: &Value, field: &str) -> Result<Vec<u8>, RpcError> {
    let raw = params
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params(&format!("missing '{field}' field")))?;
    hex::decode(raw).map_err(|_| RpcError::invalid_params(&format!("Invalid field '{field}'.")))
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
                return Err(RpcError::invalid_params(
                    "Invalid field 'marker', not valid.",
                ));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&v);
            Ok(Some(k))
        }
        Some(_) => Err(RpcError::invalid_params(
            "Invalid field 'marker', not valid.",
        )),
    }
}

fn parse_ledger_data_limit(params: &Value, default: usize, max: usize) -> Result<usize, RpcError> {
    match params.get("limit") {
        None => Ok(default),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(|v| (v as usize).min(max))
            .ok_or_else(|| RpcError::invalid_params("Invalid field 'limit', not integer.")),
        Some(_) => Err(RpcError::invalid_params(
            "Invalid field 'limit', not integer.",
        )),
    }
}

fn parse_limit_field(params: &Value, default: usize, max: usize) -> Result<usize, RpcError> {
    match params.get("limit") {
        None => Ok(default),
        Some(Value::Number(n)) => n.as_u64().map(|v| (v as usize).min(max)).ok_or_else(|| {
            RpcError::invalid_params("Invalid field 'limit', not unsigned integer.")
        }),
        Some(_) => Err(RpcError::invalid_params(
            "Invalid field 'limit', not unsigned integer.",
        )),
    }
}

fn rpc_public_key_bytes(key_pair: &crate::crypto::keys::KeyPair) -> Vec<u8> {
    match key_pair {
        crate::crypto::keys::KeyPair::Secp256k1(kp) => kp.public_key_bytes(),
        crate::crypto::keys::KeyPair::Ed25519(kp) => {
            let mut bytes = vec![0xED];
            bytes.extend_from_slice(&kp.public_key_bytes());
            bytes
        }
    }
}

fn rpc_public_key_base58(key_pair: &crate::crypto::keys::KeyPair) -> String {
    crate::crypto::base58::encode(
        crate::crypto::base58::PREFIX_NODE_PUBLIC,
        &rpc_public_key_bytes(key_pair),
    )
}

fn random_seed_entropy() -> [u8; 16] {
    let mut entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut entropy);
    entropy
}

fn parse_nft_id_field(params: &Value, field: &str) -> Result<[u8; 32], RpcError> {
    let raw = params
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params(&format!("missing '{field}' field")))?;
    let bytes = hex::decode(raw).map_err(|_| invalid_field(field))?;
    if bytes.len() != 32 {
        return Err(invalid_field(field));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
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
        Value::String(s) if s == "validated" || s == "closed" || s == "current" => {
            Ok(Some(current_seq))
        }
        Value::String(s) => s
            .parse::<u32>()
            .map(Some)
            .map_err(|_| RpcError::invalid_params("invalid ledger_index")),
        _ => Err(RpcError::invalid_params("invalid ledger_index")),
    }
}

fn parse_ledger_hash(params: &Value, ctx: &NodeContext) -> Result<Option<u32>, RpcError> {
    let Some(raw) = params.get("ledger_hash") else {
        return Ok(None);
    };
    let s = raw
        .as_str()
        .ok_or_else(|| RpcError::invalid_params("invalid ledger_hash"))?;
    let bytes = hex::decode(s).map_err(|_| RpcError::invalid_params("invalid ledger_hash"))?;
    if bytes.len() != 32 {
        return Err(RpcError::invalid_params("invalid ledger_hash"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);

    if hash == ctx.ledger_header.hash {
        return Ok(Some(ctx.ledger_seq));
    }
    Ok(ctx
        .history
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get_ledger_by_hash(&hash)
        .map(|rec| rec.header.sequence))
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

fn serialize_ledger_header_blob(header: &crate::ledger::LedgerHeader) -> Vec<u8> {
    bincode::serialize(header).unwrap_or_default()
}

fn lookup_requested_ledger(
    params: &Value,
    ctx: &NodeContext,
) -> Result<(u32, crate::ledger::LedgerHeader, Vec<[u8; 32]>), RpcError> {
    let seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);

    let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());
    if let Some(rec) = history.get_ledger(seq) {
        return Ok((seq, rec.header.clone(), rec.tx_hashes.clone()));
    }
    if seq == ctx.ledger_seq {
        return Ok((seq, ctx.ledger_header.clone(), Vec::new()));
    }
    Err(lgr_not_found())
}

fn lookup_raw_object_at_ledger(
    key: &crate::ledger::Key,
    requested_seq: u32,
    ctx: &NodeContext,
) -> Option<Vec<u8>> {
    if requested_seq != ctx.ledger_seq {
        let (_, mut map) =
            historical_state_map(requested_seq, ctx, "historical ledger lookup unavailable")
                .ok()?;
        return map.get(key);
    }
    if let Some(ref cl) = ctx.closed_ledger {
        return cl.get_raw(key);
    }
    let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
    ls.get_raw_owned(key)
}

fn recommended_fee_drops(ctx: &NodeContext) -> String {
    ctx.fees.base.max(10).to_string()
}

fn parse_u32_like(value: &Value, field: &str) -> Result<u32, RpcError> {
    match value {
        Value::Number(n) => n
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| invalid_field(field)),
        Value::String(s) => s.parse::<u32>().map_err(|_| invalid_field(field)),
        _ => Err(invalid_field(field)),
    }
}

fn parse_u64_like(value: &Value, field: &str) -> Result<u64, RpcError> {
    match value {
        Value::Number(n) => n.as_u64().ok_or_else(|| invalid_field(field)),
        Value::String(s) => s.parse::<u64>().map_err(|_| invalid_field(field)),
        _ => Err(invalid_field(field)),
    }
}

fn parse_optional_u32_field(tx_json: &Value, field: &str) -> Result<Option<u32>, RpcError> {
    tx_json
        .get(field)
        .map(|value| parse_u32_like(value, field))
        .transpose()
}

fn parse_optional_hex_field(tx_json: &Value, field: &str) -> Result<Option<Vec<u8>>, RpcError> {
    let Some(value) = tx_json.get(field) else {
        return Ok(None);
    };
    let raw = value
        .as_str()
        .ok_or_else(|| invalid_field_not_string(field))?;
    if raw.is_empty() {
        return Ok(Some(Vec::new()));
    }
    hex::decode(raw)
        .map(Some)
        .map_err(|_| RpcError::invalid_params(&format!("invalid {field}")))
}

fn parse_amount_from_value(
    value: &Value,
    field: &str,
) -> Result<crate::transaction::Amount, RpcError> {
    match value {
        Value::String(s) => s
            .parse::<u64>()
            .map(crate::transaction::Amount::Xrp)
            .map_err(|_| RpcError::invalid_params(&format!("invalid {field}"))),
        Value::Number(n) => n
            .as_u64()
            .map(crate::transaction::Amount::Xrp)
            .ok_or_else(|| RpcError::invalid_params(&format!("invalid {field}"))),
        Value::Object(obj) => {
            let value_str = obj
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::invalid_params(&format!("{field} missing 'value'")))?;
            let currency_str = obj
                .get("currency")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::invalid_params(&format!("{field} missing 'currency'")))?;
            let issuer_str = obj
                .get("issuer")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::invalid_params(&format!("{field} missing 'issuer'")))?;
            let value_f64 = value_str
                .parse::<f64>()
                .map_err(|_| RpcError::invalid_params(&format!("invalid {field} value")))?;
            let currency = crate::transaction::amount::Currency::from_code(currency_str)
                .map_err(|_| RpcError::invalid_params(&format!("invalid {field} currency")))?;
            let issuer = decode_account(issuer_str)
                .map_err(|_| RpcError::invalid_params(&format!("invalid {field} issuer")))?;
            Ok(crate::transaction::Amount::Iou {
                value: crate::transaction::amount::IouValue::from_f64(value_f64),
                currency,
                issuer,
            })
        }
        _ => Err(RpcError::invalid_params(&format!("invalid {field}"))),
    }
}

fn parse_optional_amount_field(
    tx_json: &Value,
    primary: &str,
    alternate: Option<&str>,
) -> Result<Option<crate::transaction::Amount>, RpcError> {
    if let Some(value) = tx_json.get(primary) {
        return parse_amount_from_value(value, primary).map(Some);
    }
    if let Some(alternate) = alternate {
        if let Some(value) = tx_json.get(alternate) {
            return parse_amount_from_value(value, alternate).map(Some);
        }
    }
    Ok(None)
}

fn default_simulation_sequence(tx_json: &Value, ctx: &NodeContext) -> Result<u32, RpcError> {
    if tx_json.get("TicketSequence").is_some() {
        return Ok(0);
    }
    let account = tx_json
        .get("Account")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'tx.Account' field"))?;
    let account_id = decode_account(account).map_err(|_| act_malformed())?;
    let queued = ctx
        .tx_pool
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .count_by_account(&account_id) as u32;
    if let Some(ref cl) = ctx.closed_ledger {
        use crate::ledger::views::ReadView;
        let sle = cl
            .read(&crate::ledger::keylet::account(&account_id))
            .ok_or_else(|| RpcError::not_found("source account"))?;
        let acct = crate::ledger::AccountRoot::decode(sle.data())
            .map_err(|_| RpcError::internal("account decode failed"))?;
        return Ok(acct.sequence.saturating_add(queued));
    }
    let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
    let acct = ls
        .get_account(&account_id)
        .ok_or_else(|| RpcError::not_found("source account"))?;
    Ok(acct.sequence.saturating_add(queued))
}

fn ensure_simulate_unsigned(tx_json: &mut Value) -> Result<(), RpcError> {
    if tx_json.get("secret").is_some()
        || tx_json.get("seed").is_some()
        || tx_json.get("seed_hex").is_some()
        || tx_json.get("passphrase").is_some()
    {
        return Err(RpcError::invalid_params(
            "simulate does not accept signing secrets",
        ));
    }

    if tx_json.get("Signers").is_some() {
        return Err(RpcError::invalid_params(
            "simulate does not support Signers yet",
        ));
    }

    match tx_json.get("TxnSignature") {
        Some(Value::String(s)) if !s.is_empty() => {
            Err(RpcError::invalid_params("transaction must be unsigned"))
        }
        Some(Value::String(_)) | None => {
            if let Some(obj) = tx_json.as_object_mut() {
                obj.entry("TxnSignature".to_string())
                    .or_insert_with(|| json!(""));
                obj.entry("SigningPubKey".to_string())
                    .or_insert_with(|| json!(""));
            }
            Ok(())
        }
        Some(_) => Err(invalid_field_not_string("TxnSignature")),
    }
}

fn build_unsigned_blob_from_tx_json(
    tx_json: &Value,
    ctx: &NodeContext,
) -> Result<Vec<u8>, RpcError> {
    use crate::crypto::base58::decode_account;
    use crate::transaction::builder::TxBuilder;
    use crate::transaction::serialize::serialize_fields;

    let tx_type = tx_json
        .get("TransactionType")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'tx.TransactionType' field"))?;
    let account = tx_json
        .get("Account")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'tx.Account' field"))?;

    let fee = match tx_json.get("Fee") {
        Some(value) => parse_u64_like(value, "Fee")?,
        None => recommended_fee_drops(ctx)
            .parse::<u64>()
            .map_err(|_| RpcError::internal("recommended fee unavailable"))?,
    };
    let sequence = match tx_json.get("Sequence") {
        Some(value) => parse_u32_like(value, "Sequence")?,
        None => default_simulation_sequence(tx_json, ctx)?,
    };
    let flags = tx_json
        .get("Flags")
        .map(|value| parse_u32_like(value, "Flags"))
        .transpose()?
        .unwrap_or(0);

    let mut builder = match tx_type {
        "Payment" => TxBuilder::payment(),
        "TrustSet" => TxBuilder::trust_set(),
        "OfferCreate" => TxBuilder::offer_create(),
        "OfferCancel" => TxBuilder::offer_cancel(),
        "AccountSet" => TxBuilder::account_set(),
        "EscrowCreate" => TxBuilder::escrow_create(),
        "EscrowFinish" => TxBuilder::escrow_finish(),
        "EscrowCancel" => TxBuilder::escrow_cancel(),
        "CheckCreate" => TxBuilder::check_create(),
        "CheckCash" => TxBuilder::check_cash(),
        "CheckCancel" => TxBuilder::check_cancel(),
        "PaymentChannelCreate" => TxBuilder::paychan_create(),
        "PaymentChannelFund" => TxBuilder::paychan_fund(),
        "PaymentChannelClaim" => TxBuilder::paychan_claim(),
        _ => {
            return Err(RpcError::invalid_params(&format!(
                "unsupported simulate tx type: {tx_type}"
            )))
        }
    };

    builder = builder
        .account_address(account)
        .map_err(|_| RpcError::invalid_params("invalid Account"))?
        .fee(fee)
        .sequence(sequence)
        .flags(flags);

    if let Some(value) = parse_optional_u32_field(tx_json, "TicketSequence")? {
        builder = builder.ticket_sequence(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "LastLedgerSequence")? {
        builder = builder.last_ledger_sequence(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "DestinationTag")? {
        builder = builder.destination_tag(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "SourceTag")? {
        builder = builder.source_tag(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "SetFlag")? {
        builder = builder.set_flag(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "ClearFlag")? {
        builder = builder.clear_flag(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "TransferRate")? {
        builder = builder.transfer_rate(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "OfferSequence")? {
        builder = builder.offer_sequence(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "FinishAfter")? {
        builder = builder.finish_after(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "CancelAfter")? {
        builder = builder.cancel_after(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "SettleDelay")? {
        builder = builder.settle_delay(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "Expiration")? {
        builder = builder.expiration(value);
    }
    if let Some(value) = parse_optional_u32_field(tx_json, "TickSize")? {
        builder = builder.tick_size(value as u8);
    }
    if let Some(value) = parse_optional_hex_field(tx_json, "Domain")? {
        builder = builder.domain(value);
    }
    if let Some(value) = parse_optional_hex_field(tx_json, "PublicKey")? {
        builder = builder.public_key_field(value);
    }
    if let Some(value) = tx_json.get("Channel") {
        let raw = value
            .as_str()
            .ok_or_else(|| invalid_field_not_string("Channel"))?;
        let decoded = hex::decode(raw).map_err(|_| RpcError::invalid_params("invalid Channel"))?;
        if decoded.len() != 32 {
            return Err(RpcError::invalid_params("invalid Channel"));
        }
        let mut channel = [0u8; 32];
        channel.copy_from_slice(&decoded);
        builder = builder.channel(channel);
    }
    if let Some(destination) = tx_json.get("Destination").and_then(Value::as_str) {
        builder = builder
            .destination(destination)
            .map_err(|_| RpcError::invalid_params("invalid Destination"))?;
    }
    if let Some(amount) = parse_optional_amount_field(tx_json, "Amount", Some("DeliverMax"))? {
        builder = builder.amount(amount);
    }
    if let Some(limit) = parse_optional_amount_field(tx_json, "LimitAmount", None)? {
        builder = builder.limit_amount(limit);
    }
    if let Some(pays) = parse_optional_amount_field(tx_json, "TakerPays", None)? {
        builder = builder.taker_pays(pays);
    }
    if let Some(gets) = parse_optional_amount_field(tx_json, "TakerGets", None)? {
        builder = builder.taker_gets(gets);
    }
    if let Some(send_max) = parse_optional_amount_field(tx_json, "SendMax", None)? {
        builder = builder.send_max(send_max);
    }
    if let Some(deliver_min) = parse_optional_amount_field(tx_json, "DeliverMin", None)? {
        builder = builder.deliver_min(deliver_min);
    }

    let signing_pubkey = match tx_json.get("SigningPubKey") {
        None => Vec::new(),
        Some(Value::String(s)) if s.is_empty() => Vec::new(),
        Some(Value::String(s)) => {
            hex::decode(s).map_err(|_| RpcError::invalid_params("invalid SigningPubKey"))?
        }
        Some(_) => return Err(invalid_field_not_string("SigningPubKey")),
    };

    // Validate account strings used in IOU fields before serializing.
    if let Some(Value::Object(obj)) = tx_json.get("LimitAmount") {
        if let Some(issuer) = obj.get("issuer").and_then(Value::as_str) {
            let _ = decode_account(issuer)
                .map_err(|_| RpcError::invalid_params("invalid LimitAmount issuer"))?;
        }
    }

    let mut fields = builder
        .build_fields(signing_pubkey, None)
        .map_err(|e| RpcError::invalid_params(&format!("cannot build tx_json: {e}")))?;
    Ok(serialize_fields(&mut fields, false))
}

fn parse_simulate_input(
    params: &Value,
    ctx: &NodeContext,
) -> Result<(Vec<u8>, Value, bool), RpcError> {
    let binary = match params.get("binary") {
        Some(Value::Bool(v)) => *v,
        Some(_) => return Err(invalid_field("binary")),
        None => false,
    };

    if params.get("tx_blob").is_some() && params.get("tx_json").is_some() {
        return Err(RpcError::invalid_params(
            "can only include one of 'tx_blob' or 'tx_json'",
        ));
    }

    if let Some(blob_value) = params.get("tx_blob") {
        let blob_hex = blob_value
            .as_str()
            .ok_or_else(|| invalid_field_not_string("tx_blob"))?;
        if blob_hex.is_empty() {
            return Err(RpcError::invalid_params("invalid tx_blob"));
        }
        let blob =
            hex::decode(blob_hex).map_err(|_| RpcError::invalid_params("invalid tx_blob"))?;
        let parsed = crate::transaction::parse_blob(&blob)
            .map_err(|_| RpcError::invalid_params("invalid tx_blob"))?;
        if !parsed.signature.is_empty()
            || parsed
                .signers
                .iter()
                .any(|signer| !signer.signature.is_empty())
        {
            return Err(RpcError::invalid_params("transaction must be unsigned"));
        }
        return Ok((blob, parsed_tx_json(&parsed), binary));
    }

    let tx_json = params
        .get("tx_json")
        .ok_or_else(|| RpcError::invalid_params("neither 'tx_blob' nor 'tx_json' included"))?;
    let mut tx_json = tx_json
        .as_object()
        .cloned()
        .map(Value::Object)
        .ok_or_else(|| RpcError::invalid_params("invalid tx_json"))?;
    ensure_simulate_unsigned(&mut tx_json)?;
    let blob = build_unsigned_blob_from_tx_json(&tx_json, ctx)?;
    let parsed = crate::transaction::parse_blob(&blob)
        .map_err(|e| RpcError::invalid_params(&format!("tx parse error: {e}")))?;
    Ok((blob, parsed_tx_json(&parsed), binary))
}

fn recommended_trust_set_limit(
    currency: &crate::transaction::amount::Currency,
    issuer: &[u8; 20],
    value: &crate::transaction::amount::IouValue,
) -> Value {
    format_amount(&crate::transaction::amount::Amount::Iou {
        value: value.clone(),
        currency: currency.clone(),
        issuer: *issuer,
    })
}

fn collect_account_trustlines(
    account_id: &[u8; 20],
    requested_seq: u32,
    ctx: &NodeContext,
) -> Result<Vec<(crate::ledger::Key, crate::ledger::trustline::RippleState)>, RpcError> {
    if requested_seq != ctx.ledger_seq {
        if lookup_raw_object_at_ledger(
            &crate::ledger::account::shamap_key(account_id),
            requested_seq,
            ctx,
        )
        .is_none()
        {
            return Err(RpcError::not_found(&crate::crypto::base58::encode_account(
                account_id,
            )));
        }
        let (_, mut map) = historical_state_map(
            requested_seq,
            ctx,
            "historical trust line enumeration unavailable",
        )?;
        let mut trustlines: Vec<_> = collect_historical_state_entries(&mut map)?
            .into_iter()
            .filter_map(|(key, raw)| {
                let tl = crate::ledger::trustline::RippleState::decode_from_sle(&raw)?;
                if tl.low_account == *account_id || tl.high_account == *account_id {
                    Some((key, tl))
                } else {
                    None
                }
            })
            .collect();
        trustlines.sort_by_key(|(key, _)| key.0);
        return Ok(trustlines);
    }

    let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
    if ls.get_account(account_id).is_none() {
        return Err(RpcError::not_found(&crate::crypto::base58::encode_account(
            account_id,
        )));
    }
    let mut trustlines: Vec<_> = ls
        .trustlines_for_account(account_id)
        .into_iter()
        .map(|tl| (tl.key(), tl.clone()))
        .collect();
    trustlines.sort_by_key(|(key, _)| key.0);
    Ok(trustlines)
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
            / std::mem::size_of::<libc::natural_t>())
            as libc::mach_msg_type_number_t;
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

fn append_load_fields(
    dest: &mut Value,
    load: &crate::network::load::LoadSnapshot,
    human: bool,
    include_admin_breakdown: bool,
) {
    let job_queue_json = json!({
        "threads": load.job_queue_threads,
        "job_types": load.queue_job_types.iter().map(|job| {
            json!({
                "job_type": job.job_type.clone(),
                "waiting": job.waiting,
                "in_progress": job.in_progress,
                "over_target": job.over_target,
            })
        }).collect::<Vec<_>>(),
    });
    let load_base = load.load_base.max(1);
    if human {
        dest["load_factor"] = json!(load.load_factor() as f64 / load_base as f64);
        if load.load_factor_server() != load.load_factor() {
            dest["load_factor_server"] = json!(load.load_factor_server() as f64 / load_base as f64);
        }
        dest["load_queue_overloaded"] = json!(load.queue_overloaded);
        if include_admin_breakdown {
            if let Some(local) = load.load_factor_local() {
                dest["load_factor_local"] = json!(local as f64 / load_base as f64);
            }
            if let Some(net) = load.load_factor_net() {
                dest["load_factor_net"] = json!(net as f64 / load_base as f64);
            }
            if let Some(cluster) = load.load_factor_cluster() {
                dest["load_factor_cluster"] = json!(cluster as f64 / load_base as f64);
            }
            dest["load_queue_depth"] = json!(load.queue_depth);
            dest["load_queue_capacity"] = json!(load.queue_capacity);
            dest["queued_transactions"] = json!(load.queued_transactions);
            dest["tracked_transactions"] = json!(load.tracked_transactions);
            dest["tracked_inbound_transactions"] = json!(load.tracked_inbound_transactions);
            dest["active_path_requests"] = json!(load.active_path_requests);
            dest["active_inbound_ledgers"] = json!(load.active_inbound_ledgers);
            dest["job_queue"] = job_queue_json;
        }
    } else {
        dest["load_base"] = json!(load.load_base);
        dest["load_factor"] = json!(load.load_factor());
        dest["load_factor_server"] = json!(load.load_factor_server());
        dest["load_queue_overloaded"] = json!(load.queue_overloaded);
        if include_admin_breakdown {
            if let Some(local) = load.load_factor_local() {
                dest["load_factor_local"] = json!(local);
            }
            if let Some(net) = load.load_factor_net() {
                dest["load_factor_net"] = json!(net);
            }
            if let Some(cluster) = load.load_factor_cluster() {
                dest["load_factor_cluster"] = json!(cluster);
            }
            dest["load_queue_depth"] = json!(load.queue_depth);
            dest["load_queue_capacity"] = json!(load.queue_capacity);
            dest["queued_transactions"] = json!(load.queued_transactions);
            dest["tracked_transactions"] = json!(load.tracked_transactions);
            dest["tracked_inbound_transactions"] = json!(load.tracked_inbound_transactions);
            dest["active_path_requests"] = json!(load.active_path_requests);
            dest["active_inbound_ledgers"] = json!(load.active_inbound_ledgers);
            dest["job_queue"] = job_queue_json;
        }
    }
}

fn append_open_ledger_fields(dest: &mut Value, open: &crate::ledger::open_ledger::OpenLedgerSnapshot) {
    dest["open_ledger_current_index"] = json!(open.ledger_current_index);
    dest["open_ledger_parent_ledger_index"] = json!(open.parent_ledger_index);
    dest["open_ledger_queued_transactions"] = json!(open.queued_transactions);
    dest["open_ledger_open_fee_level"] = json!(open.open_fee_level);
    dest["open_ledger_revision"] = json!(open.revision);
    dest["open_ledger_modify_count"] = json!(open.modify_count);
    dest["open_ledger_accept_count"] = json!(open.accept_count);
    dest["open_ledger_last_modified_unix"] = json!(open.last_modified_unix);
    dest["open_ledger_last_accept_unix"] = json!(open.last_accept_unix);
    dest["open_ledger_has_open_view"] = json!(open.has_open_view);
    dest["open_ledger_view_base_ledger_index"] = json!(open.open_view_base_ledger_index);
    dest["open_ledger_view_applied_transactions"] = json!(open.open_view_applied_transactions);
    dest["open_ledger_view_failed_transactions"] = json!(open.open_view_failed_transactions);
    dest["open_ledger_view_skipped_transactions"] = json!(open.open_view_skipped_transactions);
    dest["open_ledger_view_tx_count"] = json!(open.open_view_tx_count);
    dest["open_ledger_view_state_hash"] = json!(open.open_view_state_hash);
    dest["open_ledger_view_tx_hash"] = json!(open.open_view_tx_hash);
}

fn append_state_accounting_fields(
    dest: &mut Value,
    snapshot: &crate::network::ops::StateAccountingSnapshot,
) {
    dest["state_accounting"] = json!({
        "disconnected": {
            "transitions": snapshot.disconnected.transitions.to_string(),
            "duration_us": snapshot.disconnected.duration_us.to_string(),
        },
        "connected": {
            "transitions": snapshot.connected.transitions.to_string(),
            "duration_us": snapshot.connected.duration_us.to_string(),
        },
        "syncing": {
            "transitions": snapshot.syncing.transitions.to_string(),
            "duration_us": snapshot.syncing.duration_us.to_string(),
        },
        "tracking": {
            "transitions": snapshot.tracking.transitions.to_string(),
            "duration_us": snapshot.tracking.duration_us.to_string(),
        },
        "full": {
            "transitions": snapshot.full.transitions.to_string(),
            "duration_us": snapshot.full.duration_us.to_string(),
        },
    });
    dest["server_state_duration_us"] = json!(snapshot.server_state_duration_us.to_string());
    if let Some(initial_sync_duration_us) = snapshot.initial_sync_duration_us {
        dest["initial_sync_duration_us"] = json!(initial_sync_duration_us.to_string());
    }
}

fn snapshot_needs_network_ledger(sync_done: bool, ledger_seq: u32) -> bool {
    !sync_done && ledger_seq == 0
}

fn context_needs_network_ledger(ctx: &NodeContext) -> bool {
    if ctx.ledger_seq == 0 {
        return true;
    }
    ctx.fetch_info
        .as_ref()
        .map(|fetch| !fetch.have_header)
        .unwrap_or(false)
}

/// Lock-free server_info using ArcSwap snapshot — never blocks during sync.
pub fn server_info_snapshot(
    snap: &crate::rpc::RpcSnapshot,
    follower: Option<&std::sync::Arc<crate::ledger::follow::FollowerState>>,
    rpc_sync: Option<&std::sync::Arc<crate::rpc_sync::RpcSyncState>>,
) -> Result<Value, RpcError> {
    const XRPL_EPOCH_OFFSET: u64 = 946_684_800;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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
    let server_state =
        crate::network::ops::snapshot_server_state_label(snap.sync_done, age, snap.peer_count);
    let state_accounting = snap.state_accounting_snapshot.clone().unwrap_or_else(|| {
        crate::network::ops::synthetic_state_accounting_snapshot(
            snap.start_time,
            server_state,
            std::time::Instant::now(),
        )
    });

    let mut info = json!({
        "info": {
            "build_version":     snap.build_version,
            "network_id":        snap.network_id,
            "standalone":        snap.standalone_mode,
            "server_state":      server_state,
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
            "peers":             snap.peer_count,
            "pubkey_node":       snap.pubkey_node,
            "uptime":            snap.start_time.elapsed().as_secs(),
            "complete_ledgers":  snap.complete_ledgers,
            "memory_mb":         snap.memory_mb,
            "objects_stored":    snap.object_count,
        }
    });
    append_load_fields(&mut info["info"], &snap.load_snapshot, true, false);
    append_state_accounting_fields(&mut info["info"], &state_accounting);
    if snapshot_needs_network_ledger(snap.sync_done, snap.ledger_seq) {
        info["info"]["network_ledger"] = json!("waiting");
    }

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

pub fn server_state_snapshot(snap: &crate::rpc::RpcSnapshot) -> Result<Value, RpcError> {
    const XRPL_EPOCH_OFFSET: u64 = 946_684_800;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ledger_unix = snap.ledger_header.close_time as u64 + XRPL_EPOCH_OFFSET;
    let age = now_unix.saturating_sub(ledger_unix);
    let server_state =
        crate::network::ops::snapshot_server_state_label(snap.sync_done, age, snap.peer_count);
    let state_accounting = snap.state_accounting_snapshot.clone().unwrap_or_else(|| {
        crate::network::ops::synthetic_state_accounting_snapshot(
            snap.start_time,
            server_state,
            std::time::Instant::now(),
        )
    });

    let mut state = json!({
        "state": {
            "build_version": snap.build_version,
            "network_id": snap.network_id,
            "standalone": snap.standalone_mode,
            "server_state": server_state,
            "validation_quorum": snap.validation_quorum,
            "validated_ledger": {
                "seq": snap.ledger_seq,
                "hash": snap.ledger_hash,
                "base_fee": snap.fees.base,
                "reserve_base": snap.fees.reserve,
                "reserve_inc": snap.fees.increment,
                "age": age,
                "close_time": snap.ledger_header.close_time,
            },
            "peers": snap.peer_count,
            "pubkey_node": snap.pubkey_node,
            "uptime": snap.start_time.elapsed().as_secs(),
            "complete_ledgers": snap.complete_ledgers,
            "memory_mb": snap.memory_mb,
            "objects_stored": snap.object_count,
        }
    });
    append_load_fields(&mut state["state"], &snap.load_snapshot, false, false);
    append_state_accounting_fields(&mut state["state"], &state_accounting);
    if snapshot_needs_network_ledger(snap.sync_done, snap.ledger_seq) {
        state["state"]["network_ledger"] = json!("waiting");
    }
    if !snap.validator_key.is_empty() {
        state["state"]["validator_key"] = json!(snap.validator_key);
    }
    Ok(state)
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
    let validation_quorum = current_validation_quorum(ctx);
    let ops = ctx
        .network_ops_snapshot
        .clone()
        .unwrap_or_else(|| crate::network::ops::NetworkOpsSnapshot::from_context(ctx));
    let open_ledger = ctx
        .open_ledger_snapshot
        .as_ref()
        .cloned()
        .unwrap_or_default();
    let server_state = ops.server_state.clone();
    let state_accounting = ctx.state_accounting_snapshot.clone().unwrap_or_else(|| {
        crate::network::ops::synthetic_state_accounting_snapshot(
            ctx.start_time,
            &server_state,
            std::time::Instant::now(),
        )
    });

    let mut info = json!({
        "info": {
            "build_version":         ctx.build_version,
            "network_id":            ctx.network_id,
            "standalone":            ctx.standalone_mode,
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
            "peers":                 ops.peer_count,
            "cluster":               {
                "configured": ops.cluster_configured,
                "observed":   ops.cluster_observed,
                "connected":  ops.cluster_connected,
            },
            "peerfinder":            {
                "known": ops.known_peers,
                "dialable": ops.dialable_peers,
                "backed_off": ops.backed_off_peers,
                "retry_ready": ops.peerfinder_retry_ready,
                "ready": ops.peerfinder_ready,
                "cooling": ops.peerfinder_cooling,
                "cold": ops.peerfinder_cold,
                "distinct_sources": ops.peerfinder_sources,
            },
            "resource_blocked_peers": ops.blocked_peers,
            "resource_warned_peers": ops.warned_peers,
            "resource_tracked_peers": ops.resource_tracked,
            "resource_ip_balance": ops.resource_ip_balance,
            "resource_peer_balance": ops.resource_peer_balance,
            "resource_balance": ops.resource_balance,
            "resource_warning_events": ops.resource_warning_events,
            "resource_disconnect_events": ops.resource_disconnect_events,
            "tracked_inbound_ledgers": ops.tracked_inbound_ledgers,
            "failed_inbound_ledgers": ops.failed_inbound_ledgers,
            "node_store_fetch_errors": ops.node_store_fetch_errors,
            "node_store_flush_ops": ops.node_store_flush_ops,
            "node_store_last_flush_unix": ops.node_store_last_flush_unix,
            "node_store_last_flush_duration_ms": ops.node_store_last_flush_duration_ms,
            "fetch_pack_entries": ops.fetch_pack_entries,
            "fetch_pack_backend_fill_total": ops.fetch_pack_backend_fill_total,
            "fetch_pack_reused_total": ops.fetch_pack_reused_total,
            "fetch_pack_persisted_total": ops.fetch_pack_persisted_total,
            "fetch_pack_persist_errors_total": ops.fetch_pack_persist_errors_total,
            "fetch_pack_flush_ops": ops.fetch_pack_flush_ops,
            "fetch_pack_last_flush_unix": ops.fetch_pack_last_flush_unix,
            "fetch_pack_last_flush_duration_ms": ops.fetch_pack_last_flush_duration_ms,
            "tracked_transactions": ops.tracked_transactions,
            "submitted_transactions": ops.submitted_transactions,
            "pubkey_node":           ctx.pubkey_node.clone(),
            "uptime":                ctx.start_time.elapsed().as_secs(),
            "complete_ledgers":      ctx.history.read().unwrap_or_else(|e| e.into_inner()).complete_ledgers(),
            "memory_mb":             get_memory_mb(),
            "objects_stored":        ops.object_count,
        }
    });
    append_load_fields(
        &mut info["info"],
        &ctx.load_snapshot,
        true,
        ctx.admin_rpc_enabled,
    );
    append_state_accounting_fields(&mut info["info"], &state_accounting);
    if context_needs_network_ledger(ctx) {
        info["info"]["network_ledger"] = json!("waiting");
    }

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

    append_open_ledger_fields(&mut info["info"], &open_ledger);

    if !ctx.validator_key.is_empty() {
        info["info"]["validator_key"] = json!(ctx.validator_key.clone());
    }

    Ok(info)
}

pub fn server_state(ctx: &NodeContext) -> Result<Value, RpcError> {
    const XRPL_EPOCH_OFFSET: u64 = 946_684_800;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ledger_unix = ctx.ledger_header.close_time as u64 + XRPL_EPOCH_OFFSET;
    let age = now_unix.saturating_sub(ledger_unix);
    let validation_quorum = current_validation_quorum(ctx);
    let ops = ctx
        .network_ops_snapshot
        .clone()
        .unwrap_or_else(|| crate::network::ops::NetworkOpsSnapshot::from_context(ctx));
    let open_ledger = ctx
        .open_ledger_snapshot
        .as_ref()
        .cloned()
        .unwrap_or_default();
    let state_accounting = ctx.state_accounting_snapshot.clone().unwrap_or_else(|| {
        crate::network::ops::synthetic_state_accounting_snapshot(
            ctx.start_time,
            &ops.server_state,
            std::time::Instant::now(),
        )
    });

    let mut state = json!({
        "state": {
            "build_version": ctx.build_version,
            "network_id": ctx.network_id,
            "standalone": ctx.standalone_mode,
            "server_state": ops.server_state,
            "validation_quorum": validation_quorum,
            "validated_ledger": {
                "seq": ctx.ledger_seq,
                "hash": ctx.ledger_hash,
                "base_fee": ctx.fees.base,
                "reserve_base": ctx.fees.reserve,
                "reserve_inc": ctx.fees.increment,
                "age": age,
                "close_time": ctx.ledger_header.close_time,
            },
            "peers": ops.peer_count,
            "cluster": {
                "configured": ops.cluster_configured,
                "observed": ops.cluster_observed,
                "connected": ops.cluster_connected,
            },
            "peerfinder": {
                "known": ops.known_peers,
                "dialable": ops.dialable_peers,
                "backed_off": ops.backed_off_peers,
                "retry_ready": ops.peerfinder_retry_ready,
                "ready": ops.peerfinder_ready,
                "cooling": ops.peerfinder_cooling,
                "cold": ops.peerfinder_cold,
                "distinct_sources": ops.peerfinder_sources,
            },
            "resource_blocked_peers": ops.blocked_peers,
            "resource_warned_peers": ops.warned_peers,
            "resource_tracked_peers": ops.resource_tracked,
            "resource_ip_balance": ops.resource_ip_balance,
            "resource_peer_balance": ops.resource_peer_balance,
            "resource_balance": ops.resource_balance,
            "resource_warning_events": ops.resource_warning_events,
            "resource_disconnect_events": ops.resource_disconnect_events,
            "tracked_inbound_ledgers": ops.tracked_inbound_ledgers,
            "failed_inbound_ledgers": ops.failed_inbound_ledgers,
            "node_store_fetch_errors": ops.node_store_fetch_errors,
            "node_store_flush_ops": ops.node_store_flush_ops,
            "node_store_last_flush_unix": ops.node_store_last_flush_unix,
            "node_store_last_flush_duration_ms": ops.node_store_last_flush_duration_ms,
            "fetch_pack_entries": ops.fetch_pack_entries,
            "fetch_pack_backend_fill_total": ops.fetch_pack_backend_fill_total,
            "fetch_pack_reused_total": ops.fetch_pack_reused_total,
            "fetch_pack_persisted_total": ops.fetch_pack_persisted_total,
            "fetch_pack_persist_errors_total": ops.fetch_pack_persist_errors_total,
            "fetch_pack_flush_ops": ops.fetch_pack_flush_ops,
            "fetch_pack_last_flush_unix": ops.fetch_pack_last_flush_unix,
            "fetch_pack_last_flush_duration_ms": ops.fetch_pack_last_flush_duration_ms,
            "tracked_transactions": ops.tracked_transactions,
            "submitted_transactions": ops.submitted_transactions,
            "pubkey_node": ctx.pubkey_node.clone(),
            "uptime": ctx.start_time.elapsed().as_secs(),
            "complete_ledgers": ctx.history.read().unwrap_or_else(|e| e.into_inner()).complete_ledgers(),
            "memory_mb": get_memory_mb(),
            "objects_stored": ops.object_count,
        }
    });
    append_open_ledger_fields(&mut state["state"], &open_ledger);
    append_load_fields(
        &mut state["state"],
        &ctx.load_snapshot,
        false,
        ctx.admin_rpc_enabled,
    );
    append_state_accounting_fields(
        &mut state["state"],
        &state_accounting,
    );
    if context_needs_network_ledger(ctx) {
        state["state"]["network_ledger"] = json!("waiting");
    }

    if !ctx.validator_key.is_empty() {
        state["state"]["validator_key"] = json!(ctx.validator_key.clone());
    }

    Ok(state)
}

fn current_validation_quorum(ctx: &NodeContext) -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(manager) = ctx.validator_list_manager.as_ref() {
        return manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot(now)
            .validation_quorum;
    }

    let unl_size = ctx.amendments.len().max(35) as u32;
    unl_size * 80 / 100 + 1
}

pub fn version() -> Result<Value, RpcError> {
    Ok(json!({
        "version": {
            "first": "1.0.0",
            "good":  "1.0.0",
            "last":  "1.0.0"
        }
    }))
}

fn server_definition_type_name(type_code: u16) -> &'static str {
    match type_code {
        1 => "UInt16",
        2 => "UInt32",
        3 => "UInt64",
        4 => "Hash128",
        5 => "Hash256",
        6 => "Amount",
        7 => "Blob",
        8 => "AccountID",
        14 => "STObject",
        15 => "STArray",
        16 => "UInt8",
        17 => "Hash160",
        19 => "Vector256",
        _ => "Unknown",
    }
}

fn server_definition_fields() -> Vec<Value> {
    use crate::transaction::field as f;
    let defs: [(&str, crate::transaction::field::FieldDef); 43] = [
        ("TransactionType", f::TRANSACTION_TYPE),
        ("SignerWeight", f::SIGNER_WEIGHT),
        ("TransferFee", f::TRANSFER_FEE),
        ("Flags", f::FLAGS),
        ("SourceTag", f::SOURCE_TAG),
        ("Sequence", f::SEQUENCE),
        ("Expiration", f::EXPIRATION),
        ("TransferRate", f::TRANSFER_RATE),
        ("DestinationTag", f::DESTINATION_TAG),
        ("QualityIn", f::QUALITY_IN),
        ("QualityOut", f::QUALITY_OUT),
        ("OfferSequence", f::OFFER_SEQUENCE),
        ("LastLedgerSequence", f::LAST_LEDGER_SEQUENCE),
        ("CancelAfter", f::CANCEL_AFTER),
        ("FinishAfter", f::FINISH_AFTER),
        ("SettleDelay", f::SETTLE_DELAY),
        ("TicketSequence", f::TICKET_SEQUENCE),
        ("NFTokenTaxon", f::NFTOKEN_TAXON),
        ("AccountTxnID", f::ACCOUNT_TXID),
        ("NFTokenID", f::NFTOKEN_ID),
        ("InvoiceID", f::INVOICE_ID),
        ("Channel", f::CHANNEL),
        ("NFTokenBuyOffer", f::NFTOKEN_BUY_OFFER),
        ("NFTokenSellOffer", f::NFTOKEN_SELL_OFFER),
        ("Amount", f::AMOUNT),
        ("LimitAmount", f::LIMIT_AMOUNT),
        ("TakerPays", f::TAKER_PAYS),
        ("TakerGets", f::TAKER_GETS),
        ("Fee", f::FEE),
        ("SendMax", f::SEND_MAX),
        ("DeliverMin", f::DELIVER_MIN),
        ("PublicKey", f::PUBLIC_KEY),
        ("SigningPubKey", f::SIGNING_PUB_KEY),
        ("TxnSignature", f::TXN_SIGNATURE),
        ("URI", f::URI),
        ("Signature", f::SIGNATURE),
        ("MemoType", f::MEMO_TYPE),
        ("MemoData", f::MEMO_DATA),
        ("Account", f::ACCOUNT),
        ("Destination", f::DESTINATION),
        ("Issuer", f::ISSUER),
        ("Authorize", f::AUTHORIZE),
        ("Unauthorize", f::UNAUTHORIZE),
    ];
    defs.into_iter()
        .map(|(name, def)| {
            json!([
                name,
                {
                    "isSerialized": true,
                    "isSigningField": def.is_signing,
                    "isVLEncoded": def.type_code == crate::transaction::field::TypeCode::Blob as u16,
                    "nth": def.field_code,
                    "type": server_definition_type_name(def.type_code),
                }
            ])
        })
        .collect()
}

fn server_definition_transaction_types() -> Vec<Value> {
    vec![
        json!(["Payment", 0]),
        json!(["EscrowCreate", 1]),
        json!(["EscrowFinish", 2]),
        json!(["AccountSet", 3]),
        json!(["EscrowCancel", 4]),
        json!(["SetRegularKey", 5]),
        json!(["OfferCreate", 7]),
        json!(["OfferCancel", 8]),
        json!(["TicketCreate", 10]),
        json!(["PaymentChannelCreate", 13]),
        json!(["PaymentChannelFund", 14]),
        json!(["PaymentChannelClaim", 15]),
        json!(["CheckCreate", 16]),
        json!(["CheckCash", 17]),
        json!(["CheckCancel", 18]),
        json!(["DepositPreauth", 19]),
        json!(["TrustSet", 20]),
        json!(["AccountDelete", 21]),
        json!(["NFTokenMint", 25]),
        json!(["NFTokenBurn", 26]),
        json!(["NFTokenCreateOffer", 27]),
        json!(["NFTokenCancelOffer", 28]),
        json!(["NFTokenAcceptOffer", 29]),
        json!(["AMMCreate", 35]),
        json!(["AMMDeposit", 36]),
        json!(["AMMWithdraw", 37]),
        json!(["AMMVote", 38]),
        json!(["AMMBid", 39]),
        json!(["AMMDelete", 40]),
        json!(["DelegateSet", 64]),
        json!(["Batch", 71]),
    ]
}

fn server_definition_ledger_entry_types() -> Vec<Value> {
    vec![
        json!(["AccountRoot", 0x0061]),
        json!(["DirectoryNode", 0x0064]),
        json!(["RippleState", 0x0072]),
        json!(["Offer", 0x006F]),
        json!(["LedgerHashes", 0x0068]),
        json!(["Amendments", 0x0066]),
        json!(["FeeSettings", 0x0073]),
        json!(["NegativeUNL", 0x004E]),
        json!(["Escrow", 0x0075]),
        json!(["PayChannel", 0x0078]),
        json!(["Check", 0x0043]),
        json!(["DepositPreauth", 0x0070]),
        json!(["Ticket", 0x0054]),
        json!(["SignerList", 0x0053]),
        json!(["NFTokenPage", 0x0050]),
        json!(["NFTokenOffer", 0x0037]),
        json!(["AMM", 0x0079]),
        json!(["DID", 0x0049]),
        json!(["Oracle", 0x0080]),
        json!(["MPToken", 0x007F]),
        json!(["MPTokenIssuance", 0x007E]),
        json!(["Bridge", 0x0069]),
        json!(["XChainOwnedClaimID", 0x0071]),
        json!(["XChainOwnedCreateAccountClaimID", 0x0074]),
        json!(["Credential", 0x0081]),
        json!(["PermissionedDomain", 0x0082]),
        json!(["Delegate", 0x0083]),
        json!(["Vault", 0x0084]),
        json!(["LoanBroker", 0x0088]),
        json!(["Loan", 0x0089]),
    ]
}

pub fn server_definitions(params: &Value) -> Result<Value, RpcError> {
    let base = json!({
        "FIELDS": server_definition_fields(),
        "LEDGER_ENTRY_TYPES": server_definition_ledger_entry_types(),
        "TRANSACTION_TYPES": server_definition_transaction_types(),
        "TYPES": [
            ["UInt16", 1],
            ["UInt32", 2],
            ["UInt64", 3],
            ["Hash128", 4],
            ["Hash256", 5],
            ["Amount", 6],
            ["Blob", 7],
            ["AccountID", 8],
            ["STObject", 14],
            ["STArray", 15],
            ["UInt8", 16],
            ["Hash160", 17],
            ["Vector256", 19]
        ]
    });

    let encoded = serde_json::to_vec(&base).map_err(|_| RpcError::internal("definitions"))?;
    let hash = hex::encode_upper(crate::crypto::sha256(&encoded));
    if params
        .get("hash")
        .and_then(Value::as_str)
        .is_some_and(|client| client.eq_ignore_ascii_case(&hash))
    {
        return Ok(json!({ "hash": hash }));
    }

    let mut out = base;
    out["hash"] = json!(hash);
    Ok(out)
}

pub fn get_counts(ctx: &NodeContext) -> Result<Value, RpcError> {
    let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());
    let ledger_count = history.ledger_count();
    let tx_count = history.tx_count();
    let account_count = ctx
        .ledger_state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .account_count();
    let queued = ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner()).len();

    Ok(json!({
        "dbKBLedger": 0,
        "dbKBTotal": 0,
        "ledger_objects": ctx.object_count,
        "ledger_count": ledger_count,
        "transaction_count": tx_count,
        "state_account_count": account_count,
        "queued_transactions": queued,
        "uptime": ctx.start_time.elapsed().as_secs()
    }))
}

pub fn fetch_info(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let clear = params
        .get("clear")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if clear {
        if let Some(flag) = &ctx.sync_clear_requested {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let mut info = serde_json::Map::new();
    if let Some(fetch) = &ctx.fetch_info {
        let mut entry = serde_json::Map::new();
        entry.insert("hash".to_string(), json!(fetch.hash));
        entry.insert("have_header".to_string(), json!(fetch.have_header));
        entry.insert("have_state".to_string(), json!(fetch.have_state));
        entry.insert(
            "have_transactions".to_string(),
            json!(fetch.have_transactions),
        );
        entry.insert(
            "needed_state_hashes".to_string(),
            json!(fetch.needed_state_hashes),
        );
        entry.insert(
            "backend_fetch_errors".to_string(),
            json!(fetch.backend_fetch_errors),
        );
        entry.insert("peers".to_string(), json!(fetch.peers));
        entry.insert("timeouts".to_string(), json!(fetch.timeouts));
        entry.insert("in_flight".to_string(), json!(fetch.in_flight));
        entry.insert("inner_nodes".to_string(), json!(fetch.inner_nodes));
        entry.insert("state_nodes".to_string(), json!(fetch.state_nodes));
        entry.insert("pass".to_string(), json!(fetch.pass));
        entry.insert("new_objects".to_string(), json!(fetch.new_objects));
        if let Some(tail_hash) = &fetch.tail_stuck_hash {
            entry.insert("tail_stuck_hash".to_string(), json!(tail_hash));
        }
        if fetch.tail_stuck_retries > 0 {
            entry.insert(
                "tail_stuck_retries".to_string(),
                json!(fetch.tail_stuck_retries),
            );
        }
        info.insert(fetch.key.clone(), Value::Object(entry));
    }

    Ok(json!({
        "info": Value::Object(info)
    }))
}

pub fn manifest(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let public_key = params
        .get("public_key")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'public_key' field"))?;
    let (prefix, payload) = crate::crypto::base58::decode(public_key)
        .map_err(|_| RpcError::invalid_params("invalid public_key"))?;
    if prefix != crate::crypto::base58::PREFIX_NODE_PUBLIC || payload.len() != 33 {
        return Err(RpcError::invalid_params("invalid public_key"));
    }
    let mut out = json!({
        "requested": public_key
    });
    if let Some((manifest, details)) = manifest_response_for_key(ctx, public_key) {
        out["manifest"] = json!(manifest);
        out["details"] = Value::Object(details);
    }
    Ok(out)
}

pub fn channel_authorize(params: &Value, _ctx: &NodeContext) -> Result<Value, RpcError> {
    let (key_type, seed) = parse_rpc_seed(params)?;
    let channel_id = parse_channel_id(params, "channel_id")?;
    let amount = parse_drops_string(params, "amount")?;

    let signature = match key_type {
        crate::crypto::keys::KeyType::Secp256k1 => {
            let key = crate::crypto::keys::Secp256k1KeyPair::from_seed_entropy(&seed);
            let mut payload = crate::ledger::paychan::PREFIX_CLAIM.to_vec();
            payload.extend_from_slice(&channel_id);
            payload.extend_from_slice(&amount.to_be_bytes());
            key.sign(&payload)
        }
        crate::crypto::keys::KeyType::Ed25519 => {
            let key = crate::crypto::keys::Ed25519KeyPair::from_seed_entropy(&seed);
            let mut payload = crate::ledger::paychan::PREFIX_CLAIM.to_vec();
            payload.extend_from_slice(&channel_id);
            payload.extend_from_slice(&amount.to_be_bytes());
            key.sign(&payload)
        }
    };

    Ok(json!({
        "signature": hex::encode_upper(signature),
    }))
}

pub fn channel_verify(params: &Value) -> Result<Value, RpcError> {
    let public_key = parse_public_key_bytes(params, "public_key")?;
    let channel_id = parse_channel_id(params, "channel_id")?;
    let amount = parse_drops_string(params, "amount")?;
    let signature = parse_signature_hex(params, "signature")?;
    let mut payload = crate::ledger::paychan::PREFIX_CLAIM.to_vec();
    payload.extend_from_slice(&channel_id);
    payload.extend_from_slice(&amount.to_be_bytes());
    let verified = if public_key.first() == Some(&0xED) && public_key.len() == 33 {
        use ed25519_dalek::Verifier;
        let Ok(key_bytes): Result<[u8; 32], _> = public_key[1..].try_into() else {
            return Ok(json!({ "signature_verified": false }));
        };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
            return Ok(json!({ "signature_verified": false }));
        };
        let Ok(sig_bytes): Result<[u8; 64], _> = signature.as_slice().try_into() else {
            return Ok(json!({ "signature_verified": false }));
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        vk.verify(&payload, &sig).is_ok()
    } else {
        crate::crypto::keys::verify_secp256k1(&public_key, &payload, &signature)
    };
    Ok(json!({
        "signature_verified": verified,
    }))
}

fn add_iou_to_currency_map(
    map: &mut std::collections::BTreeMap<String, crate::transaction::amount::IouValue>,
    currency: &crate::transaction::amount::Currency,
    value: &crate::transaction::amount::IouValue,
) {
    let entry = map
        .entry(currency.to_ascii())
        .or_insert(crate::transaction::amount::IouValue::ZERO);
    *entry = entry.add(value);
}

fn add_iou_to_address_map(
    map: &mut std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, crate::transaction::amount::IouValue>,
    >,
    address: &[u8; 20],
    currency: &crate::transaction::amount::Currency,
    value: &crate::transaction::amount::IouValue,
) {
    let entry = map
        .entry(crate::crypto::base58::encode_account(address))
        .or_default();
    add_iou_to_currency_map(entry, currency, value);
}

fn gateway_amount_lists_json(
    map: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, crate::transaction::amount::IouValue>,
    >,
) -> Value {
    Value::Object(
        map.into_iter()
            .map(|(address, amounts)| {
                let values: Vec<Value> = amounts
                    .into_iter()
                    .map(|(currency, value)| {
                        json!({
                            "currency": currency,
                            "value": format_iou_value(&value),
                        })
                    })
                    .collect();
                (address, Value::Array(values))
            })
            .collect(),
    )
}

pub fn gateway_balances(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let account_id = parse_account_field(params, "account")?;
    let account = crate::crypto::base58::encode_account(&account_id);
    let hotwallets: std::collections::HashSet<[u8; 20]> = match params.get("hotwallet") {
        None => std::collections::HashSet::new(),
        Some(Value::String(s)) => {
            let wallet = decode_account(s).map_err(|_| invalid_field("hotwallet"))?;
            std::collections::HashSet::from([wallet])
        }
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| invalid_field("hotwallet"))
                    .and_then(|s| decode_account(s).map_err(|_| invalid_field("hotwallet")))
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(invalid_field("hotwallet")),
    };

    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let is_historical = requested_seq != ctx.ledger_seq;
    let mut response_ledger_hash = ctx.ledger_hash.clone();

    let mut obligations = std::collections::BTreeMap::new();
    let mut balances = std::collections::BTreeMap::new();
    let mut assets = std::collections::BTreeMap::new();

    let mut process_trustline = |tl: &crate::ledger::trustline::RippleState| {
        let other = if tl.low_account == account_id {
            tl.high_account
        } else if tl.high_account == account_id {
            tl.low_account
        } else {
            return;
        };
        let account_balance = tl.balance_for(&account_id);
        if account_balance.is_positive() {
            add_iou_to_address_map(&mut assets, &other, &tl.currency, &account_balance);
        } else if account_balance.is_negative() {
            let obligation = account_balance.abs();
            if hotwallets.contains(&other) {
                add_iou_to_address_map(&mut balances, &other, &tl.currency, &obligation);
            } else {
                add_iou_to_currency_map(&mut obligations, &tl.currency, &obligation);
            }
        }
    };

    if is_historical {
        let (header, mut map) = historical_state_map(
            requested_seq,
            ctx,
            "historical gateway_balances unavailable",
        )?;
        response_ledger_hash = hex::encode_upper(header.hash);
        if map
            .get(&crate::ledger::keylet::account(&account_id).key)
            .is_none()
        {
            return Err(RpcError::not_found(&account));
        }
        for (_, data) in collect_historical_state_entries(&mut map)? {
            if let Some(tl) = decode_ripple_state_any(&data) {
                process_trustline(&tl);
            }
        }
    } else {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if ls.get_account(&account_id).is_none() {
            return Err(RpcError::not_found(&account));
        }
        for tl in ls.trustlines_for_account(&account_id) {
            process_trustline(tl);
        }
    }

    let mut out = json!({
        "account": account,
        "ledger_hash": response_ledger_hash,
        "ledger_index": requested_seq,
    });
    if !obligations.is_empty() {
        out["obligations"] = Value::Object(
            obligations
                .into_iter()
                .map(|(currency, value)| (currency, json!(format_iou_value(&value))))
                .collect(),
        );
    }
    if !balances.is_empty() {
        out["balances"] = gateway_amount_lists_json(balances);
    }
    if !assets.is_empty() {
        out["assets"] = gateway_amount_lists_json(assets);
    }
    Ok(out)
}

pub fn peers(ctx: &NodeContext) -> Result<Value, RpcError> {
    let peers: Vec<Value> = ctx
        .peer_summaries
        .iter()
        .map(|peer| {
            let mut cluster = serde_json::Map::new();
            if let Some(cluster_info) = peer.cluster.as_ref() {
                cluster.insert("address".to_string(), json!(cluster_info.address));
                cluster.insert("reserved".to_string(), json!(cluster_info.reserved));
                cluster.insert("loopback".to_string(), json!(cluster_info.loopback));
                cluster.insert("connected".to_string(), json!(cluster_info.connected));
                if let Some(public_key) = cluster_info.public_key.as_ref() {
                    cluster.insert("public_key".to_string(), json!(public_key));
                }
                if let Some(tag) = cluster_info.tag.as_ref() {
                    cluster.insert("tag".to_string(), json!(tag));
                }
                if let Some(status) = cluster_info.status.as_ref() {
                    cluster.insert("status".to_string(), json!(status));
                }
                if let Some(action) = cluster_info.action.as_ref() {
                    cluster.insert("action".to_string(), json!(action));
                }
                if let Some(ledger_seq) = cluster_info.ledger_seq {
                    cluster.insert("ledger_index".to_string(), json!(ledger_seq));
                }
                if let Some((min_seq, max_seq)) = cluster_info.ledger_range {
                    cluster.insert("ledger_index_min".to_string(), json!(min_seq));
                    cluster.insert("ledger_index_max".to_string(), json!(max_seq));
                }
                if let Some(load_factor) = cluster_info.load_factor {
                    cluster.insert("load_factor".to_string(), json!(load_factor));
                }
                if let Some(connected_since) = cluster_info.connected_since_unix {
                    cluster.insert("connected_since".to_string(), json!(connected_since));
                }
                if let Some(last_status) = cluster_info.last_status_unix {
                    cluster.insert("last_status".to_string(), json!(last_status));
                }
                if let Some(last_report) = cluster_info.last_report_unix {
                    cluster.insert("last_report".to_string(), json!(last_report));
                }
            }
            let mut out = json!({
                "address": peer.address,
                "cluster": Value::Object(cluster),
                "status": peer.status,
            });
            if let Some(inbound) = peer.inbound {
                out["inbound"] = json!(inbound);
            }
            if let Some(latency) = peer.latency {
                out["latency"] = json!(latency);
            }
            if let Some(ref ledger) = peer.ledger {
                out["ledger"] = json!(ledger);
            }
            if let Some(ref protocol) = peer.protocol {
                out["protocol"] = json!(protocol);
            }
            if let Some(ref public_key) = peer.public_key {
                out["public_key"] = json!(public_key);
            }
            if let Some(ref version) = peer.version {
                out["version"] = json!(version);
            }
            out
        })
        .collect();
    Ok(json!({ "peers": peers }))
}

pub fn peer_reservations_list(ctx: &NodeContext) -> Result<Value, RpcError> {
    let reservations = ctx
        .peer_reservations
        .as_ref()
        .ok_or_else(|| RpcError::internal("peer reservations unavailable"))?
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    Ok(json!({
        "reservations": reservations
            .iter()
            .map(|(public_key, description)| json!({
                "public_key": public_key,
                "description": description,
            }))
            .collect::<Vec<_>>()
    }))
}

fn persist_peer_reservations(
    ctx: &NodeContext,
    reservations: &std::collections::BTreeMap<String, String>,
) -> Result<(), RpcError> {
    if let Some(store) = ctx.storage.as_ref() {
        store
            .save_peer_reservations(reservations)
            .map_err(|_| RpcError::internal("failed to persist peer reservations"))?;
    }
    Ok(())
}

pub fn peer_reservations_add(params: &Value, ctx: &mut NodeContext) -> Result<Value, RpcError> {
    let public_key = crate::crypto::base58::encode(
        crate::crypto::base58::PREFIX_NODE_PUBLIC,
        &parse_public_key_bytes(params, "public_key")?,
    );
    let description = match params.get("description") {
        None => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err(invalid_field("description")),
    };
    let reservations = ctx
        .peer_reservations
        .as_ref()
        .ok_or_else(|| RpcError::internal("peer reservations unavailable"))?
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut updated = reservations.clone();
    let previous = updated.insert(public_key.clone(), description.clone());
    drop(reservations);
    persist_peer_reservations(ctx, &updated)?;
    *ctx.peer_reservations
        .as_ref()
        .unwrap()
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = updated;
    let mut result = json!({});
    if let Some(prev_description) = previous {
        result["previous"] = json!({
            "public_key": public_key,
            "description": prev_description,
        });
    }
    Ok(result)
}

pub fn peer_reservations_del(params: &Value, ctx: &mut NodeContext) -> Result<Value, RpcError> {
    let public_key = crate::crypto::base58::encode(
        crate::crypto::base58::PREFIX_NODE_PUBLIC,
        &parse_public_key_bytes(params, "public_key")?,
    );
    let reservations = ctx
        .peer_reservations
        .as_ref()
        .ok_or_else(|| RpcError::internal("peer reservations unavailable"))?
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut updated = reservations.clone();
    let previous = updated.remove(&public_key);
    drop(reservations);
    persist_peer_reservations(ctx, &updated)?;
    *ctx.peer_reservations
        .as_ref()
        .unwrap()
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = updated;
    let mut result = json!({});
    if let Some(prev_description) = previous {
        result["previous"] = json!({
            "public_key": public_key,
            "description": prev_description,
        });
    }
    Ok(result)
}

pub fn log_level(params: &Value) -> Result<Value, RpcError> {
    let severity = params.get("severity").and_then(Value::as_str);
    let partition = params.get("partition").and_then(Value::as_str);
    if let Some(severity) = severity {
        crate::rpc::set_log_level(partition, severity)
            .map_err(|_| RpcError::invalid_params("Invalid field 'severity'."))?;
        return Ok(json!({}));
    }

    let levels = crate::rpc::current_log_levels();
    let mut out = serde_json::Map::new();
    out.insert("base".to_string(), json!(levels.base));
    for (partition, severity) in levels.partitions {
        out.insert(partition, json!(severity));
    }
    Ok(json!({ "levels": out }))
}

pub fn logrotate(ctx: &NodeContext) -> Result<Value, RpcError> {
    let Some(debug_log) = ctx.debug_log.as_ref() else {
        return Ok(json!({ "rotated": false }));
    };
    let Some(debug_log_path) = ctx.debug_log_path.as_ref() else {
        return Ok(json!({ "rotated": false }));
    };

    let mut file_guard = debug_log.lock().unwrap_or_else(|e| e.into_inner());
    let mut path_guard = debug_log_path.lock().unwrap_or_else(|e| e.into_inner());
    let Some(current_path) = path_guard.clone() else {
        return Ok(json!({ "rotated": false }));
    };

    // Close the current handle before renaming so rotation works on all platforms.
    *file_guard = None;
    let rotated_path = current_path.with_extension(format!(
        "rotated-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    ));
    if current_path.exists() {
        std::fs::rename(&current_path, &rotated_path)
            .map_err(|_| RpcError::internal("logrotate rename failed"))?;
    }
    let new_file = std::fs::File::create(&current_path)
        .map_err(|_| RpcError::internal("logrotate reopen failed"))?;
    *file_guard = Some(new_file);
    *path_guard = Some(current_path.clone());

    Ok(json!({
        "rotated": true,
        "path": current_path.display().to_string(),
        "rotated_to": rotated_path.display().to_string(),
    }))
}

pub fn print(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let target = params
        .get("params")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_str);

    match target {
        Some("peers") => Ok(json!({ "peers": peers(ctx)?["peers"].clone() })),
        Some("fetch_info") => fetch_info(&json!({}), ctx),
        Some("consensus") => consensus_info(ctx),
        Some("validators") => validators(ctx),
        Some("load") => Ok(json!({
            "load": {
                "load_base": ctx.load_snapshot.load_base,
                "load_factor": ctx.load_snapshot.load_factor(),
                "load_factor_server": ctx.load_snapshot.load_factor_server(),
                "load_queue_overloaded": ctx.load_snapshot.queue_overloaded,
                "load_queue_depth": ctx.load_snapshot.queue_depth,
                "load_queue_capacity": ctx.load_snapshot.queue_capacity,
                "queued_transactions": ctx.load_snapshot.queued_transactions,
                "tracked_transactions": ctx.load_snapshot.tracked_transactions,
                "tracked_inbound_transactions": ctx.load_snapshot.tracked_inbound_transactions,
                "active_path_requests": ctx.load_snapshot.active_path_requests,
                "active_inbound_ledgers": ctx.load_snapshot.active_inbound_ledgers,
                "warning_count": ctx.load_snapshot.warning_count,
                "slow_operation_count": ctx.load_snapshot.slow_operation_count,
                "sync_stall_count": ctx.load_snapshot.sync_stall_count,
                "last_warning_reason": ctx.load_snapshot.last_warning_reason,
                "job_queue": {
                    "threads": ctx.load_snapshot.job_queue_threads,
                    "job_types": ctx.load_snapshot.queue_job_types.iter().map(|job| {
                        json!({
                            "job_type": job.job_type.clone(),
                            "waiting": job.waiting,
                            "in_progress": job.in_progress,
                            "over_target": job.over_target,
                        })
                    }).collect::<Vec<_>>(),
                },
            }
        })),
        Some("peerfinder") => {
            let snapshot = ctx
                .peerfinder_snapshot
                .as_ref()
                .cloned()
                .unwrap_or_else(|| crate::network::peerfinder::PeerfinderSnapshot {
                    total_known: 0,
                    fixed: 0,
                    with_successes: 0,
                    dialable: 0,
                    backed_off: 0,
                    retry_ready: 0,
                    ready: 0,
                    cooling: 0,
                    cold: 0,
                    redirects: 0,
                    distinct_sources: 0,
                    inbound_slots: 0,
                    outbound_slots: 0,
                    active_slots: 0,
                    reserved_slots: 0,
                    top: Vec::new(),
                });
            Ok(json!({
                "peerfinder": {
                    "total_known": snapshot.total_known,
                    "fixed": snapshot.fixed,
                    "with_successes": snapshot.with_successes,
                    "dialable": snapshot.dialable,
                    "backed_off": snapshot.backed_off,
                    "ready": snapshot.ready,
                    "cooling": snapshot.cooling,
                    "cold": snapshot.cold,
                    "distinct_sources": snapshot.distinct_sources,
                    "inbound_slots": snapshot.inbound_slots,
                    "outbound_slots": snapshot.outbound_slots,
                    "active_slots": snapshot.active_slots,
                    "reserved_slots": snapshot.reserved_slots,
                    "top": snapshot.top.into_iter().map(|entry| json!({
                        "address": entry.address.to_string(),
                        "source": entry.source,
                        "fixed": entry.fixed,
                        "success_count": entry.success_count,
                        "failure_count": entry.failure_count,
                        "last_seen_unix": entry.last_seen_unix,
                        "last_connected_unix": entry.last_connected_unix,
                        "next_attempt_unix": entry.next_attempt_unix,
                    })).collect::<Vec<_>>(),
                }
            }))
        }
        Some("cluster") => {
            let snapshot = ctx.cluster_snapshot.as_ref().cloned().unwrap_or_default();
            Ok(json!({
                "cluster": {
                    "configured": snapshot.configured,
                    "connected": snapshot.connected,
                    "max_reported_load_factor": snapshot.max_reported_load_factor,
                    "entries": snapshot.entries.into_iter().map(|entry| json!({
                        "address": entry.address,
                        "public_key": entry.public_key,
                        "tag": entry.tag,
                        "reserved": entry.reserved,
                        "loopback": entry.loopback,
                        "connected": entry.connected,
                        "status": entry.status,
                        "action": entry.action,
                        "ledger_index": entry.ledger_seq,
                        "ledger_index_min": entry.ledger_range.map(|range| range.0),
                        "ledger_index_max": entry.ledger_range.map(|range| range.1),
                        "load_factor": entry.load_factor,
                        "connected_since": entry.connected_since_unix,
                        "last_status": entry.last_status_unix,
                        "last_report": entry.last_report_unix,
                    })).collect::<Vec<_>>(),
                }
            }))
        }
        Some("resource_manager") => {
            let snapshot = ctx.resource_snapshot.as_ref().cloned().unwrap_or_default();
            Ok(json!({
                "resource_manager": {
                    "tracked": snapshot.tracked,
                    "tracked_ips": snapshot.tracked_ips,
                    "tracked_peers": snapshot.tracked_peers,
                    "blocked": snapshot.blocked,
                    "warned": snapshot.warned,
                    "ip_balance": snapshot.ip_balance,
                    "peer_balance": snapshot.peer_balance,
                    "total_balance": snapshot.total_balance,
                    "activity_cycles": snapshot.activity_cycles,
                    "last_activity_unix": snapshot.last_activity_unix,
                    "entries": snapshot.entries.into_iter().map(|entry| json!({
                        "address": entry.address,
                        "balance": entry.balance,
                        "warnings": entry.warnings,
                        "disconnects": entry.disconnects,
                        "last_reason": entry.last_reason,
                        "blocked_until_ms": entry.blocked_until_ms,
                    })).collect::<Vec<_>>(),
                }
            }))
        }
        Some("node_store") => {
            let snapshot = ctx
                .node_store_snapshot
                .as_ref()
                .cloned()
                .unwrap_or_default();
            Ok(json!({
                "node_store": {
                    "fetch_hits": snapshot.fetch_hits,
                    "fetch_missing": snapshot.fetch_missing,
                    "fetch_errors": snapshot.fetch_errors,
                    "store_ops": snapshot.store_ops,
                    "store_unchecked_ops": snapshot.store_unchecked_ops,
                    "batch_store_ops": snapshot.batch_store_ops,
                    "batch_store_nodes": snapshot.batch_store_nodes,
                    "flush_ops": snapshot.flush_ops,
                    "last_flush_unix": snapshot.last_flush_unix,
                    "last_flush_duration_ms": snapshot.last_flush_duration_ms,
                    "last_error": snapshot.last_error,
                }
            }))
        }
        Some("fetch_pack") => {
            let snapshot = ctx
                .fetch_pack_snapshot
                .as_ref()
                .cloned()
                .unwrap_or_default();
            Ok(json!({
                "fetch_pack": {
                    "tracked": snapshot.tracked,
                    "stashed_total": snapshot.stashed_total,
                    "backend_fill_total": snapshot.backend_fill_total,
                    "imported_total": snapshot.imported_total,
                    "persisted_total": snapshot.persisted_total,
                    "persist_errors_total": snapshot.persist_errors_total,
                    "unchecked_fallbacks_total": snapshot.unchecked_fallbacks_total,
                    "reused_total": snapshot.reused_total,
                    "evicted_total": snapshot.evicted_total,
                    "last_import_error": snapshot.last_import_error,
                    "flush_ops": snapshot.flush_ops,
                    "last_flush_unix": snapshot.last_flush_unix,
                    "last_flush_duration_ms": snapshot.last_flush_duration_ms,
                    "last_flush_error": snapshot.last_flush_error,
                    "entries": snapshot.entries.into_iter().map(|entry| json!({
                        "hash": entry.hash,
                        "size": entry.size,
                        "first_stashed_unix": entry.first_stashed_unix,
                        "last_stashed_unix": entry.last_stashed_unix,
                        "reuse_hits": entry.reuse_hits,
                    })).collect::<Vec<_>>(),
                }
            }))
        }
        Some("path_requests") => {
            let snapshot = ctx
                .path_request_snapshot
                .as_ref()
                .cloned()
                .unwrap_or_default();
            Ok(json!({
                "path_requests": {
                    "active_requests": snapshot.active_requests,
                    "last_recompute_unix": snapshot.last_recompute_unix,
                    "entries": snapshot.entries.into_iter().map(|entry| json!({
                        "client_id": entry.client_id,
                        "source_account": entry.source_account,
                        "destination_account": entry.destination_account,
                        "destination_amount": entry.destination_amount,
                        "created_unix": entry.created_unix,
                        "updated_unix": entry.updated_unix,
                        "update_count": entry.update_count,
                        "last_status": entry.last_status,
                    })).collect::<Vec<_>>(),
                }
            }))
        }
        Some("inbound_transactions") => {
            let snapshot = ctx
                .inbound_transactions_snapshot
                .as_ref()
                .cloned()
                .unwrap_or_default();
            Ok(json!({
                "inbound_transactions": {
                    "tracked": snapshot.tracked,
                    "accepted_total": snapshot.accepted_total,
                    "duplicate_total": snapshot.duplicate_total,
                    "relayed_total": snapshot.relayed_total,
                    "persisted_total": snapshot.persisted_total,
                    "entries": snapshot.entries.into_iter().map(|entry| json!({
                        "hash": entry.hash,
                        "size": entry.size,
                        "first_seen_unix": entry.first_seen_unix,
                        "last_seen_unix": entry.last_seen_unix,
                        "first_source": entry.first_source,
                        "last_source": entry.last_source,
                        "seen_count": entry.seen_count,
                        "relayed_count": entry.relayed_count,
                        "persisted": entry.persisted,
                    })).collect::<Vec<_>>(),
                }
            }))
        }
        Some("inbound_ledgers") => {
            let snapshot = ctx
                .inbound_ledgers_snapshot
                .as_ref()
                .cloned()
                .unwrap_or_default();
            Ok(json!({
                "inbound_ledgers": {
                    "active": snapshot.active,
                    "complete": snapshot.complete,
                    "failed": snapshot.failed,
                    "retry_ready": snapshot.retry_ready,
                    "stale": snapshot.stale,
                    "fetch_rate": snapshot.fetch_rate,
                    "fetched_total": snapshot.fetched_total,
                    "fetch_pack_hits": snapshot.fetch_pack_hits,
                    "cache_size": snapshot.cache_size,
                    "sweep_total": snapshot.sweep_total,
                    "last_sweep_removed": snapshot.last_sweep_removed,
                    "last_sweep_unix": snapshot.last_sweep_unix,
                    "stop_total": snapshot.stop_total,
                    "last_stop_unix": snapshot.last_stop_unix,
                    "cached_seq_hashes": snapshot.cached_seq_hashes,
                    "cached_seq_headers": snapshot.cached_seq_headers,
                    "recent_failures": snapshot.recent_failures,
                    "history": snapshot.history,
                    "generic": snapshot.generic,
                    "consensus": snapshot.consensus,
                    "entries": snapshot.entries.into_iter().map(|entry| json!({
                        "ledger_hash": entry.ledger_hash,
                        "ledger_seq": entry.ledger_seq,
                        "reason": entry.reason,
                        "has_header": entry.has_header,
                        "has_transactions": entry.has_transactions,
                        "complete": entry.complete,
                        "failed": entry.failed,
                        "timeout_count": entry.timeout_count,
                        "age_ms": entry.age_ms,
                        "idle_ms": entry.idle_ms,
                    })).collect::<Vec<_>>(),
                }
            }))
        }
        Some("network_ops") => {
            let snapshot = ctx
                .network_ops_snapshot
                .as_ref()
                .cloned()
                .unwrap_or_default();
            let mut network_ops = serde_json::Map::new();
            network_ops.insert("server_state".into(), json!(snapshot.server_state));
            network_ops.insert("peer_count".into(), json!(snapshot.peer_count));
            network_ops.insert("object_count".into(), json!(snapshot.object_count));
            network_ops.insert("known_peers".into(), json!(snapshot.known_peers));
            network_ops.insert("dialable_peers".into(), json!(snapshot.dialable_peers));
            network_ops.insert("backed_off_peers".into(), json!(snapshot.backed_off_peers));
            network_ops.insert(
                "peerfinder_retry_ready".into(),
                json!(snapshot.peerfinder_retry_ready),
            );
            network_ops.insert("peerfinder_ready".into(), json!(snapshot.peerfinder_ready));
            network_ops.insert(
                "peerfinder_cooling".into(),
                json!(snapshot.peerfinder_cooling),
            );
            network_ops.insert("peerfinder_cold".into(), json!(snapshot.peerfinder_cold));
            network_ops.insert(
                "peerfinder_sources".into(),
                json!(snapshot.peerfinder_sources),
            );
            network_ops.insert(
                "cluster_configured".into(),
                json!(snapshot.cluster_configured),
            );
            network_ops.insert("cluster_observed".into(), json!(snapshot.cluster_observed));
            network_ops.insert(
                "cluster_connected".into(),
                json!(snapshot.cluster_connected),
            );
            network_ops.insert("blocked_peers".into(), json!(snapshot.blocked_peers));
            network_ops.insert("warned_peers".into(), json!(snapshot.warned_peers));
            network_ops.insert("resource_tracked".into(), json!(snapshot.resource_tracked));
            network_ops.insert(
                "resource_ip_balance".into(),
                json!(snapshot.resource_ip_balance),
            );
            network_ops.insert(
                "resource_peer_balance".into(),
                json!(snapshot.resource_peer_balance),
            );
            network_ops.insert("resource_balance".into(), json!(snapshot.resource_balance));
            network_ops.insert(
                "resource_warning_events".into(),
                json!(snapshot.resource_warning_events),
            );
            network_ops.insert(
                "resource_disconnect_events".into(),
                json!(snapshot.resource_disconnect_events),
            );
            network_ops.insert(
                "node_store_fetch_errors".into(),
                json!(snapshot.node_store_fetch_errors),
            );
            network_ops.insert("node_store_flush_ops".into(), json!(snapshot.node_store_flush_ops));
            network_ops.insert(
                "node_store_last_flush_unix".into(),
                json!(snapshot.node_store_last_flush_unix),
            );
            network_ops.insert(
                "node_store_last_flush_duration_ms".into(),
                json!(snapshot.node_store_last_flush_duration_ms),
            );
            network_ops.insert("fetch_pack_entries".into(), json!(snapshot.fetch_pack_entries));
            network_ops.insert(
                "fetch_pack_backend_fill_total".into(),
                json!(snapshot.fetch_pack_backend_fill_total),
            );
            network_ops.insert(
                "fetch_pack_reused_total".into(),
                json!(snapshot.fetch_pack_reused_total),
            );
            network_ops.insert(
                "fetch_pack_persisted_total".into(),
                json!(snapshot.fetch_pack_persisted_total),
            );
            network_ops.insert(
                "fetch_pack_persist_errors_total".into(),
                json!(snapshot.fetch_pack_persist_errors_total),
            );
            network_ops.insert("fetch_pack_flush_ops".into(), json!(snapshot.fetch_pack_flush_ops));
            network_ops.insert(
                "fetch_pack_last_flush_unix".into(),
                json!(snapshot.fetch_pack_last_flush_unix),
            );
            network_ops.insert(
                "fetch_pack_last_flush_duration_ms".into(),
                json!(snapshot.fetch_pack_last_flush_duration_ms),
            );
            network_ops.insert(
                "tracked_inbound_ledgers".into(),
                json!(snapshot.tracked_inbound_ledgers),
            );
            network_ops.insert(
                "failed_inbound_ledgers".into(),
                json!(snapshot.failed_inbound_ledgers),
            );
            network_ops.insert(
                "queued_transactions".into(),
                json!(snapshot.queued_transactions),
            );
            network_ops.insert(
                "tracked_transactions".into(),
                json!(snapshot.tracked_transactions),
            );
            network_ops.insert(
                "submitted_transactions".into(),
                json!(snapshot.submitted_transactions),
            );
            network_ops.insert(
                "active_path_requests".into(),
                json!(snapshot.active_path_requests),
            );
            network_ops.insert(
                "tracked_inbound_transactions".into(),
                json!(snapshot.tracked_inbound_transactions),
            );
            network_ops.insert("load_factor".into(), json!(snapshot.load_factor));
            network_ops.insert("load_queue_depth".into(), json!(snapshot.load_queue_depth));
            network_ops.insert(
                "load_queue_capacity".into(),
                json!(snapshot.load_queue_capacity),
            );
            network_ops.insert(
                "load_queue_overloaded".into(),
                json!(snapshot.load_queue_overloaded),
            );
            Ok(json!({ "network_ops": network_ops }))
        }
        Some("tx_master") => {
            let snapshot = ctx.tx_master_snapshot.as_ref().cloned().unwrap_or_default();
            Ok(json!({
                "tx_master": {
                    "tracked": snapshot.tracked,
                    "proposed_total": snapshot.proposed_total,
                    "submitted_total": snapshot.submitted_total,
                    "buffered_total": snapshot.buffered_total,
                    "accepted_total": snapshot.accepted_total,
                    "validated_total": snapshot.validated_total,
                    "relayed_total": snapshot.relayed_total,
                    "entries": snapshot.entries.into_iter().map(|entry| json!({
                        "hash": entry.hash,
                        "status": entry.status,
                        "size": entry.size,
                        "first_seen_unix": entry.first_seen_unix,
                        "updated_unix": entry.updated_unix,
                        "source": entry.source,
                        "ledger_seq": entry.ledger_seq,
                        "result": entry.result,
                        "relayed_count": entry.relayed_count,
                    })).collect::<Vec<_>>(),
                }
            }))
        }
        Some("ledger_master") => {
            let snapshot = ctx
                .ledger_master_snapshot
                .as_ref()
                .cloned()
                .unwrap_or_default();
            Ok(json!({
                "ledger_master": {
                    "validated_seq": snapshot.validated_seq,
                    "validated_hash": snapshot.validated_hash,
                    "open_ledger_seq": snapshot.open_ledger_seq,
                    "complete_ledgers": snapshot.complete_ledgers,
                    "last_close_time": snapshot.last_close_time,
                    "queued_transactions": snapshot.queued_transactions,
                    "candidate_set_hash": snapshot.candidate_set_hash,
                    "recent_validated": snapshot.recent_validated.into_iter().map(|entry| json!({
                        "seq": entry.seq,
                        "hash": entry.hash,
                    })).collect::<Vec<_>>(),
                }
            }))
        }
        Some("ledger_cleaner") => {
            let snapshot = ctx
                .ledger_cleaner_snapshot
                .as_ref()
                .cloned()
                .unwrap_or_default();
            Ok(json!({
                "ledger_cleaner": {
                    "state": snapshot.state,
                    "online_delete": snapshot.online_delete,
                    "pending": snapshot.pending,
                    "min_ledger": snapshot.min_ledger,
                    "max_ledger": snapshot.max_ledger,
                    "full": snapshot.full,
                    "fix_txns": snapshot.fix_txns,
                    "check_nodes": snapshot.check_nodes,
                    "stop_requested": snapshot.stop_requested,
                    "last_message": snapshot.last_message,
                    "last_run_started_unix": snapshot.last_run_started_unix,
                    "last_run_finished_unix": snapshot.last_run_finished_unix,
                    "history_pruned": snapshot.history_pruned,
                    "failures": snapshot.failures,
                }
            }))
        }
        Some("open_ledger") => {
            let snapshot = ctx
                .open_ledger_snapshot
                .as_ref()
                .cloned()
                .unwrap_or_default();
            Ok(json!({
                "open_ledger": {
                    "ledger_current_index": snapshot.ledger_current_index,
                    "parent_ledger_index": snapshot.parent_ledger_index,
                    "parent_hash": snapshot.parent_hash,
                    "last_close_time": snapshot.last_close_time,
                    "queued_transactions": snapshot.queued_transactions,
                "candidate_set_hash": snapshot.candidate_set_hash,
                "escalation_multiplier": snapshot.escalation_multiplier,
                "txns_expected": snapshot.txns_expected,
                "max_queue_size": snapshot.max_queue_size,
                "open_fee_level": snapshot.open_fee_level,
                "revision": snapshot.revision,
                "modify_count": snapshot.modify_count,
                "accept_count": snapshot.accept_count,
                "last_modified_unix": snapshot.last_modified_unix,
                "last_accept_unix": snapshot.last_accept_unix,
                "has_open_view": snapshot.has_open_view,
                "open_view_base_ledger_index": snapshot.open_view_base_ledger_index,
                "open_view_applied_transactions": snapshot.open_view_applied_transactions,
                "open_view_failed_transactions": snapshot.open_view_failed_transactions,
                "open_view_skipped_transactions": snapshot.open_view_skipped_transactions,
                "open_view_tx_count": snapshot.open_view_tx_count,
                "open_view_state_hash": snapshot.open_view_state_hash,
                "open_view_tx_hash": snapshot.open_view_tx_hash,
                }
            }))
        }
        Some("server") | None => {
            let ops = ctx
                .network_ops_snapshot
                .as_ref()
                .cloned()
                .unwrap_or_else(|| crate::network::ops::NetworkOpsSnapshot::from_context(ctx));
            let mut server = serde_json::Map::new();
            server.insert("network".into(), json!(ctx.network));
            server.insert("network_id".into(), json!(ctx.network_id));
            server.insert("build_version".into(), json!(ctx.build_version));
            server.insert("ledger_seq".into(), json!(ctx.ledger_seq));
            server.insert("ledger_hash".into(), json!(ctx.ledger_hash));
            server.insert("server_state".into(), json!(ops.server_state));
            server.insert("peer_count".into(), json!(ops.peer_count));
            server.insert("object_count".into(), json!(ops.object_count));
            server.insert("admin_rpc_enabled".into(), json!(ctx.admin_rpc_enabled));
            server.insert("load_factor".into(), json!(ops.load_factor));
            server.insert("load_queue_depth".into(), json!(ops.load_queue_depth));
            server.insert("load_queue_capacity".into(), json!(ops.load_queue_capacity));
            server.insert(
                "load_queue_overloaded".into(),
                json!(ops.load_queue_overloaded),
            );
            server.insert("known_peers".into(), json!(ops.known_peers));
            server.insert("dialable_peers".into(), json!(ops.dialable_peers));
            server.insert("backed_off_peers".into(), json!(ops.backed_off_peers));
            server.insert(
                "peerfinder_retry_ready".into(),
                json!(ops.peerfinder_retry_ready),
            );
            server.insert("peerfinder_ready".into(), json!(ops.peerfinder_ready));
            server.insert("peerfinder_cooling".into(), json!(ops.peerfinder_cooling));
            server.insert("peerfinder_cold".into(), json!(ops.peerfinder_cold));
            server.insert("peerfinder_sources".into(), json!(ops.peerfinder_sources));
            server.insert("cluster_configured".into(), json!(ops.cluster_configured));
            server.insert("cluster_observed".into(), json!(ops.cluster_observed));
            server.insert("cluster_connected".into(), json!(ops.cluster_connected));
            server.insert("blocked_peers".into(), json!(ops.blocked_peers));
            server.insert("warned_peers".into(), json!(ops.warned_peers));
            server.insert("resource_tracked".into(), json!(ops.resource_tracked));
            server.insert("resource_ip_balance".into(), json!(ops.resource_ip_balance));
            server.insert("resource_peer_balance".into(), json!(ops.resource_peer_balance));
            server.insert("resource_balance".into(), json!(ops.resource_balance));
            server.insert(
                "resource_warning_events".into(),
                json!(ops.resource_warning_events),
            );
            server.insert(
                "resource_disconnect_events".into(),
                json!(ops.resource_disconnect_events),
            );
            if let Some(snapshot) = ctx.state_accounting_snapshot.as_ref() {
                server.insert(
                    "state_accounting".into(),
                    json!({
                        "disconnected": {
                            "transitions": snapshot.disconnected.transitions.to_string(),
                            "duration_us": snapshot.disconnected.duration_us.to_string(),
                        },
                        "connected": {
                            "transitions": snapshot.connected.transitions.to_string(),
                            "duration_us": snapshot.connected.duration_us.to_string(),
                        },
                        "syncing": {
                            "transitions": snapshot.syncing.transitions.to_string(),
                            "duration_us": snapshot.syncing.duration_us.to_string(),
                        },
                        "tracking": {
                            "transitions": snapshot.tracking.transitions.to_string(),
                            "duration_us": snapshot.tracking.duration_us.to_string(),
                        },
                        "full": {
                            "transitions": snapshot.full.transitions.to_string(),
                            "duration_us": snapshot.full.duration_us.to_string(),
                        },
                    }),
                );
                server.insert(
                    "server_state_duration_us".into(),
                    json!(snapshot.server_state_duration_us.to_string()),
                );
                if let Some(initial_sync_duration_us) = snapshot.initial_sync_duration_us {
                    server.insert(
                        "initial_sync_duration_us".into(),
                        json!(initial_sync_duration_us.to_string()),
                    );
                }
            }
            server.insert(
                "tracked_inbound_ledgers".into(),
                json!(ops.tracked_inbound_ledgers),
            );
            server.insert(
                "failed_inbound_ledgers".into(),
                json!(ops.failed_inbound_ledgers),
            );
            server.insert("node_store_fetch_errors".into(), json!(ops.node_store_fetch_errors));
            server.insert("node_store_flush_ops".into(), json!(ops.node_store_flush_ops));
            server.insert(
                "node_store_last_flush_unix".into(),
                json!(ops.node_store_last_flush_unix),
            );
            server.insert(
                "node_store_last_flush_duration_ms".into(),
                json!(ops.node_store_last_flush_duration_ms),
            );
            server.insert("fetch_pack_entries".into(), json!(ops.fetch_pack_entries));
            server.insert(
                "fetch_pack_backend_fill_total".into(),
                json!(ops.fetch_pack_backend_fill_total),
            );
            server.insert("fetch_pack_reused_total".into(), json!(ops.fetch_pack_reused_total));
            server.insert(
                "fetch_pack_persisted_total".into(),
                json!(ops.fetch_pack_persisted_total),
            );
            server.insert(
                "fetch_pack_persist_errors_total".into(),
                json!(ops.fetch_pack_persist_errors_total),
            );
            server.insert("fetch_pack_flush_ops".into(), json!(ops.fetch_pack_flush_ops));
            server.insert(
                "fetch_pack_last_flush_unix".into(),
                json!(ops.fetch_pack_last_flush_unix),
            );
            server.insert(
                "fetch_pack_last_flush_duration_ms".into(),
                json!(ops.fetch_pack_last_flush_duration_ms),
            );
            server.insert("queued_transactions".into(), json!(ops.queued_transactions));
            server.insert("tracked_transactions".into(), json!(ops.tracked_transactions));
            server.insert("submitted_transactions".into(), json!(ops.submitted_transactions));
            server.insert("active_path_requests".into(), json!(ops.active_path_requests));
            server.insert(
                "tracked_inbound_transactions".into(),
                json!(ops.tracked_inbound_transactions),
            );
            Ok(json!({ "server": Value::Object(server) }))
        }
        Some(other) => Err(RpcError::invalid_params(&format!(
            "Unsupported print target '{other}'."
        ))),
    }
}

fn encode_validator_display(raw: &[u8]) -> String {
    if raw.len() == 33 {
        crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, raw)
    } else {
        hex::encode_upper(raw)
    }
}

fn encode_validator_hex_or_display(value: &str) -> String {
    hex::decode(value)
        .map(|raw| encode_validator_display(&raw))
        .unwrap_or_else(|_| value.to_string())
}

fn manifest_response_for_key(
    ctx: &NodeContext,
    public_key: &str,
) -> Option<(String, serde_json::Map<String, Value>)> {
    let (_, payload) = crate::crypto::base58::decode(public_key).ok()?;
    if payload.len() != 33 {
        return None;
    }

    if let Some(cache) = ctx.manifest_cache.as_ref() {
        let cache = cache.lock().unwrap_or_else(|e| e.into_inner());
        let master = cache.master_key(&payload);
        if let Some(ephemeral) = cache.signing_key_for_master(&master) {
            let mut details = serde_json::Map::new();
            details.insert(
                "master_key".to_string(),
                json!(crate::crypto::base58::encode(
                    crate::crypto::base58::PREFIX_NODE_PUBLIC,
                    &master
                )),
            );
            details.insert(
                "ephemeral_key".to_string(),
                json!(crate::crypto::base58::encode(
                    crate::crypto::base58::PREFIX_NODE_PUBLIC,
                    &ephemeral
                )),
            );
            if let Some(seq) = cache.sequence_for_master(&master) {
                details.insert("seq".to_string(), json!(seq));
            }
            if let Some(domain) = cache.domain_for_master(&master) {
                details.insert("domain".to_string(), json!(domain));
            }
            return Some((
                cache
                    .manifest_for_master(&master)
                    .map(|manifest| base64::engine::general_purpose::STANDARD.encode(manifest))
                    .unwrap_or_default(),
                details,
            ));
        }
    }

    let manager = ctx.validator_list_manager.as_ref()?;
    let manifest = manager
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .manifest_for_public_key(public_key)?;
    let mut details = serde_json::Map::new();
    details.insert(
        "master_key".to_string(),
        json!(encode_validator_hex_or_display(&manifest.master_key)),
    );
    details.insert(
        "ephemeral_key".to_string(),
        json!(encode_validator_hex_or_display(&manifest.signing_key)),
    );
    details.insert("seq".to_string(), json!(manifest.sequence));
    if let Some(domain) = manifest.domain {
        details.insert("domain".to_string(), json!(domain));
    }
    Some((manifest.raw_manifest, details))
}

pub fn validator_info(ctx: &NodeContext) -> Result<Value, RpcError> {
    if ctx.validator_key.is_empty() {
        return Err(RpcError::invalid_params(
            "This server is not configured as a validator.",
        ));
    }
    let mut info = serde_json::Map::new();
    if let Some((manifest, details)) = manifest_response_for_key(ctx, &ctx.validator_key) {
        if let Some(value) = details.get("master_key").cloned() {
            info.insert("master_key".to_string(), value);
        }
        if let Some(value) = details.get("ephemeral_key").cloned() {
            info.insert("ephemeral_key".to_string(), value);
        }
        if !manifest.is_empty() {
            info.insert("manifest".to_string(), json!(manifest));
        }
        if let Some(value) = details.get("seq").cloned() {
            info.insert("seq".to_string(), value);
        }
        if let Some(value) = details.get("domain").cloned() {
            info.insert("domain".to_string(), value);
        }
    } else {
        info.insert("master_key".to_string(), json!(ctx.validator_key.clone()));
    }
    Ok(json!(Value::Object(info)))
}

pub fn validator_list_sites(ctx: &NodeContext) -> Result<Value, RpcError> {
    let mut statuses: Vec<_> = ctx
        .validator_site_statuses
        .as_ref()
        .map(|sites| {
            sites
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if statuses.is_empty() {
        statuses = ctx
            .validator_list_sites
            .iter()
            .map(|site| crate::validator_list::ValidatorSiteStatus {
                uri: site.clone(),
                last_refresh_status: None,
                last_refresh_time: None,
                last_refresh_message: None,
                next_refresh_time: None,
                refresh_interval_secs: 5 * 60,
            })
            .collect();
    }

    statuses.sort_by(|a, b| a.uri.cmp(&b.uri));

    Ok(json!({
        "validator_sites": statuses
            .into_iter()
            .map(|site| {
                let mut entry = serde_json::Map::new();
                entry.insert("uri".to_string(), json!(site.uri));
                entry.insert(
                    "refresh_interval_min".to_string(),
                    json!(site.refresh_interval_secs / 60),
                );
                if let Some(status) = site.last_refresh_status {
                    entry.insert("last_refresh_status".to_string(), json!(status));
                }
                if let Some(time) = site.last_refresh_time {
                    entry.insert("last_refresh_time".to_string(), json!(human_time_string(time)));
                }
                if let Some(message) = site.last_refresh_message {
                    entry.insert("last_refresh_message".to_string(), json!(message));
                }
                if let Some(time) = site.next_refresh_time {
                    entry.insert("next_refresh_time".to_string(), json!(human_time_string(time)));
                }
                Value::Object(entry)
            })
            .collect::<Vec<_>>()
    }))
}

pub fn validators(ctx: &NodeContext) -> Result<Value, RpcError> {
    let manager = ctx
        .validator_list_manager
        .as_ref()
        .ok_or_else(|| RpcError::internal("validator list manager unavailable"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let snapshot = manager.lock().unwrap_or_else(|e| e.into_inner()).snapshot(now);

    let local_static_keys: Vec<String> = snapshot
        .static_validators
        .iter()
        .map(|raw| encode_validator_display(raw))
        .collect();
    let publisher_list_count = snapshot.publisher_lists.len();
    let validator_list_status = if snapshot.publisher_lists.iter().any(|list| list.available) {
        "active"
    } else if snapshot.publisher_lists.is_empty() && !snapshot.static_validators.is_empty() {
        "static"
    } else if snapshot.publisher_lists.iter().any(|list| {
        list.current
            .as_ref()
            .and_then(|current| current.expiration)
            .is_some_and(|expiration| expiration <= now)
    }) {
        "expired"
    } else {
        "unknown"
    };
    let has_non_expiring_current = snapshot.publisher_lists.iter().any(|list| {
        list.current
            .as_ref()
            .is_some_and(|current| current.expiration.is_none())
    });
    let validator_list_expires = snapshot
        .publisher_lists
        .iter()
        .filter_map(|list| list.current.as_ref().and_then(|current| current.expiration))
        .min()
        .map(human_time_string)
        .unwrap_or_else(|| {
            if snapshot.publisher_lists.is_empty() && !snapshot.static_validators.is_empty() {
                "never".to_string()
            } else if has_non_expiring_current {
                "never".to_string()
            } else {
                "unknown".to_string()
            }
        });
    let publisher_lists: Vec<Value> = snapshot
        .publisher_lists
        .iter()
        .map(|list| {
            let mut entry = serde_json::Map::new();
            entry.insert("available".to_string(), json!(list.available));
            entry.insert(
                "pubkey_publisher".to_string(),
                json!(list.publisher_key.clone()),
            );

            if let Some(current) = list.current.as_ref() {
                entry.insert(
                    "expiration".to_string(),
                    json!(
                        current
                            .expiration
                            .map(human_time_string)
                            .unwrap_or_else(|| "never".to_string())
                    ),
                );
                entry.insert("seq".to_string(), json!(current.sequence));
                entry.insert("version".to_string(), json!(1));
                entry.insert(
                    "list".to_string(),
                    json!(
                        current
                            .validators
                            .iter()
                            .map(|key| encode_validator_hex_or_display(key))
                            .collect::<Vec<_>>()
                    ),
                );
                if let Some(effective) = current.effective {
                    entry.insert("effective".to_string(), json!(human_time_string(effective)));
                }
            }

            if !list.remaining.is_empty() {
                entry.insert(
                    "remaining".to_string(),
                    Value::Array(
                        list.remaining
                            .iter()
                            .map(|remaining| {
                                let mut pending = serde_json::Map::new();
                                pending.insert("seq".to_string(), json!(remaining.sequence));
                                pending.insert("version".to_string(), json!(1));
                                pending.insert(
                                    "expiration".to_string(),
                                    json!(
                                        remaining
                                            .expiration
                                            .map(human_time_string)
                                            .unwrap_or_else(|| "never".to_string())
                                    ),
                                );
                                pending.insert(
                                    "list".to_string(),
                                    json!(
                                        remaining
                                            .validators
                                            .iter()
                                            .map(|key| encode_validator_hex_or_display(key))
                                            .collect::<Vec<_>>()
                                    ),
                                );
                                if let Some(effective) = remaining.effective {
                                    pending.insert(
                                        "effective".to_string(),
                                        json!(human_time_string(effective)),
                                    );
                                }
                                Value::Object(pending)
                            })
                            .collect(),
                    ),
                );
            }

            Value::Object(entry)
        })
        .collect();
    let trusted_validator_keys: Vec<String> = snapshot
        .effective_unl
        .iter()
        .map(|raw| encode_validator_display(raw))
        .collect();
    let validation_quorum = snapshot.validation_quorum;
    let mut signing_keys = std::collections::BTreeMap::<String, Value>::new();
    for publisher in &snapshot.publisher_lists {
        for manifest in publisher
            .current
            .iter()
            .filter_map(|current| current.manifest.as_ref())
            .chain(
                publisher
                    .remaining
                    .iter()
                    .filter_map(|remaining| remaining.manifest.as_ref()),
            )
        {
            signing_keys.insert(
                encode_validator_hex_or_display(&manifest.master_key),
                json!(encode_validator_hex_or_display(&manifest.signing_key)),
            );
        }
    }
    if let Some(cache) = ctx.manifest_cache.as_ref() {
        for (master, signing) in cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .signing_key_mappings()
        {
            signing_keys.insert(
                crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, &master),
                json!(crate::crypto::base58::encode(
                    crate::crypto::base58::PREFIX_NODE_PUBLIC,
                    &signing
                )),
            );
        }
    }

    Ok(json!({
        "listed_static_keys": local_static_keys.clone(),
        "local_static_keys": local_static_keys,
        "publisher_lists": publisher_lists,
        "signing_keys": signing_keys,
        "trusted_validator_keys": trusted_validator_keys,
        "validation_quorum": validation_quorum,
        "validator_list_expires": validator_list_expires,
        "validator_list": {
            "count": publisher_list_count,
            "expiration": validator_list_expires,
            "status": validator_list_status,
            "validator_list_threshold": snapshot.threshold,
        },
    }))
}

pub fn unl_list(ctx: &NodeContext) -> Result<Value, RpcError> {
    use std::collections::{BTreeMap, HashSet};

    let Some(manager) = ctx.validator_list_manager.as_ref() else {
        return Ok(json!({ "unl": [] }));
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let snapshot = manager
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .snapshot(now);

    let trusted: HashSet<String> = snapshot
        .effective_unl
        .iter()
        .map(|pk| crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, pk))
        .collect();

    let mut listed: BTreeMap<String, bool> = BTreeMap::new();
    for pk in &snapshot.static_validators {
        let b58 = crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, pk);
        listed.insert(b58.clone(), trusted.contains(&b58));
    }
    for publisher in &snapshot.publisher_lists {
        for validator_hex in publisher
            .current
            .iter()
            .flat_map(|current| current.validators.iter())
            .chain(
                publisher
                    .remaining
                    .iter()
                    .flat_map(|remaining| remaining.validators.iter()),
            )
        {
            let Ok(bytes) = hex::decode(validator_hex) else {
                continue;
            };
            let b58 =
                crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, &bytes);
            listed
                .entry(b58.clone())
                .and_modify(|v| *v |= trusted.contains(&b58))
                .or_insert_with(|| trusted.contains(&b58));
        }
    }

    Ok(json!({
        "unl": listed.into_iter().map(|(pubkey, trusted)| json!({
            "pubkey_validator": pubkey,
            "trusted": trusted,
        })).collect::<Vec<_>>()
    }))
}

pub fn consensus_info(ctx: &NodeContext) -> Result<Value, RpcError> {
    let info = if let Some(snapshot) = &ctx.consensus_info {
        json!({
            "consensus": snapshot.consensus,
            "converge_percent": snapshot.converge_percent,
            "elapsed_ms": snapshot.elapsed_ms,
            "ledger_seq": snapshot.ledger_seq,
            "mode": snapshot.mode,
            "phase": snapshot.phase,
            "previous_ledger": snapshot.previous_ledger,
            "proposers": snapshot.proposers,
            "validations": snapshot.validations,
            "disputes": snapshot.disputes,
            "quorum": snapshot.quorum,
            "our_position": snapshot.our_position,
        })
    } else {
        json!({
            "consensus": "idle",
            "converge_percent": 0,
            "elapsed_ms": 0,
            "ledger_seq": ctx.ledger_seq + 1,
            "mode": "observing",
            "phase": "idle",
            "proposers": 0,
            "validations": 0,
            "disputes": 0,
            "quorum": 0,
        })
    };
    Ok(json!({ "info": info }))
}

pub fn can_delete(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let target = ctx
        .can_delete_target
        .as_ref()
        .ok_or_else(|| RpcError::internal("can_delete target unavailable"))?;

    if let Some(value) = params.get("can_delete") {
        let parsed = match value {
            Value::String(s) if s.eq_ignore_ascii_case("never") => 0,
            Value::String(s) if s.eq_ignore_ascii_case("always") => u32::MAX,
            Value::String(s) if s.eq_ignore_ascii_case("now") => {
                if ctx.ledger_seq == 0 {
                    return Err(RpcError::internal("can_delete=now is not ready yet"));
                }
                ctx.ledger_seq
            }
            Value::String(s) => {
                if let Ok(sequence) = s.parse::<u32>() {
                    sequence
                } else {
                    let bytes = hex::decode(s).map_err(|_| invalid_field("can_delete"))?;
                    if bytes.len() != 32 {
                        return Err(invalid_field("can_delete"));
                    }
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&bytes);
                    if hash == ctx.ledger_header.hash {
                        ctx.ledger_seq
                    } else {
                        ctx.history
                            .read()
                            .unwrap_or_else(|e| e.into_inner())
                            .get_ledger_by_hash(&hash)
                            .map(|record| record.header.sequence)
                            .ok_or_else(lgr_not_found)?
                    }
                }
            }
            Value::Number(n) => n
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| invalid_field("can_delete"))?,
            _ => return Err(invalid_field("can_delete")),
        };
        target.store(parsed, std::sync::atomic::Ordering::SeqCst);
    }

    let current = target.load(std::sync::atomic::Ordering::SeqCst);
    let value = match current {
        0 => json!("never"),
        u32::MAX => json!("always"),
        seq => json!(seq),
    };
    Ok(json!({
        "can_delete": value,
        "online_delete": ctx.online_delete,
    }))
}

pub fn blacklist(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let threshold = params
        .get("threshold")
        .map(|value| parse_u64_like(value, "threshold"))
        .transpose()?
        .unwrap_or(0);

    let entries: Vec<Value> = ctx
        .blacklist_entries
        .iter()
        .filter(|entry| entry.expires_in_ms >= threshold)
        .map(|entry| {
            json!({
                "address": entry.address,
                "reason": entry.reason,
                "expires_in_ms": entry.expires_in_ms,
            })
        })
        .collect();

    Ok(json!({
        "blacklist": entries,
        "count": entries.len(),
    }))
}

pub fn ledger_accept(ctx: &NodeContext) -> Result<Value, RpcError> {
    if !ctx.standalone_mode {
        return Err(RpcError {
            code: "notStandAlone",
            error_code: 0,
            message: "Node is not running in standalone mode.".into(),
            extra: None,
        });
    }

    if let Some(service) = ctx.ledger_accept_service.as_ref() {
        let receiver = service.request();
        let ledger_current_index = receiver.recv_timeout(std::time::Duration::from_secs(15)).map_err(
            |_| RpcError::internal("ledger accept timed out waiting for local close"),
        )?;
        return Ok(json!({
            "ledger_current_index": ledger_current_index,
        }));
    }

    Err(RpcError::internal(
        "standalone ledger_accept requires the local consensus close loop",
    ))
}

pub fn ledger_cleaner(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let cleaner = ctx
        .ledger_cleaner
        .as_ref()
        .ok_or_else(|| RpcError::internal("ledger cleaner unavailable"))?;
    let request = crate::ledger::control::LedgerCleanerRequest {
        current_seq: ctx.ledger_seq,
        ledger: params
            .get("ledger")
            .or_else(|| params.get("ledger_index"))
            .map(|value| parse_u32_like(value, "ledger"))
            .transpose()?,
        min_ledger: params
            .get("min_ledger")
            .map(|value| parse_u32_like(value, "min_ledger"))
            .transpose()?,
        max_ledger: params
            .get("max_ledger")
            .map(|value| parse_u32_like(value, "max_ledger"))
            .transpose()?,
        full: params.get("full").and_then(Value::as_bool).unwrap_or(false),
        fix_txns: params
            .get("fix_txns")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        check_nodes: params
            .get("check_nodes")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        stop: params.get("stop").and_then(Value::as_bool).unwrap_or(false),
    };
    cleaner
        .clean(request)
        .map_err(|e| RpcError::internal(&format!("ledger cleaner failed: {e}")))?;
    let snapshot = cleaner.snapshot();

    Ok(json!({
        "message": snapshot
            .last_message
            .clone()
            .unwrap_or_else(|| "Cleaner configured".to_string()),
        "state": snapshot.state,
        "online_delete": cleaner.online_delete(),
        "pending": snapshot.pending,
        "min_ledger": snapshot.min_ledger,
        "max_ledger": snapshot.max_ledger,
        "full": snapshot.full,
        "fix_txns": snapshot.fix_txns,
        "check_nodes": snapshot.check_nodes,
        "stop_requested": snapshot.stop_requested,
        "history_pruned": snapshot.history_pruned,
        "failures": snapshot.failures,
        "last_run_started_unix": snapshot.last_run_started_unix,
        "last_run_finished_unix": snapshot.last_run_finished_unix,
    }))
}

pub fn connect(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let ip = params
        .get("ip")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'ip' field"))?;
    let ip_addr = ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| RpcError::invalid_params("invalid 'ip' field"))?;
    let port = match params.get("port") {
        None => 2459,
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| RpcError::invalid_params("invalid 'port' field"))?,
        Some(Value::String(s)) => s
            .parse::<u16>()
            .map_err(|_| RpcError::invalid_params("invalid 'port' field"))?,
        Some(_) => return Err(RpcError::invalid_params("invalid 'port' field")),
    };
    let addr = std::net::SocketAddr::new(ip_addr, port);
    let queue = ctx
        .connect_requests
        .as_ref()
        .ok_or_else(|| RpcError::internal("connect queue unavailable"))?;
    queue.lock().unwrap_or_else(|e| e.into_inner()).push(addr);
    Ok(json!({
        "message": format!("queued peer connection to {addr}")
    }))
}

pub fn stop(ctx: &NodeContext) -> Result<Value, RpcError> {
    let flag = ctx
        .shutdown_requested
        .as_ref()
        .ok_or_else(|| RpcError::internal("shutdown flag unavailable"))?;
    flag.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(json!({
        "message": "server stopping"
    }))
}

pub fn tx_reduce_relay(ctx: &NodeContext) -> Result<Value, RpcError> {
    let metrics = ctx
        .tx_relay_metrics
        .clone()
        .unwrap_or(crate::rpc::TxRelayMetricsSnapshot {
            queued_transactions: 0,
            peer_count: ctx.peer_count,
            max_queue_size: 0,
            escalation_multiplier: 0,
            txns_expected: 0,
            candidate_set_hash: "0".repeat(64),
            tracked_transactions: 0,
            submitted_transactions: 0,
            inbound_tracked: 0,
            accepted_transactions: 0,
            duplicate_transactions: 0,
            relayed_transactions: 0,
            persisted_transactions: 0,
        });

    Ok(json!({
        "queued_transactions": metrics.queued_transactions,
        "peer_count": metrics.peer_count,
        "max_queue_size": metrics.max_queue_size,
        "escalation_multiplier": metrics.escalation_multiplier,
        "txns_expected": metrics.txns_expected,
        "candidate_set_hash": metrics.candidate_set_hash,
        "tracked_transactions": metrics.tracked_transactions,
        "submitted_transactions": metrics.submitted_transactions,
        "inbound_tracked": metrics.inbound_tracked,
        "accepted_transactions": metrics.accepted_transactions,
        "duplicate_transactions": metrics.duplicate_transactions,
        "relayed_transactions": metrics.relayed_transactions,
        "persisted_transactions": metrics.persisted_transactions,
    }))
}

#[derive(Clone)]
struct OraclePriceEntry {
    base: [u8; 20],
    quote: [u8; 20],
    price: u64,
    scale: u8,
}

#[derive(Clone)]
struct OracleSnapshot {
    last_update_time: u32,
    prev_txn_id: Option<[u8; 32]>,
    prev_txn_lgrseq: Option<u32>,
    entries: Vec<OraclePriceEntry>,
}

fn parse_currency_code_value(value: &Value, field: &str) -> Result<[u8; 20], RpcError> {
    let raw = match value {
        Value::String(s) => s.as_str(),
        Value::Object(obj) => obj
            .get("currency")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_field(field))?,
        _ => return Err(invalid_field(field)),
    };

    if raw.eq_ignore_ascii_case("XRP") {
        return Ok([0u8; 20]);
    }

    if raw.len() == 3 {
        return crate::transaction::amount::Currency::from_code(raw)
            .map(|currency| currency.code)
            .map_err(|_| invalid_field(field));
    }

    if raw.len() == 40 {
        let bytes = hex::decode(raw).map_err(|_| invalid_field(field))?;
        if bytes.len() != 20 {
            return Err(invalid_field(field));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }

    Err(invalid_field(field))
}

fn oracle_state_key(account: &[u8; 20], document_id: u32) -> crate::ledger::Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&[0x00, 0x52]);
    data.extend_from_slice(account);
    data.extend_from_slice(&document_id.to_be_bytes());
    crate::ledger::Key(crate::crypto::sha512_first_half(&data))
}

fn parse_oracle_price_series(data: &[u8]) -> Option<Vec<OraclePriceEntry>> {
    let mut pos = 0usize;
    let mut entries = Vec::new();

    while pos < data.len() {
        if data[pos] == 0xF1 {
            break;
        }

        let (tc, fc, new_pos) = parse_sle_field_header(data, pos)?;
        if (tc, fc) != (14, 32) {
            return None;
        }
        pos = new_pos;

        let mut base = None;
        let mut quote = None;
        let mut price = None;
        let mut scale = 0u8;

        loop {
            if pos >= data.len() {
                return None;
            }
            if data[pos] == 0xE1 {
                pos += 1;
                break;
            }

            let (field_tc, field_fc, field_pos) = parse_sle_field_header(data, pos)?;
            pos = field_pos;
            match (field_tc, field_fc) {
                (26, 1) => {
                    if pos + 20 > data.len() {
                        return None;
                    }
                    let mut raw = [0u8; 20];
                    raw.copy_from_slice(&data[pos..pos + 20]);
                    base = Some(raw);
                    pos += 20;
                }
                (26, 2) => {
                    if pos + 20 > data.len() {
                        return None;
                    }
                    let mut raw = [0u8; 20];
                    raw.copy_from_slice(&data[pos..pos + 20]);
                    quote = Some(raw);
                    pos += 20;
                }
                (3, 23) => {
                    if pos + 8 > data.len() {
                        return None;
                    }
                    price = Some(u64::from_be_bytes(data[pos..pos + 8].try_into().ok()?));
                    pos += 8;
                }
                (16, 4) => {
                    if pos >= data.len() {
                        return None;
                    }
                    scale = data[pos];
                    pos += 1;
                }
                _ => {
                    pos = crate::ledger::meta::skip_field_raw(data, pos, field_tc);
                }
            }
        }

        entries.push(OraclePriceEntry {
            base: base?,
            quote: quote?,
            price: price?,
            scale,
        });
    }

    Some(entries)
}

fn oracle_snapshot_from_fields(
    fields: &[crate::ledger::meta::ParsedField],
    prev_txn_id: Option<[u8; 32]>,
    prev_txn_lgrseq: Option<u32>,
) -> Option<OracleSnapshot> {
    let last_update_time = parsed_fields_u32(fields, 15)?;
    let series = fields
        .iter()
        .find(|field| field.type_code == 15 && field.field_code == 24)?;
    Some(OracleSnapshot {
        last_update_time,
        prev_txn_id,
        prev_txn_lgrseq,
        entries: parse_oracle_price_series(&series.data)?,
    })
}

fn oracle_snapshot_from_raw(raw: &[u8]) -> Option<OracleSnapshot> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    if parsed.entry_type != 0x0080 {
        return None;
    }
    oracle_snapshot_from_fields(&parsed.fields, parsed.prev_txn_id, parsed.prev_txn_lgrseq)
}

fn oracle_matching_price(
    snapshot: &OracleSnapshot,
    base_asset: &[u8; 20],
    quote_asset: &[u8; 20],
) -> Option<(u32, f64)> {
    snapshot.entries.iter().find_map(|entry| {
        if &entry.base == base_asset && &entry.quote == quote_asset {
            Some((
                snapshot.last_update_time,
                (entry.price as f64) * 10f64.powi(-(entry.scale as i32)),
            ))
        } else {
            None
        }
    })
}

fn find_oracle_price_sample(
    key: &crate::ledger::Key,
    raw: &[u8],
    base_asset: &[u8; 20],
    quote_asset: &[u8; 20],
    history: &crate::ledger::history::LedgerStore,
) -> Option<(u32, f64)> {
    let snapshot = oracle_snapshot_from_raw(raw)?;
    if let Some(sample) = oracle_matching_price(&snapshot, base_asset, quote_asset) {
        return Some(sample);
    }

    let mut prev_txn_id = snapshot.prev_txn_id;
    let mut prev_txn_lgrseq = snapshot.prev_txn_lgrseq;

    for depth in 1..=3 {
        let tx_hash = prev_txn_id?;
        let _ledger_seq = prev_txn_lgrseq?;
        let tx = history.get_tx(&tx_hash)?;
        let (_, nodes) = crate::ledger::meta::parse_metadata_with_index(&tx.meta);
        let node = nodes
            .into_iter()
            .find(|node| node.entry_type == 0x0080 && node.ledger_index == key.0)?;

        if depth == 1 && matches!(node.action, crate::ledger::meta::Action::Created) {
            return None;
        }

        let snapshot =
            oracle_snapshot_from_fields(&node.fields, node.prev_txn_id, node.prev_txn_lgrseq)?;
        if let Some(sample) = oracle_matching_price(&snapshot, base_asset, quote_asset) {
            return Some(sample);
        }

        if matches!(node.action, crate::ledger::meta::Action::Created) {
            break;
        }

        prev_txn_id = snapshot.prev_txn_id;
        prev_txn_lgrseq = snapshot.prev_txn_lgrseq;
    }

    None
}

fn format_decimal_stat(value: f64) -> String {
    if !value.is_finite() || value == 0.0 {
        return "0".to_string();
    }
    format_iou_value(&crate::transaction::amount::IouValue::from_f64(value))
}

pub fn get_aggregate_price(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let oracles = params
        .get("oracles")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::invalid_params("missing 'oracles' field"))?;
    if oracles.is_empty() || oracles.len() > 200 {
        return Err(RpcError::invalid_params("invalid 'oracles' field"));
    }

    let base_asset = parse_currency_code_value(
        params
            .get("base_asset")
            .ok_or_else(|| RpcError::invalid_params("missing 'base_asset' field"))?,
        "base_asset",
    )?;
    let quote_asset = parse_currency_code_value(
        params
            .get("quote_asset")
            .ok_or_else(|| RpcError::invalid_params("missing 'quote_asset' field"))?,
        "quote_asset",
    )?;
    let trim = params
        .get("trim")
        .map(|value| parse_u32_like(value, "trim"))
        .transpose()?
        .unwrap_or(0);
    if params.get("trim").is_some() && (trim == 0 || trim > 25) {
        return Err(RpcError::invalid_params("invalid 'trim' field"));
    }
    let time_threshold = params
        .get("time_threshold")
        .map(|value| parse_u32_like(value, "time_threshold"))
        .transpose()?
        .unwrap_or(0);

    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());

    let mut samples = Vec::new();
    for oracle in oracles {
        let account = parse_account_value(
            oracle
                .get("account")
                .ok_or_else(|| RpcError::invalid_params("oracle is missing 'account' field"))?,
            "account",
        )?;
        let document_id = parse_u32_value(
            oracle.get("oracle_document_id").ok_or_else(|| {
                RpcError::invalid_params("oracle is missing 'oracle_document_id' field")
            })?,
            "oracle_document_id",
        )?;
        let key = oracle_state_key(&account, document_id);
        let Some(raw) = lookup_raw_object_at_ledger(&key, requested_seq, ctx) else {
            continue;
        };
        if let Some(sample) =
            find_oracle_price_sample(&key, &raw, &base_asset, &quote_asset, &history)
        {
            samples.push(sample);
        }
    }

    if samples.is_empty() {
        return Err(RpcError::not_found("oracle price"));
    }

    let latest_time = samples
        .iter()
        .map(|(time, _)| *time)
        .max()
        .unwrap_or_default();
    if time_threshold > 0 {
        let min_time = latest_time.saturating_sub(time_threshold);
        samples.retain(|(time, _)| *time >= min_time);
    }
    if samples.is_empty() {
        return Err(RpcError::not_found("oracle price"));
    }

    let mut values: Vec<f64> = samples.iter().map(|(_, value)| *value).collect();
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let size = values.len();
    let mean = values.iter().sum::<f64>() / size as f64;
    let standard_deviation = if size > 1 {
        let variance = values
            .iter()
            .map(|value| {
                let delta = value - mean;
                delta * delta
            })
            .sum::<f64>()
            / (size - 1) as f64;
        variance.sqrt()
    } else {
        0.0
    };
    let median = if size % 2 == 0 {
        (values[(size / 2) - 1] + values[size / 2]) / 2.0
    } else {
        values[size / 2]
    };

    let mut out = json!({
        "time": latest_time,
        "entire_set": {
            "mean": format_decimal_stat(mean),
            "size": size,
            "standard_deviation": format_decimal_stat(standard_deviation),
        },
        "median": format_decimal_stat(median),
    });

    if trim > 0 {
        let trim_count = size * trim as usize / 100;
        let (lower, upper) = if trim_count * 2 < size {
            (trim_count, size - trim_count)
        } else {
            (0, size)
        };
        let trimmed = &values[lower..upper];
        let trimmed_mean = trimmed.iter().sum::<f64>() / trimmed.len() as f64;
        let trimmed_standard_deviation = if trimmed.len() > 1 {
            let variance = trimmed
                .iter()
                .map(|value| {
                    let delta = value - trimmed_mean;
                    delta * delta
                })
                .sum::<f64>()
                / (trimmed.len() - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };
        out["trimmed_set"] = json!({
            "mean": format_decimal_stat(trimmed_mean),
            "size": trimmed.len(),
            "standard_deviation": format_decimal_stat(trimmed_standard_deviation),
        });
    }

    Ok(out)
}

pub fn wallet_propose(params: &Value) -> Result<Value, RpcError> {
    let any_seed_fields = ["passphrase", "secret", "seed", "seed_hex"]
        .iter()
        .any(|field| params.get(*field).is_some());
    let key_type = parse_key_type(params)?.unwrap_or(crate::crypto::keys::KeyType::Secp256k1);
    let entropy = if any_seed_fields {
        let (parsed_type, entropy) = parse_rpc_seed(params)?;
        if parsed_type != key_type {
            return Err(RpcError::invalid_params("mismatched key_type"));
        }
        entropy
    } else {
        random_seed_entropy()
    };

    let key_pair = match key_type {
        crate::crypto::keys::KeyType::Secp256k1 => crate::crypto::keys::KeyPair::Secp256k1(
            crate::crypto::keys::Secp256k1KeyPair::from_seed_entropy(&entropy),
        ),
        crate::crypto::keys::KeyType::Ed25519 => crate::crypto::keys::KeyPair::Ed25519(
            crate::crypto::keys::Ed25519KeyPair::from_seed_entropy(&entropy),
        ),
    };
    let public_key_bytes = rpc_public_key_bytes(&key_pair);
    let mut out = json!({
        "account_id": key_pair.account_address(),
        "key_type": match key_type {
            crate::crypto::keys::KeyType::Secp256k1 => "secp256k1",
            crate::crypto::keys::KeyType::Ed25519 => "ed25519",
        },
        "master_seed": crate::crypto::base58::encode_seed(&entropy),
        "master_seed_hex": hex::encode_upper(entropy),
        "public_key": rpc_public_key_base58(&key_pair),
        "public_key_hex": hex::encode_upper(public_key_bytes),
    });
    if any_seed_fields {
        out["warning"] = json!("deterministic key generation from supplied seed material");
    }
    Ok(out)
}

pub fn validation_create(params: &Value) -> Result<Value, RpcError> {
    if matches!(
        parse_key_type(params)?,
        Some(crate::crypto::keys::KeyType::Ed25519)
    ) {
        return Err(RpcError::invalid_params(
            "validation keys must use secp256k1",
        ));
    }
    let any_seed_fields = ["passphrase", "secret", "seed", "seed_hex"]
        .iter()
        .any(|field| params.get(*field).is_some());
    let entropy = if any_seed_fields {
        let (_, entropy) = parse_rpc_seed(params)?;
        entropy
    } else {
        random_seed_entropy()
    };
    let key_pair = crate::crypto::keys::Secp256k1KeyPair::from_seed_entropy(&entropy);
    Ok(json!({
        "validation_public_key": crate::crypto::base58::encode(
            crate::crypto::base58::PREFIX_NODE_PUBLIC,
            &key_pair.public_key_bytes(),
        ),
        "validation_seed": crate::crypto::base58::encode_seed(&entropy),
        "validation_seed_hex": hex::encode_upper(entropy),
    }))
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
        Err(RpcError {
            code: "noStorage",
            error_code: 73,
            message: "No storage configured.".into(),
            extra: None,
        })
    }
}

pub fn ping() -> Result<Value, RpcError> {
    Ok(json!({}))
}

// ── fee ──────────────────────────────────────────────────────────────────────

pub fn fee(ctx: &NodeContext) -> Result<Value, RpcError> {
    use crate::ledger::pool::{FeeMetrics, BASE_LEVEL};

    let base = ctx.fees.base;
    let (
        ledger_current_index,
        pool_size,
        open_level,
        median_fee,
        txns_expected,
        escalation_multiplier,
        max_queue_size,
    ) =
        if let Some(snapshot) = ctx.open_ledger_snapshot.as_ref() {
            (
                snapshot.ledger_current_index,
                snapshot.queued_transactions,
                snapshot.open_fee_level,
                FeeMetrics::fee_level_to_drops(snapshot.escalation_multiplier, base),
                snapshot.txns_expected,
                snapshot.escalation_multiplier,
                snapshot.max_queue_size,
            )
        } else {
            let pool = ctx.tx_pool.read().unwrap_or_else(|e| e.into_inner());
            let pool_size = pool.len();
            let metrics = &pool.metrics;
            (
                ctx.ledger_seq,
                pool_size,
                metrics.escalated_fee_level(pool_size as u64 + 1),
                FeeMetrics::fee_level_to_drops(metrics.escalation_multiplier, base),
                metrics.txns_expected,
                metrics.escalation_multiplier,
                metrics.max_queue_size(),
            )
        };
    let open_fee = FeeMetrics::fee_level_to_drops(open_level, base);

    Ok(json!({
        "current_ledger_size": pool_size.to_string(),
        "current_queue_size":  "0",
        "drops": {
            "base_fee":         base.to_string(),
            "median_fee":       median_fee.to_string(),
            "minimum_fee":      base.to_string(),
            "open_ledger_fee":  open_fee.to_string(),
        },
        "expected_ledger_size": txns_expected.to_string(),
        "ledger_current_index": ledger_current_index,
        "levels": {
            "median_level":     escalation_multiplier.to_string(),
            "minimum_level":    BASE_LEVEL.to_string(),
            "open_ledger_level": open_level.to_string(),
            "reference_level":  BASE_LEVEL.to_string(),
        },
        "max_queue_size": max_queue_size.to_string(),
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
        crate::ledger::AccountRoot::decode(&raw).map_err(|_| RpcError::not_found(address))?
    } else if let Some(ref cl) = ctx.closed_ledger {
        // New path: read from ClosedLedger via ReadView
        use crate::ledger::views::ReadView;
        let kl = crate::ledger::keylet::account(&account_id);
        let sle = cl.read(&kl).ok_or_else(|| RpcError::not_found(address))?;
        // Decode from SLE binary to typed struct for JSON response
        crate::ledger::AccountRoot::decode(sle.data()).map_err(|_| RpcError::not_found(address))?
    } else {
        // Legacy path: in-memory state with storage fallback
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        ls.get_account(&account_id)
            .cloned()
            .ok_or_else(|| RpcError::not_found(address))?
    };

    let key_hex = hex::encode_upper(crate::ledger::shamap_key(&account_id).0);

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

    let src_addr = params
        .get("source_account")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'source_account'"))?;
    let dst_addr = params
        .get("destination_account")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'destination_account'"))?;
    let dst_amount_json = params
        .get("destination_amount")
        .ok_or_else(|| RpcError::invalid_params("missing 'destination_amount'"))?;

    let src_id =
        decode_account(src_addr).map_err(|_| RpcError::invalid_params("invalid source_account"))?;
    let dst_id = decode_account(dst_addr)
        .map_err(|_| RpcError::invalid_params("invalid destination_account"))?;

    // Parse destination amount
    let (dst_currency, dst_issuer) = parse_currency_spec(Some(dst_amount_json))?;
    let dst_is_xrp = dst_currency == [0u8; 20];

    let dst_value = if dst_is_xrp {
        dst_amount_json
            .as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .or_else(|| dst_amount_json.as_u64().map(|v| v as f64))
            .unwrap_or(0.0)
    } else {
        dst_amount_json
            .get("value")
            .and_then(Value::as_str)
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
            let bal_f = if bal.mantissa == 0 {
                0.0
            } else {
                bal.mantissa as f64 * 10f64.powi(bal.exponent)
            };
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
            pays_issuer: dst_issuer,
            gets_currency: [0u8; 20], // XRP
            gets_issuer: [0u8; 20],
        };
        if let Some(book) = ls.get_book(&book_key) {
            if !book.is_empty() {
                // Estimate cost: walk cheapest offers
                let mut xrp_needed = 0f64;
                let mut remaining = dst_value;
                for key in book.iter_by_quality() {
                    if remaining <= 0.0 {
                        break;
                    }
                    if let Some(off) = ls.get_offer(key) {
                        let gets_f = amount_to_f64(&off.taker_gets); // XRP
                        let pays_f = amount_to_f64(&off.taker_pays); // IOU
                        if pays_f <= 0.0 {
                            continue;
                        }
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
        if src_currency.is_xrp() {
            continue;
        }
        if src_currency.code == dst_currency {
            continue;
        } // already handled above

        let peer = if src_id == tl.low_account {
            &tl.high_account
        } else {
            &tl.low_account
        };

        let book_key = BookKey {
            pays_currency: dst_currency,
            pays_issuer: dst_issuer,
            gets_currency: src_currency.code,
            gets_issuer: *peer,
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

        if alternatives.len() >= 6 {
            break;
        } // cap at 6
    }

    Ok(json!({
        "alternatives": alternatives,
        "destination_account": dst_addr,
        "destination_amount":  dst_amount_json,
    }))
}

pub(crate) fn path_find_update_result(
    params: &Value,
    ctx: &NodeContext,
) -> Result<Value, RpcError> {
    let mut result = ripple_path_find(params, ctx)?;
    if let Some(obj) = result.as_object_mut() {
        obj.insert("type".to_string(), json!("path_find"));
    }
    Ok(result)
}

fn path_find_client_id(params: &Value, request_id: &Value) -> Result<u64, RpcError> {
    if let Some(id) = params.get("client_id") {
        if let Some(value) = id.as_u64() {
            return Ok(value);
        }
        if let Some(text) = id.as_str() {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(&text, &mut hasher);
            return Ok(std::hash::Hasher::finish(&hasher));
        }
        return Err(RpcError::invalid_params(
            "Invalid field 'client_id'. Expected string or unsigned integer.",
        ));
    }

    if let Some(value) = request_id.as_u64() {
        return Ok(value);
    }
    if let Some(text) = request_id.as_str() {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&text, &mut hasher);
        return Ok(std::hash::Hasher::finish(&hasher));
    }

    Err(RpcError::invalid_params(
        "path_find subcommands require 'client_id' or a JSON-RPC request id.",
    ))
}

pub fn path_find(params: &Value, request_id: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let Some(manager) = ctx.path_requests.as_ref() else {
        return Err(RpcError::internal("path request manager unavailable"));
    };
    let subcommand = params
        .get("subcommand")
        .and_then(Value::as_str)
        .unwrap_or("status");
    let client_id = path_find_client_id(params, request_id)?;

    match subcommand {
        "create" => {
            let result = path_find_update_result(params, ctx)?;
            manager
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .upsert(client_id, params.clone(), &result);
            Ok(result)
        }
        "status" => {
            let stored = manager
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .request_for(client_id)
                .ok_or_else(|| RpcError::invalid_params("No active path_find request."))?;
            let result = path_find_update_result(&stored, ctx)?;
            manager
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .upsert(client_id, stored, &result);
            Ok(result)
        }
        "close" => {
            let closed = manager
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .close(client_id);
            Ok(json!({
                "closed": closed,
            }))
        }
        _ => Err(RpcError::invalid_params(
            "Unsupported path_find subcommand.",
        )),
    }
}

// ── feature (amendments) ─────────────────────────────────────────────────────

pub fn feature(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    if let Some(name) = params.get("feature").and_then(Value::as_str) {
        let enabled = ctx.amendments.contains(name);
        let mut obj = serde_json::Map::new();
        obj.insert(
            name.to_string(),
            json!({ "enabled": enabled, "supported": enabled }),
        );
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
    use crate::transaction::{builder::TxBuilder, Amount};

    let secret = params
        .get("secret")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'secret' field"))?;

    let tx_json = params
        .get("tx_json")
        .ok_or_else(|| RpcError::invalid_params("missing 'tx_json' field"))?;

    let kp = Secp256k1KeyPair::from_seed(secret)
        .map_err(|_| RpcError::invalid_params("invalid secret/seed"))?;
    let kp = KeyPair::Secp256k1(kp);

    // Extract fields from tx_json
    let tx_type = tx_json
        .get("TransactionType")
        .and_then(Value::as_str)
        .unwrap_or("Payment");
    let dest = tx_json.get("Destination").and_then(Value::as_str);
    let amount_val = tx_json.get("Amount");
    let fee = tx_json
        .get("Fee")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(12);
    let sequence = tx_json.get("Sequence").and_then(Value::as_u64).unwrap_or(0) as u32;

    let mut builder = match tx_type {
        "Payment" => TxBuilder::payment(),
        "TrustSet" => TxBuilder::trust_set(),
        "OfferCreate" => TxBuilder::offer_create(),
        "OfferCancel" => TxBuilder::offer_cancel(),
        "AccountSet" => TxBuilder::account_set(),
        "EscrowCreate" => TxBuilder::escrow_create(),
        "EscrowFinish" => TxBuilder::escrow_finish(),
        "EscrowCancel" => TxBuilder::escrow_cancel(),
        "CheckCreate" => TxBuilder::check_create(),
        "CheckCash" => TxBuilder::check_cash(),
        "CheckCancel" => TxBuilder::check_cancel(),
        "PaymentChannelCreate" => TxBuilder::paychan_create(),
        "PaymentChannelFund" => TxBuilder::paychan_fund(),
        "PaymentChannelClaim" => TxBuilder::paychan_claim(),
        _ => {
            return Err(RpcError::invalid_params(&format!(
                "unsupported tx type: {tx_type}"
            )))
        }
    };

    builder = builder.account(&kp).fee(fee).sequence(sequence);

    if let Some(d) = dest {
        builder = builder
            .destination(d)
            .map_err(|_| RpcError::invalid_params("invalid Destination"))?;
    }

    if let Some(amt) = amount_val {
        if let Some(amount_obj) = amt.as_object() {
            // IOU: { "value": "100", "currency": "USD", "issuer": "r..." }
            let value_str = amount_obj
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or("0");
            let currency_str = amount_obj
                .get("currency")
                .and_then(Value::as_str)
                .unwrap_or("USD");
            let issuer_str = amount_obj
                .get("issuer")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::invalid_params("IOU Amount missing 'issuer'"))?;
            let value_f64 = value_str
                .parse::<f64>()
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

    let signed = builder
        .sign(&kp)
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
    use crate::transaction::{builder::TxBuilder, serialize, Amount};

    let secret = params
        .get("secret")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'secret'"))?;
    let signer_addr = params
        .get("account")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'account'"))?;
    let tx_json = params
        .get("tx_json")
        .ok_or_else(|| RpcError::invalid_params("missing 'tx_json'"))?;

    let signer_account_id = decode_account(signer_addr)
        .map_err(|_| RpcError::invalid_params("invalid signer account"))?;

    let kp = Secp256k1KeyPair::from_seed(secret)
        .map_err(|_| RpcError::invalid_params("invalid secret/seed"))?;
    let kp = KeyPair::Secp256k1(kp);

    // Build tx fields with EMPTY SigningPubKey (multi-sign requirement)
    let tx_type = tx_json
        .get("TransactionType")
        .and_then(Value::as_str)
        .unwrap_or("Payment");
    let dest = tx_json.get("Destination").and_then(Value::as_str);
    let fee = tx_json
        .get("Fee")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(12);
    let sequence = tx_json.get("Sequence").and_then(Value::as_u64).unwrap_or(0) as u32;
    let account_addr = tx_json
        .get("Account")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'Account' in tx_json"))?;

    let mut builder = match tx_type {
        "Payment" => TxBuilder::payment(),
        "TrustSet" => TxBuilder::trust_set(),
        "OfferCreate" => TxBuilder::offer_create(),
        "AccountSet" => TxBuilder::account_set(),
        _ => {
            return Err(RpcError::invalid_params(&format!(
                "unsupported tx type: {tx_type}"
            )))
        }
    };

    builder = builder
        .account_address(account_addr)
        .map_err(|_| RpcError::invalid_params("invalid Account"))?
        .fee(fee)
        .sequence(sequence);
    if let Some(d) = dest {
        builder = builder
            .destination(d)
            .map_err(|_| RpcError::invalid_params("invalid Destination"))?;
    }
    if let Some(amt) = tx_json.get("Amount").and_then(Value::as_str) {
        if let Ok(drops) = amt.parse::<u64>() {
            builder = builder.amount(Amount::Xrp(drops));
        }
    }

    // Build fields with empty signing pubkey for multi-sign
    let mut fields = builder
        .build_fields(vec![], None)
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

pub fn simulate(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let (blob, mut tx_json, binary) = parse_simulate_input(params, ctx)?;
    let parsed = crate::transaction::parse_blob(&blob)
        .map_err(|e| RpcError::invalid_params(&format!("tx parse error: {e}")))?;

    let tx_hash = {
        let mut payload = crate::transaction::serialize::PREFIX_TX_ID.to_vec();
        payload.extend_from_slice(&blob);
        crate::crypto::sha512_first_half(&payload)
    };
    let sim_ctx = crate::ledger::apply::TxContext::from_parent(
        &ctx.ledger_header,
        ctx.ledger_header.close_time,
    );

    let mut sim_state = {
        let mut state = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        state.simulation_copy()
    };
    let result = crate::ledger::tx::run_tx(
        &mut sim_state,
        &parsed,
        &sim_ctx,
        crate::ledger::ter::ApplyFlags::DRY_RUN,
    );

    let mut out = json!({
        "applied": result.applied,
        "ledger_index": sim_ctx.ledger_seq,
        "engine_result": result.ter.token(),
        "engine_result_code": result.ter.code(),
        "engine_result_message": crate::ledger::ter::code_to_message(result.ter.code()),
    });
    if result.ter == crate::ledger::ter::TES_SUCCESS {
        out["engine_result_message"] = json!("The simulated transaction would have been applied.");
    }

    if result.applied {
        crate::ledger::close::stamp_touched_previous_fields(
            &mut sim_state,
            &result.touched,
            &tx_hash,
            sim_ctx.ledger_seq,
        );
        let meta_blob = crate::ledger::close::build_tx_metadata(
            &sim_state,
            &result.touched,
            tx_hash,
            sim_ctx.ledger_seq,
            0,
            result.ter.token(),
        );
        if binary {
            out["meta_blob"] = json!(hex::encode_upper(meta_blob));
        } else {
            out["meta"] = metadata_json(&meta_blob, result.ter.token());
        }
    }

    if let Some(obj) = tx_json.as_object_mut() {
        obj.insert("hash".to_string(), json!(hex::encode_upper(tx_hash)));
    }
    if binary {
        out["tx_blob"] = json!(hex::encode_upper(blob));
    } else {
        out["tx_json"] = tx_json;
    }

    Ok(out)
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
        let (header, mut map) =
            historical_state_map(target_seq, ctx, "historical ledger enumeration unavailable")?;
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
            decode_account(s).map_err(|_| RpcError::invalid_params("malformed peer address"))?,
        ),
        Some(_) => return Err(RpcError::invalid_params("malformed peer address")),
    };

    let line_json = |tl: &crate::ledger::trustline::RippleState| {
        let is_low = account_id == tl.low_account;
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
        let no_ripple = if is_low {
            tl.flags & crate::ledger::trustline::LSF_LOW_NO_RIPPLE != 0
        } else {
            tl.flags & crate::ledger::trustline::LSF_HIGH_NO_RIPPLE != 0
        };
        let no_ripple_peer = if is_low {
            tl.flags & crate::ledger::trustline::LSF_HIGH_NO_RIPPLE != 0
        } else {
            tl.flags & crate::ledger::trustline::LSF_LOW_NO_RIPPLE != 0
        };
        let authorized = if is_low {
            tl.flags & crate::ledger::trustline::LSF_LOW_AUTH != 0
        } else {
            tl.flags & crate::ledger::trustline::LSF_HIGH_AUTH != 0
        };
        let peer_authorized = if is_low {
            tl.flags & crate::ledger::trustline::LSF_HIGH_AUTH != 0
        } else {
            tl.flags & crate::ledger::trustline::LSF_LOW_AUTH != 0
        };
        let freeze = if is_low {
            tl.flags & crate::ledger::trustline::LSF_LOW_FREEZE != 0
        } else {
            tl.flags & crate::ledger::trustline::LSF_HIGH_FREEZE != 0
        };
        let freeze_peer = if is_low {
            tl.flags & crate::ledger::trustline::LSF_HIGH_FREEZE != 0
        } else {
            tl.flags & crate::ledger::trustline::LSF_LOW_FREEZE != 0
        };
        let quality_in = if is_low {
            tl.low_quality_in
        } else {
            tl.high_quality_in
        };
        let quality_out = if is_low {
            tl.low_quality_out
        } else {
            tl.high_quality_out
        };
        json!({
            "account":    crate::crypto::base58::encode_account(&peer_id),
            "balance":    format_iou_value(&balance),
            "currency":   tl.currency.to_ascii(),
            "limit":      format_iou_value(limit),
            "limit_peer": format_iou_value(limit_peer),
            "no_ripple":  no_ripple,
            "no_ripple_peer": no_ripple_peer,
            "authorized": authorized,
            "peer_authorized": peer_authorized,
            "freeze": freeze,
            "freeze_peer": freeze_peer,
            "quality_in": quality_in,
            "quality_out": quality_out,
        })
    };

    let mut line_values: Vec<Value> = Vec::new();
    let mut next_marker: Option<[u8; 32]> = None;

    if is_historical {
        if ctx
            .history
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get_ledger(requested_seq)
            .is_none()
        {
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
        let mut all_tl: Vec<(crate::ledger::Key, crate::ledger::trustline::RippleState)> =
            Vec::new();
        loop {
            let page_kl = crate::ledger::keylet::dir_page(&dir_kl.key.0, dir_page);
            let Some(dir_sle) = cl.read(&page_kl) else {
                break;
            };
            let Ok(dir_node) =
                crate::ledger::directory::DirectoryNode::decode(dir_sle.data(), page_kl.key.0)
            else {
                break;
            };
            for idx in &dir_node.indexes {
                let entry_key = crate::ledger::Key(*idx);
                // Try to read as RippleState
                if let Some(data) = cl.read(&crate::ledger::keylet::Keylet::new(
                    entry_key,
                    crate::ledger::sle::LedgerEntryType::RippleState,
                )) {
                    if let Some(tl) =
                        crate::ledger::trustline::RippleState::decode_from_sle(data.data())
                    {
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
                if key.0 != mark {
                    return false;
                }
                let peer_id = if account_id == tl.low_account {
                    tl.high_account
                } else {
                    tl.low_account
                };
                peer.map(|p| p == peer_id).unwrap_or(true)
            });
            if !marker_matches {
                return Err(RpcError::invalid_params("invalid marker"));
            }
        }
        let mut last_returned: Option<[u8; 32]> = None;
        for (key, tl) in &all_tl {
            if let Some(after) = marker {
                if key.0 <= after {
                    continue;
                }
            }
            let peer_id = if account_id == tl.low_account {
                tl.high_account
            } else {
                tl.low_account
            };
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
    } else {
        // Legacy path: in-memory state
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if ls.get_account(&account_id).is_none() {
            return Err(RpcError::not_found(address));
        }
        let mut lines: Vec<(crate::ledger::Key, &crate::ledger::trustline::RippleState)> = ls
            .trustlines_for_account(&account_id)
            .into_iter()
            .map(|tl| (tl.key(), tl))
            .collect();
        lines.sort_by_key(|(key, _)| key.0);
        if let Some(mark) = marker {
            let marker_matches = lines.iter().any(|(key, tl)| {
                if key.0 != mark {
                    return false;
                }
                let peer_id = if account_id == tl.low_account {
                    tl.high_account
                } else {
                    tl.low_account
                };
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
            let peer_id = if account_id == tl.low_account {
                tl.high_account
            } else {
                tl.low_account
            };
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
    if v.mantissa == 0 {
        return "0".to_string();
    }
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

fn amount_issue_key(amount: &crate::transaction::amount::Amount) -> Option<String> {
    match amount {
        crate::transaction::amount::Amount::Xrp(_) => Some("XRP_drops".to_string()),
        crate::transaction::amount::Amount::Iou {
            currency, issuer, ..
        } => Some(format!(
            "{}|{}",
            currency.to_ascii(),
            crate::crypto::base58::encode_account(issuer)
        )),
        crate::transaction::amount::Amount::Mpt(raw) => {
            Some(format!("MPT|{}", hex::encode_upper(raw)))
        }
    }
}

fn parsed_fields_amount(
    fields: &[crate::ledger::meta::ParsedField],
    field_code: u16,
) -> Option<crate::transaction::amount::Amount> {
    let field = fields
        .iter()
        .find(|field| field.type_code == 6 && field.field_code == field_code)?;
    crate::transaction::amount::Amount::from_bytes(&field.data)
        .ok()
        .map(|(amount, _)| amount)
}

fn parsed_fields_u32(fields: &[crate::ledger::meta::ParsedField], field_code: u16) -> Option<u32> {
    let field = fields
        .iter()
        .find(|field| field.type_code == 2 && field.field_code == field_code)?;
    (field.data.len() >= 4)
        .then(|| u32::from_be_bytes(field.data[..4].try_into().unwrap_or([0u8; 4])))
}

fn parsed_fields_hash256(
    fields: &[crate::ledger::meta::ParsedField],
    field_code: u16,
) -> Option<[u8; 32]> {
    let field = fields
        .iter()
        .find(|field| field.type_code == 5 && field.field_code == field_code)?;
    (field.data.len() >= 32).then(|| {
        let mut out = [0u8; 32];
        out.copy_from_slice(&field.data[..32]);
        out
    })
}

fn offer_quality_string(off: &crate::ledger::offer::Offer) -> String {
    let Some(pays) = amount_as_f64(&off.taker_pays) else {
        return "0".into();
    };
    let Some(gets) = amount_as_f64(&off.taker_gets) else {
        return "0".into();
    };
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
        crate::transaction::amount::Amount::Iou {
            currency, issuer, ..
        } => {
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
                return Err(RpcError::invalid_params(
                    "ledger_index_max must be >= ledger_index_min",
                ));
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
        pays_issuer: taker_pays.1,
        gets_currency: taker_gets.0,
        gets_issuer: taker_gets.1,
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
            crate::transaction::amount::Amount::Iou {
                currency, issuer, ..
            } => (currency.code, *issuer),
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
            matching = book
                .iter_by_quality()
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
            let store = ctx
                .storage
                .as_ref()
                .and_then(|s| Some(owner_funds_historical(s, requested_seq, &off)))
                .flatten();
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
    let issuer_str = obj
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("issuer required for non-XRP"))?;
    let issuer =
        decode_account(issuer_str).map_err(|_| RpcError::invalid_params("invalid issuer"))?;
    Ok((currency.code, issuer))
}

fn parse_issue_spec(v: &Value) -> Result<crate::transaction::amount::Issue, RpcError> {
    let (currency, issuer) = parse_currency_spec(Some(v))?;
    if currency == [0u8; 20] {
        Ok(crate::transaction::amount::Issue::Xrp)
    } else {
        Ok(crate::transaction::amount::Issue::Iou {
            currency: crate::transaction::amount::Currency { code: currency },
            issuer,
        })
    }
}

fn format_issue_quantity(issue: &crate::transaction::amount::Issue, value: i64) -> Value {
    match issue {
        crate::transaction::amount::Issue::Xrp => json!(value.to_string()),
        crate::transaction::amount::Issue::Iou { currency, issuer } => json!({
            "value": value.to_string(),
            "currency": currency.to_ascii(),
            "issuer": crate::crypto::base58::encode_account(issuer),
        }),
        crate::transaction::amount::Issue::Mpt(mptid) => json!({
            "value": value.to_string(),
            "mpt_issuance_id": hex::encode_upper(mptid),
        }),
    }
}

pub(crate) fn format_amount(a: &crate::transaction::amount::Amount) -> Value {
    match a {
        crate::transaction::amount::Amount::Xrp(drops) => json!(drops.to_string()),
        crate::transaction::amount::Amount::Iou {
            value,
            currency,
            issuer,
        } => {
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
                json!(u32::from_be_bytes(
                    field.data[..4].try_into().unwrap_or([0u8; 4])
                ))
            }
            3 if field.data.len() >= 8 => {
                json!(
                    u64::from_be_bytes(field.data[..8].try_into().unwrap_or([0u8; 8])).to_string()
                )
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

    let affected: Vec<Value> = nodes
        .into_iter()
        .map(|node| {
            let wrapper = match node.action {
                crate::ledger::meta::Action::Created => "CreatedNode",
                crate::ledger::meta::Action::Modified => "ModifiedNode",
                crate::ledger::meta::Action::Deleted => "DeletedNode",
            };
            let field_name = match node.action {
                crate::ledger::meta::Action::Created => "NewFields",
                crate::ledger::meta::Action::Modified | crate::ledger::meta::Action::Deleted => {
                    "FinalFields"
                }
            };
            let mut inner = serde_json::Map::new();
            inner.insert(
                "LedgerEntryType".to_string(),
                json!(sle_entry_type_name(node.entry_type)),
            );
            inner.insert(
                "LedgerIndex".to_string(),
                json!(hex::encode_upper(node.ledger_index)),
            );
            inner.insert(field_name.to_string(), metadata_fields_json(&node.fields));
            if node.action == crate::ledger::meta::Action::Modified
                && !node.previous_fields.is_empty()
            {
                inner.insert(
                    "PreviousFields".to_string(),
                    metadata_fields_json(&node.previous_fields),
                );
            }
            json!({ wrapper: Value::Object(inner) })
        })
        .collect();
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

fn human_time_string(unix: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let unix = i64::try_from(unix).unwrap_or(i64::MAX);
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs / 3_600;
    let minute = (secs % 3_600) / 60;
    let second = secs % 60;
    let month_name = MONTHS
        .get(month.saturating_sub(1) as usize)
        .copied()
        .unwrap_or("Jan");
    format!("{year:04}-{month_name}-{day:02} {hour:02}:{minute:02}:{second:02}.000000000 UTC")
}

pub(crate) fn close_time_iso_string(close_time: u64) -> String {
    const XRPL_EPOCH_OFFSET: i64 = 946_684_800;
    let unix =
        i64::try_from(close_time).unwrap_or(i64::MAX - XRPL_EPOCH_OFFSET) + XRPL_EPOCH_OFFSET;
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
        if let Some(header) = history
            .get_ledger(rec.ledger_seq)
            .map(|r| &r.header)
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

pub fn book_changes(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let explicit_ledger = params
        .get("ledger")
        .or_else(|| params.get("ledger_index"))
        .or_else(|| params.get("ledger_hash"))
        .is_some();
    let requested_seq = if let Some(ledger) = params.get("ledger") {
        match ledger {
            Value::String(s) if matches!(s.as_str(), "current" | "closed" | "validated") => {
                ctx.ledger_seq
            }
            Value::String(s) => s
                .parse::<u32>()
                .map_err(|_| RpcError::invalid_params("invalid ledger"))?,
            Value::Number(n) => n
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| RpcError::invalid_params("invalid ledger"))?,
            _ => return Err(RpcError::invalid_params("invalid ledger")),
        }
    } else {
        resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq)
    };

    let (header, txs) = {
        let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());
        if requested_seq == ctx.ledger_seq {
            let header = history
                .get_ledger(requested_seq)
                .map(|record| record.header.clone())
                .unwrap_or_else(|| ctx.ledger_header.clone());
            (header, history.ledger_txs(requested_seq))
        } else {
            let record = history
                .get_ledger(requested_seq)
                .ok_or_else(lgr_not_found)?;
            (record.header.clone(), history.ledger_txs(requested_seq))
        }
    };

    #[derive(Clone, Copy)]
    struct BookChangeSummary {
        volume_a: f64,
        volume_b: f64,
        high: f64,
        low: f64,
        open: f64,
        close: f64,
    }

    let mut tally: std::collections::BTreeMap<
        String,
        (String, String, BookChangeSummary, Option<String>),
    > = std::collections::BTreeMap::new();

    for rec in txs {
        let parsed = crate::transaction::parse_blob(&rec.blob).ok();
        let explicit_offer_cancel = match parsed.as_ref().map(|tx| tx.tx_type) {
            Some(7) | Some(8) => parsed.as_ref().and_then(|tx| tx.offer_sequence),
            _ => None,
        };

        let (_, nodes) = crate::ledger::meta::parse_metadata_with_index(&rec.meta);
        for node in nodes {
            if node.entry_type != 0x006F || node.action == crate::ledger::meta::Action::Created {
                continue;
            }
            if node.fields.is_empty() || node.previous_fields.is_empty() {
                continue;
            }

            let Some(final_gets) = parsed_fields_amount(&node.fields, 5) else {
                continue;
            };
            let Some(final_pays) = parsed_fields_amount(&node.fields, 4) else {
                continue;
            };
            let Some(prev_gets) = parsed_fields_amount(&node.previous_fields, 5) else {
                continue;
            };
            let Some(prev_pays) = parsed_fields_amount(&node.previous_fields, 4) else {
                continue;
            };

            if node.action == crate::ledger::meta::Action::Deleted {
                if let (Some(cancel_seq), Some(final_seq)) =
                    (explicit_offer_cancel, parsed_fields_u32(&node.fields, 4))
                {
                    if cancel_seq == final_seq {
                        continue;
                    }
                }
            }

            let Some(delta_gets) = amount_as_f64(&final_gets)
                .zip(amount_as_f64(&prev_gets))
                .map(|(final_v, prev_v)| (final_v - prev_v).abs())
            else {
                continue;
            };
            let Some(delta_pays) = amount_as_f64(&final_pays)
                .zip(amount_as_f64(&prev_pays))
                .map(|(final_v, prev_v)| (final_v - prev_v).abs())
            else {
                continue;
            };
            if delta_gets == 0.0 || delta_pays == 0.0 {
                continue;
            }

            let Some(gets_key) = amount_issue_key(&final_gets) else {
                continue;
            };
            let Some(pays_key) = amount_issue_key(&final_pays) else {
                continue;
            };

            let noswap = matches!(final_gets, crate::transaction::amount::Amount::Xrp(_))
                || (!matches!(final_pays, crate::transaction::amount::Amount::Xrp(_))
                    && gets_key < pays_key);

            let (currency_a, currency_b, volume_a, volume_b) = if noswap {
                (gets_key.clone(), pays_key.clone(), delta_gets, delta_pays)
            } else {
                (pays_key.clone(), gets_key.clone(), delta_pays, delta_gets)
            };
            if volume_b == 0.0 {
                continue;
            }
            let rate = volume_a / volume_b;
            let key = format!("{currency_a}|{currency_b}");
            let domain = parsed_fields_hash256(&node.fields, 34).map(hex::encode_upper);

            tally
                .entry(key)
                .and_modify(|(_, _, summary, existing_domain)| {
                    summary.volume_a += volume_a;
                    summary.volume_b += volume_b;
                    summary.high = summary.high.max(rate);
                    summary.low = summary.low.min(rate);
                    summary.close = rate;
                    if existing_domain.is_none() {
                        *existing_domain = domain.clone();
                    }
                })
                .or_insert((
                    currency_a,
                    currency_b,
                    BookChangeSummary {
                        volume_a,
                        volume_b,
                        high: rate,
                        low: rate,
                        open: rate,
                        close: rate,
                    },
                    domain,
                ));
        }
    }

    let changes: Vec<Value> = tally
        .into_values()
        .map(|(currency_a, currency_b, summary, domain)| {
            let mut value = json!({
                "currency_a": currency_a,
                "currency_b": currency_b,
                "volume_a": summary.volume_a.to_string(),
                "volume_b": summary.volume_b.to_string(),
                "high": summary.high.to_string(),
                "low": summary.low.to_string(),
                "open": summary.open.to_string(),
                "close": summary.close.to_string(),
            });
            if let Some(domain) = domain {
                value["domain"] = json!(domain);
            }
            value
        })
        .collect();

    Ok(json!({
        "type": "bookChanges",
        "validated": explicit_ledger,
        "ledger_index": requested_seq,
        "ledger_hash": hex::encode_upper(header.hash),
        "ledger_time": header.close_time,
        "changes": changes,
    }))
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
        return Err(RpcError::internal(
            "historical account_offers not available",
        ));
    } else {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if ls.get_account(&account_id).is_none() {
            return Err(RpcError::not_found(address));
        }
        let mut offers: Vec<crate::ledger::offer::Offer> = ls
            .offers_by_account(&account_id)
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
    code: &'static str,
    numeric: i32,
    message: &'static str,
}

impl EngineResult {
    const SUCCESS: Self = Self {
        code: "tesSUCCESS",
        numeric: 0,
        message: "The transaction was applied.",
    };
    const BAD_SIGNATURE: Self = Self {
        code: "temBAD_SIGNATURE",
        numeric: -281,
        message: "Transaction's signing key is not authorized.",
    };
    const BAD_AUTH: Self = Self {
        code: "temBAD_AUTH_MASTER",
        numeric: -272,
        message: "The transaction's signing key is not authorized by the account.",
    };
    const NO_ACCOUNT: Self = Self {
        code: "terNO_ACCOUNT",
        numeric: -96,
        message: "The account does not exist.",
    };
    const PAST_SEQ: Self = Self {
        code: "tefPAST_SEQ",
        numeric: -190,
        message: "This sequence number has already passed.",
    };
    const PRE_SEQ: Self = Self {
        code: "terPRE_SEQ",
        numeric: -95,
        message: "Missing/inapplicable prior transaction.",
    };
    const INSUF_FEE: Self = Self {
        code: "terINSUF_FEE_B",
        numeric: -97,
        message: "Account balance can't pay fee.",
    };
    const INSUFFICIENT_PAYMENT: Self = Self {
        code: "tecINSUFFICIENT_FUNDS",
        numeric: 148,
        message: "Insufficient balance to send.",
    };
    const INSUF_RESERVE: Self = Self {
        code: "tecINSUFFICIENT_RESERVE",
        numeric: 141,
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

    let blob =
        hex::decode(blob_hex).map_err(|_| RpcError::invalid_params("tx_blob is not valid hex"))?;

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
        Ok(p) => p,
        Err(e) => return Err(RpcError::invalid_params(&format!("tx parse error: {e}"))),
    };

    // ── 1. Signature verification ─────────────────────────────────────────────
    let sig_ok = if parsed.signing_pubkey.first() == Some(&0xED)
        && parsed.signing_pubkey.len() == 33
    {
        // Ed25519 key (0xED prefix + 32-byte key)
        let ed_key = &parsed.signing_pubkey[1..]; // strip 0xED prefix
        use ed25519_dalek::Verifier;
        (|| -> bool {
            let Ok(sig_bytes): Result<[u8; 64], _> = parsed.signature.as_slice().try_into() else {
                return false;
            };
            let Ok(pk_bytes): Result<[u8; 32], _> = ed_key.try_into() else {
                return false;
            };
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) else {
                return false;
            };
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
            &EngineResult::BAD_SIGNATURE,
            ctx,
            blob_hex,
            &tx_hash_hex,
            parsed.sequence,
            parsed.sequence,
        ));
    }

    // ── 2–3. Look up account (used for regular key check + existence) ────────
    let account_root = if let Some(ref cl) = ctx.closed_ledger {
        use crate::ledger::views::ReadView;
        let kl = crate::ledger::keylet::account(&parsed.account);
        cl.read(&kl)
            .and_then(|sle| crate::ledger::AccountRoot::decode(sle.data()).ok())
    } else {
        ctx.ledger_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_account(&parsed.account)
            .cloned()
    };

    // ── 2. Confirm the signing key matches the account ────────────────────────
    // Accept the master key OR the regular key (if set).
    let derived_account = crate::crypto::account_id(&parsed.signing_pubkey);
    if derived_account != parsed.account {
        let is_regular = account_root
            .as_ref()
            .and_then(|a| a.regular_key)
            .map(|rk| rk == derived_account)
            .unwrap_or(false);
        if !is_regular {
            return Ok(engine_result_response(
                &EngineResult::BAD_AUTH,
                ctx,
                blob_hex,
                &tx_hash_hex,
                parsed.sequence,
                parsed.sequence,
            ));
        }
    }

    // ── 3. Account existence ──────────────────────────────────────────────────
    let account_root = match account_root {
        Some(r) => r,
        None => {
            return Ok(engine_result_response(
                &EngineResult::NO_ACCOUNT,
                ctx,
                blob_hex,
                &tx_hash_hex,
                0,
                0,
            ))
        }
    };

    // Account for pending transactions in the pool when checking sequence.
    let pending_from_account = ctx
        .tx_pool
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .count_by_account(&parsed.account);
    let next_seq = account_root.sequence + pending_from_account as u32;
    let avail_seq = next_seq + 1;

    // ── 4. Sequence number check ──────────────────────────────────────────────
    if parsed.sequence < account_root.sequence {
        return Ok(engine_result_response(
            &EngineResult::PAST_SEQ,
            ctx,
            blob_hex,
            &tx_hash_hex,
            avail_seq,
            next_seq,
        ));
    }
    if parsed.sequence > next_seq {
        return Ok(engine_result_response(
            &EngineResult::PRE_SEQ,
            ctx,
            blob_hex,
            &tx_hash_hex,
            avail_seq,
            next_seq,
        ));
    }

    // ── 5. Minimum fee check ──────────────────────────────────────────────────
    if parsed.fee < ctx.fees.base {
        return Ok(engine_result_response(
            &EngineResult::INSUF_FEE,
            ctx,
            blob_hex,
            &tx_hash_hex,
            avail_seq,
            next_seq,
        ));
    }

    // ── 6. Balance checks ─────────────────────────────────────────────────────
    if account_root.balance < parsed.fee {
        return Ok(engine_result_response(
            &EngineResult::INSUF_FEE,
            ctx,
            blob_hex,
            &tx_hash_hex,
            avail_seq,
            next_seq,
        ));
    }
    if let Some(send) = parsed.amount_drops {
        let total = send.saturating_add(parsed.fee);
        if account_root.balance < total {
            return Ok(engine_result_response(
                &EngineResult::INSUFFICIENT_PAYMENT,
                ctx,
                blob_hex,
                &tx_hash_hex,
                avail_seq,
                next_seq,
            ));
        }
    }

    // ── 6. Reserve check ────────────────────────────────────────────────────
    // Account reserves use `base_reserve + owner_count * owner_reserve`.
    // These values ideally come from the FeeSettings ledger object. Until that
    // object is parsed, the handler uses the current mainnet defaults.
    {
        let reserve = ctx.fees.reserve + (account_root.owner_count as u64) * ctx.fees.increment;
        let spend = parsed.fee.saturating_add(parsed.amount_drops.unwrap_or(0));
        if account_root.balance.saturating_sub(spend) < reserve {
            // Allow the tx if it would *decrease* owner count (e.g., OfferCancel, TrustSet to 0)
            // For simplicity, only enforce on txs that increase obligations
            // Only block txs that strictly increase obligations.
            // TrustSet, NFTokenBurn, SignerListSet can decrease owner_count
            // and should NOT be blocked — they may free reserve.
            if matches!(
                parsed.tx_type,
                0  | // Payment (sends XRP)
                1  | // EscrowCreate (locks XRP + owner_count++)
                7  | // OfferCreate (owner_count++)
                10 | // TicketCreate (owner_count++)
                16 | // CheckCreate (owner_count++)
                19 | // DepositPreauth (owner_count++)
                25 // NFTokenMint (owner_count++)
            ) {
                return Ok(engine_result_response(
                    &EngineResult::INSUF_RESERVE,
                    ctx,
                    blob_hex,
                    &tx_hash_hex,
                    avail_seq,
                    next_seq,
                ));
            }
        }
    }

    // ── All checks passed — add to transaction pool and broadcast ───────────
    ctx.tx_pool
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(tx_hash, blob.clone(), &parsed);
    ctx.broadcast_queue
        .push(crate::network::relay::encode_transaction(&blob));

    Ok(engine_result_response(
        &EngineResult::SUCCESS,
        ctx,
        blob_hex,
        &tx_hash_hex,
        avail_seq,
        next_seq,
    ))
}

fn engine_result_response(
    res: &EngineResult,
    ctx: &NodeContext,
    blob_hex: &str,
    hash_hex: &str,
    seq_avail: u32,
    seq_next: u32,
) -> Value {
    let applied = res.numeric == 0;
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

pub fn transaction_entry(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let tx_hash = params
        .get("tx_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'tx_hash' field"))?;
    if tx_hash.len() != 64 {
        return Err(RpcError::invalid_params("tx_hash must be 64 hex chars"));
    }
    let hash_bytes =
        hex::decode(tx_hash).map_err(|_| RpcError::invalid_params("tx_hash must be hex"))?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);

    let ledger_seq = resolve_ledger_selector(params, ctx)?
        .ok_or_else(|| RpcError::invalid_params("ledger_index or ledger_hash is required"))?;
    let binary = parse_bool_field(params, "binary")?.unwrap_or(false);

    {
        let history = ctx.history.read().unwrap_or_else(|e| e.into_inner());
        if history.get_ledger(ledger_seq).is_none() && ledger_seq != ctx.ledger_seq {
            return Err(lgr_not_found());
        }
    }

    let rec = ctx
        .history
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get_tx(&hash)
        .cloned()
        .or_else(|| ctx.storage.as_ref().and_then(|s| s.lookup_tx(&hash)))
        .filter(|rec| rec.ledger_seq == ledger_seq)
        .ok_or_else(txn_not_found)?;

    Ok(tx_record_response(&rec, ctx, binary))
}

pub fn tx(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let binary = parse_bool_field(params, "binary")?.unwrap_or(false);
    let min_ledger = parse_i32_field(params, "min_ledger")?;
    let max_ledger = parse_i32_field(params, "max_ledger")?;
    let hash = match (
        params.get("transaction").and_then(Value::as_str),
        params.get("ctid").and_then(Value::as_str),
    ) {
        (Some(_), Some(_)) => {
            return Err(RpcError::invalid_params(
                "Specify only one of 'transaction' or 'ctid'.",
            ))
        }
        (None, None) => return Err(RpcError::invalid_params("missing 'transaction' field")),
        (Some(hash_str), None) => {
            if hash_str.len() != 64 {
                return Err(RpcError::invalid_params(
                    "transaction hash must be 64 hex chars",
                ));
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
            ctx.history
                .read()
                .unwrap_or_else(|e| e.into_inner())
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

    let rec = hash.and_then(|hash| {
        ctx.history
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get_tx(&hash)
            .cloned()
            .or_else(|| {
                // Fall back to persistent storage for persisted transactions
                ctx.storage.as_ref().and_then(|s| s.lookup_tx(&hash))
            })
    });

    if let Some((min, max)) = ledger_range {
        match rec {
            Some(rec) if rec.ledger_seq >= min && rec.ledger_seq <= max => {
                return Ok(tx_record_response(&rec, ctx, binary));
            }
            Some(_) => {
                return Err(txn_not_found_searched_all(false));
            }
            None => {
                let searched_all = ctx
                    .history
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .covers_ledger_range(min, max)
                    || ctx
                        .storage
                        .as_ref()
                        .map(|s| s.has_full_ledger_range(min, max))
                        .unwrap_or(false);
                return Err(txn_not_found_searched_all(searched_all));
            }
        }
    }

    let rec = rec.ok_or_else(txn_not_found)?;

    Ok(tx_record_response(&rec, ctx, binary))
}

pub fn tx_history(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let start = params
        .get("start")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::invalid_params("missing 'start' field"))? as usize;
    let limit = parse_limit_field(params, 20, 200)?;

    let txs = ctx
        .history
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .tx_history_page(start, limit);

    let txs_json: Vec<Value> = txs
        .into_iter()
        .map(|rec| {
            if let Ok(parsed) = crate::transaction::parse_blob(&rec.blob) {
                let mut tx = parsed_tx_json(&parsed);
                tx["hash"] = json!(hex::encode_upper(rec.hash));
                tx["ledger_index"] = json!(rec.ledger_seq);
                tx
            } else {
                json!({
                    "hash": hex::encode_upper(rec.hash),
                    "ledger_index": rec.ledger_seq,
                    "tx_blob": hex::encode_upper(rec.blob),
                })
            }
        })
        .collect();

    Ok(json!({
        "index": start,
        "txs": txs_json,
    }))
}

// ── ledger ────────────────────────────────────────────────────────────────────

pub fn ledger(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let (seq, hdr, tx_hashes) = lookup_requested_ledger(params, ctx)?;

    let hash_hex = hex::encode_upper(hdr.hash);
    let parent_hex = hex::encode_upper(hdr.parent_hash);
    let tx_hash_hex = hex::encode_upper(hdr.transaction_hash);
    let account_hex = hex::encode_upper(hdr.account_hash);

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
            "parent_close_time": hdr.parent_close_time,
            "close_time_resolution": hdr.close_time_resolution,
            "close_flags": hdr.close_flags,
        },
        "ledger_hash":  hash_hex,
        "ledger_index": seq,
        "validated":    true,
    });

    // Include transactions if requested
    if params
        .get("transactions")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let tx_list: Vec<String> = tx_hashes.iter().map(hex::encode_upper).collect();
        response["ledger"]["transactions"] = json!(tx_list);
    }

    Ok(response)
}

pub fn ledger_header(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let (_, hdr, _) = lookup_requested_ledger(params, ctx)?;
    let mut response = ledger(params, ctx)?;
    response["ledger_data"] = json!(hex::encode_upper(serialize_ledger_header_blob(&hdr)));
    Ok(response)
}

pub fn ledger_request(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    ledger(params, ctx)
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

fn sle_account_field(parsed: &crate::ledger::meta::ParsedSLE, field_code: u16) -> Option<[u8; 20]> {
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

fn sle_u32_field(parsed: &crate::ledger::meta::ParsedSLE, field_code: u16) -> Option<u32> {
    parsed.fields.iter().find_map(|field| {
        if field.type_code == 2 && field.field_code == field_code && field.data.len() >= 4 {
            Some(u32::from_be_bytes(field.data[..4].try_into().ok()?))
        } else {
            None
        }
    })
}

fn sle_hash256_field(parsed: &crate::ledger::meta::ParsedSLE, field_code: u16) -> Option<[u8; 32]> {
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

fn sle_blob_field(parsed: &crate::ledger::meta::ParsedSLE, field_code: u16) -> Option<Vec<u8>> {
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
        0x0079 => "AMM",
        0x007e => "MPTokenIssuance",
        0x007f => "MPToken",
        0x0081 => "Credential",
        0x0084 => "Vault",
        other => return format!("Unknown({other:#06x})"),
    }
    .to_string()
}

fn parse_nft_page_tokens(raw: &[u8]) -> Option<Vec<crate::ledger::nft_page::PageToken>> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    if parsed.entry_type != 0x0050 {
        return None;
    }
    let array = parsed
        .fields
        .iter()
        .find(|f| f.type_code == 15 && f.field_code == 10)?;
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
                    let (len, consumed) =
                        crate::transaction::serialize::decode_length(&array.data[pos..]);
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
            "state" | "offer" | "check" | "escrow" | "payment_channel" | "ticket"
            | "deposit_preauth" | "did" | "nft_page" | "nft_offer" => Ok(Some(s.clone())),
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
            out["Account"] = json!(crate::crypto::base58::encode_account(&sle_account_field(
                &parsed, 1
            )?));
            out["Destination"] = json!(crate::crypto::base58::encode_account(&sle_account_field(
                &parsed, 3
            )?));
            out["SendMax"] = format_amount(&sle_amount_field(&parsed, 9)?);
        }
        0x0075 => {
            out["Account"] = json!(crate::crypto::base58::encode_account(&sle_account_field(
                &parsed, 1
            )?));
            out["Destination"] = json!(crate::crypto::base58::encode_account(&sle_account_field(
                &parsed, 3
            )?));
            out["Amount"] = format_amount(&sle_amount_field(&parsed, 1)?);
        }
        0x0054 => {
            out["Account"] = json!(crate::crypto::base58::encode_account(&sle_account_field(
                &parsed, 1
            )?));
            out["TicketSequence"] = json!(sle_u32_field(&parsed, 41)?);
        }
        0x0070 => {
            out["Account"] = json!(crate::crypto::base58::encode_account(&sle_account_field(
                &parsed, 1
            )?));
            out["Authorize"] = json!(crate::crypto::base58::encode_account(&sle_account_field(
                &parsed, 5
            )?));
        }
        0x0037 => {
            out["Owner"] = json!(crate::crypto::base58::encode_account(&sle_account_field(
                &parsed, 2
            )?));
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
            out["Account"] = json!(crate::crypto::base58::encode_account(&sle_account_field(
                &parsed, 1
            )?));
            if let Some(uri) = sle_blob_field(&parsed, 5) {
                out["URI"] = json!(hex::encode_upper(uri));
            }
        }
        0x0050 => {
            let tokens = parse_nft_page_tokens(raw)?;
            out["NFTokens"] = json!(tokens
                .iter()
                .map(|t| hex::encode_upper(t.nftoken_id))
                .collect::<Vec<_>>());
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
                let seq =
                    parse_u32_value(map.get("seq").ok_or_else(|| invalid_field("offer"))?, "seq")?;
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
                    map.get("ticket_seq")
                        .ok_or_else(|| invalid_field("ticket"))?,
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
                    map.get("owner")
                        .ok_or_else(|| invalid_field("deposit_preauth"))?,
                    "owner",
                )?;
                let authorized = parse_account_value(
                    map.get("authorized")
                        .ok_or_else(|| invalid_field("deposit_preauth"))?,
                    "authorized",
                )?;
                Ok(crate::ledger::deposit_preauth::shamap_key(
                    &owner,
                    &authorized,
                ))
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
                    Ok(crate::ledger::trustline::shamap_key(
                        &account_a, &account_b, &currency,
                    ))
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
            let Some(parsed) = crate::ledger::meta::parse_sle(&raw) else {
                continue;
            };
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
            let Some(parsed) = crate::ledger::meta::parse_sle(raw) else {
                continue;
            };
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
        let (_, mut map) =
            historical_state_map(requested_seq, ctx, "historical account_nfts not available")?;
        if map
            .get(&crate::ledger::account::shamap_key(&account_id))
            .is_none()
        {
            return Err(RpcError::not_found(address));
        }
        for (key, raw) in collect_historical_state_entries(&mut map)? {
            let Some(parsed) = crate::ledger::meta::parse_sle(&raw) else {
                continue;
            };
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
            decode_account(s)
                .map_err(|_| RpcError::invalid_params("malformed destination account"))?,
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
            .filter(|(_, pc)| {
                destination_filter
                    .map(|d| pc.destination == d)
                    .unwrap_or(true)
            })
            .collect();
    } else {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        if ls.get_account(&account_id).is_none() {
            return Err(RpcError::not_found(address));
        }
        channels = ls
            .iter_paychans()
            .filter(|(_, pc)| pc.account == account_id)
            .filter(|(_, pc)| {
                destination_filter
                    .map(|d| pc.destination == d)
                    .unwrap_or(true)
            })
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
        return Err(RpcError::internal(
            "historical account_currencies not available",
        ));
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

pub fn noripple_check(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let account_str = params
        .get("account")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'account' field"))?;
    let account_id = parse_account_field(params, "account")?;
    let role = params
        .get("role")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing 'role' field"))?;
    let role_gateway = match role {
        "gateway" => true,
        "user" => false,
        _ => return Err(invalid_field("role")),
    };
    let limit = parse_limit_field(params, 300, 400)?;
    let include_transactions = parse_bool_field(params, "transactions")?.unwrap_or(false);
    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let ledger_hash = if requested_seq == ctx.ledger_seq {
        ctx.ledger_hash.clone()
    } else {
        hex::encode_upper(historical_ledger_header(requested_seq, ctx)?.hash)
    };

    let account_key = crate::ledger::account::shamap_key(&account_id);
    let account_raw = lookup_raw_object_at_ledger(&account_key, requested_seq, ctx)
        .ok_or_else(|| RpcError::not_found(account_str))?;
    let account_root = crate::ledger::AccountRoot::decode(&account_raw)
        .map_err(|_| RpcError::not_found(account_str))?;
    let mut result = json!({
        "ledger_hash": ledger_hash,
        "ledger_index": requested_seq,
        "validated": true,
        "problems": [],
    });

    let mut problems = Vec::new();
    let mut txs = Vec::new();
    let mut sequence = account_root.sequence;

    let default_ripple = account_root.flags & crate::ledger::account::LSF_DEFAULT_RIPPLE != 0;
    if default_ripple && !role_gateway {
        problems.push(json!(
            "You appear to have set your default ripple flag even though you are not a gateway. This is not recommended unless you are experimenting"
        ));
    } else if role_gateway && !default_ripple {
        problems.push(json!("You should immediately set your default ripple flag"));
        if include_transactions {
            txs.push(json!({
                "Account": account_str,
                "TransactionType": "AccountSet",
                "Sequence": sequence,
                "Fee": recommended_fee_drops(ctx),
                "SetFlag": 8,
            }));
            sequence = sequence.saturating_add(1);
        }
    }

    let trustlines = collect_account_trustlines(&account_id, requested_seq, ctx)?;
    for (_, tl) in trustlines {
        if problems.len() >= limit {
            break;
        }
        let is_low = account_id == tl.low_account;
        let no_ripple = if is_low {
            tl.flags & crate::ledger::trustline::LSF_LOW_NO_RIPPLE != 0
        } else {
            tl.flags & crate::ledger::trustline::LSF_HIGH_NO_RIPPLE != 0
        };
        let needs_fix = if role_gateway { no_ripple } else { !no_ripple };
        if !needs_fix {
            continue;
        }

        let peer = if is_low {
            tl.high_account
        } else {
            tl.low_account
        };
        let issue_limit = if is_low {
            tl.low_limit.clone()
        } else {
            tl.high_limit.clone()
        };
        let problem = if role_gateway {
            format!(
                "You should clear the no ripple flag on your {} line to {}",
                tl.currency.to_ascii(),
                crate::crypto::base58::encode_account(&peer)
            )
        } else {
            format!(
                "You should probably set the no ripple flag on your {} line to {}",
                tl.currency.to_ascii(),
                crate::crypto::base58::encode_account(&peer)
            )
        };
        problems.push(json!(problem));

        if include_transactions {
            txs.push(json!({
                "Account": account_str,
                "TransactionType": "TrustSet",
                "Sequence": sequence,
                "Fee": recommended_fee_drops(ctx),
                "LimitAmount": recommended_trust_set_limit(&tl.currency, &peer, &issue_limit),
                "Flags": if no_ripple { 0x0004_0000u32 } else { 0x0002_0000u32 },
            }));
            sequence = sequence.saturating_add(1);
        }
    }

    result["problems"] = Value::Array(problems);
    if include_transactions {
        result["transactions"] = Value::Array(txs);
    }
    Ok(result)
}

pub fn owner_info(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let address = params.get("account").and_then(Value::as_str).unwrap_or("");
    let account_data = account_info(params, ctx)?;
    let account_objects = account_objects(params, ctx)?;
    let account_lines = account_lines(params, ctx)?;
    let account_offers = account_offers(params, ctx)?;

    Ok(json!({
        "account": address,
        "account_data": account_data["account_data"].clone(),
        "ledger_current_index": ctx.ledger_seq,
        "validated": true,
        "account_objects": account_objects["account_objects"].clone(),
        "lines": account_lines["lines"].clone(),
        "offers": account_offers["offers"].clone(),
    }))
}

fn nft_offers_by_side(
    params: &Value,
    ctx: &NodeContext,
    want_sell: bool,
) -> Result<Value, RpcError> {
    let nft_id = parse_nft_id_field(params, "nft_id")?;
    let limit = parse_limit_field(params, 250, 500)?;
    let marker = parse_hex_key_marker(params)?;
    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let is_historical = requested_seq != ctx.ledger_seq;

    let mut offers: Vec<(crate::ledger::Key, crate::ledger::NFTokenOffer)> = Vec::new();
    let matches_side =
        |offer: &crate::ledger::NFTokenOffer| ((offer.flags & 0x0001) != 0) == want_sell;

    if is_historical {
        let (_, mut map) = historical_state_map(
            requested_seq,
            ctx,
            "historical NFT offer enumeration unavailable",
        )?;
        for (key, raw) in collect_historical_state_entries(&mut map)? {
            if let Some(offer) = crate::ledger::NFTokenOffer::decode_from_sle(&raw) {
                if offer.nftoken_id == nft_id && matches_side(&offer) {
                    offers.push((key, offer));
                }
            }
        }
    } else {
        let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
        offers = ls
            .iter_nft_offers()
            .filter(|(_, offer)| offer.nftoken_id == nft_id && matches_side(offer))
            .map(|(key, offer)| (*key, offer.clone()))
            .collect();
    }

    offers.sort_by_key(|(key, _)| key.0);
    if let Some(mark) = marker {
        if !offers.iter().any(|(key, _)| key.0 == mark) {
            return Err(invalid_field("marker"));
        }
    }

    let mut out = Vec::new();
    let mut next_marker = None;
    let mut last_returned = None;
    for (key, offer) in offers {
        if let Some(mark) = marker {
            if key.0 <= mark {
                continue;
            }
        }
        if out.len() == limit {
            next_marker = last_returned;
            break;
        }
        out.push(nft_offer_summary(key, &offer));
        last_returned = Some(key.0);
    }

    let mut result = json!({
        "nft_id": hex::encode_upper(nft_id),
        "offers": out,
    });
    if let Some(mark) = next_marker {
        result["marker"] = json!(hex::encode_upper(mark));
    }
    Ok(result)
}

pub fn nft_buy_offers(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    nft_offers_by_side(params, ctx, false)
}

pub fn nft_sell_offers(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    nft_offers_by_side(params, ctx, true)
}

pub fn amm_info(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);

    let (amm_key, amm_raw) = if params.get("asset").is_some() && params.get("asset2").is_some() {
        let issue1 = parse_issue_spec(
            params
                .get("asset")
                .ok_or_else(|| RpcError::invalid_params("missing 'asset' field"))?,
        )?;
        let issue2 = parse_issue_spec(
            params
                .get("asset2")
                .ok_or_else(|| RpcError::invalid_params("missing 'asset2' field"))?,
        )?;
        let key = crate::ledger::tx::amm_key(&issue1, &issue2);
        let raw = lookup_raw_object_at_ledger(&key, requested_seq, ctx)
            .ok_or_else(|| RpcError::not_found("amm"))?;
        (key, raw)
    } else if let Some(account) = params.get("amm_account") {
        let account_id = parse_account_value(account, "amm_account")?;
        let found = if requested_seq != ctx.ledger_seq {
            let (_, mut map) =
                historical_state_map(requested_seq, ctx, "historical AMM lookup unavailable")?;
            collect_historical_state_entries(&mut map)?
                .into_iter()
                .find(|(_, raw)| {
                    crate::ledger::meta::parse_sle(raw)
                        .map(|parsed| {
                            parsed.entry_type == 0x0079
                                && sle_account_field(&parsed, 1) == Some(account_id)
                        })
                        .unwrap_or(false)
                })
        } else {
            let ls = ctx.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            ls.iter_raw_entries()
                .into_iter()
                .find(|(_, raw)| {
                    crate::ledger::meta::parse_sle(raw)
                        .map(|parsed| {
                            parsed.entry_type == 0x0079
                                && sle_account_field(&parsed, 1) == Some(account_id)
                        })
                        .unwrap_or(false)
                })
                .map(|(key, raw)| (key, raw.to_vec()))
        };
        found.ok_or_else(|| RpcError::not_found("amm"))?
    } else {
        return Err(RpcError::invalid_params(
            "Provide either 'asset' and 'asset2', or 'amm_account'.",
        ));
    };

    let parsed =
        crate::ledger::meta::parse_sle(&amm_raw).ok_or_else(|| RpcError::not_found("amm"))?;
    if parsed.entry_type != 0x0079 {
        return Err(RpcError::not_found("amm"));
    }

    let issue1 = parsed
        .fields
        .iter()
        .find(|f| f.type_code == 24 && f.field_code == 3)
        .and_then(|f| crate::transaction::amount::Issue::from_bytes(&f.data))
        .map(|(issue, _)| issue)
        .ok_or_else(|| RpcError::internal("AMM asset missing"))?;
    let issue2 = parsed
        .fields
        .iter()
        .find(|f| f.type_code == 24 && f.field_code == 4)
        .and_then(|f| crate::transaction::amount::Issue::from_bytes(&f.data))
        .map(|(issue, _)| issue)
        .ok_or_else(|| RpcError::internal("AMM asset2 missing"))?;
    let trading_fee = parsed
        .fields
        .iter()
        .find(|f| f.type_code == 1 && f.field_code == 2 && f.data.len() == 2)
        .map(|f| u16::from_be_bytes([f.data[0], f.data[1]]) as u32)
        .unwrap_or(0);
    let pool1 = parsed
        .fields
        .iter()
        .find(|f| f.type_code == 9 && f.field_code == 10 && f.data.len() == 8)
        .map(|f| i64::from_be_bytes(f.data[..8].try_into().unwrap()))
        .unwrap_or(0);
    let pool2 = parsed
        .fields
        .iter()
        .find(|f| f.type_code == 9 && f.field_code == 11 && f.data.len() == 8)
        .map(|f| i64::from_be_bytes(f.data[..8].try_into().unwrap()))
        .unwrap_or(0);
    let lp_total = parsed
        .fields
        .iter()
        .find(|f| f.type_code == 9 && f.field_code == 12 && f.data.len() == 8)
        .map(|f| i64::from_be_bytes(f.data[..8].try_into().unwrap()))
        .unwrap_or(0);
    let account = sle_account_field(&parsed, 1)
        .map(|id| crate::crypto::base58::encode_account(&id))
        .unwrap_or_else(|| hex::encode_upper(amm_key.0));

    Ok(json!({
        "amm": {
            "amount": format_issue_quantity(&issue1, pool1),
            "amount2": format_issue_quantity(&issue2, pool2),
            "lp_token": json!({
                "value": lp_total.to_string(),
            }),
            "trading_fee": trading_fee,
            "account": account,
        }
    }))
}

pub fn vault_info(params: &Value, ctx: &NodeContext) -> Result<Value, RpcError> {
    let vault_key = if let Some(vault_id) = params.get("vault_id") {
        parse_key_from_hex(vault_id, "vault_id")?
    } else if params.get("owner").is_some() && params.get("seq").is_some() {
        let owner = parse_account_field(params, "owner")?;
        let seq = parse_u32_value(
            params.get("seq").ok_or_else(|| invalid_field("seq"))?,
            "seq",
        )?;
        crate::ledger::tx::vault_key(&owner, seq)
    } else {
        return Err(RpcError::invalid_params(
            "Provide either 'vault_id' or the combination of 'owner' and 'seq'.",
        ));
    };

    let requested_seq = resolve_ledger_selector(params, ctx)?.unwrap_or(ctx.ledger_seq);
    let vault_raw = lookup_raw_object_at_ledger(&vault_key, requested_seq, ctx)
        .ok_or_else(|| RpcError::not_found("vault"))?;
    let mut vault = raw_object_summary(&vault_key.0, &vault_raw).unwrap_or_else(|| {
        json!({
            "LedgerEntryType": "Vault",
            "index": hex::encode_upper(vault_key.0),
        })
    });

    if let Some(share_mptid) = crate::ledger::tx::vault_sle_share_mptid(&vault_raw) {
        let issuance_key = crate::ledger::tx::vault_mpt_issuance_key(&share_mptid);
        if let Some(share_raw) = lookup_raw_object_at_ledger(&issuance_key, requested_seq, ctx) {
            vault["shares"] =
                raw_object_summary(&issuance_key.0, &share_raw).unwrap_or_else(|| {
                    json!({
                        "index": hex::encode_upper(issuance_key.0),
                    })
                });
        }
    }

    Ok(json!({ "vault": vault }))
}

pub fn random() -> Result<Value, RpcError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Generate 256 random bits (32 bytes) using a simple entropy source.
    // Hash timestamp + pid for uniqueness.
    let seed = format!(
        "{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        std::process::id(),
    );
    let hash = crate::crypto::sha512_first_half(seed.as_bytes());
    Ok(json!({
        "random": hex::encode_upper(hash),
    }))
}

// ── ledger_closed ─────────────────────────────────────────────────────────────

pub fn ledger_closed(ctx: &NodeContext) -> Result<Value, RpcError> {
    let snapshot = ctx
        .ledger_master_snapshot
        .as_ref()
        .cloned()
        .unwrap_or_default();
    Ok(json!({
        "ledger_hash": if snapshot.validated_hash.is_empty() { ctx.ledger_hash.clone() } else { snapshot.validated_hash },
        "ledger_index": if snapshot.validated_seq == 0 { ctx.ledger_seq } else { snapshot.validated_seq },
    }))
}

// ── ledger_current ────────────────────────────────────────────────────────────

pub fn ledger_current(ctx: &NodeContext) -> Result<Value, RpcError> {
    let snapshot = ctx
        .open_ledger_snapshot
        .as_ref()
        .cloned()
        .unwrap_or_default();
    Ok(json!({
        "ledger_current_index": if snapshot.ledger_current_index == 0 {
            ctx.ledger_seq + 1
        } else {
            snapshot.ledger_current_index
        },
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
        let dest_sle = cl.read(&dest_kl).ok_or_else(|| RpcError {
            code: "actNotFound",
            error_code: 19,
            message: "Destination account not found.".into(),
            extra: None,
        })?;
        let dest_acct =
            crate::ledger::AccountRoot::decode(dest_sle.data()).map_err(|_| RpcError {
                code: "actNotFound",
                error_code: 19,
                message: "Destination account not found.".into(),
                extra: None,
            })?;
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
        let dest_acct = state.get_account(&dest_id).ok_or_else(|| RpcError {
            code: "actNotFound",
            error_code: 19,
            message: "Destination account not found.".into(),
            extra: None,
        })?;
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
    use crate::rpc::{dispatch, NodeContext, RpcRequest, RpcSnapshot};

    fn ctx() -> NodeContext {
        NodeContext {
            ledger_seq: 1000,
            ledger_hash: "A".repeat(64),
            admin_rpc_enabled: true,
            ..Default::default()
        }
    }

    fn req(method: &str, params: Value) -> RpcRequest {
        RpcRequest {
            method: method.into(),
            params,
            id: json!(1),
        }
    }

    // ── server_info ───────────────────────────────────────────────────────────

    #[test]
    fn test_server_info_shape() {
        let mut c = ctx();
        c.open_ledger_snapshot = Some(crate::ledger::open_ledger::OpenLedgerSnapshot {
            ledger_current_index: 1001,
            parent_ledger_index: 1000,
            parent_hash: "AA".repeat(32),
            last_close_time: 1,
            queued_transactions: 12,
            candidate_set_hash: "BB".repeat(32),
            escalation_multiplier: crate::ledger::pool::BASE_LEVEL * 500,
            txns_expected: 32,
            max_queue_size: 2000,
            open_fee_level: crate::ledger::pool::BASE_LEVEL * 2,
            revision: 9,
            modify_count: 4,
            accept_count: 3,
            last_modified_unix: 77,
            last_accept_unix: 88,
            ..Default::default()
        });
        let resp = dispatch(req("server_info", json!({})), &mut c);
        let r = &resp.result;
        assert_eq!(r["status"], "success");
        assert!(r["info"]["build_version"].is_string());
        assert_eq!(r["info"]["validated_ledger"]["seq"], 1000);
        assert!(r["info"]["tracked_inbound_ledgers"].is_number());
        assert!(r["info"]["failed_inbound_ledgers"].is_number());
        assert_eq!(r["info"]["open_ledger_revision"], json!(9));
        assert_eq!(r["info"]["open_ledger_accept_count"], json!(3));
        assert!(r["info"]["state_accounting"]["disconnected"]["transitions"].is_string());
        assert!(r["info"]["server_state_duration_us"].is_string());
        // server_state depends on ledger age, sync state, and peer availability.
        let state = r["info"]["server_state"].as_str().unwrap();
        assert!(["full", "tracking", "syncing", "connected", "disconnected"].contains(&state));
    }

    #[test]
    fn test_server_info_complete_ledgers() {
        let mut c = ctx();
        // Populate history so complete_ledgers is non-empty
        let hdr = crate::ledger::LedgerHeader {
            sequence: 1000,
            hash: [0u8; 32],
            parent_hash: [0u8; 32],
            close_time: 0,
            total_coins: 0,
            account_hash: [0u8; 32],
            transaction_hash: [0u8; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };
        c.history.write().unwrap().insert_ledger(hdr, vec![]);
        let resp = dispatch(req("server_info", json!({})), &mut c);
        assert_eq!(resp.result["info"]["complete_ledgers"], "1000-1000");
    }

    #[test]
    fn test_server_info_reports_waiting_network_ledger_during_initial_sync() {
        let mut c = NodeContext::default();
        c.admin_rpc_enabled = true;
        let resp = dispatch(req("server_info", json!({})), &mut c);
        assert_eq!(resp.result["info"]["network_ledger"], json!("waiting"));
    }

    #[test]
    fn test_server_info_reports_human_load_factor() {
        let mut c = ctx();
        c.load_snapshot.local_fee = crate::network::load::LOAD_BASE * 2;
        let resp = dispatch(req("server_info", json!({})), &mut c);
        assert_eq!(resp.result["info"]["load_factor"], json!(2.0));
        assert_eq!(resp.result["info"]["load_factor_local"], json!(2.0));
    }

    #[test]
    fn test_server_state_uses_state_envelope_and_numeric_load_fields() {
        let mut c = ctx();
        c.load_snapshot.local_fee = crate::network::load::LOAD_BASE * 3;
        c.open_ledger_snapshot = Some(crate::ledger::open_ledger::OpenLedgerSnapshot {
            ledger_current_index: 1002,
            parent_ledger_index: 1001,
            parent_hash: "CC".repeat(32),
            last_close_time: 2,
            queued_transactions: 4,
            candidate_set_hash: "DD".repeat(32),
            escalation_multiplier: crate::ledger::pool::BASE_LEVEL * 500,
            txns_expected: 32,
            max_queue_size: 2000,
            open_fee_level: crate::ledger::pool::BASE_LEVEL * 2,
            revision: 11,
            modify_count: 5,
            accept_count: 4,
            last_modified_unix: 91,
            last_accept_unix: 92,
            ..Default::default()
        });
        let resp = dispatch(req("server_state", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert!(resp.result.get("info").is_none());
        assert_eq!(
            resp.result["state"]["load_base"],
            json!(crate::network::load::LOAD_BASE)
        );
        assert_eq!(
            resp.result["state"]["load_factor"],
            json!(crate::network::load::LOAD_BASE * 3)
        );
        assert_eq!(
            resp.result["state"]["load_factor_local"],
            json!(crate::network::load::LOAD_BASE * 3)
        );
        assert!(
            resp.result["state"]["state_accounting"]["disconnected"]["duration_us"].is_string()
        );
        assert!(resp.result["state"]["server_state_duration_us"].is_string());
        assert_eq!(
            resp.result["state"]["open_ledger_revision"],
            json!(11)
        );
        assert_eq!(
            resp.result["state"]["open_ledger_last_accept_unix"],
            json!(92)
        );
    }

    #[test]
    fn test_server_state_reports_waiting_network_ledger_during_initial_sync() {
        let mut c = NodeContext::default();
        c.admin_rpc_enabled = true;
        let resp = dispatch(req("server_state", json!({})), &mut c);
        assert_eq!(resp.result["state"]["network_ledger"], json!("waiting"));
    }

    #[test]
    fn test_server_state_snapshot_uses_state_envelope() {
        let snap = RpcSnapshot {
            standalone_mode: true,
            state_accounting_snapshot: Some(
                crate::network::ops::synthetic_state_accounting_snapshot(
                    std::time::Instant::now(),
                    "syncing",
                    std::time::Instant::now(),
                ),
            ),
            ..Default::default()
        };

        let resp = server_state_snapshot(&snap).unwrap();
        assert!(resp.get("info").is_none());
        assert!(resp["state"]["standalone"].is_boolean());
        assert!(resp["state"]["state_accounting"]["syncing"]["transitions"].is_string());
    }

    #[test]
    fn test_server_info_uses_validator_list_quorum() {
        let mut c = ctx();
        c.validator_list_manager = Some(std::sync::Arc::new(std::sync::Mutex::new(
            crate::validator_list::ValidatorListManager::new(
                vec![vec![1u8; 33], vec![2u8; 33]],
                1,
            ),
        )));
        let resp = dispatch(req("server_info", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["info"]["validation_quorum"], json!(2));
    }

    #[test]
    fn test_server_state_uses_validator_list_quorum() {
        let mut c = ctx();
        c.validator_list_manager = Some(std::sync::Arc::new(std::sync::Mutex::new(
            crate::validator_list::ValidatorListManager::new(
                vec![vec![1u8; 33], vec![2u8; 33]],
                1,
            ),
        )));
        let resp = dispatch(req("server_state", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["state"]["validation_quorum"], json!(2));
    }

    #[test]
    fn test_version_shape() {
        let resp = dispatch(req("version", json!({})), &mut ctx());
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["version"]["first"], "1.0.0");
        assert_eq!(resp.result["version"]["good"], "1.0.0");
        assert_eq!(resp.result["version"]["last"], "1.0.0");
    }

    #[test]
    fn test_consensus_info_idle_shape() {
        let resp = dispatch(req("consensus_info", json!({})), &mut ctx());
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["info"]["phase"], "idle");
        assert_eq!(resp.result["info"]["consensus"], "idle");
    }

    #[test]
    fn test_consensus_info_active_shape() {
        let mut c = ctx();
        c.consensus_info = Some(crate::rpc::ConsensusInfoSnapshot {
            ledger_seq: 1001,
            phase: "establish".to_string(),
            mode: "proposing".to_string(),
            consensus: "yes".to_string(),
            proposers: 28,
            validations: 22,
            disputes: 3,
            quorum: 29,
            converge_percent: 88,
            elapsed_ms: 1200,
            previous_ledger: "AB".repeat(32),
            our_position: Some("CD".repeat(32)),
        });
        let resp = dispatch(req("consensus_info", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["info"]["phase"], "establish");
        assert_eq!(resp.result["info"]["quorum"], 29);
    }

    #[test]
    fn test_ledger_header_includes_blob() {
        let resp = dispatch(
            req("ledger_header", json!({"ledger_index": "validated"})),
            &mut ctx(),
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["ledger"]["ledger_index"], "1000");
        assert!(resp.result["ledger_data"].as_str().unwrap().len() > 10);
    }

    #[test]
    fn test_ledger_request_reuses_ledger_lookup() {
        let mut c = ctx();
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
        c.history.write().unwrap().insert_ledger(hdr, vec![]);
        let resp = dispatch(req("ledger_request", json!({"ledger_index": 500})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["ledger"]["ledger_index"], "500");
    }

    #[test]
    fn test_get_counts_requires_admin_rpc() {
        let mut c = ctx();
        c.admin_rpc_enabled = false;
        let resp = dispatch(req("get_counts", json!({})), &mut c);
        assert_eq!(resp.result["error"], "forbidden");
    }

    #[test]
    fn test_get_counts_shape() {
        let mut c = ctx_with_genesis();
        c.admin_rpc_enabled = true;
        let resp = dispatch(req("get_counts", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert!(resp.result["ledger_count"].is_number());
        assert!(resp.result["transaction_count"].is_number());
        assert!(resp.result["state_account_count"].is_number());
    }

    #[test]
    fn test_fetch_info_shape_and_clear_flag() {
        let mut c = ctx();
        let clear_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        c.fetch_info = Some(crate::rpc::FetchInfoSnapshot {
            key: "348928".to_string(),
            hash: "C2".repeat(32),
            have_header: true,
            have_state: false,
            have_transactions: false,
            needed_state_hashes: vec!["BF".repeat(32)],
            backend_fetch_errors: 2,
            peers: 2,
            timeouts: 1,
            in_flight: 8,
            inner_nodes: 12,
            state_nodes: 34,
            pass: 3,
            new_objects: 55,
            tail_stuck_hash: Some("AA".repeat(32)),
            tail_stuck_retries: 4,
        });
        c.sync_clear_requested = Some(clear_flag.clone());
        let resp = dispatch(req("fetch_info", json!({"clear": true})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["info"]["348928"]["peers"], 2);
        assert_eq!(resp.result["info"]["348928"]["have_header"], true);
        assert_eq!(resp.result["info"]["348928"]["have_state"], false);
        assert_eq!(resp.result["info"]["348928"]["backend_fetch_errors"], 2);
        assert_eq!(resp.result["info"]["348928"]["timeouts"], 1);
        assert!(clear_flag.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_manifest_requires_node_public_key() {
        let resp = dispatch(
            req("manifest", json!({"public_key": "not-a-key"})),
            &mut ctx(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_manifest_returns_requested_key_when_unknown() {
        let public_key =
            crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, &[7u8; 33]);
        let resp = dispatch(
            req("manifest", json!({"public_key": public_key})),
            &mut ctx(),
        );
        assert_eq!(resp.result["status"], "success");
        assert!(resp.result["requested"].is_string());
    }

    #[test]
    fn test_manifest_returns_cached_manifest_details() {
        let master = crate::crypto::keys::Secp256k1KeyPair::generate();
        let signing = crate::crypto::keys::Secp256k1KeyPair::generate();
        let manifest = crate::consensus::Manifest::new_signed(7, &master, &signing);
        let signing_b58 = crate::crypto::base58::encode(
            crate::crypto::base58::PREFIX_NODE_PUBLIC,
            &signing.public_key_bytes(),
        );
        let mut cache = crate::consensus::ManifestCache::new();
        assert!(cache.add(manifest.clone()));
        let mut c = ctx();
        c.manifest_cache = Some(std::sync::Arc::new(std::sync::Mutex::new(cache)));
        let resp = dispatch(req("manifest", json!({"public_key": signing_b58})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(
            resp.result["details"]["master_key"],
            crate::crypto::base58::encode(
                crate::crypto::base58::PREFIX_NODE_PUBLIC,
                &master.public_key_bytes()
            )
        );
        assert_eq!(resp.result["details"]["seq"], 7);
        assert!(resp.result["manifest"].is_string());
    }

    #[test]
    fn test_validator_info_requires_validator_mode() {
        let resp = dispatch(req("validator_info", json!({})), &mut ctx());
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_validator_info_shape() {
        let mut c = ctx();
        c.validator_key =
            crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, &[2u8; 33]);
        let resp = dispatch(req("validator_info", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["master_key"].as_str().unwrap(), c.validator_key);
        assert!(resp.result.get("ephemeral_key").is_none());
        assert!(resp.result.get("manifest").is_none());
    }

    #[test]
    fn test_validator_info_uses_cached_manifest_details() {
        let master = crate::crypto::keys::Secp256k1KeyPair::generate();
        let signing = crate::crypto::keys::Secp256k1KeyPair::generate();
        let manifest = crate::consensus::Manifest::new_signed(11, &master, &signing);
        let signing_b58 = crate::crypto::base58::encode(
            crate::crypto::base58::PREFIX_NODE_PUBLIC,
            &signing.public_key_bytes(),
        );
        let master_b58 = crate::crypto::base58::encode(
            crate::crypto::base58::PREFIX_NODE_PUBLIC,
            &master.public_key_bytes(),
        );
        let mut cache = crate::consensus::ManifestCache::new();
        assert!(cache.add(manifest.clone()));

        let mut c = ctx();
        c.validator_key = signing_b58.clone();
        c.manifest_cache = Some(std::sync::Arc::new(std::sync::Mutex::new(cache)));

        let resp = dispatch(req("validator_info", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["master_key"], master_b58);
        assert_eq!(resp.result["ephemeral_key"], signing_b58);
        assert_eq!(resp.result["seq"], 11);
        assert!(resp.result["manifest"].is_string());
    }

    #[test]
    fn test_can_delete_sets_target() {
        let mut c = ctx();
        let target = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        c.can_delete_target = Some(target.clone());
        c.online_delete = Some(256);
        let resp = dispatch(req("can_delete", json!({"can_delete": 500})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["can_delete"], 500);
        assert_eq!(target.load(std::sync::atomic::Ordering::SeqCst), 500);
    }

    #[test]
    fn test_can_delete_accepts_now_keyword() {
        let mut c = ctx();
        c.ledger_seq = 777;
        let target = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        c.can_delete_target = Some(target.clone());

        let resp = dispatch(req("can_delete", json!({"can_delete": "now"})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["can_delete"], 777);
        assert_eq!(target.load(std::sync::atomic::Ordering::SeqCst), 777);
    }

    #[test]
    fn test_can_delete_accepts_ledger_hash() {
        let mut c = ctx();
        let target = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        c.can_delete_target = Some(target.clone());
        let header = test_header(11);
        c.history
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert_ledger(header.clone(), vec![]);

        let resp = dispatch(
            req("can_delete", json!({"can_delete": hex::encode_upper(header.hash)})),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["can_delete"], 11);
        assert_eq!(target.load(std::sync::atomic::Ordering::SeqCst), 11);
    }

    #[test]
    fn test_connect_queues_peer() {
        let mut c = ctx();
        let queue = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        c.connect_requests = Some(queue.clone());
        let resp = dispatch(
            req("connect", json!({"ip": "127.0.0.1", "port": 51235})),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(queue.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_stop_sets_shutdown_flag() {
        let mut c = ctx();
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        c.shutdown_requested = Some(flag.clone());
        let resp = dispatch(req("stop", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_wallet_propose_from_seed_matches_genesis_account() {
        let resp = dispatch(
            req(
                "wallet_propose",
                json!({"seed": "snoPBrXtMeMyMHUVTgbuqAfg1SUTb"}),
            ),
            &mut ctx(),
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(
            resp.result["account_id"],
            "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
        );
        assert_eq!(resp.result["key_type"], "secp256k1");
    }

    #[test]
    fn test_validation_create_from_seed_is_deterministic() {
        let mut c = ctx();
        let resp = dispatch(
            req(
                "validation_create",
                json!({"seed": "snoPBrXtMeMyMHUVTgbuqAfg1SUTb"}),
            ),
            &mut c,
        );
        let expected =
            crate::crypto::keys::Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb")
                .unwrap();
        assert_eq!(resp.result["status"], "success");
        assert_eq!(
            resp.result["validation_public_key"],
            crate::crypto::base58::encode(
                crate::crypto::base58::PREFIX_NODE_PUBLIC,
                &expected.public_key_bytes(),
            )
        );
    }

    #[test]
    fn test_tx_history_returns_recent_transactions() {
        let (mut c, _) = ctx_with_account_tx_history();
        let resp = dispatch(req("tx_history", json!({"start": 0})), &mut c);
        assert_eq!(resp.result["status"], "success");
        let txs = resp.result["txs"].as_array().unwrap();
        assert!(!txs.is_empty());
        assert!(txs[0]["hash"].is_string());
        assert!(txs[0]["TransactionType"].is_string());
    }

    #[test]
    fn test_validator_list_sites_shape() {
        let statuses =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::from([(
                "https://vl.example".to_string(),
                crate::validator_list::ValidatorSiteStatus {
                    uri: "https://vl.example".to_string(),
                    last_refresh_status: Some("accepted".to_string()),
                    last_refresh_time: Some(1_700_000_000),
                    last_refresh_message: Some("ok".to_string()),
                    next_refresh_time: Some(1_700_000_420),
                    refresh_interval_secs: 7 * 60,
                },
            )])));
        let mut c = ctx();
        c.validator_site_statuses = Some(statuses);
        let resp = dispatch(req("validator_list_sites", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(
            resp.result["validator_sites"][0]["uri"],
            "https://vl.example"
        );
        assert_eq!(
            resp.result["validator_sites"][0]["last_refresh_status"],
            "accepted"
        );
        assert_eq!(resp.result["validator_sites"][0]["refresh_interval_min"], 7);
        assert!(resp.result["validator_sites"][0]["last_refresh_time"].is_string());
        assert_eq!(resp.result["validator_sites"][0]["last_refresh_message"], "ok");
        assert!(resp.result["validator_sites"][0]["next_refresh_time"].is_string());
    }

    #[test]
    fn test_server_definitions_shape_and_hash_short_circuit() {
        let mut c = ctx();
        let first = dispatch(req("server_definitions", json!({})), &mut c);
        assert_eq!(first.result["status"], "success");
        assert!(first.result["FIELDS"].is_array());
        assert!(first.result["LEDGER_ENTRY_TYPES"].is_array());
        assert!(first.result["TRANSACTION_TYPES"].is_array());
        let hash = first.result["hash"].as_str().unwrap().to_string();

        let second = dispatch(req("server_definitions", json!({ "hash": hash })), &mut c);
        assert_eq!(second.result["status"], "success");
        assert!(second.result["FIELDS"].is_null());
        assert!(second.result["hash"].is_string());
    }

    #[test]
    fn test_peers_shape() {
        let mut c = ctx();
        c.peer_summaries = vec![crate::rpc::PeerSummary {
            address: "192.0.2.10:51235".to_string(),
            status: "active".to_string(),
            inbound: Some(false),
            latency: Some(42),
            ledger: Some("AB".repeat(32)),
            protocol: Some("XRPL/2.2".to_string()),
            public_key: Some(crate::crypto::base58::encode(
                crate::crypto::base58::PREFIX_NODE_PUBLIC,
                &[4u8; 33],
            )),
            version: Some("xledgrs-test".to_string()),
            cluster: Some(crate::network::cluster::ClusterPeerSummary {
                address: "192.0.2.10:51235".to_string(),
                public_key: Some(crate::crypto::base58::encode(
                    crate::crypto::base58::PREFIX_NODE_PUBLIC,
                    &[4u8; 33],
                )),
                tag: Some("vip".to_string()),
                reserved: true,
                loopback: false,
                connected: true,
                status: Some("connected".to_string()),
                action: Some("accepted".to_string()),
                ledger_seq: Some(100),
                ledger_range: Some((1, 100)),
                load_factor: Some(crate::network::load::LOAD_BASE * 2),
                connected_since_unix: Some(1),
                last_status_unix: Some(2),
                last_report_unix: Some(3),
            }),
        }];
        let resp = dispatch(req("peers", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["peers"][0]["address"], "192.0.2.10:51235");
        assert_eq!(resp.result["peers"][0]["status"], "active");
        assert_eq!(resp.result["peers"][0]["inbound"], false);
        assert_eq!(resp.result["peers"][0]["latency"], 42);
        assert_eq!(resp.result["peers"][0]["protocol"], "XRPL/2.2");
        assert_eq!(resp.result["peers"][0]["version"], "xledgrs-test");
        assert_eq!(resp.result["peers"][0]["cluster"]["reserved"], json!(true));
        assert_eq!(resp.result["peers"][0]["cluster"]["tag"], json!("vip"));
    }

    #[test]
    fn test_peer_reservations_add_list_and_delete() {
        let public_key =
            crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, &[5u8; 33]);
        let tmp = tempfile::tempdir().unwrap();
        let storage = std::sync::Arc::new(crate::storage::Storage::open(tmp.path()).unwrap());
        let mut c = ctx();
        c.storage = Some(storage.clone());
        c.peer_reservations = Some(std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::BTreeMap::new(),
        )));

        let add = dispatch(
            req(
                "peer_reservations_add",
                json!({"public_key": public_key, "description": "vip peer"}),
            ),
            &mut c,
        );
        assert_eq!(add.result["status"], "success");

        let list = dispatch(req("peer_reservations_list", json!({})), &mut c);
        assert_eq!(list.result["status"], "success");
        assert_eq!(list.result["reservations"][0]["description"], "vip peer");
        let persisted = storage.load_peer_reservations();
        assert_eq!(
            persisted.get(&public_key).map(String::as_str),
            Some("vip peer")
        );

        let del = dispatch(
            req("peer_reservations_del", json!({"public_key": public_key})),
            &mut c,
        );
        assert_eq!(del.result["status"], "success");
        assert_eq!(del.result["previous"]["description"], "vip peer");
        let list_after = dispatch(req("peer_reservations_list", json!({})), &mut c);
        assert_eq!(
            list_after.result["reservations"].as_array().unwrap().len(),
            0
        );
        assert!(storage.load_peer_reservations().is_empty());
    }

    #[test]
    fn test_print_routes_to_named_snapshot() {
        let mut c = ctx();
        c.peer_summaries = vec![crate::rpc::PeerSummary {
            address: "192.0.2.20:51235".to_string(),
            status: "active".to_string(),
            inbound: Some(true),
            latency: Some(9),
            ledger: None,
            protocol: None,
            public_key: None,
            version: None,
            cluster: None,
        }];
        let resp = dispatch(req("print", json!({"params": ["peers"]})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["peers"][0]["address"], "192.0.2.20:51235");

        c.load_snapshot.local_fee = crate::network::load::LOAD_BASE * 2;
        c.load_snapshot.queue_overloaded = true;
        c.load_snapshot.queue_depth = 17;
        c.load_snapshot.queue_capacity = 8;
        c.load_snapshot.queued_transactions = 12;
        c.load_snapshot.tracked_transactions = 3;
        c.load_snapshot.tracked_inbound_transactions = 1;
        c.load_snapshot.active_path_requests = 1;
        c.load_snapshot.active_inbound_ledgers = 0;
        c.load_snapshot.job_queue_threads = 2;
        c.load_snapshot.queue_job_types = vec![
            crate::network::load::JobTypeSnapshot {
                job_type: "transaction_queue".to_string(),
                waiting: 12,
                in_progress: 0,
                over_target: true,
            },
            crate::network::load::JobTypeSnapshot {
                job_type: "path_requests".to_string(),
                waiting: 0,
                in_progress: 1,
                over_target: false,
            },
        ];
        let load_resp = dispatch(req("print", json!({"params": ["load"]})), &mut c);
        assert_eq!(load_resp.result["status"], "success");
        assert_eq!(load_resp.result["load"]["load_queue_overloaded"], json!(true));
        assert_eq!(load_resp.result["load"]["load_queue_depth"], json!(17));
        assert_eq!(load_resp.result["load"]["queued_transactions"], json!(12));
        assert_eq!(
            load_resp.result["load"]["job_queue"]["job_types"][0]["job_type"],
            json!("transaction_queue")
        );
        assert_eq!(
            load_resp.result["load"]["job_queue"]["job_types"][0]["waiting"],
            json!(12)
        );
        c.peerfinder_snapshot = Some(crate::network::peerfinder::PeerfinderSnapshot {
            total_known: 3,
            fixed: 1,
            with_successes: 2,
            dialable: 2,
            backed_off: 1,
            retry_ready: 1,
            ready: 2,
            cooling: 1,
            cold: 0,
            redirects: 0,
            distinct_sources: 2,
            inbound_slots: 1,
            outbound_slots: 1,
            active_slots: 2,
            reserved_slots: 1,
            top: vec![crate::network::peerfinder::PeerfinderEntry {
                address: "192.0.2.21:51235".parse().unwrap(),
                source: "peer".to_string(),
                fixed: false,
                last_seen_unix: 1,
                last_connected_unix: Some(2),
                success_count: 1,
                failure_count: 0,
                next_attempt_unix: 0,
            }],
        });
        c.cluster_snapshot = Some(crate::network::cluster::ClusterSnapshot {
            configured: 2,
            observed: 2,
            connected: 1,
            max_reported_load_factor: Some(crate::network::load::LOAD_BASE * 2),
            entries: vec![crate::network::cluster::ClusterPeerSummary {
                address: "127.0.0.1:51235".to_string(),
                public_key: Some("n9Cluster".to_string()),
                tag: Some("loopback".to_string()),
                reserved: true,
                loopback: true,
                connected: true,
                status: Some("connected".to_string()),
                action: Some("accepted".to_string()),
                ledger_seq: Some(1000),
                ledger_range: Some((900, 1000)),
                load_factor: Some(crate::network::load::LOAD_BASE * 2),
                connected_since_unix: Some(10),
                last_status_unix: Some(20),
                last_report_unix: Some(30),
            }],
        });

        let load = dispatch(req("print", json!({"params": ["load"]})), &mut c);
        assert_eq!(load.result["status"], "success");
        assert_eq!(
            load.result["load"]["load_factor"],
            json!(crate::network::load::LOAD_BASE * 2)
        );

        let peerfinder = dispatch(req("print", json!({"params": ["peerfinder"]})), &mut c);
        assert_eq!(peerfinder.result["status"], "success");
        assert_eq!(peerfinder.result["peerfinder"]["total_known"], json!(3));
        assert_eq!(peerfinder.result["peerfinder"]["backed_off"], json!(1));
        assert_eq!(peerfinder.result["peerfinder"]["ready"], json!(2));
        assert_eq!(peerfinder.result["peerfinder"]["distinct_sources"], json!(2));

        let cluster = dispatch(req("print", json!({"params": ["cluster"]})), &mut c);
        assert_eq!(cluster.result["status"], "success");
        assert_eq!(cluster.result["cluster"]["configured"], json!(2));
        assert_eq!(
            cluster.result["cluster"]["entries"][0]["loopback"],
            json!(true)
        );
        c.resource_snapshot = Some(crate::network::resource::ResourceSnapshot {
            tracked: 2,
            tracked_ips: 1,
            tracked_peers: 1,
            blocked: 1,
            warned: 2,
            ip_balance: 2500,
            peer_balance: 3500,
            total_warnings: 3,
            total_disconnects: 1,
            total_balance: 6000,
            activity_cycles: 7,
            last_activity_unix: Some(123),
            entries: vec![crate::network::resource::ResourceEntrySummary {
                address: "192.0.2.99".into(),
                balance: 6000,
                warnings: 1,
                disconnects: 1,
                last_reason: "resource_drop:spam".into(),
                blocked_until_ms: Some(1000),
            }],
        });
        let resource_manager = dispatch(
            req("print", json!({"params": ["resource_manager"]})),
            &mut c,
        );
        assert_eq!(resource_manager.result["status"], "success");
        assert_eq!(
            resource_manager.result["resource_manager"]["blocked"],
            json!(1)
        );
        assert_eq!(
            resource_manager.result["resource_manager"]["total_balance"],
            json!(6000)
        );
        assert_eq!(
            resource_manager.result["resource_manager"]["activity_cycles"],
            json!(7)
        );
        assert_eq!(
            resource_manager.result["resource_manager"]["last_activity_unix"],
            json!(123)
        );
        c.node_store_snapshot = Some(crate::ledger::node_store::NodeStoreSnapshot {
            fetch_hits: 11,
            fetch_missing: 2,
            fetch_errors: 1,
            store_ops: 3,
            store_unchecked_ops: 4,
            batch_store_ops: 5,
            batch_store_nodes: 19,
            flush_ops: 2,
            last_flush_unix: Some(88),
            last_flush_duration_ms: Some(9),
            last_error: Some("disk busy".into()),
        });
        let node_store = dispatch(req("print", json!({"params": ["node_store"]})), &mut c);
        assert_eq!(node_store.result["status"], "success");
        assert_eq!(node_store.result["node_store"]["fetch_errors"], json!(1));
        assert_eq!(node_store.result["node_store"]["batch_store_nodes"], json!(19));
        assert_eq!(node_store.result["node_store"]["last_flush_unix"], json!(88));
        assert_eq!(
            node_store.result["node_store"]["last_flush_duration_ms"],
            json!(9)
        );
        c.fetch_pack_snapshot = Some(crate::ledger::fetch_pack::FetchPackSnapshot {
            tracked: 2,
            stashed_total: 7,
            backend_fill_total: 8,
            imported_total: 5,
            reply_objects_total: 6,
            verified_objects_total: 5,
            missing_hash_total: 1,
            bad_hash_len_total: 0,
            missing_data_total: 0,
            normalize_reject_total: 1,
            hash_mismatch_total: 1,
            persisted_total: 4,
            persist_errors_total: 1,
            unchecked_fallbacks_total: 1,
            reused_total: 3,
            evicted_total: 1,
            last_import_error: Some("persist failed".into()),
            flush_ops: 2,
            last_flush_unix: Some(77),
            last_flush_duration_ms: Some(12),
            last_flush_error: Some("flush busy".into()),
            entries: vec![crate::ledger::fetch_pack::FetchPackEntrySummary {
                hash: "FE".repeat(32),
                size: 128,
                first_stashed_unix: 1,
                last_stashed_unix: 2,
                reuse_hits: 3,
            }],
        });
        let fetch_pack = dispatch(req("print", json!({"params": ["fetch_pack"]})), &mut c);
        assert_eq!(fetch_pack.result["status"], "success");
        assert_eq!(fetch_pack.result["fetch_pack"]["tracked"], json!(2));
        assert_eq!(
            fetch_pack.result["fetch_pack"]["backend_fill_total"],
            json!(8)
        );
        assert_eq!(fetch_pack.result["fetch_pack"]["reused_total"], json!(3));
        assert_eq!(fetch_pack.result["fetch_pack"]["persisted_total"], json!(4));
        assert_eq!(fetch_pack.result["fetch_pack"]["flush_ops"], json!(2));
        assert_eq!(fetch_pack.result["fetch_pack"]["last_flush_unix"], json!(77));
        assert_eq!(
            fetch_pack.result["fetch_pack"]["last_flush_duration_ms"],
            json!(12)
        );

        c.path_request_snapshot = Some(crate::rpc::path_requests::PathRequestSnapshot {
            active_requests: 1,
            last_recompute_unix: Some(55),
            entries: vec![crate::rpc::path_requests::PathRequestSummary {
                client_id: 7,
                source_account: Some("rSource".into()),
                destination_account: Some("rDest".into()),
                destination_amount: Some("10".into()),
                created_unix: 10,
                updated_unix: 20,
                update_count: 3,
                last_status: "success".into(),
            }],
        });
        c.inbound_transactions_snapshot = Some(
            crate::ledger::inbound_transactions::InboundTransactionsSnapshot {
                tracked: 2,
                accepted_total: 4,
                duplicate_total: 1,
                relayed_total: 3,
                persisted_total: 2,
                entries: vec![
                    crate::ledger::inbound_transactions::InboundTransactionSummary {
                        hash: "AB".repeat(32),
                        size: 128,
                        first_seen_unix: 11,
                        last_seen_unix: 22,
                        first_source: "peer:1".into(),
                        last_source: "peer:2".into(),
                        seen_count: 2,
                        relayed_count: 1,
                        persisted: true,
                    },
                ],
            },
        );
        c.inbound_ledgers_snapshot = Some(crate::ledger::inbound::InboundLedgersSnapshot {
            active: 2,
            complete: 1,
            failed: 0,
            retry_ready: 1,
            stale: 0,
            fetch_rate: 1,
            fetched_total: 3,
            fetch_pack_hits: 2,
            cache_size: 2,
            sweep_total: 4,
            last_sweep_removed: 1,
            last_sweep_unix: Some(77),
            stop_total: 1,
            last_stop_unix: Some(88),
            cached_seq_hashes: 3,
            cached_seq_headers: 1,
            recent_failures: 5,
            history: 1,
            generic: 0,
            consensus: 1,
            entries: vec![crate::ledger::inbound::InboundLedgerSummary {
                ledger_hash: "CD".repeat(32),
                ledger_seq: 9,
                reason: "history".into(),
                has_header: true,
                has_transactions: false,
                complete: false,
                failed: false,
                timeout_count: 2,
                age_ms: 100,
                idle_ms: 20,
            }],
        });
        c.open_ledger_snapshot = Some(crate::ledger::open_ledger::OpenLedgerSnapshot {
            ledger_current_index: 10,
            parent_ledger_index: 9,
            parent_hash: "CD".repeat(32),
            last_close_time: 44,
            queued_transactions: 2,
            candidate_set_hash: "EF".repeat(32),
            escalation_multiplier: 1,
            txns_expected: 3,
            max_queue_size: 4,
            open_fee_level: 5,
            revision: 6,
            modify_count: 2,
            accept_count: 1,
            last_modified_unix: 55,
            last_accept_unix: 66,
            ..Default::default()
        });
        c.network_ops_snapshot = Some(crate::network::ops::NetworkOpsSnapshot {
            server_state: "full".into(),
            peer_count: 1,
            object_count: 2,
            known_peers: 3,
            dialable_peers: 2,
            backed_off_peers: 1,
            peerfinder_retry_ready: 1,
            peerfinder_ready: 2,
            peerfinder_cooling: 1,
            peerfinder_cold: 0,
            peerfinder_sources: 2,
            cluster_configured: 2,
            cluster_observed: 2,
            cluster_connected: 1,
            blocked_peers: 1,
            warned_peers: 2,
            resource_tracked: 2,
            resource_ip_balance: 2500,
            resource_peer_balance: 3500,
            resource_balance: 6000,
            resource_warning_events: 3,
            resource_disconnect_events: 1,
            node_store_fetch_errors: 1,
            node_store_flush_ops: 2,
            node_store_last_flush_unix: Some(88),
            node_store_last_flush_duration_ms: Some(9),
            fetch_pack_entries: 2,
            fetch_pack_backend_fill_total: 8,
            fetch_pack_reused_total: 3,
            fetch_pack_persisted_total: 4,
            fetch_pack_persist_errors_total: 1,
            fetch_pack_flush_ops: 3,
            fetch_pack_last_flush_unix: Some(77),
            fetch_pack_last_flush_duration_ms: Some(12),
            tracked_inbound_ledgers: 2,
            failed_inbound_ledgers: 0,
            queued_transactions: 4,
            tracked_transactions: 5,
            submitted_transactions: 6,
            active_path_requests: 1,
            tracked_inbound_transactions: 2,
            load_queue_depth: 11,
            load_queue_capacity: 16,
            load_queue_overloaded: false,
            load_factor: crate::network::load::LOAD_BASE * 2,
        });

        let path_requests = dispatch(req("print", json!({"params": ["path_requests"]})), &mut c);
        assert_eq!(path_requests.result["status"], "success");
        assert_eq!(
            path_requests.result["path_requests"]["active_requests"],
            json!(1)
        );

        let inbound = dispatch(
            req("print", json!({"params": ["inbound_transactions"]})),
            &mut c,
        );
        assert_eq!(inbound.result["status"], "success");
        assert_eq!(inbound.result["inbound_transactions"]["tracked"], json!(2));

        let inbound_ledgers =
            dispatch(req("print", json!({"params": ["inbound_ledgers"]})), &mut c);
        assert_eq!(inbound_ledgers.result["status"], "success");
        assert_eq!(inbound_ledgers.result["inbound_ledgers"]["active"], json!(2));
        assert_eq!(inbound_ledgers.result["inbound_ledgers"]["complete"], json!(1));
        assert_eq!(inbound_ledgers.result["inbound_ledgers"]["retry_ready"], json!(1));
        assert_eq!(inbound_ledgers.result["inbound_ledgers"]["fetch_rate"], json!(1));
        assert_eq!(inbound_ledgers.result["inbound_ledgers"]["fetch_pack_hits"], json!(2));
        assert_eq!(
            inbound_ledgers.result["inbound_ledgers"]["recent_failures"],
            json!(5)
        );
        assert_eq!(
            inbound_ledgers.result["inbound_ledgers"]["entries"][0]["ledger_hash"],
            json!("CD".repeat(32))
        );

        let network_ops = dispatch(req("print", json!({"params": ["network_ops"]})), &mut c);
        assert_eq!(network_ops.result["status"], "success");
        assert_eq!(
            network_ops.result["network_ops"]["server_state"],
            json!("full")
        );
        assert_eq!(
            network_ops.result["network_ops"]["cluster_connected"],
            json!(1)
        );
        assert_eq!(network_ops.result["network_ops"]["blocked_peers"], json!(1));
        assert_eq!(
            network_ops.result["network_ops"]["backed_off_peers"],
            json!(1)
        );
        assert_eq!(
            network_ops.result["network_ops"]["peerfinder_ready"],
            json!(2)
        );
        assert_eq!(
            network_ops.result["network_ops"]["resource_balance"],
            json!(6000)
        );
        assert_eq!(
            network_ops.result["network_ops"]["node_store_fetch_errors"],
            json!(1)
        );
        assert_eq!(
            network_ops.result["network_ops"]["fetch_pack_entries"],
            json!(2)
        );
        assert_eq!(
            network_ops.result["network_ops"]["fetch_pack_backend_fill_total"],
            json!(8)
        );
        assert_eq!(
            network_ops.result["network_ops"]["fetch_pack_reused_total"],
            json!(3)
        );
        assert_eq!(
            network_ops.result["network_ops"]["fetch_pack_persisted_total"],
            json!(4)
        );
        assert_eq!(
            network_ops.result["network_ops"]["node_store_flush_ops"],
            json!(2)
        );
        assert_eq!(
            network_ops.result["network_ops"]["node_store_last_flush_unix"],
            json!(88)
        );
        assert_eq!(
            network_ops.result["network_ops"]["node_store_last_flush_duration_ms"],
            json!(9)
        );
        assert_eq!(
            network_ops.result["network_ops"]["fetch_pack_flush_ops"],
            json!(3)
        );
        assert_eq!(
            network_ops.result["network_ops"]["fetch_pack_last_flush_unix"],
            json!(77)
        );
        assert_eq!(
            network_ops.result["network_ops"]["fetch_pack_last_flush_duration_ms"],
            json!(12)
        );
        assert_eq!(
            network_ops.result["network_ops"]["tracked_inbound_ledgers"],
            json!(2)
        );
        assert_eq!(
            network_ops.result["network_ops"]["tracked_transactions"],
            json!(5)
        );
        assert_eq!(
            network_ops.result["network_ops"]["submitted_transactions"],
            json!(6)
        );

        c.tx_master_snapshot = Some(crate::transaction::master::TxMasterSnapshot {
            tracked: 1,
            proposed_total: 2,
            submitted_total: 7,
            buffered_total: 3,
            accepted_total: 4,
            validated_total: 5,
            relayed_total: 6,
            entries: vec![crate::transaction::master::TxMasterEntrySummary {
                hash: "CD".repeat(32),
                status: "validated".into(),
                size: 128,
                first_seen_unix: 1,
                updated_unix: 2,
                source: "validated".into(),
                ledger_seq: Some(9),
                result: Some("tesSUCCESS".into()),
                relayed_count: 3,
            }],
        });
        c.ledger_master_snapshot = Some(crate::ledger::master::LedgerMasterSnapshot {
            validated_seq: 9,
            validated_hash: "EF".repeat(32),
            open_ledger_seq: 10,
            complete_ledgers: "1-9".into(),
            last_close_time: 99,
            queued_transactions: 4,
            candidate_set_hash: "12".repeat(32),
            recent_validated: vec![crate::ledger::master::RecentValidatedLedger {
                seq: 9,
                hash: "EF".repeat(32),
            }],
        });
        c.open_ledger_snapshot = Some(crate::ledger::open_ledger::OpenLedgerSnapshot {
            ledger_current_index: 10,
            parent_ledger_index: 9,
            parent_hash: "EF".repeat(32),
            last_close_time: 99,
            queued_transactions: 4,
            candidate_set_hash: "12".repeat(32),
            escalation_multiplier: crate::ledger::pool::BASE_LEVEL * 500,
            txns_expected: 32,
            max_queue_size: 2000,
            open_fee_level: crate::ledger::pool::BASE_LEVEL,
            revision: 7,
            modify_count: 4,
            accept_count: 2,
            last_modified_unix: 100,
            last_accept_unix: 101,
            has_open_view: true,
            open_view_base_ledger_index: 9,
            open_view_applied_transactions: 2,
            open_view_failed_transactions: 0,
            open_view_skipped_transactions: 1,
            open_view_tx_count: 2,
            open_view_state_hash: "34".repeat(32),
            open_view_tx_hash: "56".repeat(32),
        });

        let tx_master = dispatch(req("print", json!({"params": ["tx_master"]})), &mut c);
        assert_eq!(tx_master.result["status"], "success");
        assert_eq!(tx_master.result["tx_master"]["tracked"], json!(1));
        assert_eq!(tx_master.result["tx_master"]["submitted_total"], json!(7));

        let ledger_master = dispatch(req("print", json!({"params": ["ledger_master"]})), &mut c);
        assert_eq!(ledger_master.result["status"], "success");
        assert_eq!(
            ledger_master.result["ledger_master"]["validated_seq"],
            json!(9)
        );

        let open_ledger = dispatch(req("print", json!({"params": ["open_ledger"]})), &mut c);
        assert_eq!(open_ledger.result["status"], "success");
        assert_eq!(
            open_ledger.result["open_ledger"]["ledger_current_index"],
            json!(10)
        );
        assert_eq!(open_ledger.result["open_ledger"]["parent_ledger_index"], json!(9));
        assert_eq!(open_ledger.result["open_ledger"]["max_queue_size"], json!(2000));
        assert_eq!(
            open_ledger.result["open_ledger"]["open_fee_level"],
            json!(crate::ledger::pool::BASE_LEVEL)
        );
        assert_eq!(open_ledger.result["open_ledger"]["revision"], json!(7));
        assert_eq!(open_ledger.result["open_ledger"]["modify_count"], json!(4));
        assert_eq!(open_ledger.result["open_ledger"]["accept_count"], json!(2));
        assert_eq!(open_ledger.result["open_ledger"]["last_modified_unix"], json!(100));
        assert_eq!(open_ledger.result["open_ledger"]["last_accept_unix"], json!(101));
        assert_eq!(open_ledger.result["open_ledger"]["has_open_view"], json!(true));
        assert_eq!(
            open_ledger.result["open_ledger"]["open_view_base_ledger_index"],
            json!(9)
        );
        assert_eq!(
            open_ledger.result["open_ledger"]["open_view_applied_transactions"],
            json!(2)
        );
        assert_eq!(
            open_ledger.result["open_ledger"]["open_view_tx_count"],
            json!(2)
        );
    }

    #[test]
    fn test_log_level_round_trips_base_and_partition() {
        let mut c = ctx();
        let set_base = dispatch(req("log_level", json!({"severity": "debug"})), &mut c);
        assert_eq!(set_base.result["status"], "success");

        let set_partition = dispatch(
            req(
                "log_level",
                json!({"partition": "sync", "severity": "trace"}),
            ),
            &mut c,
        );
        assert_eq!(set_partition.result["status"], "success");

        let get = dispatch(req("log_level", json!({})), &mut c);
        assert_eq!(get.result["status"], "success");
        assert_eq!(get.result["levels"]["base"], "debug");
        assert_eq!(get.result["levels"]["sync"], "trace");
    }

    #[test]
    fn test_logrotate_shape() {
        let mut c = ctx();
        let resp = dispatch(req("logrotate", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["rotated"], false);
    }

    #[test]
    fn test_logrotate_rotates_debug_file() {
        use std::io::Write;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sync.log");
        {
            let mut file = std::fs::File::create(&path).unwrap();
            writeln!(file, "before rotate").unwrap();
        }

        let mut c = ctx();
        c.debug_log = Some(std::sync::Arc::new(std::sync::Mutex::new(Some(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap(),
        ))));
        c.debug_log_path = Some(std::sync::Arc::new(std::sync::Mutex::new(Some(
            path.clone(),
        ))));

        let resp = dispatch(req("logrotate", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["rotated"], true);
        assert!(path.exists());
        let rotated_to = std::path::PathBuf::from(resp.result["rotated_to"].as_str().unwrap());
        assert!(rotated_to.exists());
    }

    #[test]
    fn test_validators_shape() {
        let static_validator = vec![3u8; 33];
        let publisher_key = hex::encode([8u8; 33]);
        let listed_validator = hex::encode([9u8; 33]);
        let manager = std::sync::Arc::new(std::sync::Mutex::new(
            crate::validator_list::ValidatorListManager::new(vec![static_validator.clone()], 1),
        ));
        manager.lock().unwrap_or_else(|e| e.into_inner()).apply(
            crate::validator_list::ValidatorList {
                sequence: 1,
                validators: vec![listed_validator.clone()],
                publisher_key: publisher_key.clone(),
                manifest: Some(crate::validator_list::CachedManifestInfo {
                    master_key: publisher_key.clone().to_uppercase(),
                    signing_key: hex::encode([0xAAu8; 33]).to_uppercase(),
                    sequence: 9,
                    domain: Some("vl.example".to_string()),
                    raw_manifest: "ZHVtbXk=".to_string(),
                }),
                effective: None,
                expiration: None,
                refresh_interval: Some(600),
            },
            1_700_000_000,
        );

        let mut c = ctx();
        c.validator_list_manager = Some(manager);
        let resp = dispatch(req("validators", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(
            resp.result["listed_static_keys"][0],
            crate::crypto::base58::encode(
                crate::crypto::base58::PREFIX_NODE_PUBLIC,
                &static_validator
            )
        );
        assert_eq!(resp.result["publisher_lists"][0]["seq"], 1);
        assert_eq!(resp.result["publisher_lists"][0]["version"], 1);
        assert_eq!(
            resp.result["publisher_lists"][0]["pubkey_publisher"],
            publisher_key
        );
        assert_eq!(resp.result["validation_quorum"], 2);
        assert_eq!(resp.result["validator_list"]["validator_list_threshold"], 1);
        assert!(resp.result["validator_list_expires"].is_string());
        assert!(resp.result["signing_keys"].is_object());
        assert_eq!(
            resp.result["signing_keys"][crate::crypto::base58::encode(
                crate::crypto::base58::PREFIX_NODE_PUBLIC,
                &hex::decode(&publisher_key).unwrap()
            )],
            crate::crypto::base58::encode(
                crate::crypto::base58::PREFIX_NODE_PUBLIC,
                &[0xAAu8; 33]
            )
        );
        assert!(
            resp.result["trusted_validator_keys"]
                .as_array()
                .unwrap()
                .len()
                >= 2
        );
    }

    #[test]
    fn test_validators_include_remaining_future_publisher_lists() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let publisher_key = hex::encode([7u8; 33]);
        let current_validator = hex::encode([9u8; 33]);
        let future_validator = hex::encode([10u8; 33]);
        let manager = std::sync::Arc::new(std::sync::Mutex::new(
            crate::validator_list::ValidatorListManager::new(Vec::new(), 1),
        ));
        {
            let mut guard = manager.lock().unwrap_or_else(|e| e.into_inner());
            assert!(guard
                .apply(
                    crate::validator_list::ValidatorList {
                        sequence: 5,
                        validators: vec![current_validator.clone()],
                        publisher_key: publisher_key.clone(),
                        manifest: None,
                        effective: None,
                        expiration: Some(now + 200),
                        refresh_interval: Some(600),
                    },
                    now,
                )
                .is_some());
            assert!(guard
                .apply(
                    crate::validator_list::ValidatorList {
                        sequence: 6,
                        validators: vec![future_validator.clone()],
                        publisher_key: publisher_key.clone(),
                        manifest: None,
                        effective: Some(now + 100),
                        expiration: Some(now + 300),
                        refresh_interval: Some(600),
                    },
                    now,
                )
                .is_some());
        }

        let mut c = ctx();
        c.validator_list_manager = Some(manager);
        let resp = dispatch(req("validators", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["publisher_lists"][0]["seq"], 5);
        assert_eq!(resp.result["publisher_lists"][0]["remaining"][0]["seq"], 6);
        assert!(resp.result["publisher_lists"][0]["remaining"][0]["effective"].is_string());
        let listed = resp.result["publisher_lists"][0]["list"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            listed,
            vec![encode_validator_hex_or_display(&current_validator)]
        );
    }

    #[test]
    fn test_unl_list_shape() {
        let static_validator = vec![3u8; 33];
        let publisher_key = hex::encode([8u8; 33]);
        let listed_validator = hex::encode([9u8; 33]);
        let manager = std::sync::Arc::new(std::sync::Mutex::new(
            crate::validator_list::ValidatorListManager::new(vec![static_validator.clone()], 1),
        ));
        manager.lock().unwrap_or_else(|e| e.into_inner()).apply(
            crate::validator_list::ValidatorList {
                sequence: 1,
                validators: vec![listed_validator],
                publisher_key,
                manifest: None,
                effective: None,
                expiration: None,
                refresh_interval: Some(600),
            },
            1_700_000_000,
        );

        let mut c = ctx();
        c.validator_list_manager = Some(manager);
        let resp = dispatch(req("unl_list", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        let unl = resp.result["unl"].as_array().unwrap();
        assert!(unl.len() >= 2);
        assert!(unl[0]["pubkey_validator"].is_string());
        assert!(unl[0]["trusted"].is_boolean());
    }

    #[test]
    fn test_vault_info_returns_vault_and_shares() {
        use crate::ledger::meta::ParsedField;

        let owner =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let pseudo = [0x22u8; 20];
        let share_mptid = [0x11u8; 24];
        let vault_key = crate::ledger::tx::vault_key(&owner, 7);
        let vault_raw = crate::ledger::meta::build_sle(
            0x0084,
            &[
                ParsedField {
                    type_code: 8,
                    field_code: 1,
                    data: pseudo.to_vec(),
                },
                ParsedField {
                    type_code: 8,
                    field_code: 2,
                    data: owner.to_vec(),
                },
                ParsedField {
                    type_code: 21,
                    field_code: 2,
                    data: share_mptid.to_vec(),
                },
            ],
            None,
            None,
        );
        let issuance_key = crate::ledger::tx::vault_mpt_issuance_key(&share_mptid);
        let issuance_raw = crate::ledger::meta::build_sle(
            0x007E,
            &[ParsedField {
                type_code: 8,
                field_code: 1,
                data: owner.to_vec(),
            }],
            None,
            None,
        );

        let mut c = ctx();
        {
            let mut ls = c.ledger_state.lock().unwrap();
            ls.insert_raw(vault_key, vault_raw);
            ls.insert_raw(issuance_key, issuance_raw);
        }

        let resp = dispatch(
            req(
                "vault_info",
                json!({
                    "owner": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                    "seq": 7
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["vault"]["LedgerEntryType"], "Vault");
        assert!(resp.result["vault"]["shares"]["index"].is_string());
    }

    #[test]
    fn test_amm_info_returns_pool_snapshot() {
        use crate::ledger::meta::ParsedField;

        let issuer =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let issue1 = crate::transaction::amount::Issue::Xrp;
        let issue2 = crate::transaction::amount::Issue::Iou {
            currency: crate::transaction::amount::Currency::from_code("USD").unwrap(),
            issuer,
        };
        let amm_key = crate::ledger::tx::amm_key(&issue1, &issue2);
        let amm_raw = crate::ledger::meta::build_sle(
            0x0079,
            &[
                ParsedField {
                    type_code: 8,
                    field_code: 1,
                    data: [0x33u8; 20].to_vec(),
                },
                ParsedField {
                    type_code: 1,
                    field_code: 2,
                    data: 500u16.to_be_bytes().to_vec(),
                },
                ParsedField {
                    type_code: 24,
                    field_code: 3,
                    data: issue1.to_bytes(),
                },
                ParsedField {
                    type_code: 24,
                    field_code: 4,
                    data: issue2.to_bytes(),
                },
                ParsedField {
                    type_code: 9,
                    field_code: 10,
                    data: 1000i64.to_be_bytes().to_vec(),
                },
                ParsedField {
                    type_code: 9,
                    field_code: 11,
                    data: 2000i64.to_be_bytes().to_vec(),
                },
                ParsedField {
                    type_code: 9,
                    field_code: 12,
                    data: 3000i64.to_be_bytes().to_vec(),
                },
            ],
            None,
            None,
        );

        let mut c = ctx();
        c.ledger_state.lock().unwrap().insert_raw(amm_key, amm_raw);

        let resp = dispatch(
            req(
                "amm_info",
                json!({
                    "asset": {"currency": "XRP"},
                    "asset2": {
                        "currency": "USD",
                        "issuer": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
                    }
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["amm"]["amount"], "1000");
        assert_eq!(resp.result["amm"]["amount2"]["currency"], "USD");
        assert_eq!(resp.result["amm"]["trading_fee"], 500);
    }

    #[test]
    fn test_channel_authorize_requires_admin_rpc() {
        let mut c = ctx();
        c.admin_rpc_enabled = false;
        let resp = dispatch(
            req(
                "channel_authorize",
                json!({
                    "secret": "masterpassphrase",
                    "channel_id": "AB".repeat(32),
                    "amount": "1000"
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["error"], "forbidden");
    }

    #[test]
    fn test_channel_authorize_and_verify_roundtrip() {
        let seed = crate::crypto::base58::encode_seed(&[9u8; 16]);
        let key = crate::crypto::keys::Secp256k1KeyPair::from_seed_entropy(&[9u8; 16]);
        let channel_id = "CD".repeat(32);

        let authorize = dispatch(
            req(
                "channel_authorize",
                json!({
                    "seed": seed,
                    "key_type": "secp256k1",
                    "channel_id": channel_id,
                    "amount": "1000"
                }),
            ),
            &mut ctx(),
        );
        assert_eq!(authorize.result["status"], "success");
        let signature = authorize.result["signature"].as_str().unwrap().to_string();

        let verify = dispatch(
            req(
                "channel_verify",
                json!({
                    "public_key": crate::crypto::base58::encode(
                        crate::crypto::base58::PREFIX_NODE_PUBLIC,
                        &key.public_key_bytes()
                    ),
                    "channel_id": "CD".repeat(32),
                    "amount": "1000",
                    "signature": signature,
                }),
            ),
            &mut ctx(),
        );
        assert_eq!(verify.result["status"], "success");
        assert_eq!(verify.result["signature_verified"], true);
    }

    #[test]
    fn test_gateway_balances_shape() {
        use crate::ledger::{trustline::RippleState, AccountRoot};
        use crate::transaction::amount::{Currency, IouValue};

        let issuer = [1u8; 20];
        let hotwallet = [2u8; 20];
        let customer = [3u8; 20];
        let other_issuer = [4u8; 20];
        let issuer_addr = crate::crypto::base58::encode_account(&issuer);
        let hotwallet_addr = crate::crypto::base58::encode_account(&hotwallet);
        let other_issuer_addr = crate::crypto::base58::encode_account(&other_issuer);
        let mut c = ctx();
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            for account_id in [issuer, hotwallet, customer, other_issuer] {
                ls.insert_account(AccountRoot {
                    account_id,
                    balance: 1_000_000_000,
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

            let mut obligation_to_hot =
                RippleState::new(&issuer, &hotwallet, Currency::from_code("USD").unwrap());
            obligation_to_hot.low_limit = IouValue::from_f64(100.0);
            obligation_to_hot.high_limit = IouValue::from_f64(100.0);
            obligation_to_hot.balance = if obligation_to_hot.low_account == issuer {
                IouValue::from_f64(-20.0)
            } else {
                IouValue::from_f64(20.0)
            };
            ls.insert_trustline(obligation_to_hot);

            let mut obligation_to_customer =
                RippleState::new(&issuer, &customer, Currency::from_code("USD").unwrap());
            obligation_to_customer.low_limit = IouValue::from_f64(100.0);
            obligation_to_customer.high_limit = IouValue::from_f64(100.0);
            obligation_to_customer.balance = if obligation_to_customer.low_account == issuer {
                IouValue::from_f64(-30.0)
            } else {
                IouValue::from_f64(30.0)
            };
            ls.insert_trustline(obligation_to_customer);

            let mut asset_from_other =
                RippleState::new(&issuer, &other_issuer, Currency::from_code("EUR").unwrap());
            asset_from_other.low_limit = IouValue::from_f64(100.0);
            asset_from_other.high_limit = IouValue::from_f64(100.0);
            asset_from_other.balance = if asset_from_other.low_account == issuer {
                IouValue::from_f64(5.0)
            } else {
                IouValue::from_f64(-5.0)
            };
            ls.insert_trustline(asset_from_other);
        }

        let resp = dispatch(
            req(
                "gateway_balances",
                json!({
                    "account": issuer_addr.clone(),
                    "hotwallet": [hotwallet_addr.clone()]
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["account"], issuer_addr);
        assert_eq!(resp.result["obligations"]["USD"], "30");
        let balances = resp.result["balances"].as_object().unwrap();
        let hotwallet_balances = balances.get(&hotwallet_addr).unwrap().as_array().unwrap();
        assert_eq!(hotwallet_balances[0]["currency"], "USD");
        assert_eq!(hotwallet_balances[0]["value"], "20");
        let assets = resp.result["assets"].as_object().unwrap();
        let asset_balances = assets.get(&other_issuer_addr).unwrap().as_array().unwrap();
        assert_eq!(asset_balances[0]["currency"], "EUR");
        assert_eq!(asset_balances[0]["value"], "5");
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

    #[test]
    fn test_fee_uses_open_ledger_snapshot_when_present() {
        let mut c = ctx();
        c.open_ledger_snapshot = Some(crate::ledger::open_ledger::OpenLedgerSnapshot {
            ledger_current_index: 1001,
            parent_ledger_index: 1000,
            parent_hash: "AA".repeat(32),
            last_close_time: 1,
            queued_transactions: 12,
            candidate_set_hash: "BB".repeat(32),
            escalation_multiplier: crate::ledger::pool::BASE_LEVEL * 500,
            txns_expected: 32,
            max_queue_size: 2000,
            open_fee_level: crate::ledger::pool::BASE_LEVEL * 2,
            revision: 0,
            modify_count: 0,
            accept_count: 0,
            last_modified_unix: 0,
            last_accept_unix: 0,
            ..Default::default()
        });
        let resp = dispatch(req("fee", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["ledger_current_index"], json!(1001));
        assert_eq!(resp.result["current_ledger_size"], "12");
        assert_eq!(resp.result["levels"]["open_ledger_level"], json!((crate::ledger::pool::BASE_LEVEL * 2).to_string()));
        assert_eq!(resp.result["drops"]["open_ledger_fee"], json!("20"));
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
        let resp = dispatch(
            req("account_info", json!({"account": "not_an_address"})),
            &mut ctx(),
        );
        assert_eq!(resp.result["status"], "error");
        assert_eq!(resp.result["error"], "actMalformed");
    }

    #[test]
    fn test_account_info_unfunded_not_found() {
        let resp = dispatch(
            req(
                "account_info",
                json!({"account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"}),
            ),
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
            ledger_seq: 1,
            ledger_hash: "A".repeat(64),
            ..Default::default()
        };
        ctx.ledger_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert_account(AccountRoot {
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
        ctx
    }

    fn ctx_with_trustlines_and_offers() -> (NodeContext, [u8; 20], [u8; 20], [u8; 20]) {
        use crate::crypto::keys::Secp256k1KeyPair;
        use crate::ledger::{offer::Offer, trustline::RippleState, AccountRoot};
        use crate::transaction::amount::{Amount, Currency, IouValue};

        let alice = Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap();
        let bob = Secp256k1KeyPair::generate();
        let carol = Secp256k1KeyPair::generate();
        let alice_id = crate::crypto::account_id(&alice.public_key_bytes());
        let bob_id = crate::crypto::account_id(&bob.public_key_bytes());
        let carol_id = crate::crypto::account_id(&carol.public_key_bytes());

        let ctx = NodeContext {
            ledger_seq: 1,
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
                    previous_txn_lgr_seq: 0,
                    raw_sle: None,
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
        let root_hash = state
            .nudb_root_hash()
            .expect("historical test requires NuDB root");
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
            req(
                "account_info",
                json!({"account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"}),
            ),
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
            req(
                "account_info",
                json!({
                    "account": crate::crypto::base58::encode_account(&account),
                    "ledger_index": 500
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["account_data"]["Balance"], "123456789");
        assert_eq!(resp.result["account_data"]["Sequence"], 7);
    }

    #[test]
    fn test_account_info_different_account_not_found() {
        let resp = dispatch(
            req(
                "account_info",
                json!({"account": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"}),
            ),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["error"], "actNotFound");
    }

    #[test]
    fn test_account_info_invalid_ledger_index() {
        let resp = dispatch(
            req(
                "account_info",
                json!({
                    "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                    "ledger_index": "not_a_ledger"
                }),
            ),
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
            req(
                "account_lines",
                json!({
                    "account": alice_addr,
                    "peer": bob_addr
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["lines"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_account_lines_marker_rejected() {
        let resp = dispatch(
            req(
                "account_lines",
                json!({
                    "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                    "marker": "deadbeef"
                }),
            ),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_lines_marker_paginates_without_skipping() {
        let (mut c, alice_id, _, _) = ctx_with_trustlines_and_offers();
        let first = dispatch(
            req(
                "account_lines",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "limit": 1
                }),
            ),
            &mut c,
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();
        assert_eq!(first.result["lines"].as_array().unwrap().len(), 1);

        let second = dispatch(
            req(
                "account_lines",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "limit": 1,
                    "marker": marker
                }),
            ),
            &mut c,
        );
        assert_eq!(second.result["lines"].as_array().unwrap().len(), 1);
        assert_ne!(first.result["lines"][0], second.result["lines"][0]);
    }

    #[test]
    fn test_account_lines_reports_side_specific_flags_and_qualities() {
        use crate::ledger::{trustline::RippleState, AccountRoot};
        use crate::transaction::amount::{Currency, IouValue};

        let alice =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let bob =
            crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap();

        let mut c = ctx();
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            for account_id in [alice, bob] {
                ls.insert_account(AccountRoot {
                    account_id,
                    balance: 1_000_000_000,
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

            let mut tl = RippleState::new(&alice, &bob, Currency::from_code("USD").unwrap());
            tl.low_limit = IouValue::from_f64(100.0);
            tl.high_limit = IouValue::from_f64(50.0);
            tl.low_quality_in = 12;
            tl.low_quality_out = 34;
            tl.high_quality_in = 56;
            tl.high_quality_out = 78;
            if alice == tl.low_account {
                tl.flags = crate::ledger::trustline::LSF_LOW_NO_RIPPLE
                    | crate::ledger::trustline::LSF_LOW_AUTH
                    | crate::ledger::trustline::LSF_HIGH_FREEZE;
            } else {
                tl.flags = crate::ledger::trustline::LSF_HIGH_NO_RIPPLE
                    | crate::ledger::trustline::LSF_HIGH_AUTH
                    | crate::ledger::trustline::LSF_LOW_FREEZE;
            }
            ls.insert_trustline(tl);
        }

        let resp = dispatch(
            req(
                "account_lines",
                json!({"account": crate::crypto::base58::encode_account(&alice)}),
            ),
            &mut c,
        );
        let line = &resp.result["lines"][0];
        assert_eq!(line["no_ripple"], true);
        assert_eq!(line["no_ripple_peer"], false);
        assert_eq!(line["authorized"], true);
        assert_eq!(line["peer_authorized"], false);
        assert_eq!(line["freeze"], false);
        assert_eq!(line["freeze_peer"], true);
        assert_eq!(line["quality_in"], 12);
        assert_eq!(line["quality_out"], 34);
    }

    #[test]
    fn test_noripple_check_reports_gateway_recommendations() {
        use crate::ledger::{trustline::RippleState, AccountRoot};
        use crate::transaction::amount::{Currency, IouValue};

        let gateway =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let customer =
            crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap();

        let mut c = ctx();
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            ls.insert_account(AccountRoot {
                account_id: gateway,
                balance: 1_000_000_000,
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
            ls.insert_account(AccountRoot {
                account_id: customer,
                balance: 1_000_000_000,
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

            let mut tl = RippleState::new(&gateway, &customer, Currency::from_code("USD").unwrap());
            tl.low_limit = IouValue::from_f64(100.0);
            tl.high_limit = IouValue::from_f64(100.0);
            tl.flags = if gateway == tl.low_account {
                crate::ledger::trustline::LSF_LOW_NO_RIPPLE
            } else {
                crate::ledger::trustline::LSF_HIGH_NO_RIPPLE
            };
            ls.insert_trustline(tl);
        }

        let resp = dispatch(
            req(
                "noripple_check",
                json!({
                    "account": crate::crypto::base58::encode_account(&gateway),
                    "role": "gateway",
                    "transactions": true
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["validated"], true);
        assert_eq!(resp.result["problems"].as_array().unwrap().len(), 2);
        let txs = resp.result["transactions"].as_array().unwrap();
        assert_eq!(txs[0]["TransactionType"], "AccountSet");
        assert_eq!(txs[0]["Sequence"], 7);
        assert_eq!(txs[1]["TransactionType"], "TrustSet");
        assert_eq!(txs[1]["Sequence"], 8);
        assert_eq!(txs[1]["Flags"], 0x0004_0000u32);
        assert_eq!(txs[1]["LimitAmount"]["currency"], "USD");
    }

    // ── submit ────────────────────────────────────────────────────────────────

    fn genesis_payment(seq: u32, amount: u64) -> String {
        use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
        use crate::transaction::{builder::TxBuilder, Amount};
        let kp = KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap(),
        );
        TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(amount))
            .fee(12)
            .sequence(seq)
            .sign(&kp)
            .unwrap()
            .blob_hex()
    }

    fn ctx_with_account_tx_history() -> (NodeContext, String) {
        use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
        use crate::ledger::history::TxRecord;
        use crate::transaction::{builder::TxBuilder, Amount};

        let kp = KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap(),
        );
        let account = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".to_string();
        let destination = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
        let ctx = ctx_with_genesis();

        for (seq, amount) in [(10u32, 1_000_000u64), (11, 2_000_000), (12, 3_000_000)] {
            let signed = TxBuilder::payment()
                .account(&kp)
                .destination(destination)
                .unwrap()
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
            ctx.history
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert_ledger(
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
    fn test_transaction_entry_requires_ledger_selector() {
        let (mut c, _) = ctx_with_account_tx_history();
        let resp = dispatch(
            req("transaction_entry", json!({"tx_hash": "AA".repeat(32)})),
            &mut c,
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_transaction_entry_returns_specific_ledger_match() {
        let (mut c, _) = ctx_with_account_tx_history();
        let tx_hash = {
            let history = c.history.read().unwrap_or_else(|e| e.into_inner());
            hex::encode_upper(history.ledger_txs(11)[0].hash)
        };
        let resp = dispatch(
            req(
                "transaction_entry",
                json!({"ledger_index": 11, "tx_hash": tx_hash}),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["ledger_index"], 11);
        assert_eq!(resp.result["validated"], true);
    }

    #[test]
    fn test_tx_response_meta_includes_affected_nodes_and_index() {
        use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
        use crate::ledger::close::close_ledger;
        use crate::ledger::TxPool;
        use crate::transaction::{builder::TxBuilder, Amount};

        let kp = KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap(),
        );
        let destination = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination(destination)
            .unwrap()
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
        ctx.history
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert_ledger(result.header.clone(), result.tx_records.clone());
        ctx.ledger_header = result.header.clone();
        ctx.ledger_seq = result.header.sequence;

        let tx_json = tx_record_response(&result.tx_records[0], &ctx, false);
        assert_eq!(tx_json["meta"]["TransactionResult"], "tesSUCCESS");
        assert_eq!(tx_json["meta"]["TransactionIndex"], 0);
        assert!(tx_json["meta"]["AffectedNodes"].is_array());
        assert!(!tx_json["meta"]["AffectedNodes"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_submit_missing_blob() {
        let resp = dispatch(req("submit", json!({})), &mut ctx());
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_submit_requires_admin_rpc() {
        let mut c = NodeContext::default();
        c.admin_rpc_enabled = false;
        let resp = dispatch(req("submit", json!({"tx_blob": "ABCD"})), &mut c);
        assert_eq!(resp.result["error"], "forbidden");
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
        assert_eq!(
            resp.result["error_message"],
            "Invalid parameters: tx_blob too large"
        );
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
        use crate::transaction::{builder::TxBuilder, Amount};
        let kp = KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap(),
        );
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();

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
        let mut ctx = NodeContext {
            ledger_seq: 1,
            ledger_hash: "A".repeat(64),
            ..Default::default()
        };
        ctx.ledger_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert_account(AccountRoot {
                account_id,
                balance: 100,
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
        for b in &mut blob[len - 10..] {
            *b ^= 0xFF;
        }
        let tampered = hex::encode_upper(blob);
        let resp = dispatch(
            req("submit", json!({"tx_blob": tampered})),
            &mut ctx_with_genesis(),
        );
        // Either temBAD_SIGNATURE or a parse error (invalidParams) — both are rejections
        let r = &resp.result;
        let is_rejection =
            r["engine_result"] == "temBAD_SIGNATURE" || r["error"] == "invalidParams";
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
            req(
                "tx",
                json!({
                    "transaction": oldest,
                    "binary": true,
                    "min_ledger": 10,
                    "max_ledger": 12
                }),
            ),
            &mut c,
        );
        assert_eq!(found.result["status"], "success");
        assert_eq!(found.result["ledger_index"], 10);

        let not_found_complete = dispatch(
            req(
                "tx",
                json!({
                    "transaction": "A".repeat(64),
                    "binary": true,
                    "min_ledger": 10,
                    "max_ledger": 12
                }),
            ),
            &mut c,
        );
        assert_eq!(not_found_complete.result["error"], "txnNotFound");
        assert_eq!(not_found_complete.result["searched_all"], true);

        let not_found_incomplete = dispatch(
            req(
                "tx",
                json!({
                    "transaction": "B".repeat(64),
                    "binary": true,
                    "min_ledger": 10,
                    "max_ledger": 99
                }),
            ),
            &mut c,
        );
        assert_eq!(not_found_incomplete.result["error"], "txnNotFound");
        assert_eq!(not_found_incomplete.result["searched_all"], false);
    }

    #[test]
    fn test_tx_invalid_and_excessive_ranges() {
        let resp = dispatch(
            req(
                "tx",
                json!({
                    "transaction": "A".repeat(64),
                    "min_ledger": 12,
                    "max_ledger": 10
                }),
            ),
            &mut ctx(),
        );
        assert_eq!(resp.result["error"], "invalidLgrRange");

        let resp = dispatch(
            req(
                "tx",
                json!({
                    "transaction": "A".repeat(64),
                    "min_ledger": 1,
                    "max_ledger": 1002
                }),
            ),
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
            req(
                "tx",
                json!({
                    "ctid": ctid.to_lowercase(),
                    "binary": false
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["ledger_index"], 12);
        assert_eq!(resp.result["ctid"], ctid);

        let wrong = dispatch(
            req(
                "tx",
                json!({
                    "ctid": encode_ctid(12, 0, 1).unwrap()
                }),
            ),
            &mut c,
        );
        assert_eq!(wrong.result["error"], "wrongNetwork");
        assert_eq!(wrong.result["error_code"], 4);
    }

    #[test]
    fn test_tx_transaction_and_ctid_rejected() {
        let mut c = ctx();
        let resp = dispatch(
            req(
                "tx",
                json!({
                    "transaction": "A".repeat(64),
                    "ctid": encode_ctid(12, 0, 0).unwrap()
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_tx_range_and_forward() {
        let (mut c, account) = ctx_with_account_tx_history();
        let resp = dispatch(
            req(
                "account_tx",
                json!({
                    "account": account,
                    "ledger_index_min": 11,
                    "ledger_index_max": 12,
                    "forward": true,
                    "binary": true
                }),
            ),
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
            req(
                "account_tx",
                json!({
                    "account": account,
                    "limit": 1
                }),
            ),
            &mut c,
        );
        assert_eq!(first.result["status"], "success");
        assert_eq!(first.result["transactions"].as_array().unwrap().len(), 1);
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let second = dispatch(
            req(
                "account_tx",
                json!({
                    "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                    "limit": 1,
                    "marker": marker
                }),
            ),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(second.result["transactions"].as_array().unwrap().len(), 1);
        assert_ne!(
            first.result["transactions"][0]["hash"],
            second.result["transactions"][0]["hash"]
        );
    }

    #[test]
    fn test_account_tx_invalid_limit_rejected() {
        let (mut c, account) = ctx_with_account_tx_history();
        let resp = dispatch(
            req(
                "account_tx",
                json!({
                    "account": account,
                    "limit": "not_an_int"
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_tx_exact_missing_ledger_not_found() {
        let (mut c, account) = ctx_with_account_tx_history();
        let resp = dispatch(
            req(
                "account_tx",
                json!({
                    "account": account,
                    "ledger_index": 999
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["error"], "lgrNotFound");
    }

    #[test]
    fn test_account_tx_count_and_offset() {
        let (mut c, account) = ctx_with_account_tx_history();
        let resp = dispatch(
            req(
                "account_tx",
                json!({
                    "account": account,
                    "count": true,
                    "offset": 1,
                    "limit": 1
                }),
            ),
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
            req(
                "account_tx",
                json!({
                    "account": account,
                    "limit": 1,
                    "binary": false
                }),
            ),
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
            req(
                "tx",
                json!({
                    "transaction": "A".repeat(64),
                    "binary": "yes"
                }),
            ),
            &mut ctx(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(
            resp.result["error_message"],
            "Invalid parameters: Invalid field 'binary'."
        );
    }

    #[test]
    fn test_account_tx_invalid_binary_rejected() {
        let (mut c, account) = ctx_with_account_tx_history();
        let resp = dispatch(
            req(
                "account_tx",
                json!({
                    "account": account,
                    "binary": "yes"
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(
            resp.result["error_message"],
            "Invalid parameters: Invalid field 'binary'."
        );
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
            req(
                "account_offers",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "limit": 1
                }),
            ),
            &mut c,
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();
        assert_eq!(first.result["offers"].as_array().unwrap().len(), 1);

        let second = dispatch(
            req(
                "account_offers",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "limit": 1,
                    "marker": marker
                }),
            ),
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
            req(
                "book_offers",
                json!({
                    "taker_pays": {"currency": "XRP"},
                    "taker_gets": {"currency": "USD", "issuer": issuer},
                    "limit": 1
                }),
            ),
            &mut c,
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();
        assert_eq!(first.result["offers"].as_array().unwrap().len(), 1);

        let second = dispatch(
            req(
                "book_offers",
                json!({
                    "taker_pays": {"currency": "XRP"},
                    "taker_gets": {"currency": "USD", "issuer": crate::crypto::base58::encode_account(&bob_id)},
                    "limit": 1,
                    "marker": marker
                }),
            ),
            &mut c,
        );
        assert_eq!(second.result["offers"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_book_offers_enriched_fields_and_owner_funds() {
        use crate::ledger::{offer::Offer, trustline::RippleState, AccountRoot};
        use crate::transaction::amount::{Amount, Currency, IouValue};

        let mut c = ctx();
        let issuer =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let owner =
            crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap();
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
                    previous_txn_lgr_seq: 0,
                    raw_sle: None,
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
            req(
                "book_offers",
                json!({
                    "taker_pays": {"currency": "XRP"},
                    "taker_gets": {"currency": "USD", "issuer": crate::crypto::base58::encode_account(&issuer)}
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        let offer = &resp.result["offers"][0];
        assert_eq!(
            offer["Account"],
            crate::crypto::base58::encode_account(&owner)
        );
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
            req(
                "account_currencies",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id)
                }),
            ),
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
            previous_txn_lgr_seq: 0,
            raw_sle: None,
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
            previous_txn_lgr_seq: 0,
            raw_sle: None,
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
            req(
                "account_currencies",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "ledger_index": 500
                }),
            ),
            &mut c,
        );
        // Historical queries now return error (no object_history CF)
        assert_eq!(resp.result["status"], "error");
    }

    #[test]
    fn test_account_channels_basic_and_marker() {
        let mut c = ctx_with_genesis();
        let account =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let dest =
            crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap();
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
                previous_txn_lgr_seq: 0,
                raw_sle: None,
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
            req(
                "account_channels",
                json!({
                    "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                    "limit": 1
                }),
            ),
            &mut c,
        );
        assert_eq!(first.result["status"], "success");
        assert_eq!(first.result["channels"].as_array().unwrap().len(), 1);
        let marker = first.result["marker"].as_str().unwrap().to_string();
        let second = dispatch(
            req(
                "account_channels",
                json!({
                    "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                    "limit": 1,
                    "marker": marker
                }),
            ),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(second.result["channels"].as_array().unwrap().len(), 1);
        assert_ne!(
            first.result["channels"][0]["channel_id"],
            second.result["channels"][0]["channel_id"]
        );
    }

    #[test]
    fn test_owner_info_combines_account_objects_lines_and_offers() {
        let (mut c, alice_id, _, _) = ctx_with_trustlines_and_offers();
        let resp = dispatch(
            req(
                "owner_info",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id)
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert!(resp.result["account_data"].is_object());
        assert!(resp.result["account_objects"].is_array());
        assert!(resp.result["lines"].is_array());
        assert!(resp.result["offers"].is_array());
    }

    #[test]
    fn test_nft_buy_and_sell_offers_filter_by_side() {
        let mut c = ctx_with_genesis();
        let owner =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let nft_id = [0x44; 32];
        {
            let ls = &mut *c.ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            ls.insert_nft_offer(crate::ledger::NFTokenOffer {
                account: owner,
                sequence: 1,
                nftoken_id: nft_id,
                amount: crate::transaction::amount::Amount::Xrp(1_000_000),
                destination: None,
                expiration: None,
                flags: 0x0001,
                owner_node: 0,
                nft_offer_node: 0,
                previous_txn_id: [0u8; 32],
                previous_txn_lgrseq: 0,
                raw_sle: None,
            });
            ls.insert_nft_offer(crate::ledger::NFTokenOffer {
                account: owner,
                sequence: 2,
                nftoken_id: nft_id,
                amount: crate::transaction::amount::Amount::Xrp(2_000_000),
                destination: None,
                expiration: None,
                flags: 0,
                owner_node: 0,
                nft_offer_node: 0,
                previous_txn_id: [0u8; 32],
                previous_txn_lgrseq: 0,
                raw_sle: None,
            });
        }

        let sell = dispatch(
            req(
                "nft_sell_offers",
                json!({"nft_id": hex::encode_upper(nft_id)}),
            ),
            &mut c,
        );
        assert_eq!(sell.result["status"], "success");
        assert_eq!(sell.result["offers"].as_array().unwrap().len(), 1);
        assert_eq!(sell.result["offers"][0]["Flags"], 1);

        let buy = dispatch(
            req(
                "nft_buy_offers",
                json!({"nft_id": hex::encode_upper(nft_id)}),
            ),
            &mut c,
        );
        assert_eq!(buy.result["status"], "success");
        assert_eq!(buy.result["offers"].as_array().unwrap().len(), 1);
        assert_eq!(buy.result["offers"][0]["Flags"], 0);
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
            req(
                "account_objects",
                json!({
                    "account": owner_addr,
                    "ledger_index": 500,
                    "type": "payment_channel",
                    "limit": 1
                }),
            ),
            &mut c,
        );
        assert_eq!(first_objects.result["status"], "success");
        assert_eq!(
            first_objects.result["account_objects"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            first_objects.result["account_objects"][0]["LedgerEntryType"],
            "PayChannel"
        );
        let marker = first_objects.result["marker"].as_str().unwrap().to_string();

        let second_objects = dispatch(
            req(
                "account_objects",
                json!({
                    "account": crate::crypto::base58::encode_account(&owner),
                    "ledger_index": 500,
                    "type": "payment_channel",
                    "limit": 1,
                    "marker": marker
                }),
            ),
            &mut c,
        );
        assert_eq!(second_objects.result["status"], "success");
        assert_eq!(
            second_objects.result["account_objects"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_ne!(
            first_objects.result["account_objects"][0]["index"],
            second_objects.result["account_objects"][0]["index"]
        );

        let first_channels = dispatch(
            req(
                "account_channels",
                json!({
                    "account": crate::crypto::base58::encode_account(&owner),
                    "ledger_index": 500,
                    "limit": 1
                }),
            ),
            &mut c,
        );
        assert_eq!(first_channels.result["status"], "success");
        assert_eq!(
            first_channels.result["channels"].as_array().unwrap().len(),
            1
        );
        let channel_marker = first_channels.result["marker"]
            .as_str()
            .unwrap()
            .to_string();

        let second_channels = dispatch(
            req(
                "account_channels",
                json!({
                    "account": crate::crypto::base58::encode_account(&owner),
                    "ledger_index": 500,
                    "limit": 1,
                    "marker": channel_marker
                }),
            ),
            &mut c,
        );
        assert_eq!(second_channels.result["status"], "success");
        assert_eq!(
            second_channels.result["channels"].as_array().unwrap().len(),
            1
        );
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
                previous_txn_lgr_seq: 0,
                raw_sle: None,
            });
            for serial in 1..=3u32 {
                let token_id =
                    crate::ledger::nftoken::make_nftoken_id(0x0008, 100, &alice_id, 7, serial);
                ls.insert_nftoken_paged(
                    &alice_id,
                    token_id,
                    Some(vec![serial as u8, serial as u8 + 1]),
                );
            }
        }
        (ctx, alice_id)
    }

    #[test]
    fn test_account_nfts_marker_paginates() {
        let (mut c, alice_id) = ctx_with_nft_pages();
        let first = dispatch(
            req(
                "account_nfts",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "limit": 1
                }),
            ),
            &mut c,
        );
        assert_eq!(first.result["status"], "success");
        assert_eq!(first.result["account_nfts"].as_array().unwrap().len(), 1);
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let second = dispatch(
            req(
                "account_nfts",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "limit": 1,
                    "marker": marker
                }),
            ),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(second.result["account_nfts"].as_array().unwrap().len(), 1);
        assert_ne!(
            first.result["account_nfts"][0],
            second.result["account_nfts"][0]
        );
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
            let token_id = crate::ledger::nftoken::make_nftoken_id(0x0008, 100, &owner, 7, serial);
            state.insert_nftoken_paged(&owner, token_id, Some(vec![serial as u8]));
        }

        let mut c = ctx_with_historical_state(state, 500, [0x67; 32]);
        let owner_addr = crate::crypto::base58::encode_account(&owner);
        let first = dispatch(
            req(
                "account_nfts",
                json!({
                    "account": owner_addr,
                    "ledger_index": 500,
                    "limit": 1
                }),
            ),
            &mut c,
        );
        assert_eq!(first.result["status"], "success");
        assert_eq!(first.result["account_nfts"].as_array().unwrap().len(), 1);
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let second = dispatch(
            req(
                "account_nfts",
                json!({
                    "account": crate::crypto::base58::encode_account(&owner),
                    "ledger_index": 500,
                    "limit": 1,
                    "marker": marker
                }),
            ),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(second.result["account_nfts"].as_array().unwrap().len(), 1);
        assert_ne!(
            first.result["account_nfts"][0],
            second.result["account_nfts"][0]
        );
    }

    #[test]
    fn test_account_nfts_invalid_account_and_marker_shape() {
        let (mut c, alice_id) = ctx_with_nft_pages();

        let bad_account = dispatch(
            req(
                "account_nfts",
                json!({
                    "account": 17
                }),
            ),
            &mut c,
        );
        assert_eq!(bad_account.result["error"], "invalidParams");
        assert_eq!(
            bad_account.result["error_message"],
            "Invalid parameters: Invalid field 'account'."
        );

        let first = dispatch(
            req(
                "account_nfts",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "limit": 1
                }),
            ),
            &mut c,
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();
        let bad_marker_type = dispatch(
            req(
                "account_nfts",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "marker": 17
                }),
            ),
            &mut c,
        );
        assert_eq!(bad_marker_type.result["error"], "invalidParams");
        assert_eq!(
            bad_marker_type.result["error_message"],
            "Invalid parameters: Invalid field 'marker', not string."
        );

        let fake_marker = format!("{}0", &marker[..marker.len() - 1]);
        let bad_marker_value = dispatch(
            req(
                "account_nfts",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "marker": fake_marker
                }),
            ),
            &mut c,
        );
        assert_eq!(bad_marker_value.result["error"], "invalidParams");
        assert_eq!(
            bad_marker_value.result["error_message"],
            "Invalid parameters: Invalid field 'marker'."
        );
    }

    #[test]
    fn test_ledger_entry_index_and_account_root() {
        let mut c = ctx_with_genesis();
        let account_id =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let key = crate::ledger::account::shamap_key(&account_id);

        let binary = dispatch(
            req(
                "ledger_entry",
                json!({
                    "index": hex::encode_upper(key.0),
                    "binary": true
                }),
            ),
            &mut c,
        );
        assert_eq!(binary.result["status"], "success");
        assert!(binary.result["node_binary"].as_str().unwrap().len() > 10);

        let json_resp = dispatch(
            req(
                "ledger_entry",
                json!({
                    "account_root": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
                }),
            ),
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
            req(
                "ledger_entry",
                json!({
                    "ripple_state": {
                        "accounts": [
                            crate::crypto::base58::encode_account(&alice_id),
                            crate::crypto::base58::encode_account(&bob_id)
                        ],
                        "currency": "USD"
                    }
                }),
            ),
            &mut trust_ctx,
        );
        assert_eq!(ripple.result["status"], "success");
        assert_eq!(ripple.result["node"]["LedgerEntryType"], "RippleState");

        let (mut nft_ctx, alice_id) = ctx_with_nft_pages();
        let page_key = {
            let ls = nft_ctx
                .ledger_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let key = ls
                .iter_nft_pages_for(&alice_id)
                .next()
                .map(|(k, _)| k)
                .unwrap();
            key
        };
        let page = dispatch(
            req(
                "ledger_entry",
                json!({
                    "nft_page": hex::encode_upper(page_key.0)
                }),
            ),
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
            req(
                "account_objects",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "type": "offer",
                    "limit": 1
                }),
            ),
            &mut c,
        );
        assert_eq!(first.result["status"], "success");
        assert_eq!(first.result["account_objects"].as_array().unwrap().len(), 1);
        assert_eq!(
            first.result["account_objects"][0]["LedgerEntryType"],
            "Offer"
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let second = dispatch(
            req(
                "account_objects",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "type": "offer",
                    "limit": 1,
                    "marker": marker
                }),
            ),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(
            second.result["account_objects"].as_array().unwrap().len(),
            1
        );
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
            req(
                "account_objects",
                json!({
                    "account": 17
                }),
            ),
            &mut c,
        );
        assert_eq!(bad_account.result["error"], "invalidParams");
        assert_eq!(
            bad_account.result["error_message"],
            "Invalid parameters: Invalid field 'account'."
        );

        let first = dispatch(
            req(
                "account_objects",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "type": "offer",
                    "limit": 1
                }),
            ),
            &mut c,
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let bad_marker_type = dispatch(
            req(
                "account_objects",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "marker": 17
                }),
            ),
            &mut c,
        );
        assert_eq!(bad_marker_type.result["error"], "invalidParams");
        assert_eq!(
            bad_marker_type.result["error_message"],
            "Invalid parameters: Invalid field 'marker', not string."
        );

        let bad_marker_value = dispatch(
            req(
                "account_objects",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "marker": marker.replace(',', "")
                }),
            ),
            &mut c,
        );
        assert_eq!(bad_marker_value.result["error"], "invalidParams");
        assert_eq!(
            bad_marker_value.result["error_message"],
            "Invalid parameters: Invalid field 'marker'."
        );
    }

    #[test]
    fn test_account_objects_invalid_type_and_limit_messages() {
        let (mut c, alice_id, _, _) = ctx_with_trustlines_and_offers();

        let bad_type_kind = dispatch(
            req(
                "account_objects",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "type": 10
                }),
            ),
            &mut c,
        );
        assert_eq!(bad_type_kind.result["error"], "invalidParams");
        assert_eq!(
            bad_type_kind.result["error_message"],
            "Invalid parameters: Invalid field 'type', not string."
        );

        let bad_type_value = dispatch(
            req(
                "account_objects",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "type": "expedited"
                }),
            ),
            &mut c,
        );
        assert_eq!(bad_type_value.result["error"], "invalidParams");
        assert_eq!(
            bad_type_value.result["error_message"],
            "Invalid parameters: Invalid field 'type'."
        );

        let bad_limit = dispatch(
            req(
                "account_objects",
                json!({
                    "account": crate::crypto::base58::encode_account(&alice_id),
                    "limit": -1
                }),
            ),
            &mut c,
        );
        assert_eq!(bad_limit.result["error"], "invalidParams");
        assert_eq!(
            bad_limit.result["error_message"],
            "Invalid parameters: Invalid field 'limit', not unsigned integer."
        );
    }

    #[test]
    fn test_historical_nft_offer_survives_storage_for_rpc() {
        use crate::ledger::node_store::NuDBNodeStore;
        use crate::ledger::AccountRoot;
        use crate::ledger::NFTokenOffer;
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
            previous_txn_lgr_seq: 0,
            raw_sle: None,
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
            req(
                "ledger_entry",
                json!({
                    "nft_offer": hex::encode_upper(offer_key.0),
                    "ledger_index": 500
                }),
            ),
            &mut c,
        );
        assert_eq!(entry.result["status"], "success");
        assert_eq!(entry.result["node"]["LedgerEntryType"], "NFTokenOffer");
        assert_eq!(entry.result["node"]["Amount"], "1000000");

        let objects = dispatch(
            req(
                "account_objects",
                json!({
                    "account": crate::crypto::base58::encode_account(&owner),
                    "type": "nft_offer",
                    "ledger_index": 500
                }),
            ),
            &mut c,
        );
        assert_eq!(objects.result["status"], "success");
        assert_eq!(
            objects.result["account_objects"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            objects.result["account_objects"][0]["LedgerEntryType"],
            "NFTokenOffer"
        );
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
        let resp = dispatch(
            req("ledger", json!({"ledger_index": "not_a_ledger"})),
            &mut ctx(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_lines_invalid_ledger_index() {
        let resp = dispatch(
            req(
                "account_lines",
                json!({
                    "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                    "ledger_index": "not_a_ledger"
                }),
            ),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_account_offers_invalid_ledger_index() {
        let resp = dispatch(
            req(
                "account_offers",
                json!({
                    "account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                    "ledger_index": "not_a_ledger"
                }),
            ),
            &mut ctx_with_genesis(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
    }

    #[test]
    fn test_book_offers_invalid_ledger_index() {
        let resp = dispatch(
            req(
                "book_offers",
                json!({
                    "taker_pays": { "currency": "XRP" },
                    "taker_gets": { "currency": "USD", "issuer": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh" },
                    "ledger_index": "not_a_ledger"
                }),
            ),
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
            req(
                "ledger_data",
                json!({"ledger_index": 500, "marker": "not_hex"}),
            ),
            &mut c,
        );
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(
            resp.result["error_message"],
            "Invalid parameters: Invalid field 'marker', not valid."
        );

        let resp = dispatch(
            req("ledger_data", json!({"ledger_index": 500, "marker": 17})),
            &mut c,
        );
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(
            resp.result["error_message"],
            "Invalid parameters: Invalid field 'marker', not valid."
        );
    }

    #[test]
    fn test_ledger_data_invalid_limit_message() {
        let resp = dispatch(req("ledger_data", json!({"limit": "0"})), &mut ctx());
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(
            resp.result["error_message"],
            "Invalid parameters: Invalid field 'limit', not integer."
        );
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
                    previous_txn_lgr_seq: 0,
                    raw_sle: None,
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
        assert_ne!(
            first.result["state"][0]["index"],
            second.result["state"][0]["index"]
        );
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
        assert_eq!(
            first_state[0]["index"],
            hex::encode_upper(expected_keys[0].0)
        );
        assert_eq!(
            first_state[1]["index"],
            hex::encode_upper(expected_keys[1].0)
        );
        let marker = first.result["marker"].as_str().unwrap().to_string();

        let second = dispatch(
            req(
                "ledger_data",
                json!({"ledger_index": 500, "limit": 2, "marker": marker}),
            ),
            &mut c,
        );
        assert_eq!(second.result["status"], "success");
        assert_eq!(second.result["historical"], true);
        let second_state = second.result["state"].as_array().unwrap();
        assert_eq!(second_state.len(), 1);
        assert_eq!(
            second_state[0]["index"],
            hex::encode_upper(expected_keys[2].0)
        );
        assert!(second.result.get("marker").is_none());
    }

    #[test]
    fn test_book_offers_zero_limit_rejected() {
        let resp = dispatch(
            req(
                "book_offers",
                json!({
                    "ledger_index": "validated",
                    "limit": 0,
                    "taker_pays": { "currency": "XRP" },
                    "taker_gets": { "currency": "USD", "issuer": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh" }
                }),
            ),
            &mut ctx(),
        );
        assert_eq!(resp.result["error"], "invalidParams");
        assert_eq!(
            resp.result["error_message"],
            "Invalid parameters: Invalid field 'limit'."
        );
    }

    fn test_header(sequence: u32) -> crate::ledger::LedgerHeader {
        crate::ledger::LedgerHeader {
            sequence,
            hash: [sequence as u8; 32],
            parent_hash: [0u8; 32],
            close_time: sequence as u64,
            total_coins: 100_000_000_000_000_000,
            account_hash: [0u8; 32],
            transaction_hash: [0u8; 32],
            parent_close_time: sequence.saturating_sub(1),
            close_time_resolution: 10,
            close_flags: 0,
        }
    }

    fn build_price_data_series(base: [u8; 20], quote: [u8; 20], price: u64, scale: u8) -> Vec<u8> {
        let mut data = Vec::new();
        crate::ledger::meta::write_field_header_pub(&mut data, 14, 32);
        crate::ledger::meta::write_field_header_pub(&mut data, 26, 1);
        data.extend_from_slice(&base);
        crate::ledger::meta::write_field_header_pub(&mut data, 26, 2);
        data.extend_from_slice(&quote);
        crate::ledger::meta::write_field_header_pub(&mut data, 3, 23);
        data.extend_from_slice(&price.to_be_bytes());
        crate::ledger::meta::write_field_header_pub(&mut data, 16, 4);
        data.push(scale);
        data.push(0xE1);
        data.push(0xF1);
        data
    }

    #[test]
    fn test_ledger_accept_sets_force_flag() {
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let accept_service =
            std::sync::Arc::new(crate::ledger::control::LedgerAcceptService::default());
        let accept_service_bg = accept_service.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(25));
            accept_service_bg.complete(1002);
        });
        let mut c = ctx();
        c.standalone_mode = true;
        c.force_ledger_accept = Some(flag.clone());
        c.ledger_accept_service = Some(accept_service);

        let resp = dispatch(req("ledger_accept", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["ledger_current_index"], 1002);
        assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_ledger_accept_requires_standalone_mode() {
        let mut c = ctx();
        c.standalone_mode = false;

        let resp = dispatch(req("ledger_accept", json!({})), &mut c);
        assert_eq!(resp.result["status"], "error");
        assert_eq!(resp.result["error"], "notStandAlone");
    }

    #[test]
    fn test_ledger_accept_requires_close_loop_service() {
        let mut c = ctx();
        c.standalone_mode = true;
        c.force_ledger_accept = Some(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)));

        let resp = dispatch(req("ledger_accept", json!({})), &mut c);
        assert_eq!(resp.result["status"], "error");
        assert_eq!(resp.result["error"], "internal");
    }

    #[test]
    fn test_path_find_create_status_and_close_round_trip() {
        let mut c = ctx();

        let create = dispatch(
            req(
                "path_find",
                json!({
                    "client_id": 7,
                    "subcommand": "create",
                    "source_account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                    "destination_account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
                    "destination_amount": "1"
                }),
            ),
            &mut c,
        );
        assert_eq!(create.result["status"], "success");
        assert_eq!(create.result["type"], "path_find");
        assert!(create.result["alternatives"].is_array());

        let status = dispatch(
            req(
                "path_find",
                json!({
                    "client_id": 7,
                    "subcommand": "status"
                }),
            ),
            &mut c,
        );
        assert_eq!(status.result["status"], "success");
        assert_eq!(status.result["type"], "path_find");

        let close = dispatch(
            req(
                "path_find",
                json!({
                    "client_id": 7,
                    "subcommand": "close"
                }),
            ),
            &mut c,
        );
        assert_eq!(close.result["status"], "success");
        assert_eq!(close.result["closed"], true);
    }

    #[test]
    fn test_path_find_status_requires_active_request() {
        let mut c = ctx();
        let status = dispatch(
            req(
                "path_find",
                json!({
                    "client_id": 88,
                    "subcommand": "status"
                }),
            ),
            &mut c,
        );
        assert_eq!(status.result["status"], "error");
        assert_eq!(status.result["error"], "invalidParams");
    }

    #[test]
    fn test_ledger_current_prefers_open_ledger_snapshot() {
        let mut c = ctx();
        c.open_ledger_snapshot = Some(crate::ledger::open_ledger::OpenLedgerSnapshot {
            ledger_current_index: 2001,
            parent_ledger_index: 2000,
            parent_hash: "AA".repeat(32),
            last_close_time: 1,
            queued_transactions: 0,
            candidate_set_hash: "BB".repeat(32),
            escalation_multiplier: crate::ledger::pool::BASE_LEVEL * 500,
            txns_expected: 32,
            max_queue_size: 2000,
            open_fee_level: crate::ledger::pool::BASE_LEVEL,
            revision: 0,
            modify_count: 0,
            accept_count: 0,
            last_modified_unix: 0,
            last_accept_unix: 0,
            ..Default::default()
        });
        let resp = dispatch(req("ledger_current", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["ledger_current_index"], 2001);
    }

    #[test]
    fn test_blacklist_filters_by_threshold() {
        let mut c = ctx();
        c.blacklist_entries = vec![
            crate::rpc::BlacklistEntry {
                address: "127.0.0.1:51235".into(),
                reason: "peer cooldown".into(),
                expires_in_ms: 500,
            },
            crate::rpc::BlacklistEntry {
                address: "127.0.0.1:51236".into(),
                reason: "sync cooldown".into(),
                expires_in_ms: 2_000,
            },
        ];

        let resp = dispatch(req("blacklist", json!({"threshold": 1000})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["count"], 1);
        assert_eq!(resp.result["blacklist"][0]["address"], "127.0.0.1:51236");
    }

    #[test]
    fn test_tx_reduce_relay_shape() {
        let mut c = ctx();
        c.tx_relay_metrics = Some(crate::rpc::TxRelayMetricsSnapshot {
            queued_transactions: 12,
            peer_count: 7,
            max_queue_size: 200,
            escalation_multiplier: 4,
            txns_expected: 9,
            candidate_set_hash: "AB".repeat(32),
            tracked_transactions: 11,
            submitted_transactions: 2,
            inbound_tracked: 5,
            accepted_transactions: 10,
            duplicate_transactions: 3,
            relayed_transactions: 8,
            persisted_transactions: 6,
        });

        let resp = dispatch(req("tx_reduce_relay", json!({})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["queued_transactions"], 12);
        assert_eq!(resp.result["candidate_set_hash"], "AB".repeat(32));
        assert_eq!(resp.result["tracked_transactions"], 11);
        assert_eq!(resp.result["submitted_transactions"], 2);
    }

    #[test]
    fn test_ledger_cleaner_prunes_history_when_configured() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = std::sync::Arc::new(crate::storage::Storage::open(tmp.path()).unwrap());
        for seq in 1..=3 {
            storage.save_ledger(&test_header(seq), &[]).unwrap();
        }
        let cleaner =
            crate::ledger::control::LedgerCleanerService::new(Some(storage.clone()), Some(2));

        let mut c = ctx();
        c.storage = Some(storage);
        c.ledger_seq = 5;
        c.online_delete = Some(2);
        c.ledger_cleaner = Some(cleaner.clone());

        let resp = dispatch(req("ledger_cleaner", json!({"max_ledger": 2})), &mut c);
        assert_eq!(resp.result["status"], "success");
        assert!(resp.result["message"].is_string());
        assert!(matches!(
            resp.result["state"].as_str(),
            Some("queued") | Some("cleaning") | Some("idle")
        ));
        assert_eq!(resp.result["online_delete"], 2);
        assert!(resp.result["pending"].is_boolean());
        assert_eq!(resp.result["max_ledger"], 2);
        assert!(resp.result["history_pruned"].is_number());
        assert!(resp.result["failures"].is_number());

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if !c.storage
                .as_ref()
                .unwrap()
                .has_full_ledger_range(1, 2)
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(!c.storage.as_ref().unwrap().has_full_ledger_range(1, 2));
        assert!(cleaner.snapshot().history_pruned >= 2);
    }

    #[test]
    fn test_get_aggregate_price_from_current_oracle_sle() {
        let mut c = ctx();
        let account =
            crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let usd = crate::transaction::amount::Currency::from_code("USD")
            .unwrap()
            .code;
        let eur = crate::transaction::amount::Currency::from_code("EUR")
            .unwrap()
            .code;
        let key = oracle_state_key(&account, 7);
        let raw = crate::ledger::meta::build_sle(
            0x0080,
            &[
                crate::ledger::meta::ParsedField {
                    type_code: 2,
                    field_code: 51,
                    data: 7u32.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 2,
                    field_code: 15,
                    data: 1_234u32.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 15,
                    field_code: 24,
                    data: build_price_data_series(usd, eur, 125, 2),
                },
            ],
            None,
            None,
        );
        c.ledger_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert_raw(key, raw);

        let resp = dispatch(
            req(
                "get_aggregate_price",
                json!({
                    "oracles": [{
                        "account": crate::crypto::base58::encode_account(&account),
                        "oracle_document_id": 7
                    }],
                    "base_asset": "USD",
                    "quote_asset": "EUR"
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert_eq!(resp.result["time"], 1234);
        assert_eq!(resp.result["entire_set"]["size"], 1);
        assert_eq!(resp.result["entire_set"]["mean"], "1.25");
        assert_eq!(resp.result["median"], "1.25");
    }

    #[test]
    fn test_simulate_autofills_unsigned_accountset() {
        let mut c = ctx_with_genesis();
        let genesis = crate::crypto::base58::encode_account(
            &crate::crypto::base58::decode_account("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap(),
        );

        let resp = dispatch(
            req(
                "simulate",
                json!({
                    "tx_json": {
                        "TransactionType": "AccountSet",
                        "Account": genesis,
                        "SetFlag": 1
                    }
                }),
            ),
            &mut c,
        );
        assert_eq!(resp.result["status"], "success");
        assert!(resp.result["engine_result"].is_string());
        assert!(resp.result["tx_json"]["Fee"].is_string());
        assert!(resp.result["tx_json"]["Sequence"].is_number());
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
