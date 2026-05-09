use serde_json::Value;
use std::env;
use std::fs;
use std::path::Path;

const BUNDLED: &str = "src/rpc/data/server_definitions_mainnet_3_1_2.json";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let candidate = args.next().ok_or_else(|| {
        format!("usage: server_definitions_exact_diff <candidate.json> [proof.json]")
    })?;
    let proof = args.next();

    let bundled_text = fs::read_to_string(BUNDLED)?;
    let candidate_text = fs::read_to_string(&candidate)?;
    let bundled: Value = serde_json::from_str(&bundled_text)?;
    let candidate_json: Value = serde_json::from_str(&candidate_text)?;

    let bundled_canonical = serde_json::to_string(&bundled)?;
    let candidate_canonical = serde_json::to_string(&candidate_json)?;
    let exact_match = bundled_canonical == candidate_canonical;

    let report = serde_json::json!({
        "bundled": BUNDLED,
        "candidate": candidate,
        "exact_match": exact_match,
        "bundled_sha512_half": sha512_half_hex(bundled_canonical.as_bytes()),
        "candidate_sha512_half": sha512_half_hex(candidate_canonical.as_bytes()),
        "summary": diff_summary(&bundled, &candidate_json),
    });

    if let Some(path) = proof {
        fs::write(Path::new(&path), serde_json::to_string_pretty(&report)?)?;
    }
    println!("{}", serde_json::to_string_pretty(&report)?);

    if exact_match {
        Ok(())
    } else {
        Err("server definitions differ".into())
    }
}

fn sha512_half_hex(data: &[u8]) -> String {
    hex::encode_upper(xrpl::crypto::sha512_first_half(data))
}

fn diff_summary(left: &Value, right: &Value) -> Value {
    let mut diffs = Vec::new();
    collect_diffs("", left, right, &mut diffs, 64);
    serde_json::json!({
        "first_differences": diffs,
    })
}

fn collect_diffs(path: &str, left: &Value, right: &Value, diffs: &mut Vec<Value>, limit: usize) {
    if diffs.len() >= limit || left == right {
        return;
    }
    match (left, right) {
        (Value::Object(l), Value::Object(r)) => {
            let keys: std::collections::BTreeSet<_> = l.keys().chain(r.keys()).collect();
            for key in keys {
                let next = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                match (l.get(key), r.get(key)) {
                    (Some(lv), Some(rv)) => collect_diffs(&next, lv, rv, diffs, limit),
                    (Some(_), None) => diffs
                        .push(serde_json::json!({"path": next, "kind": "missing_in_candidate"})),
                    (None, Some(_)) => {
                        diffs.push(serde_json::json!({"path": next, "kind": "extra_in_candidate"}))
                    }
                    (None, None) => {}
                }
                if diffs.len() >= limit {
                    break;
                }
            }
        }
        (Value::Array(l), Value::Array(r)) => {
            let max = l.len().max(r.len());
            for idx in 0..max {
                let next = format!("{path}[{idx}]");
                match (l.get(idx), r.get(idx)) {
                    (Some(lv), Some(rv)) => collect_diffs(&next, lv, rv, diffs, limit),
                    (Some(_), None) => diffs
                        .push(serde_json::json!({"path": next, "kind": "missing_in_candidate"})),
                    (None, Some(_)) => {
                        diffs.push(serde_json::json!({"path": next, "kind": "extra_in_candidate"}))
                    }
                    (None, None) => {}
                }
                if diffs.len() >= limit {
                    break;
                }
            }
        }
        _ => diffs.push(serde_json::json!({
            "path": path,
            "kind": "value_mismatch",
            "bundled": preview(left),
            "candidate": preview(right),
        })),
    }
}

fn preview(value: &Value) -> String {
    let mut out = value.to_string();
    if out.len() > 160 {
        out.truncate(157);
        out.push_str("...");
    }
    out
}
