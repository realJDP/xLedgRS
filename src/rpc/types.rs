//! JSON-RPC envelope types for requests, responses, and errors.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

// ── Request ───────────────────────────────────────────────────────────────────

/// A JSON-RPC request. Supports both the flat rippled format and
/// the standard JSON-RPC 2.0 format.
///
/// Rippled wraps params in an array: `{"method":"x","params":[{...}]}`
/// JSON-RPC 2.0 uses an object directly: `{"method":"x","params":{...}}`
#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub id: Value,
}

impl RpcRequest {
    /// Parse from raw JSON bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let mut req: Self = serde_json::from_slice(bytes)?;
        // Normalize a single-object rippled-style params array to an object.
        if let Value::Array(ref arr) = req.params.clone() {
            if arr.len() == 1 {
                if let Some(Value::Object(_)) = arr.first() {
                    req.params = arr[0].clone();
                }
            }
        }
        Ok(req)
    }

    /// Get a string param by key.
    pub fn param_str(&self, key: &str) -> Option<&str> {
        self.params.get(key)?.as_str()
    }

    /// Get a bool param by key (default false).
    pub fn param_bool(&self, key: &str) -> bool {
        self.params
            .get(key)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }
}

// ── Response ──────────────────────────────────────────────────────────────────

/// A JSON-RPC response matching the rippled envelope format.
#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub result: Value,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub id: Value,
}

impl RpcResponse {
    pub fn ok(mut result: Value, id: Value) -> Self {
        // Ensure the result carries `"status": "success"` by default.
        if let Value::Object(ref mut map) = result {
            map.entry("status")
                .or_insert_with(|| Value::String("success".into()));
        }
        Self { result, id }
    }

    pub fn err(error: RpcError, id: Value) -> Self {
        let mut result = serde_json::json!({
            "status":        "error",
            "error":         error.code,
            "error_code":    error.error_code,
            "error_message": error.message,
            "request":       Value::Null,
        });
        if let (Value::Object(map), Some(extra)) = (&mut result, error.extra) {
            map.extend(extra);
        }
        Self { result, id }
    }

    /// Serialize to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.into())
    }
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RpcError {
    pub code: &'static str,
    pub error_code: u32,
    pub message: String,
    pub extra: Option<Map<String, Value>>,
}

impl RpcError {
    /// Map a rippled error string to its standard numeric error code.
    fn numeric_code(code: &str) -> u32 {
        match code {
            "wrongNetwork" => 4,
            "unknownCmd" => 32,
            "invalidParams" => 31,
            "forbidden" => 403,
            "actNotFound" => 19,
            "txnNotFound" => 29,
            "actMalformed" => 35,
            "internal" => 73,
            "excessiveLgrRange" => 78,
            "invalidLgrRange" => 79,
            _ => 0,
        }
    }

    pub fn unknown_method(name: &str) -> Self {
        Self {
            code: "unknownCmd",
            error_code: Self::numeric_code("unknownCmd"),
            message: format!("Unknown method: {name}"),
            extra: None,
        }
    }

    pub fn invalid_params(detail: &str) -> Self {
        Self {
            code: "invalidParams",
            error_code: Self::numeric_code("invalidParams"),
            message: format!("Invalid parameters: {detail}"),
            extra: None,
        }
    }

    pub fn forbidden(detail: &str) -> Self {
        Self {
            code: "forbidden",
            error_code: Self::numeric_code("forbidden"),
            message: detail.to_string(),
            extra: None,
        }
    }

    pub fn not_found(what: &str) -> Self {
        Self {
            code: "actNotFound",
            error_code: Self::numeric_code("actNotFound"),
            message: format!("Not found: {what}"),
            extra: None,
        }
    }

    pub fn internal(detail: &str) -> Self {
        Self {
            code: "internal",
            error_code: Self::numeric_code("internal"),
            message: format!("Internal error: {detail}"),
            extra: None,
        }
    }
}
