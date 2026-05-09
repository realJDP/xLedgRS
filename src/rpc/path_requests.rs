use serde_json::Value;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct PathRequestSummary {
    pub client_id: u64,
    pub source_account: Option<String>,
    pub destination_account: Option<String>,
    pub destination_amount: Option<String>,
    pub created_unix: u64,
    pub updated_unix: u64,
    pub update_count: u64,
    pub last_status: String,
}

#[derive(Debug, Clone, Default)]
pub struct PathRequestSnapshot {
    pub active_requests: usize,
    pub last_recompute_unix: Option<u64>,
    pub entries: Vec<PathRequestSummary>,
}

#[derive(Debug, Clone)]
struct PathRequestEntry {
    request: Value,
    source_account: Option<String>,
    destination_account: Option<String>,
    destination_amount: Option<String>,
    created_unix: u64,
    updated_unix: u64,
    update_count: u64,
    last_status: String,
}

#[derive(Debug, Default)]
pub struct PathRequestManager {
    entries: BTreeMap<u64, PathRequestEntry>,
    last_recompute_unix: Option<u64>,
}

impl PathRequestManager {
    pub fn upsert(&mut self, client_id: u64, request: Value, result: &Value) {
        let now = unix_now();
        let last_status = result
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("success")
            .to_string();
        let source_account = request
            .get("source_account")
            .and_then(Value::as_str)
            .map(str::to_string);
        let destination_account = request
            .get("destination_account")
            .and_then(Value::as_str)
            .map(str::to_string);
        let destination_amount = request
            .get("destination_amount")
            .map(render_amount)
            .filter(|value| !value.is_empty());

        match self.entries.get_mut(&client_id) {
            Some(entry) => {
                entry.request = request;
                entry.source_account = source_account;
                entry.destination_account = destination_account;
                entry.destination_amount = destination_amount;
                entry.updated_unix = now;
                entry.update_count = entry.update_count.saturating_add(1);
                entry.last_status = last_status;
            }
            None => {
                self.entries.insert(
                    client_id,
                    PathRequestEntry {
                        request,
                        source_account,
                        destination_account,
                        destination_amount,
                        created_unix: now,
                        updated_unix: now,
                        update_count: 1,
                        last_status,
                    },
                );
            }
        }
    }

    pub fn request_for(&self, client_id: u64) -> Option<Value> {
        self.entries
            .get(&client_id)
            .map(|entry| entry.request.clone())
    }

    pub fn close(&mut self, client_id: u64) -> bool {
        self.entries.remove(&client_id).is_some()
    }

    pub fn note_recompute(&mut self) {
        self.last_recompute_unix = Some(unix_now());
    }

    pub fn snapshot(&self, limit: usize) -> PathRequestSnapshot {
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .map(|(client_id, entry)| PathRequestSummary {
                client_id: *client_id,
                source_account: entry.source_account.clone(),
                destination_account: entry.destination_account.clone(),
                destination_amount: entry.destination_amount.clone(),
                created_unix: entry.created_unix,
                updated_unix: entry.updated_unix,
                update_count: entry.update_count,
                last_status: entry.last_status.clone(),
            })
            .collect();
        entries.sort_by(|a, b| {
            b.updated_unix
                .cmp(&a.updated_unix)
                .then_with(|| a.client_id.cmp(&b.client_id))
        });
        entries.truncate(limit);
        PathRequestSnapshot {
            active_requests: self.entries.len(),
            last_recompute_unix: self.last_recompute_unix,
            entries,
        }
    }
}

fn render_amount(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Object(map) => map
            .get("value")
            .map(render_amount)
            .or_else(|| map.get("currency").map(render_amount))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn upsert_snapshot_and_close_round_trip() {
        let mut manager = PathRequestManager::default();
        let req = json!({
            "source_account": "rSource",
            "destination_account": "rDest",
            "destination_amount": "1000"
        });
        manager.upsert(
            7,
            req.clone(),
            &json!({"alternatives": [], "status": "success"}),
        );
        assert_eq!(manager.request_for(7), Some(req));

        let snapshot = manager.snapshot(8);
        assert_eq!(snapshot.active_requests, 1);
        assert_eq!(snapshot.entries[0].client_id, 7);
        assert_eq!(
            snapshot.entries[0].destination_amount.as_deref(),
            Some("1000")
        );

        assert!(manager.close(7));
        assert!(manager.request_for(7).is_none());
        assert_eq!(manager.snapshot(8).active_requests, 0);
    }

    #[test]
    fn note_recompute_updates_snapshot() {
        let mut manager = PathRequestManager::default();
        manager.note_recompute();
        assert!(manager.snapshot(1).last_recompute_unix.is_some());
    }
}
