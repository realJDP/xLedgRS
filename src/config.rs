//! Node configuration parsing.
//!
//! Supports two formats:
//! - the project-local TOML format
//! - a rippled/xrpld-style sectioned config (`xrpld.cfg`)

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryRetention {
    None,
    Full,
    Count(u32),
}

impl Default for HistoryRetention {
    fn default() -> Self {
        Self::Count(256)
    }
}

impl HistoryRetention {
    pub fn max_history_limit(self) -> Option<u32> {
        match self {
            Self::None => Some(0),
            Self::Full => None,
            Self::Count(n) => Some(n),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeConfig {
    pub peer_addr: Option<SocketAddr>,
    pub rpc_addr: Option<SocketAddr>,
    pub ws_addr: Option<SocketAddr>,
    pub grpc_addr: Option<SocketAddr>,
    pub rpc_sync: Option<String>,
    pub max_peers: Option<usize>,
    pub bootstrap_peers: Vec<String>,
    pub fixed_peers: Vec<String>,
    pub data_dir: Option<PathBuf>,
    pub network_id: Option<u32>,
    pub ledger_history: Option<HistoryRetention>,
    pub fetch_depth: Option<HistoryRetention>,
    pub online_delete: Option<u32>,
    pub standalone: Option<bool>,
    pub enable_consensus_close_loop: Option<bool>,
    pub post_sync_checkpoint_script: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigFile {
    pub validators: Vec<ValidatorEntry>,
    pub validator_lists: ValidatorListConfig,
    pub amendments: AmendmentConfig,
    pub runtime: RuntimeConfig,
    /// Base58-encoded validation seed (e.g. `sEdV19BLfe...`).
    /// When present, the node signs validations and proposals with this key
    /// instead of the random node identity key.
    pub validation_seed: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ValidatorEntry {
    /// Raw 33-byte compressed secp256k1 public key bytes.
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct AmendmentConfig {
    pub enabled: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatorListConfig {
    pub sites: Vec<String>,
    pub publisher_keys: Vec<String>,
    pub threshold: Option<u32>,
}

impl ValidatorListConfig {
    pub fn effective_threshold(&self) -> u32 {
        match self.threshold {
            Some(0) | None => {
                let n = self.publisher_keys.len() as u32;
                if n < 3 {
                    1
                } else {
                    (n / 2) + 1
                }
            }
            Some(v) => v,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct TomlConfigFile {
    #[serde(default)]
    validators: Vec<TomlValidatorEntry>,
    #[serde(default)]
    amendments: TomlAmendmentConfig,
    #[serde(default)]
    node: TomlNodeConfig,
    /// `validation_seed = "sEdV19BLfe..."` in TOML.
    validation_seed: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TomlValidatorEntry {
    public_key: String,
}

#[derive(Debug, Deserialize, Default)]
struct TomlAmendmentConfig {
    #[serde(default)]
    enabled: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct TomlNodeConfig {
    peer_addr: Option<String>,
    rpc_addr: Option<String>,
    ws_addr: Option<String>,
    grpc_addr: Option<String>,
    rpc_sync: Option<String>,
    max_peers: Option<usize>,
    #[serde(default)]
    bootstrap_peers: Vec<String>,
    #[serde(default)]
    fixed_peers: Vec<String>,
    data_dir: Option<String>,
    network_id: Option<u32>,
    ledger_history: Option<String>,
    fetch_depth: Option<String>,
    online_delete: Option<u32>,
    standalone: Option<bool>,
    enable_consensus_close_loop: Option<bool>,
    post_sync_checkpoint_script: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct SectionConfig {
    values: HashMap<String, String>,
    items: Vec<String>,
}

impl ConfigFile {
    /// Load and parse either TOML or rippled-style config.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;

        if let Ok(toml_cfg) = toml::from_str::<TomlConfigFile>(&contents) {
            return Ok(Self::from_toml(toml_cfg, path));
        }

        Self::from_rippled_cfg(&contents, path)
    }

    /// Extract the UNL as raw public key bytes.
    pub fn unl(&self) -> Vec<Vec<u8>> {
        self.validators
            .iter()
            .map(|v| v.public_key.clone())
            .collect()
    }

    /// Extract enabled amendments as a HashSet.
    pub fn enabled_amendments(&self) -> HashSet<String> {
        self.amendments.enabled.iter().cloned().collect()
    }

    fn from_toml(toml_cfg: TomlConfigFile, path: &Path) -> Self {
        let validators = toml_cfg
            .validators
            .into_iter()
            .filter_map(|v| decode_validator_key(&v.public_key))
            .map(|public_key| ValidatorEntry { public_key })
            .collect();

        let runtime = RuntimeConfig {
            peer_addr: toml_cfg.node.peer_addr.and_then(|s| s.parse().ok()),
            rpc_addr: toml_cfg.node.rpc_addr.and_then(|s| s.parse().ok()),
            ws_addr: toml_cfg.node.ws_addr.and_then(|s| s.parse().ok()),
            grpc_addr: toml_cfg.node.grpc_addr.and_then(|s| s.parse().ok()),
            rpc_sync: toml_cfg.node.rpc_sync,
            max_peers: toml_cfg.node.max_peers,
            bootstrap_peers: toml_cfg.node.bootstrap_peers,
            fixed_peers: toml_cfg.node.fixed_peers,
            data_dir: toml_cfg.node.data_dir.map(|p| resolve_path(path, &p)),
            network_id: toml_cfg.node.network_id,
            ledger_history: toml_cfg
                .node
                .ledger_history
                .as_deref()
                .and_then(parse_history_retention),
            fetch_depth: toml_cfg
                .node
                .fetch_depth
                .as_deref()
                .and_then(parse_history_retention),
            online_delete: toml_cfg.node.online_delete,
            standalone: toml_cfg.node.standalone,
            enable_consensus_close_loop: toml_cfg.node.enable_consensus_close_loop,
            post_sync_checkpoint_script: toml_cfg
                .node
                .post_sync_checkpoint_script
                .map(|p| resolve_path(path, &p)),
        };

        Self {
            validators,
            validator_lists: ValidatorListConfig::default(),
            amendments: AmendmentConfig {
                enabled: toml_cfg.amendments.enabled,
            },
            runtime,
            validation_seed: toml_cfg.validation_seed,
        }
    }

    fn from_rippled_cfg(contents: &str, path: &Path) -> Result<Self> {
        let sections = parse_sections(contents);

        let server_defaults = sections.get("server").cloned().unwrap_or_default();
        let server_names = server_defaults.items.clone();

        let mut runtime = RuntimeConfig::default();
        for name in server_names {
            if let Some(addr) =
                parse_server_port(&sections, &server_defaults.values, &name, &["peer"])
            {
                runtime.peer_addr.get_or_insert(addr);
            }
            if let Some(addr) = parse_server_port(
                &sections,
                &server_defaults.values,
                &name,
                &["http", "https"],
            ) {
                runtime.rpc_addr.get_or_insert(addr);
            }
            if let Some(addr) =
                parse_server_port(&sections, &server_defaults.values, &name, &["grpc"])
            {
                runtime.grpc_addr.get_or_insert(addr);
            }
            if let Some(addr) =
                parse_server_port(&sections, &server_defaults.values, &name, &["ws", "wss"])
            {
                runtime.ws_addr.get_or_insert(addr);
            }
        }

        if let Some(section) = sections.get("peers_max") {
            runtime.max_peers = first_scalar(section).and_then(|s| s.parse().ok());
        }
        if let Some(section) = sections.get("ips") {
            runtime.bootstrap_peers = section.items.clone();
        }
        if let Some(section) = sections.get("ips_fixed") {
            runtime.fixed_peers = section.items.clone();
        }
        if let Some(section) = sections.get("network_id") {
            runtime.network_id = first_scalar(section).and_then(parse_network_id);
        }
        if let Some(section) = sections.get("ledger_history") {
            runtime.ledger_history = first_scalar(section).and_then(parse_history_retention);
        }
        if let Some(section) = sections.get("fetch_depth") {
            runtime.fetch_depth = first_scalar(section).and_then(parse_history_retention);
        }
        if let Some(section) = sections.get("node_db") {
            runtime.online_delete = section
                .values
                .get("online_delete")
                .and_then(|v| v.parse().ok());
            if let Some(p) = section.values.get("path") {
                runtime.data_dir = Some(resolve_path(path, p));
            }
        }
        if let Some(section) = sections.get("database_path") {
            if let Some(p) = first_scalar(section) {
                runtime.data_dir = Some(resolve_path(path, p));
            }
        }
        if let Some(section) = sections.get("xledgrs") {
            runtime.rpc_sync = section.values.get("rpc_sync").cloned();
            runtime.standalone = section.values.get("standalone").and_then(|v| parse_bool(v));
            runtime.enable_consensus_close_loop = section
                .values
                .get("enable_consensus_close_loop")
                .and_then(|v| parse_bool(v));
            if let Some(p) = section.values.get("post_sync_checkpoint_script") {
                runtime.post_sync_checkpoint_script = Some(resolve_path(path, p));
            }
        }

        let mut validators = Vec::new();
        let mut validator_lists = ValidatorListConfig::default();
        if let Some(section) = sections.get("validators") {
            validators.extend(
                section
                    .items
                    .iter()
                    .filter_map(|v| decode_validator_key(v))
                    .map(|public_key| ValidatorEntry { public_key }),
            );
        }
        if let Some(section) = sections.get("validators_file") {
            if let Some(rel_path) = first_scalar(section) {
                let validator_path = resolve_path(path, rel_path);
                let file_cfg = load_validators_file(&validator_path)?;
                validators.extend(file_cfg.validators);
                validator_lists.sites.extend(file_cfg.validator_lists.sites);
                validator_lists
                    .publisher_keys
                    .extend(file_cfg.validator_lists.publisher_keys);
                validator_lists.threshold = file_cfg.validator_lists.threshold;
            }
        }

        let mut amendments = AmendmentConfig::default();
        if let Some(section) = sections.get("amendments") {
            amendments.enabled.extend(section.items.clone());
        }
        if let Some(section) = sections.get("features") {
            amendments.enabled.extend(section.items.clone());
        }

        // [validation_seed] — single line containing the base58 seed
        let validation_seed = sections
            .get("validation_seed")
            .and_then(first_scalar)
            .map(|s| s.to_string());

        Ok(Self {
            validators,
            validator_lists,
            amendments,
            runtime,
            validation_seed,
        })
    }
}

fn parse_sections(contents: &str) -> HashMap<String, SectionConfig> {
    let mut sections: HashMap<String, SectionConfig> = HashMap::new();
    let mut current: Option<String> = None;

    for raw_line in contents.lines() {
        let line = strip_comments(raw_line).trim().to_string();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            sections.entry(section.clone()).or_default();
            current = Some(section);
            continue;
        }

        let Some(section_name) = current.as_ref() else {
            continue;
        };
        let section = sections.entry(section_name.clone()).or_default();
        if let Some((key, value)) = line.split_once('=') {
            section
                .values
                .insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        } else {
            section.items.push(line);
        }
    }

    sections
}

fn strip_comments(line: &str) -> &str {
    // rippled only treats lines starting with # as comments (after trim).
    // Don't strip inline # — values like "path=/data#1" must be preserved.
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        ""
    } else {
        line
    }
}

fn parse_server_port(
    sections: &HashMap<String, SectionConfig>,
    server_defaults: &HashMap<String, String>,
    name: &str,
    wanted_protocols: &[&str],
) -> Option<SocketAddr> {
    let section = sections.get(&name.to_ascii_lowercase())?;
    let ip = section
        .values
        .get("ip")
        .or_else(|| server_defaults.get("ip"))?;
    let port = section
        .values
        .get("port")
        .or_else(|| server_defaults.get("port"))?;
    let protocols = section
        .values
        .get("protocol")
        .or_else(|| server_defaults.get("protocol"))?;
    let protocol_set: Vec<String> = protocols
        .split(',')
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    if !wanted_protocols
        .iter()
        .any(|wanted| protocol_set.iter().any(|p| p == wanted))
    {
        return None;
    }
    format!("{ip}:{port}").parse().ok()
}

fn first_scalar(section: &SectionConfig) -> Option<&str> {
    section.items.first().map(|s| s.trim())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_network_id(value: &str) -> Option<u32> {
    match value.trim().to_ascii_lowercase().as_str() {
        "main" | "mainnet" => Some(0),
        "testnet" => Some(1),
        "devnet" => Some(2),
        other => other.parse().ok(),
    }
}

fn parse_history_retention(value: &str) -> Option<HistoryRetention> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" => Some(HistoryRetention::None),
        "full" => Some(HistoryRetention::Full),
        other => other.parse().ok().map(HistoryRetention::Count),
    }
}

fn resolve_path(config_path: &Path, raw: &str) -> PathBuf {
    let candidate = PathBuf::from(raw.trim());
    if candidate.is_absolute() {
        candidate
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

fn decode_validator_key(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if let Ok(bytes) = hex::decode(trimmed) {
        if bytes.len() == 33 {
            return Some(bytes);
        }
    }
    if let Ok((prefix, payload)) = crate::crypto::base58::decode(trimmed) {
        if prefix == crate::crypto::base58::PREFIX_NODE_PUBLIC && payload.len() == 33 {
            return Some(payload);
        }
    }
    None
}

fn load_validators_file(path: &Path) -> Result<ConfigFile> {
    let contents = std::fs::read_to_string(path)?;
    let sections = parse_sections(&contents);
    let has_validators_section = sections.contains_key("validators");
    let mut validators = Vec::new();
    if let Some(section) = sections.get("validators") {
        validators.extend(
            section
                .items
                .iter()
                .filter_map(|v| decode_validator_key(v))
                .map(|public_key| ValidatorEntry { public_key }),
        );
    }
    let sites = sections
        .get("validator_list_sites")
        .map(|s| s.items.clone())
        .unwrap_or_default();
    let publisher_keys: Vec<String> = sections
        .get("validator_list_keys")
        .map(|s| {
            s.items
                .iter()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let threshold = sections
        .get("validator_list_threshold")
        .and_then(first_scalar)
        .and_then(|s| s.parse::<u32>().ok());

    if !has_validators_section
        && validators.is_empty()
        && sites.is_empty()
        && publisher_keys.is_empty()
        && threshold.is_none()
    {
        return Err(anyhow!(
            "validators file {} does not contain [validators], [validator_list_sites], [validator_list_keys], or [validator_list_threshold]",
            path.display()
        ));
    }

    Ok(ConfigFile {
        validators,
        validator_lists: ValidatorListConfig {
            sites,
            publisher_keys,
            threshold,
        },
        amendments: AmendmentConfig::default(),
        runtime: RuntimeConfig::default(),
        validation_seed: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_toml_config() {
        let cfg = ConfigFile::load(write_temp("", "toml").as_path()).unwrap();
        assert!(cfg.validators.is_empty());
        assert!(cfg.amendments.enabled.is_empty());
    }

    #[test]
    fn test_parse_toml_validators_and_amendments() {
        let toml = r#"
[[validators]]
public_key = "0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020"

[amendments]
enabled = ["FlowCross", "DeletableAccounts"]

[node]
peer_addr = "0.0.0.0:51235"
ws_addr = "127.0.0.1:6006"
max_peers = 42
bootstrap_peers = ["r.ripple.com:51235"]
ledger_history = "full"
"#;
        let cfg = ConfigFile::load(write_temp(toml, "toml").as_path()).unwrap();
        assert_eq!(cfg.validators.len(), 1);
        assert!(cfg.enabled_amendments().contains("FlowCross"));
        assert_eq!(cfg.runtime.max_peers, Some(42));
        assert_eq!(
            cfg.runtime.bootstrap_peers,
            vec!["r.ripple.com:51235".to_string()]
        );
        assert_eq!(cfg.runtime.ledger_history, Some(HistoryRetention::Full));
    }

    #[test]
    fn test_parse_toml_grpc_addr() {
        let toml = r#"
[node]
grpc_addr = "127.0.0.1:50051"
"#;
        let cfg = ConfigFile::load(write_temp(toml, "toml").as_path()).unwrap();
        assert_eq!(
            cfg.runtime.grpc_addr,
            Some("127.0.0.1:50051".parse().unwrap())
        );
    }

    #[test]
    fn test_parse_xrpld_style_ports_and_runtime() {
        let cfg_text = r#"
[server]
port_rpc
port_peer
port_ws

[port_rpc]
ip=127.0.0.1
port=5005
protocol=http

[port_peer]
ip=0.0.0.0
port=51235
protocol=peer

[port_ws]
ip=127.0.0.1
port=6006
protocol=ws

[peers_max]
33

[ips]
r.ripple.com 51235

[ledger_history]
full

[fetch_depth]
512

[node_db]
path=db/nudb
online_delete=2048

[ips_fixed]
127.0.0.1 51235
"#;
        let path = write_temp(cfg_text, "cfg");
        let cfg = ConfigFile::load(&path).unwrap();
        assert_eq!(cfg.runtime.peer_addr.unwrap().port(), 51235);
        assert_eq!(cfg.runtime.rpc_addr.unwrap().port(), 5005);
        assert_eq!(cfg.runtime.ws_addr.unwrap().port(), 6006);
        assert_eq!(cfg.runtime.max_peers, Some(33));
        assert_eq!(
            cfg.runtime.bootstrap_peers,
            vec!["r.ripple.com 51235".to_string()]
        );
        assert_eq!(cfg.runtime.ledger_history, Some(HistoryRetention::Full));
        assert_eq!(cfg.runtime.fetch_depth, Some(HistoryRetention::Count(512)));
        assert_eq!(cfg.runtime.online_delete, Some(2048));
        assert_eq!(cfg.runtime.fixed_peers, vec!["127.0.0.1 51235".to_string()]);
        assert!(cfg.runtime.data_dir.unwrap().ends_with("db/nudb"));
    }

    #[test]
    fn test_parse_validators_file_with_node_public_keys() {
        let pubkey = vec![7u8; 33];
        let encoded =
            crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, &pubkey);
        let validators_path = write_temp(&format!("[validators]\n{}\n", encoded), "txt");
        let cfg_text = format!("[validators_file]\n{}\n", validators_path.display());
        let cfg = ConfigFile::load(write_temp(&cfg_text, "cfg").as_path()).unwrap();
        assert_eq!(cfg.validators.len(), 1);
        assert_eq!(cfg.validators[0].public_key, pubkey);
        assert!(cfg.validator_lists.sites.is_empty());
        assert!(cfg.validator_lists.publisher_keys.is_empty());
    }

    #[test]
    fn test_parse_validators_file_with_empty_validators_section() {
        let validators_path = write_temp("[validators]\n# follower mode\n", "txt");
        let cfg_text = format!("[validators_file]\n{}\n", validators_path.display());
        let cfg = ConfigFile::load(write_temp(&cfg_text, "cfg").as_path()).unwrap();
        assert!(cfg.validators.is_empty());
        assert!(cfg.validator_lists.sites.is_empty());
        assert!(cfg.validator_lists.publisher_keys.is_empty());
        assert_eq!(cfg.validator_lists.threshold, None);
    }

    #[test]
    fn test_invalid_pubkey_skipped() {
        let toml = r#"
[[validators]]
public_key = "not_hex"

[[validators]]
public_key = "0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020"
"#;
        let cfg = ConfigFile::load(write_temp(toml, "toml").as_path()).unwrap();
        assert_eq!(cfg.validators.len(), 1);
    }

    #[test]
    fn test_parse_validators_file_with_publisher_lists_only() {
        let validators_path = write_temp(
            r#"
[validator_list_sites]
https://vl.ripple.com
https://unl.xrplf.org

[validator_list_keys]
ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734
ED42AEC58B701EEBB77356FFFEC26F83C1F0407263530F068C7C73D392C7E06FD1

[validator_list_threshold]
0
"#,
            "txt",
        );
        let cfg_text = format!("[validators_file]\n{}\n", validators_path.display());
        let cfg = ConfigFile::load(write_temp(&cfg_text, "cfg").as_path()).unwrap();
        assert!(cfg.validators.is_empty());
        assert_eq!(cfg.validator_lists.sites.len(), 2);
        assert_eq!(cfg.validator_lists.publisher_keys.len(), 2);
        assert_eq!(cfg.validator_lists.threshold, Some(0));
        assert_eq!(cfg.validator_lists.effective_threshold(), 1);
    }

    #[test]
    fn test_parse_validators_file_with_validators_and_publishers() {
        let pubkey = vec![9u8; 33];
        let encoded =
            crate::crypto::base58::encode(crate::crypto::base58::PREFIX_NODE_PUBLIC, &pubkey);
        let validators_path = write_temp(
            &format!(
                r#"
[validators]
{}

[validator_list_sites]
https://vl.ripple.com

[validator_list_keys]
ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734

[validator_list_threshold]
1
"#,
                encoded
            ),
            "txt",
        );
        let cfg_text = format!("[validators_file]\n{}\n", validators_path.display());
        let cfg = ConfigFile::load(write_temp(&cfg_text, "cfg").as_path()).unwrap();
        assert_eq!(cfg.validators.len(), 1);
        assert_eq!(cfg.validators[0].public_key, pubkey);
        assert_eq!(
            cfg.validator_lists.sites,
            vec!["https://vl.ripple.com".to_string()]
        );
        assert_eq!(cfg.validator_lists.publisher_keys.len(), 1);
        assert_eq!(cfg.validator_lists.effective_threshold(), 1);
    }

    #[test]
    fn test_validator_list_threshold_default_formula() {
        let mut cfg = ValidatorListConfig::default();
        assert_eq!(cfg.effective_threshold(), 1);
        cfg.publisher_keys = vec!["a".into(), "b".into()];
        assert_eq!(cfg.effective_threshold(), 1);
        cfg.publisher_keys.push("c".into());
        assert_eq!(cfg.effective_threshold(), 2);
        cfg.publisher_keys.push("d".into());
        assert_eq!(cfg.effective_threshold(), 3);
    }

    fn write_temp(contents: &str, ext: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("xledgrs_config_test_{id}.{ext}"));
        std::fs::write(&path, contents).unwrap();
        path
    }
}
