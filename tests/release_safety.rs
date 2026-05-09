use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn release_cfg_root() -> PathBuf {
    repo_root().join("cfg")
}

fn cfg_templates() -> Vec<PathBuf> {
    let mut files = fs::read_dir(release_cfg_root())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("cfg"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn release_shell_scripts() -> Vec<PathBuf> {
    let mut files = fs::read_dir(repo_root().join("scripts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sh"))
        .collect::<Vec<_>>();
    files.push(repo_root().join("post-sync-checkpoint.sh"));
    files.sort();
    files
}

fn uncommented_validation_seed_lines(contents: &str) -> Vec<(usize, String)> {
    let mut in_seed_block = false;
    let mut offending = Vec::new();

    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "[validation_seed]" {
            in_seed_block = true;
            continue;
        }
        if in_seed_block {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.starts_with('[') {
                in_seed_block = false;
                continue;
            }
            offending.push((idx + 1, trimmed.to_string()));
        }
    }

    offending
}

fn non_local_ipv4s(contents: &str) -> Vec<String> {
    const ALLOWED: &[&str] = &["0.0.0.0", "127.0.0.1"];
    let mut found = Vec::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        for token in trimmed.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
            if token.is_empty() || ALLOWED.contains(&token) {
                continue;
            }
            let parts = token.split('.').collect::<Vec<_>>();
            if parts.len() != 4 {
                continue;
            }
            if parts
                .iter()
                .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
            {
                found.push(token.to_string());
            }
        }
    }

    found.sort();
    found.dedup();
    found
}

fn hardcoded_remote_targets(contents: &str) -> Vec<String> {
    let mut found = Vec::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if !(trimmed.starts_with("ssh ")
            || trimmed.starts_with("scp ")
            || trimmed.starts_with("rsync "))
        {
            continue;
        }
        for token in trimmed.split_whitespace() {
            if token.contains('@') && !token.starts_with('$') {
                found.push(token.to_string());
            }
        }
    }

    found.sort();
    found.dedup();
    found
}

fn section_body<'a>(contents: &'a str, section: &str) -> Vec<&'a str> {
    let header = format!("[{}]", section.to_ascii_lowercase());
    let mut in_section = false;
    let mut lines = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.to_ascii_lowercase() == header {
            in_section = true;
            continue;
        }
        if in_section && trimmed.starts_with('[') {
            break;
        }
        if in_section && !trimmed.is_empty() && !trimmed.starts_with('#') {
            lines.push(trimmed);
        }
    }
    lines
}

fn section_scalar(contents: &str, section: &str) -> Option<String> {
    section_body(contents, section).first().map(|line| {
        line.split('=')
            .next_back()
            .unwrap_or(line)
            .trim()
            .to_string()
    })
}

#[test]
fn documented_public_release_files_exist() {
    for relative in [
        "README.md",
        "LICENSE",
        "Cargo.toml",
        "cfg/xLedgRSv2Beta.cfg",
        "cfg/testnet.cfg",
        "cfg/validator-mainnet.cfg",
        "cfg/validator-testnet.cfg",
        "cfg/xLedgRSv2Beta-example.cfg",
        "cfg/validators.txt",
        "scripts/start-xLedgRSv2Beta.sh",
        "scripts/start-xLedgRSv2Beta-validator.sh",
        "scripts/export-release-candidate.sh",
        "release/export-ignore.txt",
    ] {
        let path = repo_root().join(relative);
        assert!(path.exists(), "documented release file missing: {relative}");
    }
}

#[test]
fn release_export_ignore_keeps_public_config_templates() {
    let ignore = read_text(&repo_root().join("release/export-ignore.txt"));
    for cfg in [
        "cfg/xLedgRSv2Beta.cfg",
        "cfg/testnet.cfg",
        "cfg/validator-mainnet.cfg",
        "cfg/validator-testnet.cfg",
        "cfg/xLedgRSv2Beta-example.cfg",
    ] {
        assert!(
            !ignore.lines().any(|line| line.trim() == cfg),
            "release export ignore must not drop public config template {cfg}"
        );
    }
}

#[test]
fn release_cfg_templates_do_not_ship_uncommented_validation_seeds() {
    for cfg in cfg_templates() {
        let contents = read_text(&cfg);
        let offending = uncommented_validation_seed_lines(&contents);
        assert!(
            offending.is_empty(),
            "{} still contains an uncommented [validation_seed] value: {:?}",
            cfg.display(),
            offending
        );
    }
}

#[test]
fn validator_cfg_templates_do_not_enable_close_loop_without_identity() {
    for relative in ["cfg/validator-mainnet.cfg", "cfg/validator-testnet.cfg"] {
        let path = repo_root().join(relative);
        let cfg = xrpl::config::ConfigFile::load(&path).expect("validator cfg parses");
        assert_ne!(
            cfg.runtime.enable_consensus_close_loop,
            Some(true),
            "{relative} must not enable consensus close loop in the public template"
        );
        assert!(
            cfg.validation_seed.is_none()
                && cfg.validation_secret_key.is_none()
                && cfg.validator_token.is_none(),
            "{relative} must not ship an active validator identity"
        );
    }
}

#[test]
fn release_surfaces_do_not_hardcode_nonlocal_ipv4_addresses() {
    let mut paths = cfg_templates();
    paths.extend(release_shell_scripts());
    for path in paths {
        let contents = read_text(&path);
        let ips = non_local_ipv4s(&contents);
        assert!(
            ips.is_empty(),
            "{} still contains hardcoded non-local IPs: {:?}",
            path.display(),
            ips
        );
    }
}

#[test]
fn release_scripts_do_not_hardcode_remote_targets() {
    for path in release_shell_scripts() {
        let contents = read_text(&path);
        let targets = hardcoded_remote_targets(&contents);
        assert!(
            targets.is_empty(),
            "{} still contains hardcoded remote targets: {:?}",
            path.display(),
            targets
        );
    }
}

#[test]
fn public_startup_templates_keep_network_modes_distinct() {
    for (cfg, expected_network) in [
        ("cfg/xLedgRSv2Beta.cfg", "main"),
        ("cfg/validator-mainnet.cfg", "main"),
        ("cfg/testnet.cfg", "testnet"),
        ("cfg/validator-testnet.cfg", "testnet"),
    ] {
        let contents = read_text(&repo_root().join(cfg));
        assert_eq!(
            section_scalar(&contents, "network_id").as_deref(),
            Some(expected_network),
            "{cfg} must declare the intended rippled-compatible network_id"
        );
    }
}

#[test]
fn validator_close_loop_templates_require_release_safe_inputs() {
    for cfg in ["cfg/validator-mainnet.cfg", "cfg/validator-testnet.cfg"] {
        let contents = read_text(&repo_root().join(cfg));
        assert!(
            section_body(&contents, "xLedgRSv2Beta")
                .iter()
                .any(|line| *line == "enable_consensus_close_loop = 0"),
            "{cfg} must keep the consensus close loop disabled in the public template"
        );
        assert_eq!(
            section_scalar(&contents, "ledger_history").as_deref(),
            Some("full"),
            "{cfg} must keep full history for validator close-loop safety"
        );
        assert!(
            section_scalar(&contents, "validators_file").is_some(),
            "{cfg} must configure a validator list source"
        );
        assert!(
            uncommented_validation_seed_lines(&contents).is_empty(),
            "{cfg} must not ship an active validation seed"
        );
    }
}
