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
fn release_surfaces_do_not_hardcode_nonlocal_ipv4_addresses() {
    for path in cfg_templates() {
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
