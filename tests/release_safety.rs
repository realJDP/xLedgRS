use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn release_template_root() -> PathBuf {
    repo_root().join("release").join("templates")
}

fn release_cfg_root() -> PathBuf {
    let template_cfg = release_template_root().join("cfg");
    let has_cfg_files = fs::read_dir(&template_cfg)
        .ok()
        .map(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                entry.path().extension().and_then(|ext| ext.to_str()) == Some("cfg")
            })
        })
        .unwrap_or(false);
    if has_cfg_files {
        template_cfg
    } else {
        repo_root().join("cfg")
    }
}

fn release_deploy_path() -> PathBuf {
    let template_deploy = release_template_root().join("deploy-xledgrs.sh");
    if template_deploy.exists() {
        template_deploy
    } else {
        repo_root().join("deploy-xledgrs.sh")
    }
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
    let mut surfaces = cfg_templates();
    surfaces.push(release_deploy_path());

    for path in surfaces {
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
fn release_deploy_template_uses_placeholders_for_remote_hosts() {
    let deploy = read_text(&release_deploy_path());
    let allowed_placeholder_lines = [
        r#": "${VALIDATOR:?Set VALIDATOR=user@host}""#,
        r#": "${BUILD_SERVER:?Set BUILD_SERVER=user@host}""#,
    ];

    let mut offending = Vec::new();
    for (idx, line) in deploy.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.contains('@') {
            continue;
        }
        if allowed_placeholder_lines.contains(&trimmed) {
            continue;
        }
        if trimmed
            .split_whitespace()
            .any(|token| token.contains('@') && !token.contains('$'))
        {
            offending.push((idx + 1, trimmed.to_string()));
        }
    }

    assert!(
        offending.is_empty(),
        "release deploy template still contains literal remote hosts: {:?}",
        offending
    );
}

#[test]
fn export_ignore_excludes_private_operational_files() {
    let ignore = read_text(&repo_root().join("release").join("export-ignore.txt"));
    let entries = ignore.lines().map(str::trim).collect::<Vec<_>>();
    let required = [
        "cfg/xledgrs.cfg",
        "cfg/validator-mainnet.cfg",
        "cfg/validator-testnet.cfg",
        "deploy-xledgrs.sh",
        "deploy-validator.sh",
        "checkpoint-sync-base.sh",
        "restore-sync-base.sh",
        "watch.sh",
    ];

    for entry in required {
        assert!(
            entries.contains(&entry),
            "release/export-ignore.txt must exclude {entry}"
        );
    }
}
