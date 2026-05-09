use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

const REQUIRED_FINDINGS: &[u64] = &[40, 41, 42, 43, 44, 45, 46];

#[derive(Debug, Deserialize)]
struct Manifest {
    families: Vec<FixtureFamily>,
}

#[derive(Debug, Deserialize)]
struct FixtureFamily {
    id: String,
    findings: Vec<u64>,
    source: String,
    executable: bool,
    command: String,
    uses_authoritative_bridges: bool,
    private_opt_in: bool,
    skipped_by_default: bool,
    assertion: String,
}

fn load_manifest(text: &str) -> Manifest {
    serde_json::from_str(text).expect("group2 fixture manifest must be valid JSON")
}

fn production_proof_reasons(manifest: &Manifest) -> Vec<String> {
    let mut reasons = Vec::new();
    let mut covered = BTreeSet::new();
    let mut rejected: BTreeMap<u64, Vec<String>> = BTreeMap::new();

    for family in &manifest.families {
        let accepted = family.executable
            && !family.command.trim().is_empty()
            && !family.uses_authoritative_bridges
            && !family.private_opt_in
            && !family.skipped_by_default
            && matches!(family.source.as_str(), "committed" | "synthetic");

        for finding in &family.findings {
            if accepted {
                covered.insert(*finding);
            } else if REQUIRED_FINDINGS.contains(finding) {
                rejected.entry(*finding).or_default().push(format!(
                    "{} source={} executable={} bridge={} private={} skipped={}",
                    family.id,
                    family.source,
                    family.executable,
                    family.uses_authoritative_bridges,
                    family.private_opt_in,
                    family.skipped_by_default,
                ));
            }
        }
    }

    for finding in REQUIRED_FINDINGS {
        if !covered.contains(finding) {
            let evidence = rejected
                .remove(finding)
                .map(|items| items.join("; "))
                .unwrap_or_else(|| "no fixture family registered".to_string());
            reasons.push(format!(
                "finding {finding} lacks accepted proof: {evidence}"
            ));
        }
    }

    reasons
}

#[test]
fn manifest_is_parseable_and_commands_are_tied_to_assertions() {
    let manifest = load_manifest(include_str!("group2_fixture_manifest.json"));
    assert!(!manifest.families.is_empty());
    for family in &manifest.families {
        assert!(!family.id.trim().is_empty());
        assert!(
            !family.findings.is_empty(),
            "{} must map to findings",
            family.id
        );
        assert!(
            !family.assertion.trim().is_empty(),
            "{} must state the executable assertion",
            family.id,
        );
        if family.executable {
            assert!(
                !family.command.trim().is_empty(),
                "{} executable fixture must provide a command",
                family.id,
            );
        }
    }
}

#[test]
fn gate_rejects_bridge_only_and_skipped_private_proof() {
    let manifest = load_manifest(
        r#"{
          "families": [
            {
              "id": "bridge_only",
              "findings": [41],
              "source": "committed",
              "executable": true,
              "command": "cargo run --bin replay_fixture -- --bundle fixture",
              "uses_authoritative_bridges": true,
              "private_opt_in": false,
              "skipped_by_default": false,
              "assertion": "would pass only because replay bridge metadata masks local engine gaps"
            },
            {
              "id": "private_dex",
              "findings": [40],
              "source": "private",
              "executable": true,
              "command": "XLEDGRSV2BETA_BUG_B_FIXTURE=<bundle> cargo test",
              "uses_authoritative_bridges": false,
              "private_opt_in": true,
              "skipped_by_default": true,
              "assertion": "skips on fresh checkout"
            }
          ]
        }"#,
    );

    let reasons = production_proof_reasons(&manifest);
    assert!(reasons.iter().any(|reason| reason.contains("finding 40")));
    assert!(reasons.iter().any(|reason| reason.contains("finding 41")));
}

#[test]
fn actual_manifest_does_not_claim_complete_group2_production_parity_yet() {
    let manifest = load_manifest(include_str!("group2_fixture_manifest.json"));
    let reasons = production_proof_reasons(&manifest);
    assert!(
        reasons.iter().any(|reason| reason.contains("finding 45")),
        "delivered_amount replay family is intentionally still pending"
    );
    assert!(
        reasons.iter().any(|reason| reason.contains("finding 46")),
        "path_find replay family is intentionally still pending"
    );
}

#[test]
fn enforced_gate_fails_until_all_required_findings_have_non_bridge_proof() {
    if std::env::var_os("GROUP2_ENFORCE_PRODUCTION_PARITY").is_none() {
        return;
    }

    let manifest = load_manifest(include_str!("group2_fixture_manifest.json"));
    let reasons = production_proof_reasons(&manifest);
    assert!(
        reasons.is_empty(),
        "Group 2 production parity gate failed:\n{}",
        reasons.join("\n")
    );
}
