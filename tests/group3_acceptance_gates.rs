use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use xrpl::consensus::{Manifest, Proposal, Validation};
use xrpl::crypto::keys::Secp256k1KeyPair;
use xrpl::crypto::sha512_first_half;

const REQUIRED_FINDINGS: &[u64] = &[1, 32, 33, 35];
const REQUIRED_RIPPLED_SURFACES: &[&str] = &[
    "validator identity/manifest handling",
    "effective UNL/NegativeUNL filtering",
    "consensus close behavior",
    "validation signing fields",
    "amendment voting",
    "fee voting",
    "protocol-control reports",
];

#[derive(Debug, Deserialize)]
struct ManifestInventory {
    production_complete: bool,
    required_findings: Vec<u64>,
    families: Vec<FixtureFamily>,
}

#[derive(Debug, Deserialize)]
struct FixtureFamily {
    id: String,
    findings: Vec<u64>,
    surface: String,
    source: String,
    executable: bool,
    command: String,
    rippled_parity: bool,
    deterministic_harness: bool,
    private_opt_in: bool,
    skipped_by_default: bool,
    assertion: String,
    residual_blockers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ControlPlaneFixture {
    proposal: ProposalVector,
    validation: ValidationVector,
    manifest: ManifestVector,
    accepted_set: AcceptedSetVector,
}

#[derive(Debug, Deserialize)]
struct ProposalVector {
    validator_seed_entropy_hex: String,
    ledger_seq: u32,
    tx_set_hash_hex: String,
    previous_ledger_hex: String,
    close_time: u32,
    prop_seq: u32,
    signing_payload_hash_hex: String,
    proposal_hash_hex: String,
    signature_hex: String,
}

#[derive(Debug, Deserialize)]
struct ValidationVector {
    validator_seed_entropy_hex: String,
    ledger_seq: u32,
    ledger_hash_hex: String,
    consensus_hash_hex: String,
    validated_hash_hex: String,
    sign_time: u32,
    close_time: u32,
    cookie: u64,
    server_version: u64,
    signing_payload_hash_hex: String,
    validation_hash_hex: String,
    signature_hex: String,
    stobject_hex: String,
}

#[derive(Debug, Deserialize)]
struct ManifestVector {
    master_seed_entropy_hex: String,
    signing_seed_entropy_hex: String,
    sequence: u32,
    signing_payload_hash_hex: String,
    serialized_hash_hex: String,
}

#[derive(Debug, Deserialize)]
struct AcceptedSetVector {
    quorum: usize,
    peer_positions: Vec<PeerPosition>,
    expected_accepted_hash_hex: String,
}

#[derive(Debug, Deserialize)]
struct PeerPosition {
    peer: String,
    tx_set_hash_hex: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn inventory() -> ManifestInventory {
    serde_json::from_str(include_str!("group3_fixture_manifest.json"))
        .expect("group3 fixture manifest must be valid JSON")
}

fn fixture() -> ControlPlaneFixture {
    serde_json::from_str(include_str!("group3_control_plane_fixture.json"))
        .expect("group3 control-plane fixture must be valid JSON")
}

fn hex_to_bytes<const N: usize>(hex_text: &str) -> [u8; N] {
    let bytes = hex::decode(hex_text).unwrap_or_else(|err| panic!("bad hex {hex_text}: {err}"));
    bytes
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, got {}", bytes.len()))
}

fn seed(hex_text: &str) -> [u8; 16] {
    hex_to_bytes(hex_text)
}

fn proof_blockers(manifest: &ManifestInventory) -> Vec<String> {
    let mut covered = BTreeSet::new();
    let mut rejected: BTreeMap<u64, Vec<String>> = BTreeMap::new();

    for family in &manifest.families {
        let accepted = family.executable
            && !family.command.trim().is_empty()
            && family.rippled_parity
            && !family.deterministic_harness
            && !family.private_opt_in
            && !family.skipped_by_default
            && matches!(family.source.as_str(), "committed" | "reproducible");

        for finding in &family.findings {
            if accepted {
                covered.insert(*finding);
            } else if REQUIRED_FINDINGS.contains(finding) {
                rejected.entry(*finding).or_default().push(format!(
                    "{} source={} executable={} rippled={} deterministic={} private={} skipped={} blockers={}",
                    family.id,
                    family.source,
                    family.executable,
                    family.rippled_parity,
                    family.deterministic_harness,
                    family.private_opt_in,
                    family.skipped_by_default,
                    family.residual_blockers.join(" | ")
                ));
            }
        }
    }

    let mut blockers = Vec::new();
    for finding in REQUIRED_FINDINGS {
        if !covered.contains(finding) {
            let evidence = rejected
                .remove(finding)
                .map(|items| items.join("; "))
                .unwrap_or_else(|| "no fixture family registered".to_string());
            blockers.push(format!(
                "finding {finding} lacks rippled parity proof: {evidence}"
            ));
        }
    }

    for surface in REQUIRED_RIPPLED_SURFACES {
        let proved = manifest.families.iter().any(|family| {
            family.rippled_parity
                && family.executable
                && !family.private_opt_in
                && !family.skipped_by_default
                && (family.surface.contains(surface) || family.assertion.contains(surface))
        });
        if !proved {
            blockers.push(format!("surface lacks rippled parity proof: {surface}"));
        }
    }

    blockers
}

fn accepted_hash(vector: &AcceptedSetVector) -> Option<[u8; 32]> {
    let mut votes: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for position in &vector.peer_positions {
        assert!(
            !position.peer.trim().is_empty(),
            "peer fixture entries must be named"
        );
        *votes
            .entry(hex_to_bytes(&position.tx_set_hash_hex))
            .or_default() += 1;
    }
    votes
        .into_iter()
        .filter(|(_, count)| *count >= vector.quorum)
        .map(|(hash, _)| hash)
        .next()
}

#[test]
fn manifest_is_parseable_and_tracks_required_findings() {
    let manifest = inventory();
    assert_eq!(manifest.required_findings, REQUIRED_FINDINGS);
    assert!(!manifest.families.is_empty());

    let mut seen = BTreeSet::new();
    for family in &manifest.families {
        assert!(!family.id.trim().is_empty());
        assert!(
            !family.findings.is_empty(),
            "{} must map to findings",
            family.id
        );
        assert!(
            !family.assertion.trim().is_empty(),
            "{} must describe the proof assertion",
            family.id
        );
        if family.executable {
            assert!(
                !family.command.trim().is_empty(),
                "{} executable proof must provide a command",
                family.id
            );
        }
        for finding in &family.findings {
            seen.insert(*finding);
        }
    }

    for finding in REQUIRED_FINDINGS {
        assert!(seen.contains(finding), "finding {finding} is not tracked");
    }
}

#[test]
fn deterministic_local_control_plane_fixture_matches_committed_vectors() {
    let fixture = fixture();

    let proposal_key =
        Secp256k1KeyPair::from_seed_entropy(&seed(&fixture.proposal.validator_seed_entropy_hex));
    let proposal = Proposal::new_signed(
        fixture.proposal.ledger_seq,
        hex_to_bytes(&fixture.proposal.tx_set_hash_hex),
        hex_to_bytes(&fixture.proposal.previous_ledger_hex),
        fixture.proposal.close_time,
        fixture.proposal.prop_seq,
        &proposal_key,
    );
    assert!(proposal.verify_signature());
    assert_eq!(
        hex::encode(sha512_first_half(&proposal.signing_bytes())),
        fixture.proposal.signing_payload_hash_hex
    );
    assert_eq!(
        hex::encode(proposal.hash()),
        fixture.proposal.proposal_hash_hex
    );
    assert_eq!(
        hex::encode(&proposal.signature),
        fixture.proposal.signature_hex
    );

    let validation_key =
        Secp256k1KeyPair::from_seed_entropy(&seed(&fixture.validation.validator_seed_entropy_hex));
    let mut validation = Validation::new_signed(
        fixture.validation.ledger_seq,
        hex_to_bytes(&fixture.validation.ledger_hash_hex),
        fixture.validation.sign_time,
        true,
        &validation_key,
    );
    validation.close_time = Some(fixture.validation.close_time);
    validation.cookie = Some(fixture.validation.cookie);
    validation.server_version = Some(fixture.validation.server_version);
    validation.consensus_hash = Some(hex_to_bytes(&fixture.validation.consensus_hash_hex));
    validation.validated_hash = Some(hex_to_bytes(&fixture.validation.validated_hash_hex));
    validation.signature = validation_key.sign(&validation.signing_bytes());
    assert!(validation.verify_signature());
    assert_eq!(
        hex::encode(sha512_first_half(&validation.signing_bytes())),
        fixture.validation.signing_payload_hash_hex
    );
    assert_eq!(
        hex::encode(validation.hash()),
        fixture.validation.validation_hash_hex
    );
    assert_eq!(
        hex::encode(&validation.signature),
        fixture.validation.signature_hex
    );
    assert_eq!(
        hex::encode(validation.to_bytes()),
        fixture.validation.stobject_hex
    );

    let master =
        Secp256k1KeyPair::from_seed_entropy(&seed(&fixture.manifest.master_seed_entropy_hex));
    let signing =
        Secp256k1KeyPair::from_seed_entropy(&seed(&fixture.manifest.signing_seed_entropy_hex));
    let manifest = Manifest::new_signed(fixture.manifest.sequence, &master, &signing);
    assert!(manifest.verify());
    assert_eq!(
        hex::encode(sha512_first_half(&Manifest::signing_bytes(
            &manifest.master_pubkey,
            &manifest.signing_pubkey,
            manifest.sequence,
            None,
            None,
        ))),
        fixture.manifest.signing_payload_hash_hex
    );
    assert_eq!(
        hex::encode(sha512_first_half(&manifest.to_bytes())),
        fixture.manifest.serialized_hash_hex
    );

    assert_eq!(
        accepted_hash(&fixture.accepted_set).map(hex::encode),
        Some(fixture.accepted_set.expected_accepted_hash_hex)
    );
}

#[test]
fn deterministic_harnesses_cannot_be_counted_as_rippled_parity() {
    let manifest = inventory();
    let deterministic = manifest
        .families
        .iter()
        .find(|family| family.id == "control_plane_deterministic_vectors")
        .expect("deterministic vector family must be registered");
    assert!(deterministic.executable);
    assert!(deterministic.deterministic_harness);
    assert!(!deterministic.rippled_parity);
    assert!(
        !deterministic.residual_blockers.is_empty(),
        "local deterministic vectors must list exact residual rippled blockers"
    );

    let blockers = proof_blockers(&manifest);
    assert!(
        blockers.iter().any(|blocker| blocker.contains("finding 1")),
        "finding 1 must remain blocked until side-by-side rippled proof exists"
    );
    assert!(
        blockers
            .iter()
            .any(|blocker| blocker.contains("finding 32")),
        "finding 32 must remain blocked until committed rippled fixture families exist"
    );
    assert!(
        blockers
            .iter()
            .any(|blocker| blocker.contains("finding 33")),
        "finding 33 must remain blocked until replay tooling covers control-plane traffic"
    );
    assert!(
        blockers
            .iter()
            .any(|blocker| blocker.contains("finding 35")),
        "finding 35 must remain blocked until all required production surfaces are proven"
    );
}

#[test]
fn production_complete_flag_is_gated_by_real_rippled_proof() {
    let manifest = inventory();
    let blockers = proof_blockers(&manifest);
    if manifest.production_complete {
        assert!(
            blockers.is_empty(),
            "Group 3 production_complete cannot be true:\n{}",
            blockers.join("\n")
        );
    } else {
        assert!(
            !blockers.is_empty(),
            "incomplete Group 3 inventory must retain residual blockers"
        );
    }
}

#[test]
fn script_gate_uses_enforced_mode_without_hiding_blockers() {
    let script = fs::read_to_string(repo_root().join("scripts/group3_production_gate.sh"))
        .expect("group3 production gate script must exist");
    assert!(script.contains("GROUP3_ENFORCE_PRODUCTION_PARITY=1"));
    assert!(script.contains("enforced_gate_fails_until_required_rippled_proof_is_registered"));

    let blockers = proof_blockers(&inventory());
    assert!(!blockers.is_empty());
    for surface in REQUIRED_RIPPLED_SURFACES {
        assert!(
            blockers.iter().any(
                |blocker| blocker.contains("surface lacks rippled parity proof")
                    && blocker.contains(surface)
            ),
            "gate blockers should include {surface}"
        );
    }
}

#[test]
fn enforced_gate_fails_until_required_rippled_proof_is_registered() {
    if std::env::var_os("GROUP3_ENFORCE_PRODUCTION_PARITY").is_none() {
        return;
    }

    let manifest = inventory();
    let blockers = proof_blockers(&manifest);
    assert!(
        blockers.is_empty(),
        "Group 3 production parity gate failed:\n{}",
        blockers.join("\n")
    );
}
