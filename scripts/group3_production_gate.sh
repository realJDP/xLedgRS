#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

target_dir="${GROUP3_TARGET_DIR:-/private/tmp/xledgrs-group3-gate-target}"

if [[ "${GROUP3_SKIP_VECTOR_TESTS:-}" != "1" ]]; then
  cargo test --test group3_acceptance_gates deterministic_local_control_plane_fixture_matches_committed_vectors --target-dir "$target_dir"
fi

GROUP3_ENFORCE_PRODUCTION_PARITY=1 \
  cargo test --test group3_acceptance_gates enforced_gate_fails_until_required_rippled_proof_is_registered \
  --target-dir "$target_dir"
