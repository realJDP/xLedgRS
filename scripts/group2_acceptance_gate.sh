#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

target_dir="${GROUP2_TARGET_DIR:-/private/tmp/xledgrs-group2-gate-target}"

cargo test --test group2_server_definitions_exact_diff --target-dir "$target_dir"
GROUP2_ENFORCE_PRODUCTION_PARITY=1 \
  cargo test --test group2_acceptance_gates enforced_gate_fails_until_all_required_findings_have_non_bridge_proof \
  --target-dir "$target_dir"
