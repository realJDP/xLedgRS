#!/usr/bin/env bash
set -euo pipefail

XLEDGRS_ENDPOINT="${XLEDGRS_ENDPOINT:-127.0.0.1:5005}"
RIPPLED_ENDPOINT="${RIPPLED_ENDPOINT:-127.0.0.1:51234}"
OUT_DIR="${OUT_DIR:-group1-shadow-archives/run-$(date -u +%Y%m%dT%H%M%SZ)}"
DURATION_SECS="${DURATION_SECS:-300}"
INTERVAL_SECS="${INTERVAL_SECS:-5}"
MAX_LEDGER_LAG="${MAX_LEDGER_LAG:-2}"
MAX_VALIDATED_AGE_SECS="${MAX_VALIDATED_AGE_SECS:-20}"
RPC_SAMPLES="${RPC_SAMPLES:-1}"
REQUIRE_LOCAL_PROCESSES="${REQUIRE_LOCAL_PROCESSES:-1}"
RUN_FULL_STATE="${RUN_FULL_STATE:-0}"
FULL_STATE_LEDGER="${FULL_STATE_LEDGER:-}"
RUN_LOAD_SOAK="${RUN_LOAD_SOAK:-0}"
LOAD_SOAK_DURATION_SECS="${LOAD_SOAK_DURATION_SECS:-60}"
LOAD_SOAK_CONCURRENCY="${LOAD_SOAK_CONCURRENCY:-4}"
RUN_PEER_WIRE="${RUN_PEER_WIRE:-0}"
XLEDGRS_PEER_ENDPOINT="${XLEDGRS_PEER_ENDPOINT:-127.0.0.1:51235}"
BUILD_PROFILE="${BUILD_PROFILE:-operator-shadow}"

mkdir -p "$OUT_DIR"

X_HOST="${XLEDGRS_ENDPOINT%:*}"
X_PORT="${XLEDGRS_ENDPOINT##*:}"
R_HOST="${RIPPLED_ENDPOINT%:*}"
R_PORT="${RIPPLED_ENDPOINT##*:}"

require_process() {
    local name="$1"
    if ! pgrep -x "$name" > /dev/null; then
        printf 'ERROR: required local process not found: %s\n' "$name" >&2
        exit 1
    fi
}

if [ "$REQUIRE_LOCAL_PROCESSES" = "1" ]; then
    require_process xledgrs
    require_process rippled
fi

printf '{"kind":"shadow_runner_start","started_unix":%s,"xledgrs":"%s","rippled":"%s","require_local_processes":"%s"}\n' \
    "$(date -u +%s)" "$XLEDGRS_ENDPOINT" "$RIPPLED_ENDPOINT" "$REQUIRE_LOCAL_PROCESSES" \
    > "$OUT_DIR/shadow-runner.jsonl"

curl -sS --max-time 10 "http://$XLEDGRS_ENDPOINT/" \
    -d '{"method":"server_info","params":[{}]}' \
    > "$OUT_DIR/xledgrs-server-info.json" || true
curl -sS --max-time 10 "http://$RIPPLED_ENDPOINT/" \
    -d '{"method":"server_info","params":[{}]}' \
    > "$OUT_DIR/rippled-server-info.json" || true

cargo run --quiet --bin live_sync_benchmark -- \
    --xledgrs-host "$X_HOST" \
    --xledgrs-port "$X_PORT" \
    --rippled-host "$R_HOST" \
    --rippled-port "$R_PORT" \
    --duration-secs "$DURATION_SECS" \
    --interval-secs "$INTERVAL_SECS" \
    --output "$OUT_DIR/benchmark.jsonl" \
    --enforce-gates \
    --max-ledger-lag "$MAX_LEDGER_LAG" \
    --max-validated-age-secs "$MAX_VALIDATED_AGE_SECS" \
    --build-profile "$BUILD_PROFILE"

scripts/group1_rpc_parity.py \
    --xledgrs "$XLEDGRS_ENDPOINT" \
    --rippled "$RIPPLED_ENDPOINT" \
    --output "$OUT_DIR/rpc-parity.jsonl" \
    --samples "$RPC_SAMPLES" \
    --allow-ledger-lag "$MAX_LEDGER_LAG"

if [ "$RUN_FULL_STATE" = "1" ]; then
    if [ -z "$FULL_STATE_LEDGER" ]; then
        printf 'ERROR: RUN_FULL_STATE=1 requires FULL_STATE_LEDGER=seq\n' >&2
        exit 1
    fi
    OUT_DIR="$OUT_DIR/full-state" \
    XLEDGRS_ENDPOINT="$XLEDGRS_ENDPOINT" \
    RIPPLED_ENDPOINT="$RIPPLED_ENDPOINT" \
    LEDGER="$FULL_STATE_LEDGER" \
    scripts/group1_full_state_compare.sh
fi

if [ "$RUN_LOAD_SOAK" = "1" ]; then
    scripts/group1_load_soak_parity.py \
        --xledgrs "$XLEDGRS_ENDPOINT" \
        --rippled "$RIPPLED_ENDPOINT" \
        --output "$OUT_DIR/load-soak.jsonl" \
        --duration-secs "$LOAD_SOAK_DURATION_SECS" \
        --concurrency "$LOAD_SOAK_CONCURRENCY"
fi

if [ "$RUN_PEER_WIRE" = "1" ]; then
    PEER_HOST="${XLEDGRS_PEER_ENDPOINT%:*}"
    PEER_PORT="${XLEDGRS_PEER_ENDPOINT##*:}"
    scripts/group1_peer_wire_parity_probe.py \
        --host "$PEER_HOST" \
        --port "$PEER_PORT" \
        --output "$OUT_DIR/peer-wire.jsonl"
fi

ACCEPTANCE_ARGS=(--archive "$OUT_DIR")
if [ "$RUN_FULL_STATE" = "1" ]; then
    ACCEPTANCE_ARGS+=(--require-full-state)
fi
if [ "$RUN_LOAD_SOAK" = "1" ]; then
    ACCEPTANCE_ARGS+=(--require-load-soak)
fi
if [ "$RUN_PEER_WIRE" = "1" ]; then
    ACCEPTANCE_ARGS+=(--require-peer-wire)
fi
scripts/group1_acceptance_check.py "${ACCEPTANCE_ARGS[@]}"

printf '{"kind":"shadow_runner_summary","verdict":"pass","finished_unix":%s,"archive":"%s"}\n' \
    "$(date -u +%s)" "$OUT_DIR" >> "$OUT_DIR/shadow-runner.jsonl"
printf 'Group 1 shadow run passed; archive=%s\n' "$OUT_DIR"
