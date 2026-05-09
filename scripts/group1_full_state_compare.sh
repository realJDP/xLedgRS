#!/usr/bin/env bash
set -euo pipefail

XLEDGRS_ENDPOINT="${XLEDGRS_ENDPOINT:-127.0.0.1:5005}"
RIPPLED_ENDPOINT="${RIPPLED_ENDPOINT:-127.0.0.1:51234}"
LEDGER="${LEDGER:-}"
OUT_DIR="${OUT_DIR:-group1-shadow-archives/full-state-$(date -u +%Y%m%dT%H%M%SZ)}"
LIMIT="${LIMIT:-256}"
REQUEST_ROUNDS="${REQUEST_ROUNDS:-3}"
DIFF_LIMIT="${DIFF_LIMIT:-50}"

usage() {
    printf 'Usage: XLEDGRS_ENDPOINT=host:port RIPPLED_ENDPOINT=host:port LEDGER=seq OUT_DIR=dir %s\n' "$0" >&2
}

if [ -z "$LEDGER" ]; then
    usage
    exit 2
fi

mkdir -p "$OUT_DIR"
X_HOST="${XLEDGRS_ENDPOINT%:*}"
X_PORT="${XLEDGRS_ENDPOINT##*:}"
R_HOST="${RIPPLED_ENDPOINT%:*}"
R_PORT="${RIPPLED_ENDPOINT##*:}"

MANIFEST="$OUT_DIR/full_state_manifest.json"
printf '{"kind":"full_state_compare_start","ledger":%s,"xledgrs":"%s","rippled":"%s","started_unix":%s}\n' \
    "$LEDGER" "$XLEDGRS_ENDPOINT" "$RIPPLED_ENDPOINT" "$(date -u +%s)" > "$MANIFEST"

cargo run --quiet --bin dump_rippled_ledger_state -- \
    --host "$X_HOST" \
    --port "$X_PORT" \
    --ledger "$LEDGER" \
    --output "$OUT_DIR/xledgrs-ledger-$LEDGER.jsonl" \
    --limit "$LIMIT" \
    --request-rounds "$REQUEST_ROUNDS" \
    > "$OUT_DIR/xledgrs-dump.log" 2>&1

cargo run --quiet --bin dump_rippled_ledger_state -- \
    --host "$R_HOST" \
    --port "$R_PORT" \
    --ledger "$LEDGER" \
    --output "$OUT_DIR/rippled-ledger-$LEDGER.jsonl" \
    --limit "$LIMIT" \
    --request-rounds "$REQUEST_ROUNDS" \
    > "$OUT_DIR/rippled-dump.log" 2>&1

set +e
cargo run --quiet --bin diff_state_jsonl -- \
    --local "$OUT_DIR/xledgrs-ledger-$LEDGER.jsonl" \
    --reference "$OUT_DIR/rippled-ledger-$LEDGER.jsonl" \
    --limit "$DIFF_LIMIT" \
    > "$OUT_DIR/state-diff.log" 2>&1
DIFF_STATUS=$?
set -e

if grep -q 'SUMMARY matched=.* different=0 local_only=0 reference_only=0' "$OUT_DIR/state-diff.log"; then
    VERDICT="pass"
else
    VERDICT="fail"
fi

printf '{"kind":"full_state_compare_summary","ledger":%s,"verdict":"%s","diff_exit":%s,"finished_unix":%s}\n' \
    "$LEDGER" "$VERDICT" "$DIFF_STATUS" "$(date -u +%s)" >> "$MANIFEST"

if [ "$VERDICT" != "pass" ]; then
    printf 'full-state compare failed; archive=%s\n' "$OUT_DIR" >&2
    exit 1
fi

printf 'full-state compare passed; archive=%s\n' "$OUT_DIR"
