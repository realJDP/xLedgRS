#!/bin/bash
# xLedgRS purpose: Build a sanitized public release candidate tree.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="${1:-$(cd "$ROOT_DIR/.." && pwd)/xLedgRSv2Beta}"
IGNORE_FILE="$ROOT_DIR/release/export-ignore.txt"
TEMPLATE_DIR="$ROOT_DIR/release/templates"

echo "=== Exporting release candidate ==="
echo "source: $ROOT_DIR"
echo "target: $TARGET_DIR"

mkdir -p "$TARGET_DIR"

rsync -a --delete --delete-excluded --exclude-from="$IGNORE_FILE" "$ROOT_DIR/" "$TARGET_DIR/"
rsync -a "$TEMPLATE_DIR/" "$TARGET_DIR/"

echo "Running release scrub checks..."

RELEASE_SURFACES=()
while IFS= read -r -d '' file; do
    RELEASE_SURFACES+=("$file")
done < <(find "$TARGET_DIR" -type f \( -name '*.sh' -o -path "$TARGET_DIR/cfg/*.cfg" \) -print0)

: > /tmp/xLedgRSv2Beta-release-seed-scan.txt
seed_error=0
while IFS= read -r -d '' file; do
    if awk '
        /^\[validation_seed\]$/ { in_seed = 1; next }
        in_seed {
            if ($0 ~ /^[[:space:]]*$/) next
            if ($0 ~ /^[[:space:]]*#/) next
            if ($0 ~ /^\[/) { in_seed = 0; next }
            print FILENAME ":" FNR ":" $0
            bad = 1
            exit
        }
        END { exit bad ? 0 : 1 }
    ' "$file" >> /tmp/xLedgRSv2Beta-release-seed-scan.txt; then
        seed_error=1
    fi
done < <(find "$TARGET_DIR/cfg" -name '*.cfg' -print0)

if [ "$seed_error" -ne 0 ]; then
    cat /tmp/xLedgRSv2Beta-release-seed-scan.txt
    echo "ERROR: exported cfg tree still contains an uncommented validation seed"
    exit 1
fi

if rg -n -P '^\s*(?:ssh|scp|rsync)\b.*\b[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\b' \
    "${RELEASE_SURFACES[@]}" > /tmp/xLedgRSv2Beta-release-host-scan.txt; then
    cat /tmp/xLedgRSv2Beta-release-host-scan.txt
    echo "ERROR: exported deploy/config files still contain a hardcoded remote target"
    exit 1
fi

if rg -n -P '\\b(?!(?:127\\.0\\.0\\.1|0\\.0\\.0\\.0)\\b)(?:\\d{1,3}\\.){3}\\d{1,3}\\b' \
    "${RELEASE_SURFACES[@]}" > /tmp/xLedgRSv2Beta-release-ip-scan.txt; then
    cat /tmp/xLedgRSv2Beta-release-ip-scan.txt
    echo "ERROR: exported deploy/config files still contain a hardcoded non-local IP"
    exit 1
fi

echo "Release export ready"
