#!/bin/bash
# xLedgRS purpose: Run operator checkpoint hooks after sync completes.
set -euo pipefail

SYNC_SEQ="${XLEDGRSV2BETA_SYNC_LEDGER_SEQ:?missing XLEDGRSV2BETA_SYNC_LEDGER_SEQ}"
SYNC_LEDGER_HASH="${XLEDGRSV2BETA_SYNC_LEDGER_HASH:?missing XLEDGRSV2BETA_SYNC_LEDGER_HASH}"
SYNC_ACCOUNT_HASH="${XLEDGRSV2BETA_SYNC_ACCOUNT_HASH:?missing XLEDGRSV2BETA_SYNC_ACCOUNT_HASH}"
DATA_DIR="${XLEDGRSV2BETA_SYNC_DATA_DIR:?missing XLEDGRSV2BETA_SYNC_DATA_DIR}"
CHECKPOINT_DIR="${CHECKPOINT_DIR:-${DATA_DIR}-sync-base}"
TMP_DIR="${CHECKPOINT_DIR}.tmp"

mkdir -p "$TMP_DIR"
rsync -a --delete "$DATA_DIR/" "$TMP_DIR/"

cat > "$TMP_DIR/CHECKPOINT_INFO.txt" <<EOF
sync_ledger_seq=$SYNC_SEQ
sync_ledger_hash=$SYNC_LEDGER_HASH
sync_account_hash=$SYNC_ACCOUNT_HASH
created_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
source_data_dir=$DATA_DIR
EOF

rm -rf "$CHECKPOINT_DIR.prev"
if [ -d "$CHECKPOINT_DIR" ]; then
    mv "$CHECKPOINT_DIR" "$CHECKPOINT_DIR.prev"
fi
mv "$TMP_DIR" "$CHECKPOINT_DIR"
rm -rf "$CHECKPOINT_DIR.prev"

echo "checkpoint_saved seq=$SYNC_SEQ dir=$CHECKPOINT_DIR"
