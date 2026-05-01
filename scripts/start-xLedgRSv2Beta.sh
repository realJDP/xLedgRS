#!/bin/bash
# xLedgRS purpose: Start a follower node with release defaults.
set -euo pipefail

CONFIG_FILE="${XLEDGRSV2BETA_CONFIG:-$HOME/xLedgRSv2Beta.cfg}"
LOG_FILE="${XLEDGRSV2BETA_LOG:-$HOME/xLedgRSv2Beta.log}"

if pgrep -x xledgrs > /dev/null; then
    echo "ERROR: already running PID $(pgrep -x xledgrs | head -1)"
    exit 1
fi

if [ ! -x "$HOME/xledgrs" ]; then
    echo "ERROR: $HOME/xledgrs not found or not executable"
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: config file not found: $CONFIG_FILE"
    exit 1
fi

RPC_PORT="$(awk '
    /^\[port_rpc\]$/ { in_rpc = 1; next }
    /^\[/ { in_rpc = 0 }
    in_rpc && $1 == "port" {
        gsub(/[[:space:]]/, "", $3)
        print $3
        exit
    }
' "$CONFIG_FILE")"
RPC_PORT="${XLEDGRSV2BETA_RPC_PORT:-${RPC_PORT:-5005}}"

# Create data dir based on config
DATA_DIR="$HOME/xLedgRSv2Beta-data"
if grep -qE '^\s*testnet\s*$' "$CONFIG_FILE" 2>/dev/null; then
    DATA_DIR="$HOME/xLedgRSv2Beta-testnet-data"
fi
mkdir -p "$DATA_DIR"
echo "Config: $CONFIG_FILE"
echo "Data dir: $(du -sh "$DATA_DIR" 2>/dev/null | cut -f1) used"

if pgrep -x rippled > /dev/null; then
    echo "rippled: running (PID $(pgrep -x rippled | head -1))"
else
    echo "WARNING: rippled not running — no local peer available"
fi

[ -f "$LOG_FILE" ] && mv "$LOG_FILE" "$LOG_FILE.prev" && echo "Log rotated"

# RPC sync: disabled by default, peer sync handles state download.
# Set XLEDGRSV2BETA_RPC_SYNC env var to enable (e.g. "127.0.0.1:5005").
RPC_SYNC_ARGS=""
# Manual override via env var (set to "none" to disable)
if [ -n "${XLEDGRSV2BETA_RPC_SYNC:-}" ]; then
    if [ "$XLEDGRSV2BETA_RPC_SYNC" = "none" ]; then
        RPC_SYNC_ARGS=""
    else
        RPC_SYNC_ARGS="--rpc-sync $XLEDGRSV2BETA_RPC_SYNC"
    fi
fi

RUST_LOG="${RUST_LOG:-info}" nohup "$HOME/xledgrs" \
    --config "$CONFIG_FILE" \
    $RPC_SYNC_ARGS \
    >> "$LOG_FILE" 2>&1 &

sleep 3
if ! pgrep -x xledgrs > /dev/null; then
    echo "ERROR: failed to start — check $LOG_FILE"
    tail -5 "$LOG_FILE" 2>/dev/null || true
    exit 1
fi

PID=$(pgrep -x xledgrs | head -1)
echo "started PID $PID"

for i in $(seq 1 15); do
    if curl -s --connect-timeout 2 "http://127.0.0.1:$RPC_PORT" -d '{"method":"ping"}' | grep -q success; then
        echo "RPC: responding on configured port"
        break
    fi
    [ "$i" -eq 15 ] && echo "WARNING: RPC not responding after 15s"
    sleep 1
done

if INITIAL_INFO=$(curl -s --connect-timeout 2 "http://127.0.0.1:$RPC_PORT" -d '{"method":"server_info","params":[{}]}' 2>/dev/null); then
    printf '%s' "$INITIAL_INFO" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)['result']['info']
    print(f\"Ledger: {d.get('validated_ledger', {}).get('seq', 0)}\")
    print(f\"Peers: {d.get('peers', 0)}\")
    print(f\"Objects: {d.get('objects_stored', 0)}\")
    print(f\"Memory: {d.get('memory_mb', 0)} MB\")
except Exception:
    pass
" 2>/dev/null
fi
