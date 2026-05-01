#!/bin/bash
# xLedgRS purpose: Start a validator node with validator config defaults.
set -euo pipefail

CONFIG_FILE="$HOME/xLedgRSv2Beta-validator.cfg"
LOG_FILE="$HOME/xLedgRSv2Beta-validator.log"
BINARY="$HOME/xledgrs"

if pidof xledgrs > /dev/null 2>&1; then
    echo "ERROR: node already running PID $(pidof xledgrs | awk '{print $1}')"
    exit 1
fi

if [ ! -x "$BINARY" ]; then
    echo "ERROR: $BINARY not found or not executable"
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

mkdir -p "$HOME/xLedgRSv2Beta-validator-data"
echo "Config: $CONFIG_FILE"
echo "Data dir: $(du -sh "$HOME/xLedgRSv2Beta-validator-data" 2>/dev/null | cut -f1) used"

if pgrep -x rippled > /dev/null; then
    echo "rippled: running (PID $(pgrep -x rippled | head -1)) — NOT TOUCHING IT"
fi

if pgrep -x xledgrs > /dev/null; then
    echo "xledgrs node: running (PID $(pgrep -x xledgrs | head -1))"
fi

[ -f "$LOG_FILE" ] && mv "$LOG_FILE" "$LOG_FILE.prev" && echo "Log rotated"

RUST_LOG="${RUST_LOG:-info}" nohup "$BINARY" \
    --config "$CONFIG_FILE" \
    >> "$LOG_FILE" 2>&1 &

sleep 3
if ! pidof xledgrs > /dev/null 2>&1; then
    echo "ERROR: failed to start — check $LOG_FILE"
    tail -5 "$LOG_FILE" 2>/dev/null || true
    exit 1
fi

PID=$(pidof xledgrs | awk '{print $1}')
echo "started PID $PID"

for i in $(seq 1 15); do
    if curl -s --connect-timeout 2 "http://127.0.0.1:$RPC_PORT" -d '{"method":"ping"}' | grep -q success; then
        echo "RPC: responding on port $RPC_PORT"
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
