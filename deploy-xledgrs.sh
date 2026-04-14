#!/bin/bash
set -euo pipefail

: "${VALIDATOR:?Set VALIDATOR=user@host}"
: "${BUILD_SERVER:?Set BUILD_SERVER=user@host}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WIPE=false
NETWORK="mainnet"
CFG_FILE="${CFG_FILE:-xrplnode.cfg}"
BIN_NAME="${BIN_NAME:-xledgrs}"
BUILD_DIR="${BUILD_DIR:-~/xledgrs-src}"
REMOTE_DATA_DIR="${REMOTE_DATA_DIR:-xledgrs-data}"

for arg in "$@"; do
    case "$arg" in
        --wipe)
            WIPE=true
            ;;
        --testnet)
            NETWORK="testnet"
            CFG_FILE="${CFG_FILE_TESTNET:-testnet.cfg}"
            REMOTE_DATA_DIR="${REMOTE_TESTNET_DATA_DIR:-xledgrs-testnet-data}"
            ;;
    esac
done

echo "=== xLedgRS deploy ($NETWORK) ==="
echo "This script manages $BIN_NAME only. It does not touch rippled."

echo "Syncing source..."
rsync -az --delete "$SCRIPT_DIR/src/" "$BUILD_SERVER:$BUILD_DIR/src/"
rsync -az --delete "$SCRIPT_DIR/proto/" "$BUILD_SERVER:$BUILD_DIR/proto/"
rsync -az --delete "$SCRIPT_DIR/cfg/" "$BUILD_SERVER:$BUILD_DIR/cfg/"
rsync -az "$SCRIPT_DIR/Cargo.toml" "$BUILD_SERVER:$BUILD_DIR/Cargo.toml"
rsync -az "$SCRIPT_DIR/Cargo.lock" "$BUILD_SERVER:$BUILD_DIR/Cargo.lock" 2>/dev/null || true
rsync -az "$SCRIPT_DIR/build.rs" "$BUILD_SERVER:$BUILD_DIR/build.rs"

echo "Stopping node..."
ssh "$VALIDATOR" "pkill -x $BIN_NAME 2>/dev/null && echo 'sent TERM' || echo '$BIN_NAME not running'"
while ssh "$VALIDATOR" "pgrep -x $BIN_NAME > /dev/null 2>&1"; do
    sleep 1
done
echo "Confirmed stopped"

echo "Building on build server..."
ssh "$BUILD_SERVER" "source ~/.cargo/env && cd $BUILD_DIR && cargo build --release 2>&1 | tail -5"
echo "Build done"

echo "Staging binary..."
scp "$BUILD_SERVER:$BUILD_DIR/target/release/$BIN_NAME" "/tmp/$BIN_NAME-release"
scp "/tmp/$BIN_NAME-release" "$VALIDATOR:~/$BIN_NAME-next"
scp "$SCRIPT_DIR/cfg/$CFG_FILE" "$VALIDATOR:~/$BIN_NAME.cfg"
scp "$SCRIPT_DIR/cfg/validators.txt" "$VALIDATOR:~/validators.txt"
scp "$SCRIPT_DIR/post-sync-checkpoint.sh" "$VALIDATOR:~/post-sync-checkpoint.sh"

if [ "$WIPE" = true ]; then
    echo "Wiping remote data dir..."
    ssh "$VALIDATOR" "rm -rf ~/$REMOTE_DATA_DIR/* && echo 'wiped'"
fi

echo "Deploying..."
ssh "$VALIDATOR" "mv ~/$BIN_NAME-next ~/$BIN_NAME && chmod +x ~/$BIN_NAME"
ssh "$VALIDATOR" "chmod +x ~/post-sync-checkpoint.sh"
ssh -f "$VALIDATOR" "nohup ~/$BIN_NAME --config ~/$BIN_NAME.cfg > ~/$BIN_NAME.log 2>&1 < /dev/null &"

sleep 2
if ssh "$VALIDATOR" "pgrep -x $BIN_NAME > /dev/null 2>&1"; then
    echo "Started successfully"
else
    echo "WARNING: $BIN_NAME did not start"
    ssh "$VALIDATOR" "tail -20 ~/$BIN_NAME.log" 2>/dev/null
fi

echo ""
echo "=== Deploy complete ==="
echo "Monitor: ssh \$VALIDATOR 'tail -f ~/$BIN_NAME.log'"
