#!/usr/bin/env bash
# Dev Server Script for Linux/macOS
# Usage: ./scripts/dev.sh
# Or with persistent key: SERVICE_MASTER_KEY=your-key ./scripts/dev.sh

set -euo pipefail

echo "=== zid Dev Server ==="

# Set dev mode
export RUN_MODE="dev"
export RUST_LOG="${RUST_LOG:-zid_server=debug,tower_http=debug}"
export BIND_ADDRESS="${BIND_ADDRESS:-127.0.0.1:9999}"

if [ -n "${SERVICE_MASTER_KEY:-}" ]; then
    echo "Using provided SERVICE_MASTER_KEY"
else
    echo "Auto-generating SERVICE_MASTER_KEY for this session"
    unset SERVICE_MASTER_KEY 2>/dev/null || true
fi

echo "Bind Address: $BIND_ADDRESS"
echo "Log Level: $RUST_LOG"
echo ""

# Run the server
cargo run -p zid-server
