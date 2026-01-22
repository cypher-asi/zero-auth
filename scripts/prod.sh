#!/usr/bin/env bash
# Production Server Script for Linux/macOS
# Usage: SERVICE_MASTER_KEY=your-key ./scripts/prod.sh

set -euo pipefail

echo "=== zid Production Server ==="

# Require master key
if [ -z "${SERVICE_MASTER_KEY:-}" ]; then
    echo "ERROR: SERVICE_MASTER_KEY is required for production mode"
    echo "Generate one with: openssl rand -hex 32"
    exit 1
fi

# Validate key length
if [ ${#SERVICE_MASTER_KEY} -ne 64 ]; then
    echo "ERROR: SERVICE_MASTER_KEY must be 64 hex characters (32 bytes)"
    exit 1
fi

# Set prod mode
export RUN_MODE="prod"
export RUST_LOG="${RUST_LOG:-zid_server=info,tower_http=info}"
export BIND_ADDRESS="${BIND_ADDRESS:-0.0.0.0:9999}"

echo "Bind Address: $BIND_ADDRESS"
echo "Log Level: $RUST_LOG"
echo ""

# Run the server in release mode
cargo run -p zid-server --release
