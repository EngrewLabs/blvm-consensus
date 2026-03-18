#!/bin/bash
# Setup blvm-spec for CI (PROTOCOL.md + ARCHITECTURE.md for spec-lock verification)
#
# LOCAL (monorepo): ../blvm-spec already exists - no action
# CI (standalone repo): Clone blvm-spec to ../blvm-spec so verify can use spec-derived contracts

set -e

echo "🔍 Checking blvm-spec dependency (path = ../blvm-spec)..."

cd "$(dirname "$0")/.."
PARENT_DIR="$(pwd)"
cd "$PARENT_DIR/.." 2>/dev/null || cd "$PARENT_DIR"

if [ -d "blvm-spec" ]; then
    echo "✅ blvm-spec directory already exists"
    exit 0
fi

echo "📦 Cloning blvm-spec (CI: path not in tree, fetch from GitHub)..."
git clone --depth 1 https://github.com/BTCDecoded/blvm-spec.git || {
    echo "❌ Failed to clone blvm-spec"
    exit 1
}

echo "✅ blvm-spec dependency setup complete"
