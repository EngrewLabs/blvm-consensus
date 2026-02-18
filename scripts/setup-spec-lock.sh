#!/bin/bash
# Setup blvm-spec-lock dependency for CI
#
# LOCAL (monorepo): ../blvm-spec-lock already exists - no action
# CI (standalone repo): Clone blvm-spec-lock to ../blvm-spec-lock so path dep works

set -e

echo "🔍 Checking blvm-spec-lock dependency (path = ../blvm-spec-lock)..."

cd "$(dirname "$0")/.."
PARENT_DIR="$(pwd)"
cd "$PARENT_DIR/.." 2>/dev/null || cd "$PARENT_DIR"

if [ -d "blvm-spec-lock" ]; then
    echo "✅ blvm-spec-lock directory already exists"
    exit 0
fi

echo "📦 Cloning blvm-spec-lock (CI: path not in tree, fetch from GitHub)..."
git clone --depth 1 https://github.com/BTCDecoded/blvm-spec-lock.git || {
    echo "❌ Failed to clone blvm-spec-lock"
    exit 1
}

echo "✅ blvm-spec-lock dependency setup complete"
