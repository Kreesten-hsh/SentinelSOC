#!/usr/bin/env bash
# SentinelSOC — True Clean Clone Verification Script
# Clones the repository into an isolated temporary directory, runs pip install,
# auto-bootstraps the ML model from scratch, and executes the complete test suite.

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_CLONE_DIR=$(mktemp -d /tmp/sentinelsoc_clean_XXXXXX)

echo "======================================================================"
echo "🛡️  SentinelSOC — True Clean Clone Verification Pipeline"
echo "======================================================================"
echo "Source repo:     $PROJECT_ROOT"
echo "Temporary clone: $TMP_CLONE_DIR"
echo ""

cleanup() {
    echo ""
    echo "Cleaning up temporary clone at $TMP_CLONE_DIR..."
    rm -rf "$TMP_CLONE_DIR"
}
trap cleanup EXIT

# 1. Clone repository to fresh isolated location
echo "[1/5] Performing fresh local git clone into isolated temp directory..."
git clone --quiet "$PROJECT_ROOT" "$TMP_CLONE_DIR"
cd "$TMP_CLONE_DIR"

# 2. Verify models directory is empty / gitignored
echo "[2/5] Verifying no pre-existing ML binary is present in fresh clone..."
if [ -f "models/severity_model.joblib" ]; then
    echo "ERROR: severity_model.joblib found in clean clone (should be gitignored)"
    exit 1
fi
echo "✓ No pre-baked model binary found (clean state confirmed)"

# 3. Install dependencies in editable mode
echo "[3/5] Installing package in isolated clone via pip install -e \".[dev]\"..."
python3 -m pip install --quiet --break-system-packages -e ".[dev]"

# 4. Trigger ML model bootstrap
echo "[4/5] Testing automatic model training and serialization..."
python3 scripts/train_severity_model.py
if [ ! -f "models/severity_model.joblib" ]; then
    echo "ERROR: ML model failed to generate"
    exit 1
fi
echo "✓ ML model successfully bootstrapped at models/severity_model.joblib"

# 5. Run full test suite in isolated clone
echo "[5/5] Running complete test suite in clean clone directory..."
python3 -m pytest tests/ -v

echo ""
echo "======================================================================"
echo "✅ TRUE CLEAN CLONE VERIFICATION SUCCESSFUL: 100% PASSING"
echo "======================================================================"
