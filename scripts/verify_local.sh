#!/usr/bin/env bash
# SentinelSOC — Local In-Place Verification Script
# Quick sanity check on current workspace: package install, ML bootstrap, and full test suite.

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "======================================================================"
echo "🛡️  SentinelSOC — Local In-Place Verification Pipeline"
echo "======================================================================"
echo "Working directory: $PROJECT_ROOT"
echo ""

# 1. Test pip install -e ".[dev]"
echo "[1/4] Testing pip install -e \".[dev]\" with Hatchling build-backend..."
python3 -m pip install --quiet --break-system-packages -e ".[dev]"

# 2. Test package importability
echo "[2/4] Verifying importability of sentinelsoc packages..."
python3 -c "import src.models.alert; import src.agent.sentinel_agent; import backend.main; print('✓ Core modules imported successfully')"

# 3. Test ML Model bootstrap and training
echo "[3/4] Testing ML model bootstrap and training..."
python3 scripts/train_severity_model.py

# 4. Run full test suite
echo "[4/4] Executing full pytest suite..."
python3 -m pytest tests/ -v

echo ""
echo "======================================================================"
echo "✅ LOCAL VERIFICATION SUCCESSFUL: 100% of tests pass!"
echo "======================================================================"
