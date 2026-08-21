#!/usr/bin/env bash
# SentinelSOC — Clean Clone & Environment Verification Script
# Tests package installation with hatchling, auto-bootstrap, and full test suite.

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "======================================================================"
echo "🛡️  SentinelSOC — Clean Clone Verification Pipeline"
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
echo "[4/4] Executing full pytest suite (74 tests)..."
python3 -m pytest tests/ -v

echo ""
echo "======================================================================"
echo "✅ VERIFICATION SUCCESSFUL: 100% of tests pass!"
echo "======================================================================"
