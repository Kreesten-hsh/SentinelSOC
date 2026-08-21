#!/usr/bin/env bash
# SentinelSOC — Startup Script (Backend FastAPI + Frontend React Vite)

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "======================================================================"
echo "🛡️  Starting SentinelSOC Environment"
echo "======================================================================"

# Ensure directories exist
mkdir -p "$PROJECT_ROOT/data"
mkdir -p "$PROJECT_ROOT/models"

# 0. Check and Bootstrap ML Severity Model
MODEL_FILE="$PROJECT_ROOT/models/severity_model.joblib"
if [ ! -f "$MODEL_FILE" ]; then
    echo "[0/3] ML severity model not found at models/severity_model.joblib."
    echo "      Bootstrapping RandomForest classifier from investigation archetypes..."
    python3 scripts/train_severity_model.py
    echo "      ✓ ML Model successfully trained and serialized."
else
    echo "[0/3] ML severity model verified at $MODEL_FILE."
fi

# Function to clean background processes on Ctrl+C
cleanup() {
    echo ""
    echo "Stopping SentinelSOC services..."
    kill $(jobs -p) 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 1. Start FastAPI backend on port 8000
echo "[1/2] Launching FastAPI Backend on http://localhost:8000..."
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Wait for backend to be ready
sleep 2

# 2. Start Vite frontend dev server on port 5173
echo "[2/2] Launching React Vite Dashboard on http://localhost:5173..."
cd "$PROJECT_ROOT/frontend"
npm run dev -- --host 0.0.0.0 --port 5173 &
FRONTEND_PID=$!

echo ""
echo "======================================================================"
echo "✅ SentinelSOC is Live & Ready!"
echo "   - SOC Dashboard : http://localhost:5173"
echo "   - API Swagger   : http://localhost:8000/docs"
echo "   - API Health    : http://localhost:8000/api/health"
echo "======================================================================"
echo "Press Ctrl+C to terminate both servers."

wait
