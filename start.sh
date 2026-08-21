#!/usr/bin/env bash
# SentinelSOC — Startup Script (Backend FastAPI + Frontend React Vite)

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "======================================================================"
echo "🛡️  Starting SentinelSOC Environment"
echo "======================================================================"

# Ensure database directory exists
mkdir -p "$PROJECT_ROOT/data"

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
