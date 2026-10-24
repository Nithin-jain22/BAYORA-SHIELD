#!/usr/bin/env bash
# Development mode: FastAPI on :8000 + Vite dev server on :5173 with HMR.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -d "$ROOT/frontend/node_modules" ]; then
  (cd "$ROOT/frontend" && npm install --no-audit --no-fund)
fi

python3 -m uvicorn src.api.server:app --host 127.0.0.1 --port 8000 --reload &
API_PID=$!
trap 'kill "$API_PID" 2>/dev/null || true' EXIT

cd "$ROOT/frontend"
exec npm run dev
