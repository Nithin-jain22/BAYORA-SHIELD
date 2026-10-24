#!/usr/bin/env bash
# Build the React frontend (if needed) and serve the whole app from FastAPI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND="$ROOT/frontend"
PORT="${PORT:-8000}"

cd "$ROOT"

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required to build the React frontend." >&2
  exit 1
fi

if [ ! -d "$FRONTEND/node_modules" ]; then
  echo "Installing frontend dependencies…"
  (cd "$FRONTEND" && npm install --no-audit --no-fund)
fi

if [ ! -d "$FRONTEND/dist" ] || [ "$FRONTEND/src" -nt "$FRONTEND/dist" ] || [ "$FRONTEND/package.json" -nt "$FRONTEND/dist" ]; then
  echo "Building frontend…"
  (cd "$FRONTEND" && npm run build)
fi

echo "Bayora-Shield → http://127.0.0.1:$PORT"
exec python3 -m uvicorn src.api.server:app --host 127.0.0.1 --port "$PORT"
