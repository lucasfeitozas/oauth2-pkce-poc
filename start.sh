#!/usr/bin/env bash
# Sobe os três serviços da POC. Ctrl+C derruba todos.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi

UVICORN=".venv/bin/uvicorn"

trap 'kill 0' EXIT

$UVICORN auth_server:app --app-dir backend --port 9000 &
$UVICORN api:app --app-dir backend --port 8000 &
$UVICORN bff:app --app-dir backend --port 3000 &

echo
echo "Auth Server: http://localhost:9000"
echo "API:         http://localhost:8000"
echo "Front + BFF: http://localhost:3000  <- abra este"
echo

wait
