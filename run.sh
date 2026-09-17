#!/usr/bin/env bash
# One-command launcher. Creates a virtualenv on first run, then starts the app.
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
VENV=.venv

if [ ! -d "$VENV" ]; then
  echo "Creating virtualenv in $VENV ..."
  "$PY" -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet -r requirements.txt
fi

[ -f .env ] && set -a && . ./.env && set +a

echo
echo "  RippleGuard is starting."
echo "  Open http://127.0.0.1:8000  -  Ctrl-C to stop."
echo
exec "$VENV/bin/uvicorn" backend.app.main:app --host 127.0.0.1 --port "${PORT:-8000}" "$@"
