#!/usr/bin/env sh
set -eu

INTERVAL_SECONDS="${INTERVAL_SECONDS:-10}"

if [ -f /app/version.txt ]; then
  echo "[runner] Version $(tr -d '\r\n' < /app/version.txt)"
fi
echo "[runner] Starting optimus checker loop (every ${INTERVAL_SECONDS}s)"

while true; do
  python /app/app.py || true
  sleep "${INTERVAL_SECONDS}"
done
