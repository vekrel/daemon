#!/usr/bin/env bash
# Manual smoke of `vekrel serve` in front of the reference Node engine (not run by cargo test).
# Usage: scripts/smoke.sh [ENGINE_DIR] [WEB_DIR]   (or set ENGINE_DIR / WEB_DIR; PORT defaults to 3779)
# WEB_DIR is optional: when given, its apps/web/dist is copied into the engine so it serves that UI.
set -euo pipefail

ENGINE_DIR=${1:-${ENGINE_DIR:?usage: smoke.sh ENGINE_DIR [WEB_DIR]}}
WEB_DIR=${2:-${WEB_DIR:-}}
PORT=${PORT:-3779}
BIN="$ENGINE_DIR/apps/server/dist/bin.mjs"
ROOT=$(cd "$(dirname "$0")/.." && pwd)

[ -f "$BIN" ] || { echo "missing $BIN; run: pnpm --filter vekrel-engine build:bundle" >&2; exit 1; }
if [ -n "$WEB_DIR" ]; then
  [ -d "$WEB_DIR/apps/web/dist" ] || { echo "missing $WEB_DIR/apps/web/dist; run: pnpm --filter @vekrel/web build" >&2; exit 1; }
  rm -rf "$ENGINE_DIR/apps/web/dist" && cp -R "$WEB_DIR/apps/web/dist" "$ENGINE_DIR/apps/web/dist"
fi

# Fresh state dir so the smoke never touches ~/.vekrel; it holds session tokens, so it is always deleted.
VEKREL_HOME=$(mktemp -d)
export VEKREL_HOME
PID=
cleanup() {
  [ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  rm -rf "$VEKREL_HOME"
}
trap cleanup EXIT

cat > "$VEKREL_HOME/vekrel.toml" <<TOML
[server]
port = $PORT
[engine]
command = "node"
args = ["$BIN"]
TOML

(cd "$ROOT" && cargo build --release -q)
"$ROOT/target/release/vekrel" serve --config "$VEKREL_HOME/vekrel.toml" --record > "$VEKREL_HOME/serve.log" 2>&1 &
PID=$!

# /healthz says "up" once the machine endpoint answers (polled every 250 ms), so allow it a moment.
code=000
for _ in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/.well-known/vekrel/machine" || true)
  [ "$code" = 200 ] && break
  sleep 1
done
health=
for _ in $(seq 1 10); do
  health=$(curl -s "http://127.0.0.1:$PORT/healthz" || true)
  grep -q '"engine":"up"' <<<"$health" && break
  sleep 0.3
done
echo "healthz: $health"
echo "machine: $code"
if [ "$code" != 200 ] || ! grep -q '"engine":"up"' <<<"$health"; then
  echo "FAIL; serve log tail:" >&2
  tail -20 "$VEKREL_HOME/serve.log" | sed -E 's/token=[^ ]*/token=<redacted>/' >&2
  exit 1
fi

# Handlers default to serve: Rust answers these, marked by x-vekrel-served-by. Pair first (the
# engine prints a one-time token) so /api/auth/session is checked with a verified cookie.
URL="http://127.0.0.1:$PORT"
served_by() { curl -s -D - -o /dev/null "$@" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-vekrel-served-by"{print $2}'; }
token=$(grep -o '#token=[A-Za-z0-9_-]*' "$VEKREL_HOME/serve.log" | head -1 | cut -d= -f2)
pair=$(curl -s -o /dev/null -w '%{http_code}' -c "$VEKREL_HOME/jar" -X POST -H 'content-type: application/json' \
  -d "{\"credential\":\"$token\"}" "$URL/api/auth/browser-session" || true)
session=$(curl -s -b "$VEKREL_HOME/jar" "$URL/api/auth/session" || true)
machine_by=$(served_by "$URL/.well-known/vekrel/machine")
session_by=$(served_by -b "$VEKREL_HOME/jar" "$URL/api/auth/session")
echo "pairing: $pair; machine served by: ${machine_by:-node}; session served by: ${session_by:-node}"
if [ "$pair" != 200 ] || [ "$machine_by" != rust ] || [ "$session_by" != rust ] \
  || ! grep -q '"authenticated":true' <<<"$session"; then
  echo "FAIL: expected both routes answered by rust with a verified session" >&2
  exit 1
fi
echo "PASS"
