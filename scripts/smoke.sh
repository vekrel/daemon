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

# /healthz says "up" once the child is spawned; the machine endpoint answers only once Node is listening.
code=000
for _ in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/.well-known/vekrel/machine" || true)
  [ "$code" = 200 ] && break
  sleep 1
done
health=$(curl -s "http://127.0.0.1:$PORT/healthz" || true)
echo "healthz: $health"
echo "machine: $code"
if [ "$code" != 200 ] || ! grep -q '"engine":"up"' <<<"$health"; then
  echo "FAIL; serve log tail:" >&2
  tail -20 "$VEKREL_HOME/serve.log" | sed -E 's/token=[^ ]*/token=<redacted>/' >&2
  exit 1
fi
echo "PASS"
