#!/bin/sh
# One command: bring up the Linux stand-in target + the engine, headless (no harness).
#   sh scripts/standin-up.sh            (Ctrl-C stops both)
# First run creates standin/state (seat tokens 0600, never printed), takes the
# inventory, writes the baseline manifest and the runner allowlist.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
S="$ROOT/standin"
make -sC "$ROOT/node-runtime"
[ -f "$S/state/seats.json" ] || node "$ROOT/gateway/cli.js" init "$S/state"
sh "$ROOT/node-runtime/inventory-qnx.sh" "$S/state/catalog.json"
[ -f "$S/manifest.json" ] || node "$ROOT/scripts/standin-baseline.js" "$S/state/catalog.json" "$S/manifest.json"
node "$ROOT/gateway/cli.js" allowlist "$S/config.json" > "$S/state/runner.allow"
"$ROOT/node-runtime/qnx-runner" --listen 7781 --bind 127.0.0.1 --token-file "$S/state/runner.token" \
  --allow-file "$S/state/runner.allow" --spawn-log "$S/state/spawn.log" &
RUNNER=$!
trap 'kill $RUNNER 2>/dev/null' EXIT INT TERM
sleep 0.3
echo "seat tokens: $S/state/seat-*.token (MCP clients send one as a Bearer token; the harness pages need none)"
node "$ROOT/gateway/server.js" "$S/config.json"
