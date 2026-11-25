#!/bin/sh
# Phase 0 dress rehearsal: runs the REAL scripts/phase0.sh, unmodified, against stand-ins for the QNX SDP, QEMU and the
# guest's ssh (test/fake-sdp), then starts the engine on the resulting qnx/config.json and runs the proof against it.
# The "guest" is this machine, so it exercises every step's orchestration (build, snippets, boot hook, hello-world,
# survey, catalog through the runner, allowlist install, baseline, config) — not QNX itself.
#
# It writes /system/qnx-agent and /data/qnx-agent and starts processes: run it ONLY in a throwaway Linux machine or
# container, as root, with REHEARSE_PHASE0=yes. Everything else happens in a temporary copy of the engine.
#   REHEARSE_PHASE0=yes sh scripts/rehearse-phase0.sh
set -eu
[ "${REHEARSE_PHASE0:-}" = yes ] || { echo "refusing: this writes /system and /data. Run in a throwaway container with REHEARSE_PHASE0=yes"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "needs root (it creates /system/qnx-agent and /data/qnx-agent)"; exit 2; }
[ ! -e /system/qnx-agent ] || [ -f /system/qnx-agent/.rehearsal ] || { echo "/system/qnx-agent exists and is not from a rehearsal; not touching it"; exit 2; }
SRC=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d /tmp/phase0-rehearsal.XXXXXX)
cp -r "$SRC" "$W/engine"; rm -rf "$W/engine/qnx" "$W/engine/docs/phase0" "$W/engine/node-runtime/qnx-runner" "$W/engine/node-runtime/qnx-runner.x86_64"
E="$W/engine"
mkdir -p /system/qnx-agent && touch /system/qnx-agent/.rehearsal
cleanup() {
  [ -f "$W/home/image/output/qemu.pid" ] && kill "$(cat "$W/home/image/output/qemu.pid")" 2>/dev/null || true
  pkill -f "/system/qnx-agent/bin/qnx-runner" 2>/dev/null || true
  pkill -f "gateway/server.js $E/qnx/config.json" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

export PATH="$E/test/fake-sdp:$PATH" QNX_HOST="$W/qnx-host" QNX_TARGET="$W/qnx-target" QNX_AGENT_HOME="$W/home"
mkdir -p "$QNX_HOST" "$QNX_TARGET"
echo "== phase0.sh (real script, stand-in tools) =="
sh "$E/scripts/phase0.sh"

echo; echo "== engine on qnx/config.json, then the proof =="
node "$E/gateway/server.js" "$E/qnx/config.json" > "$W/engine.log" 2>&1 &
i=0; until node -e 'require("http").get("http://127.0.0.1:8095/health", r => process.exit(r.statusCode === 200 ? 0 : 1)).on("error", () => process.exit(1))'; do
  i=$((i+1)); [ $i -gt 40 ] && { cat "$W/engine.log"; exit 1; }; sleep 0.25; done
node "$E/scripts/prove.js" "$E/qnx/config.json" "$W/receipts" | tail -3
echo; echo "== receipts =="
ls "$E/docs/phase0" "$W/receipts"
echo "rehearsal workspace: $W"
