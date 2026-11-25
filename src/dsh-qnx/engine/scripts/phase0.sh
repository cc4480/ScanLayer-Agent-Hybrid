#!/bin/sh
# [SDP] Phase 0 runbook as one script — run the day the SDP lands.
# Records every receipt the done-test needs under docs/phase0/.
#   1 SDP version + qcc -V   2 build image   3 boot in QEMU (separate terminal)
#   4 hello-world on target  5 runtime survey   6 gateway pointed at the guest
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
D="$ROOT/docs/phase0"; mkdir -p "$D"
: "${QNX_HOST:?source qnxsdp-env.sh first}"

{ echo "date: $(date -u)"; echo "host: $(uname -a)"; echo "QNX_HOST=$QNX_HOST"; echo "QNX_TARGET=$QNX_TARGET"; qcc -V 2>&1; } > "$D/sdp.txt"
echo "1. SDP recorded -> $D/sdp.txt"

printf '#include <stdio.h>\nint main(void){puts("hello from QNX");return 0;}\n' > "$D/hello.c"
qcc -Vgcc_ntox86_64 -o "$D/hello" "$D/hello.c"
echo "2. hello cross-compiled ($(file "$D/hello" | cut -d: -f2))"

mkdir -p "$ROOT/qnx"
[ -f "$ROOT/qnx/state/seats.json" ] || node "$ROOT/gateway/cli.js" init "$ROOT/qnx/state"
sh "$ROOT/image/build-image.sh"
echo "3. image built. Boot it now in another terminal:  sh image/run-qemu.sh"
echo "   then press enter here once the guest prints 'qnx-runner started'"; read _

# 4 + 5: everything below goes THROUGH THE RUNNER, so it is also the runner's first test.
# The survey needs a shell for `command -v`; add the guest's sh path (VERIFY: /proc/boot/sh or /bin/sh)
# to qnx/state/runner.allow for this step only, and remove it afterwards.
SH=${QNX_SH:-/proc/boot/sh}
TOK=$(cat "$ROOT/qnx/state/runner.token")
ask() { printf '{"token":"%s","argv":%s,"timeout_ms":30000}\n' "$TOK" "$1" | nc -w 40 127.0.0.1 7781; }
ask '["/opt/qnx-agent/bin/qnx-inventory","-"]' | node -e 'let b="";process.stdin.on("data",d=>b+=d).on("end",()=>{const r=JSON.parse(b);if(!r.ok||r.exit)throw new Error(b.slice(0,400));process.stdout.write(r.stdout)})' > "$ROOT/qnx/state/catalog.json"
echo "4. catalog pulled through the runner -> qnx/state/catalog.json"
{
  ask "[\"$SH\",\"-c\",\"uname -a\"]"
  for p in python3 python node perl lua ksh sh busybox tcpdump pidin slog2info use sysctl ifconfig netstat ps find cksum nc; do
    ask "[\"$SH\",\"-c\",\"printf '%s: ' $p; command -v $p || echo MISSING\"]"
  done
} > "$D/runtime-survey.raw.txt" 2>&1
echo "5. runtime survey -> $D/runtime-survey.raw.txt  (copy hello into the image and run it the same way for the hello-world receipt)"
sed 's#"inventory_path": "../node-runtime/inventory-qnx.sh"#"inventory_path": "/opt/qnx-agent/bin/qnx-inventory"#; s#"manifest": "manifest.json"#"manifest": "../image/manifest.json"#' "$ROOT/standin/config.json" > "$ROOT/qnx/config.json"
echo "6. gateway config -> qnx/config.json. Run:  node gateway/server.js qnx/config.json  then  node scripts/prove.js qnx/config.json docs/receipts"
