#!/bin/sh
# [SDP] Phase 0 as one script — run the day the SDP lands, on an Ubuntu host (QNX supports QEMU images on Ubuntu;
# on Windows use WSL2 Ubuntu or a Linux machine). Every receipt lands in docs/phase0/.
#
#   source ~/qnx800/qnxsdp-env.sh && sh engine/scripts/phase0.sh
#
#   1 record the SDP and qcc -V             5 hello-world cross-compiled, copied in, run on the target
#   2 create qnx/state (tokens, ssh key)     6 runtime survey over ssh
#   3 build the image (runner via qcc)       7 catalog pulled THROUGH the runner; allowlist generated and installed
#   4 boot it in QEMU and wait for ssh       8 clean-image baseline manifest; qnx/config.json for the engine
#
# Done-test: QEMU boots, hello-world runs on the target, the survey is written with receipts, the runner answers.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
D="$ROOT/docs/phase0"; S="$ROOT/qnx/state"
# The ssh key and the image live on the Linux side ($HOME), not in the checkout: a checkout on a Windows drive
# (/mnt/c under WSL) cannot make a key private, so ssh refuses it, and a multi-GB image in a synced folder is slow.
K="${QNX_AGENT_HOME:-$HOME/.qnx-agent}"; OUT="$K/image"; KEY="$K/qnx-ssh"
export OUT
mkdir -p "$D" "$S" "$K"; chmod 700 "$K"
: "${QNX_HOST:?source qnxsdp-env.sh first}"
for t in qcc mkqnximage qemu-system-x86_64 ssh scp ssh-keygen node; do command -v $t >/dev/null || { echo "missing: $t"; exit 1; }; done
grep -qi ubuntu /etc/os-release 2>/dev/null || echo "note: QNX documents QEMU images for Ubuntu hosts; continuing anyway" >&2

# 1. SDP
{ echo "date: $(date -u)"; echo "host: $(uname -a)"; grep PRETTY_NAME /etc/os-release || true
  echo "QNX_HOST=$QNX_HOST"; echo "QNX_TARGET=$QNX_TARGET"; qcc -V 2>&1; } > "$D/sdp.txt"
echo "1. SDP recorded -> docs/phase0/sdp.txt"

# 2. State: seats + runner token (cli init), an ssh key for root, and a first allowlist that lets only the inventory run.
[ -f "$S/seats.json" ] || node "$ROOT/gateway/cli.js" init "$S"
[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -C qnx-agent-phase0 -f "$KEY"
printf '/system/qnx-agent/bin/qnx-inventory\n' > "$S/runner.allow"
echo "2. state ready (tokens in qnx/state, ssh key $KEY)"

# 3. Image
STATE="$S" SSH_PUB="$KEY.pub" sh "$ROOT/image/build-image.sh"
cp "$OUT/docs/"* "$D/"
echo "3. image built in $OUT/output (build receipts -> docs/phase0/)"

# 4. Boot (QEMU in the background; its serial console is the boot receipt), then wait for ssh.
SSH="ssh -i $KEY -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=$K/known_hosts -o ConnectTimeout=5 root@127.0.0.1"
SCP="scp -i $KEY -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=$K/known_hosts"
( sh "$ROOT/image/run-qemu.sh" </dev/null >"$D/qemu-console.log" 2>&1 & )
i=0; until $SSH true 2>/dev/null; do i=$((i+1)); [ $i -gt 120 ] && { echo "guest did not answer ssh in 10 min; see docs/phase0/qemu-console.log"; exit 1; }; sleep 5; done
echo "4. QNX is up (ssh on 127.0.0.1:2222)"

# 5. Hello world on the target.
printf '#include <stdio.h>\nint main(void){puts("hello from QNX");return 0;}\n' > "$D/hello.c"
qcc -Vgcc_ntox86_64 -o "$D/hello" "$D/hello.c"
$SCP "$D/hello" root@127.0.0.1:/data/qnx-agent/hello
{ echo "\$ file hello"; file "$D/hello"; echo "\$ /data/qnx-agent/hello   (on the target)"; $SSH /data/qnx-agent/hello; } > "$D/hello-world.txt" 2>&1
echo "5. hello-world: $(tail -1 "$D/hello-world.txt")"

# 6. Runtime survey (raw outputs kept).
{ for c in "uname -a" "pidin info" "pidin arg" "use -i /proc/boot/procnto-smp-instr" "ls /proc/boot /system/bin" \
           "ifconfig -a" "netstat -an" "netstat -rn" "sysctl net.inet.ip.forwarding" "ls -l /dev" "slog2info" ; do
    echo "===== \$ $c"; $SSH "$c" 2>&1 | head -200
  done
  for p in python3 python node perl lua ksh sh busybox tcpdump pidin slog2info use sysctl ifconfig netstat ps find cksum nc ping; do
    printf '%s: ' "$p"; $SSH "command -v $p || echo MISSING" 2>&1
  done; } > "$D/runtime-survey.raw.txt"
echo "6. survey -> docs/phase0/runtime-survey.raw.txt"

# 7. Catalog THROUGH the runner (its first real job), then the full allowlist from that catalog, installed on /data.
node -e '
const { RunnerClient } = require(process.argv[1] + "/gateway/lib/gate");
const fs = require("fs");
const r = new RunnerClient({ mode: "tcp", host: "127.0.0.1", port: 7781, token: fs.readFileSync(process.argv[2], "utf8").trim() });
r.run(["/system/qnx-agent/bin/qnx-inventory", "-"], 60000, 8 * 1024 * 1024).then((x) => {
  if (!x.ok || x.exit !== 0 || x.truncated) { console.error(JSON.stringify(x).slice(0, 600)); process.exit(1); }
  fs.writeFileSync(process.argv[3], x.stdout); console.error("catalog: " + JSON.parse(x.stdout).meta.tool_count + " tools");
}).catch((e) => { console.error(e.message); process.exit(1); });' "$ROOT" "$S/runner.token" "$S/catalog.json"
node -e '
const fs = require("fs"); const [src, dst] = process.argv.slice(1);
const c = JSON.parse(fs.readFileSync(src, "utf8"));
c._comment = "QNX 8.0 QEMU guest, written by scripts/phase0.sh. The runner runs in the guest, forwarded to 127.0.0.1:7781.";
c.inventory_path = "/system/qnx-agent/bin/qnx-inventory";
c.manifest = "manifest.json";
c.target_ssh = { host: "127.0.0.1", port: 2222, user: "root", key: process.argv[3], spawn_log: "/data/qnx-agent/spawn.log" };
fs.writeFileSync(dst, JSON.stringify(c, null, 2) + "\n");' "$ROOT/standin/config.json" "$ROOT/qnx/config.json" "$KEY"
node "$ROOT/gateway/cli.js" allowlist "$ROOT/qnx/config.json" > "$S/runner.allow.full"
$SCP "$S/runner.allow.full" root@127.0.0.1:/data/qnx-agent/runner.allow
echo "7. catalog pulled through the runner; allowlist of $(wc -l < "$S/runner.allow.full") tools installed on the target"

# 8. Baseline of the clean image, then point the engine at it.
$SSH "cksum /proc/boot/procnto-smp-instr /proc/boot/libc.so* /system/qnx-agent/bin/qnx-runner /system/qnx-agent/bin/qnx-inventory" > "$S/cksums.txt" 2>/dev/null || true
node "$ROOT/scripts/baseline-from-catalog.js" "$S/catalog.json" "$ROOT/qnx/manifest.json" "$S/cksums.txt"
cp "$ROOT/qnx/manifest.json" "$D/manifest-clean-image.json"
echo "8. engine config -> qnx/config.json (manifest: clean-image baseline)"
echo
echo "Phase 0 done. QEMU keeps running (stop: kill \$(cat $OUT/output/qemu.pid)). Next:"
echo "  harness: set dsh-qnx  target: qnx  and boot it, or headless:  node gateway/server.js qnx/config.json"
echo "  proof:   node scripts/prove.js qnx/config.json docs/receipts"
