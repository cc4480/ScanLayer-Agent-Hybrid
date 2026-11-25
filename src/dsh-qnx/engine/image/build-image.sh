#!/bin/sh
# [SDP] Build the QNX 8.0 x86_64 QEMU image with the agent's on-target pieces.
#
# Follows the QNX 8.0 mkqnximage reference:
#   https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkqnximage.html
# - an image directory holds `local/` (options, snippets) and `output/` (the image);
# - our files go in through local/snippets/system_files.custom (mkqnx6fsimg buildfile lines,
#   `[attributes] target_path=host_path`) onto the read-only /system partition;
# - the runner starts at boot from local/snippets/post_start.custom (ksh, included in post_startup.sh);
# - --ssh-ident lets root log in over ssh without a password (used by phase0.sh for the survey).
# Host: QNX lists QEMU images for Ubuntu hosts (on Windows, use WSL2 Ubuntu or a Linux machine).
# Still to confirm at the first real build (marked VERIFY): whether system_files target paths take a leading
# slash, and whether --ssh-ident wants the .pub file. A wrong line fails the build loudly; mkifs/mkqnx6fsimg
# line numbers refer to files in output/build (per the reference's troubleshooting section).
#
#   source ~/qnx800/qnxsdp-env.sh
#   sh image/build-image.sh            # builds into image/out/
#   sh image/run-qemu.sh               # boots it, forwards the runner and ssh ports
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
OUT=${OUT:-$HERE/out}
STATE=${STATE:-$ROOT/qnx/state}
SSH_PUB=${SSH_PUB:-$HOME/.qnx-agent/qnx-ssh.pub}

: "${QNX_TARGET:?source qnxsdp-env.sh first (QNX_TARGET unset)}"
command -v qcc >/dev/null || { echo "qcc not on PATH: source qnxsdp-env.sh"; exit 1; }
command -v mkqnximage >/dev/null || { echo "mkqnximage not on PATH: source qnxsdp-env.sh"; exit 1; }
for f in "$STATE/runner.token" "$STATE/runner.allow" "$SSH_PUB"; do
  [ -f "$f" ] || { echo "missing $f — run scripts/phase0.sh (it creates the state and key first)"; exit 1; }
done

mkdir -p "$OUT/local/snippets" "$OUT/docs"
qcc -V > "$OUT/docs/qcc-V.txt" 2>&1 || true

# 1. Cross-compile the runner for the target.
make -C "$ROOT/node-runtime" CC="qcc -Vgcc_ntox86_64" CFLAGS="-O2 -std=c99 -Wall -Wextra" OUT=qnx-runner.x86_64
file "$ROOT/node-runtime/qnx-runner.x86_64" > "$OUT/docs/runner-file.txt" 2>&1 || true

# 2. Files onto /system (read-only partition): runner, inventory, start script, token, allowlist.
#    VERIFY: target paths are relative to the partition root (/system); if the build rejects them, add a leading slash.
cat > "$OUT/local/snippets/system_files.custom" <<EOF
[perms=0755 uid=0 gid=0] qnx-agent/bin/qnx-runner=$ROOT/node-runtime/qnx-runner.x86_64
[perms=0755 uid=0 gid=0] qnx-agent/bin/qnx-inventory=$ROOT/node-runtime/inventory-qnx.sh
[perms=0755 uid=0 gid=0] qnx-agent/bin/qnx-agent-start=$HERE/qnx-agent-start.sh
[perms=0600 uid=0 gid=0] qnx-agent/etc/runner.token=$STATE/runner.token
[perms=0644 uid=0 gid=0] qnx-agent/etc/runner.allow=$STATE/runner.allow
EOF

# 3. Start the runner after the system is up.
cat > "$OUT/local/snippets/post_start.custom" <<'EOF'
# qnx-agent: on-target runner (argv only; token + allowlist; spawn log under /data)
/system/qnx-agent/bin/qnx-agent-start
EOF

# 4. Build. Options persist in local/options, so later runs need only what changes.
cd "$OUT"
mkqnximage --type=qemu --arch=x86_64 --hostname=qnxagent --ssh-ident="$SSH_PUB" --build \
  ${MKQNXIMAGE_EXTRA:-} 2>&1 | tee "$OUT/docs/mkqnximage.log"
ls -la "$OUT/output" | tee -a "$OUT/docs/mkqnximage.log"
echo "built in $OUT/output — next: sh image/run-qemu.sh"
