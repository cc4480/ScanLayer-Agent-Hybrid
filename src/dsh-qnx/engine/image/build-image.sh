#!/bin/sh
# [SDP] Build the QNX 8.0 x86_64 QEMU image with the agent's on-target pieces.
# NOT YET RUN: written before the SDP is installed. Every step marked VERIFY is
# checked against the real SDP at Phase 0 and corrected here, with receipts in
# docs/phase0/.
#
#   source ~/qnx800/qnxsdp-env.sh
#   sh image/build-image.sh            # builds into image/out/
#   sh image/run-qemu.sh               # boots it, forwards the runner port
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
OUT=${OUT:-$HERE/out}

: "${QNX_TARGET:?source qnxsdp-env.sh first (QNX_TARGET unset)}"
command -v qcc >/dev/null || { echo "qcc not on PATH: source qnxsdp-env.sh"; exit 1; }
command -v mkqnximage >/dev/null || { echo "mkqnximage not found (SDP 8.0 ships it under host tools) — VERIFY path"; exit 1; }

mkdir -p "$OUT/docs"
qcc -V > "$OUT/docs/qcc-V.txt" 2>&1 || true

# 1. Cross-compile the runner for the target.
make -C "$ROOT/node-runtime" CC="qcc -Vgcc_ntox86_64" CFLAGS="-O2 -std=c99 -Wall -Wextra" OUT=qnx-runner.x86_64
file "$ROOT/node-runtime/qnx-runner.x86_64" > "$OUT/docs/runner-file.txt" 2>&1 || true

# 2. Stage the agent's on-target files.
STAGE="$OUT/stage/opt/qnx-agent"
mkdir -p "$STAGE/bin" "$STAGE/etc"
cp "$ROOT/node-runtime/qnx-runner.x86_64" "$STAGE/bin/qnx-runner"
cp "$ROOT/node-runtime/inventory-qnx.sh" "$STAGE/bin/qnx-inventory"
chmod 755 "$STAGE/bin/"*
cp "$HERE/qnx-agent-start.sh" "$STAGE/bin/qnx-agent-start"
chmod 755 "$STAGE/bin/qnx-agent-start"
# runner.token and runner.allow are generated on the HOST by the gateway's
# `cli.js init` / `cli.js allowlist` and copied in at build time — never typed.
[ -f "$ROOT/qnx/state/runner.token" ] && cp "$ROOT/qnx/state/runner.token" "$STAGE/etc/runner.token" && chmod 600 "$STAGE/etc/runner.token"
[ -f "$ROOT/qnx/state/runner.allow" ] && cp "$ROOT/qnx/state/runner.allow" "$STAGE/etc/runner.allow"

# 3. Build the stock QEMU image with mkqnximage, adding the staged tree.
#    VERIFY: mkqnximage option names for adding files and a startup hook in
#    SDP 8.0 (expected: --type=qemu --arch=x86_64, a local snippets/extra-dirs
#    mechanism for data files and post_start commands). Adjust here.
cd "$OUT"
mkqnximage --type=qemu --arch=x86_64 --hostname=qnxagent --ssh-ident=none --build \
  ${MKQNXIMAGE_EXTRA:-} 2>&1 | tee "$OUT/docs/mkqnximage.log"

echo "built in $OUT — next: sh image/run-qemu.sh"
