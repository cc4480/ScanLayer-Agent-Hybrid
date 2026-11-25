#!/bin/sh
# [SDP] Boot the QNX 8.0 x86_64 image in QEMU with user networking and the
# runner port forwarded to the host: host 127.0.0.1:7781 -> guest :7781.
# The serial console is logged to docs/phase0/ as the boot receipt.
#
# VERIFY at Phase 0: mkqnximage's own `--run` may already wrap QEMU; if so,
# pass the hostfwd through it instead (keep the same port mapping).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$HERE/out}
LOG="$HERE/../docs/phase0/qemu-serial-$(date -u +%Y%m%dT%H%M%SZ).log"
mkdir -p "$(dirname "$LOG")"
IMG=${IMG:-$(ls "$OUT"/output/disk-qemu.vmdk "$OUT"/output/*.img 2>/dev/null | head -1)}
[ -n "$IMG" ] || { echo "no image under $OUT/output — build first (VERIFY output name)"; exit 1; }
exec qemu-system-x86_64 -m 1G -smp 2 -nographic \
  -drive file="$IMG",if=virtio \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:7781-:7781,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=n0 \
  -serial mon:stdio 2>&1 | tee "$LOG"
