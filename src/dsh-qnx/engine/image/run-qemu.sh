#!/bin/sh
# [SDP] Boot the QNX 8.0 x86_64 image in QEMU.
#
# Same devices as QNX's own sample command (QNX Everywhere "Additional QEMU specifications"):
#   -drive output/disk-qemu.vmdk,if=ide  -kernel output/ifs.bin  virtio-net-pci  virtio-rng-pci  -serial mon:stdio
# with one change: QNX's sample uses a sudo bridge (virbr0); this uses QEMU user-mode networking instead, so no
# root is needed and the host reaches the guest through forwarded ports:
#   127.0.0.1:7781 -> guest :7781   the qnx-runner (the harness's dsh-qnx bundle connects here)
#   127.0.0.1:2222 -> guest :22     ssh root (phase0.sh survey; key from --ssh-ident)
# Under WSL2, Windows reaches these through WSL's localhost forwarding. If the Windows harness cannot reach
# 127.0.0.1:7781, start this with QEMU_FWD_ADDR=0.0.0.0 (the runner still requires its token).
# KVM is used when /dev/kvm is usable; otherwise QEMU emulates (slower, still works).
# The serial console is logged to docs/phase0/ as the boot receipt. Stop with Ctrl+A then x.
#   DRY_RUN=1 sh image/run-qemu.sh   prints the command without starting QEMU
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$HERE/out}
cd "$OUT"
[ -f output/disk-qemu.vmdk ] && [ -f output/ifs.bin ] || { echo "no output/disk-qemu.vmdk + output/ifs.bin in $OUT — run image/build-image.sh first"; [ "${DRY_RUN:-}" = 1 ] || exit 1; }
ACCEL=""
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ACCEL="-enable-kvm -cpu host"; else echo "note: /dev/kvm not usable, QEMU will emulate (slower)" >&2; fi
LOG="$HERE/../docs/phase0/qemu-serial-$(date -u +%Y%m%dT%H%M%SZ).log"
mkdir -p "$(dirname "$LOG")"
set -- qemu-system-x86_64 $ACCEL -smp ${QEMU_SMP:-4} -m ${QEMU_MEM:-4G} \
  -drive file=output/disk-qemu.vmdk,if=ide,id=drv0 \
  -kernel output/ifs.bin \
  -netdev user,id=net0,hostfwd=tcp:${QEMU_FWD_ADDR:-127.0.0.1}:7781-:7781,hostfwd=tcp:${QEMU_FWD_ADDR:-127.0.0.1}:2222-:22 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:91:01:ea \
  -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0 \
  -pidfile output/qemu.pid -nographic -vga none -serial mon:stdio
if [ "${DRY_RUN:-}" = 1 ]; then echo "$@"; exit 0; fi
command -v qemu-system-x86_64 >/dev/null || { echo "qemu-system-x86_64 not installed (Ubuntu: sudo apt install qemu-system-x86)"; exit 1; }
"$@" 2>&1 | tee "$LOG"
