#!/bin/sh
# [SDP] On-target startup (QNX 8.0). Run from the image's post-start hook.
# Starts the runner on the port QEMU forwards to the host. Network mode
# requires the token; the allowlist restricts what argv[0] can be even if the
# gateway were bypassed; the spawn log is the target-side proof of what ran.
A=/opt/qnx-agent
mkdir -p /tmp/qnx-agent
$A/bin/qnx-runner --listen 7781 --token-file $A/etc/runner.token \
  --allow-file $A/etc/runner.allow --spawn-log /tmp/qnx-agent/spawn.log &
slog2info >/dev/null 2>&1 # touch: fails loudly in Phase 0 if slog2 is absent
echo "qnx-runner started on 7781"
