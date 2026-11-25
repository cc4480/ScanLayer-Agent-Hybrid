#!/bin/sh
# [SDP] On-target startup (QNX 8.0), run from local/snippets/post_start.custom at boot.
# Binaries and config sit on the read-only /system partition; the spawn log goes to /data, which is read-write.
# Network mode requires the token; the allowlist restricts what argv[0] can be even if the gateway were bypassed;
# the spawn log is the target-side proof of what actually ran.
A=/system/qnx-agent
L=/data/qnx-agent
mkdir -p $L
# The allowlist is generated from the target's own inventory after first boot (phase0.sh copies it to /data);
# until then the image's copy allows only the inventory script. The runner re-reads the file on every request.
[ -f $L/runner.allow ] || cp $A/etc/runner.allow $L/runner.allow
$A/bin/qnx-runner --listen 7781 --token-file $A/etc/runner.token \
  --allow-file $L/runner.allow --spawn-log $L/spawn.log >$L/runner.out 2>&1 &
echo "qnx-runner started on 7781"
