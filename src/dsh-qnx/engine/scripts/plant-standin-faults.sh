#!/bin/sh
# Plant known faults on the stand-in target so the checks have something real
# to find and the verification loop has true claims to confirm. Every fault is
# a real change to the target, not a mocked result.
#   plant:  sh scripts/plant-standin-faults.sh
#   clear:  sh scripts/plant-standin-faults.sh --clear
DEMO=/opt/qnx-agent-demo
if [ "$1" = "--clear" ]; then
  [ -f $DEMO/pids ] && kill -9 $(cat $DEMO/pids) 2>/dev/null
  pkill -9 -x telemetryd 2>/dev/null
  pkill -9 -x qconn 2>/dev/null
  i=0; while pgrep -x telemetryd >/dev/null || pgrep -x qconn >/dev/null || (command -v ss >/dev/null && ss -ltn | grep -q ':4444 '); do i=$((i+1)); [ $i -gt 50 ] && break; sleep 0.1; done
  rm -rf $DEMO /etc/qnx-agent-demo.conf
  [ -f /usr/local/lib/qnx-agent-image/navd ] && printf 'navd 1.4.2 build 2026-11-20\n' > /usr/local/lib/qnx-agent-image/navd
  echo "faults cleared"; exit 0
fi
mkdir -p $DEMO/bin
: > $DEMO/pids
# 1. rogue listener on every interface (undeclared service)
python3 -c "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',4444));s.listen();time.sleep(86400)" &
echo $! >> $DEMO/pids
# 2. rogue process with its own name (undeclared process)
cp /bin/sleep $DEMO/bin/telemetryd && ($DEMO/bin/telemetryd 86400 &) && sleep 0.2 && pgrep -n telemetryd >> $DEMO/pids
# 3. world-writable config in /etc (writable path in a system location)
echo "debug=1" > /etc/qnx-agent-demo.conf && chmod 666 /etc/qnx-agent-demo.conf
# 4. a stand-in imitation of QNX's qconn target agent: a process named qconn and a listener on its port, 8000.
#    (On real QNX the qnx-hardening check finds the real qconn; this only shows the check firing on the stand-in.)
cp /bin/sleep $DEMO/bin/qconn && ($DEMO/bin/qconn 86400 &) && sleep 0.2 && pgrep -n -x qconn >> $DEMO/pids
python3 -c "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',8000));s.listen();time.sleep(86400)" &
echo $! >> $DEMO/pids
# 5. tamper with a pinned image component (component drift)
printf 'navd 1.4.2 build 2026-11-20\n# patched in the field\n' > /usr/local/lib/qnx-agent-image/navd
echo "planted: listener 0.0.0.0:4444, process telemetryd, /etc/qnx-agent-demo.conf mode 666, qconn imitation on 8000, navd component drift"
