#!/bin/sh
# inventory-qnx.sh — on-target inventory for the QNX agent. POSIX sh + awk only.
#
# Writes catalog.json (to $1, default ./catalog.json; "-" = stdout) with:
#   meta               hostname, uname fields, QNX version, timestamp, tool count
#   tools[]            {name, path} per executable in the image's bin dirs + $PATH
#   processes[]        {pid, name, args} from pidin / ps / /proc
#   resource_managers[]{path, type, mode} for /dev (QNX resource managers live there)
#   network            interfaces, interface_ips, routes, listeners (+ raw outputs)
#
# QNX 8.0 first (pidin, io-sock's BSD netstat/ifconfig, /proc/boot); falls back
# to Linux equivalents so the same script runs on the pre-SDP stand-in target.
# Same JSON shape as the Parrot catalog where fields map.

OUT=${1:-catalog.json}
PATH=${QNX_INV_BIN:+$QNX_INV_BIN:}/proc/boot:/bin:/usr/bin:/sbin:/usr/sbin:$PATH  # QNX_INV_BIN: test fixtures only
export PATH LC_ALL=C

have() { command -v "$1" >/dev/null 2>&1; }

# JSON-escape stdin into one quoted string (handles \ " control chars, newlines).
jstr() {
  awk 'BEGIN{ORS=""; printf "\""}
       { if (NR>1) printf "\\n"
         s=$0
         gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/\t/,"\\t",s); gsub(/\r/,"\\r",s)
         gsub(/[\001-\010\013\014\016-\037\177]/," ",s)
         printf "%s", s }
       END{printf "\""}'
}
js() { printf '%s' "$1" | jstr; }

TMP=${TMPDIR:-/tmp}/inv.$$
mkdir -p "$TMP" || exit 1
trap 'rm -rf "$TMP"' EXIT INT TERM

OS=$(uname -s 2>/dev/null)
HOST=$(hostname 2>/dev/null || uname -n)
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---------------- tools ----------------
: > "$TMP/tools"
for d in /proc/boot /bin /usr/bin /sbin /usr/sbin $(printf '%s' "$PATH" | tr ':' ' '); do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] && [ -x "$f" ] || continue
    n=${f##*/}
    printf '%s\t%s\n' "$n" "$f"
  done
done | awk -F'\t' '!seen[$1]++' > "$TMP/tools"
TOOL_COUNT=$(wc -l < "$TMP/tools" | tr -d ' ')

# ---------------- processes ----------------
: > "$TMP/procs"
if [ "$OS" = "QNX" ] && have pidin; then
  # `pidin arg` prints: pid  full-argument-line (one row per process)
  pidin arg 2>/dev/null | awk 'NR>1 && $1 ~ /^[0-9]+$/ { pid=$1; $1=""; sub(/^ +/,""); a=$0; n=$1; sub(/.*\//,"",n); print pid "\t" n "\t" a }' > "$TMP/procs"
fi
if [ ! -s "$TMP/procs" ] && have ps; then
  ps -A -o pid= -o comm= -o args= 2>/dev/null | awk '{ pid=$1; n=$2; if (n ~ /^\//) sub(/.*\//,"",n); $1=""; $2=""; sub(/^ +/,""); print pid "\t" n "\t" $0 }' > "$TMP/procs"
fi
if [ ! -s "$TMP/procs" ] && [ -d /proc ]; then
  for p in /proc/[0-9]*; do
    pid=${p##*/}
    a=$(tr '\000' ' ' < "$p/cmdline" 2>/dev/null)
    n=$(cat "$p/comm" 2>/dev/null)
    [ -n "$n" ] || continue
    printf '%s\t%s\t%s\n' "$pid" "$n" "$a"
  done > "$TMP/procs"
fi

# ---------------- resource managers (/dev) ----------------
ls -la /dev 2>/dev/null | awk 'NR>1 && $NF!="." && $NF!=".." && NF>=9 {
  t=substr($1,1,1); name=$NF; if (t=="l") { name=$(NF-2) }
  print "/dev/" name "\t" t "\t" $1 }' > "$TMP/dev"

# ---------------- network ----------------
if have ifconfig; then ifconfig -a > "$TMP/ifc" 2>&1; IFC_CMD="ifconfig -a"
elif have ip; then ip -o addr > "$TMP/ifc" 2>&1; IFC_CMD="ip -o addr"
else : > "$TMP/ifc"; IFC_CMD=""; fi
if have netstat; then netstat -rn > "$TMP/routes" 2>&1; RT_CMD="netstat -rn"
elif have ip; then ip route > "$TMP/routes" 2>&1; RT_CMD="ip route"
else : > "$TMP/routes"; RT_CMD=""; fi
if have netstat; then netstat -an > "$TMP/ns" 2>&1; LS_CMD="netstat -an"
elif have ss; then ss -lntu > "$TMP/ns" 2>&1; LS_CMD="ss -lntu"
else : > "$TMP/ns"; LS_CMD=""; fi

# interface names: BSD/QNX `vtnet0: flags=...`, Linux net-tools `eth0: flags=...`, ip -o `2: eth0 inet ...`
awk '/^[A-Za-z0-9_.-]+: flags=/ { n=$1; sub(/:$/,"",n); print n }
     /^[0-9]+: [A-Za-z0-9_.@-]+ / { n=$2; sub(/@.*/,"",n); if (!s[n]++) print n }' "$TMP/ifc" | awk '!seen[$0]++' > "$TMP/ifnames"
# interface IPv4s: "inet 10.0.2.15 netmask" or "inet 10.0.2.15/24"
awk '{ for (i=1;i<NF;i++) if ($i=="inet") { a=$(i+1); sub(/\/.*/,"",a); sub(/^addr:/,"",a); print a } }' "$TMP/ifc" | awk '!seen[$0]++' > "$TMP/ips"
# listeners: BSD "tcp4 0 0 *.22 *.* LISTEN", net-tools "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN",
#            ss "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"; UDP sockets bound (no LISTEN state) also kept.
awk '
  $1 ~ /^(tcp|udp)/ {
    proto=$1; sub(/[46]$/,"",proto); fam=($1 ~ /6$/) ? "6" : "4"
    if ($0 ~ /LISTEN/) {
      if ($2 == "LISTEN") local=$5; else local=$4
    } else if (proto=="udp") {
      if ($2 == "UNCONN") local=$5; else local=$4
    } else next
    if (local ~ /:[0-9]+$/) { port=local; sub(/.*:/,"",port); addr=local; sub(/:[0-9]+$/,"",addr) }
    else { port=local; sub(/.*\./,"",port); addr=local; sub(/\.[^.]*$/,"",addr) }
    if (port !~ /^[0-9]+$/) next
    if (local ~ /\]/ || $1 ~ /6/ || addr ~ /:/) fam="6"
    print proto "\t" addr "\t" port "\t" fam
  }' "$TMP/ns" | awk '!seen[$0]++' > "$TMP/listen"

QNX_VERSION=""
[ "$OS" = "QNX" ] && QNX_VERSION=$(uname -r)

# ---------------- emit ----------------
{
  printf '{\n"schema":"qnx-agent.catalog.v1",\n"meta":{'
  printf '"hostname":%s,' "$(js "$HOST")"
  printf '"os":%s,' "$(js "$OS")"
  printf '"release":%s,' "$(js "$(uname -r)")"
  printf '"version":%s,' "$(js "$(uname -v)")"
  printf '"machine":%s,' "$(js "$(uname -m)")"
  printf '"uname":%s,' "$(js "$(uname -a)")"
  printf '"qnx_version":%s,' "$(js "$QNX_VERSION")"
  printf '"generated_at":%s,' "$(js "$TS")"
  printf '"tool_count":%s,' "$TOOL_COUNT"
  printf '"generator":"inventory-qnx.sh"},\n'

  printf '"tools":['
  awk -F'\t' 'BEGIN{first=1} { n=$1; p=$2; gsub(/\\/,"\\\\",n); gsub(/"/,"\\\"",n); gsub(/\\/,"\\\\",p); gsub(/"/,"\\\"",p)
     printf "%s\n{\"name\":\"%s\",\"path\":\"%s\"}", (first?"":","), n, p; first=0 }' "$TMP/tools"
  printf '],\n'

  printf '"processes":['
  awk -F'\t' 'BEGIN{first=1} { for(i=1;i<=3;i++){ gsub(/\\/,"\\\\",$i); gsub(/"/,"\\\"",$i); gsub(/[\001-\037]/," ",$i) }
     printf "%s\n{\"pid\":%d,\"name\":\"%s\",\"args\":\"%s\"}", (first?"":","), $1, $2, $3; first=0 }' "$TMP/procs"
  printf '],\n'

  printf '"resource_managers":['
  awk -F'\t' 'BEGIN{first=1} { gsub(/"/,"\\\"",$1); printf "%s\n{\"path\":\"%s\",\"type\":\"%s\",\"mode\":\"%s\"}", (first?"":","), $1, $2, $3; first=0 }' "$TMP/dev"
  printf '],\n'

  printf '"network":{'
  printf '"interfaces":['; awk 'BEGIN{f=1}{printf "%s\"%s\"", (f?"":","), $0; f=0}' "$TMP/ifnames"; printf '],'
  printf '"interface_ips":['; awk 'BEGIN{f=1}{printf "%s\"%s\"", (f?"":","), $0; f=0}' "$TMP/ips"; printf '],'
  printf '"listeners":['
  awk -F'\t' 'BEGIN{f=1}{printf "%s\n{\"proto\":\"%s\",\"addr\":\"%s\",\"port\":%d,\"family\":\"ipv%s\"}", (f?"":","), $1, $2, $3, $4; f=0}' "$TMP/listen"
  printf '],\n'
  printf '"commands":{"interfaces":%s,"routes":%s,"listeners":%s},' "$(js "$IFC_CMD")" "$(js "$RT_CMD")" "$(js "$LS_CMD")"
  printf '"raw":{"interfaces":%s,"routes":%s,"listeners":%s}' "$(jstr < "$TMP/ifc")" "$(jstr < "$TMP/routes")" "$(jstr < "$TMP/ns")"
  printf '}\n}\n'
} > "$TMP/out.json"
if [ "$OUT" = "-" ]; then cat "$TMP/out.json"; else cp "$TMP/out.json" "$OUT"; fi

echo "inventory: $TOOL_COUNT tools, $(wc -l < "$TMP/procs" | tr -d ' ') processes, $(wc -l < "$TMP/dev" | tr -d ' ') /dev entries, $(wc -l < "$TMP/listen" | tr -d ' ') listeners -> $OUT" >&2
exit 0
