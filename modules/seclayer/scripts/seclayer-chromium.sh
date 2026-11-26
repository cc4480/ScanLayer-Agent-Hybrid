#!/bin/sh
# Starts the headless browser as an unprivileged user.
#
# The app runs as root (nmap needs raw sockets), and the browser renders pages chosen by whoever
# submits a scan, with --no-sandbox because a managed container cannot give Chromium the user
# namespaces its own sandbox needs. Run as root, an exploited renderer would own the container and
# could read the app's memory and environment. This drops to the unprivileged `nobody` user first, so
# the browser can do neither. See server/browserLaunch.ts, which points SECLAYER_CHROMIUM_PATH here.
set -eu

real="$(ls /ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell 2>/dev/null | head -n 1)"
if [ -z "$real" ]; then
  echo "seclayer-chromium: headless browser binary not found under /ms-playwright" >&2
  exit 127
fi

# Not root (a developer machine, a platform that already runs unprivileged): nothing to drop.
if [ "$(id -u)" != "0" ]; then
  exec "$real" "$@"
fi

# Playwright creates the browser profile directory as the app's user, 0700. The browser, as
# `nobody`, has to be able to write to it.
for arg in "$@"; do
  case "$arg" in
    --user-data-dir=*) chown -R 65534:65534 "${arg#--user-data-dir=}" 2>/dev/null || true ;;
  esac
done

exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs "$real" "$@"
