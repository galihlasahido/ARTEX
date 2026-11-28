#!/usr/bin/env bash
# ARTEX mobile node entrypoint (Linux/KVM) — TEMPLATE.
#
# Boots the emulator, roots it with rootAVD, starts frida-server, then runs the
# node-agent which dials OUT to ARTEX core. Emulator startup differs per base
# image, so the boot section is best-effort: adjust it to your base image.
#
# Required env: ARTEX_CORE_WS, ARTEX_NODE_TOKEN. Optional: ARTEX_ADBD (default
# 127.0.0.1:5555), ARTEX_NODE_INSECURE.
set -euo pipefail

ADBD="${ARTEX_ADBD:-127.0.0.1:5555}"

log() { echo "[mobile-node] $*" >&2; }

# 1. Start the emulator. Many bases (e.g. budtmo/docker-android) auto-start it
#    via their own supervisor; if yours does not, start it here, e.g.:
#       emulator -avd "$AVD" -no-window -writable-system -no-snapshot &
#    Then wait for adbd.
log "waiting for adbd on $ADBD ..."
for _ in $(seq 1 120); do
  if adb connect "$ADBD" >/dev/null 2>&1 && adb -s "$ADBD" shell getprop sys.boot_completed 2>/dev/null | grep -q 1; then
    break
  fi
  sleep 2
done
adb -s "$ADBD" shell getprop sys.boot_completed 2>/dev/null | grep -q 1 \
  || log "WARN: emulator did not report boot_completed; continuing"

# 2. Root the AVD with rootAVD (Magisk). Skip if the base image is already
#    rooted. rootAVD patches the ramdisk and reboots; this is usually a one-time
#    host-side step rather than per-container. Documented here for completeness:
#       git clone https://github.com/galihlasahido/rootAVD /opt/rootAVD
#       (cd /opt/rootAVD && ./rootAVD.sh <ramdisk path>)
if [ -d /opt/rootAVD ] && [ "${ROOTAVD_RAMDISK:-}" != "" ]; then
  log "rooting AVD via rootAVD ($ROOTAVD_RAMDISK)"
  (cd /opt/rootAVD && ./rootAVD.sh "$ROOTAVD_RAMDISK") || log "WARN: rootAVD step failed"
fi

# 3. Start frida-server on the device (version must match the host frida-tools).
#    Push the matching frida-server binary for the device arch to the emulator
#    and launch it as root:
#       adb -s "$ADBD" push frida-server /data/local/tmp/
#       adb -s "$ADBD" shell "su 0 chmod 755 /data/local/tmp/frida-server"
#       adb -s "$ADBD" shell "su 0 /data/local/tmp/frida-server &"
if [ -x /usr/local/bin/frida-server ]; then
  log "starting frida-server on device"
  adb -s "$ADBD" push /usr/local/bin/frida-server /data/local/tmp/frida-server >/dev/null 2>&1 || true
  adb -s "$ADBD" shell "su 0 chmod 755 /data/local/tmp/frida-server" >/dev/null 2>&1 || true
  adb -s "$ADBD" shell "su 0 /data/local/tmp/frida-server &" >/dev/null 2>&1 || true
fi

# 4. Run the agent (dials OUT to core; reconnects on its own).
log "starting mobile-node-agent"
exec /usr/local/bin/mobile-node-agent -adbd "$ADBD"
