#!/bin/bash
# Install or update the native VFS495 driver for fprintd.
#
#   sudo driver/tools/install-driver.sh
#
# Installs the libfprint module and its command data, and has fprintd log each match score
# (journalctl -u fprintd | grep score; see driver/tools/scores.sh). Restarts fprintd so the new
# module is loaded. Prints enrolled before an update keep working unless the update says
# otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODULE="$ROOT/build/driver/libfprint-tod-vfs495.so"
COMMANDS="$ROOT/captures/vfs495-commands.bin"
TOD_DIR="$(pkg-config --variable=tod_driversdir libfprint-2-tod-1)"
SCORES=/etc/systemd/system/fprintd.service.d/vfs495-driver.conf

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -f "$MODULE" ] || { echo "missing $MODULE: build first (ninja -C build/driver)" >&2; exit 1; }
[ -f "$COMMANDS" ] || { echo "missing $COMMANDS: see driver/tools/make-commands.py" >&2; exit 1; }
[ -n "$TOD_DIR" ] || { echo "libfprint TOD support not found (libfprint-2-tod-dev)" >&2; exit 1; }

install -D -m 0644 "$COMMANDS" /var/lib/vfs495-driver/commands.bin
install -D -m 0644 "$MODULE" "$TOD_DIR/libfprint-tod-vfs495.so"

mkdir -p "$(dirname "$SCORES")"
cat >"$SCORES" <<'EOF'
# vfs495-driver: log the matcher's scores (>= 40 is a match) and fprintd's result for every
# swipe, for driver/tools/scores.sh.
[Service]
Environment="G_MESSAGES_DEBUG=libfprint-print fprintd"
EOF
systemctl daemon-reload
systemctl restart fprintd 2>/dev/null || systemctl stop fprintd 2>/dev/null || true
echo "installed $(basename "$MODULE") and restarted fprintd"
