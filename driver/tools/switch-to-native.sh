#!/bin/bash
# Replace vfs495-fprint (HP's tool behind a virtual reader) with the native libfprint driver.
#
#   sudo driver/tools/switch-to-native.sh
#
# Keeps /var/lib/vfs495-fprint (HP's binary, used by the research scripts) and the prints
# enrolled with the old setup (they belong to the virtual reader and come back on rollback).
# Undo with driver/tools/rollback-to-vfs495-fprint.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODULE="$ROOT/build/driver/libfprint-tod-vfs495.so"
COMMANDS="$ROOT/captures/vfs495-commands.bin"
TOD_DIR="$(pkg-config --variable=tod_driversdir libfprint-2-tod-1)"
DROPIN=/etc/systemd/system/fprintd.service.d/vfs495.conf

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -f "$MODULE" ] || { echo "missing $MODULE: build first (ninja -C build/driver)" >&2; exit 1; }
[ -f "$COMMANDS" ] || { echo "missing $COMMANDS: see driver/tools/make-commands.py" >&2; exit 1; }
[ -n "$TOD_DIR" ] || { echo "libfprint TOD support not found (libfprint-2-tod-dev)" >&2; exit 1; }

echo "1/5 installing the driver and its command data"
install -D -m 0644 "$COMMANDS" /var/lib/vfs495-driver/commands.bin
install -D -m 0644 "$MODULE" "$TOD_DIR/libfprint-tod-vfs495.so"

echo "2/5 removing vfs495-fprint (keeps HP's files in /var/lib/vfs495-fprint)"
if dpkg -s vfs495-fprint >/dev/null 2>&1; then
	apt-get remove -y vfs495-fprint
fi

echo "3/5 removing the virtual reader from fprintd"
rm -f "$DROPIN"
rmdir --ignore-fail-on-non-empty "$(dirname "$DROPIN")" 2>/dev/null || true
systemctl daemon-reload

echo "4/5 enabling Ubuntu's fingerprint login"
pam-auth-update --package --enable fprintd

echo "5/5 restarting fprintd"
systemctl restart fprintd 2>/dev/null || systemctl stop fprintd 2>/dev/null || true

echo
echo "Done. fprintd now sees:"
user="${SUDO_USER:-root}"
fprintd-list "$user" 2>&1 | sed 's/^/  /'
echo
echo "Next, as $user (not with sudo):"
echo "  fprintd-enroll -f right-index-finger"
echo "  fprintd-verify"
