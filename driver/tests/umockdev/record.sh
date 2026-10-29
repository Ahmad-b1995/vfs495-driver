#!/bin/bash
# Record one capture session with umockdev for the replay test (replay.sh), as libfprint
# records its drivers' tests: USB traffic of open, one swipe, close.
#
#   sudo driver/tests/umockdev/record.sh [NAME]     -> captures/umockdev/NAME/ (default "capture")
#
# Needs: sudo apt install umockdev, and the driver built in build/driver. fprintd is stopped
# while recording. The driver runs in libfprint's emulation mode (FP_DEVICE_EMULATION=1), so
# its random values (handshake, image key) repeat in the replay; the recording therefore holds
# the session keys and a readable fingerprint scan, and stays in the private captures/ folder.
# Re-record after changes to the command data or to what the driver sends.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$ROOT/driver/tests/umockdev"
B="$ROOT/build/driver"
NAME="${1:-capture}"
OUT="$ROOT/captures/umockdev/$NAME"

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
command -v umockdev-record >/dev/null || { echo "install umockdev: sudo apt install umockdev" >&2; exit 1; }
[ -f "$B/libfprint-tod-vfs495.so" ] || { echo "build the driver first: ninja -C build/driver" >&2; exit 1; }
DEV=""
for d in /sys/bus/usb/devices/*; do
	if [ "$(cat "$d/idVendor" 2>/dev/null)" = 138a ] && [ "$(cat "$d/idProduct" 2>/dev/null)" = 003f ]; then
		DEV="$(printf '/dev/bus/usb/%03d/%03d' "$(cat "$d/busnum")" "$(cat "$d/devnum")")"
	fi
done
[ -n "$DEV" ] || { echo "no VFS495 (138a:003f) on the USB bus" >&2; exit 1; }

systemctl stop fprintd
trap 'systemctl start fprintd' EXIT
# let the sensor idle into autosuspend (2 s), so the session starts from power-on state
sleep 5
rm -rf "$OUT"
install -d -m 0700 "$OUT"
umockdev-record "$DEV" >"$OUT/device"
echo "Swipe your finger once, normally, when the reader is ready (about a second)."
FP_DEVICE_EMULATION=1 FP_TOD_DRIVERS_DIR="$B" FP_DRIVERS_ALLOWLIST=vfs495 G_MESSAGES_DEBUG=all \
	umockdev-record -i "$DEV=$OUT/capture.ioctl" -- python3 "$HERE/capture.py" "$OUT/capture.pgm" \
	2>"$OUT/record.log"
grep -E "captured|swipe of" "$OUT/record.log" || true
if [ -n "${SUDO_USER:-}" ]; then
	chown -R "$SUDO_USER:" "$ROOT/captures/umockdev"
fi
echo "recorded $OUT"
