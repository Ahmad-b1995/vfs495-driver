#!/bin/bash
# Replay the recorded capture sessions (record.sh) through libfprint and the driver without
# the reader, as libfprint tests its drivers; each image must come out byte for byte as
# recorded. Exits 77 (skipped) without umockdev, recordings or command data.
#
#   driver/tests/umockdev/replay.sh BUILD_DIR RECORDINGS_DIR
set -uo pipefail
B="$1"
REC="$2"
HERE="$(cd "$(dirname "$0")" && pwd)"
COMMANDS="${VFS495_COMMANDS:-/usr/lib/vfs495-driver/commands.bin}"

command -v umockdev-run >/dev/null || { echo "skip: umockdev is not installed"; exit 77; }
[ -f "$COMMANDS" ] || { echo "skip: no command data at $COMMANDS"; exit 77; }
shopt -s nullglob
runs=("$REC"/*/capture.ioctl)
[ ${#runs[@]} -gt 0 ] || { echo "skip: no recordings in $REC (record.sh)"; exit 77; }

status=0
for ioctl in "${runs[@]}"; do
	dir="$(dirname "$ioctl")"
	node="$(sed -n 's/^N: //p' "$dir/device" | head -n1)"
	out="$(mktemp --suffix=.pgm)"
	FP_DEVICE_EMULATION=1 FP_TOD_DRIVERS_DIR="$B" FP_DRIVERS_ALLOWLIST=vfs495 VFS495_COMMANDS="$COMMANDS" \
		G_MESSAGES_DEBUG=all umockdev-run -d "$dir/device" -i "/dev/$node=$ioctl" -- \
		python3 "$HERE/capture.py" "$out" >"$out.log" 2>&1
	if cmp -s "$out" "$dir/capture.pgm"; then
		echo "ok   $(basename "$dir")"
	else
		echo "FAIL $(basename "$dir") (log: $out.log)"
		tail -n 20 "$out.log"
		status=1
	fi
	rm -f "$out"
done
exit $status
