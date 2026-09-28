#!/bin/bash
# Does the armed sensor stream a swipe without finger-state polls?
#   sudo research/hpdata/nopoll-test.sh
# Arms without ever polling (VFS495_NO_POLL) and waits up to 45 s per swipe; pauses up to 1 s
# are kept inside one swipe (VFS495_QUIET_MS) so their lengths can be measured.
set -uo pipefail
cd "$(dirname "$0")/../.."
D=captures/nopoll
mkdir -p "$D"
G_MESSAGES_DEBUG=all VFS495_NO_POLL=1 VFS495_QUIET_MS=1000 \
	build/driver/vfs495-tool capture captures/recipe/built-flash.bin "$D/swipe" 8 45 2>"$D/debug.log"
chown -R "${SUDO_USER:-root}" "$D"
