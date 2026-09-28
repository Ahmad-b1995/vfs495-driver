#!/bin/bash
# Live test of command files built from HP's package (driver/recipe/build-commands.py):
#   sudo research/hpdata/live-test.sh
# Opens a session with flash signatures, then with HP's RSA signatures, then captures three
# swipes with the flash-signature file. Debug output goes to captures/recipe/debug.log.
set -uo pipefail
cd "$(dirname "$0")/../.."
T=build/driver/vfs495-tool
D=captures/recipe
export G_MESSAGES_DEBUG=all
: >"$D/debug.log"

echo "== 1/3 open with the HP-built file (signatures from the sensor's flash)"
$T capture "$D/built-flash.bin" "$D/flash" 0 2>>"$D/debug.log"
echo "== 2/3 open with HP's RSA-signed patches instead"
$T capture "$D/built-rsa.bin" "$D/rsa" 0 2>>"$D/debug.log" || echo "   (refused; see debug.log)"
sleep 3
echo "== 3/3 three swipes with the HP-built file: swipe your right index at each prompt"
$T capture "$D/built-flash.bin" "$D/swipe" 3 60 2>>"$D/debug.log"
chown -R "${SUDO_USER:-root}" "$D"
