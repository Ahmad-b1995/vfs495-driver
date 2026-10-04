#!/bin/bash
# Where does the sensor setup time go, and which steps can the driver drop?
#   sudo research/session/speed-test.sh
# A: baseline timings  B: without the port reset  C: without the 512 KB flash read (#9)
# D: also without the second patch-reload block (#15-19)  E: arming during a swipe
set -uo pipefail
cd "$(dirname "$0")/../.."
T=build/driver/vfs495-tool
C=captures/recipe/built.bin
D=captures/speed
mkdir -p "$D"
export VFS495_TIMING=1

echo "== A: baseline (nothing to do)"
$T capture $C $D/a 0 2>/dev/null | grep -vE "^\[" 
sleep 4
echo "== B: no port reset after the sensor idled (nothing to do)"
VFS495_NO_RESET=1 $T capture $C $D/b 0 2>/dev/null | grep -E "open|ready|#9 |error"
sleep 2
echo "== C: without the 512 KB flash read: swipe your right index normally at each 'swipe now'"
VFS495_SKIP=9 $T capture $C $D/c 2 30 2>/dev/null | grep -vE "^   #"
sleep 2
echo "== D: also without the patch reload block: swipe normally at each 'swipe now'"
VFS495_SKIP=9,15,16,17,18,19 $T capture $C $D/d 2 30 2>/dev/null | grep -vE "^   #"
sleep 2
echo "== E: START SWIPING NOW, back and forth without stopping, until you see 'done'"
sleep 2
VFS495_SKIP=9 $T capture $C $D/e 1 10 2>/dev/null | grep -vE "^   #"
echo "done: you can stop swiping"
chown -R "${SUDO_USER:-root}" "$D"
