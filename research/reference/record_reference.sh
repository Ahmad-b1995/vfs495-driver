#!/bin/bash
# Record N HP reference swipes. Each one saves the USB traffic, the session secrets, and HP's
# own assembled image, so the raw scan lines and HP's result exist for the same swipe.
# Usage: ./record_reference.sh NAME [N]
#   -> captures/ref/NAME.K.{wire.log,session.jsonl,asm.*}
set -euo pipefail

NAME="${1:?usage: $0 NAME [N]}"
N="${2:-1}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
LIB="$ROOT/build/hplib"
HP=/var/lib/vfs495-fprint
OUT="$ROOT/captures/ref"

mkdir -p "$LIB" "$OUT"
if [ ! -f "$LIB/usblog.so" ]; then
	gcc -shared -fPIC -O2 -o "$LIB/usblog.so" "$ROOT/research/tools/usblog.c" -ldl
fi
cp "$HP"/lib/*.so.0.9.8 "$LIB/"

# HP's tool writes FingerPrint.bin/.csv into its working directory.
cd "$OUT"
for K in $(seq 1 "$N"); do
	BASE="$OUT/$NAME.$K"
	rm -f "$BASE".wire.log "$BASE".session.jsonl "$BASE".asm.*
	echo "[$K/$N] starting HP's tool: swipe about 3 seconds from now"
	# gdb asserts while tearing down after the program exits; the recordings are complete by then.
	# The subshell keeps bash's "Aborted (core dumped)" notice out of the terminal.
	( HS_OUT="$BASE.session.jsonl" REF_ASM_OUT="$BASE.asm" timeout 90 gdb -q -batch \
		-ex "set environment VFSLOG=$BASE.wire.log" \
		-ex "set environment LD_PRELOAD=$LIB/usblog.so" \
		-ex "set environment LD_LIBRARY_PATH=$LIB" \
		-ex "set args getprintwait -doinit" \
		-x "$HERE/dump_reference.py" "$HP/validity-sensor-unlocked" >"$ROOT/build/gdb.ref.$NAME.$K.out" 2>&1 ) 2>/dev/null || true
	ASM=$(ls "$BASE".asm.* 2>/dev/null | wc -l)
	echo "[$K/$N] recorded: $(wc -l <"$BASE.wire.log") transfers, $ASM assembled image(s)"
	sleep 3
done
