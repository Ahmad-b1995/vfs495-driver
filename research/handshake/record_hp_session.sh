#!/bin/bash
# Record one HP handshake: USB traffic (wire log) plus the secrets HP computes (gdb events).
# Runs HP's validity-sensor with MODE (default getprint, which does not wait for a finger;
# getprintwait waits up to 60 s for a swipe).
# Needs the vfs495-fprint package installed (HP binary in /var/lib/vfs495-fprint).
# Usage: ./record_hp_session.sh NAME [MODE]   ->  captures/wire.NAME.log, captures/session.NAME.jsonl
set -euo pipefail

NAME="${1:?usage: $0 NAME [getprint|getprintwait]}"
MODE="${2:-getprint}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
LIB="$ROOT/build/hplib"
HP=/var/lib/vfs495-fprint

mkdir -p "$LIB" "$ROOT/captures"
if [ ! -f "$LIB/usblog.so" ]; then
	gcc -shared -fPIC -O2 -o "$LIB/usblog.so" "$ROOT/research/tools/usblog.c" -ldl
fi
cp "$HP"/lib/*.so.0.9.8 "$LIB/"

WIRE="$ROOT/captures/wire.$NAME.log"
EVENTS="$ROOT/captures/session.$NAME.jsonl"
rm -f "$WIRE" "$EVENTS"

# HP's tool writes FingerPrint.bin/.csv (raw sensor data) into its working directory,
# so run it inside the git-ignored captures folder.
cd "$ROOT/captures"

# gdb asserts while tearing down after the program exits; the recordings are complete by then.
( HS_OUT="$EVENTS" timeout 90 gdb -q -batch \
	-ex "set environment VFSLOG=$WIRE" \
	-ex "set environment LD_PRELOAD=$LIB/usblog.so" \
	-ex "set environment LD_LIBRARY_PATH=$LIB" \
	-ex "set args $MODE -doinit" \
	-x "$HERE/dump_session.py" "$HP/validity-sensor-unlocked" >"$ROOT/build/gdb.$NAME.out" 2>&1 ) 2>/dev/null || true

echo "wire:   $WIRE ($(wc -l <"$WIRE") lines)"
echo "events: $EVENTS ($(wc -l <"$EVENTS") events)"
