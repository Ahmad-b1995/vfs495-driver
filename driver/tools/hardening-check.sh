#!/bin/bash
# Build the driver with AddressSanitizer and UndefinedBehaviorSanitizer and run the regression
# tests, including the replay of the fuzz corpus (driver/fuzz/README).
#   driver/tools/hardening-check.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
B="$ROOT/build/sanitize"
[ -d "$B" ] || meson setup "$B" "$ROOT/driver" -Db_sanitize=address,undefined -Db_lundef=false \
	-Dbuildtype=debugoptimized >/dev/null
ninja -C "$B" >/dev/null
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	meson test -C "$B" --print-errorlogs
