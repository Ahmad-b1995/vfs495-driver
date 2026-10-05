#!/bin/bash
# Run the four libFuzzer fuzzers in parallel (driver/fuzz/README).
#   driver/fuzz/run-fuzzers.sh [SECONDS]
# Grows captures/fuzz-work/TARGET from the seeds in captures/fuzz/TARGET; crashing inputs go to
# captures/fuzz-crashes/. Exits 1 if any fuzzer found a problem.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SECONDS_EACH="${1:-600}"
B="$ROOT/build/fuzz"
# The stitcher runs about 10x slower under libFuzzer with UBSan than with ASan alone, so it is
# fuzzed in an ASan-only build; the sanitizer build replays its corpus under UBSan as well.
BA="$ROOT/build/fuzz-asan"
W="$ROOT/captures/fuzz-work"
X="$ROOT/captures/fuzz-crashes"
[ -x "$B/fuzz-records" ] && [ -x "$BA/fuzz-assemble" ] || { echo "build the fuzzers first (driver/fuzz/README)" >&2; exit 2; }
mkdir -p "$W" "$X"
export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

for t in commands records frames assemble; do
	[ -d "$W/$t" ] || cp -r "$ROOT/captures/fuzz/$t" "$W/$t"
	max_len=16384 timeout=10 bin="$B"
	[ "$t" = assemble ] && max_len=$((400 * 264)) timeout=20 bin="$BA"
	"$bin/fuzz-$t" "$W/$t" -max_total_time="$SECONDS_EACH" -max_len=$max_len -timeout=$timeout \
		-artifact_prefix="$X/$t-" -print_final_stats=1 >"$W/$t.log" 2>&1 &
done
wait

status=0
for t in commands records frames assemble; do
	runs="$(sed -n 's/^stat::number_of_executed_units: *//p' "$W/$t.log")"
	if grep -qE "ERROR: (AddressSanitizer|LeakSanitizer|libFuzzer)|runtime error" "$W/$t.log"; then
		echo "$t: PROBLEM after ${runs:-?} runs (see $W/$t.log)"
		status=1
	else
		echo "$t: clean, ${runs:-?} runs, corpus $(ls "$W/$t" | wc -l) inputs"
	fi
done
exit $status
