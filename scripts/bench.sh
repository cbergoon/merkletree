#!/usr/bin/env bash
#
# Run the package's benchmarks, and optionally compare against a saved baseline.
#
# Benchmark numbers are noisy; a single run tells you very little. The default here
# is -count=6 so that benchstat has enough samples to say whether a difference is
# real, which is the only way to use these to answer "did my change cost anything".
#
# Usage:
#   scripts/bench.sh                          # run everything, print results
#   scripts/bench.sh -o before.txt            # save results to a file
#   scripts/bench.sh -o after.txt -b before.txt   # save, then compare to baseline
#   scripts/bench.sh Verify                   # only benchmarks matching /Verify/
#   scripts/bench.sh -s                       # smoke mode: one iteration, just checks they run
#   scripts/bench.sh -s -r                    # ...under the race detector
#
# Environment:
#   COUNT      repetitions per benchmark (default 6)
#   BENCHTIME  per-benchmark budget (default 1s)
#   PKG        package to benchmark (default ./...)

set -euo pipefail

cd "$(dirname "$0")/.."

COUNT="${COUNT:-6}"
BENCHTIME="${BENCHTIME:-1s}"
PKG="${PKG:-./...}"

out=""
baseline=""
smoke=false
race=false

while getopts ":o:b:srh" opt; do
	case "$opt" in
	o) out="$OPTARG" ;;
	b) baseline="$OPTARG" ;;
	s) smoke=true ;;
	r) race=true ;;
	h)
		sed -n '2,21p' "$0" | sed 's|^#\s\?||'
		exit 0
		;;
	\?)
		echo "unknown option -$OPTARG" >&2
		exit 1
		;;
	esac
done
shift $((OPTIND - 1))

# A bare word argument filters benchmarks by name, the same way -bench does.
pattern="${1:-.}"

if [ "$smoke" = true ]; then
	# One iteration each. This does not measure anything useful; it checks that
	# every benchmark still compiles, runs, and does not fail its assertions.
	COUNT=1
	BENCHTIME=1x
fi

args=(test -run='^$' -bench="$pattern" -benchmem -benchtime="$BENCHTIME" -count="$COUNT")

# The race detector distorts every timing it touches, so this is only useful with -s:
# it is asking whether the benchmarks race, not how fast they are. Benchmarks are the
# only place some concurrent code paths are exercised at all, and a race there is
# invisible to `go test -race` because that does not run them.
if [ "$race" = true ]; then
	args+=(-race)
fi

args+=("$PKG")

echo "go ${args[*]}"
if [ -n "$out" ]; then
	go "${args[@]}" | tee "$out"
else
	go "${args[@]}"
fi

if [ -n "$baseline" ]; then
	if [ -z "$out" ]; then
		echo "-b requires -o, so there is something to compare" >&2
		exit 1
	fi
	if ! command -v benchstat >/dev/null 2>&1; then
		echo
		echo "benchstat not installed; skipping comparison."
		echo "  go install golang.org/x/perf/cmd/benchstat@latest"
		exit 0
	fi
	echo
	echo "=== benchstat $baseline -> $out ==="
	benchstat "$baseline" "$out"
fi
