#!/usr/bin/env bash
#
# Run the package's fuzz targets.
#
# A plain `go test` run only replays each target's seed corpus; actually fuzzing
# requires naming one target at a time, which is what this script loops over.
#
# Targets are discovered from the source rather than listed here, so adding a new
# FuzzXxx function is enough to get it fuzzed both locally and in CI.
#
# Usage:
#   scripts/fuzz.sh                      # every target, 30s each
#   scripts/fuzz.sh FuzzUnmarshalBinary  # just this one
#   FUZZTIME=5m scripts/fuzz.sh          # longer budget per target
#
# Environment:
#   FUZZTIME  per-target budget, in `go test -fuzztime` form (default 30s)
#   PKG       package to fuzz (default ./...)
#
# Exits non-zero on the first target that fails. Go writes the offending input to
# testdata/fuzz/<Target>/; commit that file to turn it into a regression test.

set -euo pipefail

cd "$(dirname "$0")/.."

FUZZTIME="${FUZZTIME:-30s}"
PKG="${PKG:-./...}"

case "${1:-}" in
-h | --help)
	sed -n '3,22p' "$0" | sed 's|^#\s\?||'
	exit 0
	;;
esac

targets=()
if [ "$#" -gt 0 ]; then
	targets=("$@")
else
	# `go test -list` prints one name per line plus a trailing "ok <pkg>" summary.
	# Read with a plain loop rather than mapfile, which macOS's bash 3.2 lacks.
	while IFS= read -r name; do
		targets+=("$name")
	done < <(go test -list='Fuzz.*' "$PKG" | grep '^Fuzz' | sort -u)
fi

if [ "${#targets[@]}" -eq 0 ]; then
	echo "no fuzz targets found in $PKG" >&2
	exit 1
fi

echo "fuzzing ${#targets[@]} target(s) for $FUZZTIME each"

failed=()
for target in "${targets[@]}"; do
	echo
	echo "=== $target ==="
	# -run='^$' skips the ordinary tests so the whole budget goes to fuzzing.
	if ! go test -run='^$' -fuzz="^${target}$" -fuzztime="$FUZZTIME" "$PKG"; then
		failed+=("$target")
	fi
done

echo
if [ "${#failed[@]}" -ne 0 ]; then
	echo "FAILED: ${failed[*]}"
	echo "Failing inputs, if any, were written under testdata/fuzz/"
	exit 1
fi

echo "all ${#targets[@]} target(s) passed"
