#!/usr/bin/env sh
# Runs EVERY WEWAF fuzz target for a bounded time using Go's built-in fuzzing.
# No external dependencies, no CI minutes required — meant to be run locally
# (or in a nightly job once spare CI capacity exists).
#
# Targets are AUTO-DISCOVERED (`go test -list`) so a newly-added FuzzXxx is run
# automatically — the previous hand-maintained list silently skipped most of
# them.
#
# Usage:
#   ./scripts/fuzz.sh [seconds-per-target] [name-regex]
#   WEWAF_GO=/path/to/go ./scripts/fuzz.sh 30
#   ./scripts/fuzz.sh 45 'Canonicalize|Harden'   # only matching targets
#
# Exits non-zero if any target finds a crash (the reproducer is written under
# the package's testdata/fuzz/<Target>/ directory and becomes a permanent
# regression corpus entry — commit it).
set -u

SECONDS_PER="${1:-30}"
FILTER="${2:-.}"
GO="${WEWAF_GO:-go}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

failed=""
count=0

# Discover packages, then list each package's fuzz targets. `go test -list`
# prints the matching function names one per line followed by the package
# status line; we keep only the lines that look like a fuzz target name.
for pkg in $("$GO" -C "$ROOT" list ./... 2>/dev/null); do
	names="$("$GO" -C "$ROOT" test -list '^Fuzz' "$pkg" 2>/dev/null | grep -E '^Fuzz' || true)"
	[ -z "$names" ] && continue
	for fn in $names; do
		echo "$fn" | grep -Eq "$FILTER" || continue
		count=$((count + 1))
		echo "==== $pkg :: $fn  (${SECONDS_PER}s) ===="
		if ! "$GO" -C "$ROOT" test -run='^$' -fuzz="^${fn}\$" -fuzztime="${SECONDS_PER}s" "$pkg"; then
			failed="$failed ${pkg}::${fn}"
		fi
	done
done

echo ""
echo "ran ${count} fuzz target(s)"
if [ -n "$failed" ]; then
	echo "FUZZ FAILURES:$failed"
	echo "repro(s) under each package's testdata/fuzz/<Target>/ — commit them as regression corpus."
	exit 1
fi
echo "all ${count} fuzz targets passed"
