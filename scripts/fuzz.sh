#!/usr/bin/env sh
# Runs every WEWAF fuzz target for a bounded time using Go's built-in fuzzing.
# No external dependencies, no CI minutes required — meant to be run locally
# (or in a nightly job once spare CI capacity exists).
#
# Usage:
#   ./scripts/fuzz.sh [seconds-per-target]
#   WEWAF_GO=/path/to/go ./scripts/fuzz.sh 30
#
# Exits non-zero if any target finds a crash (the reproducer is written under
# the package's testdata/fuzz/ directory and becomes a permanent regression
# corpus entry).
set -u

SECONDS_PER="${1:-60}"
GO="${WEWAF_GO:-go}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

failed=""

# Fed via here-doc (NOT a pipe) so the loop runs in this shell and `failed`
# survives. Columns: <package> <FuzzTarget>.
while read -r pkg fn; do
	[ -z "$fn" ] && continue
	echo "==== $fn  (${SECONDS_PER}s) ===="
	if ! "$GO" -C "$ROOT" test -run='^$' -fuzz="^${fn}\$" -fuzztime="${SECONDS_PER}s" "$pkg"; then
		failed="$failed $fn"
	fi
done <<'EOF'
./internal/engine/ FuzzCanonicalize
./internal/engine/ FuzzCanonicalizePath
./internal/engine/ FuzzDecodePercentU
./internal/engine/ FuzzFoldHomoglyphs
./internal/engine/ FuzzHasObfuscatedTransferEncoding
./internal/dpi/ FuzzInspectGRPCBody
./internal/dpi/ FuzzReadWSFrame
./internal/proxy/ FuzzMaybeDecompressBody
./internal/audit/ FuzzChainResume
./internal/clientip/ FuzzClientIP
EOF

if [ -n "$failed" ]; then
	echo ""
	echo "FUZZ FAILURES:$failed"
	exit 1
fi
echo ""
echo "all fuzz targets passed"
