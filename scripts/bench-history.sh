#!/usr/bin/env bash
set -euo pipefail

# Run Cyrius benchmarks, append results to CSV history, and generate BENCHMARKS.md
#
# Usage:
#   ./scripts/bench-history.sh              # defaults to bench-history.csv
#   ./scripts/bench-history.sh results.csv  # custom output file

HISTORY_FILE="${1:-bench-history.csv}"
BENCHMARKS_MD="BENCHMARKS.md"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")

# Find cyrb
CYRB="${CYRB:-}"
if [ -z "$CYRB" ]; then
    if command -v cyrb >/dev/null 2>&1; then CYRB=cyrb
    elif [ -x "$HOME/.cyrius/bin/cyrb" ]; then CYRB="$HOME/.cyrius/bin/cyrb"
    elif [ -x "./build/cyrb" ]; then CYRB="./build/cyrb"
    else echo "ERROR: cyrb not found"; exit 1; fi
fi

# Create header if file doesn't exist
if [ ! -f "$HISTORY_FILE" ]; then
    echo "timestamp,commit,branch,benchmark,estimate_ns" > "$HISTORY_FILE"
fi

echo "╔══════════════════════════════════════════╗"
echo "║        agnosys benchmark suite           ║"
echo "╠══════════════════════════════════════════╣"
echo "║  commit: $COMMIT"
echo "║  branch: $BRANCH"
echo "║  date:   $TIMESTAMP"
echo "╚══════════════════════════════════════════╝"
echo ""

# Build benchmark binary
mkdir -p build
if [ -f tests/bench_compare.cyr ]; then
    BENCH_SRC=tests/bench_compare.cyr
else
    echo "No benchmark file found at tests/bench_compare.cyr"
    exit 1
fi

$CYRB build "$BENCH_SRC" build/bench 2>&1
echo ""

# Run benchmarks and capture output
BENCH_OUTPUT=$(./build/bench 2>&1)
echo "$BENCH_OUTPUT"
echo ""

# Parse output lines like: "getpid (raw): 295 ns/op (1000000 iters)"
while IFS= read -r line; do
    if [[ "$line" == *"ns/op"* ]]; then
        BENCH_NAME=$(echo "$line" | sed -E 's/:.*//' | xargs)
        NS=$(echo "$line" | sed -E 's/.*: ([0-9]+) ns\/op.*/\1/')
        echo "${TIMESTAMP},${COMMIT},${BRANCH},${BENCH_NAME},${NS}" >> "$HISTORY_FILE"
    fi
done <<< "$BENCH_OUTPUT"

COUNT=$(echo "$BENCH_OUTPUT" | grep -c "ns/op" || echo 0)

echo "════════════════════════════════════════════"
echo "  ${COUNT} benchmarks recorded"
echo "  CSV:      ${HISTORY_FILE}"
echo "  Markdown: ${BENCHMARKS_MD}"
echo "════════════════════════════════════════════"
