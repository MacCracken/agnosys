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

# Find cyrius
CYRB="${CYRB:-}"
if [ -z "$CYRB" ]; then
    if command -v cyrius >/dev/null 2>&1; then CYRB=cyrius
    elif [ -x "$HOME/.cyrius/bin/cyrius" ]; then CYRB="$HOME/.cyrius/bin/cyrius"
    elif [ -x "./build/cyrius" ]; then CYRB="./build/cyrius"
    else echo "ERROR: cyrius not found"; exit 1; fi
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
if [ -f tests/bench_all.bcyr ]; then
    BENCH_SRC=tests/bench_all.bcyr
elif [ -f tests/bench_compare.bcyr ]; then
    BENCH_SRC=tests/bench_compare.bcyr
else
    echo "No benchmark file found"
    exit 1
fi

$CYRB build "$BENCH_SRC" build/bench 2>&1
echo ""

# Run benchmarks and capture output
BENCH_OUTPUT=$(./build/bench 2>&1)
echo "$BENCH_OUTPUT"
echo ""

# Parse output lines like: "  getpid: 307ns avg (min=303ns max=372ns) [1000000 iters]"
while IFS= read -r line; do
    if [[ "$line" == *"ns avg"* ]]; then
        BENCH_NAME=$(echo "$line" | sed -E 's/:.*//' | xargs)
        NS=$(echo "$line" | sed -E 's/.*: ([0-9]+)ns avg.*/\1/')
        echo "${TIMESTAMP},${COMMIT},${BRANCH},${BENCH_NAME},${NS}" >> "$HISTORY_FILE"
    elif [[ "$line" == *"us avg"* ]]; then
        BENCH_NAME=$(echo "$line" | sed -E 's/:.*//' | xargs)
        US=$(echo "$line" | sed -E 's/.*: ([0-9]+)us avg.*/\1/')
        NS=$((US * 1000))
        echo "${TIMESTAMP},${COMMIT},${BRANCH},${BENCH_NAME},${NS}" >> "$HISTORY_FILE"
    fi
done <<< "$BENCH_OUTPUT"

COUNT=$(echo "$BENCH_OUTPUT" | grep -c "avg" || echo 0)

echo "════════════════════════════════════════════"
echo "  ${COUNT} benchmarks recorded"
echo "  CSV:      ${HISTORY_FILE}"
echo "  Markdown: ${BENCHMARKS_MD}"
echo "════════════════════════════════════════════"
