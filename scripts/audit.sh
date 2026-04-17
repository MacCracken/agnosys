#!/usr/bin/env bash
# audit.sh — local one-shot quality gate.
# Mirrors what CI runs so contributors can verify before pushing.
#
# Gates (each must pass):
#   1. Syntax check — every src/*.cyr
#   2. API surface — diff vs. api-surface-1.0.snapshot
#   3. Capacity     — cyrius capacity --check src/main.cyr (<85% all tables)
#   4. Build        — src/main.cyr → build/agnosys, verify ELF
#   5. Smoke        — ./build/agnosys prints "agnosys ready"
#   6. Tests        — cyrius test (tests/tcyr/*.tcyr)
#   7. Lint         — cyrius lint every src/*.cyr
#   8. Vet          — cyrius vet src/main.cyr (include-graph audit)
#   9. Fuzz         — every fuzz/*.fcyr, 10s timeout, must exit 0
#  10. Benchmarks   — tests/bcyr/bench_all.bcyr runs to completion
set -euo pipefail

GREEN='\033[32m'; RED='\033[31m'; DIM='\033[2m'; NC='\033[0m'
pass()  { printf "  ${GREEN}ok${NC}     %s\n" "$1"; }
fail()  { printf "  ${RED}FAIL${NC}   %s\n" "$1"; exit 1; }
stage() { printf "\n${DIM}[%s]${NC} %s\n" "$1" "$2"; }

stage 1/10 "syntax check"
for f in src/*.cyr; do
    cyrius check "$f" > /dev/null 2>&1 || fail "check: $f"
done
pass "$(ls src/*.cyr | wc -l) files"

stage 2/10 "API surface"
scripts/check-api-surface.sh | tail -1 | grep -q '^ok' || fail "api surface drift"
pass "snapshot matches"

stage 3/10 "capacity gate"
cyrius capacity --check src/main.cyr > /dev/null 2>&1 || fail "capacity >= 85%"
pass "all tables under 85%"

stage 4/10 "build"
mkdir -p build
cyrius build src/main.cyr build/agnosys > /dev/null 2>&1 || fail "build"
xxd -l 4 build/agnosys | grep -q "7f45 4c46" || fail "ELF magic"
pass "build/agnosys ($(wc -c < build/agnosys) bytes)"

stage 5/10 "smoke"
./build/agnosys 2>&1 | grep -q "agnosys ready" || fail "smoke"
pass "agnosys ready"

stage 6/10 "tests"
cyrius test > /tmp/audit_test.log 2>&1 || { cat /tmp/audit_test.log; fail "tests"; }
grep -q "^[0-9]* passed, 0 failed" /tmp/audit_test.log || fail "test count"
pass "$(grep -oE '^[0-9]+ passed' /tmp/audit_test.log | head -1)"

stage 7/10 "lint"
for f in src/*.cyr; do
    cyrius lint "$f" > /dev/null 2>&1 || fail "lint: $f"
done
pass "0 warnings"

stage 8/10 "vet"
cyrius vet src/main.cyr > /tmp/audit_vet.log 2>&1 || { cat /tmp/audit_vet.log; fail "vet"; }
grep -q "0 untrusted, 0 missing" /tmp/audit_vet.log || fail "vet flagged deps"
pass "$(tail -1 /tmp/audit_vet.log)"

stage 9/10 "fuzz"
if ls fuzz/*.fcyr > /dev/null 2>&1; then
    for f in fuzz/*.fcyr; do
        name=$(basename "$f" .fcyr)
        cyrius build "$f" "build/$name" > /dev/null 2>&1 || fail "fuzz build: $name"
        timeout 10 "build/$name" 500 > /dev/null 2>&1 || fail "fuzz crash: $name"
    done
    pass "$(ls fuzz/*.fcyr | wc -l) harnesses"
else
    pass "no harnesses (skipped)"
fi

stage 10/10 "benchmarks"
cyrius build tests/bcyr/bench_all.bcyr build/bench_all > /dev/null 2>&1 || fail "bench build"
./build/bench_all > /tmp/audit_bench.log 2>&1 || fail "bench run"
grep -q "done" /tmp/audit_bench.log || fail "bench incomplete"
pass "$(grep -oE '[0-9]+ groups, [0-9]+ benchmarks' /tmp/audit_bench.log | head -1)"

rm -f /tmp/audit_test.log /tmp/audit_vet.log /tmp/audit_bench.log
printf "\n${GREEN}audit clean${NC} — all 10 gates pass\n"
