#!/usr/bin/env bash
# audit.sh — local one-shot quality gate.
# Mirrors what CI runs so contributors can verify before pushing.
#
# Gates (each must pass):
#   1. Syntax check    — every src/*.cyr
#   2. API surface     — snapshot diff + prose-doc diff
#   3. Capability map  — diff docs/development/capability-map.md vs. src/
#   4. Capacity        — cyrius capacity --check src/main.cyr (<85% all tables)
#   5. Build           — src/main.cyr → build/agnosys, verify ELF
#   6. Smoke           — ./build/agnosys prints "agnosys ready"
#   7. Tests           — cyrius test (tests/tcyr/*.tcyr)
#   8. Lint            — cyrius lint every src/*.cyr
#   9. Vet             — cyrius vet src/main.cyr (include-graph audit)
#  10. Fuzz            — every fuzz/*.fcyr, 10s timeout, must exit 0
#  11. Benchmarks      — tests/bcyr/bench_all.bcyr runs to completion
set -euo pipefail

GREEN='\033[32m'; RED='\033[31m'; DIM='\033[2m'; NC='\033[0m'
pass()  { printf "  ${GREEN}ok${NC}     %s\n" "$1"; }
fail()  { printf "  ${RED}FAIL${NC}   %s\n" "$1"; exit 1; }
stage() { printf "\n${DIM}[%s]${NC} %s\n" "$1" "$2"; }

stage 1/11 "syntax check"
for f in src/*.cyr; do
    cyrius check "$f" > /dev/null 2>&1 || fail "check: $f"
done
pass "$(ls src/*.cyr | wc -l) files"

stage 2/11 "API surface"
scripts/check-api-surface.sh | tail -1 | grep -q '^ok' || fail "api surface drift"
scripts/gen-api-surface-prose.sh --check > /dev/null 2>&1 || fail "api-surface prose stale (run scripts/gen-api-surface-prose.sh)"
pass "snapshot + prose match"

stage 3/11 "capability map"
scripts/gen-capability-map.sh --check > /dev/null 2>&1 || fail "capability-map drift (run scripts/gen-capability-map.sh)"
pass "map matches src/"

stage 4/11 "capacity gate"
cyrius capacity --check src/main.cyr > /dev/null 2>&1 || fail "capacity >= 85%"
pass "all tables under 85%"

stage 5/11 "build"
mkdir -p build
cyrius build src/main.cyr build/agnosys > /tmp/audit_build.log 2>&1 || { cat /tmp/audit_build.log; fail "build"; }
# cyrius's match-coverage check fires as a build-time warning (5.8.22+).
# Promote it to a hard gate here so missing enum-handler additions
# can't slip through CI silently.
grep -q "non-exhaustive" /tmp/audit_build.log && {
    grep "non-exhaustive" /tmp/audit_build.log
    fail "non-exhaustive match"
}
xxd -l 4 build/agnosys | grep -q "7f45 4c46" || fail "ELF magic"
# Also cross-build for aarch64 if the toolchain is present locally.
# CI runs this same gate; catching it locally avoids "passes audit
# but breaks CI" surprises (per the 1.1.8 → 1.1.9 sub-8-byte
# struct-field-load incident; full diagnosis at
# docs/development/issues/2026-05-07-cyrius-aarch64-sub-8-byte-struct-load.md).
if command -v cycc_aarch64 >/dev/null 2>&1 || [ -x "$HOME/.cyrius/bin/cycc_aarch64" ]; then
    cyrius build --aarch64 src/main.cyr build/agnosys-aarch64 > /tmp/audit_build_aarch64.log 2>&1 \
        || { cat /tmp/audit_build_aarch64.log; fail "aarch64 build"; }
    grep -q "non-exhaustive" /tmp/audit_build_aarch64.log && {
        grep "non-exhaustive" /tmp/audit_build_aarch64.log
        fail "aarch64 non-exhaustive match"
    }
fi
pass "build/agnosys ($(wc -c < build/agnosys) bytes)"

stage 6/11 "smoke"
./build/agnosys 2>&1 | grep -q "agnosys ready" || fail "smoke"
pass "agnosys ready"

stage 7/11 "tests"
cyrius test > /tmp/audit_test.log 2>&1 || { cat /tmp/audit_test.log; fail "tests"; }
grep -q "^[0-9]* passed, 0 failed" /tmp/audit_test.log || fail "test count"
pass "$(grep -oE '^[0-9]+ passed' /tmp/audit_test.log | head -1)"

stage 8/11 "lint"
for f in src/*.cyr; do
    cyrius lint "$f" > /dev/null 2>&1 || fail "lint: $f"
done
pass "0 warnings"

stage 9/11 "vet"
# cyrius 5.7.x changed vet's output; we now rely on exit code only.
cyrius vet src/main.cyr > /dev/null 2>&1 || fail "vet"
pass "include-graph clean"

stage 10/11 "fuzz"
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

stage 11/11 "benchmarks"
cyrius build tests/bcyr/bench_all.bcyr build/bench_all > /dev/null 2>&1 || fail "bench build"
./build/bench_all > /tmp/audit_bench.log 2>&1 || fail "bench run"
grep -q "done" /tmp/audit_bench.log || fail "bench incomplete"
pass "$(grep -oE '[0-9]+ groups, [0-9]+ benchmarks' /tmp/audit_bench.log | head -1)"

rm -f /tmp/audit_test.log /tmp/audit_vet.log /tmp/audit_bench.log
printf "\n${GREEN}audit clean${NC} — all 11 gates pass\n"
