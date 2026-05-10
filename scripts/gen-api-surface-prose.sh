#!/usr/bin/env bash
# scripts/gen-api-surface-prose.sh — regenerate docs/development/api-surface-1.0.md
# from the snapshot + src/ comment extraction.
#
# Closes D-3 deferral from the 1.1.13 internal review.
#
# Strategy: read docs/development/api-surface-1.0.snapshot (machine-readable),
# group entries by module, find each fn's definition in src/<module>.cyr, and
# extract the contiguous `# ...` comment block immediately preceding the
# `fn <name>(...)` line. Emit a markdown doc with per-module sections.
#
# Comment-extraction rule: the fn's "doc" is the consecutive `^# ...` lines
# directly above `fn <name>(<args>)`, stopping at the first blank or
# non-comment line. Block-banner separators (`# ====...`) are stripped from
# the output text. derive-emitted accessors and shim fns that have no
# preceding comment block emit "(no behavioral docs)".
#
# Usage:
#   scripts/gen-api-surface-prose.sh         # regenerate
#   scripts/gen-api-surface-prose.sh --check # exit 1 on drift (for audit gate)

set -euo pipefail

SNAPSHOT="docs/development/api-surface-1.0.snapshot"
OUT="docs/development/api-surface-1.0.md"
TMP="$(mktemp)"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

# Map module name → src file.
src_for() {
    case "$1" in
        syscall_x86_64_linux) echo "src/syscall_x86_64_linux.cyr" ;;
        syscall_aarch64_linux) echo "src/syscall_aarch64_linux.cyr" ;;
        *) echo "src/$1.cyr" ;;
    esac
}

# Extract the doc-comment block immediately above `fn <name>(`.
# Skips banner lines (# ===...), strips leading "# " from each comment line,
# joins multi-line into a single space-separated string, trims to ~100 chars.
extract_doc() {
    local src="$1"
    local fn="$2"
    [ -f "$src" ] || { echo "(source not found)"; return; }

    # Find the line number of `fn <name>(`. Use awk for robust whole-word match.
    local lineno
    lineno=$(awk -v fn="$fn" '
        $0 ~ "^fn " fn "\\(" { print NR; exit }
    ' "$src")
    [ -z "$lineno" ] && { echo "(no behavioral docs)"; return; }

    # Walk backward collecting `^# ` lines, stopping at blank / non-comment.
    awk -v lineno="$lineno" '
        NR >= lineno { exit }
        { lines[NR] = $0 }
        END {
            doc = ""
            for (i = lineno - 1; i >= 1; i--) {
                line = lines[i]
                # Stop on blank
                if (line ~ /^[[:space:]]*$/) break
                # Stop on non-comment
                if (line !~ /^#/) break
                # Skip banner separator lines (# ====... or # ----...)
                if (line ~ /^# *[=*-]{3,}/) continue
                # Strip leading "# " or "#"
                sub(/^#[[:space:]]?/, "", line)
                # Prepend (we walked backward)
                doc = (doc == "" ? line : line " " doc)
            }
            if (doc == "") doc = "(no behavioral docs)"
            print doc
        }
    ' "$src"
}

# --- header (preserved from the curated 1.0 baseline form) ---
{
cat <<'EOF'
# Agnosys 1.0 API Surface

> Frozen at **1.0.0** (2026-04-17). The 1.0 baseline (556 fns) is the stable contract: removal or signature change of any 1.0-era fn requires a 2.0 bump. Post-1.0 additions (V1.1.x → V1.2.x) are listed inline below; all are additive.
>
> **Auto-generated** from `docs/development/api-surface-1.0.snapshot` + source-comment extraction by `scripts/gen-api-surface-prose.sh`. To regenerate: `scripts/gen-api-surface-prose.sh`. The audit gate (`stage 2/11 "API surface"`) verifies the snapshot stays in sync with the source.


## Summary

EOF

total=$(grep -c '^[a-z]' "$SNAPSHOT")
modules=$(awk -F:: '{print $1}' "$SNAPSHOT" | sort -u | wc -l)

cat <<EOF
- Total public functions: **$total**
- Modules: **$modules**
- 1.0 baseline (frozen): 556 fns
- Post-1.0 additions (V1.1 + V1.2 cycles): $((total - 556)) fns
- Outliers (fns lacking module prefix): 0


## By module


EOF

# Iterate modules in snapshot order
prev_module=""
while IFS= read -r line; do
    [ -z "$line" ] && continue
    module="${line%%::*}"
    rest="${line#*::}"
    fn_with_arity="${rest}"
    fn="${fn_with_arity%/*}"
    arity="${fn_with_arity##*/}"
    src=$(src_for "$module")

    # Build args representation: just N args, since we don't have names from the snapshot.
    if [ "$arity" -eq 0 ]; then
        args="()"
    elif [ "$arity" -eq 1 ]; then
        args="(arg)"
    else
        args="("
        for ((i=1; i<=arity; i++)); do
            [ $i -gt 1 ] && args+=", "
            args+="arg$i"
        done
        args+=")"
    fi

    if [ "$module" != "$prev_module" ]; then
        [ -n "$prev_module" ] && echo ""
        echo "### \`$module\` ($src)"
        echo ""
        prev_module="$module"
    fi

    doc=$(extract_doc "$src" "$fn")
    # Truncate doc to ~100 chars to keep the table digestible.
    if [ "${#doc}" -gt 100 ]; then
        doc="${doc:0:97}..."
    fi
    echo "- \`$fn$args\` → $doc"
done < "$SNAPSHOT"

cat <<'EOF'


## Notes

- This doc replaces the hand-curated 1.0 prose snapshot from the V1.0.0 freeze. Per-fn descriptions are now extracted programmatically from each fn's leading `#` comment block; fns without behavioral comments show `(no behavioral docs)` and may be polished by hand-editing the source-side comment block (the auto-generator picks up the change on next run).
- Argument names are placeholder (`arg1`, `arg2`, ...) since the snapshot stores arity but not names. For names + types, read the source.
- The machine-checkable companion is `docs/development/api-surface-1.0.snapshot` (one `module::fn/arity` line per public fn) — that's what CI's API-surface gate diffs against.
EOF
} > "$TMP"

if [ "$CHECK" -eq 1 ]; then
    if ! diff -q "$TMP" "$OUT" > /dev/null 2>&1; then
        echo "ERROR: $OUT is stale. Run 'scripts/gen-api-surface-prose.sh' and commit." >&2
        diff "$OUT" "$TMP" | head -40
        rm -f "$TMP"
        exit 1
    fi
    rm -f "$TMP"
    echo "ok: $OUT matches snapshot+src/"
else
    mv "$TMP" "$OUT"
    echo "regenerated: $OUT ($(wc -l < "$OUT") lines)"
fi
