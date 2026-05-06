#!/usr/bin/env bash
# check-api-surface.sh — diff the current public API surface against the 1.0 snapshot
#
# The snapshot at docs/development/api-surface-1.0.snapshot lists every public
# `fn <name>/<arity>` across src/*.cyr (underscore-prefixed names are private
# by convention and excluded). Breaking changes fail CI; additions are fine.
#
# Usage:
#   scripts/check-api-surface.sh [--update]
#     --update   regenerate the snapshot (use only when intentionally bumping API)
set -euo pipefail

# Lock collation to C so `sort` and `comm` agree on byte order regardless of
# the user/CI locale. Mixed collations were flagging renamed-adjacent entries
# (e.g. secureboot_enroll_key vs. secureboot_enrolled_key_new) as both
# removed and added.
export LC_ALL=C

SNAPSHOT="docs/development/api-surface-1.0.snapshot"
CURRENT=$(mktemp)
trap 'rm -f "$CURRENT"' EXIT

for f in src/*.cyr; do
    mod=$(basename "$f" .cyr)
    awk -v m="$mod" '
        # 1. Hand-written public fn definitions
        /^fn [a-zA-Z]/ {
            if (match($0, /^fn ([a-zA-Z0-9_]+)\(([^)]*)\)/, arr)) {
                name = arr[1]; params = arr[2]
                if (name ~ /^_/) next
                gsub(/[ \t]/, "", params)
                arity = (params == "") ? 0 : 1
                for (i = 1; i <= length(params); i++)
                    if (substr(params, i, 1) == ",") arity++
                print m "::" name "/" arity
            }
        }
        # 2. #derive(accessors) on a struct: emit synthesized getters/setters.
        # The directive sits on its own line; the struct decl follows on the
        # next non-blank line (possibly spanning multiple lines until the
        # closing brace). Field names are tokens between `{` and `}`,
        # separated by `;` (with optional `: type` annotations stripped).
        /^[[:space:]]*#derive\(accessors\)/ {
            # Collect lines from `struct <name> {` through the closing `}`
            sname = ""
            body = ""
            getline line
            while (line !~ /\{/) { getline line }
            if (match(line, /struct[[:space:]]+([a-zA-Z0-9_]+)/, sarr)) {
                sname = sarr[1]
            }
            # Body starts after `{`
            body = line
            sub(/.*\{/, "", body)
            while (body !~ /\}/) {
                getline more
                body = body " " more
            }
            sub(/\}.*/, "", body)
            # Strip comments
            gsub(/#[^;}]*/, "", body)
            # Split on `;` and emit accessor pairs
            n = split(body, fields, ";")
            for (i = 1; i <= n; i++) {
                fld = fields[i]
                # Strip whitespace and type annotation `: <type>`
                sub(/^[[:space:]]+/, "", fld)
                sub(/[[:space:]]+$/, "", fld)
                sub(/[[:space:]]*:.*$/, "", fld)
                if (fld == "" || sname == "") continue
                if (fld !~ /^[a-zA-Z][a-zA-Z0-9_]*$/) continue
                print m "::" sname "_" fld "/1"
                print m "::" sname "_set_" fld "/2"
            }
        }
    ' "$f"
done | sort -u > "$CURRENT"

if [ "${1:-}" = "--update" ]; then
    cp "$CURRENT" "$SNAPSHOT"
    echo "snapshot updated: $(wc -l < "$SNAPSHOT") functions"
    exit 0
fi

if [ ! -f "$SNAPSHOT" ]; then
    echo "snapshot missing: $SNAPSHOT" >&2
    echo "  regenerate with: $0 --update" >&2
    exit 1
fi

REMOVED=$(comm -23 "$SNAPSHOT" "$CURRENT" || true)
ADDED=$(comm -13 "$SNAPSHOT" "$CURRENT" || true)

if [ -n "$REMOVED" ]; then
    echo "BREAKING: public fn removed or signature changed since 1.0 snapshot:"
    echo "$REMOVED" | sed 's/^/  - /'
    [ -n "$ADDED" ] && { echo "(new since snapshot:)"; echo "$ADDED" | sed 's/^/  + /'; }
    exit 1
fi

if [ -n "$ADDED" ]; then
    echo "ok: $(wc -l < "$CURRENT") public fns, $(echo "$ADDED" | wc -l) added since snapshot (non-breaking)"
else
    echo "ok: $(wc -l < "$CURRENT") public fns, surface matches snapshot exactly"
fi
