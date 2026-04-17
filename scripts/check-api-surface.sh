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

SNAPSHOT="docs/development/api-surface-1.0.snapshot"
CURRENT=$(mktemp)
trap 'rm -f "$CURRENT"' EXIT

for f in src/*.cyr; do
    mod=$(basename "$f" .cyr)
    awk -v m="$mod" '
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
    ' "$f"
done | sort > "$CURRENT"

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
