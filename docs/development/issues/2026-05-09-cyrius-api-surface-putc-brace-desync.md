# cyrius `api-surface` scanner desyncs on `str_builder_putc(sb, 125)`

**Filed:** 2026-05-09
**Reporter:** agnosys 1.1.13 (during V1.1.12 `#derive(Serialize)`
migration — found while hand-rolling `_to_json` shims for
cstring-bearing diagnostic structs)
**cyrius version observed:** 5.10.15 (verified `cc5_aarch64 5.10.15` stamp)
**Severity:** LOW — silent, but surface check stays green so
the regression is invisible until someone manually verifies
counts. Workaround is one-line.
**Related:** none (independent of the
2026-05-08 multi-derive issue and 2026-05-07 lib-shadow issue).

## Summary

`cyrius api-surface --scope=project` silently drops every
public fn that follows a `str_builder_putc(sb, 125)` call
within the same `.cyr` file. The literal `125` is the ASCII
byte for `}` — the scanner appears to count braces without
tokenizing properly, so a numeric literal `125` is read as
a closing-brace and the scanner thinks the enclosing fn
body has ended early. Subsequent fn declarations in the
same module are never indexed.

Replacing `str_builder_putc(sb, 125)` with the semantically
identical `str_builder_add_cstr(sb, "}")` makes the missing
fns reappear.

## Reproduction

```sh
mkdir -p /tmp/repro/src && cd /tmp/repro
cat > cyrius.cyml <<'EOF'
[package]
name = "repro"
version = "0.0.1"
language = "cyrius"
cyrius = "5.10.15"

[build]
entry = "src/repro.cyr"
output = "repro"

[deps]
stdlib = ["string", "alloc", "str"]
EOF

cat > src/repro.cyr <<'EOF'
include "lib/string.cyr"
include "lib/alloc.cyr"
include "lib/str.cyr"

#derive(accessors)
struct widget_a { x; y; z; }

fn widget_a_to_json(w, sb) {
    str_builder_add_cstr(sb, "{\"x\":");
    str_builder_add_int(sb, widget_a_x(w));
    str_builder_add_cstr(sb, ",\"y\":");
    str_builder_add_int(sb, widget_a_y(w));
    str_builder_add_cstr(sb, ",\"z\":");
    str_builder_add_int(sb, widget_a_z(w));
    str_builder_putc(sb, 125);
    return 0;
}

#derive(accessors)
struct widget_b { p; q; r; s; t; }

fn widget_b_make() { return alloc(40); }

#derive(accessors)
struct widget_c { aa; bb; cc; dd; ee; ff; gg; }

fn widget_c_make() { return alloc(56); }
EOF

cyrius deps
touch empty.snapshot

# With putc(125):
cyrius api-surface --scope=project --snapshot=empty.snapshot --update
# → snapshot updated: 7 public fns
#   (only widget_a's 7 fns; widget_b's 11 + widget_c's 15 are MISSING)

# Replace and re-run:
sed -i 's|str_builder_putc(sb, 125);|str_builder_add_cstr(sb, "}");|' src/repro.cyr
cyrius api-surface --scope=project --snapshot=empty.snapshot --update
# → snapshot updated: 33 public fns
#   (all three structs' accessors + the to_json fn — full surface)
```

Expected: both forms emit 33 fns (the call shape doesn't
affect the public API surface). Observed: putc(125) drops 26
fns silently.

## Why this matters for agnosys

Surfaced during agnosys V1.1.12 (`#derive(Serialize)` for
diagnostic structs). Agnosys's stacked-derive case
(`#derive(accessors)` + `#derive(Serialize)` on one struct)
relies on cyrius v5.10.14's multi-derive fix. For cstring-
bearing structs that don't yet have cstring `#derive(Serialize)`
support, agnosys hand-rolls `_to_json` shims that mirror the
eventual codegen shape. Idiomatic shape ends with
`str_builder_putc(sb, 125)` to emit the closing `}`.

When all 5 hand-rolled shims used putc(125), the api-surface
gate read 657 public fns (vs the expected ~730). The
audit-stage `--update` ran clean, but `git diff
docs/development/api-surface-1.0.snapshot` showed 73 fns
removed and 9 added — a false BREAKING signal, with the
real source of the drop being downstream-of-putc fns going
invisible to the scanner.

Workaround already applied in agnosys's tree: every
hand-rolled `_to_json` closes with
`str_builder_add_cstr(sb, "}")` instead. Five sites total
across `mac.cyr`, `dmverity.cyr`, `update.cyr`, `certpin.cyr`,
`drm.cyr`. Tests still pass and the JSON output is
byte-identical.

## Suspected root cause

`cyrius api-surface` walks each `.cyr` file with a
lightweight tokenizer to find `fn`/`struct` declarations.
The scanner appears to count `{` (123) and `}` (125) bytes
to bound function bodies, but does so on raw source text
without properly skipping over numeric literal contexts.
A literal `125` in source — where `12` is the previous
2-digit number and `5` is a continuation — gets misread as
a `}` byte at the right offset, and the scanner concludes
the function body has ended. Whatever follows is then
parsed as if it were at the top level, but the parser's
state is wrong, and subsequent `fn`/`struct` lines aren't
recognized.

This is consistent with two observed properties:

1. The bug only fires if the literal `125` appears INSIDE a
   function body. Top-level `var x = 125;` doesn't
   reproduce (untested but predicted).
2. Replacing `125` with the equivalent `0x7d` may also fix
   the issue (untested but predicted — the byte value is
   the same but the source-text shape differs).

## Suggested cyrius-side fix

1. **Tokenize numeric literals before brace counting.** A
   proper lexer pass that recognizes integer literals
   (`125`, `0x7d`, `0b01111101` all the same value) would
   skip them when matching brace pairs.
2. **Skip-string-literals** also worth verifying — strings
   like `"125"` shouldn't affect brace counting either,
   though that's a separate possible bug class.
3. **Diagnose silent drops.** When the scanner exits a
   module with a non-zero brace depth (i.e., ended inside a
   function it thought ended early), emit a warning with
   the fn name and line number so users notice.

## Suggested doc update

Until the scanner is fixed, document the workaround in
`vidya/content/cyrius/language/features.cyml` `serialize`
or a new `derive_str_fields` companion entry: "When
hand-rolling JSON serializers, prefer
`str_builder_add_cstr(sb, "}")` over
`str_builder_putc(sb, 125)` to avoid an api-surface scanner
false-positive (see issue
2026-05-09-cyrius-api-surface-putc-brace-desync)."

## Reproduction artifact

Saved at `/tmp/cyrius-api-surface-putc-brace/` — drop the
two files in place, run the two `cyrius api-surface`
invocations, observe 7 vs 33 fn count.

## References

- agnosys hand-roll workaround: 5 sites across
  `src/{mac,dmverity,update,certpin,drm}.cyr` (1.1.13 commit)
- agnosys CHANGELOG `[1.1.13]` — Workaround narrative
