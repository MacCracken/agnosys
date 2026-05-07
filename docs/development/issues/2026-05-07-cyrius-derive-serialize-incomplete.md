# cyrius `#derive(Serialize)` doesn't ship working primitive-field codegen

**Filed:** 2026-05-07
**Reporter:** agnosys 1.1.12 (during V1.1.12 evaluation —
`#derive(Serialize)` for module status diagnostics).
**agnosys version observed:** 1.1.11
**cyrius version active:** 5.9.27
**Severity:** MEDIUM — the documented `#derive(Serialize)`
behavior (per vidya `features.cyml derive_str_fields`) doesn't
emit functional code for primitive-typed or untyped fields.
Generated `<struct>_to_json` is either empty or references
helpers that aren't in stdlib.

**Local reproducer:** [`/tmp/cyrius-derive-serialize-incomplete/`](/tmp/cyrius-derive-serialize-incomplete/)
— self-contained, ~2 KB. Contains:

```
README.md            ← full diagnostic + suggested fix shape
minimal_repro.cyr    ← runs both untyped and `: i64` cases
```

## Summary

Per vidya `features.cyml derive_str_fields`:

> `#derive(Serialize)` before a struct auto-generates
> `Name_to_json(ptr, sb)` that writes JSON into a str_builder.
>
> SEMANTICS:
>     Scalar fields (no type annotation) → bare JSON numbers: 42
>     Str fields (`: Str` annotation)   → quoted JSON strings: "alice"

In practice on cyrius 5.9.27:

| Field shape | Observed |
|---|---|
| `struct s { x; y; z; }` (untyped) | `s_to_json(...)` is emitted but body is empty — appends 0 bytes to the str_builder; `[]` between bracketing markers |
| `struct s { x: i64; y: i64; z: i64; }` (typed) | `s_to_json(...)` body calls `i64_to_json_sb(sb, n)` — helper not in stdlib, build warns `undefined function 'i64_to_json_sb'`, binary SIGILLs |

Neither path produces a working serializer.

## Reproduction

```sh
cd /tmp/cyrius-derive-serialize-incomplete

# Untyped fields — empty body, prints "[]\n0"
cyrius build minimal_repro.cyr minimal_repro && ./minimal_repro
# → []
# → 0

# With : i64 — undefined-fn warning then runtime SIGILL
sed -i 's/{ x; y; z; }/{ x: i64; y: i64; z: i64; }/' minimal_repro.cyr
cyrius build minimal_repro.cyr minimal_repro
# → warning: undefined function 'i64_to_json_sb'
# → error: undefined function 'i64_to_json_sb' (will crash at runtime)
./minimal_repro
# → exit 132 (SIGILL)
```

## Root cause (best guess)

The generated `to_json` body needs primitive-type helpers
(`i64_to_json_sb(sb, n)`, `Str_to_json_sb(sb, s)`, etc.) to do
the actual JSON emission. None of these helpers ship in
cyrius 5.9.27 stdlib. The only `_to_json` fns in `~/.cyrius/lib`
are in `lib/sigil.cyr` (domain-specific revocation-list
serializers, hand-rolled) and `lib/yukti.cyr` (a hand-rolled
`device_info_to_json`); none for primitive types.

For untyped fields, the codegen path apparently doesn't fall
back to inline emission (per the doc's "scalar fields → bare
JSON numbers"); it just emits a no-op body.

## What's needed upstream

1. Ship primitive-type Serialize helpers in stdlib:
   - `i64_to_json_sb(sb, n)` — emits `42`
   - `i32_to_json_sb` / `i16_to_json_sb` / `i8_to_json_sb`
   - `Str_to_json_sb(sb, s)` — emits `"alice"` with JSON escaping
   - Inverse `_from_json` helpers for the deserializer side
2. For untyped fields, either emit inline integer-to-JSON code
   in the `to_json` body (per the doc's "bare JSON numbers"
   promise) OR call `i64_to_json_sb` (treating untyped as i64) —
   the latter requires (1) anyway.
3. Update `vidya features.cyml derive_str_fields` example to
   include the helper-module include line, OR have the helpers
   come in via `lib/str.cyr` automatically.

## Why this matters for agnosys

V1.1.12's scope was generating JSON serializers for module
status structs (`mac_status`, `audit_status`, `ima_status`,
`secureboot_state`, `tpm_caps`, `drm_caps`) so consumers
(kavach, sigil, argonaut) can dump agnosys state to log without
writing per-module formatters. With `#derive(Serialize)` not
emitting functional code, this slot can't deliver the
auto-generation benefit.

agnosys 1.1.12 ships as a deferral. Hand-rolling JSON
serializers is the alternative (yukti/sigil already do this
for their domain types), but that defeats the slot's
"auto-generate" intent and a future re-migration to working
`#derive(Serialize)` would just unwind the hand-rolls.

When the primitive Serialize helpers land upstream, V1.1.12
re-opens.

## References

- `/tmp/cyrius-derive-serialize-incomplete/README.md` — full reproducer
- agnosys CHANGELOG `[1.1.12]` — deferral narrative
- vidya `content/cyrius/language/features.cyml`
  `derive_str_fields` — documents the contract this issue
  reports as not honored
- cyrius `lib/sigil.cyr` line 7243 onward — domain-specific
  hand-rolled JSON serializers
- cyrius `lib/yukti.cyr` line 941 — `device_info_to_json`,
  hand-rolled
