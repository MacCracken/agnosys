# cyrius PP_DERIVE doesn't honor stacked `#derive(...)` directives

**Filed:** 2026-05-08
**Reporter:** agnosys 1.1.12 (during V1.1.12 reopen attempt
after the 2026-05-07 ./lib/ shadow issue resolved)
**cyrius version observed:** 5.10.9 (verified `cc5_aarch64 5.10.9` stamp)
**cyrius version with fix:** 5.10.14 — stacked-line form fixed; agnosys can bump pin and reopen V1.1.12. Multi-arg `#derive(A, B)` form held forward.
**Severity:** MEDIUM — re-blocks agnosys's V1.1.12 slot.
**Related:** [`2026-05-07-cyrius-derive-serialize-incomplete.md`](2026-05-07-cyrius-derive-serialize-incomplete.md) (now resolved; this is the fresh follow-on blocker)

## 2026-05-08 — fixed at cyrius v5.10.14 (stacked-line form)

Root cause: `PP_PARSE_STRUCT_DEF` in `src/frontend/lex_pp.cyr`
had a `#`-skip loop that consumed any `#`-prefixed line
between the entry-point directive and the struct
definition. Only the first directive's codegen ran;
subsequent stacked directives were silently dropped (no
diagnostic emitted, fn family absent at runtime).

Fix landed at v5.10.14:
1. The `#`-skip loop now checks each skipped line via
   `ISDERIVE` / `ISDERIVE_DE` / `ISDERIVE_ACC` predicates
   and sets bits in a flag word at `S+0x197F08`
   (bit 0 Serialize, bit 1 Deserialize, bit 2 accessors).
2. Body emit factored: `PP_DERIVE_SERIALIZE_BODY` +
   `PP_DERIVE_ACCESSORS_BODY` operate on already-parsed
   metadata (no struct re-parse / re-emit).
3. Entry-point handlers (`PP_DERIVE_SERIALIZE` /
   `PP_DERIVE_ACCESSORS`) check the flag word after
   their own body emit and call the OTHER directive's
   `_BODY` helper if its bit is set.

Both stacked orderings (accessors-first AND
Serialize-first) emit the union of fns. The agent's
verbatim repro:

```cyr
#derive(accessors)
#derive(Serialize)
struct probe { x; y; z; }

fn main() {
    var p = alloc(24);
    probe_set_x(p, 1); probe_set_y(p, 42); probe_set_z(p, 7);
    var sb = str_builder_new();
    probe_to_json(p, sb);
    println(str_builder_build(sb));
    return 0;
}

var exit_code = main();
syscall(60, exit_code);
```

Pre-fix at v5.10.9: `warning: undefined function
'probe_to_json'`, SIGILL exit 132.

Post-fix at v5.10.14: `{"x":1,"y":42,"z":7}`, exit 0.
Both orderings verified on cyrius's dev box.

**Multi-arg form** (`#derive(accessors, Serialize)`)
held forward — currently both `ISDERIVE` and
`ISDERIVE_ACC` predicates match exact strings (e.g.
`#derive(accessors)\n` literal), so the multi-arg form
matches NEITHER and emits no codegen. Multi-arg
parsing is a separate fix tracked at cyrius's
`docs/development/roadmap.md` v5.10.x held-arc.

**Diagnostic on dropped/unknown directives** also held
forward — adding a `warning: unknown #derive(X)
directive` requires a known-directive table to
distinguish from random `#`-prefixed comment-like
lines (which are valid in macro contexts).

**Re-verification path**: bump agnosys's cyrius pin to
v5.10.14 (or later); re-run the V1.1.12 migration. The
stacked-line form is sufficient for agnosys's stated
scope (`#derive(accessors)` + `#derive(Serialize)` on
the same diagnostic struct).

## Summary

Stacking two `#derive(...)` directives on the same struct
only honors **one of them** (apparently the first that
matches a known directive type). The second directive is
silently dropped — no warning, no diagnostic. Codegen for
the dropped directive doesn't fire, the named functions are
absent, and consumer code that calls them gets
`warning: undefined function ... (will crash at runtime)`
followed by SIGILL/garbage at runtime.

Reproduces inline with all four orderings:

```cyrius
include "lib/syscalls.cyr"
include "lib/string.cyr"
include "lib/str.cyr"
include "lib/alloc.cyr"
include "lib/fmt.cyr"
include "lib/fnptr.cyr"
include "lib/vec.cyr"
include "lib/json.cyr"

#derive(accessors)
#derive(Serialize)
struct probe { x; y; z; }

fn main() {
    var p = alloc(24);
    probe_set_x(p, 1);            # accessors fire
    probe_set_y(p, 42);
    probe_set_z(p, 7);
    var sb = str_builder_new();
    probe_to_json(p, sb);         # Serialize doesn't — undefined
    println(str_builder_build(sb));
    return 0;
}

var exit_code = main();
syscall(60, exit_code);
```

| Form tried | accessors | Serialize | Outcome |
|---|---|---|---|
| `#derive(accessors)`<br>`#derive(Serialize)` | ✓ fires | ✗ undefined | `probe_to_json undefined`, SIGILL exit 132 |
| `#derive(Serialize)`<br>`#derive(accessors)` | ✗ undefined | ✓ fires | `probe_set_x undefined`, SIGILL exit 132 |
| `#derive(accessors, Serialize)` | ✗ undefined | ✗ undefined | both undefined, SIGILL exit 132 |
| `#derive(Serialize, accessors)` | ✗ undefined | ✗ undefined | both undefined, SIGILL exit 132 |

Singleton directives both work fine (`#derive(accessors)`
alone generates the setters/getters; `#derive(Serialize)`
alone generates `_to_json`/`_from_json`). The bug is
specifically in the multi-directive case.

## Why this matters for agnosys

agnosys V1.1.0 migrated all 37 of its struct-bearing
modules to `#derive(accessors)` (kavach/sigil/etc. consumers
get the V1.1.0 accessor API). V1.1.12's intended scope was
to layer `#derive(Serialize)` on top of those structs to
auto-generate `*_to_json` for the diagnostic-status
subset (audit_status, ima_status, dmverity_status,
update_state, mac_profile, certpin_info, drm_verinfo).

Without multi-derive support, agnosys cannot use
`#derive(Serialize)` on any struct that already has
`#derive(accessors)` — which is every diagnostic struct.
The slot is hard-blocked.

## Workarounds (cost-prohibitive)

1. **Parallel-struct pattern** — declare two structs per
   diagnostic (one with accessors, one with Serialize),
   write a thin adapter `to_json` that copies fields via
   accessors into a transient dump struct. Doubles struct
   declarations (7 → 14) and adds 7 hand-written
   adapters. API surface bloats (each derive emits
   public `_to_json` / `_from_json` / `_from_json_str`,
   so 7 dump structs = +21 public fns just for serializers).
2. **Hand-roll `_to_json`** — drop `#derive(Serialize)`
   entirely, write per-struct serializers using
   `lib/json.cyr` `str_builder_add_json_str` helpers.
   Defeats the slot's auto-generation intent; future
   re-migration to working `#derive(Serialize)` would
   unwind the hand-rolls.

Neither is a drop-in. agnosys 1.1.12 ships as a deferral
again pending upstream multi-directive support.

## What's needed upstream

1. **Honor stacked `#derive(...)` directives** —
   PP_DERIVE should iterate all `#derive(...)` lines
   immediately preceding a struct decl, not just the
   first match. Each directive contributes its own
   codegen pass; the resulting fn set is the union of
   all derive outputs.
2. **Or support multi-arg form**:
   `#derive(accessors, Serialize)` should run both
   codegen paths. Empirically this currently runs
   neither.
3. **Diagnostic on dropped directives** — if PP_DERIVE
   ignores a directive (whether due to syntax mismatch,
   unknown name, or multi-stack issue), emit a warning
   so the consumer notices instead of getting silent
   "undefined function" later.
4. **Document the multi-derive contract** in
   `vidya/content/cyrius/language/features.cyml`
   `derive_str_fields` and `derive_accessors`. Current
   text (`PP_DERIVE handles both — same preprocessor
   codegen pattern`) suggests they're independent, not
   that they can't coexist.

## Reproduction artifact

Inline reproducer above is self-contained — copy into a
`.cyr` file, build with `cyrius build`, and observe
`warning: undefined function 'probe_to_json'` + runtime
SIGILL.

Verified on cyrius 5.10.9 (cc5_aarch64 5.10.9, cc5 5.10.9,
all binaries from `cyriusly install 5.10.9 && cyriusly use
5.10.9`). x86_64 host; doesn't matter, the bug is in the
preprocessor not the backend.

## Status

- agnosys cyrius pin held at **5.10.9** (the previous
  ./lib/ shadow issue is fully resolved; no need to roll
  back the pin).
- agnosys V1.1.12 stays deferred. Slot reopens when
  multi-`#derive` support lands upstream.
- agnosys reverted the in-progress V1.1.12 work
  (#derive(Serialize) on src/audit.cyr, [deps] stdlib
  additions of fnptr/json, integration test additions).
