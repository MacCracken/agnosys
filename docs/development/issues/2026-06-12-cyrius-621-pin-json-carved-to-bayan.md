# Move to cyrius 6.2.1: the stale `json` stdlib dep was carved into bayan — blocks `cyrius deps`

**Filed:** 2026-06-12
**Severity:** HIGH — blocks the cyrius 6.2.1 pin (CI `cyrius deps` fails)
**Status:** OPEN — diagnosis below; one-line fix; NOT yet applied (filed instead of
patched after the working session went off the rails)

## Symptom (CI, on a 6.2.1 pin)

```
Run cyrius deps
  error: cannot read /home/runner/.cyrius/versions/6.2.1/lib/json.cyr
0 deps resolved, 1 errors
Error: Process completed with exit code 1.
```

## Root cause

The standalone `json` stdlib module was **carved into `bayan` at cyrius v6.1.25**
(the bayan/ganita data-format carve). cyrius 6.2.x ships **no `lib/json.cyr`**.
agnosys's `cyrius.cyml [deps] stdlib` list still names `"json"`, so resolving deps
against a 6.2.1 snapshot can't find it.

Verify:
```sh
ls ~/.cyrius/versions/6.1.23/lib/json.cyr   # present (pre-carve)
ls ~/.cyrius/versions/6.2.1/lib/json.cyr    # MISSING (carved to bayan @6.1.25)
```

## The fix: drop the stale `json` dep (agnosys does not use stdlib-json)

agnosys rolls its **own** JSON helpers — `journald_parse_json`,
`journald_json_get_str` (src/journald.cyr), `agnosys_json_emit_cstr_or_null`
(src/util.cyr), `drm_verinfo_to_json` (src/drm.cyr). It calls **no** stdlib-json
symbols and never `include`s json. So `"json"` in `[deps]` is dead weight.

Verify it's unused (all should be empty):
```sh
grep -rnE '\b(json_parse|json_get|json_value|json_obj|json_arr|json_key|json_build)\b' src/
grep -rnE 'include.*"json' src/ cyrius.cyml
```
(`str_builder_add_json_str` in src/util.cyr is from the **`str`** module, already
in `[deps]` — not the json module.)

**Change:** remove `"json"` from the `[deps] stdlib` array in `cyrius.cyml`. Keep
the pin at **6.2.1**. Then:
```sh
cyrius deps && cyrius build src/main.cyr build/agnosys && sh tests/test.sh
```
all pass. (Confirmed locally that build + tests are green on 6.2.1 once `json` is
dropped.)

If agnosys later wants real JSON parsing from the stdlib, add `"bayan"` and use the
`bayan_json_*` API — but that's additive, not required for this fix.

## Companion fix already in this release (1.4.2)

The daimon-class `update_save_state` `bc_buf[8]` → `[24]` boot-count buffer
overflow (src/update.cyr) — a toolchain-agnostic byte-buffer resize — is the actual
bug fix this cut carries. It is independent of the pin question.

## Working-tree note

`cyrius.cyml` currently has the pin set to 6.2.1 (uncommitted) but `[deps]` still
lists `"json"` — i.e. the half-done state. `git restore cyrius.cyml` to reset, then
apply the one-line `[deps]` edit above.
