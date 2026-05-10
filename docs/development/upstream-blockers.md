# Upstream Blockers

> Cyrius features agnosys would adopt if they shipped clean. **Not filed as fresh upstream issues** — these are tracked here so future agents/reviewers know what's blocked and *why*, without piling on the cyrius/language team's bug tracker. Realistic timelines: weeks to months. Don't refile.

**Last reviewed:** 2026-05-09 (1.2.0 ship).
**Cyrius pin:** 5.10.19.

## Active blockers

### 1. `#derive(Serialize)` cstring-pointer field support

**Slot it would close:** V1.1.12 follow-up — the 5 hand-rolled `_to_json` shims in `mac.cyr`, `dmverity.cyr`, `update.cyr`, `certpin.cyr`, `drm.cyr` exist because cyrius's `#derive(Serialize)` only handles `Str` (16-byte fat pointer) and `i64` typed fields — not bare cstring pointers (which is what agnosys's diagnostic structs hold).

**Workaround:** per-module `_<mod>_emit_cstr_or_null` helper + manual `str_builder_add_cstr` / `str_builder_add_int` calls. Mirrors the eventual codegen shape so the unwind is mechanical when upstream lands.

**Mitigation when fixed:** delete the 5 helper fns + 5 hand-rolled `_to_json` fns + add `: cstr` (or whatever the chosen syntax is) to each struct field. ~50 lines net delete across 5 files.

**Status:** Cyrius's `#derive(Serialize)` shipped in v5.10.6 → 5.10.16 with the `Str` and primitive-int paths working. cstring-pointer path not on a published roadmap that agnosys is aware of. **Don't file** — agnosys-side hand-rolls cover the use case; the real ask is "extend the directive's type set," which is upstream's call to schedule.

---

### 2. `#ifplat <arch>` codegen regression

**Slot it would close:** V1.2.1 — cosmetic migration of `#ifdef CYRIUS_ARCH_X86` / `#ifdef CYRIUS_ARCH_AARCH64` in `src/syscall_x86_64_linux.cyr` + `src/syscall_aarch64_linux.cyr` to the modern `#ifplat x86` / `#ifplat aarch64` form (cyrius 5.4.19 sugar).

**Verified-broken on cyrius 5.10.19** (2026-05-09): migrated form fails to gate the non-matching arch's body. x86 build sees aarch64-only `AT_FDCWD` as undefined and reports duplicate fn defs from the supposedly-gated block.

**Already documented upstream:** cyrius's own `lib/syscalls.cyr` v5.4.19+ note recommends staying on `#ifdef`:

> `#ifplat` ... under certain test shapes the migrated form triggers a codegen regression not yet root-caused. Directive available for new consumers; existing `#ifdef` call sites stay on the proven path until the regression ...

**Workaround:** keep `#ifdef CYRIUS_ARCH_<UPPER>` form. Already works correctly across cyrius 5.5.x → 5.10.19 — proven across 1.0.x and the V1.1 cycle.

**Mitigation when fixed:** 2 sed invocations across `src/syscall_x86_64_linux.cyr` + `src/syscall_aarch64_linux.cyr` + a comment update in `src/syscall_arch.cyr`. ~3 file diffs.

**Status:** Cyrius team aware (it's documented in their own stdlib). **Don't file** — the agnosys-side reproducer would be a duplicate of cyrius's own internal note. Wait for cyrius's stdlib to migrate first; that's the canonical signal that the regression is fixed.

---

### 3. `#deprecated("reason / migration")` attribute adoption

**Slot it would close:** V1.2.4 — graceful deprecation channel for any post-1.0 API drift before removal.

**Status:** Unproven in agnosticos. Grepped across yukti / sigil / patra / kavach src/ trees: 0 sites use `#deprecated`. The directive may exist in cyrius but no first-party consumer has shipped it in production. Adopting it from agnosys's side would be the first real-world test, and per the "low-risk slot" memory rule we don't take that bet during a delivery cycle.

**Workaround:** plain comments + CHANGELOG `Breaking` sections handle deprecations adequately for V1.0.x → V1.1.x → V1.2.x — agnosys hasn't actually had to deprecate anything yet (every V1.1.x slot was additive). The directive becomes useful when the first real removal lands.

**Mitigation when proven:** wait for one of the other agnosticos consumers (yukti / sigil) to adopt `#deprecated` first. Once there's an in-tree precedent, agnosys can follow the same pattern.

**Status:** Don't pre-validate. Defer until either the directive is exercised by another consumer OR agnosys actually needs to deprecate something.

---

## Why this file exists (not the issues directory)

The issues directory (`docs/development/issues/`) is for **active upstream tickets** with concrete reproducers — bugs that the cyrius team needs the agnosys-side context for. Examples from past cycles: the multi-derive stacking issue, the api-surface scanner desync, the `lib/process.cyr` `O_WRONLY` blocker — all filed, all fixed within weeks, all archived.

This file is for **passive blockers** — features cyrius hasn't shipped yet (or has shipped with a known regression already documented on their side). Re-filing these from agnosys's side just adds noise to the cyrius bug tracker without contributing new context. The cyrius/language team is aware of all three; the cycle time on each is upstream's call.

When any of these unblock (cyrius ships the fix / extension), the corresponding agnosys slot reopens. The mitigation paths are pre-documented above so the unblock is mechanical.

## When to revisit

- **Whenever cyrius bumps a minor** (5.11.0, 5.12.0, etc.) — re-test each blocker against the new version. Most have one-line repro recipes.
- **Whenever another agnosticos consumer** (yukti / sigil / etc.) adopts `#deprecated` or `#ifplat` — that's the green-light signal that the regression is fixed and the directive is production-proven.
- **Whenever the agnosys-side workaround starts costing more** than waiting (e.g. the 5 hand-rolled `_to_json` shims grow to 15) — at that point, either re-bet on upstream or refactor the workaround pattern.
