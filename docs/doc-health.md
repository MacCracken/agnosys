---
name: Agnodrm Documentation Health
description: Living state of doc currency in the agnodrm repo — fresh / stale / archived / open-question, refreshed as docs are touched
type: state
---

# Documentation Health — agnodrm

> **Last refresh**: 2026-06-19 (agnosys → agnodrm rename audit, paired with the 1.4.4 decomposition cut) | **Refresh cadence**: when docs are touched, update the affected row.
> **Scope**: This repo only (`agnodrm`, formerly `agnosys`) — root-level files (README, CHANGELOG, CLAUDE.md, etc.) plus the entire `docs/` tree. Cross-repo cyrius pin/version drift lives in [`development/state.md`](development/state.md), not here.

This is a **ledger**, not a one-time audit. Rewrite-in-place as docs change. Agnodrm is the AGNOS device / DRM model (renamed from agnosys at 1.4.4); device-access docs propagate to ai-hwaccel / mabda, so doc currency carries weight. The doc surface is moderate (~34 files) and most are load-bearing.

Pattern lifted from the agnostik ledger ([`agnostik/docs/doc-health.md`](https://github.com/MacCracken/agnostik/blob/main/docs/doc-health.md)) — same buckets, agnodrm-shaped tiers.

---

## 2026-06-19 — agnosys → agnodrm rename audit (1.4.4)

The decomposition renamed the repo + removed 15 modules. Doc disposition:
- ✅ **Active docs updated to agnodrm**: README, CLAUDE.md, CONTRIBUTING.md,
  SECURITY.md, `development/state.md` (identity + module table → 9 survivors +
  metrics), `development/roadmap.md` (identity + scope + consumer map),
  `src/util.cyr` header, the agnosticos genesis table. Generated docs
  (api-surface snapshot+prose, capability-map) regenerated (730 → 315 fns).
- 📦 **Historical docs preserved as-is** (renaming would falsify the record):
  ADRs, `audit/` reports, `development/issues/` + `archive/`, `reviews/`, and the
  pre-1.4.4 CHANGELOG / state-history / roadmap-phase entries — "agnosys" is the
  correct name-at-the-time in those.
- 🟡 **Staged** (deep refresh, not blocking): `development/roadmap.md`'s completed
  phases still list moved modules (flagged inline as pre-decomposition);
  `docs/architecture/*` + `docs/SECURITY-NOTES.md` per-module re-read against the
  trimmed src/.

---

## At a glance — 2026-05-10 inventory

**~34 markdown files** total (6 root + 28 under `docs/`). Bucket counts after the 1.2.1 doc cleanup pass:

| Bucket | Count | What it means |
|---|---|---|
| ✅ **Fresh — touched in 1.1.13 → 1.2.1 cycle** | ~24 | state, roadmap, CHANGELOG, CLAUDE, README, CONTRIBUTING, capacity-baseline (1.2.1 baseline added), architecture/overview, capability-map, api-surface (auto-gen), audit/2026-05-09-audit, audit/2026-05-09-cve-landscape, reviews/2026-05-09-internal-review, the 3 ADRs that shipped with 1.0.x, the 3 active issues, the 9 archived issues. |
| 🟡 **Stale — refresh in place** | 0 | All 3 stale rows from the initial audit closed in this same pass: `README.md` top-line block + footprint refreshed to 1.2.1; `CONTRIBUTING.md` Cyrius pin / gate count / workflow steps refreshed; `docs/development/capacity-baseline.md` regenerated with 1.2.1 measurements (core + 4 profile combos + full bundle), 1.0.0 baseline preserved as historical-comparison block. |
| 🟠 **Read-through outstanding** | 1 | `docs/SECURITY-NOTES.md` — last touched 2026-04-30. No version refs surfaced in the staleness scan, but a per-module re-read against current src/ would confirm the security considerations still match (V1.1.12/V1.1.14 added `_to_json` shims + the F-7..F-9 hardenings; some notes may be additive). |
| 🔵 **Probably evergreen** | 3 | `CODE_OF_CONDUCT.md`, `LICENSE`, `SECURITY.md`. No version-tied claims. Re-read pass annually. |
| 📦 **Archive / frozen by design** | ~5 | `docs/benchmarks-rust-vs-cyrius.md` (HEADLINER — Rust→Cyrius port comparison, point-in-time); `docs/audit/2026-04-26-audit.md` (1.0.1 P(-1) report); ADR-004 (1.1.x roadmap rework — historical decision); the issues `archive/` set (9 cyrius bugs that landed during V1.0/V1.1). |
| ❓ **Open strategic question** | 0 | None outstanding — see [Open questions](#open-strategic-questions) for the empty list and what would re-open it. |

**Doc cleanup completed 2026-05-09 → -10 across the 1.1.13 / 1.1.14 / 1.2.0 / 1.2.1 ship arc:**
- ✅ `state.md` — refreshed every release; tracks pin / VERSION / sizes / tests / consumers / verification hosts. 1.2.1 cleanup also reframed "In-Flight Slots" → "Slot Ledger" + dropped 4 stale future-plan items.
- ✅ `roadmap.md` — V1.1.x and V1.2.0 / V1.2.1 marked SHIPPED; gate count "10 → 11" updated; V1.2.3 next.
- ✅ `CLAUDE.md` — P(-1) cleanliness step gate count "10 → 11" updated.
- ✅ `architecture/overview.md` — `lib/` listing reflects gitignored-since-1.1.12 state; `dist/` listing shows all 6 bundles (full + 5 profiles) with sizes; scripts/ listing has all 6 actual scripts.
- ✅ `api-surface-1.0.md` — auto-generated since 1.2.1 (`scripts/gen-api-surface-prose.sh`); 824 lines covering all 730 fns.
- ✅ `capability-map.md` — auto-generated since 1.2.1 (`scripts/gen-capability-map.sh`); per-module + per-profile rollup.
- ✅ `reviews/2026-05-09-internal-review.md` — P(-1) step 3 artifact (frozen post-filing).
- ✅ `audit/2026-05-09-audit.md` + `audit/2026-05-09-cve-landscape.md` — P(-1) step 4-5 artifacts (frozen post-filing).
- ✅ Issues directory — 3 passive blockers filed internally (cstring `#derive(Serialize)`, `#ifplat`, `#deprecated`); all 9 prior-cycle resolved tickets archived.

---

## Tier 1 — Root files

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-05-10 | ✅ Fresh | Top-line refreshed to 1.2.1 / Cyrius 5.10.19 / 730 fns / ~10 300 lines / 153 KB binary / ~170 ms compile. Adds profile-bundle table (V1.2.0+) + the 5-bundle distlib commands. Quality-gates section now lists 11 gates + 247 assertions + 7 fuzz harnesses. Docs section adds state.md, capability-map, doc-health. |
| `CHANGELOG.md` | 2026-05-09 | ✅ Fresh | Source of truth for shipped work. Entries through 1.2.1. |
| `CLAUDE.md` | 2026-05-09 | ✅ Fresh | Durable rules. P(-1) cleanliness gate count refreshed 10 → 11. |
| `CONTRIBUTING.md` | 2026-05-10 | ✅ Fresh | Cyrius prereq refreshed to "pinned in cyrius.cyml (currently 5.10.19)"; workflow step has 11 gates + the new auto-gen scripts (`gen-api-surface-prose.sh`, `gen-capability-map.sh`); commands table includes `cyrius deps`, the 5 profile-bundle options, and `cyrius build --aarch64`; "Adding a Module" section uses `[lib] modules` (per ADR-003) + profile picker; Cyrius Conventions notes `#derive(accessors)` adopted (V1.1.0) and points at the ifplat issue ticket. |
| `SECURITY.md` | 2026-04-30 | 🔵 Evergreen | Reporting policy + scope. No version-tied claims; re-read annually. |
| `CODE_OF_CONDUCT.md` | 2026-04-30 | 🔵 Evergreen | Standard. |
| `VERSION` | 2026-05-09 | ✅ Fresh | `1.2.1` — single source of truth, read into `cyrius.cyml` via `${file:VERSION}`. |
| `LICENSE` | (initial commit) | 🔵 Evergreen | GPL-3.0-only. |

---

## Tier 2 — Project state (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `state.md` | 2026-05-09 | ✅ Fresh | Live volatile state — VERSION cell, cyrius pin, build sizes, test count, consumer table, recent releases, slot ledger. Refreshed every release. 1.2.1 cleanup also reframed slot section. |
| `roadmap.md` | 2026-05-09 | ✅ Fresh | V1.1.x + V1.2.0/V1.2.1 marked SHIPPED. V1.2.3 (consumer integration CI) is the next concrete slot. V1.2.1 / V1.2.4 deferred to issue tickets. |
| `api-surface-1.0.md` | 2026-05-09 | ✅ Fresh — auto-gen | 1.0 baseline framing + auto-generated per-fn prose for all 730 current fns (was V1.0-era 556-fn curated snapshot). Regen via `scripts/gen-api-surface-prose.sh`. Audit gate 2 verifies staleness. |
| `api-surface-1.0.snapshot` | 2026-05-09 | ✅ Fresh | Machine-checkable companion (one `module::fn/arity` line per public fn). Audit gate 2 diffs against this. |
| `capability-map.md` | 2026-05-09 | ✅ Fresh — auto-gen | Per-module kernel-surface map (syscalls, sys_* wrappers, exec paths, fs paths) + per-profile rollup matching the V1.2.0 dist bundles. Regen via `scripts/gen-capability-map.sh`. Audit gate 3 verifies staleness. |
| `capacity-baseline.md` | 2026-05-10 | ✅ Fresh | Re-captured at 1.2.1 baseline. New rows: `dist/agnosys-core.cyr` standalone + 4 core+profile combos (security/storage/trust/system) + full bundle. 1.0.0 baseline preserved as historical-comparison block. Highest util at 1.2.1: full bundle 35% code_size, 30% fn_table — well under the 85% gate. |

---

## Tier 3 — Architecture (`docs/architecture/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `overview.md` | 2026-05-09 | ✅ Fresh | Module map + include model + data flow. Refreshed in 1.2.1 cleanup: `lib/` reflects gitignored state, `dist/` lists all 6 bundles, scripts/ has all 6 scripts, include-model section explains profile bundles. |

---

## Tier 4 — ADRs (`docs/adr/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `001-argv-exec-for-kernel-boundary-subprocesses.md` | 2026-04-30 | ✅ Fresh | Accepted (1.0.1). Argv-only exec policy. Verified 0 `sys_system` sites in src/ at every release; the rule holds. |
| `002-luks-cipher-allowlist.md` | 2026-04-30 | ✅ Fresh | Accepted (1.0.1). Cipher allowlist + null-substring rejection. Wired into `luks_config_validate`. |
| `003-lib-modules-manifest-refactor.md` | 2026-04-30 | ✅ Fresh | Accepted (1.0.1). `[lib].modules` not `[build].modules`. V1.2.0 extended this to `[lib.<profile>]`; the original ADR's reasoning carries forward. |
| `004-1-1-x-roadmap-rework.md` | 2026-05-06 | 📦 Frozen | Accepted (planning for 1.1.0). 1.1.x cycle is now complete; the rework decision is historical. Re-read at major cuts to confirm the slot-rhythm pattern still holds. |

**ADR posture**: low decision-velocity. Only architecturally significant calls earn an ADR — minor decisions ride CHANGELOG + design comments. V1.2.0 (multi-profile distlib) was a candidate but didn't earn an ADR (the V1.2.0 CHANGELOG entry + roadmap section carry the rationale; no architectural reversal was made). Re-evaluate at v2.0.0 cut.

---

## Tier 5 — Audit reports (`docs/audit/`)

Date-stamped, frozen by design. Each P(-1) hardening pass per CLAUDE.md cadence lands a new report — old reports stay verbatim as the historical record.

| File | Date | Status | Notes |
|---|---|---|---|
| `2026-04-26-audit.md` | 2026-04-26 | 📦 Frozen | Pre-1.0.0 P(-1) hardening — F-1..F-6 closed in 1.0.1. Historical record. |
| `2026-05-09-audit.md` | 2026-05-09 | ✅ Fresh | 1.1.14 P(-1) step 5 — F-7 INFO + F-8/F-9 LOW closed in 1.1.14, F-10 verified clean. |
| `2026-05-09-cve-landscape.md` | 2026-05-09 | ✅ Fresh | 1.1.14 P(-1) step 4 — CVE class survey across the 17 module-bound kernel interfaces. Pairs with 2026-05-09-audit.md. |

Next audit slot: at v1.3.0 cut (or sooner if a CVE pattern surfaces in agnosys's parser surfaces — audit netlink, IMA records, EFI signature lists, /proc/mounts, CalVer parser, /etc/passwd — or in cyrius itself).

---

## Tier 6 — Engineering reviews (`docs/development/reviews/`)

Date-stamped, frozen by design. Internal review artifacts — point-in-time read of code structure / API consistency / dead-code / parser correctness.

| File | Date | Status | Notes |
|---|---|---|---|
| `2026-05-09-internal-review.md` | 2026-05-09 | ✅ Fresh | 1.1.13 P(-1) step 3 — internal deep review of 20 modules. 3 hotspots filed (H-1 / H-2 / H-3); all resolved or downgraded by 1.1.14. Historical record. |

Next review slot: at v1.3.0 cut (paired with the next audit pass), or earlier if API surface drifts unexpectedly.

---

## Tier 7 — Engineering issues (`docs/development/issues/`)

Active issues sit at the top level; resolved issues move to `archive/` when the upstream fix lands and a workaround is no longer needed. Per the agnosys agent's "don't pile on cyrius bug reports" rule, **active issues here are passive trackers** for upstream-blocked slots, not fresh tickets pushed to the cyrius bug tracker.

### Active (3 — passive trackers, not refiled upstream)

| File | Filed | Status | Notes |
|---|---|---|---|
| `2026-05-09-cyrius-derive-serialize-cstring.md` | 2026-05-09 | 🟠 Open — passive | cstring-pointer field gap in `#derive(Serialize)`. Workaround: 5 hand-rolled `_to_json` shims (V1.1.12). Reopens when cyrius extends the directive's type set. |
| `2026-05-09-cyrius-ifplat-codegen.md` | 2026-05-09 | 🟠 Open — passive | `#ifplat` codegen regression already documented in cyrius's own `lib/syscalls.cyr` v5.4.19 note. Workaround: stay on `#ifdef CYRIUS_ARCH_<UPPER>`. Reopens when cyrius's stdlib migrates first. |
| `2026-05-09-cyrius-deprecated-unproven.md` | 2026-05-09 | 🟠 Open — passive | `#deprecated` directive unproven across agnosticos consumers. Defer until another consumer adopts it OR until agnosys actually has a fn to deprecate. |

### Archived (9 — resolved during V1.0 / V1.1 cycles)

| File | Resolved | Notes |
|---|---|---|
| `archive/2026-05-01-sys-stat-x86-portability.md` | 1.1.4 (cyrius 5.9.20) | sys_stat now in both arch peer files. |
| `archive/2026-05-06-cyrius-api-surface-derive-blind.md` | 1.0.13 (cyrius 5.9.13) | --scope=project + --snapshot=PATH flags. |
| `archive/2026-05-06-cyrius-ct-eq-bytes-stdlib.md` | 1.1.3 (cyrius 5.9.18) | ct_eq_bytes shipped in lib/ct.cyr. |
| `archive/2026-05-06-cyrius-derive-accessors-32-struct-cap.md` | 1.0.11 (cyrius 5.9.7) | derive struct cap lifted. |
| `archive/2026-05-06-cyrius-match-coverage-fn-name-dependent.md` | 1.1.6 (cyrius 5.9.25) | hash-bucket dispatch fixed. |
| `archive/2026-05-07-cyrius-aarch64-sub-8-byte-struct-load.md` | 1.1.10 (cyrius 5.9.27) | aarch64 backend implements sub-8-byte loads. |
| `archive/2026-05-07-cyrius-derive-serialize-incomplete.md` | 1.1.12 (lib-shadow root cause; cyrius 5.10.6+) | The big one — agnosys-side ./lib/ shadow misdiagnosis arc. |
| `archive/2026-05-08-cyrius-derive-multi-stacking.md` | cyrius 5.10.14 | Stacked `#derive` directives now honored. |
| `archive/2026-05-09-cyrius-api-surface-putc-brace-desync.md` | cyrius 5.10.16 | api-surface scanner tokenizes numeric literals. |

---

## Tier 8 — Headliner / heritage docs

| File | Last touched | Status | Notes |
|---|---|---|---|
| `docs/benchmarks-rust-vs-cyrius.md` | 2026-04-30 | 📦 Frozen — HEADLINER | Rust → Cyrius port comparison, point-in-time at agnosys 0.97.1 (Cyrius 3.2.5). Per CLAUDE.md, kept at `docs/` root deliberately. Live perf data lives elsewhere (`bench-history.csv`, gitignored). Don't refresh in place — this is the port-arc historical record. |
| `docs/SECURITY-NOTES.md` | 2026-04-30 | 🟠 Read-through | Per-module security considerations. Most claims are durable (LUKS cipher allowlist, audit-rule path validation, etc.). Worth a fresh read at 1.2.x against current src/ to confirm V1.1.12 + V1.1.14 changes (Serialize shims + F-7/F-8/F-9 hardenings) don't invalidate any per-module note. |

---

## Open strategic questions

None outstanding for the 1.2.1 cut. This section will repopulate when:

- A new doc category appears that doesn't fit an existing tier (e.g. a `docs/guides/` if/when consumer onboarding docs become a thing — currently consumers refer to `dist/agnosys-<profile>.cyr` headers + the per-module module headers in src/).
- The audit / review cadence shifts (current pattern: P(-1) at minor cuts, internal review paired). If V1.3.x adopts a different rhythm, this file's tiers might need restructuring.
- An ADR needs to be retired without a successor — would force a posture call (close the series vs. write a closure ADR).

---

## In-flight (blocked, not stale)

- The 3 active issue tickets (Tier 7) are the in-flight blockers. They are *blocked on upstream cyrius schedule*, not on agnosys-side action. Agnosys-side mitigation paths are documented in each ticket; no follow-up action is owed unless one unblocks.

---

## Forward doc-policy commitments

| # | Commitment | Trigger | Source | Notes |
|---|---|---|---|---|
| 1 | **Audit report retention** — keep all `docs/audit/YYYY-MM-DD-audit.md` reports verbatim through at least v2.0.0; re-evaluate at the major cut whether pre-1.0 reports get folded into a single historical summary. | v2.0.0 cut | This file | Today's surface is 3 reports — purge pressure is zero. |
| 2 | **Issue archive purge** — the `docs/development/issues/archive/` set is a record of upstream cyrius bugs that landed during agnosys development. Keep through v2.0.0; at major cut, decide whether to roll them up into a single CHANGELOG-of-cyrius-quirks file. | v2.0.0 cut | This file | 9 archived tickets at 1.2.1; the V1.0 / V1.1 cycle generated most of them. |
| 3 | **Review report retention** — same posture as audit reports. `docs/development/reviews/` may grow with the audit cadence. | v2.0.0 cut | This file | 1 review at 1.2.1; expect ~1 per major P(-1) pass. |
| 4 | **Auto-gen + staleness gate** — `api-surface-1.0.md` and `capability-map.md` are auto-generated; audit gates 2 + 3 enforce sync. New auto-generated docs (if any) should follow the same pattern: generator script + `--check` mode + audit gate. | When adding next auto-doc | This file | Pattern proven by `scripts/gen-{api-surface-prose,capability-map}.sh`. |

---

## Refresh procedure

When docs are touched:

1. Find the affected row in the relevant tier table.
2. Update **Last touched** column to the new date.
3. Update **Status** column if the bucket changed.
4. Update **Notes** column if the next step changed.
5. If a doc moved or was archived, update its row to reflect the new home.
6. Re-anchor "Last refresh" date in the header.

When the bucket counts at the top drift by more than ~3 in any cell, refresh the at-a-glance table.

This file's refresh cadence is **opportunistic** (touched when other docs are touched), not periodic. The 1.1.13 → 1.2.1 cycle established the baseline; each minor cut's doc-sync step (CLAUDE.md Closeout Pass §9) updates this file alongside CHANGELOG + roadmap + state.md.

---

## What this file is NOT

- Not a substitute for [`development/state.md`](development/state.md) (which holds live version/size/test/consumer state).
- Not a CHANGELOG (which records what shipped, not what's stale).
- Not a roadmap (forward work lives in [`development/roadmap.md`](development/roadmap.md)).
- Not a per-doc review log (we record the result of an audit pass, not the per-doc reasoning).

---

*Last refresh: 2026-05-10 (initial audit, paired with the 1.2.1 doc cleanup pass). Refresh in place when docs are touched.*
