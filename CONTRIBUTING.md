# Contributing to Agnosys

Thank you for your interest in contributing.

## Prerequisites

- [Cyrius](https://github.com/MacCracken/cyrius) toolchain pinned in `cyrius.cyml` (currently **6.0.24** at 1.3.1; install via `curl -sSfL https://raw.githubusercontent.com/MacCracken/cyrius/main/scripts/install.sh | sh`, then `cyriusly use $(grep -oP '(?<=^cyrius = ")[^"]+' cyrius.cyml)`)
- Linux x86_64 (primary host) or aarch64 (cross-build via `cycc_aarch64`, renamed from `cc5_aarch64` in Cyrius 6.0); macOS / Windows is a cyrius-side roadmap item
- `./lib/` is gitignored — populated on first build by `cyrius deps` from the `[deps] stdlib` list

## Development Workflow

1. Fork and clone
2. Create a feature branch from `main`
3. `cyrius deps` to populate `./lib/` from the pinned cyrius stdlib
4. Make your changes under `src/`, `tests/`, `fuzz/`, or `docs/`
5. **Run `scripts/audit.sh`** — 11 gates, same as CI (syntax → API surface (snapshot + prose) → capability map → capacity → build → smoke → tests → lint → vet → fuzz → benchmarks)
6. If you renamed or removed a public function, update the snapshot intentionally: `scripts/check-api-surface.sh --update` and record the rename in `CHANGELOG.md` under `Breaking`
7. If any `src/*.cyr` changed, regenerate all bundles: `cyrius distlib && for p in core security storage trust system; do cyrius distlib $p; done`
8. If `src/*.cyr` comments / public surface changed, regenerate the prose + capability map: `scripts/gen-api-surface-prose.sh && scripts/gen-capability-map.sh`
9. Open a PR

## Commands

| Command | Description |
|---------|-------------|
| `cyrius deps` | Vendor the pinned stdlib into `./lib/` (gitignored) |
| `cyrius build src/main.cyr build/agnosys` | Compile |
| `cyrius build --aarch64 src/main.cyr build/agnosys-aarch64` | Cross-build for aarch64 |
| `cyrius run src/main.cyr` | Compile + run |
| `cyrius check src/<module>.cyr` | Syntax check |
| `cyrius test` | Run `tests/tcyr/*.tcyr` |
| `cyrius lint src/<module>.cyr` | Static analysis |
| `cyrius vet src/main.cyr` | Include-graph audit |
| `cyrius capacity --check src/main.cyr` | 85% table-utilization gate |
| `cyrius distlib [<profile>]` | Regenerate `dist/agnosys.cyr` (or `dist/agnosys-<profile>.cyr` — core/security/storage/trust/system) |
| `scripts/audit.sh` | Full 11-gate local quality run |
| `scripts/check-api-surface.sh` | Diff public API vs. snapshot |
| `scripts/gen-api-surface-prose.sh [--check]` | Regen / check `api-surface-1.0.md` prose |
| `scripts/gen-capability-map.sh [--check]` | Regen / check `capability-map.md` |
| `scripts/bench-history.sh` | Append a bench-history row + regen `BENCHMARKS.md` |

## Adding a Module

The 1.0 surface is **frozen** — adding new modules is rare and requires a major-cycle conversation. If you do:

1. Create `src/<module>.cyr`. Prefix every public function with `<module>_` (see CLAUDE.md for why — it's a freeze-gated convention)
2. Return `Ok(value)` / `Err(error)` via `lib/tagged.cyr` for any function that can fail
3. Use the error constructors from `src/error.cyr` (`err_invalid_argument`, `err_permission_denied`, `err_from_errno`, ...)
4. Add `include "src/<module>.cyr"` where appropriate (typically test harnesses)
5. Register the module in `cyrius.cyml`'s `[lib] modules` list in declared order (per ADR-003 — **not** `[build] modules`)
6. Pick the right `[lib.<profile>]` section to add the module to (V1.2.0+) — usually one of `security` / `storage` / `trust` / `system`. `core` is reserved for foundational fns (error, syscall, logging).
7. Run `cyrius distlib && cyrius distlib <profile>` to refresh both the full bundle and the relevant profile bundle
8. Add integration assertions in `tests/tcyr/test_integration.tcyr` (at least 5 per module)
9. Add a fuzz harness in `fuzz/<module>_<parser>.fcyr` if the module exposes a parser
10. Update `README.md`, `CLAUDE.md`, `docs/architecture/overview.md` module tables; the auto-generated `api-surface-1.0.md` + `capability-map.md` pick up the new fns on next regen

## Cyrius Conventions

- Default type is i64. Multi-width primitives available (`i8`/`i16`/`i32`/`i64`); typed struct fields land at sub-i64 widths from V1.1.8 onward (kernel-ABI structs use `: i32` etc.)
- Structs: heap-allocated via `alloc()`, fields accessed at fixed offsets — but **prefer `#derive(accessors)`** for new structs (V1.1.0+ adopted; 37 derive structs across 16 modules). Stack `#derive(Serialize)` on top for diagnostic JSON dumps where the field set is `i64` / `Str` only (V1.1.12+; cyrius 5.10.14+ honors stacked `#derive`)
- Strings: null-terminated C strings at boundaries; `lib/str.cyr` fat pointers (`Str`) internally. Parsers built on `str_split` expect `Str`, not cstring — wrap with `str_from(cstr)` when calling from outside
- Error propagation: `if (is_err_result(res) == 1) { return res; }`
- Comments: `#` to end of line
- Reserved keywords (cannot be used as var names): `match`, `default`, `shared`, `in`, `secret`
- Max 6 function parameters — 7+ trigger a create/set split (CLAUDE.md)
- `#define LINUX` at the top of every `.cyr` that includes `lib/syscalls.cyr`
- Arch-gated blocks use `#ifdef CYRIUS_ARCH_X86 / AARCH64` (NOT `#ifplat` — see [`docs/development/issues/2026-05-09-cyrius-ifplat-codegen.md`](docs/development/issues/2026-05-09-cyrius-ifplat-codegen.md))

## Code Style

- One module per `src/<module>.cyr` file, `lib.cyr` equivalent is `src/<module>.cyr` itself — there's no per-module lib entry point in agnosys
- Module-level comment block at the top describing subsystem coverage
- Function naming: `<module>_<struct>_<field>` for accessors (e.g. `audit_rule_path`, `certpin_entry_host`), `<module>_<verb>_<noun>` for actions (`mac_detect_system`, `audit_open`)
- Constants via `enum` blocks (avoids global var slot limits)
- Caller-provided buffers for hot-path functions (avoid heap allocation in syscall wrappers)
- Packed errors (`syserr_pack`) for fast paths, heap errors (`syserr_new`) when diagnostics matter

## Commits, Tags, Releases

- The maintainer (Robert MacCracken) handles all git operations — do not push, tag, or release
- Version is bumped via `./scripts/version-bump.sh <new-version>`; `VERSION` is the single source of truth (read into `cyrius.cyml` via `${file:VERSION}`)
- SemVer. 1.0.0 is the API freeze target; no breaking changes after
