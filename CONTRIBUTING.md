# Contributing to Agnosys

Thank you for your interest in contributing.

## Prerequisites

- [Cyrius](https://github.com/MacCracken/cyrius) toolchain **5.2.0+** (install via `curl -sSfL https://raw.githubusercontent.com/MacCracken/cyrius/main/scripts/install.sh | sh`)
- Linux x86_64 for now; macOS / Windows support is a Cyrius-side roadmap item

## Development Workflow

1. Fork and clone
2. Create a feature branch from `main`
3. Make your changes under `src/`, `tests/`, `fuzz/`, or `docs/`
4. **Run `scripts/audit.sh`** — 10 gates, same as CI
5. If you renamed or removed a public function, update the snapshot intentionally: `scripts/check-api-surface.sh --update` and record the rename in `CHANGELOG.md` under `Breaking`
6. If any `src/*.cyr` changed, regenerate the bundle: `cyrius distlib`
7. Open a PR

## Commands

| Command | Description |
|---------|-------------|
| `cyrius build src/main.cyr build/agnosys` | Compile |
| `cyrius run src/main.cyr` | Compile + run |
| `cyrius check src/<module>.cyr` | Syntax check |
| `cyrius test` | Run `tests/tcyr/*.tcyr` |
| `cyrius lint src/<module>.cyr` | Static analysis |
| `cyrius vet src/main.cyr` | Include-graph audit |
| `cyrius capacity --check src/main.cyr` | 85% table-utilization gate |
| `cyrius distlib` | Regenerate `dist/agnosys.cyr` |
| `scripts/audit.sh` | Full 10-gate local quality run |
| `scripts/check-api-surface.sh` | Diff public API vs. 1.0 snapshot |

## Adding a Module

1. Create `src/<module>.cyr`. Prefix every public function with `<module>_` (see CLAUDE.md for why — it's a freeze-gated convention)
2. Return `Ok(value)` / `Err(error)` via `lib/tagged.cyr` for any function that can fail
3. Use the error constructors from `src/error.cyr` (`err_invalid_argument`, `err_permission_denied`, `err_from_errno`, ...)
4. Add `include "src/<module>.cyr"` where appropriate (typically test harnesses)
5. Register the module in `cyrius.cyml`'s `[build] modules` list in declared order
6. Run `cyrius distlib` to include the module in `dist/agnosys.cyr`
7. Add integration assertions in `tests/tcyr/test_integration.tcyr` (at least 5 per module)
8. Add a fuzz harness in `fuzz/<module>_<parser>.fcyr` if the module exposes a parser
9. Update `README.md`, `CLAUDE.md`, `docs/architecture/overview.md` module tables

## Cyrius Conventions

- Default type is i64. Multi-width primitives available (`i8`/`i16`/`i32`/`i64`); type annotations are optional and documentation-only
- Structs: heap-allocated via `alloc()`, fields accessed at fixed offsets with `load64` / `store64` (and 8/16/32-bit variants). `#derive(accessors)` is available but not yet adopted in agnosys
- Strings: null-terminated C strings at boundaries; `lib/str.cyr` fat pointers (`Str`) internally. Parsers built on `str_split` expect `Str`, not cstring — wrap with `str_from(cstr)` when calling from outside
- Error propagation: `if (is_err_result(res) == 1) { return res; }`
- Comments: `#` to end of line
- Reserved keywords (cannot be used as var names): `match`, `default`, `shared`, `in`
- Max 6 function parameters — 7+ trigger a create/set split (CLAUDE.md)
- `#define LINUX` at the top of every `.cyr` that includes `lib/syscalls.cyr`

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
