# Agnosys — Claude Code Instructions

> **Core rule**: this file is **preferences, process, and procedures** — durable rules that change rarely. Volatile state (current version, binary sizes, test counts, in-flight work, consumer status, verification hosts) lives in [`docs/development/state.md`](docs/development/state.md), refreshed every release. Do not inline state here — inlined state rots within a minor.

---

## Project Identity

**Agnosys** (agi + nosys — the gnosis of AGI at the system level) — the AGNOS kernel interface library. Cyrius bindings for Linux kernel syscalls and security primitives. Consumers include only the modules they need, or include `dist/agnosys.cyr` for the full bundle.

- **Type**: Shared library (flat, single-include modules + bundled distlib)
- **License**: GPL-3.0-only
- **Language**: Cyrius (toolchain pinned in `cyrius.cyml [package].cyrius`)
- **Version**: `VERSION` at the project root is the source of truth — do not inline the number here
- **Genesis repo**: [agnosticos](https://github.com/MacCracken/agnosticos)
- **Philosophy**: [AGNOS Philosophy & Intention](https://github.com/MacCracken/agnosticos/blob/main/docs/philosophy.md)
- **Standards**: [First-Party Standards](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-standards.md) · [First-Party Documentation](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-documentation.md)
- **Recipes**: [zugot](https://github.com/MacCracken/zugot) — takumi build recipes
- **Heritage**: Ported from Rust in 2026. Rust source deleted at 0.97.1, preserved in git history. Head-to-head numbers in [`docs/benchmarks-rust-vs-cyrius.md`](docs/benchmarks-rust-vs-cyrius.md).

## Goal

**Own the Linux kernel boundary for AGNOS.** Every syscall, every audit netlink frame, every TPM/IMA/dm-verity ioctl flows through agnosys. Higher-level primitives (device abstraction, sandbox policy, container runtime, rendering pipeline) are the consumer's job; agnosys delivers the safe, measurable, auditable bottom-of-stack.

Scope boundaries (non-owned, by design):
- **Higher-level device abstraction** → yukti (consumes agnosys[udev])
- **Sandbox policy engine** → kavach (consumes agnosys[landlock,seccomp])
- **Firewall rules** → nein (consumes agnosys[netns])
- **Container runtime** → stiva (consumes agnosys[luks,dmverity])
- **Rendering pipeline** → soorat (consumes agnosys[drm])

## Current State

Volatile state lives in [`docs/development/state.md`](docs/development/state.md) — current version, module count, binary size, test/assertion counts, consumer status, in-flight slots, recent releases, verification hosts. Refreshed every release.

Per-module security considerations live in [`docs/SECURITY-NOTES.md`](docs/SECURITY-NOTES.md). Module map and data flow live in [`docs/architecture/overview.md`](docs/architecture/overview.md).

## Scaffolding

Project is a flat Cyrius library. **Do not manually create project structure** — use `cyrius` tooling. If the tools are missing something, fix the tools. Module discipline:

- `src/<module>.cyr` is included via `include "src/<module>.cyr"` from `src/main.cyr`
- `cyrius.cyml [lib] modules` lists the modules `cyrius distlib` concatenates into `dist/agnosys.cyr`
- `cyrius.cyml [build]` does **not** carry `modules` — that re-includes through main.cyr's `include` directives and inflates the binary by ~76% (see CHANGELOG 1.0.1)

## Quick Start

```sh
cyrius build src/main.cyr build/agnosys     # compile
CYRIUS_DCE=1 cyrius build ...               # release build with dead-code elim
cyrius run src/main.cyr                     # compile + run
cyrius check src/main.cyr                   # syntax check
cyrius test                                 # run tests/tcyr/*.tcyr
cyrius bench tests/bcyr/bench_all.bcyr      # run benchmarks
cyrius distlib                              # regenerate dist/agnosys.cyr
cyrius capacity --check src/main.cyr        # compiler-table utilization gate
cyrius lint src/*.cyr                       # static checks
cyrius vet src/main.cyr                     # include-graph audit
cyrius fmt <file> [--check]                 # format / check
scripts/audit.sh                            # full local quality run (CI parity)
scripts/check-api-surface.sh                # diff public API vs. 1.0 snapshot
```

## Key Principles

- **Correctness is the optimum sovereignty** — if it's wrong, you don't own it; the bugs own you
- **Every change passes `scripts/audit.sh`** — same gates as CI; never claim a change is ready without it
- Test after EVERY change, not after the feature is "done"
- ONE change at a time — never bundle unrelated changes
- **Tests + benchmarks prove the change.** Don't claim perf wins without a bench diff
- **Own the stack.** If an AGNOS crate wraps an external lib, depend on the AGNOS crate
- **No magic.** Every operation is measurable, auditable, traceable
- **Packed errors on hot paths** — `syserr_pack(kind, errno)` for zero-alloc
- **Heap errors on cold paths** — `syserr_new(kind, errno, message)` when diagnostics matter
- **Caller-provided buffers** — avoid heap allocation in syscall wrappers; caller owns memory
- **Prefix all functions** — every public fn starts with its module prefix (`agnosys_`, `mac_`, `audit_`, `pam_`, `security_`, ...). API surface frozen at `docs/development/api-surface-1.0.md`; drift fails CI
- **`AGNOSYS_LOG` env var** controls log level
- Programs call `main()` at top level: `var exit_code = main(); syscall(60, exit_code);`
- Source files only need project includes — stdlib auto-resolves from `cyrius.cyml [deps] stdlib`

## Rules (Hard Constraints)

- **Read the genesis repo's CLAUDE.md first** — [agnosticos/CLAUDE.md](https://github.com/MacCracken/agnosticos/blob/main/CLAUDE.md)
- **Do not commit or push** — the user handles all git operations (commit, push, tag)
- **NEVER use `gh` CLI** — use `curl` to GitHub API only
- Do not add runtime dependencies — agnosys is a kernel interface, keep it lean (zero non-stdlib deps today)
- Do not skip `scripts/audit.sh` before claiming a change is ready
- Do not skip benchmarks before claiming performance improvements
- Do not skip fuzz verification before claiming a parser change works
- Do not commit `build/`
- Do not edit `dist/agnosys.cyr` by hand — regenerate via `cyrius distlib`
- Do not hardcode toolchain versions in CI YAML — the `cyrius = "X.Y.Z"` pin in `cyrius.cyml [package]` is the only source of truth
- Do not rename a public function without bumping the API snapshot via `scripts/check-api-surface.sh --update` and updating CHANGELOG `Breaking`
- Do not use reserved keywords as variable names (`match`, `default`, `shared`, `in`, `secret`)
- Do not define functions with 7+ parameters — split into `module_thing_new(...)` + `module_thing_set_*(...)` pattern
- Do not use `sys_system()` with unsanitized input — command injection risk
- Do not trust external data (file content, network input, user args) without validation
- Do not use `break` in while loops with `var` declarations — use flag + `continue`

## Process

### P(-1): Scaffold / Project Hardening (before any new features)

1. **Cleanliness** — `scripts/audit.sh` clean; all 10 gates pass
2. **Benchmark baseline** — `cyrius bench tests/bcyr/bench_all.bcyr`, record CSV via `scripts/bench-history.sh`
3. **Internal deep review** — gaps, optimizations, correctness, docs
4. **External research** — domain completeness, best practices, current CVE landscape for the kernel interfaces we bind
5. **Security audit** — input handling, syscall usage, buffer sizes, pointer validation. File findings in `docs/audit/YYYY-MM-DD-audit.md`
6. **Additional tests / benchmarks / fuzz harnesses** from findings
7. **Post-review benchmarks** — prove the wins against step 2
8. **Documentation audit** — ADRs for decisions made, source citations, guides for public API
9. **Repeat if heavy** — keep drilling until clean

### Work Loop (continuous)

1. **Work phase** — new features, roadmap items, bug fixes (see `docs/development/roadmap.md`)
2. **Build check** — `cyrius build src/main.cyr build/agnosys`
3. **Test + benchmark additions** for new code
4. **Internal review** — performance, memory, correctness, edge cases
5. **Security check** — any new syscall usage, user input handling, buffer allocation
6. **Local audit** — `scripts/audit.sh` clean
7. **Documentation** — CHANGELOG, roadmap, `docs/development/state.md`, any ADR the change earned
8. **Version check** — `VERSION`, `cyrius.cyml`, CHANGELOG header in sync (`cyrius.cyml` reads VERSION via `${file:VERSION}`, so `./scripts/version-bump.sh <new>` is enough)
9. **Regenerate `dist/agnosys.cyr`** if any `src/*.cyr` changed
10. **Return to step 1**

### Security Hardening (before every release)

Per [first-party-standards § Security Hardening](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-standards.md#security-hardening-new--required-before-every-release). Minimum:

1. **Input validation** — every fn accepting external data validates bounds, types, ranges
2. **Buffer safety** — every `var buf[N]` verified; N is **bytes**, max access < N. NB: cyrius emits `var buf[N]` *inside fn scope* as **static data, not stack** — consecutive calls clobber any borrowed Str/buf return. Check call patterns at every site
3. **Syscall review** — every syscall validated: args checked, returns handled, error paths complete
4. **Pointer validation** — no raw pointer dereference of untrusted input without bounds
5. **No command injection** — use `exec_vec()` with explicit argv; never `sys_system()` with unsanitized input
6. **No path traversal** — file paths from external input validated, no `../` escape
7. **Known CVE review** — check kernel interfaces (audit netlink, dm-verity, IMA, FUSE, LUKS, TPM, Landlock, seccomp, secureboot, PAM) against current CVE databases
8. **Document findings** — all issues in `docs/audit/YYYY-MM-DD-audit.md`

Severity levels: **CRITICAL** (remote / privilege escalation), **HIGH** (moderate effort), **MEDIUM** (specific conditions), **LOW** (defense-in-depth).

### Closeout Pass (before every minor/major bump)

Run a closeout pass before tagging `X.Y.0` or `X.0.0`. Ship as the last patch of the current minor (e.g. `1.1.5` before `1.2.0`).

1. **Full test suite** — all `tests/tcyr/*.tcyr` pass, zero failures
2. **Benchmark baseline** — `cyrius bench`, save CSV via `scripts/bench-history.sh`; compare against prior closeout
3. **Dead code audit** — `cyrius build` reports `dead:` lines under DCE; record floor in CHANGELOG
4. **Refactor pass** — consolidate the minor's additions where parallel codepaths accreted
5. **Code review pass** — walk diffs end-to-end for missed guards, ABI leaks, off-by-ones, silently-ignored errors
6. **Cleanup sweep** — stale comments, dead `#ifdef` branches, unused includes, orphaned files
7. **Security re-scan** — quick grep for new `sys_system`, unchecked writes, unsanitized input, buffer size mismatches, large `var buf[N]` (≥64KB)
8. **Downstream check** — every consumer in `docs/development/state.md` still builds against the new version
9. **Doc sync** — CHANGELOG, roadmap, `docs/development/state.md`, CLAUDE.md (if durable content changed)
10. **Version verify** — `VERSION`, `cyrius.cyml`, CHANGELOG header, intended git tag all match
11. **Full build from clean** — `rm -rf build && cyrius deps && CYRIUS_DCE=1 cyrius build` passes clean
12. **API surface check** — `scripts/check-api-surface.sh` clean (no signature drift vs. snapshot)

### Task Sizing

- **Low/Medium effort**: batch freely — multiple items per work loop cycle
- **Large effort**: small bites only — break into sub-tasks, verify each before moving to the next
- **If unsure**: treat it as large

### Refactoring Policy

- Refactor when the code tells you to — duplication, unclear boundaries, measured bottlenecks
- Never refactor speculatively. Wait for the third instance before extracting an abstraction
- Every refactor must pass the same test + fuzz + benchmark gates as new code
- 3 failed attempts = defer and document — don't burn time in a rabbit hole

## Cyrius Conventions

- **Error encoding**: packed `kind << 16 | errno` (fast) or heap `{ kind, errno, message_ptr }` (diagnostic)
- **Result convention**: `Ok(value)` / `Err(error)` via `lib/tagged.cyr`
- **Error propagation**: `if (is_err_result(res) == 1) { return res; }`
- **Syscall wrappers** return raw values; use `wrap_syscall(ret)` or `agnosys_checked_syscall(ret)` for Result wrapping
- **Structs**: heap-allocated via `alloc()`, accessed via `store64`/`load64` at fixed offsets. `#derive(accessors)` adoption is post-1.0 follow-up (see roadmap Phase 8)
- **Strings**: null-terminated C strings at boundaries; `lib/str.cyr` fat pointers (`Str`) internally. Parser inputs from `str_split` expect `Str`, not cstring
- **`toml_get` family** in cyrius 5.x stdlib expects **cstr** keys, not `Str` — passing `str_from("key")` silently returns 0
- **Benchmarks**: `lib/bench.cyr` with `now_ns()`; CSV history via `scripts/bench-history.sh`
- **`var buf[N]` inside a function** is **static data**, not stack — consecutive calls clobber. Diagnostic: build emits "large static data (N bytes)" warning. Always heap-allocate large buffers; small bufs are OK only when their contents are copied out before the next call
- **Heap large buffers** — `var buf[256000]` bloats the binary by 256KB (and creates the static-data hazard above)
- **Enum values for constants** — don't consume `gvar_toks` slots (256 initialized globals limit)
- **No negative literals** — write `(0 - N)` not `-N`
- **No mixed `&&` / `||`** in one expression — nest `if` blocks
- **`return;` without value is invalid** — always `return 0;`
- **All `var` declarations are function-scoped** — no block scoping
- **Max limits per compilation unit**: 4,096 variables, 1,024 functions, 256 initialized globals — guarded by `cyrius capacity --check`

## CI / Release

- **Toolchain pin**: `cyrius = "X.Y.Z"` field in `cyrius.cyml [package]`. **No separate `.cyrius-toolchain` file, no `CYRIUS_VERSION` env in workflow YAML.** CI and release both `grep` the pin out of `cyrius.cyml`.
- **Tarball install**: CI fetches `https://github.com/MacCracken/cyrius/releases/download/$VER/cyrius-$VER-x86_64-linux.tar.gz` rather than the floating `install.sh` from main, so a cyrius patch can't silently change a release-tagged build.
- **Dead code elimination**: every `cyrius build` in CI and release runs with `CYRIUS_DCE=1`. Binary size is a release metric — track it in `docs/development/state.md`.
- **Tag filter**: release workflow accepts both `vX.Y.Z` and `X.Y.Z` tag shapes; the version-verify step strips a leading `v` and asserts `VERSION == tag`.
- **Lockfile**: `cyrius.lock` (when present) gates dep hashes via `cyrius deps --verify`. Skip-if-absent on first-push.
- **fmt drift gate**: `cyrius fmt --check` per file; CI fails on any diff against the committed file.
- **lint warn-fail**: `cyrius lint` per file; any `warn ` line fails CI.
- **dist staleness gate**: CI runs `cyrius distlib` and fails if `dist/agnosys.cyr` differs from the committed copy.
- **Workflow layout**:
  - `.github/workflows/ci.yml` — toolchain → syntax → API surface → capacity → deps → fmt → lint → vet → dist gate → DCE build → ELF verify → aarch64 cross (best-effort) → smoke → tests → fuzz → bench
  - `.github/workflows/release.yml` — version gate → CI gate → DCE build → aarch64 cross → tests → fuzz → regenerate dist → archive (source tar, single-file `.cyr`, prebuilt x86_64 + aarch64 binaries, cyrius.lock, SHA256SUMS)
- **Concurrency**: CI uses `cancel-in-progress: true` keyed on workflow + ref.

## Docs

- [`docs/adr/`](docs/adr/) — architecture decision records. *Why X over Y?*
- [`docs/architecture/`](docs/architecture/) — non-obvious constraints and quirks. Module map, data flow, consumer wiring
- [`docs/audit/`](docs/audit/) — security audit reports, named `YYYY-MM-DD-audit.md`
- [`docs/guides/`](docs/guides/) — task-oriented how-tos
- [`docs/examples/`](docs/examples/) — runnable examples
- [`docs/development/roadmap.md`](docs/development/roadmap.md) — completed, backlog, future, v1.0+ criteria
- [`docs/development/state.md`](docs/development/state.md) — **live state snapshot, refreshed every release**
- [`docs/development/api-surface-1.0.md`](docs/development/api-surface-1.0.md) — public API snapshot (human-readable)
- [`docs/development/api-surface-1.0.snapshot`](docs/development/api-surface-1.0.snapshot) — machine-checkable (`module::fn/arity`)
- [`docs/development/capacity-baseline.md`](docs/development/capacity-baseline.md) — compiler-table utilization record
- [`docs/SECURITY-NOTES.md`](docs/SECURITY-NOTES.md) — per-module security considerations
- [`docs/benchmarks-rust-vs-cyrius.md`](docs/benchmarks-rust-vs-cyrius.md) — Rust → Cyrius port numbers (headliner; kept at `docs/` root deliberately)
- [`CHANGELOG.md`](CHANGELOG.md) — source of truth for all changes

New quirks land in `docs/architecture/` as numbered items (`NNN-kebab-case.md`). New decisions land in `docs/adr/` (use the agnosticos template). **Never renumber either series.**

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md,
  SECURITY.md, CODE_OF_CONDUCT.md, LICENSE,
  VERSION, cyrius.cyml

docs/ (required):
  benchmarks-rust-vs-cyrius.md           — HEADLINER: Rust→Cyrius port numbers
  SECURITY-NOTES.md                       — per-module security considerations
  architecture/overview.md                — module map, data flow, consumers
  development/roadmap.md                  — completed, backlog, future
  development/state.md                    — live state snapshot (volatile)
  development/api-surface-1.0.md          — public API snapshot (human-readable)
  development/api-surface-1.0.snapshot    — machine-checkable (module::fn/arity)
  development/capacity-baseline.md        — compiler-table utilization record

docs/ (when earned):
  adr/        — architectural decision records
  audit/      — security audit reports (YYYY-MM-DD-audit.md)
  guides/     — usage guides, integration patterns
  examples/   — worked examples
  standards/  — external spec conformance
  sources.md  — source citations for algorithms/formulas
```

## .gitignore (Required)

```gitignore
# Build
/build/

# Resolved deps (auto-generated by cyrius deps)
# (kernel-interface lib has no git-pinned external deps today;
#  if any are added under [deps.<name>], gitignore the resolved
#  copies and keep only the lockfile and stdlib refresh)

# Release / toolchain artifacts
cyrius-*.tar.gz
*.tar.gz
SHA256SUMS

# IDE
.idea/
.vscode/
*.swp
*~

# OS
.DS_Store
Thumbs.db
```

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/). Performance claims **must** include benchmark numbers. Breaking changes get a **Breaking** section with migration guide. Security fixes get a **Security** section with CVE references where applicable. See [first-party-documentation § CHANGELOG](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-documentation.md#changelog) for the full conventions.
