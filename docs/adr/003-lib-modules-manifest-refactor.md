# ADR-003 — `[lib] modules` manifest layout (do not move back to `[build]`)

**Status:** Accepted (1.0.1)
**Context window:** cyrius 5.5+
**Supersedes:** —
**Superseded by:** —

## Context

The `cyrius.cyml` manifest has two locations a contributor might list module source files:

```toml
[build]
modules = ["src/error.cyr", "src/syscall.cyr", ...]   # ❌ inflates binary

[lib]
modules = ["src/error.cyr", "src/syscall.cyr", ...]   # ✅ correct
```

Pre-1.0.1, agnosys carried `modules` under `[build]`. The cyrius 5.x build behavior is: `cyrius build src/main.cyr` prepends every file in `[build] modules` *before* the `src/main.cyr` source — and `src/main.cyr` then `include`s those same files via its top-of-file `include "src/<module>.cyr"` directives. The result is that every module's source ends up in the AST twice. Cyrius 5.7's DCE eliminates duplicate top-level definitions, but the lexer/parser/IR phases still pay the cost, and a non-trivial amount of the duplicated bodies survives DCE as cold-but-reachable.

Empirical: agnosys 1.0.0 release binary was **306,344 bytes**. After moving `modules = [...]` from `[build]` to `[lib]`, the same source compiled to **73,144 bytes** — a 76% reduction with zero source changes. The `dist/agnosys.cyr` bundle (concatenation produced by `cyrius distlib` from the same `[lib] modules` list) was byte-identical before and after, so nothing about the public API or the bundled distlib shape changed.

## Decision

**`cyrius.cyml` lists module source files under `[lib] modules`. The `[build]` table does NOT carry `modules`. This is true for agnosys, and for any future agnosys-derived crate.**

`[build]` settings — entry source, output name, target — remain in `[build]`. `[lib] modules` is the single source of truth that:

- `cyrius distlib` reads to produce `dist/agnosys.cyr`.
- `cyrius build src/main.cyr` does NOT need to re-list, because `src/main.cyr` already pulls each one in via `include "src/<module>.cyr"`.

The yukti consumer crate (separate repo) follows the same layout; this ADR documents the reasoning so future agnosys contributors don't "fix" the manifest by moving it back.

## Consequences

**Positive:**
- 73 KB binary vs. 306 KB. The kernel-interface library now ships in roughly one filesystem block.
- `cyrius build` and `cyrius distlib` have one consistent way to discover the module set.
- Fast iteration: a single-module change rebuilds in < 500 ms because there's no double-include parse cost.

**Negative:**
- Slight asymmetry — a contributor reading `cyrius.cyml` for the first time may expect `modules` under `[build]` because that's what the table is named for. The CLAUDE.md preferences file calls this out explicitly under "Scaffolding".
- If a future cyrius release reverses the semantics (treats `[lib] modules` as a no-op for `cyrius build`), the manifest needs to flip. We pin the toolchain via `cyrius = "X.Y.Z"` in `[package]` precisely to control when that kind of change is absorbed.

## Detection / regression guard

`scripts/audit.sh` step 4 records the build size; CHANGELOG records the binary size for every release in the `Verified` block. Any regression to ≥ 200 KB without a corresponding source-size justification is the signal that someone has moved the manifest back. CI's "build" step in `.github/workflows/ci.yml` does not currently fail on size — adding a hard gate is tracked as a Phase 8 backlog item.

## References

- CHANGELOG `[1.0.1]` — manifest refactor narrative + size delta
- CLAUDE.md "Scaffolding" — DO-NOT for `[build] modules`
- `cyrius.cyml` — current manifest
- `docs/development/state.md` — current binary size record
