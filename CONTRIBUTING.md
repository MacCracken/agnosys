# Contributing to Agnosys

Thank you for your interest in contributing to Agnosys.

## Development Workflow

1. Fork and clone the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run `cyrb check` on modified files
5. Build and test: `cyrb build src/main.cyr build/agnosys && ./build/agnosys`
6. Open a pull request

## Prerequisites

- [Cyrius](https://github.com/MacCracken/cyrius) toolchain (cc2 + cyrb)
- Linux x86_64

## Build Commands

| Command | Description |
|---------|-------------|
| `cyrb build src/main.cyr build/agnosys` | Compile |
| `cyrb run src/main.cyr` | Compile + run |
| `cyrb check src/file.cyr` | Syntax check |
| `cyrb audit` | Full check (if available) |

## Adding a Module

1. Create `src/module_name.cyr`
2. Prefix all functions with `modulename_` to avoid namespace collisions
3. Use `Ok()`/`Err()` from `lib/tagged.cyr` for error handling
4. Use error constructors from `src/error.cyr`
5. Add `include "src/module_name.cyr"` to `src/main.cyr`
6. Update the module table in `CLAUDE.md` and `README.md`

## Cyrius Conventions

- Everything is i64 — no types, no generics
- Heap allocation via `alloc()` from `lib/alloc.cyr`
- Memory access via `store64/load64` (and 8/16/32 variants)
- Strings are null-terminated C strings
- Error propagation: `if (is_err_result(res) == 1) { return res; }`
- Comments with `#`
- No `match`, `default`, `shared`, `in` as variable names (reserved keywords)
- Max 6 function parameters (7+ use stack, may hit parser issues)

## Code Style

- One module per `.cyr` file
- Module-level comment block at top explaining what it ports
- Function names: `prefix_verb_noun()` (e.g., `mac_detect_system()`, `audit_open()`)
- Constants via `enum` blocks (avoids global var slot limits)
- Caller-provided buffers for hot-path functions (avoid heap allocation)
- Packed errors (`syserr_pack`) for fast paths, heap errors (`syserr_new`) for diagnostics
