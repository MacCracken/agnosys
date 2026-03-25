# Agnosys Migration Notes

## Phase 1 Status: Complete

All 19 modules from `userland/agnos-sys/src/` have been copied to `agnosys/src/`. The `lib.rs` wires them with feature gates. The `Cargo.toml` has all dependencies declared.

### Completed Items

1. **Error type alignment** — `SysError` with 8 variants, errno mapping, `Cow<'static, str>` strings. All modules use `crate::error::{Result, SysError}`.
2. **`agnos_common` dependency removed** — Agent types defined locally in `agent.rs`. No external AGNOS crate dependencies.
3. **Cross-module references** — Feature-gate-aware imports working across all 23 modules.
4. **Test migration** — 919 lib tests + 76 integration tests + 1 doctest passing. All `#[cfg(test)]` blocks use correct paths.
5. **Integration tests** — Rewritten to match actual public API (2026-03-24).
6. **Examples** — All 6 examples updated to match actual module exports (2026-03-24).
7. **Clippy clean** — Zero warnings with `-D warnings` across all features.

### Consumer Migration (Phase 2-3)

Once consumers are ready to migrate:

```toml
# userland/agnos-sys/Cargo.toml
[dependencies]
agnosys = { version = "0.23", features = ["full"] }

# Re-export everything
# lib.rs: pub use agnosys::*;
```

Then consumers migrate one at a time:
- `use agnos_sys::security::` → `use agnosys::security::`
- `agnos-sys = { workspace = true }` → `agnosys = { version = "0.23", features = ["security"] }`
