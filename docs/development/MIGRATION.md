# Agnosys Migration Notes

## Phase 1 Status: Modules Copied

All 19 modules from `userland/agnos-sys/src/` have been copied to `agnosys/src/`. The `lib.rs` wires them with feature gates. The `Cargo.toml` has all dependencies declared.

### What Compiles
- Default features (syscall + error) — clean
- Individual modules need error type alignment

### What Needs P(-1) Work

1. **Error type alignment** — The monolith modules use `crate::error::{Result, SysError}` but the exact variants and helper methods differ between the old monolith error module and the new agnosys error module. Each module needs its `use` statements updated to match agnosys's `SysError` API.

2. **`agnos_common` dependency** — `agent.rs` imports types from `agnos_common` (AgentConfig, AgentId, AgentStatus, etc.). Options:
   - Re-define these types locally in `agent.rs`
   - Create a minimal types module in agnosys
   - Wait for `agnostik` crate extraction (Phase 1 of monolith extraction)

3. **Cross-module references** — Some modules may reference other modules (e.g., `security.rs` types used in `audit.rs`). These need feature-gate-aware imports.

4. **Test migration** — The monolith's tests reference the old module paths. Each module's `#[cfg(test)]` block needs path updates.

### Priority Order

1. `error.rs` — align error types (foundation for everything)
2. `security.rs` — most consumed module (kavach, daimon, agnoshi all use it)
3. `syscall.rs` — base layer
4. `certpin.rs` — hoosh needs it
5. `audit.rs` — libro needs it
6. Remaining modules in roadmap phase order

### Consumer Migration (Phase 2-3)

Once agnosys compiles clean with all features:

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
