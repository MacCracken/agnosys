# Agnosys Roadmap

> **Agnosys** is the kernel interface foundation. It extracts from the monolithic
> `userland/agnos-sys/` in agnosticos into a standalone, feature-gated crate on crates.io.
>
> See [monolith-extraction.md](https://github.com/MacCracken/agnosticos/blob/main/docs/development/monolith-extraction.md) for the full extraction plan.

## Scope

Agnosys owns **safe Rust bindings to Linux kernel interfaces**. It does NOT own:
- **Higher-level device abstraction** → yukti (consumes agnosys[udev])
- **Sandbox policy engine** → kavach (consumes agnosys[landlock,seccomp])
- **Firewall rules** → nein (consumes agnosys[netns])
- **Container runtime** → stiva (consumes agnosys[luks,dmverity])
- **Rendering pipeline** → soorat (consumes agnosys[drm])

## Phase 1 — Core (V0.1) ✅

- [x] `error` — SysError with errno mapping, Cow<'static, str>, Result type alias
- [x] `syscall` — Low-level syscall wrappers, SysInfo, checked_syscall
- [x] `logging` — AGNOSYS_LOG env var, tracing-subscriber init
- [x] Feature gate infrastructure — each module behind its own feature flag
- [x] `#[non_exhaustive]` on all public enums
- [x] `#[must_use]` on all pure functions
- [x] `tracing` instrumentation on all kernel operations
- [x] Send+Sync compile-time assertions on all public types
- [x] Tests + benchmarks (86 tests, 27 benchmarks at phase completion)
- [x] CI/CD pipeline (ci.yml, release.yml, deny.toml, codecov.yml)
- [x] Community files (SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md)

## Phase 2 — Security Modules (V0.23) ✅

- [x] `landlock` — Filesystem/network sandboxing via Landlock LSM (ABI v1-v5)
- [x] `seccomp` — BPF syscall filter builder, allowlist approach, architecture validation
- [x] `mac` — LSM detection (SELinux/AppArmor/Smack/9 others), security contexts, labels
- [x] `audit` — Kernel audit netlink socket, status queries, log parsing, line parser
- [x] `pam` — PAM service inspection, stack parsing, config analysis

Consumer validation: **kavach** ✅, **aegis** ✅, **shakti** ✅, **libro** ✅

## Phase 3 — Storage, Integrity & Trust (V0.23) ✅

- [x] `luks` — LUKS header parsing, key slot inspection, dm-crypt volume management
- [x] `dmverity` — Verity superblock parsing, root hash validation (constant-time), volume status
- [x] `ima` — IMA runtime measurements, policy parsing, violation count
- [x] `certpin` — SHA-256 pin computation (zero-dep), base64, SPKI extraction, PinSet validation
- [ ] `tpm` — TPM2 context, PCR read/extend, quote, seal/unseal
- [ ] `secureboot` — Secure Boot state detection, EFI variable reading
- [ ] `fuse` — FUSE session setup, request dispatch, reply

Consumer validation: **stiva** ✅, **sigil** partial (certpin+ima done, tpm+secureboot pending)

## Phase 4 — System Services & Device

- [x] `agent` — Process naming, OOM score, cgroup inspection, capabilities, systemd watchdog
- [x] `netns` — Network namespace create, enter, list, current ns fd/inode
- [x] `udev` — Pure sysfs/netlink device enumeration, hotplug monitoring, uevent parsing
- [x] `drm` — DRM/KMS device enumeration, driver version, capabilities, mode resources, connectors
- [ ] `journald` — Systemd journal write, structured log entry, cursor-based reading
- [ ] `bootloader` — Bootloader detection, entry management, default setting
- [ ] `update` — Atomic update primitives (rename, sync, pivot)

Consumer validation: **daimon** ✅, **nein** ✅, **yukti** ✅, **soorat** ✅, **argonaut** pending, **ark** partial

## Remaining (8 modules)

| Module | Consumer | Status | Complexity |
|--------|----------|--------|------------|
| `tpm` | sigil | Not started | High — TPM2 command set |
| `secureboot` | sigil | Not started | Low — EFI variable reading |
| `journald` | argonaut | Not started | Low — journal socket write |
| `bootloader` | argonaut | Not started | Medium — bootctl/EFI vars |
| `fuse` | ark | Not started | High — FUSE protocol |
| `update` | ark | Not started | Medium — atomic fs ops |

## V1.0 — Stable API

- [ ] All 22 modules implemented
- [ ] API stabilization across all modules
- [ ] Comprehensive benchmarks (currently 100 benchmarks across 14 modules)
- [ ] Documentation with security considerations per module
- [ ] All consumers migrated from monolith `agnos-sys` to crates.io `agnosys`
- [ ] Monolith `userland/agnos-sys/` deprecated (thin wrapper that re-exports agnosys)
- [ ] Published to crates.io

## Progress

| Metric | Count |
|--------|-------|
| Modules implemented | **14 / 22** (64%) |
| Consumer crates unblocked | **10 / 12** (sigil partial, argonaut pending, ark partial) |
| Unit tests | 394 |
| Integration tests | 51 |
| Doc-tests | 13 |
| Total tests | **458** |
| Benchmarks | **100** |
| Version | 0.23.3 |

## Migration Strategy

The extraction is non-breaking. The monolith `agnos-sys` becomes a thin wrapper:

```rust
// userland/agnos-sys/src/lib.rs (after extraction)
// Thin re-export — consumers migrate to agnosys directly over time
pub use agnosys::*;
```

Each phase delivers independently. Consumers can migrate one module at a time:

```toml
# Before (depends on entire monolith)
agnos-sys = { path = "../agnos-sys" }

# After (only pulls what's needed)
agnosys = { version = "0.23", features = ["landlock", "seccomp"] }
```

## Consumer Map

| Consumer | Features needed | Status |
|----------|----------------|--------|
| kavach | landlock, seccomp | ✅ Ready |
| aegis | mac | ✅ Ready |
| shakti | pam | ✅ Ready |
| libro | audit | ✅ Ready |
| stiva | luks, dmverity | ✅ Ready |
| sigil | tpm, ima, secureboot, certpin | 🔶 2/4 done (certpin, ima) |
| ark | fuse, update | ⬜ Pending |
| argonaut | journald, bootloader | ⬜ Pending |
| daimon | seccomp, certpin, agent | ✅ Ready |
| nein | netns | ✅ Ready |
| yukti | udev | ✅ Ready |
| soorat | drm | ✅ Ready |
| hoosh | certpin | ✅ Ready |
