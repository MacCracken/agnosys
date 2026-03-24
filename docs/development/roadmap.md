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
- [x] CI/CD pipeline (ci.yml, release.yml, deny.toml, codecov.yml)
- [x] Community files (SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md)

## Phase 2 — Security Modules ✅

- [x] `landlock` — Filesystem/network sandboxing via Landlock LSM (ABI v1-v5)
- [x] `seccomp` — BPF syscall filter builder, allowlist approach, architecture validation
- [x] `mac` — LSM detection (SELinux/AppArmor/Smack/9 others), security contexts, labels
- [x] `audit` — Kernel audit netlink socket, status queries, log parsing, line parser
- [x] `pam` — PAM service inspection, stack parsing, config analysis

Consumer validation: **kavach** ✅, **aegis** ✅, **shakti** ✅, **libro** ✅

## Phase 3 — Storage, Integrity & Trust ✅

- [x] `luks` — LUKS header parsing, key slot inspection, dm-crypt volume management
- [x] `dmverity` — Verity superblock parsing, root hash validation (constant-time), volume status
- [x] `ima` — IMA runtime measurements, policy parsing, violation count
- [x] `certpin` — SHA-256 pin computation (zero-dep), base64, SPKI extraction, PinSet validation
- [x] `tpm` — TPM2 device detection, PCR bank reading, capabilities, event log access
- [x] `secureboot` — Secure Boot state, EFI variable reading, PK/KEK/db/dbx key databases
- [x] `fuse` — FUSE protocol over /dev/fuse, request/reply, mount listing

Consumer validation: **stiva** ✅, **sigil** ✅, **ark** ✅ (partial — fuse done)

## Phase 4 — System Services & Device ✅

- [x] `agent` — Process naming, OOM score, cgroup inspection, capabilities, systemd watchdog
- [x] `netns` — Network namespace create, enter, list, current ns fd/inode
- [x] `udev` — Pure sysfs/netlink device enumeration, hotplug monitoring, uevent parsing
- [x] `drm` — DRM/KMS device enumeration, driver version, capabilities, mode resources, connectors
- [x] `journald` — Structured journal log sending, journal file listing, disk usage
- [x] `bootloader` — systemd-boot/GRUB detection, boot entry parsing, kernel listing
- [x] `update` — Atomic write/copy/swap, fsync, directory sync, renameat2(RENAME_EXCHANGE)

Consumer validation: **daimon** ✅, **nein** ✅, **yukti** ✅, **soorat** ✅, **argonaut** ✅, **ark** ✅

## All Modules Complete ✅

All 22 modules implemented. All 13 consumers unblocked.

## V1.0 — Stable API (Next)

- [x] All 22 modules implemented
- [ ] API stabilization review — freeze public API signatures
- [ ] Comprehensive documentation with security considerations per module
- [ ] All consumers migrated from monolith `agnos-sys` to path dependency on `agnosys`
- [ ] Monolith `userland/agnos-sys/` deprecated (thin wrapper that re-exports agnosys)
- [ ] Fuzz testing for parsers (LUKS header, verity superblock, DER/SPKI, audit lines, PAM config)
- [ ] `cargo-semver-checks` integration for API stability
- [ ] Example programs for each major module
- [ ] Coverage target: 80%+ line coverage via `cargo llvm-cov`

> **Note:** Agnosys is an internal library crate — it is NOT published to crates.io.
> Consumers depend on it via path or git dependency within the AGNOS workspace.

## Progress

| Metric | Count |
|--------|-------|
| Modules implemented | **22 / 22** (100%) |
| Consumer crates unblocked | **13 / 13** (100%) |
| Unit tests | 511 |
| Integration tests | 75 |
| Doc-tests | 19 |
| Total tests | **605** |
| Benchmarks | **132** |
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
agnosys = { path = "../agnosys", features = ["landlock", "seccomp"] }
```

## Consumer Map

| Consumer | Features needed | Status |
|----------|----------------|--------|
| kavach | landlock, seccomp | ✅ Ready |
| aegis | mac | ✅ Ready |
| shakti | pam | ✅ Ready |
| libro | audit | ✅ Ready |
| stiva | luks, dmverity | ✅ Ready |
| sigil | tpm, ima, secureboot, certpin | ✅ Ready |
| ark | fuse, update | ✅ Ready |
| argonaut | journald, bootloader | ✅ Ready |
| daimon | seccomp, certpin, agent | ✅ Ready |
| nein | netns | ✅ Ready |
| yukti | udev | ✅ Ready |
| soorat | drm | ✅ Ready |
| hoosh | certpin | ✅ Ready |
