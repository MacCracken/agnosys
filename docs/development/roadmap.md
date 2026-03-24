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

## Phase 1 — Extract Core (V0.1)

Extract the foundational modules that every consumer needs:

- [ ] `error` — SysError with errno mapping, Result type alias
- [ ] `syscall` — Low-level syscall wrappers (clone, mount, pivot_root, etc.)
- [ ] Feature gate infrastructure — each module behind its own feature flag
- [ ] `#[non_exhaustive]` on all public enums
- [ ] `tracing` instrumentation on all kernel operations
- [ ] Tests extracted from monolith + new edge case tests
- [ ] Benchmarks for hot-path syscall wrappers
- [ ] CI/CD pipeline (ci.yml, release.yml)

## Phase 2 — Security Modules (V0.2)

The modules kavach, daimon, and aegis depend on:

- [ ] `landlock` — Filesystem access control (ruleset create, add rule, enforce)
- [ ] `seccomp` — BPF syscall filter (compile, load, enforce)
- [ ] `mac` — Mandatory Access Control (AppArmor/SELinux abstraction)
- [ ] `audit` — Kernel audit subsystem (audit_open, audit_add_rule, read events)
- [ ] `pam` — PAM conversation, authenticate, session management

Consumer validation: kavach and aegis depend on this phase.

## Phase 3 — Storage & Integrity (V0.3)

The modules stiva, sigil, and ark depend on:

- [ ] `luks` — LUKS header parsing, key slot management, dm-crypt setup
- [ ] `dmverity` — dm-verity table creation, verification, activation
- [ ] `ima` — IMA policy loading, measurement list reading, appraisal
- [ ] `tpm` — TPM2 context, PCR read/extend, quote, seal/unseal
- [ ] `certpin` — SPKI pin computation, pin verification, certificate chain
- [ ] `secureboot` — Secure Boot state detection, MOK management
- [ ] `fuse` — FUSE session setup, request dispatch, reply

Consumer validation: stiva and sigil depend on this phase.

## Phase 4 — System Services (V0.4)

The modules argonaut, ark, and daimon depend on:

- [ ] `journald` — Journal fd, structured log entry, cursor-based reading
- [ ] `bootloader` — Bootloader detection, entry management, default setting
- [ ] `update` — Atomic update primitives (rename, sync, pivot)
- [ ] `agent` — Agent process management (clone, namespace setup, cgroup)
- [ ] `netns` — Network namespace create, enter, veth pair setup

Consumer validation: argonaut and nein depend on this phase.

## Phase 5 — Device & Rendering (V0.5)

The modules yukti and soorat depend on:

- [ ] `udev` — Netlink socket, uevent parsing, device enumeration from sysfs
- [ ] `drm` — DRM/KMS mode setting, buffer management, display enumeration (new)

Consumer validation: yukti and soorat depend on this phase.

## V1.0 — Stable API

- [ ] API stabilization across all modules
- [ ] Comprehensive benchmarks (syscall overhead, ioctl latency)
- [ ] Documentation with security considerations per module
- [ ] All consumers migrated from monolith `agnos-sys` to crates.io `agnosys`
- [ ] Monolith `userland/agnos-sys/` deprecated (thin wrapper that re-exports agnosys)
- [ ] Published to crates.io

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
agnosys = { version = "0.3", features = ["landlock", "seccomp"] }
```

## Consumer Map

| Consumer | Features needed | Phase |
|----------|----------------|-------|
| kavach | landlock, seccomp | 2 |
| aegis | mac, audit | 2 |
| shakti | pam | 2 |
| stiva | luks, dmverity | 3 |
| sigil | tpm, ima, secureboot, certpin | 3 |
| ark | fuse, update | 3 |
| libro | audit | 2 |
| argonaut | journald, bootloader | 4 |
| daimon | seccomp, certpin, agent | 2-4 |
| nein | netns | 4 |
| yukti | udev | 5 |
| soorat | drm | 5 |
| hoosh | certpin | 3 |
