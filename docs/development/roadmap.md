# Agnosys Roadmap

> **Agnosys** is the AGNOS kernel interface library. Cyrius bindings for Linux
> kernel syscalls and security primitives. Consumers include only the modules
> they need.
>
> Genesis repo: [agnosticos](https://github.com/MacCracken/agnosticos)

## Scope

Agnosys owns **Cyrius bindings to Linux kernel interfaces**. It does NOT own:
- **Higher-level device abstraction** → yukti (consumes agnosys[udev])
- **Sandbox policy engine** → kavach (consumes agnosys[landlock,seccomp])
- **Firewall rules** → nein (consumes agnosys[netns])
- **Container runtime** → stiva (consumes agnosys[luks,dmverity])
- **Rendering pipeline** → soorat (consumes agnosys[drm])

## Phase 1 — Core (V0.1)

- [x] `error` — SysError types, errno mapping, Result helpers
- [x] `syscall` — getpid/uid/hostname/sysinfo wrappers
- [x] `logging` — Log level control via AGNOSYS_LOG env var
- [x] CI/CD pipeline (ci.yml, release.yml)
- [x] Community files (SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md)

## Phase 2 — Security Modules

- [x] `security` — Landlock filesystem sandboxing, seccomp-BPF syscall filtering, namespace creation
- [x] `mac` — SELinux/AppArmor detection and context management
- [x] `audit` — Kernel audit netlink socket, rule management
- [x] `pam` — PAM service inspection, passwd/who parsing

Consumer validation: **kavach**, **aegis**, **shakti**, **libro**

## Phase 3 — Storage, Integrity & Trust

- [x] `luks` — LUKS2 encrypted volume management
- [x] `dmverity` — dm-verity integrity verification
- [x] `ima` — IMA measurements, policy rules
- [x] `certpin` — Certificate pin validation, SPKI computation
- [x] `tpm` — TPM2 device, PCR reading, seal/unseal
- [x] `secureboot` — Secure Boot EFI variable reading
- [x] `fuse` — FUSE mount parsing, mount/unmount

Consumer validation: **stiva**, **sigil**, **ark**

## Phase 4 — System Services & Device

- [x] ~~`agent`~~ — *(moved to agnosai crate)*
- [x] `netns` — Network namespace create/destroy, veth, nftables
- [x] `udev` — Device enumeration via udevadm
- [x] `drm` — DRM device enumeration, ioctl version/caps
- [x] `journald` — Systemd journal send/query
- [x] `bootloader` — systemd-boot/GRUB detection, cmdline validation
- [x] `update` — Atomic file ops, version comparison

Consumer validation: **daimon**, **nein**, **yukti**, **soorat**, **argonaut**, **ark**

## Phase 5 — Cyrius Port (V0.60.0)

- [x] **Full port from Rust to Cyrius** — 29,257 lines Rust → ~8,500 lines Cyrius
- [x] Zero dependencies, native ELF binary
- [x] Dual-encoding errors: packed (hot path) + heap (diagnostics)
- [x] Caller-provided stack buffers for syscall wrappers
- [x] Security hardening across all modules
- [x] Benchmark parity with Rust on syscall paths

## Phase 6 — Compiler Upgrade & Optimization (V0.90.0)

- [x] Cyrius 1.6.1 → 1.9.2 upgrade across 13 compiler releases
- [x] Return comparison simplification (~25 patterns across 16 files)
- [x] `syscall_name_to_nr`: O(n) → O(1) hashmap (23x faster miss case)
- [x] `bootloader_validate_kernel_cmdline`: single-pass tokenizer (1.8x faster)
- [x] `mac_default_profile`: stack-alloc strings (13 → 2 heap allocs)
- [x] `create_basic_seccomp_filter`: unrolled BPF writes
- [x] Integration test suite (45 assertions, 12 modules)
- [x] Batch-amortized benchmark suite (30 benchmarks, 11 groups)
- [x] Include-once module independence (`cyrb check` on all src/*.cyr)

## V1.0 — Stable API (Next)

- [x] All 20 modules implemented (agent/llm moved to agnosai/hoosh)
- [x] All 13 consumers unblocked
- [x] All modules pass `cyrb check` independently
- [ ] All consumers migrated from monolith `agnos-sys` to `include "src/module.cyr"`
- [ ] Monolith `userland/agnos-sys/` deprecated
- [ ] Expanded test coverage (target: 100+ integration assertions)
- [ ] `cyrb audit` clean pass
- [ ] `cyrb fmt --check` on all files
- [ ] Architecture overview documentation

## Progress

| Metric | Count |
|--------|-------|
| Modules implemented | **20 / 20** (100%) |
| Consumer crates unblocked | **13 / 13** (100%) |
| Source lines (src/) | 8,672 |
| Stdlib lines (lib/) | 3,562 |
| Integration assertions | 45 |
| Benchmarks | 30 |
| Binary size | 52KB |
| Compile time | 34ms |
| Dependencies | 0 |
| Compiler | Cyrius 1.9.2 |
| Version | 0.90.0 |

## Consumer Map

| Consumer | Modules needed | Status |
|----------|---------------|--------|
| kavach | security (landlock, seccomp) | Ready |
| aegis | mac | Ready |
| shakti | pam | Ready |
| libro | audit | Ready |
| stiva | luks, dmverity | Ready |
| sigil | tpm, ima, secureboot, certpin | Ready |
| ark | fuse, update | Ready |
| argonaut | journald, bootloader | Ready |
| daimon | security (seccomp), certpin | Ready |
| nein | netns | Ready |
| yukti | udev | Ready |
| soorat | drm | Ready |
| hoosh | certpin | Ready |
