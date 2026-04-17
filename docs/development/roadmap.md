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

## Phase 5 — Cyrius Port (V0.60.0) ✅

## Phase 6 — Compiler Upgrade & Optimization (V0.90.0) ✅

## Phase 7 — Scaffold Hardening & Audit (V0.95.0) ✅

- [x] `cyrius audit` clean pass (24/24: compile, test, lint, format)
- [x] 197 integration assertions across all 20 modules
- [x] 5 bugs fixed (2 critical, 1 high, 2 medium)
- [x] Cyrius 2.4.0 upgrade with `cyrfmt`/`cyrlint`
- [x] Architecture overview documentation
- [x] Security notes rewritten for Cyrius

## V1.0 — Stable API

Original checklist:

- [ ] Consumer migration from monolith `agnos-sys` — **tracked on consumer crates (sigil, kavach, daimon, argonaut, stiva, nein, ...), not agnosys-side work**
- [x] Quality gate in CI — `cyrius lint`, `cyrius vet`, `cyrius capacity --check`, API surface check, fuzz, integration tests. Bundled as `scripts/audit.sh` for local one-shot runs
- [x] Fuzz testing for parsers — `fuzz/certpin_pin.fcyr`, `fuzz/audit_nlmsg.fcyr`, `fuzz/pam_config.fcyr`. All run under `cyrius build` + 10s timeout at 500 iters in CI
- [x] Additional edge-case tests from audit observations — `test_edge_cases()` in `tests/tcyr/test_integration.tcyr` adds 25 boundary assertions (version year/month bounds, username length+charset, cmdline danger tokens, pin length boundaries, errno mapping)

Freeze prerequisites added at 0.98.0 / Unreleased:

- [x] API surface snapshot — `docs/development/api-surface-1.0.md` (556 public fns, 20 modules, 0 outliers)
- [x] API surface regression check — `scripts/check-api-surface.sh`; fails on any public fn removed or arity-changed vs. `api-surface-1.0.snapshot`. Wired into CI
- [x] Capacity baseline — `docs/development/capacity-baseline.md`
- [x] README consumer quickstart — per-module and full-bundle patterns documented
- [x] Full naming sweep — 139 public fns renamed so every module carries its prefix. Zero remaining prefix outliers. Breaking change landed once pre-1.0 to avoid v2 churn.
- [x] Local audit runner — `scripts/audit.sh` (10 gates, mirrors CI)

Remaining before cutting 1.0 tag: none on agnosys' side. All items above are live on `main` via `[Unreleased]`. Consumer migration proceeds on consumer repos; once enough consumers report green against Unreleased, the tag follows.

## Progress

| Metric | Count |
|--------|-------|
| Modules implemented | **20 / 20** (100%) |
| Consumer crates unblocked | **13 / 13** (100%) |
| Source lines (src/) | 9 884 |
| Stdlib lines (lib/) | ~4 000 |
| Public functions | 556 |
| Integration assertions | 220 |
| Benchmarks | 30 |
| Binary size | 291 KB (core demo) |
| Compile time | ~460 ms |
| Dependencies | 0 |
| Compiler | Cyrius 5.2.0 |
| Version | 0.98.0 |

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
