# Agnosys — Live State

> Volatile snapshot. Refreshed every release. Durable rules live in [`CLAUDE.md`](../../CLAUDE.md). Historical release narrative is in [`CHANGELOG.md`](../../CHANGELOG.md). Future work is in [`roadmap.md`](roadmap.md).

**Last refresh:** 2026-04-26 (1.0.2)

## Version & Toolchain

| Item | Value |
|---|---|
| `VERSION` | **1.0.2** |
| `cyrius.cyml [package].cyrius` | **5.7.8** |
| Min Cyrius (consumer) | 5.7.8 |
| Last cyrius bump | 5.7.6 → 5.7.8 (1.0.2) |

## Build Metrics

| Metric | Value | Notes |
|---|---|---|
| Binary size (DCE) | **73,144 B** | down from 306,344 B at 1.0.0 — `[build] modules` → `[lib] modules` refactor |
| `dist/agnosys.cyr` size | 314,910 B | bundled distlib (full library) |
| Fn-table utilization | 289 / 4,096 (7%) | from `cyrius capacity --check` |
| Var-table | 302 / 8,192 | |
| Fixup-table | 724 / 262,144 | |
| String-data | 1,376 / 262,144 | |
| Code-size | 67,552 / 1,048,576 | |
| Compile time | ~460 ms | recorded at 1.0.0 closeout |

## Module Count

**20 modules implemented (100%)** — surface frozen at 1.0.

| Module | Public fns | Description |
|---|---|---|
| error | (snapshot) | SysError types, errno mapping, Result helpers |
| syscall | (snapshot) | `agnosys_*` getpid/uid/hostname/sysinfo wrappers |
| logging | (snapshot) | `log_*` level control via `AGNOSYS_LOG` |
| security | (snapshot) | Landlock, seccomp BPF, namespace creation |
| mac | (snapshot) | SELinux/AppArmor detection and context management |
| audit | (snapshot) | Kernel audit netlink socket, rule management |
| pam | (snapshot) | PAM service inspection, passwd/who parsing |
| journald | (snapshot) | Systemd journal send/query |
| luks | (snapshot) | LUKS2 encrypted volume management |
| dmverity | (snapshot) | dm-verity integrity verification |
| ima | (snapshot) | IMA measurements, policy rules |
| tpm | (snapshot) | TPM2 device, PCR reading, seal/unseal |
| certpin | (snapshot) | Certificate pin validation, SPKI computation |
| secureboot | (snapshot) | Secure Boot EFI variable reading |
| udev | (snapshot) | Device enumeration via udevadm |
| drm | (snapshot) | DRM device enumeration, ioctl version/caps |
| netns | (snapshot) | Network namespace create/destroy, veth, nftables |
| bootloader | (snapshot) | systemd-boot/GRUB detection, cmdline validation |
| update | (snapshot) | Atomic file ops, version comparison |
| fuse | (snapshot) | FUSE mount parsing, mount/unmount |

Per-module public-fn arity is tracked in [`api-surface-1.0.snapshot`](api-surface-1.0.snapshot) (machine-checkable; CI-gated via `scripts/check-api-surface.sh`). 556 public fns total.

## Test / Fuzz / Bench Coverage

| Category | Count | Where |
|---|---|---|
| Integration tests passed | **234 / 234** | `cyrius test` |
| Integration assertions | 257 | `tests/tcyr/test_integration.tcyr` (audit-regression block added 1.0.2) |
| Fuzz harnesses | 6 | `fuzz/audit_nlmsg.fcyr`, `fuzz/audit_reply.fcyr`, `fuzz/certpin_pin.fcyr`, `fuzz/journald_filter.fcyr`, `fuzz/luks_cipher.fcyr`, `fuzz/pam_config.fcyr` |
| Benchmarks | 30 (11 groups) | `tests/bcyr/bench_all.bcyr` |
| Bench file (compare) | 1 | `tests/bcyr/bench_compare.bcyr` (Cyrius vs Rust port baseline) |

## Local Audit Gates (`scripts/audit.sh`)

10 gates, all green at 1.0.2: syntax → API surface → capacity → build → smoke → tests → lint → vet → fuzz → benchmarks. Mirrors CI.

## CI Workflow Status

- `.github/workflows/ci.yml` — yukti-pattern: tarball install via cyrius.cyml-derived version, deps + verify-hashes, fmt-check, lint warn-fail, vet, dist staleness gate, DCE build, ELF magic, aarch64 best-effort cross, smoke, integration, fuzz, bench, security scan, docs check.
- `.github/workflows/release.yml` — accepts `vX.Y.Z` and `X.Y.Z`; verify-version, install toolchain, deps + verify, DCE build, aarch64 best-effort, tests, fuzz, regenerate dist, archive (source tar + bundled `.cyr` + prebuilt x86_64 + aarch64 binaries + cyrius.lock + SHA256SUMS).

## Dependencies

- **Runtime**: 0
- **Stdlib via `[deps] stdlib`**: `syscalls`, `string`, `alloc`, `fmt`, `vec`, `str`, `io` (7)
- **Git-pinned**: 0 (no `[deps.<name>]` stanzas; no `cyrius.lock` needed today)
- **Vendored stdlib refresh** (last): 2026-04-26 to cyrius 5.7.6 snapshot (`alloc.cyr`, `io.cyr`, `string.cyr`, `syscalls.cyr` — 5.5.x split into per-OS dispatch). 5.7.7 and 5.7.8 introduced no stdlib changes affecting agnosys's `[deps] stdlib = [syscalls, string, alloc, fmt, vec, str, io]` set; `cyrius deps` is a no-op against the existing vendor.

## Consumer Status

13 / 13 consumer crates unblocked at 1.0. Each consumer pulls only the modules it needs.

| Consumer | Modules | Status |
|---|---|---|
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

Automated consumer-integration CI is roadmap Phase 8 (item 5).

## Verification Hosts

- **Linux x86_64** — primary; `cyrius build` + `cyrius test` self-host.
- **Linux aarch64** — best-effort; CI cross-builds when `cc5_aarch64` is bundled in the toolchain release.
- **macOS / Windows** — not supported. Most modules are kernel-Linux-only by definition (audit netlink, PAM, journald, dm-verity, IMA, secureboot). See roadmap Phase 8 (item 3).

## Recent Releases

| Tag | Date | Headline |
|---|---|---|
| **1.0.2** | 2026-04-26 | P(-1) sweep follow-up: audit-regression integration tests, three ADRs, SECURITY-NOTES F-4/F-5 entries, bench-history row for 1.0.1; toolchain pin 5.7.6 → 5.7.8 (skipping 5.7.7 — `cyrius check` regression, fixed in 5.7.8) |
| 1.0.1 | 2026-04-26 | Toolchain bump 5.2.0 → 5.7.6; CI ported to yukti pattern; binary size 76% reduction via `[lib]`-modules refactor; audit findings F-1..F-6 fixed |
| 1.0.0 | 2026-04-17 | API freeze. 139 renames, 20 modules ported, 556 public fns, 220 integration assertions, 30 benchmarks |
| 0.97.1 | 2026-04 (pre-1.0) | Rust source deleted, Cyrius port complete |

Full narrative in [`CHANGELOG.md`](../../CHANGELOG.md).

## In-Flight Slots

None. Post-1.0.2 backlog is in [`roadmap.md`](roadmap.md) Phase 8.

## Last Security Audit

[`docs/audit/2026-04-26-audit.md`](../audit/2026-04-26-audit.md) — P(-1) hardening pass at 1.0.1.
