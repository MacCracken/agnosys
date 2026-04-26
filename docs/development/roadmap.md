# Agnosys Roadmap

> **Agnosys** is the AGNOS kernel interface library. Cyrius bindings for Linux
> kernel syscalls and security primitives. Consumers include only the modules
> they need.
>
> Genesis repo: [agnosticos](https://github.com/MacCracken/agnosticos)
>
> **Live state** (versions, sizes, counts, in-flight) → [`state.md`](state.md).
> Roadmap is durable: completed phases stay; future phases get appended.

## Scope

Agnosys owns **Cyrius bindings to Linux kernel interfaces**. It does NOT own:
- **Higher-level device abstraction** → yukti (consumes agnosys[udev])
- **Sandbox policy engine** → kavach (consumes agnosys[landlock,seccomp])
- **Firewall rules** → nein (consumes agnosys[netns])
- **Container runtime** → stiva (consumes agnosys[luks,dmverity])
- **Rendering pipeline** → soorat (consumes agnosys[drm])

## Phase 1 — Core (V0.1) ✅

- [x] `error` — SysError types, errno mapping, Result helpers
- [x] `syscall` — getpid/uid/hostname/sysinfo wrappers
- [x] `logging` — Log level control via AGNOSYS_LOG env var
- [x] CI/CD pipeline (ci.yml, release.yml)
- [x] Community files (SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md)

## Phase 2 — Security Modules ✅

- [x] `security` — Landlock filesystem sandboxing, seccomp-BPF syscall filtering, namespace creation
- [x] `mac` — SELinux/AppArmor detection and context management
- [x] `audit` — Kernel audit netlink socket, rule management
- [x] `pam` — PAM service inspection, passwd/who parsing

Consumer validation: **kavach**, **aegis**, **shakti**, **libro**

## Phase 3 — Storage, Integrity & Trust ✅

- [x] `luks` — LUKS2 encrypted volume management
- [x] `dmverity` — dm-verity integrity verification
- [x] `ima` — IMA measurements, policy rules
- [x] `certpin` — Certificate pin validation, SPKI computation
- [x] `tpm` — TPM2 device, PCR reading, seal/unseal
- [x] `secureboot` — Secure Boot EFI variable reading
- [x] `fuse` — FUSE mount parsing, mount/unmount

Consumer validation: **stiva**, **sigil**, **ark**

## Phase 4 — System Services & Device ✅

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

## V1.0 — Stable API ✅

Original checklist — closed:

- [x] Consumer migration from monolith `agnos-sys` — **tracked on consumer crates** (sigil, kavach, daimon, argonaut, stiva, nein, ...). 13/13 consumers unblocked
- [x] Quality gate in CI — `cyrius lint`, `cyrius vet`, `cyrius capacity --check`, API surface check, fuzz, integration tests. Bundled as `scripts/audit.sh` for local one-shot runs
- [x] Fuzz testing for parsers — `fuzz/certpin_pin.fcyr`, `fuzz/audit_nlmsg.fcyr`, `fuzz/pam_config.fcyr`. All run under `cyrius build` + 10s timeout at 500 iters in CI
- [x] Additional edge-case tests from audit observations — `test_edge_cases()` in `tests/tcyr/test_integration.tcyr` adds 25 boundary assertions

Freeze prerequisites added pre-1.0 — closed:

- [x] API surface snapshot — `docs/development/api-surface-1.0.md` (556 public fns, 20 modules, 0 outliers)
- [x] API surface regression check — `scripts/check-api-surface.sh`; fails on any public fn removed or arity-changed vs. `api-surface-1.0.snapshot`. Wired into CI
- [x] Capacity baseline — `docs/development/capacity-baseline.md`
- [x] README consumer quickstart — per-module and full-bundle patterns documented
- [x] Full naming sweep — 139 public fns renamed so every module carries its prefix. Zero remaining prefix outliers
- [x] Local audit runner — `scripts/audit.sh` (10 gates, mirrors CI)

## V1.0.1 — Toolchain Alignment & CI Hardening ✅ (2026-04-26)

- [x] Cyrius pin 5.2.0 → 5.7.6
- [x] `[build] modules` → `[lib] modules` refactor (binary 306,344 → 73,144 B, −76%)
- [x] CI/release workflows ported to yukti pattern (tarball install, deps verify, fmt-check, lint warn-fail, vet, dist gate, DCE, aarch64 best-effort, tag accepts both `vX.Y.Z` and `X.Y.Z`)
- [x] CLAUDE.md restructured to template (durable rules only); volatile state moved to `docs/development/state.md`
- [x] `docs/development/state.md` created
- [x] P(-1) Scaffold Hardening pass; security audit at `docs/audit/2026-04-26-audit.md`

## Phase 8 — Post-1.0 Backlog (V1.1.0+)

Open items that don't block 1.x consumer adoption but tighten the platform.

### 8.1 — `#derive(accessors)` adoption (post-1.0 follow-up; CLAUDE.md-flagged)

- [ ] Migrate all 20 modules' struct accessors from `store64`/`load64` at fixed offsets to `#derive(accessors)` syntax.
- [ ] Update `docs/development/api-surface-1.0.snapshot` if accessor naming changes (likely additive — add to snapshot, no breakage).
- [ ] Each module's struct migration ships as its own patch with bench parity proof.

**Rationale:** removes hand-written offset arithmetic; reduces off-by-one risk; readable. Cyrius 5.x supports it. Mechanical but invasive (touches every struct), so kept off the 1.0 freeze.

### 8.2 — Multi-profile `cyrius distlib` (yukti pattern)

- [ ] Add `[lib.security]` (security + mac + audit + pam) → `dist/agnosys-security.cyr`
- [ ] Add `[lib.storage]` (luks + dmverity + fuse) → `dist/agnosys-storage.cyr`
- [ ] Add `[lib.trust]` (tpm + ima + secureboot + certpin) → `dist/agnosys-trust.cyr`
- [ ] Add `[lib.system]` (journald + bootloader + udev + drm + netns + update) → `dist/agnosys-system.cyr`
- [ ] Add `[lib.core]` (error + syscall + logging) → `dist/agnosys-core.cyr` — kernel-safe subset for AGNOS-kernel direct consumption (no alloc, no syscall, pure enums/types)
- [ ] CI dist-staleness gate extended to all five profiles
- [ ] Release archive ships every profile bundle alongside the full `dist/agnosys.cyr`

**Rationale:** kavach pulls 314 KB today for what it actually uses (~50 KB security surface). Profile bundles cut consumer binary size and clarify the agnosys → consumer wiring.

### 8.3 — Platform abstraction (Linux-only declaration + portability hooks)

- [ ] Per-module `#ifplat` guards declaring Linux-only modules (audit, pam, journald, dmverity, ima, secureboot — kernel-Linux-by-definition)
- [ ] Cross-platform candidates declared as such: `error`, `syscall` (already split via `lib/syscalls_*.cyr` in cyrius 5.5.x), `logging`, `certpin` (pure crypto, no syscalls)
- [ ] `docs/architecture/NNN-platform-matrix.md` documenting the matrix
- [ ] Track upstream cyrius macOS/Windows port progress; revisit when consumer demand exists

**Rationale:** cyrius 5.5.16 added macOS dispatch in `lib/syscalls.cyr`; 5.x is heading cross-platform. Most agnosys modules are intrinsically Linux (audit netlink frames, PAM config, dm-verity ioctls), but declaring the matrix prevents accidental Linux-isms in the few modules that *could* be portable.

### 8.4 — Consumer integration CI

- [ ] Nightly GitHub Actions job per consumer: clone, vendor agnosys main, build, run consumer's tests
- [ ] Failures open an issue tagged `consumer-break` (linked to consumer + agnosys commit)
- [ ] 13 consumers in scope (see `state.md` consumer table); start with sigil + kavach (highest module surface), expand

**Rationale:** v1.0 deferred this to "tracked on consumer crates" — i.e., manual. Automated drift detection means an agnosys patch that breaks sigil's TPM caller fails before that consumer notices.

### 8.5 — Capability map per public fn (machine-checkable)

- [ ] `docs/development/capability-map.md` listing every public fn → set of syscalls it can invoke
- [ ] `scripts/check-capabilities.sh` parses module source, derives the actual syscall set, diffs against the doc — fails CI on drift
- [ ] Consumers can map fn → syscall → seccomp filter without reading source

**Rationale:** `docs/SECURITY-NOTES.md` covers per-module concerns at prose level. A machine-checkable surface gives kavach/daimon a programmatic basis for seccomp policy generation.

### 8.6 — Refresh `docs/development/state.md` cadence

- [x] state.md created at 1.0.1
- [ ] Release post-hook auto-bumps state.md (version, binary size, test counts)
- [ ] CI gate that fails the release if state.md `Last refresh` doesn't match the tag

**Rationale:** template's "release post-hook bumps state.md. If the hook doesn't, fix the hook — don't hand-maintain state."

### Audit-derived fixes — all landed in 1.0.1

The 2026-04-26 P(-1) audit's actionable findings (F-1 HIGH, F-2 MEDIUM, F-3/F-4/F-5 LOW, F-6 DiD) all shipped in 1.0.1 with fuzz coverage. See [`docs/audit/2026-04-26-audit.md`](../audit/2026-04-26-audit.md) and CHANGELOG. Phase 8 below covers only items that are NOT security-blocking and were never gated on this release.

## V1.0+ Verification

- [ ] Once 8.1 / 8.2 land, cut **1.1.0** (bundle profiles + derive-accessors).
- [ ] 8.3 / 8.4 / 8.5 may ship in any order across 1.1.x / 1.2.x.
- [ ] 8.6 lands when the agnosticos meta-tooling supports it (cross-repo concern).

## Consumer Map (durable)

Volatile per-consumer status lives in [`state.md`](state.md). The mapping itself is durable:

| Consumer | Modules needed |
|----------|---------------|
| kavach | security (landlock, seccomp) |
| aegis | mac |
| shakti | pam |
| libro | audit |
| stiva | luks, dmverity |
| sigil | tpm, ima, secureboot, certpin |
| ark | fuse, update |
| argonaut | journald, bootloader |
| daimon | security (seccomp), certpin |
| nein | netns |
| yukti | udev |
| soorat | drm |
| hoosh | certpin |
