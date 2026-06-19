# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.4] — 2026-06-19

**Renamed `agnosys` → `agnodrm`; decomposed to the device / DRM model.** The
library narrows from "AGNOS kernel interface" to its device-access core (udev +
DRM/KMS) on a small error + util support layer. Its other subsystems folded to
their proper homes in the agnosys → agnodrm decomposition (see the agnosticos
decomposition plan).

### Breaking
- **Repository + package renamed `agnosys` → `agnodrm`.** The bundle is now
  `dist/agnodrm.cyr` (+ `dist/agnodrm-core.cyr`). GitHub redirects the old repo
  URL, so consumers pinned to existing tags keep resolving until they bump.
- **Removed 15 modules** (moved to their proper homes):
  - trust: `tpm` / `ima` / `secureboot` / `certpin` / `dmverity` / `luks` → **sigil**
  - security: `security` (Landlock/seccomp) / `mac` / `audit` → **kavach**
  - `pam` → **aegis**
  - `logging` → **sakshi**
  - `syscall` / `syscall_arch` / `syscall_x86_64_linux` / `syscall_aarch64_linux`
    → **cyrius** (stdlib `syscalls_*.cyr` is canonical)
- **Profiles**: the `security` / `storage` / `trust` / `system` profile bundles
  were removed with their modules. Only `[lib.core]` (error/util/udev/drm) remains
  alongside the full `dist/agnodrm.cyr`.

### Changed
- **Survivors**: `error`, `util`, `udev`, `drm` (the device-access core) + the
  deferred Linux-eccentric group `journald` / `netns` / `bootloader` / `update` /
  `fuse` (parked here post-v1 — no agnos story yet, revisit then).
- Made the deferred survivors self-contained after the syscall-layer move:
  `journald` inlines its socket-syscall numbers; `util.cyr` provides the two
  wrappers `update.cyr` needs (`agnosys_fsync` / `agnosys_rename`) via
  `UTIL_SYS_*` constants (distinct names to avoid an `lib/syscalls.cyr` collision).
- `main.cyr` rewritten as a device-model build smoke.
- Test suite trimmed to the survivors: `test_integration.tcyr` (22 → 9 module
  tests, 93/0), `bench_all.bcyr` (11 → 6 groups); obsolete fuzzers (pam / audit /
  certpin / luks) + `bench_compare` removed; fuse + journald fuzzers kept.
- CI swept to `agnodrm` + the `core` profile (`ci.yml` / `release.yml`);
  `consumer-integration.yml` paused until downstream consumers rewire.
- api-surface snapshot regenerated (730 → 315 public fns); capability-map
  regenerated. Full `scripts/audit.sh` clean (11/11).

## [1.4.3] — 2026-06-15

**cyrius pin → 6.2.11.**

### Changed
- **cyrius pin `6.2.1` → `6.2.11`**, tracking the 6.2.x maintenance line
  (bug-fix / optimization patches only, no API surface change). Pure toolchain
  refresh — no `src/*.cyr` edits. Validated green from clean (`rm -rf lib build
  && cyrius deps`): DCE build OK (432 unreachable fns NOPed, 124,376 B), all 252
  tests pass, full `scripts/audit.sh` clean (11/11). All 6 `dist/` bundles
  regenerated to stamp the v1.4.3 header (1-line drift each). Bench delta vs
  1.4.2 within run-to-run noise; minor improvements on the constant-time
  comparison paths (`ct_streq` −8/−12%, `is_dangerous_token` −8/−12%).

## [1.4.2] — 2026-06-12

**Daimon-class buffer fix + cyrius pin → 6.2.1.**

### Fixed
- **`update_save_state` `bc_buf` boot-count scratch overflow.** The JSON writer
  formatted `boot_count` (an i64) into a `var bc_buf[8]` = 8-byte buffer via
  `fmt_int_buf`, which needs up to ~20 digits — a boot_count ≥ 8 digits
  (≥ 10,000,000) overran the buffer into adjacent stack/static memory. Bumped to
  `var bc_buf[24]`. Surfaced by the cyrius v6.2.1 address-taken-local-array audit
  (the daimon byte-vs-slot class). Latent (layout-masked) until now. Plain
  byte-buffer resize — toolchain-agnostic.

### Changed
- **cyrius pin `6.1.23` → `6.2.1`**, as part of the ecosystem-wide stdlib pin
  sweep onto the current toolchain. Required dropping the stale **`"json"`**
  entry from `[deps] stdlib`: the standalone `json` stdlib module was carved into
  **bayan** at cyrius 6.1.25, so 6.2.x ships no `lib/json.cyr` and resolving it
  broke `cyrius deps`. agnosys rolls its own JSON helpers (`journald_parse_json`,
  `agnosys_json_emit_cstr_or_null`, `drm_verinfo_to_json`) and calls no stdlib
  `json_*` symbols, so the entry was dead weight. Verified green on 6.2.1:
  `cyrius deps` resolves cleanly, build + tests pass, dist regenerated.

## [1.4.1] — 2026-06-10

**Cyrius pin 6.0.56 → 6.1.23 — first 6.1.x adoption; absorbs the v6.0.64
thread-safe allocator.** The cyrius stdlib `lib/alloc.cyr` gained a process-wide
allocation spinlock + vtable allocator at **v6.0.64** (a CLONE_VM/threads
correctness fix upstream). Adopting it required three agnosys-side changes and
carries a measured allocation-path regression (below). Audit clean (11/11);
252 tests, 7 fuzz harnesses; API surface unchanged (737 public fns, no drift).
Binary **159,392 → 162,784 B (+3,392)** — the new allocator's lock/vtable code.

### Changed

- cyrius pin `6.0.56` → `6.1.23`. `dist/agnosys.cyr` +
  `dist/agnosys-{core,security,storage,trust,system}.cyr` regenerated at v1.4.1.
- **`cyrius.cyml [deps] stdlib` += `"atomic"`.** v6.0.64's `alloc.cyr` does
  `include "lib/atomic.cyr"`; cyrius does **not** resolve transitive stdlib
  includes, so `atomic` must be declared explicitly or `cyrius deps` won't vendor
  it and the build breaks on undefined `atomic_cas`/`atomic_fence`.

### Fixed

- **`tests/tcyr/test_integration.tcyr` SIGSEGV under the new allocator.** The test
  called `alloc_reset(); alloc_init()` between every module group. v6.0.64
  **memoizes** the process default allocator (`_default_allocator`) as a struct
  bump-allocated from the heap; `alloc_reset()` rewinds the bump pointer but does
  **not** clear that cached pointer, so the next allocations overwrite the cached
  allocator's vtable fnptr → `str_builder` growth dispatched a call through string
  data → crash (first hit: `certpin_info_to_json`). Removed the inter-group global
  resets (kept the module-state resets); the functional test allocates trivially
  so heap growth is a non-issue.
- **`tests/bcyr/bench_all.bcyr` + `bench_compare.bcyr`** carried the same
  `alloc_reset()`-between-groups pattern (same dangling-cache hang) **and** called
  `query_sysinfo()` with no argument — the wrapper takes a caller-provided buffer
  (`out`), so the missing arg passed a garbage pointer that corrupted allocator
  state under the new lock (clean exit on the old bump allocator, infinite spin on
  the locked one). Removed the resets; `bench_all` now passes a real `alloc(128)`
  buffer to `query_sysinfo`.

### Performance

The v6.0.64 allocator serializes every `alloc()` behind a CAS spinlock + ACQUIRE/
RELEASE fences and dispatches through an allocator vtable. agnosys is
single-threaded, so this is pure overhead on **allocation-bound** paths. vs the
1.3.2 baseline (30 benches, x86_64):

| bench | 1.3.2 | 1.4.1 | Δ |
|---|---|---|---|
| `ok_create` (Result heap alloc) | 14 ns | 59 ns | **+321%** |
| `from_errno_eperm` (heap SysError) | 21 ns | 65 ns | **+210%** |
| `mac_default_profile` | 211 ns | 367 ns | +74% |
| `validate_ver_good` | 105 ns | 180 ns | +71% |
| `compare_versions` | 171 ns | 232 ns | +36% |
| `syserr_pack` (zero-alloc hot path) | 3 ns | 3 ns | 0% |
| `map_get_hit` | 70 ns | 62 ns | −11% |

The hit is confined to heap-allocating paths — agnosys's design keeps these on
**cold/diagnostic** routes (packed `syserr_pack` on hot paths is unchanged at
3 ns; per the "packed errors on hot paths" rule). Non-allocating benches are flat
or slightly faster. The regression is the documented cost of the upstream
thread-safety fix, not an agnosys codegen change. **Follow-up:** there is no
single-thread opt-out in the cyrius stdlib today; eliminating the lock cost needs
either an upstream `CYRIUS_SINGLE_THREADED` no-op gate or migrating hot
allocations to the non-locking freelist allocator (the patra pattern). Tracked in
roadmap.

### Housekeeping

- Regenerated `docs/development/api-surface-1.0.md` and
  `docs/development/capability-map.md`, both stale since the 1.4.0 AGNOS
  doc-comment changes (descriptions only; no signature or capability changes).

## [1.4.0] — 2026-06-06 (AGNOS as a build target — the core syscall layer now supports both Linux and agnos)

### Added

- **AGNOS platform support in `agnosys-core`** (`src/syscall.cyr`). The kernel-interface wrappers consumed by userland tools (mihi/iam/chakshu) now compile and run under `cyrius build --agnos`, gated inline with `#ifdef CYRIUS_TARGET_AGNOS`:
  - `agnosys_uname` → AGNOS `uname` syscall #34 + the sovereign 64-byte identity struct (4 × 16-byte NUL-padded fields: sysname/nodename/release/machine) vs Linux's 390-byte `utsname`. `UtsOffset`/`UTS_SIZE` gated accordingly.
  - `query_sysinfo` → AGNOS `sysinfo` syscall #35 + the sovereign 40-byte all-u64 struct (uptime_secs/totalram/freeram/procs/cpus, byte counts direct — no `mem_unit`) vs Linux's 112-byte struct. `SysInfoOffset`/accessors gated (the memory accessors skip the unit multiply on agnos; `sysinfo_procs` reads u64 not u16).
  - `agnosys_gettid` → `getpid` on agnos (single-threaded single-core; no `gettid`), `agnosys_geteuid` → `getuid` (no separate effective-uid surface). The literal syscall numbers 34/35 are used because the agnos cyrius peer doesn't define `SYS_UNAME`/`SYS_SYSINFO`/`SYS_GETTID`/`SYS_GETEUID`, and the x86 Linux peer wrongly defines `SYS_SYSINFO=99` on the agnos x86 target (peers self-gate by arch, not OS).
- The Linux path is unchanged (additive gating). The `security`/`storage`/`trust`/`system` profiles remain Linux-only (Landlock/seccomp/LUKS/TPM have no agnos equivalent yet); only `agnosys-core` is agnos-portable — consumers needing the kernel-interface on agnos pull the `core` bundle.

### Changed

- cyrius pin `6.0.52` → `6.0.56` (the agnos-target toolchain; matches agnoshi + the agnos kernel). `dist/agnosys.cyr` + `dist/agnosys-core.cyr` regenerated at v1.4.0.

### Validated

- `cyrius distlib core` → `dist/agnosys-core.cyr`; a `--agnos` compile-test (`agnosys_uname` + `query_sysinfo`) builds **OK** (both reachable; the `sys_fork`/`sys_dup2`/`WIF*` warnings are Linux-only process helpers in `logging`/`util`, unreachable + DCE'd). Linux build unaffected.

## [1.3.2] — 2026-06-03

**Cyrius pin 6.0.24 → 6.0.52 — toolchain refresh with a real codegen win.** No
agnosys source changes. Unlike the pure-TLS 6.0.14 → 6.0.24 window, the
6.0.25–6.0.52 arc carries a codegen change: the agnosys binary moves 159,024 →
159,392 B (+368) and every hot path measures faster. Audit clean (11/11);
252 tests, 7 fuzz harnesses; API surface unchanged (no drift).

### Performance

Broad hot-path improvements from the 6.0.25–6.0.52 codegen window — 30
benchmarks, **zero regressions**, reproduced on a second run (so not run-to-run
noise). Representative deltas vs 1.3.1:

- `update_compare_versions` 229 → 171 ns (−25%)
- `certpin_ct_streq` (equal) 170 → 129 ns (−24%), (diff) 176 → 129 ns (−27%)
- `validate_pin_valid` 288 → 236 ns (−18%), `validate_ver_good` 129 → 105 ns (−19%)
- `bootloader` `validate_cmdline_safe` 582 → 487 ns (−16%)
- `wrap_syscall_ok` 344 → 300 ns (−13%), `map_get_miss` 53 → 39 ns (−26%)
- `memeq_16` 36 → 29 ns (−19%), `syserr_pack` 4 → 3 ns

New `bench-history.csv` row appended; `BENCHMARKS.md` regenerated (derived).

### Changed

- **`cyrius.cyml [package].cyrius`** — pin 6.0.24 → 6.0.52.
- **Vendored stdlib snapshot** — 25 → 29 files. The 6.0.x AGNOS-target peers
  (`alloc_agnos.cyr`, `syscalls_x86_64_agnos.cyr`) plus the macOS/Windows
  syscall + process peers (`syscalls_macos.cyr`, `syscalls_windows.cyr`,
  `process_win.cyr`) are now pulled transitively by `cyrius deps`. None affect
  the Linux x86_64/aarch64 build.
- **DCE floor** — 490 unreachable fns NOPed (108,466 dead bytes), vs 488 /
  108,443 at 1.3.1 (+2 fns, +23 bytes).
- **`dist/agnosys.cyr` + 5 profile bundles** — regenerated at 1.3.2 (version
  header only; line counts unchanged from 1.3.1).

## [1.3.1] — 2026-06-01

**`src/util.cyr` consolidation closeout.** Two non-breaking dedups deferred from
1.3.0, both folding into the shared helpers. Audit clean (11/11).

### Added

- `agnosys_is_name_char` — shared dm-name allowlist (alphanumeric + `-`/`_`);
  `dmverity_is_name_char` / `luks_is_name_char` are now thin wrappers.
- `agnosys_read_fd_to_str(fd, cap)` — drains a fd into a NUL-terminated `Str`,
  replacing 3 byte-identical loops in pam (`pam_read_service_config`,
  `pam_list_users`, `pam_get_user_info`). The shared helper allocates `cap + 1`,
  closing a **latent 1-byte overflow** the per-module copies carried (they
  alloc'd exactly `cap` and wrote the terminator at offset `cap` — same class as
  F-11, but bounded to ≥8KB PAM configs / ≥64KB `/etc/passwd`).
- Regression test `readfd_cap`. Test count 251 → 252.
- +2 public fns (additive, non-breaking; 735 → 737).

### Deprecated

Doc-only notices (cyrius `#deprecated` is still unproven — see roadmap V1.2.4),
scheduled for removal in **2.0.0** (roadmap V2.0):

- `agnosys_checked_syscall` — public but 0 callers and byte-redundant with
  `wrap_syscall`. *Migration:* use `wrap_syscall`.
- The `label` parameter of `dmverity_validate_hex` (currently ignored) — the
  function drops to arity 1 in 2.0.0. *Migration:* drop the second argument.

### Changed

- **`dist/agnosys.cyr` + 5 profile bundles** — regenerated at 1.3.1.

## [1.3.0] — 2026-06-01

**Cyrius pin 6.0.14 → 6.0.24 + correctness/security pass + refactor &
optimization closeout.** A real minor: four buffer/exec defects fixed (one
HIGH), cross-module duplication consolidated into a new `src/util.cyr`, and
benchmarked hot-path wins. Full audit clean (11/11). See
[`docs/audit/2026-06-01-audit.md`](docs/audit/2026-06-01-audit.md).

The 6.0.15–6.0.24 upstream window is entirely the native-TLS arc
(`lib/tls_native.cyr`, "no compiler change"); the agnosys binary is unchanged at
159,024 B. No language modernization was applicable.

### Security

- **F-11 (HIGH) — `update_check` heap overflow.** The manifest read loop let
  `total` reach the 16384-byte buffer end, so `store8(buf + total, 0)` wrote one
  byte past the allocation on any manifest ≥16KB (manifests come from external
  `file://` input). Fixed by reserving the terminator byte (mirrors
  `ima_read_measurements`). Regression test added (18KB manifest).
- **F-12 (MEDIUM) — `update_save_state` fixed-buffer overflow.** JSON was built
  into a fixed `alloc(512)` from `version`/`pending` fields that can come from a
  loaded state file. Now sized from the actual field lengths.
- **F-13 (MEDIUM) — `ima_read_measurements` silent truncation.** The IMA log was
  truncated at 64KB, hiding measurements from attestation. Now grows to EOF with
  a 32MB ceiling (errors past it instead of silently dropping the tail).
- **F-14 (LOW) — `netns` exec hardening.** The `ip`/`nft`/`mkdir` exec path was
  non-functional (argv array passed as a single arg; bare command names
  `execve` can't resolve) and PATH-hijackable. Rewrote all 15 sites onto
  `exec_vec` with **absolute** command paths. Regression test
  `exec_vec_multiarg` added.

### Added

- **`src/util.cyr`** — shared `agnosys_*` cross-module helpers, in `[lib.core]`
  (every profile bundle resolves them): `agnosys_json_emit_cstr_or_null`,
  `agnosys_is_hex_char`, `agnosys_cstr_starts_with`, `agnosys_run_capture`,
  `agnosys_run_checked`. +5 public fns (additive, non-breaking; 730 → 735).
- Regression tests: `big_check_*` (F-11), `exec_vec_multiarg` (F-14).
  Test count 247 → 251.
- **CLAUDE.md** — benchmarks are now run on **every** version bump
  (`scripts/bench-history.sh`, with a delta/regression check) as a Work-Loop
  step and a hard constraint.

### Changed

- **`cyrius.cyml`** — pin 6.0.14 → 6.0.24; `src/util.cyr` added to `[lib]` and
  `[lib.core]`.
- **Cross-module dedup (Tier 1)** — 5 byte-identical `_<mod>_emit_cstr_or_null`
  shims, the hex-char predicate (ima/dmverity/tpm/update), the cstr prefix check
  (fuse/udev), and the subprocess wrappers (dmverity/luks/tpm `*_run_capture`/
  `*_run_checked`) collapsed onto the shared helpers. Public names retained as
  thin wrappers — **no API surface change** beyond the 5 additions.
- **Hygiene (Tier 3)** — removed `break` from `var`-declaring `while` loops
  (audit, mac); `journald` filter argv uses generated `journald_filter_*`
  accessors instead of raw offsets; `audit_open` emits a real `log_warn`.
- **`dist/agnosys.cyr` + 5 profile bundles** — regenerated at 1.3.0
  (10,110 → 10,062 lines on the full bundle; dedup outweighs the new module).

### Performance

Benchmarked against the 6.0.24 baseline (`scripts/bench-history.sh`):

- **`agnosys_cstr_starts_with` single-pass** (drops the up-front `strlen` of the
  subject): `starts_with_hit` **47 → 15ns** (−68%), `starts_with_miss`
  **31 → 7ns** (−77%).
- **`mac_default_profile`** builds straight into the heap allocation (removes a
  static staging buffer, an extra copy, and a `var buf[N]` static-data hazard):
  **324 → 239ns** (−26%).
- `tpm_get_random` sizes its hex buffer to `count*2+8` and drops a dead `memset`
  (allocation reduction; not benchmarked — execs an external tool).

## [1.2.8] — 2026-05-28

**Cyrius pin bump 6.0.1 → 6.0.14 + workaround audit.**

Toolchain refresh across the 6.0 patch series. No agnosys source
changes. The 6.0.2 → 6.0.14 work upstream is the native-TLS arc
(sigil/stdlib-internal) plus three toolchain fixes; none touch the
kernel-interface surface agnosys binds. Full audit clean against the
new pin (11/11 gates green).

### Changed

- **`cyrius.cyml`** — pin 6.0.1 → 6.0.14.
- **`./lib/`** — refreshed via `cyrius deps` (gitignored; repopulated
  from the 6.0.14 stdlib snapshot — 24 → 25 files). The new file is
  `syscalls_linux_common.cyr` (shared Linux syscall numbers), now
  pulled transitively where it was a not-pulled peer at 6.0.1.
- **`dist/agnosys.cyr` + 5 profile bundles** — regenerated at 1.2.8.
  src content is byte-identical to 1.2.7 (distlib is pure
  concatenation of `src/*.cyr`); two changes per bundle: the embedded
  `# Version: 1.2.8` header, and the **cyrius 6.0.9 distlib blank-line
  residue fix** collapsing the double blank line after the header and
  between modules. Net −72 lines on the full bundle (10,182 → 10,110);
  formatting only.
- **`docs/development/capability-map.md`** — regenerated header
  (timestamp / source commit / version).
- **`docs/development/state.md`** — full refresh (pin, version, binary
  metrics, stdlib list, recent releases).
- **`CONTRIBUTING.md`** — Prerequisites refreshed (`6.0.14` at 1.2.8).

### Workaround audit — none repairable yet

Reviewed every in-tree workaround left from prior cyrius bugs against
6.0.14; all three are **still required** (verified empirically, not
from the changelog narrative):

- **Hand-rolled JSON serializers** (`mac`, `certpin`, `drm`,
  `dmverity`, `update`). `#derive(Serialize)` still emits a
  cstr-pointer field as its **pointer decimal** in 6.0.14 (tested: a
  two-cstr-field struct serialized to `849649872` instead of the
  string). The hand-rolled serializers stay; `#derive(Serialize)`
  adoption remains a post-1.0 Phase 8 follow-up gated on cstr-field
  support landing upstream.
- **CI fmt diff-gate** (`.github/workflows/ci.yml`). `cyrius fmt
  --check <file>` still errors to `Usage: cyrfmt --check <file.cyr>`
  in 6.0.14 (no gating behavior), so the per-file `diff` against
  `cyrius fmt` stdout remains the drift gate.
- **CI `cycc_aarch64` top-level fallback** — defensive cross-shape
  coverage (release tarballs ship the aarch64 cross compiler under
  `bin/` or top-level depending on shape); harmless, retained.

### Notable cyrius 6.0.2 → 6.0.14 deltas

- **6.0.9 aarch64 syscall correctness** — `lib/args.cyr` raw x86-only
  syscall numbers and the compiler's own `syscall(60, ...)` exit fixed
  to arch-dispatched forms. **agnosys unaffected**: `src/main.cyr`
  already exits via `syscall(SYS_EXIT, r)` (the arch enum), not raw
  `syscall(60)`.
- **6.0.3 `str_from` overload misroute** — `str_from(<i64-returning
  call>)` no longer silently routes to `str_from_int`. agnosys's
  cstr-emit paths pass through `_emit_cstr_or_null` helpers; no
  affected call sites.
- **6.0.2 `cyrius deps` empty-lock fix** — N/A; agnosys ships no
  `cyrius.lock` (zero non-stdlib deps).

### Build metrics

- Binary (DCE-aware): 156,768 B (1.2.7) → **159,024 B** (+2,256 B from
  6.0.1 → 6.0.14 codegen + stdlib growth). 488 unreachable fns NOPed
  (108,443 bytes).

### Verified

- `cyrius build src/main.cyr build/agnosys`: green (x86_64).
- `scripts/audit.sh`: 11/11 gates pass.
- 247 / 247 integration tests pass.
- 7 / 7 fuzz harnesses pass.
- 30 / 30 benchmarks (11 groups) run to completion.

## [1.2.7] — 2026-05-21

**Cyrius pin bump 5.11.4 → 6.0.1 — first major upstream release.**

Toolchain refresh across a major version boundary. No agnosys
source changes; full audit clean against the new pin (11/11
gates green).

### Changed
- **`cyrius.cyml`** — pin 5.11.4 → 6.0.1.
- **`./lib/`** — refreshed via `cyrius deps` (gitignored;
  repopulated from the v6.0.1 stdlib snapshot — 24 files).
  Upstream renamed `cc5` → `cycc` throughout stdlib comments;
  new `syscalls_linux_common.cyr` peer (not pulled by agnosys's
  `[deps] stdlib` list).
- **`docs/development/capability-map.md`** — regenerated header
  (carry-forward of the 1.2.6 source-commit / version refresh
  that landed after the tag).
- **`dist/agnosys.cyr` + 5 profile bundles** — regenerated at
  1.2.7. Content is identical to 1.2.6 (distlib is pure
  concatenation of `src/*.cyr`); only the embedded
  `# Version: 1.2.7` header line changes per bundle.
- **`docs/development/state.md`** — full refresh (pin, version,
  binary metrics, capacity table, stdlib list, recent releases).
- **`.github/workflows/ci.yml` + `.github/workflows/release.yml`**
  — `cc5_aarch64` → `cycc_aarch64` (renamed in Cyrius 6.0);
  `cc5 --version` verify step swapped for `cyrius --version`
  (wrapper-stable across compiler renames); install step gains
  the tarball-top-level `cycc_aarch64` fallback that
  sankoch / yukti already carry (some 6.0 release shapes ship
  it outside `bin/`).
- **`scripts/audit.sh`** — aarch64 cross-build guard updated
  to `cycc_aarch64`.
- **`CONTRIBUTING.md`** — Prerequisites refreshed (`6.0.1` /
  `cycc_aarch64`).

### Notable cyrius 6.0 deltas affecting agnosys

- **Fn-table capacity doubled** 4,096 → 8,192. Current
  utilization 424 / 8,192 (5%), down from 390 / 4,096 (10%).
- **DCE strategy** — switched from full elimination to in-place
  NOP. `CYRIUS_DCE=1` build now reports "478 unreachable fns
  (106,230 bytes NOPed)"; binary size identical to non-DCE
  build (156,768 B). The dead bytes are still in the file but
  unreachable; `CYRIUS_DCE_VERBOSE=1` lists them.
- **Binary size** — 132,952 B (1.2.5, DCE) → 156,768 B (1.2.7,
  DCE-aware). +23,816 B from cyrius 6.0 codegen + stdlib growth
  across 5.11 → 6.0.

### Verified

- `cyrius build src/main.cyr build/agnosys`: green (x86_64).
- `scripts/audit.sh`: 11/11 gates pass.
- 247 / 247 integration tests pass.
- 7 / 7 fuzz harnesses pass (10s timeout each).
- 30 / 30 benchmarks (11 groups) run to completion.

## [1.2.6] — 2026-05-11

**Stdlib annotation pass + cyrius pin 5.10.44 → 5.11.4.**

Every public fn in `src/*.cyr` (351 fns) gains a `: i64`
return-type annotation. Mechanical pass matching cyrius's
v5.11.x annotation arc (Phases 1-6 in cyrius/CHANGELOG.md);
parse-only, zero runtime / codegen change.

Profile bundles all regenerated at v1.2.6:
- `dist/agnosys.cyr` (700 fns, 10111 lines)
- `dist/agnosys-core.cyr` (758 lines)
- `dist/agnosys-security.cyr` (2337 lines)
- `dist/agnosys-storage.cyr` (1511 lines)
- `dist/agnosys-system.cyr` (3366 lines)
- `dist/agnosys-trust.cyr` (2139 lines)

Ready for the next cyrius-side fold-in slot.

### Verified

- `cyrius build src/main.cyr build/agnosys`: green.
- All 6 profile bundles regenerated cleanly via `cyrius distlib`.

## [1.2.5] — 2026-05-11

**Cyrius pin bump 5.10.34 → 5.10.44.**

Toolchain refresh; no agnosys source changes. cyrius 5.10.35 →
5.10.44 covers ten patch releases of upstream improvements
(parser/codegen polish, stdlib additions); agnosys's audit gates
all pass clean against the new toolchain.

### Changed
- **`cyrius.cyml`** — pin 5.10.34 → 5.10.44.
- **`./lib/`** — refreshed via `cyrius deps` (gitignored;
  populated from the v5.10.44 stdlib snapshot).
- **`docs/development/capability-map.md`** — regenerated header
  (version + source-commit refresh).
- **`docs/development/api-surface-1.0.md`** — regenerated header.
- **`dist/agnosys.cyr` + 5 profile bundles** — regenerated at
  1.2.5 header.

### Verified
- All 11 audit gates pass under cyrius 5.10.44.
- 247 / 247 integration tests pass (no test changes).
- 30 benchmarks across 11 groups; bench parity unchanged.
- 7 fuzz harnesses.
- API surface: 730 public fns, no drift since 1.2.4 (pure
  toolchain bump).

## [1.2.4] — 2026-05-10

**Cyrius pin bump 5.10.19 → 5.10.34.**

Toolchain refresh; no agnosys source changes. cyrius 5.10.20 →
5.10.34 covers fifteen patch releases of upstream improvements
(parser/codegen polish, stdlib additions); agnosys's audit gates
all pass clean against the new toolchain.

### Changed
- **`cyrius.cyml`** — pin 5.10.19 → 5.10.34.
- **`./lib/`** — refreshed via `cyrius deps` (gitignored;
  populated from the v5.10.34 stdlib snapshot).
- **`docs/development/capability-map.md`** — regenerated header
  (version + source-commit refresh).
- **`docs/development/api-surface-1.0.md`** — regenerated header.
- **`dist/agnosys.cyr` + 5 profile bundles** — regenerated at
  1.2.4 header.

### Verified
- All 11 audit gates pass under cyrius 5.10.34.
- 247 / 247 integration tests pass (no test changes).
- 30 benchmarks across 11 groups; bench parity unchanged.
- 7 fuzz harnesses.
- API surface: 730 public fns, no drift since 1.2.3 (pure
  toolchain bump).

## [1.2.3] — 2026-05-10

**V1.2.3 consumer integration CI + 1.2.1 doc cleanup carry-forward.**

Skips 1.2.2 — that slot's deliverable (capability map per public fn)
was folded into the 1.2.1 ship. Per the agnosys slot-rhythm
convention (slot # = agnosys VERSION #), V1.2.3 (consumer
integration CI) gets its own version.

### Added
- **`.github/workflows/consumer-integration.yml`** — V1.2.3 slot.
  Nightly @ 06:00 UTC + `workflow_dispatch`. Runs in its own
  workflow file; **NOT part of the primary build/test pipeline**
  (failures are signal, not blocker — agnosys's own audit gates
  remain authoritative for the tag).
  - Per-job: checks out agnosys + the consumer; builds agnosys's
    6 dist bundles (full + 5 profiles); vendors them into the
    consumer's `lib/`; force-syncs the consumer's cyrius pin to
    match agnosys's; runs the consumer's declared audit command.
  - Initial matrix: kavach (`cyrius test`) + sigil
    (`scripts/check.sh`) — highest-module-surface consumers per
    the V1.2.3 spec. Expand the matrix once the pair runs cleanly
    for a few cycles.
  - On failure: auto-files a `consumer-break` issue here with
    agnosys commit + cyrius pin + run log + triage checklist.
    Dedups by title prefix — re-fires comment on the existing
    issue rather than creating duplicates.
  - Notification channel: GitHub Issues (the auto-filed
    `consumer-break` ticket). No Slack / Discord wiring — repo
    Issues is the canonical inbox.
- **`docs/doc-health.md`** — living ledger of doc currency
  (fresh / stale / read-through / evergreen / archive / open-
  question buckets per tier). Mirrors the agnostik pattern,
  agnosys-shaped tiers (root / project state / architecture /
  ADRs / audit / reviews / issues / headliner). Refresh cadence
  is opportunistic — touched when other docs are touched.

### Changed
- **`README.md`** — top-line block refreshed to 1.2.3 / Cyrius
  5.10.19 / 730 fns / ~10 300 lines / ~153 KB binary / ~170 ms
  compile (was 1.0.0 / Cyrius 5.2.0 / 556 fns / 291 KB / 460 ms).
  Build section adds the 5 profile-bundle distlib commands.
  Per-module example replaced with profile-bundle example +
  5-bundle table. Quality gates: 10 → 11. Test/fuzz counts:
  222 / 3 → 247 / 7. Docs section adds state.md, capability-map,
  doc-health.
- **`CONTRIBUTING.md`** — Cyrius prereq refreshed
  ("pinned in cyrius.cyml; currently 5.10.19"); workflow has
  11 gates + the new auto-gen scripts (`gen-api-surface-prose`,
  `gen-capability-map`); commands table includes `cyrius deps`,
  the 5 profile-bundle options, `cyrius build --aarch64`.
  "Adding a Module" uses `[lib] modules` (per ADR-003) + profile
  picker + freeze framing. Cyrius Conventions notes
  `#derive(accessors)` adopted (V1.1.0); arch-gating on
  `#ifdef CYRIUS_ARCH_<UPPER>` (NOT `#ifplat` — points at the
  upstream-blocker ticket).
- **`docs/development/capacity-baseline.md`** — re-captured at
  1.2.3 baseline. 7 rows: live core demo + core profile +
  4 core+profile combos + full bundle. 1.0.0 baseline preserved
  as historical-comparison block. Highest util at 1.2.3: full
  bundle 35% code_size, 30% fn_table — well under the 85% gate.
- **`scripts/version-bump.sh`** — removed the auto-suggested
  `git add` / `commit` / `tag` / `push` next-steps block that
  was misleading agents. Replaced with an explicit
  "Maintainer-only follow-up (NOT for agents)" framing per
  CLAUDE.md hard-constraint § "do not commit or push".

### Verified
- All 11 audit gates pass under cyrius 5.10.19.
- 247 / 247 integration tests pass (no test changes since 1.2.1).
- 30 benchmarks across 11 groups; bench parity unchanged.
- 7 fuzz harnesses.
- API surface: 730 public fns, no drift since 1.2.1.
- 6 dist bundles (full + 5 profiles) regenerated at 1.2.3 header.

## [1.2.1] — 2026-05-09

**V1.2.2 capability map + Phase 8 doc-tooling + 3 upstream-blocker
issues filed internally + audit-gate tightening.**

Consumer-facing transparency + tooling polish following the V1.2.0
multi-profile distlib ship. No source changes; everything is doc /
script / CI infrastructure.

### Added
- **`scripts/gen-capability-map.sh`** — auto-generates the per-module
  kernel-surface capability map from src/. `--check` mode for
  staleness detection.
- **`docs/development/capability-map.md`** (638 lines, auto-generated)
  — per-module breakdown of direct syscalls, `sys_*` wrappers,
  subprocess binaries, and hardcoded sysfs/procfs/devfs paths.
  Plus per-profile rollup mapping each `dist/agnosys-<profile>.cyr`
  bundle to its capability set so downstream sandbox-policy
  authors (kavach Landlock / seccomp filters, etc.) can derive
  their allowlists by aggregating the modules in their profile.
  Closes V1.2.2 slot.
- **`scripts/gen-api-surface-prose.sh`** — auto-generates
  `api-surface-1.0.md` per-fn prose from the snapshot + source
  comment extraction. `--check` mode wired into audit. Closes the
  D-3 deferral from the 1.1.13 internal review (Phase 8
  doc-tooling slot).
- **`docs/development/issues/2026-05-09-cyrius-derive-serialize-cstring.md`**
  — internal tracking of cstring `#derive(Serialize)` gap.
  Passive (not refiled upstream); cyrius's Serialize handles
  `Str` and primitive-int paths cleanly, cstring extension is
  upstream's call to schedule. Hand-rolled `_to_json` shims
  (V1.1.12) are the durable workaround.
- **`docs/development/issues/2026-05-09-cyrius-ifplat-codegen.md`**
  — internal tracking of `#ifplat` codegen regression.
  Passive (cyrius's own `lib/syscalls.cyr` v5.4.19 note already
  documents the same regression). agnosys reverted V1.1.15 /
  V1.2.1 migration attempt cleanly; tracks here without piling on
  upstream.
- **`docs/development/issues/2026-05-09-cyrius-deprecated-unproven.md`**
  — internal tracking of `#deprecated` directive's unverified
  status across agnosticos consumers. Defer until proven by
  another consumer first OR until agnosys has a real fn to
  deprecate.

### Changed
- **`docs/development/api-surface-1.0.md`** — regenerated by the
  new prose generator. Was V1.0-era curated 556-fn snapshot; now
  auto-covers all 730 current fns. Header preserves the 1.0-baseline
  framing (still the stable-contract record). Comment blocks above
  each fn become the prose; "(no behavioral docs)" flags fns
  without leading comments — improving src/ comments propagates to
  the doc on next regen.
- **`scripts/audit.sh`** — tightened from 10 to 11 gates:
  - Stage 2 (API surface) now checks both the snapshot AND the
    prose doc (`snapshot + prose match`).
  - Stage 3 (capability map) added — verifies
    `docs/development/capability-map.md` is in sync via
    `scripts/gen-capability-map.sh --check`.
  - Stages 4-11 renumbered (was 3-10).

### Verified
- All 11 audit gates pass under cyrius 5.10.19.
- 247 / 247 integration tests pass (no test changes).
- 30 benchmarks across 11 groups; bench parity unchanged.
- 7 fuzz harnesses.
- API surface unchanged (730 public fns, no drift since 1.2.0).
- 6 dist bundles (full + 5 profiles) regenerated at 1.2.1 header.
- No new cyrius language features used (proven primitives only —
  shell, awk, sed for tooling; existing `cyrius distlib` /
  `cyrius api-surface` for surface generation).

### Issues directory state
- 3 active (passive — not refiled upstream): the three V1.2.x
  upstream blockers above.
- 9 archived (resolved during V1.0/V1.1 cycles).

## [1.2.0] — 2026-05-09

**V1.2.0 — multi-profile `cyrius distlib`. Five profile bundles
ship alongside the full bundle; consumers cut ~60-78% of
distribution size by including only the domain they wire to.**

The consumer-facing distribution shape changes in 1.2.0: instead
of the single `dist/agnosys.cyr` bundle (329 KB / 10,182 lines),
agnosys now ships five additional profile bundles, each scoped
to a domain. Consumers include `dist/agnosys-core.cyr` plus the
profile that matches their use, e.g. kavach pulls
core (23 KB) + security (76 KB) = ~99 KB instead of the full
324 KB — a 70% reduction.

Closes the V1.2.0 roadmap slot. Headline 1.2 cycle because it
changes the consumer-facing distribution shape; gets its own
minor cycle per the roadmap.

### Added
- **`[lib.core]`** profile (`dist/agnosys-core.cyr`, 23 KB,
  779 lines) — error, syscall, logging + per-arch syscall peers.
  Foundational for every other profile.
- **`[lib.security]`** profile
  (`dist/agnosys-security.cyr`, 76 KB, 2,355 lines) —
  security, mac, audit, pam. Consumed by kavach + aegis +
  shakti + libro.
- **`[lib.storage]`** profile
  (`dist/agnosys-storage.cyr`, 49 KB, 1,526 lines) —
  luks, dmverity, fuse. Consumed by stiva + ark.
- **`[lib.trust]`** profile
  (`dist/agnosys-trust.cyr`, 70 KB, 2,157 lines) —
  tpm, ima, secureboot, certpin. Consumed by sigil + daimon
  + hoosh.
- **`[lib.system]`** profile
  (`dist/agnosys-system.cyr`, 111 KB, 3,390 lines) —
  journald, bootloader, udev, drm, netns, update. Consumed
  by argonaut + yukti + soorat + nein.

### Changed
- **`cyrius.cyml`** — added 5 `[lib.<profile>]` sections.
  `[lib]` (full bundle) unchanged. Yukti pattern.
- **`.github/workflows/ci.yml`** — dist-staleness gate
  extended from 1 bundle to 6. CI runs `cyrius distlib`
  + 5 `cyrius distlib <profile>` invocations and asserts
  no diff against committed bundles.
- **`.github/workflows/release.yml`** — release archive
  ships every profile bundle alongside the full one
  (`agnosys-<TAG>-<profile>.cyr` × 5 + `agnosys-<TAG>.cyr`).

### Consumer-side wins (vs 1.1.x's full-bundle-only model)

| Consumer | Profiles needed | 1.1.x size | 1.2.0 size | Cut |
|---|---|---|---|---|
| kavach | core + security | 324 KB | ~99 KB | 70% |
| stiva | core + storage | 324 KB | ~72 KB | 78% |
| sigil / daimon / hoosh | core + trust | 324 KB | ~92 KB | 72% |
| argonaut / yukti / soorat / nein | core + system | 324 KB | ~134 KB | 59% |
| aegis / shakti / libro | core + security | 324 KB | ~99 KB | 70% |
| ark | core + storage | 324 KB | ~72 KB | 78% |

### Verified
- All 10 audit gates pass under cyrius 5.10.19.
- 247 / 247 integration tests pass (no test changes).
- 30 benchmarks across 11 groups; bench parity unchanged.
- 7 fuzz harnesses.
- Smoke-tested core profile in isolated `/tmp/core_test/`
  consumer (cyrius.cyml + main.cyr + `cyrius deps`):
  `err_invalid_argument`, `is_err_result`,
  `agnosys_getpid` all work standalone against the
  23 KB core bundle.
- API surface: ~733 public fns, no drift since 1.1.14
  (purely additive distribution shape change; no source
  changes).
- No new cyrius language features used — proven primitive
  (`cyrius distlib <profile>` is what yukti has shipped
  in production with).

## [1.1.14] — 2026-05-09

**P(-1) hardening pass — security audit findings landed.**

Completes the P(-1) hardening pass kicked off in 1.1.13.
Steps 4-8 of CLAUDE.md's P(-1) discipline produced three
new audit/review docs and four small source changes
(F-7 / F-8 / F-9 + H-2 smoke). 0 critical / 0 high / 0
medium severity findings; 3 LOW + 1 informational, all
addressed in this release.

### Added
- `docs/audit/2026-05-09-cve-landscape.md` — P(-1) step 4.
  Maps the 17 module-bound kernel interfaces to issue
  classes and historical CVE shapes (audit netlink,
  dm-verity, IMA, FUSE, LUKS, TPM, Landlock, seccomp,
  secureboot, PAM, etc.). Source citations included
  (kernel headers, UEFI Spec §8.2, TCG TPM 2.0 §27, etc.).
- `docs/audit/2026-05-09-audit.md` — P(-1) step 5.
  Security audit drilling into the 8 carry-forward items
  from step 4. Findings F-7 through F-10 documented.
- `docs/development/reviews/2026-05-09-internal-review.md`
  — P(-1) step 3 (filed in 1.1.13; cross-referenced here).
- `fuzz/fuse_parse.fcyr` — new fuzz harness for
  `fuse_extract_field` covering octal-escape edge cases,
  empty / one-field / multi-whitespace lines, adversarial
  backslash density, 8 KB synthetic input, 500-iteration
  stress (audit gate 9 now 7 harnesses, was 6).
- `test_security` integration block extended with H-2
  smoke: exercises `security_fs_rule_new` →
  `security_fs_rule_path` round-trip and
  `security_syscall_map_reset` rebuild path. Closes the
  internal-review observation that 10 `security_*` fns
  were DCE'd in agnosys's own self-test.
- `test_fuse` extended with 3 F-7 escape assertions
  (`\040` → space, `\134` → backslash, no-escape
  passthrough).

### Changed
- **F-7** — `src/fuse.cyr` `fuse_extract_field`: now
  unescapes 3-digit octal escapes (`\NNN`) per fstab(5)
  conventions. Mounts whose fields contain spaces, tabs,
  or backslashes (e.g. `mount.nfs //host/share with space
  /mnt`) parse correctly instead of field-shifting.
- **F-8** — `src/bootloader.cyr`
  `_bootloader_danger_init`: extended the kernel-cmdline
  danger-flag set with kernel-lockdown / module-signing
  downgrades (`lockdown=none`, `lockdown=integrity`,
  `module.sig_enforce=0`), LSM disable
  (`selinux=0`, `apparmor=0`, `enforcing=0`, `audit=0`),
  heap-hardening downgrades (`init_on_alloc=0`,
  `init_on_free=0`, `slab_nomerge=0`), and
  `efi=disable_early_pci_dma`.
- **F-9** — `src/dmverity.cyr` `dmverity_format` and
  `dmverity_status`: explicit
  `store8(&outbuf + 4095, 0)` after each
  `dmverity_run_capture` / `exec_capture` call.
  Defense-in-depth — the `4095`-max contract on the
  capture fn already reserved the trailing byte; this
  makes the null-terminator explicit so a future
  refactor of capture fns can't quietly invalidate the
  `strlen(&outbuf)` reads downstream.
- **`docs/development/api-surface-1.0.md`** — Summary
  block refreshed to clarify the 1.0 baseline (556 fns)
  vs current shipping (730 fns at 1.1.13). Per-fn prose
  for the V1.1.x additions deferred pending a
  `cyrius api-surface --update --prose` style generator
  (Phase 8 doc-tooling slot).

### Verified
- All 10 audit gates pass under cyrius 5.10.19.
- 247 / 247 integration tests pass (+5 vs 1.1.13:
  3 fuse escape + 2 security smoke).
- 30 benchmarks across 11 groups; bench parity unchanged
  vs 1.1.13 baseline (33 timings re-recorded for
  commit `c157062` post-source-change).
- 7 fuzz harnesses (was 6: +`fuse_parse`).
- API surface: ~733 public fns (+3 vs 1.1.13:
  H-2 smoke exercises `security_fs_rule_new` and
  `security_fs_rule_path`); all additive, no removals.
- F-9 verification: byte-identical output of
  `dmverity_format` / `dmverity_status` paths under
  smoke; the explicit terminator is harmless when the
  capture fn already terminated and definitive when
  it doesn't.

### Audit findings (P(-1) step 5)

| ID | Severity | Status |
|---|---|---|
| F-7 | INFO | Closed in this release. |
| F-8 | LOW | Closed in this release. |
| F-9 | LOW | Closed in this release. |
| F-10 | LOW (verified clean) | No code change required; recorded for audit traceability. |

## [1.1.13] — 2026-05-09

**Doc reconciliation post-1.1.12 ship + P(-1) hardening
baseline.**

The V1.1.12 `#derive(Serialize)` slot tagged as 1.1.12
on 2026-05-09 with all the work folded in (2 derived
serializers + 5 hand-rolled `_to_json` shims + cyrius pin
arc through 5.10.19 + ./lib/ gitignored). Pre-tag,
CHANGELOG/state.md/roadmap.md had stray references to a
1.1.13 placeholder version that was never minted; this
release reconciles those documents to reflect the actual
1.1.12 ship narrative, and starts the post-V1.1 P(-1)
hardening pass per CLAUDE.md.

### Changed
- **`CHANGELOG.md`** — `[1.1.12]` entry rewritten with the
  shipped narrative (was the deferred narrative); the
  never-tagged `[1.1.13]` entry removed (its content was
  the actual 1.1.12 ship narrative folded into `[1.1.12]`).
- **`docs/development/state.md`** — Last refresh, VERSION
  cell, cyrius pin (5.10.16 → 5.10.19), Recent Releases
  table, V1.1.x slot list, integration assertion count,
  audit-gates header all reconciled to the 1.1.12 ship.
- **`docs/development/roadmap.md`** — `V1.1.12 / V1.1.13`
  section header collapsed to `V1.1.12`; trailing
  "agnosys 1.1.13 ships:" → "agnosys 1.1.12 ships:".

### P(-1) hardening pass — kicked off
- **Step 1 — Cleanliness:** `scripts/audit.sh` clean —
  10/10 gates pass at cyrius 5.10.19, 242 / 242
  integration tests, build 152,880 B, 30 benchmarks
  green, no lint warnings, no API surface drift.
- **Step 2 — Benchmark baseline:** 33 timings recorded for
  commit `9ec6063` via `scripts/bench-history.sh`
  (gitignored CSV + BENCHMARKS.md). Baseline for
  comparison against any post-V1.1 perf work.

Steps 3-9 (internal deep review, external research, security
audit, additional tests/fuzz, post-review benchmarks,
documentation audit) tracked as separate slot patches.

### Verified
- All 10 audit gates pass under cyrius 5.10.19.
- 242 / 242 integration tests pass (no test changes since
  1.1.12).
- API surface clean: ~730 fns, no drift since 1.1.12.

## [1.1.12] — 2026-05-09

**V1.1.12 — `#derive(Serialize)` for diagnostic status
structs ships. Two-week investigation arc closes.**

The slot scoped generating JSON serializers for module
diagnostic-status structs so consumers (kavach, sigil,
argonaut) can dump agnosys state to log without writing
per-module formatters. Initial filing 2026-05-07 deferred
the slot on apparent aarch64 SIGILL with `#derive(Serialize)`;
root-cause discovery 2026-05-08 (cyrius team's
`pwd && ls -la lib/` diagnostic) was that agnosys's vendored
`./lib/fnptr.cyr` (1,207 B stub) and `./lib/json.cyr`
(4,389 B stub) were shadowing v5.10.x stdlib's full
versions; PP_DERIVE codegen referenced helpers absent from
the stubs, fixup wrote sentinel offsets, aarch64 binary hit
SIGILL. The "x86 instructions in aarch64 body" disasm was
sentinel-byte misread by the disassembler — not a real
codegen bug. cyrius's PP_DERIVE was correct on both arches
the entire time.

Three follow-on cyrius issues filed and resolved during the
arc:
- `2026-05-08-cyrius-derive-multi-stacking` — stacked
  `#derive(accessors)` + `#derive(Serialize)` only honored
  one directive. Fixed cyrius 5.10.14.
- `2026-05-09-cyrius-api-surface-putc-brace-desync` —
  api-surface scanner mistook literal `125` (the byte for
  `}`) for a brace. Fixed cyrius 5.10.16.
- `lib/process.cyr O_WRONLY` syntax-check blocker — process
  module used `O_WRONLY` from `lib/io.cyr` without
  including it. Fixed cyrius 5.10.18 + 5.10.19.

### Added
- `audit_status_to_json/2` + `audit_status_from_json/1` —
  derive-emitted via stacked `#derive(accessors)` +
  `#derive(Serialize)` (numeric struct, both arches
  verified on real Pi).
- `ima_status_to_json/2` + `ima_status_from_json/1` —
  derive-emitted.
- `mac_profile_to_json/2`, `dmverity_status_to_json/2`,
  `update_state_to_json/2`, `certpin_info_to_json/2`,
  `drm_verinfo_to_json/2` — hand-rolled cstring-aware
  serializers using a per-module
  `_<mod>_emit_cstr_or_null` helper (null cstring →
  `"null"`, populated → JSON-quoted via
  `str_builder_add_json_str(str_from(c))`). Hand-rolls
  unwind cleanly when cyrius adds cstring
  `#derive(Serialize)` support.
- 8 new integration assertions covering populated and
  null-field JSON output (242 tests total, was 234).

### Changed
- **`cyrius.cyml`** — pin 5.9.27 → 5.10.19; `[deps] stdlib`
  extended from 9 to 18 modules (adds `fnptr`, `json`,
  `tagged`, `assert`, `bench`, `fs`, `hashmap`, `net`,
  `process`) for Serialize helper resolution + post-5.7.x
  `tagged` → `result` split + closing the
  vendored-stub-shadow issue once and for all.
- **`.gitignore`** — `/lib/` added (matches yukti/patra
  convention; vendored stdlib auto-populated by
  `cyrius deps` from the version-pinned snapshot, no longer
  committed).
- **`.github/workflows/ci.yml`** — `Resolve dependencies`
  step moved to immediately after `Verify toolchain` so
  downstream steps (syntax check, api-surface, capacity,
  fmt, lint, vet, dist verify, build) all see a fresh
  `./lib/` populated at the pinned version.
- **Workaround**: hand-rolled `_to_json` shims close with
  `str_builder_add_cstr(sb, "}")` rather than the idiomatic
  `str_builder_putc(sb, 125)` — both forms work on 5.10.16+,
  keeping add_cstr to avoid diff churn from the
  api-surface-scanner-bug-era code.

### Resolved & archived
- `2026-05-07-cyrius-derive-serialize-incomplete.md` —
  agnosys-side `./lib/` shadow misdiagnosed as cyrius bug;
  cyrius PP_DERIVE Serialize was correct.
- `2026-05-08-cyrius-derive-multi-stacking.md` — cyrius
  5.10.14 honors stacked `#derive` directives.
- `2026-05-09-cyrius-api-surface-putc-brace-desync.md` —
  cyrius 5.10.16 tokenizes numeric literals before brace
  counting.

### Verified
- All 10 audit gates pass under cyrius 5.10.19.
- 242 / 242 integration tests pass (+8 vs 1.1.11: 8 to_json
  round-trip assertions across the 7 diagnostic structs).
- 30 benchmarks across 11 groups; bench parity unchanged.
- API surface: ~730 public fns, +9 since 1.1.11
  (7 `_to_json` shims + 2 `_from_json` from the derived
  structs); all additive, no removals.
- Real Pi (aarch64, Ubuntu 6.8.0-1053-raspi) build runs
  clean for every `#derive(Serialize)` struct shape
  verified during the investigation arc.

## [1.1.11] — 2026-05-07

**V1.1.11 — slice migration for syscall + parser buffers.**
The roadmap slot scoped "35 sites" of `var buf[N]; pass &buf, N`
patterns for conversion to bounds-checked `slice<u8>`. Survey
shows most aren't real slice candidates:

- ~10 tiny fmt buffers (24 B; one-shot `fmt_int_buf` →
  `sys_write`) — no indexed access, no slicing benefit.
- ~6 stack-local kernel-ABI structs (8–16 B; LandlockRulesetAttr,
  sock_fprog, BPF program prog) — different pattern; per
  vidya `multi_width_types` stack locals use 8-byte slots
  regardless of width. Stays as `var buf[N]; store{N}` per
  V1.1.8's deferred items.
- ~7 build-and-pass-to-syscall buffers (utsname 392 B, sysinfo
  120 B, etc.) — one-shot use, no indexed access.
- ~12 large parser buffers with explicit `pos < outlen` walks
  using `memeq`/`memcpy` (length-bounded by construction) —
  slice subscript would re-validate already-validated bounds.

**One representative site migrated** to demonstrate the pattern:
`src/ima.cyr fn ima_get_status`'s newline-counting loop over
the 4 KB `rbuf` after each `sys_read`. The loop now uses
`slice_set` + `s[ri]` bounds-checked indexing instead of
`load8(&rbuf + ri)`. Bounds against `s.len` (set per read
length) replace the explicit `ri < n` check. Net: 2 added
lines (slice declaration + slice_set call); the inner loop
gains compile-time-protected bounds against future drift.

### Changed
- **`cyrius.cyml [deps].stdlib`** += `"slice"` (auto-prepend for
  `cyrius build/test/bench/fuzz/check/soak/smoke`).
- **`src/main.cyr`** + **`tests/tcyr/test_integration.tcyr`** —
  added `include "lib/slice.cyr"` to the explicit include
  manifests.
- **`src/ima.cyr`** — added `include "lib/slice.cyr"` (required
  for `cyrius check` standalone-mode resolution of slice
  subscript helpers; auto-prepend doesn't apply to the audit
  gate-1 syntax check). `ima_get_status`'s rbuf newline counter
  converted to `slice<u8>` form.
- **`dist/agnosys.cyr`** regenerated. 9,912 → 9,914 lines.

### Verified
- All 10 audit gates pass under cyrius 5.9.27, including the
  aarch64 cross-build gate (slice support is on both arches in
  5.9.27).
- 234 / 234 integration tests pass; `ima_get_status` behavior
  unchanged.
- 30 benchmarks across 11 groups; bench parity unchanged.
- API surface clean: 721 fns, no drift.

### Items deliberately scoped out

The remaining 34 `var buf[N]` sites stay on their existing
patterns. The roadmap's "bounds-checked indexing closes the
off-by-one class" rationale doesn't apply to most of agnosys's
buffer use, where bounds are already explicit and the access
patterns are `memeq`/`memcpy` calls rather than scalar
subscripts. When future code adds new scalar-subscript parser
loops, prefer the slice form from the start (per the ima
example).

## [1.1.10] — 2026-05-07

**V1.1.8 reopens — cyrius 5.9.27 implements aarch64 sub-8-byte
struct field loads.** The 1.1.9 revert is now reverted; the
V1.1.8 source changes (typed kernel-ABI structs + pointer-to-
struct dot syntax) are back in place and now build clean on both
x86_64 and aarch64.

### Changed
- **`cyrius.cyml [package].cyrius`** pinned `5.9.25` → `5.9.27`.
- **`src/audit.cyr`** + **`src/security.cyr`** — V1.1.8's typed
  struct decls (`sockaddr_nl`, `nlmsghdr`, `audit_kstatus`,
  `bpf_insn`) and pointer-to-struct dot-syntax write/read sites
  restored from the original V1.1.8 commit. 14 explicit
  `store{8,16,32}` calls + 3 width-load reads are once again
  delegated to width-correct codegen via typed fields.
- **`docs/development/issues/2026-05-07-cyrius-aarch64-sub-8-byte-struct-load.md`**
  → moved to `archive/`; status header updated to RESOLVED with
  cyrius 5.9.27 verification trail.
- **`dist/agnosys.cyr`** regenerated. 9,886 → 9,912 lines (back
  to the V1.1.8 size — typed struct decls are textual additions).

### Verified
- All 10 audit gates pass under cyrius 5.9.27, including the
  aarch64 cross-build gate added in 1.1.9 (which is now clean
  on the same source that broke it on 5.9.25/5.9.26).
- 234 / 234 integration tests pass.
- Bench parity: 30 benchmarks across 11 groups; no regressions
  vs the pre-revert 1.1.8 baseline.
- API surface clean: 721 fns, no drift.
- Issues directory empty again (6 archived, 0 open).

### V1.1.8 closure

V1.1.8 (multi-width struct fields for kernel binary protocols)
is now durably shipped:

| Struct | Size | Sites | Status |
|---|---|---|---|
| `sockaddr_nl` | 12 B | `audit_sockaddr_nl` | ✅ both arches |
| `nlmsghdr` | 16 B | `audit_build_nlmsg` write + `audit_recv_raw` read | ✅ both arches |
| `audit_kstatus` | 32 B | `audit_get_status` read + `audit_set_enabled` write | ✅ both arches |
| `bpf_insn` | 8 B | `security_bpf_write_insn` | ✅ both arches |

Stack-local kernel-ABI writes (LandlockRulesetAttr, sock_fprog
at security.cyr:106 and 195) remain on the explicit
`var buf[N]` + `store{N}` pattern — stack locals use 8-byte
slots regardless of declared width per vidya `multi_width_types`,
which is unchanged in 5.9.27.

## [1.1.9] — 2026-05-07

**V1.1.8 reverted — cyrius aarch64 backend doesn't support
sub-8-byte struct field loads.** The V1.1.8 multi-width struct
field migration shipped clean on x86_64 but broke the aarch64
CI cross-build:

```
compile fuzz/audit_nlmsg.fcyr -> build/audit_nlmsg-aarch64 [aarch64] FAIL
error:4225: sub-8-byte struct field load is x86-only for v5.6.0; aarch64 + cx pending
```

The error message itself flags the gap as known-pending in
cyrius. agnosys 1.1.9 reverts source-side and adds an aarch64
cross-build to local audit so this regression class doesn't
slip past local validation again.

### Changed
- **`src/audit.cyr`** + **`src/security.cyr`** — V1.1.8's typed
  struct decls + pointer-to-struct dot syntax reverted to the
  pre-V1.1.8 explicit `store16`/`store32`/`load16`/`load32`
  pattern. The original kernel-ABI byte layout is preserved
  (which is the same as V1.1.8 produced; this is purely a
  source-style revert).
- **`scripts/audit.sh` gate 4 (build)** — added `cyrius build
  --aarch64` cross-build when `cc5_aarch64` is present locally,
  with the same `non-exhaustive`-warning gate as the x86_64
  build. Catches the aarch64-specific class of regression
  (sub-8-byte struct field loads, future arch-only codegen
  paths) in local audit instead of CI-only.
- **`docs/development/issues/2026-05-07-cyrius-aarch64-sub-8-byte-struct-load.md`**
  — new upstream issue filed; reproducer at
  `/tmp/cyrius-aarch64-sub-8-byte-struct-load/`.
- **`dist/agnosys.cyr`** regenerated. 9,912 → 9,886 lines (back
  to the pre-V1.1.8 size since the typed struct decls are
  reverted).

### Verified
- All 10 audit gates pass under cyrius 5.9.25, including the
  new aarch64 cross-build step.
- 234 / 234 integration tests pass.
- API surface clean: 721 fns, no drift.

### Status of V1.1.8

V1.1.8 (multi-width struct fields for kernel binary protocols)
re-enters the queue. The migration shape (typed `struct` decl
+ `var s: T = ptr;` pointer-to-struct dot syntax for kernel-ABI
write/read) is correct and verified working on x86_64. When the
cyrius aarch64 backend implements sub-8-byte struct field loads
(per the issue's "Suggested upstream investigation" — the fix
is parallel to the existing aarch64 sub-8-byte STORE codegen),
V1.1.8 reopens with the same source change.

## [1.1.8] — 2026-05-07

**V1.1.8 — Multi-width struct fields for kernel binary protocols.**
Four kernel-ABI structs migrated from explicit
`store8`/`store16`/`store32` calls + offset comments to typed
`struct` decls + pointer-to-struct dot syntax. cyrius's
width-correct codegen emits the correct `store16`/`store32`/
`load16`/`load32` instructions automatically; the kernel-correct
tight-packed byte layout is enforced by the typed field
declarations.

### Changed
- **`src/audit.cyr`** — three kernel-ABI structs added:
  - `struct sockaddr_nl { nl_family: i16; nl_pad: i16; nl_pid: i32;
    nl_groups: i32; }` (12 B). `audit_sockaddr_nl(pid)` rewritten
    to use dot syntax.
  - `struct nlmsghdr { nlmsg_len: i32; nlmsg_type: i16;
    nlmsg_flags: i16; nlmsg_seq: i32; nlmsg_pid: i32; }` (16 B).
    `audit_build_nlmsg` write side rewritten; `audit_recv_raw`
    read side at the parser checkpoint converted from
    `load32(recv_buf)`/`load16(recv_buf+4)`/`load32(recv_buf+8)`
    to `var hdr: nlmsghdr = recv_buf; hdr.nlmsg_len/...`.
  - `struct audit_kstatus { mask: i32; enabled: i32; failure: i32;
    pid: i32; rate_limit: i32; backlog_limit: i32; lost: i32;
    backlog: i32; }` (32 B — first 32 bytes of the kernel
    `audit_status`). `audit_get_status`'s payload parser at
    lines 470-478 rewritten from 6 paired `store64(... load32(pld+N))`
    calls to typed dot-syntax field reads. `audit_set_enabled`'s
    payload write at line 500-501 also rewritten.
- **`src/security.cyr`** — `struct bpf_insn { code: i16; jt: i8;
  jf: i8; k: i32; }` (8 B). `security_bpf_write_insn` rewritten
  to use dot syntax. Other stack-local kernel-ABI writes
  (`landlock_attr` at line 106, `sock_fprog` at line 195) left
  as-is — stack locals use 8-byte slots regardless of declared
  width per vidya `multi_width_types`, so the typed-struct-on-stack
  pattern doesn't preserve kernel ABI for them.
- **`dist/agnosys.cyr`** regenerated. 9,886 → 9,912 lines (+26
  from new struct decls; struct decls are textual, not
  compiled-out).

### Verified
- All 10 audit gates pass under cyrius 5.9.25.
- 234 / 234 integration tests pass — including the audit-regression
  block that exercises `audit_recv_raw`'s nlmsghdr parser and
  `audit_get_status`'s audit_status payload reader.
- 30 benchmarks across 11 groups; bench parity unchanged.
- API surface clean: 721 fns, no drift (struct decls are not
  public fns; the dot-syntax writes don't add accessor surface).
- 14 explicit width-store calls eliminated (3 store16 + 7 store32
  in audit.cyr; 1 store16 + 2 store8 + 1 store32 in security.cyr)
  + 3 width-load reads in `audit_recv_raw`.

### Discovery worth recording

Two cyrius behaviors verified during this slot:

1. **`#derive(accessors)` lays typed fields out at i64 slots,
   NOT at FIELDOFF tight-packed offsets.** A struct
   `{ x: i16; y: i16; z: i32; }` has `sizeof = 8` (correct via
   `sizeof(struct)`), but derive's generated accessors write
   `set_x` at +0, `set_y` at +8, `set_z` at +16 — using i64
   slot spacing. Means `#derive(accessors)` is suitable for
   internal-layout structs but NOT for kernel-ABI structs where
   the byte layout must match.
2. **Pointer-to-struct dot syntax (`var s: T = ptr; s.f = v;`)
   honors width-aware tight-packed offsets.** Verified by
   byte-dumping after writes — `set_nl_family` at offset 0 (2 bytes),
   `set_nl_pid` at offset 4 (4 bytes), kernel-ABI-correct.
   This is the migration vehicle for V1.1.8.

These are language-design observations, not bugs — each codegen
path serves a different use case. Worth documenting because
"use derive for accessors, use dot syntax for kernel-ABI structs"
is the rule that emerges.

## [1.1.7] — 2026-05-07

**V1.1.7 — Tagged-union `Result` adoption verification.**
The slot anticipated migrating agnosys's `Result`/`Option`
construction from `lib/tagged.cyr`'s hand-rolled `tagged_new`/
`tag`/`is_tag` primitives to cyrius's first-class
`enum Result<T, E> { Ok(v); Err(e); }` form. Verification on
cyrius 5.9.25 stdlib:

- `lib/result.cyr` (v5.8.28 carve-out from lib/tagged.cyr) defines
  `Result<T, E>` as a first-class sum type with derive-emitted
  `Ok(v)` and `Err(e)` constructors.
- `lib/tagged.cyr` (v5.8.23) defines `Option { None(); Some(v); }`
  the same way.
- agnosys's call sites use **only** the high-level API: `Ok(...)`,
  `Err(...)`, `is_ok(res)`, `is_err_result(res)`, `payload(res)`.
  Zero direct `tagged_new(...)`, `tag(...)`, or `is_tag(...)`
  calls in src/* — confirmed via grep across all 24 source files.

Net for agnosys: when `return Ok(value);` is compiled, cyrius
resolves `Ok` to the first-class sum-type constructor in
`lib/result.cyr`, which emits the heap-allocated 16-byte pair
(tag at +0, payload at +8). Same shape as the pre-5.8.21
hand-rolled `tagged_new(OK, value)`, transparently. agnosys is
already on first-class tagged unions via the stdlib's transparent
migration; no source changes needed.

The roadmap slot's "35 call sites" referred to the cumulative
high-level API usage (`Ok`, `Err`, `is_ok`, `payload`), not
direct `tagged_new`/`tag`/`is_tag` primitives. These call sites
already use the first-class form by routing through stdlib;
they don't need a syntactic migration.

Pattern-payload destructuring (`match res { Ok(v) => use(v) }`)
is NOT yet shipped in cyrius (per vidya `tagged_unions_v58x`:
"That's a future slot"). When it lands, agnosys's `if (is_err_result(res) == 1) { return res; } var v = payload(res);` chains
will become candidates for the cleaner `match` form. Until then,
the if/payload chain is the canonical idiom and stays.

### Changed
- **`VERSION`** 1.1.6 → 1.1.7.
- **`dist/agnosys.cyr`** regenerated (header v1.1.7 — no body
  changes).

### Verified
- All 10 audit gates pass.
- 234 / 234 integration tests pass; Result/Option behavior
  unchanged.
- 30 benchmarks across 11 groups; bench parity unchanged.
- API surface clean: 721 fns, no drift.

## [1.1.6] — 2026-05-07

**cyrius pin 5.9.20 → 5.9.25 — match-coverage check now
deterministic across fn names. 1.1.5 corrigendum.**

The match-coverage non-exhaustive warning that 1.1.5 wired into
the audit gate was fn-name-dependent on cyrius 5.9.20–5.9.21
(roughly 50/50 hit rate across hash buckets in the coverage
check's internal bookkeeping). The 1.1.5 CHANGELOG attributed
the inconsistency to DCE-gating; that diagnosis was wrong. The
real cause was a hash-table indexing bug, fixed upstream in
cyrius 5.9.25.

### Changed
- **`cyrius.cyml [package].cyrius`** pinned `5.9.20` → `5.9.25`.
- **`docs/development/issues/2026-05-06-cyrius-match-coverage-fn-name-dependent.md`**
  → moved to `archive/`; status header updated to RESOLVED with
  cyrius 5.9.25 verification trail.
- **`dist/agnosys.cyr`** regenerated.

### Corrigendum to 1.1.5

The 1.1.5 CHANGELOG claimed:

> The check fires for ALL enum forms (explicit-value `= N`,
> bare-name auto-incremented, paren'd-variant sum types) —
> earlier testing missed this because dead-code-eliminated fns
> are skipped before the check runs. Adding a caller surfaces
> the warning reliably.

The "DCE skips dead fns" hypothesis was wrong. Re-running the
original failing probe under controlled fn-name variations
revealed the real cause was **fn-name-dependent dispatch** in the
coverage check — same source, only the fn identifier changed,
warning fires for some names and silently skips others (e.g.
`fn n` fires, `fn nm` doesn't; `fn name` doesn't, `fn dispatch_e1`
does). The "adding a caller surfaces the warning" effect was
correlation: the names used in successful probes happened to be
in lucky hash buckets; the names in failed probes were in unlucky
ones. Fixed in cyrius 5.9.25; full diagnosis in the now-archived
[`docs/development/issues/archive/2026-05-06-cyrius-match-coverage-fn-name-dependent.md`](docs/development/issues/archive/2026-05-06-cyrius-match-coverage-fn-name-dependent.md).

The 1.1.5 audit gate as written (`scripts/audit.sh` step 4
greps build log for `non-exhaustive`) was correct as a CI hook.
On 5.9.20–5.9.21 its effective coverage was hash-bucket-dependent
(about half of agnosys's matches would have been silently skipped
if more than one existed — `syserr_print` happened to be in a
lucky bucket). On 5.9.25 the gate now reliably catches every
non-exhaustive match across the entire compiled surface.

### Side-observation also fixed

cyrius 5.9.21's `cyrius --version` emitted a trailing `\xb3`
byte before the newline (`cyrius 5.9.21\xb3\n`). cyrius 5.9.25
emits clean `cyrius 5.9.25\n`. Worth noting for any tooling
that consumed the version string.

### Verified
- All 10 audit gates pass under cyrius 5.9.25.
- 234 / 234 integration tests pass.
- Sweep across 13 fn-name variations: all 13 fire the warning
  on 5.9.25 (was a roughly 50/50 mix on 5.9.21).
- API surface clean: 721 fns, no drift.
- Issues directory now empty again — all upstream tooling gaps
  found during V1.1 are archived as resolved.

## [1.1.5] — 2026-05-06

**V1.1.3 — exhaustive `match` coverage adoption.** First match
block in agnosys; first audit-gate enforcement of the
exhaustiveness check.

The roadmap slot anticipated wiring cyrius lint's exhaustive-match
warning across every enum dispatch in src/*. Verification on
cyrius 5.9.20:

- The check fires for ALL enum forms (explicit-value `= N`,
  bare-name auto-incremented, paren'd-variant sum types) — earlier
  testing missed this because dead-code-eliminated fns are skipped
  before the check runs. Adding a caller surfaces the warning
  reliably.
- The warning fires from `cyrius build`, NOT `cyrius lint`. The
  audit's existing lint gate (step 7) does not catch it; the
  build gate (step 4) needs to grep build output to enforce the
  check as a CI failure.
- Most agnosys enum dispatches are already correct as
  if/elif/else chains with explicit catch-all `else` arms (which
  serve as wire-format / debug-output safety nets). Converting
  these to match wholesale would change runtime behavior for
  malformed inputs without gaining exhaustiveness (the catch-all
  → `_ =>` opt-out suppresses the check). Only one fn —
  `syserr_print` — has the right shape for exhaustive-match
  conversion: state-machine error printing where missing a new
  variant should fail loud, not degrade silently.

### Changed
- **`src/error.cyr fn syserr_print`** — converted from a
  7-elif + else chain into a `match kind { ... }` block with all
  8 `SysErrorKind` variants explicit and **no `_ =>` opt-out**.
  This is agnosys's first `match` use. Behavior change: missing
  enum variants (impossible today; potential after future enum
  additions) fall through to the trailing newline + return
  rather than printing "unknown error: ". The compile-time
  warning catches the missing handler before that runtime
  behavior is reachable.
- **`scripts/audit.sh` gate 4 (build)** — now greps the build
  log for `non-exhaustive` and fails the gate with the offending
  warning surfaced. Verified by removing the `ERR_IO` arm
  temporarily; gate fires with the expected message and exits
  non-zero.
- **`dist/agnosys.cyr`** regenerated.

### Verified
- All 10 audit gates pass under cyrius 5.9.20.
- 234 / 234 integration tests pass.
- 30 benchmarks across 11 groups; bench parity unchanged.
- API surface clean: 721 fns, no drift.
- Regression-test verified: deliberately removing a match arm
  triggers the new audit gate failure (not silent).

### Items deliberately scoped out

The 14 enum-to-string fns surveyed earlier (e.g. `update_phase_str`,
`pam_service_name`, `tpm_bank_str`, `update_state_*`) are wire-
format / debug-output serializers that intentionally fall back
to `"unknown"` for malformed input. Converting them to match
without `_ =>` would replace graceful degradation with
fall-through-to-zero (a worse failure mode for non-enum input).
Converting them WITH `_ =>` would suppress the exhaustiveness
check (no protection gained). Their existing if/return chains
are correct as-is.

If a future enum-to-string fn is added where missing-variant-
should-fail-loud IS the right semantic (like `syserr_print`),
prefer match without `_ =>` from the start.

## [1.1.4] — 2026-05-06

**cyrius pin 5.9.18 → 5.9.20 — closes the long-open
sys-stat-x86 issue, completes V1.1.2's stdlib delegation, and
clears the issues directory.**

### Changed
- **`cyrius.cyml [package].cyrius`** pinned `5.9.18` → `5.9.20`.
- **`src/certpin.cyr`** — `certpin_ct_streq(a, b)` body shrunk
  from a 5-line length-check + delegate to a 1-line full
  delegation: `return ct_eq_bytes_lens(a, strlen(a), b, strlen(b));`.
  cyrius 5.9.20 added the dual-length variant `ct_eq_bytes_lens`
  to `lib/ct.cyr` (sigil-paired consolidation; sigil 3.0.2
  retired its own hand-rolled `ct_eq` at the same time). Length
  check is now inside stdlib; cstring wrapper preserved (pin
  storage flows as cstring pointers; length is non-secret).
- **`docs/development/issues/2026-05-01-sys-stat-x86-portability.md`**
  → moved to `archive/`; status header updated to RESOLVED with
  the cyrius 5.9.20 verification trail. The 2026-05-01 issue —
  filed by sigil 3.0 against agnosys 1.0.4 — has been latent
  through the entire 1.0.x and early 1.1.x line because no
  production consumer reached `fuse_validate_mountpoint`. cyrius
  5.9.20 now ships `sys_stat` in both arch peer files
  (`lib/syscalls_x86_64_linux.cyr:309` +
  `lib/syscalls_aarch64_linux.cyr:346`); no agnosys-side shim
  needed.
- **`dist/agnosys.cyr`** regenerated. 9,883 → 9,880 lines (-3
  from the certpin one-liner).

### Verified
- All 10 audit gates pass under cyrius 5.9.20.
- 234 / 234 integration tests pass.
- Bench parity (certpin hot paths, 1.1.3 → 1.1.4):
  - `validate_pin_valid` 234ns → 227ns
  - `validate_pin_invalid` 14ns → 14ns
  - `ct_streq_equal` 129ns → 130ns
  - `ct_streq_diff` 140ns → 139ns
  All within run-to-run noise.
- Issues directory now empty (all 4 V1.x-era issues archived;
  none open).

### Note on sigil 3.1.0

sigil 3.1.0 ships against agnosys 1.1.x as a downstream
confirmation point. sigil's `lib/sigil.cyr:1316 ct_eq` and
`:1332 ct_eq_32` hand-rolls were retired in sigil 3.0.2 (paired
with cyrius 5.9.18 + 5.9.20 stdlib additions). agnosys's public
API has been additive-only across all of V1.1, so the upgrade
is drop-in for sigil and the other 12 consumers.

## [1.1.3] — 2026-05-06

**V1.1.2 reopens — `certpin_ct_streq` now delegates to stdlib's
`ct_eq_bytes`. cyrius pin 5.9.14 → 5.9.18.**
The 1.1.2 deferral landed upstream: cyrius 5.9.18 ships
`ct_eq_bytes(a, b, n)` in `lib/ct.cyr` with the exact body
proposed in the now-archived
[`docs/development/issues/archive/2026-05-06-cyrius-ct-eq-bytes-stdlib.md`](docs/development/issues/archive/2026-05-06-cyrius-ct-eq-bytes-stdlib.md).
agnosys's hand-rolled body shrinks from 16 lines to a 5-line
cstring wrapper that delegates the byte-loop to stdlib.

### Changed
- **`cyrius.cyml [package].cyrius`** pinned `5.9.14` → `5.9.18`.
- **`cyrius.cyml [deps].stdlib`** — added `"ct"` so `lib/ct.cyr`
  is auto-prepended for `cyrius build/test/bench/fuzz/check/soak/smoke`.
- **`src/main.cyr`** — added explicit `include "lib/ct.cyr"`.
- **`tests/tcyr/test_integration.tcyr`** — added explicit
  `include "lib/ct.cyr"`.
- **`src/certpin.cyr`** — `certpin_ct_streq(a, b)` body
  rewritten. Length-mismatch early-return preserved (cstring
  wrapper concern; pin length is non-secret in agnosys — 44-char
  base64 SHA-256, fixed by spec). Byte loop replaced with a call
  into `ct_eq_bytes(a, b, alen)`. Public signature unchanged;
  semantics unchanged.
- **`docs/development/issues/2026-05-06-cyrius-ct-eq-bytes-stdlib.md`**
  → moved to `archive/`; status header updated to RESOLVED with
  the cyrius 5.9.18 verification trail.
- **`dist/agnosys.cyr`** regenerated.

### Verified
- All 10 audit gates pass under cyrius 5.9.18.
- 234 / 234 integration tests pass.
- `fuzz/certpin_pin.fcyr` unchanged behavior.
- Bench parity (certpin hot paths, comparing 1.1.2 → 1.1.3):
  - `validate_pin_valid` 224ns → 234ns (within run-to-run noise)
  - `validate_pin_invalid` 14ns → 14ns (unchanged)
  - `ct_streq_equal` 125ns → 129ns (within noise; no fn-call
    overhead measurable over the 16+ byte XOR loop)
  - `ct_streq_diff` 135ns → 140ns (within noise)
- API surface clean: 721 fns, no drift.

## [1.1.2] — 2026-05-06

**V1.1.2 — `secret var` + `ct_eq` builtin in certpin —
DEFERRED, slot's upstream premise incomplete.**
The roadmap slot anticipated swapping
`src/certpin.cyr:120 fn certpin_ct_streq(a, b)` to a cyrius
compiler-backed `ct_eq` primitive plus `secret var` annotation
on pin storage. Verification on cyrius 5.9.14 shows the
prerequisites aren't shipped:

- `ct_eq` is not a compiler builtin (build warns "undefined
  function 'ct_eq'", binary SIGILLs at runtime).
- `lib/ct.cyr` ships only `ct_select`; no `ct_eq*` helper.
- `secret var` requires array form (`secret var buf[N]`); scalar
  declaration rejected. Pin storage flows as cstring pointers
  through struct boundaries — doesn't fit the array-only
  contract.

The hand-rolled `certpin_ct_streq` in `src/certpin.cyr:120` is
correct (canonical XOR-accumulate; no data-dependent branches);
nothing in the existing implementation needs fixing for
correctness.

Filed upstream issue
[`docs/development/issues/2026-05-06-cyrius-ct-eq-bytes-stdlib.md`](docs/development/issues/2026-05-06-cyrius-ct-eq-bytes-stdlib.md)
proposing `ct_eq_bytes(a, b, n)` for `lib/ct.cyr`. Local
reproducer at `/tmp/cyrius-ct-eq-stdlib/`. When the helper lands,
the V1.1.2 slot reopens as a one-line swap (replace certpin's
hand-roll body with a call into stdlib).

### Bench parity

Audit gate 10 (benchmarks) passes; certpin hot paths unchanged
from 1.1.1 baseline (`ct_streq_equal` ~125ns, `ct_streq_diff`
~135ns).

### Changed
- **`docs/development/issues/2026-05-06-cyrius-ct-eq-bytes-stdlib.md`**
  — new upstream issue: `ct_eq_bytes` should be added to
  `lib/ct.cyr` to deduplicate hand-rolled CT-equality across
  agnosys's `certpin_ct_streq` and sigil's `lib/sigil.cyr:1316
  ct_eq`.
- **`VERSION`** 1.1.1 → 1.1.2.
- **`dist/agnosys.cyr`** regenerated (header v1.1.2 — no body
  changes).

### Verified
- All 10 audit gates pass.
- 234 / 234 integration tests pass; `fuzz/certpin_pin.fcyr`
  unchanged behavior.
- 30 benchmarks across 11 groups; bench parity unchanged.
- API surface clean: 721 fns, no drift.

## [1.1.1] — 2026-05-06

**V1.1.1 — `defer { }` adoption / resource-cleanup audit.**
The roadmap slot anticipated migrating flag-based cleanup paths
to per-flag `defer { }` blocks. The audit found that the work was
largely already done during the original Rust → Cyrius port:
24 `defer { sys_close(...) }` sites were already in place across
mac, fuse, drm, audit, journald, luks, dmverity, ima, tpm,
secureboot, pam, netns, update, security, and logging. This slot
ships as the **verification + audit pass** with the findings
documented; no source changes were needed.

### Audit scope

- Every `sys_open`, `sys_socket`, `syscall(SYS_LANDLOCK_*)`, and
  other fd-returning syscall site walked end-to-end against its
  cleanup path.
- For each fn that opens an fd, verified that all return paths
  either close it (manually or via defer) or pass ownership to
  the caller.
- For each existing `defer { }` site, verified that the defer
  registration sits immediately after the fd-validity check —
  before any other fallible call — so all subsequent error
  returns hit the cleanup.
- Surveyed every `sys_close` call that's not inside a `defer { }`
  block (9 sites) and classified each as deliberate vs. needs-fix.

### Findings — no leaks

The 9 non-defer `sys_close` sites are all deliberate:

| Site | Pattern | Why explicit close |
|---|---|---|
| `audit.cyr` `audit_open` | close-on-error before returning fd to caller | defer would close the fd we want to return on success path |
| `bootloader.cyr` `bootloader_detect` (×2) | existence-probe (open, close, return immediately) | structure simpler than defer; close-before-return is one line |
| `drm.cyr` `drm_close` | the close API itself | this IS the consumer cleanup fn, not a candidate |
| `netns.cyr` ruleset-write | close before subprocess that reads the file | defer at fn-end closes too late; nft would see unflushed data |
| `secureboot.cyr` `secureboot_detect_state` / `secureboot_list_efi_variables` | existence-probe (open, close, continue) | fd is just used for existence check; close ASAP |
| `update.cyr` `update_get_current_slot` (×2) | open-read-close-then-parse | parse uses the buffer, not the fd; explicit close is more memory-efficient than holding fd open until fn end |

`security.cyr` `security_apply_landlock` opens `path_fd` inside a
loop and explicitly closes after each iteration's
`SYS_LANDLOCK_ADD_RULE`. defer would not fit here — cyrius's defer
registration is fn-level, not iteration-level (per
vidya `features.cyml` `defer_statement`: 8 defer blocks per
function, registered once when first reached). The current
explicit-close pattern is the correct shape for resource
acquisition inside a loop.

### Bench parity

Audit gate 10 (benchmarks) passes; 30 benchmarks across 11 groups
unchanged from 1.1.0 baseline. No defer-epilogue overhead was
added because no new defer sites were introduced.

### Items deliberately scoped out

- The roadmap's "Migrate flag-based cleanup paths in audit /
  journald / luks / tpm / dmverity / fuse" was already complete
  in the inherited port; no flag-based cleanup remains.
- `update_atomic_write` and `update_atomic_copy` already use
  defer for both source and destination fds (1.0 baseline).

### Changed
- **`VERSION`** 1.1.0 → 1.1.1.
- **`dist/agnosys.cyr`** regenerated (header v1.1.1 — no body
  changes).

### Verified
- All 10 audit gates pass.
- 234 / 234 integration tests pass.
- 30 benchmarks across 11 groups; bench parity unchanged from 1.1.0.
- API surface clean: 721 fns, no drift vs 1.0 snapshot.

## [1.1.0] — 2026-05-06

> **agnosys 1.1.0 — `#derive(accessors)` adoption.** First minor
> release after the 1.0 freeze. Pure refactor on the project
> side; pure ergonomics for downstream consumers. Drop-in upgrade
> from any 1.0.x. cyrius 5.9.14 required.

### What's in 1.1.0

The `[1.1.0]` tag is the cumulative end of the 1.0.6 → 1.0.13
patch line. The slot-by-slot detail lives in those entries; this
banner is the consumer-facing summary.

**Theme:** every heap-allocated struct in agnosys's 16
struct-bearing modules now uses cyrius's `#derive(accessors)`
syntax instead of hand-written `store64` / `load64` at fixed
offsets. 37 derive structs total. The migration removes ~635
raw offset-arithmetic call sites from the implementation while
keeping the public API additive-only — every fn that existed
in 1.0 still exists with the same name and arity.

### Migration notes for consumers

- **Drop-in.** No source changes required. The 1.0 public surface
  is preserved exactly; `scripts/check-api-surface.sh` against
  the 1.0 snapshot reports zero removals and zero arity changes
  across all of V1.1.
- **New additive surface.** 160 new accessor entries (the auto-
  generated `<struct>_set_<field>(p, v)` setters that 1.0 didn't
  ship). Snapshot count: 561 (1.0 freeze) → 721 (1.1.0). All
  new entries are additive — opt-in for consumers, no behavior
  change for callers that don't use them.
- **cyrius pin.** 1.1.0 requires cyrius **5.9.14** or later
  (5.9.7+ for the `#derive(accessors)` 32-struct cap fix; 5.9.12+
  for `cyrius api-surface --scope=project`; 5.9.14+ for the
  `cyrius_api_surface` helper binary in the release tarball).
- **No breaking changes.** No fn renamed, removed, or arity-
  changed since 1.0.0.
- **No security fixes.** All findings from the 2026-04-26 P(-1)
  audit shipped in 1.0.1; nothing security-relevant in V1.1.

### Cumulative numbers (recorded at 1.0.13 closeout)

- 16 of 16 struct-bearing modules migrated; 37 derive structs.
- 234 / 234 integration tests pass.
- 30 benchmarks across 11 groups — flat vs 1.0.5 baseline,
  except `update_compare_versions` (132 → 158 ns, +20%, code-
  locality artifact from struct decls landing in the same file;
  function body unchanged).
- Binary size (DCE): 85,592 B unchanged from 1.0.5.
- `dist/agnosys.cyr`: 9,886 lines (-68 from 1.0.5; removed
  hand-written accessor fns).
- 282 dead-code fns under `CYRIUS_DCE=1` (consumers compile only
  their needed subset).
- All 10 audit gates clean.

### Items intentionally not migrated (legitimate non-derive cases)

These three are documented inline at the relevant src sites:

- `src/error.cyr` `syserr` (3 fields, packed-vs-heap dispatch on
  the integer value — `#derive(accessors)` would only handle the
  heap branch and would conflict with the public dispatch fns).
- `src/audit.cyr` `sockaddr_nl` (12 B, multi-width: u16/u16/u32/u32
  — packed kernel ABI, not a heap bag of i64s).
- `src/security.cyr` BPF instruction (8 B, multi-width:
  u16/u8/u8/u32 — packed kernel ABI).

### What's next

The 1.1.x backlog from `docs/development/roadmap.md` queues
seven feature-adoption slots that build on the cyrius
language surface that landed during V1.1.0:

- **1.1.1** — `defer { }` adoption for resource-cleanup paths
- **1.1.2** — `secret var` + `ct_eq` builtin in certpin (replaces
  hand-rolled `certpin_ct_streq`)
- **1.1.3** — exhaustive `match` coverage adoption
- **1.1.4** — first-class tagged-union `Result` replacing
  `lib/tagged.cyr`
- **1.1.5** — multi-width struct fields for kernel binary
  protocols (audit_status, dm_verity_args, IMA, TPM)
- **1.1.6** — slice migration for syscall + parser buffers
- **1.1.7** — `#derive(Serialize)` for diagnostic JSON output

V1.2.0 (multi-profile `cyrius distlib`) follows. See
[`docs/development/roadmap.md`](docs/development/roadmap.md)
for the full plan and [ADR-004](docs/adr/004-1-1-x-roadmap-rework.md)
for the slotting rationale.

### References

- Slot-by-slot detail: 1.0.6 (mac) → 1.0.7 (fuse/drm/bootloader)
  → 1.0.8 (dmverity/luks/certpin) → 1.0.9 (udev/journald/audit)
  → 1.0.10 (ima/tpm/secureboot) → 1.0.11 (pam/netns/update +
  cyrius 5.9.7) → 1.0.12 (api-surface tooling cleanup +
  cyrius 5.9.14) → 1.0.13 (closeout + baseline).
- Cyrius bugs filed and resolved during V1.1.0:
  - `docs/development/issues/archive/2026-05-06-cyrius-derive-accessors-32-struct-cap.md`
    (resolved cyrius 5.9.7)
  - `docs/development/issues/archive/2026-05-06-cyrius-api-surface-derive-blind.md`
    (resolved cyrius 5.9.9 + 5.9.12 + 5.9.13 + 5.9.14)

## [1.0.13] — 2026-05-06

**V1.1.0 closeout — final 1.0.x patch before tagging 1.1.0.**
The eight slots from 1.0.6 → 1.0.12 (mac → fuse/drm/bootloader →
dmverity/luks/certpin → udev/journald/audit → ima/tpm/secureboot →
pam/netns/update → toolchain bumps + tooling cleanup) ship as
1.1.0. Per CLAUDE.md "Closeout Pass": this patch is the final
1.0.x slot; cumulative bench/audit/dead-code/binary-size baseline
recorded; ready for 1.1.0 tag.

### Closeout — Cumulative V1.1.0 baseline

| Metric | Value | Notes |
|---|---|---|
| Modules migrated | **16 of 16** struct-bearing | mac, fuse, drm, bootloader (×2), dmverity (×2), luks, certpin (×3), udev, journald (×2), audit (×4), ima (×3), tpm (×2), secureboot (×3), pam (×3), netns (×4), update (×4) |
| Derive structs | **37** | All under cyrius's 5.9.7+ derive-emitter (32-struct cap fixed in 5.9.7) |
| Public fns (snapshot) | **721** | up from 561 at 1.0.0 freeze; +160 additive entries (no removals, no signature drift). Cumulative additions since 1.0 freeze: 160 |
| Binary size (DCE) | **85,592 B** | unchanged from 1.0.5 baseline; V1.1 migration is pure refactor |
| `dist/agnosys.cyr` size | **9,886 lines** | down from 9,954 at 1.0.5 (-68 lines from removing hand-written accessor fns) |
| Dead-code count | **282 fns** | under `CYRIUS_DCE=1`; consumers compile only their needed subset |
| Integration tests | **234 / 234** pass | unchanged from 1.0.5 |
| Bench groups | **30 benchmarks across 11 groups** | overall flat vs 1.0.5 baseline; one observed drift below |
| Fuzz harnesses | **6** | audit_nlmsg, audit_reply, certpin_pin, journald_filter, luks_cipher, pam_config |
| Audit gates | **10 / 10** clean | syntax, API surface, capacity, build, smoke, tests, lint, vet, fuzz, benchmarks |
| cyrius pin | **5.9.14** | up from 5.7.6 at 1.0.0 freeze |

### Bench drift observation

`update_compare_versions`: 132 ns (1.0.5) → 157–158 ns (1.0.12+,
reproducible across runs). +20% drift. Function body **unchanged**
across V1.1 — the regression is a code-locality artifact from
adding 4 derive-struct decls + accessor emissions to the same
file (cache-line / page layout shift). Not blocking; flagged here
for posterity. No other bench shows comparable drift.

### Items not migrated (legitimate non-derive cases)

- `src/error.cyr` `syserr` (24 B, 3 fields: kind/errno/message).
  The public fns `syserr_kind/1`, `syserr_errno/1`,
  `syserr_message/1` dispatch on packed-vs-heap encoding — packed
  errors live in the integer value (`kind << 16 | errno`), heap
  errors are pointers to the 24-byte struct. `#derive(accessors)`
  would only handle the heap branch and would conflict with the
  dual-encoding fn names. Hand-written `store64`/`load64` in
  `syserr_new` is the correct shape.
- `src/audit.cyr` `sockaddr_nl` (12 B, multi-width fields:
  u16/u16/u32/u32). Packed kernel ABI struct, not a heap bag of
  i64s. `store16`/`store32` are kernel-correct; the layout
  comment is necessary documentation, not stale.
- `src/security.cyr` BPF instruction (8 B, multi-width:
  u16/u8/u8/u32). Same — packed ABI struct, not a derive
  candidate. Kernel-defined layout documented inline.

### Downstream check (best-effort)

13 consumers in scope per `docs/development/roadmap.md`:
kavach, aegis, shakti, libro, stiva, sigil, ark, argonaut,
daimon, nein, yukti, soorat, hoosh. All consume only the modules
they need (per the consumer-map). Public API surface is
1.0-additive only across all of V1.1 — no consumer should require
a code change to upgrade from agnosys 1.0.x to 1.1.0. Automated
per-consumer integration CI is roadmap V1.2.3 (not blocking 1.1).

### Roadmap state

V1.1.0 (`#derive(accessors)` migration) — **complete**. Ready for
1.1.0 tag. Subsequent 1.1.x slots from `docs/development/roadmap.md`
remain queued: `defer { }` adoption (1.1.1), `secret var` +
`ct_eq` in certpin (1.1.2), exhaustive match coverage (1.1.3),
tagged-union sum types (1.1.4), multi-width struct fields (1.1.5),
slice migration (1.1.6), `#derive(Serialize)` diagnostics (1.1.7).

### Changed
- **`VERSION`** 1.0.12 → 1.0.13.
- **`bench-history.csv`** — closeout snapshot recorded
  (33 benchmarks; one row per bench).
- **`dist/agnosys.cyr`** regenerated (header v1.0.13).

### Verified
- Full clean DCE build from `rm -rf build`: produces 85,592-byte
  binary, reproducible.
- All 10 audit gates pass.
- 234 / 234 integration tests pass.
- API surface clean against 1.0 snapshot — 721 fns, no drift.

## [1.0.12] — 2026-05-06

**Tooling cleanup — `cyrius api-surface` adoption + cyrius pin
bump to 5.9.14.** All three blockers tracked in the api-surface
issue resolved upstream; `scripts/check-api-surface.sh` reduced
from a 70-line awk walker to a four-line wrapper around the
official command. Snapshot byte-identical (721 fns); no API
change for consumers.

### Changed
- **`cyrius.cyml [package].cyrius`** pinned `5.9.7` → `5.9.14`.
  cyrius 5.9.13 closed the last open item from
  [`docs/development/issues/archive/2026-05-06-cyrius-api-surface-derive-blind.md`](docs/development/issues/archive/2026-05-06-cyrius-api-surface-derive-blind.md):
  `--snapshot=PATH` is now honored. Combined with 5.9.9
  (derive-aware scanner) and 5.9.12 (`--scope=project`), the
  official command produces output byte-identical to agnosys's
  previous in-script awk walker. The 5.9.13 release tarball
  shipped without the `cyrius_api_surface` helper that
  `cyrius api-surface` shells out to, breaking CI's
  curl + tar + cp install (locally the helper was masked by an
  older install lingering in `~/.cyrius/bin/`); cyrius 5.9.14
  ships the helper in `bin/cyrius_api_surface` so the pin lands
  there directly.
- **`scripts/check-api-surface.sh`** — replaced with a thin
  wrapper. The previous awk-based walker (with the
  `#derive(accessors)` extension added in 1.0.6) is gone in
  favor of `exec cyrius api-surface "$@" --scope=project
  --snapshot=docs/development/api-surface-1.0.snapshot`.
  Both diff-mode and `--update`-mode UX preserved. The
  hand-written derive-walker that 1.0.6 added is no longer
  needed since cyrius 5.9.9's derive-aware scanner; the stdlib
  filter is no longer needed since cyrius 5.9.12's
  `--scope=project`; the snapshot path no longer needs
  redirection now that cyrius 5.9.13 honors `--snapshot=PATH`.
- **`docs/development/issues/2026-05-06-cyrius-api-surface-derive-blind.md`**
  → moved to `archive/`; status header updated to RESOLVED
  with the 5.9.9/5.9.12/5.9.13 version trail.
- **`docs/development/issues/2026-05-06-cyrius-derive-accessors-32-struct-cap.md`**
  → already moved to `archive/` in 1.0.11; status header noting
  cyrius 5.9.7 as the fix is unchanged.
- **`dist/agnosys.cyr`** regenerated.

### Verified
- All 10 audit gates pass under cyrius 5.9.14.
- `scripts/check-api-surface.sh` (four-line wrapper) reports
  "ok: 721 public fns, surface matches snapshot exactly".
- `scripts/check-api-surface.sh --update` regenerates the
  snapshot in place at `docs/development/api-surface-1.0.snapshot`;
  byte-identical content to the previous awk-walker output.
- `tar tzf cyrius-5.9.14-x86_64-linux.tar.gz | grep cyrius_api_surface`
  lists `cyrius-5.9.14-x86_64-linux/bin/cyrius_api_surface`
  (absent from the 5.9.13 tarball; that's why this slot pins
  5.9.14 not 5.9.13).

## [1.0.11] — 2026-05-06

**V1.1.0 `#derive(accessors)` migration complete — final batch
(pam + netns + update) + cyrius toolchain bump to 5.9.7.**
All 16 struct-bearing modules migrated; 11 structs in this slot.
Cumulative: 16 of 16. Ready for V1.1.0 closeout pass next.

### Changed
- **`cyrius.cyml [package].cyrius`** pinned `5.9.1` → `5.9.7`.
  cyrius 5.9.7 fixes the derive-accessors 32-struct cap bug
  documented in
  [`docs/development/issues/2026-05-06-cyrius-derive-accessors-32-struct-cap.md`](docs/development/issues/2026-05-06-cyrius-derive-accessors-32-struct-cap.md).
  Verified under both modes of the local reproducer at
  `/tmp/cyrius-derive-truncation/` — Mode 1 sweep (N=28..36) is
  clean across the range; Mode 2 agnosys-flavor 37-struct case
  resolves all derive-emitted accessors and runs to exit 0.
- **`src/pam.cyr`** — three structs migrated to `#derive(accessors)`:
  - `pam_rule` (32 B, 4 fields). Field name `type` matches the
    1.0 getter `pam_rule_type/1` (not the constructor arg
    `rule_type`). Adds 4 setters (additive).
  - `pam_user` (56 B, 7 fields). Field `home` matches the 1.0
    getter (not constructor arg `home_dir`). Field `groups_arr`
    dodges the 3-arg `pam_user_set_groups(u, groups, is_system)/3`
    collision; the 1.0 `pam_user_groups/1` getter and 3-arg setter
    stay as thin wrappers. The 6-arg multi-field setter
    `pam_user_set/6` keeps its name and delegates through derive
    setters. Adds 7 setters + 1 getter (`groups_arr`) additive.
  - `pam_session` (48 B, 6 fields). Field `id` matches the 1.0
    getter (not constructor arg `session_id`). Adds 6 setters.
- **`src/netns.cyr`** — four structs migrated:
  - `netns_config` (56 B, 7 fields). 3-arg
    `netns_config_set_dns(c, dns_arr, dns_count)/3` keeps its
    name and delegates through derive setters. Adds 7 setters +
    2 getters (`dns_arr`, `dns_count`) additive.
  - `netns_handle` (32 B, 4 fields). Clean swap; 4 setters added.
  - `netns_fw_rule` (48 B, 6 fields). Clean swap; 6 setters added.
  - `netns_fw_policy` (32 B, 4 fields). Field names match 1.0
    getters: `default_in`/`default_out` (not `default_inbound`/
    `default_outbound`). Field `rules_arr` dodges the 3-arg
    `set_rules/3` collision; 1.0 `rules`/`set_rules` stay as
    wrappers. Adds 4 setters + 1 getter (`rules_arr`) additive.
- **`src/update.cyr`** — four structs migrated:
  - `update_state` (40 B, 5 fields). Field names match 1.0
    getters (`slot`/`version`/`pending`/`rollback_available`/
    `boot_count`), not the doc-comment names. The 1.0 `set_rollback/2`
    setter (asymmetric — getter is `rollback_available`) stays as
    a thin wrapper delegating through `set_rollback_available/2`.
    Adds 5 setters new for the field names + 1 (`set_rollback_available`)
    additive.
  - `update_config` (56 B, 7 fields). Field-name shortenings to
    match 1.0 getters: `url`/`slot_a`/`slot_b` (not `update_url`/
    `slot_a_device`/`slot_b_device`); `verify` (not
    `verify_after_apply`). Adds 7 setters additive.
    `update_config_device_for_slot/2` body rewired to call derive
    accessors instead of raw `load64`.
  - `update_manifest` (48 B, 6 fields). Field `files` matches 1.0
    getter (not doc `files_vec`). Adds 6 setters additive.
  - `update_file` (40 B, 5 fields). Field `size` matches 1.0
    getter (not `size_bytes`). Adds 5 setters additive.
- **`docs/development/api-surface-1.0.snapshot`** — additive bump:
  62 new entries across the three modules (15 pam, 22 netns, 25
  update). 1.0 surface preserved exactly; no removals. Snapshot
  total: 721 fns.
- **`dist/agnosys.cyr`** regenerated. 9,894 (1.0.10) → 9,886 lines.

### Verified
- All 10 audit gates pass under cyrius 5.9.7.
- 234 / 234 integration tests pass (the previously-failing
  `tests/tcyr/test_integration.tcyr` now resolves all
  derive-emitted accessors cleanly).
- 30 benchmarks across 11 groups; no regressions.
- 6 fuzz harnesses pass.
- Local reproducer at `/tmp/cyrius-derive-truncation/` confirms
  the upstream cyrius 5.9.7 fix:
  - Mode 1 threshold sweep (N=28..36): 0 undefined-fn warnings
    at any N (cap lifted).
  - Mode 2 agnosys-flavor 37-struct repro: 0 undefined-fn
    warnings; binary runs to exit 0.

## [1.0.10] — 2026-05-06

**V1.1.0 `#derive(accessors)` slots 11–13 — ima, tpm, secureboot.**
Three modules, eight structs migrated. Cumulative: 13 of ~13
struct-bearing modules done (security has no heap structs). Last
batch is the larger pam + netns + update set.

### Changed
- **`src/ima.cyr`** — three structs migrated:
  - `ima_rule` (56 B, 7 fields: action, target, uid, fowner, fsuuid,
    obj_type, mask). The 1.0 surface had 5 hand-written setters
    (uid/fowner/fsuuid/obj_type/mask) that returned the rule
    pointer; derive replaces them with same names + arity, returning
    the standard derive value (no callers chained the return —
    grep-verified). Action/target setters new (additive).
  - `ima_status` (24 B, 3 fields: active, measurement_count,
    policy_loaded). Clean swap; 3 setters new.
  - `ima_measurement` (40 B, 5 fields: pcr, template_hash,
    template_name, filedata_hash, filename). Clean swap; 5 setters
    new.
- **`src/tpm.cyr`** — two structs migrated:
  - `tpm_pcr_value` (24 B, 3 fields: index, bank, value). Clean
    swap; 3 setters new.
  - `tpm_sealed` (16 B, 2 fields). Field names `context`/`pcr_sel`
    chosen to match the 1.0 getter names rather than the constructor
    arg names (`context_path`/`pcr_selection`). 2 setters new.
- **`src/secureboot.cyr`** — three structs migrated, all with
  struct-name-vs-getter-prefix mismatches resolved by naming the
  struct after the getter prefix (constructor names are independent
  fn names and stay as-is):
  - `secureboot_key` (40 B, 5 fields: subject, issuer, fingerprint,
    not_before, not_after). 1.0 getter prefix is `secureboot_key_*`
    not `secureboot_enrolled_key_*` — struct named `secureboot_key`;
    constructor `secureboot_enrolled_key_new/5` keeps its name.
    5 setters new.
  - `secureboot_sig` (32 B, 4 fields: module, has_sig, signer,
    algorithm). 1.0 getter prefix is `secureboot_sig_*` not
    `secureboot_sig_info_*`, and field-name shortenings:
    `module_path → module`, `sig_algorithm → algorithm`.
    Constructor `secureboot_sig_info_new/4` keeps its name.
    4 setters new.
  - `secureboot_efi_var` (16 B, 2 fields: name, data_size). 1.0
    getter is `_data_size` (not `_size`) — field named `data_size`
    to match. 2 setters new.
- **`docs/development/api-surface-1.0.snapshot`** — additive bump:
  26 new entries (10 ima, 5 tpm, 11 secureboot). 1.0 surface
  preserved exactly; no removals. Snapshot total: 659 fns.
- **`dist/agnosys.cyr`** regenerated. 9,909 (1.0.9) → 9,894 lines.

### Verified
- All 10 audit gates pass.
- 234 / 234 integration tests pass.
- Bench parity: 30 benchmarks across 11 groups; no regressions.

## [1.0.9] — 2026-05-06

**V1.1.0 `#derive(accessors)` slots 8–10 — udev, journald, audit.**
Three modules, seven structs migrated. Cumulative: 10 of ~13
struct-bearing modules done.

### Changed
- **`src/udev.cyr`** — `udev_devinfo` (72 B, 9 fields: syspath,
  devpath, subsystem, devtype, driver, devnode, prop_keys, prop_vals,
  prop_count) migrated to `#derive(accessors)`. The 9 hand-written
  getters and 6 hand-written single-field setters replaced by 18
  generated accessors (6 setters identical, 9 getters identical,
  3 setters new for the prop_* trio). The 4-arg
  `udev_devinfo_set_props(d, keys, vals, count)/4` keeps its public
  signature; body now delegates through the per-field derive setters.
- **`src/journald.cyr`** — two structs migrated:
  - `journald_entry` (56 B, 7 fields: timestamp, unit, priority,
    message, pid, field_keys, field_vals). 7 hand-written getters
    replaced by 14 generated accessors (7 getters identical, 7
    setters new). `journald_entry_new` rewired through derive
    setters; the `add_field` helper (different name, different
    semantics — appends to the field_keys/field_vals vecs)
    keeps its body.
  - `journald_filter` (56 B, 7 fields: unit, since, until, priority,
    grep, lines, boot). Full hand-written get/set parallel; clean
    swap, byte-identical layout, identical names — no API surface
    change for this struct.
- **`src/audit.cyr`** — four structs migrated:
  - `audit_config` (24 B, 3 fields: use_netlink, use_proc, proc_path).
    The 1.0 surface uses **asymmetric setter names** — getters keep
    the `use_` prefix (`audit_config_use_netlink/use_proc`), but
    setters drop it (`audit_config_set_netlink/set_proc`). Field
    names match the getters; derive generates `set_use_netlink/2`
    and `set_use_proc/2` (additive). The 1.0 `set_netlink/2` and
    `set_proc/2` setters stay as thin wrappers delegating through
    the derive setters.
  - `audit_handle` (16 B, 2 fields: fd, config). Clean swap; 2
    setters added (additive).
  - `audit_status` (48 B, 6 fields: enabled, failure_action, pid,
    backlog_limit, lost, backlog). Clean swap; 6 setters added
    (additive). `audit_status_new()` rewired through derive setters.
  - `audit_rule` (32 B, 4 fields: type, path, syscall_nr, key).
    The 1.0 surface ships `audit_rule_syscall(r)/1` as the getter,
    but `syscall` is a cyrius builtin and can't be a struct field
    name (lib/syscalls_x86_64_linux.cyr line 614 — "expected
    identifier, got unknown"). Field is named `syscall_nr` (matches
    the constructor arg name); derive generates `audit_rule_syscall_nr/1`
    + `set_syscall_nr/2`. The 1.0 `audit_rule_syscall(r)/1` getter
    stays as a thin wrapper. `audit_rule_new/4` rewired through
    derive setters.
- **`docs/development/api-surface-1.0.snapshot`** — additive bump:
  25 new entries (15 audit, 7 journald, 3 udev). 1.0 surface
  preserved exactly; no removals. Snapshot total: 633 fns.
  Cumulative additions since 1.0 freeze: 72.
- **`dist/agnosys.cyr`** regenerated. 9,923 (1.0.8) → 9,909 lines.

### Verified
- All 10 audit gates pass.
- 234 / 234 integration tests pass.
- Bench parity: 30 benchmarks across 11 groups; no regressions vs.
  1.0.8 baseline.

## [1.0.8] — 2026-05-06

**V1.1.0 `#derive(accessors)` slots 5–7 — dmverity, luks, certpin.**
Three modules, six structs migrated. Cumulative: 7 of ~13
struct-bearing modules done.

### Changed
- **`src/dmverity.cyr`** — two structs migrated to `#derive(accessors)`:
  - `dmverity_config` (64 B, 8 fields: name, data_device, hash_device,
    data_block_size, hash_block_size, hash_algorithm, root_hash, salt).
    The 8 hand-written getters replaced by 16 generated accessors
    (8 getters keep their existing names; 8 setters are new additive
    surface). The two named multi-field setters
    `dmverity_config_set_devices(c, name, data_device, hash_device)/4`
    and `dmverity_config_set_params(c, …×5)/6` keep their public
    signatures; their bodies now delegate through the per-field
    derive setters.
  - `dmverity_status` (40 B, 5 fields: name, is_active, is_verified,
    corruption_detected, root_hash). 5 hand-written getters replaced
    by 10 generated accessors (5 getters identical, 5 setters new).
    `dmverity_status_new` rewired through derive setters.
- **`src/luks.cyr`** — `luks_config` (72 B, 9 fields: name,
  backing_path, size_mb, mount_point, filesystem, cipher_algo,
  cipher_mode, key_size_bits, pbkdf) migrated to
  `#derive(accessors)`. 9 hand-written getters replaced by 18
  generated accessors. The two named multi-field setters
  `luks_config_set_core(c, …×5)/6` and `luks_config_set_crypto(c, …×4)/5`
  keep their public signatures; bodies delegate through derive
  setters.
- **`src/certpin.cyr`** — three structs migrated:
  - `certpin_entry` (48 B, 6 fields). The 1.0 surface ships 3-arg
    `set_pins(e, ptr, count)` and `set_backups(e, ptr, count)`
    convenience setters that would collide with derive's auto-generated
    2-arg setters. Resolved by naming the array-pointer fields
    `pins_arr` / `backups_arr` (with new derive accessors); the 1.0
    `pins`/`backups` getters and 3-arg setters stay as thin wrappers.
  - `certpin_set` (24 B, 3 fields). Same pattern as certpin_entry —
    `entries` field renamed to `entries_arr` to dodge the 3-arg
    `certpin_set_set_entries(s, ptr, count)/3` collision; 1.0
    accessors preserved as wrappers.
  - `certpin_info` (56 B, 7 fields: subject, issuer, serial, not_before,
    not_after, sha256_fp, spki_sha256). Full hand-written get/set
    parallel; clean swap, byte-identical layout, identical names —
    no API surface change for this struct.
- **Multi-line struct decl convention.** dmverity_config (8 fields)
  and luks_config (9 fields) decls reformatted onto multi-line
  bodies — the single-line form crossed `cyrius lint`'s
  120-character ceiling. The api-surface awk parser handles
  multi-line struct bodies (was already validated against the
  multi-field bodies).
- **`docs/development/api-surface-1.0.snapshot`** — additive bump:
  34 new entries (12 certpin, 13 dmverity, 9 luks). 1.0 surface
  preserved exactly; no removals. Cumulative additions since 1.0
  freeze: 47 (5 mac in 1.0.6 + 13 fuse/drm/bootloader in 1.0.7 +
  34 dmverity/luks/certpin in 1.0.8 + the 4 pre-existing 1.0.4
  agnosys_fsync/agnosys_rename additions).
- **`dist/agnosys.cyr`** regenerated. 9,932 (1.0.7) → 9,923 lines.

### Verified
- **Bench parity (certpin)** — `validate_pin_valid` 224ns→223ns;
  `validate_pin_invalid` 14ns→13ns; `ct_streq_equal` 129ns→125ns;
  `ct_streq_diff` 139ns→135ns. All within run-to-run noise; no
  regressions on the certpin hot paths.

## [1.0.7] — 2026-05-06

**V1.1.0 `#derive(accessors)` slots 2–4 — fuse, drm, bootloader.**
Three modules, four structs migrated. Cumulative: 4 of ~13
struct-bearing modules done (mac in 1.0.6 + fuse/drm/bootloader
in 1.0.7).

### Changed
- **`src/fuse.cyr`** — `FuseMount` (32 B, 4 ptr fields:
  device/mountpoint/fstype/options) migrated to
  `#derive(accessors) struct fuse_mount { … }`. The 4 hand-written
  `fuse_mount_*` getters are gone, replaced by 8 compiler-generated
  accessors (4 getters keep their existing names; 4 setters are new
  additive surface). `fuse_mount_new` rewired to use the generated
  setters. The pre-existing `fn fuse_mount(...)` syscall wrapper
  (unrelated to the struct) is unaffected — cyrius accepts a struct
  and a same-named fn peacefully because derive emits
  `fuse_mount_<field>` not `fuse_mount` itself.
- **`src/drm.cyr`** — `DrmVersionInfo` (48 B, 6 fields:
  major/minor/patch/name/date/desc) migrated to
  `#derive(accessors) struct drm_verinfo { … }`. The 6 hand-written
  getters replaced by 12 compiler-generated accessors (6 getters
  keep their existing names; 6 setters are new additive surface).
  `drm_verinfo_new` rewired to use the generated setters.
- **`src/bootloader.cyr`** — `BootEntry` (56 B, 7 fields:
  id/title/linux/initrd/options/is_default/version) migrated to
  `#derive(accessors) struct bootloader_entry { … }`. Replaces 14
  hand-written get/set fns with 14 compiler-generated ones —
  byte-identical layout, identical names, no API surface change for
  this struct. `BootConfig` (40 B) also migrated, but with a wrinkle:
  the 1.0 surface ships a 3-arg
  `bootloader_config_set_entries(c, arr, count)` convenience setter
  that writes both the array pointer and the count atomically; that
  would collide with derive's auto-generated 2-arg setter. Resolved
  by naming the array-pointer field `entries_arr` (matching the
  original layout doc); the 1.0 `bootloader_config_entries(c)` getter
  and 3-arg `set_entries(c, arr, count)` setter stay as thin
  hand-written wrappers that delegate through the new derive
  accessors. Net additive surface for BootConfig: `entries_arr/1`,
  `set_entries_arr/2`, `set_entry_count/2`.
- **`docs/development/api-surface-1.0.snapshot`** — additive bump:
  13 new entries across the three modules (4 fuse setters, 6 drm
  setters, 3 BootConfig accessors). 1.0 surface preserved exactly;
  no removals.
- **`dist/agnosys.cyr`** regenerated. Bundle shrinks from 9,954 lines
  (1.0.6) to 9,932 lines (1.0.7) — net -22 lines from replacing
  hand-written accessor fns with struct decls + derive directives.

## [1.0.6] — 2026-05-06

**First V1.1.0 `#derive(accessors)` slot — `src/mac.cyr` migrated.**
1 of ~13 struct-bearing modules done. Ships as a 1.0.x patch
(continuing the per-change patch line); V1.1.0 tags at the cumulative
closeout when all modules are migrated.

### Changed
- **`src/mac.cyr`** — first V1.1.0 `#derive(accessors)` migration slot.
  The `mac_profile` heap struct (24 bytes, 3 ptr fields: agent_type,
  selinux_ctx, apparmor_name) is now declared as
  `#derive(accessors) struct mac_profile { ... }`; the 5 hand-written
  `mac_profile_*` getters/setters are replaced by compiler-generated
  ones with byte-identical layout. `mac_profile_new` body switched
  to use the generated setters. Bench parity verified
  (`mac_default_profile`: 285ns → 294ns, +3%, within run-to-run noise).
- **`scripts/check-api-surface.sh`** — extended awk parser to also
  count `#derive(accessors)`-generated accessor pairs as public fns.
  Without this, every `#derive(accessors)` migration would look like
  a BREAKING removal of the hand-written accessors. The script now
  parses the `struct <name> { f1; f2; ... }` body following each
  `#derive(accessors)` directive and emits `<name>_<field>/1` +
  `<name>_set_<field>/2` for each field.
- **`docs/development/api-surface-1.0.snapshot`** — additive bump
  for the mac slot: `mac::mac_profile_set_agent_type/2` is new
  (the auto-generated setter for a field that previously had no
  hand-written setter — `mac_profile_new` was the only initializer).
  Other 6 mac_profile accessors keep their existing names + arities.
- **`dist/agnosys.cyr`** regenerated.

## [1.0.5] — 2026-05-06

**Toolchain pin bump.** No source changes; pulls in the cyrius
5.8.x / 5.9.x improvements while keeping 1.0's API surface frozen.

### Changed
- **`cyrius.cyml [package].cyrius`** pinned `5.7.48` → `5.9.1`.
  All 10 audit gates pass under the new toolchain (syntax, API
  surface, capacity, build, smoke, 234 tests, lint, vet, 6 fuzz
  harnesses, 30 benchmarks across 11 groups). Binary size on
  `CYRIUS_DCE=1` build: 85592 bytes.
- **`dist/agnosys.cyr`** regenerated — header version stamp only;
  bundle body unchanged from 1.0.4.

### Fixed
- **`.github/workflows/ci.yml`** — fmt drift gate now invokes
  `cyrius fmt "$f"` instead of `cyrius fmt "$f" --check`. The
  `--check` flag became a no-op in cyrius 5.9.x (emits nothing,
  exits 0 regardless of drift), which made CI's
  `diff <(cyrius fmt … --check) "$f"` report every file as
  drifted on the 5.9.1 bump even though the committed sources
  were already correctly formatted. The diff-against-committed-
  source approach is the actual drift check; `--check` was
  redundant from the start. CLAUDE.md updated to match.

## [1.0.4] — 2026-04-30

**aarch64 portability sweep — full agnosys-side fix per the
2026-04-28 phylax handoff doc.** 1.0.3 patched the single
`syscall(SYS_OPEN, …)` site that downstream consumers hit on the
cross-build dead-code path; 1.0.4 closes the remaining
agnosys-internal arch-hardcoded sites flagged by the same audit.
After this release, `cyrius build --aarch64 src/main.cyr` produces
a well-formed ELF with no agnosys-side syscall-number drift, and
the `dist/agnosys.cyr` bundle ships both arches' constants
self-gated for downstream consumers (sigil 2.9.5+, phylax 1.1.x+).

### Added
- **`src/syscall_x86_64_linux.cyr`** + **`src/syscall_aarch64_linux.cyr`**
  — per-arch peer files holding agnosys-private syscall numbers
  (`SYS_PRCTL`, `SYS_SYSINFO`, `SYS_UNSHARE`, `SYS_SOCKET_NR`,
  `SYS_BIND_NR`, `SYS_SENDTO_NR`, `SYS_RECVFROM_NR`,
  `AGNOS_SYS_FSYNC`, `AGNOS_SYS_RENAME` / `AGNOS_SYS_RENAMEAT2`)
  plus arch-correct `agnosys_fsync(fd)` / `agnosys_rename(old, new)`
  wrappers. Each peer self-gates with
  `#ifdef CYRIUS_ARCH_X86 / AARCH64` so both ship in
  `dist/agnosys.cyr` (cyrius distlib strips include lines but
  concatenates everything in `[lib] modules`); only the matching
  arch's block compiles in the consumer's build. Pattern mirrors
  `lib/syscalls_x86_64_linux.cyr` / `lib/syscalls_aarch64_linux.cyr`
  in cyrius stdlib; deliberate file-per-arch split chosen over
  inline `#ifdef` for read-clarity (per-repo arch deltas live
  in their own discoverable file).
- **`src/syscall_arch.cyr`** — dispatcher; consumed by
  `src/syscall.cyr`, `src/security.cyr`, `src/audit.cyr`,
  and (transitively) `src/journald.cyr` for the in-binary
  build path. Source-tree-only; the bundle path ships the
  peer files directly via `[lib] modules`.

### Changed
- **`cyrius.cyml [package].cyrius`** pinned `5.7.8` → `5.7.48`.
  Picks up the syscall-portability narrative landed in cyrius
  5.7.x: `lib/syscalls.cyr` now exposes `SYS_GETDENTS64` /
  `SYS_GETRANDOM` / `SYS_LANDLOCK_*` / `SYS_UNAME` constants and
  matching `sys_*` wrappers on both arches. The 2026-04-28
  handoff doc's "Cyrius stdlib gaps" section is therefore
  resolved — agnosys no longer needs to redefine these locally.
- **`cyrius.cyml [lib] modules`** — peer files prepended to the
  module list so they bundle ahead of every consumer
  (audit/security/syscall/etc.).
- **`src/syscall.cyr`** — dropped the `SysNrExt` enum entirely.
  `SYS_GETTID` / `SYS_UNAME` now come from cyrius stdlib;
  `SYS_PRCTL` / `SYS_SYSINFO` come from the per-arch peer.
  Single call-site fix: `syscall(SYS_UNAME_NR, out)` →
  `syscall(SYS_UNAME, out)` (uses stdlib's now-portable name).
- **`src/security.cyr`** — dropped local `SYS_LANDLOCK_*` (stdlib),
  `SYS_PRCTL` (peer), `SYS_UNSHARE` (peer); LandlockConst enum
  trimmed to the access-flag / rule-type bits only.
- **`src/audit.cyr`** — dropped `SysNrAudit` enum
  (`SYS_SOCKET_NR` / `SYS_BIND_NR` / `SYS_SENDTO_NR` /
  `SYS_RECVFROM_NR` come from peer); `SYS_AGNOS_AUDIT_LOG = 520`
  (the AGNOS-defined custom syscall, arch-invariant) stays.
- **`src/drm.cyr`** — dropped local `SYS_IOCTL` / `SYS_GETDENTS64`
  redefinitions; both now resolve from cyrius stdlib at the
  arch-correct value.
- **`src/luks.cyr`** — dropped local `SYS_GETRANDOM` redefinition;
  resolves from cyrius stdlib.
- **`src/journald.cyr`** — dropped local `SYS_SENDTO = 44` from
  `JournalConst`, dropped two function-scope `var SYS_SOCKET = 41`
  declarations; call sites switched to peer-file
  `SYS_SOCKET_NR` / `SYS_SENDTO_NR` (matches existing audit.cyr
  convention).

### Fixed (raw-numeric syscall sweep — not in the original handoff doc)
- **`src/error.cyr`** — 20× `syscall(1, 2, …)` (raw SYS_WRITE
  with x86_64-hardcoded number 1; aarch64 syscall #1 is
  `io_cancel`) → `sys_write(2, …)`. These stderr writes would
  have silently invoked the wrong syscall on aarch64 builds.
- **`src/main.cyr`** — 15× `syscall(1, 1, …)` → `sys_write(1, …)`.
  Same x86_64 hardcode; same silent-misfire on aarch64.
- **`src/logging.cyr`** — 10× `syscall(1, 2, …)` →
  `sys_write(2, …)`.
- **`src/fuse.cyr`** — `syscall(4, path, statbuf)` (SYS_STAT
  number 4 on x86_64; on aarch64 generic-table the legacy `stat`
  number was retired in favor of `newfstatat`) →
  `sys_stat(path, statbuf)` (stdlib wrapper, dispatches per-arch).
- **`src/update.cyr`** — 5× `syscall(87, …)` (raw SYS_UNLINK) →
  `sys_unlink(…)`; 2× `syscall(74, fd)` (raw SYS_FSYNC, x86_64=74,
  aarch64=82) → `agnosys_fsync(fd)`; 2× `syscall(82, old, new)`
  (raw SYS_RENAME — does not exist on aarch64 generic-table) →
  `agnosys_rename(old, new)` (peer-file wrapper, routes via
  `renameat2(AT_FDCWD, …)` on aarch64).
- **`src/netns.cyr`** — `syscall(87, tmp_path)` →
  `sys_unlink(tmp_path)`.
- **`src/dmverity.cyr` / `src/tpm.cyr` / `src/ima.cyr` /
  `src/luks.cyr`** — 13× `syscall(SYS_ACCESS, path, mode)` →
  `sys_access(path, mode)`. Stdlib's `sys_access` dispatches
  to `SYS_ACCESS` on x86_64 and `SYS_FACCESSAT(AT_FDCWD, …)`
  on aarch64. Was the largest single class of breakage in
  the handoff doc's catalog (13 sites across 4 files).

### Verified
- `CYRIUS_DCE=1 cyrius build src/main.cyr build/agnosys`
  (x86_64) — clean (only dead-symbol pruning notes).
- `cyrius build --aarch64 src/main.cyr build/agnosys-aarch64`
  — produces a well-formed `ELF 64-bit LSB executable, ARM
  aarch64`. 11 `syscall arity mismatch` warnings remain; 9 are
  pre-existing cc5_aarch64 false-positives in
  `lib/syscalls_aarch64_linux.cyr`'s at-family wrappers
  (reproducible against a 4-line empty cyrius program — see
  the cyrius CHANGELOG `_SC_ARITY` entries for prior fixes in
  the same family); the remaining 2 sit at preprocessed-unit
  lines 3477 / 3509 and are likely the same false-positive
  class hitting agnosys-side calls. None correspond to a real
  arity bug — every call site was hand-verified against the
  Linux kernel `__SYSCALL` arity table for the relevant arch.
  Tracked as a cyrius-side hygiene item; does not block this
  release.
- `cyrius test tests/tcyr/test_integration.tcyr` — 234/234
  pass (unchanged from 1.0.3).
- `cyrius distlib` — `dist/agnosys.cyr` regenerated at
  9,957 lines (was 9,883 in 1.0.3; +74 lines = peer files
  + dispatcher + per-arch wrappers). Header now
  `# Version: 1.0.4`.

## [1.0.3] — 2026-04-28

**aarch64-portability fix.** Single call site in `src/security.cyr` was using
the raw `syscall(SYS_OPEN, …)` form, which only resolves on x86_64 Linux —
aarch64 Linux has no `open` syscall (only `openat`). When `dist/agnosys.cyr`
was bundled into a downstream consumer (sigil → phylax) and that consumer
attempted an aarch64 cross-build, the unresolved `SYS_OPEN` constant aborted
compilation with `undefined variable 'SYS_OPEN'`. Standalone agnosys
builds were unaffected because they got their syscalls module from cyrius
stdlib at compile time and the dead-code path simply didn't reach the call
site.

The other 19 `sys_open(...)` call sites across `src/drm.cyr`,
`src/secureboot.cyr`, `src/logging.cyr`, `src/bootloader.cyr`,
`src/update.cyr`, `src/audit.cyr`, `src/luks.cyr`, `src/tpm.cyr`,
`src/mac.cyr` already used the portable `sys_open(path, flags, mode)`
stdlib wrapper that internally dispatches to `SYS_OPEN` (x86_64) or
`SYS_OPENAT(AT_FDCWD, ...)` (aarch64). This patch makes the security/
landlock site match.

### Fixed
- `src/security.cyr:96` — `syscall(SYS_OPEN, path, 0x280000, 0)` →
  `sys_open(path, 0x280000, 0)`. Behavior identical on x86_64 (stdlib
  helper expands to the same syscall); aarch64 now resolves through
  `SYS_OPENAT` with `AT_FDCWD`. No semantic change to the landlock
  ruleset wiring.

### Verified
- `cyrius test tests/tcyr/test_integration.tcyr` — 234 passed, 0 failed
  (unchanged from 1.0.2).
- `cyrius build src/main.cyr build/agnosys` (x86_64, DCE) — clean.
- `cyrius build --aarch64 src/main.cyr build/agnosys-aarch64` — clean
  (warnings only — pre-existing arity mismatches on the agnosys-internal
  syscall-table aliases, unrelated to this patch).
- `cyrius distlib` — `dist/agnosys.cyr` regenerated, header now
  `# Version: 1.0.3`. Module bodies differ from 1.0.2 only at the one
  patched call site; bundle stays at 9,900 lines.

## [1.0.2] — 2026-04-26

**P(-1) sweep follow-up to 1.0.1 + cyrius 5.7.7 toolchain bump.** Doc + test gaps caught while re-walking the P(-1) Scaffold/Project Hardening process against the just-released 1.0.1 tree. No `src/*.cyr` changes; the audit fixes themselves shipped clean in 1.0.1. This release closes the regression-test contract (audit step 6), the documentation contract (audit step 8), and bumps the toolchain pin to the latest cyrius.

### Changed
- `cyrius.cyml [package].cyrius`: pin `5.7.6` → `5.7.8` (skipping 5.7.7). agnosys builds clean against 5.7.8 with no source or vendored-stdlib changes — `cyrius deps` is a no-op against the existing vendor (no changes to the `syscalls` / `string` / `alloc` / `fmt` / `vec` / `str` / `io` modules in our dep list across the 5.7.6→5.7.8 range). 5.7.7 was skipped because of a `cyrius check <module>` regression (exit 1 with empty `error:` on every project module file); 5.7.8 fixes the dispatcher path so per-file `cyrius check` resolves through the `[lib] modules` graph correctly. `scripts/audit.sh` step 1 and the CI "Syntax check" step are unchanged from 1.0.1. Binary size unchanged at 73,144 B; integration tests 234/234.

### Added
- `tests/tcyr/test_integration.tcyr::test_audit_regressions` — 12 deterministic assertions pinning the 1.0.1 audit-finding fixes. F-1 round-trips shell-metacharacter strings through `journald_filter_set_grep` / `set_unit` and asserts verbatim get-back (would catch any future setter that escapes or splits). F-2 covers seven cipher allowlist cases: three `null` substring variants (`cipher_null`, `Cipher_Null`, `xts-NULL`), two off-allowlist rejections, two allowed pairs (`aes`/`xts-plain64`, `serpent`/`cbc-essiv:sha256`). F-3 calls `luks_keyfile_path()` twice and asserts the paths differ (proves the getrandom suffix is actually random, not a degraded constant). Total integration assertions: 245 → 257.
- `docs/adr/` — directory created. Three ADRs covering the material 1.0.1 decisions:
  - **ADR-001** — argv-based exec for kernel-boundary subprocess invocation. Generalizes F-1's fix into a project-wide rule: every userspace tool wrapper goes through `lib/process.cyr::exec_capture` with explicit `argv` vec; `sys_system` is reserved for shell-feature-required, no-caller-input cases (currently zero call sites).
  - **ADR-002** — LUKS cipher allowlist with case-insensitive `null`-substring rejection. Records the policy (allowlist over denylist), the 4×4 algo×mode matrix, and why the substring check exists on top of the allowlist.
  - **ADR-003** — `[lib] modules` manifest layout, with the 306 KB → 73 KB measurement and a "do not move back to `[build]`" guardrail for future contributors.
- `bench-history.csv` — row recorded at commit `562a014` (1.0.1). The prior 1.0.1 release shipped without one because the closeout step 2 was skipped during the interrupted session. Notable: `ct_streq_equal` 239 → 139 ns, `ct_streq_diff` 238 → 148 ns under the 5.7.6 toolchain. The constant-time XOR-accumulator implementation is unchanged; the wider equal-vs-diff gap (~9 ns) appears to be a 5.7.6 codegen artifact and is being tracked.

### Documentation
- `docs/SECURITY-NOTES.md` — secureboot section now references F-4 (the `agnosys_uname`-driven sign-file fallback) and explains that the pre-1.0.1 hardcoded path resolved to a non-existent file on every supported distro. dmverity section gains the rationale for 4 KB function-scope `var buf[N]` output buffers (cyrius static-data hazard does not apply at these specific sites because contents are consumed before any sibling function reuses the slot) and notes that CI's security scan tightened to warn ≥ 4 KB / fail ≥ 64 KB in 1.0.1 (audit finding F-5).

### Verified
- `cyrius test` → 234 passed, 0 failed (was 222 in 1.0.1; +12 audit-regression assertions).
- `scripts/audit.sh` 10-gate pass.
- `dist/agnosys.cyr` regenerated. The only delta vs. 1.0.1 is the `# Version:` stamp in the header comment; module bodies are identical (no `src/*.cyr` changes; manifest list unchanged).
- Binary size unchanged at 73,144 B.

## [1.0.1] — 2026-04-26

**Toolchain bump 5.2.0 → 5.7.6 + CI/release alignment with the yukti pattern.** No source changes; agnosys built and tested clean against 5.7.6 as-is. The win is the manifest refactor: moving `modules` from `[build]` to `[lib]` cuts the binary 306,344 → 73,144 B (76% reduction) by eliminating the double-include path (5.x `cyrius build` prepends `[build] modules` before `src/main.cyr`, which then re-includes them via `include` directives).

### Changed
- `cyrius.cyml`: pin `cyrius = "5.2.0"` → `"5.7.6"`; moved module list from `[build] modules` → `[lib] modules` (yukti pattern). `cyrius distlib` still produces a byte-identical `dist/agnosys.cyr`.
- `.github/workflows/ci.yml`: ported to yukti shape — toolchain version derived from `cyrius.cyml` (no `CYRIUS_VERSION` env pin), tarball install from tagged release, `cyrius deps --verify` gate (skip-if-no-lock), `cyrius fmt --check` drift gate, `cyrius lint` warn-fail with auto-discovery, dist-bundle staleness gate, `CYRIUS_DCE=1` builds, best-effort aarch64 cross-build, awk-based comment filtering in security scan.
- `.github/workflows/release.yml`: accepts both `v1.0.1` and `1.0.1` tag shapes; strips optional `v` prefix for VERSION match; DCE build; aarch64 cross-build; regenerates `dist/agnosys.cyr` before archive; ships prebuilt x86_64 + aarch64 binaries alongside source tarball + bundle + SHA256SUMS + cyrius.lock.
- `CLAUDE.md`: min cyrius version 5.2.0 → 5.7.6; reserved-keyword DO-NOT list adds `secret` (introduced as a sigil-driven qualifier in 5.3.5, lexer-reserved through the 5.6.45 grammar refresh).
- `scripts/audit.sh`: vet gate now relies on exit code only; cyrius 5.7.x changed `cyrius vet` output format and the prior `grep "0 untrusted, 0 missing"` no longer matches. Aligns with the yukti CI pattern.
- Vendored stdlib refreshed via `cyrius deps` to match the cyrius 5.7.6 snapshot: `lib/alloc.cyr`, `lib/io.cyr`, `lib/string.cyr`, `lib/syscalls.cyr`. Note the alloc/syscalls diff is large because 5.5.x split syscalls into per-OS modules (`syscalls_linux.cyr` / `syscalls_agnos.cyr` already vendored; `lib/syscalls.cyr` is now a thin dispatcher) and 5.5.16 added macOS support — relevant to the planned Mac/Windows platform-abstraction work.
- Reformatted `src/pam.cyr`, `src/secureboot.cyr`, `src/update.cyr` (whitespace-only via `cyrius fmt`); shortened over-120-byte lines in `tests/bcyr/bench_compare.bcyr` (box-drawing separator) and `fuzz/certpin_pin.fcyr` (split trailing comments) so the new lint warn-fail gate stays green.
- CLAUDE.md restructured to template (durable rules only); volatile state moved to `docs/development/state.md` (new file). Roadmap gains Phase 8 backlog (8.1–8.9) covering `#derive(accessors)` adoption, multi-profile distlib, platform abstraction, consumer-integration CI, capability map, state-cadence automation, and the three follow-ups from the audit below.
- `.github/workflows/ci.yml` security scan: fn-scope buffer threshold lowered 65536 → 4096 (warn) / 65536 (fail) per audit F-5 — surfaces the cyrius static-data hazard class without breaking existing 4 KB call sites.

### Documentation
- Added `docs/development/state.md` (live state snapshot, refreshed every release).
- Added `docs/audit/2026-04-26-audit.md` — P(-1) Scaffold Hardening security audit. 1 HIGH, 1 MEDIUM, 3 LOW, 2 defense-in-depth findings; cross-references current CVE landscape (netlink validation flaws CVE-2026-31495 / CVE-2026-31407 / CVE-2026-23231; PAM/udisks privilege escalation CVE-2025-6018/6019/6020/8941; LUKS2 confidential-VM cipher_null disclosure from Trail of Bits). **All actionable findings closed in this same release.**
- Updated `docs/SECURITY-NOTES.md` per-module to reflect the post-fix state.

### Security
- **F-1 (HIGH) — journald shell-injection FIXED.** `journald_query` now calls `lib/process.cyr::exec_capture(args, buf, buflen)` with an argv vec built by `_journald_build_argv(filter)`. Every filter value (`unit`, `grep`, `since`, `until`, `boot`, `priority`, `lines`) lands in its own `argv[i]` and is read verbatim by journalctl — no shell, no metacharacter expansion. The previously-public `journald_build_args/1` helper (only useful as a shell-injection input format) is removed; the API snapshot drops it. **Breaking** for any consumer that called `journald_build_args` directly.
- **F-2 (MEDIUM) — LUKS cipher allowlist FIXED.** New public fn `luks_validate_cipher(algo, mode)` allowlists `aes`/`serpent`/`twofish`/`camellia` × `xts-plain64`/`cbc-plain64`/`xts-essiv:sha256`/`cbc-essiv:sha256`. Case-insensitive `null` substring rejection catches `cipher_null-ecb` (Trail of Bits Oct 2025 confidential-VM attack vector), `Cipher_Null`, `NULL`, etc. Wired into `luks_config_validate` so `luks_format` and `luks_open` both gate on it.
- **F-3 (LOW) — LUKS keyfile predictability FIXED.** `luks_keyfile_path` now appends 8 random bytes from `getrandom(2)` (16 hex chars) to the per-PID prefix and returns `Result` so callers handle getrandom failure. `luks_write_keyfile` opens with `O_EXCL | O_NOFOLLOW` (mode 0600). Closes CVE-2025-6020-class symlink-race patterns. **Breaking:** `luks_keyfile_path/0` now returns `Result(path)` instead of a raw pointer; callers must `payload(...)` after `is_err_result` check.
- **F-4 (LOW) — secureboot sign-file fallback FIXED.** Replaced bogus hardcoded `/usr/lib/modules-load.d/../linux/scripts/sign-file` (resolved to a non-existent path on every supported distro) with runtime detection: `agnosys_uname` to get the running kernel release, then probe `/lib/modules/<release>/build/scripts/sign-file` and `/usr/src/linux/scripts/sign-file` via `sys_access`.
- **F-6 (DiD) — audit netlink reply validation FIXED.** `audit_get_status` reply parser now validates `nlmsg_len` against bytes received, requires `nlmsg_seq == 1`, surfaces `NLMSG_ERROR` (type 2) as structured `err_syscall_failed` with the negative-errno from the payload, and rejects any other unexpected `nlmsg_type`. Constants `NLMSG_NOOP`/`NLMSG_ERROR`/`NLMSG_DONE` added to the audit enum block.
- New fuzz harnesses: `fuzz/journald_filter.fcyr` (shell-metacharacter inputs through every filter setter), `fuzz/luks_cipher.fcyr` (positive cases + null-attack variants + off-list rejection), `fuzz/audit_reply.fcyr` (8+ classes of malformed nlmsg replies). Each runs at 500-iter / 10-s in CI; all pass clean.

### Verified
- `cyrius build src/main.cyr build/agnosys` → 73,144-byte ELF (down from 306,344 B), clean.
- `cyrius distlib` → `dist/agnosys.cyr` byte-identical to committed (314,910 B).
- `cyrius test` → 222 passed, 0 failed.
- `./build/agnosys` smoke prints "agnosys ready — 20 modules ported" through the full module list.
- `scripts/audit.sh` 10-gate pass.

## [1.0.0] - 2026-04-17

**API freeze.** Every public function carries its module prefix; the surface at `docs/development/api-surface-1.0.snapshot` is the stable contract. Future 1.x releases add functions; removing or changing signatures will bump to 2.0.

### Breaking — 1.0 naming sweep (all landed pre-freeze to avoid v2 churn)

Every public function in `src/` now carries its module prefix. **139 renames across 7 module groups, 20 public fns still exactly matching the snapshot for the 11 modules that were already clean (`audit`, `certpin` entry/set families, `drm`, `error`, `fuse`, `ima`, `logging`, `luks`, `mac`, `pam`, `secureboot`, `tpm`, `udev`, `update`, syscall's `agnosys_*`/`sysinfo_*`/`uname_*` families).**

Renames by module group:

- **certpin** (15 fns): `certinfo_*` → `certpin_info_*` (CertInfo struct accessors — sibling to `certpin_entry_*` / `certpin_set_*`)
- **security** (14 fns): `fs_rule_*`, `apply_landlock`, `bpf_write_insn`, `load_seccomp`, `create_basic_seccomp_filter`, `seccomp_filter_{ptr,len}`, `create_namespace`, `syscall_map_reset`, `syscall_name_to_nr` — all now `security_*`. `create_namespace` was the highest collision-risk (very generic name in a global include).
- **journald** (36 fns): `journal_*` → `journald_*`
- **dmverity** (32 fns): `verity_*` → `dmverity_*`
- **bootloader** (25 fns): `boot_entry_*` / `boot_config_*` → `bootloader_entry_*` / `bootloader_config_*`, plus `bootloader_*` for non-struct helpers
- **netns** (16 fns): `fw_*` → `netns_fw_*`, `nft_*` → `netns_nft_*` (preserves the `fw` / `nft` sub-namespaces under the module prefix)
- **syscall** (1 fn): `checked_syscall` → `agnosys_checked_syscall`

**Consumer impact:** all 13 consumers listed in `docs/development/roadmap.md` must update call sites before upgrading to Unreleased/1.0. Principally: **sigil** (certpin), **kavach** + **daimon** (security), **argonaut** (journald, bootloader), **stiva** (dmverity), **nein** (netns firewall helpers). The `dist/agnosys.cyr` bundle was regenerated with the new names.

**Why this release, not spread across several:** the 1.0 API freeze is imminent. Shipping these renames in a single pre-1.0 version lets consumers migrate once, and avoids forcing a 2.0 purely for naming consistency.

### Added — V1.0 checklist closeout (all agnosys-side items)

- **Parser fuzz harnesses** — `fuzz/certpin_pin.fcyr`, `fuzz/audit_nlmsg.fcyr`, `fuzz/pam_config.fcyr`. Each runs under 10 s at 500 iters in the CI fuzz step; exercises boundary lengths, malformed inputs, and iteration stress.
- **`test_edge_cases()` in integration suite** — 25 boundary assertions: `update_validate_version` year/month bounds, `update_compare_versions` lexicographic fallback, `pam_validate_username` length + first-char + body-char rules, `bootloader_validate_kernel_cmdline` danger tokens (`rd.break`, `single`), `certpin_validate_pin_format` length edges, `err_from_errno` errno→kind mapping. Total integration assertions: 220 → 245.
- **`cyrius vet` CI gate** — new step in `ci.yml`; fails if include-graph introduces untrusted or missing deps.
- **`scripts/audit.sh`** — local one-shot quality runner, 10 gates matching CI (syntax → API surface → capacity → build → smoke → tests → lint → vet → fuzz → benchmarks). Clean output suitable for pre-push verification.

### Added — 1.0 freeze prerequisites

- **API surface snapshot** — `docs/development/api-surface-1.0.md` (722 lines) lists every public `fn` across the 20 modules with arity and a one-line summary. 555 public functions catalogued; 16 outliers flagged for pre-freeze review. Principal finding: the `certinfo_*` family (15 fns) in `certpin.cyr` breaks the module-prefix convention and should be renamed to `certpin_*` before 1.0.
- **API surface regression check** — `scripts/check-api-surface.sh` diffs `src/*.cyr` against `docs/development/api-surface-1.0.snapshot` (`module::fn/arity` per line). Exits non-zero on any removal or arity change; additions are allowed. Wired as a new CI step.
- **Capacity baseline** — `docs/development/capacity-baseline.md` records Cyrius compiler-table utilization for three representative builds (core demo, single-module consumer, full bundle). Highest today: fixup_table 32%, code_size 42% on the full bundle — well under the 85% gate.
- **Capacity gate in CI** — `cyrius capacity --check src/main.cyr` runs on every build; fails if any compiler table crosses 85%.
- **Consumer quickstart in README** — per-module (feature-gated) and full-bundle (`dist/agnosys.cyr`) patterns with measured footprints.

### Changed

- **CI install flow canonicalised** — replaced manual tarball curl + cp chain with `curl install.sh | sh` (honors `$CYRIUS_VERSION`). Same flow in `ci.yml` and `release.yml`.
- **Roadmap V1.0 section** — freeze prerequisites added alongside the original four items; Progress table refreshed (9 884 LOC, 556 public fns, 220 assertions, Cyrius 5.2.0).

## [0.98.0] - 2026-04-16

### Added

- **`dist/agnosys.cyr` bundle** — single-file distribution (9704 lines) generated via `cyrius distlib` from the 20 modules declared in `cyrius.cyml [build] modules`. Consumers can now `include "dist/agnosys.cyr"` for the full surface area while per-module includes from `src/*.cyr` remain available for feature-gated consumption.

### Changed

- **Minimum Cyrius version raised to 5.2.0** — picks up `cyrius distlib`, `[build] modules`, `${file:VERSION}` expansion, `cyrius capacity --check`, `cyrius soak`. (`cyrius.cyml` already aligned.)
- **`src/main.cyr` header** — removed stale `cc2` and Rust line-count references; now describes the feature-gated vs. `dist/` bundled consumption model.
- **Test layout → canonical `tests/tcyr/` + `tests/bcyr/`** — `cyrius test` auto-discovery in 5.2.0 reliably finds `.tcyr` only under `tests/tcyr/`. Moved `tests/test_integration.tcyr` → `tests/tcyr/`, `tests/bench_{all,compare}.bcyr` → `tests/bcyr/`. Matches sakshi/patra layout. `ci.yml` and `scripts/bench-history.sh` updated to the new paths.

### Notes — 5.2 adoption opportunities (tracked for follow-up, not in this release)

- `#derive(accessors)` could replace ~661 hand-written `load64`/`store64` accessors across 20 modules — large audit-gated refactor.
- `cyrius capacity --check` and `cyrius soak` worth wiring into `ci.yml` once a capacity budget is agreed. (`capacity --check` landed in Unreleased.)
- `sakshi` 2.0.0 could back `src/logging.cyr` with structured tracing instead of the current `AGNOSYS_LOG`-gated `eprint` path.

## [0.97.2] - 2026-04-09

### Changed

- **Minimum Cyrius version raised to 3.2.6** — CI toolchain updated in ci.yml and release.yml (was 3.2.5)

## [0.97.1] - 2026-04-09

### Changed — Cyrius 3.2.5 Upgrade

- **Compiler upgraded Cyrius 3.2.1 → 3.2.5** — `strstr()` substring search, hashmap `map_get_or`/`map_size`/`map_iter`, `#derive(Serialize)` fixes, function table 1024→2048, Known Gotcha #6 (nested while+load8) documented, Patra structured storage
- **Vendored stdlib re-synced** (10 modules updated from upstream):
  - **string.cyr**: Added `atoi()`, `strstr()` (memeq-based, avoids nested while loop codegen bug)
  - **alloc.cyr**: Added arena allocator (`arena_new`, `arena_alloc`, `arena_reset`)
  - **hashmap.cyr**: Internal refactor, added `map_get_or()`, `map_size()`, `map_iter()`, removed unused constants
  - **io.cyr**: Added file locking (`file_lock/unlock/trylock/lock_shared`), `file_append_locked()`, `getenv()`
  - **fmt.cyr**: Added `fmt_float_buf()`, `fmt_float()`
  - **bench.cyr**: Added `bench_run_batch1` (single-arg variant)
  - **str.cyr**: `str_contains`/`str_ends_with` now take Str needle (was C string)
  - **tagged.cyr**: Comment fix
- **CI**: Upgraded toolchain `3.2.1` → `3.2.5` in both ci.yml and release.yml

### Added — Port Completion

- **update.cyr**: Ported A/B update state machine from Rust — `UpdateState`, `UpdateConfig`, `UpdateManifest`, `UpdateFile` structs with full accessors. Added `update_get_current_slot()` (/proc/cmdline + state file fallback), `update_save_state()`/`update_load_state()` (JSON persistence via atomic write), `update_verify_manifest()` (structural validation + hex hash check), `update_check()` (local manifest comparison), `update_apply()` (dd to inactive slot with staging path validation), `update_switch_slot()` (slot marker + efibootmgr), `update_rollback()`, `update_mark_boot_successful()`, `update_needs_rollback()`. Network fetch deferred — local file paths only. SHA-256 digest verification deferred pending Cyrius SHA-256 stdlib.
- **secureboot.cyr**: Added `EnrolledKey` struct with accessors, `secureboot_parse_mokutil_list()` (mokutil output parser), `secureboot_list_enrolled_keys()`, `secureboot_enroll_key()` (MOK import), `secureboot_sign_module()` (kmodsign with sign-file fallback), `ModuleSignatureInfo` struct, `secureboot_verify_module()` (modinfo parser), `EfiVariable` struct, `secureboot_list_efi_variables()` (filtered sysfs listing)
- **fuse.cyr**: Added `fuse_is_available()` (/dev/fuse check), `fuse_validate_mountpoint()` (stat + directory check), `fuse_list_mounts()` (convenience wrapper returning vec), `FuseStatus` enum, `fuse_get_status()` (mountpoint lookup)

### Fixed

- **process.cyr**: Pipe fd read corrected — was `load64` at offset 8, now `load32` at offset 4 (pipe(2) returns 32-bit fds). Buffer `[2]` → `[16]`. Affects all `run_capture`/`exec_capture` callers across 14 modules.
- **fs.cyr**: `is_dir` return fix — explicit `return 1`/`return 0` instead of `return n >= 0`

### Changed — API Migration

- **mac.cyr**: 7 `str_contains` call sites updated to wrap C string literals with `str_from()` (LSM detection, AppArmor mode parsing)
- **pam.cyr**: 1 `str_contains` call site updated (`".."` path traversal check)

### Changed — Heap Buffer Migration

- Converted large stack `var buf[N]` arrays to heap `alloc(N)` in tpm.cyr (8200 + 4096), secureboot.cyr (16384 + 4096 + 4096), update.cyr (4096 + 1024) — frees ~30KB from data segment, keeps test binary under 262KB output limit

### Removed

- **`rust-old/` directory removed** (304MB, 29,257 lines Rust) — port complete, Rust source preserved in git history. Final Rust-vs-Cyrius benchmark comparison saved to `docs/benchmarks-rust-vs-cyrius.md` (originally at repo root; moved to `docs/` at Unreleased as a headliner historical record).

### Metrics

- **Source**: 9,884 lines across 21 files (20 modules + main) (was 8,687)
- **Binary**: 55,688 bytes
- **Compile**: 35ms
- **Tests**: 197 integration assertions, 30 benchmarks
- **Lint**: 0 warnings across 21 modules
- **Compiler**: Cyrius 3.2.5

## [0.96.0] - 2026-04-09

### Changed — Cyrius 3.2.1 Upgrade

- **Compiler upgraded Cyrius 2.4.0 → 3.2.1** — defer statement, multi-width types, sizeof, tail call optimization, constant folding
- Adopted `defer` for guaranteed resource cleanup across 14 modules (30+ sites):
  - **security.cyr**: `apply_landlock()` — ruleset fd auto-close on all 3 error paths (was manual close on each)
  - **luks.cyr**: `luks_format()`, `luks_open()` — keyfile auto-unlink via defer
  - **audit.cyr**: `audit_read_proc_events()` — fd auto-close
  - **mac.cyr**: `mac_read_file()`, `mac_write_file()` — fd auto-close
  - **journald.cyr**: `journal_send()`, `journal_send_fields()` — socket fd auto-close
  - **fuse.cyr**: `fuse_parse_proc_mounts()` — fd auto-close
  - **drm.cyr**: `drm_list_devices()` — fd auto-close
  - **secureboot.cyr**: `secureboot_read_efi_variable()` — fd auto-close
  - **ima.cyr**: `ima_get_status()`, `ima_read_measurements()`, `ima_write_policy()` — fd auto-close
  - **pam.cyr**: `pam_read_service_config()`, `pam_list_users()`, `pam_get_user_info()` — fd auto-close
  - **logging.cyr**: `log_init_from_env()` — fd auto-close
  - **tpm.cyr**: `tpm_seal()` — fd auto-close
  - **update.cyr**: `update_atomic_write()`, `update_atomic_copy()` — fd auto-close on all error paths
  - **netns.cyr**: `netns_apply_nftables_ruleset()` — temp file auto-unlink

### Refactored

- **luks.cyr**: Extracted `luks_keyfile_path()` and `luks_write_keyfile()` helpers — eliminated duplicated 15-line keyfile creation pattern in `luks_format()` and `luks_open()`
- **secureboot.cyr**: Replaced 45-line deeply-nested byte-by-byte string matching in mokutil fallback with 3 `memeq()` calls (7 lines)
- **drm.cyr**: Replaced 4-deep nested `load8()` char checks with single `memeq(name_ptr, "card", 4)` call

### Changed — CI/Release Modernization

- **CI**: Upgraded toolchain `2.7.2` → `3.2.1`, replaced `cat | cc2` pipe with `cyrius build`
- **CI**: Consolidated separate build/check/test/bench jobs into single `build-and-test` job
- **CI**: Added `cyrius check` (syntax), `cyrius lint`, `cyrius test`, fuzz harness execution
- **CI**: Added `cyrius.toml` to required docs check, added toml version consistency verification
- **CI**: Added Cyrius script copy to toolchain install (`scripts/cyrius`)
- **Release**: Replaced `cat | cc2` with `cyrius build`, added toml version gate
- **Release**: Fixed changelog extraction (was in build job, read in release job on different runner)
- **Release**: Aligned structure with majra release workflow (source archive only, no binary)

### Fixed

- **pam.cyr**: Fixed misaligned brace indentation in `pam_validate_rule()` dangerous char check

### Performance — No Regressions

| Benchmark | Pre-refactor | Post-refactor |
|-----------|-------------|---------------|
| getpid | 311ns | 308ns |
| from_errno | 21ns | 18ns |
| syscall_name_to_nr_hit | 120ns | 107ns |
| validate_cmdline | 529ns | 540ns |
| compare_versions | 140ns | 140ns |
| mac_default_profile | 416ns | 395ns |

### Metrics

- **Source**: 8,687 lines across 21 files (20 modules + main)
- **Binary**: 51,976 bytes (was 52,040 — 64 bytes smaller)
- **Compile**: 32ms
- **Dependencies**: 0
- **Tests**: 197 integration assertions, 30 benchmarks
- **Compiler**: Cyrius 3.2.1

---

## [0.95.0] - 2026-04-09

### Fixed — Audit Round

- **`syscall.cyr`: SI_MEM_UNIT offset 112 → 104** — `sysinfo_total_memory()` was reading past the struct into zeroed buffer. Worked by accident when `mem_unit == 1` (common case) but returned wrong values on exotic configs
- **`certpin.cyr`: buffer overflow in `certpin_compute_spki_pin`** — 1024-byte shell command buffer had no length check on `cert_path`. Added max 896 char validation
- **`secureboot.cyr`: `run_capture(cmd, argv)` wrong signature** — called with 2 args but function takes 5. Replaced with `exec_capture(args, buf, buflen)` matching codebase pattern
- **`luks.cyr`: missing write error check in `luks_open`** — `sys_write()` return value for key material was unchecked. Added error propagation
- **`logging.cyr`: log level parse false positive** — `AGNOSYS_LOG=track` matched as "trace" (only first byte checked). Now checks first two bytes

### Changed — Toolchain Upgrade

- **Compiler upgraded Cyrius 1.9.2 → 2.4.0** — globals limit raised, `cyriusup` version manager, `cyrfmt`/`cyrlint` available
- Build tool renamed `cyrb` → `cyrius` (build, check, test, bench, audit, fmt, lint)
- Test files renamed `.cyr` → `.tcyr`, benchmark files `.cyr` → `.bcyr`
- `scripts/bench-history.sh` updated for new toolchain and output format

### Added — Testing & Quality

- **197 integration assertions** (was 45) across all 20 modules in `tests/test_integration.tcyr`
- New test coverage: logging (7), security (11), certpin (13), update (12), bootloader (10), audit (12), pam (15), mac (5), dmverity (8), luks (10), ima (10), tpm (9), secureboot (5), fuse (4), udev (7), drm (7), netns (13), journald (6)
- `cyrius audit` clean pass (24/24): compile, test, lint, format
- `cyrfmt` applied to all src/*.cyr files
- `cyrlint` 0 warnings across all modules
- Include-once module independence — each module includes its own deps for standalone `cyrius check`

### Added — Documentation

- `docs/architecture/overview.md` — module map, include model, data flow, dependency graph, consumer map
- `docs/development/roadmap.md` — rewritten for Cyrius port reality, added Phase 5-6, updated metrics
- `docs/SECURITY-NOTES.md` — rewritten for Cyrius (was Rust-centric)

### Performance — No Regressions

| Benchmark | Pre-audit | Post-audit |
|-----------|-----------|------------|
| getpid | 307ns | 311ns |
| from_errno | 18ns | 21ns |
| syscall_name_to_nr_hit | 107ns | 120ns |
| validate_cmdline | 543ns | 529ns |
| compare_versions | 141ns | 140ns |
| mac_default_profile | 402ns | 416ns |

### Metrics

- **Source**: 8,752 lines across 21 files (20 modules + main)
- **Binary**: 52,016 bytes
- **Compile**: 31ms
- **Dependencies**: 0
- **Tests**: 197 integration assertions, 30 benchmarks
- **Compiler**: Cyrius 2.4.0

---

## [0.90.0] - 2026-04-07

### Changed — Cyrius 1.9.2 Upgrade
- **Compiler upgraded 1.6.1 → 1.9.2** across 13 compiler releases
- CI workflows updated to Cyrius 1.9.2
- `cyrb.toml` updated with consumer dep spec documentation for `modules = [...]` selective includes

### Refactored — Return Comparisons (Cyrius 1.7.x)
- Simplified ~25 if/return patterns to direct return comparisons across 16 files
- `is_syscall_err`: `return ret < 0;`
- `mac_file_exists`: `return sys_access(path, 0) == 0;`
- `certpin_ct_streq`: `return acc == 0;`
- `secureboot_is_enforcing`: `return state == SB_ENABLED;`
- `WIFEXITED`: `return (status & 0x7F) == 0;`
- `WIFSIGNALED`: `return sig > 0 && sig != 0x7F;`
- `sigset_has`: `return (mask & (1 << (signum - 1))) != 0;`
- `is_err`: `return ret < 0;`
- `map_has`: `return load64(ep + 16) == 1;`
- `is_dir`: `return n >= 0;`
- Applied to both `lib/syscalls_linux.cyr` and `lib/syscalls_agnos.cyr`

### Optimized — Algorithm Improvements
- **`syscall_name_to_nr`: O(n) → O(1)** — replaced 75-entry if/elif chain with hashmap lookup. Miss case: 1.0us → 44ns (23x faster). Hit case: 28ns → 106ns (hashmap overhead vs best-case first-entry match)
- **`bootloader_validate_kernel_cmdline`: single-pass** — replaced 8 sequential full-string scans with single-pass tokenizer + hashmap danger lookup. Static init (once). 975ns → 533ns (1.8x faster)
- **`mac_default_profile`: stack-alloc strings** — replaced str_builder (13 heap allocs) with stack buffers + single heap copy. 2 allocs instead of 13
- **`create_basic_seccomp_filter`: unrolled** — eliminated loop + 160-byte temp array. Direct BPF instruction writes, same 184-byte output

### Added — Testing
- `tests/test_integration.cyr` — integration test suite covering 12 modules, 45 assertions using `lib/assert.cyr`. Parity with `rust-old/tests/integration.rs`
- `tests/bench_all.cyr` — batch-amortized benchmark suite (10K iters × 100 rounds). 12 modules, 30 benchmarks across 11 groups. Eliminates per-iteration `clock_gettime` overhead (~370ns)
- `lib/bench.cyr` — added `bench_run_batch(b, fp, iters, rounds)` for batch-amortized timing
- `syscall_map_reset()` / `bootloader_danger_reset()` — reset static hashmaps after `alloc_reset()` to prevent use-after-free in test harness

### Added — Compiler Features Used
- Return comparisons (`return expr == expr`) — v1.7.0
- `&&`/`||` in return statements — v1.7.6
- Nested `Err(fn())` calls — v1.7.6
- Identifier deduplication (50% tok_names savings) — v1.7.8
- Include-once semantics — v1.8.0
- VCNT expanded 2048 → 4096 — v1.8.2
- Preprocess buffer expanded 256KB → 512KB — v1.8.0
- Codebuf expanded 192KB → 256KB — v1.8.5
- Dense switch optimization — v1.7.7
- Constant folding `+ - & | ^` — v1.7.7
- f64 transcendentals — v1.7.8
- Dep spec `modules = [...]` — v1.9.2

### Performance — Batch-Amortized Benchmarks vs Rust
| Benchmark | Rust | Cyrius | Ratio |
|-----------|------|--------|-------|
| getpid | 308ns | 307ns | 1.0x (parity) |
| getuid | 292ns | 288ns | 1.0x (parity) |
| is_root | 292ns | 299ns | 1.0x (parity) |
| from_errno | 11ns | 18ns | 1.6x |
| wrap_syscall | 306ns | 317ns | 1.0x (parity) |
| validate_cmdline | 373ns | 533ns | 1.4x |
| compare_versions | 74ns | 139ns | 1.9x |
| validate_pin (valid) | 73ns | 249ns | 3.4x |
| validate_pin (invalid) | 57ns | 9ns | 0.2x (Cyrius 6x faster) |
| mac_default_profile | 275ns | 409ns | 1.5x |
| streq (16ch) | — | 79ns | — |
| map_get (hit) | — | 52ns | — |

### Metrics
- **Source**: 8,460 lines across 21 files (20 modules + main)
- **Binary**: 52,016 bytes (was 53,312 at 0.60.0)
- **Compile**: 8ms
- **Dependencies**: 0
- **Tests**: 45 integration assertions, 30 benchmarks
- **Compiler**: Cyrius 1.9.2

---

## [0.60.0] - 2026-04-06

### Changed
- **Ported from Rust to Cyrius** — 29,257 lines of Rust → 8,559 lines of Cyrius. Zero dependencies. 117KB binary. 8ms compile time.
- All 20 modules rewritten in Cyrius: error, syscall, logging, security, mac, audit, pam, journald, luks, dmverity, ima, tpm, certpin, secureboot, udev, drm, netns, bootloader, update, fuse
- CI/CD workflows rewritten for Cyrius toolchain (`cyrb build/check`)
- Release workflow produces native ELF binary + source archive (no cargo vendor)
- Dual-encoding errors: packed `kind << 16 | errno` on hot paths (6 ns), heap-allocated with message on cold paths (20 ns)
- Caller-provided stack buffers for syscall wrappers (query_sysinfo, hostname) — zero heap allocation
- Original Rust source preserved in `rust-old/` for reference

### Added
- `src/error.cyr` — packed + heap error encoding, errno mapping, error printing
- `src/syscall.cyr` — getpid/uid/tid/hostname/sysinfo with stack-buffer API
- `src/security.cyr` — Landlock, seccomp BPF filter generation, namespace creation
- `src/logging.cyr` — AGNOSYS_LOG env var log level control
- `tests/bench_compare.cyr` — benchmark suite for Rust-vs-Cyrius comparison

### Security
- certpin: path validation rejects single quotes/newlines before shell execution
- audit: path traversal check rejects `..` components in file watch rules
- luks: per-PID keyfile path instead of predictable `/tmp/.agnos-luks-keyfile`
- netns: per-PID nftables temp file instead of fixed path
- journald: skip fields with newline characters in keys (injection prevention)
- syscall: saturating multiply guard on sysinfo memory calculations
- netns: nftables buffer increased to 16KB with bounds checking
- ima: policy buffer sized to match per-rule buffer (512 bytes/rule)

### Performance
- Syscall wrappers at parity with Rust (getpid 306 ns, getuid 290 ns)
- Packed error creation: 6 ns (vs Rust 11 ns — 1.8x faster)
- query_sysinfo: 465 ns (vs Rust 467 ns — parity)
- Ok(42) tagged union: 2 ns
- Compile time: 8ms (vs Rust 11.7s — 1,462x faster)
- Binary size: 117KB (vs Rust 6.9MB rlib — 59x smaller)

### Metrics
- **Source**: 8,559 lines across 21 modules
- **Binary**: 117KB ELF (x86_64)
- **Compile**: 8ms
- **Dependencies**: 0

---

## [0.50.0] - 2026-04-02

### Breaking Changes
- **audit.rs**: `read_agnos_audit_events(proc_path: &str)` now takes `&Path` instead of `&str` for consistency with all other path-taking functions
- **netns.rs**: `destroy_agent_netns()` now consumes `NetNamespaceHandle` by value (was `&NetNamespaceHandle`) to match resource ownership semantics
- **pam.rs**: `PamService::service_name()` renamed to `PamService::as_str()` for consistency with all other enum accessor methods
- **udev.rs / journald.rs**: `HashMap<String, String>` fields replaced with `BTreeMap<String, String>` for deterministic iteration order in security-critical contexts
- `#[non_exhaustive]` added to all 56 public structs — external code constructing structs with `Struct { .. }` syntax must use constructors instead

### Added
- **Security documentation**: All 20 modules now include `# Security Considerations` sections covering required privileges, input validation, data sensitivity, and threat model notes
- **8 new example programs**: `audit_status`, `pam_users`, `journal_query`, `boot_info`, `cert_pinning`, `verity_check`, `update_state`, `network_namespaces` (14 total)
- **cargo-semver-checks** CI job to catch breaking API changes automatically
- `UdevRule::new()` and `UpdateState::new()` constructors for non-exhaustive struct initialization
- Documentation added to all `#[cfg(not(target_os = "linux"))]` stub functions (pam, journald, update)
- 226 new unit tests across 7 modules (tpm, netns, update, secureboot, bootloader, fuse, luks)

### Changed
- `#[must_use]` refined: removed from `Result`-returning functions (redundant — `Result` is already `#[must_use]`), kept on non-Result value types
- `#[inline]` added to ~24 hot-path accessors (`as_str()`, `is_*()`, simple constructors) across all modules
- `#[non_exhaustive]` now on all public structs (was only on enums)

### Performance
- No regressions from hardening changes (72/90 benchmarks improved, remainder within noise)

### Metrics
- **Tests**: 1,625 (1,551 unit + 73 integration + 1 doc)
- **Benchmarks**: 147 across 20 modules
- **Line coverage**: 86.56% (all modules above 80%)
- **Fuzz targets**: 8 parser fuzzers

## [0.5.0] - 2026-03-26

### Changed
- **SemVer migration**: Moved from CalVer (0.25.x) to SemVer, targeting 1.0.0
- **agent/llm modules removed**: Extracted to dedicated crates (`agnosai` for agents, `hoosh` for LLM inference). Removes reqwest, tokio, async-trait, anyhow, once_cell from dep tree.
- `#[non_exhaustive]` on all 28 public enums (was only 3)
- `#[must_use]` on ~50 pure/query functions across all modules
- deny.toml trimmed: removed 7 stale license entries from removed deps
- Consumer map updated: daimon uses seccomp+certpin (agent moved to agnosai)

### Fixed
- update.rs: swapped day/month labels in `validate_version()` error messages
- Feature gate completeness: 8 features (tpm, certpin, fuse, pam, mac, journald, bootloader, update) were missing standalone deps — all now compile individually
- ima feature missing `dep:hex` and `serde` dependencies

### Performance
- ima.rs: `write!()` over `format!()` in policy building, `static` array for valid masks
- certpin.rs: iterator chain instead of clone+extend in pin verification
- secureboot.rs: `Option<&str>` instead of String in parse loop, Vec pre-allocation
- Vec::with_capacity() across 13 sites in 5 modules (bootloader, journald, audit, udev, pam)

## [0.23.3] - 2026-03-24

### Added
- landlock: Filesystem sandboxing via Landlock LSM (ABI v1-v4) — ruleset builder, path rules, net port rules
- seccomp: Syscall filtering via seccomp-BPF — filter builder, allowlist/denylist policies, architecture validation
- drm: Direct Rendering Manager — device enumeration, driver version, capabilities, KMS resources, connector queries
- netns: Network namespaces — create, enter, list, current ns fd/inode
- certpin: Certificate pinning — SHA-256 pin computation (zero-dep), base64, SPKI extraction, PinSet validation
- agent: Agent runtime support — process naming, OOM score, cgroup inspection, capability check, systemd watchdog *(moved to agnosai crate)*
- luks: LUKS encrypted storage — header parsing, key slot inspection, dm-crypt volume management
- dmverity: dm-verity integrity — superblock parsing, root hash validation (constant-time), volume status
- audit: Kernel audit subsystem — netlink audit socket, status queries, log parsing, audit line parser
- pam: PAM service inspection — list services, parse PAM stacks, read service configs
- mac: Mandatory Access Control — LSM detection, SELinux/AppArmor/Smack queries, security contexts
- ima: Integrity Measurement Architecture — runtime measurements, policy parsing, violation count
- fuse: FUSE protocol — /dev/fuse device, request reading, reply writing, mount listing
- update: Atomic update primitives — atomic_write, atomic_copy, atomic_swap, fsync, directory sync
- tpm: TPM2 interface — device detection, PCR banks/values, capabilities, event log access
- secureboot: Secure Boot — EFI variable reading, SecureBoot/SetupMode state, PK/KEK/db/dbx inspection
- journald: Systemd journal — structured log sending via native socket, journal file listing, disk usage
- bootloader: Bootloader interface — systemd-boot/GRUB detection, boot entry parsing, loader.conf, kernel listing
- SysInfo struct: Single sysinfo(2) call for uptime/memory/procs
- query_sysinfo() convenience function
- Send+Sync compile-time assertions on all public types
- Full project scaffold: CI, release workflow, deny.toml, codecov.yml, bench-history.sh
- Community files: SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md

### Changed
- SysError fields now use Cow<'static, str> (zero-alloc on known errno paths)
- serde dependency is now optional (behind "serde" feature flag)
- syscall feature now correctly depends on error feature
- License identifier updated to GPL-3.0-only (SPDX compliant)
- Example detect_hardware no longer requires unimplemented udev feature

### Fixed
- errno read order in checked_syscall (read before tracing to prevent clobbering)
- --all-features build (commented out unimplemented module declarations)
- cargo fmt / clippy issues in benches and tests

## [0.1.0] - 2026-03-23

### Added
- error: SysError with errno mapping, #[non_exhaustive], io::Error From impl
- syscall: checked_syscall wrapper, getpid, gettid, getuid, geteuid, is_root, uptime, total_memory, available_memory, hostname
- logging: AGNOSYS_LOG env var for tracing init
- Feature gate infrastructure: 22 feature flags for granular kernel interface selection
- Project scaffold: Cargo.toml, CI, roadmap, benchmarks, integration tests
