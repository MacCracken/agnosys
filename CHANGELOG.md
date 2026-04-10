# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

- **`rust-old/` directory removed** (304MB, 29,257 lines Rust) — port complete, Rust source preserved in git history. Final Rust-vs-Cyrius benchmark comparison saved to `BENCHMARKS-RUST-VS-CYRIUS.md`.

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
