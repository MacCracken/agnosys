# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
