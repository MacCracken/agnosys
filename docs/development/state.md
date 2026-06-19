# Agnodrm — Live State

> Volatile snapshot. Refreshed every release. Durable rules live in [`CLAUDE.md`](../../CLAUDE.md). Historical release narrative is in [`CHANGELOG.md`](../../CHANGELOG.md). Future work is in [`roadmap.md`](roadmap.md).

**Last refresh:** 2026-06-19 (1.4.4)

> **Renamed `agnosys` → `agnodrm` at 1.4.4** — decomposed from the AGNOS kernel-interface library to the **device / DRM model** (udev + DRM/KMS on error/util support). 15 modules moved to their proper homes (trust→sigil, security/mac/audit→kavach, pam→aegis, logging→sakshi, syscall layer→cyrius). See the [decomposition plan](2026-06-18-agnosys-to-agnodrm-decomposition-plan.md). Metrics below predating 1.4.4 describe the old 20-module surface and are being refreshed as touched.

## Version & Toolchain

| Item | Value |
|---|---|
| `VERSION` | **1.4.4** |
| `cyrius.cyml [package].cyrius` | **6.2.11** |
| Min Cyrius (consumer) | 6.2.11 |
| Last cyrius bump | 6.2.1 → 6.2.11 (2026-06-15; 6.2.x maintenance line, bug-fix/optimization patches only). Pure pin refresh — no `src/*.cyr` edits; validated green from clean deps. Prior: 6.1.23 → 6.2.1 at 1.4.2 (stdlib pin sweep; dropped stale `"json"` dep — carved into bayan at 6.1.25), 6.0.56 → 6.1.23 (2026-06-10; first 6.1.x adoption). Absorbs the **v6.0.64 thread-safe allocator** (`lib/alloc.cyr` global CAS spinlock + vtable). Required: `[deps] stdlib += atomic` (transitive include not auto-resolved), and removing `alloc_reset()`-between-groups from the integration test + benches (incompatible with the new memoized default allocator — dangling cache → SIGSEGV/spin). Binary **159,392 → 162,784 B (+3,392)** from the lock/vtable code. **Perf regression** on alloc-bound paths (`ok_create` +321%, `from_errno` +210%) — single-threaded agnosys pays for the lock; confined to cold/diagnostic heap paths (zero-alloc `syserr_pack` hot path unchanged at 3 ns). Prior bumps: 6.0.52 → 6.0.56 at 1.4.0 (AGNOS-target work), 6.0.24 → 6.0.52 at 1.3.2 (codegen change, +368 B). |

## Build Metrics

| Metric | Value | Notes |
|---|---|---|
| Binary size (DCE) | **128,728 B** (1.4.4) | The device-model smoke `main.cyr` over error/util/udev/drm. Was 124,376 B at 1.4.3 for the old 20-module surface — not directly comparable (different program). |
| `dist/agnodrm.cyr` size | ~137 KB / 4,091 lines (1.4.4) | Full bundle = the 9 surviving modules. Down from ~327 KB / 10,125 lines (`dist/agnosys.cyr`, 1.4.3) — the 15 moved modules left with their code. Plus `dist/agnodrm-core.cyr` (error/util/udev/drm). |
| Fn-table utilization | 433 / 8,192 (5%) | +9 fns since 1.2.7 (stdlib snapshot growth pulled into the include graph) |
| Var-table | 342 / 8,192 | |
| Fixup-table | 865 / 262,144 | |
| String-data | 1,494 / 2,097,152 | |
| Code-size | 97,928 / 1,048,576 | |
| Compile time | ~460 ms | recorded at 1.0.0 closeout |

## Module Count

**9 modules** post-decomposition (1.4.4): the **device-model core** (error, util, udev, drm) + the **deferred Linux-eccentric group** (journald, netns, bootloader, update, fuse — parked post-v1, no agnos story yet). Down from 20; the other 15 moved to their proper homes (see the decomposition plan / CHANGELOG 1.4.4).

| Module | Group | Description |
|---|---|---|
| error | core | SysError types, errno mapping, Result helpers |
| util | core | Shared `agnodrm_*` helpers — json-emit, hex/name-char, cstr-starts-with, run_capture/checked, read-fd, fsync/rename |
| udev | core | Device enumeration via udevadm |
| drm | core | DRM device enumeration, ioctl version/caps |
| journald | deferred | Systemd journal send/query |
| netns | deferred | Network namespace create/destroy, veth, nftables |
| bootloader | deferred | systemd-boot/GRUB detection, cmdline validation |
| update | deferred | Atomic file ops, version comparison |
| fuse | deferred | FUSE mount parsing, mount/unmount |

Moved out at 1.4.4: `syscall`/`logging` → cyrius/sakshi; `security`/`mac`/`audit` → kavach; `pam` → aegis; `luks`/`dmverity`/`ima`/`tpm`/`certpin`/`secureboot` → sigil.

Per-module public-fn arity is tracked in [`api-surface-1.0.snapshot`](api-surface-1.0.snapshot) (machine-checkable; CI-gated via `scripts/check-api-surface.sh`). **315 public fns** total post-decomposition (was 737 — the 422 removed went with their modules; the `core` profile is `[lib.core]` = error/util/udev/drm).

## Test / Fuzz / Bench Coverage

| Category | Count | Where |
|---|---|---|
| Integration tests passed | **252 / 252** | `cyrius test` |
| Integration assertions | 275 | `tests/tcyr/test_integration.tcyr` (1.3.0 added 4 — 3 `big_check_*` + 1 `exec_vec_multiarg`; 1.3.1 added 1 — `readfd_cap` for the shared read-fd helper) |
| Fuzz harnesses | 7 | `fuzz/audit_nlmsg.fcyr`, `fuzz/audit_reply.fcyr`, `fuzz/certpin_pin.fcyr`, `fuzz/fuse_parse.fcyr` (1.1.14), `fuzz/journald_filter.fcyr`, `fuzz/luks_cipher.fcyr`, `fuzz/pam_config.fcyr` |
| Benchmarks | 30 (11 groups) | `tests/bcyr/bench_all.bcyr` |
| Bench file (compare) | 1 | `tests/bcyr/bench_compare.bcyr` (Cyrius vs Rust port baseline) |

## Local Audit Gates (`scripts/audit.sh`)

11 gates, all green at 1.2.7: syntax → API surface (snapshot + prose) → capability map → capacity → build → smoke → tests → lint → vet → fuzz → benchmarks. Mirrors CI.

## CI Workflow Status

- `.github/workflows/ci.yml` — yukti-pattern: tarball install via cyrius.cyml-derived version, deps + verify-hashes, fmt-check, lint warn-fail, vet, dist staleness gate, DCE build, ELF magic, aarch64 best-effort cross, smoke, integration, fuzz, bench, security scan, docs check.
- `.github/workflows/release.yml` — accepts `vX.Y.Z` and `X.Y.Z`; verify-version, install toolchain, deps + verify, DCE build, aarch64 best-effort, tests, fuzz, regenerate dist, archive (source tar + bundled `.cyr` + prebuilt x86_64 + aarch64 binaries + cyrius.lock + SHA256SUMS).

## Dependencies

- **Runtime**: 0
- **Stdlib via `[deps] stdlib`**: `syscalls`, `string`, `alloc`, `fmt`, `vec`, `str`, `io`, `ct`, `slice`, `fnptr`, `json`, `tagged`, `assert`, `bench`, `fs`, `hashmap`, `net`, `process` (18 — `ct` added 1.1.3 for `ct_eq_bytes`; `slice` added 1.1.11 for `slice<u8>` indexing; `fnptr`/`json`/`tagged` added 1.1.12 for `#derive(Serialize)`; `assert`/`bench`/`fs`/`hashmap`/`net`/`process` added across 1.2.x for downstream-bundle completeness)
- **Git-pinned**: 0 (no `[deps.<name>]` stanzas; no `cyrius.lock` needed today)
- **Vendored stdlib refresh** (last): 2026-06-03 to cyrius 6.0.52 snapshot (full `./lib/` re-populated via `cyrius deps` after `rm -rf lib`; 29 stdlib files). Count 25 → 29: the AGNOS-target peers `alloc_agnos.cyr` + `syscalls_x86_64_agnos.cyr` and the macOS/Windows peers `syscalls_macos.cyr` / `syscalls_windows.cyr` / `process_win.cyr` are now pulled transitively. None affect the Linux build.

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
- **Linux aarch64** — best-effort; CI cross-builds when `cycc_aarch64` (renamed from `cc5_aarch64` in Cyrius 6.0) is bundled in the toolchain release.
- **macOS / Windows** — not supported. Most modules are kernel-Linux-only by definition (audit netlink, PAM, journald, dm-verity, IMA, secureboot). See roadmap Phase 8 (item 3).

## Recent Releases

| Tag | Date | Headline |
|---|---|---|
| **1.4.3** | 2026-06-15 | **cyrius pin 6.2.1 → 6.2.11** — 6.2.x maintenance line (bug-fix/optimization patches only, no API change). Pure pin refresh, no `src/*.cyr` edits; validated green from clean deps (`rm -rf lib build && cyrius deps`). DCE build 124,376 B (byte-identical to 1.4.2), 252 tests pass, audit clean (11/11). All 6 `dist/` bundles version-stamped. Bench delta within noise; minor wins on constant-time compares (`ct_streq` −8/−12%). |
| **1.4.2** | 2026-06-12 | **Daimon-class buffer fix + cyrius pin 6.1.23 → 6.2.1.** `update_save_state` `bc_buf` boot-count scratch overflow fixed (`var bc_buf[8]` → `[24]`; `fmt_int_buf` of an i64 needs ~20 digits — boot_count ≥ 10,000,000 overran into adjacent static memory; surfaced by the 6.2.1 address-taken-local-array audit, latent/layout-masked until now). Pin sweep onto current toolchain required dropping the stale `"json"` `[deps] stdlib` entry — the standalone json stdlib module was carved into bayan at 6.1.25, so 6.2.x ships no `lib/json.cyr`; agnosys rolls its own JSON helpers and calls no stdlib `json_*` symbols. |
| **1.4.1** | 2026-06-10 | **Cyrius pin 6.0.56 → 6.1.23 — first 6.1.x adoption; absorbs the v6.0.64 thread-safe allocator** (`lib/alloc.cyr` global CAS spinlock + vtable). Required `[deps] stdlib += atomic` (transitive include not auto-resolved) + removing `alloc_reset()`-between-groups from the integration test + benches (dangling memoized-allocator cache → SIGSEGV/spin) + fixing a no-arg `query_sysinfo()` miscall in benches. Binary 159,392 → 162,784 B (+3,392, lock/vtable). **Perf regression** on alloc-bound paths (`ok_create` +321%, `from_errno` +210%, `mac_default_profile` +74%) — single-threaded agnosys pays for the lock; zero-alloc hot path (`syserr_pack` 3 ns) unchanged. Follow-up: upstream single-thread no-op gate or freelist hot-path migration (patra pattern). Audit clean (11/11); 252 tests, 7 fuzz, 30 benches; API surface unchanged. |
| **1.4.0** | 2026-06-06 | **AGNOS as a build target — `agnosys-core` now compiles under `cyrius build --agnos`.** `agnosys_uname` (syscall #34 + 64-byte sovereign identity struct), `query_sysinfo` (syscall #35 + 40-byte all-u64 struct), `agnosys_gettid`→getpid, `agnosys_geteuid`→getuid, all gated inline with `#ifdef CYRIUS_TARGET_AGNOS` in `src/syscall.cyr`. Linux path unchanged (additive gating; binary 159,392 B unchanged). security/storage/trust/system profiles remain Linux-only; only `core` is agnos-portable. cyrius pin 6.0.52 → 6.0.56. `dist/agnosys.cyr` + core bundle regenerated (+79 lines). |
| **1.3.2** | 2026-06-03 | **Cyrius pin 6.0.24 → 6.0.52 — toolchain refresh with a real codegen win.** No agnosys source changes. Unlike the pure-TLS 6.0.14 → 6.0.24 window, the 6.0.25–6.0.52 arc carries a codegen change: binary 159,024 → 159,392 B (+368), 490 fns NOPed (108,466 dead bytes). Broad hot-path wins across all 30 benches, **zero regressions**, reproduced on a second run (`update_compare_versions` −25%, `certpin_ct_streq` −24%, `validate_pin_valid` −18%, `validate_cmdline_safe` −16%, `wrap_syscall_ok` −13%). Stdlib snapshot 25 → 29 files (AGNOS-target + macOS/Windows peers now transitive). 6 dist bundles regenerated (version header only). Audit clean (11/11); 252 tests. |
| **1.3.1** | 2026-06-01 | **`util.cyr` consolidation closeout** (deferred non-breaking items from 1.3.0). New `agnosys_is_name_char` (dmverity/luks wrappers) + `agnosys_read_fd_to_str` replacing 3 byte-identical pam drain loops — the shared helper allocs `cap+1`, closing a latent 1-byte overflow the per-module copies carried (F-11 class, ≥8KB/≥64KB files). +2 public fns (735 → 737, non-breaking). Regression test `readfd_cap` (251 → 252). 6 dist bundles regenerated (−16 lines). Deprecation notices (doc-only) for `agnosys_checked_syscall` + `dmverity_validate_hex` `label` param → 2.0.0. Audit clean (11/11). |
| **1.3.0** | 2026-06-01 | **Real minor: cyrius pin 6.0.14 → 6.0.24 + correctness/security + refactor/optimization closeout.** 4 buffer/exec defects fixed — F-11 (HIGH) `update_check` 1-byte heap overflow, F-12 `update_save_state` fixed-buffer overflow, F-13 `ima_read_measurements` silent 64KB truncation, F-14 netns exec non-functional + bare command names (rewritten onto `exec_vec` + absolute paths). New `src/util.cyr` consolidates 5 JSON shims + hex/starts_with/run-wrapper duplication (+5 `agnosys_*`, public names kept as wrappers; 730 → 735 fns, non-breaking). Bench wins: `starts_with` −68%/−77%, `mac_default_profile` 324 → 239ns (−26%). Tier-3 hygiene (break-in-var-loops, journald accessors, audit log_warn). Tests 247 → 251; 6 dist bundles regenerated (10,110 → 10,062 lines). CLAUDE.md: per-version benchmarking now mandatory. Audit clean (11/11). See `docs/audit/2026-06-01-audit.md`. |
| **1.2.8** | 2026-05-28 | Cyrius pin bump 6.0.1 → 6.0.14 (6.0 patch series — native-TLS arc + toolchain fixes). No agnosys source changes. Stdlib snapshot 24 → 25 files (`syscalls_linux_common.cyr` now transitive). 6 dist bundles regenerated; full bundle −72 lines (cyrius 6.0.9 distlib blank-line fix). Binary 156,768 → 159,024 B. **Workaround audit:** all 3 in-tree workarounds (hand-rolled JSON serializers, CI fmt diff-gate, CI cycc_aarch64 fallback) re-verified still required against 6.0.14 — none repairable yet. capability-map header refresh. Audit clean (11/11). |
| **1.2.7** | 2026-05-21 | Cyrius pin bump 5.11.4 → 6.0.1. First major upstream release — `cc5` → `cycc` rename across stdlib, new `syscalls_linux_common.cyr` peer, fn-table capacity doubled 4,096 → 8,192, DCE switched to in-place NOP (478 unreachable fns NOPed, 106,230 dead bytes). No agnosys source changes. 6 dist bundles regenerated; capability-map header refresh (carry-forward from 1.2.6 — prior tag committed before regen). Audit clean (11/11). |
| 1.2.6 | 2026-05-11 | Stdlib annotation pass + cyrius pin 5.10.44 → 5.11.4. Every public fn in `src/*.cyr` (351 fns) gains `: i64` return-type annotation matching cyrius v5.11.x annotation arc (Phases 1-6); parse-only, zero runtime / codegen change. All 6 dist bundles regenerated. |
| 1.2.5 | 2026-05-11 | Cyrius pin bump 5.10.34 → 5.10.44. Toolchain refresh (10 upstream patch releases — parser/codegen polish + stdlib additions); no agnosys source changes. Audit clean against the new pin. 6 dist bundles + capability-map + api-surface prose regenerated at 1.2.5 headers. |
| 1.2.4 | 2026-05-10 | Cyrius pin bump 5.10.19 → 5.10.34. Toolchain refresh (15 upstream patch releases — parser/codegen polish + stdlib additions); no agnosys source changes. Audit clean against the new pin. 6 dist bundles + capability-map + api-surface prose regenerated at 1.2.4 headers. |
| 1.2.3 | 2026-05-10 | V1.2.3 consumer integration CI shipped — nightly GitHub Actions workflow ([`.github/workflows/consumer-integration.yml`](../../.github/workflows/consumer-integration.yml)) builds kavach + sigil against agnosys main; vendors freshly-built dist bundles into the consumer's `lib/`, force-syncs cyrius pin, runs the consumer's audit. Failures auto-file `consumer-break` issues here (with dedup). Separate from primary build/test pipeline — schedule + workflow_dispatch only. Plus the 1.2.1 doc-cleanup carry-forward: `docs/doc-health.md` ledger added; README/CONTRIBUTING/capacity-baseline refreshed at 1.2.3 numbers; `version-bump.sh` no longer suggests git ops to agents. Skipped 1.2.2 (folded into 1.2.1 ship per slot rhythm). |
| 1.2.1 | 2026-05-09 | V1.2.2 capability map (per-module kernel surface — syscalls, sys_*, exec paths, sysfs/procfs/devfs paths) shipped via auto-generator (`scripts/gen-capability-map.sh`). Phase 8 doc-tooling: api-surface prose generator (`scripts/gen-api-surface-prose.sh`) closes the D-3 deferral from 1.1.13; `api-surface-1.0.md` regen now covers all 730 fns. 3 upstream-blocker tickets filed internally (passive — `#derive(Serialize)` cstring gap, `#ifplat` codegen regression, `#deprecated` unproven). audit.sh tightened: 10 → 11 gates (+capability-map, prose-doc check folded into API surface). No source changes. |
| 1.2.0 | 2026-05-09 | V1.2.0 multi-profile `cyrius distlib` shipped — 5 profile bundles (`core`, `security`, `storage`, `trust`, `system`) ship alongside the full bundle. Consumer-facing distribution-shape change: kavach 324 KB → ~99 KB (70% cut), stiva → ~72 KB (78%), sigil → ~92 KB (72%). `[lib.<profile>]` sections in `cyrius.cyml`; CI dist-staleness gate covers all 6 bundles; release archive ships every profile per tag. No source changes; no API surface drift. Yukti pattern; proven primitive. |
| 1.1.14 | 2026-05-09 | P(-1) hardening pass — security audit findings landed. 0 critical / 0 high / 0 medium severity; 3 LOW + 1 informational, all closed. F-7 (`fuse_extract_field` octal-escape unescape), F-8 (bootloader cmdline danger-flag list extended with lockdown/sig_enforce/LSM-disable/heap-hardening flags), F-9 (`dmverity` outbuf explicit null-terminator). H-2 smoke + new `fuse_parse` fuzz harness. 247 tests (+5), 7 fuzz harnesses (+1). Adds `docs/audit/2026-05-09-cve-landscape.md` + `docs/audit/2026-05-09-audit.md` + `docs/development/reviews/2026-05-09-internal-review.md`. |
| 1.1.13 | 2026-05-09 | Doc reconciliation post-1.1.12 ship + P(-1) hardening pass kicked off (audit clean baseline + bench-history baseline at commit `9ec6063`). CHANGELOG/state.md/roadmap.md cleaned up of stray 1.1.13-placeholder refs that never tagged; the actual 1.1.12 ship narrative folded back into `[1.1.12]`. No source changes since 1.1.12; tests + API surface unchanged. |
| 1.1.12 | 2026-05-09 | V1.1.12 `#derive(Serialize)` — SHIPPED. Two derived serializers (`audit_status_to_json`, `ima_status_to_json` — all-numeric structs) using stacked `#derive(accessors)` + `#derive(Serialize)`. Five hand-rolled `_to_json` shims for cstring-bearing diagnostic structs (`mac_profile`, `dmverity_status`, `update_state`, `certpin_info`, `drm_verinfo`) — pattern: per-module `_<mod>_emit_cstr_or_null` helper handles null-or-quoted, mixed with `str_builder_add_int` for numerics. Closes a two-week investigation arc: original SIGILL was agnosys-side `./lib/` shadow (resolved 2026-05-08); three cyrius bugs filed and fixed during the arc — multi-derive (5.10.14), api-surface scanner (5.10.16), lib/process.cyr O_WRONLY (5.10.18 + 5.10.19). cyrius pin arc: 5.9.27 → 5.10.19. `./lib/` gitignored + `cyrius deps` moved before syntax check in CI (matches yukti/patra). Hand-rolls unwind cleanly when cyrius adds cstring `#derive(Serialize)` support |
| 1.1.11 | 2026-05-07 | V1.1.11 slice migration — survey shows most `var buf[N]` sites aren't real slice candidates (tiny fmt bufs, kernel-ABI stack structs, one-shot syscall args, length-bounded `memeq`/`memcpy` walks). One representative site (`ima_get_status` rbuf newline counter) migrated to `slice<u8>` with bounds-checked indexing as the canonical pattern for future scalar-subscript parsers |
| 1.1.10 | 2026-05-07 | V1.1.8 reopens — cyrius 5.9.27 implements aarch64 sub-8-byte struct field load codegen; the 1.1.9 revert is now itself reverted. Typed kernel-ABI structs + pointer-to-struct dot syntax build clean on both arches; resolved issue archived |
| 1.1.9 | 2026-05-07 | V1.1.8 reverted — cyrius aarch64 backend rejected sub-8-byte struct field loads (`error:1610`). x86_64 build clean; aarch64 CI broke. `scripts/audit.sh` gate 4 extended to also cross-build aarch64 so regression class is caught locally. Upstream issue filed; V1.1.8 re-entered queue |
| 1.1.8 | 2026-05-07 | V1.1.8 multi-width struct fields — 4 kernel-ABI structs (`sockaddr_nl`, `nlmsghdr`, `audit_kstatus`, `bpf_insn`) migrated to typed `struct` decls + pointer-to-struct dot syntax; 14 explicit `store{8,16,32}` calls eliminated. **Note:** reverted in 1.1.9 due to aarch64 sub-8-byte struct-field-load gap |
| 1.1.7 | 2026-05-07 | V1.1.7 tagged-union `Result` adoption — verification slot. agnosys uses only high-level `Ok`/`Err`/`is_ok`/`payload` API; cyrius v5.8.28 already migrated `lib/result.cyr` to first-class `enum Result<T, E>`. agnosys is on first-class tagged unions transparently; no source changes needed |
| 1.1.6 | 2026-05-07 | cyrius pin 5.9.20 → 5.9.25 — match-coverage check now deterministic (was fn-name-hash-bucket-dependent on 5.9.20–5.9.21); `--version` trailing-byte fix. 1.1.5 corrigendum: the "DCE-gated" hypothesis was wrong; real cause was hash-table indexing |
| 1.1.5 | 2026-05-06 | V1.1.3 exhaustive `match` coverage adoption — `syserr_print` converted to match (8 SysErrorKind variants explicit, no `_ =>`); audit gate 4 now greps build output for `non-exhaustive` warnings as a CI failure. Other 14 enum-to-string fns intentionally kept as if/elif chains (catch-all defaults are correct for wire-format serializers) |
| 1.1.4 | 2026-05-06 | cyrius pin 5.9.18 → 5.9.20 — `ct_eq_bytes_lens` dual-length variant lets `certpin_ct_streq` collapse to a one-liner full stdlib delegation; `sys_stat` now in both arch peer files closes the 2026-05-01 portability issue (filed by sigil 3.0 against 1.0.4). Issues directory now empty |
| 1.1.3 | 2026-05-06 | V1.1.2 reopens — cyrius 5.9.18 ships `ct_eq_bytes` in `lib/ct.cyr`. `certpin_ct_streq` body shrinks to a length-check + delegation into stdlib; bench parity confirmed; resolved issue archived. cyrius pin 5.9.14 → 5.9.18 |
| 1.1.2 | 2026-05-06 | V1.1.2 `secret var` + `ct_eq` in certpin — DEFERRED, upstream premise incomplete. `ct_eq` not a builtin; `lib/ct.cyr` lacks `ct_eq_bytes`; `secret var` requires array form, doesn't fit cstring-pointer pin storage. Existing hand-rolled `certpin_ct_streq` is correct as-is. Filed upstream issue `cyrius-ct-eq-bytes-stdlib`; slot re-opens when the helper lands |
| 1.1.1 | 2026-05-06 | V1.1.1 `defer { }` adoption — audit pass; no leaks found, no source changes needed. The 24 existing `defer { sys_close(...) }` sites (already in place from the port) are correctly placed; the 9 non-defer `sys_close` sites are all deliberate (existence probes, return-fd APIs, in-loop closes, close-before-subprocess) |
| 1.1.0 | 2026-05-06 | First minor release after 1.0 freeze. `#derive(accessors)` migration complete across 16 struct-bearing modules (37 derive structs). Pure refactor; drop-in upgrade from 1.0.x; 160 additive public fns (no removals/drift). cyrius pin 5.9.14 |
| 1.0.13 | 2026-05-06 | V1.1.0 closeout patch — final 1.0.x slot before 1.1.0 tag. Cumulative baseline recorded: 16/16 modules migrated, 37 derive structs, 721 public fns (+160 additive), 85,592 B binary unchanged, 234 tests pass, 30 benches flat (one bench-locality drift in update_compare_versions noted) |
| 1.0.12 | 2026-05-06 | Tooling cleanup — `cyrius api-surface` adoption (5.9.14 ships `--scope=project`, `--snapshot=PATH`, and the `cyrius_api_surface` helper binary); `scripts/check-api-surface.sh` reduced from 70-line awk walker to a four-line wrapper; resolved api-surface issue archived |
| 1.0.11 | 2026-05-06 | V1.1.0 `#derive(accessors)` migration complete — pam + netns + update migrated (11 structs across 3 modules); cyrius pin 5.9.1 → 5.9.7 lifts the derive 32-struct cap; 16 of 16 struct-bearing modules done; ready for V1.1.0 closeout |
| 1.0.10 | 2026-05-06 | V1.1.0 `#derive(accessors)` slots 11–13 — ima + tpm + secureboot migrated (8 structs across 3 modules); 13 of 13 struct-bearing modules done; one batch left (pam + netns + update) |
| 1.0.9 | 2026-05-06 | V1.1.0 `#derive(accessors)` slots 8–10 — udev + journald + audit migrated (7 structs across 3 modules); 10 of ~13 struct-bearing modules done; learned: `syscall` is a reserved field name, asymmetric setter API needs wrappers |
| 1.0.8 | 2026-05-06 | V1.1.0 `#derive(accessors)` slots 5–7 — dmverity + luks + certpin migrated (6 structs across 3 modules); 7 of ~13 struct-bearing modules done; multi-line struct decl convention adopted |
| 1.0.7 | 2026-05-06 | V1.1.0 `#derive(accessors)` slots 2–4 — fuse + drm + bootloader migrated (4 structs across 3 modules); 4 of ~13 struct-bearing modules done |
| 1.0.6 | 2026-05-06 | First V1.1.0 `#derive(accessors)` slot — `src/mac.cyr` migrated (1 of ~13 struct-bearing modules); `scripts/check-api-surface.sh` extended to count derive-generated accessors |
| 1.0.5 | 2026-05-06 | Toolchain pin bump 5.7.48 → 5.9.1; no source changes, all 10 audit gates green |
| 1.0.4 | 2026-04-30 | aarch64 portability sweep — per-arch syscall peer files, raw-numeric syscall sweep across error/journald/etc.; toolchain pin 5.7.8 → 5.7.48 |
| 1.0.2 | 2026-04-26 | P(-1) sweep follow-up: audit-regression integration tests, three ADRs, SECURITY-NOTES F-4/F-5 entries, bench-history row for 1.0.1; toolchain pin 5.7.6 → 5.7.8 (skipping 5.7.7 — `cyrius check` regression, fixed in 5.7.8) |
| 1.0.1 | 2026-04-26 | Toolchain bump 5.2.0 → 5.7.6; CI ported to yukti pattern; binary size 76% reduction via `[lib]`-modules refactor; audit findings F-1..F-6 fixed |
| 1.0.0 | 2026-04-17 | API freeze. 139 renames, 20 modules ported, 556 public fns, 220 integration assertions, 30 benchmarks |
| 0.97.1 | 2026-04 (pre-1.0) | Rust source deleted, Cyrius port complete |

Full narrative in [`CHANGELOG.md`](../../CHANGELOG.md).

## Slot Ledger

V1.1.x cycle and V1.2.0 / V1.2.1 are all shipped; nothing is currently in-flight. V1.2.3 (consumer integration CI) is the next concrete slot to pick up — see [`roadmap.md`](roadmap.md). The deferred V1.2.1 (`#ifplat`) and V1.2.4 (`#deprecated`) live in [`issues/`](issues/) as passive upstream-blocker tickets.

**V1.1.0 — `#derive(accessors)` migration — SHIPPED 2026-05-06**

37 derive structs across 16 modules; 721 public fns (561 at 1.0 freeze + 160 additive across V1.1). All slots and the closeout patch shipped in the 1.0.6 → 1.0.13 patch line; tagged as 1.1.0. See [CHANGELOG `[1.1.0]`](../../CHANGELOG.md) for the consumer-facing summary, [`[1.0.13]`](../../CHANGELOG.md) for the cumulative baseline, [`roadmap.md`](roadmap.md) V1.1 for the full slot list.

**V1.1.x — language-feature adoption (slot # = version #)**
- [x] V1.1.1 — `defer { }` audit pass — no leaks; 24 defer sites already correct from the port
- [x] V1.1.2 — `ct_eq_bytes` deferral — issue filed; certpin's hand-roll correct as-is pending upstream
- [x] V1.1.3 — `ct_eq_bytes` reopen — cyrius 5.9.18 added `ct_eq_bytes`; `certpin_ct_streq` body shrunk to a 5-line cstring wrapper delegating into stdlib
- [x] V1.1.4 — `ct_eq_bytes_lens` one-liner + `sys_stat` x86 fix — cyrius 5.9.20 added `ct_eq_bytes_lens` (certpin further shrunk to one-liner) and `sys_stat` for x86_64 (closed 2026-05-01 sys-stat issue)
- [x] V1.1.5 — exhaustive `match` coverage — `syserr_print` converted; audit gate 4 enforces non-exhaustive warnings; 14 enum-to-string serializers kept as if/elif chains (catch-all defaults are correct)
- [x] V1.1.6 — match-coverage corrigendum + cyrius 5.9.25 pin — fixed 5.9.20–5.9.21 fn-name-dependent dispatch (hash-bucket bug); `--version` trailing-byte cleanup
- [x] V1.1.7 — tagged-union `Result` adoption — verification slot. agnosys's high-level `Ok`/`Err`/`is_ok`/`payload` API already routes through cyrius's first-class `enum Result<T, E>` (v5.8.28 stdlib migration); zero direct `tagged_new`/`tag`/`is_tag` calls in src/*. Pattern-payload destructuring (`match res { Ok(v) => ... }`) waits for cyrius — not yet shipped.
- [x] V1.1.8 — multi-width struct fields — `sockaddr_nl`/`nlmsghdr`/`audit_kstatus`/`bpf_insn` migrated to typed struct decls + pointer-to-struct dot syntax; 14 explicit width-store calls + 3 width-load reads converted
- [x] V1.1.9 — V1.1.8 revert (aarch64 sub-8-byte struct field load gap); upstream issue filed; `scripts/audit.sh` gate 4 extended with permanent `cyrius build --aarch64` cross-build
- [x] V1.1.10 — V1.1.8 reopen (cyrius pin 5.9.25 → 5.9.27); both arches clean
- [x] V1.1.11 — slice migration — most agnosys `var buf[N]` sites aren't real slice candidates (verification finding); one representative site migrated as the canonical pattern (`ima_get_status` rbuf newline counter)
- [x] V1.1.12 — `#derive(Serialize)`. 2 derived serializers (`audit_status`, `ima_status` — both all-numeric) using stacked `#derive(accessors)` + `#derive(Serialize)` (cyrius 5.10.14+). 5 hand-rolled `_to_json` shims for cstring-bearing structs (`mac_profile`, `dmverity_status`, `update_state`, `certpin_info`, `drm_verinfo`) — pattern: per-module `_<mod>_emit_cstr_or_null` helper handles null-or-quoted, mixed with `str_builder_add_int` for numeric fields. Slot ran from 2026-05-07 deferral through 2026-05-09 ship; three cyrius issues filed and resolved during the arc: `2026-05-08-cyrius-derive-multi-stacking` (fixed 5.10.14), `2026-05-09-cyrius-api-surface-putc-brace-desync` (fixed 5.10.16), `lib/process.cyr O_WRONLY blocker` (fixed 5.10.18 + 5.10.19); plus the agnosys-side `./lib/` shadow root cause for the original SIGILL (resolved 2026-05-08). Pin arc: 5.9.27 → 5.10.19. `./lib/` gitignored, `cyrius deps` moved before syntax check in CI (matches yukti/patra). Issues directory empty; 9 issues in archive. Hand-rolls unwind cleanly when cyrius adds cstring `#derive(Serialize)` support.
- [x] V1.1.13 — Doc reconciliation + P(-1) hardening kicked off. CHANGELOG/state.md/roadmap.md cleaned up of stray 1.1.13-placeholder refs that never tagged (folded back into the actual `[1.1.12]` ship narrative). P(-1) steps 1+2 done: audit clean baseline (10/10 gates, 242 tests, 152,880 B build) + bench-history baseline at commit `9ec6063` (33 timings recorded via `scripts/bench-history.sh`).
- [x] V1.1.14 — P(-1) hardening pass completed (steps 3-8). Internal deep review filed (3 hotspots — H-1/H-2/H-3 — all resolved or downgraded). CVE landscape doc filed for the 17 module-bound kernel interfaces. Security audit produced 4 findings (F-7 INFO, F-8/F-9/F-10 LOW); F-7/F-8/F-9 closed by source changes in this release, F-10 verified clean (no code change). New `fuse_parse.fcyr` fuzz harness (7 total). 247 integration tests (+5: 3 fuse escape + 2 security smoke). Post-review bench rerun: 30 benches stable, no regressions. No new ADRs earned (changes were mechanical, not architectural). Cyrius pin held at 5.10.19.

**V1.2.x — ecosystem (consumer-facing)**
- [x] V1.2.0 — multi-profile `cyrius distlib`. 5 profile bundles (`core`, `security`, `storage`, `trust`, `system`) ship alongside the full bundle (`dist/agnosys-<profile>.cyr`). Consumer-facing distribution-shape change: kavach 324 KB → ~99 KB (70% cut), stiva → ~72 KB (78%), sigil → ~92 KB (72%), argonaut/yukti/soorat/nein → ~134 KB (59%). `[lib.<profile>]` sections in `cyrius.cyml`; CI dist-staleness gate extended to all 6 bundles; `release.yml` archive ships every profile per tag. Yukti pattern (`cyrius distlib core`); proven primitive — no new cyrius language features. No source changes; 247 tests / API surface unchanged.
- [x] V1.2.1 — V1.2.2 capability map (per-module kernel-surface map: syscalls, sys_* wrappers, exec paths, sysfs/procfs/devfs paths) + Phase 8 doc-tooling (api-surface prose generator) + 3 upstream-blocker tickets filed internally (passive: cstring `#derive(Serialize)`, `#ifplat` codegen, `#deprecated` unproven — all "don't refile" framing). audit.sh tightened from 10 → 11 gates: stage 2 covers snapshot + prose, stage 3 added for capability-map staleness. New scripts: `gen-capability-map.sh`, `gen-api-surface-prose.sh`, both with `--check` mode. Closes V1.2.2 + Phase 8 doc-tooling slots; defers V1.2.1 (`#ifplat`) and V1.2.4 (`#deprecated`) to upstream-blocker tracking. No source changes; no API surface drift.
- [x] V1.2.2 — capability map per public fn — shipped as part of V1.2.1 (per-module granularity; per-fn would require a real cyrius AST walker for transitive call resolution and is deferred).
- [x] V1.2.3 — consumer integration CI. Nightly GitHub Actions workflow ([`.github/workflows/consumer-integration.yml`](../../.github/workflows/consumer-integration.yml)) builds each consumer (kavach, sigil to start) against agnosys main: vendors the freshly-built `dist/agnosys.cyr` + 5 profile bundles into the consumer's `lib/`, force-syncs the consumer's cyrius pin to agnosys's pin, runs the consumer's declared audit command. Failures auto-file a `consumer-break` issue here (with dedup by title prefix). Separate from the primary build/test pipeline — runs on schedule + workflow_dispatch only, never on push or PR. Notification channel is GitHub Issues (the auto-filed `consumer-break` ticket); no Slack / Discord wiring.

Slot # = agnosys VERSION # for this minor cycle. Multi-version
shipping arcs (1.1.2-1.1.4 ct_eq_bytes; 1.1.5-1.1.6 exhaustive
match; 1.1.8-1.1.10 multi-width struct fields) get one slot per
shipped patch.

V1.2.0 (multi-profile `cyrius distlib`) shipped 2026-05-09. V1.2.1 ship batched V1.2.2 capability map + Phase 8 prose generator + audit-gate tightening + 3 upstream-blocker tickets (passive). V1.2.3 (consumer integration CI — nightly kavach + sigil rebuild) shipped 2026-05-10 as a separate workflow. V1.2.1 (`#ifplat` cosmetic migration) and V1.2.4 (`#deprecated` adoption) remain held in the upstream-blocker tickets. See [`roadmap.md`](roadmap.md) for the full plan.

## Last Security Audit

[`docs/audit/2026-05-09-audit.md`](../audit/2026-05-09-audit.md) — P(-1) hardening pass at 1.1.14. Pairs with [`2026-05-09-cve-landscape.md`](../audit/2026-05-09-cve-landscape.md) (CVE class survey) and [`reviews/2026-05-09-internal-review.md`](reviews/2026-05-09-internal-review.md) (internal deep review). 0 critical / 0 high / 0 medium findings; 3 LOW + 1 INFO closed in this release. Prior round: [`docs/audit/2026-04-26-audit.md`](../audit/2026-04-26-audit.md) at 1.0.1.
