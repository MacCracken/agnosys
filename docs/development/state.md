# Agnosys — Live State

> Volatile snapshot. Refreshed every release. Durable rules live in [`CLAUDE.md`](../../CLAUDE.md). Historical release narrative is in [`CHANGELOG.md`](../../CHANGELOG.md). Future work is in [`roadmap.md`](roadmap.md).

**Last refresh:** 2026-05-09 (1.2.0)

## Version & Toolchain

| Item | Value |
|---|---|
| `VERSION` | **1.2.0** |
| `cyrius.cyml [package].cyrius` | **5.10.19** |
| Min Cyrius (consumer) | 5.10.19 |
| Last cyrius bump | 5.10.18 → 5.10.19 (2026-05-09; closes the lib/process.cyr O_WRONLY syntax-check blocker that survived 5.10.18). Multi-step bump arc 5.9.27 → 5.10.19 covered: 5.10.6→.9 lib version-pinning + RFC 8259 §7 escaping; 5.10.14 stacked `#derive` fix; 5.10.16 api-surface scanner desync fix; 5.10.18 + 5.10.19 lib/process.cyr O_WRONLY fix. |

## Build Metrics

| Metric | Value | Notes |
|---|---|---|
| Binary size (DCE) | **132,952 B** | +47,360 B vs 1.1.12 (85,592 B) — `[deps] stdlib` adds `fnptr` (33 KB src) + `json` (49 KB src) + `tagged` (3.9 KB src) for `#derive(Serialize)` helper resolution. DCE drops 66 of those fns but global JTAG_* constants persist. |
| `dist/agnosys.cyr` size | ~326 KB / 10,051 lines | +165 lines vs 1.1.12 — adds 7 `_to_json` fns (2 derived + 5 hand-rolled) and a private `_<mod>_emit_cstr_or_null` helper per cstring-bearing module. |
| Fn-table utilization | 390 / 4,096 (10%) | +101 fns since 1.1.12; #derive(Serialize)-emitted to_json + from_json + from_json_str + hand-rolled shims |
| Var-table | 319 / 8,192 | |
| Fixup-table | 826 / 262,144 | |
| String-data | 1,400 / 2,097,152 | |
| Code-size | 85,200 / 1,048,576 | |
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
| Integration tests passed | **247 / 247** | `cyrius test` |
| Integration assertions | 270 | `tests/tcyr/test_integration.tcyr` (audit-regression block added 1.0.2; 1.1.12 added 8 to_json round-trip assertions; 1.1.14 added 5 — 3 fuse escape + 2 security smoke) |
| Fuzz harnesses | 7 | `fuzz/audit_nlmsg.fcyr`, `fuzz/audit_reply.fcyr`, `fuzz/certpin_pin.fcyr`, `fuzz/fuse_parse.fcyr` (1.1.14), `fuzz/journald_filter.fcyr`, `fuzz/luks_cipher.fcyr`, `fuzz/pam_config.fcyr` |
| Benchmarks | 30 (11 groups) | `tests/bcyr/bench_all.bcyr` |
| Bench file (compare) | 1 | `tests/bcyr/bench_compare.bcyr` (Cyrius vs Rust port baseline) |

## Local Audit Gates (`scripts/audit.sh`)

10 gates, all green at 1.1.14: syntax → API surface → capacity → build → smoke → tests → lint → vet → fuzz → benchmarks. Mirrors CI.

## CI Workflow Status

- `.github/workflows/ci.yml` — yukti-pattern: tarball install via cyrius.cyml-derived version, deps + verify-hashes, fmt-check, lint warn-fail, vet, dist staleness gate, DCE build, ELF magic, aarch64 best-effort cross, smoke, integration, fuzz, bench, security scan, docs check.
- `.github/workflows/release.yml` — accepts `vX.Y.Z` and `X.Y.Z`; verify-version, install toolchain, deps + verify, DCE build, aarch64 best-effort, tests, fuzz, regenerate dist, archive (source tar + bundled `.cyr` + prebuilt x86_64 + aarch64 binaries + cyrius.lock + SHA256SUMS).

## Dependencies

- **Runtime**: 0
- **Stdlib via `[deps] stdlib`**: `syscalls`, `string`, `alloc`, `fmt`, `vec`, `str`, `io`, `ct`, `slice` (9 — `ct` added 1.1.3 for `ct_eq_bytes`; `slice` added 1.1.11 for `slice<u8>` indexing)
- **Git-pinned**: 0 (no `[deps.<name>]` stanzas; no `cyrius.lock` needed today)
- **Vendored stdlib refresh** (last): 2026-04-26 to cyrius 5.7.6 snapshot (`alloc.cyr`, `io.cyr`, `string.cyr`, `syscalls.cyr` — 5.5.x split into per-OS dispatch). 5.7.7 through 5.9.1 introduced no stdlib changes affecting agnosys's `[deps] stdlib = [syscalls, string, alloc, fmt, vec, str, io]` set; `cyrius deps` is a no-op against the existing vendor.

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
| **1.2.0** | 2026-05-09 | V1.2.0 multi-profile `cyrius distlib` shipped — 5 profile bundles (`core`, `security`, `storage`, `trust`, `system`) ship alongside the full bundle. Consumer-facing distribution-shape change: kavach 324 KB → ~99 KB (70% cut), stiva → ~72 KB (78%), sigil → ~92 KB (72%). `[lib.<profile>]` sections in `cyrius.cyml`; CI dist-staleness gate covers all 6 bundles; release archive ships every profile per tag. No source changes; no API surface drift. Yukti pattern; proven primitive. |
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

## In-Flight Slots

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

Slot # = agnosys VERSION # for this minor cycle. Multi-version
shipping arcs (1.1.2-1.1.4 ct_eq_bytes; 1.1.5-1.1.6 exhaustive
match; 1.1.8-1.1.10 multi-width struct fields) get one slot per
shipped patch.
- [ ] 1.1.4 — first-class tagged-union `Result` replacing lib/tagged.cyr
- [ ] 1.1.5 — multi-width struct fields for kernel binary protocols
- [ ] 1.1.6 — slice migration for syscall + parser buffers
- [ ] 1.1.7 — `#derive(Serialize)` for diagnostic JSON output

V1.2.0 (multi-profile `cyrius distlib`) shipped 2026-05-09. V1.2.1 (`#ifplat` cosmetic migration — held pending upstream codegen fix per the cyrius-side note in `lib/syscalls.cyr` v5.4.19+) and V1.2.2 (capability map per public fn) follow next. See [`roadmap.md`](roadmap.md) for the full plan.

## Last Security Audit

[`docs/audit/2026-05-09-audit.md`](../audit/2026-05-09-audit.md) — P(-1) hardening pass at 1.1.14. Pairs with [`2026-05-09-cve-landscape.md`](../audit/2026-05-09-cve-landscape.md) (CVE class survey) and [`reviews/2026-05-09-internal-review.md`](reviews/2026-05-09-internal-review.md) (internal deep review). 0 critical / 0 high / 0 medium findings; 3 LOW + 1 INFO closed in this release. Prior round: [`docs/audit/2026-04-26-audit.md`](../audit/2026-04-26-audit.md) at 1.0.1.
