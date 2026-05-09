# Agnosys — Live State

> Volatile snapshot. Refreshed every release. Durable rules live in [`CLAUDE.md`](../../CLAUDE.md). Historical release narrative is in [`CHANGELOG.md`](../../CHANGELOG.md). Future work is in [`roadmap.md`](roadmap.md).

**Last refresh:** 2026-05-07 (1.1.12)

## Version & Toolchain

| Item | Value |
|---|---|
| `VERSION` | **1.1.12** |
| `cyrius.cyml [package].cyrius` | **5.10.9** |
| Min Cyrius (consumer) | 5.10.9 |
| Last cyrius bump | 5.9.27 → 5.10.9 (2026-05-08; bumped during V1.1.12 reopen attempt — see in-flight slots below). The 5.10.x series introduced the version-pinned cc5_aarch64 lib resolution (kills cross-version contamination per [`archive/2026-05-07-cyrius-derive-serialize-incomplete.md`](issues/archive/2026-05-07-cyrius-derive-serialize-incomplete.md)) and full RFC 8259 §7 Serialize-side JSON escaping. |

## Build Metrics

| Metric | Value | Notes |
|---|---|---|
| Binary size (DCE) | **85,592 B** | unchanged across V1.1 (pure refactor; no behavior change) |
| `dist/agnosys.cyr` size | ~330 KB / 9,886 lines | bundled distlib (full library); -68 lines vs 1.0.5 from removing hand-written accessor fns |
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

10 gates, all green at 1.0.5: syntax → API surface → capacity → build → smoke → tests → lint → vet → fuzz → benchmarks. Mirrors CI.

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
| **1.1.12** | 2026-05-07 | V1.1.12 `#derive(Serialize)` — DEFERRED. cyrius 5.9.27 ships the `#derive(Serialize)` syntax but generated `_to_json` body is either empty (untyped fields) or references nonexistent stdlib helpers (`i64_to_json_sb`, etc. for typed fields). Filed upstream issue; slot reopens when primitive Serialize helpers land |
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
- [~] V1.1.12 — `#derive(Serialize)` — DEFERRED (twice). Original 2026-05-07 file (`cyrius-derive-serialize-incomplete`) **resolved** 2026-05-08 — root cause was agnosys's vendored `./lib/fnptr.cyr` and `./lib/json.cyr` stubs (5.7.6-era) shadowing v5.10.9 stdlib; cyrius's PP_DERIVE Serialize codegen at v5.10.6+ is correct on both arches. Reopen attempt then surfaced a fresh upstream blocker (`2026-05-08-cyrius-derive-multi-stacking`): cyrius PP_DERIVE doesn't honor stacked `#derive(...)` directives, so `#derive(Serialize)` cannot layer on top of agnosys's existing `#derive(accessors)` structs. Slot stays deferred until cyrius supports multi-derive. cyrius pin held at 5.10.9 (the pin bump arc through 5.10.6 → 5.10.7 → 5.10.8 → 5.10.9 is durable; only the slot work was reverted).

Slot # = agnosys VERSION # for this minor cycle. Multi-version
shipping arcs (1.1.2-1.1.4 ct_eq_bytes; 1.1.5-1.1.6 exhaustive
match; 1.1.8-1.1.10 multi-width struct fields) get one slot per
shipped patch.
- [ ] 1.1.4 — first-class tagged-union `Result` replacing lib/tagged.cyr
- [ ] 1.1.5 — multi-width struct fields for kernel binary protocols
- [ ] 1.1.6 — slice migration for syscall + parser buffers
- [ ] 1.1.7 — `#derive(Serialize)` for diagnostic JSON output

V1.2.0 (multi-profile `cyrius distlib`) follows. See [`roadmap.md`](roadmap.md) for the full plan.

## Last Security Audit

[`docs/audit/2026-04-26-audit.md`](../audit/2026-04-26-audit.md) — P(-1) hardening pass at 1.0.1.
