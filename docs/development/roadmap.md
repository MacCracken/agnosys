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

## Phase 8 — Post-1.0 Backlog (replanned 2026-05-06)

Reorganized into 1.1.x (language-feature adoption) → 1.2.x (ecosystem) → 1.3+ (cross-repo).
The 2026-05-06 P(-1) review against the cyrius 5.9.1 feature surface (vidya
`content/cyrius/language/`) added new slots leveraging `defer`, first-class
slices, tagged-union sum types, exhaustive match, `secret var`, multi-width
struct fields, and `#derive(Serialize)` — none of which existed when the agnosys
port shipped at 5.7.6. See [ADR-004](../adr/004-1-1-x-roadmap-rework.md) for the
reasoning. Audit-derived fixes from the 2026-04-26 P(-1) all landed in 1.0.1
(see [`docs/audit/2026-04-26-audit.md`](../audit/2026-04-26-audit.md)); this
phase covers items that are not security-blocking.

### V1.1 — Language-feature adoption

Theme: leverage cyrius 5.8.x / 5.9.x features that landed after the agnosys
port. Min-cyrius pin stays at 5.9.x for the duration unless a specific bug fix
in a later 5.9.y matters (cyrius 5.9.x is the maintenance line — improvements
and optimizations only, not new features).

#### V1.1.0 — `#derive(accessors)` migration ✅ SHIPPED 2026-05-06

- [x] Migrated all 16 struct-bearing modules' accessors from `store64`/`load64` at fixed offsets to `#derive(accessors)` syntax. 37 derive structs total. (3 modules — error/audit/security — have legitimate non-derive cases documented inline; remaining modules had no heap structs to migrate.)
- [x] Snapshot updated additively — 561 → 721 public fns; no removals or arity changes.
- [x] Slot-by-slot patches: 1.0.6 (mac) → 1.0.7 (fuse/drm/bootloader) → 1.0.8 (dmverity/luks/certpin) → 1.0.9 (udev/journald/audit) → 1.0.10 (ima/tpm/secureboot) → 1.0.11 (pam/netns/update + cyrius 5.9.7) → 1.0.12 (tooling cleanup + cyrius 5.9.14) → 1.0.13 (closeout) → tagged as 1.1.0.

**Rationale:** removes hand-written offset arithmetic across the most-touched code in agnosys; reduces off-by-one risk; readable. Mechanical but invasive (touches every struct), so kept off the 1.0 freeze. Headline 1.1 cycle because every other 1.1.x slot interacts with the accessor surface.

#### V1.1.1 — `defer { }` adoption for resource cleanup ✅ SHIPPED 2026-05-06

- [x] Audit found that the work was already done during the original port — 24 `defer { sys_close(...) }` sites in place across mac/fuse/drm/audit/journald/luks/dmverity/ima/tpm/secureboot/pam/netns/update/security/logging.
- [x] Bench parity verified — no defer-epilogue overhead since no new defer sites added.
- [x] Leak audit — no early-return leaks found. The 9 non-defer `sys_close` sites (audit_open conditional close, drm_close API, bootloader/secureboot existence probes, netns close-before-subprocess, update_get_current_slot read-then-close, security_apply_landlock in-loop close) are all deliberate.

Slot shipped as a verification + audit pass; CHANGELOG `[1.1.1]` documents the findings and the deliberate non-defer cases. No source changes were required.

**Rationale:** exit-path safety; cyrius 5.8.x ships per-defer runtime flags so unreached defers skip cleanly. Today's flag+continue patterns are equivalent in correctness but harder to audit.

#### V1.1.2 — `ct_eq_bytes` deferral (issue filed) ✅ SHIPPED 2026-05-06

The slot's premise — `ct_eq` as a cyrius compiler builtin or
`lib/ct.cyr` helper — turned out incomplete on cyrius 5.9.14:
`ct_eq` was not a builtin; `lib/ct.cyr` shipped only `ct_select`;
`secret var` rejected scalar declarations (didn't fit
cstring-pointer pin storage). The existing
`src/certpin.cyr:120 fn certpin_ct_streq` was correct as-is
(canonical XOR-accumulate, no data-dependent branches).

Filed [`docs/development/issues/archive/2026-05-06-cyrius-ct-eq-bytes-stdlib.md`](../issues/archive/2026-05-06-cyrius-ct-eq-bytes-stdlib.md)
proposing `ct_eq_bytes(a, b, n)` for `lib/ct.cyr`. Slot shipped
as a deferral — issue + verification + roadmap defer note.

**Rationale:** the compiler-backed primitive is the canonical path post-5.8.x (sigil's PQC code uses it). Our hand-rolled version works but isn't the supported pattern.

#### V1.1.3 — `ct_eq_bytes` reopen ✅ SHIPPED 2026-05-06

cyrius 5.9.18 added `ct_eq_bytes(a, b, n)` to `lib/ct.cyr`
(canonical XOR-accumulate; doc-comment credits the agnosys
filing). agnosys-side migration:

- [x] `cyrius.cyml [deps].stdlib` += `"ct"` (auto-prepend).
- [x] `src/certpin.cyr fn certpin_ct_streq` body shrunk from a
  16-line hand-roll to a 5-line cstring wrapper that delegates
  the byte loop into `ct_eq_bytes(a, b, alen)`. Length-mismatch
  early-return preserved (pin length is non-secret in agnosys —
  44-char base64 SHA-256, fixed by spec).
- [x] Bench parity verified: `ct_streq_equal` 125→129ns,
  `ct_streq_diff` 135→140ns (within run-to-run noise).

`secret var` annotation deferred indefinitely — pin storage in
certpin flows through cstring pointers across struct boundaries,
which doesn't fit cyrius's array-only `secret var` contract.
Revisit if/when `secret var` gains a pointer-form or a separate
`secret_str` annotation.

#### V1.1.4 — `ct_eq_bytes_lens` one-liner + `sys_stat` x86 fix ✅ SHIPPED 2026-05-06

cyrius 5.9.20 closed two upstream gaps in one bump:

- [x] `lib/ct.cyr` added `ct_eq_bytes_lens(a, a_len, b, b_len)`
  (dual-length variant; sigil-paired consolidation). agnosys's
  `certpin_ct_streq` body further shrunk to a one-liner full
  delegation: `return ct_eq_bytes_lens(a, strlen(a), b, strlen(b));`.
- [x] `lib/syscalls_x86_64_linux.cyr:309` added `fn sys_stat`
  (peer with the existing aarch64 entry at line 346) — closed
  the long-open
  [`docs/development/issues/archive/2026-05-01-sys-stat-x86-portability.md`](../issues/archive/2026-05-01-sys-stat-x86-portability.md)
  filed by sigil 3.0 against agnosys 1.0.4. No agnosys-side
  shim needed.

#### V1.1.5 — Exhaustive `match` coverage adoption ✅ SHIPPED 2026-05-06

agnosys's first `match` block — `src/error.cyr fn syserr_print`
converted from a 7-elif + else chain to a `match kind { ... }`
over all 8 `SysErrorKind` variants, no `_ =>` opt-out. Future
`SysErrorKind` additions trigger a build-time warning until
handled.

- [x] `scripts/audit.sh` gate 4 now greps the build log for
  `non-exhaustive` and fails the gate. Verified by regression
  test (deliberately removed an arm; gate fired with the
  expected message).
- [x] Other 14 enum-to-string fns
  (`update_phase_str`, `pam_service_name`, `tpm_bank_str`, etc.)
  kept as if/elif chains — their catch-all defaults are correct
  for wire-format / debug serializers where missing-variant
  should degrade gracefully rather than fall through silently.

#### V1.1.6 — Match-coverage corrigendum + cyrius 5.9.25 pin ✅ SHIPPED 2026-05-07

The match-coverage check on cyrius 5.9.20–5.9.21 was
fn-name-dependent (hash-bucket dispatch in coverage bookkeeping;
a roughly 50/50 mix of warning-fires vs warning-skips across fn
names). agnosys 1.1.5's CHANGELOG attributed the inconsistency
to DCE-gating; that diagnosis was wrong. Filed
[`docs/development/issues/archive/2026-05-06-cyrius-match-coverage-fn-name-dependent.md`](../issues/archive/2026-05-06-cyrius-match-coverage-fn-name-dependent.md);
fix landed in cyrius 5.9.25.

- [x] cyrius pin 5.9.20 → 5.9.25.
- [x] CHANGELOG corrigendum to 1.1.5: real cause was hash-table
  indexing, not DCE-gating. The 1.1.5 audit gate is still correct
  as a CI hook; on 5.9.25 its coverage is now reliable across
  every fn name.
- [x] Side-observation also fixed: `cyrius --version` no longer
  emits the trailing `\xb3` byte.

(`syserr_print` happened to be in a "lucky" hash bucket on
5.9.20–5.9.21, so the V1.1.5 gate was correct in practice for
agnosys's one match block — just hash-bucket-dependent for any
future second match. 5.9.25 makes the gate reliable for new
matches landing in V1.1.7+.)

#### V1.1.7 — Tagged-union `Result` adoption ✅ SHIPPED 2026-05-07 (verification slot)

The slot anticipated migrating agnosys's `Result`/`Option`
construction from `lib/tagged.cyr`'s hand-rolled `tagged_new`/
`tag`/`is_tag` primitives to cyrius's first-class
`enum Result<T, E> { Ok(v); Err(e); }` form. Verification
showed the migration was already complete via stdlib evolution:

- [x] cyrius v5.8.23 migrated `lib/tagged.cyr`'s `Option` to a
  first-class sum type. v5.8.28 carved `Result<T, E>` out into
  `lib/result.cyr` as a typed first-class sum type
  (transitively included by lib/tagged.cyr).
- [x] agnosys's call sites use only the high-level API (`Ok(...)`,
  `Err(...)`, `is_ok(res)`, `is_err_result(res)`, `payload(res)`).
  Zero direct `tagged_new(...)`, `tag(...)`, or `is_tag(...)`
  calls in src/* (verified across all 24 source files).
- [x] When agnosys writes `return Ok(value);`, cyrius resolves
  `Ok` to the derive-emitted constructor in lib/result.cyr —
  same heap layout as the pre-v5.8.21 hand-rolled
  `tagged_new(0, value)`, transparently.

Pattern-payload destructuring (`match res { Ok(v) => use(v) }`)
is NOT yet shipped in cyrius (per vidya `tagged_unions_v58x`:
"That's a future slot"). When it lands, agnosys's
`if (is_err_result(res) == 1) { return res; } var v = payload(res);`
chains become candidates for the cleaner `match` form. Until
then the if/payload chain stays as the canonical idiom.

**Rationale:** the lib/tagged.cyr API still works but is the pre-5.8.21 hand-rolled pattern. First-class sum types compile to byte-identical layout for arity-1, and exhaustive-match (V1.1.5) becomes load-bearing once Result is a real enum.

#### V1.1.8 — Multi-width struct fields for kernel binary protocols ✅ SHIPPED 2026-05-07

Four kernel-ABI structs migrated to typed `struct` decls +
pointer-to-struct dot syntax:

- [x] `sockaddr_nl` (12 B; u16/u16/u32/u32) in audit.cyr
- [x] `nlmsghdr` (16 B; u32/u16/u16/u32/u32) in audit.cyr —
  both write side (`audit_build_nlmsg`) and read side
  (`audit_recv_raw`'s parser)
- [x] `audit_kstatus` (32 B; 8× u32) in audit.cyr — read side
  in `audit_get_status` and write side in `audit_set_enabled`
- [x] `bpf_insn` (8 B; u16/u8/u8/u32) in security.cyr

14 explicit width-store calls eliminated; 3 width-load reads
also converted. cyrius's width-correct codegen emits the right
`store16`/`store32`/`load16`/`load32` instructions automatically;
the kernel-correct tight-packed byte layout is enforced by the
typed field declarations.

Stack-local kernel-ABI writes (LandlockRulesetAttr,
LandlockPathBeneathAttr, sock_fprog at security.cyr lines 106
and 195) **deferred** — per vidya `multi_width_types`, stack
locals use 8-byte slots regardless of declared width, so
`var attr: T;` doesn't preserve kernel ABI on the stack. The
existing `var buf[N]; store32(&buf+N, ...);` pattern stays
correct for those sites.

**Discovery worth recording (in CHANGELOG `[1.1.8]`):**
1. `#derive(accessors)` lays typed fields out at i64 slots, NOT
   FIELDOFF tight-packed offsets. Suitable for internal-layout
   structs; NOT for kernel-ABI structs.
2. Pointer-to-struct dot syntax (`var s: T = ptr; s.f = v;`)
   honors width-aware tight-packed offsets — verified by
   byte-dumping. This is V1.1.8's migration vehicle.

**Rationale:** cyrius 5.8.x ships width-correct codegen — `var x: i32 = …` does the right `mov dword [addr], eax`. Today's hand-rolled mixed-width store/load pattern is correct but loses the type system's ability to catch a `store64` where a `store32` was meant.

#### V1.1.9 — V1.1.8 revert (aarch64 sub-8-byte struct field load gap) ✅ SHIPPED 2026-05-07

V1.1.8 shipped clean on x86_64 but broke aarch64 cross-build
(`error:1610: sub-8-byte struct field load is x86-only for
v5.6.0; aarch64 + cx pending`). Reverted source-side back to
the explicit `store{8,16,32}` pattern. Filed
[`docs/development/issues/archive/2026-05-07-cyrius-aarch64-sub-8-byte-struct-load.md`](../issues/archive/2026-05-07-cyrius-aarch64-sub-8-byte-struct-load.md)
and added a permanent `cyrius build --aarch64` gate to
`scripts/audit.sh` step 4 so the regression class is caught
in local audit, not just CI.

#### V1.1.10 — V1.1.8 reopen (cyrius 5.9.27 pin) ✅ SHIPPED 2026-05-07

cyrius 5.9.27 implemented the aarch64 backend's `EFLLOAD_W`
codegen for sub-32-bit struct field loads. agnosys reopened
V1.1.8 by restoring the typed kernel-ABI struct decls + dot
syntax and bumping the cyrius pin `5.9.25` → `5.9.27`. Both
arches clean; aarch64 cross-build gate confirms.

#### V1.1.11 — Slice migration for syscall + parser buffers ✅ SHIPPED 2026-05-07

Survey of the 35 `var buf[N]` sites in src/* showed most aren't
real slice candidates: ~10 tiny fmt buffers (no indexed access),
~6 kernel-ABI stack structs (different pattern), ~7 one-shot
syscall arg buffers (no indexed access), ~12 large parser
buffers using `memeq`/`memcpy` with explicit `pos < outlen`
walks (length-bounded by construction; slice subscript would
re-validate already-validated bounds).

- [x] One representative site migrated as the canonical pattern:
  `src/ima.cyr fn ima_get_status`'s newline-counting loop over
  the 4 KB rbuf converted from `load8(&rbuf + ri)` with explicit
  `ri < n` to `slice_set(&s, &rbuf, n)` + `s[ri]` with
  `ri < s.len`. Bounds-checked indexing replaces the manual
  bound and protects against future drift.
- [x] `cyrius.cyml [deps].stdlib += "slice"`; explicit
  `include "lib/slice.cyr"` added to entry-point sources and
  to `src/ima.cyr` (required for `cyrius check` standalone-mode
  syntax resolution of slice subscript helpers).
- [x] Both arches clean (cyrius 5.9.27 has slice support on
  aarch64).

Future scalar-subscript parser loops should adopt the slice
form from the start; the existing `memeq`/`memcpy`-based parsers
stay as-is since their bounds are already explicit.

**Rationale:** bounds-checked indexing on the agnosys parsers (audit netlink, fuse mount entries, EFI var bytes, IMA measurement records) closes the off-by-one class without a runtime cost we can't already amortize.

#### V1.1.12 — `#derive(Serialize)` ✅ SHIPPED 2026-05-09

The slot's premise — `#derive(Serialize)` auto-generates a
working `<struct>_to_json(ptr, sb)` per vidya
`derive_str_fields` — initially deferred 2026-05-07 due to
an apparent SIGILL on aarch64. Root cause discovered
2026-05-08 (cyrius team's `pwd && ls -la lib/` diagnostic):
agnosys's vendored `./lib/fnptr.cyr` and `./lib/json.cyr`
stubs (5.7.6-era) were shadowing v5.10.x stdlib's full
versions; PP_DERIVE Serialize codegen referenced helpers
absent from the stubs. cyrius's PP_DERIVE was correct on
both arches the entire time.

agnosys 1.1.12 ships:

- **2 derived serializers** via stacked `#derive`
  (cyrius 5.10.14+): `audit_status_to_json`,
  `ima_status_to_json` — both all-numeric structs, both
  arches verified on real Pi.
- **5 hand-rolled `_to_json` shims** for cstring-bearing
  diagnostic structs (`mac_profile`, `dmverity_status`,
  `update_state`, `certpin_info`, `drm_verinfo`). Pattern:
  per-module `_<mod>_emit_cstr_or_null` helper handles
  null-or-quoted cstring emission, mixed with
  `str_builder_add_int` for numeric fields.

Hand-rolls unwind cleanly when cyrius adds cstring
`#derive(Serialize)` support — the future migration is
mechanical (delete the shim + helper, add
`#derive(Serialize)` directive line, regenerate snapshot).

Three issues filed and resolved during the arc:
- `archive/2026-05-07-cyrius-derive-serialize-incomplete`
  — agnosys-side `./lib/` shadow, not cyrius.
- `archive/2026-05-08-cyrius-derive-multi-stacking` —
  fixed cyrius 5.10.14.
- `archive/2026-05-09-cyrius-api-surface-putc-brace-desync`
  — fixed cyrius 5.10.16.

cyrius pin arc: 5.9.27 → 5.10.16. Min consumer cyrius is
now 5.10.16 (multi-derive + scanner fixes baked in).

**Rationale:** consumer ergonomics. Today every consumer that wants to log agnosys state writes its own formatter. `#derive(Serialize)` ships the canonical one with the module.

### V1.2 — Ecosystem

Theme: consumer-facing wiring and platform discipline. Independent of the 1.1.x
language-feature surface — these are durable infrastructure improvements.

#### V1.2.0 — Multi-profile `cyrius distlib` ✅ SHIPPED 2026-05-09

- [x] Add `[lib.security]` (security + mac + audit + pam) → `dist/agnosys-security.cyr` (76 KB)
- [x] Add `[lib.storage]` (luks + dmverity + fuse) → `dist/agnosys-storage.cyr` (49 KB)
- [x] Add `[lib.trust]` (tpm + ima + secureboot + certpin) → `dist/agnosys-trust.cyr` (70 KB)
- [x] Add `[lib.system]` (journald + bootloader + udev + drm + netns + update) → `dist/agnosys-system.cyr` (111 KB)
- [x] Add `[lib.core]` (error + syscall + logging + arch peers) → `dist/agnosys-core.cyr` (23 KB). The "kernel-safe subset for AGNOS-kernel direct consumption (no alloc, no syscall, pure enums/types)" is a future refinement on top of this V1.2.0 deliverable — current `[lib.core]` ships the listed modules as-is; trimming alloc/syscall paths to a pure-enum form is a follow-up slot if/when AGNOS-kernel direct consumption lands.
- [x] CI dist-staleness gate extended to all five profiles + the full bundle (6 total).
- [x] Release archive ships every profile bundle alongside the full `dist/agnosys.cyr`.

**Rationale:** kavach pulls 324 KB today for what it actually uses (~50 KB security surface). Profile bundles cut consumer binary size and clarify the agnosys → consumer wiring. Headline 1.2 cycle because it changes the consumer-facing distribution shape — gets its own minor cycle.

#### V1.2.1 — `#ifplat` cosmetic migration (was 8.3)

- [ ] Migrate `#ifdef CYRIUS_ARCH_X86` / `#ifdef CYRIUS_ARCH_AARCH64` to `#ifplat x86` / `#ifplat aarch64` across `src/syscall_*_linux.cyr` and any other arch-gated blocks.
- [ ] Per-module Linux-only declaration: audit / pam / journald / dmverity / ima / secureboot are kernel-Linux-by-definition (kernel netlink frames, PAM config, dm-verity ioctls).
- [ ] Cross-platform candidates declared: `error`, `syscall` (already split via `lib/syscalls_*.cyr` in cyrius 5.5.x), `logging`, `certpin` (pure crypto, no syscalls).
- [ ] `docs/architecture/NNN-platform-matrix.md` documenting the matrix.
- [ ] Track upstream cyrius macOS/Windows port progress; revisit when consumer demand exists.

**Rationale:** purely cosmetic syntactic uplift on the arch-gated code, plus documentation discipline so accidental Linux-isms in portable modules get caught early.

#### V1.2.2 — Capability map per public fn ✅ SHIPPED 2026-05-09 (in 1.2.1)

- [x] `docs/development/capability-map.md` — auto-generated, per-module granularity (638 lines). Per-fn rows would need a real cyrius AST walker for transitive call resolution — deferred to a future slot if downstream demand surfaces.
- [x] `scripts/gen-capability-map.sh` — parses each module's source, extracts direct syscalls + sys_* wrappers + exec paths + filesystem paths. `--check` mode wired into audit.sh as gate 3/11 (fails CI on drift).
- [x] Per-profile rollup added: `dist/agnosys-<profile>.cyr` bundles map cleanly to module sets, so kavach (security profile) etc. derive their seccomp/Landlock allowlist by aggregating the modules in their profile.

**Rationale:** `docs/SECURITY-NOTES.md` covers per-module concerns at prose level. A machine-checkable surface gives kavach/daimon a programmatic basis for seccomp policy generation.

#### V1.2.3 — Consumer integration CI (was 8.4)

- [ ] Nightly GitHub Actions job per consumer: clone, vendor agnosys main, build, run consumer's tests
- [ ] Failures open an issue tagged `consumer-break` (linked to consumer + agnosys commit)
- [ ] 13 consumers in scope (see `state.md` consumer table); start with sigil + kavach (highest module surface), expand

**Rationale:** v1.0 deferred this to "tracked on consumer crates" — i.e., manual. Automated drift detection means an agnosys patch that breaks sigil's TPM caller fails before that consumer notices.

#### V1.2.4 — `#deprecated` adoption channel

- [ ] Adopt cyrius's `#deprecated("reason / migration")` attribute for any post-1.0 API drift (graceful deprecation path before removal).
- [ ] Document the soft-removal protocol in CONTRIBUTING.md: deprecate → one-minor bake → remove with `Breaking` in CHANGELOG.

**Rationale:** today every public-fn rename is either a hard break (snapshot bump) or a frozen API call. `#deprecated` adds a third channel — warning at every call site, snapshot still passes, consumers see the warning in their CI before the actual removal.

### V1.3+ — Cross-repo / meta-tooling

#### V1.3.0 — `state.md` release post-hook (was 8.6)

- [x] state.md created at 1.0.1
- [ ] Release post-hook auto-bumps state.md (version, binary size, test counts)
- [ ] CI gate that fails the release if state.md `Last refresh` doesn't match the tag

**Rationale:** template's "release post-hook bumps state.md. If the hook doesn't, fix the hook — don't hand-maintain state." Lands when agnosticos meta-tooling supports it (cross-repo concern — hook lives in agnosticos toolchain, not this repo).

## V1.0+ Verification

- [x] **1.1.0** shipped 2026-05-06 — V1.1.0 (`#derive(accessors)`) complete; closeout patch (1.0.13) clean; 16 of 16 struct-bearing modules migrated. See CHANGELOG `[1.1.0]` for the consumer banner and `[1.0.13]` for the cumulative baseline.
- [ ] Subsequent V1.1.x slots (1.1.1 through 1.1.7) ship as patches against 1.1.
- [ ] **1.2.0** ships when V1.2.0 (multi-profile distlib) is complete; closeout against the consumer set.
- [ ] V1.2.x slots may ship in any order; gate is bench parity + audit clean.
- [ ] V1.3.0 ships when the agnosticos meta-tooling supports the release post-hook.

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
