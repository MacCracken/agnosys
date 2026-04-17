# Agnosys — Claude Code Instructions

## Project Identity

**Agnosys** (agi + nosys — the gnosis of AGI at the system level) is the AGNOS kernel interface library. Cyrius bindings for Linux kernel syscalls and security primitives. Consumers include only the modules they need, or include `dist/agnosys.cyr` for the full bundle.

- **Language**: Cyrius (min 5.2.0)
- **License**: GPL-3.0-only
- **Genesis repo**: [agnosticos](https://github.com/MacCracken/agnosticos)
- **Philosophy**: [AGNOS Philosophy & Intention](https://github.com/MacCracken/agnosticos/blob/main/docs/philosophy.md)
- **Standards**: [First-Party Standards](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-standards.md)
- **Recipes**: [zugot](https://github.com/MacCracken/zugot) — takumi build recipes
- **Heritage**: Ported from Rust in 2026. Rust source deleted at 0.97.1, preserved in git history. Head-to-head numbers in [`docs/benchmarks-rust-vs-cyrius.md`](docs/benchmarks-rust-vs-cyrius.md) — kept at `docs/` root rather than buried under `docs/development/` because it's a headliner.

## Architecture

Flat library. Modules under `src/`, stdlib vendored in `lib/`, full bundle in `dist/`. Each module is a `.cyr` file included via `include "src/<module>.cyr"`; a single bundled file is available at `dist/agnosys.cyr`.

```
src/           — 20 agnosys modules (error, syscall, security, mac, audit, pam, ...)
lib/           — vendored Cyrius stdlib (alloc, vec, str, tagged, syscalls, ...)
dist/          — bundled single-file distribution (cyrius distlib output)
tests/tcyr/    — integration tests (.tcyr, discovered by `cyrius test`)
tests/bcyr/    — benchmarks (.bcyr)
fuzz/          — parser fuzz harnesses (.fcyr, run by CI + audit.sh)
scripts/       — version-bump.sh, bench-history.sh, audit.sh, check-api-surface.sh
build/         — compiled binaries (gitignored)
```

## Build

```sh
cyrius build src/main.cyr build/agnosys   # compile
cyrius run src/main.cyr                   # compile + run
cyrius check src/main.cyr                 # syntax check
cyrius test                               # run tests/tcyr/*.tcyr
cyrius distlib                            # regenerate dist/agnosys.cyr
cyrius capacity --check src/main.cyr      # compiler-table utilization gate
scripts/audit.sh                          # full 10-gate local quality run
scripts/check-api-surface.sh              # diff public API vs. 1.0 snapshot
```

## Development Loop

1. Work — new features, roadmap items (see `docs/development/roadmap.md`)
2. Verify — `scripts/audit.sh` locally (syntax, API surface, capacity, build, smoke, tests, lint, vet, fuzz, benchmarks)
3. Document — update CHANGELOG, roadmap, module docs
4. Version — bump `VERSION` via `./scripts/version-bump.sh <new>`; `cyrius.cyml` reads it via `${file:VERSION}`
5. Regenerate `dist/agnosys.cyr` if any `src/*.cyr` changed

### Key Principles

- **Every change passes `scripts/audit.sh`** — 10 gates, same as CI
- **Tests + benchmarks prove the change.** Don't claim perf wins without a bench diff
- **Own the stack.** If an AGNOS crate wraps an external lib, depend on the AGNOS crate
- **No magic.** Every operation is measurable, auditable, traceable
- **Packed errors on hot paths** — `syserr_pack(kind, errno)` for zero-alloc
- **Heap errors on cold paths** — `syserr_new(kind, errno, message)` when diagnostics matter
- **Caller-provided buffers** — avoid heap allocation in syscall wrappers; caller owns memory
- **Prefix all functions** — every public fn starts with its module prefix (`agnosys_`, `mac_`, `audit_`, `pam_`, `security_`, ...). API surface frozen at `docs/development/api-surface-1.0.md`; drift fails CI
- **`AGNOSYS_LOG` env var** for log level control

## Conventions

- Error encoding: packed `kind << 16 | errno` (fast) or heap `{ kind, errno, message_ptr }` (diagnostic)
- Result convention: `Ok(value)` / `Err(error)` via `lib/tagged.cyr`
- Error propagation: `if (is_err_result(res) == 1) { return res; }`
- Syscall wrappers return raw values; use `wrap_syscall(ret)` or `agnosys_checked_syscall(ret)` for Result wrapping
- Structs: heap-allocated via `alloc()`, accessed via `store64/load64` at fixed offsets. `#derive(accessors)` adoption is a post-1.0 follow-up
- Strings: null-terminated C strings at boundaries; `lib/str.cyr` fat pointers (`Str`) internally. Parser inputs that come from `str_split` expect `Str`, not cstring
- Benchmarks: `lib/bench.cyr` with `now_ns()`, CSV history via `scripts/bench-history.sh`
- CI gates (`.github/workflows/ci.yml`): syntax check → API surface → capacity → build → ELF verify → smoke → deps → integration → lint → vet → fuzz → benchmarks

## Modules (20)

| Module | File | Description |
|--------|------|-------------|
| error | src/error.cyr | SysError types, errno mapping, Result helpers |
| syscall | src/syscall.cyr | `agnosys_*` getpid/uid/hostname/sysinfo wrappers |
| logging | src/logging.cyr | `log_*` level control via AGNOSYS_LOG env var |
| security | src/security.cyr | `security_*` — Landlock, seccomp BPF, namespace creation |
| mac | src/mac.cyr | `mac_*` — SELinux/AppArmor detection and context management |
| audit | src/audit.cyr | `audit_*` — Kernel audit netlink socket, rule management |
| pam | src/pam.cyr | `pam_*` — PAM service inspection, passwd/who parsing |
| journald | src/journald.cyr | `journald_*` — Systemd journal send/query |
| luks | src/luks.cyr | `luks_*` — LUKS2 encrypted volume management |
| dmverity | src/dmverity.cyr | `dmverity_*` — dm-verity integrity verification |
| ima | src/ima.cyr | `ima_*` — IMA measurements, policy rules |
| tpm | src/tpm.cyr | `tpm_*` — TPM2 device, PCR reading, seal/unseal |
| certpin | src/certpin.cyr | `certpin_*` — Certificate pin validation, SPKI computation |
| secureboot | src/secureboot.cyr | `secureboot_*` — Secure Boot EFI variable reading |
| udev | src/udev.cyr | `udev_*` — Device enumeration via udevadm |
| drm | src/drm.cyr | `drm_*` — DRM device enumeration, ioctl version/caps |
| netns | src/netns.cyr | `netns_*` — Network namespace create/destroy, veth, nftables |
| bootloader | src/bootloader.cyr | `bootloader_*` — systemd-boot/GRUB detection, cmdline validation |
| update | src/update.cyr | `update_*` — Atomic file ops, version comparison |
| fuse | src/fuse.cyr | `fuse_*` — FUSE mount parsing, mount/unmount |

## Consumer Map

| Consumer | Modules |
|----------|---------|
| yukti | udev |
| kavach | security (landlock, seccomp) |
| nein | netns |
| stiva | luks, dmverity |
| sigil | tpm, ima, secureboot, certpin |
| soorat | drm |
| libro | audit |
| argonaut | journald, bootloader |
| shakti | pam |
| aegis | mac |
| ark | fuse, update |
| daimon | security (seccomp), certpin |
| hoosh | certpin |

## DO NOT

- **Do not commit or push** — the user handles all git operations (commit, push, tag)
- **NEVER use `gh` CLI** — use `curl` to GitHub API only
- Do not add runtime dependencies — this is a kernel interface, keep it lean
- Do not skip `scripts/audit.sh` before claiming a change is ready
- Do not skip benchmarks before claiming performance improvements
- Do not commit `build/`
- Do not use reserved keywords as variable names (`match`, `default`, `shared`, `in`)
- Do not define functions with 7+ parameters — split into `module_thing_new(...)` + `module_thing_set_*(...)` pattern
- Do not rename a public function without bumping the API snapshot via `scripts/check-api-surface.sh --update` and updating CHANGELOG `Breaking`
- Do not edit `dist/agnosys.cyr` by hand — regenerate via `cyrius distlib`

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md,
  SECURITY.md, CODE_OF_CONDUCT.md, LICENSE

docs/ (required):
  benchmarks-rust-vs-cyrius.md  — HEADLINER: Rust-vs-Cyrius port numbers
  architecture/overview.md      — module map, data flow, consumers
  SECURITY-NOTES.md             — per-module security considerations
  development/roadmap.md        — completed, backlog, v1.0 criteria
  development/api-surface-1.0.md       — public API snapshot (human-readable)
  development/api-surface-1.0.snapshot — machine-checkable (module::fn/arity)
  development/capacity-baseline.md     — compiler-table utilization record

docs/ (when earned):
  adr/ — architectural decision records
  guides/ — usage guides, integration patterns
  examples/ — worked examples
  standards/ — external spec conformance
  sources.md — source citations for algorithms/formulas
```
