# Agnosys — Claude Code Instructions

## Project Identity

**Agnosys** (agi + nosys — the gnosis of AGI at the system level) is the AGNOS kernel interface library. Cyrius bindings for Linux kernel syscalls and security primitives. Consumers include only the modules they need.

- **Language**: Cyrius
- **License**: GPL-3.0-only
- **Genesis repo**: [agnosticos](https://github.com/MacCracken/agnosticos)
- **Philosophy**: [AGNOS Philosophy & Intention](https://github.com/MacCracken/agnosticos/blob/main/docs/philosophy.md)
- **Standards**: [First-Party Standards](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-standards.md)
- **Recipes**: [zugot](https://github.com/MacCracken/zugot) — takumi build recipes
- **Ported from**: Rust (29,257 lines → 9,884 lines Cyrius). Rust source removed at 0.97.1, preserved in git history. See `BENCHMARKS-RUST-VS-CYRIUS.md`.

## Architecture

Flat library. Modules under `src/`, stdlib vendored in `lib/`. Each module is a `.cyr` file included via `include "src/module.cyr"`. Consumers include only what they need — this is the Cyrius equivalent of feature-gating.

```
src/           — agnosys modules (error, syscall, security, mac, audit, pam, ...)
lib/           — vendored Cyrius stdlib (alloc, vec, str, tagged, syscalls, ...)
tests/         — test and benchmark programs
build/         — compiled binaries (gitignored)
```

## Build

```sh
cyrius build src/main.cyr build/agnosys   # compile
cyrius run src/main.cyr                   # compile + run
cyrius check src/main.cyr                 # syntax check
```

## Development Process

### P(-1): Scaffold Hardening (before any new features)

0. Read roadmap, CHANGELOG, and open issues — know what was intended before auditing what was built
1. Test + benchmark sweep of existing code
2. Cleanliness check: `cyrb check` on all src/*.cyr, `cyrb audit` if available
3. Get baseline benchmarks (`./scripts/bench-history.sh`)
4. Initial refactor + audit (performance, memory, security, edge cases)
5. Cleanliness check — must be clean after audit
6. Additional tests/benchmarks from observations
7. Post-audit benchmarks — prove the wins
8. Repeat audit if heavy
9. Documentation audit — ADRs, source citations, guides, examples

### Development Loop (continuous)

1. Work phase — new features, roadmap items
2. Cleanliness check: `cyrb check` all src/*.cyr
3. Test + benchmark additions for new code
4. Run benchmarks (`./scripts/bench-history.sh`)
5. Audit phase — review performance, memory, security, throughput
6. Cleanliness check — must be clean after audit
7. Deeper tests/benchmarks from audit observations
8. Run benchmarks again — prove the wins
9. If audit heavy → return to step 5
10. Documentation — update CHANGELOG, roadmap, docs
11. Version check — VERSION in sync
12. Return to step 1

### Key Principles

- **Never skip benchmarks.** Numbers don't lie. The CSV history is the proof.
- **Tests + benchmarks are the way.**
- **Own the stack.** If an AGNOS crate wraps an external lib, depend on the AGNOS crate.
- **No magic.** Every operation is measurable, auditable, traceable.
- **Packed errors on hot paths** — `syserr_pack(kind, errno)` for zero-alloc error returns.
- **Heap errors on cold paths** — `syserr_new(kind, errno, message)` when diagnostics matter.
- **Caller-provided buffers** — avoid heap allocation in syscall wrappers; let the caller own the memory.
- **Prefix all functions** — `agnosys_`, `mac_`, `audit_`, `pam_`, etc. to avoid collisions in global namespace.
- **`AGNOSYS_LOG` env var** for log level control.

## Conventions

- Error encoding: packed `kind << 16 | errno` (fast) or heap `{ kind, errno, message_ptr }` (diagnostic)
- Result convention: `Ok(value)` / `Err(error)` via `lib/tagged.cyr`
- Error propagation: `if (is_err_result(res) == 1) { return res; }`
- Syscall wrappers return raw values; use `wrap_syscall(ret)` for Result wrapping
- Structs: heap-allocated via `alloc()`, accessed via `store64/load64` at fixed offsets
- Strings: null-terminated C strings; use `lib/str.cyr` for fat pointers when needed
- Benchmarks: `lib/bench.cyr` with `now_ns()`, CSV history via `scripts/bench-history.sh`
- CI: syntax check + build + smoke test + benchmarks

## Modules (20)

| Module | File | Description |
|--------|------|-------------|
| error | src/error.cyr | SysError types, errno mapping, Result helpers |
| syscall | src/syscall.cyr | getpid/uid/hostname/sysinfo wrappers |
| logging | src/logging.cyr | Log level control via AGNOSYS_LOG env var |
| security | src/security.cyr | Landlock, seccomp BPF, namespace creation |
| mac | src/mac.cyr | SELinux/AppArmor detection and context management |
| audit | src/audit.cyr | Kernel audit netlink socket, rule management |
| pam | src/pam.cyr | PAM service inspection, passwd/who parsing |
| journald | src/journald.cyr | Systemd journal send/query |
| luks | src/luks.cyr | LUKS2 encrypted volume management |
| dmverity | src/dmverity.cyr | dm-verity integrity verification |
| ima | src/ima.cyr | IMA measurements, policy rules |
| tpm | src/tpm.cyr | TPM2 device, PCR reading, seal/unseal |
| certpin | src/certpin.cyr | Certificate pin validation, SPKI computation |
| secureboot | src/secureboot.cyr | Secure Boot EFI variable reading |
| udev | src/udev.cyr | Device enumeration via udevadm |
| drm | src/drm.cyr | DRM device enumeration, ioctl version/caps |
| netns | src/netns.cyr | Network namespace create/destroy, veth, nftables |
| bootloader | src/bootloader.cyr | systemd-boot/GRUB detection, cmdline validation |
| update | src/update.cyr | Atomic file ops, version comparison |
| fuse | src/fuse.cyr | FUSE mount parsing, mount/unmount |

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

## DO NOT

- **Do not commit or push** — the user handles all git operations (commit, push, tag)
- **NEVER use `gh` CLI** — use `curl` to GitHub API only
- Do not add unnecessary library dependencies — this is a kernel interface, keep it lean
- Do not skip benchmarks before claiming performance improvements
- Do not commit `build/` directory
- Do not use reserved keywords as variable names (`match`, `default`, `shared`, `in`)
- Do not define functions with 7+ parameters — split into create + set pattern

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, LICENSE

docs/ (required):
  architecture/overview.md — module map, data flow, consumers
  development/roadmap.md — completed, backlog, future, v1.0 criteria

docs/ (when earned):
  adr/ — architectural decision records
  guides/ — usage guides, integration patterns
  examples/ — worked examples
  standards/ — external spec conformance
  sources.md — source citations for algorithms/formulas
```
