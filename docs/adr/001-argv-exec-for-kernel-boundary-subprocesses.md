# ADR-001 — argv-based exec for kernel-boundary subprocess invocation

**Status:** Accepted (1.0.1)
**Context window:** post-1.0 freeze
**Supersedes:** —
**Superseded by:** —

## Context

agnosys wraps several kernel-adjacent userspace tools that have no direct syscall equivalent (or whose syscall surface would multiply our maintenance burden by an order of magnitude): `journalctl`, `cryptsetup`, `veritysetup`, `tpm2-tools`, `kmodsign` / `sign-file`, `evmctl`, `mokutil`, `efivar`, `losetup`, `mkfs.*`, `mount`, `umount`, `nft`, `udevadm`. These are invoked from the `journald`, `luks`, `dmverity`, `tpm`, `secureboot`, `ima`, `netns`, and `udev` modules.

Two implementation patterns were available:

1. **Shell pipeline** — `sys_system("/bin/sh -c '<cmd> <args>'")` — short, ergonomic, but every value interpolated into the command string is a metacharacter expansion site. Any external input flowing into one of these wrappers becomes a command-injection sink.
2. **Direct exec with argv vec** — `exec_capture(argv_vec, buf, buflen)` (in `lib/process.cyr`) — `fork(2)` + `execve(2)` with an explicit `argv` array. The kernel reads `argv[i]` byte-for-byte; there is no shell, no metacharacter expansion, no quoting layer.

The `journald_query` path before 1.0.1 used pattern (1). The 2026-04-26 P(-1) audit (finding F-1, HIGH) demonstrated that any consumer setting `journald_filter_set_grep(filter, user_input)` where `user_input` came from a network or filesystem source could inject arbitrary shell commands.

## Decision

**Every subprocess invocation across all kernel-boundary modules uses the argv-based exec pattern via `lib/process.cyr::exec_capture` (or `exec_vec` for fire-and-forget). Filter values, paths, kernel cmdline tokens, and any other caller-supplied data MUST land in their own `argv[i]` slot. The shell is never on the path.**

Implementation contract:

- A module-private `_<module>_build_argv(input)` helper builds the `vec` of cstring args.
- The helper appends each filter/option as a *separate* `vec_push` call — never concatenates with `" "` and pushes a single composite string.
- Consumers of the public API can pass arbitrarily hostile bytes; the worst case is the underlying tool refusing the input, never command injection.
- `sys_system` is reserved for the (currently empty) set of cases where we genuinely need shell features (pipelines, redirects, env expansion) AND every interpolated value is internally constructed (no caller input). At time of writing, the codebase has zero such call sites, and `scripts/audit.sh` greps for `sys_system` to keep it that way.

## Consequences

**Positive:**
- One construction-site rule prevents shell injection in every kernel-boundary wrapper.
- Each new module that needs to invoke a userspace tool inherits the safety property by following the existing `journald` / `luks` / `dmverity` shape — no per-module reasoning about quoting required.
- `exec_capture` returns bytes-read or a typed `Err`, so caller error handling is identical across modules.
- Fuzz harnesses can target the public setter API and exercise the full input space without worrying that `/bin/sh` will swallow the test case.

**Negative:**
- Slightly more boilerplate per call site vs. a one-line `sys_system` (typically 10–20 LoC for the argv builder).
- Argv arrays must be heap-allocated (`vec`), so there's a small allocation cost per subprocess invocation. Acceptable: subprocess fork itself dominates by orders of magnitude.
- We can't lean on shell features (`|`, `>`, `<<`) — operations that need them must be implemented as multiple `exec_capture` calls with explicit pipe/temp-file management. To date, no agnosys feature has needed this.

**Neutral:**
- This rule extends to test fuzz harnesses. `fuzz/journald_filter.fcyr` exercises shell metacharacters through every filter setter; the assertion is that the values appear verbatim in the resulting argv vec, not that shell escaping works correctly (it doesn't — there is no shell to escape for).

## References

- Audit finding F-1 (HIGH) — `docs/audit/2026-04-26-audit.md`
- CHANGELOG `[1.0.1]` Security section
- `lib/process.cyr::exec_capture` — implementation
- `src/journald.cyr::_journald_build_argv` — canonical example
- Per-module security notes in `docs/SECURITY-NOTES.md`
