# Security Policy

## Scope

Agnosys is a kernel interface library providing Cyrius bindings for Linux syscalls and security primitives (Landlock, seccomp, TPM, LUKS, dm-verity, IMA, Secure Boot, PAM, audit, netns, ...). Every public function either wraps a syscall, parses a kernel-reported structure, or validates a security-sensitive input.

## Attack Surface

| Area | Risk | Mitigation |
|------|------|------------|
| Syscall wrappers | Incorrect errno handling, TOCTOU | Return-value checked; errno mapped via `err_from_errno` / `err_from_syscall_ret` |
| Landlock | Policy bypass via bad rule construction | `security_fs_rule_*` builders validate flags; `security_apply_landlock` opens with `O_PATH \| O_CLOEXEC` |
| Seccomp | Filter bypass, incomplete deny | Unrolled 23-instruction allowlist; AUDIT_ARCH check first; `PR_SET_NO_NEW_PRIVS` set before load |
| LUKS / dm-verity | Key material exposure | Caller-provided buffers for keys; no secrets in log output |
| TPM | PCR misread, attestation forgery | Validated response parsing; no raw passthrough |
| Certificate pinning | Pin bypass, stale pins | `certpin_check_pin_expiry`; `certpin_ct_streq` constant-time compare |
| PAM | Authentication bypass | Thin wrappers over `pam_*`; no shortcut APIs |
| Namespace ops | Privilege escalation via ns_enter | Capability expectations documented per fn |
| Audit netlink | Kernel message forgery | Message length validation in `audit_nlmsg_len`; pid stamp set from `sys_getpid` |
| Kernel cmdline | Dangerous-token injection via `bootloader_validate_kernel_cmdline` | Allow/deny token list; `init=`, `rd.break`, `single`, etc. rejected |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.98.x | Yes |
| < 0.98 | No |

Once 1.0 ships, 1.x is the supported line. Earlier 0.x releases are snapshot-only.

## Reporting a Vulnerability

Please report security issues to **security@agnos.dev**.

- Acknowledgement within 48 hours
- 90-day coordinated disclosure
- Do not open public issues for vulnerabilities

## Design Principles

- **Kernel at the boundary.** Every module wraps a specific kernel interface; no policy decisions hide in agnosys — those live in consumers (kavach for sandbox policy, nein for firewall rules, sigil for trust chain, ...).
- **Caller-owned memory.** Hot-path syscall wrappers take pre-allocated buffers; no surprise heap allocations.
- **Packed errors on hot paths** (`syserr_pack`, zero allocation), heap errors on cold paths (`syserr_new`, carries a diagnostic string).
- **Constant-time comparisons** for security-sensitive matches (`certpin_ct_streq` for pins; dm-verity root hash via byte memcmp kept off the log path).
- **Kernel-reported sizes capped** to prevent OOM (DRM, LUKS, dm-verity).
- **No secret material in log output.** `src/logging.cyr` filters do not cover structured fields automatically — callers must not pass keys/tokens to log arguments.
- **Parsers reject before dereference.** Every public parser (`audit_rule_validate`, `pam_parse_passwd_line`, `bootloader_parse_loader_conf`, ...) checks field count and length bounds before indexing.
- **Module-prefixed functions** so the global namespace cannot collide as consumers mix modules.
- **Fuzz harnesses in `fuzz/`** stress certpin, audit netlink, and PAM parsers with malformed inputs at every CI run.

## Per-Module Security Notes

See [docs/SECURITY-NOTES.md](docs/SECURITY-NOTES.md) for detailed per-module considerations (privileges required, irreversible operations, TOCTOU hazards, sharp edges).
