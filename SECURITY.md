# Security Policy

## Scope

Agnosys is a kernel interface crate providing safe Rust bindings for Linux syscalls and security primitives (Landlock, seccomp, TPM, LUKS, dm-verity, IMA, etc.). The library wraps `unsafe` syscall interfaces in safe Rust APIs.

## Attack Surface

| Area | Risk | Mitigation |
|------|------|------------|
| Syscall wrappers | Incorrect errno handling, TOCTOU races | Return-value checked; errno mapped to typed errors |
| Landlock | Policy bypass via incorrect rule construction | Type-safe rule builder; validates flags before syscall |
| Seccomp | Filter bypass, incomplete deny lists | BPF filter validation; allowlist-preferred API |
| LUKS / dm-verity | Key material exposure in memory | Zeroize key buffers on drop; no logging of secrets |
| TPM | PCR misread, attestation forgery | Validated response parsing; no raw TPM pass-through |
| Certificate pinning | Pin bypass, stale pin sets | Expiry-aware pin validation |
| PAM | Authentication bypass | Direct pam_* call wrappers; no shortcut APIs |
| Namespace ops | Privilege escalation via ns_enter | Capability checks before namespace operations |
| `unsafe` code | Memory safety violations | Minimal unsafe surface; each block documented |
| Dependencies | Supply chain compromise | cargo-deny, cargo-audit in CI; minimal deps |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x | Yes |

## Reporting a Vulnerability

Please report security issues to **security@agnos.dev**.

- You will receive acknowledgement within 48 hours
- We follow a 90-day coordinated disclosure timeline
- Please do not open public issues for security vulnerabilities

## Design Principles

- Minimal `unsafe` — only at the syscall boundary
- All public types are `Send + Sync` where applicable
- No secret material in log output (tracing spans redact sensitive fields)
- Minimal dependency surface (core depends only on libc, serde, thiserror, tracing)
- Feature-gated modules — consumers compile only what they use
- `#[non_exhaustive]` on all public enums to allow safe evolution
- Constant-time comparisons for security-sensitive operations (dm-verity root hash)
- Kernel-reported sizes capped to prevent OOM (DRM, LUKS, dm-verity)

## Per-Module Security Notes

See [docs/SECURITY-NOTES.md](docs/SECURITY-NOTES.md) for detailed security considerations per module.
