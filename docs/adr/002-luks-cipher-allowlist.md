# ADR-002 — LUKS cipher allowlist with case-insensitive null-substring rejection

**Status:** Accepted (1.0.1)
**Context window:** post-1.0 freeze
**Supersedes:** —
**Superseded by:** —

## Context

`luks_format` and `luks_open` accept a `LuksConfig` struct with caller-supplied `cipher_algo` and `cipher_mode` strings. Pre-1.0.1, `luks_config_validate` checked the strings were non-null and non-empty but did not constrain their *content*. The two strings were then concatenated to produce the `--cipher` argument passed to `cryptsetup luksFormat`.

Two attack vectors were demonstrated by Trail of Bits in October 2025 against confidential-VM LUKS deployments:

1. **`cipher_null-ecb`** — cryptsetup will pass through a "null" cipher unmodified. Encrypted volumes mount and decrypt to plaintext. Confidential-VM threat models that assume disk encryption-at-rest are silently broken.
2. **Case-and-format variants** — `Cipher_Null`, `CIPHER_NULL`, `cipher-null-ecb`, `null-ecb`, etc. — exercise different paths through cryptsetup's parser. A naïve substring check on a single canonical form misses these.

The audit (finding F-2, MEDIUM) flagged that any consumer that sources cipher selection from external configuration (config files, env vars, CLI flags) is vulnerable.

## Decision

**`luks_validate_cipher(algo, mode)` is the single gate, called from `luks_config_validate`. It enforces three rules in order:**

1. **Non-null, non-empty** — `algo` and `mode` must be non-zero pointers and `strlen > 0`.
2. **Case-insensitive `null` substring rejection** — `_luks_contains_null_ci(s)` scans for `n`/`N` followed by `u`/`U` followed by `l`/`L` followed by `l`/`L` anywhere in the string. Catches `cipher_null`, `Cipher_Null`, `CIPHER_NULL`, `null-ecb`, `aes-NULL`, `aes-Null-cbc`, etc.
3. **Allowlist match** — algo must be one of `aes`, `serpent`, `twofish`, `camellia`. Mode must be one of `xts-plain64`, `cbc-plain64`, `xts-essiv:sha256`, `cbc-essiv:sha256`. Anything else is rejected.

Both `luks_format` and `luks_open` go through `luks_config_validate` before any subprocess invocation, so the gate cannot be bypassed by jumping straight to a different entry point.

## Why an allowlist (not a denylist)

Denylists fail open. The cipher landscape changes — cryptsetup added 12 new combinations between 2.5 and 2.7 — and any cipher we forgot to deny becomes an attack surface. An allowlist fails closed: a new cipher is rejected until we've explicitly evaluated it and added it. The cost is a one-line PR per addition, paid by the agnosys maintainers, not by every downstream consumer who would otherwise eat the bug.

## Why a substring check on top of the allowlist

The allowlist already excludes any algo containing `null`. The redundant substring check exists because:

- It produces a clearer error message — `"LUKS cipher algo contains forbidden token \"null\""` vs. the generic `"not on allowlist"`. Operators searching logs for cipher_null incidents find the explicit token.
- It's defense-in-depth against future allowlist drift — if someone ever adds a cipher whose name contains "null" (unlikely but not impossible: `aes-256-null-padding`-style names exist in some cipher catalogues), the substring check still rejects it until the allowlist guard is explicitly relaxed.

## Consequences

**Positive:**
- A single function call gates every confidential-VM-relevant code path.
- Fuzz harness (`fuzz/luks_cipher.fcyr`) exercises positive cases, all known null-attack variants, and arbitrary off-list inputs at 500 iterations / 10 s in CI.
- Deterministic regression test in `tests/tcyr/test_integration.tcyr::test_audit_regressions` pins seven specific cases (added 1.0.2): three null-substring variants, two off-list rejections, two allowed combinations.

**Negative:**
- Adding a new cipher requires editing two places (`_luks_algo_allowed` and / or `_luks_mode_allowed`, and the documentation). Forgetting either fails the test suite, which is the point.
- The four-algo × four-mode allowlist excludes some legitimate-but-rare combinations (`adiantum`, `ChaCha20-Poly1305` for LUKS2). Consumers needing them must contribute the allowlist update with rationale; agnosys does not silently accept arbitrary input.

## References

- Audit finding F-2 (MEDIUM) — `docs/audit/2026-04-26-audit.md`
- CHANGELOG `[1.0.1]` Security section
- Trail of Bits — *Faulty defaults and weak cryptography in confidential VMs* (Oct 2025)
- `src/luks.cyr::luks_validate_cipher`
- `src/luks.cyr::_luks_contains_null_ci`
- `fuzz/luks_cipher.fcyr`
- `tests/tcyr/test_integration.tcyr::test_audit_regressions` (F-2 assertions)
