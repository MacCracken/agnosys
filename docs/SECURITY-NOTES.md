# Module Security Notes

Per-module security considerations for agnosys. Each module wraps kernel interfaces
with different trust boundaries and privilege requirements.

## error

- Pure integer error types. No heap allocation on packed error path.
- `syserr_pack(kind, errno)` encodes `kind << 16 | errno` — zero-alloc, ~6ns.
- `syserr_new(kind, errno, message)` heap-allocates for diagnostics — cold path only.
- `err_from_syscall_ret()` maps known errnos to typed variants.

## syscall

- Direct `syscall()` for getpid, gettid, getuid, geteuid, sysinfo, uname.
- `checked_syscall(ret)` wraps raw return with Result error handling.
- `query_sysinfo()` uses a caller-provided stack buffer — no heap allocation.
- `SysInfo` fields read from a single `sysinfo(2)` snapshot — no TOCTOU between fields.
- Hostname read into stack buffer; null-terminated.

## security (landlock)

- Raw `syscall()` for landlock_create_ruleset/add_rule/restrict_self.
- **Privilege: none required** — Landlock works without CAP_SYS_ADMIN (sets PR_SET_NO_NEW_PRIVS automatically).
- **Irreversible:** `restrict_self` is permanent for the calling thread.
- Handled access rights declared at construction time.
- `apply_landlock()` opens paths with O_PATH | O_CLOEXEC and closes immediately after adding the rule.

## security (seccomp)

- Raw `syscall()` for seccomp BPF filter loading.
- **Privilege: PR_SET_NO_NEW_PRIVS** — set automatically before filter load.
- **Irreversible:** Once loaded, seccomp filters cannot be removed.
- Architecture validation: BPF program checks AUDIT_ARCH first; mismatch kills process.
- Unrolled BPF instruction writes — fixed 23-instruction filter, 184 bytes.
- **Allowlist approach** — default action is KILL_PROCESS with explicit ALLOW rules.

## udev

- Shells out to `udevadm` for device enumeration.
- Device attributes read from command output are untrusted strings — consumers should validate.

## drm

- Raw `syscall()` ioctl for DRM_IOCTL_VERSION, GET_CAP, MODE_GETRESOURCES.
- **Privilege: read access to /dev/dri/card*.** Usually `video` group.
- Buffer sizes from kernel capped to prevent malicious responses from causing OOM.
- Two-pass ioctl pattern (get sizes, then get data).

## netns

- Raw `syscall()` for setns/unshare.
- **Privilege: CAP_SYS_ADMIN** required for namespace operations.
- **Irreversible (unshare):** creates new namespace for calling thread.
- Per-PID nftables temp file instead of fixed path (avoids races).
- nftables buffer increased to 16KB with bounds checking.

## certpin

- Pure Cyrius SHA-256 + base64 + DER parsing. Zero external crypto dependencies.
- SHA-256 verified against NIST test vectors.
- DER/SPKI extraction is best-effort — complex certificates may fail silently.
- Path validation rejects single quotes/newlines before shell execution.
- Pin validation uses linear scan — O(n), fine for typical 1-10 pin sets.

## luks

- Shells out to `cryptsetup`, `fallocate`, `losetup`, `mkfs.*`, `mount`, `umount`.
- Per-PID keyfile path instead of predictable `/tmp/.agnos-luks-keyfile`.
- Keyfile created with mode 0600.

## dmverity

- Shells out to `veritysetup` for format and verify operations.
- Constant-time root hash comparison to prevent timing side-channels.
- Salt size capped to prevent malicious superblock OOM.

## audit

- Raw netlink AUDIT protocol via `syscall()`.
- **Privilege: CAP_AUDIT_READ or CAP_AUDIT_CONTROL** for socket operations.
- Netlink header serialized via manual byte writes — no struct casting.
- Path traversal check rejects `..` components in file watch rules.
- `parse_audit_line()` handles quoted values but does NOT decode hex-encoded fields.

## pam

- Pure file reads of /etc/pam.d/ and /etc/passwd.
- PAM stack parsing is read-only — no authentication operations.
- `@include` directives are skipped (not resolved).
- Username validation rejects control characters.

## mac

- Reads /sys/kernel/security/lsm for LSM detection — requires securityfs mounted.
- Security context reads from /proc/self/attr/current.
- Stack-allocated string buffers for profile building (2 heap allocs instead of 13).

## ima

- Reads /sys/kernel/security/ima for measurement list and policy.
- Measurement list may be large — loaded into heap buffer.
- IMA policy reading requires root privileges.

## fuse

- Raw fd operations on /dev/fuse.
- **Privilege: access to /dev/fuse** (usually `fuse` group).
- Request body is raw bytes — consumers must parse per-opcode.
- ENODEV from read indicates clean unmount.

## update

- `atomic_write()`: temp file → fsync → rename → dir sync. Crash-safe.
- `atomic_swap()` uses renameat2(RENAME_EXCHANGE) when available, three-way rename fallback.
- Temp files use PID suffix for uniqueness.
- Cross-filesystem rename will fail (checked via device ID comparison).

## tpm

- Shells out to tpm2-tools (tpm2_pcrread, tpm2_unseal, tpm2_getrandom, etc).
- No direct TPM device commands — all via standard tpm2-tools interface.

## secureboot

- Reads EFI variables from /sys/firmware/efi/efivars/.
- EFI variable format: 4-byte attributes header + data payload.
- Boolean variables (SecureBoot, SetupMode) check byte at offset 4.

## journald

- Unix datagram socket to /run/systemd/journal/socket.
- Journal protocol: `KEY=VALUE\n` for single-line, binary length prefix for multi-line.
- Fields with newline characters in keys are skipped (injection prevention).
- No authentication — any process can write to the journal socket.

## bootloader

- Reads /boot/loader/entries/*.conf and /boot/grub/grub.cfg.
- **Privilege: read access to /boot.**
- Kernel cmdline validation uses single-pass tokenizer with hashmap danger lookup.

## logging

- Reads AGNOSYS_LOG env var for log level control.
- Pure configuration — no kernel interface.
