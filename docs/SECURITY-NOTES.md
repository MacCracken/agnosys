# Module Security Notes

Per-module security considerations for agnosys. Each module wraps kernel interfaces
with different trust boundaries and privilege requirements.

## error

- **No unsafe code.** Pure Rust error types.
- `Cow<'static, str>` fields prevent accidental heap allocation on hot error paths.
- `from_errno` maps known errnos to typed variants; unknown errnos include the OS error message via `io::Error::from_raw_os_error`, which calls into libc `strerror_r`.

## syscall

- **Unsafe: minimal.** Direct `libc::` FFI calls (getpid, gettid, sysinfo, gethostname).
- `checked_syscall` reads errno **before** tracing to prevent tracing-induced clobbering.
- `hostname()` uses a 256-byte stack buffer — safe, but output is `from_utf8_lossy` (non-UTF8 hostnames are lossily converted).
- `SysInfo` fields are read from a single `sysinfo(2)` snapshot — no TOCTOU between fields.

## landlock

- **Unsafe: syscall wrappers.** Raw `libc::syscall()` for landlock_create_ruleset/add_rule/restrict_self.
- **Privilege: none required** — Landlock works without CAP_SYS_ADMIN (sets PR_SET_NO_NEW_PRIVS automatically).
- **Irreversible:** `restrict_self()` consumes the Ruleset — the restriction is permanent for the calling thread.
- Handled access rights are declared at construction time and sent to the kernel immediately — cannot be widened after creation.
- `allow_path()` opens paths with `O_PATH | O_CLOEXEC` and closes them immediately after adding the rule.

## seccomp

- **Unsafe: BPF loading.** Raw `libc::syscall(SYS_seccomp)` to load BPF filters.
- **Privilege: PR_SET_NO_NEW_PRIVS** — set automatically before filter load.
- **Irreversible:** Once loaded, seccomp filters cannot be removed (only made stricter).
- Architecture validation: BPF program always checks `AUDIT_ARCH_NATIVE` first; mismatched architecture kills the process.
- Rule limit: panics at build time if >254 rules (BPF u8 jump offset limit).
- **Allowlist approach recommended** — default action should be KillProcess or Errno, with explicit Allow rules.

## udev

- **Unsafe: netlink socket.** Raw `libc::socket/bind/recv` for uevent monitoring.
- **No privilege required** for sysfs enumeration.
- **Privilege: may need CAP_NET_ADMIN** for uevent netlink socket in some configurations.
- Device attributes read from sysfs are untrusted strings — consumers should validate.
- Monitor socket is SOCK_NONBLOCK — `try_recv()` never blocks.

## drm

- **Unsafe: ioctl calls.** Raw `libc::ioctl` for DRM_IOCTL_VERSION, GET_CAP, MODE_GETRESOURCES, MODE_GETCONNECTOR.
- **Privilege: requires read access to /dev/dri/card*.** Usually `video` group.
- **Buffer safety:** Kernel-reported sizes capped at `MAX_VERSION_STRING` (4096) and `MAX_RESOURCE_COUNT` (1024) to prevent malicious/buggy kernel responses from causing OOM.
- Two-pass ioctl pattern (get sizes, then get data) matches standard DRM API usage.

## netns

- **Unsafe: setns/unshare.** Raw `libc::setns()` and `libc::unshare()`.
- **Privilege: CAP_SYS_ADMIN** required for `enter()` and `unshare_net()`.
- **Irreversible (unshare):** `unshare_net()` creates a new namespace for the calling thread. Old namespace is lost unless saved via `current()` first.
- Namespace fd is opened with `O_RDONLY | O_CLOEXEC`.
- `current_ns_id()` parses `/proc/self/ns/net` symlink — TOCTOU-safe (reads inode from link target).

## certpin

- **No unsafe code.** Pure Rust SHA-256 + base64 + DER parsing.
- **Zero external crypto dependencies** — built-in SHA-256 implementation.
- SHA-256 is verified against NIST test vectors (empty, "hello", "abc").
- DER/SPKI extraction is best-effort — complex certificates may fail silently (returns false from `validate_der`).
- `PinSet` uses linear scan — O(n) per validation. Fine for typical pin sets (1-10 pins).

## agent

- **Unsafe: prctl, env vars.** `prctl(PR_SET_NAME)`, `prctl(PR_CAPBSET_READ)`, env var access.
- **Privilege: CAP_SYS_RESOURCE** needed for negative OOM score adjustments.
- Process name truncated to 15 bytes (kernel limit).
- OOM score validated to [-1000, 1000] range before writing to `/proc/self/oom_score_adj`.
- Watchdog notify uses SOCK_DGRAM to `$NOTIFY_SOCKET` — abstract socket support included.

## luks

- **No unsafe code.** Pure sysfs/procfs reads.
- LUKS header parsing is read-only — no key material is handled.
- Key slot status is inferred from the magic value `0x00AC71F3` (LUKS_KEY_ENABLED).
- **No dm-crypt setup** — this module only inspects headers and queries dm status. Actual volume open/close requires privileged dm-ioctl operations not yet implemented.

## dmverity

- **No unsafe code.** Pure file reads.
- `validate_root_hash()` uses **constant-time comparison** to prevent timing side-channels.
- Superblock salt_size capped at 256 bytes to prevent malicious superblock OOM.
- Verity status read from `/sys/block/dm-*/dm/target_type` — requires read access to sysfs.

## audit

- **Unsafe: netlink socket + ptr::read_unaligned.** Raw netlink AUDIT protocol.
- **Privilege: CAP_AUDIT_READ or CAP_AUDIT_CONTROL** for socket operations.
- `AuditStatus` is read via `ptr::read_unaligned` (response buffer may not be aligned).
- Netlink header serialized via manual `to_ne_bytes()` — no transmute.
- `parse_audit_line()` handles quoted values but does NOT decode hex-encoded fields (documented).

## pam

- **No unsafe code.** Pure file reads of /etc/pam.d/.
- PAM stack parsing is read-only — no authentication operations.
- `@include` directives are skipped (not resolved).
- Dash-prefixed entries (optional modules) are parsed correctly.

## mac

- **Unsafe: getxattr.** `libc::getxattr` for reading security labels from files.
- LSM detection reads `/sys/kernel/security/lsm` — requires securityfs mounted.
- Security context reads from `/proc/self/attr/current` may contain null bytes — trimmed.
- `file_context()` tries SELinux xattr first, then AppArmor.

## ima

- **No unsafe code.** Pure sysfs reads.
- IMA measurement list may be large — `read_all_measurements()` loads entire file into memory.
- IMA policy reading requires appropriate privileges (typically root).

## fuse

- **Unsafe: open/read/write on /dev/fuse.** Raw fd operations.
- **Privilege: access to /dev/fuse** (usually `fuse` group).
- `read_request()` uses `ptr::read_unaligned` for FuseInHeader.
- Request body is a raw byte buffer — consumers must parse per-opcode.
- `write_reply()` combines header + data into a single write (kernel requires atomic writes).
- ENODEV from read indicates clean unmount.

## update

- **Unsafe: libc::fsync, libc::access, libc::syscall(SYS_renameat2).** Low-level fs operations.
- `atomic_write()` guarantees: temp file → fsync → rename → dir sync. Crash-safe.
- `atomic_swap()` uses `renameat2(RENAME_EXCHANGE)` when available, falls back to three-way rename (not atomic but best-effort).
- `same_filesystem()` compares device IDs — rename across filesystems will fail.
- Temp files use PID suffix for uniqueness.

## tpm

- **No unsafe code.** Pure sysfs reads.
- TPM device info read from sysfs attributes — no TPM commands issued.
- PCR values read from legacy `/sys/class/tpm/tpm0/pcr` interface (may not be available on modern systems).
- Event log path points to `/sys/kernel/security/tpm0/binary_bios_measurements`.

## secureboot

- **No unsafe code.** Pure EFI variable reads from sysfs.
- EFI variable format: 4-byte attributes header + data payload.
- Boolean variables (SecureBoot, SetupMode) check byte at offset 4.
- `list_efi_vars()` reads `/sys/firmware/efi/efivars/` — may be slow on systems with many variables.
- Key database sizes can be large (db/dbx may be several KB).

## journald

- **Unsafe: socket/sendto.** Raw Unix datagram socket to journal.
- Journal protocol: `KEY=VALUE\n` for single-line, binary length prefix for multi-line.
- Socket path hardcoded to `/run/systemd/journal/socket`.
- No authentication — any process can write to the journal socket.

## bootloader

- **No unsafe code.** Pure file reads.
- Boot entry parsing reads `/boot/loader/entries/*.conf` — requires read access to /boot.
- EFI LoaderInfo variable decoded as UTF-16LE.
- GRUB detection checks `/boot/grub/grub.cfg` and `/boot/grub2/grub.cfg`.

## logging

- **No unsafe code.** Wraps tracing-subscriber.
- `try_init()` is idempotent — safe to call multiple times.
- `AGNOSYS_LOG` env var controls filter level.
