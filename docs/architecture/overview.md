# Architecture Overview

## Layout

```
agnosys/
├── src/           20 modules + main entry point
│   ├── main.cyr   self-test entry, includes core modules
│   ├── error.cyr  SysError types, errno mapping, Result helpers
│   ├── syscall.cyr  getpid/uid/hostname/sysinfo wrappers
│   ├── logging.cyr  AGNOSYS_LOG env var log level
│   ├── security.cyr  Landlock, seccomp BPF, namespace creation
│   ├── mac.cyr    SELinux/AppArmor detection, contexts
│   ├── audit.cyr  kernel audit netlink socket, rules
│   ├── pam.cyr    PAM service inspection, passwd parsing
│   ├── journald.cyr  systemd journal send/query
│   ├── luks.cyr   LUKS2 encrypted volume management
│   ├── dmverity.cyr  dm-verity integrity verification
│   ├── ima.cyr    IMA measurements, policy rules
│   ├── tpm.cyr    TPM2 device, PCR reading
│   ├── certpin.cyr  certificate pin validation, SPKI
│   ├── secureboot.cyr  Secure Boot EFI variables
│   ├── udev.cyr   device enumeration via udevadm
│   ├── drm.cyr    DRM device enumeration, ioctl
│   ├── netns.cyr  network namespace create/destroy, veth
│   ├── bootloader.cyr  systemd-boot/GRUB detection
│   ├── update.cyr  atomic file ops, version compare
│   └── fuse.cyr   FUSE mount parsing, mount/unmount
├── lib/           vendored Cyrius stdlib (23 files)
│   ├── alloc.cyr  heap allocator (brk syscall)
│   ├── string.cyr  C string operations
│   ├── str.cyr    fat pointer strings (data + length)
│   ├── vec.cyr    dynamic array
│   ├── tagged.cyr  tagged unions (Ok/Err Result type)
│   ├── hashmap.cyr  hash table (string keys, i64 values)
│   ├── fmt.cyr    integer/hex formatting
│   ├── syscalls.cyr  platform-switchable syscall bindings
│   ├── process.cyr  fork/exec/waitpid
│   ├── fs.cyr     directory listing, file operations
│   ├── io.cyr     file I/O wrappers
│   ├── net.cyr    TCP/UDP sockets
│   ├── bench.cyr  benchmark timing utilities
│   └── ...
├── tests/         test and benchmark programs
├── build/         compiled binaries (gitignored)
└── rust-old/      original Rust implementation (reference)
```

## Include Model

Cyrius uses a flat include model. Each `.cyr` file is a module. Programs include
the stdlib files they need from `lib/`, then the `src/` modules they need:

```
include "lib/alloc.cyr"
include "lib/syscalls.cyr"
include "src/error.cyr"
include "src/syscall.cyr"
```

Cyrius 1.8.0+ provides **include-once semantics** — a file included multiple
times is only processed once. Each `src/` module includes its own dependencies,
so modules can be checked independently with `cyrb check`.

## Data Flow

```
                   ┌─────────────────────────────────────────┐
                   │              Consumer Programs          │
                   │  (kavach, nein, sigil, yukti, etc.)      │
                   └──────────────┬──────────────────────────┘
                                  │ include "src/module.cyr"
                   ┌──────────────▼──────────────────────────┐
                   │           src/ modules (20)              │
                   │  error → syscall → security, mac, ...   │
                   └──────────────┬──────────────────────────┘
                                  │ include "lib/*.cyr"
                   ┌──────────────▼──────────────────────────┐
                   │         lib/ stdlib (vendored)           │
                   │  alloc, vec, str, tagged, syscalls, ...  │
                   └──────────────┬──────────────────────────┘
                                  │ syscall()
                   ┌──────────────▼──────────────────────────┐
                   │          Linux Kernel (x86_64)           │
                   └─────────────────────────────────────────┘
```

## Module Dependency Graph

Core modules that other modules depend on:
- **error.cyr** — all modules use error types and Result convention
- **lib/tagged.cyr** — Ok/Err tagged unions
- **lib/syscalls.cyr** → **lib/syscalls_linux.cyr** — raw syscall numbers and wrappers

Module clusters by kernel subsystem:

| Cluster | Modules | Kernel Interface |
|---------|---------|-----------------|
| Process | syscall, logging | getpid, sysinfo, uname |
| Security | security, mac, audit, pam | landlock, seccomp, netlink, /etc/pam.d |
| Storage | luks, dmverity, fuse, update | dm-crypt, dm-verity, /dev/fuse, rename |
| Integrity | ima, tpm, certpin, secureboot | /sys/kernel/security/ima, /dev/tpm0, EFI vars |
| Device | udev, drm | sysfs, ioctl |
| Network | netns, journald | setns/unshare, /run/systemd/journal/socket |
| Boot | bootloader | /boot/loader, /boot/grub |

## Error Convention

Two error encodings, chosen by call-site:

- **Packed (hot path)**: `syserr_pack(kind, errno)` — `kind << 16 | errno`, zero-alloc, 6ns
- **Heap (diagnostic)**: `syserr_new(kind, errno, message)` — heap-allocated struct, 20ns

All functions return `Result` via `lib/tagged.cyr`:
```
Ok(value)                              # success
Err(syserr_pack(ERR_PERMISSION_DENIED, EPERM))  # fast error
Err(syserr_new(ERR_IO, errno, "read failed"))    # diagnostic error
```

Propagation pattern:
```
var res = some_function();
if (is_err_result(res) == 1) { return res; }
var value = payload(res);
```

## Memory Model

- **Stack buffers** for syscall wrappers — caller owns the memory
- **Heap via `alloc()`** (brk-based) for dynamic data
- **`alloc_reset()`** for arena-style bulk deallocation in test harnesses
- No garbage collection, no reference counting
- Strings: null-terminated C strings or fat pointers via `lib/str.cyr`

## Consumer Map

| Consumer | Modules | Purpose |
|----------|---------|---------|
| yukti | udev | Device management |
| kavach | security | Sandbox policy engine |
| nein | netns | Network namespace management |
| stiva | luks, dmverity | Encrypted container runtime |
| sigil | tpm, ima, secureboot, certpin | Trust chain verification |
| soorat | drm | Display/rendering |
| libro | audit | Audit log collection |
| argonaut | journald, bootloader | System journal + boot |
| shakti | pam | Authentication |
| aegis | mac | Mandatory access control |
| ark | fuse, update | Filesystem + updates |
| daimon | security, certpin | Agent sandboxing |
| hoosh | certpin | LLM inference pinning |
