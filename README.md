# Agnosys

> **Agnosys** (agnos + sys — toward knowledge of the system) — AGNOS kernel interface

Cyrius bindings for Linux kernel syscalls and security primitives. Consumers include only the modules they need. The foundation layer that every AGNOS program depends on.

Ported from 29,257 lines of Rust to 8,460 lines of Cyrius. 117KB binary. Compiles in 8ms.

## Architecture

```
Consumer programs:
  yukti      ──→ agnosys[udev]              (device hotplug)        ✅
  kavach     ──→ agnosys[security]           (sandboxing)           ✅
  nein       ──→ agnosys[netns]             (network namespaces)    ✅
  stiva      ──→ agnosys[luks,dmverity]     (encrypted storage)     ✅
  sigil      ──→ agnosys[tpm,ima,certpin]   (trust verification)    ✅
  soorat     ──→ agnosys[drm]              (GPU rendering)          ✅
  libro      ──→ agnosys[audit]            (kernel audit)           ✅
  argonaut   ──→ agnosys[journald,bootloader] (init system)         ✅
  shakti     ──→ agnosys[pam]              (authentication)         ✅
  aegis      ──→ agnosys[mac]             (mandatory access control) ✅
  ark        ──→ agnosys[fuse,update]      (package management)     ✅
  daimon     ──→ agnosys[security,certpin]  (daemon runtime)        ✅
```

## Modules (20)

| Module | Description |
|--------|-------------|
| error | Unified error type with errno mapping, packed + heap dual encoding |
| syscall | getpid, getuid, hostname, sysinfo wrappers |
| logging | AGNOSYS_LOG env var log level control |
| security | Landlock filesystem sandboxing, seccomp BPF, namespace creation |
| mac | SELinux/AppArmor detection and context management |
| audit | Kernel audit subsystem via netlink |
| pam | PAM service inspection, passwd/who parsing |
| journald | Systemd journal structured log send/query |
| luks | LUKS2 encrypted volume management via cryptsetup |
| dmverity | dm-verity integrity verification |
| ima | IMA measurements, policy rules, file integrity |
| tpm | TPM2 device detection, PCR reading, seal/unseal |
| certpin | Certificate pin validation, SPKI computation |
| secureboot | Secure Boot EFI variable reading |
| udev | Device enumeration via udevadm |
| drm | DRM/KMS device enumeration, ioctl caps |
| netns | Network namespace create/destroy, veth, nftables |
| bootloader | systemd-boot/GRUB detection, cmdline validation |
| update | Atomic file operations, version comparison |
| fuse | FUSE mount parsing, mount/unmount |

## Build

```sh
cyrb build src/main.cyr build/agnosys    # compile
cyrb run src/main.cyr                     # compile + run
cyrb check src/main.cyr                   # syntax check only
```

## Usage

Programs include only the modules they need:

```cyrius
include "lib/alloc.cyr"
include "lib/tagged.cyr"
include "lib/syscalls.cyr"
include "src/error.cyr"
include "src/syscall.cyr"
include "src/security.cyr"

fn main() {
    alloc_init();
    # ... use agnosys functions ...
    return 0;
}
```

## License

GPL-3.0-only
