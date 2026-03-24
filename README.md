# Agnosys

> **Agnosys** (agnos + sys — toward knowledge of the system) — AGNOS kernel interface

Safe Rust bindings for Linux kernel syscalls and security primitives. Feature-gated so consumers pull only the kernel interfaces they need. The foundation layer that every AGNOS crate depends on.

## Architecture

```
Consumer crates:
  yukti      ──→ agnosys[udev]          (device hotplug)
  kavach     ──→ agnosys[landlock,seccomp] (sandboxing)
  nein       ──→ agnosys[netns]         (network namespaces)
  stiva      ──→ agnosys[luks,dmverity] (container images)
  sigil      ──→ agnosys[tpm,ima]       (trust verification)
  soorat     ──→ agnosys[drm]           (GPU rendering)
  libro      ──→ agnosys[audit]         (kernel audit)
  argonaut   ──→ agnosys[journald,bootloader] (init system)
  shakti     ──→ agnosys[pam]           (privilege escalation)
  aegis      ──→ agnosys[mac]           (mandatory access control)
  ark        ──→ agnosys[fuse,update]   (package management)
  daimon     ──→ agnosys[certpin,agent] (agent runtime)
```

## Feature Flags

| Feature | Lines | Consumer | Description |
|---------|-------|----------|-------------|
| `syscall` | ~200 | all | Low-level syscall wrappers |
| `error` | ~70 | all | Unified error type with errno mapping |
| `udev` | ~960 | yukti | Device enumeration, hotplug monitoring |
| `landlock` | ~1400 | kavach | Filesystem access control |
| `seccomp` | ~1400 | kavach, daimon | Syscall filtering |
| `netns` | ~1420 | nein | Network namespace management |
| `luks` | ~1640 | stiva | LUKS encrypted storage |
| `dmverity` | ~1240 | stiva, argonaut | dm-verity integrity |
| `ima` | ~810 | sigil | Integrity Measurement Architecture |
| `tpm` | ~740 | sigil | Trusted Platform Module |
| `certpin` | ~1220 | daimon, hoosh | Certificate pinning |
| `fuse` | ~1030 | ark | Filesystem in Userspace |
| `pam` | ~1050 | shakti | Pluggable Authentication |
| `mac` | ~1120 | aegis | Mandatory Access Control |
| `audit` | ~1740 | libro | Kernel audit subsystem |
| `journald` | ~830 | argonaut | Systemd journal |
| `bootloader` | ~980 | argonaut | Bootloader interface |
| `secureboot` | ~730 | sigil | Secure Boot verification |
| `update` | ~1120 | ark | System update primitives |
| `agent` | ~1370 | daimon | Agent runtime kernel support |
| `drm` | new | soorat | Direct Rendering Manager |

## Quick Start

```rust
// Only pull what you need
// Cargo.toml: agnosys = { version = "0.1", features = ["udev", "landlock"] }

use agnosys::error::SysError;

// Device enumeration (feature: udev)
#[cfg(feature = "udev")]
use agnosys::udev;

// Filesystem sandboxing (feature: landlock)
#[cfg(feature = "landlock")]
use agnosys::landlock;
```

## Building

```sh
cargo build                    # default features only (syscall, error)
cargo build --all-features     # everything
cargo test --all-features
```

## Roadmap

See [docs/development/roadmap.md](docs/development/roadmap.md).

## License

GPL-3.0 — see [LICENSE](LICENSE).
