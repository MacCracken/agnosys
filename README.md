# Agnosys

> **Agnosys** (agnos + sys — toward knowledge of the system) — AGNOS kernel interface

Safe Rust bindings for Linux kernel syscalls and security primitives. Feature-gated so consumers pull only the kernel interfaces they need. The foundation layer that every AGNOS crate depends on.

## Architecture

```
Consumer crates:
  yukti      ──→ agnosys[udev]              (device hotplug)        ✅
  kavach     ──→ agnosys[landlock,seccomp]   (sandboxing)           ✅
  nein       ──→ agnosys[netns]             (network namespaces)    ✅
  stiva      ──→ agnosys[luks,dmverity]     (encrypted storage)     ✅
  sigil      ──→ agnosys[tpm,ima,certpin]   (trust verification)    🔶
  soorat     ──→ agnosys[drm]              (GPU rendering)          ✅
  libro      ──→ agnosys[audit]            (kernel audit)           ✅
  argonaut   ──→ agnosys[journald,bootloader] (init system)         ⬜
  shakti     ──→ agnosys[pam]              (authentication)         ✅
  aegis      ──→ agnosys[mac]             (mandatory access control) ✅
  ark        ──→ agnosys[fuse,update]      (package management)     ⬜
  daimon     ──→ agnosys[certpin,agent]    (agent runtime)          ✅
```

## Feature Flags

| Feature | Consumer | Description | Status |
|---------|----------|-------------|--------|
| `syscall` | all | Low-level syscall wrappers, SysInfo | ✅ |
| `error` | all | Unified error type with errno mapping, Cow fields | ✅ |
| `logging` | all | AGNOSYS_LOG env var tracing init | ✅ |
| `udev` | yukti | Device enumeration, hotplug monitoring | ✅ |
| `landlock` | kavach | Filesystem/network sandboxing (ABI v1-v5) | ✅ |
| `seccomp` | kavach, daimon | BPF syscall filtering | ✅ |
| `netns` | nein | Network namespace management | ✅ |
| `luks` | stiva | LUKS header parsing, dm-crypt volumes | ✅ |
| `dmverity` | stiva | dm-verity integrity verification | ✅ |
| `ima` | sigil | Integrity Measurement Architecture | ✅ |
| `certpin` | daimon, hoosh | Certificate pinning (zero-dep SHA-256) | ✅ |
| `pam` | shakti | PAM service inspection | ✅ |
| `mac` | aegis | LSM detection, security contexts | ✅ |
| `audit` | libro | Kernel audit netlink interface | ✅ |
| `agent` | daimon | Agent runtime kernel support | ✅ |
| `drm` | soorat | Direct Rendering Manager / KMS | ✅ |
| `tpm` | sigil | Trusted Platform Module | ⬜ |
| `secureboot` | sigil | Secure Boot verification | ⬜ |
| `journald` | argonaut | Systemd journal | ⬜ |
| `bootloader` | argonaut | Bootloader interface | ⬜ |
| `fuse` | ark | Filesystem in Userspace | ⬜ |
| `update` | ark | System update primitives | ⬜ |
| `serde` | optional | Serde derive support | ✅ |

## Quick Start

```rust
// Only pull what you need
// Cargo.toml: agnosys = { version = "0.23", features = ["udev", "landlock"] }

use agnosys::error::SysError;

// Device enumeration
#[cfg(feature = "udev")]
let devices = agnosys::udev::enumerate("net").unwrap();

// Filesystem sandboxing
#[cfg(feature = "landlock")]
let ruleset = agnosys::landlock::Ruleset::new(
    agnosys::landlock::FsAccess::READ_FILE | agnosys::landlock::FsAccess::EXECUTE,
).unwrap();
```

## Building

```sh
cargo build                    # default features only (syscall, error)
cargo build --all-features     # everything
cargo test --all-features      # 458 tests
cargo bench --all-features     # 100 benchmarks
make check                     # fmt + clippy + test + audit
```

## Roadmap

See [docs/development/roadmap.md](docs/development/roadmap.md).

**Progress:** 14/22 modules implemented, 10/12 consumers unblocked, 458 tests, 100 benchmarks.

## License

GPL-3.0-only — see [LICENSE](LICENSE).
