# Changelog

## [0.5.0] - 2026-03-26

### Changed
- **SemVer migration**: Moved from CalVer (0.25.x) to SemVer, targeting 1.0.0
- **agent/llm modules removed**: Extracted to dedicated crates (`agnosai` for agents, `hoosh` for LLM inference). Removes reqwest, tokio, async-trait, anyhow, once_cell from dep tree.
- `#[non_exhaustive]` on all 28 public enums (was only 3)
- `#[must_use]` on ~50 pure/query functions across all modules
- deny.toml trimmed: removed 7 stale license entries from removed deps
- Consumer map updated: daimon uses seccomp+certpin (agent moved to agnosai)

### Fixed
- update.rs: swapped day/month labels in `validate_version()` error messages
- Feature gate completeness: 8 features (tpm, certpin, fuse, pam, mac, journald, bootloader, update) were missing standalone deps — all now compile individually
- ima feature missing `dep:hex` and `serde` dependencies

### Performance
- ima.rs: `write!()` over `format!()` in policy building, `static` array for valid masks
- certpin.rs: iterator chain instead of clone+extend in pin verification
- secureboot.rs: `Option<&str>` instead of String in parse loop, Vec pre-allocation
- Vec::with_capacity() across 13 sites in 5 modules (bootloader, journald, audit, udev, pam)

## [0.23.3] - 2026-03-24

### Added
- landlock: Filesystem sandboxing via Landlock LSM (ABI v1-v4) — ruleset builder, path rules, net port rules
- seccomp: Syscall filtering via seccomp-BPF — filter builder, allowlist/denylist policies, architecture validation
- drm: Direct Rendering Manager — device enumeration, driver version, capabilities, KMS resources, connector queries
- netns: Network namespaces — create, enter, list, current ns fd/inode
- certpin: Certificate pinning — SHA-256 pin computation (zero-dep), base64, SPKI extraction, PinSet validation
- agent: Agent runtime support — process naming, OOM score, cgroup inspection, capability check, systemd watchdog *(moved to agnosai crate)*
- luks: LUKS encrypted storage — header parsing, key slot inspection, dm-crypt volume management
- dmverity: dm-verity integrity — superblock parsing, root hash validation (constant-time), volume status
- audit: Kernel audit subsystem — netlink audit socket, status queries, log parsing, audit line parser
- pam: PAM service inspection — list services, parse PAM stacks, read service configs
- mac: Mandatory Access Control — LSM detection, SELinux/AppArmor/Smack queries, security contexts
- ima: Integrity Measurement Architecture — runtime measurements, policy parsing, violation count
- fuse: FUSE protocol — /dev/fuse device, request reading, reply writing, mount listing
- update: Atomic update primitives — atomic_write, atomic_copy, atomic_swap, fsync, directory sync
- tpm: TPM2 interface — device detection, PCR banks/values, capabilities, event log access
- secureboot: Secure Boot — EFI variable reading, SecureBoot/SetupMode state, PK/KEK/db/dbx inspection
- journald: Systemd journal — structured log sending via native socket, journal file listing, disk usage
- bootloader: Bootloader interface — systemd-boot/GRUB detection, boot entry parsing, loader.conf, kernel listing
- SysInfo struct: Single sysinfo(2) call for uptime/memory/procs
- query_sysinfo() convenience function
- Send+Sync compile-time assertions on all public types
- Full project scaffold: CI, release workflow, deny.toml, codecov.yml, bench-history.sh
- Community files: SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md

### Changed
- SysError fields now use Cow<'static, str> (zero-alloc on known errno paths)
- serde dependency is now optional (behind "serde" feature flag)
- syscall feature now correctly depends on error feature
- License identifier updated to GPL-3.0-only (SPDX compliant)
- Example detect_hardware no longer requires unimplemented udev feature

### Fixed
- errno read order in checked_syscall (read before tracing to prevent clobbering)
- --all-features build (commented out unimplemented module declarations)
- cargo fmt / clippy issues in benches and tests

## [0.1.0] - 2026-03-23

### Added
- error: SysError with errno mapping, #[non_exhaustive], io::Error From impl
- syscall: checked_syscall wrapper, getpid, gettid, getuid, geteuid, is_root, uptime, total_memory, available_memory, hostname
- logging: AGNOSYS_LOG env var for tracing init
- Feature gate infrastructure: 22 feature flags for granular kernel interface selection
- Project scaffold: Cargo.toml, CI, roadmap, benchmarks, integration tests
