# Changelog

## [0.1.0] - 2026-03-23

### Added
- error: SysError with errno mapping, #[non_exhaustive], io::Error From impl
- syscall: checked_syscall wrapper, getpid, gettid, getuid, geteuid, is_root, uptime, total_memory, available_memory, hostname
- logging: AGNOSYS_LOG env var for tracing init
- Feature gate infrastructure: 22 feature flags for granular kernel interface selection
- Project scaffold: Cargo.toml, CI, roadmap, benchmarks, integration tests
