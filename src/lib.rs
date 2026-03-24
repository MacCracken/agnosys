//! Agnosys — AGNOS kernel interface
//!
//! Safe Rust bindings for Linux kernel syscalls and security primitives.
//! Feature-gated so consumers pull only the kernel interfaces they need.
//!
//! # Modules
//!
//! - [`error`] — Unified error type with errno mapping
//! - [`syscall`] — Low-level syscall wrappers
//! - [`udev`] — Device enumeration, hotplug monitoring (consumed by yukti)
//! - [`landlock`] — Filesystem sandboxing (consumed by kavach)
//! - [`seccomp`] — Syscall filtering (consumed by kavach, daimon)
//! - [`netns`] — Network namespaces (consumed by nein)
//! - [`luks`] — Encrypted storage (consumed by stiva)
//! - [`dmverity`] — Verified boot / integrity (consumed by stiva, argonaut)
//! - [`ima`] — Integrity Measurement Architecture (consumed by sigil)
//! - [`tpm`] — Trusted Platform Module (consumed by sigil)
//! - [`certpin`] — Certificate pinning (consumed by daimon, hoosh)
//! - [`fuse`] — Filesystem in Userspace (consumed by ark)
//! - [`pam`] — Pluggable Authentication Modules (consumed by shakti)
//! - [`mac`] — Mandatory Access Control (consumed by aegis)
//! - [`audit`] — Kernel audit subsystem (consumed by libro)
//! - [`journald`] — Systemd journal (consumed by argonaut)
//! - [`bootloader`] — Bootloader interface (consumed by argonaut)
//! - [`secureboot`] — Secure Boot verification (consumed by sigil)
//! - [`update`] — System update primitives (consumed by ark)
//! - [`agent`] — Agent runtime kernel support (consumed by daimon)
//! - [`drm`] — Direct Rendering Manager (consumed by soorat)

#[cfg(feature = "error")]
pub mod error;

#[cfg(feature = "syscall")]
pub mod syscall;

#[cfg(feature = "udev")]
pub mod udev;

#[cfg(feature = "landlock")]
pub mod landlock;

#[cfg(feature = "netns")]
pub mod netns;
#[cfg(feature = "seccomp")]
pub mod seccomp;
// #[cfg(feature = "luks")] pub mod luks;
// #[cfg(feature = "dmverity")] pub mod dmverity;
// #[cfg(feature = "ima")] pub mod ima;
// #[cfg(feature = "tpm")] pub mod tpm;
#[cfg(feature = "certpin")]
pub mod certpin;
// #[cfg(feature = "fuse")] pub mod fuse;
// #[cfg(feature = "pam")] pub mod pam;
// #[cfg(feature = "mac")] pub mod mac;
// #[cfg(feature = "audit")] pub mod audit;
// #[cfg(feature = "journald")] pub mod journald;
// #[cfg(feature = "bootloader")] pub mod bootloader;
// #[cfg(feature = "secureboot")] pub mod secureboot;
// #[cfg(feature = "update")] pub mod update;
#[cfg(feature = "agent")]
pub mod agent;
#[cfg(feature = "drm")]
pub mod drm;

#[cfg(feature = "logging")]
pub mod logging;
