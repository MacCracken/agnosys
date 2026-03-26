//! Agnosys — AGNOS kernel interface
//!
//! Safe Rust bindings for Linux kernel syscalls and security primitives.
//! Feature-gated so consumers pull only the kernel interfaces they need.
//!
//! Extracted from the AGNOS monolith (`userland/agnos-sys/`).

pub mod error;

#[cfg(feature = "syscall")]
pub mod syscall;

#[cfg(feature = "security")]
pub mod security;

#[cfg(feature = "udev")]
pub mod udev;

#[cfg(feature = "netns")]
pub mod netns;

#[cfg(feature = "luks")]
pub mod luks;

#[cfg(feature = "dmverity")]
pub mod dmverity;

#[cfg(feature = "ima")]
pub mod ima;

#[cfg(feature = "tpm")]
pub mod tpm;

#[cfg(feature = "certpin")]
pub mod certpin;

#[cfg(feature = "fuse")]
pub mod fuse;

#[cfg(feature = "pam")]
pub mod pam;

#[cfg(feature = "mac")]
pub mod mac;

#[cfg(feature = "audit")]
pub mod audit;

#[cfg(feature = "journald")]
pub mod journald;

#[cfg(feature = "bootloader")]
pub mod bootloader;

#[cfg(feature = "secureboot")]
pub mod secureboot;

#[cfg(feature = "update")]
pub mod update;

#[cfg(feature = "drm")]
pub mod drm;

#[cfg(feature = "logging")]
pub mod logging;

pub use error::{Result, SysError};
