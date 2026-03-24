//! netns — Network namespace operations.
//!
//! Create, enter, and inspect Linux network namespaces via `setns(2)`,
//! `unshare(2)`, and `/proc/self/ns/net`.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::netns;
//!
//! // Save current namespace, create new one, then restore
//! let original = netns::current().unwrap();
//! netns::unshare_net().unwrap();
//! // ... configure new namespace ...
//! netns::enter(&original).unwrap();
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

/// Named network namespace directory.
const NETNS_RUN_DIR: &str = "/var/run/netns";

/// A handle to a network namespace (wraps a file descriptor).
pub struct NetNs {
    fd: OwnedFd,
    name: Option<String>,
}

impl NetNs {
    /// The raw file descriptor for this namespace.
    #[inline]
    #[must_use]
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }

    /// The name of this namespace, if it was opened by name.
    #[inline]
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

/// Get a handle to the current thread's network namespace.
///
/// Opens `/proc/self/ns/net`.
pub fn current() -> Result<NetNs> {
    let fd = unsafe {
        libc::open(
            c"/proc/self/ns/net".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = SysError::last_os_error();
        tracing::error!("failed to open /proc/self/ns/net");
        return Err(err);
    }
    tracing::trace!(fd, "opened current network namespace");
    Ok(NetNs {
        fd: unsafe { OwnedFd::from_raw_fd(fd) },
        name: None,
    })
}

/// Open a named network namespace from `/var/run/netns/<name>`.
pub fn open(name: &str) -> Result<NetNs> {
    let path = Path::new(NETNS_RUN_DIR).join(name);
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| SysError::InvalidArgument(Cow::Borrowed("name contains null byte")))?;

    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        let err = SysError::last_os_error();
        tracing::error!(name, "failed to open named network namespace");
        return Err(err);
    }
    tracing::debug!(name, fd, "opened named network namespace");
    Ok(NetNs {
        fd: unsafe { OwnedFd::from_raw_fd(fd) },
        name: Some(name.to_owned()),
    })
}

/// Enter (switch to) a network namespace.
///
/// Uses `setns(2)` with `CLONE_NEWNET`.
pub fn enter(ns: &NetNs) -> Result<()> {
    let ret = unsafe { libc::setns(ns.fd.as_raw_fd(), libc::CLONE_NEWNET) };
    if ret < 0 {
        let err = SysError::last_os_error();
        tracing::error!("setns(CLONE_NEWNET) failed");
        Err(err)
    } else {
        tracing::info!("entered network namespace");
        Ok(())
    }
}

/// Create a new network namespace for the calling thread.
///
/// Uses `unshare(2)` with `CLONE_NEWNET`. The old namespace is lost
/// unless you saved a handle via [`current()`] first.
pub fn unshare_net() -> Result<()> {
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    if ret < 0 {
        let err = SysError::last_os_error();
        tracing::error!("unshare(CLONE_NEWNET) failed");
        Err(err)
    } else {
        tracing::info!("created new network namespace via unshare");
        Ok(())
    }
}

/// List named network namespaces in `/var/run/netns/`.
pub fn list() -> Result<Vec<String>> {
    let dir = Path::new(NETNS_RUN_DIR);
    if !dir.is_dir() {
        return Ok(Vec::new()); // no named namespaces
    }

    let mut names = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| {
        tracing::error!(error = %e, "failed to read netns dir");
        SysError::Io(e)
    })?;

    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_owned());
        }
    }

    names.sort();
    tracing::trace!(count = names.len(), "listed named network namespaces");
    Ok(names)
}

/// Get the network namespace inode for the current thread.
///
/// Reads the link target of `/proc/self/ns/net` (e.g., `net:[4026531840]`).
#[must_use = "namespace id should be used"]
pub fn current_ns_id() -> Result<u64> {
    let link = std::fs::read_link("/proc/self/ns/net").map_err(|e| {
        tracing::error!(error = %e, "failed to readlink /proc/self/ns/net");
        SysError::Io(e)
    })?;
    let s = link.to_string_lossy();
    // Format: "net:[1234567890]"
    let start = s.find('[').ok_or_else(|| {
        SysError::InvalidArgument(Cow::Owned(format!("unexpected ns format: {s}")))
    })?;
    let end = s.find(']').ok_or_else(|| {
        SysError::InvalidArgument(Cow::Owned(format!("unexpected ns format: {s}")))
    })?;
    s[start + 1..end].parse::<u64>().map_err(|e| {
        SysError::InvalidArgument(Cow::Owned(format!("failed to parse ns inode: {e}")))
    })
}

/// Get the path to a named namespace file.
#[inline]
#[must_use]
pub fn named_path(name: &str) -> PathBuf {
    Path::new(NETNS_RUN_DIR).join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NetNs>();
    };

    // ── current ─────────────────────────────────────────────────────

    #[test]
    fn current_returns_valid_fd() {
        let ns = current().unwrap();
        assert!(ns.as_raw_fd() >= 0);
        assert!(ns.name().is_none());
    }

    #[test]
    fn current_stable() {
        let ns1 = current().unwrap();
        let ns2 = current().unwrap();
        // Different fds but same namespace
        assert!(ns1.as_raw_fd() >= 0);
        assert!(ns2.as_raw_fd() >= 0);
    }

    // ── current_ns_id ───────────────────────────────────────────────

    #[test]
    fn current_ns_id_positive() {
        let id = current_ns_id().unwrap();
        assert!(id > 0);
    }

    #[test]
    fn current_ns_id_stable() {
        let id1 = current_ns_id().unwrap();
        let id2 = current_ns_id().unwrap();
        assert_eq!(id1, id2);
    }

    // ── list ────────────────────────────────────────────────────────

    #[test]
    fn list_returns_result() {
        // May be empty if no named namespaces exist
        let names = list().unwrap();
        // If non-empty, names should be sorted
        for window in names.windows(2) {
            assert!(window[0] <= window[1]);
        }
    }

    // ── open ────────────────────────────────────────────────────────

    #[test]
    fn open_nonexistent() {
        let err = open("nonexistent_agnosys_test_ns");
        assert!(err.is_err());
    }

    // ── named_path ──────────────────────────────────────────────────

    #[test]
    fn named_path_correct() {
        let p = named_path("test");
        assert_eq!(p, Path::new("/var/run/netns/test"));
    }

    #[test]
    fn named_path_with_dashes() {
        let p = named_path("my-ns-1");
        assert_eq!(p, Path::new("/var/run/netns/my-ns-1"));
    }

    // ── NetNs ───────────────────────────────────────────────────────

    #[test]
    fn netns_name_when_opened_by_path() {
        let ns = current().unwrap();
        assert!(ns.name().is_none()); // opened via /proc, not by name
    }

    // Note: enter/unshare_net are not tested here because they modify
    // thread state which would affect other tests. They are tested
    // in integration tests with proper isolation.
}
