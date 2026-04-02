//! Low-level syscall wrappers.
//!
//! Safe wrappers around raw Linux syscalls. These are the primitives
//! that higher-level modules (landlock, seccomp, netns, etc.) build on.

use crate::error::{Result, SysError};

/// Wrapper around `libc::syscall` that checks the return value.
///
/// Returns the syscall result on success, or `SysError` on failure.
#[inline]
#[must_use = "syscall result contains the return value or error"]
pub fn checked_syscall(name: &str, ret: libc::c_long) -> Result<libc::c_long> {
    if ret < 0 {
        // Read errno BEFORE any tracing — tracing may allocate and clobber errno
        let errno = unsafe { *libc::__errno_location() };
        let err = SysError::from_errno(errno);
        tracing::error!(syscall = name, errno, "syscall failed");
        Err(err)
    } else {
        Ok(ret)
    }
}

/// Get the current process ID.
#[inline]
#[must_use]
pub fn getpid() -> i32 {
    unsafe { libc::getpid() }
}

/// Get the current thread ID.
#[inline]
#[must_use]
pub fn gettid() -> i64 {
    unsafe { libc::syscall(libc::SYS_gettid) as i64 }
}

/// Get the current user ID.
#[inline]
#[must_use]
pub fn getuid() -> u32 {
    unsafe { libc::getuid() }
}

/// Get the current effective user ID.
#[inline]
#[must_use]
pub fn geteuid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Check if the current process has root privileges.
#[inline]
#[must_use]
pub fn is_root() -> bool {
    geteuid() == 0
}

// ── sysinfo helpers ─────────────────────────────────────────────────

/// Cached result of a single `sysinfo(2)` call.
///
/// Use [`query_sysinfo`] to fetch, then access fields directly.
/// This avoids redundant kernel roundtrips when you need multiple values.
#[non_exhaustive]
pub struct SysInfo {
    inner: libc::sysinfo,
}

impl SysInfo {
    /// System uptime in seconds.
    #[inline]
    #[must_use]
    pub fn uptime(&self) -> f64 {
        self.inner.uptime as f64
    }

    /// Total physical RAM in bytes.
    #[inline]
    #[must_use]
    pub fn total_memory(&self) -> u64 {
        self.inner.totalram * self.inner.mem_unit as u64
    }

    /// Free physical RAM in bytes.
    #[inline]
    #[must_use]
    pub fn free_memory(&self) -> u64 {
        self.inner.freeram * self.inner.mem_unit as u64
    }

    /// Number of current processes.
    #[inline]
    #[must_use]
    pub fn procs(&self) -> u16 {
        self.inner.procs
    }
}

/// Perform a single `sysinfo(2)` call and return a [`SysInfo`] snapshot.
#[inline]
#[must_use = "sysinfo result should be used"]
pub fn query_sysinfo() -> Result<SysInfo> {
    let mut inner: libc::sysinfo = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::sysinfo(&mut inner) };
    if ret < 0 {
        let err = SysError::last_os_error();
        tracing::error!("sysinfo syscall failed");
        return Err(err);
    }
    tracing::trace!(
        "sysinfo: uptime={}s total_ram={}",
        inner.uptime,
        inner.totalram
    );
    Ok(SysInfo { inner })
}

/// Get system uptime in seconds.
///
/// For multiple sysinfo fields, prefer [`query_sysinfo`] to avoid repeated syscalls.
#[inline]
#[must_use = "uptime result should be used"]
pub fn uptime() -> Result<f64> {
    query_sysinfo().map(|s| s.uptime())
}

/// Get total system memory in bytes.
///
/// For multiple sysinfo fields, prefer [`query_sysinfo`] to avoid repeated syscalls.
#[inline]
#[must_use = "memory result should be used"]
pub fn total_memory() -> Result<u64> {
    query_sysinfo().map(|s| s.total_memory())
}

/// Get available system memory in bytes.
///
/// For multiple sysinfo fields, prefer [`query_sysinfo`] to avoid repeated syscalls.
#[inline]
#[must_use = "memory result should be used"]
pub fn available_memory() -> Result<u64> {
    query_sysinfo().map(|s| s.free_memory())
}

/// Get the hostname.
///
/// Buffer is 256 bytes (exceeds `HOST_NAME_MAX` of 64 on Linux).
#[inline]
#[must_use = "hostname result should be used"]
pub fn hostname() -> Result<String> {
    let mut buf = [0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret < 0 {
        let err = SysError::last_os_error();
        tracing::error!("gethostname syscall failed");
        return Err(err);
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name = String::from_utf8(buf[..len].to_vec())
        .map_err(|e| SysError::InvalidArgument(std::borrow::Cow::Owned(e.to_string())))?;
    tracing::trace!(hostname = %name, "gethostname");
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SysInfo>();
    };

    // ── checked_syscall ─────────────────────────────────────────────

    #[test]
    fn checked_syscall_success() {
        let ret = checked_syscall("getpid", unsafe { libc::syscall(libc::SYS_getpid) });
        assert!(ret.is_ok());
        assert!(ret.unwrap() > 0);
    }

    #[test]
    fn checked_syscall_failure() {
        let ret = checked_syscall("bad_syscall", -1);
        assert!(ret.is_err());
    }

    #[test]
    fn checked_syscall_failure_returns_syserror() {
        // Force a known errno (EBADF) then call checked_syscall with -1
        unsafe { libc::close(-1) }; // sets errno to EBADF
        let ret = checked_syscall("close", -1);
        assert!(ret.is_err());
        // The error should be a valid SysError variant
        let msg = ret.unwrap_err().to_string();
        assert!(!msg.is_empty());
    }

    #[test]
    fn checked_syscall_preserves_positive_value() {
        let ret = checked_syscall("test", 42);
        assert_eq!(ret.unwrap(), 42);
    }

    #[test]
    fn checked_syscall_zero_is_ok() {
        let ret = checked_syscall("zero", 0);
        assert!(ret.is_ok());
        assert_eq!(ret.unwrap(), 0);
    }

    // ── getpid ──────────────────────────────────────────────────────

    #[test]
    fn getpid_positive() {
        assert!(getpid() > 0);
    }

    #[test]
    fn getpid_stable() {
        let a = getpid();
        let b = getpid();
        assert_eq!(a, b);
    }

    #[test]
    fn getpid_matches_libc() {
        let ours = getpid();
        let theirs = unsafe { libc::getpid() };
        assert_eq!(ours, theirs);
    }

    // ── gettid ──────────────────────────────────────────────────────

    #[test]
    fn gettid_positive() {
        assert!(gettid() > 0);
    }

    #[test]
    fn gettid_stable() {
        let a = gettid();
        let b = gettid();
        assert_eq!(a, b);
    }

    // ── getuid / geteuid ────────────────────────────────────────────

    #[test]
    fn getuid_matches_libc() {
        assert_eq!(getuid(), unsafe { libc::getuid() });
    }

    #[test]
    fn geteuid_matches_libc() {
        assert_eq!(geteuid(), unsafe { libc::geteuid() });
    }

    #[test]
    fn euid_gte_zero() {
        // u32 is always >= 0, but verify the call succeeds
        let _ = geteuid();
    }

    // ── is_root ─────────────────────────────────────────────────────

    #[test]
    fn is_root_consistent_with_euid() {
        assert_eq!(is_root(), geteuid() == 0);
    }

    // ── uptime ──────────────────────────────────────────────────────

    #[test]
    fn uptime_positive() {
        let up = uptime().unwrap();
        assert!(up > 0.0);
    }

    #[test]
    fn uptime_monotonic() {
        let a = uptime().unwrap();
        let b = uptime().unwrap();
        assert!(b >= a);
    }

    // ── total_memory ────────────────────────────────────────────────

    #[test]
    fn total_memory_positive() {
        let mem = total_memory().unwrap();
        assert!(mem > 0);
    }

    #[test]
    fn total_memory_reasonable() {
        let mem = total_memory().unwrap();
        // At least 32 MB, less than 256 TB
        assert!(mem >= 32 * 1024 * 1024);
        assert!(mem < 256 * 1024 * 1024 * 1024 * 1024);
    }

    #[test]
    fn total_memory_stable() {
        let a = total_memory().unwrap();
        let b = total_memory().unwrap();
        assert_eq!(a, b);
    }

    // ── available_memory ────────────────────────────────────────────

    #[test]
    fn available_memory_positive() {
        let mem = available_memory().unwrap();
        assert!(mem > 0);
    }

    #[test]
    fn available_lte_total() {
        let total = total_memory().unwrap();
        let avail = available_memory().unwrap();
        assert!(avail <= total);
    }

    // ── hostname ────────────────────────────────────────────────────

    #[test]
    fn hostname_not_empty() {
        let name = hostname().unwrap();
        assert!(!name.is_empty());
    }

    #[test]
    fn hostname_valid_utf8() {
        let name = hostname().unwrap();
        // If we got here, it's valid UTF-8. Also check reasonable length.
        assert!(name.len() <= 255);
    }

    #[test]
    fn hostname_stable() {
        let a = hostname().unwrap();
        let b = hostname().unwrap();
        assert_eq!(a, b);
    }

    // ── query_sysinfo / SysInfo ──────────────────────────────────────

    #[test]
    fn query_sysinfo_succeeds() {
        let info = query_sysinfo().unwrap();
        assert!(info.uptime() > 0.0);
        assert!(info.total_memory() > 0);
        assert!(info.free_memory() > 0);
        assert!(info.procs() > 0);
    }

    #[test]
    fn query_sysinfo_single_call_consistent() {
        let info = query_sysinfo().unwrap();
        // From one snapshot, free must be <= total
        assert!(info.free_memory() <= info.total_memory());
    }

    #[test]
    fn query_sysinfo_matches_convenience_fns() {
        let info = query_sysinfo().unwrap();
        // Convenience functions each call sysinfo independently,
        // so values may differ slightly — just sanity check same order of magnitude
        let total_direct = total_memory().unwrap();
        assert_eq!(info.total_memory(), total_direct);
    }

    #[test]
    fn sysinfo_uptime_positive() {
        let info = query_sysinfo().unwrap();
        assert!(info.uptime() > 0.0);
    }

    #[test]
    fn sysinfo_total_memory_reasonable() {
        let info = query_sysinfo().unwrap();
        assert!(info.total_memory() >= 32 * 1024 * 1024);
        assert!(info.total_memory() < 256 * 1024 * 1024 * 1024 * 1024);
    }

    #[test]
    fn sysinfo_procs_reasonable() {
        let info = query_sysinfo().unwrap();
        // Any running system has at least 1 process, upper bound sanity
        assert!(info.procs() >= 1);
        assert!(info.procs() < 65535);
    }

    #[test]
    fn sysinfo_uptime_monotonic() {
        let a = query_sysinfo().unwrap();
        let b = query_sysinfo().unwrap();
        assert!(b.uptime() >= a.uptime());
    }
}
