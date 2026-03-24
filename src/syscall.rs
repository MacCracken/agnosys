//! Low-level syscall wrappers.
//!
//! Safe wrappers around raw Linux syscalls. These are the primitives
//! that higher-level modules (landlock, seccomp, netns, etc.) build on.

use crate::error::{Result, SysError};

/// Wrapper around `libc::syscall` that checks the return value.
///
/// Returns the syscall result on success, or `SysError` on failure.
#[inline]
pub fn checked_syscall(name: &str, ret: libc::c_long) -> Result<libc::c_long> {
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        tracing::error!(syscall = name, errno, "syscall failed");
        Err(SysError::from_errno(errno))
    } else {
        Ok(ret)
    }
}

/// Get the current process ID.
#[inline]
pub fn getpid() -> i32 {
    unsafe { libc::getpid() }
}

/// Get the current thread ID.
#[inline]
pub fn gettid() -> i64 {
    unsafe { libc::syscall(libc::SYS_gettid) as i64 }
}

/// Get the current user ID.
#[inline]
pub fn getuid() -> u32 {
    unsafe { libc::getuid() }
}

/// Get the current effective user ID.
#[inline]
pub fn geteuid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Check if the current process has root privileges.
#[inline]
pub fn is_root() -> bool {
    geteuid() == 0
}

/// Get system uptime in seconds.
pub fn uptime() -> Result<f64> {
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::sysinfo(&mut info) };
    if ret < 0 {
        return Err(SysError::last_os_error());
    }
    Ok(info.uptime as f64)
}

/// Get total system memory in bytes.
pub fn total_memory() -> Result<u64> {
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::sysinfo(&mut info) };
    if ret < 0 {
        return Err(SysError::last_os_error());
    }
    Ok(info.totalram * info.mem_unit as u64)
}

/// Get available system memory in bytes.
pub fn available_memory() -> Result<u64> {
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::sysinfo(&mut info) };
    if ret < 0 {
        return Err(SysError::last_os_error());
    }
    Ok(info.freeram * info.mem_unit as u64)
}

/// Get the hostname.
pub fn hostname() -> Result<String> {
    let mut buf = [0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret < 0 {
        return Err(SysError::last_os_error());
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..len].to_vec()).map_err(|e| SysError::InvalidArgument(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
