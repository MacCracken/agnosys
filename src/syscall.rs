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

    #[test]
    fn test_getpid() {
        assert!(getpid() > 0);
    }

    #[test]
    fn test_gettid() {
        assert!(gettid() > 0);
    }

    #[test]
    fn test_getuid() {
        // Just verify it doesn't panic
        let _ = getuid();
    }

    #[test]
    fn test_geteuid() {
        let _ = geteuid();
    }

    #[test]
    fn test_is_root() {
        // In CI, we're not root
        let _ = is_root();
    }

    #[test]
    fn test_uptime() {
        let up = uptime().unwrap();
        assert!(up > 0.0);
    }

    #[test]
    fn test_total_memory() {
        let mem = total_memory().unwrap();
        assert!(mem > 0);
    }

    #[test]
    fn test_available_memory() {
        let mem = available_memory().unwrap();
        assert!(mem > 0);
    }

    #[test]
    fn test_hostname() {
        let name = hostname().unwrap();
        assert!(!name.is_empty());
    }

    #[test]
    fn test_checked_syscall_success() {
        let ret = checked_syscall("getpid", unsafe { libc::syscall(libc::SYS_getpid) });
        assert!(ret.is_ok());
        assert!(ret.unwrap() > 0);
    }
}
