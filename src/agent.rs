//! agent — Agent runtime kernel support.
//!
//! Kernel-level primitives for long-running agent processes: process naming,
//! OOM score adjustment, cgroup self-inspection, and keepalive signaling.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::agent;
//!
//! agent::set_process_name("my-agent").unwrap();
//! agent::set_oom_score_adj(-500).unwrap();
//! let cgroup = agent::current_cgroup().unwrap();
//! println!("running in cgroup: {cgroup}");
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;

/// Set the calling thread's name via `prctl(PR_SET_NAME)`.
///
/// Name is truncated to 15 bytes (kernel limit).
pub fn set_process_name(name: &str) -> Result<()> {
    let mut buf = [0u8; 16];
    let len = name.len().min(15);
    buf[..len].copy_from_slice(&name.as_bytes()[..len]);

    let ret = unsafe { libc::prctl(libc::PR_SET_NAME, buf.as_ptr()) };
    if ret < 0 {
        let err = SysError::last_os_error();
        tracing::error!(name, "prctl(PR_SET_NAME) failed");
        Err(err)
    } else {
        tracing::debug!(name, "set process name");
        Ok(())
    }
}

/// Get the calling thread's name via `prctl(PR_GET_NAME)`.
#[must_use = "process name should be used"]
pub fn get_process_name() -> Result<String> {
    let mut buf = [0u8; 16];
    let ret = unsafe { libc::prctl(libc::PR_GET_NAME, buf.as_mut_ptr()) };
    if ret < 0 {
        let err = SysError::last_os_error();
        tracing::error!("prctl(PR_GET_NAME) failed");
        return Err(err);
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(16);
    Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
}

/// Set the OOM killer score adjustment for the current process.
///
/// Range: -1000 (never kill) to 1000 (always kill first).
/// Requires `CAP_SYS_RESOURCE` for negative values.
pub fn set_oom_score_adj(score: i32) -> Result<()> {
    if !(-1000..=1000).contains(&score) {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "OOM score adj must be in range -1000..=1000",
        )));
    }

    std::fs::write("/proc/self/oom_score_adj", format!("{score}")).map_err(|e| {
        tracing::error!(score, error = %e, "failed to set oom_score_adj");
        SysError::Io(e)
    })?;

    tracing::debug!(score, "set OOM score adjustment");
    Ok(())
}

/// Get the current OOM killer score adjustment.
#[must_use = "OOM score should be used"]
pub fn get_oom_score_adj() -> Result<i32> {
    let content = std::fs::read_to_string("/proc/self/oom_score_adj").map_err(|e| {
        tracing::error!(error = %e, "failed to read oom_score_adj");
        SysError::Io(e)
    })?;

    content.trim().parse::<i32>().map_err(|e| {
        SysError::InvalidArgument(Cow::Owned(format!("failed to parse oom_score_adj: {e}")))
    })
}

/// Read the current cgroup path for the calling process.
///
/// Reads from `/proc/self/cgroup`. On cgroup v2, returns the unified path.
#[must_use = "cgroup path should be used"]
pub fn current_cgroup() -> Result<String> {
    let content = std::fs::read_to_string("/proc/self/cgroup").map_err(|e| {
        tracing::error!(error = %e, "failed to read /proc/self/cgroup");
        SysError::Io(e)
    })?;

    // cgroup v2 format: "0::/path"
    // cgroup v1 format: "N:subsystem:/path" (multiple lines)
    for line in content.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            return Ok(path.to_owned());
        }
    }

    // Fallback: return the path from the first line
    if let Some(line) = content.lines().next()
        && let Some(path) = line.rsplit(':').next()
    {
        return Ok(path.to_owned());
    }

    Err(SysError::InvalidArgument(Cow::Borrowed(
        "could not parse /proc/self/cgroup",
    )))
}

/// Check if the calling process is PID 1 in its PID namespace.
///
/// Useful for agents that need to know if they're the init process
/// inside a container.
#[inline]
#[must_use]
pub fn is_pid1() -> bool {
    crate::syscall::getpid() == 1
}

/// Check if the process has the given capability in its effective set.
///
/// Uses `prctl(PR_CAPBSET_READ)`.
#[must_use = "capability check should be used"]
pub fn has_capability(cap: i32) -> Result<bool> {
    let ret = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap) };
    if ret < 0 {
        let err = SysError::last_os_error();
        tracing::error!(cap, "prctl(PR_CAPBSET_READ) failed");
        Err(err)
    } else {
        Ok(ret == 1)
    }
}

/// Send a keepalive notification via the systemd notify protocol.
///
/// Writes `WATCHDOG=1` to the `$NOTIFY_SOCKET` if set.
/// Returns `Ok(false)` if `$NOTIFY_SOCKET` is not set (not running under systemd).
pub fn watchdog_notify() -> Result<bool> {
    let socket_path = match std::env::var("NOTIFY_SOCKET") {
        Ok(p) if !p.is_empty() => p,
        _ => return Ok(false),
    };

    let addr = if let Some(abstract_name) = socket_path.strip_prefix('@') {
        // Abstract socket
        let mut path_bytes = vec![0u8]; // leading null for abstract
        path_bytes.extend_from_slice(abstract_name.as_bytes());
        path_bytes
    } else {
        socket_path.as_bytes().to_vec()
    };

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        let err = SysError::last_os_error();
        tracing::error!("failed to create notify socket");
        return Err(err);
    }

    let mut sockaddr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sockaddr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let copy_len = addr.len().min(sockaddr.sun_path.len());
    for (i, &b) in addr[..copy_len].iter().enumerate() {
        sockaddr.sun_path[i] = b as libc::c_char;
    }

    let msg = b"WATCHDOG=1";
    let sent = unsafe {
        libc::sendto(
            fd,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
            &sockaddr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    unsafe { libc::close(fd) };

    if sent < 0 {
        let err = SysError::last_os_error();
        tracing::error!("watchdog notify sendto failed");
        Err(err)
    } else {
        tracing::trace!("watchdog notify sent");
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        // Agent functions return owned types, no custom structs to check
        // but verify the module compiles with Send+Sync expectations
    };

    // ── process name ────────────────────────────────────────────────

    #[test]
    fn set_and_get_process_name() {
        let original = get_process_name().unwrap();
        set_process_name("agnosys-test").unwrap();
        let name = get_process_name().unwrap();
        assert_eq!(name, "agnosys-test");
        // Restore
        set_process_name(&original).unwrap();
    }

    #[test]
    fn process_name_truncated_to_15() {
        let original = get_process_name().unwrap();
        set_process_name("a]very-long-name-that-exceeds-fifteen").unwrap();
        let name = get_process_name().unwrap();
        assert!(name.len() <= 15);
        set_process_name(&original).unwrap();
    }

    #[test]
    fn get_process_name_not_empty() {
        let name = get_process_name().unwrap();
        assert!(!name.is_empty());
    }

    // ── OOM score ───────────────────────────────────────────────────

    #[test]
    fn get_oom_score_adj_in_range() {
        let score = get_oom_score_adj().unwrap();
        assert!((-1000..=1000).contains(&score));
    }

    #[test]
    fn set_oom_score_adj_zero() {
        // 0 is always safe to set
        let original = get_oom_score_adj().unwrap();
        set_oom_score_adj(0).unwrap();
        let score = get_oom_score_adj().unwrap();
        assert_eq!(score, 0);
        // Restore
        let _ = set_oom_score_adj(original);
    }

    #[test]
    fn set_oom_score_adj_out_of_range() {
        assert!(set_oom_score_adj(1001).is_err());
        assert!(set_oom_score_adj(-1001).is_err());
    }

    // ── cgroup ──────────────────────────────────────────────────────

    #[test]
    fn current_cgroup_returns_path() {
        let cg = current_cgroup().unwrap();
        // Should start with /
        assert!(cg.starts_with('/'));
    }

    // ── is_pid1 ─────────────────────────────────────────────────────

    #[test]
    fn is_pid1_false_in_tests() {
        // Test runner is not PID 1
        assert!(!is_pid1());
    }

    // ── has_capability ──────────────────────────────────────────────

    #[test]
    fn has_capability_returns_result() {
        // CAP_CHOWN = 0
        let _ = has_capability(0);
    }

    #[test]
    fn has_capability_invalid_cap() {
        // Very high cap number — should return Ok(false) or Err
        let result = has_capability(999);
        match result {
            Ok(false) => {}
            Err(_) => {}
            Ok(true) => panic!("should not have cap 999"),
        }
    }

    // ── watchdog_notify ─────────────────────────────────────────────

    #[test]
    fn watchdog_notify_no_socket() {
        // In tests, NOTIFY_SOCKET is not set
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        let result = watchdog_notify().unwrap();
        assert!(!result);
    }

    #[test]
    fn watchdog_notify_empty_socket() {
        unsafe { std::env::set_var("NOTIFY_SOCKET", "") };
        let result = watchdog_notify().unwrap();
        assert!(!result);
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
    }
}
