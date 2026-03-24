//! mac — Mandatory Access Control.
//!
//! Detect and query Linux Security Modules (LSMs): SELinux, AppArmor, Smack.
//! Read security contexts, labels, and LSM status without linking to
//! libselinux or libapparmor.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::mac;
//!
//! let lsm = mac::active_lsm().unwrap();
//! println!("active LSM: {lsm}");
//!
//! if let Ok(ctx) = mac::current_context() {
//!     println!("security context: {ctx}");
//! }
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;
use std::path::Path;

// ── Constants ───────────────────────────────────────────────────────

const LSM_PATH: &str = "/sys/kernel/security/lsm";
const SELINUX_ENFORCE_PATH: &str = "/sys/fs/selinux/enforce";
// const SELINUX_STATUS_PATH: &str = "/sys/fs/selinux/status"; // reserved for future use
const APPARMOR_PROFILES_PATH: &str = "/sys/kernel/security/apparmor/profiles";
const PROC_ATTR_CURRENT: &str = "/proc/self/attr/current";
const PROC_ATTR_APPARMOR: &str = "/proc/self/attr/apparmor/current";

// ── Public types ────────────────────────────────────────────────────

/// Known Linux Security Module types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Lsm {
    /// Security-Enhanced Linux.
    SELinux,
    /// Application Armor.
    AppArmor,
    /// Simplified Mandatory Access Control Kernel.
    Smack,
    /// TOMOYO Linux.
    Tomoyo,
    /// Landlock (handled separately in agnosys::landlock).
    Landlock,
    /// Yama ptrace restrictions.
    Yama,
    /// LoadPin module signature verification.
    LoadPin,
    /// SafeSetID UID/GID transitions.
    SafeSetID,
    /// BPF LSM.
    Bpf,
    /// Unknown LSM.
    Other(u8),
}

impl Lsm {
    fn from_name(name: &str) -> Self {
        match name.trim() {
            "selinux" => Self::SELinux,
            "apparmor" => Self::AppArmor,
            "smack" => Self::Smack,
            "tomoyo" => Self::Tomoyo,
            "landlock" => Self::Landlock,
            "yama" => Self::Yama,
            "loadpin" => Self::LoadPin,
            "safesetid" => Self::SafeSetID,
            "bpf" => Self::Bpf,
            _ => Self::Other(0),
        }
    }
}

impl std::fmt::Display for Lsm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SELinux => write!(f, "selinux"),
            Self::AppArmor => write!(f, "apparmor"),
            Self::Smack => write!(f, "smack"),
            Self::Tomoyo => write!(f, "tomoyo"),
            Self::Landlock => write!(f, "landlock"),
            Self::Yama => write!(f, "yama"),
            Self::LoadPin => write!(f, "loadpin"),
            Self::SafeSetID => write!(f, "safesetid"),
            Self::Bpf => write!(f, "bpf"),
            Self::Other(_) => write!(f, "unknown"),
        }
    }
}

/// SELinux enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SELinuxMode {
    /// SELinux is disabled.
    Disabled,
    /// SELinux is in permissive mode (logs but doesn't enforce).
    Permissive,
    /// SELinux is enforcing.
    Enforcing,
}

// ── LSM detection ───────────────────────────────────────────────────

/// List all active LSMs on the system.
///
/// Reads from `/sys/kernel/security/lsm`.
pub fn list_lsms() -> Result<Vec<Lsm>> {
    let content = std::fs::read_to_string(LSM_PATH).map_err(|e| {
        tracing::debug!(error = %e, "failed to read /sys/kernel/security/lsm");
        SysError::Io(e)
    })?;

    let lsms: Vec<Lsm> = content
        .trim()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(Lsm::from_name)
        .collect();

    tracing::trace!(count = lsms.len(), "listed active LSMs");
    Ok(lsms)
}

/// Get the primary (first) active LSM as a string.
pub fn active_lsm() -> Result<String> {
    let content = std::fs::read_to_string(LSM_PATH).map_err(|e| {
        tracing::debug!(error = %e, "failed to read /sys/kernel/security/lsm");
        SysError::Io(e)
    })?;

    let first = content.trim().split(',').next().unwrap_or("").to_owned();

    Ok(first)
}

/// Raw LSM string from the kernel (comma-separated).
pub fn lsm_string() -> Result<String> {
    std::fs::read_to_string(LSM_PATH)
        .map(|s| s.trim().to_owned())
        .map_err(|e| {
            tracing::debug!(error = %e, "failed to read LSM string");
            SysError::Io(e)
        })
}

/// Check if a specific LSM is active.
pub fn is_lsm_active(lsm: Lsm) -> Result<bool> {
    let lsms = list_lsms()?;
    Ok(lsms.contains(&lsm))
}

// ── SELinux ─────────────────────────────────────────────────────────

/// Check if SELinux is available on this system.
#[must_use]
pub fn selinux_available() -> bool {
    Path::new(SELINUX_ENFORCE_PATH).exists()
}

/// Get the current SELinux enforcement mode.
pub fn selinux_mode() -> Result<SELinuxMode> {
    if !selinux_available() {
        return Ok(SELinuxMode::Disabled);
    }

    let content = std::fs::read_to_string(SELINUX_ENFORCE_PATH).map_err(|e| {
        tracing::error!(error = %e, "failed to read SELinux enforce");
        SysError::Io(e)
    })?;

    match content.trim() {
        "1" => Ok(SELinuxMode::Enforcing),
        "0" => Ok(SELinuxMode::Permissive),
        _ => Ok(SELinuxMode::Disabled),
    }
}

// ── AppArmor ────────────────────────────────────────────────────────

/// Check if AppArmor is available on this system.
#[must_use]
pub fn apparmor_available() -> bool {
    Path::new(APPARMOR_PROFILES_PATH).exists()
}

/// Count loaded AppArmor profiles.
pub fn apparmor_profile_count() -> Result<usize> {
    let content = std::fs::read_to_string(APPARMOR_PROFILES_PATH).map_err(|e| {
        tracing::debug!(error = %e, "failed to read AppArmor profiles");
        SysError::Io(e)
    })?;

    Ok(content.lines().count())
}

// ── Security context ────────────────────────────────────────────────

/// Read the current process security context.
///
/// Tries `/proc/self/attr/apparmor/current` first (AppArmor),
/// then `/proc/self/attr/current` (SELinux/Smack).
pub fn current_context() -> Result<String> {
    // Try AppArmor first
    if let Ok(ctx) = std::fs::read_to_string(PROC_ATTR_APPARMOR) {
        let ctx = ctx.trim().to_owned();
        if !ctx.is_empty() {
            return Ok(ctx);
        }
    }

    // Fall back to generic (SELinux/Smack)
    let ctx = std::fs::read_to_string(PROC_ATTR_CURRENT).map_err(|e| {
        tracing::debug!(error = %e, "failed to read security context");
        SysError::Io(e)
    })?;

    Ok(ctx.trim().trim_end_matches('\0').to_owned())
}

/// Read the security context of a specific process.
pub fn process_context(pid: i32) -> Result<String> {
    let path = format!("/proc/{pid}/attr/current");
    let ctx = std::fs::read_to_string(&path).map_err(|e| {
        tracing::debug!(pid, error = %e, "failed to read process security context");
        SysError::Io(e)
    })?;

    Ok(ctx.trim().trim_end_matches('\0').to_owned())
}

/// Read the security label of a file via its extended attributes.
///
/// Reads from `/proc/self/attr/` indirectly — for direct xattr access,
/// use the `security.selinux` or `security.apparmor` xattr.
pub fn file_context(path: &Path) -> Result<String> {
    // Use getxattr for security.selinux
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| SysError::InvalidArgument(Cow::Borrowed("path contains null byte")))?;

    let c_name = c"/security.selinux";
    let mut buf = [0u8; 512];

    let ret = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };

    if ret >= 0 {
        let len = ret as usize;
        let ctx = String::from_utf8_lossy(&buf[..len])
            .trim_end_matches('\0')
            .to_owned();
        return Ok(ctx);
    }

    // Try AppArmor xattr
    let c_name = c"/security.apparmor";
    let ret = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };

    if ret >= 0 {
        let len = ret as usize;
        return Ok(String::from_utf8_lossy(&buf[..len])
            .trim_end_matches('\0')
            .to_owned());
    }

    Err(SysError::NotSupported {
        feature: Cow::Borrowed("no security label found"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Lsm>();
        assert_send_sync::<SELinuxMode>();
    };

    // ── Lsm ─────────────────────────────────────────────────────────

    #[test]
    fn lsm_from_name_all() {
        assert_eq!(Lsm::from_name("selinux"), Lsm::SELinux);
        assert_eq!(Lsm::from_name("apparmor"), Lsm::AppArmor);
        assert_eq!(Lsm::from_name("smack"), Lsm::Smack);
        assert_eq!(Lsm::from_name("tomoyo"), Lsm::Tomoyo);
        assert_eq!(Lsm::from_name("landlock"), Lsm::Landlock);
        assert_eq!(Lsm::from_name("yama"), Lsm::Yama);
        assert_eq!(Lsm::from_name("loadpin"), Lsm::LoadPin);
        assert_eq!(Lsm::from_name("safesetid"), Lsm::SafeSetID);
        assert_eq!(Lsm::from_name("bpf"), Lsm::Bpf);
        assert!(matches!(Lsm::from_name("unknown"), Lsm::Other(_)));
    }

    #[test]
    fn lsm_display() {
        assert_eq!(format!("{}", Lsm::SELinux), "selinux");
        assert_eq!(format!("{}", Lsm::AppArmor), "apparmor");
        assert_eq!(format!("{}", Lsm::Landlock), "landlock");
    }

    #[test]
    fn lsm_debug() {
        let dbg = format!("{:?}", Lsm::SELinux);
        assert!(dbg.contains("SELinux"));
    }

    #[test]
    fn lsm_eq() {
        assert_eq!(Lsm::SELinux, Lsm::SELinux);
        assert_ne!(Lsm::SELinux, Lsm::AppArmor);
    }

    #[test]
    fn lsm_copy() {
        let a = Lsm::AppArmor;
        let b = a;
        assert_eq!(a, b);
    }

    // ── SELinuxMode ─────────────────────────────────────────────────

    #[test]
    fn selinux_mode_eq() {
        assert_eq!(SELinuxMode::Enforcing, SELinuxMode::Enforcing);
        assert_ne!(SELinuxMode::Enforcing, SELinuxMode::Permissive);
    }

    #[test]
    fn selinux_mode_debug() {
        let dbg = format!("{:?}", SELinuxMode::Enforcing);
        assert!(dbg.contains("Enforcing"));
    }

    // ── LSM detection ───────────────────────────────────────────────

    #[test]
    fn list_lsms_returns_result() {
        let _ = list_lsms();
    }

    #[test]
    fn active_lsm_returns_result() {
        let _ = active_lsm();
    }

    #[test]
    fn lsm_string_returns_result() {
        let _ = lsm_string();
    }

    #[test]
    fn is_lsm_active_returns_result() {
        let _ = is_lsm_active(Lsm::Landlock);
    }

    // ── SELinux ─────────────────────────────────────────────────────

    #[test]
    fn selinux_available_returns_bool() {
        let _ = selinux_available();
    }

    #[test]
    fn selinux_mode_returns_result() {
        let _ = selinux_mode();
    }

    // ── AppArmor ────────────────────────────────────────────────────

    #[test]
    fn apparmor_available_returns_bool() {
        let _ = apparmor_available();
    }

    #[test]
    fn apparmor_profile_count_returns_result() {
        let _ = apparmor_profile_count();
    }

    // ── Security context ────────────────────────────────────────────

    #[test]
    fn current_context_returns_result() {
        let _ = current_context();
    }

    #[test]
    fn process_context_self() {
        let pid = crate::syscall::getpid();
        let _ = process_context(pid);
    }

    #[test]
    fn process_context_nonexistent() {
        let result = process_context(999999999);
        assert!(result.is_err());
    }

    #[test]
    fn file_context_returns_result() {
        let _ = file_context(Path::new("/etc/passwd"));
    }

    #[test]
    fn file_context_nonexistent() {
        let result = file_context(Path::new("/nonexistent_agnosys"));
        assert!(result.is_err());
    }
}
