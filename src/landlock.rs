//! Landlock LSM — filesystem and network sandboxing.
//!
//! Safe Rust bindings for the Landlock Linux Security Module (kernel 5.13+).
//! Build a [`Ruleset`] with filesystem and network rules, then call
//! [`Ruleset::restrict_self`] to enforce it on the current thread.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::landlock::{Ruleset, FsAccess};
//! use std::path::Path;
//!
//! let access = FsAccess::READ_FILE | FsAccess::READ_DIR | FsAccess::EXECUTE | FsAccess::WRITE_FILE;
//! let rs = Ruleset::new(access).expect("landlock not supported");
//! rs.allow_path(Path::new("/usr"), FsAccess::READ_FILE | FsAccess::EXECUTE).unwrap();
//! rs.allow_path(Path::new("/tmp"), FsAccess::READ_FILE | FsAccess::WRITE_FILE).unwrap();
//! rs.restrict_self().unwrap();
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

// ── Syscall numbers (not in libc) ───────────────────────────────────

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

// ── Rule types ──────────────────────────────────────────────────────

const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
const LANDLOCK_RULE_NET_PORT: libc::c_int = 2;

// ── Create-ruleset flags ────────────────────────────────────────────

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

// ── Kernel structures ───────────────────────────────────────────────

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct NetPortAttr {
    allowed_access: u64,
    port: u64,
}

// ── Filesystem access flags ─────────────────────────────────────────

bitflags::bitflags! {
    /// Filesystem access rights for Landlock rules.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FsAccess: u64 {
        /// Execute a file.
        const EXECUTE      = 1 << 0;
        /// Open a file with write access.
        const WRITE_FILE   = 1 << 1;
        /// Open a file with read access.
        const READ_FILE    = 1 << 2;
        /// Open a directory or list its content.
        const READ_DIR     = 1 << 3;
        /// Remove an empty directory.
        const REMOVE_DIR   = 1 << 4;
        /// Unlink a file.
        const REMOVE_FILE  = 1 << 5;
        /// Create a character device.
        const MAKE_CHAR    = 1 << 6;
        /// Create a directory.
        const MAKE_DIR     = 1 << 7;
        /// Create a regular file.
        const MAKE_REG     = 1 << 8;
        /// Create a UNIX domain socket.
        const MAKE_SOCK    = 1 << 9;
        /// Create a named pipe.
        const MAKE_FIFO    = 1 << 10;
        /// Create a block device.
        const MAKE_BLOCK   = 1 << 11;
        /// Create a symbolic link.
        const MAKE_SYM     = 1 << 12;
        /// Rename or link across directories (ABI v2+).
        const REFER        = 1 << 13;
        /// Truncate a file (ABI v3+).
        const TRUNCATE     = 1 << 14;
        /// Device ioctl (ABI v5+).
        const IOCTL_DEV    = 1 << 15;
    }
}

// ── Network access flags ────────────────────────────────────────────

bitflags::bitflags! {
    /// Network access rights for Landlock rules (ABI v4+).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NetAccess: u64 {
        /// Bind a TCP socket to a port.
        const BIND_TCP    = 1 << 0;
        /// Connect a TCP socket to a port.
        const CONNECT_TCP = 1 << 1;
    }
}

// ── ABI version masks per version ───────────────────────────────────

/// All filesystem access flags supported by ABI version 1.
const ABI_V1_FS: u64 = 0x1FFF; // bits 0-12
/// Filesystem flags added in ABI version 2.
const ABI_V2_FS: u64 = 1 << 13; // REFER
/// Filesystem flags added in ABI version 3.
const ABI_V3_FS: u64 = 1 << 14; // TRUNCATE

// ── Raw syscall wrappers ────────────────────────────────────────────

#[inline]
fn raw_create_ruleset(attr: &RulesetAttr, flags: u32) -> Result<i32> {
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            flags,
        )
    };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        tracing::error!(errno, "landlock_create_ruleset failed");
        Err(SysError::from_errno(errno))
    } else {
        Ok(ret as i32)
    }
}

#[inline]
fn raw_add_rule(ruleset_fd: i32, rule_type: libc::c_int, attr: *const libc::c_void) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            rule_type,
            attr,
            0u32, // flags, must be 0
        )
    };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        tracing::error!(errno, rule_type, "landlock_add_rule failed");
        Err(SysError::from_errno(errno))
    } else {
        Ok(())
    }
}

#[inline]
fn raw_restrict_self(ruleset_fd: i32, flags: u32) -> Result<()> {
    let ret = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, flags) };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        tracing::error!(errno, "landlock_restrict_self failed");
        Err(SysError::from_errno(errno))
    } else {
        Ok(())
    }
}

// ── Public API ──────────────────────────────────────────────────────

/// Query the Landlock ABI version supported by the running kernel.
///
/// Returns `Ok(version)` where version >= 1, or an error if Landlock
/// is not supported (kernel < 5.13 or Landlock disabled).
#[inline]
#[must_use = "ABI version should be checked"]
pub fn abi_version() -> Result<i32> {
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        tracing::debug!(errno, "landlock ABI version query failed");
        if errno == libc::ENOSYS {
            return Err(SysError::NotSupported {
                feature: Cow::Borrowed("landlock"),
            });
        }
        Err(SysError::from_errno(errno))
    } else {
        tracing::debug!(abi_version = ret, "landlock ABI version");
        Ok(ret as i32)
    }
}

/// Best-effort filesystem access mask for the detected ABI version.
///
/// Returns the set of `FsAccess` flags the running kernel understands.
pub fn supported_fs_access() -> Result<FsAccess> {
    let v = abi_version()?;
    let mut bits = ABI_V1_FS;
    if v >= 2 {
        bits |= ABI_V2_FS;
    }
    if v >= 3 {
        bits |= ABI_V3_FS;
    }
    // ABI v4 adds net, not fs
    if v >= 5 {
        bits |= 1 << 15; // IOCTL_DEV
    }
    Ok(FsAccess::from_bits_truncate(bits))
}

/// A Landlock ruleset under construction.
///
/// Build rules, then call [`restrict_self`](Ruleset::restrict_self) to enforce.
///
/// The handled access rights are declared at construction time and sent to the
/// kernel immediately. Any handled access not explicitly allowed via
/// [`allow_path`](Ruleset::allow_path) or [`allow_net_port`](Ruleset::allow_net_port)
/// will be denied after [`restrict_self`](Ruleset::restrict_self).
pub struct Ruleset {
    fd: OwnedFd,
    handled_fs: u64,
    handled_net: u64,
}

impl Ruleset {
    /// Create a ruleset that handles the given filesystem access rights.
    ///
    /// The kernel ruleset is created immediately with these access rights.
    /// Fails if Landlock is not supported on this kernel.
    pub fn new(fs: FsAccess) -> Result<Self> {
        Self::with_net(fs, NetAccess::empty())
    }

    /// Create a ruleset that handles both filesystem and network access rights.
    ///
    /// Network access requires Landlock ABI v4+ (kernel 6.2+).
    pub fn with_net(fs: FsAccess, net: NetAccess) -> Result<Self> {
        abi_version()?;

        let attr = RulesetAttr {
            handled_access_fs: fs.bits(),
            handled_access_net: net.bits(),
        };
        let fd = raw_create_ruleset(&attr, 0)?;
        tracing::debug!(
            fd,
            fs = fs.bits(),
            net = net.bits(),
            "created landlock ruleset"
        );
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            handled_fs: fs.bits(),
            handled_net: net.bits(),
        })
    }

    /// The filesystem access rights this ruleset handles.
    #[inline]
    #[must_use]
    pub fn handled_fs(&self) -> FsAccess {
        FsAccess::from_bits_truncate(self.handled_fs)
    }

    /// The network access rights this ruleset handles.
    #[inline]
    #[must_use]
    pub fn handled_net(&self) -> NetAccess {
        NetAccess::from_bits_truncate(self.handled_net)
    }

    /// Allow specific filesystem access beneath a directory path.
    pub fn allow_path(&self, path: &Path, access: FsAccess) -> Result<()> {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| SysError::InvalidArgument(Cow::Borrowed("path contains null byte")))?;

        let parent_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if parent_fd < 0 {
            let err = SysError::last_os_error();
            tracing::error!(path = %path.display(), "failed to open path for landlock rule");
            return Err(err);
        }

        let attr = PathBeneathAttr {
            allowed_access: access.bits(),
            parent_fd,
        };

        let result = raw_add_rule(
            self.fd.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const PathBeneathAttr as *const libc::c_void,
        );

        unsafe { libc::close(parent_fd) };

        if result.is_ok() {
            tracing::trace!(
                path = %path.display(),
                access = access.bits(),
                "added landlock path rule"
            );
        }

        result
    }

    /// Allow TCP bind/connect on a specific port (ABI v4+).
    pub fn allow_net_port(&self, port: u16, access: NetAccess) -> Result<()> {
        let attr = NetPortAttr {
            allowed_access: access.bits(),
            port: port as u64,
        };
        let result = raw_add_rule(
            self.fd.as_raw_fd(),
            LANDLOCK_RULE_NET_PORT,
            &attr as *const NetPortAttr as *const libc::c_void,
        );

        if result.is_ok() {
            tracing::trace!(port, access = access.bits(), "added landlock net port rule");
        }

        result
    }

    /// Enforce the ruleset on the current thread.
    ///
    /// Sets `PR_SET_NO_NEW_PRIVS` first (required unless `CAP_SYS_ADMIN`),
    /// then applies the Landlock restriction.
    ///
    /// After this call, any handled access not explicitly allowed is denied.
    pub fn restrict_self(self) -> Result<()> {
        // Set no_new_privs (required for unprivileged landlock)
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret < 0 {
            let err = SysError::last_os_error();
            tracing::error!("prctl(PR_SET_NO_NEW_PRIVS) failed");
            return Err(err);
        }

        raw_restrict_self(self.fd.as_raw_fd(), 0)?;
        tracing::info!(
            handled_fs = self.handled_fs,
            handled_net = self.handled_net,
            "landlock restriction enforced"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FsAccess>();
        assert_send_sync::<NetAccess>();
        assert_send_sync::<Ruleset>();
    };

    // ── ABI version ─────────────────────────────────────────────────

    #[test]
    fn abi_version_returns_result() {
        // May succeed or fail depending on kernel — just verify no panic
        let _ = abi_version();
    }

    // ── FsAccess flags ──────────────────────────────────────────────

    #[test]
    fn fs_access_bits_are_powers_of_two() {
        assert_eq!(FsAccess::EXECUTE.bits(), 1);
        assert_eq!(FsAccess::WRITE_FILE.bits(), 2);
        assert_eq!(FsAccess::READ_FILE.bits(), 4);
        assert_eq!(FsAccess::READ_DIR.bits(), 8);
    }

    #[test]
    fn fs_access_combine() {
        let rw = FsAccess::READ_FILE | FsAccess::WRITE_FILE;
        assert!(rw.contains(FsAccess::READ_FILE));
        assert!(rw.contains(FsAccess::WRITE_FILE));
        assert!(!rw.contains(FsAccess::EXECUTE));
    }

    #[test]
    fn fs_access_remaining_bits() {
        assert_eq!(FsAccess::REMOVE_DIR.bits(), 1 << 4);
        assert_eq!(FsAccess::REMOVE_FILE.bits(), 1 << 5);
        assert_eq!(FsAccess::MAKE_CHAR.bits(), 1 << 6);
        assert_eq!(FsAccess::MAKE_DIR.bits(), 1 << 7);
        assert_eq!(FsAccess::MAKE_REG.bits(), 1 << 8);
        assert_eq!(FsAccess::MAKE_SOCK.bits(), 1 << 9);
        assert_eq!(FsAccess::MAKE_FIFO.bits(), 1 << 10);
        assert_eq!(FsAccess::MAKE_BLOCK.bits(), 1 << 11);
        assert_eq!(FsAccess::MAKE_SYM.bits(), 1 << 12);
        assert_eq!(FsAccess::REFER.bits(), 1 << 13);
        assert_eq!(FsAccess::TRUNCATE.bits(), 1 << 14);
        assert_eq!(FsAccess::IOCTL_DEV.bits(), 1 << 15);
    }

    #[test]
    fn fs_access_empty() {
        let empty = FsAccess::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.bits(), 0);
    }

    #[test]
    fn fs_access_intersection() {
        let a = FsAccess::READ_FILE | FsAccess::WRITE_FILE | FsAccess::EXECUTE;
        let b = FsAccess::READ_FILE | FsAccess::READ_DIR;
        let inter = a & b;
        assert_eq!(inter, FsAccess::READ_FILE);
    }

    #[test]
    fn fs_access_difference() {
        let a = FsAccess::READ_FILE | FsAccess::WRITE_FILE;
        let diff = a - FsAccess::WRITE_FILE;
        assert_eq!(diff, FsAccess::READ_FILE);
    }

    #[test]
    fn fs_access_debug() {
        let dbg = format!("{:?}", FsAccess::READ_FILE | FsAccess::EXECUTE);
        assert!(dbg.contains("READ_FILE"));
        assert!(dbg.contains("EXECUTE"));
    }

    #[test]
    fn fs_access_all_abi_v1_bits() {
        let all_v1 = FsAccess::from_bits_truncate(ABI_V1_FS);
        assert!(all_v1.contains(FsAccess::EXECUTE));
        assert!(all_v1.contains(FsAccess::MAKE_SYM));
        assert!(!all_v1.contains(FsAccess::REFER));
    }

    // ── NetAccess flags ─────────────────────────────────────────────

    #[test]
    fn net_access_bits() {
        assert_eq!(NetAccess::BIND_TCP.bits(), 1);
        assert_eq!(NetAccess::CONNECT_TCP.bits(), 2);
    }

    #[test]
    fn net_access_combine() {
        let both = NetAccess::BIND_TCP | NetAccess::CONNECT_TCP;
        assert!(both.contains(NetAccess::BIND_TCP));
        assert!(both.contains(NetAccess::CONNECT_TCP));
    }

    // ── Ruleset (kernel-dependent) ──────────────────────────────────

    #[test]
    fn ruleset_new_returns_result() {
        let _ = Ruleset::new(FsAccess::READ_FILE);
    }

    #[test]
    fn ruleset_with_net_returns_result() {
        let _ = Ruleset::with_net(FsAccess::READ_FILE | FsAccess::EXECUTE, NetAccess::BIND_TCP);
    }

    #[test]
    fn supported_fs_access_returns_result() {
        let _ = supported_fs_access();
    }

    // ── Conditional tests (only on landlock-capable kernels) ────────

    #[test]
    fn ruleset_allow_path_on_supported_kernel() {
        let rs = match Ruleset::new(FsAccess::READ_FILE) {
            Ok(rs) => rs,
            Err(_) => return,
        };
        let result = rs.allow_path(Path::new("/tmp"), FsAccess::READ_FILE);
        assert!(result.is_ok());
    }

    #[test]
    fn ruleset_allow_path_bad_path() {
        let rs = match Ruleset::new(FsAccess::READ_FILE) {
            Ok(rs) => rs,
            Err(_) => return,
        };
        let result = rs.allow_path(
            Path::new("/nonexistent_agnosys_test_path"),
            FsAccess::READ_FILE,
        );
        assert!(result.is_err());
    }

    #[test]
    fn ruleset_allow_path_null_byte() {
        let rs = match Ruleset::new(FsAccess::READ_FILE) {
            Ok(rs) => rs,
            Err(_) => return,
        };
        let result = rs.allow_path(Path::new("/tmp/\0bad"), FsAccess::READ_FILE);
        assert!(result.is_err());
    }

    #[test]
    fn ruleset_handled_fs_matches_constructor() {
        let access = FsAccess::READ_FILE | FsAccess::WRITE_FILE;
        let rs = match Ruleset::new(access) {
            Ok(rs) => rs,
            Err(_) => return,
        };
        assert_eq!(rs.handled_fs(), access);
        assert!(rs.handled_net().is_empty());
    }

    #[test]
    fn ruleset_with_net_tracks_both() {
        let fs = FsAccess::EXECUTE;
        let net = NetAccess::BIND_TCP | NetAccess::CONNECT_TCP;
        let rs = match Ruleset::with_net(fs, net) {
            Ok(rs) => rs,
            Err(_) => return,
        };
        assert_eq!(rs.handled_fs(), fs);
        assert_eq!(rs.handled_net(), net);
    }

    #[test]
    fn ruleset_multiple_path_rules() {
        let rs = match Ruleset::new(FsAccess::READ_FILE | FsAccess::EXECUTE) {
            Ok(rs) => rs,
            Err(_) => return,
        };
        assert!(
            rs.allow_path(Path::new("/tmp"), FsAccess::READ_FILE)
                .is_ok()
        );
        assert!(rs.allow_path(Path::new("/usr"), FsAccess::EXECUTE).is_ok());
    }
}
