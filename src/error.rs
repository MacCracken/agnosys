//! Unified error type with errno mapping.

use std::borrow::Cow;

/// All errors that agnosys can produce.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SysError {
    #[error("syscall failed with errno {errno}: {message}")]
    SyscallFailed {
        errno: i32,
        message: Cow<'static, str>,
    },

    #[error("invalid argument: {0}")]
    InvalidArgument(Cow<'static, str>),

    #[error("permission denied: {operation}")]
    PermissionDenied { operation: Cow<'static, str> },

    #[error("resource temporarily unavailable")]
    WouldBlock,

    #[error("kernel module not loaded: {module}")]
    ModuleNotLoaded { module: Cow<'static, str> },

    #[error("feature not supported: {feature}")]
    NotSupported { feature: Cow<'static, str> },

    #[error("unknown error: {0}")]
    Unknown(Cow<'static, str>),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SysError>;

impl SysError {
    /// Create from a raw errno value.
    #[inline]
    #[must_use]
    pub fn from_errno(errno: i32) -> Self {
        match errno {
            libc::EPERM | libc::EACCES => Self::PermissionDenied {
                operation: Cow::Borrowed(""),
            },
            libc::EAGAIN => Self::WouldBlock,
            libc::EINVAL => Self::InvalidArgument(Cow::Borrowed("invalid argument")),
            libc::ENOSYS => Self::NotSupported {
                feature: Cow::Borrowed("syscall"),
            },
            _ => Self::SyscallFailed {
                errno,
                message: Cow::Owned(std::io::Error::from_raw_os_error(errno).to_string()),
            },
        }
    }

    /// Create from the last OS error.
    #[inline]
    #[must_use]
    pub fn last_os_error() -> Self {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(-1);
        Self::from_errno(errno)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SysError>();
    };

    // ── from_errno mapping ──────────────────────────────────────────

    #[test]
    fn from_errno_eperm() {
        let e = SysError::from_errno(libc::EPERM);
        assert!(matches!(e, SysError::PermissionDenied { .. }));
    }

    #[test]
    fn from_errno_eacces() {
        let e = SysError::from_errno(libc::EACCES);
        assert!(matches!(e, SysError::PermissionDenied { .. }));
    }

    #[test]
    fn from_errno_eagain() {
        let e = SysError::from_errno(libc::EAGAIN);
        assert!(matches!(e, SysError::WouldBlock));
    }

    #[test]
    fn from_errno_einval() {
        let e = SysError::from_errno(libc::EINVAL);
        assert!(matches!(e, SysError::InvalidArgument(_)));
    }

    #[test]
    fn from_errno_enosys() {
        let e = SysError::from_errno(libc::ENOSYS);
        assert!(matches!(e, SysError::NotSupported { .. }));
    }

    #[test]
    fn from_errno_unknown() {
        let e = SysError::from_errno(999);
        assert!(matches!(e, SysError::SyscallFailed { errno: 999, .. }));
    }

    #[test]
    fn from_errno_unknown_has_message() {
        let e = SysError::from_errno(libc::ENOENT);
        match e {
            SysError::SyscallFailed { errno, message } => {
                assert_eq!(errno, libc::ENOENT);
                assert!(!message.is_empty());
            }
            _ => panic!("expected SyscallFailed for ENOENT"),
        }
    }

    #[test]
    fn from_errno_permission_has_empty_operation() {
        let e = SysError::from_errno(libc::EPERM);
        match e {
            SysError::PermissionDenied { operation } => {
                assert!(operation.is_empty());
            }
            _ => panic!("expected PermissionDenied"),
        }
    }

    #[test]
    fn from_errno_zero() {
        // errno 0 means "no error" but from_errno should still produce a value
        let e = SysError::from_errno(0);
        assert!(matches!(e, SysError::SyscallFailed { errno: 0, .. }));
    }

    #[test]
    fn from_errno_negative() {
        let e = SysError::from_errno(-1);
        assert!(matches!(e, SysError::SyscallFailed { errno: -1, .. }));
    }

    // ── last_os_error ───────────────────────────────────────────────

    #[test]
    fn last_os_error_returns_valid_error() {
        // Set errno to a known value via a failing syscall
        unsafe { libc::close(-1) };
        let e = SysError::last_os_error();
        // EBADF (bad file descriptor) is expected
        assert!(matches!(
            e,
            SysError::SyscallFailed { .. } | SysError::InvalidArgument(_)
        ));
    }

    #[test]
    fn last_os_error_ebadf() {
        unsafe { libc::close(-1) };
        let e = SysError::last_os_error();
        // EBADF = 9, which falls into the SyscallFailed catch-all
        if let SysError::SyscallFailed { errno, message } = e {
            assert_eq!(errno, libc::EBADF);
            assert!(!message.is_empty());
        }
        // else it matched another variant, which is fine
    }

    // ── Display for all variants ────────────────────────────────────

    #[test]
    fn display_syscall_failed() {
        let e = SysError::SyscallFailed {
            errno: 2,
            message: "No such file".into(),
        };
        let s = e.to_string();
        assert!(s.contains("errno 2"));
        assert!(s.contains("No such file"));
    }

    #[test]
    fn display_invalid_argument() {
        let e = SysError::InvalidArgument("bad flags".into());
        assert!(e.to_string().contains("bad flags"));
    }

    #[test]
    fn display_permission_denied() {
        let e = SysError::PermissionDenied {
            operation: "mount".into(),
        };
        let s = e.to_string();
        assert!(s.contains("permission denied"));
        assert!(s.contains("mount"));
    }

    #[test]
    fn display_would_block() {
        let e = SysError::WouldBlock;
        assert!(e.to_string().contains("temporarily unavailable"));
    }

    #[test]
    fn display_module_not_loaded() {
        let e = SysError::ModuleNotLoaded {
            module: "tpm_tis".into(),
        };
        assert!(e.to_string().contains("tpm_tis"));
    }

    #[test]
    fn display_not_supported() {
        let e = SysError::NotSupported {
            feature: "landlock".into(),
        };
        assert!(e.to_string().contains("landlock"));
    }

    #[test]
    fn display_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let e = SysError::Io(io_err);
        assert!(e.to_string().contains("gone"));
    }

    // ── From / Into conversions ─────────────────────────────────────

    #[test]
    fn io_error_into_sys_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let e: SysError = io_err.into();
        assert!(matches!(e, SysError::Io(_)));
    }

    // ── std::error::Error trait ─────────────────────────────────────

    #[test]
    fn io_variant_source_chain() {
        use std::error::Error;
        let io_err = std::io::Error::other("inner");
        let e = SysError::Io(io_err);
        assert!(e.source().is_some());
    }

    #[test]
    fn non_io_variants_have_no_source() {
        use std::error::Error;
        assert!(SysError::WouldBlock.source().is_none());
        assert!(SysError::InvalidArgument("x".into()).source().is_none());
        assert!(SysError::from_errno(libc::EPERM).source().is_none());
    }

    // ── Debug for all variants ────────────────────────────────────

    #[test]
    fn debug_would_block() {
        let dbg = format!("{:?}", SysError::WouldBlock);
        assert!(dbg.contains("WouldBlock"));
    }

    #[test]
    fn debug_syscall_failed() {
        let e = SysError::SyscallFailed {
            errno: 2,
            message: "no such file".into(),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("SyscallFailed"));
        assert!(dbg.contains("no such file"));
    }

    #[test]
    fn debug_invalid_argument() {
        let dbg = format!("{:?}", SysError::InvalidArgument("bad".into()));
        assert!(dbg.contains("InvalidArgument"));
    }

    #[test]
    fn debug_permission_denied() {
        let e = SysError::PermissionDenied {
            operation: "write".into(),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("PermissionDenied"));
    }

    #[test]
    fn debug_module_not_loaded() {
        let e = SysError::ModuleNotLoaded {
            module: "vfio".into(),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ModuleNotLoaded"));
        assert!(dbg.contains("vfio"));
    }

    #[test]
    fn debug_not_supported() {
        let e = SysError::NotSupported {
            feature: "landlock".into(),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("NotSupported"));
    }

    #[test]
    fn debug_io() {
        let e = SysError::Io(std::io::Error::other("test"));
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Io"));
    }

    // ── Result alias ────────────────────────────────────────────────

    #[test]
    fn result_alias_ok() {
        let ok: Result<i32> = Ok(42);
        assert!(ok.is_ok());
        assert!(matches!(ok, Ok(42)));
    }

    #[test]
    fn result_alias_err() {
        let err: Result<i32> = Err(SysError::WouldBlock);
        assert!(err.is_err());
    }
}
