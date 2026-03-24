//! Unified error type with errno mapping.

/// All errors that agnosys can produce.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SysError {
    #[error("syscall failed with errno {errno}: {message}")]
    SyscallFailed { errno: i32, message: String },

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("permission denied: {operation}")]
    PermissionDenied { operation: String },

    #[error("resource temporarily unavailable")]
    WouldBlock,

    #[error("kernel module not loaded: {module}")]
    ModuleNotLoaded { module: String },

    #[error("feature not supported: {feature}")]
    NotSupported { feature: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SysError>;

impl SysError {
    /// Create from a raw errno value.
    #[inline]
    pub fn from_errno(errno: i32) -> Self {
        match errno {
            libc::EPERM | libc::EACCES => Self::PermissionDenied {
                operation: String::new(),
            },
            libc::EAGAIN => Self::WouldBlock,
            libc::EINVAL => Self::InvalidArgument("invalid argument".into()),
            libc::ENOSYS => Self::NotSupported {
                feature: "syscall".into(),
            },
            _ => Self::SyscallFailed {
                errno,
                message: std::io::Error::from_raw_os_error(errno).to_string(),
            },
        }
    }

    /// Create from the last OS error.
    #[inline]
    pub fn last_os_error() -> Self {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(-1);
        Self::from_errno(errno)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_errno_eperm() {
        let e = SysError::from_errno(libc::EPERM);
        assert!(matches!(e, SysError::PermissionDenied { .. }));
    }

    #[test]
    fn test_from_errno_eacces() {
        let e = SysError::from_errno(libc::EACCES);
        assert!(matches!(e, SysError::PermissionDenied { .. }));
    }

    #[test]
    fn test_from_errno_eagain() {
        let e = SysError::from_errno(libc::EAGAIN);
        assert!(matches!(e, SysError::WouldBlock));
    }

    #[test]
    fn test_from_errno_einval() {
        let e = SysError::from_errno(libc::EINVAL);
        assert!(matches!(e, SysError::InvalidArgument(_)));
    }

    #[test]
    fn test_from_errno_enosys() {
        let e = SysError::from_errno(libc::ENOSYS);
        assert!(matches!(e, SysError::NotSupported { .. }));
    }

    #[test]
    fn test_from_errno_unknown() {
        let e = SysError::from_errno(999);
        assert!(matches!(e, SysError::SyscallFailed { errno: 999, .. }));
    }

    #[test]
    fn test_display_permission() {
        let e = SysError::PermissionDenied {
            operation: "mount".into(),
        };
        assert!(e.to_string().contains("permission denied"));
        assert!(e.to_string().contains("mount"));
    }

    #[test]
    fn test_display_module() {
        let e = SysError::ModuleNotLoaded {
            module: "tpm_tis".into(),
        };
        assert!(e.to_string().contains("tpm_tis"));
    }

    #[test]
    fn test_display_not_supported() {
        let e = SysError::NotSupported {
            feature: "landlock".into(),
        };
        assert!(e.to_string().contains("landlock"));
    }

    #[test]
    fn test_result_alias() {
        let ok: Result<i32> = Ok(42);
        assert!(ok.is_ok());
    }

    #[test]
    fn test_io_error_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let e: SysError = io_err.into();
        assert!(matches!(e, SysError::Io(_)));
    }
}
