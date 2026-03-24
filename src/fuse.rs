//! fuse — Filesystem in Userspace.
//!
//! Low-level FUSE protocol implementation over `/dev/fuse`. Open a FUSE
//! session, read kernel requests, and write replies. This is the raw
//! protocol layer — higher-level filesystem abstractions belong in ark.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::fuse;
//!
//! let dev = fuse::FuseDev::open().unwrap();
//! println!("FUSE fd: {}", dev.as_raw_fd());
//! // Mount with: mount -t fuse -o fd=N,rootmode=40000,user_id=1000 none /mnt
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

// ── FUSE protocol constants ─────────────────────────────────────────

const FUSE_DEV_PATH: &str = "/dev/fuse";

/// FUSE kernel protocol version.
pub const FUSE_KERNEL_VERSION: u32 = 7;
/// FUSE kernel minor version (we target 7.31+).
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 31;

// FUSE opcodes
const FUSE_LOOKUP: u32 = 1;
const FUSE_FORGET: u32 = 2;
const FUSE_GETATTR: u32 = 3;
const FUSE_SETATTR: u32 = 4;
const FUSE_READLINK: u32 = 5;
const FUSE_OPEN: u32 = 14;
const FUSE_READ: u32 = 15;
const FUSE_WRITE: u32 = 16;
const FUSE_RELEASE: u32 = 18;
const FUSE_OPENDIR: u32 = 27;
const FUSE_READDIR: u32 = 28;
const FUSE_RELEASEDIR: u32 = 29;
const FUSE_INIT: u32 = 26;
const FUSE_DESTROY: u32 = 38;

/// Default read buffer size for FUSE requests.
const FUSE_MIN_READ_BUFFER: usize = 8192 + 4096;

// ── FUSE protocol structures ────────────────────────────────────────

/// FUSE request header (from kernel to userspace).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub padding: u32,
}

/// FUSE reply header (from userspace to kernel).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseOutHeader {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

/// FUSE init request body.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

/// FUSE init reply body.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseInitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
    pub flags2: u32,
    pub unused: [u32; 7],
}

// ── Public types ────────────────────────────────────────────────────

/// FUSE operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FuseOp {
    Init,
    Destroy,
    Lookup,
    Forget,
    GetAttr,
    SetAttr,
    ReadLink,
    Open,
    Read,
    Write,
    Release,
    OpenDir,
    ReadDir,
    ReleaseDir,
    Other(u32),
}

impl FuseOp {
    /// Classify a raw FUSE opcode.
    #[must_use]
    pub fn from_opcode(op: u32) -> Self {
        match op {
            FUSE_INIT => Self::Init,
            FUSE_DESTROY => Self::Destroy,
            FUSE_LOOKUP => Self::Lookup,
            FUSE_FORGET => Self::Forget,
            FUSE_GETATTR => Self::GetAttr,
            FUSE_SETATTR => Self::SetAttr,
            FUSE_READLINK => Self::ReadLink,
            FUSE_OPEN => Self::Open,
            FUSE_READ => Self::Read,
            FUSE_WRITE => Self::Write,
            FUSE_RELEASE => Self::Release,
            FUSE_OPENDIR => Self::OpenDir,
            FUSE_READDIR => Self::ReadDir,
            FUSE_RELEASEDIR => Self::ReleaseDir,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for FuseOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init => write!(f, "INIT"),
            Self::Destroy => write!(f, "DESTROY"),
            Self::Lookup => write!(f, "LOOKUP"),
            Self::Forget => write!(f, "FORGET"),
            Self::GetAttr => write!(f, "GETATTR"),
            Self::SetAttr => write!(f, "SETATTR"),
            Self::ReadLink => write!(f, "READLINK"),
            Self::Open => write!(f, "OPEN"),
            Self::Read => write!(f, "READ"),
            Self::Write => write!(f, "WRITE"),
            Self::Release => write!(f, "RELEASE"),
            Self::OpenDir => write!(f, "OPENDIR"),
            Self::ReadDir => write!(f, "READDIR"),
            Self::ReleaseDir => write!(f, "RELEASEDIR"),
            Self::Other(op) => write!(f, "UNKNOWN({op})"),
        }
    }
}

/// A raw FUSE request read from the kernel.
#[derive(Debug)]
pub struct FuseRequest {
    /// The request header.
    pub header: FuseInHeader,
    /// The raw request body (after the header).
    pub body: Vec<u8>,
}

impl FuseRequest {
    /// The FUSE operation type.
    #[inline]
    #[must_use]
    pub fn op(&self) -> FuseOp {
        FuseOp::from_opcode(self.header.opcode)
    }

    /// The unique request ID (for matching replies).
    #[inline]
    #[must_use]
    pub fn unique(&self) -> u64 {
        self.header.unique
    }

    /// The inode number this request targets.
    #[inline]
    #[must_use]
    pub fn nodeid(&self) -> u64 {
        self.header.nodeid
    }
}

// ── FUSE device ─────────────────────────────────────────────────────

/// Handle to an open `/dev/fuse` device.
pub struct FuseDev {
    fd: OwnedFd,
}

impl FuseDev {
    /// Open `/dev/fuse`.
    pub fn open() -> Result<Self> {
        let fd = unsafe { libc::open(c"/dev/fuse".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            let err = SysError::last_os_error();
            tracing::error!("failed to open /dev/fuse");
            return Err(err);
        }
        tracing::debug!(fd, "opened /dev/fuse");
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Get the raw file descriptor (for passing to mount as `fd=N`).
    #[inline]
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Read the next FUSE request from the kernel.
    ///
    /// Blocks until a request is available. Returns `None` on clean shutdown.
    pub fn read_request(&self) -> Result<Option<FuseRequest>> {
        let mut buf = vec![0u8; FUSE_MIN_READ_BUFFER];
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };

        if n < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::ENODEV {
                // Filesystem was unmounted
                return Ok(None);
            }
            return Err(SysError::from_errno(errno));
        }

        let n = n as usize;
        if n < std::mem::size_of::<FuseInHeader>() {
            return Err(SysError::InvalidArgument(Cow::Borrowed(
                "FUSE read too short for header",
            )));
        }

        let header: FuseInHeader =
            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const FuseInHeader) };

        let body_start = std::mem::size_of::<FuseInHeader>();
        let body = buf[body_start..n].to_vec();

        tracing::trace!(
            opcode = header.opcode,
            unique = header.unique,
            nodeid = header.nodeid,
            "read FUSE request"
        );

        Ok(Some(FuseRequest { header, body }))
    }

    /// Write a raw FUSE reply to the kernel.
    pub fn write_reply(&self, unique: u64, error: i32, data: &[u8]) -> Result<()> {
        let header = FuseOutHeader {
            len: (std::mem::size_of::<FuseOutHeader>() + data.len()) as u32,
            error,
            unique,
        };

        let header_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &header as *const FuseOutHeader as *const u8,
                std::mem::size_of::<FuseOutHeader>(),
            )
        };

        // Combine header + data into one write (kernel expects atomic write)
        let mut reply = Vec::with_capacity(header_bytes.len() + data.len());
        reply.extend_from_slice(header_bytes);
        reply.extend_from_slice(data);

        let n = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                reply.as_ptr() as *const libc::c_void,
                reply.len(),
            )
        };

        if n < 0 {
            let errno = unsafe { *libc::__errno_location() };
            tracing::error!(errno, unique, "FUSE write reply failed");
            Err(SysError::from_errno(errno))
        } else {
            tracing::trace!(unique, len = reply.len(), "wrote FUSE reply");
            Ok(())
        }
    }

    /// Send an error reply for a FUSE request.
    #[inline]
    pub fn reply_error(&self, unique: u64, errno: i32) -> Result<()> {
        self.write_reply(unique, -errno, &[])
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Check if FUSE is available on this system.
#[must_use]
pub fn is_available() -> bool {
    Path::new(FUSE_DEV_PATH).exists()
}

/// List active FUSE mount points from `/proc/self/mountinfo`.
pub fn list_mounts() -> Result<Vec<FuseMount>> {
    let content = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| {
        tracing::error!(error = %e, "failed to read mountinfo");
        SysError::Io(e)
    })?;

    let mounts: Vec<FuseMount> = content
        .lines()
        .filter(|l| l.contains("fuse"))
        .filter_map(parse_fuse_mount)
        .collect();

    tracing::trace!(count = mounts.len(), "listed FUSE mounts");
    Ok(mounts)
}

/// An active FUSE mount point.
#[derive(Debug, Clone)]
pub struct FuseMount {
    /// Mount point path.
    pub mount_point: String,
    /// Filesystem type (e.g., "fuse.sshfs", "fuse.ntfs-3g").
    pub fs_type: String,
    /// Mount source.
    pub source: String,
}

fn parse_fuse_mount(line: &str) -> Option<FuseMount> {
    // mountinfo format: id parent major:minor root mount_point options - fstype source options
    let parts: Vec<&str> = line.split(' ').collect();
    let sep_idx = parts.iter().position(|&p| p == "-")?;
    if sep_idx + 2 >= parts.len() {
        return None;
    }
    let mount_point = parts.get(4)?.to_string();
    let fs_type = parts.get(sep_idx + 1)?.to_string();
    let source = parts.get(sep_idx + 2)?.to_string();

    if !fs_type.contains("fuse") {
        return None;
    }

    Some(FuseMount {
        mount_point,
        fs_type,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FuseDev>();
        assert_send_sync::<FuseRequest>();
        assert_send_sync::<FuseOp>();
        assert_send_sync::<FuseInHeader>();
        assert_send_sync::<FuseOutHeader>();
        assert_send_sync::<FuseMount>();
    };

    // ── FuseOp ──────────────────────────────────────────────────────

    #[test]
    fn fuse_op_from_opcode_all() {
        assert_eq!(FuseOp::from_opcode(FUSE_INIT), FuseOp::Init);
        assert_eq!(FuseOp::from_opcode(FUSE_DESTROY), FuseOp::Destroy);
        assert_eq!(FuseOp::from_opcode(FUSE_LOOKUP), FuseOp::Lookup);
        assert_eq!(FuseOp::from_opcode(FUSE_FORGET), FuseOp::Forget);
        assert_eq!(FuseOp::from_opcode(FUSE_GETATTR), FuseOp::GetAttr);
        assert_eq!(FuseOp::from_opcode(FUSE_SETATTR), FuseOp::SetAttr);
        assert_eq!(FuseOp::from_opcode(FUSE_READLINK), FuseOp::ReadLink);
        assert_eq!(FuseOp::from_opcode(FUSE_OPEN), FuseOp::Open);
        assert_eq!(FuseOp::from_opcode(FUSE_READ), FuseOp::Read);
        assert_eq!(FuseOp::from_opcode(FUSE_WRITE), FuseOp::Write);
        assert_eq!(FuseOp::from_opcode(FUSE_RELEASE), FuseOp::Release);
        assert_eq!(FuseOp::from_opcode(FUSE_OPENDIR), FuseOp::OpenDir);
        assert_eq!(FuseOp::from_opcode(FUSE_READDIR), FuseOp::ReadDir);
        assert_eq!(FuseOp::from_opcode(FUSE_RELEASEDIR), FuseOp::ReleaseDir);
        assert_eq!(FuseOp::from_opcode(9999), FuseOp::Other(9999));
    }

    #[test]
    fn fuse_op_display() {
        assert_eq!(format!("{}", FuseOp::Init), "INIT");
        assert_eq!(format!("{}", FuseOp::Read), "READ");
        assert_eq!(format!("{}", FuseOp::Other(42)), "UNKNOWN(42)");
    }

    #[test]
    fn fuse_op_debug() {
        let dbg = format!("{:?}", FuseOp::Init);
        assert!(dbg.contains("Init"));
    }

    #[test]
    fn fuse_op_eq() {
        assert_eq!(FuseOp::Init, FuseOp::Init);
        assert_ne!(FuseOp::Init, FuseOp::Read);
        assert_eq!(FuseOp::Other(5), FuseOp::Other(5));
    }

    #[test]
    fn fuse_op_copy() {
        let a = FuseOp::Read;
        let b = a;
        assert_eq!(a, b);
    }

    // ── FuseInHeader ────────────────────────────────────────────────

    #[test]
    fn fuse_in_header_default() {
        let h = FuseInHeader::default();
        assert_eq!(h.len, 0);
        assert_eq!(h.opcode, 0);
        assert_eq!(h.unique, 0);
    }

    #[test]
    fn fuse_in_header_size() {
        assert_eq!(std::mem::size_of::<FuseInHeader>(), 40);
    }

    // ── FuseOutHeader ───────────────────────────────────────────────

    #[test]
    fn fuse_out_header_default() {
        let h = FuseOutHeader::default();
        assert_eq!(h.len, 0);
        assert_eq!(h.error, 0);
        assert_eq!(h.unique, 0);
    }

    #[test]
    fn fuse_out_header_size() {
        assert_eq!(std::mem::size_of::<FuseOutHeader>(), 16);
    }

    // ── is_available ────────────────────────────────────────────────

    #[test]
    fn fuse_is_available() {
        let _ = is_available();
    }

    // ── list_mounts ─────────────────────────────────────────────────

    #[test]
    fn list_mounts_returns_result() {
        let _ = list_mounts();
    }

    // ── FuseDev ─────────────────────────────────────────────────────

    #[test]
    fn fuse_dev_open_returns_result() {
        // May fail without /dev/fuse access
        let _ = FuseDev::open();
    }

    // ── FuseMount ───────────────────────────────────────────────────

    #[test]
    fn fuse_mount_debug() {
        let m = FuseMount {
            mount_point: "/mnt/test".into(),
            fs_type: "fuse.sshfs".into(),
            source: "user@host:".into(),
        };
        let dbg = format!("{m:?}");
        assert!(dbg.contains("sshfs"));
    }

    #[test]
    fn fuse_mount_clone() {
        let m = FuseMount {
            mount_point: "/mnt".into(),
            fs_type: "fuse".into(),
            source: "none".into(),
        };
        let m2 = m.clone();
        assert_eq!(m.mount_point, m2.mount_point);
    }

    // ── parse_fuse_mount ────────────────────────────────────────────

    #[test]
    fn parse_fuse_mount_valid() {
        let line = "42 1 0:38 / /mnt/sshfs rw,nosuid - fuse.sshfs user@host: rw";
        let m = parse_fuse_mount(line).unwrap();
        assert_eq!(m.mount_point, "/mnt/sshfs");
        assert_eq!(m.fs_type, "fuse.sshfs");
        assert_eq!(m.source, "user@host:");
    }

    #[test]
    fn parse_fuse_mount_not_fuse() {
        let line = "1 0 8:1 / / rw - ext4 /dev/sda1 rw";
        assert!(parse_fuse_mount(line).is_none());
    }

    #[test]
    fn parse_fuse_mount_no_separator() {
        assert!(parse_fuse_mount("no separator here").is_none());
    }

    // ── FuseRequest ─────────────────────────────────────────────────

    #[test]
    fn fuse_request_accessors() {
        let req = FuseRequest {
            header: FuseInHeader {
                len: 40,
                opcode: FUSE_GETATTR,
                unique: 42,
                nodeid: 1,
                uid: 1000,
                gid: 1000,
                pid: 1234,
                padding: 0,
            },
            body: vec![],
        };
        assert_eq!(req.op(), FuseOp::GetAttr);
        assert_eq!(req.unique(), 42);
        assert_eq!(req.nodeid(), 1);
    }

    // ── Protocol constants ──────────────────────────────────────────

    #[test]
    fn fuse_protocol_version() {
        assert_eq!(FUSE_KERNEL_VERSION, 7);
        let minor = FUSE_KERNEL_MINOR_VERSION;
        assert!(minor >= 31);
    }
}
