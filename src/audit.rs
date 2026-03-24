//! audit — Kernel audit subsystem.
//!
//! Interface to the Linux kernel audit system via the netlink AUDIT protocol.
//! Read audit events, manage audit rules, and query audit status.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::audit;
//!
//! let status = audit::get_status().unwrap();
//! println!("audit enabled: {}", status.enabled);
//! println!("pid: {}", status.pid);
//! println!("lost: {}", status.lost);
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;

// ── Netlink audit constants ─────────────────────────────────────────

/// Netlink protocol for audit.
const NETLINK_AUDIT: libc::c_int = 9;

// Audit message types (public for consumers who need raw type matching)
/// Audit GET status request.
pub const AUDIT_GET: u16 = 1000;
/// Audit SET status request.
pub const AUDIT_SET: u16 = 1001;
/// Audit list rules request.
pub const AUDIT_LIST_RULES: u16 = 1013;
/// First user-space audit message type.
pub const AUDIT_FIRST_USER_MSG: u16 = 1100;
/// Syscall audit record.
pub const AUDIT_SYSCALL: u16 = 1300;
/// File path audit record.
pub const AUDIT_PATH: u16 = 1302;
/// Current working directory audit record.
pub const AUDIT_CWD: u16 = 1307;
/// Execve arguments audit record.
pub const AUDIT_EXECVE: u16 = 1309;

// Netlink header
const NLMSG_HDRLEN: usize = 16;

// ── Kernel structures ───────────────────────────────────────────────

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct AuditStatus {
    mask: u32,
    enabled: u32,
    failure: u32,
    pid: u32,
    rate_limit: u32,
    backlog_limit: u32,
    lost: u32,
    backlog: u32,
    // kernel 3.12+ fields
    version: u32,
    backlog_wait_time: u32,
}

#[repr(C)]
#[derive(Default)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

// ── Public types ────────────────────────────────────────────────────

/// Audit subsystem status.
#[derive(Debug, Clone)]
pub struct Status {
    /// Whether audit is enabled (1 = enabled, 0 = disabled, 2 = locked).
    pub enabled: u32,
    /// PID of the audit daemon (0 if no daemon).
    pub pid: u32,
    /// Number of lost audit records.
    pub lost: u32,
    /// Current backlog count.
    pub backlog: u32,
    /// Backlog limit.
    pub backlog_limit: u32,
    /// Rate limit (messages per second, 0 = unlimited).
    pub rate_limit: u32,
    /// Failure mode (0=silent, 1=printk, 2=panic).
    pub failure: u32,
}

/// A parsed audit event message.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// The audit message type.
    pub msg_type: AuditMsgType,
    /// Raw message data.
    pub data: String,
    /// Sequence number.
    pub seq: u32,
}

/// Audit message type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditMsgType {
    /// Syscall audit record.
    Syscall,
    /// Current working directory.
    Cwd,
    /// File path accessed.
    Path,
    /// Execve arguments.
    Execve,
    /// User-space audit message.
    User,
    /// Status query response.
    StatusReply,
    /// Rule listing response.
    RuleList,
    /// Other/unknown message type.
    Other(u16),
}

impl AuditMsgType {
    /// Classify a raw audit message type number.
    #[must_use]
    pub fn from_raw(t: u16) -> Self {
        match t {
            AUDIT_SYSCALL => Self::Syscall,
            AUDIT_CWD => Self::Cwd,
            AUDIT_PATH => Self::Path,
            AUDIT_EXECVE => Self::Execve,
            AUDIT_GET => Self::StatusReply,
            AUDIT_LIST_RULES => Self::RuleList,
            t if (AUDIT_FIRST_USER_MSG..AUDIT_SYSCALL).contains(&t) => Self::User,
            other => Self::Other(other),
        }
    }
}

// ── Audit socket ────────────────────────────────────────────────────

/// A handle to the kernel audit netlink socket.
pub struct AuditSocket {
    fd: std::os::fd::OwnedFd,
    seq: u32,
}

impl AuditSocket {
    /// Open a netlink audit socket.
    ///
    /// Requires `CAP_AUDIT_READ` or `CAP_AUDIT_CONTROL` for most operations.
    pub fn new() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                NETLINK_AUDIT,
            )
        };
        if fd < 0 {
            let err = SysError::last_os_error();
            tracing::error!("failed to create audit netlink socket");
            return Err(err);
        }

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = 0;
        addr.nl_pid = 0; // kernel assigns

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = SysError::last_os_error();
            unsafe { libc::close(fd) };
            tracing::error!("failed to bind audit netlink socket");
            return Err(err);
        }

        tracing::debug!(fd, "opened audit netlink socket");
        Ok(Self {
            fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
            seq: 1,
        })
    }

    /// Send an audit netlink message and receive the response.
    fn send_recv(&mut self, msg_type: u16, data: &[u8]) -> Result<Vec<u8>> {
        use std::os::fd::AsRawFd;

        let total_len = NLMSG_HDRLEN + data.len();
        let mut buf = vec![0u8; total_len];

        // Build nlmsghdr
        let hdr = NlMsgHdr {
            nlmsg_len: total_len as u32,
            nlmsg_type: msg_type,
            nlmsg_flags: 0x01, // NLM_F_REQUEST
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };
        self.seq += 1;

        // Copy header
        let hdr_bytes: [u8; NLMSG_HDRLEN] = unsafe { std::mem::transmute(hdr) };
        buf[..NLMSG_HDRLEN].copy_from_slice(&hdr_bytes);
        buf[NLMSG_HDRLEN..].copy_from_slice(data);

        // Send
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
            )
        };
        if sent < 0 {
            let err = SysError::last_os_error();
            tracing::error!(msg_type, "audit netlink send failed");
            return Err(err);
        }

        // Receive response
        let mut resp_buf = vec![0u8; 8192];
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                resp_buf.as_mut_ptr() as *mut libc::c_void,
                resp_buf.len(),
                0,
            )
        };
        if n < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                return Ok(Vec::new());
            }
            return Err(SysError::from_errno(errno));
        }
        resp_buf.truncate(n as usize);
        Ok(resp_buf)
    }

    /// Query current audit status.
    pub fn get_status(&mut self) -> Result<Status> {
        let data = vec![0u8; std::mem::size_of::<AuditStatus>()];
        let resp = self.send_recv(AUDIT_GET, &data)?;

        if resp.len() < NLMSG_HDRLEN + std::mem::size_of::<AuditStatus>() {
            return Err(SysError::InvalidArgument(Cow::Borrowed(
                "audit status response too short",
            )));
        }

        let status: AuditStatus =
            unsafe { std::ptr::read(resp[NLMSG_HDRLEN..].as_ptr() as *const AuditStatus) };

        tracing::trace!(
            enabled = status.enabled,
            pid = status.pid,
            lost = status.lost,
            "queried audit status"
        );

        Ok(Status {
            enabled: status.enabled,
            pid: status.pid,
            lost: status.lost,
            backlog: status.backlog,
            backlog_limit: status.backlog_limit,
            rate_limit: status.rate_limit,
            failure: status.failure,
        })
    }

    /// Get the raw file descriptor for polling.
    #[inline]
    #[must_use]
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.fd.as_raw_fd()
    }
}

use std::os::fd::FromRawFd;

// ── Convenience functions ───────────────────────────────────────────

/// Check if the audit subsystem is available.
pub fn is_available() -> bool {
    AuditSocket::new().is_ok()
}

/// Query audit status (convenience wrapper).
pub fn get_status() -> Result<Status> {
    let mut sock = AuditSocket::new()?;
    sock.get_status()
}

/// Read the audit log from `/var/log/audit/audit.log` if accessible.
pub fn read_log_tail(lines: usize) -> Result<Vec<String>> {
    let log_path = "/var/log/audit/audit.log";
    let content = std::fs::read_to_string(log_path).map_err(|e| {
        tracing::debug!(error = %e, "failed to read audit log");
        SysError::Io(e)
    })?;

    let result: Vec<String> = content
        .lines()
        .rev()
        .take(lines)
        .map(|s| s.to_owned())
        .collect();

    tracing::trace!(count = result.len(), "read audit log tail");
    Ok(result)
}

/// Parse a raw audit message line into key=value pairs.
#[must_use]
pub fn parse_audit_line(line: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();

    // Skip the "type=XXXX msg=audit(timestamp:serial):" prefix
    let body = if let Some(pos) = line.find("): ") {
        &line[pos + 3..]
    } else {
        line
    };

    // Parse key=value pairs (some values may be quoted)
    let mut chars = body.chars().peekable();
    while chars.peek().is_some() {
        // Skip whitespace
        while chars.peek() == Some(&' ') {
            chars.next();
        }

        // Read key
        let key: String = chars.by_ref().take_while(|&c| c != '=').collect();
        if key.is_empty() {
            break;
        }

        // Read value
        let value = if chars.peek() == Some(&'"') {
            chars.next(); // skip opening quote
            let v: String = chars.by_ref().take_while(|&c| c != '"').collect();
            v
        } else {
            chars.by_ref().take_while(|&c| c != ' ').collect()
        };

        map.insert(key, value);
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Status>();
        assert_send_sync::<AuditEvent>();
        assert_send_sync::<AuditMsgType>();
        assert_send_sync::<AuditSocket>();
    };

    // ── AuditMsgType ────────────────────────────────────────────────

    #[test]
    fn msg_type_from_raw() {
        assert_eq!(AuditMsgType::from_raw(AUDIT_SYSCALL), AuditMsgType::Syscall);
        assert_eq!(AuditMsgType::from_raw(AUDIT_CWD), AuditMsgType::Cwd);
        assert_eq!(AuditMsgType::from_raw(AUDIT_PATH), AuditMsgType::Path);
        assert_eq!(AuditMsgType::from_raw(AUDIT_EXECVE), AuditMsgType::Execve);
        assert_eq!(AuditMsgType::from_raw(AUDIT_GET), AuditMsgType::StatusReply);
        assert_eq!(
            AuditMsgType::from_raw(AUDIT_LIST_RULES),
            AuditMsgType::RuleList
        );
        assert_eq!(
            AuditMsgType::from_raw(AUDIT_FIRST_USER_MSG),
            AuditMsgType::User
        );
    }

    #[test]
    fn msg_type_other() {
        assert_eq!(AuditMsgType::from_raw(9999), AuditMsgType::Other(9999));
    }

    #[test]
    fn msg_type_debug() {
        let dbg = format!("{:?}", AuditMsgType::Syscall);
        assert!(dbg.contains("Syscall"));
    }

    #[test]
    fn msg_type_eq() {
        assert_eq!(AuditMsgType::Syscall, AuditMsgType::Syscall);
        assert_ne!(AuditMsgType::Syscall, AuditMsgType::Cwd);
        assert_eq!(AuditMsgType::Other(5), AuditMsgType::Other(5));
    }

    #[test]
    fn msg_type_copy() {
        let a = AuditMsgType::Syscall;
        let b = a;
        assert_eq!(a, b);
    }

    // ── is_available ────────────────────────────────────────────────

    #[test]
    fn audit_is_available_returns_bool() {
        let _ = is_available();
    }

    // ── AuditSocket ─────────────────────────────────────────────────

    #[test]
    fn audit_socket_new() {
        // May fail without CAP_AUDIT_READ
        let _ = AuditSocket::new();
    }

    #[test]
    fn audit_socket_get_status() {
        let mut sock = match AuditSocket::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        // May fail without privileges
        let _ = sock.get_status();
    }

    #[test]
    fn audit_socket_raw_fd() {
        let sock = match AuditSocket::new() {
            Ok(s) => s,
            Err(_) => return,
        };
        assert!(sock.as_raw_fd() >= 0);
    }

    // ── parse_audit_line ────────────────────────────────────────────

    #[test]
    fn parse_simple_kv() {
        let map = parse_audit_line("key1=val1 key2=val2");
        assert_eq!(map.get("key1").unwrap(), "val1");
        assert_eq!(map.get("key2").unwrap(), "val2");
    }

    #[test]
    fn parse_quoted_values() {
        let map = parse_audit_line(r#"cmd="ls -la" path="/etc/passwd""#);
        assert_eq!(map.get("cmd").unwrap(), "ls -la");
        assert_eq!(map.get("path").unwrap(), "/etc/passwd");
    }

    #[test]
    fn parse_with_prefix() {
        let line =
            "type=SYSCALL msg=audit(1234567890.123:42): arch=c000003e syscall=59 success=yes";
        let map = parse_audit_line(line);
        assert_eq!(map.get("arch").unwrap(), "c000003e");
        assert_eq!(map.get("syscall").unwrap(), "59");
        assert_eq!(map.get("success").unwrap(), "yes");
    }

    #[test]
    fn parse_empty_line() {
        let map = parse_audit_line("");
        assert!(map.is_empty());
    }

    // ── read_log_tail ───────────────────────────────────────────────

    #[test]
    fn read_log_tail_returns_result() {
        // May fail without read access to audit log
        let _ = read_log_tail(10);
    }

    // ── Status ──────────────────────────────────────────────────────

    #[test]
    fn status_debug() {
        let s = Status {
            enabled: 1,
            pid: 42,
            lost: 0,
            backlog: 0,
            backlog_limit: 8192,
            rate_limit: 0,
            failure: 1,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("enabled"));
        assert!(dbg.contains("42"));
    }

    #[test]
    fn status_clone() {
        let s = Status {
            enabled: 1,
            pid: 0,
            lost: 5,
            backlog: 0,
            backlog_limit: 0,
            rate_limit: 0,
            failure: 0,
        };
        let s2 = s.clone();
        assert_eq!(s.enabled, s2.enabled);
        assert_eq!(s.lost, s2.lost);
    }

    // ── AuditEvent ──────────────────────────────────────────────────

    #[test]
    fn audit_event_debug() {
        let e = AuditEvent {
            msg_type: AuditMsgType::Syscall,
            data: "test data".into(),
            seq: 1,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Syscall"));
        assert!(dbg.contains("test data"));
    }

    #[test]
    fn audit_event_clone() {
        let e = AuditEvent {
            msg_type: AuditMsgType::Path,
            data: "path".into(),
            seq: 42,
        };
        let e2 = e.clone();
        assert_eq!(e.seq, e2.seq);
        assert_eq!(e.msg_type, e2.msg_type);
    }
}
