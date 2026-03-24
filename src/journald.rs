//! journald — Systemd journal interface.
//!
//! Send structured log entries to the systemd journal via the native
//! journal socket protocol, and query journal metadata.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::journald;
//!
//! // Send a structured log entry
//! journald::send(&[
//!     ("MESSAGE", "Service started"),
//!     ("PRIORITY", "6"),
//!     ("SYSLOG_IDENTIFIER", "my-agent"),
//! ]).unwrap();
//!
//! // Check journal availability
//! assert!(journald::is_available());
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;
use std::path::{Path, PathBuf};

// ── Constants ───────────────────────────────────────────────────────

const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";
const JOURNAL_DIR: &str = "/var/log/journal";
const JOURNAL_RUNTIME_DIR: &str = "/run/log/journal";

// ── Journal sending ─────────────────────────────────────────────────

/// Send a structured log entry to the systemd journal.
///
/// Each entry is a slice of `(key, value)` pairs. Keys must be uppercase
/// and contain only `[A-Z0-9_]`. The `MESSAGE` key is required by convention.
///
/// Uses the native journal socket protocol (datagram to `/run/systemd/journal/socket`).
pub fn send(fields: &[(&str, &str)]) -> Result<()> {
    let mut payload = Vec::new();
    for (key, value) in fields {
        // Journal protocol: KEY=VALUE\n for single-line values
        // For multi-line: KEY\n<u64 LE length><raw bytes>\n
        if value.contains('\n') {
            payload.extend_from_slice(key.as_bytes());
            payload.push(b'\n');
            let len_bytes = (value.len() as u64).to_le_bytes();
            payload.extend_from_slice(&len_bytes);
            payload.extend_from_slice(value.as_bytes());
            payload.push(b'\n');
        } else {
            payload.extend_from_slice(key.as_bytes());
            payload.push(b'=');
            payload.extend_from_slice(value.as_bytes());
            payload.push(b'\n');
        }
    }

    send_raw(&payload)
}

/// Send a simple message to the journal with a given priority.
///
/// Priority levels: 0=emerg, 1=alert, 2=crit, 3=err, 4=warning, 5=notice, 6=info, 7=debug
pub fn send_message(message: &str, priority: u8, identifier: &str) -> Result<()> {
    let pri = priority.min(7).to_string();
    send(&[
        ("MESSAGE", message),
        ("PRIORITY", &pri),
        ("SYSLOG_IDENTIFIER", identifier),
    ])
}

/// Send raw journal protocol bytes to the socket.
fn send_raw(data: &[u8]) -> Result<()> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        let err = SysError::last_os_error();
        tracing::error!("failed to create journal socket");
        return Err(err);
    }

    let c_path = std::ffi::CString::new(JOURNAL_SOCKET)
        .map_err(|_| SysError::InvalidArgument(Cow::Borrowed("socket path error")))?;

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_bytes = c_path.as_bytes_with_nul();
    let copy_len = path_bytes.len().min(addr.sun_path.len());
    for (i, &b) in path_bytes[..copy_len].iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }

    let sent = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    unsafe { libc::close(fd) };

    if sent < 0 {
        let err = SysError::last_os_error();
        tracing::error!("journal sendto failed");
        Err(err)
    } else {
        tracing::trace!(bytes = sent, "sent journal entry");
        Ok(())
    }
}

// ── Journal status ──────────────────────────────────────────────────

/// Check if the systemd journal socket is available.
#[must_use]
pub fn is_available() -> bool {
    Path::new(JOURNAL_SOCKET).exists()
}

/// Check if persistent journal storage exists.
#[must_use]
pub fn has_persistent_storage() -> bool {
    Path::new(JOURNAL_DIR).is_dir()
}

/// Check if volatile (runtime) journal storage exists.
#[must_use]
pub fn has_volatile_storage() -> bool {
    Path::new(JOURNAL_RUNTIME_DIR).is_dir()
}

/// Get the persistent journal directory path.
#[inline]
#[must_use]
pub fn journal_dir() -> &'static Path {
    Path::new(JOURNAL_DIR)
}

/// Get the runtime journal directory path.
#[inline]
#[must_use]
pub fn runtime_dir() -> &'static Path {
    Path::new(JOURNAL_RUNTIME_DIR)
}

// ── Journal metadata ────────────────────────────────────────────────

/// Get the machine ID (used as journal subdirectory name).
pub fn machine_id() -> Result<String> {
    std::fs::read_to_string("/etc/machine-id")
        .map(|s| s.trim().to_owned())
        .map_err(|e| {
            tracing::debug!(error = %e, "failed to read machine-id");
            SysError::Io(e)
        })
}

/// List journal files in the persistent storage directory.
pub fn list_journal_files() -> Result<Vec<PathBuf>> {
    let mid = machine_id()?;
    let dir = Path::new(JOURNAL_DIR).join(&mid);

    if !dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| {
        tracing::error!(dir = %dir.display(), error = %e, "failed to read journal dir");
        SysError::Io(e)
    })?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|ext| ext == "journal" || ext == "journal~")
        {
            files.push(path);
        }
    }

    files.sort();
    tracing::trace!(count = files.len(), "listed journal files");
    Ok(files)
}

/// Estimate total journal disk usage in bytes.
pub fn disk_usage() -> Result<u64> {
    let files = list_journal_files()?;
    let mut total: u64 = 0;
    for f in &files {
        if let Ok(meta) = std::fs::metadata(f) {
            total += meta.len();
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    // No custom types requiring Send+Sync (all functions)

    // ── is_available ────────────────────────────────────────────────

    #[test]
    fn is_available_returns_bool() {
        let _ = is_available();
    }

    #[test]
    fn has_persistent_storage_returns_bool() {
        let _ = has_persistent_storage();
    }

    #[test]
    fn has_volatile_storage_returns_bool() {
        let _ = has_volatile_storage();
    }

    // ── Paths ───────────────────────────────────────────────────────

    #[test]
    fn journal_dir_correct() {
        assert_eq!(journal_dir(), Path::new("/var/log/journal"));
    }

    #[test]
    fn runtime_dir_correct() {
        assert_eq!(runtime_dir(), Path::new("/run/log/journal"));
    }

    // ── machine_id ──────────────────────────────────────────────────

    #[test]
    fn machine_id_returns_result() {
        let _ = machine_id();
    }

    #[test]
    fn machine_id_format() {
        if let Ok(mid) = machine_id() {
            // Machine ID is 32 hex chars
            assert_eq!(mid.len(), 32);
            assert!(mid.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    // ── Journal files ───────────────────────────────────────────────

    #[test]
    fn list_journal_files_returns_result() {
        let _ = list_journal_files();
    }

    #[test]
    fn list_journal_files_sorted() {
        if let Ok(files) = list_journal_files() {
            for window in files.windows(2) {
                assert!(window[0] <= window[1]);
            }
        }
    }

    #[test]
    fn disk_usage_returns_result() {
        let _ = disk_usage();
    }

    // ── send ────────────────────────────────────────────────────────

    #[test]
    fn send_returns_result() {
        // May fail if journal socket not available
        let _ = send(&[("MESSAGE", "agnosys test"), ("PRIORITY", "7")]);
    }

    #[test]
    fn send_message_returns_result() {
        let _ = send_message("agnosys unit test", 7, "agnosys-test");
    }

    // ── Conditional: systemd system ─────────────────────────────────

    #[test]
    fn send_on_systemd() {
        if !is_available() {
            return;
        }
        // This actually sends to the journal — priority 7 = debug
        let result = send(&[
            ("MESSAGE", "agnosys integration test"),
            ("PRIORITY", "7"),
            ("SYSLOG_IDENTIFIER", "agnosys-test"),
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn send_multiline_value() {
        if !is_available() {
            return;
        }
        let result = send(&[
            ("MESSAGE", "line1\nline2\nline3"),
            ("PRIORITY", "7"),
            ("SYSLOG_IDENTIFIER", "agnosys-test"),
        ]);
        assert!(result.is_ok());
    }
}
