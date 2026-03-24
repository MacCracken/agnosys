//! update — Atomic system update primitives.
//!
//! Safe atomic file and directory operations for system updates.
//! Provides rename-based atomic replacement, fsync guarantees,
//! and directory synchronization for crash-safe updates.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::update;
//! use std::path::Path;
//!
//! // Atomically replace a file
//! update::atomic_write(Path::new("/etc/config.toml"), b"new content").unwrap();
//!
//! // Sync a directory to ensure metadata is persisted
//! update::sync_dir(Path::new("/etc")).unwrap();
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

// ── Atomic file operations ──────────────────────────────────────────

/// Atomically write data to a file using rename.
///
/// Writes to a temporary file in the same directory, fsyncs it,
/// then renames over the target. This ensures the file is either
/// the old content or the new content, never a partial write.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or(SysError::InvalidArgument(Cow::Borrowed(
            "path has no parent directory",
        )))?;

    let tmp_path = tmp_path_for(path);

    // Write to temp file
    std::fs::write(&tmp_path, data).map_err(|e| {
        tracing::error!(path = %tmp_path.display(), error = %e, "failed to write temp file");
        SysError::Io(e)
    })?;

    // Fsync the temp file
    fsync_file(&tmp_path)?;

    // Atomic rename
    std::fs::rename(&tmp_path, path).map_err(|e| {
        // Clean up temp file on failure
        let _ = std::fs::remove_file(&tmp_path);
        tracing::error!(
            src = %tmp_path.display(),
            dst = %path.display(),
            error = %e,
            "atomic rename failed"
        );
        SysError::Io(e)
    })?;

    // Fsync the directory to persist the rename
    sync_dir(dir)?;

    tracing::trace!(path = %path.display(), len = data.len(), "atomic write complete");
    Ok(())
}

/// Atomically replace a file by copying from a source path.
///
/// Same guarantees as [`atomic_write`] but reads from an existing file.
pub fn atomic_copy(src: &Path, dst: &Path) -> Result<()> {
    let data = std::fs::read(src).map_err(|e| {
        tracing::error!(src = %src.display(), error = %e, "failed to read source");
        SysError::Io(e)
    })?;
    atomic_write(dst, &data)
}

/// Atomically swap two files using a temporary intermediate.
///
/// After this operation, `a` has `b`'s old content and vice versa.
/// Uses `renameat2(RENAME_EXCHANGE)` if available, otherwise falls
/// back to a three-way rename.
pub fn atomic_swap(a: &Path, b: &Path) -> Result<()> {
    // Try renameat2 with RENAME_EXCHANGE first
    let c_a = std::ffi::CString::new(a.as_os_str().as_encoded_bytes())
        .map_err(|_| SysError::InvalidArgument(Cow::Borrowed("path contains null byte")))?;
    let c_b = std::ffi::CString::new(b.as_os_str().as_encoded_bytes())
        .map_err(|_| SysError::InvalidArgument(Cow::Borrowed("path contains null byte")))?;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            c_a.as_ptr(),
            libc::AT_FDCWD,
            c_b.as_ptr(),
            2u32, // RENAME_EXCHANGE
        )
    };

    if ret == 0 {
        tracing::trace!(a = %a.display(), b = %b.display(), "atomic swap via RENAME_EXCHANGE");
        // Sync both parent directories
        if let Some(dir) = a.parent() {
            let _ = sync_dir(dir);
        }
        if let Some(dir) = b.parent() {
            let _ = sync_dir(dir);
        }
        return Ok(());
    }

    // Fallback: three-way rename (not truly atomic but best effort)
    let tmp = tmp_path_for(a);
    std::fs::rename(a, &tmp).map_err(SysError::Io)?;
    if let Err(e) = std::fs::rename(b, a) {
        // Rollback
        let _ = std::fs::rename(&tmp, a);
        return Err(SysError::Io(e));
    }
    std::fs::rename(&tmp, b).map_err(SysError::Io)?;

    tracing::trace!(a = %a.display(), b = %b.display(), "atomic swap via three-way rename");
    Ok(())
}

// ── Sync operations ─────────────────────────────────────────────────

/// Fsync a file to ensure its contents are persisted to disk.
pub fn fsync_file(path: &Path) -> Result<()> {
    let file = std::fs::File::open(path).map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "failed to open for fsync");
        SysError::Io(e)
    })?;
    file.sync_all().map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "fsync failed");
        SysError::Io(e)
    })?;
    tracing::trace!(path = %path.display(), "fsync complete");
    Ok(())
}

/// Fsync a directory to ensure metadata (renames, creates) are persisted.
pub fn sync_dir(dir: &Path) -> Result<()> {
    let d = std::fs::File::open(dir).map_err(|e| {
        tracing::error!(dir = %dir.display(), error = %e, "failed to open dir for sync");
        SysError::Io(e)
    })?;
    // fsync on a directory fd syncs the directory entries
    let ret = unsafe { libc::fsync(d.as_raw_fd()) };
    if ret < 0 {
        let err = SysError::last_os_error();
        tracing::error!(dir = %dir.display(), "dir fsync failed");
        Err(err)
    } else {
        tracing::trace!(dir = %dir.display(), "dir sync complete");
        Ok(())
    }
}

/// Fdatasync a file (sync data but not necessarily metadata).
pub fn fdatasync_file(path: &Path) -> Result<()> {
    let file = std::fs::File::open(path).map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "failed to open for fdatasync");
        SysError::Io(e)
    })?;
    file.sync_data().map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "fdatasync failed");
        SysError::Io(e)
    })?;
    Ok(())
}

// ── Validation ──────────────────────────────────────────────────────

/// Check if a path is on a read-write filesystem.
pub fn is_writable(path: &Path) -> Result<bool> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| SysError::InvalidArgument(Cow::Borrowed("path contains null byte")))?;

    let ret = unsafe { libc::access(c_path.as_ptr(), libc::W_OK) };
    Ok(ret == 0)
}

/// Check if two paths are on the same filesystem (same device).
///
/// Atomic rename only works within a single filesystem.
pub fn same_filesystem(a: &Path, b: &Path) -> Result<bool> {
    let meta_a = std::fs::metadata(a).map_err(SysError::Io)?;
    let meta_b = std::fs::metadata(b).map_err(SysError::Io)?;

    use std::os::unix::fs::MetadataExt;
    Ok(meta_a.dev() == meta_b.dev())
}

// ── Internal helpers ────────────────────────────────────────────────

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".agnosys_tmp_{}", std::process::id()));
    PathBuf::from(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    // No custom types to assert Send+Sync on (all functions, no structs)

    // ── atomic_write ────────────────────────────────────────────────

    #[test]
    fn atomic_write_and_read_back() {
        let tmp = &format!("/tmp/agnosys_test_atomic_{}", std::process::id());
        let path = Path::new(tmp);
        atomic_write(path, b"hello atomic").unwrap();
        let content = std::fs::read_to_string(path).unwrap();
        assert_eq!(content, "hello atomic");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn atomic_write_overwrite() {
        let tmp = &format!("/tmp/agnosys_test_atomic_ow_{}", std::process::id());
        let path = Path::new(tmp);
        atomic_write(path, b"first").unwrap();
        atomic_write(path, b"second").unwrap();
        let content = std::fs::read_to_string(path).unwrap();
        assert_eq!(content, "second");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn atomic_write_no_parent() {
        // Root path has no parent
        let result = atomic_write(Path::new("/"), b"data");
        // This should fail because we can't write to /
        assert!(result.is_err());
    }

    // ── atomic_copy ─────────────────────────────────────────────────

    #[test]
    fn atomic_copy_round_trip() {
        let src = &format!("/tmp/agnosys_test_copy_src_{}", std::process::id());
        let dst = &format!("/tmp/agnosys_test_copy_dst_{}", std::process::id());
        std::fs::write(src, "copy me").unwrap();
        atomic_copy(Path::new(src), Path::new(dst)).unwrap();
        assert_eq!(std::fs::read_to_string(dst).unwrap(), "copy me");
        std::fs::remove_file(src).unwrap();
        std::fs::remove_file(dst).unwrap();
    }

    #[test]
    fn atomic_copy_nonexistent_src() {
        let result = atomic_copy(
            Path::new("/tmp/nonexistent_agnosys_src"),
            Path::new("/tmp/agnosys_copy_dst"),
        );
        assert!(result.is_err());
    }

    // ── fsync_file ──────────────────────────────────────────────────

    #[test]
    fn fsync_file_works() {
        let tmp = &format!("/tmp/agnosys_test_fsync_{}", std::process::id());
        std::fs::write(tmp, "sync me").unwrap();
        fsync_file(Path::new(tmp)).unwrap();
        std::fs::remove_file(tmp).unwrap();
    }

    #[test]
    fn fsync_file_nonexistent() {
        assert!(fsync_file(Path::new("/tmp/nonexistent_agnosys_fsync")).is_err());
    }

    // ── sync_dir ────────────────────────────────────────────────────

    #[test]
    fn sync_dir_tmp() {
        sync_dir(Path::new("/tmp")).unwrap();
    }

    #[test]
    fn sync_dir_nonexistent() {
        assert!(sync_dir(Path::new("/nonexistent_agnosys_dir")).is_err());
    }

    // ── fdatasync_file ──────────────────────────────────────────────

    #[test]
    fn fdatasync_works() {
        let tmp = &format!("/tmp/agnosys_test_fdata_{}", std::process::id());
        std::fs::write(tmp, "data sync").unwrap();
        fdatasync_file(Path::new(tmp)).unwrap();
        std::fs::remove_file(tmp).unwrap();
    }

    // ── is_writable ─────────────────────────────────────────────────

    #[test]
    fn is_writable_tmp() {
        assert!(is_writable(Path::new("/tmp")).unwrap());
    }

    #[test]
    fn is_writable_proc() {
        // /proc is not writable by normal users
        assert!(!is_writable(Path::new("/proc/1")).unwrap());
    }

    // ── same_filesystem ─────────────────────────────────────────────

    #[test]
    fn same_filesystem_true() {
        assert!(same_filesystem(Path::new("/tmp"), Path::new("/tmp")).unwrap());
    }

    #[test]
    fn same_filesystem_nonexistent() {
        assert!(same_filesystem(Path::new("/nonexistent_a"), Path::new("/nonexistent_b")).is_err());
    }

    // ── tmp_path_for ────────────────────────────────────────────────

    #[test]
    fn tmp_path_appends_suffix() {
        let p = tmp_path_for(Path::new("/etc/config.toml"));
        let s = p.to_string_lossy();
        assert!(s.starts_with("/etc/config.toml.agnosys_tmp_"));
    }

    // ── atomic_swap ─────────────────────────────────────────────────

    #[test]
    fn atomic_swap_files() {
        let a = &format!("/tmp/agnosys_test_swap_a_{}", std::process::id());
        let b = &format!("/tmp/agnosys_test_swap_b_{}", std::process::id());
        std::fs::write(a, "content_a").unwrap();
        std::fs::write(b, "content_b").unwrap();

        atomic_swap(Path::new(a), Path::new(b)).unwrap();

        assert_eq!(std::fs::read_to_string(a).unwrap(), "content_b");
        assert_eq!(std::fs::read_to_string(b).unwrap(), "content_a");

        std::fs::remove_file(a).unwrap();
        std::fs::remove_file(b).unwrap();
    }
}
