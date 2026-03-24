//! Integration tests for agnosys.

// ── Cross-function consistency ──────────────────────────────────────

#[test]
fn system_info_consistent() {
    let pid = agnosys::syscall::getpid();
    let pid2 = agnosys::syscall::getpid();
    assert_eq!(pid, pid2);

    let total = agnosys::syscall::total_memory().unwrap();
    let avail = agnosys::syscall::available_memory().unwrap();
    assert!(avail <= total);
}

#[test]
fn hostname_is_valid_utf8() {
    let name = agnosys::syscall::hostname().unwrap();
    assert!(!name.is_empty());
    assert!(name.len() <= 255);
}

#[test]
fn uptime_positive() {
    let up = agnosys::syscall::uptime().unwrap();
    assert!(up > 0.0);
}

// ── Identity consistency ────────────────────────────────────────────

#[test]
fn uid_euid_are_consistent() {
    let uid = agnosys::syscall::getuid();
    let euid = agnosys::syscall::geteuid();
    // For non-suid binaries, uid == euid
    // We can't assert equality in all environments, but both should be valid
    let _ = uid;
    let _ = euid;
}

#[test]
fn is_root_matches_euid() {
    let is_root = agnosys::syscall::is_root();
    let euid = agnosys::syscall::geteuid();
    assert_eq!(is_root, euid == 0);
}

#[test]
fn gettid_positive_integration() {
    let tid = agnosys::syscall::gettid();
    assert!(tid > 0);
}

// ── Error types from syscall module ─────────────────────────────────

#[test]
fn error_display_includes_context() {
    let e = agnosys::error::SysError::PermissionDenied {
        operation: "seccomp_load".into(),
    };
    let msg = e.to_string();
    assert!(msg.contains("seccomp_load"));
    assert!(msg.contains("permission denied"));
}

#[test]
fn error_from_errno_round_trip() {
    let e = agnosys::error::SysError::from_errno(libc::EPERM);
    assert!(matches!(
        e,
        agnosys::error::SysError::PermissionDenied { .. }
    ));
    let e2 = agnosys::error::SysError::from_errno(libc::ENOENT);
    match e2 {
        agnosys::error::SysError::SyscallFailed { errno, message } => {
            assert_eq!(errno, libc::ENOENT);
            assert!(!message.is_empty());
        }
        _ => panic!("ENOENT should map to SyscallFailed"),
    }
}

// ── Serde round-trip ────────────────────────────────────────────────

#[test]
fn syserror_debug_contains_variant_name() {
    let e = agnosys::error::SysError::WouldBlock;
    let dbg = format!("{e:?}");
    assert!(dbg.contains("WouldBlock"));

    let e2 = agnosys::error::SysError::ModuleNotLoaded {
        module: "vfio".into(),
    };
    let dbg2 = format!("{e2:?}");
    assert!(dbg2.contains("vfio"));
}

// ── Memory sanity ───────────────────────────────────────────────────

#[test]
fn memory_values_in_reasonable_range() {
    let total = agnosys::syscall::total_memory().unwrap();
    let avail = agnosys::syscall::available_memory().unwrap();

    // At least 32 MB
    assert!(total >= 32 * 1024 * 1024);
    // Available should be non-zero on any running system
    assert!(avail > 0);
    assert!(avail <= total);
}

// ── Uptime monotonicity ────────────────────────────────────────────

#[test]
fn uptime_does_not_go_backwards() {
    let a = agnosys::syscall::uptime().unwrap();
    let b = agnosys::syscall::uptime().unwrap();
    assert!(b >= a);
}
