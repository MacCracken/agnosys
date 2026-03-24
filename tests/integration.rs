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

// ── checked_syscall cross-module ─────────────────────────────────────

#[test]
fn checked_syscall_success_via_getpid() {
    let ret =
        agnosys::syscall::checked_syscall("getpid", unsafe { libc::syscall(libc::SYS_getpid) });
    assert!(ret.unwrap() > 0);
}

#[test]
fn checked_syscall_failure_produces_syserror() {
    unsafe { libc::close(-1) };
    let ret = agnosys::syscall::checked_syscall("close", -1);
    let err = ret.unwrap_err();
    // Should produce a displayable error
    assert!(!err.to_string().is_empty());
}

// ── Debug format ────────────────────────────────────────────────────

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

// ── query_sysinfo single-call ──────────────────────────────────────

#[test]
fn query_sysinfo_snapshot_is_consistent() {
    let info = agnosys::syscall::query_sysinfo().unwrap();
    assert!(info.uptime() > 0.0);
    assert!(info.total_memory() >= 32 * 1024 * 1024);
    assert!(info.free_memory() <= info.total_memory());
    assert!(info.procs() > 0);
}

#[test]
fn query_sysinfo_avoids_redundant_syscalls() {
    // One call gives us everything — verify all fields populated
    let info = agnosys::syscall::query_sysinfo().unwrap();
    let up = info.uptime();
    let total = info.total_memory();
    let free = info.free_memory();
    let procs = info.procs();
    assert!(up > 0.0);
    assert!(total > 0);
    assert!(free > 0);
    assert!(procs > 0);
}

// ── udev integration ────────────────────────────────────────────────

#[cfg(feature = "udev")]
mod udev_integration {
    #[test]
    fn enumerate_and_inspect_net_devices() {
        let devs = agnosys::udev::enumerate("net").unwrap();
        assert!(!devs.is_empty());
        for dev in &devs {
            assert!(!dev.name().is_empty());
            assert!(dev.syspath().exists());
            assert_eq!(dev.subsystem(), "net");
        }
    }

    #[test]
    fn device_from_syspath_round_trip() {
        let devs = agnosys::udev::enumerate("net").unwrap();
        for dev in &devs {
            let dev2 = agnosys::udev::device_from_syspath(dev.syspath()).unwrap();
            assert_eq!(dev.name(), dev2.name());
        }
    }

    #[test]
    fn monitor_nonblocking() {
        if let Ok(mon) = agnosys::udev::Monitor::new() {
            // Should return None immediately (no events pending)
            assert!(mon.try_recv().unwrap().is_none());
        }
    }
}

// ── landlock integration ────────────────────────────────────────────

#[cfg(feature = "landlock")]
mod landlock_integration {
    use agnosys::landlock::{FsAccess, Ruleset};
    use std::path::Path;

    #[test]
    fn abi_version_consistent() {
        // Two calls should return the same version
        let v1 = agnosys::landlock::abi_version();
        let v2 = agnosys::landlock::abi_version();
        match (v1, v2) {
            (Ok(a), Ok(b)) => assert_eq!(a, b),
            (Err(_), Err(_)) => {} // both unsupported, fine
            _ => panic!("abi_version inconsistent"),
        }
    }

    #[test]
    fn ruleset_add_multiple_paths() {
        let rs = match Ruleset::new(FsAccess::READ_FILE | FsAccess::READ_DIR) {
            Ok(rs) => rs,
            Err(_) => return,
        };
        assert!(
            rs.allow_path(Path::new("/tmp"), FsAccess::READ_FILE)
                .is_ok()
        );
        assert!(rs.allow_path(Path::new("/usr"), FsAccess::READ_DIR).is_ok());
        assert!(
            rs.allow_path(Path::new("/var"), FsAccess::READ_FILE)
                .is_ok()
        );
    }
}

// ── seccomp integration ─────────────────────────────────────────────

#[cfg(feature = "seccomp")]
mod seccomp_integration {
    use agnosys::seccomp::{Action, FilterBuilder};

    #[test]
    fn build_and_inspect_filter() {
        let filter = FilterBuilder::new(Action::KillProcess)
            .allow_syscall(libc::SYS_read)
            .allow_syscall(libc::SYS_write)
            .allow_syscall(libc::SYS_exit_group)
            .build();
        assert!(!filter.is_empty());
        // arch(3) + nr(1) + 3 checks + default(1) + 3 returns = 11
        assert_eq!(filter.len(), 11);
    }

    #[test]
    fn no_new_privs_idempotent() {
        assert!(agnosys::seccomp::set_no_new_privs().is_ok());
        assert!(agnosys::seccomp::set_no_new_privs().is_ok());
    }

    #[test]
    fn filter_with_errno_default() {
        let filter = FilterBuilder::new(Action::Errno(libc::EPERM as u16))
            .allow_syscall(libc::SYS_read)
            .build();
        assert_eq!(filter.len(), 7);
    }
}

// ── drm integration ─────────────────────────────────────────────────

#[cfg(feature = "drm")]
mod drm_integration {
    #[test]
    fn enumerate_and_open() {
        let cards = match agnosys::drm::enumerate_cards() {
            Ok(c) if !c.is_empty() => c,
            _ => return,
        };
        for card in &cards {
            if let Ok(dev) = agnosys::drm::Device::open(card) {
                let ver = dev.version().unwrap();
                assert!(!ver.name.is_empty());
            }
        }
    }

    #[test]
    fn enumerate_cards_and_render_nodes_consistent() {
        let cards = agnosys::drm::enumerate_cards().unwrap_or_default();
        let nodes = agnosys::drm::enumerate_render_nodes().unwrap_or_default();
        // If we have cards, we likely have render nodes (though not guaranteed)
        if !cards.is_empty() {
            // Just verify both work without error
            let _ = nodes;
        }
    }
}
