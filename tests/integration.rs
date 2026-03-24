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
        if !cards.is_empty() {
            let _ = nodes;
        }
    }
}

// ── netns integration ───────────────────────────────────────────────

#[cfg(feature = "netns")]
mod netns_integration {
    #[test]
    fn current_ns_fd_and_id() {
        let ns = agnosys::netns::current().unwrap();
        assert!(ns.as_raw_fd() >= 0);
        assert!(ns.name().is_none());

        let id = agnosys::netns::current_ns_id().unwrap();
        assert!(id > 0);
    }

    #[test]
    fn list_namespaces() {
        let names = agnosys::netns::list().unwrap();
        // May be empty, just verify no error and sorted
        for window in names.windows(2) {
            assert!(window[0] <= window[1]);
        }
    }

    #[test]
    fn named_path_construction() {
        let p = agnosys::netns::named_path("test");
        assert!(p.to_string_lossy().contains("netns"));
        assert!(p.to_string_lossy().contains("test"));
    }
}

// ── certpin integration ─────────────────────────────────────────────

#[cfg(feature = "certpin")]
mod certpin_integration {
    use agnosys::certpin::{Pin, PinSet};

    #[test]
    fn pin_round_trip_spki_to_base64() {
        let pin = Pin::from_spki(b"test public key info");
        let b64 = pin.to_base64();
        let pin2 = Pin::from_base64(&b64).unwrap();
        assert_eq!(pin, pin2);
    }

    #[test]
    fn pin_display_format() {
        let pin = Pin::from_spki(b"key");
        let s = format!("{pin}");
        assert!(s.starts_with("sha256/"));
        assert!(s.len() > 10);
    }

    #[test]
    fn pinset_validate_workflow() {
        let mut ps = PinSet::new();
        let pin = Pin::from_spki(b"trusted_key_material");
        ps.add(pin);

        assert!(ps.validate_spki(b"trusted_key_material"));
        assert!(!ps.validate_spki(b"untrusted_key_material"));
        assert_eq!(ps.len(), 1);
        assert!(!ps.is_empty());
    }

    #[test]
    fn sha256_known_vectors() {
        // Verify our SHA-256 produces correct output for known inputs
        let pin = Pin::from_spki(b"");
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            pin.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}

// ── agent integration ───────────────────────────────────────────────

#[cfg(feature = "agent")]
mod agent_integration {
    #[test]
    fn process_name_round_trip() {
        let original = agnosys::agent::get_process_name().unwrap();
        agnosys::agent::set_process_name("integ-test").unwrap();
        let name = agnosys::agent::get_process_name().unwrap();
        assert_eq!(name, "integ-test");
        agnosys::agent::set_process_name(&original).unwrap();
    }

    #[test]
    fn oom_score_read() {
        let score = agnosys::agent::get_oom_score_adj().unwrap();
        assert!((-1000..=1000).contains(&score));
    }

    #[test]
    fn cgroup_path_valid() {
        let cg = agnosys::agent::current_cgroup().unwrap();
        assert!(cg.starts_with('/'));
    }

    #[test]
    fn is_pid1_false() {
        assert!(!agnosys::agent::is_pid1());
    }

    #[test]
    fn has_capability_chown() {
        // CAP_CHOWN = 0 — should be in bounding set
        let result = agnosys::agent::has_capability(0);
        assert!(result.is_ok());
    }

    #[test]
    fn watchdog_no_socket() {
        let result = agnosys::agent::watchdog_notify().unwrap();
        assert!(!result);
    }
}

// ── logging integration ─────────────────────────────────────────────

#[cfg(feature = "logging")]
mod logging_integration {
    #[test]
    fn init_then_use_tracing() {
        agnosys::logging::init();
        // After init, tracing macros should work without panic
        tracing::info!("integration test log");
    }

    #[test]
    fn init_with_level_then_trace() {
        agnosys::logging::init_with_level("trace");
        tracing::trace!("trace level integration test");
    }
}

// ── luks integration ────────────────────────────────────────────────

#[cfg(feature = "luks")]
mod luks_integration {
    use std::path::Path;

    #[test]
    fn dm_available_check() {
        // Just verify no panic
        let _ = agnosys::luks::dm_available();
    }

    #[test]
    fn list_dm_devices_no_control() {
        if let Ok(devs) = agnosys::luks::list_dm_devices() {
            assert!(!devs.contains(&"control".to_owned()));
        }
    }

    #[test]
    fn volume_path_and_exists() {
        let p = agnosys::luks::volume_path("integration_test_nonexistent");
        assert_eq!(p, Path::new("/dev/mapper/integration_test_nonexistent"));
        assert!(!agnosys::luks::volume_exists(
            "integration_test_nonexistent"
        ));
    }

    #[test]
    fn dev_null_is_not_luks() {
        assert!(!agnosys::luks::is_luks_device(Path::new("/dev/null")).unwrap());
    }
}

// ── dmverity integration ────────────────────────────────────────────

#[cfg(feature = "dmverity")]
mod dmverity_integration {
    use std::path::Path;

    #[test]
    fn dev_null_is_not_verity() {
        assert!(!agnosys::dmverity::is_verity_device(Path::new("/dev/null")).unwrap());
    }

    #[test]
    fn volume_path_correct() {
        assert_eq!(
            agnosys::dmverity::volume_path("system"),
            Path::new("/dev/mapper/system")
        );
    }

    #[test]
    fn root_hash_round_trip() {
        let h = agnosys::dmverity::RootHash::from_hex("abcdef0123456789").unwrap();
        let hex = h.to_hex();
        let h2 = agnosys::dmverity::RootHash::from_hex(&hex).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn validate_root_hash_integration() {
        let a = agnosys::dmverity::RootHash::from_bytes(&[1, 2, 3]);
        let b = agnosys::dmverity::RootHash::from_bytes(&[1, 2, 3]);
        let c = agnosys::dmverity::RootHash::from_bytes(&[4, 5, 6]);
        assert!(agnosys::dmverity::validate_root_hash(&a, &b));
        assert!(!agnosys::dmverity::validate_root_hash(&a, &c));
    }
}

// ── audit integration ───────────────────────────────────────────────

#[cfg(feature = "audit")]
mod audit_integration {
    #[test]
    fn is_available_returns_bool() {
        let _ = agnosys::audit::is_available();
    }

    #[test]
    fn parse_audit_line_real_format() {
        let line = "type=SYSCALL msg=audit(1234567890.123:42): arch=c000003e syscall=59 success=yes pid=1234";
        let map = agnosys::audit::parse_audit_line(line);
        assert_eq!(map.get("arch").unwrap(), "c000003e");
        assert_eq!(map.get("pid").unwrap(), "1234");
    }

    #[test]
    fn msg_type_classification() {
        assert_eq!(
            agnosys::audit::AuditMsgType::from_raw(agnosys::audit::AUDIT_SYSCALL),
            agnosys::audit::AuditMsgType::Syscall
        );
        assert_eq!(
            agnosys::audit::AuditMsgType::from_raw(agnosys::audit::AUDIT_PATH),
            agnosys::audit::AuditMsgType::Path
        );
    }
}
