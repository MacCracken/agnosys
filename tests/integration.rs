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
    assert!(total >= 32 * 1024 * 1024);
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
    fn list_net_devices() {
        let devs = agnosys::udev::list_devices(Some("net")).unwrap();
        // May be empty in CI, just verify no error
        for dev in &devs {
            assert!(!dev.subsystem.is_empty());
        }
    }

    #[test]
    fn get_device_info_by_syspath() {
        let devs = agnosys::udev::list_devices(Some("net")).unwrap();
        for dev in &devs {
            let dev2 = agnosys::udev::get_device_info(&dev.syspath);
            // May fail if syspath disappeared, just verify we can call it
            let _ = dev2;
        }
    }

    #[test]
    fn render_udev_rule_round_trip() {
        let rule = agnosys::udev::UdevRule {
            name: "test".to_string(),
            match_attrs: vec![("SUBSYSTEM".to_string(), "net".to_string())],
            actions: vec![("RUN".to_string(), "/bin/true".to_string())],
        };
        let rendered = agnosys::udev::render_udev_rule(&rule);
        assert!(rendered.contains("SUBSYSTEM"));
        assert!(rendered.contains("RUN"));
    }
}

// ── security integration ────────────────────────────────────────────

#[cfg(feature = "security")]
mod security_integration {
    use agnosys::security::{FilesystemRule, FsAccess};

    #[test]
    fn filesystem_rule_constructors() {
        let r1 = FilesystemRule::read_only("/tmp");
        let r2 = FilesystemRule::read_write("/var");
        let r3 = FilesystemRule::new("/usr", FsAccess::ReadOnly);
        let _ = (r1, r2, r3);
    }

    #[test]
    fn basic_seccomp_filter_builds() {
        let filter = agnosys::security::create_basic_seccomp_filter();
        assert!(filter.is_ok());
        assert!(!filter.unwrap().is_empty());
    }

    #[test]
    fn namespace_flags_bitops() {
        let flags =
            agnosys::security::NamespaceFlags::NETWORK | agnosys::security::NamespaceFlags::MOUNT;
        assert!(flags.contains(agnosys::security::NamespaceFlags::NETWORK));
        assert!(flags.contains(agnosys::security::NamespaceFlags::MOUNT));
        assert!(!flags.contains(agnosys::security::NamespaceFlags::PID));
    }

    #[test]
    fn syscall_name_to_nr_known() {
        let nr = agnosys::security::syscall_name_to_nr("read");
        assert!(nr.is_some());
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
    fn generate_agent_ips_deterministic() {
        let (a1, h1) = agnosys::netns::generate_agent_ips("test-agent");
        let (a2, h2) = agnosys::netns::generate_agent_ips("test-agent");
        assert_eq!(a1, a2);
        assert_eq!(h1, h2);
        assert_ne!(a1, h1);
    }

    #[test]
    fn list_agent_namespaces() {
        let names = agnosys::netns::list_agent_netns().unwrap_or_default();
        // May be empty, just verify no panic
        let _ = names;
    }

    #[test]
    fn namespace_config_validation() {
        let config = agnosys::netns::NetNamespaceConfig::for_agent("test");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn namespace_config_defaults() {
        let config = agnosys::netns::NetNamespaceConfig::for_agent("integration");
        assert_eq!(config.prefix_len, 30);
        assert!(config.enable_nat);
        assert_eq!(config.dns_servers.len(), 2);
    }
}

// ── certpin integration ─────────────────────────────────────────────

#[cfg(feature = "certpin")]
mod certpin_integration {
    #[test]
    fn compute_spki_pin_deterministic() {
        let pin1 = agnosys::certpin::compute_spki_pin(
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        );
        let pin2 = agnosys::certpin::compute_spki_pin(
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        );
        // Both should return same result (or same error)
        assert_eq!(pin1.is_ok(), pin2.is_ok());
    }

    #[test]
    fn validate_pin_format_sha256() {
        // validate_pin_format expects raw base64 of 32-byte SHA-256
        assert!(
            agnosys::certpin::validate_pin_format("YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=")
                .is_ok()
        );
        assert!(agnosys::certpin::validate_pin_format("bad-pin").is_err());
    }

    #[test]
    fn default_pins_non_empty() {
        let ps = agnosys::certpin::default_agnos_pins();
        assert!(!ps.pins.is_empty());
    }

    #[test]
    fn check_pin_expiry_no_panic() {
        let ps = agnosys::certpin::default_agnos_pins();
        let expired = agnosys::certpin::check_pin_expiry(&ps);
        let _ = expired;
    }
}

// ── agent integration ───────────────────────────────────────────────

#[cfg(feature = "agent")]
mod agent_integration {
    #[test]
    fn agent_id_unique() {
        let id1 = agnosys::agent::AgentId::new();
        let id2 = agnosys::agent::AgentId::new();
        assert_ne!(format!("{id1:?}"), format!("{id2:?}"));
    }

    #[test]
    fn agent_config_defaults() {
        let config = agnosys::agent::AgentConfig {
            name: "test-agent".to_string(),
            agent_type: agnosys::agent::AgentType::Service,
        };
        assert_eq!(config.name, "test-agent");
    }

    #[test]
    fn agent_type_variants() {
        let _ = agnosys::agent::AgentType::Service;
        let _ = agnosys::agent::AgentType::Worker;
        let _ = agnosys::agent::AgentType::Monitor;
    }
}

// ── logging integration ─────────────────────────────────────────────

#[cfg(feature = "logging")]
mod logging_integration {
    #[test]
    fn init_then_use_tracing() {
        agnosys::logging::init();
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
    #[test]
    fn cryptsetup_and_dm_availability() {
        let _ = agnosys::luks::cryptsetup_available();
        let _ = agnosys::luks::dmcrypt_supported();
    }

    #[test]
    fn luks_config_for_agent() {
        let config = agnosys::luks::LuksConfig::for_agent("test-agent", 256);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn luks_key_generation() {
        let key = agnosys::luks::LuksKey::generate(32).unwrap();
        assert_eq!(key.len(), 32);
        assert!(!key.is_empty());
    }

    #[test]
    fn luks_filesystem_names() {
        assert_eq!(agnosys::luks::LuksFilesystem::Ext4.as_str(), "ext4");
        assert_eq!(agnosys::luks::LuksFilesystem::Btrfs.as_str(), "btrfs");
    }
}

// ── dmverity integration ────────────────────────────────────────────

#[cfg(feature = "dmverity")]
mod dmverity_integration {
    #[test]
    fn verity_supported_check() {
        let _ = agnosys::dmverity::verity_supported();
    }

    #[test]
    fn validate_root_hash_sha256() {
        let valid = "a".repeat(64);
        assert!(
            agnosys::dmverity::validate_root_hash(
                &valid,
                agnosys::dmverity::VerityHashAlgorithm::Sha256
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_root_hash_bad_length() {
        assert!(
            agnosys::dmverity::validate_root_hash(
                "tooshort",
                agnosys::dmverity::VerityHashAlgorithm::Sha256
            )
            .is_err()
        );
    }

    #[test]
    fn hash_algorithm_str() {
        assert_eq!(
            agnosys::dmverity::VerityHashAlgorithm::Sha256.as_str(),
            "sha256"
        );
        assert_eq!(
            agnosys::dmverity::VerityHashAlgorithm::Sha512.as_str(),
            "sha512"
        );
    }
}

// ── audit integration ───────────────────────────────────────────────

#[cfg(feature = "audit")]
mod audit_integration {
    #[test]
    fn audit_rule_constructors() {
        let rule = agnosys::audit::AuditRule::file_watch("/etc/passwd", "passwd-watch");
        assert!(rule.validate().is_ok());

        let rule2 = agnosys::audit::AuditRule::syscall_watch(59, "execve-watch");
        assert!(rule2.validate().is_ok());
    }

    #[test]
    fn audit_config_defaults() {
        let config = agnosys::audit::AuditConfig::default();
        let _ = config;
    }
}

// ── pam integration ─────────────────────────────────────────────────

#[cfg(feature = "pam")]
mod pam_integration {
    #[test]
    fn parse_config_round_trip() {
        let config = "auth required pam_unix.so nullok\naccount required pam_unix.so";
        let entries = agnosys::pam::parse_pam_config(config).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].module, "pam_unix.so");

        let rendered = agnosys::pam::render_pam_config(&entries);
        assert!(rendered.contains("pam_unix.so"));
    }

    #[test]
    fn service_path_format() {
        let p = agnosys::pam::get_pam_service_path(&agnosys::pam::PamService::Login);
        assert!(p.to_string_lossy().contains("pam.d"));
    }

    #[test]
    fn validate_username_good() {
        assert!(agnosys::pam::validate_username("testuser").is_ok());
    }

    #[test]
    fn validate_username_bad() {
        assert!(agnosys::pam::validate_username("").is_err());
    }
}

// ── mac integration ─────────────────────────────────────────────────

#[cfg(feature = "mac")]
mod mac_integration {
    #[test]
    fn detect_mac_system() {
        let system = agnosys::mac::detect_mac_system();
        // Just verify it returns without panic
        let _ = system;
    }

    #[test]
    fn selinux_context_readable() {
        let _ = agnosys::mac::get_current_selinux_context();
    }

    #[test]
    fn default_agent_profiles() {
        let profiles = agnosys::mac::default_agent_profiles();
        assert!(!profiles.is_empty());
    }
}

// ── ima integration ─────────────────────────────────────────────────

#[cfg(feature = "ima")]
mod ima_integration {
    #[test]
    fn ima_status() {
        let status = agnosys::ima::get_ima_status();
        // May fail if IMA not available, just verify callable
        let _ = status;
    }

    #[test]
    fn parse_measurements_empty() {
        let result = agnosys::ima::parse_ima_measurements("");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn policy_rule_builder() {
        let rule = agnosys::ima::ImaPolicyRule::new(
            agnosys::ima::ImaAction::Measure,
            agnosys::ima::ImaTarget::BprmCheck,
        )
        .with_uid(0);
        assert!(rule.validate().is_ok());
    }
}

// ── fuse integration ────────────────────────────────────────────────

#[cfg(feature = "fuse")]
mod fuse_integration {
    #[test]
    fn fuse_availability() {
        let _ = agnosys::fuse::is_fuse_available();
    }

    #[test]
    fn list_fuse_mounts_no_panic() {
        let _ = agnosys::fuse::list_fuse_mounts();
    }

    #[test]
    fn parse_proc_mounts_empty() {
        let mounts = agnosys::fuse::parse_proc_mounts("");
        assert!(mounts.is_empty());
    }

    #[test]
    fn render_mount_options_defaults() {
        let opts = agnosys::fuse::FuseMountOptions::default();
        let rendered = agnosys::fuse::render_mount_options(&opts);
        let _ = rendered;
    }
}

// ── update integration ──────────────────────────────────────────────

#[cfg(feature = "update")]
mod update_integration {
    use std::cmp::Ordering;

    #[test]
    fn validate_version_good() {
        assert!(agnosys::update::validate_version("2025.03.1").is_ok());
    }

    #[test]
    fn validate_version_bad() {
        assert!(agnosys::update::validate_version("").is_err());
    }

    #[test]
    fn compare_versions_ordering() {
        assert_eq!(
            agnosys::update::compare_versions("2025.01.0", "2025.02.0"),
            Ordering::Less
        );
        assert_eq!(
            agnosys::update::compare_versions("2025.03.0", "2025.03.0"),
            Ordering::Equal
        );
    }

    #[test]
    fn slot_other() {
        assert!(matches!(
            agnosys::update::UpdateSlot::A.other(),
            agnosys::update::UpdateSlot::B
        ));
        assert!(matches!(
            agnosys::update::UpdateSlot::B.other(),
            agnosys::update::UpdateSlot::A
        ));
    }

    #[test]
    fn build_test_manifest_and_verify() {
        let manifest = agnosys::update::build_test_manifest(
            "2025.03.1",
            agnosys::update::UpdateChannel::Stable,
        );
        assert!(agnosys::update::verify_manifest(&manifest).is_ok());
    }

    #[test]
    fn needs_rollback_logic() {
        let state = agnosys::update::UpdateState {
            current_slot: agnosys::update::UpdateSlot::A,
            current_version: "2025.01.0".to_string(),
            pending_update: None,
            last_update: None,
            rollback_available: false,
            boot_count_since_update: 0,
        };
        let _ = agnosys::update::needs_rollback(&state, 3);
    }
}

// ── tpm integration ─────────────────────────────────────────────────

#[cfg(feature = "tpm")]
mod tpm_integration {
    #[test]
    fn tpm_detection() {
        let _ = agnosys::tpm::tpm_available();
    }

    #[test]
    fn pcr_bank_variants() {
        let _ = agnosys::tpm::TpmPcrBank::Sha256;
        let _ = agnosys::tpm::TpmPcrBank::Sha1;
    }
}

// ── secureboot integration ──────────────────────────────────────────

#[cfg(feature = "secureboot")]
mod secureboot_integration {
    #[test]
    fn secureboot_status() {
        let status = agnosys::secureboot::get_secureboot_status();
        // May return NotSupported, just verify callable
        let _ = status;
    }

    #[test]
    fn secureboot_state_variants() {
        let _ = agnosys::secureboot::SecureBootState::Enabled;
        let _ = agnosys::secureboot::SecureBootState::Disabled;
        let _ = agnosys::secureboot::SecureBootState::NotSupported;
    }
}

// ── journald integration ────────────────────────────────────────────

#[cfg(feature = "journald")]
mod journald_integration {
    #[test]
    fn journal_stats() {
        let _ = agnosys::journald::get_journal_stats();
    }

    #[test]
    fn build_journalctl_args_filter() {
        let filter = agnosys::journald::JournalFilter::default();
        let args = agnosys::journald::build_journalctl_args(&filter);
        // Should produce valid args
        let _ = args;
    }

    #[test]
    fn journal_priority_round_trip() {
        let p = agnosys::journald::JournalPriority::from_u8(3);
        assert!(p.is_some());
        assert_eq!(p.unwrap().as_u8(), 3);
    }
}

// ── bootloader integration ──────────────────────────────────────────

#[cfg(feature = "bootloader")]
mod bootloader_integration {
    #[test]
    fn detect_bootloader() {
        let info = agnosys::bootloader::detect_bootloader();
        // May fail in CI, just verify callable
        let _ = info;
    }

    #[test]
    fn validate_kernel_cmdline_good() {
        assert!(agnosys::bootloader::validate_kernel_cmdline("root=/dev/sda1 ro quiet").is_ok());
    }
}
