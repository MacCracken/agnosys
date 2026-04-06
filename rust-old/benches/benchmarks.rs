use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_syscall(c: &mut Criterion) {
    use agnosys::syscall::*;
    let mut group = c.benchmark_group("syscall");

    group.bench_function("getpid", |b| b.iter(getpid));
    group.bench_function("gettid", |b| b.iter(gettid));
    group.bench_function("getuid", |b| b.iter(getuid));
    group.bench_function("geteuid", |b| b.iter(geteuid));
    group.bench_function("is_root", |b| b.iter(is_root));
    group.bench_function("uptime", |b| b.iter(uptime));
    group.bench_function("total_memory", |b| b.iter(total_memory));
    group.bench_function("available_memory", |b| b.iter(available_memory));
    group.bench_function("hostname", |b| b.iter(hostname));
    group.bench_function("checked_syscall_ok", |b| {
        b.iter(|| checked_syscall("getpid", unsafe { libc::syscall(libc::SYS_getpid) }))
    });
    group.bench_function("checked_syscall_err", |b| {
        b.iter(|| {
            unsafe { libc::close(-1) };
            checked_syscall("close", black_box(-1))
        })
    });
    group.bench_function("query_sysinfo", |b| b.iter(query_sysinfo));
    group.bench_function("query_sysinfo_all_fields", |b| {
        b.iter(|| {
            let info = query_sysinfo().unwrap();
            black_box((
                info.uptime(),
                info.total_memory(),
                info.free_memory(),
                info.procs(),
            ))
        })
    });
    group.bench_function("sysinfo_field_access", |b| {
        let info = query_sysinfo().unwrap();
        b.iter(|| {
            black_box(info.uptime());
            black_box(info.total_memory());
            black_box(info.free_memory());
            black_box(info.procs());
        })
    });
    group.bench_function("sysinfo_uptime", |b| {
        let info = query_sysinfo().unwrap();
        b.iter(|| black_box(info.uptime()))
    });
    group.bench_function("sysinfo_total_memory", |b| {
        let info = query_sysinfo().unwrap();
        b.iter(|| black_box(info.total_memory()))
    });

    group.finish();
}

fn bench_error(c: &mut Criterion) {
    use agnosys::error::SysError;
    let mut group = c.benchmark_group("error");

    group.bench_function("from_errno_eperm", |b| {
        b.iter(|| SysError::from_errno(black_box(libc::EPERM)))
    });
    group.bench_function("from_errno_eacces", |b| {
        b.iter(|| SysError::from_errno(black_box(libc::EACCES)))
    });
    group.bench_function("from_errno_eagain", |b| {
        b.iter(|| SysError::from_errno(black_box(libc::EAGAIN)))
    });
    group.bench_function("from_errno_einval", |b| {
        b.iter(|| SysError::from_errno(black_box(libc::EINVAL)))
    });
    group.bench_function("from_errno_enosys", |b| {
        b.iter(|| SysError::from_errno(black_box(libc::ENOSYS)))
    });
    group.bench_function("from_errno_unknown", |b| {
        b.iter(|| SysError::from_errno(black_box(999)))
    });
    group.bench_function("last_os_error", |b| {
        b.iter(|| {
            unsafe { libc::close(-1) };
            SysError::last_os_error()
        })
    });
    group.bench_function("display_syscall_failed", |b| {
        let e = SysError::SyscallFailed {
            errno: 2,
            message: "No such file".into(),
        };
        b.iter(|| format!("{}", black_box(&e)))
    });
    group.bench_function("display_permission_denied", |b| {
        let e = SysError::PermissionDenied {
            operation: "mount".into(),
        };
        b.iter(|| format!("{}", black_box(&e)))
    });
    group.bench_function("display_would_block", |b| {
        let e = SysError::WouldBlock;
        b.iter(|| format!("{}", black_box(&e)))
    });

    group.finish();
}

#[cfg(feature = "security")]
fn bench_security(c: &mut Criterion) {
    use agnosys::security::*;
    let mut group = c.benchmark_group("security");

    group.bench_function("create_basic_seccomp_filter", |b| {
        b.iter(create_basic_seccomp_filter)
    });
    group.bench_function("syscall_name_to_nr_read", |b| {
        b.iter(|| syscall_name_to_nr(black_box("read")))
    });
    group.bench_function("syscall_name_to_nr_miss", |b| {
        b.iter(|| syscall_name_to_nr(black_box("nonexistent")))
    });
    group.bench_function("filesystem_rule_read_only", |b| {
        b.iter(|| FilesystemRule::read_only(black_box("/tmp")))
    });
    group.bench_function("filesystem_rule_read_write", |b| {
        b.iter(|| FilesystemRule::read_write(black_box("/var")))
    });
    group.bench_function("namespace_flags_combine", |b| {
        b.iter(|| black_box(NamespaceFlags::NETWORK | NamespaceFlags::MOUNT | NamespaceFlags::PID))
    });

    group.finish();
}

#[cfg(not(feature = "security"))]
fn bench_security(_c: &mut Criterion) {}

#[cfg(feature = "udev")]
fn bench_udev(c: &mut Criterion) {
    let mut group = c.benchmark_group("udev");

    group.bench_function("list_devices_net", |b| {
        b.iter(|| agnosys::udev::list_devices(Some(black_box("net"))))
    });
    group.bench_function("get_device_info_lo", |b| {
        b.iter(|| agnosys::udev::get_device_info(black_box("/sys/class/net/lo")))
    });
    group.bench_function("render_udev_rule", |b| {
        let rule = agnosys::udev::UdevRule::new(
            "test",
            vec![("SUBSYSTEM".to_string(), "net".to_string())],
            vec![("RUN".to_string(), "/bin/true".to_string())],
        );
        b.iter(|| agnosys::udev::render_udev_rule(black_box(&rule)))
    });

    group.finish();
}

#[cfg(not(feature = "udev"))]
fn bench_udev(_c: &mut Criterion) {}

#[cfg(feature = "drm")]
fn bench_drm(c: &mut Criterion) {
    let mut group = c.benchmark_group("drm");

    group.bench_function("enumerate_cards", |b| b.iter(agnosys::drm::enumerate_cards));
    group.bench_function("enumerate_render_nodes", |b| {
        b.iter(agnosys::drm::enumerate_render_nodes)
    });

    if let Ok(cards) = agnosys::drm::enumerate_cards()
        && let Some(path) = cards.first()
        && let Ok(dev) = agnosys::drm::Device::open(path)
    {
        let dev = Box::leak(Box::new(dev));
        group.bench_function("device_version", |b| b.iter(|| dev.version()));
        group.bench_function("get_cap_dumb_buffer", |b| {
            b.iter(|| dev.get_cap(agnosys::drm::Cap::DumbBuffer))
        });
        if dev.mode_resources().is_ok() {
            group.bench_function("mode_resources", |b| b.iter(|| dev.mode_resources()));
        }
    }

    group.finish();
}

#[cfg(not(feature = "drm"))]
fn bench_drm(_c: &mut Criterion) {}

#[cfg(feature = "netns")]
fn bench_netns(c: &mut Criterion) {
    let mut group = c.benchmark_group("netns");

    group.bench_function("generate_agent_ips", |b| {
        b.iter(|| agnosys::netns::generate_agent_ips(black_box("test-agent")))
    });
    group.bench_function("list_agent_netns", |b| {
        b.iter(agnosys::netns::list_agent_netns)
    });
    group.bench_function("config_for_agent", |b| {
        b.iter(|| agnosys::netns::NetNamespaceConfig::for_agent(black_box("bench")))
    });

    group.finish();
}

#[cfg(not(feature = "netns"))]
fn bench_netns(_c: &mut Criterion) {}

#[cfg(feature = "certpin")]
fn bench_certpin(c: &mut Criterion) {
    let mut group = c.benchmark_group("certpin");

    group.bench_function("compute_spki_pin", |b| {
        let pem =
            "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...test...==\n-----END CERTIFICATE-----";
        b.iter(|| agnosys::certpin::compute_spki_pin(black_box(pem)))
    });
    group.bench_function("validate_pin_format_valid", |b| {
        b.iter(|| {
            agnosys::certpin::validate_pin_format(black_box(
                "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
            ))
        })
    });
    group.bench_function("validate_pin_format_invalid", |b| {
        b.iter(|| agnosys::certpin::validate_pin_format(black_box("bad")))
    });
    group.bench_function("default_agnos_pins", |b| {
        b.iter(agnosys::certpin::default_agnos_pins)
    });
    group.bench_function("check_pin_expiry", |b| {
        let ps = agnosys::certpin::default_agnos_pins();
        b.iter(|| agnosys::certpin::check_pin_expiry(black_box(&ps)))
    });

    group.finish();
}

#[cfg(not(feature = "certpin"))]
fn bench_certpin(_c: &mut Criterion) {}

#[cfg(feature = "logging")]
fn bench_logging(c: &mut Criterion) {
    let mut group = c.benchmark_group("logging");
    group.bench_function("init", |b| b.iter(agnosys::logging::init));
    group.bench_function("init_with_level", |b| {
        b.iter(|| agnosys::logging::init_with_level(black_box("info")))
    });
    group.finish();
}

#[cfg(not(feature = "logging"))]
fn bench_logging(_c: &mut Criterion) {}

#[cfg(feature = "luks")]
fn bench_luks(c: &mut Criterion) {
    let mut group = c.benchmark_group("luks");

    group.bench_function("cryptsetup_available", |b| {
        b.iter(agnosys::luks::cryptsetup_available)
    });
    group.bench_function("dmcrypt_supported", |b| {
        b.iter(agnosys::luks::dmcrypt_supported)
    });
    group.bench_function("config_for_agent", |b| {
        b.iter(|| agnosys::luks::LuksConfig::for_agent(black_box("bench"), 256))
    });
    group.bench_function("key_generate_32", |b| {
        b.iter(|| agnosys::luks::LuksKey::generate(black_box(32)))
    });
    group.bench_function("filesystem_as_str", |b| {
        b.iter(|| agnosys::luks::LuksFilesystem::Ext4.as_str())
    });

    group.finish();
}

#[cfg(not(feature = "luks"))]
fn bench_luks(_c: &mut Criterion) {}

#[cfg(feature = "dmverity")]
fn bench_dmverity(c: &mut Criterion) {
    let mut group = c.benchmark_group("dmverity");

    group.bench_function("verity_supported", |b| {
        b.iter(agnosys::dmverity::verity_supported)
    });
    group.bench_function("validate_root_hash_sha256", |b| {
        let hash = "a".repeat(64);
        b.iter(|| {
            agnosys::dmverity::validate_root_hash(
                black_box(&hash),
                agnosys::dmverity::VerityHashAlgorithm::Sha256,
            )
        })
    });
    group.bench_function("hash_algorithm_str", |b| {
        b.iter(|| agnosys::dmverity::VerityHashAlgorithm::Sha256.as_str())
    });

    group.finish();
}

#[cfg(not(feature = "dmverity"))]
fn bench_dmverity(_c: &mut Criterion) {}

#[cfg(feature = "audit")]
fn bench_audit(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit");

    group.bench_function("rule_file_watch", |b| {
        b.iter(|| agnosys::audit::AuditRule::file_watch(black_box("/etc/passwd"), "test"))
    });
    group.bench_function("rule_syscall_watch", |b| {
        b.iter(|| agnosys::audit::AuditRule::syscall_watch(black_box(59), "test"))
    });
    group.bench_function("rule_validate", |b| {
        let rule = agnosys::audit::AuditRule::file_watch("/etc/passwd", "test");
        b.iter(|| rule.validate())
    });

    group.finish();
}

#[cfg(not(feature = "audit"))]
fn bench_audit(_c: &mut Criterion) {}

#[cfg(feature = "pam")]
fn bench_pam(c: &mut Criterion) {
    let mut group = c.benchmark_group("pam");

    group.bench_function("validate_username_good", |b| {
        b.iter(|| agnosys::pam::validate_username(black_box("testuser")))
    });
    group.bench_function("validate_username_bad", |b| {
        b.iter(|| agnosys::pam::validate_username(black_box("")))
    });
    group.bench_function("parse_pam_config", |b| {
        let config =
            "auth required pam_unix.so\naccount required pam_unix.so\nsession optional pam_systemd.so";
        b.iter(|| agnosys::pam::parse_pam_config(black_box(config)))
    });
    group.bench_function("render_pam_config", |b| {
        let rules = agnosys::pam::parse_pam_config(
            "auth required pam_unix.so\naccount required pam_unix.so",
        )
        .unwrap();
        b.iter(|| agnosys::pam::render_pam_config(black_box(&rules)))
    });
    group.bench_function("get_pam_service_path", |b| {
        b.iter(|| agnosys::pam::get_pam_service_path(&agnosys::pam::PamService::Login))
    });

    group.finish();
}

#[cfg(not(feature = "pam"))]
fn bench_pam(_c: &mut Criterion) {}

#[cfg(feature = "mac")]
fn bench_mac(c: &mut Criterion) {
    let mut group = c.benchmark_group("mac");

    group.bench_function("detect_mac_system", |b| {
        b.iter(agnosys::mac::detect_mac_system)
    });
    group.bench_function("get_current_selinux_context", |b| {
        b.iter(agnosys::mac::get_current_selinux_context)
    });
    group.bench_function("get_selinux_mode", |b| {
        b.iter(agnosys::mac::get_selinux_mode)
    });
    group.bench_function("default_agent_profiles", |b| {
        b.iter(agnosys::mac::default_agent_profiles)
    });

    group.finish();
}

#[cfg(not(feature = "mac"))]
fn bench_mac(_c: &mut Criterion) {}

#[cfg(feature = "ima")]
fn bench_ima(c: &mut Criterion) {
    let mut group = c.benchmark_group("ima");

    group.bench_function("get_ima_status", |b| b.iter(agnosys::ima::get_ima_status));
    group.bench_function("parse_ima_measurements_empty", |b| {
        b.iter(|| agnosys::ima::parse_ima_measurements(black_box("")))
    });
    group.bench_function("policy_rule_build", |b| {
        b.iter(|| {
            agnosys::ima::ImaPolicyRule::new(
                agnosys::ima::ImaAction::Measure,
                agnosys::ima::ImaTarget::BprmCheck,
            )
            .with_uid(0)
            .validate()
        })
    });

    group.finish();
}

#[cfg(not(feature = "ima"))]
fn bench_ima(_c: &mut Criterion) {}

#[cfg(feature = "fuse")]
fn bench_fuse(c: &mut Criterion) {
    let mut group = c.benchmark_group("fuse");

    group.bench_function("is_fuse_available", |b| {
        b.iter(agnosys::fuse::is_fuse_available)
    });
    group.bench_function("list_fuse_mounts", |b| {
        b.iter(agnosys::fuse::list_fuse_mounts)
    });
    group.bench_function("parse_proc_mounts_empty", |b| {
        b.iter(|| agnosys::fuse::parse_proc_mounts(black_box("")))
    });
    group.bench_function("render_mount_options", |b| {
        let opts = agnosys::fuse::FuseMountOptions::default();
        b.iter(|| agnosys::fuse::render_mount_options(black_box(&opts)))
    });

    group.finish();
}

#[cfg(not(feature = "fuse"))]
fn bench_fuse(_c: &mut Criterion) {}

#[cfg(feature = "update")]
fn bench_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("update");

    group.bench_function("validate_version_good", |b| {
        b.iter(|| agnosys::update::validate_version(black_box("2025.03.1")))
    });
    group.bench_function("validate_version_bad", |b| {
        b.iter(|| agnosys::update::validate_version(black_box("")))
    });
    group.bench_function("compare_versions", |b| {
        b.iter(|| agnosys::update::compare_versions(black_box("2025.01.0"), black_box("2025.02.0")))
    });
    group.bench_function("build_test_manifest", |b| {
        b.iter(|| {
            agnosys::update::build_test_manifest(
                black_box("2025.03.1"),
                agnosys::update::UpdateChannel::Stable,
            )
        })
    });
    group.bench_function("verify_manifest", |b| {
        let m = agnosys::update::build_test_manifest(
            "2025.03.1",
            agnosys::update::UpdateChannel::Stable,
        );
        b.iter(|| agnosys::update::verify_manifest(black_box(&m)))
    });
    group.bench_function("slot_other", |b| {
        b.iter(|| agnosys::update::UpdateSlot::A.other())
    });

    group.finish();
}

#[cfg(not(feature = "update"))]
fn bench_update(_c: &mut Criterion) {}

#[cfg(feature = "tpm")]
fn bench_tpm(c: &mut Criterion) {
    let mut group = c.benchmark_group("tpm");

    group.bench_function("tpm_available", |b| b.iter(agnosys::tpm::tpm_available));

    group.finish();
}

#[cfg(not(feature = "tpm"))]
fn bench_tpm(_c: &mut Criterion) {}

#[cfg(feature = "secureboot")]
fn bench_secureboot(c: &mut Criterion) {
    let mut group = c.benchmark_group("secureboot");

    group.bench_function("get_secureboot_status", |b| {
        b.iter(agnosys::secureboot::get_secureboot_status)
    });

    group.finish();
}

#[cfg(not(feature = "secureboot"))]
fn bench_secureboot(_c: &mut Criterion) {}

#[cfg(feature = "journald")]
fn bench_journald(c: &mut Criterion) {
    let mut group = c.benchmark_group("journald");

    group.bench_function("get_journal_stats", |b| {
        b.iter(agnosys::journald::get_journal_stats)
    });
    group.bench_function("build_journalctl_args", |b| {
        let filter = agnosys::journald::JournalFilter::default();
        b.iter(|| agnosys::journald::build_journalctl_args(black_box(&filter)))
    });
    group.bench_function("priority_from_u8", |b| {
        b.iter(|| agnosys::journald::JournalPriority::from_u8(black_box(3)))
    });

    group.finish();
}

#[cfg(not(feature = "journald"))]
fn bench_journald(_c: &mut Criterion) {}

#[cfg(feature = "bootloader")]
fn bench_bootloader(c: &mut Criterion) {
    let mut group = c.benchmark_group("bootloader");

    group.bench_function("detect_bootloader", |b| {
        b.iter(agnosys::bootloader::detect_bootloader)
    });
    group.bench_function("validate_kernel_cmdline", |b| {
        b.iter(|| {
            agnosys::bootloader::validate_kernel_cmdline(black_box("root=/dev/sda1 ro quiet"))
        })
    });

    group.finish();
}

#[cfg(not(feature = "bootloader"))]
fn bench_bootloader(_c: &mut Criterion) {}

criterion_group!(
    benches,
    bench_syscall,
    bench_error,
    bench_security,
    bench_udev,
    bench_drm,
    bench_netns,
    bench_certpin,
    bench_logging,
    bench_luks,
    bench_dmverity,
    bench_audit,
    bench_pam,
    bench_mac,
    bench_ima,
    bench_fuse,
    bench_update,
    bench_tpm,
    bench_secureboot,
    bench_journald,
    bench_bootloader,
);
criterion_main!(benches);
