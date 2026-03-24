use criterion::{Criterion, black_box, criterion_group, criterion_main};

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

    // from_errno — all mapped branches
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

    // last_os_error
    group.bench_function("last_os_error", |b| {
        b.iter(|| {
            unsafe { libc::close(-1) };
            SysError::last_os_error()
        })
    });

    // Display — all variants
    group.bench_function("display_syscall_failed", |b| {
        let e = SysError::SyscallFailed {
            errno: 2,
            message: "No such file".into(),
        };
        b.iter(|| format!("{}", black_box(&e)))
    });
    group.bench_function("display_invalid_argument", |b| {
        let e = SysError::InvalidArgument("bad flags".into());
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
    group.bench_function("display_module_not_loaded", |b| {
        let e = SysError::ModuleNotLoaded {
            module: "tpm_tis".into(),
        };
        b.iter(|| format!("{}", black_box(&e)))
    });
    group.bench_function("display_not_supported", |b| {
        let e = SysError::NotSupported {
            feature: "landlock".into(),
        };
        b.iter(|| format!("{}", black_box(&e)))
    });

    group.finish();
}

#[cfg(feature = "landlock")]
fn bench_landlock(c: &mut Criterion) {
    let mut group = c.benchmark_group("landlock");

    group.bench_function("abi_version", |b| b.iter(agnosys::landlock::abi_version));
    group.bench_function("supported_fs_access", |b| {
        b.iter(agnosys::landlock::supported_fs_access)
    });
    group.bench_function("fs_access_combine", |b| {
        use agnosys::landlock::FsAccess;
        b.iter(|| {
            black_box(
                FsAccess::READ_FILE | FsAccess::WRITE_FILE | FsAccess::EXECUTE | FsAccess::READ_DIR,
            )
        })
    });
    group.bench_function("ruleset_new", |b| {
        use agnosys::landlock::{FsAccess, Ruleset};
        b.iter(|| Ruleset::new(black_box(FsAccess::READ_FILE)))
    });
    if let Ok(rs) = agnosys::landlock::Ruleset::new(agnosys::landlock::FsAccess::READ_FILE) {
        // Leak the ruleset so we can use it in the closure without lifetime issues
        let rs = Box::leak(Box::new(rs));
        group.bench_function("ruleset_allow_path", |b| {
            b.iter(|| {
                rs.allow_path(
                    std::path::Path::new("/tmp"),
                    black_box(agnosys::landlock::FsAccess::READ_FILE),
                )
            })
        });
    }

    group.finish();
}

#[cfg(not(feature = "landlock"))]
fn bench_landlock(_c: &mut Criterion) {}

#[cfg(feature = "seccomp")]
fn bench_seccomp(c: &mut Criterion) {
    use agnosys::seccomp::{Action, FilterBuilder};
    let mut group = c.benchmark_group("seccomp");

    group.bench_function("build_empty", |b| {
        b.iter(|| FilterBuilder::new(Action::KillProcess).build())
    });
    group.bench_function("build_5_rules", |b| {
        b.iter(|| {
            FilterBuilder::new(Action::KillProcess)
                .allow_syscall(libc::SYS_read)
                .allow_syscall(libc::SYS_write)
                .allow_syscall(libc::SYS_exit_group)
                .allow_syscall(libc::SYS_brk)
                .allow_syscall(libc::SYS_mmap)
                .build()
        })
    });
    group.bench_function("build_20_rules", |b| {
        b.iter(|| {
            let mut fb = FilterBuilder::new(Action::KillProcess);
            for i in 0..20 {
                fb = fb.allow_syscall(black_box(i));
            }
            fb.build()
        })
    });
    group.bench_function("filter_len", |b| {
        let f = FilterBuilder::new(Action::KillProcess)
            .allow_syscall(libc::SYS_read)
            .build();
        b.iter(|| black_box(f.len()))
    });
    group.bench_function("filter_is_empty", |b| {
        let f = FilterBuilder::new(Action::KillProcess).build();
        b.iter(|| black_box(f.is_empty()))
    });
    group.finish();
}

#[cfg(not(feature = "seccomp"))]
fn bench_seccomp(_c: &mut Criterion) {}

#[cfg(feature = "udev")]
fn bench_udev(c: &mut Criterion) {
    let mut group = c.benchmark_group("udev");

    group.bench_function("enumerate_net", |b| {
        b.iter(|| agnosys::udev::enumerate(black_box("net")))
    });
    group.bench_function("device_from_syspath_lo", |b| {
        b.iter(|| agnosys::udev::device_from_syspath(std::path::Path::new("/sys/class/net/lo")))
    });
    group.bench_function("device_attr_read", |b| {
        let dev =
            agnosys::udev::device_from_syspath(std::path::Path::new("/sys/class/net/lo")).unwrap();
        b.iter(|| dev.attr(black_box("address")))
    });
    group.bench_function("enumerate_bus_platform", |b| {
        b.iter(|| agnosys::udev::enumerate_bus(black_box("platform")))
    });
    group.bench_function("device_name", |b| {
        let dev =
            agnosys::udev::device_from_syspath(std::path::Path::new("/sys/class/net/lo")).unwrap();
        b.iter(|| black_box(dev.name()))
    });
    group.bench_function("device_properties", |b| {
        let dev =
            agnosys::udev::device_from_syspath(std::path::Path::new("/sys/class/net/lo")).unwrap();
        b.iter(|| black_box(dev.properties()))
    });
    group.bench_function("device_devnode", |b| {
        let dev =
            agnosys::udev::device_from_syspath(std::path::Path::new("/sys/class/net/lo")).unwrap();
        b.iter(|| black_box(dev.devnode()))
    });
    group.bench_function("device_driver", |b| {
        let dev =
            agnosys::udev::device_from_syspath(std::path::Path::new("/sys/class/net/lo")).unwrap();
        b.iter(|| black_box(dev.driver()))
    });
    group.bench_function("device_subsystem", |b| {
        let dev =
            agnosys::udev::device_from_syspath(std::path::Path::new("/sys/class/net/lo")).unwrap();
        b.iter(|| black_box(dev.subsystem()))
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

    // Conditional GPU benchmarks
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
    group.bench_function("current", |b| b.iter(agnosys::netns::current));
    group.bench_function("current_ns_id", |b| b.iter(agnosys::netns::current_ns_id));
    group.bench_function("list", |b| b.iter(agnosys::netns::list));
    group.finish();
}

#[cfg(not(feature = "netns"))]
fn bench_netns(_c: &mut Criterion) {}

#[cfg(feature = "certpin")]
fn bench_certpin(c: &mut Criterion) {
    use agnosys::certpin::{Pin, PinSet};
    let mut group = c.benchmark_group("certpin");
    group.bench_function("sha256_32b", |b| {
        b.iter(|| Pin::from_spki(black_box(&[0xAB; 32])))
    });
    group.bench_function("sha256_256b", |b| {
        b.iter(|| Pin::from_spki(black_box(&[0xAB; 256])))
    });
    group.bench_function("pin_to_base64", |b| {
        let pin = Pin::from_spki(b"test");
        b.iter(|| black_box(&pin).to_base64())
    });
    group.bench_function("pin_to_hex", |b| {
        let pin = Pin::from_spki(b"test");
        b.iter(|| black_box(&pin).to_hex())
    });
    group.bench_function("pinset_validate_hit", |b| {
        let mut ps = PinSet::new();
        ps.add(Pin::from_spki(b"key1"));
        b.iter(|| ps.validate_spki(black_box(b"key1")))
    });
    group.bench_function("pinset_validate_miss", |b| {
        let mut ps = PinSet::new();
        ps.add(Pin::from_spki(b"key1"));
        b.iter(|| ps.validate_spki(black_box(b"key2")))
    });
    group.bench_function("pin_from_base64", |b| {
        let pin = Pin::from_spki(b"bench");
        let b64 = pin.to_base64();
        b.iter(|| Pin::from_base64(black_box(&b64)))
    });
    group.bench_function("pin_from_bytes", |b| {
        let hash = [0xABu8; 32];
        b.iter(|| Pin::from_bytes(black_box(hash)))
    });
    group.bench_function("pinset_add", |b| {
        b.iter(|| {
            let mut ps = PinSet::new();
            ps.add(Pin::from_spki(b"k1"));
            ps.add(Pin::from_spki(b"k2"));
            ps.add(Pin::from_spki(b"k3"));
            black_box(&ps);
        })
    });
    group.finish();
}

#[cfg(not(feature = "certpin"))]
fn bench_certpin(_c: &mut Criterion) {}

#[cfg(feature = "agent")]
fn bench_agent(c: &mut Criterion) {
    let mut group = c.benchmark_group("agent");
    group.bench_function("get_process_name", |b| {
        b.iter(agnosys::agent::get_process_name)
    });
    group.bench_function("get_oom_score_adj", |b| {
        b.iter(agnosys::agent::get_oom_score_adj)
    });
    group.bench_function("current_cgroup", |b| b.iter(agnosys::agent::current_cgroup));
    group.bench_function("is_pid1", |b| b.iter(agnosys::agent::is_pid1));
    group.bench_function("set_process_name", |b| {
        b.iter(|| agnosys::agent::set_process_name(black_box("bench")))
    });
    group.bench_function("has_capability", |b| {
        b.iter(|| agnosys::agent::has_capability(black_box(0)))
    });
    group.bench_function("watchdog_notify", |b| {
        b.iter(agnosys::agent::watchdog_notify)
    });
    group.finish();
}

#[cfg(not(feature = "agent"))]
fn bench_agent(_c: &mut Criterion) {}

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
    group.bench_function("dm_available", |b| b.iter(agnosys::luks::dm_available));
    group.bench_function("list_dm_devices", |b| {
        b.iter(agnosys::luks::list_dm_devices)
    });
    group.bench_function("volume_exists", |b| {
        b.iter(|| agnosys::luks::volume_exists(black_box("nonexistent")))
    });
    group.bench_function("volume_path", |b| {
        b.iter(|| agnosys::luks::volume_path(black_box("test")))
    });
    group.bench_function("volume_status", |b| {
        b.iter(|| agnosys::luks::volume_status(black_box("nonexistent")))
    });
    group.bench_function("is_luks_device", |b| {
        b.iter(|| agnosys::luks::is_luks_device(std::path::Path::new("/dev/null")))
    });
    group.finish();
}

#[cfg(not(feature = "luks"))]
fn bench_luks(_c: &mut Criterion) {}

#[cfg(feature = "dmverity")]
fn bench_dmverity(c: &mut Criterion) {
    let mut group = c.benchmark_group("dmverity");
    group.bench_function("volume_active", |b| {
        b.iter(|| agnosys::dmverity::volume_active(black_box("nonexistent")))
    });
    group.bench_function("volume_path", |b| {
        b.iter(|| agnosys::dmverity::volume_path(black_box("system")))
    });
    group.bench_function("validate_root_hash_match", |b| {
        let a = agnosys::dmverity::RootHash::from_bytes(&[0xAB; 32]);
        let bb = agnosys::dmverity::RootHash::from_bytes(&[0xAB; 32]);
        b.iter(|| agnosys::dmverity::validate_root_hash(black_box(&a), black_box(&bb)))
    });
    group.bench_function("root_hash_from_hex", |b| {
        b.iter(|| agnosys::dmverity::RootHash::from_hex(black_box("abcdef0123456789")))
    });
    group.bench_function("is_verity_device", |b| {
        b.iter(|| agnosys::dmverity::is_verity_device(std::path::Path::new("/dev/null")))
    });
    group.bench_function("verity_status", |b| {
        b.iter(|| agnosys::dmverity::verity_status(black_box("nonexistent")))
    });
    group.finish();
}

#[cfg(not(feature = "dmverity"))]
fn bench_dmverity(_c: &mut Criterion) {}

#[cfg(feature = "audit")]
fn bench_audit(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit");
    group.bench_function("is_available", |b| b.iter(agnosys::audit::is_available));
    group.bench_function("parse_audit_line_simple", |b| {
        b.iter(|| agnosys::audit::parse_audit_line(black_box("key1=val1 key2=val2")))
    });
    group.bench_function("parse_audit_line_real", |b| {
        let line = "type=SYSCALL msg=audit(1234567890.123:42): arch=c000003e syscall=59 success=yes pid=1234 ppid=1 uid=0";
        b.iter(|| agnosys::audit::parse_audit_line(black_box(line)))
    });
    group.bench_function("msg_type_from_raw", |b| {
        b.iter(|| agnosys::audit::AuditMsgType::from_raw(black_box(1300)))
    });
    group.finish();
}

#[cfg(not(feature = "audit"))]
fn bench_audit(_c: &mut Criterion) {}

#[cfg(feature = "pam")]
fn bench_pam(c: &mut Criterion) {
    let mut group = c.benchmark_group("pam");
    group.bench_function("is_available", |b| b.iter(agnosys::pam::is_available));
    group.bench_function("list_services", |b| b.iter(agnosys::pam::list_services));
    group.bench_function("service_exists", |b| {
        b.iter(|| agnosys::pam::service_exists(black_box("login")))
    });
    group.bench_function("parse_pam_config", |b| {
        let config = "auth required pam_unix.so\naccount required pam_unix.so\nsession optional pam_systemd.so";
        b.iter(|| agnosys::pam::parse_pam_config(black_box(config)))
    });
    group.finish();
}

#[cfg(not(feature = "pam"))]
fn bench_pam(_c: &mut Criterion) {}

#[cfg(feature = "mac")]
fn bench_mac(c: &mut Criterion) {
    let mut group = c.benchmark_group("mac");
    group.bench_function("selinux_available", |b| {
        b.iter(agnosys::mac::selinux_available)
    });
    group.bench_function("apparmor_available", |b| {
        b.iter(agnosys::mac::apparmor_available)
    });
    group.bench_function("list_lsms", |b| b.iter(agnosys::mac::list_lsms));
    group.bench_function("current_context", |b| b.iter(agnosys::mac::current_context));
    group.finish();
}

#[cfg(not(feature = "mac"))]
fn bench_mac(_c: &mut Criterion) {}

#[cfg(feature = "ima")]
fn bench_ima(c: &mut Criterion) {
    let mut group = c.benchmark_group("ima");
    group.bench_function("is_available", |b| b.iter(agnosys::ima::is_available));
    group.bench_function("parse_policy", |b| {
        let policy =
            "measure func=FILE_CHECK\ndont_measure fsmagic=0x9fa0\nappraise func=FILE_CHECK";
        b.iter(|| agnosys::ima::parse_policy(black_box(policy)))
    });
    group.finish();
}

#[cfg(not(feature = "ima"))]
fn bench_ima(_c: &mut Criterion) {}

#[cfg(feature = "fuse")]
fn bench_fuse(c: &mut Criterion) {
    let mut group = c.benchmark_group("fuse");
    group.bench_function("is_available", |b| b.iter(agnosys::fuse::is_available));
    group.bench_function("list_mounts", |b| b.iter(agnosys::fuse::list_mounts));
    group.finish();
}

#[cfg(not(feature = "fuse"))]
fn bench_fuse(_c: &mut Criterion) {}

#[cfg(feature = "update")]
fn bench_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("update");
    group.bench_function("is_writable_tmp", |b| {
        b.iter(|| agnosys::update::is_writable(std::path::Path::new("/tmp")))
    });
    group.bench_function("sync_dir_tmp", |b| {
        b.iter(|| agnosys::update::sync_dir(std::path::Path::new("/tmp")))
    });
    group.bench_function("atomic_write", |b| {
        let path = std::path::Path::new("/tmp/agnosys_bench_atomic");
        b.iter(|| agnosys::update::atomic_write(path, black_box(b"bench data")));
        let _ = std::fs::remove_file(path);
    });
    group.finish();
}

#[cfg(not(feature = "update"))]
fn bench_update(_c: &mut Criterion) {}

criterion_group!(
    benches,
    bench_syscall,
    bench_error,
    bench_landlock,
    bench_seccomp,
    bench_udev,
    bench_drm,
    bench_netns,
    bench_certpin,
    bench_agent,
    bench_logging,
    bench_luks,
    bench_dmverity,
    bench_audit,
    bench_pam,
    bench_mac,
    bench_ima,
    bench_fuse,
    bench_update
);
criterion_main!(benches);
