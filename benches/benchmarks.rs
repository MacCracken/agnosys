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
    group.finish();
}

#[cfg(not(feature = "udev"))]
fn bench_udev(_c: &mut Criterion) {}

criterion_group!(
    benches,
    bench_syscall,
    bench_error,
    bench_landlock,
    bench_seccomp,
    bench_udev
);
criterion_main!(benches);
