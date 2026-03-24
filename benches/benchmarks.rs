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

criterion_group!(benches, bench_syscall, bench_error);
criterion_main!(benches);
