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
    group.bench_function("hostname", |b| b.iter(hostname));

    group.finish();
}

fn bench_error(c: &mut Criterion) {
    use agnosys::error::SysError;
    let mut group = c.benchmark_group("error");

    group.bench_function("from_errno_known", |b| {
        b.iter(|| SysError::from_errno(black_box(libc::EPERM)))
    });
    group.bench_function("from_errno_unknown", |b| {
        b.iter(|| SysError::from_errno(black_box(999)))
    });

    group.finish();
}

criterion_group!(benches, bench_syscall, bench_error);
criterion_main!(benches);
