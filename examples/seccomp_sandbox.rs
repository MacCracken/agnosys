//! Example: build and inspect a seccomp filter (does NOT load it).

fn main() {
    // Build a restrictive filter
    let filter = agnosys::seccomp::FilterBuilder::new(agnosys::seccomp::Action::KillProcess)
        .allow_syscall(libc::SYS_read)
        .allow_syscall(libc::SYS_write)
        .allow_syscall(libc::SYS_exit_group)
        .allow_syscall(libc::SYS_brk)
        .allow_syscall(libc::SYS_mmap)
        .allow_syscall(libc::SYS_munmap)
        .allow_syscall(libc::SYS_close)
        .allow_syscall(libc::SYS_fstat)
        .allow_syscall(libc::SYS_mprotect)
        .allow_syscall(libc::SYS_rt_sigaction)
        .build();

    println!("Seccomp filter built:");
    println!("  BPF instructions: {}", filter.len());
    println!("  Default action:   KillProcess");
    println!("  Allowed syscalls: 10");
    println!();
    println!("(Not loading — would restrict this process)");
}
