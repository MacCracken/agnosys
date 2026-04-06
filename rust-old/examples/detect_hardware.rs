//! Example: basic system info using agnosys syscall wrappers.

fn main() {
    println!("PID: {}", agnosys::syscall::getpid());
    println!("UID: {}", agnosys::syscall::getuid());
    println!("Root: {}", agnosys::syscall::is_root());
    println!("Hostname: {}", agnosys::syscall::hostname().unwrap());
    println!("Uptime: {:.0}s", agnosys::syscall::uptime().unwrap());

    let total = agnosys::syscall::total_memory().unwrap();
    let avail = agnosys::syscall::available_memory().unwrap();
    println!(
        "Memory: {:.1} GB total, {:.1} GB available",
        total as f64 / 1e9,
        avail as f64 / 1e9
    );
}
