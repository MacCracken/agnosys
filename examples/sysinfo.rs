//! Example: system information via a single sysinfo(2) call.

fn main() {
    let info = agnosys::syscall::query_sysinfo().unwrap();
    println!("System Information (single syscall):");
    println!("  Uptime:       {:.0}s", info.uptime());
    println!("  Total RAM:    {:.1} GB", info.total_memory() as f64 / 1e9);
    println!("  Free RAM:     {:.1} GB", info.free_memory() as f64 / 1e9);
    println!("  Processes:    {}", info.procs());
    println!("  Hostname:     {}", agnosys::syscall::hostname().unwrap());
    println!("  PID:          {}", agnosys::syscall::getpid());
    println!("  Root:         {}", agnosys::syscall::is_root());
}
