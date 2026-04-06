//! Example: open an audit handle and query the audit subsystem status.

fn main() -> agnosys::error::Result<()> {
    // Open an audit connection using the default netlink config
    let config = agnosys::audit::AuditConfig::default();
    let handle = agnosys::audit::open_audit(&config)?;

    // Query current audit subsystem status
    let status = agnosys::audit::get_audit_status(&handle)?;
    println!("Audit Status:");
    println!("  Enabled:        {}", status.enabled);
    println!("  Failure action: {}", status.failure_action);
    println!("  Daemon PID:     {}", status.pid);
    println!("  Backlog limit:  {}", status.backlog_limit);
    println!("  Lost messages:  {}", status.lost);
    println!("  Current backlog:{}", status.backlog);

    // Clean up
    agnosys::audit::close_audit(handle);
    Ok(())
}
