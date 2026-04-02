//! Example: list system users and active login sessions.

fn main() -> agnosys::error::Result<()> {
    // List all system users from /etc/passwd
    let users = agnosys::pam::list_users()?;
    println!("System users ({} total):", users.len());
    for u in &users {
        println!("  {} (uid={}, gid={}, home={})", u.username, u.uid, u.gid, u.home_dir.display());
    }

    println!();

    // List active login sessions (from `who`)
    let sessions = agnosys::pam::list_sessions()?;
    if sessions.is_empty() {
        println!("No active sessions.");
    } else {
        println!("Active sessions ({}):", sessions.len());
        for s in &sessions {
            println!("  {} on {} since {}",
                s.user,
                s.tty.as_deref().unwrap_or("(unknown)"),
                s.login_time,
            );
        }
    }

    Ok(())
}
