//! Example: query recent journal entries with a priority filter.

fn main() -> agnosys::error::Result<()> {
    // Build a filter: last 20 entries at warning priority or higher
    let mut filter = agnosys::journald::JournalFilter::default();
    filter.priority = Some(agnosys::journald::JournalPriority::Warning);
    filter.lines = Some(20);

    // Query the systemd journal
    let entries = agnosys::journald::query_journal(&filter)?;
    println!("Recent journal entries (priority <= warning, max 20):");
    for entry in &entries {
        println!(
            "  [{}] {}: {}",
            entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
            entry.unit,
            entry.message,
        );
    }

    // Show journal disk usage stats
    let stats = agnosys::journald::get_journal_stats()?;
    println!("\nJournal stats:");
    println!("  Total entries: {}", stats.total_entries);
    println!(
        "  Disk usage:    {:.1} MB",
        stats.disk_usage_bytes as f64 / 1_048_576.0
    );

    Ok(())
}
