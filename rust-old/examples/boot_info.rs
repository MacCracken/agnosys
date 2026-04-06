//! Example: detect the bootloader and list boot entries.

fn main() -> agnosys::error::Result<()> {
    // Detect installed bootloader (systemd-boot or GRUB2)
    let bootloader = agnosys::bootloader::detect_bootloader()?;
    println!("Detected bootloader: {bootloader}");

    // Read overall boot configuration
    let config = agnosys::bootloader::read_boot_config()?;
    println!("Timeout:  {}s", config.timeout_secs);
    println!(
        "Default:  {}",
        config.default_entry.as_deref().unwrap_or("(none)")
    );

    // List all boot entries
    println!("\nBoot entries ({}):", config.entries.len());
    for entry in &config.entries {
        let marker = if entry.is_default { " [default]" } else { "" };
        println!("  {} — {}{}", entry.id, entry.title, marker);
        println!("    kernel:  {}", entry.linux.display());
        println!("    options: {}", entry.options);
    }

    Ok(())
}
