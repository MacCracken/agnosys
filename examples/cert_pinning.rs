//! Example: show default AGNOS certificate pins and verify a pin.

fn main() -> agnosys::error::Result<()> {
    // Load the built-in AGNOS development pin set
    let pin_set = agnosys::certpin::default_agnos_pins();
    println!("Default AGNOS pin set (enforce={}):", pin_set.enforce);
    for pin in &pin_set.pins {
        println!("  {} — {} primary pin(s), {} backup(s)",
            pin.host, pin.pin_sha256.len(), pin.backup_pins.len());
    }

    // Verify a known pin against the set
    let host = "api.anthropic.com";
    let test_pin = "jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=";
    let result = agnosys::certpin::verify_pin(host, test_pin, &pin_set);
    println!("\nVerify pin for {host}: {result:?}");

    // Check for pins expiring within 30 days
    let expiring = agnosys::certpin::check_pin_expiry(&pin_set);
    if expiring.is_empty() {
        println!("No pins expiring within 30 days.");
    } else {
        println!("Pins expiring soon:");
        for p in &expiring {
            println!("  {} — expires {:?}", p.host, p.expires);
        }
    }

    Ok(())
}
