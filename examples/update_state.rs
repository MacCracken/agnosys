//! Example: show current A/B update slot and check rollback status.

fn main() -> agnosys::error::Result<()> {
    // Detect which slot is currently booted
    let current_slot = agnosys::update::get_current_slot()?;
    println!("Current boot slot: {current_slot}");
    println!("Inactive slot:     {}", current_slot.other());

    // Build a sample update state to demonstrate rollback detection
    let mut state = agnosys::update::UpdateState::new(current_slot, "2025.4.1");
    state.rollback_available = true;
    state.boot_count_since_update = 5;
    state.pending_update = Some("2025.4.2".into());

    println!("\nSimulated update state:");
    println!("  Current version: {}", state.current_version);
    println!("  Pending update:  {:?}", state.pending_update);
    println!("  Rollback avail:  {}", state.rollback_available);
    println!("  Boots since upd: {}", state.boot_count_since_update);

    // Check if a rollback is needed (threshold = 3 boots)
    let rollback = agnosys::update::needs_rollback(&state, 3);
    println!("  Needs rollback (max 3 boots): {rollback}");

    Ok(())
}
