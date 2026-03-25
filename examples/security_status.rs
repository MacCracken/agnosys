//! Example: query system security posture.

fn main() {
    println!("Security Status:");

    // MAC system
    let mac = agnosys::mac::detect_mac_system();
    println!("  MAC system:   {mac:?}");

    // SELinux context
    match agnosys::mac::get_current_selinux_context() {
        Ok(ctx) if !ctx.is_empty() => println!("  SELinux ctx:  {ctx}"),
        _ => println!("  SELinux ctx:  (none)"),
    }

    // Secure Boot
    match agnosys::secureboot::get_secureboot_status() {
        Ok(state) => println!("  Secure Boot:  {state:?}"),
        Err(e) => println!("  Secure Boot:  error: {e}"),
    }

    // TPM
    println!(
        "  TPM:          {}",
        if agnosys::tpm::tpm_available() {
            "available"
        } else {
            "not available"
        }
    );

    // IMA
    match agnosys::ima::get_ima_status() {
        Ok(status) => println!("  IMA:          {status:?}"),
        Err(_) => println!("  IMA:          not available"),
    }
}
