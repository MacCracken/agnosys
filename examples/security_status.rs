//! Example: query system security posture.

fn main() {
    println!("Security Status:");

    // LSM
    match agnosys::mac::lsm_string() {
        Ok(lsms) => println!("  LSMs:         {lsms}"),
        Err(_) => println!("  LSMs:         (unavailable)"),
    }

    // SELinux
    if agnosys::mac::selinux_available() {
        match agnosys::mac::selinux_mode() {
            Ok(mode) => println!("  SELinux:      {mode:?}"),
            Err(e) => println!("  SELinux:      error: {e}"),
        }
    } else {
        println!("  SELinux:      not available");
    }

    // AppArmor
    if agnosys::mac::apparmor_available() {
        match agnosys::mac::apparmor_profile_count() {
            Ok(n) => println!("  AppArmor:     {n} profiles loaded"),
            Err(e) => println!("  AppArmor:     error: {e}"),
        }
    } else {
        println!("  AppArmor:     not available");
    }

    // Landlock
    match agnosys::landlock::abi_version() {
        Ok(v) => println!("  Landlock:     ABI v{v}"),
        Err(_) => println!("  Landlock:     not available"),
    }

    // Secure Boot
    if agnosys::secureboot::is_efi() {
        match agnosys::secureboot::state() {
            Ok(s) => {
                println!(
                    "  Secure Boot:  {}",
                    if s.secure_boot { "enabled" } else { "disabled" }
                );
                println!(
                    "  Setup Mode:   {}",
                    if s.setup_mode { "yes" } else { "no" }
                );
            }
            Err(e) => println!("  Secure Boot:  error: {e}"),
        }
    } else {
        println!("  Secure Boot:  not EFI");
    }

    // TPM
    if agnosys::tpm::is_available() {
        match agnosys::tpm::device_info() {
            Ok(info) => println!(
                "  TPM:          {} v{}",
                info.manufacturer, info.tpm_version
            ),
            Err(e) => println!("  TPM:          error: {e}"),
        }
    } else {
        println!("  TPM:          not available");
    }

    // IMA
    println!(
        "  IMA:          {}",
        if agnosys::ima::is_available() {
            "available"
        } else {
            "not available"
        }
    );

    // Security context
    match agnosys::mac::current_context() {
        Ok(ctx) if !ctx.is_empty() => println!("  Context:      {ctx}"),
        _ => println!("  Context:      (none)"),
    }
}
