#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz PAM config parsing (exercises line-oriented rule extraction)
        let _ = agnosys::pam::parse_pam_config(s);

        // Fuzz passwd line parsing
        let _ = agnosys::pam::parse_passwd_line(s);

        // Fuzz who output parsing
        let _ = agnosys::pam::parse_who_output(s);

        // Fuzz username validation
        let _ = agnosys::pam::validate_username(s);
    }
});
