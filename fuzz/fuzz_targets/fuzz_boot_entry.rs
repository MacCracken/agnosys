#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz kernel cmdline validation (exercises string parsing + security checks)
        let _ = agnosys::bootloader::validate_kernel_cmdline(s);
    }
});
