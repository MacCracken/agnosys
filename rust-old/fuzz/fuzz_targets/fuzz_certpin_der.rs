#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz pin format validation (exercises base64 + SHA-256 hex format checks)
        let _ = agnosys::certpin::validate_pin_format(s);

        // Fuzz certificate PEM/text parsing
        let _ = agnosys::certpin::parse_openssl_cert(s);

        // Fuzz SPKI pin computation from PEM input
        let _ = agnosys::certpin::compute_spki_pin(s);
    }
});
