#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the SPKI pin computation (exercises SHA-256 + DER parsing)
    let pin = agnosys::certpin::Pin::from_spki(data);
    let _ = pin.to_base64();
    let _ = pin.to_hex();

    // Fuzz the PinSet validate_der path (exercises DER/ASN.1 extraction)
    let mut ps = agnosys::certpin::PinSet::new();
    ps.add(agnosys::certpin::Pin::from_spki(b"known"));
    let _ = ps.validate_der(data);

    // Fuzz base64 decode
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = agnosys::certpin::Pin::from_base64(s);
    }
});
