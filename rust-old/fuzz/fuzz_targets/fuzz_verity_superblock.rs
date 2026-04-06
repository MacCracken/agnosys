#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz root hash validation (exercises hex format + length checks)
        let _ = agnosys::dmverity::validate_root_hash(
            s,
            agnosys::dmverity::VerityHashAlgorithm::Sha256,
        );
        let _ = agnosys::dmverity::validate_root_hash(
            s,
            agnosys::dmverity::VerityHashAlgorithm::Sha512,
        );
    }
});
