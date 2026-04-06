#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz LUKS config validation (exercises name/size/cipher validation)
        if s.len() < 256 {
            let config = agnosys::luks::LuksConfig::for_agent(s, 64);
            let _ = config.validate();
        }

        // Fuzz passphrase-based key derivation validation
        let _ = agnosys::luks::LuksKey::from_passphrase(s);
    }
});
