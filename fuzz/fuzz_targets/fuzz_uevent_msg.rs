#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the uevent parser by creating a Monitor-like scenario
    // We can't call parse_uevent_msg directly (private), but we can
    // exercise the public API paths that accept arbitrary data

    // Fuzz device_from_syspath with arbitrary paths
    if let Ok(s) = std::str::from_utf8(data) {
        if s.len() < 256 && !s.contains('\0') {
            let _ = agnosys::udev::device_from_syspath(std::path::Path::new(s));
        }
    }
});
