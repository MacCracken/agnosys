#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz udevadm info output parsing (exercises key=value extraction)
        let _ = agnosys::udev::parse_udevadm_info(s);

        // Fuzz device subsystem parsing
        let _ = agnosys::udev::DeviceSubsystem::parse(s);

        // Fuzz device event parsing
        let _ = agnosys::udev::DeviceEvent::parse(s);
    }
});
