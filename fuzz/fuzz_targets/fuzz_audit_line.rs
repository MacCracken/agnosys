#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = agnosys::audit::parse_audit_line(s);
        let _ = agnosys::audit::AuditMsgType::from_raw(data.first().copied().unwrap_or(0) as u16);
    }
});
