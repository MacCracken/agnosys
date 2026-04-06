#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz JSON deserialization of audit entries (exercises serde_json parsing)
        let _ = serde_json::from_str::<agnosys::audit::RawAuditEntry>(s);

        // Fuzz audit rule validation with arbitrary strings
        if s.len() < 512 {
            let rule = agnosys::audit::AuditRule::file_watch(s, s);
            let _ = rule.validate();

            let rule = agnosys::audit::AuditRule::syscall_watch(
                data.first().copied().unwrap_or(0) as u32,
                s,
            );
            let _ = rule.validate();
        }
    }
});
