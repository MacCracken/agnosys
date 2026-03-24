#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    // Write fuzz data to temp file and try to parse as LUKS header
    let tmp = format!("/tmp/fuzz_luks_{}", std::process::id());
    if std::fs::write(&tmp, data).is_ok() {
        let _ = agnosys::luks::is_luks_device(Path::new(&tmp));
        let _ = agnosys::luks::read_header(Path::new(&tmp));
        let _ = std::fs::remove_file(&tmp);
    }
});
