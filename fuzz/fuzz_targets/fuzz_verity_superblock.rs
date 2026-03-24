#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let tmp = format!("/tmp/fuzz_verity_{}", std::process::id());
    if std::fs::write(&tmp, data).is_ok() {
        let _ = agnosys::dmverity::is_verity_device(Path::new(&tmp));
        let _ = agnosys::dmverity::read_superblock(Path::new(&tmp));
        let _ = std::fs::remove_file(&tmp);
    }
});
