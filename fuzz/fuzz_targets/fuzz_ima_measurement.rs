#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz IMA measurement log parsing (exercises line-oriented field extraction)
        let _ = agnosys::ima::parse_ima_measurements(s);

        // Fuzz IMA policy rule validation
        let rule = agnosys::ima::ImaPolicyRule::new(
            agnosys::ima::ImaAction::Measure,
            agnosys::ima::ImaTarget::BprmCheck,
        )
        .with_obj_type(s)
        .with_fsuuid(s);
        let _ = rule.validate();
        let _ = rule.to_policy_line();
    }
});
