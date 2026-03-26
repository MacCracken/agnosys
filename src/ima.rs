//! IMA/EVM — Integrity Measurement Architecture and Extended Verification Module
//!
//! Provides file integrity verification using the kernel's IMA subsystem.
//! IMA measures files on access and can enforce policies that prevent
//! execution of tampered binaries.
//!
//! On non-Linux platforms, all operations return `SysError::NotSupported`.

use crate::error::{Result, SysError};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// IMA policy action.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImaAction {
    /// Measure the file (record hash in measurement list).
    Measure,
    /// Appraise the file (verify stored hash on access).
    Appraise,
    /// Log an audit event for the file access.
    Audit,
    /// Compute and store the hash without enforcing anything.
    Hash,
    /// Do not measure/appraise.
    DontMeasure,
    /// Do not appraise.
    DontAppraise,
}

impl ImaAction {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            ImaAction::Measure => "measure",
            ImaAction::Appraise => "appraise",
            ImaAction::Audit => "audit",
            ImaAction::Hash => "hash",
            ImaAction::DontMeasure => "dont_measure",
            ImaAction::DontAppraise => "dont_appraise",
        }
    }
}

impl std::fmt::Display for ImaAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Target type (func) for an IMA policy rule.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImaTarget {
    /// All files opened for read.
    FileCheck,
    /// Binaries executed via exec.
    BprmCheck,
    /// Shared libraries loaded via mmap.
    MmapCheck,
    /// Kernel modules loaded.
    ModuleCheck,
    /// Firmware loaded.
    FirmwareCheck,
    /// Policy files.
    PolicyCheck,
}

impl ImaTarget {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            ImaTarget::FileCheck => "FILE_CHECK",
            ImaTarget::BprmCheck => "BPRM_CHECK",
            ImaTarget::MmapCheck => "MMAP_CHECK",
            ImaTarget::ModuleCheck => "MODULE_CHECK",
            ImaTarget::FirmwareCheck => "FIRMWARE_CHECK",
            ImaTarget::PolicyCheck => "POLICY_CHECK",
        }
    }
}

impl std::fmt::Display for ImaTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single IMA policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImaPolicyRule {
    /// Action to take.
    pub action: ImaAction,
    /// Target (func=).
    pub target: ImaTarget,
    /// Optional uid filter.
    pub uid: Option<u32>,
    /// Optional fowner filter.
    pub fowner: Option<u32>,
    /// Optional fsuuid filter (hex UUID without dashes).
    pub fsuuid: Option<String>,
    /// Optional obj_type filter (e.g., for smack/selinux labels).
    pub obj_type: Option<String>,
    /// Mask filter: MAY_READ, MAY_WRITE, MAY_EXEC, MAY_APPEND.
    pub mask: Option<String>,
}

impl ImaPolicyRule {
    /// Create a new rule with the given action and target.
    pub fn new(action: ImaAction, target: ImaTarget) -> Self {
        Self {
            action,
            target,
            uid: None,
            fowner: None,
            fsuuid: None,
            obj_type: None,
            mask: None,
        }
    }

    /// Set UID filter.
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    /// Set file-owner filter.
    pub fn with_fowner(mut self, fowner: u32) -> Self {
        self.fowner = Some(fowner);
        self
    }

    /// Set filesystem UUID filter (hex, no dashes).
    pub fn with_fsuuid(mut self, fsuuid: impl Into<String>) -> Self {
        self.fsuuid = Some(fsuuid.into());
        self
    }

    /// Set object type filter.
    pub fn with_obj_type(mut self, obj_type: impl Into<String>) -> Self {
        self.obj_type = Some(obj_type.into());
        self
    }

    /// Set access mask filter.
    pub fn with_mask(mut self, mask: impl Into<String>) -> Self {
        self.mask = Some(mask.into());
        self
    }

    /// Validate the rule.
    pub fn validate(&self) -> Result<()> {
        if let Some(ref uuid) = self.fsuuid {
            if uuid.is_empty() {
                return Err(SysError::InvalidArgument("fsuuid cannot be empty".into()));
            }
            if !uuid.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(SysError::InvalidArgument(
                    format!("fsuuid contains non-hex characters: {}", uuid).into(),
                ));
            }
            if uuid.len() != 32 {
                return Err(SysError::InvalidArgument(
                    format!("fsuuid must be 32 hex characters, got {}", uuid.len()).into(),
                ));
            }
        }

        if let Some(ref mask) = self.mask {
            let valid_masks = ["MAY_READ", "MAY_WRITE", "MAY_EXEC", "MAY_APPEND"];
            if !valid_masks.contains(&mask.as_str()) {
                return Err(SysError::InvalidArgument(
                    format!(
                        "Invalid mask '{}', expected one of: {:?}",
                        mask, valid_masks
                    )
                    .into(),
                ));
            }
        }

        Ok(())
    }

    /// Render this rule as a policy line suitable for
    /// `/sys/kernel/security/ima/policy`.
    #[must_use = "policy line should be used"]
    pub fn to_policy_line(&self) -> Result<String> {
        self.validate()?;

        let mut parts = vec![format!("{}", self.action), format!("func={}", self.target)];

        if let Some(uid) = self.uid {
            parts.push(format!("uid={}", uid));
        }
        if let Some(fowner) = self.fowner {
            parts.push(format!("fowner={}", fowner));
        }
        if let Some(ref uuid) = self.fsuuid {
            parts.push(format!("fsuuid={}", uuid));
        }
        if let Some(ref obj_type) = self.obj_type {
            parts.push(format!("obj_type={}", obj_type));
        }
        if let Some(ref mask) = self.mask {
            parts.push(format!("mask={}", mask));
        }

        Ok(parts.join(" "))
    }
}

/// A complete IMA policy (set of rules).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImaPolicy {
    pub rules: Vec<ImaPolicyRule>,
}

impl ImaPolicy {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule to the policy.
    pub fn add_rule(mut self, rule: ImaPolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Validate all rules in the policy.
    pub fn validate(&self) -> Result<()> {
        if self.rules.is_empty() {
            return Err(SysError::InvalidArgument("IMA policy has no rules".into()));
        }
        for (i, rule) in self.rules.iter().enumerate() {
            rule.validate().map_err(|e| {
                SysError::InvalidArgument(format!("Rule {} invalid: {}", i, e).into())
            })?;
        }
        Ok(())
    }

    /// Render the full policy as a string (newline-separated rules).
    #[must_use = "policy string should be used"]
    pub fn to_policy_string(&self) -> Result<String> {
        self.validate()?;
        let lines: Result<Vec<String>> = self.rules.iter().map(|r| r.to_policy_line()).collect();
        Ok(lines?.join("\n"))
    }
}

impl Default for ImaPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// A parsed IMA measurement from `ascii_runtime_measurements`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImaMeasurement {
    /// PCR register index (typically 10).
    pub pcr: u32,
    /// Template hash (hex).
    pub template_hash: String,
    /// Template name (e.g. `ima-ng`, `ima-sig`).
    pub template_name: String,
    /// File data hash with algorithm prefix (e.g. `sha256:abcd...`).
    pub filedata_hash: String,
    /// Filename that was measured.
    pub filename: String,
}

/// IMA subsystem status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImaStatus {
    /// Whether IMA is active (securityfs path exists).
    pub active: bool,
    /// Number of measurements recorded.
    pub measurement_count: usize,
    /// Policy loaded.
    pub policy_loaded: bool,
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// Check whether IMA is active on this system.
#[must_use = "IMA status should be used"]
pub fn get_ima_status() -> Result<ImaStatus> {
    #[cfg(target_os = "linux")]
    {
        let ima_dir = Path::new("/sys/kernel/security/ima");
        let active = ima_dir.exists();

        if !active {
            return Ok(ImaStatus {
                active: false,
                measurement_count: 0,
                policy_loaded: false,
            });
        }

        let measurements_path = ima_dir.join("ascii_runtime_measurements");
        let measurement_count = if measurements_path.exists() {
            std::fs::read_to_string(&measurements_path)
                .map(|s| s.lines().count())
                .unwrap_or(0)
        } else {
            0
        };

        let policy_path = ima_dir.join("policy");
        let policy_loaded = policy_path.exists();

        Ok(ImaStatus {
            active,
            measurement_count,
            policy_loaded,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SysError::NotSupported {
            feature: "ima".into(),
        })
    }
}

/// Parse the IMA ascii_runtime_measurements file.
///
/// Each line has the format:
/// `PCR TEMPLATE_HASH TEMPLATE_NAME FILEDATA_HASH FILENAME`
///
/// Example:
/// `10 abc123...def ima-ng sha256:deadbeef...cafe /usr/bin/bash`
#[must_use = "IMA measurements should be used"]
pub fn read_ima_ascii_runtime_measurements(path: &Path) -> Result<Vec<ImaMeasurement>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        SysError::Unknown(
            format!(
                "Failed to read IMA measurements from {}: {}",
                path.display(),
                e
            )
            .into(),
        )
    })?;

    parse_ima_measurements(&content)
}

/// Parse IMA measurement lines from a string.
#[must_use = "parsed IMA measurements should be used"]
pub fn parse_ima_measurements(content: &str) -> Result<Vec<ImaMeasurement>> {
    let mut measurements = Vec::new();

    for (line_no, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(5, ' ').collect();
        if parts.len() < 5 {
            return Err(SysError::InvalidArgument(
                format!(
                    "IMA measurement line {} has {} fields, expected 5: '{}'",
                    line_no + 1,
                    parts.len(),
                    line
                )
                .into(),
            ));
        }

        let pcr: u32 = parts[0].parse().map_err(|_| {
            SysError::InvalidArgument(
                format!(
                    "IMA measurement line {}: invalid PCR '{}' (not a number)",
                    line_no + 1,
                    parts[0]
                )
                .into(),
            )
        })?;

        measurements.push(ImaMeasurement {
            pcr,
            template_hash: parts[1].to_string(),
            template_name: parts[2].to_string(),
            filedata_hash: parts[3].to_string(),
            filename: parts[4].to_string(),
        });
    }

    Ok(measurements)
}

/// Write IMA policy rules to the kernel's IMA policy file.
///
/// **WARNING:** IMA policy is append-only in the kernel; once rules are
/// written they cannot be removed until the next reboot.
pub fn write_ima_policy(policy: &ImaPolicy) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let policy_str = policy.to_policy_string()?;
        let policy_path = Path::new("/sys/kernel/security/ima/policy");

        if !policy_path.exists() {
            return Err(SysError::Unknown(
                "IMA policy file not found; is IMA enabled?".into(),
            ));
        }

        std::fs::write(policy_path, policy_str.as_bytes()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                SysError::PermissionDenied {
                    operation: "write ima policy".into(),
                }
            } else {
                SysError::Unknown(format!("Failed to write IMA policy: {}", e).into())
            }
        })?;

        tracing::info!("Wrote {} IMA policy rules", policy.rules.len());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
        Err(SysError::NotSupported {
            feature: "ima".into(),
        })
    }
}

/// Verify a file's integrity by reading its `security.ima` xattr and
/// comparing against a freshly computed SHA-256 hash.
///
/// Returns `true` if the stored hash matches.
pub fn verify_file_integrity(path: &Path) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        use sha2::{Digest, Sha256};

        if !path.exists() {
            return Err(SysError::InvalidArgument(
                format!("File not found: {}", path.display()).into(),
            ));
        }

        // Read security.ima xattr via getfattr
        let output = std::process::Command::new("getfattr")
            .args(["-n", "security.ima", "--only-values", "--dump"])
            .arg(path)
            .output()
            .map_err(|e| SysError::Unknown(format!("Failed to run getfattr: {}", e).into()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No such attribute") || stderr.contains("not supported") {
                return Err(SysError::Unknown(
                    format!("File has no security.ima xattr: {}", path.display()).into(),
                ));
            }
            return Err(SysError::Unknown(
                format!("getfattr failed: {}", stderr.trim()).into(),
            ));
        }

        let stored_raw = output.stdout;

        // Compute SHA-256 of the file
        let file_data = std::fs::read(path).map_err(|e| {
            SysError::Unknown(format!("Failed to read {}: {}", path.display(), e).into())
        })?;

        let mut hasher = Sha256::new();
        hasher.update(&file_data);
        let computed = hasher.finalize();
        let computed_hex = hex::encode(computed);

        // The xattr value may be binary or hex; compare both ways.
        let stored_hex = hex::encode(&stored_raw);
        let matches = stored_hex.contains(&computed_hex)
            || String::from_utf8_lossy(&stored_raw)
                .trim()
                .contains(&computed_hex);

        Ok(matches)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(SysError::NotSupported {
            feature: "ima".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- ImaAction tests ---

    #[test]
    fn test_ima_action_as_str() {
        assert_eq!(ImaAction::Measure.as_str(), "measure");
        assert_eq!(ImaAction::Appraise.as_str(), "appraise");
        assert_eq!(ImaAction::Audit.as_str(), "audit");
        assert_eq!(ImaAction::Hash.as_str(), "hash");
        assert_eq!(ImaAction::DontMeasure.as_str(), "dont_measure");
        assert_eq!(ImaAction::DontAppraise.as_str(), "dont_appraise");
    }

    #[test]
    fn test_ima_action_display() {
        assert_eq!(format!("{}", ImaAction::Measure), "measure");
        assert_eq!(format!("{}", ImaAction::Appraise), "appraise");
    }

    #[test]
    fn test_ima_action_serde_roundtrip() {
        for action in &[
            ImaAction::Measure,
            ImaAction::Appraise,
            ImaAction::Audit,
            ImaAction::Hash,
            ImaAction::DontMeasure,
            ImaAction::DontAppraise,
        ] {
            let json = serde_json::to_string(action).unwrap();
            let back: ImaAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, back);
        }
    }

    // --- ImaTarget tests ---

    #[test]
    fn test_ima_target_as_str() {
        assert_eq!(ImaTarget::FileCheck.as_str(), "FILE_CHECK");
        assert_eq!(ImaTarget::BprmCheck.as_str(), "BPRM_CHECK");
        assert_eq!(ImaTarget::MmapCheck.as_str(), "MMAP_CHECK");
        assert_eq!(ImaTarget::ModuleCheck.as_str(), "MODULE_CHECK");
        assert_eq!(ImaTarget::FirmwareCheck.as_str(), "FIRMWARE_CHECK");
        assert_eq!(ImaTarget::PolicyCheck.as_str(), "POLICY_CHECK");
    }

    #[test]
    fn test_ima_target_display() {
        assert_eq!(format!("{}", ImaTarget::BprmCheck), "BPRM_CHECK");
    }

    #[test]
    fn test_ima_target_serde_roundtrip() {
        for target in &[
            ImaTarget::FileCheck,
            ImaTarget::BprmCheck,
            ImaTarget::MmapCheck,
            ImaTarget::ModuleCheck,
            ImaTarget::FirmwareCheck,
            ImaTarget::PolicyCheck,
        ] {
            let json = serde_json::to_string(target).unwrap();
            let back: ImaTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(*target, back);
        }
    }

    // --- ImaPolicyRule builder ---

    #[test]
    fn test_rule_builder_basic() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck);
        assert_eq!(rule.action, ImaAction::Measure);
        assert_eq!(rule.target, ImaTarget::BprmCheck);
        assert!(rule.uid.is_none());
        assert!(rule.fowner.is_none());
        assert!(rule.fsuuid.is_none());
        assert!(rule.mask.is_none());
    }

    #[test]
    fn test_rule_builder_chained() {
        let rule = ImaPolicyRule::new(ImaAction::Appraise, ImaTarget::FileCheck)
            .with_uid(0)
            .with_fowner(1000)
            .with_fsuuid("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
            .with_mask("MAY_EXEC");

        assert_eq!(rule.uid, Some(0));
        assert_eq!(rule.fowner, Some(1000));
        assert_eq!(
            rule.fsuuid,
            Some("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string())
        );
        assert_eq!(rule.mask, Some("MAY_EXEC".to_string()));
    }

    #[test]
    fn test_rule_to_policy_line_basic() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck);
        let line = rule.to_policy_line().unwrap();
        assert_eq!(line, "measure func=BPRM_CHECK");
    }

    #[test]
    fn test_rule_to_policy_line_full() {
        let rule = ImaPolicyRule::new(ImaAction::Appraise, ImaTarget::FileCheck)
            .with_uid(0)
            .with_fowner(1000)
            .with_fsuuid("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
            .with_mask("MAY_READ");
        let line = rule.to_policy_line().unwrap();
        assert!(line.starts_with("appraise func=FILE_CHECK"));
        assert!(line.contains("uid=0"));
        assert!(line.contains("fowner=1000"));
        assert!(line.contains("fsuuid=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));
        assert!(line.contains("mask=MAY_READ"));
    }

    // --- Validation ---

    #[test]
    fn test_rule_validate_bad_fsuuid_non_hex() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck)
            .with_fsuuid("ZZZZ0000111122223333444455556666");
        assert!(rule.validate().is_err());
    }

    #[test]
    fn test_rule_validate_bad_fsuuid_wrong_length() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck).with_fsuuid("aabb");
        let err = rule.validate().unwrap_err();
        assert!(err.to_string().contains("32 hex"));
    }

    #[test]
    fn test_rule_validate_bad_fsuuid_empty() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck).with_fsuuid("");
        let err = rule.validate().unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_rule_validate_bad_mask() {
        let rule =
            ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck).with_mask("INVALID");
        let err = rule.validate().unwrap_err();
        assert!(err.to_string().contains("Invalid mask"));
    }

    #[test]
    fn test_rule_validate_all_valid_masks() {
        for mask in &["MAY_READ", "MAY_WRITE", "MAY_EXEC", "MAY_APPEND"] {
            let rule =
                ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck).with_mask(*mask);
            assert!(rule.validate().is_ok(), "mask '{}' should be valid", mask);
        }
    }

    // --- ImaPolicy ---

    #[test]
    fn test_policy_empty_validation_fails() {
        let policy = ImaPolicy::new();
        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_policy_default_is_empty() {
        let policy = ImaPolicy::default();
        assert!(policy.rules.is_empty());
    }

    #[test]
    fn test_policy_add_rule_and_render() {
        let policy = ImaPolicy::new()
            .add_rule(ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck))
            .add_rule(ImaPolicyRule::new(ImaAction::Appraise, ImaTarget::FileCheck).with_uid(0));

        assert_eq!(policy.rules.len(), 2);
        let rendered = policy.to_policy_string().unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "measure func=BPRM_CHECK");
        assert!(lines[1].contains("appraise func=FILE_CHECK uid=0"));
    }

    #[test]
    fn test_policy_validate_propagates_rule_error() {
        let policy = ImaPolicy::new()
            .add_rule(ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck))
            .add_rule(
                ImaPolicyRule::new(ImaAction::Audit, ImaTarget::FileCheck).with_mask("GARBAGE"),
            );
        let err = policy.validate().unwrap_err();
        assert!(err.to_string().contains("Rule 1"));
    }

    #[test]
    fn test_policy_serde_roundtrip() {
        let policy = ImaPolicy::new()
            .add_rule(ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck))
            .add_rule(
                ImaPolicyRule::new(ImaAction::Appraise, ImaTarget::ModuleCheck).with_fowner(0),
            );
        let json = serde_json::to_string(&policy).unwrap();
        let back: ImaPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rules.len(), 2);
        assert_eq!(back, policy);
    }

    // --- Measurement parsing ---

    #[test]
    fn test_parse_measurements_valid() {
        let input = "\
10 abc123def456abc123def456abc123def456abc1 ima-ng sha256:deadbeefcafe0123 /usr/bin/bash
10 111222333444555666777888999000aaabbbccc ima-ng sha256:0000111122223333 /lib/libc.so.6
";
        let ms = parse_ima_measurements(input).unwrap();
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].pcr, 10);
        assert_eq!(ms[0].template_name, "ima-ng");
        assert_eq!(ms[0].filename, "/usr/bin/bash");
        assert_eq!(ms[1].filename, "/lib/libc.so.6");
    }

    #[test]
    fn test_parse_measurements_empty() {
        let ms = parse_ima_measurements("").unwrap();
        assert!(ms.is_empty());
    }

    #[test]
    fn test_parse_measurements_blank_lines() {
        let input = "\n\n  \n";
        let ms = parse_ima_measurements(input).unwrap();
        assert!(ms.is_empty());
    }

    #[test]
    fn test_parse_measurements_too_few_fields() {
        let input = "10 abc123 ima-ng sha256:dead";
        let err = parse_ima_measurements(input).unwrap_err();
        assert!(err.to_string().contains("fields"));
    }

    #[test]
    fn test_parse_measurements_bad_pcr() {
        let input = "notanumber abc123 ima-ng sha256:dead /file";
        let err = parse_ima_measurements(input).unwrap_err();
        assert!(err.to_string().contains("PCR"));
    }

    #[test]
    fn test_parse_measurements_filename_with_spaces() {
        let input = "10 abc123def456abc123def456abc123def456abc1 ima-ng sha256:dead /path/with spaces/file.txt";
        let ms = parse_ima_measurements(input).unwrap();
        assert_eq!(ms[0].filename, "/path/with spaces/file.txt");
    }

    // --- ImaMeasurement serde ---

    #[test]
    fn test_ima_measurement_serde_roundtrip() {
        let m = ImaMeasurement {
            pcr: 10,
            template_hash: "abc".to_string(),
            template_name: "ima-ng".to_string(),
            filedata_hash: "sha256:dead".to_string(),
            filename: "/bin/test".to_string(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: ImaMeasurement = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    // --- ImaStatus ---

    #[test]
    fn test_ima_status_serde() {
        let s = ImaStatus {
            active: true,
            measurement_count: 42,
            policy_loaded: true,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: ImaStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn test_ima_status_debug() {
        let s = ImaStatus {
            active: false,
            measurement_count: 0,
            policy_loaded: false,
        };
        let dbg = format!("{:?}", s);
        assert!(dbg.contains("ImaStatus"));
    }

    // --- Rule with obj_type ---

    #[test]
    fn test_rule_with_obj_type() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::FileCheck)
            .with_obj_type("unconfined_t");
        let line = rule.to_policy_line().unwrap();
        assert!(line.contains("obj_type=unconfined_t"));
    }

    // --- Clone/Eq ---

    #[test]
    fn test_rule_clone_eq() {
        let rule = ImaPolicyRule::new(ImaAction::Audit, ImaTarget::MmapCheck).with_uid(500);
        let cloned = rule.clone();
        assert_eq!(rule, cloned);
    }

    // --- Additional ImaAction tests ---

    #[test]
    fn test_ima_action_display_all_variants() {
        assert_eq!(format!("{}", ImaAction::Audit), "audit");
        assert_eq!(format!("{}", ImaAction::Hash), "hash");
        assert_eq!(format!("{}", ImaAction::DontMeasure), "dont_measure");
        assert_eq!(format!("{}", ImaAction::DontAppraise), "dont_appraise");
    }

    #[test]
    fn test_ima_action_debug() {
        assert_eq!(format!("{:?}", ImaAction::Measure), "Measure");
        assert_eq!(format!("{:?}", ImaAction::DontMeasure), "DontMeasure");
    }

    #[test]
    fn test_ima_action_clone_copy_eq() {
        let a = ImaAction::Measure;
        let b = a;
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn test_ima_action_ne() {
        assert_ne!(ImaAction::Measure, ImaAction::Appraise);
        assert_ne!(ImaAction::Audit, ImaAction::Hash);
        assert_ne!(ImaAction::DontMeasure, ImaAction::DontAppraise);
    }

    // --- Additional ImaTarget tests ---

    #[test]
    fn test_ima_target_display_all_variants() {
        assert_eq!(format!("{}", ImaTarget::FileCheck), "FILE_CHECK");
        assert_eq!(format!("{}", ImaTarget::MmapCheck), "MMAP_CHECK");
        assert_eq!(format!("{}", ImaTarget::ModuleCheck), "MODULE_CHECK");
        assert_eq!(format!("{}", ImaTarget::FirmwareCheck), "FIRMWARE_CHECK");
        assert_eq!(format!("{}", ImaTarget::PolicyCheck), "POLICY_CHECK");
    }

    #[test]
    fn test_ima_target_debug() {
        assert_eq!(format!("{:?}", ImaTarget::BprmCheck), "BprmCheck");
        assert_eq!(format!("{:?}", ImaTarget::FirmwareCheck), "FirmwareCheck");
    }

    #[test]
    fn test_ima_target_clone_copy_eq() {
        let a = ImaTarget::BprmCheck;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_ima_target_ne() {
        assert_ne!(ImaTarget::FileCheck, ImaTarget::BprmCheck);
        assert_ne!(ImaTarget::ModuleCheck, ImaTarget::FirmwareCheck);
    }

    // --- Additional ImaPolicyRule tests ---

    #[test]
    fn test_rule_ne() {
        let a = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck);
        let b = ImaPolicyRule::new(ImaAction::Appraise, ImaTarget::BprmCheck);
        assert_ne!(a, b);
    }

    #[test]
    fn test_rule_ne_different_target() {
        let a = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck);
        let b = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::FileCheck);
        assert_ne!(a, b);
    }

    #[test]
    fn test_rule_debug() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck)
            .with_uid(0)
            .with_mask("MAY_EXEC");
        let dbg = format!("{:?}", rule);
        assert!(dbg.contains("ImaPolicyRule"));
        assert!(dbg.contains("Measure"));
        assert!(dbg.contains("BprmCheck"));
    }

    #[test]
    fn test_rule_with_obj_type_in_policy_line() {
        let rule = ImaPolicyRule::new(ImaAction::Appraise, ImaTarget::FileCheck)
            .with_obj_type("system_u:object_r:bin_t:s0");
        let line = rule.to_policy_line().unwrap();
        assert!(line.contains("obj_type=system_u:object_r:bin_t:s0"));
    }

    #[test]
    fn test_rule_to_policy_line_all_actions() {
        for (action, expected) in [
            (ImaAction::Measure, "measure"),
            (ImaAction::Appraise, "appraise"),
            (ImaAction::Audit, "audit"),
            (ImaAction::Hash, "hash"),
            (ImaAction::DontMeasure, "dont_measure"),
            (ImaAction::DontAppraise, "dont_appraise"),
        ] {
            let rule = ImaPolicyRule::new(action, ImaTarget::BprmCheck);
            let line = rule.to_policy_line().unwrap();
            assert!(
                line.starts_with(expected),
                "action {:?} should produce line starting with '{}'",
                action,
                expected
            );
        }
    }

    #[test]
    fn test_rule_to_policy_line_all_targets() {
        for (target, expected) in [
            (ImaTarget::FileCheck, "FILE_CHECK"),
            (ImaTarget::BprmCheck, "BPRM_CHECK"),
            (ImaTarget::MmapCheck, "MMAP_CHECK"),
            (ImaTarget::ModuleCheck, "MODULE_CHECK"),
            (ImaTarget::FirmwareCheck, "FIRMWARE_CHECK"),
            (ImaTarget::PolicyCheck, "POLICY_CHECK"),
        ] {
            let rule = ImaPolicyRule::new(ImaAction::Measure, target);
            let line = rule.to_policy_line().unwrap();
            assert!(
                line.contains(&format!("func={}", expected)),
                "target {:?} should produce func={}",
                target,
                expected
            );
        }
    }

    #[test]
    fn test_rule_to_policy_line_uid_zero() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck).with_uid(0);
        let line = rule.to_policy_line().unwrap();
        assert!(line.contains("uid=0"));
    }

    #[test]
    fn test_rule_to_policy_line_uid_large() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck).with_uid(u32::MAX);
        let line = rule.to_policy_line().unwrap();
        assert!(line.contains(&format!("uid={}", u32::MAX)));
    }

    #[test]
    fn test_rule_to_policy_line_fowner_zero() {
        let rule = ImaPolicyRule::new(ImaAction::Appraise, ImaTarget::FileCheck).with_fowner(0);
        let line = rule.to_policy_line().unwrap();
        assert!(line.contains("fowner=0"));
    }

    #[test]
    fn test_rule_validate_valid_fsuuid() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck)
            .with_fsuuid("abcdef01234567890abcdef012345678");
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_rule_validate_fsuuid_with_uppercase() {
        // Uppercase hex should be valid
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck)
            .with_fsuuid("ABCDEF01234567890ABCDEF012345678");
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_rule_validate_fsuuid_31_chars_too_short() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck)
            .with_fsuuid("abcdef0123456789abcdef012345678"); // 31 chars
        let err = rule.validate().unwrap_err();
        assert!(err.to_string().contains("32 hex"));
    }

    #[test]
    fn test_rule_validate_fsuuid_33_chars_too_long() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck)
            .with_fsuuid("abcdef0123456789abcdef0123456789a"); // 33 chars
        let err = rule.validate().unwrap_err();
        assert!(err.to_string().contains("32 hex"));
    }

    #[test]
    fn test_rule_validate_fsuuid_with_dashes_rejected() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck)
            .with_fsuuid("abcdef01-2345-6789-abcd-ef0123456789");
        let err = rule.validate().unwrap_err();
        assert!(err.to_string().contains("non-hex"));
    }

    #[test]
    fn test_rule_validate_no_filters_is_valid() {
        let rule = ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck);
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_rule_serde_roundtrip() {
        let rule = ImaPolicyRule::new(ImaAction::Appraise, ImaTarget::FileCheck)
            .with_uid(0)
            .with_fowner(1000)
            .with_fsuuid("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
            .with_obj_type("unconfined_t")
            .with_mask("MAY_EXEC");
        let json = serde_json::to_string(&rule).unwrap();
        let back: ImaPolicyRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn test_rule_to_policy_line_with_invalid_fsuuid_fails() {
        let rule =
            ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck).with_fsuuid("short");
        assert!(rule.to_policy_line().is_err());
    }

    #[test]
    fn test_rule_to_policy_line_with_invalid_mask_fails() {
        let rule =
            ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck).with_mask("INVALID_MASK");
        assert!(rule.to_policy_line().is_err());
    }

    // --- Additional ImaPolicy tests ---

    #[test]
    fn test_policy_single_rule() {
        let policy =
            ImaPolicy::new().add_rule(ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck));
        assert_eq!(policy.rules.len(), 1);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_policy_to_policy_string_empty_fails() {
        let policy = ImaPolicy::new();
        assert!(policy.to_policy_string().is_err());
    }

    #[test]
    fn test_policy_to_policy_string_with_invalid_rule_fails() {
        let policy = ImaPolicy::new().add_rule(
            ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck).with_mask("BAD"),
        );
        assert!(policy.to_policy_string().is_err());
    }

    #[test]
    fn test_policy_multiple_rules_rendered_newline_separated() {
        let policy = ImaPolicy::new()
            .add_rule(ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck))
            .add_rule(ImaPolicyRule::new(ImaAction::Measure, ImaTarget::MmapCheck))
            .add_rule(ImaPolicyRule::new(
                ImaAction::Appraise,
                ImaTarget::ModuleCheck,
            ));
        let rendered = policy.to_policy_string().unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "measure func=BPRM_CHECK");
        assert_eq!(lines[1], "measure func=MMAP_CHECK");
        assert_eq!(lines[2], "appraise func=MODULE_CHECK");
    }

    #[test]
    fn test_policy_validate_error_includes_rule_index() {
        let policy = ImaPolicy::new()
            .add_rule(ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck))
            .add_rule(ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck))
            .add_rule(
                ImaPolicyRule::new(ImaAction::Audit, ImaTarget::FileCheck).with_fsuuid("not-hex!"),
            );
        let err = policy.validate().unwrap_err();
        assert!(err.to_string().contains("Rule 2"));
    }

    #[test]
    fn test_policy_clone_eq() {
        let policy =
            ImaPolicy::new().add_rule(ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck));
        let cloned = policy.clone();
        assert_eq!(policy, cloned);
    }

    #[test]
    fn test_policy_debug() {
        let policy =
            ImaPolicy::new().add_rule(ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck));
        let dbg = format!("{:?}", policy);
        assert!(dbg.contains("ImaPolicy"));
    }

    #[test]
    fn test_policy_default_eq_new() {
        assert_eq!(ImaPolicy::default(), ImaPolicy::new());
    }

    // --- Additional measurement parsing tests ---

    #[test]
    fn test_parse_measurements_pcr_zero() {
        let input = "0 abc123 ima-ng sha256:dead /boot/vmlinuz";
        let ms = parse_ima_measurements(input).unwrap();
        assert_eq!(ms[0].pcr, 0);
    }

    #[test]
    fn test_parse_measurements_large_pcr() {
        let input = "4294967295 abc123 ima-ng sha256:dead /file";
        let ms = parse_ima_measurements(input).unwrap();
        assert_eq!(ms[0].pcr, u32::MAX);
    }

    #[test]
    fn test_parse_measurements_negative_pcr_fails() {
        let input = "-1 abc123 ima-ng sha256:dead /file";
        let err = parse_ima_measurements(input).unwrap_err();
        assert!(err.to_string().contains("PCR"));
    }

    #[test]
    fn test_parse_measurements_ima_sig_template() {
        let input =
            "10 abc123def456abc123def456abc123def456abc1 ima-sig sha256:dead /usr/sbin/init";
        let ms = parse_ima_measurements(input).unwrap();
        assert_eq!(ms[0].template_name, "ima-sig");
    }

    #[test]
    fn test_parse_measurements_preserves_filedata_hash_prefix() {
        let input =
            "10 abc123def456abc123def456abc123def456abc1 ima-ng sha512:aabbccdd /usr/bin/test";
        let ms = parse_ima_measurements(input).unwrap();
        assert_eq!(ms[0].filedata_hash, "sha512:aabbccdd");
    }

    #[test]
    fn test_parse_measurements_mixed_blank_and_valid_lines() {
        let input =
            "\n10 abc123 ima-ng sha256:dead /file1\n\n  \n10 def456 ima-ng sha256:beef /file2\n";
        let ms = parse_ima_measurements(input).unwrap();
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].filename, "/file1");
        assert_eq!(ms[1].filename, "/file2");
    }

    #[test]
    fn test_parse_measurements_single_field_line_fails() {
        let input = "10";
        let err = parse_ima_measurements(input).unwrap_err();
        assert!(err.to_string().contains("fields"));
    }

    #[test]
    fn test_parse_measurements_two_fields_fails() {
        let input = "10 abc123";
        let err = parse_ima_measurements(input).unwrap_err();
        assert!(err.to_string().contains("fields"));
    }

    #[test]
    fn test_parse_measurements_three_fields_fails() {
        let input = "10 abc123 ima-ng";
        let err = parse_ima_measurements(input).unwrap_err();
        assert!(err.to_string().contains("fields"));
    }

    #[test]
    fn test_parse_measurements_four_fields_fails() {
        let input = "10 abc123 ima-ng sha256:dead";
        let err = parse_ima_measurements(input).unwrap_err();
        assert!(err.to_string().contains("fields"));
    }

    #[test]
    fn test_parse_measurements_error_includes_line_number() {
        let input = "10 abc123 ima-ng sha256:dead /file\nBAD LINE";
        let err = parse_ima_measurements(input).unwrap_err();
        assert!(err.to_string().contains("line 2"));
    }

    #[test]
    fn test_parse_measurements_filename_with_multiple_spaces() {
        let input = "10 abc123 ima-ng sha256:dead /path/to/my file with many spaces.txt";
        let ms = parse_ima_measurements(input).unwrap();
        assert_eq!(ms[0].filename, "/path/to/my file with many spaces.txt");
    }

    // --- Additional ImaMeasurement tests ---

    #[test]
    fn test_ima_measurement_clone_eq() {
        let m = ImaMeasurement {
            pcr: 10,
            template_hash: "abc".to_string(),
            template_name: "ima-ng".to_string(),
            filedata_hash: "sha256:dead".to_string(),
            filename: "/bin/test".to_string(),
        };
        let cloned = m.clone();
        assert_eq!(m, cloned);
    }

    #[test]
    fn test_ima_measurement_ne() {
        let a = ImaMeasurement {
            pcr: 10,
            template_hash: "abc".to_string(),
            template_name: "ima-ng".to_string(),
            filedata_hash: "sha256:dead".to_string(),
            filename: "/bin/a".to_string(),
        };
        let b = ImaMeasurement {
            pcr: 10,
            template_hash: "def".to_string(),
            template_name: "ima-ng".to_string(),
            filedata_hash: "sha256:beef".to_string(),
            filename: "/bin/b".to_string(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_ima_measurement_debug() {
        let m = ImaMeasurement {
            pcr: 10,
            template_hash: "abc".to_string(),
            template_name: "ima-ng".to_string(),
            filedata_hash: "sha256:dead".to_string(),
            filename: "/bin/test".to_string(),
        };
        let dbg = format!("{:?}", m);
        assert!(dbg.contains("ImaMeasurement"));
        assert!(dbg.contains("/bin/test"));
    }

    // --- Additional ImaStatus tests ---

    #[test]
    fn test_ima_status_clone_eq() {
        let s = ImaStatus {
            active: true,
            measurement_count: 100,
            policy_loaded: true,
        };
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn test_ima_status_ne() {
        let a = ImaStatus {
            active: true,
            measurement_count: 100,
            policy_loaded: true,
        };
        let b = ImaStatus {
            active: false,
            measurement_count: 0,
            policy_loaded: false,
        };
        assert_ne!(a, b);
    }

    // --- get_ima_status (safe to call) ---

    #[test]
    fn test_get_ima_status_no_crash() {
        let _ = get_ima_status();
    }

    // --- read_ima_ascii_runtime_measurements with nonexistent file ---

    #[test]
    fn test_read_ima_measurements_nonexistent_file() {
        let result = read_ima_ascii_runtime_measurements(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    // --- Policy ordering tests ---

    #[test]
    fn test_policy_rule_order_preserved() {
        let policy = ImaPolicy::new()
            .add_rule(ImaPolicyRule::new(
                ImaAction::DontMeasure,
                ImaTarget::FileCheck,
            ))
            .add_rule(ImaPolicyRule::new(ImaAction::Measure, ImaTarget::BprmCheck))
            .add_rule(ImaPolicyRule::new(
                ImaAction::Appraise,
                ImaTarget::ModuleCheck,
            ));
        let rendered = policy.to_policy_string().unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with("dont_measure"));
        assert!(lines[1].starts_with("measure"));
        assert!(lines[2].starts_with("appraise"));
    }
}
