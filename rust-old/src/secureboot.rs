//! UEFI Secure Boot integration for AGNOS
//!
//! Manages secure boot state, key enrollment, and kernel/module signing.
//! Shells out to `mokutil`, `kmodsign`, and `modinfo` where needed.
//!
//! On non-Linux platforms, all operations return `SysError::NotSupported`.
//!
//! # Security Considerations
//!
//! - EFI variables under `/sys/firmware/efi/efivars/` are firmware-managed;
//!   reading Secure Boot state is unprivileged but modifying keys requires root.
//! - MOK (Machine Owner Key) enrollment via `mokutil` requires physical
//!   presence at the next reboot to confirm — this is by design.
//! - Signature verification trusts the kernel's built-in keyring; a
//!   compromised kernel undermines all verification.
//! - Module signing keys are security-critical and must be stored with
//!   restricted permissions.
//! - Key file paths and EFI variable paths must be validated to prevent path
//!   traversal; callers should canonicalize paths before passing them in.
//! - Enrolled keys (PK, KEK, db) and signing key material are highly sensitive;
//!   leaking private keys allows an attacker to sign arbitrary code as trusted.
//! - An attacker who can enroll their own MOK or replace db entries can sign
//!   malicious bootloaders/modules; physical-presence confirmation and
//!   Setup Mode detection mitigate this but do not eliminate supply-chain risks.

use crate::error::{Result, SysError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Secure Boot state.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureBootState {
    /// Secure Boot is enabled and enforcing.
    Enabled,
    /// Secure Boot is disabled.
    Disabled,
    /// Firmware is in Setup Mode (keys can be enrolled without authentication).
    SetupMode,
    /// System does not support UEFI Secure Boot (legacy BIOS, non-EFI).
    NotSupported,
}

impl SecureBootState {
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            SecureBootState::Enabled => "enabled",
            SecureBootState::Disabled => "disabled",
            SecureBootState::SetupMode => "setup_mode",
            SecureBootState::NotSupported => "not_supported",
        }
    }

    /// Whether enforcement is active.
    #[inline]
    #[must_use]
    pub fn is_enforcing(&self) -> bool {
        matches!(self, SecureBootState::Enabled)
    }
}

impl std::fmt::Display for SecureBootState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// An enrolled MOK (Machine Owner Key).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolledKey {
    /// Subject / Common Name.
    pub subject: String,
    /// Issuer.
    pub issuer: String,
    /// SHA-1 fingerprint (hex).
    pub fingerprint: String,
    /// Not-before date (text).
    pub not_before: String,
    /// Not-after date (text).
    pub not_after: String,
}

/// Information about a kernel module's signature.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleSignatureInfo {
    /// Module file path.
    pub module_path: PathBuf,
    /// Whether the module has a signature attached.
    pub has_signature: bool,
    /// Signer name (if available).
    pub signer: Option<String>,
    /// Signature algorithm (if available).
    pub sig_algorithm: Option<String>,
}

/// An EFI variable read from sysfs.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EfiVariable {
    /// Variable name (e.g. `SecureBoot-8be4df61-...`).
    pub name: String,
    /// Raw hex-encoded value.
    pub value_hex: String,
    /// Size in bytes.
    pub size: usize,
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// Get the current Secure Boot state.
///
/// Reads `/sys/firmware/efi/efivars/SecureBoot-*` or falls back to `mokutil`.
#[must_use = "secure boot status should be used"]
pub fn get_secureboot_status() -> Result<SecureBootState> {
    #[cfg(target_os = "linux")]
    {
        // First check if EFI is even available
        let efi_dir = Path::new("/sys/firmware/efi");
        if !efi_dir.exists() {
            return Ok(SecureBootState::NotSupported);
        }

        // Try reading from efivars
        let efivars_dir = Path::new("/sys/firmware/efi/efivars");
        if efivars_dir.exists()
            && let Some(state) = read_secureboot_efivar(efivars_dir)
        {
            return Ok(state);
        }

        // Fallback: mokutil --sb-state
        match run_command("mokutil", &["--sb-state"]) {
            Ok(output) => {
                let lower = output.to_lowercase();
                if lower.contains("secureboot enabled") {
                    Ok(SecureBootState::Enabled)
                } else if lower.contains("secureboot disabled") {
                    Ok(SecureBootState::Disabled)
                } else if lower.contains("setup mode") {
                    Ok(SecureBootState::SetupMode)
                } else {
                    Ok(SecureBootState::Disabled)
                }
            }
            Err(_) => {
                // mokutil not available; can't determine
                Ok(SecureBootState::NotSupported)
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SysError::NotSupported {
            feature: "secureboot".into(),
        })
    }
}

/// Read the SecureBoot EFI variable from sysfs.
#[cfg(target_os = "linux")]
fn read_secureboot_efivar(efivars_dir: &Path) -> Option<SecureBootState> {
    // The variable is named SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
    let sb_guid = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
    let sb_path = efivars_dir.join(format!("SecureBoot-{}", sb_guid));

    if !sb_path.exists() {
        return None;
    }

    let data = std::fs::read(&sb_path).ok()?;
    // EFI variable: 4-byte attributes + payload
    if data.len() < 5 {
        return None;
    }

    // The actual SecureBoot value is byte 4 (after the 4-byte attributes header)
    let value = data[4];
    if value == 1 {
        // Check SetupMode
        let setup_path = efivars_dir.join(format!("SetupMode-{}", sb_guid));
        if let Ok(setup_data) = std::fs::read(&setup_path)
            && setup_data.len() >= 5
            && setup_data[4] == 1
        {
            return Some(SecureBootState::SetupMode);
        }
        Some(SecureBootState::Enabled)
    } else {
        Some(SecureBootState::Disabled)
    }
}

/// List enrolled MOK (Machine Owner Key) certificates.
///
/// Uses `mokutil --list-enrolled`.
#[must_use = "enrolled keys should be used"]
pub fn list_enrolled_keys() -> Result<Vec<EnrolledKey>> {
    #[cfg(target_os = "linux")]
    {
        let output = run_command("mokutil", &["--list-enrolled"])?;
        parse_mokutil_list(&output)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SysError::NotSupported {
            feature: "secureboot".into(),
        })
    }
}

/// Parse mokutil --list-enrolled output into EnrolledKey structs.
///
/// Each key block looks like:
/// ```text
/// [key 1]
/// SHA1 Fingerprint: aa:bb:cc:...
///   Subject: CN=My Key
///   Issuer: CN=My CA
///   Valid from: ...
///   Valid until: ...
/// ```
#[must_use = "parsed keys should be used"]
pub fn parse_mokutil_list(output: &str) -> Result<Vec<EnrolledKey>> {
    // Pre-count key blocks to avoid repeated Vec reallocation
    let key_count = output
        .lines()
        .filter(|l| l.trim().starts_with("[key "))
        .count();
    let mut keys = Vec::with_capacity(key_count);
    let mut current_subject: Option<&str> = None;
    let mut current_issuer: Option<&str> = None;
    let mut current_fingerprint: Option<String> = None;
    let mut current_not_before: Option<&str> = None;
    let mut current_not_after: Option<&str> = None;
    let mut in_key = false;

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("[key ") {
            // Save previous key if any
            if in_key && let Some(fp) = current_fingerprint.take() {
                keys.push(EnrolledKey {
                    subject: current_subject.unwrap_or("").to_string(),
                    issuer: current_issuer.unwrap_or("").to_string(),
                    fingerprint: fp,
                    not_before: current_not_before.unwrap_or("").to_string(),
                    not_after: current_not_after.unwrap_or("").to_string(),
                });
            }
            current_subject = None;
            current_issuer = None;
            current_fingerprint = None;
            current_not_before = None;
            current_not_after = None;
            in_key = true;
            continue;
        }

        if !in_key {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("SHA1 Fingerprint:") {
            // Fingerprint requires transformation so it must be an owned String
            current_fingerprint = Some(rest.trim().replace(':', "").to_lowercase());
        } else if let Some(rest) = trimmed.strip_prefix("Subject:") {
            current_subject = Some(rest.trim());
        } else if let Some(rest) = trimmed.strip_prefix("Issuer:") {
            current_issuer = Some(rest.trim());
        } else if let Some(rest) = trimmed.strip_prefix("Valid from:") {
            current_not_before = Some(rest.trim());
        } else if let Some(rest) = trimmed.strip_prefix("Valid until:") {
            current_not_after = Some(rest.trim());
        }
    }

    // Don't forget the last key
    if in_key && let Some(fp) = current_fingerprint {
        keys.push(EnrolledKey {
            subject: current_subject.unwrap_or("").to_string(),
            issuer: current_issuer.unwrap_or("").to_string(),
            fingerprint: fp,
            not_before: current_not_before.unwrap_or("").to_string(),
            not_after: current_not_after.unwrap_or("").to_string(),
        });
    }

    Ok(keys)
}

/// Enroll a DER-encoded certificate into the MOK list.
///
/// Uses `mokutil --import <path>`. A reboot is required to complete enrollment.
#[must_use = "enrollment result should be checked"]
pub fn enroll_key(der_path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !der_path.exists() {
            return Err(SysError::InvalidArgument(
                format!("Certificate file not found: {}", der_path.display()).into(),
            ));
        }

        let ext = der_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !["der", "cer", "crt", "pem"].contains(&ext) {
            return Err(SysError::InvalidArgument(
                format!(
                    "Unexpected certificate extension '{}', expected .der/.cer/.crt/.pem",
                    ext
                )
                .into(),
            ));
        }

        run_command_checked("mokutil", &["--import", &der_path.to_string_lossy()])?;

        tracing::info!(
            "Enrolled key {} into MOK — reboot required to complete",
            der_path.display()
        );
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = der_path;
        Err(SysError::NotSupported {
            feature: "secureboot".into(),
        })
    }
}

/// Sign a kernel module with a private key and certificate.
///
/// Uses `kmodsign` (or `/usr/src/linux-headers-*/scripts/sign-file`).
pub fn sign_kernel_module(
    module_path: &Path,
    private_key: &Path,
    certificate: &Path,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !module_path.exists() {
            return Err(SysError::InvalidArgument(
                format!("Module not found: {}", module_path.display()).into(),
            ));
        }
        if !private_key.exists() {
            return Err(SysError::InvalidArgument(
                format!("Private key not found: {}", private_key.display()).into(),
            ));
        }
        if !certificate.exists() {
            return Err(SysError::InvalidArgument(
                format!("Certificate not found: {}", certificate.display()).into(),
            ));
        }

        // Verify it looks like a .ko file
        let ext = module_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if ext != "ko" {
            return Err(SysError::InvalidArgument(
                format!("Expected .ko kernel module, got '.{}'", ext).into(),
            ));
        }

        // Try kmodsign first, fall back to sign-file
        let sign_result = run_command(
            "kmodsign",
            &[
                "sha256",
                &private_key.to_string_lossy(),
                &certificate.to_string_lossy(),
                &module_path.to_string_lossy(),
            ],
        );

        if sign_result.is_err() {
            // Fallback: sign-file from kernel headers
            run_command_checked(
                "/usr/lib/modules-load.d/../linux/scripts/sign-file",
                &[
                    "sha256",
                    &private_key.to_string_lossy(),
                    &certificate.to_string_lossy(),
                    &module_path.to_string_lossy(),
                ],
            )?;
        }

        tracing::info!("Signed kernel module: {}", module_path.display());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (module_path, private_key, certificate);
        Err(SysError::NotSupported {
            feature: "secureboot".into(),
        })
    }
}

/// Verify a kernel module's signature using `modinfo`.
#[must_use = "signature info should be used"]
pub fn verify_module_signature(module_path: &Path) -> Result<ModuleSignatureInfo> {
    #[cfg(target_os = "linux")]
    {
        if !module_path.exists() {
            return Err(SysError::InvalidArgument(
                format!("Module not found: {}", module_path.display()).into(),
            ));
        }

        let output = run_command("modinfo", &[&module_path.to_string_lossy()])?;

        let has_signature = output.contains("sig_id:") || output.contains("signature:");
        let signer = output
            .lines()
            .find(|l| l.starts_with("signer:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string());
        let sig_algorithm = output
            .lines()
            .find(|l| l.starts_with("sig_hashalgo:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string());

        Ok(ModuleSignatureInfo {
            module_path: module_path.to_path_buf(),
            has_signature,
            signer,
            sig_algorithm,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = module_path;
        Err(SysError::NotSupported {
            feature: "secureboot".into(),
        })
    }
}

/// List relevant EFI variables from sysfs.
#[must_use = "EFI variables should be used"]
pub fn get_efi_variables() -> Result<Vec<EfiVariable>> {
    #[cfg(target_os = "linux")]
    {
        let efivars_dir = Path::new("/sys/firmware/efi/efivars");
        if !efivars_dir.exists() {
            return Err(SysError::Unknown(
                "EFI variables directory not found; is this a UEFI system?".into(),
            ));
        }

        let relevant_prefixes = [
            "SecureBoot-",
            "SetupMode-",
            "PK-",
            "KEK-",
            "db-",
            "dbx-",
            "MokList",
        ];

        let mut variables = Vec::new();

        let entries = std::fs::read_dir(efivars_dir)
            .map_err(|e| SysError::Unknown(format!("Failed to read efivars: {}", e).into()))?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                SysError::Unknown(format!("Failed to read efivars entry: {}", e).into())
            })?;
            let name = entry.file_name().to_string_lossy().to_string();

            if !relevant_prefixes.iter().any(|p| name.starts_with(p)) {
                continue;
            }

            let data = std::fs::read(entry.path()).unwrap_or_default();
            let value_hex = hex::encode(&data);
            let size = data.len();

            variables.push(EfiVariable {
                name,
                value_hex,
                size,
            });
        }

        variables.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(variables)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SysError::NotSupported {
            feature: "secureboot".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Run a command and return its stdout.
#[cfg(target_os = "linux")]
fn run_command(cmd: &str, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to run {}: {}", cmd, e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SysError::Unknown(
            format!("{} {} failed: {}", cmd, args.join(" "), stderr.trim()).into(),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run a command and check for success.
#[cfg(target_os = "linux")]
fn run_command_checked(cmd: &str, args: &[&str]) -> Result<()> {
    let _ = run_command(cmd, args)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SecureBootState ---

    #[test]
    fn test_secureboot_state_as_str() {
        assert_eq!(SecureBootState::Enabled.as_str(), "enabled");
        assert_eq!(SecureBootState::Disabled.as_str(), "disabled");
        assert_eq!(SecureBootState::SetupMode.as_str(), "setup_mode");
        assert_eq!(SecureBootState::NotSupported.as_str(), "not_supported");
    }

    #[test]
    fn test_secureboot_state_display() {
        assert_eq!(format!("{}", SecureBootState::Enabled), "enabled");
        assert_eq!(format!("{}", SecureBootState::SetupMode), "setup_mode");
    }

    #[test]
    fn test_secureboot_state_is_enforcing() {
        assert!(SecureBootState::Enabled.is_enforcing());
        assert!(!SecureBootState::Disabled.is_enforcing());
        assert!(!SecureBootState::SetupMode.is_enforcing());
        assert!(!SecureBootState::NotSupported.is_enforcing());
    }

    #[test]
    fn test_secureboot_state_serde_roundtrip() {
        for state in &[
            SecureBootState::Enabled,
            SecureBootState::Disabled,
            SecureBootState::SetupMode,
            SecureBootState::NotSupported,
        ] {
            let json = serde_json::to_string(state).unwrap();
            let back: SecureBootState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, back);
        }
    }

    #[test]
    fn test_secureboot_state_clone_copy_eq() {
        let a = SecureBootState::Enabled;
        let b = a;
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(SecureBootState::Enabled, SecureBootState::Disabled);
    }

    #[test]
    fn test_secureboot_state_debug() {
        assert_eq!(format!("{:?}", SecureBootState::Enabled), "Enabled");
        assert_eq!(format!("{:?}", SecureBootState::SetupMode), "SetupMode");
    }

    // --- parse_mokutil_list ---

    #[test]
    fn test_parse_mokutil_list_single_key() {
        let output = r#"[key 1]
SHA1 Fingerprint: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd
        Subject: CN=AGNOS Signing Key
        Issuer: CN=AGNOS CA
        Valid from: Jan  1 00:00:00 2026 GMT
        Valid until: Dec 31 23:59:59 2030 GMT
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].subject, "CN=AGNOS Signing Key");
        assert_eq!(keys[0].issuer, "CN=AGNOS CA");
        assert_eq!(
            keys[0].fingerprint,
            "aabbccddeeff00112233445566778899aabbccdd"
        );
        assert!(keys[0].not_before.contains("2026"));
        assert!(keys[0].not_after.contains("2030"));
    }

    #[test]
    fn test_parse_mokutil_list_multiple_keys() {
        let output = r#"[key 1]
SHA1 Fingerprint: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd
        Subject: CN=Key One
        Issuer: CN=CA One
        Valid from: Jan 1 2026
        Valid until: Dec 31 2030
[key 2]
SHA1 Fingerprint: 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44
        Subject: CN=Key Two
        Issuer: CN=CA Two
        Valid from: Feb 1 2026
        Valid until: Feb 1 2031
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].subject, "CN=Key One");
        assert_eq!(keys[1].subject, "CN=Key Two");
        assert_eq!(
            keys[1].fingerprint,
            "11223344556677889900aabbccddeeff11223344"
        );
    }

    #[test]
    fn test_parse_mokutil_list_empty() {
        let keys = parse_mokutil_list("").unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_mokutil_list_no_keys() {
        let output = "MokListRT is empty\n";
        let keys = parse_mokutil_list(output).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_mokutil_list_partial_key() {
        // Key header without fingerprint → not included
        let output = "[key 1]\n        Subject: CN=Orphan\n";
        let keys = parse_mokutil_list(output).unwrap();
        assert!(keys.is_empty());
    }

    // --- EnrolledKey ---

    #[test]
    fn test_enrolled_key_serde_roundtrip() {
        let key = EnrolledKey {
            subject: "CN=Test".to_string(),
            issuer: "CN=CA".to_string(),
            fingerprint: "aabb".to_string(),
            not_before: "2026".to_string(),
            not_after: "2030".to_string(),
        };
        let json = serde_json::to_string(&key).unwrap();
        let back: EnrolledKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }

    #[test]
    fn test_enrolled_key_clone_eq() {
        let key = EnrolledKey {
            subject: "CN=A".to_string(),
            issuer: "CN=B".to_string(),
            fingerprint: "ff".to_string(),
            not_before: "now".to_string(),
            not_after: "later".to_string(),
        };
        let cloned = key.clone();
        assert_eq!(key, cloned);
    }

    // --- ModuleSignatureInfo ---

    #[test]
    fn test_module_signature_info_serde() {
        let info = ModuleSignatureInfo {
            module_path: PathBuf::from("/lib/modules/test.ko"),
            has_signature: true,
            signer: Some("AGNOS".to_string()),
            sig_algorithm: Some("sha256".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: ModuleSignatureInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }

    #[test]
    fn test_module_signature_info_no_sig() {
        let info = ModuleSignatureInfo {
            module_path: PathBuf::from("/tmp/unsigned.ko"),
            has_signature: false,
            signer: None,
            sig_algorithm: None,
        };
        assert!(!info.has_signature);
        assert!(info.signer.is_none());
    }

    // --- EfiVariable ---

    #[test]
    fn test_efi_variable_serde() {
        let var = EfiVariable {
            name: "SecureBoot-8be4df61".to_string(),
            value_hex: "0600000001".to_string(),
            size: 5,
        };
        let json = serde_json::to_string(&var).unwrap();
        let back: EfiVariable = serde_json::from_str(&json).unwrap();
        assert_eq!(var, back);
    }

    #[test]
    fn test_efi_variable_debug() {
        let var = EfiVariable {
            name: "PK-1234".to_string(),
            value_hex: "ff".to_string(),
            size: 1,
        };
        let dbg = format!("{:?}", var);
        assert!(dbg.contains("EfiVariable"));
        assert!(dbg.contains("PK-1234"));
    }

    // --- get_secureboot_status (safe to call) ---

    #[test]
    fn test_get_secureboot_status_no_crash() {
        // This may return Enabled, Disabled, or NotSupported depending on the
        // environment — just verify it does not panic.
        let _ = get_secureboot_status();
    }

    // --- Additional SecureBootState tests ---

    #[test]
    fn test_secureboot_state_display_all_variants() {
        assert_eq!(format!("{}", SecureBootState::Disabled), "disabled");
        assert_eq!(
            format!("{}", SecureBootState::NotSupported),
            "not_supported"
        );
    }

    #[test]
    fn test_secureboot_state_debug_all_variants() {
        assert_eq!(format!("{:?}", SecureBootState::Disabled), "Disabled");
        assert_eq!(
            format!("{:?}", SecureBootState::NotSupported),
            "NotSupported"
        );
    }

    #[test]
    fn test_secureboot_state_ne() {
        assert_ne!(SecureBootState::Enabled, SecureBootState::SetupMode);
        assert_ne!(SecureBootState::Disabled, SecureBootState::NotSupported);
        assert_ne!(SecureBootState::SetupMode, SecureBootState::NotSupported);
    }

    // --- Additional parse_mokutil_list tests ---

    #[test]
    fn test_parse_mokutil_list_key_without_subject() {
        let output = r#"[key 1]
SHA1 Fingerprint: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd
        Issuer: CN=CA Only
        Valid from: Jan 1 2026
        Valid until: Dec 31 2030
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].subject, ""); // Subject missing, defaults to empty
        assert_eq!(keys[0].issuer, "CN=CA Only");
    }

    #[test]
    fn test_parse_mokutil_list_key_without_dates() {
        let output = r#"[key 1]
SHA1 Fingerprint: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd
        Subject: CN=No Dates
        Issuer: CN=CA
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].not_before, "");
        assert_eq!(keys[0].not_after, "");
    }

    #[test]
    fn test_parse_mokutil_list_three_keys() {
        let output = r#"[key 1]
SHA1 Fingerprint: 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
        Subject: CN=Key1
        Issuer: CN=CA1
        Valid from: Jan 1 2026
        Valid until: Dec 31 2030
[key 2]
SHA1 Fingerprint: 22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22
        Subject: CN=Key2
        Issuer: CN=CA2
        Valid from: Feb 1 2026
        Valid until: Feb 1 2031
[key 3]
SHA1 Fingerprint: 33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33
        Subject: CN=Key3
        Issuer: CN=CA3
        Valid from: Mar 1 2026
        Valid until: Mar 1 2031
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].subject, "CN=Key1");
        assert_eq!(keys[1].subject, "CN=Key2");
        assert_eq!(keys[2].subject, "CN=Key3");
        assert_eq!(
            keys[0].fingerprint,
            "1111111111111111111111111111111111111111"
        );
        assert_eq!(
            keys[2].fingerprint,
            "3333333333333333333333333333333333333333"
        );
    }

    #[test]
    fn test_parse_mokutil_list_fingerprint_colons_stripped() {
        let output = r#"[key 1]
SHA1 Fingerprint: AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD
        Subject: CN=Test
        Issuer: CN=CA
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(
            keys[0].fingerprint,
            "aabbccddeeff00112233445566778899aabbccdd"
        );
    }

    #[test]
    fn test_parse_mokutil_list_lines_before_first_key_ignored() {
        let output = r#"Some header text
Another line
[key 1]
SHA1 Fingerprint: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd
        Subject: CN=Test
        Issuer: CN=CA
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].subject, "CN=Test");
    }

    #[test]
    fn test_parse_mokutil_list_only_headers_no_fingerprints() {
        let output = "[key 1]\n[key 2]\n[key 3]\n";
        let keys = parse_mokutil_list(output).unwrap();
        // None have fingerprints, so none are included
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_mokutil_list_key_header_variations() {
        // mokutil uses "[key N]" format with different numbers
        let output = r#"[key 42]
SHA1 Fingerprint: ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff
        Subject: CN=Key42
        Issuer: CN=CA42
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].subject, "CN=Key42");
    }

    #[test]
    fn test_parse_mokutil_list_whitespace_only() {
        let output = "   \n  \n   \n";
        let keys = parse_mokutil_list(output).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_mokutil_list_subject_with_multiple_fields() {
        let output = r#"[key 1]
SHA1 Fingerprint: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd
        Subject: C=US, ST=CA, O=AGNOS, CN=Signing Key
        Issuer: C=US, O=AGNOS CA, CN=Root CA
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys[0].subject, "C=US, ST=CA, O=AGNOS, CN=Signing Key");
        assert_eq!(keys[0].issuer, "C=US, O=AGNOS CA, CN=Root CA");
    }

    // --- Additional EnrolledKey tests ---

    #[test]
    fn test_enrolled_key_debug() {
        let key = EnrolledKey {
            subject: "CN=Test".to_string(),
            issuer: "CN=CA".to_string(),
            fingerprint: "aabb".to_string(),
            not_before: "2026".to_string(),
            not_after: "2030".to_string(),
        };
        let dbg = format!("{:?}", key);
        assert!(dbg.contains("EnrolledKey"));
        assert!(dbg.contains("CN=Test"));
    }

    #[test]
    fn test_enrolled_key_ne() {
        let a = EnrolledKey {
            subject: "CN=A".to_string(),
            issuer: "CN=CA".to_string(),
            fingerprint: "aa".to_string(),
            not_before: "now".to_string(),
            not_after: "later".to_string(),
        };
        let b = EnrolledKey {
            subject: "CN=B".to_string(),
            issuer: "CN=CA".to_string(),
            fingerprint: "bb".to_string(),
            not_before: "now".to_string(),
            not_after: "later".to_string(),
        };
        assert_ne!(a, b);
    }

    // --- Additional ModuleSignatureInfo tests ---

    #[test]
    fn test_module_signature_info_debug() {
        let info = ModuleSignatureInfo {
            module_path: PathBuf::from("/tmp/test.ko"),
            has_signature: true,
            signer: Some("AGNOS".to_string()),
            sig_algorithm: Some("sha256".to_string()),
        };
        let dbg = format!("{:?}", info);
        assert!(dbg.contains("ModuleSignatureInfo"));
        assert!(dbg.contains("test.ko"));
    }

    #[test]
    fn test_module_signature_info_clone_eq() {
        let info = ModuleSignatureInfo {
            module_path: PathBuf::from("/tmp/test.ko"),
            has_signature: false,
            signer: None,
            sig_algorithm: None,
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[test]
    fn test_module_signature_info_ne() {
        let a = ModuleSignatureInfo {
            module_path: PathBuf::from("/tmp/a.ko"),
            has_signature: true,
            signer: Some("A".to_string()),
            sig_algorithm: Some("sha256".to_string()),
        };
        let b = ModuleSignatureInfo {
            module_path: PathBuf::from("/tmp/b.ko"),
            has_signature: false,
            signer: None,
            sig_algorithm: None,
        };
        assert_ne!(a, b);
    }

    // --- Additional EfiVariable tests ---

    #[test]
    fn test_efi_variable_clone_eq() {
        let var = EfiVariable {
            name: "SecureBoot-8be4df61".to_string(),
            value_hex: "0600000001".to_string(),
            size: 5,
        };
        let cloned = var.clone();
        assert_eq!(var, cloned);
    }

    #[test]
    fn test_efi_variable_ne() {
        let a = EfiVariable {
            name: "SecureBoot-abc".to_string(),
            value_hex: "01".to_string(),
            size: 1,
        };
        let b = EfiVariable {
            name: "SetupMode-abc".to_string(),
            value_hex: "00".to_string(),
            size: 1,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_efi_variable_empty_value() {
        let var = EfiVariable {
            name: "test".to_string(),
            value_hex: String::new(),
            size: 0,
        };
        assert_eq!(var.size, 0);
        assert!(var.value_hex.is_empty());
    }

    // --- get_efi_variables (safe to call) ---

    #[test]
    fn test_get_efi_variables_no_crash() {
        let _ = get_efi_variables();
    }

    // --- list_enrolled_keys (safe to call) ---

    #[test]
    fn test_list_enrolled_keys_no_crash() {
        let _ = list_enrolled_keys();
    }

    // -----------------------------------------------------------------------
    // Additional coverage — untested code paths
    // -----------------------------------------------------------------------

    // --- parse_mokutil_list: key blocks with extra/interleaved lines ---

    #[test]
    fn test_parse_mokutil_list_extra_unknown_lines() {
        // Lines that don't match any prefix inside a key block are silently skipped
        let output = r#"[key 1]
SHA1 Fingerprint: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd
        Subject: CN=Test
        Issuer: CN=CA
        SomeUnknownField: should be ignored
        AnotherWeirdLine
        Valid from: Jan 1 2026
        Valid until: Dec 31 2030
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].subject, "CN=Test");
        assert_eq!(keys[0].issuer, "CN=CA");
        assert!(keys[0].not_before.contains("2026"));
    }

    #[test]
    fn test_parse_mokutil_list_fingerprint_only() {
        // A key with only a fingerprint (no subject/issuer/dates) should still be captured
        let output = "[key 1]\nSHA1 Fingerprint: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd\n";
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].subject, "");
        assert_eq!(keys[0].issuer, "");
        assert_eq!(keys[0].not_before, "");
        assert_eq!(keys[0].not_after, "");
    }

    #[test]
    fn test_parse_mokutil_list_two_keys_first_missing_fingerprint() {
        // First key has no fingerprint -> skipped when second key header appears
        // Second key has fingerprint -> captured
        let output = r#"[key 1]
        Subject: CN=Orphan
[key 2]
SHA1 Fingerprint: 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44
        Subject: CN=Valid
        Issuer: CN=CA
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].subject, "CN=Valid");
    }

    #[test]
    fn test_parse_mokutil_list_consecutive_key_headers_flush_previous() {
        // Key 1 has fingerprint and subject, then key 2 appears -> key 1 is flushed
        let output = r#"[key 1]
SHA1 Fingerprint: aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa
        Subject: CN=Key1
[key 2]
SHA1 Fingerprint: bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb
        Subject: CN=Key2
"#;
        let keys = parse_mokutil_list(output).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].subject, "CN=Key1");
        assert_eq!(keys[0].issuer, "");
        assert_eq!(keys[1].subject, "CN=Key2");
    }

    // --- SecureBootState: exhaustive as_str + Display coverage ---

    #[test]
    fn test_secureboot_state_as_str_matches_display() {
        for state in &[
            SecureBootState::Enabled,
            SecureBootState::Disabled,
            SecureBootState::SetupMode,
            SecureBootState::NotSupported,
        ] {
            assert_eq!(state.as_str(), format!("{}", state));
        }
    }

    // --- ModuleSignatureInfo: field-level construction with Some/None permutations ---

    #[test]
    fn test_module_signature_info_signer_some_algo_none() {
        let info = ModuleSignatureInfo {
            module_path: PathBuf::from("/lib/modules/partial.ko"),
            has_signature: true,
            signer: Some("Partial Signer".to_string()),
            sig_algorithm: None,
        };
        assert!(info.has_signature);
        assert!(info.signer.is_some());
        assert!(info.sig_algorithm.is_none());
        let json = serde_json::to_string(&info).unwrap();
        let back: ModuleSignatureInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signer, Some("Partial Signer".to_string()));
        assert!(back.sig_algorithm.is_none());
    }

    #[test]
    fn test_module_signature_info_signer_none_algo_some() {
        let info = ModuleSignatureInfo {
            module_path: PathBuf::from("/lib/modules/algo.ko"),
            has_signature: true,
            signer: None,
            sig_algorithm: Some("sha512".to_string()),
        };
        assert!(info.signer.is_none());
        assert_eq!(info.sig_algorithm, Some("sha512".to_string()));
        let json = serde_json::to_string(&info).unwrap();
        let back: ModuleSignatureInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, info);
    }

    // --- EfiVariable: construction edge cases ---

    #[test]
    fn test_efi_variable_large_value() {
        let var = EfiVariable {
            name: "db-8be4df61-93ca-11d2-aa0d-00e098032b8c".to_string(),
            value_hex: "ff".repeat(2048),
            size: 2048,
        };
        assert_eq!(var.size, 2048);
        assert_eq!(var.value_hex.len(), 4096);
        let json = serde_json::to_string(&var).unwrap();
        let back: EfiVariable = serde_json::from_str(&json).unwrap();
        assert_eq!(back, var);
    }

    // --- EnrolledKey: all fields empty ---

    #[test]
    fn test_enrolled_key_all_empty_fields() {
        let key = EnrolledKey {
            subject: String::new(),
            issuer: String::new(),
            fingerprint: String::new(),
            not_before: String::new(),
            not_after: String::new(),
        };
        let json = serde_json::to_string(&key).unwrap();
        let back: EnrolledKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
        assert!(key.subject.is_empty());
    }

    // --- SecureBootState serde from known JSON values ---

    #[test]
    fn test_secureboot_state_deserialize_from_json() {
        let enabled: SecureBootState = serde_json::from_str("\"Enabled\"").unwrap();
        assert_eq!(enabled, SecureBootState::Enabled);
        let disabled: SecureBootState = serde_json::from_str("\"Disabled\"").unwrap();
        assert_eq!(disabled, SecureBootState::Disabled);
        let setup: SecureBootState = serde_json::from_str("\"SetupMode\"").unwrap();
        assert_eq!(setup, SecureBootState::SetupMode);
        let ns: SecureBootState = serde_json::from_str("\"NotSupported\"").unwrap();
        assert_eq!(ns, SecureBootState::NotSupported);
    }

    #[test]
    fn test_secureboot_state_invalid_json() {
        let result = serde_json::from_str::<SecureBootState>("\"Invalid\"");
        assert!(result.is_err());
    }

    // --- parse_mokutil_list: verify pre-capacity optimization ---

    #[test]
    fn test_parse_mokutil_list_large_number_of_keys() {
        let mut output = String::new();
        for i in 0..50 {
            output.push_str(&format!("[key {}]\n", i + 1));
            output.push_str(&format!(
                "SHA1 Fingerprint: {:02x}:{:02x}:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd\n",
                i / 256, i % 256
            ));
            output.push_str(&format!("        Subject: CN=Key{}\n", i));
            output.push_str(&format!("        Issuer: CN=CA{}\n", i));
        }
        let keys = parse_mokutil_list(&output).unwrap();
        assert_eq!(keys.len(), 50);
        assert_eq!(keys[49].subject, "CN=Key49");
    }

    #[test]
    fn send_sync_assertions() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SecureBootState>();
        assert_send_sync::<EnrolledKey>();
        assert_send_sync::<ModuleSignatureInfo>();
        assert_send_sync::<EfiVariable>();
    }
}
