//! Bootloader Configuration Management
//!
//! Supports both systemd-boot and GRUB2 bootloaders. Auto-detects which
//! bootloader is installed and provides a unified interface for reading/writing
//! boot configuration, managing boot entries, and modifying kernel command lines.
//!
//! On non-Linux platforms, all operations return `SysError::NotSupported`.

use crate::error::{Result, SysError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Detected bootloader type.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Bootloader {
    SystemdBoot,
    Grub2,
    Unknown,
}

impl std::fmt::Display for Bootloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bootloader::SystemdBoot => write!(f, "systemd-boot"),
            Bootloader::Grub2 => write!(f, "GRUB2"),
            Bootloader::Unknown => write!(f, "unknown"),
        }
    }
}

/// A single boot entry (kernel + initrd + options).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootEntry {
    /// Unique identifier (filename stem for systemd-boot, menuentry index/id for GRUB2)
    pub id: String,
    /// Human-readable title shown in the boot menu
    pub title: String,
    /// Path to the kernel image (e.g. `/boot/vmlinuz-6.6.0-agnos`)
    pub linux: PathBuf,
    /// Path to the initramfs image
    pub initrd: Option<PathBuf>,
    /// Kernel command line options
    pub options: String,
    /// Whether this entry is the current default
    pub is_default: bool,
    /// Kernel version string (parsed from the entry or filename)
    pub version: Option<String>,
}

/// Aggregate boot configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootConfig {
    /// Detected bootloader
    pub bootloader: Bootloader,
    /// Boot menu timeout in seconds
    pub timeout_secs: u32,
    /// ID of the default boot entry
    pub default_entry: Option<String>,
    /// All available boot entries
    pub entries: Vec<BootEntry>,
}

// ---------------------------------------------------------------------------
// Well-known paths
// ---------------------------------------------------------------------------

const SYSTEMD_BOOT_DIR: &str = "/boot/efi/EFI/systemd";
const SYSTEMD_LOADER_CONF: &str = "/boot/loader/loader.conf";
const SYSTEMD_ENTRIES_DIR: &str = "/boot/loader/entries";

const GRUB_CFG: &str = "/boot/grub/grub.cfg";
const GRUB_DEFAULT_FILE: &str = "/etc/default/grub";

/// Kernel command-line tokens that must never appear (security-sensitive).
const DANGEROUS_CMDLINE_TOKENS: &[&str] = &[
    "init=/bin/sh",
    "init=/bin/bash",
    "init=/bin/dash",
    "init=/sbin/init.debug",
    "single",
    "emergency",
    "rd.break",
    "debug_shell",
    "systemd.debug-shell",
];

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Detect the installed bootloader by probing well-known paths.
///
/// Checks for systemd-boot first (presence of `/boot/efi/EFI/systemd/`),
/// then GRUB2 (`/boot/grub/grub.cfg`). Returns `Bootloader::Unknown` if
/// neither is found.
pub fn detect_bootloader() -> Result<Bootloader> {
    #[cfg(target_os = "linux")]
    {
        if Path::new(SYSTEMD_BOOT_DIR).is_dir() {
            return Ok(Bootloader::SystemdBoot);
        }
        if Path::new(GRUB_CFG).is_file() {
            return Ok(Bootloader::Grub2);
        }
        Ok(Bootloader::Unknown)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SysError::NotSupported {
            feature: "bootloader".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Reading configuration
// ---------------------------------------------------------------------------

/// Read the full boot configuration (bootloader type, timeout, default entry, and all entries).
pub fn read_boot_config() -> Result<BootConfig> {
    #[cfg(target_os = "linux")]
    {
        let bootloader = detect_bootloader()?;
        match bootloader {
            Bootloader::SystemdBoot => read_systemd_boot_config(),
            Bootloader::Grub2 => read_grub2_config(),
            Bootloader::Unknown => {
                Err(SysError::Unknown("No supported bootloader detected".into()))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SysError::NotSupported {
            feature: "bootloader".into(),
        })
    }
}

/// List all available boot entries for the detected bootloader.
pub fn list_boot_entries() -> Result<Vec<BootEntry>> {
    let config = read_boot_config()?;
    Ok(config.entries)
}

/// Get the current default boot entry.
pub fn get_default_entry() -> Result<BootEntry> {
    let config = read_boot_config()?;
    config
        .entries
        .into_iter()
        .find(|e| e.is_default)
        .or(None)
        .ok_or_else(|| SysError::Unknown("No default boot entry found".into()))
}

/// Set the default boot entry by its ID.
pub fn set_default_entry(id: &str) -> Result<()> {
    validate_entry_id(id)?;

    #[cfg(target_os = "linux")]
    {
        let bootloader = detect_bootloader()?;
        match bootloader {
            Bootloader::SystemdBoot => set_systemd_boot_default(id),
            Bootloader::Grub2 => set_grub2_default(id),
            Bootloader::Unknown => {
                Err(SysError::Unknown("No supported bootloader detected".into()))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = id;
        Err(SysError::NotSupported {
            feature: "bootloader".into(),
        })
    }
}

/// Modify the kernel command line for a specific boot entry.
pub fn set_kernel_cmdline(entry_id: &str, options: &str) -> Result<()> {
    validate_entry_id(entry_id)?;
    validate_kernel_cmdline(options)?;

    #[cfg(target_os = "linux")]
    {
        let bootloader = detect_bootloader()?;
        match bootloader {
            Bootloader::SystemdBoot => set_systemd_boot_cmdline(entry_id, options),
            Bootloader::Grub2 => set_grub2_cmdline(entry_id, options),
            Bootloader::Unknown => {
                Err(SysError::Unknown("No supported bootloader detected".into()))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (entry_id, options);
        Err(SysError::NotSupported {
            feature: "bootloader".into(),
        })
    }
}

/// Set the boot menu timeout in seconds (capped at 300).
pub fn set_timeout(seconds: u32) -> Result<()> {
    if seconds > 300 {
        return Err(SysError::InvalidArgument(
            format!("Timeout {} exceeds maximum of 300 seconds", seconds).into(),
        ));
    }

    #[cfg(target_os = "linux")]
    {
        let bootloader = detect_bootloader()?;
        match bootloader {
            Bootloader::SystemdBoot => set_systemd_boot_timeout(seconds),
            Bootloader::Grub2 => set_grub2_timeout(seconds),
            Bootloader::Unknown => {
                Err(SysError::Unknown("No supported bootloader detected".into()))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = seconds;
        Err(SysError::NotSupported {
            feature: "bootloader".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate kernel command-line parameters.
///
/// Rejects dangerous options such as `init=/bin/sh`, `single`, `rd.break`,
/// and `debug_shell` that could bypass normal boot security.
pub fn validate_kernel_cmdline(options: &str) -> Result<()> {
    if options.len() > 4096 {
        return Err(SysError::InvalidArgument(
            "Kernel command line exceeds 4096-character limit".into(),
        ));
    }

    let lower = options.to_lowercase();
    for token in DANGEROUS_CMDLINE_TOKENS {
        if lower.contains(&token.to_lowercase()) {
            return Err(SysError::InvalidArgument(
                format!(
                    "Kernel command line contains dangerous parameter: {}",
                    token
                )
                .into(),
            ));
        }
    }

    // Reject non-printable / non-ASCII characters
    if options
        .chars()
        .any(|c| !c.is_ascii() || c.is_ascii_control())
    {
        return Err(SysError::InvalidArgument(
            "Kernel command line contains non-printable or non-ASCII characters".into(),
        ));
    }

    Ok(())
}

/// Validate that a boot-entry ID is well-formed.
fn validate_entry_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(SysError::InvalidArgument(
            "Boot entry ID cannot be empty".into(),
        ));
    }
    if id.len() > 256 {
        return Err(SysError::InvalidArgument(
            "Boot entry ID too long (max 256)".into(),
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(SysError::InvalidArgument(
            format!("Boot entry ID contains invalid characters: {}", id).into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// systemd-boot implementation
// ---------------------------------------------------------------------------

/// Parse `/boot/loader/loader.conf` and `/boot/loader/entries/*.conf`.
#[cfg(target_os = "linux")]
fn read_systemd_boot_config() -> Result<BootConfig> {
    let (timeout, default_id) = parse_loader_conf(Path::new(SYSTEMD_LOADER_CONF))?;
    let entries =
        parse_systemd_boot_entries(Path::new(SYSTEMD_ENTRIES_DIR), default_id.as_deref())?;

    Ok(BootConfig {
        bootloader: Bootloader::SystemdBoot,
        timeout_secs: timeout,
        default_entry: default_id,
        entries,
    })
}

/// Parse `loader.conf` for `timeout` and `default` directives.
#[cfg(target_os = "linux")]
fn parse_loader_conf(path: &Path) -> Result<(u32, Option<String>)> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        SysError::Unknown(format!("Failed to read {}: {}", path.display(), e).into())
    })?;

    let mut timeout: u32 = 5; // sensible default
    let mut default_id: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(val) = line.strip_prefix("timeout") {
            let val = val.trim();
            if let Ok(t) = val.parse::<u32>() {
                timeout = t;
            }
        } else if let Some(val) = line.strip_prefix("default") {
            let val = val.trim().trim_end_matches(".conf");
            if !val.is_empty() {
                default_id = Some(val.to_string());
            }
        }
    }

    Ok((timeout, default_id))
}

/// Parse all `*.conf` files in the systemd-boot entries directory.
#[cfg(target_os = "linux")]
fn parse_systemd_boot_entries(dir: &Path, default_id: Option<&str>) -> Result<Vec<BootEntry>> {
    let mut entries = Vec::new();

    let read_dir = std::fs::read_dir(dir).map_err(|e| {
        SysError::Unknown(format!("Failed to read entries dir {}: {}", dir.display(), e).into())
    })?;

    for entry in read_dir {
        let entry =
            entry.map_err(|e| SysError::Unknown(format!("Dir entry error: {}", e).into()))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("conf") {
            continue;
        }

        if let Ok(boot_entry) = parse_systemd_boot_entry(&path, default_id) {
            entries.push(boot_entry);
        }
    }

    // Sort by ID for deterministic output
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(entries)
}

/// Parse a single systemd-boot entry file.
#[cfg(target_os = "linux")]
fn parse_systemd_boot_entry(path: &Path, default_id: Option<&str>) -> Result<BootEntry> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        SysError::Unknown(format!("Failed to read entry {}: {}", path.display(), e).into())
    })?;

    let id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    let mut title = String::new();
    let mut linux = PathBuf::new();
    let mut initrd: Option<PathBuf> = None;
    let mut options = String::new();
    let mut version: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(val) = line.strip_prefix("title") {
            title = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("linux") {
            linux = PathBuf::from(val.trim());
        } else if let Some(val) = line.strip_prefix("initrd") {
            initrd = Some(PathBuf::from(val.trim()));
        } else if let Some(val) = line.strip_prefix("options") {
            options = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("version") {
            version = Some(val.trim().to_string());
        }
    }

    let is_default = default_id.is_some_and(|d| d == id);

    Ok(BootEntry {
        id,
        title,
        linux,
        initrd,
        options,
        is_default,
        version,
    })
}

#[cfg(target_os = "linux")]
fn set_systemd_boot_default(id: &str) -> Result<()> {
    let conf_path = Path::new(SYSTEMD_LOADER_CONF);
    let content = std::fs::read_to_string(conf_path).map_err(|e| {
        SysError::Unknown(format!("Failed to read {}: {}", conf_path.display(), e).into())
    })?;

    let mut lines: Vec<String> = Vec::new();
    let mut found = false;
    for line in content.lines() {
        if line.trim().starts_with("default") {
            lines.push(format!("default {}.conf", id));
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !found {
        lines.push(format!("default {}.conf", id));
    }

    let new_content = lines.join("\n") + "\n";
    std::fs::write(conf_path, new_content).map_err(|e| {
        SysError::Unknown(format!("Failed to write {}: {}", conf_path.display(), e).into())
    })?;

    tracing::info!("Set systemd-boot default entry to: {}", id);
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_systemd_boot_cmdline(entry_id: &str, options: &str) -> Result<()> {
    let entry_path = Path::new(SYSTEMD_ENTRIES_DIR).join(format!("{}.conf", entry_id));
    if !entry_path.exists() {
        return Err(SysError::InvalidArgument(
            format!("Boot entry not found: {}", entry_id).into(),
        ));
    }

    let content = std::fs::read_to_string(&entry_path).map_err(|e| {
        SysError::Unknown(format!("Failed to read {}: {}", entry_path.display(), e).into())
    })?;

    let mut lines: Vec<String> = Vec::new();
    let mut found = false;
    for line in content.lines() {
        if line.trim().starts_with("options") {
            lines.push(format!("options {}", options));
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !found {
        lines.push(format!("options {}", options));
    }

    let new_content = lines.join("\n") + "\n";
    std::fs::write(&entry_path, new_content).map_err(|e| {
        SysError::Unknown(format!("Failed to write {}: {}", entry_path.display(), e).into())
    })?;

    tracing::info!("Set kernel cmdline for {} to: {}", entry_id, options);
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_systemd_boot_timeout(seconds: u32) -> Result<()> {
    let conf_path = Path::new(SYSTEMD_LOADER_CONF);
    let content = std::fs::read_to_string(conf_path).map_err(|e| {
        SysError::Unknown(format!("Failed to read {}: {}", conf_path.display(), e).into())
    })?;

    let mut lines: Vec<String> = Vec::new();
    let mut found = false;
    for line in content.lines() {
        if line.trim().starts_with("timeout") {
            lines.push(format!("timeout {}", seconds));
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !found {
        lines.push(format!("timeout {}", seconds));
    }

    let new_content = lines.join("\n") + "\n";
    std::fs::write(conf_path, new_content).map_err(|e| {
        SysError::Unknown(format!("Failed to write {}: {}", conf_path.display(), e).into())
    })?;

    tracing::info!("Set systemd-boot timeout to: {}s", seconds);
    Ok(())
}

// ---------------------------------------------------------------------------
// GRUB2 implementation
// ---------------------------------------------------------------------------

/// Read GRUB2 configuration by parsing `grub.cfg` and `/etc/default/grub`.
#[cfg(target_os = "linux")]
fn read_grub2_config() -> Result<BootConfig> {
    let timeout = parse_grub_default_timeout()?;
    let (entries, default_id) = parse_grub_cfg(Path::new(GRUB_CFG))?;

    Ok(BootConfig {
        bootloader: Bootloader::Grub2,
        timeout_secs: timeout,
        default_entry: default_id.clone(),
        entries,
    })
}

/// Parse `GRUB_TIMEOUT` from `/etc/default/grub`.
#[cfg(target_os = "linux")]
fn parse_grub_default_timeout() -> Result<u32> {
    let content = std::fs::read_to_string(GRUB_DEFAULT_FILE).map_err(|e| {
        SysError::Unknown(format!("Failed to read {}: {}", GRUB_DEFAULT_FILE, e).into())
    })?;

    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("GRUB_TIMEOUT=") {
            let val = val.trim().trim_matches('"');
            if let Ok(t) = val.parse::<u32>() {
                return Ok(t);
            }
        }
    }

    Ok(5) // default
}

/// Parse `grub.cfg` for menuentry blocks.
///
/// Extracts title, linux, initrd, and options from each menuentry.
#[cfg(target_os = "linux")]
fn parse_grub_cfg(path: &Path) -> Result<(Vec<BootEntry>, Option<String>)> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        SysError::Unknown(format!("Failed to read {}: {}", path.display(), e).into())
    })?;

    let mut entries = Vec::new();
    let mut default_entry: Option<String> = None;
    let mut entry_index: usize = 0;

    // Parse `set default="..."` directive
    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("set default=\"")
            && let Some(val) = val.strip_suffix('"')
        {
            default_entry = Some(val.to_string());
        }
    }

    // Parse menuentry blocks
    let mut in_entry = false;
    let mut title = String::new();
    let mut linux = PathBuf::new();
    let mut initrd: Option<PathBuf> = None;
    let mut options = String::new();

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with("menuentry ") {
            in_entry = true;
            // Extract title from: menuentry 'Title' ... {
            title = line
                .split('\'')
                .nth(1)
                .or_else(|| line.split('"').nth(1))
                .unwrap_or("Unknown")
                .to_string();
            linux = PathBuf::new();
            initrd = None;
            options = String::new();
        } else if in_entry && line == "}" {
            let id = entry_index.to_string();
            let is_default = default_entry
                .as_ref()
                .map_or(entry_index == 0, |d| d == &id || d == &title);

            let version = extract_version_from_path(&linux);

            entries.push(BootEntry {
                id,
                title: title.clone(),
                linux: linux.clone(),
                initrd: initrd.clone(),
                options: options.clone(),
                is_default,
                version,
            });
            entry_index += 1;
            in_entry = false;
        } else if in_entry {
            if let Some(rest) = line.strip_prefix("linux") {
                // "linux /boot/vmlinuz-... root=UUID=... quiet"
                // or "linux16 ..."
                let rest = rest.trim_start_matches("16").trim();
                let parts: Vec<&str> = rest.splitn(2, ' ').collect();
                if !parts.is_empty() {
                    linux = PathBuf::from(parts[0]);
                }
                if parts.len() > 1 {
                    options = parts[1].to_string();
                }
            } else if let Some(rest) = line.strip_prefix("initrd") {
                let rest = rest.trim_start_matches("16").trim();
                if !rest.is_empty() {
                    initrd = Some(PathBuf::from(rest));
                }
            }
        }
    }

    Ok((entries, default_entry))
}

/// Try to extract a kernel version from a path like `/boot/vmlinuz-6.6.0-agnos`.
fn extract_version_from_path(path: &Path) -> Option<String> {
    let filename = path.file_name()?.to_str()?;
    let version = filename.strip_prefix("vmlinuz-")?;
    Some(version.to_string())
}

#[cfg(target_os = "linux")]
fn set_grub2_default(id: &str) -> Result<()> {
    let output = std::process::Command::new("grub-set-default")
        .arg(id)
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to run grub-set-default: {}", e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SysError::Unknown(
            format!("grub-set-default failed: {}", stderr.trim()).into(),
        ));
    }

    tracing::info!("Set GRUB2 default entry to: {}", id);
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_grub2_cmdline(entry_id: &str, options: &str) -> Result<()> {
    // GRUB2 kernel cmdline is typically set via /etc/default/grub
    // For per-entry modification, we update GRUB_CMDLINE_LINUX_DEFAULT
    // and regenerate grub.cfg.
    let content = std::fs::read_to_string(GRUB_DEFAULT_FILE).map_err(|e| {
        SysError::Unknown(format!("Failed to read {}: {}", GRUB_DEFAULT_FILE, e).into())
    })?;

    let mut lines: Vec<String> = Vec::new();
    let mut found = false;
    for line in content.lines() {
        if line.trim().starts_with("GRUB_CMDLINE_LINUX_DEFAULT=") {
            lines.push(format!("GRUB_CMDLINE_LINUX_DEFAULT=\"{}\"", options));
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !found {
        lines.push(format!("GRUB_CMDLINE_LINUX_DEFAULT=\"{}\"", options));
    }

    let new_content = lines.join("\n") + "\n";
    std::fs::write(GRUB_DEFAULT_FILE, new_content).map_err(|e| {
        SysError::Unknown(format!("Failed to write {}: {}", GRUB_DEFAULT_FILE, e).into())
    })?;

    // Regenerate grub.cfg
    let output = std::process::Command::new("grub-mkconfig")
        .arg("-o")
        .arg(GRUB_CFG)
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to run grub-mkconfig: {}", e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SysError::Unknown(
            format!("grub-mkconfig failed: {}", stderr.trim()).into(),
        ));
    }

    tracing::info!(
        "Set GRUB2 kernel cmdline for entry {} and regenerated grub.cfg",
        entry_id
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_grub2_timeout(seconds: u32) -> Result<()> {
    let content = std::fs::read_to_string(GRUB_DEFAULT_FILE).map_err(|e| {
        SysError::Unknown(format!("Failed to read {}: {}", GRUB_DEFAULT_FILE, e).into())
    })?;

    let mut lines: Vec<String> = Vec::new();
    let mut found = false;
    for line in content.lines() {
        if line.trim().starts_with("GRUB_TIMEOUT=") {
            lines.push(format!("GRUB_TIMEOUT={}", seconds));
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !found {
        lines.push(format!("GRUB_TIMEOUT={}", seconds));
    }

    let new_content = lines.join("\n") + "\n";
    std::fs::write(GRUB_DEFAULT_FILE, new_content).map_err(|e| {
        SysError::Unknown(format!("Failed to write {}: {}", GRUB_DEFAULT_FILE, e).into())
    })?;

    tracing::info!("Set GRUB2 timeout to: {}s", seconds);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Bootloader enum tests --

    #[test]
    fn test_bootloader_display() {
        assert_eq!(Bootloader::SystemdBoot.to_string(), "systemd-boot");
        assert_eq!(Bootloader::Grub2.to_string(), "GRUB2");
        assert_eq!(Bootloader::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_bootloader_equality() {
        assert_eq!(Bootloader::SystemdBoot, Bootloader::SystemdBoot);
        assert_ne!(Bootloader::SystemdBoot, Bootloader::Grub2);
        assert_ne!(Bootloader::Grub2, Bootloader::Unknown);
    }

    #[test]
    fn test_bootloader_clone() {
        let b = Bootloader::Grub2;
        let b2 = b;
        assert_eq!(b, b2);
    }

    // -- Validation tests --

    #[test]
    fn test_validate_cmdline_safe() {
        assert!(validate_kernel_cmdline("root=UUID=abc quiet splash").is_ok());
    }

    #[test]
    fn test_validate_cmdline_empty() {
        assert!(validate_kernel_cmdline("").is_ok());
    }

    #[test]
    fn test_validate_cmdline_rejects_init_bin_sh() {
        let result = validate_kernel_cmdline("root=UUID=abc init=/bin/sh");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("dangerous"), "Error: {}", err);
    }

    #[test]
    fn test_validate_cmdline_rejects_init_bin_bash() {
        let result = validate_kernel_cmdline("root=UUID=abc init=/bin/bash quiet");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_cmdline_rejects_single() {
        assert!(validate_kernel_cmdline("root=UUID=abc single").is_err());
    }

    #[test]
    fn test_validate_cmdline_rejects_rd_break() {
        assert!(validate_kernel_cmdline("rd.break root=UUID=abc").is_err());
    }

    #[test]
    fn test_validate_cmdline_rejects_debug_shell() {
        assert!(validate_kernel_cmdline("systemd.debug-shell quiet").is_err());
    }

    #[test]
    fn test_validate_cmdline_rejects_emergency() {
        assert!(validate_kernel_cmdline("emergency").is_err());
    }

    #[test]
    fn test_validate_cmdline_rejects_too_long() {
        let long_line = "a".repeat(4097);
        let result = validate_kernel_cmdline(&long_line);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("4096"));
    }

    #[test]
    fn test_validate_cmdline_rejects_non_ascii() {
        let result = validate_kernel_cmdline("root=UUID=abc quiet\x00hidden");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-printable"));
    }

    #[test]
    fn test_validate_cmdline_case_insensitive_dangerous() {
        // The check should be case-insensitive
        assert!(validate_kernel_cmdline("INIT=/BIN/SH").is_err());
    }

    // -- Entry ID validation --

    #[test]
    fn test_validate_entry_id_valid() {
        assert!(validate_entry_id("agnos-6.6.0").is_ok());
        assert!(validate_entry_id("entry_1").is_ok());
        assert!(validate_entry_id("0").is_ok());
    }

    #[test]
    fn test_validate_entry_id_empty() {
        assert!(validate_entry_id("").is_err());
    }

    #[test]
    fn test_validate_entry_id_too_long() {
        let long_id = "a".repeat(257);
        assert!(validate_entry_id(&long_id).is_err());
    }

    #[test]
    fn test_validate_entry_id_invalid_chars() {
        assert!(validate_entry_id("entry id with spaces").is_err());
        assert!(validate_entry_id("entry;drop").is_err());
    }

    // -- Timeout validation --

    #[test]
    fn test_set_timeout_rejects_over_300() {
        let result = set_timeout(301);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("300"));
    }

    #[test]
    fn test_set_timeout_boundary_300_accepted() {
        // 300 should not fail validation (will fail on actual write since no bootloader,
        // but should pass the bounds check)
        let result = set_timeout(300);
        // On non-linux or without a real bootloader, this may fail for other reasons,
        // but not the bounds check
        if let Err(e) = result {
            assert!(
                !e.to_string().contains("300 exceeds"),
                "300 should be accepted: {}",
                e
            );
        }
    }

    // -- Version extraction --

    #[test]
    fn test_extract_version_from_path() {
        let p = PathBuf::from("/boot/vmlinuz-6.6.0-agnos");
        assert_eq!(
            extract_version_from_path(&p),
            Some("6.6.0-agnos".to_string())
        );
    }

    #[test]
    fn test_extract_version_no_prefix() {
        let p = PathBuf::from("/boot/bzImage");
        assert_eq!(extract_version_from_path(&p), None);
    }

    // -- Serialization round-trips --

    #[test]
    fn test_bootloader_serde_roundtrip() {
        let b = Bootloader::SystemdBoot;
        let json = serde_json::to_string(&b).unwrap();
        let b2: Bootloader = serde_json::from_str(&json).unwrap();
        assert_eq!(b, b2);
    }

    #[test]
    fn test_boot_entry_serde_roundtrip() {
        let entry = BootEntry {
            id: "agnos-6.6.0".to_string(),
            title: "AGNOS 6.6.0".to_string(),
            linux: PathBuf::from("/boot/vmlinuz-6.6.0-agnos"),
            initrd: Some(PathBuf::from("/boot/initramfs-6.6.0-agnos.img")),
            options: "root=UUID=abc quiet splash".to_string(),
            is_default: true,
            version: Some("6.6.0-agnos".to_string()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let entry2: BootEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, entry2);
    }

    #[test]
    fn test_boot_config_serde_roundtrip() {
        let config = BootConfig {
            bootloader: Bootloader::Grub2,
            timeout_secs: 10,
            default_entry: Some("0".to_string()),
            entries: vec![BootEntry {
                id: "0".to_string(),
                title: "AGNOS".to_string(),
                linux: PathBuf::from("/boot/vmlinuz"),
                initrd: None,
                options: "quiet".to_string(),
                is_default: true,
                version: None,
            }],
        };
        let json = serde_json::to_string(&config).unwrap();
        let config2: BootConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.bootloader, config2.bootloader);
        assert_eq!(config.timeout_secs, config2.timeout_secs);
        assert_eq!(config.default_entry, config2.default_entry);
        assert_eq!(config.entries.len(), config2.entries.len());
        assert_eq!(config.entries[0], config2.entries[0]);
    }

    // -- Detection (runs on the host; result depends on environment) --

    #[test]
    fn test_detect_bootloader_returns_ok() {
        // Should never panic — returns Ok(Unknown) if neither bootloader is present
        let result = detect_bootloader();
        assert!(result.is_ok());
    }

    // -- Dangerous tokens coverage --

    #[test]
    fn test_all_dangerous_tokens_rejected() {
        for token in DANGEROUS_CMDLINE_TOKENS {
            let result = validate_kernel_cmdline(token);
            assert!(
                result.is_err(),
                "Expected rejection for dangerous token: {}",
                token
            );
        }
    }

    // -- Additional validate_kernel_cmdline edge cases --

    #[test]
    fn test_validate_cmdline_exactly_4096_chars() {
        let line = "a".repeat(4096);
        assert!(validate_kernel_cmdline(&line).is_ok());
    }

    #[test]
    fn test_validate_cmdline_rejects_unicode() {
        let result = validate_kernel_cmdline("root=UUID=abc quiet splash\u{00e9}");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-printable"));
    }

    #[test]
    fn test_validate_cmdline_rejects_tab() {
        // Tab is ASCII control
        let result = validate_kernel_cmdline("root=UUID=abc\tquiet");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-printable"));
    }

    #[test]
    fn test_validate_cmdline_rejects_newline() {
        let result = validate_kernel_cmdline("root=UUID=abc\nquiet");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-printable"));
    }

    #[test]
    fn test_validate_cmdline_rejects_null_byte() {
        let result = validate_kernel_cmdline("root=UUID=abc\x00quiet");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_cmdline_rejects_init_bin_dash() {
        assert!(validate_kernel_cmdline("init=/bin/dash").is_err());
    }

    #[test]
    fn test_validate_cmdline_rejects_init_sbin_init_debug() {
        assert!(validate_kernel_cmdline("init=/sbin/init.debug").is_err());
    }

    #[test]
    fn test_validate_cmdline_rejects_debug_shell_alone() {
        assert!(validate_kernel_cmdline("debug_shell").is_err());
    }

    #[test]
    fn test_validate_cmdline_mixed_case_dangerous() {
        assert!(validate_kernel_cmdline("EMERGENCY").is_err());
        assert!(validate_kernel_cmdline("RD.BREAK").is_err());
        assert!(validate_kernel_cmdline("Debug_Shell").is_err());
        assert!(validate_kernel_cmdline("Systemd.Debug-Shell").is_err());
        assert!(validate_kernel_cmdline("SINGLE").is_err());
    }

    #[test]
    fn test_validate_cmdline_dangerous_token_embedded_in_options() {
        // "single" substring appears embedded — still rejected by contains()
        assert!(validate_kernel_cmdline("root=UUID=abc single quiet").is_err());
    }

    #[test]
    fn test_validate_cmdline_allows_normal_complex_options() {
        assert!(validate_kernel_cmdline(
            "root=UUID=12345678-abcd-ef01-2345-6789abcdef01 ro quiet splash loglevel=3 rd.udev.log_priority=3"
        ).is_ok());
    }

    #[test]
    fn test_validate_cmdline_allows_printable_ascii() {
        assert!(
            validate_kernel_cmdline(
                "root=/dev/sda1 ro quiet splash console=tty0 console=ttyS0,115200n8"
            )
            .is_ok()
        );
    }

    // -- Additional entry ID validation edge cases --

    #[test]
    fn test_validate_entry_id_exactly_256() {
        let id = "a".repeat(256);
        assert!(validate_entry_id(&id).is_ok());
    }

    #[test]
    fn test_validate_entry_id_single_char() {
        assert!(validate_entry_id("a").is_ok());
        assert!(validate_entry_id("0").is_ok());
        assert!(validate_entry_id("-").is_ok());
        assert!(validate_entry_id("_").is_ok());
        assert!(validate_entry_id(".").is_ok());
    }

    #[test]
    fn test_validate_entry_id_rejects_slash() {
        assert!(validate_entry_id("entry/bad").is_err());
    }

    #[test]
    fn test_validate_entry_id_rejects_path_traversal() {
        assert!(validate_entry_id("../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_entry_id_accepts_unicode_alphanumeric() {
        // NOTE: is_alphanumeric() accepts unicode chars like 'e'. This is a potential
        // security concern since entry IDs are used in file paths. Consider using
        // is_ascii_alphanumeric() in the validation function instead.
        assert!(validate_entry_id("entr\u{00e9}").is_ok());
    }

    #[test]
    fn test_validate_entry_id_rejects_null() {
        assert!(validate_entry_id("entry\x00id").is_err());
    }

    #[test]
    fn test_validate_entry_id_rejects_shell_metacharacters() {
        assert!(validate_entry_id("entry;rm -rf /").is_err());
        assert!(validate_entry_id("entry|cat").is_err());
        assert!(validate_entry_id("entry`id`").is_err());
        assert!(validate_entry_id("entry$(cmd)").is_err());
    }

    // -- extract_version_from_path additional cases --

    #[test]
    fn test_extract_version_from_vmlinuz() {
        let p = PathBuf::from("/boot/vmlinuz-5.15.0-generic");
        assert_eq!(
            extract_version_from_path(&p),
            Some("5.15.0-generic".to_string())
        );
    }

    #[test]
    fn test_extract_version_from_vmlinuz_just_version() {
        let p = PathBuf::from("vmlinuz-6.1.0");
        assert_eq!(extract_version_from_path(&p), Some("6.1.0".to_string()));
    }

    #[test]
    fn test_extract_version_from_path_no_filename() {
        let p = PathBuf::from("/");
        assert_eq!(extract_version_from_path(&p), None);
    }

    #[test]
    fn test_extract_version_from_non_vmlinuz() {
        let p = PathBuf::from("/boot/initramfs-6.6.0.img");
        assert_eq!(extract_version_from_path(&p), None);
    }

    #[test]
    fn test_extract_version_empty_path() {
        let p = PathBuf::from("");
        assert_eq!(extract_version_from_path(&p), None);
    }

    #[test]
    fn test_extract_version_vmlinuz_no_dash() {
        // "vmlinuz" alone, no dash-version suffix
        let p = PathBuf::from("/boot/vmlinuz");
        assert_eq!(extract_version_from_path(&p), None);
    }

    // -- BootEntry construction tests --

    #[test]
    fn test_boot_entry_without_initrd() {
        let entry = BootEntry {
            id: "test".to_string(),
            title: "Test Entry".to_string(),
            linux: PathBuf::from("/boot/vmlinuz-test"),
            initrd: None,
            options: "quiet".to_string(),
            is_default: false,
            version: None,
        };
        assert!(entry.initrd.is_none());
        assert!(!entry.is_default);
        assert!(entry.version.is_none());
    }

    #[test]
    fn test_boot_entry_with_all_fields() {
        let entry = BootEntry {
            id: "full-entry".to_string(),
            title: "Full Test".to_string(),
            linux: PathBuf::from("/boot/vmlinuz-6.6.0"),
            initrd: Some(PathBuf::from("/boot/initramfs-6.6.0.img")),
            options: "root=UUID=abc quiet splash".to_string(),
            is_default: true,
            version: Some("6.6.0".to_string()),
        };
        assert_eq!(entry.id, "full-entry");
        assert!(entry.is_default);
        assert_eq!(entry.version, Some("6.6.0".to_string()));
        assert_eq!(
            entry.initrd,
            Some(PathBuf::from("/boot/initramfs-6.6.0.img"))
        );
    }

    // -- BootConfig construction --

    #[test]
    fn test_boot_config_empty_entries() {
        let config = BootConfig {
            bootloader: Bootloader::Unknown,
            timeout_secs: 0,
            default_entry: None,
            entries: vec![],
        };
        assert_eq!(config.bootloader, Bootloader::Unknown);
        assert_eq!(config.timeout_secs, 0);
        assert!(config.default_entry.is_none());
        assert!(config.entries.is_empty());
    }

    #[test]
    fn test_boot_config_multiple_entries() {
        let entries = vec![
            BootEntry {
                id: "0".to_string(),
                title: "Entry 0".to_string(),
                linux: PathBuf::from("/boot/vmlinuz-6.6.0"),
                initrd: None,
                options: "quiet".to_string(),
                is_default: true,
                version: Some("6.6.0".to_string()),
            },
            BootEntry {
                id: "1".to_string(),
                title: "Entry 1".to_string(),
                linux: PathBuf::from("/boot/vmlinuz-6.5.0"),
                initrd: Some(PathBuf::from("/boot/initramfs-6.5.0.img")),
                options: "quiet splash".to_string(),
                is_default: false,
                version: Some("6.5.0".to_string()),
            },
        ];
        let config = BootConfig {
            bootloader: Bootloader::Grub2,
            timeout_secs: 10,
            default_entry: Some("0".to_string()),
            entries,
        };
        assert_eq!(config.entries.len(), 2);
        assert!(config.entries[0].is_default);
        assert!(!config.entries[1].is_default);
    }

    // -- Bootloader serde coverage for all variants --

    #[test]
    fn test_bootloader_serde_all_variants() {
        for b in &[
            Bootloader::SystemdBoot,
            Bootloader::Grub2,
            Bootloader::Unknown,
        ] {
            let json = serde_json::to_string(b).unwrap();
            let b2: Bootloader = serde_json::from_str(&json).unwrap();
            assert_eq!(*b, b2);
        }
    }

    // -- Timeout boundary tests --

    #[test]
    fn test_set_timeout_zero() {
        let result = set_timeout(0);
        // Should pass validation (0 is valid), may fail later for other reasons
        if let Err(e) = result {
            assert!(
                !e.to_string().contains("exceeds"),
                "0 should be accepted: {}",
                e
            );
        }
    }

    #[test]
    fn test_set_timeout_rejects_u32_max() {
        let result = set_timeout(u32::MAX);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("300"));
    }

    // -- parse_loader_conf tests (via tempfile) --

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_loader_conf_basic() {
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("loader.conf");
        std::fs::write(&conf_path, "timeout 10\ndefault agnos-6.6.0.conf\n").unwrap();

        let (timeout, default_id) = parse_loader_conf(&conf_path).unwrap();
        assert_eq!(timeout, 10);
        assert_eq!(default_id, Some("agnos-6.6.0".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_loader_conf_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("loader.conf");
        std::fs::write(
            &conf_path,
            "# This is a comment\n\ntimeout 3\n# another comment\ndefault myentry.conf\n",
        )
        .unwrap();

        let (timeout, default_id) = parse_loader_conf(&conf_path).unwrap();
        assert_eq!(timeout, 3);
        assert_eq!(default_id, Some("myentry".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_loader_conf_no_default() {
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("loader.conf");
        std::fs::write(&conf_path, "timeout 7\n").unwrap();

        let (timeout, default_id) = parse_loader_conf(&conf_path).unwrap();
        assert_eq!(timeout, 7);
        assert_eq!(default_id, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_loader_conf_no_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("loader.conf");
        std::fs::write(&conf_path, "default myentry.conf\n").unwrap();

        let (timeout, default_id) = parse_loader_conf(&conf_path).unwrap();
        assert_eq!(timeout, 5); // default value
        assert_eq!(default_id, Some("myentry".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_loader_conf_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("loader.conf");
        std::fs::write(&conf_path, "").unwrap();

        let (timeout, default_id) = parse_loader_conf(&conf_path).unwrap();
        assert_eq!(timeout, 5); // default
        assert_eq!(default_id, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_loader_conf_invalid_timeout_uses_default() {
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("loader.conf");
        std::fs::write(&conf_path, "timeout not-a-number\n").unwrap();

        let (timeout, _) = parse_loader_conf(&conf_path).unwrap();
        assert_eq!(timeout, 5); // falls back to default
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_loader_conf_missing_file() {
        let result = parse_loader_conf(Path::new("/nonexistent/path/loader.conf"));
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_loader_conf_default_without_conf_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let conf_path = dir.path().join("loader.conf");
        std::fs::write(&conf_path, "default myentry\n").unwrap();

        let (_, default_id) = parse_loader_conf(&conf_path).unwrap();
        assert_eq!(default_id, Some("myentry".to_string()));
    }

    // -- parse_systemd_boot_entry tests --

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_systemd_boot_entry_full() {
        let dir = tempfile::tempdir().unwrap();
        let entry_path = dir.path().join("agnos-6.6.0.conf");
        std::fs::write(
            &entry_path,
            "title AGNOS 6.6.0\nlinux /boot/vmlinuz-6.6.0\ninitrd /boot/initramfs-6.6.0.img\noptions root=UUID=abc quiet\nversion 6.6.0\n",
        )
        .unwrap();

        let entry = parse_systemd_boot_entry(&entry_path, Some("agnos-6.6.0")).unwrap();
        assert_eq!(entry.id, "agnos-6.6.0");
        assert_eq!(entry.title, "AGNOS 6.6.0");
        assert_eq!(entry.linux, PathBuf::from("/boot/vmlinuz-6.6.0"));
        assert_eq!(
            entry.initrd,
            Some(PathBuf::from("/boot/initramfs-6.6.0.img"))
        );
        assert_eq!(entry.options, "root=UUID=abc quiet");
        assert!(entry.is_default);
        assert_eq!(entry.version, Some("6.6.0".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_systemd_boot_entry_minimal() {
        let dir = tempfile::tempdir().unwrap();
        let entry_path = dir.path().join("minimal.conf");
        std::fs::write(&entry_path, "title Minimal\nlinux /boot/vmlinuz\n").unwrap();

        let entry = parse_systemd_boot_entry(&entry_path, None).unwrap();
        assert_eq!(entry.id, "minimal");
        assert_eq!(entry.title, "Minimal");
        assert_eq!(entry.linux, PathBuf::from("/boot/vmlinuz"));
        assert!(entry.initrd.is_none());
        assert_eq!(entry.options, "");
        assert!(!entry.is_default);
        assert!(entry.version.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_systemd_boot_entry_not_default() {
        let dir = tempfile::tempdir().unwrap();
        let entry_path = dir.path().join("other.conf");
        std::fs::write(&entry_path, "title Other\nlinux /boot/vmlinuz-other\n").unwrap();

        let entry = parse_systemd_boot_entry(&entry_path, Some("not-this-one")).unwrap();
        assert!(!entry.is_default);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_systemd_boot_entry_with_comments() {
        let dir = tempfile::tempdir().unwrap();
        let entry_path = dir.path().join("commented.conf");
        std::fs::write(
            &entry_path,
            "# This is a comment\ntitle Commented Entry\n\n# another comment\nlinux /boot/vmlinuz-6.6.0\noptions quiet\n",
        )
        .unwrap();

        let entry = parse_systemd_boot_entry(&entry_path, None).unwrap();
        assert_eq!(entry.title, "Commented Entry");
        assert_eq!(entry.linux, PathBuf::from("/boot/vmlinuz-6.6.0"));
        assert_eq!(entry.options, "quiet");
    }

    // -- parse_systemd_boot_entries tests --

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_systemd_boot_entries_multiple() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("entry-a.conf"),
            "title Entry A\nlinux /boot/vmlinuz-a\noptions quiet\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("entry-b.conf"),
            "title Entry B\nlinux /boot/vmlinuz-b\noptions splash\n",
        )
        .unwrap();
        // Non-conf file should be skipped
        std::fs::write(dir.path().join("README.txt"), "not a config").unwrap();

        let entries = parse_systemd_boot_entries(dir.path(), Some("entry-b")).unwrap();
        assert_eq!(entries.len(), 2);
        // Sorted by ID
        assert_eq!(entries[0].id, "entry-a");
        assert_eq!(entries[1].id, "entry-b");
        assert!(!entries[0].is_default);
        assert!(entries[1].is_default);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_systemd_boot_entries_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let entries = parse_systemd_boot_entries(dir.path(), None).unwrap();
        assert!(entries.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_systemd_boot_entries_nonexistent_dir() {
        let result = parse_systemd_boot_entries(Path::new("/nonexistent/entries/dir"), None);
        assert!(result.is_err());
    }

    // -- parse_grub_cfg tests --

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_grub_cfg_basic() {
        let dir = tempfile::tempdir().unwrap();
        let grub_path = dir.path().join("grub.cfg");
        std::fs::write(
            &grub_path,
            r#"set default="0"
set timeout=5
menuentry 'AGNOS 6.6.0' --class agnos {
    linux /boot/vmlinuz-6.6.0 root=UUID=abc quiet
    initrd /boot/initramfs-6.6.0.img
}
menuentry 'AGNOS 6.5.0' --class agnos {
    linux /boot/vmlinuz-6.5.0 root=UUID=def
    initrd /boot/initramfs-6.5.0.img
}
"#,
        )
        .unwrap();

        let (entries, default_id) = parse_grub_cfg(&grub_path).unwrap();
        assert_eq!(default_id, Some("0".to_string()));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "0");
        assert_eq!(entries[0].title, "AGNOS 6.6.0");
        assert_eq!(entries[0].linux, PathBuf::from("/boot/vmlinuz-6.6.0"));
        assert_eq!(entries[0].options, "root=UUID=abc quiet");
        assert_eq!(
            entries[0].initrd,
            Some(PathBuf::from("/boot/initramfs-6.6.0.img"))
        );
        assert!(entries[0].is_default);
        assert_eq!(entries[0].version, Some("6.6.0".to_string()));

        assert_eq!(entries[1].id, "1");
        assert_eq!(entries[1].title, "AGNOS 6.5.0");
        assert!(!entries[1].is_default);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_grub_cfg_default_by_title() {
        let dir = tempfile::tempdir().unwrap();
        let grub_path = dir.path().join("grub.cfg");
        std::fs::write(
            &grub_path,
            r#"set default="AGNOS 6.5.0"
menuentry 'AGNOS 6.6.0' {
    linux /boot/vmlinuz-6.6.0 quiet
}
menuentry 'AGNOS 6.5.0' {
    linux /boot/vmlinuz-6.5.0 quiet
}
"#,
        )
        .unwrap();

        let (entries, _) = parse_grub_cfg(&grub_path).unwrap();
        assert!(!entries[0].is_default);
        assert!(entries[1].is_default);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_grub_cfg_no_set_default() {
        let dir = tempfile::tempdir().unwrap();
        let grub_path = dir.path().join("grub.cfg");
        std::fs::write(
            &grub_path,
            r#"menuentry 'Entry A' {
    linux /boot/vmlinuz-a quiet
}
menuentry 'Entry B' {
    linux /boot/vmlinuz-b quiet
}
"#,
        )
        .unwrap();

        let (entries, default_id) = parse_grub_cfg(&grub_path).unwrap();
        assert_eq!(default_id, None);
        // Without a default directive, entry_index == 0 is treated as default
        assert!(entries[0].is_default);
        assert!(!entries[1].is_default);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_grub_cfg_empty() {
        let dir = tempfile::tempdir().unwrap();
        let grub_path = dir.path().join("grub.cfg");
        std::fs::write(&grub_path, "# empty grub config\n").unwrap();

        let (entries, default_id) = parse_grub_cfg(&grub_path).unwrap();
        assert!(entries.is_empty());
        assert!(default_id.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_grub_cfg_linux16() {
        let dir = tempfile::tempdir().unwrap();
        let grub_path = dir.path().join("grub.cfg");
        std::fs::write(
            &grub_path,
            r#"menuentry 'Legacy Boot' {
    linux16 /boot/vmlinuz-legacy root=UUID=abc
    initrd16 /boot/initramfs-legacy.img
}
"#,
        )
        .unwrap();

        let (entries, _) = parse_grub_cfg(&grub_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].linux, PathBuf::from("/boot/vmlinuz-legacy"));
        assert_eq!(entries[0].options, "root=UUID=abc");
        assert_eq!(
            entries[0].initrd,
            Some(PathBuf::from("/boot/initramfs-legacy.img"))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_grub_cfg_double_quoted_title() {
        let dir = tempfile::tempdir().unwrap();
        let grub_path = dir.path().join("grub.cfg");
        std::fs::write(
            &grub_path,
            "menuentry \"Double Quoted\" {\n    linux /boot/vmlinuz quiet\n}\n",
        )
        .unwrap();

        let (entries, _) = parse_grub_cfg(&grub_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Double Quoted");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_grub_cfg_no_initrd() {
        let dir = tempfile::tempdir().unwrap();
        let grub_path = dir.path().join("grub.cfg");
        std::fs::write(
            &grub_path,
            "menuentry 'No Initrd' {\n    linux /boot/vmlinuz quiet\n}\n",
        )
        .unwrap();

        let (entries, _) = parse_grub_cfg(&grub_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].initrd.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_grub_cfg_nonexistent_file() {
        let result = parse_grub_cfg(Path::new("/nonexistent/grub.cfg"));
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_grub_cfg_linux_no_options() {
        let dir = tempfile::tempdir().unwrap();
        let grub_path = dir.path().join("grub.cfg");
        std::fs::write(
            &grub_path,
            "menuentry 'Bare' {\n    linux /boot/vmlinuz\n}\n",
        )
        .unwrap();

        let (entries, _) = parse_grub_cfg(&grub_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].linux, PathBuf::from("/boot/vmlinuz"));
        assert_eq!(entries[0].options, "");
    }

    // -- read_systemd_boot_config integration test via tempdir --

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_systemd_boot_entry_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let entry_path = dir.path().join("empty.conf");
        std::fs::write(&entry_path, "").unwrap();

        let entry = parse_systemd_boot_entry(&entry_path, None).unwrap();
        assert_eq!(entry.id, "empty");
        assert_eq!(entry.title, "");
        assert_eq!(entry.linux, PathBuf::new());
        assert!(entry.initrd.is_none());
        assert_eq!(entry.options, "");
        assert!(!entry.is_default);
        assert!(entry.version.is_none());
    }

    // -- Bootloader Debug formatting --

    #[test]
    fn test_bootloader_debug() {
        let b = Bootloader::SystemdBoot;
        let debug = format!("{:?}", b);
        assert!(debug.contains("SystemdBoot"));
    }

    // -- BootEntry equality --

    #[test]
    fn test_boot_entry_equality() {
        let entry1 = BootEntry {
            id: "test".to_string(),
            title: "Test".to_string(),
            linux: PathBuf::from("/boot/vmlinuz"),
            initrd: None,
            options: "quiet".to_string(),
            is_default: false,
            version: None,
        };
        let entry2 = entry1.clone();
        assert_eq!(entry1, entry2);
    }

    #[test]
    fn test_boot_entry_inequality() {
        let entry1 = BootEntry {
            id: "test1".to_string(),
            title: "Test".to_string(),
            linux: PathBuf::from("/boot/vmlinuz"),
            initrd: None,
            options: "quiet".to_string(),
            is_default: false,
            version: None,
        };
        let entry2 = BootEntry {
            id: "test2".to_string(),
            title: "Test".to_string(),
            linux: PathBuf::from("/boot/vmlinuz"),
            initrd: None,
            options: "quiet".to_string(),
            is_default: false,
            version: None,
        };
        assert_ne!(entry1, entry2);
    }

    // -- set_default_entry validation --

    #[test]
    fn test_set_default_entry_rejects_empty_id() {
        let result = set_default_entry("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_set_default_entry_rejects_invalid_chars() {
        let result = set_default_entry("bad entry!");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid characters")
        );
    }

    // -- set_kernel_cmdline validation --

    #[test]
    fn test_set_kernel_cmdline_rejects_empty_entry_id() {
        let result = set_kernel_cmdline("", "quiet");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_set_kernel_cmdline_rejects_dangerous_options() {
        let result = set_kernel_cmdline("valid-entry", "init=/bin/sh");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("dangerous"));
    }

    #[test]
    fn test_set_kernel_cmdline_rejects_both_bad_id_and_options() {
        // ID is checked first
        let result = set_kernel_cmdline("", "init=/bin/sh");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }
}
