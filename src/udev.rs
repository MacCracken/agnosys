//! udev Device Management Interface
//!
//! Userland wrappers for udev device enumeration, monitoring, and rule management.
//! Shells out to `udevadm` (part of systemd/eudev).
//!
//! On non-Linux platforms, all operations return `SysError::NotSupported`.

use crate::error::{Result, SysError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Information about a single device as reported by udev / sysfs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Kernel sysfs path (e.g. `/sys/devices/pci0000:00/...`)
    pub syspath: String,
    /// Kernel devpath (relative, e.g. `/devices/pci0000:00/...`)
    pub devpath: String,
    /// Subsystem the device belongs to (e.g. `block`, `net`)
    pub subsystem: String,
    /// Device type within the subsystem (optional)
    pub devtype: Option<String>,
    /// Kernel driver bound to this device (optional)
    pub driver: Option<String>,
    /// Device node path (e.g. `/dev/sda`, optional)
    pub devnode: Option<String>,
    /// All udev properties as key-value pairs
    pub properties: HashMap<String, String>,
}

/// Well-known device subsystems.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeviceSubsystem {
    Block,
    Net,
    Input,
    Usb,
    Pci,
    Tty,
    Gpu,
    Sound,
    Other(String),
}

impl DeviceSubsystem {
    /// Parse a subsystem string into the enum.
    pub fn parse(s: &str) -> Self {
        match s {
            "block" => Self::Block,
            "net" => Self::Net,
            "input" => Self::Input,
            "usb" => Self::Usb,
            "pci" => Self::Pci,
            "tty" => Self::Tty,
            "drm" => Self::Gpu,
            "sound" | "snd" => Self::Sound,
            other => Self::Other(other.to_string()),
        }
    }
}

impl std::fmt::Display for DeviceSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::Net => write!(f, "net"),
            Self::Input => write!(f, "input"),
            Self::Usb => write!(f, "usb"),
            Self::Pci => write!(f, "pci"),
            Self::Tty => write!(f, "tty"),
            Self::Gpu => write!(f, "drm"),
            Self::Sound => write!(f, "sound"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

/// A udev rule definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdevRule {
    /// Rule file stem (e.g. `99-agnos-agent`), without `.rules` extension
    pub name: String,
    /// Match conditions (`SUBSYSTEM=="net"`, `ATTR{idVendor}=="1234"`, etc.)
    pub match_attrs: Vec<(String, String)>,
    /// Assignment actions (`MODE="0660"`, `OWNER="agnos"`, `TAG+="systemd"`, etc.)
    pub actions: Vec<(String, String)>,
}

/// Lifecycle events emitted by the kernel / udev.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeviceEvent {
    Add,
    Remove,
    Change,
    Bind,
    Unbind,
}

impl std::fmt::Display for DeviceEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Add => write!(f, "add"),
            Self::Remove => write!(f, "remove"),
            Self::Change => write!(f, "change"),
            Self::Bind => write!(f, "bind"),
            Self::Unbind => write!(f, "unbind"),
        }
    }
}

impl DeviceEvent {
    /// Parse a string into a `DeviceEvent`.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "add" => Ok(Self::Add),
            "remove" => Ok(Self::Remove),
            "change" => Ok(Self::Change),
            "bind" => Ok(Self::Bind),
            "unbind" => Ok(Self::Unbind),
            other => Err(SysError::InvalidArgument(
                format!("Unknown device event: {}", other).into(),
            )),
        }
    }
}

/// Configuration for spawning a udev monitor process.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMonitorConfig {
    /// Only report events for this subsystem (e.g. `"block"`)
    pub subsystem_filter: Option<String>,
    /// Only report events for this devtype within the subsystem
    pub devtype_filter: Option<String>,
}

// ---------------------------------------------------------------------------
// Dangerous / invalid action keys that must be rejected in rules
// ---------------------------------------------------------------------------

/// Action keys that are potentially dangerous in udev rules.
const DANGEROUS_ACTIONS: &[&str] = &["RUN", "PROGRAM", "IMPORT{program}", "IMPORT{builtin}"];

/// Valid udev assignment action keys.
const VALID_ACTION_KEYS: &[&str] = &[
    "MODE",
    "OWNER",
    "GROUP",
    "TAG",
    "TAG+=",
    "SYMLINK",
    "SYMLINK+=",
    "ENV",
    "ATTR",
    "NAME",
    "OPTIONS",
];

/// Valid udev match keys.
const VALID_MATCH_KEYS: &[&str] = &[
    "SUBSYSTEM",
    "KERNEL",
    "DRIVER",
    "ATTR",
    "ATTRS",
    "ACTION",
    "DEVPATH",
    "ENV",
    "TAG",
];

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// List devices, optionally filtered by subsystem.
///
/// Uses `udevadm info --export-db` and parses the output.
pub fn list_devices(subsystem: Option<&str>) -> Result<Vec<DeviceInfo>> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("udevadm")
            .args(["info", "--export-db"])
            .output()
            .map_err(|e| SysError::Unknown(format!("Failed to run udevadm: {}", e).into()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SysError::Unknown(
                format!("udevadm info --export-db failed: {}", stderr).into(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let devices = parse_export_db(&stdout)?;

        match subsystem {
            Some(sub) => Ok(devices.into_iter().filter(|d| d.subsystem == sub).collect()),
            None => Ok(devices),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = subsystem;
        Err(SysError::NotSupported {
            feature: "udev".into(),
        })
    }
}

/// Get detailed information about a single device by its sysfs path.
pub fn get_device_info(syspath: &str) -> Result<DeviceInfo> {
    #[cfg(target_os = "linux")]
    {
        if syspath.is_empty() {
            return Err(SysError::InvalidArgument("syspath cannot be empty".into()));
        }

        let output = std::process::Command::new("udevadm")
            .args(["info", &format!("--path={}", syspath)])
            .output()
            .map_err(|e| SysError::Unknown(format!("Failed to run udevadm: {}", e).into()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SysError::Unknown(
                format!("udevadm info failed: {}", stderr).into(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_udevadm_info(&stdout)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = syspath;
        Err(SysError::NotSupported {
            feature: "udev".into(),
        })
    }
}

/// Parse the output of `udevadm info` for a single device.
///
/// Expected line prefixes:
/// - `P:` — devpath (sysfs path relative to `/sys`)
/// - `N:` — device node name (relative to `/dev`)
/// - `S:` — symlink (relative to `/dev`)
/// - `E:` — property key=value
pub fn parse_udevadm_info(output: &str) -> Result<DeviceInfo> {
    let mut devpath = String::new();
    let mut devnode: Option<String> = None;
    let mut properties: HashMap<String, String> = HashMap::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(val) = line.strip_prefix("P: ") {
            devpath = val.to_string();
        } else if let Some(val) = line.strip_prefix("N: ") {
            devnode = Some(format!("/dev/{}", val));
        } else if let Some(val) = line.strip_prefix("S: ") {
            // Accumulate symlinks into property
            let existing = properties.entry("DEVLINKS".to_string()).or_default();
            if !existing.is_empty() {
                existing.push(' ');
            }
            existing.push_str(&format!("/dev/{}", val));
        } else if let Some(val) = line.strip_prefix("E: ")
            && let Some((k, v)) = val.split_once('=')
        {
            properties.insert(k.to_string(), v.to_string());
        }
    }

    if devpath.is_empty() {
        return Err(SysError::InvalidArgument(
            "udevadm output missing P: (devpath) line".into(),
        ));
    }

    let syspath = format!("/sys{}", devpath);
    let subsystem = properties.get("SUBSYSTEM").cloned().unwrap_or_default();
    let devtype = properties.get("DEVTYPE").cloned();
    let driver = properties.get("DRIVER").cloned();

    // devnode from N: line or DEVNAME property
    let devnode = devnode.or_else(|| properties.get("DEVNAME").cloned());

    Ok(DeviceInfo {
        syspath,
        devpath,
        subsystem,
        devtype,
        driver,
        devnode,
        properties,
    })
}

/// Parse the full `udevadm info --export-db` output into a list of devices.
///
/// Device records are separated by blank lines. Each record uses the same
/// P:/N:/S:/E: prefix format as single-device output.
fn parse_export_db(output: &str) -> Result<Vec<DeviceInfo>> {
    let mut devices = Vec::new();
    let mut current_block = String::new();

    for line in output.lines() {
        if line.trim().is_empty() {
            if !current_block.is_empty() {
                // Only include blocks that have a P: line
                if (current_block.contains("\nP: ") || current_block.starts_with("P: "))
                    && let Ok(dev) = parse_udevadm_info(&current_block)
                {
                    devices.push(dev);
                }
                current_block.clear();
            }
        } else {
            if !current_block.is_empty() {
                current_block.push('\n');
            }
            current_block.push_str(line);
        }
    }

    // Handle trailing block without final newline
    if !current_block.is_empty()
        && (current_block.contains("\nP: ") || current_block.starts_with("P: "))
        && let Ok(dev) = parse_udevadm_info(&current_block)
    {
        devices.push(dev);
    }

    Ok(devices)
}

/// Trigger a udev re-evaluation for a device.
pub fn trigger_device(syspath: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if syspath.is_empty() {
            return Err(SysError::InvalidArgument("syspath cannot be empty".into()));
        }

        let output = std::process::Command::new("udevadm")
            .args(["trigger", "--action=change", syspath])
            .output()
            .map_err(|e| {
                SysError::Unknown(format!("Failed to run udevadm trigger: {}", e).into())
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SysError::Unknown(
                format!("udevadm trigger failed: {}", stderr).into(),
            ));
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = syspath;
        Err(SysError::NotSupported {
            feature: "udev".into(),
        })
    }
}

/// Render a `UdevRule` to the string content of a `.rules` file.
///
/// This is a pure function with no side effects.
pub fn render_udev_rule(rule: &UdevRule) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Match conditions use `==`
    for (key, value) in &rule.match_attrs {
        parts.push(format!("{}==\"{}\"", key, value));
    }

    // Assignment actions
    for (key, value) in &rule.actions {
        if key.ends_with("+=") {
            // Append-style keys already include the operator
            parts.push(format!("{}\"{}\"", key, value));
        } else {
            parts.push(format!("{}=\"{}\"", key, value));
        }
    }

    let mut output = format!("# AGNOS udev rule: {}\n", rule.name);
    output.push_str(&parts.join(", "));
    output.push('\n');
    output
}

/// Write a udev rule file to the specified rules directory.
///
/// Returns the path to the written file.
pub fn write_udev_rule(rule: &UdevRule, rules_dir: &Path) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        validate_rule(rule)?;

        let filename = format!("{}.rules", rule.name);
        let path = rules_dir.join(&filename);

        // Validate the directory exists
        if !rules_dir.exists() {
            return Err(SysError::InvalidArgument(
                format!("Rules directory does not exist: {}", rules_dir.display()).into(),
            ));
        }

        let content = render_udev_rule(rule);
        std::fs::write(&path, &content)
            .map_err(|e| SysError::Unknown(format!("Failed to write rule file: {}", e).into()))?;

        Ok(path)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (rule, rules_dir);
        Err(SysError::NotSupported {
            feature: "udev".into(),
        })
    }
}

/// Remove a udev rule file.
pub fn remove_udev_rule(name: &str, rules_dir: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if name.is_empty() {
            return Err(SysError::InvalidArgument(
                "Rule name cannot be empty".into(),
            ));
        }
        // Prevent path traversal
        if name.contains('/') || name.contains("..") {
            return Err(SysError::InvalidArgument(
                "Rule name contains invalid characters".into(),
            ));
        }

        let filename = format!("{}.rules", name);
        let path = rules_dir.join(&filename);

        if !path.exists() {
            return Err(SysError::InvalidArgument(
                format!("Rule file does not exist: {}", path.display()).into(),
            ));
        }

        std::fs::remove_file(&path)
            .map_err(|e| SysError::Unknown(format!("Failed to remove rule file: {}", e).into()))?;

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, rules_dir);
        Err(SysError::NotSupported {
            feature: "udev".into(),
        })
    }
}

/// Reload udev rules and trigger re-evaluation.
pub fn reload_udev_rules() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("udevadm")
            .args(["control", "--reload-rules"])
            .output()
            .map_err(|e| SysError::Unknown(format!("Failed to reload udev rules: {}", e).into()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SysError::Unknown(
                format!("udevadm control --reload-rules failed: {}", stderr).into(),
            ));
        }

        let output = std::process::Command::new("udevadm")
            .arg("trigger")
            .output()
            .map_err(|e| SysError::Unknown(format!("Failed to trigger udev: {}", e).into()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SysError::Unknown(
                format!("udevadm trigger failed: {}", stderr).into(),
            ));
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SysError::NotSupported {
            feature: "udev".into(),
        })
    }
}

/// Spawn a `udevadm monitor` child process for real-time device events.
///
/// The caller is responsible for reading stdout and waiting on the child.
pub fn monitor_devices(config: &DeviceMonitorConfig) -> Result<std::process::Child> {
    #[cfg(target_os = "linux")]
    {
        let mut cmd = std::process::Command::new("udevadm");
        cmd.arg("monitor").arg("--udev").arg("--property");

        if let Some(ref sub) = config.subsystem_filter {
            if let Some(ref devtype) = config.devtype_filter {
                cmd.arg(format!("--subsystem-match={}:{}", sub, devtype));
            } else {
                cmd.arg(format!("--subsystem-match={}", sub));
            }
        }

        let child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                SysError::Unknown(format!("Failed to spawn udevadm monitor: {}", e).into())
            })?;

        Ok(child)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(SysError::NotSupported {
            feature: "udev".into(),
        })
    }
}

/// Validate a udev rule for correctness and safety.
///
/// Rejects rules with:
/// - Empty name or match conditions
/// - Path traversal in name
/// - Dangerous action keys (`RUN`, `PROGRAM`, `IMPORT{program}`)
/// - Unknown match or action keys
pub fn validate_rule(rule: &UdevRule) -> Result<()> {
    // Name validation
    if rule.name.is_empty() {
        return Err(SysError::InvalidArgument(
            "Rule name cannot be empty".into(),
        ));
    }
    if rule.name.len() > 128 {
        return Err(SysError::InvalidArgument(
            "Rule name too long (max 128)".into(),
        ));
    }
    if !rule
        .name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(SysError::InvalidArgument(
            format!("Rule name contains invalid characters: {}", rule.name).into(),
        ));
    }

    // Must have at least one match condition
    if rule.match_attrs.is_empty() {
        return Err(SysError::InvalidArgument(
            "Rule must have at least one match condition".into(),
        ));
    }

    // Validate match keys
    for (key, value) in &rule.match_attrs {
        // Extract the base key (before any `{...}` qualifier)
        let base_key = key.split('{').next().unwrap_or(key);
        if !VALID_MATCH_KEYS.contains(&base_key) {
            return Err(SysError::InvalidArgument(
                format!("Invalid match key: {}", key).into(),
            ));
        }
        if value.is_empty() {
            return Err(SysError::InvalidArgument(
                format!("Empty value for match key: {}", key).into(),
            ));
        }
    }

    // Validate action keys — reject dangerous ones
    for (key, _value) in &rule.actions {
        let base_key = key.split('{').next().unwrap_or(key);
        // Strip trailing += for comparison
        let base_key_stripped = base_key.trim_end_matches("+=");

        if DANGEROUS_ACTIONS.contains(&key.as_str()) || DANGEROUS_ACTIONS.contains(&base_key) {
            return Err(SysError::InvalidArgument(
                format!("Dangerous action key rejected: {}", key).into(),
            ));
        }

        // Check if it is a valid action key (check both with and without +=)
        if !VALID_ACTION_KEYS.contains(&key.as_str())
            && !VALID_ACTION_KEYS.contains(&base_key)
            && !VALID_ACTION_KEYS.contains(&base_key_stripped)
        {
            return Err(SysError::InvalidArgument(
                format!("Invalid action key: {}", key).into(),
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_udevadm_info ------------------------------------------------

    #[test]
    fn test_parse_udevadm_info_basic() {
        let output = "\
P: /devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda
N: sda
S: disk/by-id/ata-VBOX_HARDDISK_VB12345678-abcdefgh
E: SUBSYSTEM=block
E: DEVTYPE=disk
E: DEVNAME=/dev/sda
E: DRIVER=sd
";
        let info = parse_udevadm_info(output).unwrap();
        assert_eq!(
            info.devpath,
            "/devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda"
        );
        assert_eq!(
            info.syspath,
            "/sys/devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda"
        );
        assert_eq!(info.subsystem, "block");
        assert_eq!(info.devtype, Some("disk".into()));
        assert_eq!(info.devnode, Some("/dev/sda".into()));
        assert_eq!(info.driver, Some("sd".into()));
    }

    #[test]
    fn test_parse_udevadm_info_devnode_from_n_line() {
        let output = "\
P: /devices/virtual/net/lo
N: lo
E: SUBSYSTEM=net
";
        let info = parse_udevadm_info(output).unwrap();
        // N: line takes priority when DEVNAME is absent
        assert_eq!(info.devnode, Some("/dev/lo".into()));
    }

    #[test]
    fn test_parse_udevadm_info_devnode_from_property() {
        let output = "\
P: /devices/virtual/tty/tty0
E: SUBSYSTEM=tty
E: DEVNAME=/dev/tty0
";
        let info = parse_udevadm_info(output).unwrap();
        assert_eq!(info.devnode, Some("/dev/tty0".into()));
    }

    #[test]
    fn test_parse_udevadm_info_missing_devpath() {
        let output = "E: SUBSYSTEM=block\n";
        let err = parse_udevadm_info(output).unwrap_err();
        assert!(err.to_string().contains("devpath"));
    }

    #[test]
    fn test_parse_udevadm_info_empty_input() {
        let err = parse_udevadm_info("").unwrap_err();
        assert!(err.to_string().contains("devpath"));
    }

    #[test]
    fn test_parse_udevadm_info_symlinks_accumulated() {
        let output = "\
P: /devices/pci0000:00/block/sda
N: sda
S: disk/by-id/ata-VBOX1
S: disk/by-path/pci-0000
E: SUBSYSTEM=block
";
        let info = parse_udevadm_info(output).unwrap();
        let devlinks = info.properties.get("DEVLINKS").unwrap();
        assert!(devlinks.contains("/dev/disk/by-id/ata-VBOX1"));
        assert!(devlinks.contains("/dev/disk/by-path/pci-0000"));
    }

    // -- parse_export_db ---------------------------------------------------

    #[test]
    fn test_parse_export_db_multiple_devices() {
        let output = "\
P: /devices/pci0000:00/block/sda
N: sda
E: SUBSYSTEM=block

P: /devices/virtual/net/lo
E: SUBSYSTEM=net

";
        let devices = parse_export_db(output).unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].subsystem, "block");
        assert_eq!(devices[1].subsystem, "net");
    }

    #[test]
    fn test_parse_export_db_trailing_block_no_newline() {
        let output = "P: /devices/virtual/tty/tty0\nE: SUBSYSTEM=tty";
        let devices = parse_export_db(output).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].subsystem, "tty");
    }

    // -- DeviceSubsystem ---------------------------------------------------

    #[test]
    fn test_subsystem_from_str_known() {
        assert_eq!(DeviceSubsystem::parse("block"), DeviceSubsystem::Block);
        assert_eq!(DeviceSubsystem::parse("net"), DeviceSubsystem::Net);
        assert_eq!(DeviceSubsystem::parse("input"), DeviceSubsystem::Input);
        assert_eq!(DeviceSubsystem::parse("usb"), DeviceSubsystem::Usb);
        assert_eq!(DeviceSubsystem::parse("pci"), DeviceSubsystem::Pci);
        assert_eq!(DeviceSubsystem::parse("tty"), DeviceSubsystem::Tty);
        assert_eq!(DeviceSubsystem::parse("drm"), DeviceSubsystem::Gpu);
        assert_eq!(DeviceSubsystem::parse("sound"), DeviceSubsystem::Sound);
        assert_eq!(DeviceSubsystem::parse("snd"), DeviceSubsystem::Sound);
    }

    #[test]
    fn test_subsystem_from_str_other() {
        assert_eq!(
            DeviceSubsystem::parse("thunderbolt"),
            DeviceSubsystem::Other("thunderbolt".into())
        );
    }

    #[test]
    fn test_subsystem_display_roundtrip() {
        let subs = [
            DeviceSubsystem::Block,
            DeviceSubsystem::Net,
            DeviceSubsystem::Gpu,
        ];
        for sub in &subs {
            let s = sub.to_string();
            assert!(!s.is_empty());
        }
        assert_eq!(DeviceSubsystem::Other("nvme".into()).to_string(), "nvme");
    }

    // -- DeviceEvent -------------------------------------------------------

    #[test]
    fn test_device_event_display() {
        assert_eq!(DeviceEvent::Add.to_string(), "add");
        assert_eq!(DeviceEvent::Remove.to_string(), "remove");
        assert_eq!(DeviceEvent::Change.to_string(), "change");
        assert_eq!(DeviceEvent::Bind.to_string(), "bind");
        assert_eq!(DeviceEvent::Unbind.to_string(), "unbind");
    }

    #[test]
    fn test_device_event_from_str() {
        assert_eq!(DeviceEvent::parse("add").unwrap(), DeviceEvent::Add);
        assert_eq!(DeviceEvent::parse("remove").unwrap(), DeviceEvent::Remove);
        assert!(DeviceEvent::parse("invalid").is_err());
    }

    // -- render_udev_rule --------------------------------------------------

    #[test]
    fn test_render_udev_rule_basic() {
        let rule = UdevRule {
            name: "99-agnos-usb".to_string(),
            match_attrs: vec![
                ("SUBSYSTEM".into(), "usb".into()),
                ("ATTR{idVendor}".into(), "1234".into()),
            ],
            actions: vec![
                ("MODE".into(), "0660".into()),
                ("GROUP".into(), "agnos".into()),
            ],
        };
        let rendered = render_udev_rule(&rule);
        assert!(rendered.contains("# AGNOS udev rule: 99-agnos-usb"));
        assert!(rendered.contains("SUBSYSTEM==\"usb\""));
        assert!(rendered.contains("ATTR{idVendor}==\"1234\""));
        assert!(rendered.contains("MODE=\"0660\""));
        assert!(rendered.contains("GROUP=\"agnos\""));
    }

    #[test]
    fn test_render_udev_rule_append_operator() {
        let rule = UdevRule {
            name: "99-test".to_string(),
            match_attrs: vec![("SUBSYSTEM".into(), "net".into())],
            actions: vec![("TAG+=".into(), "systemd".into())],
        };
        let rendered = render_udev_rule(&rule);
        assert!(rendered.contains("TAG+=\"systemd\""));
    }

    // -- validate_rule -----------------------------------------------------

    #[test]
    fn test_validate_rule_valid() {
        let rule = UdevRule {
            name: "99-agnos-test".to_string(),
            match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
            actions: vec![("MODE".into(), "0660".into())],
        };
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_rule_empty_name() {
        let rule = UdevRule {
            name: String::new(),
            match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
            actions: vec![],
        };
        let err = validate_rule(&rule).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_validate_rule_dangerous_run() {
        let rule = UdevRule {
            name: "99-bad".to_string(),
            match_attrs: vec![("SUBSYSTEM".into(), "usb".into())],
            actions: vec![("RUN".into(), "/bin/malicious".into())],
        };
        let err = validate_rule(&rule).unwrap_err();
        assert!(err.to_string().contains("Dangerous"));
    }

    #[test]
    fn test_validate_rule_dangerous_program() {
        let rule = UdevRule {
            name: "99-bad".to_string(),
            match_attrs: vec![("SUBSYSTEM".into(), "usb".into())],
            actions: vec![("PROGRAM".into(), "/bin/exploit".into())],
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_rule_no_match_attrs() {
        let rule = UdevRule {
            name: "99-empty".to_string(),
            match_attrs: vec![],
            actions: vec![("MODE".into(), "0660".into())],
        };
        let err = validate_rule(&rule).unwrap_err();
        assert!(err.to_string().contains("match condition"));
    }

    #[test]
    fn test_validate_rule_invalid_match_key() {
        let rule = UdevRule {
            name: "99-bad-key".to_string(),
            match_attrs: vec![("BOGUS_KEY".into(), "value".into())],
            actions: vec![],
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_rule_empty_match_value() {
        let rule = UdevRule {
            name: "99-empty-val".to_string(),
            match_attrs: vec![("SUBSYSTEM".into(), "".into())],
            actions: vec![],
        };
        let err = validate_rule(&rule).unwrap_err();
        assert!(err.to_string().contains("Empty value"));
    }

    #[test]
    fn test_validate_rule_name_path_traversal() {
        let rule = UdevRule {
            name: "../etc/passwd".to_string(),
            match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
            actions: vec![],
        };
        assert!(validate_rule(&rule).is_err());
    }

    // -- DeviceInfo serialization ------------------------------------------

    #[test]
    fn test_device_info_serialize_deserialize() {
        let info = DeviceInfo {
            syspath: "/sys/devices/pci0000:00/block/sda".into(),
            devpath: "/devices/pci0000:00/block/sda".into(),
            subsystem: "block".into(),
            devtype: Some("disk".into()),
            driver: None,
            devnode: Some("/dev/sda".into()),
            properties: {
                let mut m = HashMap::new();
                m.insert("ID_SERIAL".into(), "VBOX123".into());
                m
            },
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: DeviceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }

    #[test]
    fn test_udev_rule_serialize_deserialize() {
        let rule = UdevRule {
            name: "99-test".into(),
            match_attrs: vec![("SUBSYSTEM".into(), "net".into())],
            actions: vec![("MODE".into(), "0644".into())],
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: UdevRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    // -- DeviceMonitorConfig -----------------------------------------------

    #[test]
    fn test_device_monitor_config_default() {
        let config = DeviceMonitorConfig::default();
        assert!(config.subsystem_filter.is_none());
        assert!(config.devtype_filter.is_none());
    }

    // ---- parse_udevadm_info edge cases ----

    #[test]
    fn test_parse_udevadm_info_no_devnode() {
        let output = "\
P: /devices/platform/serial8250
E: SUBSYSTEM=platform
";
        let info = parse_udevadm_info(output).unwrap();
        assert!(info.devnode.is_none());
        assert_eq!(info.subsystem, "platform");
    }

    #[test]
    fn test_parse_udevadm_info_no_driver() {
        let output = "\
P: /devices/virtual/misc/cpu_dma_latency
E: SUBSYSTEM=misc
";
        let info = parse_udevadm_info(output).unwrap();
        assert!(info.driver.is_none());
    }

    #[test]
    fn test_parse_udevadm_info_no_devtype() {
        let output = "\
P: /devices/virtual/net/lo
N: lo
E: SUBSYSTEM=net
";
        let info = parse_udevadm_info(output).unwrap();
        assert!(info.devtype.is_none());
    }

    #[test]
    fn test_parse_udevadm_info_multiple_properties() {
        let output = "\
P: /devices/pci0000:00/0000:00:02.0
E: SUBSYSTEM=pci
E: PCI_CLASS=30000
E: PCI_ID=8086:1234
E: PCI_SLOT_NAME=0000:00:02.0
E: DRIVER=i915
";
        let info = parse_udevadm_info(output).unwrap();
        assert_eq!(info.properties.get("PCI_CLASS").unwrap(), "30000");
        assert_eq!(info.properties.get("PCI_ID").unwrap(), "8086:1234");
        assert_eq!(info.driver, Some("i915".into()));
    }

    #[test]
    fn test_parse_udevadm_info_devnode_n_line_priority_over_devname() {
        // When both N: and DEVNAME are present, N: line should be used
        let output = "\
P: /devices/virtual/tty/tty0
N: tty0
E: SUBSYSTEM=tty
E: DEVNAME=/dev/tty0
";
        let info = parse_udevadm_info(output).unwrap();
        assert_eq!(info.devnode, Some("/dev/tty0".into()));
    }

    #[test]
    fn test_parse_udevadm_info_only_empty_lines() {
        let err = parse_udevadm_info("\n\n\n").unwrap_err();
        assert!(err.to_string().contains("devpath"));
    }

    #[test]
    fn test_parse_udevadm_info_e_line_without_equals() {
        // E: lines without '=' should be silently skipped
        let output = "\
P: /devices/virtual/misc/test
E: SUBSYSTEM=misc
E: MALFORMED_LINE
";
        let info = parse_udevadm_info(output).unwrap();
        assert_eq!(info.subsystem, "misc");
        // The malformed E: line should not cause a crash
    }

    #[test]
    fn test_parse_udevadm_info_e_line_value_with_equals() {
        // E: KEY=value=with=equals — split_once should only split on first '='
        let output = "\
P: /devices/virtual/misc/test
E: SUBSYSTEM=misc
E: COMPLEX_VAL=key=value=pair
";
        let info = parse_udevadm_info(output).unwrap();
        assert_eq!(
            info.properties.get("COMPLEX_VAL").unwrap(),
            "key=value=pair"
        );
    }

    // ---- parse_export_db edge cases ----

    #[test]
    fn test_parse_export_db_empty_input() {
        let devices = parse_export_db("").unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn test_parse_export_db_only_blank_lines() {
        let devices = parse_export_db("\n\n\n").unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn test_parse_export_db_block_without_p_line_skipped() {
        let output = "\
E: SUBSYSTEM=block
E: DEVNAME=/dev/sda

P: /devices/virtual/net/lo
E: SUBSYSTEM=net
";
        let devices = parse_export_db(output).unwrap();
        // First block has no P: line, should be skipped
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].subsystem, "net");
    }

    #[test]
    fn test_parse_export_db_three_devices() {
        let output = "\
P: /devices/pci0000:00/block/sda
E: SUBSYSTEM=block

P: /devices/virtual/net/lo
E: SUBSYSTEM=net

P: /devices/virtual/tty/tty0
E: SUBSYSTEM=tty
";
        let devices = parse_export_db(output).unwrap();
        assert_eq!(devices.len(), 3);
    }

    #[test]
    fn test_parse_export_db_no_trailing_newline() {
        let output = "P: /devices/test\nE: SUBSYSTEM=test";
        let devices = parse_export_db(output).unwrap();
        assert_eq!(devices.len(), 1);
    }

    // ---- DeviceSubsystem display roundtrip ----

    #[test]
    fn test_subsystem_display_all_variants() {
        assert_eq!(DeviceSubsystem::Block.to_string(), "block");
        assert_eq!(DeviceSubsystem::Net.to_string(), "net");
        assert_eq!(DeviceSubsystem::Input.to_string(), "input");
        assert_eq!(DeviceSubsystem::Usb.to_string(), "usb");
        assert_eq!(DeviceSubsystem::Pci.to_string(), "pci");
        assert_eq!(DeviceSubsystem::Tty.to_string(), "tty");
        assert_eq!(DeviceSubsystem::Gpu.to_string(), "drm");
        assert_eq!(DeviceSubsystem::Sound.to_string(), "sound");
        assert_eq!(
            DeviceSubsystem::Other("custom".into()).to_string(),
            "custom"
        );
    }

    // ---- DeviceEvent parse all valid values ----

    #[test]
    fn test_device_event_parse_all() {
        assert_eq!(DeviceEvent::parse("change").unwrap(), DeviceEvent::Change);
        assert_eq!(DeviceEvent::parse("bind").unwrap(), DeviceEvent::Bind);
        assert_eq!(DeviceEvent::parse("unbind").unwrap(), DeviceEvent::Unbind);
    }

    #[test]
    fn test_device_event_parse_case_sensitive() {
        assert!(DeviceEvent::parse("Add").is_err());
        assert!(DeviceEvent::parse("REMOVE").is_err());
        assert!(DeviceEvent::parse("").is_err());
    }

    // ---- validate_rule comprehensive coverage ----

    #[test]
    fn test_validate_rule_name_too_long() {
        let rule = UdevRule {
            name: "a".repeat(129),
            match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
            actions: vec![],
        };
        let err = validate_rule(&rule).unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn test_validate_rule_name_exactly_128() {
        let rule = UdevRule {
            name: "a".repeat(128),
            match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
            actions: vec![],
        };
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_rule_name_with_spaces() {
        let rule = UdevRule {
            name: "name with spaces".into(),
            match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
            actions: vec![],
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_rule_name_with_dots() {
        let rule = UdevRule {
            name: "99.test.rule".into(),
            match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
            actions: vec![],
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_rule_name_with_dash_and_underscore() {
        let rule = UdevRule {
            name: "99-agnos_test".into(),
            match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
            actions: vec![],
        };
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_rule_dangerous_import_program() {
        let rule = UdevRule {
            name: "99-bad".into(),
            match_attrs: vec![("SUBSYSTEM".into(), "usb".into())],
            actions: vec![("IMPORT{program}".into(), "/bin/exploit".into())],
        };
        let err = validate_rule(&rule).unwrap_err();
        assert!(err.to_string().contains("Dangerous"));
    }

    #[test]
    fn test_validate_rule_dangerous_import_builtin() {
        let rule = UdevRule {
            name: "99-bad".into(),
            match_attrs: vec![("SUBSYSTEM".into(), "usb".into())],
            actions: vec![("IMPORT{builtin}".into(), "path_id".into())],
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_rule_invalid_action_key() {
        let rule = UdevRule {
            name: "99-bad".into(),
            match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
            actions: vec![("BOGUS_ACTION".into(), "value".into())],
        };
        let err = validate_rule(&rule).unwrap_err();
        assert!(err.to_string().contains("Invalid action key"));
    }

    #[test]
    fn test_validate_rule_valid_with_attr_qualifier() {
        let rule = UdevRule {
            name: "99-test".into(),
            match_attrs: vec![("ATTR{idVendor}".into(), "1234".into())],
            actions: vec![("MODE".into(), "0660".into())],
        };
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_rule_valid_all_match_keys() {
        for key in &["SUBSYSTEM", "KERNEL", "DRIVER", "ACTION", "DEVPATH", "TAG"] {
            let rule = UdevRule {
                name: "99-test".into(),
                match_attrs: vec![(key.to_string(), "value".into())],
                actions: vec![],
            };
            assert!(validate_rule(&rule).is_ok(), "Key {} should be valid", key);
        }
    }

    #[test]
    fn test_validate_rule_valid_env_match_key() {
        let rule = UdevRule {
            name: "99-test".into(),
            match_attrs: vec![("ENV{ID_SERIAL}".into(), "ABC123".into())],
            actions: vec![],
        };
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_rule_valid_attrs_match_key() {
        let rule = UdevRule {
            name: "99-test".into(),
            match_attrs: vec![("ATTRS{idVendor}".into(), "1234".into())],
            actions: vec![],
        };
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_rule_valid_action_keys() {
        for key in &["MODE", "OWNER", "GROUP", "NAME", "OPTIONS"] {
            let rule = UdevRule {
                name: "99-test".into(),
                match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
                actions: vec![(key.to_string(), "value".into())],
            };
            assert!(
                validate_rule(&rule).is_ok(),
                "Action key {} should be valid",
                key
            );
        }
    }

    #[test]
    fn test_validate_rule_symlink_append() {
        let rule = UdevRule {
            name: "99-test".into(),
            match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
            actions: vec![("SYMLINK+=".into(), "my-device".into())],
        };
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_rule_tag_append() {
        let rule = UdevRule {
            name: "99-test".into(),
            match_attrs: vec![("SUBSYSTEM".into(), "block".into())],
            actions: vec![("TAG+=".into(), "systemd".into())],
        };
        assert!(validate_rule(&rule).is_ok());
    }

    // ---- render_udev_rule edge cases ----

    #[test]
    fn test_render_udev_rule_empty_actions() {
        let rule = UdevRule {
            name: "99-match-only".into(),
            match_attrs: vec![("SUBSYSTEM".into(), "net".into())],
            actions: vec![],
        };
        let rendered = render_udev_rule(&rule);
        assert!(rendered.contains("# AGNOS udev rule: 99-match-only"));
        assert!(rendered.contains("SUBSYSTEM==\"net\""));
    }

    #[test]
    fn test_render_udev_rule_multiple_symlinks() {
        let rule = UdevRule {
            name: "99-links".into(),
            match_attrs: vec![("KERNEL".into(), "sd*".into())],
            actions: vec![
                ("SYMLINK+=".into(), "disk/by-name/first".into()),
                ("SYMLINK+=".into(), "disk/by-name/second".into()),
            ],
        };
        let rendered = render_udev_rule(&rule);
        assert!(rendered.contains("SYMLINK+=\"disk/by-name/first\""));
        assert!(rendered.contains("SYMLINK+=\"disk/by-name/second\""));
    }

    #[test]
    fn test_render_udev_rule_mixed_actions() {
        let rule = UdevRule {
            name: "99-mixed".into(),
            match_attrs: vec![("SUBSYSTEM".into(), "usb".into())],
            actions: vec![
                ("MODE".into(), "0660".into()),
                ("GROUP".into(), "plugdev".into()),
                ("TAG+=".into(), "uaccess".into()),
            ],
        };
        let rendered = render_udev_rule(&rule);
        assert!(rendered.contains("MODE=\"0660\""));
        assert!(rendered.contains("GROUP=\"plugdev\""));
        assert!(rendered.contains("TAG+=\"uaccess\""));
        // All parts should be comma-separated
        assert!(rendered.contains(", "));
    }

    // ---- DeviceSubsystem parse + serde ----

    #[test]
    fn test_subsystem_parse_empty_string() {
        assert_eq!(
            DeviceSubsystem::parse(""),
            DeviceSubsystem::Other("".into())
        );
    }

    #[test]
    fn test_subsystem_serde_roundtrip() {
        let subs = vec![
            DeviceSubsystem::Block,
            DeviceSubsystem::Net,
            DeviceSubsystem::Gpu,
            DeviceSubsystem::Other("nvme".into()),
        ];
        for sub in &subs {
            let json = serde_json::to_string(sub).unwrap();
            let back: DeviceSubsystem = serde_json::from_str(&json).unwrap();
            assert_eq!(sub, &back);
        }
    }

    // ---- DeviceEvent serde roundtrip ----

    #[test]
    fn test_device_event_serde_roundtrip() {
        let events = [
            DeviceEvent::Add,
            DeviceEvent::Remove,
            DeviceEvent::Change,
            DeviceEvent::Bind,
            DeviceEvent::Unbind,
        ];
        for ev in &events {
            let json = serde_json::to_string(ev).unwrap();
            let back: DeviceEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(*ev, back);
        }
    }

    // ---- DeviceMonitorConfig serde ----

    #[test]
    fn test_device_monitor_config_serde_roundtrip() {
        let config = DeviceMonitorConfig {
            subsystem_filter: Some("block".into()),
            devtype_filter: Some("disk".into()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: DeviceMonitorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.subsystem_filter, Some("block".into()));
        assert_eq!(back.devtype_filter, Some("disk".into()));
    }

    // ---- DeviceInfo with all optional fields None ----

    #[test]
    fn test_device_info_minimal() {
        let info = DeviceInfo {
            syspath: "/sys/devices/test".into(),
            devpath: "/devices/test".into(),
            subsystem: "test".into(),
            devtype: None,
            driver: None,
            devnode: None,
            properties: HashMap::new(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: DeviceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
        assert!(back.devtype.is_none());
        assert!(back.driver.is_none());
        assert!(back.devnode.is_none());
    }

    // ---- parse_udevadm_info: syspath constructed correctly ----

    #[test]
    fn test_parse_udevadm_info_syspath_prefixed() {
        let output = "\
P: /devices/test/device
E: SUBSYSTEM=test
";
        let info = parse_udevadm_info(output).unwrap();
        assert_eq!(info.syspath, "/sys/devices/test/device");
        assert_eq!(info.devpath, "/devices/test/device");
    }

    // ---- parse_export_db: mixed valid and invalid blocks ----

    #[test]
    fn test_parse_export_db_mixed_valid_invalid() {
        let output = "\
P: /devices/valid1
E: SUBSYSTEM=block

E: NO_P_LINE=true

P: /devices/valid2
E: SUBSYSTEM=net

";
        let devices = parse_export_db(output).unwrap();
        assert_eq!(devices.len(), 2);
    }

    // ---- Symlinks accumulation ----

    #[test]
    fn test_parse_udevadm_info_three_symlinks() {
        let output = "\
P: /devices/pci0000:00/block/sda
N: sda
S: disk/by-id/ata-VBOX1
S: disk/by-path/pci-0000
S: disk/by-uuid/1234-ABCD
E: SUBSYSTEM=block
";
        let info = parse_udevadm_info(output).unwrap();
        let devlinks = info.properties.get("DEVLINKS").unwrap();
        assert!(devlinks.contains("/dev/disk/by-id/ata-VBOX1"));
        assert!(devlinks.contains("/dev/disk/by-path/pci-0000"));
        assert!(devlinks.contains("/dev/disk/by-uuid/1234-ABCD"));
        // Should be space-separated
        let count = devlinks.split(' ').count();
        assert_eq!(count, 3);
    }
}
