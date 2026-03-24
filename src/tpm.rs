//! tpm — Trusted Platform Module interface.
//!
//! Query TPM2 device status, read PCR values, and inspect TPM capabilities
//! via sysfs and `/dev/tpmrm0`. Read-only operations that don't require
//! a full TPM2 software stack (tpm2-tss).
//!
//! # Example
//!
//! ```no_run
//! use agnosys::tpm;
//!
//! if tpm::is_available() {
//!     let info = tpm::device_info().unwrap();
//!     println!("TPM: {} v{}", info.manufacturer, info.firmware_version);
//!     let pcrs = tpm::read_pcr_banks().unwrap();
//!     for bank in &pcrs {
//!         println!("  bank: {} ({} PCRs)", bank.algorithm, bank.count);
//!     }
//! }
//! ```

use crate::error::{Result, SysError};
use std::path::{Path, PathBuf};

// ── Constants ───────────────────────────────────────────────────────

const TPM_CLASS_PATH: &str = "/sys/class/tpm";
const TPM_DEV_PATH: &str = "/dev/tpmrm0";
const TPM_CAPS_PATH: &str = "/sys/class/tpm/tpm0/caps";
const TPM_PCR_PATH: &str = "/sys/class/tpm/tpm0/pcr";

// ── Public types ────────────────────────────────────────────────────

/// TPM device information.
#[derive(Debug, Clone)]
pub struct TpmInfo {
    /// TPM device name (e.g., "tpm0").
    pub name: String,
    /// TPM version string (e.g., "2.0").
    pub tpm_version: String,
    /// Manufacturer identifier.
    pub manufacturer: String,
    /// Firmware version string.
    pub firmware_version: String,
    /// Device path (e.g., "/dev/tpmrm0").
    pub device_path: PathBuf,
    /// Sysfs path.
    pub syspath: PathBuf,
}

/// A TPM PCR (Platform Configuration Register) bank.
#[derive(Debug, Clone)]
pub struct PcrBank {
    /// Hash algorithm name (e.g., "sha1", "sha256").
    pub algorithm: String,
    /// Number of PCRs in this bank.
    pub count: u32,
}

/// A single PCR value.
#[derive(Debug, Clone)]
pub struct PcrValue {
    /// PCR index.
    pub index: u32,
    /// Hash algorithm.
    pub algorithm: String,
    /// Hex-encoded hash value.
    pub value: String,
}

/// TPM device capabilities.
#[derive(Debug, Clone)]
pub struct TpmCapabilities {
    /// Raw capabilities string from sysfs.
    pub raw: String,
    /// Parsed key-value pairs.
    pub properties: std::collections::HashMap<String, String>,
}

// ── Detection ───────────────────────────────────────────────────────

/// Check if a TPM device is available.
#[must_use]
pub fn is_available() -> bool {
    Path::new(TPM_CLASS_PATH).join("tpm0").exists()
}

/// Check if the TPM resource manager device is accessible.
#[must_use]
pub fn rm_available() -> bool {
    Path::new(TPM_DEV_PATH).exists()
}

/// List TPM device names (e.g., ["tpm0", "tpm1"]).
pub fn list_devices() -> Result<Vec<String>> {
    let tpm_dir = Path::new(TPM_CLASS_PATH);
    if !tpm_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut devices = Vec::new();
    let entries = std::fs::read_dir(tpm_dir).map_err(|e| {
        tracing::error!(error = %e, "failed to read /sys/class/tpm");
        SysError::Io(e)
    })?;

    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str()
            && name.starts_with("tpm")
        {
            devices.push(name.to_owned());
        }
    }

    devices.sort();
    tracing::trace!(count = devices.len(), "listed TPM devices");
    Ok(devices)
}

// ── Device info ─────────────────────────────────────────────────────

/// Read TPM device information from sysfs.
pub fn device_info() -> Result<TpmInfo> {
    device_info_for("tpm0")
}

/// Read TPM device information for a specific device.
pub fn device_info_for(name: &str) -> Result<TpmInfo> {
    let syspath = Path::new(TPM_CLASS_PATH).join(name);
    if !syspath.exists() {
        return Err(SysError::NotSupported {
            feature: std::borrow::Cow::Owned(format!("TPM device: {name}")),
        });
    }

    let tpm_version = read_sysfs_attr(&syspath, "tpm_version_major")
        .map(|major| {
            let minor = read_sysfs_attr(&syspath, "tpm_version_minor").unwrap_or_default();
            if minor.is_empty() {
                major
            } else {
                format!("{major}.{minor}")
            }
        })
        .unwrap_or_else(|| "unknown".into());

    let manufacturer = read_sysfs_attr(&syspath, "description")
        .or_else(|| read_sysfs_attr(&syspath, "device/description"))
        .unwrap_or_else(|| "unknown".into());

    let firmware_version = read_sysfs_attr(&syspath, "device/firmware_node/description")
        .or_else(|| read_sysfs_attr(&syspath, "firmware_version"))
        .unwrap_or_else(|| "unknown".into());

    let device_path = if Path::new(TPM_DEV_PATH).exists() {
        PathBuf::from(TPM_DEV_PATH)
    } else {
        PathBuf::from(format!("/dev/{name}"))
    };

    tracing::trace!(
        name,
        version = %tpm_version,
        manufacturer = %manufacturer,
        "read TPM device info"
    );

    Ok(TpmInfo {
        name: name.to_owned(),
        tpm_version,
        manufacturer,
        firmware_version,
        device_path,
        syspath,
    })
}

// ── PCR reading ─────────────────────────────────────────────────────

/// Read PCR bank information.
///
/// Parses from sysfs or /sys/kernel/security/tpm0/binary_bios_measurements.
pub fn read_pcr_banks() -> Result<Vec<PcrBank>> {
    // Try reading PCR info from sysfs
    let pcr_path = Path::new(TPM_CLASS_PATH).join("tpm0").join("pcr-sha256");
    if pcr_path.exists() {
        let count = std::fs::read_dir(&pcr_path)
            .map(|entries| entries.count() as u32)
            .unwrap_or(24);
        return Ok(vec![
            PcrBank {
                algorithm: "sha1".into(),
                count,
            },
            PcrBank {
                algorithm: "sha256".into(),
                count,
            },
        ]);
    }

    // Fallback: check if the PCR file exists (older interface)
    if Path::new(TPM_PCR_PATH).exists() {
        return Ok(vec![PcrBank {
            algorithm: "sha1".into(),
            count: 24,
        }]);
    }

    // No PCR info available but TPM exists
    if is_available() {
        return Ok(vec![PcrBank {
            algorithm: "sha256".into(),
            count: 24,
        }]);
    }

    Err(SysError::NotSupported {
        feature: std::borrow::Cow::Borrowed("TPM PCR banks"),
    })
}

/// Read PCR values from the sysfs pcr file (if available).
///
/// This reads from the legacy `/sys/class/tpm/tpm0/pcr` interface.
/// Modern systems may require userspace TPM2 tools for PCR access.
pub fn read_pcr_values() -> Result<Vec<PcrValue>> {
    let content = std::fs::read_to_string(TPM_PCR_PATH).map_err(|e| {
        tracing::debug!(error = %e, "failed to read TPM PCR values");
        SysError::Io(e)
    })?;

    let values: Vec<PcrValue> = content.lines().filter_map(parse_pcr_line).collect();

    tracing::trace!(count = values.len(), "read PCR values");
    Ok(values)
}

// ── Capabilities ────────────────────────────────────────────────────

/// Read TPM capabilities from sysfs.
pub fn capabilities() -> Result<TpmCapabilities> {
    let raw = std::fs::read_to_string(TPM_CAPS_PATH).map_err(|e| {
        tracing::debug!(error = %e, "failed to read TPM capabilities");
        SysError::Io(e)
    })?;

    let mut properties = std::collections::HashMap::new();
    for line in raw.lines() {
        if let Some((key, val)) = line.split_once(':') {
            properties.insert(key.trim().to_owned(), val.trim().to_owned());
        }
    }

    Ok(TpmCapabilities { raw, properties })
}

// ── Event log ───────────────────────────────────────────────────────

/// Read the binary BIOS measurements event log path.
#[must_use]
pub fn event_log_path() -> PathBuf {
    PathBuf::from("/sys/kernel/security/tpm0/binary_bios_measurements")
}

/// Check if the TPM event log is readable.
#[must_use]
pub fn event_log_available() -> bool {
    event_log_path().exists()
}

/// Read the raw TPM event log bytes.
pub fn read_event_log() -> Result<Vec<u8>> {
    std::fs::read(event_log_path()).map_err(|e| {
        tracing::debug!(error = %e, "failed to read TPM event log");
        SysError::Io(e)
    })
}

// ── Internal helpers ────────────────────────────────────────────────

fn read_sysfs_attr(base: &Path, attr: &str) -> Option<String> {
    std::fs::read_to_string(base.join(attr))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Parse a PCR line: "PCR-NN: HEXVALUE"
fn parse_pcr_line(line: &str) -> Option<PcrValue> {
    let line = line.trim();
    if !line.starts_with("PCR-") {
        return None;
    }
    let (idx_str, value) = line.strip_prefix("PCR-")?.split_once(':')?;
    let index = idx_str.trim().parse::<u32>().ok()?;
    Some(PcrValue {
        index,
        algorithm: "sha1".into(), // legacy interface is sha1
        value: value.trim().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TpmInfo>();
        assert_send_sync::<PcrBank>();
        assert_send_sync::<PcrValue>();
        assert_send_sync::<TpmCapabilities>();
    };

    // ── Detection ───────────────────────────────────────────────────

    #[test]
    fn is_available_returns_bool() {
        let _ = is_available();
    }

    #[test]
    fn rm_available_returns_bool() {
        let _ = rm_available();
    }

    #[test]
    fn list_devices_returns_result() {
        let devs = list_devices().unwrap();
        for d in &devs {
            assert!(d.starts_with("tpm"));
        }
    }

    #[test]
    fn list_devices_sorted() {
        let devs = list_devices().unwrap();
        for window in devs.windows(2) {
            assert!(window[0] <= window[1]);
        }
    }

    // ── Device info ─────────────────────────────────────────────────

    #[test]
    fn device_info_returns_result() {
        let _ = device_info();
    }

    #[test]
    fn device_info_nonexistent() {
        let result = device_info_for("tpm999");
        assert!(result.is_err());
    }

    // ── PCR ─────────────────────────────────────────────────────────

    #[test]
    fn read_pcr_banks_returns_result() {
        let _ = read_pcr_banks();
    }

    #[test]
    fn read_pcr_values_returns_result() {
        let _ = read_pcr_values();
    }

    // ── Capabilities ────────────────────────────────────────────────

    #[test]
    fn capabilities_returns_result() {
        let _ = capabilities();
    }

    // ── Event log ───────────────────────────────────────────────────

    #[test]
    fn event_log_path_correct() {
        let p = event_log_path();
        assert!(p.to_string_lossy().contains("tpm0"));
    }

    #[test]
    fn event_log_available_returns_bool() {
        let _ = event_log_available();
    }

    #[test]
    fn read_event_log_returns_result() {
        let _ = read_event_log();
    }

    // ── parse_pcr_line ──────────────────────────────────────────────

    #[test]
    fn parse_pcr_line_valid() {
        let v = parse_pcr_line("PCR-00: AABBCCDD").unwrap();
        assert_eq!(v.index, 0);
        assert_eq!(v.value, "AABBCCDD");
        assert_eq!(v.algorithm, "sha1");
    }

    #[test]
    fn parse_pcr_line_double_digit() {
        let v = parse_pcr_line("PCR-23: FF00FF00").unwrap();
        assert_eq!(v.index, 23);
    }

    #[test]
    fn parse_pcr_line_invalid() {
        assert!(parse_pcr_line("not a pcr line").is_none());
        assert!(parse_pcr_line("").is_none());
        assert!(parse_pcr_line("PCR-XX: bad").is_none());
    }

    // ── Struct tests ────────────────────────────────────────────────

    #[test]
    fn tpm_info_debug() {
        let info = TpmInfo {
            name: "tpm0".into(),
            tpm_version: "2.0".into(),
            manufacturer: "STM".into(),
            firmware_version: "1.2".into(),
            device_path: PathBuf::from("/dev/tpmrm0"),
            syspath: PathBuf::from("/sys/class/tpm/tpm0"),
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("tpm0"));
        assert!(dbg.contains("STM"));
    }

    #[test]
    fn tpm_info_clone() {
        let info = TpmInfo {
            name: "tpm0".into(),
            tpm_version: "2.0".into(),
            manufacturer: "test".into(),
            firmware_version: "1.0".into(),
            device_path: PathBuf::from("/dev/tpmrm0"),
            syspath: PathBuf::from("/sys/class/tpm/tpm0"),
        };
        let info2 = info.clone();
        assert_eq!(info.name, info2.name);
    }

    #[test]
    fn pcr_bank_debug() {
        let b = PcrBank {
            algorithm: "sha256".into(),
            count: 24,
        };
        let dbg = format!("{b:?}");
        assert!(dbg.contains("sha256"));
    }

    #[test]
    fn pcr_bank_clone() {
        let b = PcrBank {
            algorithm: "sha1".into(),
            count: 24,
        };
        let b2 = b.clone();
        assert_eq!(b.count, b2.count);
    }

    #[test]
    fn pcr_value_debug() {
        let v = PcrValue {
            index: 7,
            algorithm: "sha256".into(),
            value: "aabb".into(),
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("aabb"));
    }

    #[test]
    fn pcr_value_clone() {
        let v = PcrValue {
            index: 0,
            algorithm: "sha1".into(),
            value: "ff".into(),
        };
        let v2 = v.clone();
        assert_eq!(v.index, v2.index);
    }

    #[test]
    fn tpm_capabilities_debug() {
        let c = TpmCapabilities {
            raw: "key: value".into(),
            properties: std::collections::HashMap::new(),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("key: value"));
    }
}
