//! bootloader — Bootloader interface.
//!
//! Detect the active bootloader, read boot entries, and inspect boot
//! configuration. Supports systemd-boot and GRUB detection via
//! standard Linux paths.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::bootloader;
//!
//! let bl = bootloader::detect().unwrap();
//! println!("bootloader: {}", bl.name);
//! for entry in bootloader::list_entries().unwrap() {
//!     println!("  {}: {}", entry.id, entry.title);
//! }
//! ```

use crate::error::{Result, SysError};
use std::path::{Path, PathBuf};

// ── Constants ───────────────────────────────────────────────────────

const LOADER_ENTRIES_PATH: &str = "/boot/loader/entries";
const LOADER_CONF_PATH: &str = "/boot/loader/loader.conf";
const GRUB_CFG_PATH: &str = "/boot/grub/grub.cfg";
const GRUB2_CFG_PATH: &str = "/boot/grub2/grub.cfg";
const EFI_LOADER_PATH: &str =
    "/sys/firmware/efi/efivars/LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

// ── Public types ────────────────────────────────────────────────────

/// Detected bootloader information.
#[derive(Debug, Clone)]
pub struct BootloaderInfo {
    /// Bootloader name (e.g., "systemd-boot", "grub", "unknown").
    pub name: String,
    /// Bootloader type classification.
    pub kind: BootloaderKind,
    /// Configuration file path (if found).
    pub config_path: Option<PathBuf>,
}

/// Bootloader type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BootloaderKind {
    /// systemd-boot (formerly gummiboot).
    SystemdBoot,
    /// GRUB (version 1 or 2).
    Grub,
    /// Unknown bootloader.
    Unknown,
}

impl std::fmt::Display for BootloaderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SystemdBoot => write!(f, "systemd-boot"),
            Self::Grub => write!(f, "grub"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A boot entry (systemd-boot .conf file).
#[derive(Debug, Clone)]
pub struct BootEntry {
    /// Entry ID (filename without extension).
    pub id: String,
    /// Display title.
    pub title: String,
    /// Linux kernel path.
    pub linux: String,
    /// Initrd path(s).
    pub initrd: Vec<String>,
    /// Kernel command line options.
    pub options: String,
    /// Full path to the entry file.
    pub path: PathBuf,
}

/// Parsed loader.conf settings.
#[derive(Debug, Clone, Default)]
pub struct LoaderConfig {
    /// Default boot entry pattern.
    pub default: String,
    /// Timeout in seconds (empty = no timeout).
    pub timeout: String,
    /// Console mode setting.
    pub console_mode: String,
    /// Editor enabled/disabled.
    pub editor: String,
}

// ── Detection ───────────────────────────────────────────────────────

/// Detect the active bootloader.
pub fn detect() -> Result<BootloaderInfo> {
    // Check systemd-boot first (has loader entries dir)
    if Path::new(LOADER_ENTRIES_PATH).is_dir() {
        return Ok(BootloaderInfo {
            name: "systemd-boot".into(),
            kind: BootloaderKind::SystemdBoot,
            config_path: if Path::new(LOADER_CONF_PATH).is_file() {
                Some(PathBuf::from(LOADER_CONF_PATH))
            } else {
                None
            },
        });
    }

    // Check for EFI loader info variable
    if Path::new(EFI_LOADER_PATH).exists()
        && let Ok(data) = std::fs::read(EFI_LOADER_PATH)
        && data.len() > 4
    {
        let name = decode_utf16le(&data[4..]);
        if name.to_lowercase().contains("systemd") {
            return Ok(BootloaderInfo {
                name,
                kind: BootloaderKind::SystemdBoot,
                config_path: None,
            });
        }
    }

    // Check GRUB
    for path in [GRUB_CFG_PATH, GRUB2_CFG_PATH] {
        if Path::new(path).is_file() {
            return Ok(BootloaderInfo {
                name: "grub".into(),
                kind: BootloaderKind::Grub,
                config_path: Some(PathBuf::from(path)),
            });
        }
    }

    Ok(BootloaderInfo {
        name: "unknown".into(),
        kind: BootloaderKind::Unknown,
        config_path: None,
    })
}

// ── Boot entries (systemd-boot) ─────────────────────────────────────

/// List boot entries from `/boot/loader/entries/*.conf`.
pub fn list_entries() -> Result<Vec<BootEntry>> {
    let dir = Path::new(LOADER_ENTRIES_PATH);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let dir_entries = std::fs::read_dir(dir).map_err(|e| {
        tracing::error!(error = %e, "failed to read loader entries");
        SysError::Io(e)
    })?;

    for entry in dir_entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "conf")
            && let Ok(boot_entry) = parse_boot_entry(&path)
        {
            entries.push(boot_entry);
        }
    }

    entries.sort_by(|a, b| a.id.cmp(&b.id));
    tracing::trace!(count = entries.len(), "listed boot entries");
    Ok(entries)
}

/// Read a specific boot entry by ID.
pub fn read_entry(id: &str) -> Result<BootEntry> {
    let path = Path::new(LOADER_ENTRIES_PATH).join(format!("{id}.conf"));
    parse_boot_entry(&path)
}

// ── Loader config ───────────────────────────────────────────────────

/// Read the systemd-boot loader.conf configuration.
pub fn read_loader_config() -> Result<LoaderConfig> {
    let content = std::fs::read_to_string(LOADER_CONF_PATH).map_err(|e| {
        tracing::debug!(error = %e, "failed to read loader.conf");
        SysError::Io(e)
    })?;

    Ok(parse_loader_config(&content))
}

/// Parse loader.conf content.
#[must_use]
pub fn parse_loader_config(content: &str) -> LoaderConfig {
    let mut config = LoaderConfig::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once(char::is_whitespace) {
            let val = val.trim();
            match key {
                "default" => config.default = val.to_owned(),
                "timeout" => config.timeout = val.to_owned(),
                "console-mode" => config.console_mode = val.to_owned(),
                "editor" => config.editor = val.to_owned(),
                _ => {}
            }
        }
    }

    config
}

// ── Boot partition ──────────────────────────────────────────────────

/// Check if `/boot` is mounted.
#[must_use]
pub fn boot_mounted() -> bool {
    // Check if /boot has its own mount (different device from /)
    if let (Ok(root_meta), Ok(boot_meta)) = (std::fs::metadata("/"), std::fs::metadata("/boot")) {
        use std::os::unix::fs::MetadataExt;
        return boot_meta.dev() != root_meta.dev()
            || Path::new("/boot/vmlinuz").exists()
            || Path::new("/boot/loader").exists();
    }
    false
}

/// List kernel images in `/boot`.
pub fn list_kernels() -> Result<Vec<PathBuf>> {
    let boot = Path::new("/boot");
    if !boot.is_dir() {
        return Ok(Vec::new());
    }

    let mut kernels = Vec::new();
    let entries = std::fs::read_dir(boot).map_err(|e| {
        tracing::error!(error = %e, "failed to read /boot");
        SysError::Io(e)
    })?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("vmlinuz") || name_str.starts_with("bzImage") {
            kernels.push(entry.path());
        }
    }

    kernels.sort();
    tracing::trace!(count = kernels.len(), "listed kernels in /boot");
    Ok(kernels)
}

// ── Internal helpers ────────────────────────────────────────────────

fn parse_boot_entry(path: &Path) -> Result<BootEntry> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        tracing::debug!(path = %path.display(), error = %e, "failed to read boot entry");
        SysError::Io(e)
    })?;

    let id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_owned();

    let mut title = String::new();
    let mut linux = String::new();
    let mut initrd = Vec::new();
    let mut options = String::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once(char::is_whitespace) {
            let val = val.trim();
            match key {
                "title" => title = val.to_owned(),
                "linux" => linux = val.to_owned(),
                "initrd" => initrd.push(val.to_owned()),
                "options" => options = val.to_owned(),
                _ => {}
            }
        }
    }

    Ok(BootEntry {
        id,
        title,
        linux,
        initrd,
        options,
        path: path.to_owned(),
    })
}

/// Decode a null-terminated UTF-16LE string.
fn decode_utf16le(data: &[u8]) -> String {
    let mut chars = Vec::new();
    for chunk in data.chunks_exact(2) {
        let c = u16::from_le_bytes([chunk[0], chunk[1]]);
        if c == 0 {
            break;
        }
        chars.push(c);
    }
    String::from_utf16_lossy(&chars)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BootloaderInfo>();
        assert_send_sync::<BootloaderKind>();
        assert_send_sync::<BootEntry>();
        assert_send_sync::<LoaderConfig>();
    };

    // ── Detection ───────────────────────────────────────────────────

    #[test]
    fn detect_returns_result() {
        let info = detect().unwrap();
        assert!(!info.name.is_empty());
    }

    // ── BootloaderKind ──────────────────────────────────────────────

    #[test]
    fn bootloader_kind_display() {
        assert_eq!(format!("{}", BootloaderKind::SystemdBoot), "systemd-boot");
        assert_eq!(format!("{}", BootloaderKind::Grub), "grub");
        assert_eq!(format!("{}", BootloaderKind::Unknown), "unknown");
    }

    #[test]
    fn bootloader_kind_eq() {
        assert_eq!(BootloaderKind::SystemdBoot, BootloaderKind::SystemdBoot);
        assert_ne!(BootloaderKind::SystemdBoot, BootloaderKind::Grub);
    }

    #[test]
    fn bootloader_kind_debug() {
        let dbg = format!("{:?}", BootloaderKind::SystemdBoot);
        assert!(dbg.contains("SystemdBoot"));
    }

    #[test]
    fn bootloader_kind_copy() {
        let a = BootloaderKind::Grub;
        let b = a;
        assert_eq!(a, b);
    }

    // ── Boot entries ────────────────────────────────────────────────

    #[test]
    fn list_entries_returns_result() {
        let _ = list_entries();
    }

    #[test]
    fn list_entries_sorted() {
        if let Ok(entries) = list_entries() {
            for window in entries.windows(2) {
                assert!(window[0].id <= window[1].id);
            }
        }
    }

    // ── parse_loader_config ─────────────────────────────────────────

    #[test]
    fn parse_loader_config_full() {
        let content = "\
default arch-*
timeout 5
console-mode auto
editor yes
";
        let config = parse_loader_config(content);
        assert_eq!(config.default, "arch-*");
        assert_eq!(config.timeout, "5");
        assert_eq!(config.console_mode, "auto");
        assert_eq!(config.editor, "yes");
    }

    #[test]
    fn parse_loader_config_empty() {
        let config = parse_loader_config("");
        assert!(config.default.is_empty());
        assert!(config.timeout.is_empty());
    }

    #[test]
    fn parse_loader_config_comments() {
        let content = "\
# comment
default linux
# another comment
";
        let config = parse_loader_config(content);
        assert_eq!(config.default, "linux");
    }

    // ── Boot entry parsing ──────────────────────────────────────────

    #[test]
    fn parse_boot_entry_synthetic() {
        let tmp = &format!("/tmp/agnosys_test_boot_entry_{}.conf", std::process::id());
        let content = "\
title Arch Linux
linux /vmlinuz-linux
initrd /initramfs-linux.img
options root=UUID=abc123 rw
";
        std::fs::write(tmp, content).unwrap();
        let entry = parse_boot_entry(Path::new(tmp)).unwrap();
        std::fs::remove_file(tmp).unwrap();

        assert_eq!(entry.title, "Arch Linux");
        assert_eq!(entry.linux, "/vmlinuz-linux");
        assert_eq!(entry.initrd, vec!["/initramfs-linux.img"]);
        assert!(entry.options.contains("root=UUID=abc123"));
    }

    #[test]
    fn parse_boot_entry_multiple_initrd() {
        let tmp = &format!("/tmp/agnosys_test_boot_multi_{}.conf", std::process::id());
        let content = "\
title Test
linux /vmlinuz
initrd /intel-ucode.img
initrd /initramfs.img
options quiet
";
        std::fs::write(tmp, content).unwrap();
        let entry = parse_boot_entry(Path::new(tmp)).unwrap();
        std::fs::remove_file(tmp).unwrap();

        assert_eq!(entry.initrd.len(), 2);
    }

    #[test]
    fn parse_boot_entry_nonexistent() {
        assert!(parse_boot_entry(Path::new("/nonexistent_agnosys.conf")).is_err());
    }

    // ── Boot partition ──────────────────────────────────────────────

    #[test]
    fn boot_mounted_returns_bool() {
        let _ = boot_mounted();
    }

    #[test]
    fn list_kernels_returns_result() {
        let _ = list_kernels();
    }

    #[test]
    fn list_kernels_sorted() {
        if let Ok(kernels) = list_kernels() {
            for window in kernels.windows(2) {
                assert!(window[0] <= window[1]);
            }
        }
    }

    // ── BootloaderInfo struct ───────────────────────────────────────

    #[test]
    fn bootloader_info_debug() {
        let info = BootloaderInfo {
            name: "systemd-boot".into(),
            kind: BootloaderKind::SystemdBoot,
            config_path: Some(PathBuf::from("/boot/loader/loader.conf")),
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("systemd-boot"));
    }

    #[test]
    fn bootloader_info_clone() {
        let info = BootloaderInfo {
            name: "grub".into(),
            kind: BootloaderKind::Grub,
            config_path: None,
        };
        let info2 = info.clone();
        assert_eq!(info.name, info2.name);
        assert_eq!(info.kind, info2.kind);
    }

    // ── BootEntry struct ────────────────────────────────────────────

    #[test]
    fn boot_entry_debug() {
        let e = BootEntry {
            id: "arch".into(),
            title: "Arch Linux".into(),
            linux: "/vmlinuz".into(),
            initrd: vec!["/initramfs.img".into()],
            options: "quiet".into(),
            path: PathBuf::from("/boot/loader/entries/arch.conf"),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Arch Linux"));
    }

    #[test]
    fn boot_entry_clone() {
        let e = BootEntry {
            id: "test".into(),
            title: "Test".into(),
            linux: "/vmlinuz".into(),
            initrd: vec![],
            options: String::new(),
            path: PathBuf::from("/test"),
        };
        let e2 = e.clone();
        assert_eq!(e.id, e2.id);
    }

    // ── decode_utf16le ──────────────────────────────────────────────

    #[test]
    fn decode_utf16le_basic() {
        // "ABC" in UTF-16LE + null terminator
        let data = [0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x00, 0x00];
        assert_eq!(decode_utf16le(&data), "ABC");
    }

    #[test]
    fn decode_utf16le_empty() {
        let data = [0x00, 0x00];
        assert_eq!(decode_utf16le(&data), "");
    }

    #[test]
    fn decode_utf16le_no_null() {
        let data = [0x41, 0x00, 0x42, 0x00];
        assert_eq!(decode_utf16le(&data), "AB");
    }

    // ── LoaderConfig struct ─────────────────────────────────────────

    #[test]
    fn loader_config_debug() {
        let c = LoaderConfig {
            default: "arch-*".into(),
            timeout: "5".into(),
            ..Default::default()
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("arch-*"));
    }

    #[test]
    fn loader_config_default() {
        let c = LoaderConfig::default();
        assert!(c.default.is_empty());
        assert!(c.timeout.is_empty());
        assert!(c.console_mode.is_empty());
        assert!(c.editor.is_empty());
    }
}
