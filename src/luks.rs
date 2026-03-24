//! luks — LUKS encrypted storage.
//!
//! Manage dm-crypt volumes via the device-mapper ioctl interface and
//! LUKS header inspection. Open, close, and query encrypted volumes
//! without shelling out to cryptsetup.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::luks;
//!
//! // Check if a device has a LUKS header
//! use std::path::Path;
//! if luks::is_luks_device(Path::new("/dev/sda2")).unwrap() {
//!     let header = luks::read_header(Path::new("/dev/sda2")).unwrap();
//!     println!("LUKS version: {}", header.version);
//!     println!("Cipher: {}-{}", header.cipher_name, header.cipher_mode);
//! }
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;
use std::path::{Path, PathBuf};

// ── LUKS magic and constants ────────────────────────────────────────

/// LUKS1 magic bytes: "LUKS\xba\xbe"
const LUKS1_MAGIC: [u8; 6] = [0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE];
/// LUKS2 magic bytes: "LUKS\xba\xbe" (same magic, version field differs)
const LUKS_MAGIC_LEN: usize = 6;
/// Minimum header size to read for identification
const LUKS_HEADER_READ_SIZE: usize = 592;
/// LUKS key slot count (LUKS1)
const LUKS1_NUM_KEYS: usize = 8;

// ── DM ioctl constants ──────────────────────────────────────────────

const DM_DIR: &str = "mapper";
const DM_CONTROL_PATH: &str = "/dev/mapper/control";

// ── Public types ────────────────────────────────────────────────────

/// LUKS header information.
#[derive(Debug, Clone)]
pub struct LuksHeader {
    /// LUKS format version (1 or 2).
    pub version: u16,
    /// Cipher name (e.g., "aes").
    pub cipher_name: String,
    /// Cipher mode (e.g., "xts-plain64").
    pub cipher_mode: String,
    /// Hash spec (e.g., "sha256").
    pub hash_spec: String,
    /// Payload offset in sectors.
    pub payload_offset: u32,
    /// Master key length in bytes.
    pub key_bytes: u32,
    /// UUID of the LUKS partition.
    pub uuid: String,
    /// Key slot status (LUKS1: 8 slots, active/inactive).
    pub key_slots: Vec<KeySlotStatus>,
}

/// Status of a LUKS key slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeySlotStatus {
    /// Slot is inactive (no key material).
    Inactive,
    /// Slot is active (contains encrypted key).
    Active,
}

/// Status of an open dm-crypt volume.
#[derive(Debug, Clone)]
pub struct VolumeStatus {
    /// The dm name (e.g., "my_encrypted").
    pub name: String,
    /// The device-mapper device path.
    pub dm_path: PathBuf,
    /// Whether the volume is active.
    pub active: bool,
}

// ── LUKS header reading ─────────────────────────────────────────────

/// Check if a device has a valid LUKS header.
pub fn is_luks_device(path: &Path) -> Result<bool> {
    let data = read_device_bytes(path, LUKS_MAGIC_LEN)?;
    Ok(data.len() >= LUKS_MAGIC_LEN && data[..LUKS_MAGIC_LEN] == LUKS1_MAGIC)
}

/// Read and parse the LUKS header from a device.
pub fn read_header(path: &Path) -> Result<LuksHeader> {
    let data = read_device_bytes(path, LUKS_HEADER_READ_SIZE)?;

    if data.len() < LUKS_HEADER_READ_SIZE {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "device too small for LUKS header",
        )));
    }

    // Verify magic
    if data[..LUKS_MAGIC_LEN] != LUKS1_MAGIC {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "not a LUKS device (bad magic)",
        )));
    }

    // Parse LUKS1 header (big-endian)
    let version = u16::from_be_bytes([data[6], data[7]]);
    let cipher_name = read_null_string(&data[8..40]);
    let cipher_mode = read_null_string(&data[40..72]);
    let hash_spec = read_null_string(&data[72..104]);
    let payload_offset = u32::from_be_bytes([data[104], data[105], data[106], data[107]]);
    let key_bytes = u32::from_be_bytes([data[108], data[109], data[110], data[111]]);

    // UUID at offset 168, 40 bytes
    let uuid = read_null_string(&data[168..208]);

    // Key slots start at offset 208, each 48 bytes (LUKS1)
    let mut key_slots = Vec::with_capacity(LUKS1_NUM_KEYS);
    for i in 0..LUKS1_NUM_KEYS {
        let slot_offset = 208 + i * 48;
        if slot_offset + 4 <= data.len() {
            let active = u32::from_be_bytes([
                data[slot_offset],
                data[slot_offset + 1],
                data[slot_offset + 2],
                data[slot_offset + 3],
            ]);
            // 0x00AC71F3 = LUKS_KEY_ENABLED
            key_slots.push(if active == 0x00AC71F3 {
                KeySlotStatus::Active
            } else {
                KeySlotStatus::Inactive
            });
        }
    }

    tracing::trace!(
        version,
        cipher = %cipher_name,
        uuid = %uuid,
        "parsed LUKS header"
    );

    Ok(LuksHeader {
        version,
        cipher_name,
        cipher_mode,
        hash_spec,
        payload_offset,
        key_bytes,
        uuid,
        key_slots,
    })
}

// ── dm-crypt volume management ──────────────────────────────────────

/// Check if the device-mapper control device is accessible.
pub fn dm_available() -> bool {
    Path::new(DM_CONTROL_PATH).exists()
}

/// List active device-mapper device names in `/dev/mapper/`.
pub fn list_dm_devices() -> Result<Vec<String>> {
    let mapper_dir = Path::new("/dev").join(DM_DIR);
    if !mapper_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    let entries = std::fs::read_dir(&mapper_dir).map_err(|e| {
        tracing::error!(error = %e, "failed to read /dev/mapper");
        SysError::Io(e)
    })?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str != "control" {
            names.push(name_str.into_owned());
        }
    }

    names.sort();
    tracing::trace!(count = names.len(), "listed dm devices");
    Ok(names)
}

/// Check if a named dm-crypt volume exists.
#[must_use]
pub fn volume_exists(name: &str) -> bool {
    Path::new("/dev").join(DM_DIR).join(name).exists()
}

/// Get the device path for a named dm volume.
#[inline]
#[must_use]
pub fn volume_path(name: &str) -> PathBuf {
    Path::new("/dev").join(DM_DIR).join(name)
}

/// Query status of a dm-crypt volume by reading /sys/block.
pub fn volume_status(name: &str) -> Result<VolumeStatus> {
    let dm_path = volume_path(name);
    let active = dm_path.exists();

    Ok(VolumeStatus {
        name: name.to_owned(),
        dm_path,
        active,
    })
}

// ── Internal helpers ────────────────────────────────────────────────

/// Read the first `count` bytes from a device/file.
fn read_device_bytes(path: &Path, count: usize) -> Result<Vec<u8>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "failed to open device");
        SysError::Io(e)
    })?;

    let mut buf = vec![0u8; count];
    let n = file.read(&mut buf).map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "failed to read device");
        SysError::Io(e)
    })?;
    buf.truncate(n);
    Ok(buf)
}

/// Read a null-terminated string from a byte slice.
fn read_null_string(data: &[u8]) -> String {
    let len = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..len]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LuksHeader>();
        assert_send_sync::<KeySlotStatus>();
        assert_send_sync::<VolumeStatus>();
    };

    // ── LUKS magic ──────────────────────────────────────────────────

    #[test]
    fn luks_magic_bytes() {
        assert_eq!(&LUKS1_MAGIC, b"LUKS\xba\xbe");
    }

    // ── is_luks_device ──────────────────────────────────────────────

    #[test]
    fn is_luks_nonexistent_device() {
        let result = is_luks_device(Path::new("/dev/nonexistent_agnosys_test"));
        assert!(result.is_err());
    }

    #[test]
    fn is_luks_regular_file() {
        // /dev/null is not a LUKS device
        let result = is_luks_device(Path::new("/dev/null"));
        // /dev/null reads as empty, so not LUKS
        assert!(matches!(result, Ok(false)));
    }

    // ── read_header ─────────────────────────────────────────────────

    #[test]
    fn read_header_nonexistent() {
        let result = read_header(Path::new("/dev/nonexistent_agnosys_test"));
        assert!(result.is_err());
    }

    #[test]
    fn read_header_not_luks() {
        // /dev/zero has magic bytes of all zeros
        let result = read_header(Path::new("/dev/zero"));
        assert!(result.is_err());
    }

    // ── read_null_string ────────────────────────────────────────────

    #[test]
    fn read_null_string_normal() {
        assert_eq!(read_null_string(b"hello\0world"), "hello");
    }

    #[test]
    fn read_null_string_no_null() {
        assert_eq!(read_null_string(b"hello"), "hello");
    }

    #[test]
    fn read_null_string_empty() {
        assert_eq!(read_null_string(b"\0"), "");
    }

    #[test]
    fn read_null_string_all_null() {
        assert_eq!(read_null_string(b"\0\0\0"), "");
    }

    // ── dm_available ────────────────────────────────────────────────

    #[test]
    fn dm_available_returns_bool() {
        let _ = dm_available();
    }

    // ── list_dm_devices ─────────────────────────────────────────────

    #[test]
    fn list_dm_devices_returns_result() {
        let _ = list_dm_devices();
    }

    #[test]
    fn list_dm_devices_excludes_control() {
        if let Ok(devs) = list_dm_devices() {
            assert!(!devs.contains(&"control".to_owned()));
        }
    }

    #[test]
    fn list_dm_devices_sorted() {
        if let Ok(devs) = list_dm_devices() {
            for window in devs.windows(2) {
                assert!(window[0] <= window[1]);
            }
        }
    }

    // ── volume_exists ───────────────────────────────────────────────

    #[test]
    fn volume_exists_nonexistent() {
        assert!(!volume_exists("nonexistent_agnosys_test_vol"));
    }

    // ── volume_path ─────────────────────────────────────────────────

    #[test]
    fn volume_path_correct() {
        let p = volume_path("my_vol");
        assert_eq!(p, Path::new("/dev/mapper/my_vol"));
    }

    // ── volume_status ───────────────────────────────────────────────

    #[test]
    fn volume_status_nonexistent() {
        let status = volume_status("nonexistent_agnosys_test").unwrap();
        assert!(!status.active);
        assert_eq!(status.name, "nonexistent_agnosys_test");
    }

    #[test]
    fn volume_status_dm_path() {
        let status = volume_status("test_vol").unwrap();
        assert_eq!(status.dm_path, Path::new("/dev/mapper/test_vol"));
    }

    // ── KeySlotStatus ───────────────────────────────────────────────

    #[test]
    fn key_slot_status_eq() {
        assert_eq!(KeySlotStatus::Active, KeySlotStatus::Active);
        assert_ne!(KeySlotStatus::Active, KeySlotStatus::Inactive);
    }

    #[test]
    fn key_slot_status_debug() {
        let dbg = format!("{:?}", KeySlotStatus::Active);
        assert!(dbg.contains("Active"));
    }

    #[test]
    fn key_slot_status_copy() {
        let a = KeySlotStatus::Active;
        let b = a;
        assert_eq!(a, b);
    }

    // ── LuksHeader ──────────────────────────────────────────────────

    #[test]
    fn luks_header_debug() {
        let h = LuksHeader {
            version: 1,
            cipher_name: "aes".into(),
            cipher_mode: "xts-plain64".into(),
            hash_spec: "sha256".into(),
            payload_offset: 4096,
            key_bytes: 64,
            uuid: "12345678-1234-1234-1234-123456789abc".into(),
            key_slots: vec![KeySlotStatus::Active, KeySlotStatus::Inactive],
        };
        let dbg = format!("{h:?}");
        assert!(dbg.contains("aes"));
        assert!(dbg.contains("sha256"));
    }

    #[test]
    fn luks_header_clone() {
        let h = LuksHeader {
            version: 2,
            cipher_name: "aes".into(),
            cipher_mode: "xts-plain64".into(),
            hash_spec: "sha512".into(),
            payload_offset: 0,
            key_bytes: 32,
            uuid: "test".into(),
            key_slots: vec![],
        };
        let h2 = h.clone();
        assert_eq!(h.version, h2.version);
        assert_eq!(h.cipher_name, h2.cipher_name);
    }

    // ── VolumeStatus ────────────────────────────────────────────────

    #[test]
    fn volume_status_debug() {
        let v = VolumeStatus {
            name: "test".into(),
            dm_path: PathBuf::from("/dev/mapper/test"),
            active: true,
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("test"));
        assert!(dbg.contains("true"));
    }

    #[test]
    fn volume_status_clone() {
        let v = VolumeStatus {
            name: "vol".into(),
            dm_path: PathBuf::from("/dev/mapper/vol"),
            active: false,
        };
        let v2 = v.clone();
        assert_eq!(v.name, v2.name);
        assert_eq!(v.active, v2.active);
    }

    // ── Header parsing with synthetic data ──────────────────────────

    #[test]
    fn parse_synthetic_luks1_header() {
        let mut header = vec![0u8; LUKS_HEADER_READ_SIZE];
        // Magic
        header[..6].copy_from_slice(&LUKS1_MAGIC);
        // Version = 1
        header[6..8].copy_from_slice(&1u16.to_be_bytes());
        // Cipher name "aes"
        header[8..11].copy_from_slice(b"aes");
        // Cipher mode "xts-plain64"
        header[40..51].copy_from_slice(b"xts-plain64");
        // Hash spec "sha256"
        header[72..78].copy_from_slice(b"sha256");
        // Payload offset = 4096
        header[104..108].copy_from_slice(&4096u32.to_be_bytes());
        // Key bytes = 64
        header[108..112].copy_from_slice(&64u32.to_be_bytes());
        // UUID
        let uuid = "12345678-1234-1234-1234-123456789abc";
        header[168..168 + uuid.len()].copy_from_slice(uuid.as_bytes());
        // Key slot 0 active (0x00AC71F3)
        header[208..212].copy_from_slice(&0x00AC71F3u32.to_be_bytes());
        // Key slot 1 inactive (0xDEAD)
        header[256..260].copy_from_slice(&0x0000DEADu32.to_be_bytes());

        // Write to temp file and parse
        let tmp = &format!("/tmp/agnosys_test_luks_header_{}", std::process::id());
        std::fs::write(tmp, &header).unwrap();
        let h = read_header(Path::new(tmp)).unwrap();
        std::fs::remove_file(tmp).unwrap();

        assert_eq!(h.version, 1);
        assert_eq!(h.cipher_name, "aes");
        assert_eq!(h.cipher_mode, "xts-plain64");
        assert_eq!(h.hash_spec, "sha256");
        assert_eq!(h.payload_offset, 4096);
        assert_eq!(h.key_bytes, 64);
        assert_eq!(h.uuid, uuid);
        assert_eq!(h.key_slots[0], KeySlotStatus::Active);
        assert_eq!(h.key_slots[1], KeySlotStatus::Inactive);
    }

    #[test]
    fn is_luks_synthetic() {
        let mut header = vec![0u8; 16];
        header[..6].copy_from_slice(&LUKS1_MAGIC);
        let tmp = &format!("/tmp/agnosys_test_luks_magic_{}", std::process::id());
        std::fs::write(tmp, &header).unwrap();
        assert!(is_luks_device(Path::new(tmp)).unwrap());
        std::fs::remove_file(tmp).unwrap();
    }

    #[test]
    fn is_luks_too_small() {
        let tmp = &format!("/tmp/agnosys_test_luks_small_{}", std::process::id());
        std::fs::write(tmp, [0x4C, 0x55]).unwrap(); // Only 2 bytes
        assert!(!is_luks_device(Path::new(tmp)).unwrap());
        std::fs::remove_file(tmp).unwrap();
    }

    #[test]
    fn read_header_truncated_with_magic() {
        let tmp = &format!("/tmp/agnosys_test_luks_trunc_{}", std::process::id());
        let mut data = vec![0u8; 100]; // < 592
        data[..6].copy_from_slice(&LUKS1_MAGIC);
        std::fs::write(tmp, &data).unwrap();
        let result = read_header(Path::new(tmp));
        assert!(result.is_err());
        std::fs::remove_file(tmp).unwrap();
    }

    #[test]
    fn parse_all_8_key_slots() {
        let mut header = vec![0u8; LUKS_HEADER_READ_SIZE];
        header[..6].copy_from_slice(&LUKS1_MAGIC);
        header[6..8].copy_from_slice(&1u16.to_be_bytes());
        header[8..11].copy_from_slice(b"aes");
        header[40..51].copy_from_slice(b"xts-plain64");
        header[72..78].copy_from_slice(b"sha256");
        header[104..108].copy_from_slice(&4096u32.to_be_bytes());
        header[108..112].copy_from_slice(&64u32.to_be_bytes());
        // Set slots 0,2,4 active, rest inactive
        for i in 0..LUKS1_NUM_KEYS {
            let offset = 208 + i * 48;
            if i % 2 == 0 {
                header[offset..offset + 4].copy_from_slice(&0x00AC71F3u32.to_be_bytes());
            } else {
                header[offset..offset + 4].copy_from_slice(&0x0000DEADu32.to_be_bytes());
            }
        }
        let tmp = &format!("/tmp/agnosys_test_luks_8slots_{}", std::process::id());
        std::fs::write(tmp, &header).unwrap();
        let h = read_header(Path::new(tmp)).unwrap();
        std::fs::remove_file(tmp).unwrap();

        assert_eq!(h.key_slots.len(), 8);
        assert_eq!(h.key_slots[0], KeySlotStatus::Active);
        assert_eq!(h.key_slots[1], KeySlotStatus::Inactive);
        assert_eq!(h.key_slots[2], KeySlotStatus::Active);
        assert_eq!(h.key_slots[3], KeySlotStatus::Inactive);
        assert_eq!(h.key_slots[4], KeySlotStatus::Active);
    }

    #[test]
    fn is_not_luks_synthetic() {
        let header = vec![0u8; 16];
        let tmp = &format!("/tmp/agnosys_test_not_luks_{}", std::process::id());
        std::fs::write(tmp, &header).unwrap();
        assert!(!is_luks_device(Path::new(tmp)).unwrap());
        std::fs::remove_file(tmp).unwrap();
    }
}
