//! dmverity — dm-verity integrity verification.
//!
//! Read-only integrity checking for block devices via the kernel's
//! dm-verity target. Parse verity superblocks, validate root hashes,
//! and inspect active verity volumes.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::dmverity;
//!
//! // Check verity status of an active volume
//! if let Ok(status) = dmverity::verity_status("system") {
//!     println!("verity: {} ({})", status.name, if status.verified { "verified" } else { "unverified" });
//! }
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;
use std::path::{Path, PathBuf};

// ── Constants ───────────────────────────────────────────────────────

/// dm-verity superblock magic: "verity\0\0"
const VERITY_MAGIC: [u8; 8] = [0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x00, 0x00];
const VERITY_MAGIC_LEN: usize = 8;
/// Superblock size to read
const VERITY_SB_READ_SIZE: usize = 512;

// ── Public types ────────────────────────────────────────────────────

/// Verity superblock information.
#[derive(Debug, Clone)]
pub struct VeritySuperblock {
    /// Format version (typically 1).
    pub version: u32,
    /// Hash algorithm name (e.g., "sha256").
    pub hash_algorithm: String,
    /// Data block size in bytes (typically 4096).
    pub data_block_size: u32,
    /// Hash block size in bytes (typically 4096).
    pub hash_block_size: u32,
    /// Number of data blocks.
    pub data_blocks: u64,
    /// Salt as hex string.
    pub salt: String,
    /// UUID of the verity volume.
    pub uuid: String,
}

/// Status of a dm-verity volume.
#[derive(Debug, Clone)]
pub struct VerityStatus {
    /// The dm name.
    pub name: String,
    /// The device path.
    pub dm_path: PathBuf,
    /// Whether the volume is active.
    pub active: bool,
    /// Whether verity verification has been confirmed.
    pub verified: bool,
    /// The dm target type (should be "verity").
    pub target_type: String,
}

/// Root hash for verity validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootHash {
    bytes: Vec<u8>,
}

impl RootHash {
    /// Create from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    /// Create from hex string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex_decode(hex)?;
        Ok(Self { bytes })
    }

    /// Get the raw bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encode as hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(self.bytes.len() * 2);
        for b in &self.bytes {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Length in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the hash is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Display for RootHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ── Superblock reading ──────────────────────────────────────────────

/// Check if a device/file has a verity superblock.
pub fn is_verity_device(path: &Path) -> Result<bool> {
    let data = read_bytes(path, VERITY_MAGIC_LEN)?;
    Ok(data.len() >= VERITY_MAGIC_LEN && data[..VERITY_MAGIC_LEN] == VERITY_MAGIC)
}

/// Read and parse a verity superblock.
pub fn read_superblock(path: &Path) -> Result<VeritySuperblock> {
    let data = read_bytes(path, VERITY_SB_READ_SIZE)?;

    if data.len() < VERITY_SB_READ_SIZE {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "device too small for verity superblock",
        )));
    }

    if data[..VERITY_MAGIC_LEN] != VERITY_MAGIC {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "not a verity device (bad magic)",
        )));
    }

    // Parse fields (little-endian for verity superblock)
    let version = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let hash_type = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let uuid_bytes = &data[16..32];
    let hash_algorithm = read_null_str(&data[32..64]);
    let data_block_size = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
    let hash_block_size = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);
    let data_blocks = u64::from_le_bytes([
        data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
    ]);

    // Salt at offset 80, up to 256 bytes, preceded by salt_size at 80
    let salt_size = (u16::from_le_bytes([data[80], data[81]]) as usize).min(256);
    let salt_start = 84; // after salt_size (2 bytes) + padding (2 bytes)
    let salt = if salt_size > 0 && salt_start + salt_size <= data.len() {
        hex_encode(&data[salt_start..salt_start + salt_size])
    } else {
        String::new()
    };

    let uuid = format_uuid(uuid_bytes);

    tracing::trace!(version, hash_type, algorithm = %hash_algorithm, "parsed verity superblock");

    Ok(VeritySuperblock {
        version,
        hash_algorithm,
        data_block_size,
        hash_block_size,
        data_blocks,
        salt,
        uuid,
    })
}

// ── Volume status ───────────────────────────────────────────────────

/// Check if a named dm-verity volume is active.
#[must_use]
pub fn volume_active(name: &str) -> bool {
    Path::new("/dev/mapper").join(name).exists()
}

/// Get the device path for a named verity volume.
#[inline]
#[must_use]
pub fn volume_path(name: &str) -> PathBuf {
    Path::new("/dev/mapper").join(name)
}

/// Query verity status by reading /sys/block/dm-*/dm/name and dm-table status.
pub fn verity_status(name: &str) -> Result<VerityStatus> {
    let dm_path = volume_path(name);
    let active = dm_path.exists();

    // Try to read target type from /sys
    let target_type = read_dm_target_type(name).unwrap_or_default();
    let verified = active && target_type == "verity";

    Ok(VerityStatus {
        name: name.to_owned(),
        dm_path,
        active,
        verified,
        target_type,
    })
}

/// Validate a root hash against an expected value.
#[must_use]
pub fn validate_root_hash(actual: &RootHash, expected: &RootHash) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    // Constant-time comparison to prevent timing attacks
    let mut diff = 0u8;
    for (a, b) in actual.bytes.iter().zip(expected.bytes.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ── Internal helpers ────────────────────────────────────────────────

fn read_bytes(path: &Path, count: usize) -> Result<Vec<u8>> {
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

fn read_null_str(data: &[u8]) -> String {
    let len = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..len]).into_owned()
}

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "hex string must have even length",
        )));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn hex_digit(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(SysError::InvalidArgument(Cow::Borrowed(
            "invalid hex digit",
        ))),
    }
}

fn format_uuid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return hex_encode(bytes);
    }
    format!(
        "{}-{}-{}-{}-{}",
        hex_encode(&bytes[0..4]),
        hex_encode(&bytes[4..6]),
        hex_encode(&bytes[6..8]),
        hex_encode(&bytes[8..10]),
        hex_encode(&bytes[10..16]),
    )
}

fn read_dm_target_type(name: &str) -> Option<String> {
    // Walk /sys/block/dm-*/dm/name to find the right dm device
    let sys_block = Path::new("/sys/block");
    let entries = std::fs::read_dir(sys_block).ok()?;
    for entry in entries.flatten() {
        let entry_name = entry.file_name();
        let entry_str = entry_name.to_string_lossy();
        if !entry_str.starts_with("dm-") {
            continue;
        }
        let dm_name_path = entry.path().join("dm").join("name");
        if let Ok(dm_name) = std::fs::read_to_string(&dm_name_path)
            && dm_name.trim() == name
        {
            let target_path = entry.path().join("dm").join("target_type");
            if let Ok(tt) = std::fs::read_to_string(&target_path) {
                return Some(tt.trim().to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VeritySuperblock>();
        assert_send_sync::<VerityStatus>();
        assert_send_sync::<RootHash>();
    };

    // ── is_verity_device ────────────────────────────────────────────

    #[test]
    fn is_verity_nonexistent() {
        assert!(is_verity_device(Path::new("/dev/nonexistent_agnosys")).is_err());
    }

    #[test]
    fn is_verity_null() {
        assert!(!is_verity_device(Path::new("/dev/null")).unwrap());
    }

    // ── read_superblock ─────────────────────────────────────────────

    #[test]
    fn read_superblock_nonexistent() {
        assert!(read_superblock(Path::new("/dev/nonexistent_agnosys")).is_err());
    }

    #[test]
    fn read_superblock_not_verity() {
        assert!(read_superblock(Path::new("/dev/zero")).is_err());
    }

    // ── RootHash ────────────────────────────────────────────────────

    #[test]
    fn root_hash_from_bytes() {
        let h = RootHash::from_bytes(&[0xAB; 32]);
        assert_eq!(h.len(), 32);
        assert!(!h.is_empty());
    }

    #[test]
    fn root_hash_from_hex() {
        let h = RootHash::from_hex("abcdef01").unwrap();
        assert_eq!(h.as_bytes(), &[0xAB, 0xCD, 0xEF, 0x01]);
    }

    #[test]
    fn root_hash_from_hex_invalid() {
        assert!(RootHash::from_hex("xyz").is_err());
        assert!(RootHash::from_hex("abc").is_err()); // odd length
    }

    #[test]
    fn root_hash_to_hex() {
        let h = RootHash::from_bytes(&[0xAB, 0xCD, 0x01]);
        assert_eq!(h.to_hex(), "abcd01");
    }

    #[test]
    fn root_hash_display() {
        let h = RootHash::from_bytes(&[0xFF, 0x00]);
        assert_eq!(format!("{h}"), "ff00");
    }

    #[test]
    fn root_hash_debug() {
        let h = RootHash::from_bytes(&[1, 2]);
        let dbg = format!("{h:?}");
        assert!(dbg.contains("RootHash"));
    }

    #[test]
    fn root_hash_eq() {
        let a = RootHash::from_bytes(&[1, 2, 3]);
        let b = RootHash::from_bytes(&[1, 2, 3]);
        let c = RootHash::from_bytes(&[4, 5, 6]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn root_hash_clone() {
        let a = RootHash::from_bytes(&[1, 2, 3]);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn root_hash_empty() {
        let h = RootHash::from_bytes(&[]);
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
    }

    // ── validate_root_hash ──────────────────────────────────────────

    #[test]
    fn validate_root_hash_match() {
        let a = RootHash::from_bytes(&[1, 2, 3, 4]);
        let b = RootHash::from_bytes(&[1, 2, 3, 4]);
        assert!(validate_root_hash(&a, &b));
    }

    #[test]
    fn validate_root_hash_mismatch() {
        let a = RootHash::from_bytes(&[1, 2, 3, 4]);
        let b = RootHash::from_bytes(&[1, 2, 3, 5]);
        assert!(!validate_root_hash(&a, &b));
    }

    #[test]
    fn validate_root_hash_different_lengths() {
        let a = RootHash::from_bytes(&[1, 2, 3]);
        let b = RootHash::from_bytes(&[1, 2, 3, 4]);
        assert!(!validate_root_hash(&a, &b));
    }

    // ── volume helpers ──────────────────────────────────────────────

    #[test]
    fn volume_active_nonexistent() {
        assert!(!volume_active("nonexistent_agnosys_verity"));
    }

    #[test]
    fn volume_path_correct() {
        assert_eq!(volume_path("system"), Path::new("/dev/mapper/system"));
    }

    #[test]
    fn verity_status_nonexistent() {
        let s = verity_status("nonexistent_agnosys_verity").unwrap();
        assert!(!s.active);
        assert!(!s.verified);
    }

    #[test]
    fn verity_status_debug() {
        let s = VerityStatus {
            name: "test".into(),
            dm_path: PathBuf::from("/dev/mapper/test"),
            active: false,
            verified: false,
            target_type: String::new(),
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("test"));
    }

    #[test]
    fn verity_status_clone() {
        let s = VerityStatus {
            name: "vol".into(),
            dm_path: PathBuf::from("/dev/mapper/vol"),
            active: true,
            verified: true,
            target_type: "verity".into(),
        };
        let s2 = s.clone();
        assert_eq!(s.name, s2.name);
        assert_eq!(s.verified, s2.verified);
    }

    // ── hex helpers ─────────────────────────────────────────────────

    #[test]
    fn hex_round_trip() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = hex_encode(&data);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_decode_uppercase() {
        let decoded = hex_decode("DEADBEEF").unwrap();
        assert_eq!(decoded, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    // ── format_uuid ─────────────────────────────────────────────────

    #[test]
    fn format_uuid_16_bytes() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let uuid = format_uuid(&bytes);
        assert_eq!(uuid, "01020304-0506-0708-090a-0b0c0d0e0f10");
    }

    #[test]
    fn format_uuid_short() {
        let bytes = [0x01, 0x02];
        let uuid = format_uuid(&bytes);
        assert_eq!(uuid, "0102"); // falls back to hex
    }

    // ── Superblock parsing with synthetic data ──────────────────────

    #[test]
    fn parse_synthetic_verity_superblock() {
        let mut sb = vec![0u8; VERITY_SB_READ_SIZE];
        sb[..8].copy_from_slice(&VERITY_MAGIC);
        sb[8..12].copy_from_slice(&1u32.to_le_bytes()); // version=1
        sb[12..16].copy_from_slice(&1u32.to_le_bytes()); // hash_type=1
        // UUID at 16..32
        sb[16..32].copy_from_slice(&[0x01; 16]);
        // hash algo at 32..64
        sb[32..38].copy_from_slice(b"sha256");
        // data_block_size at 64..68
        sb[64..68].copy_from_slice(&4096u32.to_le_bytes());
        // hash_block_size at 68..72
        sb[68..72].copy_from_slice(&4096u32.to_le_bytes());
        // data_blocks at 72..80
        sb[72..80].copy_from_slice(&1000u64.to_le_bytes());

        let tmp = &format!("/tmp/agnosys_test_verity_sb_{}", std::process::id());
        std::fs::write(tmp, &sb).unwrap();
        let parsed = read_superblock(Path::new(tmp)).unwrap();
        std::fs::remove_file(tmp).unwrap();

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.hash_algorithm, "sha256");
        assert_eq!(parsed.data_block_size, 4096);
        assert_eq!(parsed.hash_block_size, 4096);
        assert_eq!(parsed.data_blocks, 1000);
    }

    #[test]
    fn read_superblock_truncated_with_magic() {
        let tmp = &format!("/tmp/agnosys_test_verity_trunc_{}", std::process::id());
        let mut data = vec![0u8; 100]; // < 512
        data[..8].copy_from_slice(&VERITY_MAGIC);
        std::fs::write(tmp, &data).unwrap();
        let result = read_superblock(Path::new(tmp));
        assert!(result.is_err());
        std::fs::remove_file(tmp).unwrap();
    }

    #[test]
    fn verity_superblock_debug() {
        let sb = VeritySuperblock {
            version: 1,
            hash_algorithm: "sha256".into(),
            data_block_size: 4096,
            hash_block_size: 4096,
            data_blocks: 1000,
            salt: "abcd".into(),
            uuid: "test-uuid".into(),
        };
        let dbg = format!("{sb:?}");
        assert!(dbg.contains("sha256"));
        assert!(dbg.contains("4096"));
    }

    #[test]
    fn verity_superblock_clone() {
        let sb = VeritySuperblock {
            version: 1,
            hash_algorithm: "sha256".into(),
            data_block_size: 4096,
            hash_block_size: 4096,
            data_blocks: 500,
            salt: String::new(),
            uuid: String::new(),
        };
        let sb2 = sb.clone();
        assert_eq!(sb.version, sb2.version);
        assert_eq!(sb.data_blocks, sb2.data_blocks);
    }

    #[test]
    fn validate_root_hash_both_empty() {
        let a = RootHash::from_bytes(&[]);
        let b = RootHash::from_bytes(&[]);
        assert!(validate_root_hash(&a, &b));
    }

    #[test]
    fn root_hash_hex_round_trip() {
        let h = RootHash::from_hex("deadbeef01234567").unwrap();
        let hex = h.to_hex();
        let h2 = RootHash::from_hex(&hex).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn is_verity_synthetic() {
        let mut data = vec![0u8; 16];
        data[..8].copy_from_slice(&VERITY_MAGIC);
        let tmp = &format!("/tmp/agnosys_test_verity_magic_{}", std::process::id());
        std::fs::write(tmp, &data).unwrap();
        assert!(is_verity_device(Path::new(tmp)).unwrap());
        std::fs::remove_file(tmp).unwrap();
    }
}
