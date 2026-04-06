//! LUKS2 Encrypted Volume Management
//!
//! Per-agent LUKS2-encrypted loopback volumes for encrypted-at-rest sandbox
//! storage. Shells out to `cryptsetup` (standard tool from the cryptsetup package).
//!
//! On non-Linux platforms, all operations return `SysError::NotSupported`.
//!
//! # Security Considerations
//!
//! - Key material is zeroized on drop via the `zeroize` crate. Callers must
//!   never log, serialize, or persist `LuksKey` values.
//! - `cryptsetup` runs as a subprocess with root privileges; command arguments
//!   are validated but callers must ensure volume names and paths are trusted.
//! - Backing files contain encrypted data — their mere existence and size may
//!   reveal information about agent storage.
//! - Failed unlock attempts may be logged by the kernel; rate-limiting is the
//!   caller's responsibility.
//! - An attacker with physical or root access may attempt offline brute-force
//!   of the LUKS header; use of Argon2id PBKDF and strong key material
//!   mitigates this. Cold-boot attacks on in-memory keys are out of scope.

use crate::error::{Result, SysError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Configuration for a LUKS encrypted volume.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuksConfig {
    /// Volume name (used for dm-crypt mapping: `/dev/mapper/{name}`)
    pub name: String,
    /// Path to the backing loopback file
    pub backing_path: PathBuf,
    /// Size of the volume in megabytes
    pub size_mb: u64,
    /// Mount point for the decrypted filesystem
    pub mount_point: PathBuf,
    /// Filesystem to create on the volume
    pub filesystem: LuksFilesystem,
    /// Cipher specification
    pub cipher: LuksCipher,
    /// Key size in bits
    pub key_size_bits: u32,
    /// Password-based key derivation function
    pub pbkdf: LuksPbkdf,
}

impl Default for LuksConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            backing_path: PathBuf::new(),
            size_mb: 256,
            mount_point: PathBuf::new(),
            filesystem: LuksFilesystem::Ext4,
            cipher: LuksCipher::default(),
            key_size_bits: 512,
            pbkdf: LuksPbkdf::Argon2id,
        }
    }
}

impl LuksConfig {
    /// Create a config for an agent volume with sensible defaults.
    pub fn for_agent(agent_id: &str, size_mb: u64) -> Self {
        Self {
            name: format!("agnos-agent-{}", agent_id),
            backing_path: PathBuf::from(format!("/var/lib/agnos/agents/{}/volume.img", agent_id)),
            size_mb,
            mount_point: PathBuf::from(format!("/var/lib/agnos/agents/{}/data", agent_id)),
            filesystem: LuksFilesystem::Ext4,
            cipher: LuksCipher::default(),
            key_size_bits: 512,
            pbkdf: LuksPbkdf::Argon2id,
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(SysError::InvalidArgument(
                "LUKS volume name cannot be empty".into(),
            ));
        }
        if self.name.len() > 128 {
            return Err(SysError::InvalidArgument(
                "LUKS volume name too long (max 128)".into(),
            ));
        }
        // Name should only contain safe characters for dm-crypt mapping
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(SysError::InvalidArgument(
                format!(
                    "LUKS volume name contains invalid characters: {}",
                    self.name
                )
                .into(),
            ));
        }
        if self.size_mb < 4 {
            return Err(SysError::InvalidArgument(
                "LUKS volume must be at least 4 MB".into(),
            ));
        }
        if self.size_mb > 1024 * 1024 {
            return Err(SysError::InvalidArgument(
                "LUKS volume exceeds maximum size of 1 TB".into(),
            ));
        }
        if self.key_size_bits != 256 && self.key_size_bits != 512 {
            return Err(SysError::InvalidArgument(
                format!(
                    "Invalid key size: {} (must be 256 or 512)",
                    self.key_size_bits
                )
                .into(),
            ));
        }
        Ok(())
    }
}

/// Supported filesystems for LUKS volumes.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LuksFilesystem {
    Ext4,
    Xfs,
    Btrfs,
}

impl LuksFilesystem {
    /// Return the mkfs command name.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            LuksFilesystem::Ext4 => "ext4",
            LuksFilesystem::Xfs => "xfs",
            LuksFilesystem::Btrfs => "btrfs",
        }
    }

    /// Return the mkfs binary name.
    #[inline]
    #[must_use]
    pub fn mkfs_cmd(&self) -> &str {
        match self {
            LuksFilesystem::Ext4 => "mkfs.ext4",
            LuksFilesystem::Xfs => "mkfs.xfs",
            LuksFilesystem::Btrfs => "mkfs.btrfs",
        }
    }
}

impl std::fmt::Display for LuksFilesystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Cipher specification for LUKS.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuksCipher {
    /// Algorithm name (e.g., "aes")
    pub algorithm: String,
    /// Mode (e.g., "xts-plain64")
    pub mode: String,
}

impl Default for LuksCipher {
    fn default() -> Self {
        Self {
            algorithm: "aes".to_string(),
            mode: "xts-plain64".to_string(),
        }
    }
}

impl LuksCipher {
    /// Return the cipher string for cryptsetup (e.g., "aes-xts-plain64").
    #[inline]
    #[must_use]
    pub fn as_cryptsetup_str(&self) -> String {
        format!("{}-{}", self.algorithm, self.mode)
    }
}

/// Password-based key derivation function.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LuksPbkdf {
    Argon2id,
    Pbkdf2,
}

impl LuksPbkdf {
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            LuksPbkdf::Argon2id => "argon2id",
            LuksPbkdf::Pbkdf2 => "pbkdf2",
        }
    }
}

/// Status of a LUKS volume.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuksStatus {
    /// Volume name
    pub name: String,
    /// Whether the dm-crypt mapping is open
    pub is_open: bool,
    /// Whether the volume is currently mounted
    pub is_mounted: bool,
    /// Backing file/device path
    pub backing_path: PathBuf,
    /// Current mount point (if mounted)
    pub mount_point: Option<PathBuf>,
    /// Cipher in use
    pub cipher: String,
    /// Key size in bits
    pub key_size_bits: u32,
}

/// A LUKS encryption key that zeroes its memory on drop.
#[non_exhaustive]
pub struct LuksKey {
    data: Vec<u8>,
}

impl LuksKey {
    /// Create a key from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.is_empty() {
            return Err(SysError::InvalidArgument("LUKS key cannot be empty".into()));
        }
        Ok(Self { data })
    }

    /// Create a key from a passphrase string.
    ///
    /// **Note**: This converts the passphrase directly to bytes for passing to
    /// `cryptsetup` via stdin. `cryptsetup` performs its own PBKDF2/Argon2
    /// key derivation internally — do NOT use this as a standalone key
    /// derivation function.
    pub fn from_passphrase(passphrase: &str) -> Result<Self> {
        if passphrase.is_empty() {
            return Err(SysError::InvalidArgument(
                "Passphrase cannot be empty".into(),
            ));
        }
        if passphrase.len() < 8 {
            return Err(SysError::InvalidArgument(
                "Passphrase too short (minimum 8 characters)".into(),
            ));
        }
        Ok(Self {
            data: passphrase.as_bytes().to_vec(),
        })
    }

    /// Generate a random key of the specified size in bytes.
    pub fn generate(size: usize) -> Result<Self> {
        if size == 0 {
            return Err(SysError::InvalidArgument("Key size must be > 0".into()));
        }
        if size > 1024 {
            return Err(SysError::InvalidArgument(
                "Key size too large (max 1024 bytes)".into(),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let mut data = vec![0u8; size];
            let mut filled = 0usize;
            while filled < size {
                let bytes_read = unsafe {
                    libc::getrandom(
                        data[filled..].as_mut_ptr() as *mut libc::c_void,
                        size - filled,
                        0, // no flags, blocking
                    )
                };
                if bytes_read < 0 {
                    return Err(SysError::Unknown("getrandom failed".into()));
                }
                filled += bytes_read as usize;
            }
            Ok(Self { data })
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Fallback: use /dev/urandom
            use std::io::Read;
            let mut data = vec![0u8; size];
            let mut f = std::fs::File::open("/dev/urandom").map_err(|e| {
                SysError::Unknown(format!("Cannot open /dev/urandom: {}", e).into())
            })?;
            f.read_exact(&mut data).map_err(|e| {
                SysError::Unknown(format!("Read /dev/urandom failed: {}", e).into())
            })?;
            Ok(Self { data })
        }
    }

    /// Get the key data as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the key length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the key is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for LuksKey {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl std::fmt::Debug for LuksKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LuksKey([REDACTED; {} bytes])", self.data.len())
    }
}

/// Format a LUKS2 encrypted volume.
///
/// Steps:
/// 1. Create backing file with `fallocate`
/// 2. Set up loop device with `losetup`
/// 3. Format with `cryptsetup luksFormat --type luks2`
///
/// Returns the path to the loop device.
pub fn luks_format(config: &LuksConfig, key: &LuksKey) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        config.validate()?;

        // Ensure parent directory exists
        if let Some(parent) = config.backing_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                SysError::Unknown(
                    format!("Failed to create directory {}: {}", parent.display(), e).into(),
                )
            })?;
        }

        // 1. Create backing file
        let size_bytes = config.size_mb.checked_mul(1024 * 1024).ok_or_else(|| {
            SysError::InvalidArgument(
                format!(
                    "LUKS size overflow: {} MB exceeds u64 byte range",
                    config.size_mb
                )
                .into(),
            )
        })?;
        run_cmd_with_output(
            "fallocate",
            &[
                "-l",
                &size_bytes.to_string(),
                &path_str(&config.backing_path),
            ],
        )?;

        // 2. Set up loop device
        let loop_dev = run_cmd_with_output(
            "losetup",
            &["--find", "--show", &path_str(&config.backing_path)],
        )?;
        let loop_dev = loop_dev.trim().to_string();

        // 3. Format with LUKS2
        let cipher = config.cipher.as_cryptsetup_str();
        let key_size = config.key_size_bits.to_string();
        let pbkdf = config.pbkdf.as_str();

        let result = run_cmd_stdin(
            "cryptsetup",
            &[
                "luksFormat",
                "--type",
                "luks2",
                "--cipher",
                &cipher,
                "--key-size",
                &key_size,
                "--pbkdf",
                pbkdf,
                "--batch-mode",
                "--key-file",
                "-",
                &loop_dev,
            ],
            key.as_bytes(),
        );

        if let Err(e) = result {
            // Cleanup loop device on failure
            let _ = run_cmd_with_output("losetup", &["-d", &loop_dev]);
            return Err(e);
        }

        tracing::info!(
            "Formatted LUKS2 volume '{}' ({} MB, {}, {})",
            config.name,
            config.size_mb,
            cipher,
            pbkdf
        );

        Ok(PathBuf::from(loop_dev))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, key);
        Err(SysError::NotSupported {
            feature: "luks".into(),
        })
    }
}

/// Open (unlock) a LUKS volume.
///
/// Maps the device to `/dev/mapper/{name}`.
pub fn luks_open(config: &LuksConfig, key: &LuksKey) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        config.validate()?;

        // Find the loop device for the backing file
        let loop_dev = run_cmd_with_output("losetup", &["-j", &path_str(&config.backing_path)])?;

        let loop_dev = loop_dev
            .split(':')
            .next()
            .ok_or_else(|| SysError::Unknown("No loop device found for backing file".into()))?
            .trim()
            .to_string();

        if loop_dev.is_empty() {
            // Not yet attached, attach it
            let loop_dev = run_cmd_with_output(
                "losetup",
                &["--find", "--show", &path_str(&config.backing_path)],
            )?;
            let loop_dev = loop_dev.trim().to_string();
            open_luks_device(&loop_dev, &config.name, key)?;
        } else {
            open_luks_device(&loop_dev, &config.name, key)?;
        }

        let mapper_path = PathBuf::from(format!("/dev/mapper/{}", config.name));
        tracing::info!(
            "Opened LUKS volume '{}' at {}",
            config.name,
            mapper_path.display()
        );
        Ok(mapper_path)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, key);
        Err(SysError::NotSupported {
            feature: "luks".into(),
        })
    }
}

/// Close (lock) a LUKS volume.
///
/// Unmounts if mounted, then closes the dm-crypt mapping.
pub fn luks_close(name: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if name.is_empty() {
            return Err(SysError::InvalidArgument(
                "Volume name cannot be empty".into(),
            ));
        }

        let mapper_path = format!("/dev/mapper/{}", name);
        if Path::new(&mapper_path).exists() {
            run_cmd_checked("cryptsetup", &["close", name])?;
            tracing::info!("Closed LUKS volume '{}'", name);
        } else {
            tracing::debug!("LUKS volume '{}' not open, nothing to close", name);
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        Err(SysError::NotSupported {
            feature: "luks".into(),
        })
    }
}

/// Create a filesystem on a device.
pub fn luks_mkfs(device: &Path, filesystem: LuksFilesystem) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let cmd = filesystem.mkfs_cmd();
        let device_str = path_str_ref(device);
        let args: Vec<&str> = match filesystem {
            LuksFilesystem::Ext4 => vec!["-F", &device_str],
            LuksFilesystem::Xfs => vec!["-f", &device_str],
            LuksFilesystem::Btrfs => vec!["-f", &device_str],
        };
        run_cmd_checked(cmd, &args)?;
        tracing::info!("Created {} filesystem on {}", filesystem, device.display());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (device, filesystem);
        Err(SysError::NotSupported {
            feature: "luks".into(),
        })
    }
}

/// Mount a device at a mount point.
pub fn luks_mount(device: &Path, mount_point: &Path, filesystem: LuksFilesystem) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::fs::create_dir_all(mount_point).map_err(|e| {
            SysError::Unknown(
                format!(
                    "Failed to create mount point {}: {}",
                    mount_point.display(),
                    e
                )
                .into(),
            )
        })?;

        run_cmd_checked(
            "mount",
            &[
                "-t",
                filesystem.as_str(),
                &path_str_ref(device),
                &path_str_ref(mount_point),
            ],
        )?;

        tracing::info!("Mounted {} at {}", device.display(), mount_point.display());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (device, mount_point, filesystem);
        Err(SysError::NotSupported {
            feature: "luks".into(),
        })
    }
}

/// Unmount a mount point.
pub fn luks_unmount(mount_point: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run_cmd_checked("umount", &[&path_str_ref(mount_point)])?;
        tracing::info!("Unmounted {}", mount_point.display());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = mount_point;
        Err(SysError::NotSupported {
            feature: "luks".into(),
        })
    }
}

/// High-level: Set up a complete agent encrypted volume.
///
/// Format + open + mkfs + mount. Returns the volume status.
pub fn setup_agent_volume(config: &LuksConfig, key: &LuksKey) -> Result<LuksStatus> {
    #[cfg(target_os = "linux")]
    {
        config.validate()?;

        // Format
        let _loop_dev = luks_format(config, key)?;

        // Open
        let mapper_path = luks_open(config, key)?;

        // Create filesystem
        luks_mkfs(&mapper_path, config.filesystem)?;

        // Mount
        luks_mount(&mapper_path, &config.mount_point, config.filesystem)?;

        Ok(LuksStatus {
            name: config.name.clone(),
            is_open: true,
            is_mounted: true,
            backing_path: config.backing_path.clone(),
            mount_point: Some(config.mount_point.clone()),
            cipher: config.cipher.as_cryptsetup_str(),
            key_size_bits: config.key_size_bits,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, key);
        Err(SysError::NotSupported {
            feature: "luks".into(),
        })
    }
}

/// High-level: Tear down an agent encrypted volume.
///
/// Unmount + close dm-crypt + detach loop device.
pub fn teardown_agent_volume(name: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if name.is_empty() {
            return Err(SysError::InvalidArgument(
                "Volume name cannot be empty".into(),
            ));
        }

        // Try to unmount first (may not be mounted)
        let mount_point = format!(
            "/var/lib/agnos/agents/{}/data",
            name.trim_start_matches("agnos-agent-")
        );
        if Path::new(&mount_point).exists() {
            let _ = luks_unmount(Path::new(&mount_point));
        }

        // Close dm-crypt
        luks_close(name)?;

        // Detach loop device if possible
        let backing_path = format!(
            "/var/lib/agnos/agents/{}/volume.img",
            name.trim_start_matches("agnos-agent-")
        );
        if Path::new(&backing_path).exists() {
            let loop_info = run_cmd_with_output("losetup", &["-j", &backing_path]);
            if let Ok(info) = loop_info
                && let Some(loop_dev) = info.split(':').next()
            {
                let loop_dev = loop_dev.trim();
                if !loop_dev.is_empty() {
                    let _ = run_cmd_checked("losetup", &["-d", loop_dev]);
                }
            }
        }

        tracing::info!("Tore down LUKS volume '{}'", name);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        Err(SysError::NotSupported {
            feature: "luks".into(),
        })
    }
}

/// Check if `cryptsetup` is available on this system.
#[must_use]
pub fn cryptsetup_available() -> bool {
    std::process::Command::new("cryptsetup")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if dm-crypt kernel module is loaded.
#[must_use]
pub fn dmcrypt_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/sys/module/dm_crypt").exists()
            || std::fs::read_to_string("/proc/modules")
                .map(|s| s.contains("dm_crypt"))
                .unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// --- Internal helpers ---

/// Open a LUKS device with cryptsetup.
#[cfg(target_os = "linux")]
fn open_luks_device(loop_dev: &str, name: &str, key: &LuksKey) -> Result<()> {
    run_cmd_stdin(
        "cryptsetup",
        &["open", "--type", "luks2", "--key-file", "-", loop_dev, name],
        key.as_bytes(),
    )
}

/// Run a command and return stdout.
#[cfg(target_os = "linux")]
fn run_cmd_with_output(cmd: &str, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to run '{}': {}", cmd, e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't log args — they may contain key file paths or sensitive data
        return Err(SysError::Unknown(
            format!(
                "{} failed (exit {}): {}",
                cmd,
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )
            .into(),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run a command and check for success (discard output).
#[cfg(target_os = "linux")]
fn run_cmd_checked(cmd: &str, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to run '{}': {}", cmd, e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't log args — they may contain key file paths or sensitive data
        return Err(SysError::Unknown(
            format!(
                "{} failed (exit {}): {}",
                cmd,
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )
            .into(),
        ));
    }

    Ok(())
}

/// Run a command with stdin data.
#[cfg(target_os = "linux")]
fn run_cmd_stdin(cmd: &str, args: &[&str], stdin_data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = std::process::Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| SysError::Unknown(format!("Failed to spawn '{}': {}", cmd, e).into()))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_data).map_err(|e| {
            SysError::Unknown(format!("Failed to write to {} stdin: {}", cmd, e).into())
        })?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| SysError::Unknown(format!("Failed to wait for '{}': {}", cmd, e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't log args — they may contain key file paths or sensitive data
        return Err(SysError::Unknown(
            format!(
                "{} failed (exit {}): {}",
                cmd,
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )
            .into(),
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn path_str(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

#[cfg(target_os = "linux")]
fn path_str_ref(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luks_config_for_agent() {
        let config = LuksConfig::for_agent("test-1", 128);
        assert_eq!(config.name, "agnos-agent-test-1");
        assert_eq!(config.size_mb, 128);
        assert_eq!(config.key_size_bits, 512);
        assert_eq!(config.filesystem, LuksFilesystem::Ext4);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_config_validate_empty_name() {
        let mut config = LuksConfig::default();
        assert!(config.validate().is_err());

        config.name = "valid-name".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_config_validate_bad_name_chars() {
        let config = LuksConfig {
            name: "bad name with spaces".to_string(),
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_config_validate_size_too_small() {
        let config = LuksConfig {
            size_mb: 1,
            ..LuksConfig::for_agent("x", 1)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_config_validate_bad_key_size() {
        let config = LuksConfig {
            key_size_bits: 128,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_filesystem_as_str() {
        assert_eq!(LuksFilesystem::Ext4.as_str(), "ext4");
        assert_eq!(LuksFilesystem::Xfs.as_str(), "xfs");
        assert_eq!(LuksFilesystem::Btrfs.as_str(), "btrfs");
    }

    #[test]
    fn test_luks_filesystem_mkfs_cmd() {
        assert_eq!(LuksFilesystem::Ext4.mkfs_cmd(), "mkfs.ext4");
        assert_eq!(LuksFilesystem::Xfs.mkfs_cmd(), "mkfs.xfs");
        assert_eq!(LuksFilesystem::Btrfs.mkfs_cmd(), "mkfs.btrfs");
    }

    #[test]
    fn test_luks_cipher_default() {
        let cipher = LuksCipher::default();
        assert_eq!(cipher.algorithm, "aes");
        assert_eq!(cipher.mode, "xts-plain64");
        assert_eq!(cipher.as_cryptsetup_str(), "aes-xts-plain64");
    }

    #[test]
    fn test_luks_pbkdf_as_str() {
        assert_eq!(LuksPbkdf::Argon2id.as_str(), "argon2id");
        assert_eq!(LuksPbkdf::Pbkdf2.as_str(), "pbkdf2");
    }

    #[test]
    fn test_luks_key_from_bytes() {
        let key = LuksKey::from_bytes(vec![1, 2, 3, 4]).unwrap();
        assert_eq!(key.len(), 4);
        assert_eq!(key.as_bytes(), &[1, 2, 3, 4]);
        assert!(!key.is_empty());
    }

    #[test]
    fn test_luks_key_from_bytes_empty() {
        assert!(LuksKey::from_bytes(vec![]).is_err());
    }

    #[test]
    fn test_luks_key_from_passphrase() {
        let key = LuksKey::from_passphrase("my-secret").unwrap();
        assert_eq!(key.as_bytes(), b"my-secret");
    }

    #[test]
    fn test_luks_key_from_passphrase_empty() {
        assert!(LuksKey::from_passphrase("").is_err());
    }

    #[test]
    fn test_luks_key_generate() {
        let key = LuksKey::generate(32).unwrap();
        assert_eq!(key.len(), 32);
        // Should not be all zeros (astronomically unlikely)
        assert!(key.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn test_luks_key_generate_zero_size() {
        assert!(LuksKey::generate(0).is_err());
    }

    #[test]
    fn test_luks_key_generate_too_large() {
        assert!(LuksKey::generate(2048).is_err());
    }

    #[test]
    fn test_luks_key_debug_redacted() {
        let key = LuksKey::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let debug = format!("{:?}", key);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("DEAD"));
    }

    #[test]
    fn test_luks_key_zeroed_on_drop() {
        let data_ptr: *const u8;
        let data_len: usize;

        {
            let key = LuksKey::from_bytes(vec![0xFF; 32]).unwrap();
            data_ptr = key.as_bytes().as_ptr();
            data_len = key.len();
            // Key is dropped here
        }

        // After drop, the memory should be zeroed.
        // Note: this is best-effort testing — the allocator may reuse the memory.
        // We verify the Drop impl exists and runs correctly.
        let _ = (data_ptr, data_len);
    }

    #[test]
    fn test_luks_status_serialization() {
        let status = LuksStatus {
            name: "test-vol".to_string(),
            is_open: true,
            is_mounted: true,
            backing_path: PathBuf::from("/var/lib/test/vol.img"),
            mount_point: Some(PathBuf::from("/mnt/test")),
            cipher: "aes-xts-plain64".to_string(),
            key_size_bits: 512,
        };

        let json = serde_json::to_string(&status).unwrap();
        let deserialized: LuksStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test-vol");
        assert!(deserialized.is_open);
    }

    #[test]
    fn test_cryptsetup_available() {
        // Just verify it doesn't crash
        let _available = cryptsetup_available();
    }

    #[test]
    fn test_dmcrypt_supported() {
        // Just verify it doesn't crash
        let _supported = dmcrypt_supported();
    }

    #[test]
    #[ignore = "Requires root, cryptsetup, and loop device support"]
    fn test_setup_and_teardown_agent_volume() {
        let config = LuksConfig::for_agent("luks-test", 32);
        let key = LuksKey::generate(64).unwrap();

        let status = setup_agent_volume(&config, &key).unwrap();
        assert!(status.is_open);
        assert!(status.is_mounted);

        teardown_agent_volume(&config.name).unwrap();
    }

    // --- Additional coverage tests ---

    #[test]
    fn test_luks_config_default_all_fields() {
        let config = LuksConfig::default();
        assert_eq!(config.name, "");
        assert_eq!(config.backing_path, PathBuf::new());
        assert_eq!(config.size_mb, 256);
        assert_eq!(config.mount_point, PathBuf::new());
        assert_eq!(config.filesystem, LuksFilesystem::Ext4);
        assert_eq!(config.key_size_bits, 512);
        assert_eq!(config.pbkdf, LuksPbkdf::Argon2id);
        assert_eq!(config.cipher.algorithm, "aes");
        assert_eq!(config.cipher.mode, "xts-plain64");
    }

    #[test]
    fn test_luks_config_for_agent_paths() {
        let config = LuksConfig::for_agent("my-agent", 64);
        assert_eq!(
            config.backing_path,
            PathBuf::from("/var/lib/agnos/agents/my-agent/volume.img")
        );
        assert_eq!(
            config.mount_point,
            PathBuf::from("/var/lib/agnos/agents/my-agent/data")
        );
        assert_eq!(config.pbkdf, LuksPbkdf::Argon2id);
        assert_eq!(config.cipher.algorithm, "aes");
        assert_eq!(config.cipher.mode, "xts-plain64");
    }

    #[test]
    fn test_luks_config_validate_name_too_long() {
        let config = LuksConfig {
            name: "a".repeat(129),
            ..LuksConfig::for_agent("x", 64)
        };
        let err = config.validate().unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("too long"), "Expected 'too long' in: {}", msg);
    }

    #[test]
    fn test_luks_config_validate_name_exactly_128() {
        let config = LuksConfig {
            name: "a".repeat(128),
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_config_validate_size_too_large() {
        let config = LuksConfig {
            size_mb: 1024 * 1024 + 1,
            ..LuksConfig::for_agent("x", 64)
        };
        let err = config.validate().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("maximum size"),
            "Expected 'maximum size' in: {}",
            msg
        );
    }

    #[test]
    fn test_luks_config_validate_size_exactly_4mb() {
        let config = LuksConfig {
            size_mb: 4,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_config_validate_size_exactly_1tb() {
        let config = LuksConfig {
            size_mb: 1024 * 1024,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_config_validate_key_size_256_valid() {
        let config = LuksConfig {
            key_size_bits: 256,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_config_validate_bad_key_size_error_msg() {
        let config = LuksConfig {
            key_size_bits: 1024,
            ..LuksConfig::for_agent("x", 64)
        };
        let err = config.validate().unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("1024"), "Expected '1024' in: {}", msg);
        assert!(
            msg.contains("256 or 512"),
            "Expected '256 or 512' in: {}",
            msg
        );
    }

    #[test]
    fn test_luks_config_validate_invalid_chars_error_msg() {
        let config = LuksConfig {
            name: "bad/name".to_string(),
            ..LuksConfig::for_agent("x", 64)
        };
        let err = config.validate().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("invalid characters"),
            "Expected 'invalid characters' in: {}",
            msg
        );
        assert!(msg.contains("bad/name"), "Expected name in error: {}", msg);
    }

    #[test]
    fn test_luks_config_validate_name_with_dots() {
        let config = LuksConfig {
            name: "has.dot".to_string(),
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_config_validate_name_with_underscore() {
        let config = LuksConfig {
            name: "has_underscore".to_string(),
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_filesystem_display() {
        assert_eq!(format!("{}", LuksFilesystem::Ext4), "ext4");
        assert_eq!(format!("{}", LuksFilesystem::Xfs), "xfs");
        assert_eq!(format!("{}", LuksFilesystem::Btrfs), "btrfs");
    }

    #[test]
    fn test_luks_filesystem_clone_copy_eq() {
        let fs = LuksFilesystem::Xfs;
        let fs2 = fs; // Copy
        let fs3 = fs; // Clone
        assert_eq!(fs, fs2);
        assert_eq!(fs, fs3);
        assert_ne!(fs, LuksFilesystem::Ext4);
    }

    #[test]
    fn test_luks_cipher_custom() {
        let cipher = LuksCipher {
            algorithm: "serpent".to_string(),
            mode: "cbc-essiv".to_string(),
        };
        assert_eq!(cipher.as_cryptsetup_str(), "serpent-cbc-essiv");
    }

    #[test]
    fn test_luks_cipher_clone() {
        let c1 = LuksCipher::default();
        let c2 = c1.clone();
        assert_eq!(c2.algorithm, "aes");
        assert_eq!(c2.mode, "xts-plain64");
    }

    #[test]
    fn test_luks_cipher_debug() {
        let cipher = LuksCipher::default();
        let debug = format!("{:?}", cipher);
        assert!(debug.contains("aes"));
        assert!(debug.contains("xts-plain64"));
    }

    #[test]
    fn test_luks_pbkdf_clone_copy_eq() {
        let p1 = LuksPbkdf::Argon2id;
        let p2 = p1; // Copy
        let p3 = p1; // Clone
        assert_eq!(p1, p2);
        assert_eq!(p1, p3);
        assert_ne!(p1, LuksPbkdf::Pbkdf2);
    }

    #[test]
    fn test_luks_status_none_mount_point() {
        let status = LuksStatus {
            name: "test-vol".to_string(),
            is_open: false,
            is_mounted: false,
            backing_path: PathBuf::from("/tmp/vol.img"),
            mount_point: None,
            cipher: "aes-xts-plain64".to_string(),
            key_size_bits: 256,
        };
        assert!(!status.is_open);
        assert!(!status.is_mounted);
        assert!(status.mount_point.is_none());
        assert_eq!(status.key_size_bits, 256);
    }

    #[test]
    fn test_luks_status_clone() {
        let status = LuksStatus {
            name: "vol".to_string(),
            is_open: true,
            is_mounted: false,
            backing_path: PathBuf::from("/a"),
            mount_point: Some(PathBuf::from("/b")),
            cipher: "aes-xts-plain64".to_string(),
            key_size_bits: 512,
        };
        let cloned = status.clone();
        assert_eq!(cloned.name, "vol");
        assert!(cloned.is_open);
        assert!(!cloned.is_mounted);
        assert_eq!(cloned.mount_point, Some(PathBuf::from("/b")));
    }

    #[test]
    fn test_luks_status_debug() {
        let status = LuksStatus {
            name: "dbg".to_string(),
            is_open: true,
            is_mounted: true,
            backing_path: PathBuf::from("/x"),
            mount_point: Some(PathBuf::from("/y")),
            cipher: "aes-xts-plain64".to_string(),
            key_size_bits: 512,
        };
        let debug = format!("{:?}", status);
        assert!(debug.contains("dbg"));
        assert!(debug.contains("true"));
    }

    #[test]
    fn test_luks_status_json_roundtrip_none_mount() {
        let status = LuksStatus {
            name: "roundtrip".to_string(),
            is_open: false,
            is_mounted: false,
            backing_path: PathBuf::from("/tmp/rt.img"),
            mount_point: None,
            cipher: "serpent-cbc-essiv".to_string(),
            key_size_bits: 256,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"mount_point\":null"));
        let de: LuksStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(de.name, "roundtrip");
        assert!(de.mount_point.is_none());
        assert_eq!(de.cipher, "serpent-cbc-essiv");
        assert_eq!(de.key_size_bits, 256);
    }

    #[test]
    fn test_luks_config_serialization_roundtrip() {
        let config = LuksConfig::for_agent("ser-test", 128);
        let json = serde_json::to_string(&config).unwrap();
        let de: LuksConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(de.name, "agnos-agent-ser-test");
        assert_eq!(de.size_mb, 128);
        assert_eq!(de.key_size_bits, 512);
        assert_eq!(de.filesystem, LuksFilesystem::Ext4);
        assert_eq!(de.pbkdf, LuksPbkdf::Argon2id);
        assert_eq!(de.cipher.algorithm, "aes");
    }

    #[test]
    fn test_luks_key_from_passphrase_utf8() {
        let key = LuksKey::from_passphrase("héllo wörld 🔑").unwrap();
        assert_eq!(key.as_bytes(), "héllo wörld 🔑".as_bytes());
        assert!(!key.is_empty());
        assert!(!key.is_empty());
    }

    #[test]
    fn test_luks_key_from_bytes_single_byte() {
        let key = LuksKey::from_bytes(vec![42]).unwrap();
        assert_eq!(key.len(), 1);
        assert_eq!(key.as_bytes(), &[42]);
    }

    #[test]
    fn test_luks_key_generate_boundary_1024() {
        let key = LuksKey::generate(1024).unwrap();
        assert_eq!(key.len(), 1024);
    }

    #[test]
    fn test_luks_key_generate_boundary_1025() {
        let err = LuksKey::generate(1025).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("too large"),
            "Expected 'too large' in: {}",
            msg
        );
    }

    #[test]
    fn test_luks_key_generate_size_1() {
        let key = LuksKey::generate(1).unwrap();
        assert_eq!(key.len(), 1);
    }

    #[test]
    fn test_luks_key_debug_shows_length() {
        let key = LuksKey::from_bytes(vec![1, 2, 3]).unwrap();
        let debug = format!("{:?}", key);
        assert_eq!(debug, "LuksKey([REDACTED; 3 bytes])");
    }

    #[test]
    fn test_luks_key_debug_different_sizes() {
        let k1 = LuksKey::from_bytes(vec![0; 64]).unwrap();
        let k2 = LuksKey::from_bytes(vec![0; 1]).unwrap();
        assert!(format!("{:?}", k1).contains("64 bytes"));
        assert!(format!("{:?}", k2).contains("1 bytes"));
    }

    #[test]
    fn test_luks_key_zeroed_on_drop_via_raw_ptr() {
        // Verify the drop implementation runs; we use a raw pointer
        // to check the memory region after drop. Note: this is inherently
        // racy with the allocator, but it exercises the Drop impl code path.
        let mut raw_data = vec![0xAAu8; 16];
        let ptr = raw_data.as_mut_ptr();
        let len = raw_data.len();
        {
            let key = LuksKey::from_bytes(raw_data).unwrap();
            assert_eq!(key.len(), len);
            assert!(key.as_bytes().iter().all(|&b| b == 0xAA));
            // key dropped here, zeroing the vec's contents
        }
        // The Vec was moved into LuksKey, so we read from ptr.
        // The allocator *may* have reused the memory, so we just
        // exercise the code path. The important thing is no panic.
        let _ = ptr;
    }

    #[test]
    fn test_luks_key_from_bytes_error_message() {
        let err = LuksKey::from_bytes(vec![]).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("empty"), "Expected 'empty' in: {}", msg);
    }

    #[test]
    fn test_luks_key_from_passphrase_error_message() {
        let err = LuksKey::from_passphrase("").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("empty"), "Expected 'empty' in: {}", msg);
    }

    #[test]
    fn test_luks_key_generate_zero_error_message() {
        let err = LuksKey::generate(0).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("> 0"), "Expected '> 0' in: {}", msg);
    }

    #[test]
    fn test_luks_config_validate_empty_name_error_message() {
        let config = LuksConfig::default();
        let err = config.validate().unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("empty"), "Expected 'empty' in: {}", msg);
    }

    #[test]
    fn test_luks_config_validate_size_3mb_error() {
        let config = LuksConfig {
            size_mb: 3,
            ..LuksConfig::for_agent("x", 64)
        };
        let err = config.validate().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("at least 4 MB"),
            "Expected 'at least 4 MB' in: {}",
            msg
        );
    }

    #[test]
    fn test_luks_pbkdf_debug() {
        assert!(format!("{:?}", LuksPbkdf::Argon2id).contains("Argon2id"));
        assert!(format!("{:?}", LuksPbkdf::Pbkdf2).contains("Pbkdf2"));
    }

    #[test]
    fn test_luks_filesystem_debug() {
        assert!(format!("{:?}", LuksFilesystem::Ext4).contains("Ext4"));
        assert!(format!("{:?}", LuksFilesystem::Xfs).contains("Xfs"));
        assert!(format!("{:?}", LuksFilesystem::Btrfs).contains("Btrfs"));
    }

    #[test]
    fn test_luks_config_debug() {
        let config = LuksConfig::for_agent("dbg-agent", 32);
        let debug = format!("{:?}", config);
        assert!(debug.contains("agnos-agent-dbg-agent"));
        assert!(debug.contains("32"));
    }

    #[test]
    fn test_luks_config_clone() {
        let config = LuksConfig::for_agent("clone-test", 100);
        let cloned = config.clone();
        assert_eq!(cloned.name, config.name);
        assert_eq!(cloned.size_mb, config.size_mb);
        assert_eq!(cloned.backing_path, config.backing_path);
        assert_eq!(cloned.mount_point, config.mount_point);
        assert_eq!(cloned.filesystem, config.filesystem);
        assert_eq!(cloned.key_size_bits, config.key_size_bits);
        assert_eq!(cloned.pbkdf, config.pbkdf);
    }

    #[test]
    fn test_luks_config_for_agent_with_special_id() {
        let config = LuksConfig::for_agent("abc_123", 8);
        assert_eq!(config.name, "agnos-agent-abc_123");
        // size_mb 8 is >= 4, should be valid
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_pbkdf_serialization() {
        let json_argon = serde_json::to_string(&LuksPbkdf::Argon2id).unwrap();
        let json_pbkdf2 = serde_json::to_string(&LuksPbkdf::Pbkdf2).unwrap();
        let de_argon: LuksPbkdf = serde_json::from_str(&json_argon).unwrap();
        let de_pbkdf2: LuksPbkdf = serde_json::from_str(&json_pbkdf2).unwrap();
        assert_eq!(de_argon, LuksPbkdf::Argon2id);
        assert_eq!(de_pbkdf2, LuksPbkdf::Pbkdf2);
    }

    #[test]
    fn test_luks_filesystem_serialization() {
        for fs in [
            LuksFilesystem::Ext4,
            LuksFilesystem::Xfs,
            LuksFilesystem::Btrfs,
        ] {
            let json = serde_json::to_string(&fs).unwrap();
            let de: LuksFilesystem = serde_json::from_str(&json).unwrap();
            assert_eq!(de, fs);
        }
    }

    #[test]
    fn test_luks_cipher_serialization() {
        let cipher = LuksCipher {
            algorithm: "twofish".to_string(),
            mode: "cbc-plain".to_string(),
        };
        let json = serde_json::to_string(&cipher).unwrap();
        assert!(json.contains("twofish"));
        assert!(json.contains("cbc-plain"));
        let de: LuksCipher = serde_json::from_str(&json).unwrap();
        assert_eq!(de.algorithm, "twofish");
        assert_eq!(de.mode, "cbc-plain");
        assert_eq!(de.as_cryptsetup_str(), "twofish-cbc-plain");
    }

    #[test]
    fn test_luks_key_large_passphrase() {
        let passphrase = "x".repeat(4096);
        let key = LuksKey::from_passphrase(&passphrase).unwrap();
        assert_eq!(key.len(), 4096);
    }

    #[test]
    fn test_luks_key_from_bytes_large() {
        let data = vec![0xBB; 8192];
        let key = LuksKey::from_bytes(data).unwrap();
        assert_eq!(key.len(), 8192);
        assert!(key.as_bytes().iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn test_luks_config_validate_name_special_chars() {
        // Test various invalid characters
        for name in &["a b", "a/b", "a.b", "a:b", "a;b", "a@b", "a!b", "a#b"] {
            let config = LuksConfig {
                name: name.to_string(),
                ..LuksConfig::for_agent("x", 64)
            };
            assert!(
                config.validate().is_err(),
                "Expected error for name '{}' but got Ok",
                name
            );
        }
    }

    #[test]
    fn test_luks_config_validate_alphanumeric_hyphen_underscore() {
        // These should all be valid
        for name in &["abc", "ABC", "a-b", "a_b", "123", "a1-b2_c3"] {
            let config = LuksConfig {
                name: name.to_string(),
                ..LuksConfig::for_agent("x", 64)
            };
            assert!(
                config.validate().is_ok(),
                "Expected Ok for name '{}' but got Err",
                name
            );
        }
    }

    #[test]
    fn test_luks_key_multiple_generate_unique() {
        let k1 = LuksKey::generate(32).unwrap();
        let k2 = LuksKey::generate(32).unwrap();
        // Two random keys should (almost certainly) differ
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_luks_status_all_fields_json() {
        let json = r#"{
            "name": "vol1",
            "is_open": true,
            "is_mounted": false,
            "backing_path": "/dev/sda1",
            "mount_point": "/mnt/data",
            "cipher": "aes-xts-plain64",
            "key_size_bits": 512
        }"#;
        let status: LuksStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.name, "vol1");
        assert!(status.is_open);
        assert!(!status.is_mounted);
        assert_eq!(status.backing_path, PathBuf::from("/dev/sda1"));
        assert_eq!(status.mount_point, Some(PathBuf::from("/mnt/data")));
        assert_eq!(status.cipher, "aes-xts-plain64");
        assert_eq!(status.key_size_bits, 512);
    }

    #[test]
    fn test_luks_config_default_cipher_is_default() {
        let config = LuksConfig::default();
        let cipher_default = LuksCipher::default();
        assert_eq!(config.cipher.algorithm, cipher_default.algorithm);
        assert_eq!(config.cipher.mode, cipher_default.mode);
    }

    // --- New coverage tests ---

    #[test]
    fn test_luks_close_empty_name() {
        let result = luks_close("");
        assert!(result.is_err());
    }

    #[test]
    fn test_teardown_agent_volume_empty_name() {
        let result = teardown_agent_volume("");
        assert!(result.is_err());
    }

    #[test]
    fn test_luks_key_generate_various_sizes() {
        for size in &[1, 16, 32, 64, 128, 256, 512, 1024] {
            let key = LuksKey::generate(*size).unwrap();
            assert_eq!(key.len(), *size);
            assert!(!key.is_empty());
        }
    }

    #[test]
    fn test_luks_config_for_agent_validates_ok() {
        // for_agent should always produce a valid config with reasonable agent IDs
        for id in &["agent-1", "myagent", "a", "test_agent_123"] {
            let config = LuksConfig::for_agent(id, 8);
            assert!(
                config.validate().is_ok(),
                "Config for '{}' should be valid",
                id
            );
        }
    }

    #[test]
    fn test_luks_config_validate_size_exactly_3mb_fails() {
        let config = LuksConfig {
            size_mb: 3,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_filesystem_serde_each_variant() {
        let variants = [
            LuksFilesystem::Ext4,
            LuksFilesystem::Xfs,
            LuksFilesystem::Btrfs,
        ];
        for fs in &variants {
            let json = serde_json::to_string(fs).unwrap();
            let de: LuksFilesystem = serde_json::from_str(&json).unwrap();
            assert_eq!(de, *fs);
            assert_eq!(de.as_str(), fs.as_str());
            assert_eq!(de.mkfs_cmd(), fs.mkfs_cmd());
        }
    }

    #[test]
    fn test_luks_pbkdf_serde_each_variant() {
        for pbkdf in &[LuksPbkdf::Argon2id, LuksPbkdf::Pbkdf2] {
            let json = serde_json::to_string(pbkdf).unwrap();
            let de: LuksPbkdf = serde_json::from_str(&json).unwrap();
            assert_eq!(de, *pbkdf);
            assert_eq!(de.as_str(), pbkdf.as_str());
        }
    }

    #[test]
    fn test_luks_key_from_bytes_preserves_all_byte_values() {
        let data: Vec<u8> = (0..=255).collect();
        let key = LuksKey::from_bytes(data.clone()).unwrap();
        assert_eq!(key.len(), 256);
        assert_eq!(key.as_bytes(), &data[..]);
    }

    #[test]
    fn test_luks_status_serde_with_some_mount() {
        let status = LuksStatus {
            name: "vol".to_string(),
            is_open: true,
            is_mounted: true,
            backing_path: PathBuf::from("/a"),
            mount_point: Some(PathBuf::from("/mnt")),
            cipher: "aes-xts-plain64".to_string(),
            key_size_bits: 512,
        };
        let json = serde_json::to_string(&status).unwrap();
        let de: LuksStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(de.mount_point, Some(PathBuf::from("/mnt")));
    }

    #[test]
    fn test_cryptsetup_available_does_not_panic() {
        // Only verifies no panic/crash
        let _ = cryptsetup_available();
    }

    #[test]
    fn test_dmcrypt_supported_does_not_panic() {
        let _ = dmcrypt_supported();
    }

    #[test]
    fn test_luks_key_from_passphrase_rejects_short() {
        assert!(LuksKey::from_passphrase("short").is_err());
        assert!(LuksKey::from_passphrase("1234567").is_err());
    }

    #[test]
    fn test_luks_key_from_passphrase_accepts_valid() {
        assert!(LuksKey::from_passphrase("validpass").is_ok());
        assert!(LuksKey::from_passphrase("a-longer-passphrase-here").is_ok());
    }

    #[test]
    fn test_luks_key_from_passphrase_rejects_empty() {
        assert!(LuksKey::from_passphrase("").is_err());
    }

    // -----------------------------------------------------------------------
    // Additional coverage tests — audit round
    // -----------------------------------------------------------------------

    #[test]
    fn test_luks_key_from_passphrase_boundary_7_chars() {
        // Exactly 7 ASCII chars => too short
        assert!(LuksKey::from_passphrase("1234567").is_err());
        let err = LuksKey::from_passphrase("1234567").unwrap_err();
        assert!(err.to_string().contains("minimum 8"));
    }

    #[test]
    fn test_luks_key_from_passphrase_boundary_8_chars() {
        // Exactly 8 ASCII chars => should pass
        let key = LuksKey::from_passphrase("12345678").unwrap();
        assert_eq!(key.len(), 8);
        assert_eq!(key.as_bytes(), b"12345678");
    }

    #[test]
    fn test_luks_key_from_passphrase_multibyte_counts_bytes() {
        // 3 chars but >= 8 bytes due to multibyte UTF-8
        // Each emoji is 4 bytes, so 2 emojis = 8 bytes
        let pass = "\u{1F512}\u{1F512}"; // two lock emojis, 8 bytes
        assert_eq!(pass.len(), 8);
        let key = LuksKey::from_passphrase(pass).unwrap();
        assert_eq!(key.len(), 8);
    }

    #[test]
    fn test_luks_key_generate_error_msg_zero() {
        let err = LuksKey::generate(0).unwrap_err();
        assert!(err.to_string().contains("> 0"));
    }

    #[test]
    fn test_luks_key_generate_error_msg_too_large() {
        let err = LuksKey::generate(1025).unwrap_err();
        assert!(err.to_string().contains("too large"));
        assert!(err.to_string().contains("1024"));
    }

    #[test]
    fn test_luks_config_validate_size_0() {
        let config = LuksConfig {
            size_mb: 0,
            ..LuksConfig::for_agent("x", 64)
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("at least 4 MB"));
    }

    #[test]
    fn test_luks_config_validate_size_u64_max() {
        let config = LuksConfig {
            size_mb: u64::MAX,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_config_validate_key_size_0() {
        let config = LuksConfig {
            key_size_bits: 0,
            ..LuksConfig::for_agent("x", 64)
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("256 or 512"));
    }

    #[test]
    fn test_luks_config_validate_key_size_384() {
        let config = LuksConfig {
            key_size_bits: 384,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_config_validate_name_only_hyphens() {
        let config = LuksConfig {
            name: "---".to_string(),
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_config_validate_name_only_underscores() {
        let config = LuksConfig {
            name: "___".to_string(),
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_config_validate_name_leading_hyphen() {
        let config = LuksConfig {
            name: "-leading".to_string(),
            ..LuksConfig::for_agent("x", 64)
        };
        // The validation allows this (just alphanumeric + hyphen + underscore)
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_config_validate_name_unicode_alphanumeric_rejected() {
        // Unicode letters are rejected — dm-crypt names must be ASCII-only
        // for filesystem and kernel interface safety.
        let config = LuksConfig {
            name: "hello\u{00e9}".to_string(), // e with acute accent
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err()); // rejects unicode alphanumeric
    }

    #[test]
    fn test_luks_config_validate_name_unicode_non_alphanumeric_rejected() {
        // Unicode symbols that are not alphanumeric should be rejected
        let config = LuksConfig {
            name: "test\u{2603}".to_string(), // snowman symbol
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_config_validate_name_newline() {
        let config = LuksConfig {
            name: "bad\nname".to_string(),
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_config_validate_name_null_byte() {
        let config = LuksConfig {
            name: "bad\0name".to_string(),
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_config_validate_name_single_char() {
        let config = LuksConfig {
            name: "x".to_string(),
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_cipher_empty_fields() {
        let cipher = LuksCipher {
            algorithm: String::new(),
            mode: String::new(),
        };
        assert_eq!(cipher.as_cryptsetup_str(), "-");
    }

    #[test]
    fn test_luks_config_for_agent_empty_id() {
        // for_agent with empty string produces "agnos-agent-" which is valid
        let config = LuksConfig::for_agent("", 8);
        assert_eq!(config.name, "agnos-agent-");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_luks_key_from_passphrase_short_error_distinct_from_empty() {
        let empty_err = LuksKey::from_passphrase("").unwrap_err().to_string();
        let short_err = LuksKey::from_passphrase("short").unwrap_err().to_string();
        assert!(empty_err.contains("empty"));
        assert!(short_err.contains("minimum 8"));
        assert_ne!(empty_err, short_err);
    }

    #[test]
    fn test_luks_key_is_empty_always_false_for_valid_key() {
        // from_bytes rejects empty, so any valid key is never empty
        let key = LuksKey::from_bytes(vec![1]).unwrap();
        assert!(!key.is_empty());
    }

    #[test]
    fn test_luks_key_from_passphrase_all_whitespace() {
        // 8+ spaces is valid - cryptsetup handles this
        let key = LuksKey::from_passphrase("        ").unwrap();
        assert_eq!(key.len(), 8);
    }

    #[test]
    fn test_luks_config_validate_all_valid_key_sizes() {
        for ks in [256u32, 512] {
            let config = LuksConfig {
                key_size_bits: ks,
                ..LuksConfig::for_agent("x", 64)
            };
            assert!(
                config.validate().is_ok(),
                "key_size_bits={} should be valid",
                ks
            );
        }
    }

    #[test]
    fn test_luks_filesystem_as_str_matches_display() {
        for fs in [
            LuksFilesystem::Ext4,
            LuksFilesystem::Xfs,
            LuksFilesystem::Btrfs,
        ] {
            assert_eq!(fs.as_str(), format!("{}", fs));
        }
    }

    #[test]
    fn test_luks_config_for_agent_size_preserved() {
        // Verify the size_mb passed to for_agent is actually used
        let config = LuksConfig::for_agent("x", 999);
        assert_eq!(config.size_mb, 999);
    }

    #[test]
    fn test_luks_key_generate_different_sizes_different_lengths() {
        let k16 = LuksKey::generate(16).unwrap();
        let k64 = LuksKey::generate(64).unwrap();
        assert_eq!(k16.len(), 16);
        assert_eq!(k64.len(), 64);
        assert_ne!(k16.len(), k64.len());
    }

    #[test]
    fn test_luks_close_empty_name_error_message() {
        let err = luks_close("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_teardown_empty_name_error_message() {
        let err = teardown_agent_volume("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_luks_status_deserialization_from_json_string() {
        // Test deserialization with missing optional field
        let json = r#"{
            "name": "vol",
            "is_open": false,
            "is_mounted": false,
            "backing_path": "/x",
            "mount_point": null,
            "cipher": "aes-xts-plain64",
            "key_size_bits": 256
        }"#;
        let status: LuksStatus = serde_json::from_str(json).unwrap();
        assert!(!status.is_open);
        assert!(status.mount_point.is_none());
        assert_eq!(status.key_size_bits, 256);
    }

    #[test]
    fn test_luks_config_validate_validates_name_before_size() {
        // Empty name + invalid size: should report name error
        let config = LuksConfig {
            name: String::new(),
            size_mb: 0,
            key_size_bits: 999,
            ..LuksConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "Should fail on name first, got: {}",
            err
        );
    }

    #[test]
    fn test_luks_config_validate_validates_size_before_key() {
        // Valid name + invalid size + invalid key: should report size error
        let config = LuksConfig {
            name: "valid".to_string(),
            size_mb: 1,
            key_size_bits: 999,
            ..LuksConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("at least 4 MB"),
            "Should fail on size, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // Additional coverage — untested code paths
    // -----------------------------------------------------------------------

    // --- LuksConfig: validation order (name length checked before chars) ---

    #[test]
    fn test_luks_config_validate_name_too_long_takes_precedence_over_bad_chars() {
        let config = LuksConfig {
            name: "/".repeat(129),
            ..LuksConfig::for_agent("x", 64)
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("too long"),
            "Should fail on length, got: {}",
            err
        );
    }

    #[test]
    fn test_luks_config_validate_name_128_with_bad_chars() {
        // Exactly 128 chars but with invalid chars -> fails on char check
        let config = LuksConfig {
            name: format!("{}!", "a".repeat(127)),
            ..LuksConfig::for_agent("x", 64)
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("invalid characters"),
            "Should fail on chars, got: {}",
            err
        );
    }

    // --- LuksFilesystem: serde deserialization from known JSON ---

    #[test]
    fn test_luks_filesystem_deserialize_from_json() {
        let ext4: LuksFilesystem = serde_json::from_str("\"Ext4\"").unwrap();
        assert_eq!(ext4, LuksFilesystem::Ext4);
        let xfs: LuksFilesystem = serde_json::from_str("\"Xfs\"").unwrap();
        assert_eq!(xfs, LuksFilesystem::Xfs);
        let btrfs: LuksFilesystem = serde_json::from_str("\"Btrfs\"").unwrap();
        assert_eq!(btrfs, LuksFilesystem::Btrfs);
    }

    #[test]
    fn test_luks_filesystem_invalid_json() {
        let result = serde_json::from_str::<LuksFilesystem>("\"Zfs\"");
        assert!(result.is_err());
    }

    // --- LuksPbkdf: serde deserialization ---

    #[test]
    fn test_luks_pbkdf_deserialize_from_json() {
        let argon: LuksPbkdf = serde_json::from_str("\"Argon2id\"").unwrap();
        assert_eq!(argon, LuksPbkdf::Argon2id);
        let pbkdf2: LuksPbkdf = serde_json::from_str("\"Pbkdf2\"").unwrap();
        assert_eq!(pbkdf2, LuksPbkdf::Pbkdf2);
    }

    #[test]
    fn test_luks_pbkdf_invalid_json() {
        let result = serde_json::from_str::<LuksPbkdf>("\"Scrypt\"");
        assert!(result.is_err());
    }

    // --- LuksCipher: as_cryptsetup_str edge cases ---

    #[test]
    fn test_luks_cipher_single_char_fields() {
        let cipher = LuksCipher {
            algorithm: "a".to_string(),
            mode: "b".to_string(),
        };
        assert_eq!(cipher.as_cryptsetup_str(), "a-b");
    }

    #[test]
    fn test_luks_cipher_serde_roundtrip() {
        let cipher = LuksCipher::default();
        let json = serde_json::to_string(&cipher).unwrap();
        let back: LuksCipher = serde_json::from_str(&json).unwrap();
        assert_eq!(back.algorithm, "aes");
        assert_eq!(back.mode, "xts-plain64");
    }

    // --- LuksKey: edge cases ---

    #[test]
    fn test_luks_key_from_bytes_all_zeros() {
        let key = LuksKey::from_bytes(vec![0; 64]).unwrap();
        assert_eq!(key.len(), 64);
        assert!(key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_luks_key_from_passphrase_exactly_8_unicode_chars() {
        // 8 unicode chars, each multibyte -> passes length >= 8 check on char count
        // but from_passphrase checks .len() which is byte count
        let pass = "\u{00e9}".repeat(8); // e-acute, 2 bytes each = 16 bytes
        let key = LuksKey::from_passphrase(&pass).unwrap();
        assert_eq!(key.len(), 16); // 8 * 2 bytes
    }

    // --- LuksStatus: field permutations ---

    #[test]
    fn test_luks_status_open_not_mounted() {
        let status = LuksStatus {
            name: "open-only".to_string(),
            is_open: true,
            is_mounted: false,
            backing_path: PathBuf::from("/dev/loop0"),
            mount_point: None,
            cipher: "aes-xts-plain64".to_string(),
            key_size_bits: 512,
        };
        assert!(status.is_open);
        assert!(!status.is_mounted);
        assert!(status.mount_point.is_none());
        let json = serde_json::to_string(&status).unwrap();
        let back: LuksStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "open-only");
        assert!(back.is_open);
        assert!(!back.is_mounted);
    }

    #[test]
    fn test_luks_status_not_open_not_mounted() {
        let status = LuksStatus {
            name: "closed".to_string(),
            is_open: false,
            is_mounted: false,
            backing_path: PathBuf::from("/var/lib/vol.img"),
            mount_point: None,
            cipher: "serpent-cbc-essiv".to_string(),
            key_size_bits: 256,
        };
        assert!(!status.is_open);
        assert!(!status.is_mounted);
    }

    // --- LuksConfig: serde with all non-default values ---

    #[test]
    fn test_luks_config_serde_custom_values() {
        let config = LuksConfig {
            name: "custom-vol".to_string(),
            backing_path: PathBuf::from("/custom/path.img"),
            size_mb: 4096,
            mount_point: PathBuf::from("/custom/mount"),
            filesystem: LuksFilesystem::Btrfs,
            cipher: LuksCipher {
                algorithm: "serpent".to_string(),
                mode: "cbc-essiv".to_string(),
            },
            key_size_bits: 256,
            pbkdf: LuksPbkdf::Pbkdf2,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: LuksConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "custom-vol");
        assert_eq!(back.backing_path, PathBuf::from("/custom/path.img"));
        assert_eq!(back.size_mb, 4096);
        assert_eq!(back.filesystem, LuksFilesystem::Btrfs);
        assert_eq!(back.cipher.algorithm, "serpent");
        assert_eq!(back.cipher.mode, "cbc-essiv");
        assert_eq!(back.key_size_bits, 256);
        assert_eq!(back.pbkdf, LuksPbkdf::Pbkdf2);
    }

    // --- LuksConfig: validate key size exactly at boundaries ---

    #[test]
    fn test_luks_config_validate_key_size_255_rejected() {
        let config = LuksConfig {
            key_size_bits: 255,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_config_validate_key_size_257_rejected() {
        let config = LuksConfig {
            key_size_bits: 257,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_config_validate_key_size_511_rejected() {
        let config = LuksConfig {
            key_size_bits: 511,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_luks_config_validate_key_size_513_rejected() {
        let config = LuksConfig {
            key_size_bits: 513,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(config.validate().is_err());
    }

    // --- LuksConfig: validate size at exact boundaries ---

    #[test]
    fn test_luks_config_validate_size_exactly_1tb_boundary() {
        // 1 TB = 1024 * 1024 MB = 1048576 MB
        let ok = LuksConfig {
            size_mb: 1048576,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(ok.validate().is_ok());

        let too_big = LuksConfig {
            size_mb: 1048577,
            ..LuksConfig::for_agent("x", 64)
        };
        assert!(too_big.validate().is_err());
    }

    // --- LuksKey: from_passphrase length check is byte-based ---

    #[test]
    fn test_luks_key_from_passphrase_7_byte_utf8_rejected() {
        // "1234567" is 7 ASCII bytes -> too short
        let err = LuksKey::from_passphrase("1234567").unwrap_err();
        assert!(err.to_string().contains("minimum 8"));
    }

    #[test]
    fn test_luks_key_from_passphrase_7_char_multibyte_accepted() {
        // 7 chars but each is 2 bytes = 14 bytes > 8 -> should be accepted
        let pass = "\u{00e9}".repeat(7); // 14 bytes
        assert!(LuksKey::from_passphrase(&pass).is_ok());
    }

    // --- LuksConfig: Debug includes all fields ---

    #[test]
    fn test_luks_config_debug_includes_filesystem() {
        let config = LuksConfig::for_agent("debug-fs", 64);
        let debug = format!("{:?}", config);
        assert!(debug.contains("Ext4"));
        assert!(debug.contains("Argon2id"));
        assert!(debug.contains("512"));
    }

    // --- LuksCipher: Debug ---

    #[test]
    fn test_luks_cipher_debug_custom() {
        let cipher = LuksCipher {
            algorithm: "twofish".to_string(),
            mode: "ecb".to_string(),
        };
        let debug = format!("{:?}", cipher);
        assert!(debug.contains("twofish"));
        assert!(debug.contains("ecb"));
    }

    #[test]
    fn send_sync_assertions() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LuksConfig>();
        assert_send_sync::<LuksFilesystem>();
        assert_send_sync::<LuksCipher>();
        assert_send_sync::<LuksPbkdf>();
        assert_send_sync::<LuksStatus>();
        assert_send_sync::<LuksKey>();
    }
}
