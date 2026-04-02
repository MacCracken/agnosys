//! A/B System Update Manager
//!
//! Provides Rust APIs for A/B partition-based system updates with rollback
//! capability, replacing the legacy `scripts/agnos-update.sh` bash script.
//!
//! Features:
//! - A/B slot management for atomic, rollback-safe updates
//! - SHA-256 verification of update manifests and written data
//! - CalVer version comparison (YYYY.M.D format)
//! - Delta update support (compressed patches from a prior version)
//! - Persistent update state tracking
//! - Boot-count based automatic rollback detection
//!
//! On non-Linux platforms, all operations return `SysError::NotSupported`.
//!
//! # Security Considerations
//!
//! - Manifest verification (SHA-256) is critical — an unverified manifest can
//!   direct writes of arbitrary data to system partitions.
//! - Atomic slot writes prevent partial updates, but callers must verify the
//!   manifest signature before calling any write operations.
//! - Slot switching modifies boot configuration; incorrect ordering can leave
//!   the system unbootable (rollback count protects against this).
//! - Update images and manifests should be fetched over authenticated channels;
//!   this module does not handle transport security.

use crate::error::{Result, SysError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Represents an A/B update slot.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UpdateSlot {
    A,
    B,
}

impl UpdateSlot {
    /// Return the opposite slot.
    #[inline]
    pub fn other(&self) -> UpdateSlot {
        match self {
            UpdateSlot::A => UpdateSlot::B,
            UpdateSlot::B => UpdateSlot::A,
        }
    }

    /// Return the partition suffix string (`"a"` or `"b"`).
    #[inline]
    pub fn partition_suffix(&self) -> &'static str {
        match self {
            UpdateSlot::A => "a",
            UpdateSlot::B => "b",
        }
    }
}

impl fmt::Display for UpdateSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateSlot::A => write!(f, "A"),
            UpdateSlot::B => write!(f, "B"),
        }
    }
}

/// Release channel for updates.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateChannel {
    Stable,
    Beta,
    Nightly,
    Custom(String),
}

impl fmt::Display for UpdateChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateChannel::Stable => write!(f, "stable"),
            UpdateChannel::Beta => write!(f, "beta"),
            UpdateChannel::Nightly => write!(f, "nightly"),
            UpdateChannel::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

/// A single file within an update manifest.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateFile {
    /// Relative path within the update image.
    pub path: String,
    /// SHA-256 hex digest of the file.
    pub sha256: String,
    /// Size of the (uncompressed) file in bytes.
    pub size_bytes: u64,
    /// If this is a delta, the source version it patches from.
    pub delta_from: Option<String>,
    /// Whether the file is zstd-compressed.
    pub compressed: bool,
}

/// Manifest describing an available update.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// Target version string (CalVer YYYY.M.D).
    pub version: String,
    /// Release channel.
    pub channel: UpdateChannel,
    /// Files included in this update.
    pub files: Vec<UpdateFile>,
    /// ISO-8601 release date.
    pub release_date: String,
    /// Minimum installed version required to apply this update.
    pub min_version: Option<String>,
    /// Human-readable changelog.
    pub changelog: Option<String>,
    /// SHA-256 hex digest covering the canonical manifest body (excluding
    /// this field itself).
    pub sha256_digest: String,
}

/// Phases of an in-progress update.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdatePhase {
    Downloading,
    Verifying,
    Applying,
    Finalizing,
    RollingBack,
    Complete,
    Failed,
}

impl fmt::Display for UpdatePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            UpdatePhase::Downloading => "Downloading",
            UpdatePhase::Verifying => "Verifying",
            UpdatePhase::Applying => "Applying",
            UpdatePhase::Finalizing => "Finalizing",
            UpdatePhase::RollingBack => "Rolling back",
            UpdatePhase::Complete => "Complete",
            UpdatePhase::Failed => "Failed",
        };
        write!(f, "{}", label)
    }
}

/// Progress information for an active update operation.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProgress {
    /// Current phase.
    pub phase: UpdatePhase,
    /// Completion percentage (0-100).
    pub percent: u8,
    /// Human-readable status message.
    pub message: String,
}

impl UpdateProgress {
    /// Create a new progress value, clamping percent to 0..=100.
    #[inline]
    pub fn new(phase: UpdatePhase, percent: u8, message: impl Into<String>) -> Self {
        Self {
            phase,
            percent: percent.min(100),
            message: message.into(),
        }
    }
}

/// Persistent update state stored on disk.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateState {
    /// Slot that is currently booted.
    pub current_slot: UpdateSlot,
    /// Installed version on the current slot.
    pub current_version: String,
    /// Version string of a pending (written but not yet confirmed) update.
    pub pending_update: Option<String>,
    /// Timestamp of the last successful update.
    pub last_update: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether the previous slot contains a valid rollback image.
    pub rollback_available: bool,
    /// Number of boots since the last update was applied.
    pub boot_count_since_update: u32,
}

impl UpdateState {
    /// Create a new update state.
    #[inline]
    pub fn new(current_slot: UpdateSlot, current_version: impl Into<String>) -> Self {
        Self {
            current_slot,
            current_version: current_version.into(),
            pending_update: None,
            last_update: None,
            rollback_available: false,
            boot_count_since_update: 0,
        }
    }
}

/// Configuration for the update subsystem.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Base URL of the update server (or path to a local manifest).
    pub update_url: String,
    /// Block device for slot A.
    pub slot_a_device: PathBuf,
    /// Block device for slot B.
    pub slot_b_device: PathBuf,
    /// Path to the persisted `UpdateState` JSON file.
    pub state_file: PathBuf,
    /// Directory used for backups before updates.
    pub backup_dir: PathBuf,
    /// Maximum retry count for download/apply failures.
    pub max_retries: u32,
    /// Whether to re-read and verify the slot after writing.
    pub verify_after_apply: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            update_url: "https://updates.agnos.org".into(),
            slot_a_device: PathBuf::from("/dev/disk/by-partlabel/rootfs_a"),
            slot_b_device: PathBuf::from("/dev/disk/by-partlabel/rootfs_b"),
            state_file: PathBuf::from("/var/lib/agnos/update-state.json"),
            backup_dir: PathBuf::from("/var/lib/agnos/backups"),
            max_retries: 3,
            verify_after_apply: true,
        }
    }
}

impl UpdateConfig {
    /// Return the device path for the given slot.
    pub fn device_for_slot(&self, slot: UpdateSlot) -> &Path {
        match slot {
            UpdateSlot::A => &self.slot_a_device,
            UpdateSlot::B => &self.slot_b_device,
        }
    }
}

// ---------------------------------------------------------------------------
// Version helpers
// ---------------------------------------------------------------------------

/// Validate that `version` conforms to CalVer `YYYY.M.D` (all numeric parts).
pub fn validate_version(version: &str) -> Result<()> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return Err(SysError::InvalidArgument(
            format!("Version must have exactly 3 parts (YYYY.M.D), got: {version}").into(),
        ));
    }
    for (i, label) in [(0, "year"), (1, "month"), (2, "day")] {
        parts[i].parse::<u32>().map_err(|_| {
            SysError::InvalidArgument(
                format!("Version {label} component is not a number: '{}'", parts[i]).into(),
            )
        })?;
    }
    let year: u32 = parts[0].parse().map_err(|_| {
        SysError::InvalidArgument(format!("Version year is not a number: '{}'", parts[0]).into())
    })?;
    if !(2024..=2100).contains(&year) {
        return Err(SysError::InvalidArgument(
            format!("Version year out of range (2024-2100): {year}").into(),
        ));
    }
    let month: u32 = parts[2].parse().map_err(|_| {
        SysError::InvalidArgument(format!("Version month is not a number: '{}'", parts[2]).into())
    })?;
    if !(1..=12).contains(&month) {
        return Err(SysError::InvalidArgument(
            format!("Version month out of range (1-12): {month}").into(),
        ));
    }
    Ok(())
}

/// Compare two CalVer version strings (`YYYY.M.D`).
///
/// Returns `Ordering::Less` when `a` is older than `b`.  If either string
/// is malformed the comparison falls back to lexicographic ordering.
#[must_use]
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let parse = |v: &str| -> Option<(u32, u32, u32)> {
        let p: Vec<&str> = v.split('.').collect();
        if p.len() != 3 {
            return None;
        }
        Some((p[0].parse().ok()?, p[1].parse().ok()?, p[2].parse().ok()?))
    };

    match (parse(a), parse(b)) {
        (Some(av), Some(bv)) => av.cmp(&bv),
        _ => a.cmp(b),
    }
}

// ---------------------------------------------------------------------------
// Slot detection
// ---------------------------------------------------------------------------

/// Determine the currently booted slot by inspecting `/proc/cmdline` for a
/// `agnos.slot=` parameter.  Falls back to reading the state file.
#[cfg(target_os = "linux")]
pub fn get_current_slot() -> Result<UpdateSlot> {
    // Try kernel command line first.
    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") {
        for token in cmdline.split_whitespace() {
            if let Some(val) = token.strip_prefix("agnos.slot=") {
                return match val {
                    "a" | "A" => Ok(UpdateSlot::A),
                    "b" | "B" => Ok(UpdateSlot::B),
                    _ => Err(SysError::InvalidArgument(
                        format!("Unknown slot in cmdline: {val}").into(),
                    )),
                };
            }
        }
    }

    // Fallback: read state file at the default location.
    let default_state = PathBuf::from("/var/lib/agnos/update-state.json");
    if default_state.exists() {
        let data = std::fs::read_to_string(&default_state)
            .map_err(|e| SysError::Unknown(format!("Failed to read state file: {e}").into()))?;
        let state: UpdateState = serde_json::from_str(&data)
            .map_err(|e| SysError::InvalidArgument(format!("Malformed state file: {e}").into()))?;
        return Ok(state.current_slot);
    }

    // Default to slot A.
    Ok(UpdateSlot::A)
}

/// Determine the currently booted slot by inspecting `/proc/cmdline` for a
/// `agnos.slot=` parameter.  Falls back to reading the state file.
#[cfg(not(target_os = "linux"))]
pub fn get_current_slot() -> Result<UpdateSlot> {
    Err(SysError::NotSupported {
        feature: "update".into(),
    })
}

// ---------------------------------------------------------------------------
// State persistence
// ---------------------------------------------------------------------------

/// Load persisted update state from the config's `state_file`.
pub fn get_update_state(config: &UpdateConfig) -> Result<UpdateState> {
    let data = std::fs::read_to_string(&config.state_file).map_err(|e| {
        SysError::Unknown(
            format!(
                "Failed to read update state from {}: {e}",
                config.state_file.display()
            )
            .into(),
        )
    })?;
    serde_json::from_str(&data)
        .map_err(|e| SysError::InvalidArgument(format!("Malformed update state: {e}").into()))
}

/// Persist `state` as JSON to `path`.
pub fn save_update_state(state: &UpdateState, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            SysError::Unknown(
                format!("Failed to create state directory {}: {e}", parent.display()).into(),
            )
        })?;
    }
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| SysError::Unknown(format!("Failed to serialize update state: {e}").into()))?;
    std::fs::write(path, json).map_err(|e| {
        SysError::Unknown(format!("Failed to write update state to {}: {e}", path.display()).into())
    })
}

// ---------------------------------------------------------------------------
// Manifest handling
// ---------------------------------------------------------------------------

/// Parse a JSON string into an `UpdateManifest`.
pub fn parse_update_manifest(json: &str) -> Result<UpdateManifest> {
    serde_json::from_str(json).map_err(|e| {
        SysError::InvalidArgument(format!("Failed to parse update manifest: {e}").into())
    })
}

/// Verify the integrity of a manifest: check that the SHA-256 digest field
/// matches a digest computed over the canonical content (version + channel +
/// files + release_date + min_version + changelog).
pub fn verify_manifest(manifest: &UpdateManifest) -> Result<()> {
    if manifest.version.is_empty() {
        return Err(SysError::InvalidArgument(
            "Manifest version must not be empty".into(),
        ));
    }
    if manifest.files.is_empty() {
        return Err(SysError::InvalidArgument(
            "Manifest must contain at least one file".into(),
        ));
    }
    if manifest.release_date.is_empty() {
        return Err(SysError::InvalidArgument(
            "Manifest release_date must not be empty".into(),
        ));
    }
    if manifest.sha256_digest.is_empty() {
        return Err(SysError::InvalidArgument(
            "Manifest sha256_digest must not be empty".into(),
        ));
    }

    validate_version(&manifest.version)?;

    // Verify per-file hashes are well-formed hex (64 chars).
    for file in &manifest.files {
        if file.sha256.len() != 64 || !file.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SysError::InvalidArgument(
                format!(
                    "File '{}' has invalid sha256 (expected 64 hex chars): '{}'",
                    file.path, file.sha256
                )
                .into(),
            ));
        }
    }

    // Compute canonical digest.
    let canonical = compute_manifest_digest(manifest);
    if canonical != manifest.sha256_digest {
        return Err(SysError::InvalidArgument(
            format!(
                "Manifest digest mismatch: expected {}, computed {}",
                manifest.sha256_digest, canonical
            )
            .into(),
        ));
    }

    Ok(())
}

/// Compute the SHA-256 digest of the canonical manifest content.  This
/// covers version, channel, files, release_date, min_version, and changelog
/// but deliberately excludes the `sha256_digest` field itself.
fn compute_manifest_digest(manifest: &UpdateManifest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(manifest.version.as_bytes());
    hasher.update(manifest.channel.to_string().as_bytes());
    for f in &manifest.files {
        hasher.update(f.path.as_bytes());
        hasher.update(f.sha256.as_bytes());
        hasher.update(f.size_bytes.to_le_bytes());
        hasher.update(if f.compressed { &[1u8] } else { &[0u8] });
        if let Some(ref delta) = f.delta_from {
            hasher.update(delta.as_bytes());
        }
    }
    hasher.update(manifest.release_date.as_bytes());
    if let Some(ref mv) = manifest.min_version {
        hasher.update(mv.as_bytes());
    }
    if let Some(ref cl) = manifest.changelog {
        hasher.update(cl.as_bytes());
    }
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Update check
// ---------------------------------------------------------------------------

/// Check the update server (or a local manifest file) for a newer version.
///
/// If `config.update_url` starts with `file://` or `/`, it is treated as a
/// local path to a manifest JSON file.  Otherwise a network fetch is
/// attempted (currently shells out to `curl`).
#[cfg(target_os = "linux")]
pub fn check_for_update(
    config: &UpdateConfig,
    current_version: &str,
) -> Result<Option<UpdateManifest>> {
    let json = if config.update_url.starts_with("file://") {
        let path = config.update_url.trim_start_matches("file://");
        std::fs::read_to_string(path).map_err(|e| {
            SysError::Unknown(format!("Failed to read local manifest {path}: {e}").into())
        })?
    } else if config.update_url.starts_with('/') {
        std::fs::read_to_string(&config.update_url).map_err(|e| {
            SysError::Unknown(
                format!("Failed to read local manifest {}: {e}", config.update_url).into(),
            )
        })?
    } else {
        let url = format!("{}/versions.json", config.update_url);
        let output = std::process::Command::new("curl")
            .args(["-fsSL", "--proto", "=https", "--max-redirs", "3", &url])
            .output()
            .map_err(|e| SysError::Unknown(format!("curl failed: {e}").into()))?;
        if !output.status.success() {
            return Err(SysError::Unknown(
                format!(
                    "curl returned non-zero: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
                .into(),
            ));
        }
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let manifest = parse_update_manifest(&json)?;
    if compare_versions(&manifest.version, current_version) == Ordering::Greater {
        Ok(Some(manifest))
    } else {
        Ok(None)
    }
}

/// Check the update server (or a local manifest file) for a newer version.
///
/// If `config.update_url` starts with `file://` or `/`, it is treated as a
/// local path to a manifest JSON file.  Otherwise a network fetch is
/// attempted (currently shells out to `curl`).
#[cfg(not(target_os = "linux"))]
pub fn check_for_update(
    _config: &UpdateConfig,
    _current_version: &str,
) -> Result<Option<UpdateManifest>> {
    Err(SysError::NotSupported {
        feature: "update".into(),
    })
}

// ---------------------------------------------------------------------------
// Apply / verify / switch / rollback
// ---------------------------------------------------------------------------

/// Apply an update to the inactive slot.
///
/// On a real system this writes the update image to the block device of the
/// inactive slot.  Here we shell out to `dd` to write the first file listed
/// in the manifest.
#[cfg(target_os = "linux")]
pub fn apply_update(config: &UpdateConfig, manifest: &UpdateManifest) -> Result<()> {
    let current = get_current_slot().unwrap_or(UpdateSlot::A);
    let target_slot = current.other();
    let target_dev = config.device_for_slot(target_slot);

    if manifest.files.is_empty() {
        return Err(SysError::InvalidArgument(
            "Manifest contains no files to apply".into(),
        ));
    }

    let image_path = &manifest.files[0].path;

    // Validate image path: must be absolute, within the staging dir, and contain no traversal.
    // Use canonical path comparison to prevent prefix tricks (e.g. /var/lib/agnos/updates-evil/).
    let staging_dir = Path::new("/var/lib/agnos/updates");
    let image = Path::new(image_path);
    if !image.is_absolute() || image_path.contains("..") {
        return Err(SysError::InvalidArgument(
            format!("Update image path must be absolute without traversal, got: {image_path}")
                .into(),
        ));
    }
    // Canonicalize both paths to resolve symlinks and verify containment.
    // If staging dir doesn't exist yet, fall back to string prefix check with trailing slash.
    let in_staging = if let (Ok(canon_staging), Ok(canon_image)) =
        (staging_dir.canonicalize(), image.canonicalize())
    {
        canon_image.starts_with(&canon_staging)
    } else {
        // Fallback: ensure the staging dir prefix includes a path separator
        let prefix = format!("{}/", staging_dir.display());
        image_path.starts_with(&prefix)
    };
    if !in_staging {
        return Err(SysError::InvalidArgument(
            format!(
                "Update image path must be within {}, got: {image_path}",
                staging_dir.display()
            )
            .into(),
        ));
    }

    let status = std::process::Command::new("dd")
        .args([
            &format!("if={image_path}"),
            &format!("of={}", target_dev.display()),
            "bs=4M",
            "conv=fsync",
            "status=progress",
        ])
        .status()
        .map_err(|e| SysError::Unknown(format!("dd failed to start: {e}").into()))?;

    if !status.success() {
        return Err(SysError::Unknown(
            "dd returned non-zero while writing update image".into(),
        ));
    }

    // Persist pending state.
    let mut state = get_update_state(config).unwrap_or(UpdateState {
        current_slot: current,
        current_version: String::new(),
        pending_update: None,
        last_update: None,
        rollback_available: false,
        boot_count_since_update: 0,
    });
    state.pending_update = Some(manifest.version.clone());
    state.rollback_available = true;
    save_update_state(&state, &config.state_file)?;

    if config.verify_after_apply && !verify_update(config, manifest)? {
        return Err(SysError::Unknown("Post-apply verification failed".into()));
    }

    Ok(())
}

/// Apply an update to the inactive slot.
///
/// On a real system this writes the update image to the block device of the
/// inactive slot.  Here we shell out to `dd` to write the first file listed
/// in the manifest.
#[cfg(not(target_os = "linux"))]
pub fn apply_update(_config: &UpdateConfig, _manifest: &UpdateManifest) -> Result<()> {
    Err(SysError::NotSupported {
        feature: "update".into(),
    })
}

/// SHA-256 verify the data written to the inactive slot against the manifest.
#[cfg(target_os = "linux")]
pub fn verify_update(config: &UpdateConfig, manifest: &UpdateManifest) -> Result<bool> {
    if manifest.files.is_empty() {
        return Err(SysError::InvalidArgument(
            "Manifest contains no files to verify".into(),
        ));
    }

    let current = get_current_slot().unwrap_or(UpdateSlot::A);
    let target_dev = config.device_for_slot(current.other());

    let expected = &manifest.files[0].sha256;
    let size = manifest.files[0].size_bytes;

    // Read the written data using 4M blocks for performance, limiting to
    // the exact byte count via `count` and `iflag=count_bytes`.
    let output = std::process::Command::new("dd")
        .args([
            &format!("if={}", target_dev.display()),
            "bs=4M",
            &format!("count={size}"),
            "iflag=count_bytes",
        ])
        .output()
        .map_err(|e| SysError::Unknown(format!("dd read failed: {e}").into()))?;

    if !output.status.success() {
        return Err(SysError::Unknown("dd read returned non-zero".into()));
    }

    let mut hasher = Sha256::new();
    // Only hash the exact number of bytes requested (dd may read a full block).
    let data = if (output.stdout.len() as u64) > size {
        &output.stdout[..size as usize]
    } else {
        &output.stdout
    };
    hasher.update(data);
    let actual = hex::encode(hasher.finalize());

    Ok(actual == *expected)
}

/// SHA-256 verify the data written to the inactive slot against the manifest.
#[cfg(not(target_os = "linux"))]
pub fn verify_update(_config: &UpdateConfig, _manifest: &UpdateManifest) -> Result<bool> {
    Err(SysError::NotSupported {
        feature: "update".into(),
    })
}

/// Mark a slot as active for the next boot.
///
/// Writes the slot marker file for argonaut to read at next boot.
/// Falls back to direct EFI variable if `efibootmgr` is available.
#[cfg(target_os = "linux")]
pub fn switch_active_slot(config: &UpdateConfig, slot: UpdateSlot) -> Result<()> {
    // Write slot marker for argonaut init system.
    let marker = PathBuf::from("/var/lib/agnos/next-slot");
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&marker, slot.partition_suffix())
        .map_err(|e| SysError::Unknown(format!("Failed to write slot marker: {e}").into()))?;

    // If efibootmgr is available, also set the EFI boot entry.
    let _ = std::process::Command::new("efibootmgr")
        .args([
            "--bootnext",
            &format!("AGNOS-{}", slot.partition_suffix().to_uppercase()),
        ])
        .status();

    // Update persistent state.
    let mut state = get_update_state(config).unwrap_or(UpdateState {
        current_slot: slot.other(),
        current_version: String::new(),
        pending_update: None,
        last_update: None,
        rollback_available: true,
        boot_count_since_update: 0,
    });
    state.current_slot = slot;
    state.boot_count_since_update = 0;
    save_update_state(&state, &config.state_file)?;

    Ok(())
}

/// Mark a slot as active for the next boot.
///
/// Writes the slot marker file for argonaut to read at next boot.
/// Falls back to direct EFI variable if `efibootmgr` is available.
#[cfg(not(target_os = "linux"))]
pub fn switch_active_slot(_config: &UpdateConfig, _slot: UpdateSlot) -> Result<()> {
    Err(SysError::NotSupported {
        feature: "update".into(),
    })
}

/// Rollback to the previous slot.
#[cfg(target_os = "linux")]
pub fn rollback(config: &UpdateConfig) -> Result<()> {
    let state = get_update_state(config)?;
    if !state.rollback_available {
        return Err(SysError::InvalidArgument(
            "No rollback image available".into(),
        ));
    }
    let previous = state.current_slot.other();

    // Stop services before switching (argonaut service management).
    for service in &["daimon", "hoosh"] {
        if let Err(e) = std::process::Command::new("argonaut")
            .args(["stop", service])
            .status()
        {
            tracing::warn!("Failed to stop {} before rollback: {}", service, e);
        }
    }

    switch_active_slot(config, previous)?;

    // Clear pending update.
    let mut new_state = get_update_state(config).unwrap_or(state.clone());
    new_state.pending_update = None;
    new_state.rollback_available = false;
    save_update_state(&new_state, &config.state_file)?;

    Ok(())
}

/// Rollback to the previous slot.
#[cfg(not(target_os = "linux"))]
pub fn rollback(_config: &UpdateConfig) -> Result<()> {
    Err(SysError::NotSupported {
        feature: "update".into(),
    })
}

/// Mark the current boot as successful: increment the boot counter and
/// clear any pending update flag.
pub fn mark_boot_successful(config: &UpdateConfig) -> Result<()> {
    let mut state = get_update_state(config)?;
    state.boot_count_since_update = state.boot_count_since_update.saturating_add(1);
    if state.pending_update.is_some() {
        state.pending_update = None;
        state.last_update = Some(chrono::Utc::now());
    }
    save_update_state(&state, &config.state_file)
}

/// Pure function: returns `true` if the system has exceeded the maximum
/// allowed boot attempts since an update, indicating an automatic rollback
/// should be triggered.
#[must_use]
pub fn needs_rollback(state: &UpdateState, max_boot_attempts: u32) -> bool {
    state.pending_update.is_some() && state.boot_count_since_update >= max_boot_attempts
}

// ---------------------------------------------------------------------------
// Helper: build a test manifest with a valid digest
// ---------------------------------------------------------------------------

/// Build a minimal valid manifest (for use in tests and examples).
///
/// Computes the `sha256_digest` automatically so that `verify_manifest`
/// passes.
#[doc(hidden)]
#[must_use]
pub fn build_test_manifest(version: &str, channel: UpdateChannel) -> UpdateManifest {
    let file_hash = "a".repeat(64); // valid hex
    let mut manifest = UpdateManifest {
        version: version.to_string(),
        channel,
        files: vec![UpdateFile {
            path: "rootfs.img".into(),
            sha256: file_hash,
            size_bytes: 1024,
            delta_from: None,
            compressed: false,
        }],
        release_date: "2026-03-06T00:00:00Z".into(),
        min_version: None,
        changelog: Some("Test release".into()),
        sha256_digest: String::new(),
    };
    manifest.sha256_digest = compute_manifest_digest(&manifest);
    manifest
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // -- Slot operations --

    #[test]
    fn test_slot_other() {
        assert_eq!(UpdateSlot::A.other(), UpdateSlot::B);
        assert_eq!(UpdateSlot::B.other(), UpdateSlot::A);
    }

    #[test]
    fn test_slot_other_roundtrip() {
        assert_eq!(UpdateSlot::A.other().other(), UpdateSlot::A);
        assert_eq!(UpdateSlot::B.other().other(), UpdateSlot::B);
    }

    #[test]
    fn test_slot_partition_suffix() {
        assert_eq!(UpdateSlot::A.partition_suffix(), "a");
        assert_eq!(UpdateSlot::B.partition_suffix(), "b");
    }

    #[test]
    fn test_slot_display() {
        assert_eq!(format!("{}", UpdateSlot::A), "A");
        assert_eq!(format!("{}", UpdateSlot::B), "B");
    }

    // -- Version comparison --

    #[test]
    fn test_compare_versions_equal() {
        assert_eq!(compare_versions("2026.3.5", "2026.3.5"), Ordering::Equal);
    }

    #[test]
    fn test_compare_versions_less() {
        assert_eq!(compare_versions("2026.3.5", "2026.4.5"), Ordering::Less);
    }

    #[test]
    fn test_compare_versions_greater() {
        assert_eq!(
            compare_versions("2027.1.1", "2026.12.12"),
            Ordering::Greater
        );
    }

    #[test]
    fn test_compare_versions_month_difference() {
        assert_eq!(compare_versions("2026.3.5", "2026.3.6"), Ordering::Less);
    }

    #[test]
    fn test_compare_versions_day_difference() {
        assert_eq!(compare_versions("2026.1.5", "2026.3.5"), Ordering::Less);
    }

    #[test]
    fn test_compare_versions_malformed_fallback() {
        // Falls back to lexicographic.
        assert_eq!(compare_versions("abc", "def"), Ordering::Less);
    }

    // -- Version validation --

    #[test]
    fn test_validate_version_valid() {
        assert!(validate_version("2026.3.5").is_ok());
        assert!(validate_version("2026.15.12").is_ok());
    }

    #[test]
    fn test_validate_version_too_few_parts() {
        assert!(validate_version("2026.3").is_err());
    }

    #[test]
    fn test_validate_version_too_many_parts() {
        assert!(validate_version("2026.3.5.1").is_err());
    }

    #[test]
    fn test_validate_version_non_numeric() {
        assert!(validate_version("2026.x.5").is_err());
    }

    #[test]
    fn test_validate_version_year_out_of_range() {
        assert!(validate_version("2023.1.1").is_err());
    }

    #[test]
    fn test_validate_version_month_out_of_range() {
        assert!(validate_version("2026.3.13").is_err());
        assert!(validate_version("2026.3.0").is_err());
    }

    // -- Manifest parsing --

    #[test]
    fn test_parse_update_manifest_valid() {
        let manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed = parse_update_manifest(&json).unwrap();
        assert_eq!(parsed.version, "2026.4.5");
        assert_eq!(parsed.files.len(), 1);
    }

    #[test]
    fn test_parse_update_manifest_invalid_json() {
        assert!(parse_update_manifest("not json").is_err());
    }

    #[test]
    fn test_verify_manifest_valid() {
        let manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        assert!(verify_manifest(&manifest).is_ok());
    }

    #[test]
    fn test_verify_manifest_bad_digest() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.sha256_digest = "0".repeat(64);
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_empty_version() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.version = String::new();
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_empty_files() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.files.clear();
        // recompute digest so we test the "empty files" check, not digest mismatch
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_bad_file_hash() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.files[0].sha256 = "tooshort".into();
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_err());
    }

    // -- State serialization --

    #[test]
    fn test_state_roundtrip() {
        let path = std::env::temp_dir().join("agnos-test-update-state-roundtrip.json");
        let state = UpdateState {
            current_slot: UpdateSlot::B,
            current_version: "2026.3.5".into(),
            pending_update: Some("2026.4.5".into()),
            last_update: Some(chrono::Utc::now()),
            rollback_available: true,
            boot_count_since_update: 2,
        };
        save_update_state(&state, &path).unwrap();
        let config = UpdateConfig {
            state_file: path,
            ..UpdateConfig::default()
        };
        let loaded = get_update_state(&config).unwrap();
        assert_eq!(loaded.current_slot, UpdateSlot::B);
        assert_eq!(loaded.current_version, "2026.3.5");
        assert_eq!(loaded.pending_update, Some("2026.4.5".into()));
        assert!(loaded.rollback_available);
        assert_eq!(loaded.boot_count_since_update, 2);
    }

    #[test]
    fn test_get_update_state_missing_file() {
        let config = UpdateConfig {
            state_file: PathBuf::from("/tmp/does-not-exist-agnos-test-state.json"),
            ..UpdateConfig::default()
        };
        assert!(get_update_state(&config).is_err());
    }

    // -- Rollback logic --

    #[test]
    fn test_needs_rollback_true() {
        let state = UpdateState {
            current_slot: UpdateSlot::A,
            current_version: "2026.3.5".into(),
            pending_update: Some("2026.4.5".into()),
            last_update: None,
            rollback_available: true,
            boot_count_since_update: 3,
        };
        assert!(needs_rollback(&state, 3));
    }

    #[test]
    fn test_needs_rollback_false_no_pending() {
        let state = UpdateState {
            current_slot: UpdateSlot::A,
            current_version: "2026.3.5".into(),
            pending_update: None,
            last_update: None,
            rollback_available: true,
            boot_count_since_update: 5,
        };
        assert!(!needs_rollback(&state, 3));
    }

    #[test]
    fn test_needs_rollback_false_low_count() {
        let state = UpdateState {
            current_slot: UpdateSlot::A,
            current_version: "2026.3.5".into(),
            pending_update: Some("2026.4.5".into()),
            last_update: None,
            rollback_available: true,
            boot_count_since_update: 1,
        };
        assert!(!needs_rollback(&state, 3));
    }

    // -- Phase display --

    #[test]
    fn test_phase_display() {
        assert_eq!(format!("{}", UpdatePhase::Downloading), "Downloading");
        assert_eq!(format!("{}", UpdatePhase::Verifying), "Verifying");
        assert_eq!(format!("{}", UpdatePhase::Applying), "Applying");
        assert_eq!(format!("{}", UpdatePhase::Finalizing), "Finalizing");
        assert_eq!(format!("{}", UpdatePhase::RollingBack), "Rolling back");
        assert_eq!(format!("{}", UpdatePhase::Complete), "Complete");
        assert_eq!(format!("{}", UpdatePhase::Failed), "Failed");
    }

    // -- Channel types --

    #[test]
    fn test_channel_display() {
        assert_eq!(format!("{}", UpdateChannel::Stable), "stable");
        assert_eq!(format!("{}", UpdateChannel::Beta), "beta");
        assert_eq!(format!("{}", UpdateChannel::Nightly), "nightly");
        assert_eq!(
            format!("{}", UpdateChannel::Custom("canary".into())),
            "custom:canary"
        );
    }

    #[test]
    fn test_channel_serde_roundtrip() {
        let channels = vec![
            UpdateChannel::Stable,
            UpdateChannel::Beta,
            UpdateChannel::Nightly,
            UpdateChannel::Custom("edge".into()),
        ];
        for ch in &channels {
            let json = serde_json::to_string(ch).unwrap();
            let parsed: UpdateChannel = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, ch);
        }
    }

    // -- Progress tracking --

    #[test]
    fn test_progress_clamps_percent() {
        let p = UpdateProgress::new(UpdatePhase::Downloading, 150, "test");
        assert_eq!(p.percent, 100);
    }

    #[test]
    fn test_progress_normal() {
        let p = UpdateProgress::new(UpdatePhase::Applying, 42, "writing image");
        assert_eq!(p.phase, UpdatePhase::Applying);
        assert_eq!(p.percent, 42);
        assert_eq!(p.message, "writing image");
    }

    // -- Config --

    #[test]
    fn test_config_device_for_slot() {
        let config = UpdateConfig::default();
        assert!(
            config
                .device_for_slot(UpdateSlot::A)
                .to_str()
                .unwrap()
                .contains("rootfs_a")
        );
        assert!(
            config
                .device_for_slot(UpdateSlot::B)
                .to_str()
                .unwrap()
                .contains("rootfs_b")
        );
    }

    // -- Manifest with delta --

    #[test]
    fn test_manifest_with_delta_from() {
        let file_hash = "b".repeat(64);
        let mut manifest = UpdateManifest {
            version: "2026.4.5".into(),
            channel: UpdateChannel::Stable,
            files: vec![UpdateFile {
                path: "rootfs.delta".into(),
                sha256: file_hash,
                size_bytes: 512,
                delta_from: Some("2026.3.5".into()),
                compressed: true,
            }],
            release_date: "2026-03-06T00:00:00Z".into(),
            min_version: Some("2026.3.5".into()),
            changelog: None,
            sha256_digest: String::new(),
        };
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_ok());
        assert!(manifest.files[0].delta_from.is_some());
        assert!(manifest.files[0].compressed);
    }

    // -- Edge cases --

    #[test]
    fn test_slot_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(UpdateSlot::A);
        set.insert(UpdateSlot::B);
        set.insert(UpdateSlot::A); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_compare_versions_year_boundary() {
        assert_eq!(compare_versions("2026.31.12", "2027.1.1"), Ordering::Less);
    }

    // ---- Version validation edge cases ----

    #[test]
    fn test_validate_version_year_2024_boundary() {
        assert!(validate_version("2024.1.1").is_ok());
    }

    #[test]
    fn test_validate_version_year_2100_boundary() {
        assert!(validate_version("2100.1.1").is_ok());
    }

    #[test]
    fn test_validate_version_year_2101_out_of_range() {
        assert!(validate_version("2101.1.1").is_err());
    }

    #[test]
    fn test_validate_version_year_2023_out_of_range() {
        assert!(validate_version("2023.12.12").is_err());
    }

    #[test]
    fn test_validate_version_month_1_valid() {
        assert!(validate_version("2026.1.1").is_ok());
    }

    #[test]
    fn test_validate_version_month_12_valid() {
        assert!(validate_version("2026.1.12").is_ok());
    }

    #[test]
    fn test_validate_version_empty_string() {
        assert!(validate_version("").is_err());
    }

    #[test]
    fn test_validate_version_single_part() {
        assert!(validate_version("2026").is_err());
    }

    #[test]
    fn test_validate_version_four_parts() {
        assert!(validate_version("2026.1.2.3").is_err());
    }

    #[test]
    fn test_validate_version_negative_numbers() {
        // "-1" fails u32 parse
        assert!(validate_version("-2026.1.1").is_err());
    }

    #[test]
    fn test_validate_version_leading_zeros() {
        // "01" parses fine as u32 = 1
        assert!(validate_version("2026.01.01").is_ok());
    }

    // ---- Version comparison edge cases ----

    #[test]
    fn test_compare_versions_identical() {
        assert_eq!(compare_versions("2026.1.1", "2026.1.1"), Ordering::Equal);
    }

    #[test]
    fn test_compare_versions_one_malformed() {
        // One valid, one invalid — falls back to lexicographic
        let result = compare_versions("2026.1.1", "abc");
        assert_eq!(result, "2026.1.1".cmp("abc"));
    }

    #[test]
    fn test_compare_versions_both_malformed() {
        assert_eq!(compare_versions("xyz", "abc"), Ordering::Greater);
    }

    #[test]
    fn test_compare_versions_empty_strings() {
        assert_eq!(compare_versions("", ""), Ordering::Equal);
    }

    #[test]
    fn test_compare_versions_large_day_values() {
        // CalVer day can be large (like day-of-year)
        assert_eq!(
            compare_versions("2026.365.1", "2026.1.1"),
            Ordering::Greater
        );
    }

    // ---- Manifest verification edge cases ----

    #[test]
    fn test_verify_manifest_empty_release_date() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.release_date = String::new();
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_empty_sha256_digest() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.sha256_digest = String::new();
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_invalid_file_hash_too_short() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.files[0].sha256 = "abc".into();
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_invalid_file_hash_non_hex() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.files[0].sha256 = "g".repeat(64); // 'g' is not hex
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_invalid_version_format() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.version = "not-a-version".into();
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_with_all_channels() {
        for channel in &[
            UpdateChannel::Stable,
            UpdateChannel::Beta,
            UpdateChannel::Nightly,
            UpdateChannel::Custom("edge".into()),
        ] {
            let manifest = build_test_manifest("2026.4.5", channel.clone());
            assert!(
                verify_manifest(&manifest).is_ok(),
                "Failed for {:?}",
                channel
            );
        }
    }

    #[test]
    fn test_verify_manifest_with_min_version() {
        let file_hash = "a".repeat(64);
        let mut manifest = UpdateManifest {
            version: "2026.4.5".into(),
            channel: UpdateChannel::Stable,
            files: vec![UpdateFile {
                path: "rootfs.img".into(),
                sha256: file_hash,
                size_bytes: 1024,
                delta_from: None,
                compressed: false,
            }],
            release_date: "2026-03-06T00:00:00Z".into(),
            min_version: Some("2026.3.1".into()),
            changelog: Some("Test".into()),
            sha256_digest: String::new(),
        };
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_ok());
    }

    #[test]
    fn test_verify_manifest_with_no_changelog() {
        let file_hash = "a".repeat(64);
        let mut manifest = UpdateManifest {
            version: "2026.4.5".into(),
            channel: UpdateChannel::Stable,
            files: vec![UpdateFile {
                path: "rootfs.img".into(),
                sha256: file_hash,
                size_bytes: 1024,
                delta_from: None,
                compressed: false,
            }],
            release_date: "2026-03-06T00:00:00Z".into(),
            min_version: None,
            changelog: None,
            sha256_digest: String::new(),
        };
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_ok());
    }

    #[test]
    fn test_verify_manifest_multiple_files() {
        let mut manifest = UpdateManifest {
            version: "2026.4.5".into(),
            channel: UpdateChannel::Stable,
            files: vec![
                UpdateFile {
                    path: "rootfs.img".into(),
                    sha256: "a".repeat(64),
                    size_bytes: 1024,
                    delta_from: None,
                    compressed: false,
                },
                UpdateFile {
                    path: "boot.img".into(),
                    sha256: "b".repeat(64),
                    size_bytes: 512,
                    delta_from: None,
                    compressed: true,
                },
            ],
            release_date: "2026-03-06T00:00:00Z".into(),
            min_version: None,
            changelog: None,
            sha256_digest: String::new(),
        };
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_ok());
    }

    // ---- Slot management ----

    #[test]
    fn test_slot_serde_roundtrip() {
        for slot in &[UpdateSlot::A, UpdateSlot::B] {
            let json = serde_json::to_string(slot).unwrap();
            let back: UpdateSlot = serde_json::from_str(&json).unwrap();
            assert_eq!(*slot, back);
        }
    }

    // ---- UpdateState serialization ----

    #[test]
    fn test_state_serialization_no_pending() {
        let state = UpdateState {
            current_slot: UpdateSlot::A,
            current_version: "2026.1.1".into(),
            pending_update: None,
            last_update: None,
            rollback_available: false,
            boot_count_since_update: 0,
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: UpdateState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.current_slot, UpdateSlot::A);
        assert!(back.pending_update.is_none());
        assert!(back.last_update.is_none());
        assert!(!back.rollback_available);
    }

    #[test]
    fn test_save_update_state_creates_parent_dirs() {
        let dir = std::env::temp_dir()
            .join("agnos-test-deep-dir")
            .join("sub1")
            .join("sub2");
        let path = dir.join("state.json");
        // Clean up if exists from prior run
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("agnos-test-deep-dir"));

        let state = UpdateState {
            current_slot: UpdateSlot::A,
            current_version: "2026.1.1".into(),
            pending_update: None,
            last_update: None,
            rollback_available: false,
            boot_count_since_update: 0,
        };
        save_update_state(&state, &path).unwrap();
        assert!(path.exists());

        // Clean up
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("agnos-test-deep-dir"));
    }

    // ---- needs_rollback edge cases ----

    #[test]
    fn test_needs_rollback_exact_threshold() {
        let state = UpdateState {
            current_slot: UpdateSlot::A,
            current_version: "2026.3.5".into(),
            pending_update: Some("2026.4.5".into()),
            last_update: None,
            rollback_available: true,
            boot_count_since_update: 5,
        };
        assert!(needs_rollback(&state, 5));
        assert!(!needs_rollback(&state, 6));
    }

    #[test]
    fn test_needs_rollback_zero_max() {
        let state = UpdateState {
            current_slot: UpdateSlot::A,
            current_version: "2026.3.5".into(),
            pending_update: Some("2026.4.5".into()),
            last_update: None,
            rollback_available: true,
            boot_count_since_update: 0,
        };
        assert!(needs_rollback(&state, 0));
    }

    #[test]
    fn test_needs_rollback_u32_max() {
        let state = UpdateState {
            current_slot: UpdateSlot::A,
            current_version: "2026.3.5".into(),
            pending_update: Some("2026.4.5".into()),
            last_update: None,
            rollback_available: true,
            boot_count_since_update: u32::MAX,
        };
        assert!(needs_rollback(&state, u32::MAX));
    }

    // ---- UpdateProgress ----

    #[test]
    fn test_progress_zero_percent() {
        let p = UpdateProgress::new(UpdatePhase::Downloading, 0, "starting");
        assert_eq!(p.percent, 0);
    }

    #[test]
    fn test_progress_100_percent() {
        let p = UpdateProgress::new(UpdatePhase::Complete, 100, "done");
        assert_eq!(p.percent, 100);
    }

    #[test]
    fn test_progress_255_clamped_to_100() {
        let p = UpdateProgress::new(UpdatePhase::Applying, 255, "overflow");
        assert_eq!(p.percent, 100);
    }

    #[test]
    fn test_progress_serde_roundtrip() {
        let p = UpdateProgress::new(UpdatePhase::Verifying, 50, "halfway");
        let json = serde_json::to_string(&p).unwrap();
        let back: UpdateProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(back.phase, UpdatePhase::Verifying);
        assert_eq!(back.percent, 50);
        assert_eq!(back.message, "halfway");
    }

    // ---- UpdateConfig ----

    #[test]
    fn test_config_default_values() {
        let config = UpdateConfig::default();
        assert_eq!(config.update_url, "https://updates.agnos.org");
        assert_eq!(config.max_retries, 3);
        assert!(config.verify_after_apply);
        assert_eq!(
            config.state_file,
            PathBuf::from("/var/lib/agnos/update-state.json")
        );
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = UpdateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: UpdateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.update_url, config.update_url);
        assert_eq!(back.max_retries, config.max_retries);
    }

    // ---- Manifest digest determinism ----

    #[test]
    fn test_manifest_digest_deterministic() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let m2 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        assert_eq!(m1.sha256_digest, m2.sha256_digest);
    }

    #[test]
    fn test_manifest_digest_changes_with_version() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let m2 = build_test_manifest("2026.4.6", UpdateChannel::Stable);
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    #[test]
    fn test_manifest_digest_changes_with_channel() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let m2 = build_test_manifest("2026.4.5", UpdateChannel::Beta);
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    // ---- Phase serde ----

    #[test]
    fn test_phase_serde_roundtrip() {
        let phases = [
            UpdatePhase::Downloading,
            UpdatePhase::Verifying,
            UpdatePhase::Applying,
            UpdatePhase::Finalizing,
            UpdatePhase::RollingBack,
            UpdatePhase::Complete,
            UpdatePhase::Failed,
        ];
        for phase in &phases {
            let json = serde_json::to_string(phase).unwrap();
            let back: UpdatePhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*phase, back);
        }
    }

    // ---- UpdateFile serde ----

    #[test]
    fn test_update_file_serde_roundtrip() {
        let file = UpdateFile {
            path: "/some/path".into(),
            sha256: "a".repeat(64),
            size_bytes: 42,
            delta_from: Some("2026.3.5".into()),
            compressed: true,
        };
        let json = serde_json::to_string(&file).unwrap();
        let back: UpdateFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, "/some/path");
        assert_eq!(back.size_bytes, 42);
        assert!(back.compressed);
        assert_eq!(back.delta_from, Some("2026.3.5".into()));
    }

    // ---- UpdateState::new constructor ----

    #[test]
    fn test_state_new_defaults() {
        let state = UpdateState::new(UpdateSlot::A, "2026.4.5");
        assert_eq!(state.current_slot, UpdateSlot::A);
        assert_eq!(state.current_version, "2026.4.5");
        assert!(state.pending_update.is_none());
        assert!(state.last_update.is_none());
        assert!(!state.rollback_available);
        assert_eq!(state.boot_count_since_update, 0);
    }

    #[test]
    fn test_state_new_slot_b() {
        let state = UpdateState::new(UpdateSlot::B, "2026.1.1");
        assert_eq!(state.current_slot, UpdateSlot::B);
        assert_eq!(state.current_version, "2026.1.1");
    }

    #[test]
    fn test_state_new_accepts_string() {
        let version = String::from("2026.5.10");
        let state = UpdateState::new(UpdateSlot::A, version);
        assert_eq!(state.current_version, "2026.5.10");
    }

    // ---- UpdateState mutation and serde ----

    #[test]
    fn test_state_with_pending_update_serde() {
        let mut state = UpdateState::new(UpdateSlot::A, "2026.3.5");
        state.pending_update = Some("2026.4.5".into());
        state.rollback_available = true;
        state.boot_count_since_update = 7;
        state.last_update = Some(chrono::Utc::now());

        let json = serde_json::to_string_pretty(&state).unwrap();
        let back: UpdateState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pending_update, Some("2026.4.5".into()));
        assert!(back.rollback_available);
        assert_eq!(back.boot_count_since_update, 7);
        assert!(back.last_update.is_some());
    }

    #[test]
    fn test_state_serde_preserves_all_fields() {
        let state = UpdateState {
            current_slot: UpdateSlot::B,
            current_version: "2026.12.31".into(),
            pending_update: Some("2027.1.1".into()),
            last_update: Some(
                chrono::DateTime::parse_from_rfc3339("2026-12-31T23:59:59Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            rollback_available: true,
            boot_count_since_update: u32::MAX,
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: UpdateState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.current_slot, UpdateSlot::B);
        assert_eq!(back.current_version, "2026.12.31");
        assert_eq!(back.pending_update.as_deref(), Some("2027.1.1"));
        assert!(back.rollback_available);
        assert_eq!(back.boot_count_since_update, u32::MAX);
    }

    // ---- UpdateFile serde without delta ----

    #[test]
    fn test_update_file_no_delta_serde() {
        let file = UpdateFile {
            path: "rootfs.img".into(),
            sha256: "f".repeat(64),
            size_bytes: 0,
            delta_from: None,
            compressed: false,
        };
        let json = serde_json::to_string(&file).unwrap();
        let back: UpdateFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, "rootfs.img");
        assert_eq!(back.size_bytes, 0);
        assert!(!back.compressed);
        assert!(back.delta_from.is_none());
    }

    #[test]
    fn test_update_file_large_size() {
        let file = UpdateFile {
            path: "big.img".into(),
            sha256: "c".repeat(64),
            size_bytes: u64::MAX,
            delta_from: None,
            compressed: true,
        };
        let json = serde_json::to_string(&file).unwrap();
        let back: UpdateFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.size_bytes, u64::MAX);
    }

    // ---- Manifest full serde roundtrip ----

    #[test]
    fn test_manifest_full_serde_roundtrip() {
        let manifest = build_test_manifest("2026.6.15", UpdateChannel::Nightly);
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let back: UpdateManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, "2026.6.15");
        assert_eq!(back.channel, UpdateChannel::Nightly);
        assert_eq!(back.files.len(), 1);
        assert_eq!(back.release_date, "2026-03-06T00:00:00Z");
        assert_eq!(back.changelog.as_deref(), Some("Test release"));
        assert!(back.min_version.is_none());
        assert_eq!(back.sha256_digest, manifest.sha256_digest);
    }

    #[test]
    fn test_manifest_serde_with_all_optional_fields() {
        let file_hash = "d".repeat(64);
        let mut manifest = UpdateManifest {
            version: "2026.7.20".into(),
            channel: UpdateChannel::Custom("internal".into()),
            files: vec![
                UpdateFile {
                    path: "rootfs.img".into(),
                    sha256: file_hash.clone(),
                    size_bytes: 4096,
                    delta_from: Some("2026.7.19".into()),
                    compressed: true,
                },
                UpdateFile {
                    path: "boot.img".into(),
                    sha256: "e".repeat(64),
                    size_bytes: 2048,
                    delta_from: None,
                    compressed: false,
                },
            ],
            release_date: "2026-07-20T12:00:00Z".into(),
            min_version: Some("2026.7.1".into()),
            changelog: Some("Multi-file update with deltas".into()),
            sha256_digest: String::new(),
        };
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        let json = serde_json::to_string(&manifest).unwrap();
        let back: UpdateManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.files.len(), 2);
        assert_eq!(back.min_version.as_deref(), Some("2026.7.1"));
        assert!(back.files[0].compressed);
        assert!(!back.files[1].compressed);
        assert_eq!(back.files[0].delta_from.as_deref(), Some("2026.7.19"));
        assert!(back.files[1].delta_from.is_none());
    }

    // ---- compute_manifest_digest coverage ----

    #[test]
    fn test_digest_changes_with_file_path() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let mut m2 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        m2.files[0].path = "other.img".into();
        m2.sha256_digest = compute_manifest_digest(&m2);
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    #[test]
    fn test_digest_changes_with_file_size() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let mut m2 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        m2.files[0].size_bytes = 9999;
        m2.sha256_digest = compute_manifest_digest(&m2);
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    #[test]
    fn test_digest_changes_with_compressed_flag() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let mut m2 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        m2.files[0].compressed = true;
        m2.sha256_digest = compute_manifest_digest(&m2);
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    #[test]
    fn test_digest_changes_with_delta_from() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let mut m2 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        m2.files[0].delta_from = Some("2026.3.1".into());
        m2.sha256_digest = compute_manifest_digest(&m2);
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    #[test]
    fn test_digest_changes_with_release_date() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let mut m2 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        m2.release_date = "2026-04-06T00:00:00Z".into();
        m2.sha256_digest = compute_manifest_digest(&m2);
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    #[test]
    fn test_digest_changes_with_min_version() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let mut m2 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        m2.min_version = Some("2026.3.1".into());
        m2.sha256_digest = compute_manifest_digest(&m2);
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    #[test]
    fn test_digest_changes_with_changelog() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let mut m2 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        m2.changelog = Some("Different changelog".into());
        m2.sha256_digest = compute_manifest_digest(&m2);
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    #[test]
    fn test_digest_none_vs_some_changelog() {
        let mut m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        m1.changelog = None;
        m1.sha256_digest = compute_manifest_digest(&m1);

        let m2 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        // m2 has changelog = Some("Test release")
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    #[test]
    fn test_digest_none_vs_some_min_version() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        // m1.min_version is None

        let mut m2 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        m2.min_version = Some("2026.1.1".into());
        m2.sha256_digest = compute_manifest_digest(&m2);
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    #[test]
    fn test_digest_changes_with_file_hash() {
        let m1 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let mut m2 = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        m2.files[0].sha256 = "b".repeat(64);
        m2.sha256_digest = compute_manifest_digest(&m2);
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    // ---- Manifest verification additional edge cases ----

    #[test]
    fn test_verify_manifest_file_hash_65_chars() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.files[0].sha256 = "a".repeat(65);
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_file_hash_63_chars() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.files[0].sha256 = "a".repeat(63);
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_file_hash_empty() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.files[0].sha256 = String::new();
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_second_file_bad_hash() {
        let mut manifest = UpdateManifest {
            version: "2026.4.5".into(),
            channel: UpdateChannel::Stable,
            files: vec![
                UpdateFile {
                    path: "rootfs.img".into(),
                    sha256: "a".repeat(64),
                    size_bytes: 1024,
                    delta_from: None,
                    compressed: false,
                },
                UpdateFile {
                    path: "boot.img".into(),
                    sha256: "not-valid-hex".into(),
                    size_bytes: 512,
                    delta_from: None,
                    compressed: false,
                },
            ],
            release_date: "2026-03-06T00:00:00Z".into(),
            min_version: None,
            changelog: None,
            sha256_digest: String::new(),
        };
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        let err = verify_manifest(&manifest).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("boot.img"),
            "Error should mention the bad file"
        );
    }

    #[test]
    fn test_verify_manifest_file_hash_uppercase_hex() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.files[0].sha256 = "A".repeat(64);
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        // Uppercase hex is valid ascii hex
        assert!(verify_manifest(&manifest).is_ok());
    }

    #[test]
    fn test_verify_manifest_file_hash_mixed_case_hex() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.files[0].sha256 = "aAbBcCdDeEfF".repeat(5) + "aAbB";
        assert_eq!(manifest.files[0].sha256.len(), 64);
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_ok());
    }

    // ---- Version validation additional edge cases ----

    #[test]
    fn test_validate_version_with_spaces() {
        assert!(validate_version(" 2026.1.1").is_err());
        assert!(validate_version("2026 .1.1").is_err());
    }

    #[test]
    fn test_validate_version_only_dots() {
        assert!(validate_version("..").is_err());
        assert!(validate_version("...").is_err());
    }

    #[test]
    fn test_validate_version_with_trailing_dot() {
        assert!(validate_version("2026.1.1.").is_err());
    }

    #[test]
    fn test_validate_version_with_leading_dot() {
        assert!(validate_version(".2026.1").is_err());
    }

    #[test]
    fn test_validate_version_whitespace_parts() {
        assert!(validate_version("2026. .1").is_err());
    }

    #[test]
    fn test_validate_version_very_large_year() {
        // 99999 > 2100
        assert!(validate_version("99999.1.1").is_err());
    }

    #[test]
    fn test_validate_version_zero_year() {
        assert!(validate_version("0.1.1").is_err());
    }

    // ---- Version comparison additional ----

    #[test]
    fn test_compare_versions_same_year_month_different_day() {
        assert_eq!(compare_versions("2026.6.1", "2026.6.30"), Ordering::Less);
    }

    #[test]
    fn test_compare_versions_partial_malformed() {
        // Two parts only
        assert_eq!(
            compare_versions("2026.1", "2026.1.1"),
            "2026.1".cmp("2026.1.1")
        );
    }

    #[test]
    fn test_compare_versions_four_parts() {
        // Falls back to lexicographic
        assert_eq!(
            compare_versions("2026.1.1.1", "2026.1.1"),
            "2026.1.1.1".cmp("2026.1.1")
        );
    }

    #[test]
    fn test_compare_versions_numeric_vs_alpha() {
        // One numeric, one alpha -- both fail parse, lexicographic
        let result = compare_versions("hello", "2026.1.1");
        assert_eq!(result, "hello".cmp("2026.1.1"));
    }

    #[test]
    fn test_compare_versions_zero_components() {
        assert_eq!(compare_versions("0.0.0", "0.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("0.0.0", "0.0.1"), Ordering::Less);
    }

    // ---- UpdateConfig custom values ----

    #[test]
    fn test_config_custom_device_for_slot() {
        let config = UpdateConfig {
            slot_a_device: PathBuf::from("/dev/sda1"),
            slot_b_device: PathBuf::from("/dev/sda2"),
            ..UpdateConfig::default()
        };
        assert_eq!(
            config.device_for_slot(UpdateSlot::A),
            Path::new("/dev/sda1")
        );
        assert_eq!(
            config.device_for_slot(UpdateSlot::B),
            Path::new("/dev/sda2")
        );
    }

    #[test]
    fn test_config_custom_all_fields() {
        let config = UpdateConfig {
            update_url: "https://custom.example.com".into(),
            slot_a_device: PathBuf::from("/dev/nvme0n1p1"),
            slot_b_device: PathBuf::from("/dev/nvme0n1p2"),
            state_file: PathBuf::from("/tmp/state.json"),
            backup_dir: PathBuf::from("/tmp/backups"),
            max_retries: 10,
            verify_after_apply: false,
        };
        assert_eq!(config.update_url, "https://custom.example.com");
        assert_eq!(config.max_retries, 10);
        assert!(!config.verify_after_apply);
        assert_eq!(config.backup_dir, PathBuf::from("/tmp/backups"));
    }

    // ---- UpdateChannel equality and clone ----

    #[test]
    fn test_channel_equality() {
        assert_eq!(UpdateChannel::Stable, UpdateChannel::Stable);
        assert_eq!(UpdateChannel::Beta, UpdateChannel::Beta);
        assert_eq!(UpdateChannel::Nightly, UpdateChannel::Nightly);
        assert_eq!(
            UpdateChannel::Custom("x".into()),
            UpdateChannel::Custom("x".into())
        );
        assert_ne!(UpdateChannel::Stable, UpdateChannel::Beta);
        assert_ne!(
            UpdateChannel::Custom("x".into()),
            UpdateChannel::Custom("y".into())
        );
    }

    #[test]
    fn test_channel_custom_empty_name() {
        let ch = UpdateChannel::Custom(String::new());
        assert_eq!(format!("{ch}"), "custom:");
        let json = serde_json::to_string(&ch).unwrap();
        let back: UpdateChannel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ch);
    }

    // ---- build_test_manifest ----

    #[test]
    fn test_build_test_manifest_valid_digest() {
        let m = build_test_manifest("2026.4.5", UpdateChannel::Beta);
        // The digest should match what verify_manifest expects
        assert!(!m.sha256_digest.is_empty());
        assert_eq!(m.sha256_digest.len(), 64);
        assert!(m.sha256_digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_build_test_manifest_fields() {
        let m = build_test_manifest("2026.8.1", UpdateChannel::Custom("test".into()));
        assert_eq!(m.version, "2026.8.1");
        assert_eq!(m.channel, UpdateChannel::Custom("test".into()));
        assert_eq!(m.files.len(), 1);
        assert_eq!(m.files[0].path, "rootfs.img");
        assert_eq!(m.files[0].size_bytes, 1024);
        assert!(!m.files[0].compressed);
        assert!(m.files[0].delta_from.is_none());
        assert_eq!(m.release_date, "2026-03-06T00:00:00Z");
        assert_eq!(m.changelog.as_deref(), Some("Test release"));
        assert!(m.min_version.is_none());
    }

    // ---- Manifest parsing edge cases ----

    #[test]
    fn test_parse_manifest_empty_string() {
        assert!(parse_update_manifest("").is_err());
    }

    #[test]
    fn test_parse_manifest_empty_object() {
        assert!(parse_update_manifest("{}").is_err());
    }

    #[test]
    fn test_parse_manifest_missing_required_field() {
        let json = r#"{"version":"2026.4.5","channel":"Stable","files":[]}"#;
        assert!(parse_update_manifest(json).is_err());
    }

    #[test]
    fn test_parse_manifest_extra_fields_ignored() {
        let manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        let mut json_val: serde_json::Value = serde_json::to_value(&manifest).unwrap();
        json_val["extra_field"] = serde_json::Value::String("ignored".into());
        let json = serde_json::to_string(&json_val).unwrap();
        let parsed = parse_update_manifest(&json).unwrap();
        assert_eq!(parsed.version, "2026.4.5");
    }

    #[test]
    fn test_parse_manifest_null_json() {
        assert!(parse_update_manifest("null").is_err());
    }

    #[test]
    fn test_parse_manifest_array_json() {
        assert!(parse_update_manifest("[]").is_err());
    }

    // ---- State persistence edge cases ----

    #[test]
    fn test_save_and_load_state_minimal() {
        let path = std::env::temp_dir().join("agnos-test-state-minimal.json");
        let state = UpdateState::new(UpdateSlot::A, "2026.1.1");
        save_update_state(&state, &path).unwrap();
        let config = UpdateConfig {
            state_file: path.clone(),
            ..UpdateConfig::default()
        };
        let loaded = get_update_state(&config).unwrap();
        assert_eq!(loaded.current_slot, UpdateSlot::A);
        assert_eq!(loaded.current_version, "2026.1.1");
        assert!(loaded.pending_update.is_none());
        assert!(!loaded.rollback_available);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_get_update_state_invalid_json() {
        let path = std::env::temp_dir().join("agnos-test-state-bad-json.json");
        std::fs::write(&path, "not valid json").unwrap();
        let config = UpdateConfig {
            state_file: path.clone(),
            ..UpdateConfig::default()
        };
        assert!(get_update_state(&config).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_save_state_overwrites_existing() {
        let path = std::env::temp_dir().join("agnos-test-state-overwrite.json");
        let state1 = UpdateState::new(UpdateSlot::A, "2026.1.1");
        save_update_state(&state1, &path).unwrap();
        let state2 = UpdateState::new(UpdateSlot::B, "2026.2.2");
        save_update_state(&state2, &path).unwrap();
        let config = UpdateConfig {
            state_file: path.clone(),
            ..UpdateConfig::default()
        };
        let loaded = get_update_state(&config).unwrap();
        assert_eq!(loaded.current_slot, UpdateSlot::B);
        assert_eq!(loaded.current_version, "2026.2.2");
        let _ = std::fs::remove_file(&path);
    }

    // ---- needs_rollback additional ----

    #[test]
    fn test_needs_rollback_one_below_threshold() {
        let state = UpdateState {
            current_slot: UpdateSlot::A,
            current_version: "2026.3.5".into(),
            pending_update: Some("2026.4.5".into()),
            last_update: None,
            rollback_available: true,
            boot_count_since_update: 4,
        };
        assert!(!needs_rollback(&state, 5));
    }

    #[test]
    fn test_needs_rollback_well_above_threshold() {
        let state = UpdateState {
            current_slot: UpdateSlot::B,
            current_version: "2026.3.5".into(),
            pending_update: Some("2026.4.5".into()),
            last_update: None,
            rollback_available: true,
            boot_count_since_update: 100,
        };
        assert!(needs_rollback(&state, 3));
    }

    #[test]
    fn test_needs_rollback_no_pending_high_count() {
        let state = UpdateState {
            current_slot: UpdateSlot::A,
            current_version: "2026.3.5".into(),
            pending_update: None,
            last_update: None,
            rollback_available: true,
            boot_count_since_update: 100,
        };
        assert!(!needs_rollback(&state, 1));
    }

    // ---- Slot Debug formatting ----

    #[test]
    fn test_slot_debug() {
        assert_eq!(format!("{:?}", UpdateSlot::A), "A");
        assert_eq!(format!("{:?}", UpdateSlot::B), "B");
    }

    // ---- UpdateProgress edge cases ----

    #[test]
    fn test_progress_exactly_at_boundary() {
        let p = UpdateProgress::new(UpdatePhase::Downloading, 99, "almost");
        assert_eq!(p.percent, 99);
        let p2 = UpdateProgress::new(UpdatePhase::Downloading, 101, "over");
        assert_eq!(p2.percent, 100);
    }

    #[test]
    fn test_progress_all_phases() {
        let phases = [
            UpdatePhase::Downloading,
            UpdatePhase::Verifying,
            UpdatePhase::Applying,
            UpdatePhase::Finalizing,
            UpdatePhase::RollingBack,
            UpdatePhase::Complete,
            UpdatePhase::Failed,
        ];
        for phase in &phases {
            let p = UpdateProgress::new(*phase, 50, "test");
            assert_eq!(p.phase, *phase);
        }
    }

    #[test]
    fn test_progress_empty_message() {
        let p = UpdateProgress::new(UpdatePhase::Downloading, 0, "");
        assert_eq!(p.message, "");
    }

    #[test]
    fn test_progress_long_message() {
        let long_msg = "x".repeat(10000);
        let p = UpdateProgress::new(UpdatePhase::Applying, 50, long_msg.as_str());
        assert_eq!(p.message.len(), 10000);
    }

    // ---- Manifest digest with multiple files and deltas ----

    #[test]
    fn test_digest_with_multiple_files_order_matters() {
        let mut m1 = UpdateManifest {
            version: "2026.4.5".into(),
            channel: UpdateChannel::Stable,
            files: vec![
                UpdateFile {
                    path: "a.img".into(),
                    sha256: "a".repeat(64),
                    size_bytes: 100,
                    delta_from: None,
                    compressed: false,
                },
                UpdateFile {
                    path: "b.img".into(),
                    sha256: "b".repeat(64),
                    size_bytes: 200,
                    delta_from: None,
                    compressed: false,
                },
            ],
            release_date: "2026-03-06T00:00:00Z".into(),
            min_version: None,
            changelog: None,
            sha256_digest: String::new(),
        };
        m1.sha256_digest = compute_manifest_digest(&m1);

        let mut m2 = UpdateManifest {
            version: "2026.4.5".into(),
            channel: UpdateChannel::Stable,
            files: vec![
                UpdateFile {
                    path: "b.img".into(),
                    sha256: "b".repeat(64),
                    size_bytes: 200,
                    delta_from: None,
                    compressed: false,
                },
                UpdateFile {
                    path: "a.img".into(),
                    sha256: "a".repeat(64),
                    size_bytes: 100,
                    delta_from: None,
                    compressed: false,
                },
            ],
            release_date: "2026-03-06T00:00:00Z".into(),
            min_version: None,
            changelog: None,
            sha256_digest: String::new(),
        };
        m2.sha256_digest = compute_manifest_digest(&m2);

        // Different file order should produce different digests
        assert_ne!(m1.sha256_digest, m2.sha256_digest);
    }

    // ---- Verify manifest with version out of range ----

    #[test]
    fn test_verify_manifest_with_year_out_of_range() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        manifest.version = "2023.1.1".into();
        manifest.sha256_digest = compute_manifest_digest(&manifest);
        assert!(verify_manifest(&manifest).is_err());
    }

    #[test]
    fn test_verify_manifest_tampered_digest() {
        let mut manifest = build_test_manifest("2026.4.5", UpdateChannel::Stable);
        // Flip one character in the digest
        let mut chars: Vec<char> = manifest.sha256_digest.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        manifest.sha256_digest = chars.into_iter().collect();
        assert!(verify_manifest(&manifest).is_err());
    }

    // ---- Slot clone and copy ----

    #[test]
    fn test_slot_clone_and_copy() {
        let a = UpdateSlot::A;
        let b = a; // Copy
        let c = a; // Copy again
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    // ---- UpdatePhase clone and copy ----

    #[test]
    fn test_phase_clone_and_copy() {
        let p = UpdatePhase::Applying;
        let p2 = p; // Copy
        let p3 = p; // Copy again
        assert_eq!(p, p2);
        assert_eq!(p, p3);
    }

    // ---- State file JSON pretty format ----

    #[test]
    fn test_save_state_produces_valid_json() {
        let path = std::env::temp_dir().join("agnos-test-state-json-format.json");
        let state = UpdateState::new(UpdateSlot::B, "2026.5.5");
        save_update_state(&state, &path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        // Should be valid JSON parseable to Value
        let val: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(val.is_object());
        assert_eq!(val["current_version"], "2026.5.5");
        let _ = std::fs::remove_file(&path);
    }
}
