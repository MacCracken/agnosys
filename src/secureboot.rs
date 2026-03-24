//! secureboot — Secure Boot verification.
//!
//! Read UEFI Secure Boot state from EFI variables in sysfs.
//! Detect whether Secure Boot is enabled, check SetupMode,
//! and inspect key databases (PK, KEK, db, dbx).
//!
//! # Example
//!
//! ```no_run
//! use agnosys::secureboot;
//!
//! if secureboot::is_efi() {
//!     let state = secureboot::state().unwrap();
//!     println!("Secure Boot: {}", if state.secure_boot { "enabled" } else { "disabled" });
//!     println!("Setup Mode: {}", if state.setup_mode { "yes" } else { "no" });
//! }
//! ```

use crate::error::{Result, SysError};
use std::path::{Path, PathBuf};

// ── Constants ───────────────────────────────────────────────────────

const EFI_VARS_PATH: &str = "/sys/firmware/efi/efivars";
const EFI_PATH: &str = "/sys/firmware/efi";

// EFI variable GUIDs
const EFI_GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const EFI_IMAGE_SECURITY_GUID: &str = "d719b2cb-3d3a-4596-a3bc-dad00e67656f";

// ── Public types ────────────────────────────────────────────────────

/// Secure Boot state summary.
#[derive(Debug, Clone)]
pub struct SecureBootState {
    /// Whether Secure Boot is enabled.
    pub secure_boot: bool,
    /// Whether the system is in Setup Mode (keys can be enrolled).
    pub setup_mode: bool,
    /// Whether the Platform Key (PK) is enrolled.
    pub pk_enrolled: bool,
}

/// Information about an EFI variable.
#[derive(Debug, Clone)]
pub struct EfiVariable {
    /// Variable name.
    pub name: String,
    /// Variable GUID.
    pub guid: String,
    /// Raw variable data (first 4 bytes are attributes, rest is data).
    pub data: Vec<u8>,
}

/// Secure Boot key database type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyDb {
    /// Platform Key — root of trust.
    PK,
    /// Key Exchange Key — can update db/dbx.
    KEK,
    /// Signature Database — allowed signatures.
    Db,
    /// Forbidden Signature Database — revoked signatures.
    Dbx,
}

impl KeyDb {
    /// The EFI variable name for this key database.
    #[must_use]
    pub fn var_name(&self) -> &'static str {
        match self {
            Self::PK => "PK",
            Self::KEK => "KEK",
            Self::Db => "db",
            Self::Dbx => "dbx",
        }
    }

    /// The GUID for this key database's EFI variable.
    #[must_use]
    pub fn guid(&self) -> &'static str {
        match self {
            Self::PK | Self::KEK => EFI_GLOBAL_GUID,
            Self::Db | Self::Dbx => EFI_IMAGE_SECURITY_GUID,
        }
    }
}

impl std::fmt::Display for KeyDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.var_name())
    }
}

// ── EFI detection ───────────────────────────────────────────────────

/// Check if the system booted in EFI mode.
#[must_use]
pub fn is_efi() -> bool {
    Path::new(EFI_PATH).is_dir()
}

/// Check if EFI variables are accessible.
#[must_use]
pub fn efivars_available() -> bool {
    Path::new(EFI_VARS_PATH).is_dir()
}

// ── Secure Boot state ───────────────────────────────────────────────

/// Read the current Secure Boot state.
pub fn state() -> Result<SecureBootState> {
    let secure_boot = read_efi_bool("SecureBoot", EFI_GLOBAL_GUID).unwrap_or(false);
    let setup_mode = read_efi_bool("SetupMode", EFI_GLOBAL_GUID).unwrap_or(false);
    let pk_enrolled = efi_var_exists("PK", EFI_GLOBAL_GUID);

    tracing::trace!(
        secure_boot,
        setup_mode,
        pk_enrolled,
        "read Secure Boot state"
    );

    Ok(SecureBootState {
        secure_boot,
        setup_mode,
        pk_enrolled,
    })
}

/// Check if Secure Boot is enabled.
pub fn is_secure_boot_enabled() -> Result<bool> {
    read_efi_bool("SecureBoot", EFI_GLOBAL_GUID)
}

/// Check if the system is in Setup Mode.
pub fn is_setup_mode() -> Result<bool> {
    read_efi_bool("SetupMode", EFI_GLOBAL_GUID)
}

// ── EFI variable reading ────────────────────────────────────────────

/// Read a raw EFI variable.
pub fn read_efi_var(name: &str, guid: &str) -> Result<EfiVariable> {
    let path = efi_var_path(name, guid);
    let data = std::fs::read(&path).map_err(|e| {
        tracing::debug!(name, guid, error = %e, "failed to read EFI variable");
        SysError::Io(e)
    })?;

    Ok(EfiVariable {
        name: name.to_owned(),
        guid: guid.to_owned(),
        data,
    })
}

/// Check if an EFI variable exists.
#[must_use]
pub fn efi_var_exists(name: &str, guid: &str) -> bool {
    efi_var_path(name, guid).exists()
}

/// Get the sysfs path for an EFI variable.
#[inline]
#[must_use]
pub fn efi_var_path(name: &str, guid: &str) -> PathBuf {
    Path::new(EFI_VARS_PATH).join(format!("{name}-{guid}"))
}

/// List all EFI variable names in efivars.
pub fn list_efi_vars() -> Result<Vec<String>> {
    let dir = Path::new(EFI_VARS_PATH);
    if !dir.is_dir() {
        return Err(SysError::NotSupported {
            feature: std::borrow::Cow::Borrowed("EFI variables"),
        });
    }

    let mut vars = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| {
        tracing::error!(error = %e, "failed to read efivars");
        SysError::Io(e)
    })?;

    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            vars.push(name.to_owned());
        }
    }

    vars.sort();
    tracing::trace!(count = vars.len(), "listed EFI variables");
    Ok(vars)
}

// ── Key database inspection ─────────────────────────────────────────

/// Check if a key database variable is populated.
#[must_use]
pub fn key_db_exists(db: KeyDb) -> bool {
    efi_var_exists(db.var_name(), db.guid())
}

/// Read the raw data of a key database variable.
pub fn read_key_db(db: KeyDb) -> Result<EfiVariable> {
    read_efi_var(db.var_name(), db.guid())
}

/// Get the size of a key database variable in bytes.
pub fn key_db_size(db: KeyDb) -> Result<u64> {
    let path = efi_var_path(db.var_name(), db.guid());
    let meta = std::fs::metadata(&path).map_err(|e| {
        tracing::debug!(db = %db, error = %e, "failed to stat key db");
        SysError::Io(e)
    })?;
    Ok(meta.len())
}

// ── Internal helpers ────────────────────────────────────────────────

/// Read an EFI boolean variable (4 bytes attributes + 1 byte value).
fn read_efi_bool(name: &str, guid: &str) -> Result<bool> {
    let var = read_efi_var(name, guid)?;
    // EFI variable format: 4 bytes attributes, then data
    // A boolean var has 1 byte of data after the 4-byte attributes
    if var.data.len() >= 5 {
        Ok(var.data[4] != 0)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SecureBootState>();
        assert_send_sync::<EfiVariable>();
        assert_send_sync::<KeyDb>();
    };

    // ── EFI detection ───────────────────────────────────────────────

    #[test]
    fn is_efi_returns_bool() {
        let _ = is_efi();
    }

    #[test]
    fn efivars_available_returns_bool() {
        let _ = efivars_available();
    }

    // ── Secure Boot state ───────────────────────────────────────────

    #[test]
    fn state_returns_result() {
        let _ = state();
    }

    #[test]
    fn is_secure_boot_enabled_returns_result() {
        let _ = is_secure_boot_enabled();
    }

    #[test]
    fn is_setup_mode_returns_result() {
        let _ = is_setup_mode();
    }

    // ── KeyDb ───────────────────────────────────────────────────────

    #[test]
    fn key_db_var_names() {
        assert_eq!(KeyDb::PK.var_name(), "PK");
        assert_eq!(KeyDb::KEK.var_name(), "KEK");
        assert_eq!(KeyDb::Db.var_name(), "db");
        assert_eq!(KeyDb::Dbx.var_name(), "dbx");
    }

    #[test]
    fn key_db_guids() {
        assert_eq!(KeyDb::PK.guid(), EFI_GLOBAL_GUID);
        assert_eq!(KeyDb::KEK.guid(), EFI_GLOBAL_GUID);
        assert_eq!(KeyDb::Db.guid(), EFI_IMAGE_SECURITY_GUID);
        assert_eq!(KeyDb::Dbx.guid(), EFI_IMAGE_SECURITY_GUID);
    }

    #[test]
    fn key_db_display() {
        assert_eq!(format!("{}", KeyDb::PK), "PK");
        assert_eq!(format!("{}", KeyDb::Dbx), "dbx");
    }

    #[test]
    fn key_db_debug() {
        let dbg = format!("{:?}", KeyDb::PK);
        assert!(dbg.contains("PK"));
    }

    #[test]
    fn key_db_eq() {
        assert_eq!(KeyDb::PK, KeyDb::PK);
        assert_ne!(KeyDb::PK, KeyDb::KEK);
    }

    #[test]
    fn key_db_copy() {
        let a = KeyDb::Db;
        let b = a;
        assert_eq!(a, b);
    }

    // ── EFI variable paths ──────────────────────────────────────────

    #[test]
    fn efi_var_path_format() {
        let p = efi_var_path("SecureBoot", EFI_GLOBAL_GUID);
        let s = p.to_string_lossy();
        assert!(s.contains("efivars"));
        assert!(s.contains("SecureBoot"));
        assert!(s.contains(EFI_GLOBAL_GUID));
    }

    #[test]
    fn efi_var_exists_nonexistent() {
        assert!(!efi_var_exists(
            "NonExistentVar",
            "00000000-0000-0000-0000-000000000000"
        ));
    }

    // ── Key database ────────────────────────────────────────────────

    #[test]
    fn key_db_exists_returns_bool() {
        let _ = key_db_exists(KeyDb::PK);
        let _ = key_db_exists(KeyDb::KEK);
        let _ = key_db_exists(KeyDb::Db);
        let _ = key_db_exists(KeyDb::Dbx);
    }

    // ── List EFI vars ───────────────────────────────────────────────

    #[test]
    fn list_efi_vars_returns_result() {
        let _ = list_efi_vars();
    }

    // ── SecureBootState struct ──────────────────────────────────────

    #[test]
    fn secure_boot_state_debug() {
        let s = SecureBootState {
            secure_boot: true,
            setup_mode: false,
            pk_enrolled: true,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("secure_boot"));
        assert!(dbg.contains("true"));
    }

    #[test]
    fn secure_boot_state_clone() {
        let s = SecureBootState {
            secure_boot: false,
            setup_mode: true,
            pk_enrolled: false,
        };
        let s2 = s.clone();
        assert_eq!(s.secure_boot, s2.secure_boot);
        assert_eq!(s.setup_mode, s2.setup_mode);
    }

    // ── EfiVariable struct ──────────────────────────────────────────

    #[test]
    fn efi_variable_debug() {
        let v = EfiVariable {
            name: "SecureBoot".into(),
            guid: EFI_GLOBAL_GUID.into(),
            data: vec![0x06, 0x00, 0x00, 0x00, 0x01],
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("SecureBoot"));
    }

    #[test]
    fn efi_variable_clone() {
        let v = EfiVariable {
            name: "test".into(),
            guid: "guid".into(),
            data: vec![1, 2, 3],
        };
        let v2 = v.clone();
        assert_eq!(v.name, v2.name);
        assert_eq!(v.data, v2.data);
    }

    // ── Conditional: real EFI system ────────────────────────────────

    #[test]
    fn state_on_efi_system() {
        if !is_efi() {
            return;
        }
        let s = state().unwrap();
        // On a real EFI system, PK should be enrolled if SB is enabled
        if s.secure_boot {
            assert!(s.pk_enrolled);
        }
    }

    #[test]
    fn list_efi_vars_on_efi_system() {
        if !efivars_available() {
            return;
        }
        let vars = list_efi_vars().unwrap();
        assert!(!vars.is_empty());
    }
}
