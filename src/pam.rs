//! pam — Pluggable Authentication Modules.
//!
//! Query PAM configuration and service files without linking to libpam.
//! Inspect available PAM services, parse PAM stack configurations,
//! and check authentication prerequisites.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::pam;
//!
//! let services = pam::list_services().unwrap();
//! for svc in &services {
//!     println!("PAM service: {svc}");
//! }
//!
//! if let Ok(stack) = pam::read_service("login") {
//!     for entry in &stack {
//!         println!("  {} {} {}", entry.entry_type, entry.control, entry.module);
//!     }
//! }
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;
use std::path::{Path, PathBuf};

// ── Constants ───────────────────────────────────────────────────────

const PAM_DIR: &str = "/etc/pam.d";
const PAM_CONF: &str = "/etc/pam.conf";

// ── Public types ────────────────────────────────────────────────────

/// A PAM stack entry type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryType {
    Auth,
    Account,
    Password,
    Session,
}

impl EntryType {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "auth" => Some(Self::Auth),
            "account" => Some(Self::Account),
            "password" => Some(Self::Password),
            "session" => Some(Self::Session),
            _ => None,
        }
    }
}

impl std::fmt::Display for EntryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth => write!(f, "auth"),
            Self::Account => write!(f, "account"),
            Self::Password => write!(f, "password"),
            Self::Session => write!(f, "session"),
        }
    }
}

/// A single entry in a PAM service stack.
#[derive(Debug, Clone)]
pub struct PamEntry {
    /// The entry type (auth, account, password, session).
    pub entry_type: EntryType,
    /// Control flag (required, requisite, sufficient, optional, or [value=action ...]).
    pub control: String,
    /// Module path (e.g., "pam_unix.so").
    pub module: String,
    /// Module arguments.
    pub args: Vec<String>,
}

// ── Service enumeration ─────────────────────────────────────────────

/// List available PAM service names from `/etc/pam.d/`.
pub fn list_services() -> Result<Vec<String>> {
    let pam_dir = Path::new(PAM_DIR);
    if !pam_dir.is_dir() {
        return Err(SysError::NotSupported {
            feature: Cow::Borrowed("PAM (/etc/pam.d not found)"),
        });
    }

    let mut services = Vec::new();
    let entries = std::fs::read_dir(pam_dir).map_err(|e| {
        tracing::error!(error = %e, "failed to read /etc/pam.d");
        SysError::Io(e)
    })?;

    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            // Skip hidden files and backups
            if !name.starts_with('.') && !name.ends_with('~') {
                services.push(name.to_owned());
            }
        }
    }

    services.sort();
    tracing::trace!(count = services.len(), "listed PAM services");
    Ok(services)
}

/// Check if a PAM service exists.
#[must_use]
pub fn service_exists(name: &str) -> bool {
    Path::new(PAM_DIR).join(name).is_file()
}

/// Get the path to a PAM service file.
#[inline]
#[must_use]
pub fn service_path(name: &str) -> PathBuf {
    Path::new(PAM_DIR).join(name)
}

/// Check if PAM is configured on this system.
#[must_use]
pub fn is_available() -> bool {
    Path::new(PAM_DIR).is_dir() || Path::new(PAM_CONF).is_file()
}

// ── PAM stack parsing ───────────────────────────────────────────────

/// Read and parse a PAM service stack from `/etc/pam.d/<name>`.
pub fn read_service(name: &str) -> Result<Vec<PamEntry>> {
    let path = service_path(name);
    let content = std::fs::read_to_string(&path).map_err(|e| {
        tracing::error!(service = name, error = %e, "failed to read PAM service");
        SysError::Io(e)
    })?;

    let entries = parse_pam_config(&content);
    tracing::trace!(
        service = name,
        entries = entries.len(),
        "parsed PAM service"
    );
    Ok(entries)
}

/// Parse PAM configuration text into entries.
///
/// Handles both `/etc/pam.d/` per-service format and `@include` directives.
#[must_use]
pub fn parse_pam_config(content: &str) -> Vec<PamEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Skip @include directives (we don't resolve them)
        if line.starts_with("@include") {
            continue;
        }

        // Handle -type (optional module, dash prefix)
        let line = line.strip_prefix('-').unwrap_or(line);

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let entry_type = match EntryType::parse(parts[0]) {
            Some(t) => t,
            None => continue,
        };

        // Control can be a simple keyword or [value=action ...] bracket form
        let control = parts[1].to_owned();
        let module = parts[2].to_owned();
        let args: Vec<String> = if parts.len() > 3 {
            parts[3..].iter().map(|s| (*s).to_owned()).collect()
        } else {
            Vec::new()
        };

        entries.push(PamEntry {
            entry_type,
            control,
            module,
            args,
        });
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EntryType>();
        assert_send_sync::<PamEntry>();
    };

    // ── EntryType ───────────────────────────────────────────────────

    #[test]
    fn entry_type_parse() {
        assert_eq!(EntryType::parse("auth"), Some(EntryType::Auth));
        assert_eq!(EntryType::parse("account"), Some(EntryType::Account));
        assert_eq!(EntryType::parse("password"), Some(EntryType::Password));
        assert_eq!(EntryType::parse("session"), Some(EntryType::Session));
        assert_eq!(EntryType::parse("unknown"), None);
    }

    #[test]
    fn entry_type_display() {
        assert_eq!(format!("{}", EntryType::Auth), "auth");
        assert_eq!(format!("{}", EntryType::Account), "account");
        assert_eq!(format!("{}", EntryType::Password), "password");
        assert_eq!(format!("{}", EntryType::Session), "session");
    }

    #[test]
    fn entry_type_eq() {
        assert_eq!(EntryType::Auth, EntryType::Auth);
        assert_ne!(EntryType::Auth, EntryType::Session);
    }

    #[test]
    fn entry_type_debug() {
        let dbg = format!("{:?}", EntryType::Auth);
        assert!(dbg.contains("Auth"));
    }

    #[test]
    fn entry_type_copy() {
        let a = EntryType::Auth;
        let b = a;
        assert_eq!(a, b);
    }

    // ── parse_pam_config ────────────────────────────────────────────

    #[test]
    fn parse_simple_config() {
        let config = "\
auth    required    pam_unix.so
account required    pam_unix.so
";
        let entries = parse_pam_config(config);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].entry_type, EntryType::Auth);
        assert_eq!(entries[0].control, "required");
        assert_eq!(entries[0].module, "pam_unix.so");
    }

    #[test]
    fn parse_with_args() {
        let config = "auth sufficient pam_unix.so nullok try_first_pass";
        let entries = parse_pam_config(config);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].args, vec!["nullok", "try_first_pass"]);
    }

    #[test]
    fn parse_comments_and_empty() {
        let config = "\
# This is a comment

auth required pam_unix.so
# Another comment
";
        let entries = parse_pam_config(config);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn parse_include_directive() {
        let config = "\
@include common-auth
auth required pam_unix.so
";
        let entries = parse_pam_config(config);
        assert_eq!(entries.len(), 1); // @include skipped
    }

    #[test]
    fn parse_optional_dash_prefix() {
        let config = "-session optional pam_systemd.so";
        let entries = parse_pam_config(config);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_type, EntryType::Session);
        assert_eq!(entries[0].control, "optional");
    }

    #[test]
    fn parse_bracket_control() {
        let config = "auth [success=1 default=ignore] pam_unix.so";
        let entries = parse_pam_config(config);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].control.starts_with('['));
    }

    #[test]
    fn parse_empty_config() {
        let entries = parse_pam_config("");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_invalid_type_skipped() {
        let config = "bogus required pam_unix.so";
        let entries = parse_pam_config(config);
        assert!(entries.is_empty());
    }

    // ── PamEntry ────────────────────────────────────────────────────

    #[test]
    fn pam_entry_debug() {
        let e = PamEntry {
            entry_type: EntryType::Auth,
            control: "required".into(),
            module: "pam_unix.so".into(),
            args: vec!["nullok".into()],
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Auth"));
        assert!(dbg.contains("pam_unix"));
    }

    #[test]
    fn pam_entry_clone() {
        let e = PamEntry {
            entry_type: EntryType::Session,
            control: "optional".into(),
            module: "pam_systemd.so".into(),
            args: vec![],
        };
        let e2 = e.clone();
        assert_eq!(e.module, e2.module);
    }

    // ── Service enumeration ─────────────────────────────────────────

    #[test]
    fn list_services_returns_result() {
        let _ = list_services();
    }

    #[test]
    fn is_available_returns_bool() {
        let _ = is_available();
    }

    #[test]
    fn service_exists_nonexistent() {
        assert!(!service_exists("nonexistent_agnosys_test_svc"));
    }

    #[test]
    fn service_path_correct() {
        assert_eq!(service_path("login"), Path::new("/etc/pam.d/login"));
    }

    #[test]
    fn read_service_nonexistent() {
        assert!(read_service("nonexistent_agnosys_test_svc").is_err());
    }

    // ── Conditional: real PAM config ────────────────────────────────

    #[test]
    fn list_services_sorted() {
        if let Ok(svcs) = list_services() {
            for window in svcs.windows(2) {
                assert!(window[0] <= window[1]);
            }
        }
    }

    #[test]
    fn read_real_service() {
        // "other" or "login" typically exist
        for name in ["other", "login", "su"] {
            if service_exists(name) {
                let entries = read_service(name).unwrap();
                // Should have at least one entry
                assert!(!entries.is_empty());
                return;
            }
        }
    }
}
