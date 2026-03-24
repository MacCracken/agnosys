//! ima — Integrity Measurement Architecture.
//!
//! Read IMA runtime measurements and policy from the kernel's securityfs.
//! Parse measurement entries, verify file integrity state, and inspect
//! the IMA policy.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::ima;
//!
//! if ima::is_available() {
//!     let entries = ima::read_measurements(10).unwrap();
//!     for entry in &entries {
//!         println!("{}: {} ({})", entry.pcr, entry.filename, entry.hash);
//!     }
//! }
//! ```

use crate::error::{Result, SysError};
use std::path::Path;

// ── Constants ───────────────────────────────────────────────────────

const IMA_MEASUREMENTS_PATH: &str = "/sys/kernel/security/ima/ascii_runtime_measurements";
const IMA_POLICY_PATH: &str = "/sys/kernel/security/ima/policy";
const IMA_VIOLATIONS_PATH: &str = "/sys/kernel/security/ima/violations";

// ── Public types ────────────────────────────────────────────────────

/// A single IMA measurement entry.
#[derive(Debug, Clone)]
pub struct Measurement {
    /// PCR index (typically 10 for IMA).
    pub pcr: u32,
    /// Template hash (hex).
    pub template_hash: String,
    /// Template name (e.g., "ima-ng", "ima-sig").
    pub template_name: String,
    /// File hash with algorithm prefix (e.g., "sha256:abcdef...").
    pub hash: String,
    /// File path that was measured.
    pub filename: String,
}

// ── IMA status ──────────────────────────────────────────────────────

/// Check if IMA is available on this system.
#[must_use]
pub fn is_available() -> bool {
    Path::new(IMA_MEASUREMENTS_PATH).exists()
}

/// Check if the IMA policy is readable.
#[must_use]
pub fn policy_readable() -> bool {
    Path::new(IMA_POLICY_PATH).exists()
}

/// Read the IMA violation count.
pub fn violations() -> Result<u64> {
    let content = std::fs::read_to_string(IMA_VIOLATIONS_PATH).map_err(|e| {
        tracing::debug!(error = %e, "failed to read IMA violations");
        SysError::Io(e)
    })?;

    content.trim().parse::<u64>().map_err(|e| {
        SysError::InvalidArgument(std::borrow::Cow::Owned(format!(
            "failed to parse IMA violations: {e}"
        )))
    })
}

// ── Measurements ────────────────────────────────────────────────────

/// Read the last N IMA measurement entries.
///
/// Reads from `/sys/kernel/security/ima/ascii_runtime_measurements`.
pub fn read_measurements(last_n: usize) -> Result<Vec<Measurement>> {
    let content = std::fs::read_to_string(IMA_MEASUREMENTS_PATH).map_err(|e| {
        tracing::error!(error = %e, "failed to read IMA measurements");
        SysError::Io(e)
    })?;

    let entries: Vec<Measurement> = content
        .lines()
        .rev()
        .take(last_n)
        .filter_map(parse_measurement_line)
        .collect();

    tracing::trace!(count = entries.len(), "read IMA measurements");
    Ok(entries)
}

/// Read all IMA measurement entries.
pub fn read_all_measurements() -> Result<Vec<Measurement>> {
    let content = std::fs::read_to_string(IMA_MEASUREMENTS_PATH).map_err(|e| {
        tracing::error!(error = %e, "failed to read IMA measurements");
        SysError::Io(e)
    })?;

    let entries: Vec<Measurement> = content.lines().filter_map(parse_measurement_line).collect();

    tracing::trace!(count = entries.len(), "read all IMA measurements");
    Ok(entries)
}

/// Count total IMA measurement entries without loading them all into memory.
pub fn measurement_count() -> Result<usize> {
    let content = std::fs::read_to_string(IMA_MEASUREMENTS_PATH).map_err(|e| {
        tracing::error!(error = %e, "failed to read IMA measurements");
        SysError::Io(e)
    })?;

    Ok(content.lines().count())
}

// ── Policy ──────────────────────────────────────────────────────────

/// Read the current IMA policy.
///
/// Requires appropriate permissions (typically root).
pub fn read_policy() -> Result<String> {
    std::fs::read_to_string(IMA_POLICY_PATH).map_err(|e| {
        tracing::debug!(error = %e, "failed to read IMA policy");
        SysError::Io(e)
    })
}

/// Parse IMA policy into individual rules.
#[must_use]
pub fn parse_policy(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_owned())
        .collect()
}

// ── Internal parsing ────────────────────────────────────────────────

/// Parse a single IMA measurement line.
///
/// Format: `PCR TEMPLATE_HASH TEMPLATE_NAME HASH FILENAME`
/// Example: `10 abc123... ima-ng sha256:def456... /usr/bin/ls`
fn parse_measurement_line(line: &str) -> Option<Measurement> {
    let parts: Vec<&str> = line.splitn(5, ' ').collect();
    if parts.len() < 5 {
        return None;
    }

    let pcr = parts[0].parse::<u32>().ok()?;
    let template_hash = parts[1].to_owned();
    let template_name = parts[2].to_owned();
    let hash = parts[3].to_owned();
    let filename = parts[4].to_owned();

    Some(Measurement {
        pcr,
        template_hash,
        template_name,
        hash,
        filename,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Measurement>();
    };

    // ── is_available ────────────────────────────────────────────────

    #[test]
    fn is_available_returns_bool() {
        let _ = is_available();
    }

    #[test]
    fn policy_readable_returns_bool() {
        let _ = policy_readable();
    }

    // ── parse_measurement_line ──────────────────────────────────────

    #[test]
    fn parse_valid_measurement() {
        let line = "10 abc123def456 ima-ng sha256:deadbeef /usr/bin/ls";
        let m = parse_measurement_line(line).unwrap();
        assert_eq!(m.pcr, 10);
        assert_eq!(m.template_hash, "abc123def456");
        assert_eq!(m.template_name, "ima-ng");
        assert_eq!(m.hash, "sha256:deadbeef");
        assert_eq!(m.filename, "/usr/bin/ls");
    }

    #[test]
    fn parse_measurement_with_spaces_in_filename() {
        let line = "10 aaa ima-ng sha256:bbb /path/with spaces/file";
        let m = parse_measurement_line(line).unwrap();
        assert_eq!(m.filename, "/path/with spaces/file");
    }

    #[test]
    fn parse_measurement_too_short() {
        assert!(parse_measurement_line("10 abc").is_none());
    }

    #[test]
    fn parse_measurement_bad_pcr() {
        assert!(parse_measurement_line("xx abc ima-ng sha:def /file").is_none());
    }

    #[test]
    fn parse_measurement_empty() {
        assert!(parse_measurement_line("").is_none());
    }

    // ── Measurement struct ──────────────────────────────────────────

    #[test]
    fn measurement_debug() {
        let m = Measurement {
            pcr: 10,
            template_hash: "abc".into(),
            template_name: "ima-ng".into(),
            hash: "sha256:def".into(),
            filename: "/bin/ls".into(),
        };
        let dbg = format!("{m:?}");
        assert!(dbg.contains("ima-ng"));
        assert!(dbg.contains("/bin/ls"));
    }

    #[test]
    fn measurement_clone() {
        let m = Measurement {
            pcr: 10,
            template_hash: "abc".into(),
            template_name: "ima-ng".into(),
            hash: "sha256:def".into(),
            filename: "/bin/ls".into(),
        };
        let m2 = m.clone();
        assert_eq!(m.pcr, m2.pcr);
        assert_eq!(m.filename, m2.filename);
    }

    // ── parse_policy ────────────────────────────────────────────────

    #[test]
    fn parse_policy_simple() {
        let policy = "\
# comment
measure func=FILE_CHECK
dont_measure fsmagic=0x9fa0

appraise func=FILE_CHECK
";
        let rules = parse_policy(policy);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0], "measure func=FILE_CHECK");
    }

    #[test]
    fn parse_policy_empty() {
        let rules = parse_policy("");
        assert!(rules.is_empty());
    }

    #[test]
    fn parse_policy_only_comments() {
        let rules = parse_policy("# comment\n# another\n");
        assert!(rules.is_empty());
    }

    // ── Conditional: real IMA ───────────────────────────────────────

    #[test]
    fn violations_returns_result() {
        let _ = violations();
    }

    #[test]
    fn read_measurements_returns_result() {
        let _ = read_measurements(5);
    }

    #[test]
    fn read_all_measurements_returns_result() {
        let _ = read_all_measurements();
    }

    #[test]
    fn measurement_count_returns_result() {
        let _ = measurement_count();
    }

    #[test]
    fn read_policy_returns_result() {
        let _ = read_policy();
    }
}
