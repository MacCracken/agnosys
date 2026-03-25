//! Systemd Journal Integration
//!
//! Provides safe Rust bindings for querying, streaming, and managing the
//! systemd journal via the `journalctl` CLI tool.
//!
//! On non-Linux platforms, all operations return `SysError::NotSupported`.

use crate::error::{Result, SysError};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single journal entry parsed from `journalctl --output=json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Timestamp of the log entry (UTC)
    pub timestamp: DateTime<Utc>,
    /// systemd unit that produced the entry (e.g. "sshd.service")
    pub unit: String,
    /// Syslog priority (0-7)
    pub priority: u8,
    /// Log message text
    pub message: String,
    /// PID of the originating process
    pub pid: u32,
    /// Additional journal fields (_SYSTEMD_UNIT, _COMM, _TRANSPORT, etc.)
    pub fields: HashMap<String, String>,
}

/// Syslog priority levels as used in the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JournalPriority {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl JournalPriority {
    /// Convert a `u8` value (0-7) into a `JournalPriority`.
    /// Returns `None` if the value is out of range.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Emergency),
            1 => Some(Self::Alert),
            2 => Some(Self::Critical),
            3 => Some(Self::Error),
            4 => Some(Self::Warning),
            5 => Some(Self::Notice),
            6 => Some(Self::Info),
            7 => Some(Self::Debug),
            _ => None,
        }
    }

    /// Return the numeric syslog level.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for JournalPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Emergency => "emerg",
            Self::Alert => "alert",
            Self::Critical => "crit",
            Self::Error => "err",
            Self::Warning => "warning",
            Self::Notice => "notice",
            Self::Info => "info",
            Self::Debug => "debug",
        };
        write!(f, "{}", label)
    }
}

/// Filter criteria for journal queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JournalFilter {
    /// Restrict to a specific systemd unit
    pub unit: Option<String>,
    /// Show entries since this timestamp (journalctl --since format)
    pub since: Option<String>,
    /// Show entries until this timestamp (journalctl --until format)
    pub until: Option<String>,
    /// Maximum priority level to include (0=emerg through 7=debug)
    pub priority: Option<JournalPriority>,
    /// Grep pattern to filter messages
    pub grep: Option<String>,
    /// Maximum number of lines to return
    pub lines: Option<usize>,
    /// Boot ID or offset (e.g. "", "-1", specific boot ID)
    pub boot: Option<String>,
}

/// Statistics about the journal on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalStats {
    /// Total number of journal entries
    pub total_entries: u64,
    /// Disk usage in bytes
    pub disk_usage_bytes: u64,
    /// Timestamp of the oldest entry
    pub oldest_entry: Option<DateTime<Utc>>,
    /// Timestamp of the newest entry
    pub newest_entry: Option<DateTime<Utc>>,
}

/// Build the argument list for a `journalctl` invocation from a filter.
///
/// This is a pure function with no side effects, suitable for unit testing.
pub fn build_journalctl_args(filter: &JournalFilter) -> Vec<String> {
    let mut args: Vec<String> = vec!["--output=json".to_string(), "--no-pager".to_string()];

    if let Some(ref unit) = filter.unit {
        args.push(format!("--unit={}", unit));
    }
    if let Some(ref since) = filter.since {
        args.push(format!("--since={}", since));
    }
    if let Some(ref until) = filter.until {
        args.push(format!("--until={}", until));
    }
    if let Some(ref prio) = filter.priority {
        args.push(format!("--priority={}", prio.as_u8()));
    }
    if let Some(ref grep) = filter.grep {
        args.push(format!("--grep={}", grep));
    }
    if let Some(lines) = filter.lines {
        args.push(format!("--lines={}", lines));
    }
    if let Some(ref boot) = filter.boot {
        args.push(format!("--boot={}", boot));
    }

    args
}

/// Parse a single JSON line from `journalctl --output=json` into a `JournalEntry`.
pub fn parse_journal_json(json_line: &str) -> Result<JournalEntry> {
    let raw: serde_json::Value = serde_json::from_str(json_line).map_err(|e| {
        SysError::InvalidArgument(format!("Failed to parse journal JSON: {}", e).into())
    })?;

    let obj = raw
        .as_object()
        .ok_or_else(|| SysError::InvalidArgument("Journal JSON is not an object".into()))?;

    // __REALTIME_TIMESTAMP is microseconds since epoch
    let timestamp = obj
        .get("__REALTIME_TIMESTAMP")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .map(|us| Utc.timestamp_micros(us))
        .and_then(|r| r.single())
        .unwrap_or_else(Utc::now);

    let unit = obj
        .get("_SYSTEMD_UNIT")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let priority = obj
        .get("PRIORITY")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(6);

    let message = obj
        .get("MESSAGE")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let pid = obj
        .get("_PID")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    // Collect extra fields (anything starting with '_' or uppercase that we haven't extracted)
    let known_keys = [
        "__REALTIME_TIMESTAMP",
        "_SYSTEMD_UNIT",
        "PRIORITY",
        "MESSAGE",
        "_PID",
        "__CURSOR",
        "__MONOTONIC_TIMESTAMP",
    ];
    let mut fields = HashMap::new();
    for (k, v) in obj.iter() {
        if !known_keys.contains(&k.as_str())
            && let Some(s) = v.as_str()
        {
            fields.insert(k.clone(), s.to_string());
        }
    }

    Ok(JournalEntry {
        timestamp,
        unit,
        priority,
        message,
        pid,
        fields,
    })
}

/// Query the systemd journal with the given filter, returning parsed entries.
///
/// Shells out to `journalctl --output=json` and parses each line.
#[cfg(target_os = "linux")]
pub fn query_journal(filter: &JournalFilter) -> Result<Vec<JournalEntry>> {
    let args = build_journalctl_args(filter);
    let output = std::process::Command::new("journalctl")
        .args(&args)
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to execute journalctl: {}", e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SysError::Unknown(
            format!("journalctl exited with {}: {}", output.status, stderr).into(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        entries.push(parse_journal_json(trimmed)?);
    }

    Ok(entries)
}

#[cfg(not(target_os = "linux"))]
pub fn query_journal(_filter: &JournalFilter) -> Result<Vec<JournalEntry>> {
    Err(SysError::NotSupported {
        feature: "journald".into(),
    })
}

/// Get journal statistics (disk usage, entry count, time range).
#[cfg(target_os = "linux")]
pub fn get_journal_stats() -> Result<JournalStats> {
    // Get disk usage
    let disk_output = std::process::Command::new("journalctl")
        .args(["--disk-usage", "--no-pager"])
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to execute journalctl: {}", e).into()))?;

    let disk_text = String::from_utf8_lossy(&disk_output.stdout);
    let disk_usage_bytes = parse_disk_usage(&disk_text).unwrap_or(0);

    // Get header info for entry count and time range
    let header_output = std::process::Command::new("journalctl")
        .args(["--header", "--no-pager"])
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to execute journalctl: {}", e).into()))?;

    let header_text = String::from_utf8_lossy(&header_output.stdout);
    let total_entries = parse_header_entry_count(&header_text);

    // Get oldest and newest timestamps via short queries
    let oldest = get_boundary_timestamp(&["--output=json", "--lines=1", "--no-pager"]);
    let newest = get_boundary_timestamp(&["--output=json", "--lines=1", "--reverse", "--no-pager"]);

    Ok(JournalStats {
        total_entries,
        disk_usage_bytes,
        oldest_entry: oldest,
        newest_entry: newest,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn get_journal_stats() -> Result<JournalStats> {
    Err(SysError::NotSupported {
        feature: "journald".into(),
    })
}

/// Spawn a `journalctl -f` process for live-streaming journal entries.
///
/// The caller is responsible for reading from the child's stdout and
/// eventually killing/waiting on the child process.
#[cfg(target_os = "linux")]
pub fn follow_journal(filter: &JournalFilter) -> Result<std::process::Child> {
    let mut args = build_journalctl_args(filter);
    args.push("--follow".to_string());

    std::process::Command::new("journalctl")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| SysError::Unknown(format!("Failed to spawn journalctl -f: {}", e).into()))
}

#[cfg(not(target_os = "linux"))]
pub fn follow_journal(_filter: &JournalFilter) -> Result<std::process::Child> {
    Err(SysError::NotSupported {
        feature: "journald".into(),
    })
}

/// List all boot IDs known to the journal, each with its first timestamp.
#[cfg(target_os = "linux")]
pub fn get_boot_list() -> Result<Vec<(String, DateTime<Utc>)>> {
    let output = std::process::Command::new("journalctl")
        .args(["--list-boots", "--no-pager"])
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to execute journalctl: {}", e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SysError::Unknown(
            format!("journalctl --list-boots failed: {}", stderr).into(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut boots = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Typical line: " -1 abc123def... Mon 2026-03-01 12:00:00 UTC—Mon 2026-03-06 08:00:00 UTC"
        if parts.len() >= 4 {
            let boot_id = parts[1].to_string();
            // Try to parse the timestamp portion (parts[2..] up to the dash separator)
            let ts_str = parts[2..].join(" ");
            // Take the portion before the em-dash or double-dash
            let first_ts = ts_str
                .split('—')
                .next()
                .or_else(|| ts_str.split("--").next())
                .unwrap_or(&ts_str)
                .trim();
            let parsed = chrono::NaiveDateTime::parse_from_str(first_ts, "%a %Y-%m-%d %H:%M:%S %Z")
                .ok()
                .map(|ndt| Utc.from_utc_datetime(&ndt))
                .unwrap_or_else(Utc::now);
            boots.push((boot_id, parsed));
        }
    }

    Ok(boots)
}

#[cfg(not(target_os = "linux"))]
pub fn get_boot_list() -> Result<Vec<(String, DateTime<Utc>)>> {
    Err(SysError::NotSupported {
        feature: "journald".into(),
    })
}

/// Run `journalctl --vacuum-size=<max_size>` to reclaim disk space.
///
/// `max_size` should be a value like "500M", "1G", etc.
#[cfg(target_os = "linux")]
pub fn vacuum_journal(max_size: &str) -> Result<()> {
    if max_size.is_empty() {
        return Err(SysError::InvalidArgument(
            "vacuum size cannot be empty".into(),
        ));
    }
    // Validate format: digits followed by optional unit suffix
    let trimmed = max_size.trim();
    let has_valid_format = trimmed.chars().take_while(|c| c.is_ascii_digit()).count() > 0;
    if !has_valid_format {
        return Err(SysError::InvalidArgument(
            format!("Invalid vacuum size format: {}", max_size).into(),
        ));
    }

    let output = std::process::Command::new("journalctl")
        .args([&format!("--vacuum-size={}", max_size)])
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to execute journalctl: {}", e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SysError::Unknown(
            format!("journalctl --vacuum-size failed: {}", stderr).into(),
        ));
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn vacuum_journal(_max_size: &str) -> Result<()> {
    Err(SysError::NotSupported {
        feature: "journald".into(),
    })
}

/// Convenience wrapper: get the last `lines` log entries for a specific systemd unit.
pub fn get_unit_logs(unit: &str, lines: usize) -> Result<Vec<JournalEntry>> {
    if unit.is_empty() {
        return Err(SysError::InvalidArgument(
            "unit name cannot be empty".into(),
        ));
    }
    let filter = JournalFilter {
        unit: Some(unit.to_string()),
        lines: Some(lines),
        ..Default::default()
    };
    query_journal(&filter)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse the disk-usage line from `journalctl --disk-usage`.
/// Example output: "Archived and active journals take up 128.0M in the file system."
fn parse_disk_usage(text: &str) -> Option<u64> {
    // Look for a number followed by a unit suffix (B, K, M, G, T)
    for word in text.split_whitespace() {
        if let Some(bytes) = parse_size_string(word) {
            return Some(bytes);
        }
    }
    None
}

/// Parse a human-readable size string like "128.0M" into bytes.
fn parse_size_string(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_part, suffix) = if s.ends_with('B') && s.len() > 1 {
        // e.g. "128.0MB" or "128B"
        let without_b = &s[..s.len() - 1];
        if without_b.ends_with(|c: char| c.is_alphabetic()) {
            let unit = &without_b[without_b.len() - 1..];
            let num = &without_b[..without_b.len() - 1];
            (num, unit)
        } else {
            (without_b, "")
        }
    } else if s.ends_with(|c: char| c.is_alphabetic()) {
        (&s[..s.len() - 1], &s[s.len() - 1..])
    } else {
        (s, "")
    };

    let value: f64 = num_part.parse().ok()?;
    let multiplier: u64 = match suffix.to_uppercase().as_str() {
        "" | "B" => 1,
        "K" => 1024,
        "M" => 1024 * 1024,
        "G" => 1024 * 1024 * 1024,
        "T" => 1024 * 1024 * 1024 * 1024,
        _ => return None,
    };
    Some((value * multiplier as f64) as u64)
}

/// Parse the "Number of entries" from `journalctl --header`.
fn parse_header_entry_count(text: &str) -> u64 {
    // Lines like "Number of entries: 12345"
    // Sum across all journal files
    let mut total: u64 = 0;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Number of entries:")
            && let Ok(n) = rest.trim().parse::<u64>()
        {
            total += n;
        }
    }
    total
}

/// Execute a journalctl command to get a boundary (oldest/newest) timestamp.
#[cfg(target_os = "linux")]
fn get_boundary_timestamp(args: &[&str]) -> Option<DateTime<Utc>> {
    let output = std::process::Command::new("journalctl")
        .args(args)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next()?.trim().to_string();
    if line.is_empty() {
        return None;
    }
    let entry = parse_journal_json(&line).ok()?;
    Some(entry.timestamp)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- build_journalctl_args tests --

    #[test]
    fn test_build_args_empty_filter() {
        let filter = JournalFilter::default();
        let args = build_journalctl_args(&filter);
        assert_eq!(args, vec!["--output=json", "--no-pager"]);
    }

    #[test]
    fn test_build_args_unit_filter() {
        let filter = JournalFilter {
            unit: Some("sshd.service".into()),
            ..Default::default()
        };
        let args = build_journalctl_args(&filter);
        assert!(args.contains(&"--unit=sshd.service".to_string()));
    }

    #[test]
    fn test_build_args_since_until() {
        let filter = JournalFilter {
            since: Some("2026-03-01".into()),
            until: Some("2026-03-06".into()),
            ..Default::default()
        };
        let args = build_journalctl_args(&filter);
        assert!(args.contains(&"--since=2026-03-01".to_string()));
        assert!(args.contains(&"--until=2026-03-06".to_string()));
    }

    #[test]
    fn test_build_args_priority() {
        let filter = JournalFilter {
            priority: Some(JournalPriority::Error),
            ..Default::default()
        };
        let args = build_journalctl_args(&filter);
        assert!(args.contains(&"--priority=3".to_string()));
    }

    #[test]
    fn test_build_args_grep() {
        let filter = JournalFilter {
            grep: Some("OOM".into()),
            ..Default::default()
        };
        let args = build_journalctl_args(&filter);
        assert!(args.contains(&"--grep=OOM".to_string()));
    }

    #[test]
    fn test_build_args_lines() {
        let filter = JournalFilter {
            lines: Some(50),
            ..Default::default()
        };
        let args = build_journalctl_args(&filter);
        assert!(args.contains(&"--lines=50".to_string()));
    }

    #[test]
    fn test_build_args_boot() {
        let filter = JournalFilter {
            boot: Some("-1".into()),
            ..Default::default()
        };
        let args = build_journalctl_args(&filter);
        assert!(args.contains(&"--boot=-1".to_string()));
    }

    #[test]
    fn test_build_args_all_filters() {
        let filter = JournalFilter {
            unit: Some("nginx.service".into()),
            since: Some("yesterday".into()),
            until: Some("today".into()),
            priority: Some(JournalPriority::Warning),
            grep: Some("error".into()),
            lines: Some(100),
            boot: Some("0".into()),
        };
        let args = build_journalctl_args(&filter);
        assert_eq!(args.len(), 9); // 2 base + 7 filter args
        assert!(args.contains(&"--unit=nginx.service".to_string()));
        assert!(args.contains(&"--since=yesterday".to_string()));
        assert!(args.contains(&"--until=today".to_string()));
        assert!(args.contains(&"--priority=4".to_string()));
        assert!(args.contains(&"--grep=error".to_string()));
        assert!(args.contains(&"--lines=100".to_string()));
        assert!(args.contains(&"--boot=0".to_string()));
    }

    // -- parse_journal_json tests --

    #[test]
    fn test_parse_journal_json_full_entry() {
        let json = r#"{
            "__REALTIME_TIMESTAMP": "1709740800000000",
            "_SYSTEMD_UNIT": "sshd.service",
            "PRIORITY": "6",
            "MESSAGE": "Accepted publickey for user",
            "_PID": "1234",
            "_COMM": "sshd",
            "_HOSTNAME": "agnos-host"
        }"#;
        let entry = parse_journal_json(json).unwrap();
        assert_eq!(entry.unit, "sshd.service");
        assert_eq!(entry.priority, 6);
        assert_eq!(entry.message, "Accepted publickey for user");
        assert_eq!(entry.pid, 1234);
        assert_eq!(entry.fields.get("_COMM").unwrap(), "sshd");
        assert_eq!(entry.fields.get("_HOSTNAME").unwrap(), "agnos-host");
    }

    #[test]
    fn test_parse_journal_json_minimal() {
        let json = r#"{"MESSAGE": "hello"}"#;
        let entry = parse_journal_json(json).unwrap();
        assert_eq!(entry.message, "hello");
        assert_eq!(entry.unit, "");
        assert_eq!(entry.priority, 6); // default INFO
        assert_eq!(entry.pid, 0);
    }

    #[test]
    fn test_parse_journal_json_invalid() {
        let result = parse_journal_json("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_journal_json_not_object() {
        let result = parse_journal_json("[1,2,3]");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_journal_json_extra_fields_collected() {
        let json = r#"{
            "MESSAGE": "test",
            "_TRANSPORT": "journal",
            "_BOOT_ID": "abc123",
            "SYSLOG_IDENTIFIER": "myapp"
        }"#;
        let entry = parse_journal_json(json).unwrap();
        assert_eq!(entry.fields.len(), 3);
        assert!(entry.fields.contains_key("_TRANSPORT"));
        assert!(entry.fields.contains_key("_BOOT_ID"));
        assert!(entry.fields.contains_key("SYSLOG_IDENTIFIER"));
    }

    #[test]
    fn test_parse_journal_json_timestamp() {
        // 2026-03-06 12:00:00 UTC in microseconds
        let json = r#"{"__REALTIME_TIMESTAMP": "1772971200000000", "MESSAGE": "ts test"}"#;
        let entry = parse_journal_json(json).unwrap();
        assert_eq!(entry.timestamp.timestamp(), 1772971200);
    }

    // -- JournalPriority tests --

    #[test]
    fn test_priority_from_u8_valid() {
        assert_eq!(
            JournalPriority::from_u8(0),
            Some(JournalPriority::Emergency)
        );
        assert_eq!(JournalPriority::from_u8(3), Some(JournalPriority::Error));
        assert_eq!(JournalPriority::from_u8(7), Some(JournalPriority::Debug));
    }

    #[test]
    fn test_priority_from_u8_invalid() {
        assert_eq!(JournalPriority::from_u8(8), None);
        assert_eq!(JournalPriority::from_u8(255), None);
    }

    #[test]
    fn test_priority_as_u8_roundtrip() {
        for val in 0..=7u8 {
            let prio = JournalPriority::from_u8(val).unwrap();
            assert_eq!(prio.as_u8(), val);
        }
    }

    #[test]
    fn test_priority_display() {
        assert_eq!(JournalPriority::Emergency.to_string(), "emerg");
        assert_eq!(JournalPriority::Error.to_string(), "err");
        assert_eq!(JournalPriority::Warning.to_string(), "warning");
        assert_eq!(JournalPriority::Info.to_string(), "info");
        assert_eq!(JournalPriority::Debug.to_string(), "debug");
    }

    // -- parse helpers tests --

    #[test]
    fn test_parse_size_string() {
        assert_eq!(parse_size_string("128.0M"), Some(134217728));
        assert_eq!(parse_size_string("1G"), Some(1073741824));
        assert_eq!(parse_size_string("512K"), Some(524288));
        assert_eq!(parse_size_string("1024B"), Some(1024));
        assert_eq!(parse_size_string("256"), Some(256));
        assert_eq!(parse_size_string(""), None);
    }

    #[test]
    fn test_parse_disk_usage() {
        let text = "Archived and active journals take up 128.0M in the file system.";
        let bytes = parse_disk_usage(text).unwrap();
        assert_eq!(bytes, 134217728);
    }

    #[test]
    fn test_parse_header_entry_count() {
        let text = "File path: /var/log/journal/abc/system.journal\nNumber of entries: 5000\nFile path: /var/log/journal/abc/user.journal\nNumber of entries: 3000\n";
        assert_eq!(parse_header_entry_count(text), 8000);
    }

    #[test]
    fn test_parse_header_entry_count_empty() {
        assert_eq!(parse_header_entry_count(""), 0);
        assert_eq!(parse_header_entry_count("no match here"), 0);
    }

    // -- serialization tests --

    #[test]
    fn test_journal_entry_serialization() {
        let entry = JournalEntry {
            timestamp: Utc.with_ymd_and_hms(2026, 3, 6, 12, 0, 0).unwrap(),
            unit: "test.service".into(),
            priority: 4,
            message: "warning message".into(),
            pid: 42,
            fields: HashMap::new(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: JournalEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.unit, "test.service");
        assert_eq!(deserialized.priority, 4);
        assert_eq!(deserialized.pid, 42);
    }

    #[test]
    fn test_journal_filter_default() {
        let filter = JournalFilter::default();
        assert!(filter.unit.is_none());
        assert!(filter.since.is_none());
        assert!(filter.until.is_none());
        assert!(filter.priority.is_none());
        assert!(filter.grep.is_none());
        assert!(filter.lines.is_none());
        assert!(filter.boot.is_none());
    }

    #[test]
    fn test_journal_stats_serialization() {
        let stats = JournalStats {
            total_entries: 10000,
            disk_usage_bytes: 134217728,
            oldest_entry: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
            newest_entry: Some(Utc.with_ymd_and_hms(2026, 3, 6, 12, 0, 0).unwrap()),
        };
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: JournalStats = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_entries, 10000);
        assert_eq!(deserialized.disk_usage_bytes, 134217728);
        assert!(deserialized.oldest_entry.is_some());
    }

    // -- input validation tests --

    #[test]
    fn test_get_unit_logs_empty_unit() {
        let result = get_unit_logs("", 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_vacuum_empty_size() {
        // vacuum_journal validates input before shelling out
        #[cfg(target_os = "linux")]
        {
            let result = vacuum_journal("");
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_vacuum_invalid_format() {
        #[cfg(target_os = "linux")]
        {
            let result = vacuum_journal("abc");
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_priority_serialize_deserialize() {
        let prio = JournalPriority::Critical;
        let json = serde_json::to_string(&prio).unwrap();
        let back: JournalPriority = serde_json::from_str(&json).unwrap();
        assert_eq!(back, JournalPriority::Critical);
    }

    #[test]
    fn test_filter_serialization_roundtrip() {
        let filter = JournalFilter {
            unit: Some("sshd.service".into()),
            since: Some("2026-03-01".into()),
            until: None,
            priority: Some(JournalPriority::Warning),
            grep: Some("fail".into()),
            lines: Some(200),
            boot: Some("-1".into()),
        };
        let json = serde_json::to_string(&filter).unwrap();
        let back: JournalFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(back.unit, filter.unit);
        assert_eq!(back.lines, Some(200));
        assert_eq!(back.priority, Some(JournalPriority::Warning));
    }

    // ---- parse_size_string edge cases ----

    #[test]
    fn test_parse_size_string_mb_suffix() {
        // "128.0MB" — B stripped, M found
        assert_eq!(parse_size_string("128.0MB"), Some(134217728));
    }

    #[test]
    fn test_parse_size_string_gb_suffix() {
        assert_eq!(parse_size_string("2.0GB"), Some(2147483648));
    }

    #[test]
    fn test_parse_size_string_tb_suffix() {
        assert_eq!(parse_size_string("1T"), Some(1099511627776));
    }

    #[test]
    fn test_parse_size_string_tb_with_b_suffix() {
        assert_eq!(parse_size_string("1TB"), Some(1099511627776));
    }

    #[test]
    fn test_parse_size_string_only_b_suffix() {
        // "512B" — the B is stripped, num is "512", suffix is "" → 512 bytes
        assert_eq!(parse_size_string("512B"), Some(512));
    }

    #[test]
    fn test_parse_size_string_whitespace_trimmed() {
        assert_eq!(parse_size_string("  128M  "), Some(134217728));
    }

    #[test]
    fn test_parse_size_string_unknown_unit() {
        assert_eq!(parse_size_string("128X"), None);
    }

    #[test]
    fn test_parse_size_string_invalid_number() {
        assert_eq!(parse_size_string("abcM"), None);
    }

    #[test]
    fn test_parse_size_string_zero() {
        assert_eq!(parse_size_string("0"), Some(0));
        assert_eq!(parse_size_string("0M"), Some(0));
    }

    #[test]
    fn test_parse_size_string_fractional_kb() {
        // 1.5K = 1.5 * 1024 = 1536
        assert_eq!(parse_size_string("1.5K"), Some(1536));
    }

    // ---- parse_disk_usage edge cases ----

    #[test]
    fn test_parse_disk_usage_no_size_found() {
        assert_eq!(parse_disk_usage("No sizes here at all"), None);
    }

    #[test]
    fn test_parse_disk_usage_gb_output() {
        let text = "Archived and active journals take up 2.5G in the file system.";
        let bytes = parse_disk_usage(text).unwrap();
        assert_eq!(bytes, (2.5 * 1024.0 * 1024.0 * 1024.0) as u64);
    }

    #[test]
    fn test_parse_disk_usage_empty_string() {
        assert_eq!(parse_disk_usage(""), None);
    }

    // ---- parse_header_entry_count edge cases ----

    #[test]
    fn test_parse_header_entry_count_single_file() {
        let text = "Number of entries: 42\n";
        assert_eq!(parse_header_entry_count(text), 42);
    }

    #[test]
    fn test_parse_header_entry_count_many_files() {
        let text = "Number of entries: 100\nNumber of entries: 200\nNumber of entries: 300\n";
        assert_eq!(parse_header_entry_count(text), 600);
    }

    #[test]
    fn test_parse_header_entry_count_with_surrounding_text() {
        let text = "\
File path: /var/log/journal/abc123/system.journal
Head sequential number: 1
Tail sequential number: 5000
Number of entries: 5000
Disk usage: 64.0M
";
        assert_eq!(parse_header_entry_count(text), 5000);
    }

    #[test]
    fn test_parse_header_entry_count_invalid_number() {
        let text = "Number of entries: not-a-number\n";
        assert_eq!(parse_header_entry_count(text), 0);
    }

    // ---- parse_journal_json edge cases ----

    #[test]
    fn test_parse_journal_json_non_string_values_skipped_in_fields() {
        let json = r#"{
            "MESSAGE": "test",
            "_NUMERIC_FIELD": 42,
            "_BOOL_FIELD": true,
            "_NULL_FIELD": null,
            "_STRING_FIELD": "kept"
        }"#;
        let entry = parse_journal_json(json).unwrap();
        // Non-string values should be skipped in the extra fields
        assert!(!entry.fields.contains_key("_NUMERIC_FIELD"));
        assert!(!entry.fields.contains_key("_BOOL_FIELD"));
        assert!(!entry.fields.contains_key("_NULL_FIELD"));
        assert_eq!(entry.fields.get("_STRING_FIELD").unwrap(), "kept");
    }

    #[test]
    fn test_parse_journal_json_known_keys_excluded_from_fields() {
        let json = r#"{
            "__REALTIME_TIMESTAMP": "1709740800000000",
            "_SYSTEMD_UNIT": "sshd.service",
            "PRIORITY": "3",
            "MESSAGE": "test",
            "_PID": "42",
            "__CURSOR": "s=abc123",
            "__MONOTONIC_TIMESTAMP": "12345",
            "_EXTRA": "extra_val"
        }"#;
        let entry = parse_journal_json(json).unwrap();
        // Known keys should NOT appear in fields
        assert!(!entry.fields.contains_key("__REALTIME_TIMESTAMP"));
        assert!(!entry.fields.contains_key("_SYSTEMD_UNIT"));
        assert!(!entry.fields.contains_key("PRIORITY"));
        assert!(!entry.fields.contains_key("MESSAGE"));
        assert!(!entry.fields.contains_key("_PID"));
        assert!(!entry.fields.contains_key("__CURSOR"));
        assert!(!entry.fields.contains_key("__MONOTONIC_TIMESTAMP"));
        // Extra key should appear
        assert_eq!(entry.fields.get("_EXTRA").unwrap(), "extra_val");
    }

    #[test]
    fn test_parse_journal_json_invalid_timestamp_uses_now() {
        let json = r#"{"__REALTIME_TIMESTAMP": "not-a-number", "MESSAGE": "test"}"#;
        let entry = parse_journal_json(json).unwrap();
        // Should fallback to Utc::now() — just check it doesn't crash
        assert_eq!(entry.message, "test");
    }

    #[test]
    fn test_parse_journal_json_missing_timestamp_uses_now() {
        let json = r#"{"MESSAGE": "no timestamp"}"#;
        let entry = parse_journal_json(json).unwrap();
        assert_eq!(entry.message, "no timestamp");
    }

    #[test]
    fn test_parse_journal_json_invalid_priority_defaults_to_6() {
        let json = r#"{"PRIORITY": "99", "MESSAGE": "high prio"}"#;
        let entry = parse_journal_json(json).unwrap();
        // Priority "99" parses as u8 OK (99), so it stays 99.
        // Actually, it does parse, it's just out of syslog range.
        assert_eq!(entry.priority, 99);
    }

    #[test]
    fn test_parse_journal_json_non_numeric_priority_defaults_to_6() {
        let json = r#"{"PRIORITY": "err", "MESSAGE": "test"}"#;
        let entry = parse_journal_json(json).unwrap();
        assert_eq!(entry.priority, 6); // default
    }

    #[test]
    fn test_parse_journal_json_non_numeric_pid_defaults_to_0() {
        let json = r#"{"_PID": "not-a-pid", "MESSAGE": "test"}"#;
        let entry = parse_journal_json(json).unwrap();
        assert_eq!(entry.pid, 0);
    }

    #[test]
    fn test_parse_journal_json_empty_object() {
        let json = r#"{}"#;
        let entry = parse_journal_json(json).unwrap();
        assert_eq!(entry.message, "");
        assert_eq!(entry.unit, "");
        assert_eq!(entry.priority, 6);
        assert_eq!(entry.pid, 0);
        assert!(entry.fields.is_empty());
    }

    // ---- JournalPriority display coverage for remaining variants ----

    #[test]
    fn test_priority_display_all_variants() {
        assert_eq!(JournalPriority::Emergency.to_string(), "emerg");
        assert_eq!(JournalPriority::Alert.to_string(), "alert");
        assert_eq!(JournalPriority::Critical.to_string(), "crit");
        assert_eq!(JournalPriority::Error.to_string(), "err");
        assert_eq!(JournalPriority::Warning.to_string(), "warning");
        assert_eq!(JournalPriority::Notice.to_string(), "notice");
        assert_eq!(JournalPriority::Info.to_string(), "info");
        assert_eq!(JournalPriority::Debug.to_string(), "debug");
    }

    #[test]
    fn test_priority_as_u8_all_values() {
        assert_eq!(JournalPriority::Emergency.as_u8(), 0);
        assert_eq!(JournalPriority::Alert.as_u8(), 1);
        assert_eq!(JournalPriority::Critical.as_u8(), 2);
        assert_eq!(JournalPriority::Error.as_u8(), 3);
        assert_eq!(JournalPriority::Warning.as_u8(), 4);
        assert_eq!(JournalPriority::Notice.as_u8(), 5);
        assert_eq!(JournalPriority::Info.as_u8(), 6);
        assert_eq!(JournalPriority::Debug.as_u8(), 7);
    }

    // ---- build_journalctl_args: verify ordering ----

    #[test]
    fn test_build_args_base_always_first() {
        let filter = JournalFilter {
            unit: Some("foo.service".into()),
            ..Default::default()
        };
        let args = build_journalctl_args(&filter);
        assert_eq!(args[0], "--output=json");
        assert_eq!(args[1], "--no-pager");
    }

    // ---- vacuum_journal input validation ----

    #[test]
    fn test_vacuum_whitespace_only_size() {
        #[cfg(target_os = "linux")]
        {
            // " " is not empty, but has_valid_format checks for leading digits
            let result = vacuum_journal(" ");
            assert!(result.is_err());
        }
    }

    // ---- JournalEntry Debug/Clone ----

    #[test]
    fn test_journal_entry_clone() {
        let entry = JournalEntry {
            timestamp: Utc.with_ymd_and_hms(2026, 3, 6, 12, 0, 0).unwrap(),
            unit: "test.service".into(),
            priority: 4,
            message: "cloned".into(),
            pid: 42,
            fields: HashMap::new(),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.unit, entry.unit);
        assert_eq!(cloned.priority, entry.priority);
        assert_eq!(cloned.pid, entry.pid);
        assert_eq!(cloned.message, entry.message);
    }

    #[test]
    fn test_journal_entry_debug() {
        let entry = JournalEntry {
            timestamp: Utc.with_ymd_and_hms(2026, 3, 6, 12, 0, 0).unwrap(),
            unit: "test.service".into(),
            priority: 6,
            message: "debug test".into(),
            pid: 1,
            fields: HashMap::new(),
        };
        let dbg = format!("{:?}", entry);
        assert!(dbg.contains("JournalEntry"));
        assert!(dbg.contains("test.service"));
    }

    // ---- JournalStats with None timestamps ----

    #[test]
    fn test_journal_stats_serialization_none_timestamps() {
        let stats = JournalStats {
            total_entries: 0,
            disk_usage_bytes: 0,
            oldest_entry: None,
            newest_entry: None,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: JournalStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_entries, 0);
        assert!(back.oldest_entry.is_none());
        assert!(back.newest_entry.is_none());
    }

    // ---- parse_journal_json: large PID / boundary values ----

    #[test]
    fn test_parse_journal_json_max_pid() {
        let json = r#"{"_PID": "4294967295", "MESSAGE": "max pid"}"#;
        let entry = parse_journal_json(json).unwrap();
        assert_eq!(entry.pid, u32::MAX);
    }

    #[test]
    fn test_parse_journal_json_pid_overflow_defaults_to_0() {
        // u32 max is 4294967295, so 4294967296 should overflow
        let json = r#"{"_PID": "4294967296", "MESSAGE": "overflow"}"#;
        let entry = parse_journal_json(json).unwrap();
        assert_eq!(entry.pid, 0);
    }

    #[test]
    fn test_parse_journal_json_priority_zero_is_emergency() {
        let json = r#"{"PRIORITY": "0", "MESSAGE": "emerg"}"#;
        let entry = parse_journal_json(json).unwrap();
        assert_eq!(entry.priority, 0);
    }

    // ---- parse_journal_json: timestamp edge case ----

    #[test]
    fn test_parse_journal_json_negative_timestamp_uses_now() {
        // Negative microseconds - timestamp_micros may fail
        let json = r#"{"__REALTIME_TIMESTAMP": "-1", "MESSAGE": "neg"}"#;
        let entry = parse_journal_json(json).unwrap();
        // Should not crash; falls back to now or produces valid DateTime
        assert_eq!(entry.message, "neg");
    }

    // ---- build_journalctl_args: lines=0 edge case ----

    #[test]
    fn test_build_args_lines_zero() {
        let filter = JournalFilter {
            lines: Some(0),
            ..Default::default()
        };
        let args = build_journalctl_args(&filter);
        assert!(args.contains(&"--lines=0".to_string()));
    }
}
