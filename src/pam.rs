//! PAM Authentication and User/Session Management
//!
//! Provides PAM service configuration, user management (via `/etc/passwd` and
//! standard tools like `useradd`/`userdel`/`usermod`), and session listing
//! (via `who`/`loginctl`).
//!
//! On non-Linux platforms, all operations return `SysError::NotSupported`.
//!
//! # Security Considerations
//!
//! - PAM configuration files define the authentication stack; writing to
//!   `/etc/pam.d/` requires root and incorrect config can lock out all logins.
//! - Enumerating users via `/etc/passwd` can facilitate user enumeration attacks
//!   if results are exposed to untrusted parties. UIDs and group memberships are
//!   included in parsed output.
//! - Password hashes are never read (they live in `/etc/shadow`), but the
//!   presence/absence of users is still information-sensitive.
//! - Callers must validate service names to prevent path traversal in
//!   `/etc/pam.d/<service>`.

use crate::error::{Result, SysError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// PAM service identifiers.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PamService {
    Login,
    Sudo,
    Sshd,
    AgnosAgent,
    Custom(String),
}

impl PamService {
    /// Returns the service name string used in `/etc/pam.d/`.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            PamService::Login => "login",
            PamService::Sudo => "sudo",
            PamService::Sshd => "sshd",
            PamService::AgnosAgent => "agnos-agent",
            PamService::Custom(name) => name.as_str(),
        }
    }
}

impl fmt::Display for PamService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result of a PAM authentication attempt.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthResult {
    Success,
    Denied(String),
    AccountExpired,
    PasswordExpired,
    SessionError(String),
    Unknown(i32),
}

impl fmt::Display for AuthResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthResult::Success => write!(f, "Authentication successful"),
            AuthResult::Denied(reason) => write!(f, "Authentication denied: {}", reason),
            AuthResult::AccountExpired => write!(f, "Account expired"),
            AuthResult::PasswordExpired => write!(f, "Password expired"),
            AuthResult::SessionError(msg) => write!(f, "Session error: {}", msg),
            AuthResult::Unknown(code) => write!(f, "Unknown PAM result code: {}", code),
        }
    }
}

/// Information about a system user (parsed from `/etc/passwd` and groups).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home_dir: PathBuf,
    pub shell: String,
    pub groups: Vec<String>,
    pub is_system_user: bool,
}

impl UserInfo {
    /// Heuristic: UIDs below 1000 (or 500 on some distros) are system users.
    fn detect_system_user(uid: u32) -> bool {
        uid < 1000
    }
}

/// Information about an active login session.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub user: String,
    pub login_time: String,
    pub tty: Option<String>,
    pub remote_host: Option<String>,
    pub pid: u32,
}

/// PAM configuration for a service.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PamConfig {
    pub service: PamService,
    pub rules: Vec<PamRule>,
}

/// A single PAM rule line.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PamRule {
    pub rule_type: PamRuleType,
    pub control: PamControl,
    pub module: String,
    pub args: Vec<String>,
}

impl fmt::Display for PamRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let line = render_pam_rule(self);
        write!(f, "{}", line)
    }
}

/// PAM rule type (which stack the rule belongs to).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PamRuleType {
    Auth,
    Account,
    Session,
    Password,
}

impl PamRuleType {
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            PamRuleType::Auth => "auth",
            PamRuleType::Account => "account",
            PamRuleType::Session => "session",
            PamRuleType::Password => "password",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "auth" => Ok(PamRuleType::Auth),
            "account" => Ok(PamRuleType::Account),
            "session" => Ok(PamRuleType::Session),
            "password" => Ok(PamRuleType::Password),
            _ => Err(SysError::InvalidArgument(
                format!("Unknown PAM rule type: {}", s).into(),
            )),
        }
    }
}

impl fmt::Display for PamRuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// PAM control flag.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PamControl {
    Required,
    Requisite,
    Sufficient,
    Optional,
    Include,
}

impl PamControl {
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            PamControl::Required => "required",
            PamControl::Requisite => "requisite",
            PamControl::Sufficient => "sufficient",
            PamControl::Optional => "optional",
            PamControl::Include => "include",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "required" => Ok(PamControl::Required),
            "requisite" => Ok(PamControl::Requisite),
            "sufficient" => Ok(PamControl::Sufficient),
            "optional" => Ok(PamControl::Optional),
            "include" => Ok(PamControl::Include),
            _ => Err(SysError::InvalidArgument(
                format!("Unknown PAM control flag: {}", s).into(),
            )),
        }
    }
}

impl fmt::Display for PamControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Username validation
// ---------------------------------------------------------------------------

/// Validate a UNIX username.
///
/// Rules: max 32 chars, must start with a lowercase letter or underscore,
/// may contain lowercase letters, digits, hyphens, underscores; no shell
/// metacharacters.
pub fn validate_username(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(SysError::InvalidArgument("Username cannot be empty".into()));
    }
    if name.len() > 32 {
        return Err(SysError::InvalidArgument(
            format!("Username too long ({} chars, max 32)", name.len()).into(),
        ));
    }
    let first = name.chars().next().unwrap();
    if !first.is_ascii_lowercase() && first != '_' {
        return Err(SysError::InvalidArgument(
            format!(
                "Username must start with a lowercase letter or underscore, got '{}'",
                first
            )
            .into(),
        ));
    }
    for ch in name.chars() {
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_') {
            return Err(SysError::InvalidArgument(
                format!("Username contains invalid character: '{}'", ch).into(),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Passwd parsing (pure)
// ---------------------------------------------------------------------------

/// Parse a single `/etc/passwd` line into a [`UserInfo`].
///
/// Format: `username:x:uid:gid:gecos:home:shell`
pub fn parse_passwd_line(line: &str) -> Result<UserInfo> {
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() < 7 {
        return Err(SysError::InvalidArgument(
            format!(
                "Malformed passwd line (expected 7 fields, got {}): {}",
                fields.len(),
                line
            )
            .into(),
        ));
    }
    let username = fields[0].to_string();
    let uid: u32 = fields[2].parse().map_err(|_| {
        SysError::InvalidArgument(format!("Invalid UID '{}' in passwd line", fields[2]).into())
    })?;
    let gid: u32 = fields[3].parse().map_err(|_| {
        SysError::InvalidArgument(format!("Invalid GID '{}' in passwd line", fields[3]).into())
    })?;
    let home_dir = PathBuf::from(fields[5]);
    let shell = fields[6].to_string();

    Ok(UserInfo {
        username,
        uid,
        gid,
        home_dir,
        shell,
        groups: Vec::new(), // populated separately
        is_system_user: UserInfo::detect_system_user(uid),
    })
}

// ---------------------------------------------------------------------------
// Who output parsing (pure)
// ---------------------------------------------------------------------------

/// Parse the output of the `who` command into a list of [`SessionInfo`].
///
/// Typical `who` output lines:
/// ```text
/// user1    pts/0        2026-03-06 10:30 (192.168.1.5)
/// user2    tty1         2026-03-06 09:15
/// ```
#[must_use]
pub fn parse_who_output(output: &str) -> Vec<SessionInfo> {
    let mut sessions = Vec::with_capacity(output.lines().count());
    for (idx, line) in output.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let user = parts[0].to_string();
        let tty = parts[1].to_string();

        // Date + time may be in columns 2+3
        let login_time = if parts.len() >= 4 {
            format!("{} {}", parts[2], parts[3])
        } else {
            parts[2].to_string()
        };

        // Remote host is in parens at the end, e.g. "(192.168.1.5)"
        let remote_host = parts.last().and_then(|p| {
            if p.starts_with('(') && p.ends_with(')') {
                Some(p[1..p.len() - 1].to_string())
            } else {
                None
            }
        });

        sessions.push(SessionInfo {
            session_id: format!("who-{}", idx),
            user,
            login_time,
            tty: Some(tty),
            remote_host,
            pid: 0, // `who` does not report PID by default
        });
    }
    sessions
}

// ---------------------------------------------------------------------------
// PAM config parsing / rendering (pure)
// ---------------------------------------------------------------------------

/// Parse PAM config file content into a list of [`PamRule`]s.
///
/// Each non-blank, non-comment line has the format:
/// ```text
/// type  control  module  [args...]
/// ```
pub fn parse_pam_config(content: &str) -> Result<Vec<PamRule>> {
    let mut rules = Vec::with_capacity(content.lines().count());
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(SysError::InvalidArgument(
                format!(
                    "Malformed PAM rule (need at least type, control, module): {}",
                    line
                )
                .into(),
            ));
        }
        let rule_type = PamRuleType::from_str(parts[0])?;
        let control = PamControl::from_str(parts[1])?;
        let module = parts[2].to_string();
        let args: Vec<String> = parts[3..].iter().map(|s| s.to_string()).collect();
        rules.push(PamRule {
            rule_type,
            control,
            module,
            args,
        });
    }
    Ok(rules)
}

/// Render a single PAM rule to its config-file representation.
fn render_pam_rule(rule: &PamRule) -> String {
    let mut line = format!(
        "{}\t{}\t{}",
        rule.rule_type.as_str(),
        rule.control.as_str(),
        rule.module
    );
    for arg in &rule.args {
        line.push('\t');
        line.push_str(arg);
    }
    line
}

/// Render a list of PAM rules to a full config file string.
#[must_use]
pub fn render_pam_config(rules: &[PamRule]) -> String {
    let mut out = String::new();
    out.push_str("# Generated by AGNOS PAM manager\n");
    for rule in rules {
        out.push_str(&render_pam_rule(rule));
        out.push('\n');
    }
    out
}

/// Validate a PAM rule: check module path looks reasonable and args have no
/// shell metacharacters.
pub fn validate_pam_rule(rule: &PamRule) -> Result<()> {
    if rule.module.is_empty() {
        return Err(SysError::InvalidArgument(
            "PAM module path cannot be empty".into(),
        ));
    }
    // Module must be a bare name (e.g. pam_unix.so) or an absolute path
    if rule.module.contains("..") {
        return Err(SysError::InvalidArgument(
            format!("PAM module path must not contain '..': {}", rule.module).into(),
        ));
    }
    // Reject shell metacharacters in module name
    let dangerous = ['|', ';', '&', '$', '`', '>', '<', '!', '{', '}'];
    for ch in dangerous {
        if rule.module.contains(ch) {
            return Err(SysError::InvalidArgument(
                format!(
                    "PAM module path contains dangerous character '{}': {}",
                    ch, rule.module
                )
                .into(),
            ));
        }
    }
    // Same check for arguments
    for arg in &rule.args {
        for ch in dangerous {
            if arg.contains(ch) {
                return Err(SysError::InvalidArgument(
                    format!(
                        "PAM argument contains dangerous character '{}': {}",
                        ch, arg
                    )
                    .into(),
                ));
            }
        }
    }
    Ok(())
}

/// Get the filesystem path for a PAM service config file.
#[must_use]
pub fn get_pam_service_path(service: &PamService) -> PathBuf {
    PathBuf::from(format!("/etc/pam.d/{}", service.as_str()))
}

// ---------------------------------------------------------------------------
// System-interacting functions (Linux only)
// ---------------------------------------------------------------------------

/// Retrieve information about a user by name.
///
/// Reads `/etc/passwd` for basic fields, then runs `id -Gn <username>` to
/// resolve group memberships.
#[cfg(target_os = "linux")]
pub fn get_user_info(username: &str) -> Result<UserInfo> {
    validate_username(username)?;

    let passwd_content = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| SysError::Unknown(format!("Failed to read /etc/passwd: {}", e).into()))?;

    let mut info = passwd_content
        .lines()
        .find(|line| line.split(':').next() == Some(username))
        .ok_or_else(|| SysError::InvalidArgument(format!("User not found: {}", username).into()))
        .and_then(parse_passwd_line)?;

    // Resolve groups via `id`
    let output = std::process::Command::new("id")
        .args(["-Gn", username])
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to run id: {}", e).into()))?;

    if output.status.success() {
        let groups_str = String::from_utf8_lossy(&output.stdout);
        info.groups = groups_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
    }

    Ok(info)
}

/// Retrieve information about a user by name.
///
/// Reads `/etc/passwd` for basic fields, then runs `id -Gn <username>` to
/// resolve group memberships.
#[cfg(not(target_os = "linux"))]
pub fn get_user_info(_username: &str) -> Result<UserInfo> {
    Err(SysError::NotSupported {
        feature: "pam".into(),
    })
}

/// List all users from `/etc/passwd`.
#[cfg(target_os = "linux")]
pub fn list_users() -> Result<Vec<UserInfo>> {
    let passwd_content = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| SysError::Unknown(format!("Failed to read /etc/passwd: {}", e).into()))?;

    let mut users = Vec::with_capacity(passwd_content.lines().count());
    for line in passwd_content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_passwd_line(line) {
            Ok(info) => users.push(info),
            Err(_) => continue, // skip malformed lines
        }
    }
    Ok(users)
}

/// List all users from `/etc/passwd`.
#[cfg(not(target_os = "linux"))]
pub fn list_users() -> Result<Vec<UserInfo>> {
    Err(SysError::NotSupported {
        feature: "pam".into(),
    })
}

/// List active login sessions by parsing `who` output.
#[cfg(target_os = "linux")]
pub fn list_sessions() -> Result<Vec<SessionInfo>> {
    let output = std::process::Command::new("who")
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to run who: {}", e).into()))?;

    if !output.status.success() {
        return Err(SysError::Unknown(
            format!("who exited with status {}", output.status).into(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_who_output(&stdout))
}

/// List active login sessions by parsing `who` output.
#[cfg(not(target_os = "linux"))]
pub fn list_sessions() -> Result<Vec<SessionInfo>> {
    Err(SysError::NotSupported {
        feature: "pam".into(),
    })
}

/// Create a system user with `useradd --system`.
#[cfg(target_os = "linux")]
pub fn create_system_user(username: &str, home_dir: Option<&Path>) -> Result<()> {
    validate_username(username)?;

    let mut cmd = std::process::Command::new("useradd");
    cmd.arg("--system");
    if let Some(home) = home_dir {
        cmd.args(["--home-dir", &home.to_string_lossy()]);
        cmd.arg("--create-home");
    }
    cmd.arg(username);

    let output = cmd
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to run useradd: {}", e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SysError::Unknown(
            format!("useradd failed (exit {}): {}", output.status, stderr).into(),
        ));
    }
    Ok(())
}

/// Create a system user with `useradd --system`.
#[cfg(not(target_os = "linux"))]
pub fn create_system_user(_username: &str, _home_dir: Option<&Path>) -> Result<()> {
    Err(SysError::NotSupported {
        feature: "pam".into(),
    })
}

/// Delete a user with `userdel`.
#[cfg(target_os = "linux")]
pub fn delete_user(username: &str) -> Result<()> {
    validate_username(username)?;

    let output = std::process::Command::new("userdel")
        .arg(username)
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to run userdel: {}", e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SysError::Unknown(
            format!("userdel failed (exit {}): {}", output.status, stderr).into(),
        ));
    }
    Ok(())
}

/// Delete a user with `userdel`.
#[cfg(not(target_os = "linux"))]
pub fn delete_user(_username: &str) -> Result<()> {
    Err(SysError::NotSupported {
        feature: "pam".into(),
    })
}

/// Add a user to a group with `usermod -aG`.
#[cfg(target_os = "linux")]
pub fn add_user_to_group(username: &str, group: &str) -> Result<()> {
    validate_username(username)?;
    // Validate group name with same rules
    validate_username(group)
        .map_err(|_| SysError::InvalidArgument(format!("Invalid group name: {}", group).into()))?;

    let output = std::process::Command::new("usermod")
        .args(["-aG", group, username])
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to run usermod: {}", e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SysError::Unknown(
            format!("usermod failed (exit {}): {}", output.status, stderr).into(),
        ));
    }
    Ok(())
}

/// Add a user to a group with `usermod -aG`.
#[cfg(not(target_os = "linux"))]
pub fn add_user_to_group(_username: &str, _group: &str) -> Result<()> {
    Err(SysError::NotSupported {
        feature: "pam".into(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Username validation ------------------------------------------------

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("agnos").is_ok());
        assert!(validate_username("_system").is_ok());
        assert!(validate_username("user-01").is_ok());
        assert!(validate_username("a").is_ok());
        assert!(validate_username("abc_def-123").is_ok());
    }

    #[test]
    fn test_validate_username_empty() {
        let err = validate_username("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_validate_username_too_long() {
        let long = "a".repeat(33);
        let err = validate_username(&long).unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn test_validate_username_starts_with_digit() {
        let err = validate_username("1user").unwrap_err();
        assert!(err.to_string().contains("must start with"));
    }

    #[test]
    fn test_validate_username_uppercase() {
        let err = validate_username("Root").unwrap_err();
        assert!(err.to_string().contains("must start with"));
    }

    #[test]
    fn test_validate_username_shell_metachar() {
        assert!(validate_username("user;rm").is_err());
        assert!(validate_username("user$HOME").is_err());
        assert!(validate_username("user`id`").is_err());
    }

    #[test]
    fn test_validate_username_max_length_exact() {
        let name = "a".repeat(32);
        assert!(validate_username(&name).is_ok());
    }

    // -- Passwd parsing -----------------------------------------------------

    #[test]
    fn test_parse_passwd_line_root() {
        let line = "root:x:0:0:root:/root:/bin/bash";
        let info = parse_passwd_line(line).unwrap();
        assert_eq!(info.username, "root");
        assert_eq!(info.uid, 0);
        assert_eq!(info.gid, 0);
        assert_eq!(info.home_dir, PathBuf::from("/root"));
        assert_eq!(info.shell, "/bin/bash");
        assert!(info.is_system_user);
        assert!(info.groups.is_empty());
    }

    #[test]
    fn test_parse_passwd_line_regular_user() {
        let line = "agnos:x:1000:1000:AGNOS User:/home/agnos:/bin/zsh";
        let info = parse_passwd_line(line).unwrap();
        assert_eq!(info.username, "agnos");
        assert_eq!(info.uid, 1000);
        assert_eq!(info.gid, 1000);
        assert_eq!(info.home_dir, PathBuf::from("/home/agnos"));
        assert_eq!(info.shell, "/bin/zsh");
        assert!(!info.is_system_user);
    }

    #[test]
    fn test_parse_passwd_line_system_user() {
        let line = "daemon:x:2:2:daemon:/usr/sbin:/usr/sbin/nologin";
        let info = parse_passwd_line(line).unwrap();
        assert!(info.is_system_user);
    }

    #[test]
    fn test_parse_passwd_line_malformed_too_few_fields() {
        let line = "badline:x:1000";
        let err = parse_passwd_line(line).unwrap_err();
        assert!(err.to_string().contains("Malformed"));
    }

    #[test]
    fn test_parse_passwd_line_invalid_uid() {
        let line = "user:x:notanumber:1000::/home/user:/bin/sh";
        let err = parse_passwd_line(line).unwrap_err();
        assert!(err.to_string().contains("Invalid UID"));
    }

    #[test]
    fn test_parse_passwd_line_invalid_gid() {
        let line = "user:x:1000:bad::/home/user:/bin/sh";
        let err = parse_passwd_line(line).unwrap_err();
        assert!(err.to_string().contains("Invalid GID"));
    }

    // -- Who output parsing -------------------------------------------------

    #[test]
    fn test_parse_who_output_basic() {
        let output = "alice    pts/0        2026-03-06 10:30 (192.168.1.5)\nbob      tty1         2026-03-06 09:15\n";
        let sessions = parse_who_output(output);
        assert_eq!(sessions.len(), 2);

        assert_eq!(sessions[0].user, "alice");
        assert_eq!(sessions[0].tty, Some("pts/0".to_string()));
        assert_eq!(sessions[0].login_time, "2026-03-06 10:30");
        assert_eq!(sessions[0].remote_host, Some("192.168.1.5".to_string()));

        assert_eq!(sessions[1].user, "bob");
        assert_eq!(sessions[1].tty, Some("tty1".to_string()));
        assert!(sessions[1].remote_host.is_none());
    }

    #[test]
    fn test_parse_who_output_empty() {
        let sessions = parse_who_output("");
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_parse_who_output_blank_lines() {
        let output = "\n   \n\n";
        let sessions = parse_who_output(output);
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_parse_who_session_ids_are_unique() {
        let output = "a pts/0 2026-01-01 00:00\nb pts/1 2026-01-01 00:01\n";
        let sessions = parse_who_output(output);
        assert_ne!(sessions[0].session_id, sessions[1].session_id);
    }

    // -- PAM config parsing / rendering -------------------------------------

    #[test]
    fn test_parse_pam_config_basic() {
        let content =
            "# PAM config\nauth\trequired\tpam_unix.so\naccount\tsufficient\tpam_permit.so\n";
        let rules = parse_pam_config(content).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].rule_type, PamRuleType::Auth);
        assert_eq!(rules[0].control, PamControl::Required);
        assert_eq!(rules[0].module, "pam_unix.so");
        assert!(rules[0].args.is_empty());
        assert_eq!(rules[1].rule_type, PamRuleType::Account);
        assert_eq!(rules[1].control, PamControl::Sufficient);
    }

    #[test]
    fn test_parse_pam_config_with_args() {
        let content = "session\toptional\tpam_limits.so\tconf=/etc/limits.conf\n";
        let rules = parse_pam_config(content).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].args, vec!["conf=/etc/limits.conf"]);
    }

    #[test]
    fn test_parse_pam_config_skips_comments_and_blanks() {
        let content = "# comment\n\n   \n# another comment\nauth required pam_deny.so\n";
        let rules = parse_pam_config(content).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn test_parse_pam_config_malformed_line() {
        let content = "auth required\n"; // missing module
        let err = parse_pam_config(content).unwrap_err();
        assert!(err.to_string().contains("Malformed"));
    }

    #[test]
    fn test_parse_pam_config_unknown_type() {
        let content = "badtype required pam_unix.so\n";
        let err = parse_pam_config(content).unwrap_err();
        assert!(err.to_string().contains("Unknown PAM rule type"));
    }

    #[test]
    fn test_parse_pam_config_unknown_control() {
        let content = "auth badcontrol pam_unix.so\n";
        let err = parse_pam_config(content).unwrap_err();
        assert!(err.to_string().contains("Unknown PAM control flag"));
    }

    #[test]
    fn test_render_pam_config_roundtrip() {
        let rules = vec![
            PamRule {
                rule_type: PamRuleType::Auth,
                control: PamControl::Required,
                module: "pam_unix.so".to_string(),
                args: vec![],
            },
            PamRule {
                rule_type: PamRuleType::Session,
                control: PamControl::Optional,
                module: "pam_systemd.so".to_string(),
                args: vec!["kill-session-processes=1".to_string()],
            },
        ];
        let rendered = render_pam_config(&rules);
        let parsed_back = parse_pam_config(&rendered).unwrap();
        assert_eq!(parsed_back.len(), 2);
        assert_eq!(parsed_back[0].module, "pam_unix.so");
        assert_eq!(parsed_back[1].module, "pam_systemd.so");
        assert_eq!(parsed_back[1].args, vec!["kill-session-processes=1"]);
    }

    // -- PAM rule validation ------------------------------------------------

    #[test]
    fn test_validate_pam_rule_ok() {
        let rule = PamRule {
            rule_type: PamRuleType::Auth,
            control: PamControl::Required,
            module: "pam_unix.so".to_string(),
            args: vec!["try_first_pass".to_string()],
        };
        assert!(validate_pam_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_pam_rule_empty_module() {
        let rule = PamRule {
            rule_type: PamRuleType::Auth,
            control: PamControl::Required,
            module: String::new(),
            args: vec![],
        };
        let err = validate_pam_rule(&rule).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_validate_pam_rule_dotdot_module() {
        let rule = PamRule {
            rule_type: PamRuleType::Auth,
            control: PamControl::Required,
            module: "/etc/../evil.so".to_string(),
            args: vec![],
        };
        assert!(validate_pam_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_pam_rule_dangerous_chars() {
        for ch in ['|', ';', '&', '$', '`', '>', '<'] {
            let rule = PamRule {
                rule_type: PamRuleType::Auth,
                control: PamControl::Required,
                module: format!("pam_evil{}so", ch),
                args: vec![],
            };
            assert!(
                validate_pam_rule(&rule).is_err(),
                "Should reject '{}' in module",
                ch
            );
        }
    }

    #[test]
    fn test_validate_pam_rule_dangerous_arg() {
        let rule = PamRule {
            rule_type: PamRuleType::Auth,
            control: PamControl::Required,
            module: "pam_unix.so".to_string(),
            args: vec!["arg;evil".to_string()],
        };
        assert!(validate_pam_rule(&rule).is_err());
    }

    // -- Service paths ------------------------------------------------------

    #[test]
    fn test_get_pam_service_path_builtins() {
        assert_eq!(
            get_pam_service_path(&PamService::Login),
            PathBuf::from("/etc/pam.d/login")
        );
        assert_eq!(
            get_pam_service_path(&PamService::Sudo),
            PathBuf::from("/etc/pam.d/sudo")
        );
        assert_eq!(
            get_pam_service_path(&PamService::Sshd),
            PathBuf::from("/etc/pam.d/sshd")
        );
        assert_eq!(
            get_pam_service_path(&PamService::AgnosAgent),
            PathBuf::from("/etc/pam.d/agnos-agent")
        );
    }

    #[test]
    fn test_get_pam_service_path_custom() {
        assert_eq!(
            get_pam_service_path(&PamService::Custom("myservice".to_string())),
            PathBuf::from("/etc/pam.d/myservice")
        );
    }

    // -- Display impls ------------------------------------------------------

    #[test]
    fn test_auth_result_display() {
        assert_eq!(AuthResult::Success.to_string(), "Authentication successful");
        assert!(
            AuthResult::Denied("bad password".into())
                .to_string()
                .contains("bad password")
        );
        assert!(AuthResult::AccountExpired.to_string().contains("expired"));
        assert!(AuthResult::PasswordExpired.to_string().contains("expired"));
        assert!(
            AuthResult::SessionError("oops".into())
                .to_string()
                .contains("oops")
        );
        assert!(AuthResult::Unknown(42).to_string().contains("42"));
    }

    #[test]
    fn test_pam_service_display() {
        assert_eq!(PamService::Login.to_string(), "login");
        assert_eq!(PamService::AgnosAgent.to_string(), "agnos-agent");
        assert_eq!(
            PamService::Custom("my-svc".to_string()).to_string(),
            "my-svc"
        );
    }

    #[test]
    fn test_pam_rule_type_display() {
        assert_eq!(PamRuleType::Auth.to_string(), "auth");
        assert_eq!(PamRuleType::Account.to_string(), "account");
        assert_eq!(PamRuleType::Session.to_string(), "session");
        assert_eq!(PamRuleType::Password.to_string(), "password");
    }

    #[test]
    fn test_pam_control_display() {
        assert_eq!(PamControl::Required.to_string(), "required");
        assert_eq!(PamControl::Requisite.to_string(), "requisite");
        assert_eq!(PamControl::Sufficient.to_string(), "sufficient");
        assert_eq!(PamControl::Optional.to_string(), "optional");
        assert_eq!(PamControl::Include.to_string(), "include");
    }

    // -- Serialization roundtrip --------------------------------------------

    #[test]
    fn test_user_info_serde_roundtrip() {
        let info = UserInfo {
            username: "agnos".to_string(),
            uid: 1000,
            gid: 1000,
            home_dir: PathBuf::from("/home/agnos"),
            shell: "/bin/bash".to_string(),
            groups: vec!["wheel".to_string(), "docker".to_string()],
            is_system_user: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: UserInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, deserialized);
    }

    #[test]
    fn test_session_info_serde_roundtrip() {
        let info = SessionInfo {
            session_id: "sess-1".to_string(),
            user: "root".to_string(),
            login_time: "2026-03-06 10:00".to_string(),
            tty: Some("pts/0".to_string()),
            remote_host: None,
            pid: 1234,
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: SessionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, deserialized);
    }

    #[test]
    fn test_pam_rule_display() {
        let rule = PamRule {
            rule_type: PamRuleType::Auth,
            control: PamControl::Required,
            module: "pam_unix.so".to_string(),
            args: vec!["try_first_pass".to_string()],
        };
        let display = rule.to_string();
        assert!(display.contains("auth"));
        assert!(display.contains("required"));
        assert!(display.contains("pam_unix.so"));
        assert!(display.contains("try_first_pass"));
    }

    #[test]
    fn test_validate_pam_rule_absolute_path_ok() {
        let rule = PamRule {
            rule_type: PamRuleType::Auth,
            control: PamControl::Required,
            module: "/lib/security/pam_unix.so".to_string(),
            args: vec![],
        };
        assert!(validate_pam_rule(&rule).is_ok());
    }

    #[test]
    fn test_parse_passwd_line_nologin_shell() {
        let line = "sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/usr/sbin/nologin";
        let info = parse_passwd_line(line).unwrap();
        assert_eq!(info.shell, "/usr/sbin/nologin");
        assert!(info.is_system_user); // UID 74 < 1000
    }

    // --- Audit coverage additions ---

    // -- Username validation edge cases --

    #[test]
    fn test_validate_username_starts_with_underscore() {
        assert!(validate_username("_backup").is_ok());
    }

    #[test]
    fn test_validate_username_only_underscore() {
        assert!(validate_username("_").is_ok());
    }

    #[test]
    fn test_validate_username_all_digits_after_start() {
        assert!(validate_username("a123456789").is_ok());
    }

    #[test]
    fn test_validate_username_hyphen_start() {
        let err = validate_username("-user").unwrap_err();
        assert!(err.to_string().contains("must start with"));
    }

    #[test]
    fn test_validate_username_dot_rejected() {
        let err = validate_username("user.name").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn test_validate_username_space_rejected() {
        let err = validate_username("user name").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn test_validate_username_newline_rejected() {
        let err = validate_username("user\nname").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn test_validate_username_null_byte_rejected() {
        let err = validate_username("user\0name").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn test_validate_username_exactly_33_chars() {
        let name = "a".repeat(33);
        let err = validate_username(&name).unwrap_err();
        assert!(err.to_string().contains("too long"));
        assert!(err.to_string().contains("33"));
    }

    #[test]
    fn test_validate_username_uppercase_middle() {
        let err = validate_username("aUser").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn test_validate_username_starts_with_uppercase_underscore_ok() {
        // Starts with underscore is OK even if rest has digits/hyphens
        assert!(validate_username("_a-1").is_ok());
    }

    // -- Passwd parsing edge cases --

    #[test]
    fn test_parse_passwd_line_uid_boundary_999() {
        let line = "svc:x:999:999::/home/svc:/bin/sh";
        let info = parse_passwd_line(line).unwrap();
        assert!(info.is_system_user); // 999 < 1000
    }

    #[test]
    fn test_parse_passwd_line_uid_boundary_1000() {
        let line = "user:x:1000:1000::/home/user:/bin/sh";
        let info = parse_passwd_line(line).unwrap();
        assert!(!info.is_system_user); // 1000 is NOT system
    }

    #[test]
    fn test_parse_passwd_line_uid_zero() {
        let line = "root:x:0:0:root:/root:/bin/bash";
        let info = parse_passwd_line(line).unwrap();
        assert!(info.is_system_user);
        assert_eq!(info.uid, 0);
    }

    #[test]
    fn test_parse_passwd_line_large_uid() {
        let line = "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin";
        let info = parse_passwd_line(line).unwrap();
        assert_eq!(info.uid, 65534);
        assert!(!info.is_system_user); // 65534 >= 1000
    }

    #[test]
    fn test_parse_passwd_line_empty_gecos() {
        let line = "testuser:x:1001:1001::/home/testuser:/bin/bash";
        let info = parse_passwd_line(line).unwrap();
        assert_eq!(info.username, "testuser");
    }

    #[test]
    fn test_parse_passwd_line_extra_colons() {
        // More than 7 fields should still work (extra fields ignored)
        let line = "user:x:1000:1000:gecos:/home/user:/bin/sh:extra:fields";
        let info = parse_passwd_line(line).unwrap();
        assert_eq!(info.username, "user");
        assert_eq!(info.shell, "/bin/sh");
    }

    #[test]
    fn test_parse_passwd_line_empty_string() {
        let err = parse_passwd_line("").unwrap_err();
        assert!(err.to_string().contains("Malformed"));
    }

    #[test]
    fn test_parse_passwd_line_six_fields() {
        let err = parse_passwd_line("a:b:1:2:c:d").unwrap_err();
        assert!(err.to_string().contains("expected 7"));
    }

    #[test]
    fn test_parse_passwd_line_negative_uid() {
        let line = "user:x:-1:1000::/home/user:/bin/sh";
        let err = parse_passwd_line(line).unwrap_err();
        assert!(err.to_string().contains("Invalid UID"));
    }

    #[test]
    fn test_parse_passwd_line_uid_overflow() {
        let line = "user:x:99999999999:1000::/home/user:/bin/sh";
        let err = parse_passwd_line(line).unwrap_err();
        assert!(err.to_string().contains("Invalid UID"));
    }

    #[test]
    fn test_parse_passwd_line_gid_non_numeric() {
        let line = "user:x:1000:abc::/home/user:/bin/sh";
        let err = parse_passwd_line(line).unwrap_err();
        assert!(err.to_string().contains("Invalid GID"));
    }

    // -- Who output parsing edge cases --

    #[test]
    fn test_parse_who_output_short_line_two_fields() {
        // Lines with fewer than 3 fields are skipped
        let output = "onlyuser pts/0\n";
        let sessions = parse_who_output(output);
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_parse_who_output_one_field() {
        let output = "onlyuser\n";
        let sessions = parse_who_output(output);
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_parse_who_output_three_fields_no_time() {
        // Exactly 3 fields: user tty date (no time)
        let output = "alice pts/0 2026-03-06\n";
        let sessions = parse_who_output(output);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].user, "alice");
        assert_eq!(sessions[0].login_time, "2026-03-06");
        assert!(sessions[0].remote_host.is_none());
    }

    #[test]
    fn test_parse_who_output_remote_host_parsing() {
        let output = "alice pts/0 2026-03-06 10:30 (10.0.0.1)\n";
        let sessions = parse_who_output(output);
        assert_eq!(sessions[0].remote_host, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_parse_who_output_no_parens_last_field() {
        // Last field is not in parens, so no remote host
        let output = "bob tty1 2026-03-06 09:15\n";
        let sessions = parse_who_output(output);
        assert!(sessions[0].remote_host.is_none());
    }

    #[test]
    fn test_parse_who_output_session_id_format() {
        let output = "alice pts/0 2026-03-06 10:30\n";
        let sessions = parse_who_output(output);
        assert_eq!(sessions[0].session_id, "who-0");
    }

    #[test]
    fn test_parse_who_output_pid_is_zero() {
        // `who` doesn't report PID, so it should always be 0
        let output = "alice pts/0 2026-03-06 10:30\n";
        let sessions = parse_who_output(output);
        assert_eq!(sessions[0].pid, 0);
    }

    #[test]
    fn test_parse_who_output_mixed_valid_and_blank() {
        let output = "alice pts/0 2026-03-06 10:30\n\n  \nbob tty1 2026-03-06 09:15\n\n";
        let sessions = parse_who_output(output);
        assert_eq!(sessions.len(), 2);
    }

    // -- PAM config parsing edge cases --

    #[test]
    fn test_parse_pam_config_empty_string() {
        let rules = parse_pam_config("").unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_parse_pam_config_only_comments() {
        let rules = parse_pam_config("# comment 1\n# comment 2\n").unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_parse_pam_config_only_whitespace() {
        let rules = parse_pam_config("   \n\t\n  \n").unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_parse_pam_config_password_rule_type() {
        let content = "password requisite pam_pwquality.so retry=3\n";
        let rules = parse_pam_config(content).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_type, PamRuleType::Password);
        assert_eq!(rules[0].control, PamControl::Requisite);
        assert_eq!(rules[0].args, vec!["retry=3"]);
    }

    #[test]
    fn test_parse_pam_config_include_control() {
        let content = "auth include system-auth\n";
        let rules = parse_pam_config(content).unwrap();
        assert_eq!(rules[0].control, PamControl::Include);
    }

    #[test]
    fn test_parse_pam_config_multiple_args() {
        let content = "auth required pam_unix.so try_first_pass nullok audit\n";
        let rules = parse_pam_config(content).unwrap();
        assert_eq!(rules[0].args, vec!["try_first_pass", "nullok", "audit"]);
    }

    #[test]
    fn test_parse_pam_config_tabs_and_spaces() {
        let content = "auth\t\trequired\t\tpam_unix.so\ttry_first_pass\n";
        let rules = parse_pam_config(content).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].module, "pam_unix.so");
    }

    #[test]
    fn test_parse_pam_config_single_word_line() {
        let err = parse_pam_config("badline\n").unwrap_err();
        assert!(err.to_string().contains("Malformed"));
    }

    // -- PAM rule validation edge cases --

    #[test]
    fn test_validate_pam_rule_module_with_dotdot_in_name() {
        // ".." embedded in name like "pam_..so" should be rejected
        let rule = PamRule {
            rule_type: PamRuleType::Auth,
            control: PamControl::Required,
            module: "pam_..so".to_string(),
            args: vec![],
        };
        assert!(validate_pam_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_pam_rule_exclamation_in_module() {
        let rule = PamRule {
            rule_type: PamRuleType::Auth,
            control: PamControl::Required,
            module: "pam_unix!.so".to_string(),
            args: vec![],
        };
        assert!(validate_pam_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_pam_rule_braces_in_module() {
        let rule = PamRule {
            rule_type: PamRuleType::Auth,
            control: PamControl::Required,
            module: "pam_{evil}.so".to_string(),
            args: vec![],
        };
        assert!(validate_pam_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_pam_rule_dangerous_chars_in_arg() {
        for ch in ['|', ';', '&', '$', '`', '>', '<', '!', '{', '}'] {
            let rule = PamRule {
                rule_type: PamRuleType::Auth,
                control: PamControl::Required,
                module: "pam_unix.so".to_string(),
                args: vec![format!("arg{}val", ch)],
            };
            assert!(
                validate_pam_rule(&rule).is_err(),
                "Should reject '{}' in arg",
                ch
            );
        }
    }

    #[test]
    fn test_validate_pam_rule_multiple_args_second_bad() {
        let rule = PamRule {
            rule_type: PamRuleType::Auth,
            control: PamControl::Required,
            module: "pam_unix.so".to_string(),
            args: vec!["good_arg".to_string(), "bad;arg".to_string()],
        };
        assert!(validate_pam_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_pam_rule_no_args_ok() {
        let rule = PamRule {
            rule_type: PamRuleType::Session,
            control: PamControl::Optional,
            module: "pam_systemd.so".to_string(),
            args: vec![],
        };
        assert!(validate_pam_rule(&rule).is_ok());
    }

    // -- render_pam_config --

    #[test]
    fn test_render_pam_config_empty_rules() {
        let rendered = render_pam_config(&[]);
        assert!(rendered.starts_with("# Generated by AGNOS"));
        // Only the header line, no rule lines
        assert_eq!(rendered.lines().count(), 1);
    }

    #[test]
    fn test_render_pam_config_header() {
        let rules = vec![PamRule {
            rule_type: PamRuleType::Auth,
            control: PamControl::Required,
            module: "pam_unix.so".to_string(),
            args: vec![],
        }];
        let rendered = render_pam_config(&rules);
        assert!(rendered.starts_with("# Generated by AGNOS PAM manager\n"));
    }

    // -- PamRule Display --

    #[test]
    fn test_pam_rule_display_no_args() {
        let rule = PamRule {
            rule_type: PamRuleType::Account,
            control: PamControl::Sufficient,
            module: "pam_permit.so".to_string(),
            args: vec![],
        };
        let s = rule.to_string();
        assert!(s.contains("account"));
        assert!(s.contains("sufficient"));
        assert!(s.contains("pam_permit.so"));
    }

    #[test]
    fn test_pam_rule_display_multiple_args() {
        let rule = PamRule {
            rule_type: PamRuleType::Password,
            control: PamControl::Requisite,
            module: "pam_pwquality.so".to_string(),
            args: vec!["retry=3".to_string(), "minlen=8".to_string()],
        };
        let s = rule.to_string();
        assert!(s.contains("retry=3"));
        assert!(s.contains("minlen=8"));
    }

    // -- PamService --

    #[test]
    fn test_pam_service_sshd_name() {
        assert_eq!(PamService::Sshd.as_str(), "sshd");
    }

    #[test]
    fn test_pam_service_custom_empty() {
        let svc = PamService::Custom(String::new());
        assert_eq!(svc.as_str(), "");
    }

    #[test]
    fn test_pam_service_eq() {
        assert_eq!(PamService::Login, PamService::Login);
        assert_ne!(PamService::Login, PamService::Sudo);
        assert_eq!(
            PamService::Custom("x".into()),
            PamService::Custom("x".into())
        );
        assert_ne!(
            PamService::Custom("x".into()),
            PamService::Custom("y".into())
        );
    }

    // -- PamConfig --

    #[test]
    fn test_pam_config_serde_roundtrip() {
        let config = PamConfig {
            service: PamService::AgnosAgent,
            rules: vec![PamRule {
                rule_type: PamRuleType::Auth,
                control: PamControl::Required,
                module: "pam_unix.so".to_string(),
                args: vec!["try_first_pass".to_string()],
            }],
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: PamConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.service, PamService::AgnosAgent);
        assert_eq!(back.rules.len(), 1);
        assert_eq!(back.rules[0].module, "pam_unix.so");
    }

    // -- AuthResult --

    #[test]
    fn test_auth_result_serde_roundtrip() {
        let variants = vec![
            AuthResult::Success,
            AuthResult::Denied("bad pw".into()),
            AuthResult::AccountExpired,
            AuthResult::PasswordExpired,
            AuthResult::SessionError("session fail".into()),
            AuthResult::Unknown(-7),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: AuthResult = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn test_auth_result_eq() {
        assert_eq!(AuthResult::Success, AuthResult::Success);
        assert_ne!(AuthResult::Success, AuthResult::AccountExpired);
        assert_eq!(
            AuthResult::Denied("x".into()),
            AuthResult::Denied("x".into())
        );
        assert_ne!(
            AuthResult::Denied("x".into()),
            AuthResult::Denied("y".into())
        );
        assert_eq!(AuthResult::Unknown(0), AuthResult::Unknown(0));
        assert_ne!(AuthResult::Unknown(0), AuthResult::Unknown(1));
    }

    // -- UserInfo --

    #[test]
    fn test_user_info_detect_system_user_boundary() {
        assert!(UserInfo::detect_system_user(0));
        assert!(UserInfo::detect_system_user(999));
        assert!(!UserInfo::detect_system_user(1000));
        assert!(!UserInfo::detect_system_user(65534));
    }

    #[test]
    fn test_user_info_debug() {
        let info = UserInfo {
            username: "test".to_string(),
            uid: 1000,
            gid: 1000,
            home_dir: PathBuf::from("/home/test"),
            shell: "/bin/sh".to_string(),
            groups: vec![],
            is_system_user: false,
        };
        let dbg = format!("{:?}", info);
        assert!(dbg.contains("UserInfo"));
        assert!(dbg.contains("test"));
    }

    // -- SessionInfo --

    #[test]
    fn test_session_info_with_remote_host() {
        let info = SessionInfo {
            session_id: "s1".to_string(),
            user: "alice".to_string(),
            login_time: "2026-01-01 00:00".to_string(),
            tty: Some("pts/0".to_string()),
            remote_host: Some("10.0.0.1".to_string()),
            pid: 42,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: SessionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.remote_host, Some("10.0.0.1".to_string()));
        assert_eq!(back.pid, 42);
    }

    #[test]
    fn test_session_info_without_tty_and_remote() {
        let info = SessionInfo {
            session_id: "s2".to_string(),
            user: "bob".to_string(),
            login_time: "2026-01-01".to_string(),
            tty: None,
            remote_host: None,
            pid: 0,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: SessionInfo = serde_json::from_str(&json).unwrap();
        assert!(back.tty.is_none());
        assert!(back.remote_host.is_none());
    }

    // -- PamRuleType from_str edge cases --

    #[test]
    fn test_pam_rule_type_from_str_case_sensitive() {
        // Should reject uppercase
        assert!(PamRuleType::from_str("Auth").is_err());
        assert!(PamRuleType::from_str("AUTH").is_err());
        assert!(PamRuleType::from_str("SESSION").is_err());
    }

    // -- PamControl from_str edge cases --

    #[test]
    fn test_pam_control_from_str_case_sensitive() {
        assert!(PamControl::from_str("Required").is_err());
        assert!(PamControl::from_str("REQUIRED").is_err());
    }

    #[test]
    fn test_pam_control_from_str_empty() {
        let err = PamControl::from_str("").unwrap_err();
        assert!(err.to_string().contains("Unknown PAM control flag"));
    }

    #[test]
    fn test_pam_rule_type_from_str_empty() {
        let err = PamRuleType::from_str("").unwrap_err();
        assert!(err.to_string().contains("Unknown PAM rule type"));
    }
}
