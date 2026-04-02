//! Per-Agent Network Namespace Interface
//!
//! Creates isolated network namespaces with veth pairs for AGNOS agents.
//! Shells out to `ip` (standard practice — avoids ~1000 LOC of raw netlink code).
//!
//! Firewall policy (nftables rule generation) is handled by the `nein` crate.
//! Use [`apply_nftables_ruleset`] to apply a pre-rendered ruleset (from nein)
//! inside a namespace.
//!
//! On non-Linux platforms, all operations return `SysError::NotSupported`.
//!
//! # Security Considerations
//!
//! - Network namespace creation requires `CAP_SYS_ADMIN` (or root). The `ip`
//!   commands run as subprocesses with inherited privileges.
//! - Veth pairs bridge the namespace to the host network — misconfigured
//!   routing or missing firewall rules can leak traffic between namespaces.
//! - `nft` is invoked as a subprocess to apply firewall rulesets; callers
//!   must supply pre-validated rulesets (from the `nein` crate) to prevent
//!   rule injection.
//! - Agent IP addresses and namespace names are not secrets but may reveal
//!   internal network topology.

use crate::error::{Result, SysError};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Configuration for creating a per-agent network namespace.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetNamespaceConfig {
    /// Agent identifier (used for naming)
    pub name: String,
    /// IP address assigned to the agent side of the veth pair
    pub agent_ip: String,
    /// IP address assigned to the host side of the veth pair
    pub host_ip: String,
    /// CIDR prefix length (typically 30 for a /30 point-to-point link)
    pub prefix_len: u8,
    /// Whether to enable NAT (masquerade) for outbound traffic
    pub enable_nat: bool,
    /// DNS servers to configure inside the namespace
    pub dns_servers: Vec<String>,
}

impl NetNamespaceConfig {
    /// Create a config with auto-generated IPs based on the agent name hash.
    pub fn for_agent(name: impl Into<String>) -> Self {
        let name = name.into();
        let (host_ip, agent_ip) = generate_agent_ips(&name);
        Self {
            name,
            agent_ip,
            host_ip,
            prefix_len: 30,
            enable_nat: true,
            dns_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(SysError::InvalidArgument(
                "Namespace name cannot be empty".into(),
            ));
        }
        if self.name.len() > 64 {
            return Err(SysError::InvalidArgument(
                "Namespace name too long (max 64)".into(),
            ));
        }
        if self.agent_ip.is_empty() || self.host_ip.is_empty() {
            return Err(SysError::InvalidArgument(
                "IP addresses cannot be empty".into(),
            ));
        }
        if self.prefix_len == 0 || self.prefix_len > 32 {
            return Err(SysError::InvalidArgument(
                format!("Invalid prefix length: {} (must be 1-32)", self.prefix_len).into(),
            ));
        }
        // Validate IPs are well-formed
        self.agent_ip.parse::<std::net::Ipv4Addr>().map_err(|_| {
            SysError::InvalidArgument(format!("Invalid agent IP: {}", self.agent_ip).into())
        })?;
        self.host_ip.parse::<std::net::Ipv4Addr>().map_err(|_| {
            SysError::InvalidArgument(format!("Invalid host IP: {}", self.host_ip).into())
        })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Firewall types — used by kavach to express policy, rendered to nftables.
// ---------------------------------------------------------------------------

/// Direction of network traffic relative to the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TrafficDirection {
    Inbound,
    Outbound,
}

/// Network protocol for firewall rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Protocol {
    Tcp,
    Udp,
    Any,
}

/// Firewall rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FirewallAction {
    Accept,
    Drop,
}

/// A single firewall rule for an agent's network namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FirewallRule {
    pub direction: TrafficDirection,
    pub protocol: Protocol,
    pub port: u16,
    pub remote_addr: String,
    pub action: FirewallAction,
    pub comment: String,
}

impl FirewallRule {
    /// Create a new firewall rule.
    pub fn new(
        direction: TrafficDirection,
        protocol: Protocol,
        port: u16,
        remote_addr: impl Into<String>,
        action: FirewallAction,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            direction,
            protocol,
            port,
            remote_addr: remote_addr.into(),
            action,
            comment: comment.into(),
        }
    }
}

/// Complete firewall policy for an agent namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FirewallPolicy {
    pub default_inbound: FirewallAction,
    pub default_outbound: FirewallAction,
    pub rules: Vec<FirewallRule>,
}

impl FirewallPolicy {
    /// Create a new firewall policy.
    pub fn new(
        default_inbound: FirewallAction,
        default_outbound: FirewallAction,
        rules: Vec<FirewallRule>,
    ) -> Self {
        Self {
            default_inbound,
            default_outbound,
            rules,
        }
    }
}

/// Render a [`FirewallPolicy`] as an nftables ruleset string.
#[must_use]
fn render_nftables_ruleset(policy: &FirewallPolicy) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "table inet kavach {{");

    // Input chain
    let in_policy = match policy.default_inbound {
        FirewallAction::Accept => "accept",
        FirewallAction::Drop => "drop",
    };
    let _ = writeln!(
        out,
        "  chain input {{ type filter hook input priority 0; policy {in_policy};"
    );
    let _ = writeln!(out, "    ct state established,related accept");
    let _ = writeln!(out, "    iif lo accept");
    for rule in &policy.rules {
        if rule.direction != TrafficDirection::Inbound {
            continue;
        }
        let action = match rule.action {
            FirewallAction::Accept => "accept",
            FirewallAction::Drop => "drop",
        };
        let proto = match rule.protocol {
            Protocol::Tcp => Some("tcp"),
            Protocol::Udp => Some("udp"),
            Protocol::Any => None,
        };
        if let Some(proto) = proto
            && rule.port > 0
        {
            let _ = writeln!(
                out,
                "    {proto} dport {port} {action} comment \"{comment}\"",
                port = rule.port,
                comment = rule.comment,
            );
        }
        if !rule.remote_addr.is_empty() {
            let _ = writeln!(
                out,
                "    ip saddr {addr} {action} comment \"{comment}\"",
                addr = rule.remote_addr,
                comment = rule.comment,
            );
        }
    }
    let _ = writeln!(out, "  }}");

    // Output chain
    let out_policy = match policy.default_outbound {
        FirewallAction::Accept => "accept",
        FirewallAction::Drop => "drop",
    };
    let _ = writeln!(
        out,
        "  chain output {{ type filter hook output priority 0; policy {out_policy};"
    );
    let _ = writeln!(out, "    ct state established,related accept");
    let _ = writeln!(out, "    oif lo accept");
    for rule in &policy.rules {
        if rule.direction != TrafficDirection::Outbound {
            continue;
        }
        let action = match rule.action {
            FirewallAction::Accept => "accept",
            FirewallAction::Drop => "drop",
        };
        let proto = match rule.protocol {
            Protocol::Tcp => Some("tcp"),
            Protocol::Udp => Some("udp"),
            Protocol::Any => None,
        };
        if let Some(proto) = proto
            && rule.port > 0
        {
            let _ = writeln!(
                out,
                "    {proto} dport {port} {action} comment \"{comment}\"",
                port = rule.port,
                comment = rule.comment,
            );
        }
        if !rule.remote_addr.is_empty() {
            let _ = writeln!(
                out,
                "    ip daddr {addr} {action} comment \"{comment}\"",
                addr = rule.remote_addr,
                comment = rule.comment,
            );
        }
    }
    let _ = writeln!(out, "  }}");
    let _ = writeln!(out, "}}");
    out
}

/// Apply a [`FirewallPolicy`] to an agent's network namespace.
///
/// Renders the policy to an nftables ruleset and applies it via
/// [`apply_nftables_ruleset`].
pub fn apply_firewall_rules(handle: &NetNamespaceHandle, policy: &FirewallPolicy) -> Result<()> {
    let ruleset = render_nftables_ruleset(policy);
    tracing::debug!(
        rules = policy.rules.len(),
        "Applying firewall policy to namespace '{}'",
        handle.name
    );
    apply_nftables_ruleset(handle, &ruleset)
}

/// Handle for an active network namespace.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetNamespaceHandle {
    /// Namespace name (`agnos-agent-{id}`)
    pub name: String,
    /// Host-side veth interface name
    pub veth_host: String,
    /// Agent-side veth interface name
    pub veth_agent: String,
    /// Path to the namespace (`/var/run/netns/agnos-agent-{id}`)
    pub netns_path: String,
}

/// Generate IP addresses for an agent based on a hash of its name.
///
/// Uses the 10.100.x.y/30 range. Returns (host_ip, agent_ip).
#[must_use]
pub fn generate_agent_ips(agent_name: &str) -> (String, String) {
    let mut hasher = DefaultHasher::new();
    agent_name.hash(&mut hasher);
    let hash = hasher.finish();
    let third_octet = (hash % 255) as u8;
    // Use .1 and .2 within a /30 block (base .0 is network, .3 is broadcast)
    (
        format!("10.100.{}.1", third_octet),
        format!("10.100.{}.2", third_octet),
    )
}

/// Truncate a veth interface name to the max allowed length (15 chars on Linux).
fn truncate_veth_name(base: &str) -> String {
    if base.len() > 15 {
        base[..15].to_string()
    } else {
        base.to_string()
    }
}

/// Create a network namespace for an agent with veth pair and IP configuration.
///
/// Steps:
/// 1. `ip netns add agnos-agent-{name}`
/// 2. `ip link add veth-{name}-h type veth peer name veth-{name}-a`
/// 3. Move agent-side veth into namespace
/// 4. Assign IPs to both sides
/// 5. Bring both interfaces up
///
/// Requires root or `CAP_NET_ADMIN`.
pub fn create_agent_netns(config: &NetNamespaceConfig) -> Result<NetNamespaceHandle> {
    #[cfg(target_os = "linux")]
    {
        config.validate()?;

        let ns_name = format!("agnos-agent-{}", config.name);
        let veth_host = truncate_veth_name(&format!("veth-{}-h", config.name));
        let veth_agent = truncate_veth_name(&format!("veth-{}-a", config.name));

        // 1. Create namespace
        run_ip_cmd(&["netns", "add", &ns_name])?;

        // 2. Create veth pair
        if let Err(e) = run_ip_cmd(&[
            "link",
            "add",
            &veth_host,
            "type",
            "veth",
            "peer",
            "name",
            &veth_agent,
        ]) {
            // Cleanup namespace on failure
            let _ = run_ip_cmd(&["netns", "delete", &ns_name]);
            return Err(e);
        }

        // 3. Move agent-side veth into namespace
        if let Err(e) = run_ip_cmd(&["link", "set", &veth_agent, "netns", &ns_name]) {
            let _ = run_ip_cmd(&["link", "delete", &veth_host]);
            let _ = run_ip_cmd(&["netns", "delete", &ns_name]);
            return Err(e);
        }

        // 4. Assign IPs
        let host_cidr = format!("{}/{}", config.host_ip, config.prefix_len);
        let agent_cidr = format!("{}/{}", config.agent_ip, config.prefix_len);

        if let Err(e) = run_ip_cmd(&["addr", "add", &host_cidr, "dev", &veth_host]) {
            let _ = cleanup_netns(&ns_name, &veth_host);
            return Err(e);
        }
        if let Err(e) =
            run_ip_netns_cmd(&ns_name, &["addr", "add", &agent_cidr, "dev", &veth_agent])
        {
            let _ = cleanup_netns(&ns_name, &veth_host);
            return Err(e);
        }

        // 5. Bring interfaces up
        if let Err(e) = run_ip_cmd(&["link", "set", &veth_host, "up"]) {
            tracing::warn!("Failed to bring up host veth {}: {}", veth_host, e);
        }
        if let Err(e) = run_ip_netns_cmd(&ns_name, &["link", "set", &veth_agent, "up"]) {
            tracing::warn!("Failed to bring up agent veth {}: {}", veth_agent, e);
        }
        if let Err(e) = run_ip_netns_cmd(&ns_name, &["link", "set", "lo", "up"]) {
            tracing::warn!("Failed to bring up loopback in {}: {}", ns_name, e);
        }

        // Set default route inside namespace
        if let Err(e) = run_ip_netns_cmd(
            &ns_name,
            &["route", "add", "default", "via", &config.host_ip],
        ) {
            tracing::warn!("Failed to set default route in {}: {}", ns_name, e);
        }

        // Enable NAT on host side if requested
        if config.enable_nat {
            if let Err(e) = run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]) {
                tracing::warn!("Failed to enable IP forwarding: {}", e);
            }
            if let Err(e) = run_cmd(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-s",
                    &format!("{}/{}", config.agent_ip, config.prefix_len),
                    "-j",
                    "MASQUERADE",
                ],
            ) {
                tracing::warn!("Failed to set up NAT masquerade: {}", e);
            }
        }

        let handle = NetNamespaceHandle {
            name: ns_name.clone(),
            veth_host,
            veth_agent,
            netns_path: format!("/var/run/netns/{}", ns_name),
        };

        tracing::info!(
            "Created network namespace '{}' (host={}, agent={})",
            ns_name,
            config.host_ip,
            config.agent_ip
        );

        Ok(handle)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(SysError::NotSupported {
            feature: "netns".into(),
        })
    }
}

/// Apply a pre-rendered nftables ruleset inside an agent's network namespace.
///
/// The `ruleset` should be a complete nftables script (as produced by
/// `nein::Firewall::render()`). It is written to a temp file and executed
/// via `ip netns exec <ns> nft -f <path>`.
///
/// Requires root or `CAP_NET_ADMIN`.
pub fn apply_nftables_ruleset(handle: &NetNamespaceHandle, ruleset: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Write ruleset to a unique temp file under /run to avoid predictable paths
        let run_dir = std::path::Path::new("/run/agnos");
        let _ = std::fs::create_dir_all(run_dir);
        let pid = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_name = format!("nft-{}-{}.conf", pid, ts);
        let tmp_path = run_dir.join(&tmp_name);
        let tmp_path_str = tmp_path.to_string_lossy().to_string();
        std::fs::write(&tmp_path, ruleset)
            .map_err(|e| SysError::Unknown(format!("Failed to write nft rules: {}", e).into()))?;

        let result = run_cmd(
            "ip",
            &["netns", "exec", &handle.name, "nft", "-f", &tmp_path_str],
        );

        let _ = std::fs::remove_file(&tmp_path);
        result?;

        tracing::info!(
            "Applied nftables ruleset ({} bytes) to namespace '{}'",
            ruleset.len(),
            handle.name
        );
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (handle, ruleset);
        Err(SysError::NotSupported {
            feature: "netns".into(),
        })
    }
}

/// Destroy an agent's network namespace and clean up veth pairs.
pub fn destroy_agent_netns(handle: NetNamespaceHandle) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Delete host-side veth (peer is auto-deleted)
        let _ = run_ip_cmd(&["link", "delete", &handle.veth_host]);

        // Delete namespace
        run_ip_cmd(&["netns", "delete", &handle.name])?;

        tracing::info!("Destroyed network namespace '{}'", handle.name);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = handle;
        Err(SysError::NotSupported {
            feature: "netns".into(),
        })
    }
}

/// List all AGNOS agent network namespaces.
///
/// Returns names of namespaces matching the `agnos-agent-*` pattern.
pub fn list_agent_netns() -> Result<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ip")
            .args(["netns", "list"])
            .output()
            .map_err(|e| {
                SysError::Unknown(format!("Failed to run 'ip netns list': {}", e).into())
            })?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let namespaces: Vec<String> = stdout
            .lines()
            .filter_map(|line| {
                // Format: "name (id: N)" or just "name"
                let name = line.split_whitespace().next()?;
                if name.starts_with("agnos-agent-") {
                    Some(name.to_string())
                } else {
                    None
                }
            })
            .collect();

        Ok(namespaces)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SysError::NotSupported {
            feature: "netns".into(),
        })
    }
}

/// Run an `ip` command with the given arguments.
#[cfg(target_os = "linux")]
fn run_ip_cmd(args: &[&str]) -> Result<()> {
    run_cmd("ip", args)
}

/// Run an `ip netns exec <ns> ip <args>` command.
#[cfg(target_os = "linux")]
fn run_ip_netns_cmd(ns_name: &str, args: &[&str]) -> Result<()> {
    let mut full_args = vec!["netns", "exec", ns_name, "ip"];
    full_args.extend_from_slice(args);
    run_cmd("ip", &full_args)
}

/// Run a command and check for success.
#[cfg(target_os = "linux")]
fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| SysError::Unknown(format!("Failed to run '{}': {}", cmd, e).into()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SysError::Unknown(
            format!("{} {} failed: {}", cmd, args.join(" "), stderr.trim()).into(),
        ));
    }

    Ok(())
}

/// Clean up a namespace and veth pair on error.
#[cfg(target_os = "linux")]
fn cleanup_netns(ns_name: &str, veth_host: &str) -> Result<()> {
    let _ = run_ip_cmd(&["link", "delete", veth_host]);
    run_ip_cmd(&["netns", "delete", ns_name])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_agent_ips() {
        let (host, agent) = generate_agent_ips("test-agent-1");
        assert!(host.starts_with("10.100."));
        assert!(host.ends_with(".1"));
        assert!(agent.starts_with("10.100."));
        assert!(agent.ends_with(".2"));
    }

    #[test]
    fn test_generate_agent_ips_deterministic() {
        let (h1, a1) = generate_agent_ips("same-agent");
        let (h2, a2) = generate_agent_ips("same-agent");
        assert_eq!(h1, h2);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_generate_agent_ips_different() {
        let (h1, _) = generate_agent_ips("agent-a");
        let (h2, _) = generate_agent_ips("agent-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_truncate_veth_name() {
        assert_eq!(truncate_veth_name("short"), "short");
        assert_eq!(truncate_veth_name("exactly15chars!"), "exactly15chars!");
        assert_eq!(
            truncate_veth_name("this-is-a-very-long-name"),
            "this-is-a-very-"
        );
    }

    #[test]
    fn test_net_namespace_config_for_agent() {
        let config = NetNamespaceConfig::for_agent("test-1");
        assert_eq!(config.name, "test-1");
        assert_eq!(config.prefix_len, 30);
        assert!(config.enable_nat);
        assert!(!config.dns_servers.is_empty());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_net_namespace_config_validate_empty_name() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.name = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_net_namespace_config_validate_bad_ip() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.agent_ip = "not-an-ip".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_net_namespace_config_validate_bad_prefix() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.prefix_len = 0;
        assert!(config.validate().is_err());

        config.prefix_len = 33;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_net_namespace_handle_serialization() {
        let handle = NetNamespaceHandle {
            name: "agnos-agent-test".to_string(),
            veth_host: "veth-test-h".to_string(),
            veth_agent: "veth-test-a".to_string(),
            netns_path: "/var/run/netns/agnos-agent-test".to_string(),
        };

        let json = serde_json::to_string(&handle).unwrap();
        let deserialized: NetNamespaceHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "agnos-agent-test");
        assert_eq!(deserialized.veth_host, "veth-test-h");
    }

    #[test]
    #[ignore = "Requires root and ip/nft tools"]
    fn test_create_and_destroy_netns() {
        let config = NetNamespaceConfig::for_agent("integration-test");
        let handle = create_agent_netns(&config).unwrap();
        assert!(handle.name.contains("integration-test"));

        let namespaces = list_agent_netns().unwrap();
        assert!(namespaces.iter().any(|n| n.contains("integration-test")));

        destroy_agent_netns(handle).unwrap();
    }

    #[test]
    fn test_net_namespace_config_validate_long_name() {
        let mut config = NetNamespaceConfig::for_agent("x");
        config.name = "a".repeat(65);
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn test_net_namespace_config_validate_exactly_64_chars() {
        let mut config = NetNamespaceConfig::for_agent("x");
        config.name = "a".repeat(64);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_net_namespace_config_validate_empty_agent_ip() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.agent_ip = String::new();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_net_namespace_config_validate_empty_host_ip() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.host_ip = String::new();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_net_namespace_config_validate_bad_host_ip() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.host_ip = "not-an-ip".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("Invalid host IP"));
    }

    #[test]
    fn test_net_namespace_config_validate_prefix_len_32() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.prefix_len = 32;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_net_namespace_config_validate_prefix_len_1() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.prefix_len = 1;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_net_namespace_config_clone() {
        let config = NetNamespaceConfig::for_agent("test-clone");
        let cloned = config.clone();
        assert_eq!(cloned.name, config.name);
        assert_eq!(cloned.agent_ip, config.agent_ip);
        assert_eq!(cloned.host_ip, config.host_ip);
        assert_eq!(cloned.prefix_len, config.prefix_len);
        assert_eq!(cloned.enable_nat, config.enable_nat);
        assert_eq!(cloned.dns_servers, config.dns_servers);
    }

    #[test]
    fn test_net_namespace_config_debug() {
        let config = NetNamespaceConfig::for_agent("dbg");
        let dbg = format!("{:?}", config);
        assert!(dbg.contains("NetNamespaceConfig"));
        assert!(dbg.contains("dbg"));
    }

    #[test]
    fn test_net_namespace_config_serialization_roundtrip() {
        let config = NetNamespaceConfig::for_agent("serde-test");
        let json = serde_json::to_string(&config).unwrap();
        let back: NetNamespaceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "serde-test");
        assert_eq!(back.agent_ip, config.agent_ip);
        assert_eq!(back.host_ip, config.host_ip);
        assert_eq!(back.prefix_len, 30);
        assert!(back.enable_nat);
        assert_eq!(back.dns_servers.len(), 2);
    }

    #[test]
    fn test_net_namespace_handle_clone_and_debug() {
        let handle = NetNamespaceHandle {
            name: "agnos-agent-test".to_string(),
            veth_host: "veth-test-h".to_string(),
            veth_agent: "veth-test-a".to_string(),
            netns_path: "/var/run/netns/agnos-agent-test".to_string(),
        };
        let cloned = handle.clone();
        assert_eq!(cloned.name, handle.name);
        assert_eq!(cloned.netns_path, handle.netns_path);
        let dbg = format!("{:?}", handle);
        assert!(dbg.contains("NetNamespaceHandle"));
    }

    #[test]
    fn test_generate_agent_ips_range() {
        for name in &["a", "bb", "ccc", "dddd", "eeeeee"] {
            let (host, agent) = generate_agent_ips(name);
            assert!(host.starts_with("10.100."));
            assert!(host.ends_with(".1"));
            assert!(agent.starts_with("10.100."));
            assert!(agent.ends_with(".2"));
            let parts: Vec<&str> = host.split('.').collect();
            let third: u8 = parts[2].parse().unwrap();
            assert!(third <= 254);
        }
    }

    #[test]
    fn test_truncate_veth_name_exact_15() {
        let name = "123456789012345";
        assert_eq!(truncate_veth_name(name), name);
    }

    #[test]
    fn test_truncate_veth_name_16() {
        let name = "1234567890123456";
        assert_eq!(truncate_veth_name(name), "123456789012345");
    }

    #[test]
    fn test_truncate_veth_name_empty() {
        assert_eq!(truncate_veth_name(""), "");
    }

    #[test]
    fn test_net_namespace_config_for_agent_dns_defaults() {
        let config = NetNamespaceConfig::for_agent("dns-test");
        assert_eq!(config.dns_servers, vec!["8.8.8.8", "8.8.4.4"]);
    }

    #[test]
    fn test_net_namespace_config_for_agent_nat_default() {
        let config = NetNamespaceConfig::for_agent("nat-test");
        assert!(config.enable_nat);
    }

    #[test]
    fn test_generate_agent_ips_empty_name() {
        let (host, agent) = generate_agent_ips("");
        assert!(host.starts_with("10.100."));
        assert!(agent.starts_with("10.100."));
    }

    #[test]
    fn test_generate_agent_ips_long_name() {
        let name = "a".repeat(1000);
        let (host, agent) = generate_agent_ips(&name);
        assert!(host.starts_with("10.100."));
        assert!(agent.ends_with(".2"));
    }

    #[test]
    fn test_net_namespace_config_for_agent_from_owned_string() {
        let config = NetNamespaceConfig::for_agent(String::from("owned-name"));
        assert_eq!(config.name, "owned-name");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_net_namespace_config_validate_prefix_len_zero_error_msg() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.prefix_len = 0;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("prefix length"));
    }

    #[test]
    fn test_net_namespace_config_validate_prefix_len_33_error_msg() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.prefix_len = 33;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("prefix length"));
    }

    #[test]
    fn test_net_namespace_config_validate_agent_ip_invalid_format() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.agent_ip = "999.999.999.999".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_net_namespace_config_for_agent_ip_determinism() {
        let c1 = NetNamespaceConfig::for_agent("deterministic");
        let c2 = NetNamespaceConfig::for_agent("deterministic");
        assert_eq!(c1.agent_ip, c2.agent_ip);
        assert_eq!(c1.host_ip, c2.host_ip);
    }

    #[test]
    fn test_truncate_veth_name_single_char() {
        assert_eq!(truncate_veth_name("x"), "x");
    }

    #[test]
    fn test_generate_agent_ips_all_valid_ipv4() {
        for i in 0..100 {
            let name = format!("agent-{}", i);
            let (host, agent) = generate_agent_ips(&name);
            assert!(
                host.parse::<std::net::Ipv4Addr>().is_ok(),
                "host IP not valid: {}",
                host
            );
            assert!(
                agent.parse::<std::net::Ipv4Addr>().is_ok(),
                "agent IP not valid: {}",
                agent
            );
        }
    }

    #[test]
    fn test_net_namespace_config_validate_ipv6_rejected() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.agent_ip = "::1".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_net_namespace_config_validate_all_valid_prefix_lens() {
        for pl in 1..=32u8 {
            let mut config = NetNamespaceConfig::for_agent("test");
            config.prefix_len = pl;
            assert!(
                config.validate().is_ok(),
                "prefix_len {} should be valid",
                pl
            );
        }
    }

    // -- Firewall types --

    #[test]
    fn test_firewall_rule_serde_roundtrip() {
        let rule = FirewallRule::new(
            TrafficDirection::Outbound,
            Protocol::Tcp,
            443,
            "",
            FirewallAction::Accept,
            "Allow HTTPS",
        );
        let json = serde_json::to_string(&rule).unwrap();
        let back: FirewallRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.port, 443);
        assert_eq!(back.direction, TrafficDirection::Outbound);
        assert_eq!(back.protocol, Protocol::Tcp);
        assert_eq!(back.action, FirewallAction::Accept);
    }

    #[test]
    fn test_firewall_policy_serde_roundtrip() {
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![
                FirewallRule::new(
                    TrafficDirection::Outbound,
                    Protocol::Tcp,
                    443,
                    "",
                    FirewallAction::Accept,
                    "HTTPS",
                ),
                FirewallRule::new(
                    TrafficDirection::Inbound,
                    Protocol::Tcp,
                    8080,
                    "",
                    FirewallAction::Accept,
                    "API",
                ),
            ],
        );
        let json = serde_json::to_string(&policy).unwrap();
        let back: FirewallPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rules.len(), 2);
        assert_eq!(back.default_inbound, FirewallAction::Drop);
    }

    #[test]
    fn test_render_nftables_ruleset_drop_all() {
        let policy = FirewallPolicy::new(FirewallAction::Drop, FirewallAction::Drop, vec![]);
        let ruleset = render_nftables_ruleset(&policy);
        assert!(ruleset.contains("table inet kavach"));
        assert!(ruleset.contains("policy drop"));
        assert!(ruleset.contains("chain input"));
        assert!(ruleset.contains("chain output"));
        assert!(ruleset.contains("ct state established,related accept"));
    }

    #[test]
    fn test_render_nftables_ruleset_with_rules() {
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![
                FirewallRule::new(
                    TrafficDirection::Outbound,
                    Protocol::Tcp,
                    443,
                    "",
                    FirewallAction::Accept,
                    "HTTPS out",
                ),
                FirewallRule::new(
                    TrafficDirection::Outbound,
                    Protocol::Any,
                    0,
                    "10.0.0.1",
                    FirewallAction::Accept,
                    "Allow host",
                ),
                FirewallRule::new(
                    TrafficDirection::Inbound,
                    Protocol::Tcp,
                    8080,
                    "",
                    FirewallAction::Accept,
                    "API in",
                ),
            ],
        );
        let ruleset = render_nftables_ruleset(&policy);
        assert!(ruleset.contains("tcp dport 443 accept"));
        assert!(ruleset.contains("ip daddr 10.0.0.1 accept"));
        assert!(ruleset.contains("tcp dport 8080 accept"));
    }

    #[test]
    fn test_render_nftables_ruleset_accept_all() {
        let policy = FirewallPolicy::new(FirewallAction::Accept, FirewallAction::Accept, vec![]);
        let ruleset = render_nftables_ruleset(&policy);
        assert!(ruleset.contains("policy accept"));
    }

    #[test]
    fn test_render_nftables_udp_rule() {
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![FirewallRule::new(
                TrafficDirection::Outbound,
                Protocol::Udp,
                53,
                "",
                FirewallAction::Accept,
                "DNS",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        assert!(ruleset.contains("udp dport 53 accept"));
    }

    #[test]
    fn test_traffic_direction_variants() {
        assert_ne!(TrafficDirection::Inbound, TrafficDirection::Outbound);
    }

    #[test]
    fn test_protocol_variants() {
        assert_ne!(Protocol::Tcp, Protocol::Udp);
        assert_ne!(Protocol::Tcp, Protocol::Any);
    }

    #[test]
    fn test_firewall_action_variants() {
        assert_ne!(FirewallAction::Accept, FirewallAction::Drop);
    }

    // -- Render nftables: inbound remote_addr --

    #[test]
    fn test_render_nftables_inbound_remote_addr() {
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![FirewallRule::new(
                TrafficDirection::Inbound,
                Protocol::Any,
                0,
                "192.168.1.0/24",
                FirewallAction::Accept,
                "Allow LAN",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        assert!(
            ruleset.contains("ip saddr 192.168.1.0/24 accept"),
            "ruleset: {ruleset}"
        );
        // Should NOT appear in output chain
        assert!(
            !ruleset.contains("ip daddr 192.168.1.0/24"),
            "inbound rule leaked to output chain"
        );
    }

    #[test]
    fn test_render_nftables_inbound_tcp_port_and_remote_addr() {
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![FirewallRule::new(
                TrafficDirection::Inbound,
                Protocol::Tcp,
                22,
                "10.0.0.5",
                FirewallAction::Drop,
                "Block SSH from host",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        // Both the port rule and the addr rule should be emitted for inbound
        assert!(
            ruleset.contains("tcp dport 22 drop"),
            "ruleset: {ruleset}"
        );
        assert!(
            ruleset.contains("ip saddr 10.0.0.5 drop"),
            "ruleset: {ruleset}"
        );
    }

    #[test]
    fn test_render_nftables_inbound_udp_rule() {
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![FirewallRule::new(
                TrafficDirection::Inbound,
                Protocol::Udp,
                5353,
                "",
                FirewallAction::Accept,
                "mDNS",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        assert!(ruleset.contains("udp dport 5353 accept"));
    }

    #[test]
    fn test_render_nftables_drop_action_in_rules() {
        let policy = FirewallPolicy::new(
            FirewallAction::Accept,
            FirewallAction::Accept,
            vec![
                FirewallRule::new(
                    TrafficDirection::Outbound,
                    Protocol::Tcp,
                    25,
                    "",
                    FirewallAction::Drop,
                    "Block SMTP",
                ),
                FirewallRule::new(
                    TrafficDirection::Inbound,
                    Protocol::Tcp,
                    23,
                    "",
                    FirewallAction::Drop,
                    "Block Telnet",
                ),
            ],
        );
        let ruleset = render_nftables_ruleset(&policy);
        assert!(ruleset.contains("tcp dport 25 drop"));
        assert!(ruleset.contains("tcp dport 23 drop"));
        assert!(ruleset.contains("policy accept"));
    }

    #[test]
    fn test_render_nftables_outbound_port_and_remote_addr() {
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![FirewallRule::new(
                TrafficDirection::Outbound,
                Protocol::Udp,
                443,
                "1.1.1.1",
                FirewallAction::Accept,
                "QUIC to Cloudflare",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        assert!(ruleset.contains("udp dport 443 accept"));
        assert!(ruleset.contains("ip daddr 1.1.1.1 accept"));
    }

    #[test]
    fn test_render_nftables_any_protocol_port_ignored() {
        // Protocol::Any with port > 0: no proto line emitted (since proto is None)
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![FirewallRule::new(
                TrafficDirection::Outbound,
                Protocol::Any,
                80,
                "",
                FirewallAction::Accept,
                "Any proto port 80",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        // No "tcp dport" or "udp dport" should appear
        assert!(
            !ruleset.contains("dport 80"),
            "Protocol::Any should not emit dport line: {ruleset}"
        );
    }

    #[test]
    fn test_render_nftables_zero_port_not_emitted() {
        // port == 0 means the proto+port line is skipped even with Tcp/Udp
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![FirewallRule::new(
                TrafficDirection::Outbound,
                Protocol::Tcp,
                0,
                "10.0.0.1",
                FirewallAction::Accept,
                "No port",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        assert!(
            !ruleset.contains("tcp dport"),
            "port 0 should skip dport line: {ruleset}"
        );
        assert!(ruleset.contains("ip daddr 10.0.0.1 accept"));
    }

    #[test]
    fn test_render_nftables_mixed_default_policies() {
        let policy =
            FirewallPolicy::new(FirewallAction::Accept, FirewallAction::Drop, vec![]);
        let ruleset = render_nftables_ruleset(&policy);
        // Input chain: accept, output chain: drop
        assert!(ruleset.contains("chain input { type filter hook input priority 0; policy accept;"));
        assert!(
            ruleset.contains("chain output { type filter hook output priority 0; policy drop;")
        );
    }

    #[test]
    fn test_render_nftables_comment_preserved() {
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![FirewallRule::new(
                TrafficDirection::Outbound,
                Protocol::Tcp,
                443,
                "",
                FirewallAction::Accept,
                "Allow HTTPS outbound",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        assert!(ruleset.contains("comment \"Allow HTTPS outbound\""));
    }

    #[test]
    fn test_render_nftables_loopback_accept() {
        let policy = FirewallPolicy::new(FirewallAction::Drop, FirewallAction::Drop, vec![]);
        let ruleset = render_nftables_ruleset(&policy);
        assert!(ruleset.contains("iif lo accept"));
        assert!(ruleset.contains("oif lo accept"));
    }

    #[test]
    fn test_render_nftables_many_rules() {
        let rules: Vec<FirewallRule> = (1..=10)
            .map(|i| {
                FirewallRule::new(
                    if i % 2 == 0 {
                        TrafficDirection::Inbound
                    } else {
                        TrafficDirection::Outbound
                    },
                    Protocol::Tcp,
                    i * 100,
                    "",
                    FirewallAction::Accept,
                    format!("rule-{i}"),
                )
            })
            .collect();
        let policy = FirewallPolicy::new(FirewallAction::Drop, FirewallAction::Drop, rules);
        let ruleset = render_nftables_ruleset(&policy);
        // All rules should appear
        for i in 1..=10u16 {
            assert!(
                ruleset.contains(&format!("tcp dport {}", i * 100)),
                "missing rule for port {}",
                i * 100
            );
        }
    }

    #[test]
    fn test_render_nftables_inbound_any_proto_empty_addr_no_rule_lines() {
        // Protocol::Any + port 0 + empty addr => no rule-specific lines at all
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![FirewallRule::new(
                TrafficDirection::Inbound,
                Protocol::Any,
                0,
                "",
                FirewallAction::Accept,
                "No-op",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        assert!(!ruleset.contains("No-op"), "empty rule should produce no lines: {ruleset}");
    }

    // -- Firewall type construction and traits --

    #[test]
    fn test_firewall_rule_new_fields() {
        let rule = FirewallRule::new(
            TrafficDirection::Inbound,
            Protocol::Udp,
            53,
            "8.8.8.8",
            FirewallAction::Drop,
            "Block DNS",
        );
        assert_eq!(rule.direction, TrafficDirection::Inbound);
        assert_eq!(rule.protocol, Protocol::Udp);
        assert_eq!(rule.port, 53);
        assert_eq!(rule.remote_addr, "8.8.8.8");
        assert_eq!(rule.action, FirewallAction::Drop);
        assert_eq!(rule.comment, "Block DNS");
    }

    #[test]
    fn test_firewall_rule_clone() {
        let rule = FirewallRule::new(
            TrafficDirection::Outbound,
            Protocol::Tcp,
            443,
            "1.2.3.4",
            FirewallAction::Accept,
            "HTTPS",
        );
        let cloned = rule.clone();
        assert_eq!(cloned.port, rule.port);
        assert_eq!(cloned.remote_addr, rule.remote_addr);
        assert_eq!(cloned.comment, rule.comment);
        assert_eq!(cloned.direction, rule.direction);
        assert_eq!(cloned.protocol, rule.protocol);
        assert_eq!(cloned.action, rule.action);
    }

    #[test]
    fn test_firewall_rule_debug() {
        let rule = FirewallRule::new(
            TrafficDirection::Inbound,
            Protocol::Any,
            0,
            "",
            FirewallAction::Drop,
            "debug test",
        );
        let dbg = format!("{:?}", rule);
        assert!(dbg.contains("FirewallRule"));
        assert!(dbg.contains("debug test"));
    }

    #[test]
    fn test_firewall_policy_new_fields() {
        let policy = FirewallPolicy::new(FirewallAction::Accept, FirewallAction::Drop, vec![]);
        assert_eq!(policy.default_inbound, FirewallAction::Accept);
        assert_eq!(policy.default_outbound, FirewallAction::Drop);
        assert!(policy.rules.is_empty());
    }

    #[test]
    fn test_firewall_policy_clone() {
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Accept,
            vec![FirewallRule::new(
                TrafficDirection::Outbound,
                Protocol::Tcp,
                80,
                "",
                FirewallAction::Accept,
                "HTTP",
            )],
        );
        let cloned = policy.clone();
        assert_eq!(cloned.rules.len(), 1);
        assert_eq!(cloned.default_inbound, FirewallAction::Drop);
        assert_eq!(cloned.default_outbound, FirewallAction::Accept);
    }

    #[test]
    fn test_firewall_policy_debug() {
        let policy = FirewallPolicy::new(FirewallAction::Drop, FirewallAction::Drop, vec![]);
        let dbg = format!("{:?}", policy);
        assert!(dbg.contains("FirewallPolicy"));
    }

    // -- Enum serde roundtrips --

    #[test]
    fn test_traffic_direction_serde_roundtrip() {
        for dir in [TrafficDirection::Inbound, TrafficDirection::Outbound] {
            let json = serde_json::to_string(&dir).unwrap();
            let back: TrafficDirection = serde_json::from_str(&json).unwrap();
            assert_eq!(back, dir);
        }
    }

    #[test]
    fn test_protocol_serde_roundtrip() {
        for proto in [Protocol::Tcp, Protocol::Udp, Protocol::Any] {
            let json = serde_json::to_string(&proto).unwrap();
            let back: Protocol = serde_json::from_str(&json).unwrap();
            assert_eq!(back, proto);
        }
    }

    #[test]
    fn test_firewall_action_serde_roundtrip() {
        for action in [FirewallAction::Accept, FirewallAction::Drop] {
            let json = serde_json::to_string(&action).unwrap();
            let back: FirewallAction = serde_json::from_str(&json).unwrap();
            assert_eq!(back, action);
        }
    }

    // -- Enum copy semantics --

    #[test]
    fn test_traffic_direction_copy() {
        let d = TrafficDirection::Inbound;
        let d2 = d; // Copy
        assert_eq!(d, d2);
    }

    #[test]
    fn test_protocol_copy() {
        let p = Protocol::Tcp;
        let p2 = p;
        assert_eq!(p, p2);
    }

    #[test]
    fn test_firewall_action_copy() {
        let a = FirewallAction::Accept;
        let a2 = a;
        assert_eq!(a, a2);
    }

    // -- NetNamespaceHandle additional tests --

    #[test]
    fn test_net_namespace_handle_serde_all_fields() {
        let handle = NetNamespaceHandle {
            name: "agnos-agent-full".to_string(),
            veth_host: "veth-full-h".to_string(),
            veth_agent: "veth-full-a".to_string(),
            netns_path: "/var/run/netns/agnos-agent-full".to_string(),
        };
        let json = serde_json::to_string(&handle).unwrap();
        let back: NetNamespaceHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "agnos-agent-full");
        assert_eq!(back.veth_host, "veth-full-h");
        assert_eq!(back.veth_agent, "veth-full-a");
        assert_eq!(back.netns_path, "/var/run/netns/agnos-agent-full");
    }

    // -- Config with custom values --

    #[test]
    fn test_net_namespace_config_custom_dns() {
        let mut config = NetNamespaceConfig::for_agent("custom-dns");
        config.dns_servers = vec!["1.1.1.1".to_string()];
        assert_eq!(config.dns_servers.len(), 1);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_net_namespace_config_nat_disabled() {
        let mut config = NetNamespaceConfig::for_agent("no-nat");
        config.enable_nat = false;
        assert!(!config.enable_nat);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_net_namespace_config_custom_ips() {
        let config = NetNamespaceConfig {
            name: "custom".to_string(),
            agent_ip: "172.16.0.2".to_string(),
            host_ip: "172.16.0.1".to_string(),
            prefix_len: 24,
            enable_nat: false,
            dns_servers: vec![],
        };
        assert!(config.validate().is_ok());
        assert_eq!(config.prefix_len, 24);
    }

    #[test]
    fn test_net_namespace_config_validate_host_ip_ipv6_rejected() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.host_ip = "fe80::1".to_string();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("Invalid host IP"));
    }

    #[test]
    fn test_net_namespace_config_validate_agent_ip_with_port_rejected() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.agent_ip = "10.0.0.1:8080".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_net_namespace_config_validate_agent_ip_cidr_rejected() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.agent_ip = "10.0.0.1/24".to_string();
        assert!(config.validate().is_err());
    }

    // -- IP generation edge cases --

    #[test]
    fn test_generate_agent_ips_special_chars() {
        let (host, agent) = generate_agent_ips("agent-with-special_chars.v2");
        assert!(host.parse::<std::net::Ipv4Addr>().is_ok());
        assert!(agent.parse::<std::net::Ipv4Addr>().is_ok());
    }

    #[test]
    fn test_generate_agent_ips_unicode() {
        let (host, agent) = generate_agent_ips("日本語エージェント");
        assert!(host.parse::<std::net::Ipv4Addr>().is_ok());
        assert!(agent.parse::<std::net::Ipv4Addr>().is_ok());
    }

    #[test]
    fn test_generate_agent_ips_whitespace() {
        let (host, agent) = generate_agent_ips("agent with spaces");
        assert!(host.starts_with("10.100."));
        assert!(agent.ends_with(".2"));
    }

    #[test]
    fn test_generate_agent_ips_host_agent_differ() {
        let (host, agent) = generate_agent_ips("any-agent");
        assert_ne!(host, agent, "host and agent IPs must differ");
    }

    // -- Firewall rule with owned String args --

    #[test]
    fn test_firewall_rule_new_with_owned_strings() {
        let rule = FirewallRule::new(
            TrafficDirection::Inbound,
            Protocol::Tcp,
            80,
            String::from("10.0.0.0/8"),
            FirewallAction::Accept,
            String::from("Allow private"),
        );
        assert_eq!(rule.remote_addr, "10.0.0.0/8");
        assert_eq!(rule.comment, "Allow private");
    }

    // -- Config validation: prefix_len boundary 255 --

    #[test]
    fn test_net_namespace_config_validate_prefix_len_255() {
        let mut config = NetNamespaceConfig::for_agent("test");
        config.prefix_len = 255;
        assert!(config.validate().is_err());
    }

    // -- Serialization: config with empty dns --

    #[test]
    fn test_net_namespace_config_serde_empty_dns() {
        let config = NetNamespaceConfig {
            name: "no-dns".to_string(),
            agent_ip: "10.100.0.2".to_string(),
            host_ip: "10.100.0.1".to_string(),
            prefix_len: 30,
            enable_nat: false,
            dns_servers: vec![],
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: NetNamespaceConfig = serde_json::from_str(&json).unwrap();
        assert!(back.dns_servers.is_empty());
        assert!(!back.enable_nat);
    }

    // -- Render nftables: outbound rule skipped in input chain --

    #[test]
    fn test_render_nftables_outbound_not_in_input() {
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![FirewallRule::new(
                TrafficDirection::Outbound,
                Protocol::Tcp,
                9999,
                "",
                FirewallAction::Accept,
                "outbound only",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        // The tcp dport 9999 should only appear in the output section.
        // Split at "chain output" and check it's only in the second half.
        let parts: Vec<&str> = ruleset.split("chain output").collect();
        assert_eq!(parts.len(), 2);
        assert!(
            !parts[0].contains("tcp dport 9999"),
            "outbound rule appeared in input chain"
        );
        assert!(
            parts[1].contains("tcp dport 9999"),
            "outbound rule missing from output chain"
        );
    }

    #[test]
    fn test_render_nftables_inbound_not_in_output() {
        let policy = FirewallPolicy::new(
            FirewallAction::Drop,
            FirewallAction::Drop,
            vec![FirewallRule::new(
                TrafficDirection::Inbound,
                Protocol::Tcp,
                7777,
                "",
                FirewallAction::Accept,
                "inbound only",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        let parts: Vec<&str> = ruleset.split("chain output").collect();
        assert_eq!(parts.len(), 2);
        assert!(
            parts[0].contains("tcp dport 7777"),
            "inbound rule missing from input chain"
        );
        assert!(
            !parts[1].contains("tcp dport 7777"),
            "inbound rule leaked to output chain"
        );
    }

    // -- Render nftables: remote_addr with drop action --

    #[test]
    fn test_render_nftables_outbound_remote_addr_drop() {
        let policy = FirewallPolicy::new(
            FirewallAction::Accept,
            FirewallAction::Accept,
            vec![FirewallRule::new(
                TrafficDirection::Outbound,
                Protocol::Any,
                0,
                "192.168.0.0/16",
                FirewallAction::Drop,
                "Block private range",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        assert!(ruleset.contains("ip daddr 192.168.0.0/16 drop"));
    }

    #[test]
    fn test_render_nftables_inbound_remote_addr_drop() {
        let policy = FirewallPolicy::new(
            FirewallAction::Accept,
            FirewallAction::Accept,
            vec![FirewallRule::new(
                TrafficDirection::Inbound,
                Protocol::Any,
                0,
                "0.0.0.0/0",
                FirewallAction::Drop,
                "Block everything",
            )],
        );
        let ruleset = render_nftables_ruleset(&policy);
        assert!(ruleset.contains("ip saddr 0.0.0.0/0 drop"));
    }
}
