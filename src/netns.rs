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

use crate::error::{Result, SysError};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Configuration for creating a per-agent network namespace.
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

/// Handle for an active network namespace.
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
pub fn destroy_agent_netns(handle: &NetNamespaceHandle) -> Result<()> {
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

        destroy_agent_netns(&handle).unwrap();
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
}
