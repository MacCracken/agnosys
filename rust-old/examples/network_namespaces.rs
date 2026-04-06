//! Example: list existing agent network namespaces.

fn main() -> agnosys::error::Result<()> {
    // List all AGNOS agent network namespaces currently on the system
    let namespaces = agnosys::netns::list_agent_netns()?;
    if namespaces.is_empty() {
        println!("No agent network namespaces found.");
    } else {
        println!("Agent network namespaces ({}):", namespaces.len());
        for ns in &namespaces {
            println!("  {ns}");
        }
    }

    // Show what IPs would be generated for a hypothetical agent
    let agent_name = "example-agent";
    let (host_ip, agent_ip) = agnosys::netns::generate_agent_ips(agent_name);
    println!("\nGenerated IPs for '{agent_name}':");
    println!("  Host side:  {host_ip}");
    println!("  Agent side: {agent_ip}");

    Ok(())
}
