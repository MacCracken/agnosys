//! Example: enumerate network and block devices via sysfs.

fn main() {
    println!("Network interfaces:");
    for dev in agnosys::udev::list_devices(Some("net")).unwrap() {
        let addr = dev.properties.get("address").cloned().unwrap_or_default();
        println!("  {} ({})", dev.devpath, addr);
    }

    println!("\nBlock devices:");
    match agnosys::udev::list_devices(Some("block")) {
        Ok(devs) => {
            for dev in devs {
                let size = dev.properties.get("size").cloned().unwrap_or_default();
                println!("  {} (size: {} sectors)", dev.devpath, size);
            }
        }
        Err(e) => println!("  (not available: {e})"),
    }
}
