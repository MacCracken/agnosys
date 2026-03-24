//! Example: enumerate network and block devices via sysfs.

fn main() {
    println!("Network interfaces:");
    for dev in agnosys::udev::enumerate("net").unwrap() {
        let addr = dev.attr("address").unwrap_or_default();
        println!("  {} ({})", dev.name(), addr);
    }

    println!("\nBlock devices:");
    match agnosys::udev::enumerate("block") {
        Ok(devs) => {
            for dev in devs {
                let size = dev.attr("size").unwrap_or_default();
                println!("  {} (size: {} sectors)", dev.name(), size);
            }
        }
        Err(e) => println!("  (not available: {e})"),
    }
}
